#![cfg(all(test, feature = "std"))]

mod common;

use common::{create_service_and_client_nodes, get_lsps_message, Node};

use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::lsps2::event::{LSPS2ClientEvent, LSPS2ServiceEvent};
use lightning_liquidity::lsps2::msgs::LSPS2RawOpeningFeeParams;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig;
use lightning_liquidity::lsps2::utils::is_valid_opening_fee_params;
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};

use lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA;
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::log_error;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning::util::logger::Logger;

use lightning_invoice::{Bolt11Invoice, InvoiceBuilder, RoutingFees};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;

use std::str::FromStr;
use std::time::Duration;

fn create_jit_invoice(
	node: &Node, service_node_id: PublicKey, intercept_scid: u64, cltv_expiry_delta: u32,
	payment_size_msat: Option<u64>, description: &str, expiry_secs: u32,
) -> Result<Bolt11Invoice, ()> {
	// LSPS2 requires min_final_cltv_expiry_delta to be at least 2 more than usual.
	let min_final_cltv_expiry_delta = MIN_FINAL_CLTV_EXPIRY_DELTA + 2;
	let (payment_hash, payment_secret) = node
		.channel_manager
		.create_inbound_payment(None, expiry_secs, Some(min_final_cltv_expiry_delta))
		.map_err(|e| {
			log_error!(node.logger, "Failed to register inbound payment: {:?}", e);
			()
		})?;

	let route_hint = RouteHint(vec![RouteHintHop {
		src_node_id: service_node_id,
		short_channel_id: intercept_scid,
		fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
		cltv_expiry_delta: cltv_expiry_delta as u16,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	}]);

	let payment_hash = sha256::Hash::from_slice(&payment_hash.0).map_err(|e| {
		log_error!(node.logger, "Invalid payment hash: {:?}", e);
		()
	})?;

	let currency = Network::Bitcoin.into();
	let mut invoice_builder = InvoiceBuilder::new(currency)
		.description(description.to_string())
		.payment_hash(payment_hash)
		.payment_secret(payment_secret)
		.current_timestamp()
		.min_final_cltv_expiry_delta(min_final_cltv_expiry_delta.into())
		.expiry_time(Duration::from_secs(expiry_secs.into()))
		.private_route(route_hint);

	if let Some(amount_msat) = payment_size_msat {
		invoice_builder = invoice_builder.amount_milli_satoshis(amount_msat).basic_mpp();
	}

	invoice_builder
		.build_signed(|hash| {
			Secp256k1::new().sign_ecdsa_recoverable(hash, &node.keys_manager.get_node_secret_key())
		})
		.map_err(|e| {
			log_error!(node.logger, "Failed to build and sign invoice: {}", e);
			()
		})
}

#[test]
fn invoice_generation_flow() {
	let promise_secret = [42; 32];
	let lsps2_service_config = LSPS2ServiceConfig { promise_secret };
	let service_config = LiquidityServiceConfig {
		#[cfg(lsps1_service)]
		lsps1_service_config: None,
		lsps2_service_config: Some(lsps2_service_config),
		lsps5_service_config: None,
		advertise_service: true,
	};

	let lsps2_client_config = LSPS2ClientConfig::default();
	let client_config = LiquidityClientConfig {
		lsps1_client_config: None,
		lsps2_client_config: Some(lsps2_client_config),
		lsps5_client_config: None,
	};

	let (service_node, client_node) =
		create_service_and_client_nodes("invoice_generation_flow", service_config, client_config);

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let service_node_id = service_node.channel_manager.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let client_node_id = client_node.channel_manager.get_our_node_id();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	match get_info_event {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo {
			request_id,
			counterparty_node_id,
			token,
		}) => {
			assert_eq!(request_id, get_info_request_id);
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(token, None);
		},
		_ => panic!("Unexpected event"),
	}

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: 100,
		proportional: 21,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1,
		max_payment_size_msat: 100_000_000,
	};

	service_handler
		.opening_fee_params_generated(
			&client_node_id,
			get_info_request_id.clone(),
			vec![raw_opening_params],
		)
		.unwrap();
	let get_info_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let opening_params_event = client_node.liquidity_manager.next_event().unwrap();
	let opening_fee_params = match opening_params_event {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			request_id,
			counterparty_node_id,
			opening_fee_params_menu,
		}) => {
			assert_eq!(request_id, get_info_request_id);
			assert_eq!(counterparty_node_id, service_node_id);
			let opening_fee_params = opening_fee_params_menu.first().unwrap().clone();
			assert!(is_valid_opening_fee_params(&opening_fee_params, &promise_secret));
			opening_fee_params
		},
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(1_000_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params.clone())
		.unwrap();

	let buy_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id).unwrap();

	let buy_event = service_node.liquidity_manager.next_event().unwrap();
	match buy_event {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::BuyRequest {
			request_id,
			counterparty_node_id,
			opening_fee_params: ofp,
			payment_size_msat: psm,
		}) => {
			assert_eq!(request_id, buy_request_id);
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(opening_fee_params, ofp);
			assert_eq!(payment_size_msat, psm);
		},
		_ => panic!("Unexpected event"),
	}

	let user_channel_id = 42;
	let cltv_expiry_delta = 144;
	let intercept_scid = service_node.channel_manager.get_intercept_scid();
	let client_trusts_lsp = true;

	service_handler
		.invoice_parameters_generated(
			&client_node_id,
			buy_request_id.clone(),
			intercept_scid,
			cltv_expiry_delta,
			client_trusts_lsp,
			user_channel_id,
		)
		.unwrap();

	let buy_response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(buy_response, service_node_id).unwrap();

	let invoice_params_event = client_node.liquidity_manager.next_event().unwrap();
	match invoice_params_event {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::InvoiceParametersReady {
			request_id,
			counterparty_node_id,
			intercept_scid: iscid,
			cltv_expiry_delta: ced,
			payment_size_msat: psm,
		}) => {
			assert_eq!(request_id, buy_request_id);
			assert_eq!(counterparty_node_id, service_node_id);
			assert_eq!(intercept_scid, iscid);
			assert_eq!(cltv_expiry_delta, ced);
			assert_eq!(payment_size_msat, psm);
		},
		_ => panic!("Unexpected event"),
	};

	let description = "asdf";
	let expiry_secs = 3600;
	let _invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		description,
		expiry_secs,
	)
	.unwrap();
}
