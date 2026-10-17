#![cfg(all(test, feature = "std", feature = "time"))]

mod common;

use common::{
	create_service_and_client_nodes_with_kv_stores,
	create_service_client_and_payer_nodes_with_kv_stores, get_lsps_message, LSPSNodes,
	LSPSNodesWithPayer, LiquidityNode,
};

use lightning::events::{ClosureReason, Event, HTLCHandlingFailureType};
use lightning::get_event_msg;
use lightning::ln::channelmanager::{
	OptionalBolt11PaymentParams, PaymentId, TrustedChannelFeatures,
};
use lightning::ln::functional_test_utils::*;
use lightning::ln::msgs::BaseMessageHandler;
use lightning::ln::msgs::ChannelMessageHandler;
use lightning::ln::msgs::MessageSendEvent;
use lightning::ln::types::ChannelId;

use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::lsps2::event::LSPS2ClientEvent;
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent;
use lightning_liquidity::lsps2::msgs::LSPS2RawOpeningFeeParams;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig;
use lightning_liquidity::lsps2::utils::is_valid_opening_fee_params;
use lightning_liquidity::utils::time::{DefaultTimeProvider, TimeProvider};
use lightning_liquidity::{LiquidityClientConfig, LiquidityManagerSync, LiquidityServiceConfig};

use lightning::ln::channelmanager::{InterceptId, MIN_FINAL_CLTV_EXPIRY_DELTA};
use lightning::ln::functional_test_utils::{
	create_chanmon_cfgs, create_node_cfgs, create_node_chanmgrs,
};
use lightning::ln::functional_test_utils::{create_network, Node};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::log_error;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning::sign::NodeSigner;
use lightning::util::config::HTLCInterceptionFlags;
use lightning::util::errors::APIError;
use lightning::util::logger::Logger;
use lightning::util::test_utils::{TestBroadcaster, TestStore};

use lightning_invoice::{Bolt11Invoice, InvoiceBuilder, RoutingFees};

use lightning_types::payment::PaymentHash;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use lightning_types::payment::PaymentPreimage;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const MAX_PENDING_REQUESTS_PER_PEER: usize = 10;
const MAX_TOTAL_PENDING_REQUESTS: usize = 1000;

fn build_lsps2_configs() -> ([u8; 32], LiquidityServiceConfig, LiquidityClientConfig) {
	let promise_secret = [42; 32];
	let lsps2_service_config = LSPS2ServiceConfig { promise_secret };
	let service_config = LiquidityServiceConfig {
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

	(promise_secret, service_config, client_config)
}

fn setup_test_lsps2_nodes_with_kv_stores<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, service_kv_store: Arc<TestStore>, client_kv_store: Arc<TestStore>,
) -> (LSPSNodes<'a, 'b, 'c>, [u8; 32]) {
	let (promise_secret, service_config, client_config) = build_lsps2_configs();
	let lsps_nodes = create_service_and_client_nodes_with_kv_stores(
		nodes,
		service_config,
		client_config,
		Arc::new(DefaultTimeProvider),
		service_kv_store,
		client_kv_store,
	);
	(lsps_nodes, promise_secret)
}

fn setup_test_lsps2_nodes<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>,
) -> (LSPSNodes<'a, 'b, 'c>, [u8; 32]) {
	let service_kv_store = Arc::new(TestStore::new(false));
	let client_kv_store = Arc::new(TestStore::new(false));
	setup_test_lsps2_nodes_with_kv_stores(nodes, service_kv_store, client_kv_store)
}

fn setup_test_lsps2_nodes_with_payer<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>,
) -> (LSPSNodesWithPayer<'a, 'b, 'c>, [u8; 32]) {
	setup_test_lsps2_nodes_with_payer_and_kv_stores(
		nodes,
		Arc::new(TestStore::new(false)),
		Arc::new(TestStore::new(false)),
	)
}

fn setup_test_lsps2_nodes_with_payer_and_kv_stores<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, service_kv_store: Arc<TestStore>, client_kv_store: Arc<TestStore>,
) -> (LSPSNodesWithPayer<'a, 'b, 'c>, [u8; 32]) {
	let (promise_secret, service_config, client_config) = build_lsps2_configs();
	let lsps_nodes = create_service_client_and_payer_nodes_with_kv_stores(
		nodes,
		service_config,
		client_config,
		Arc::new(DefaultTimeProvider),
		service_kv_store,
		client_kv_store,
	);
	(lsps_nodes, promise_secret)
}

fn create_jit_invoice(
	node: &LiquidityNode<'_, '_, '_>, service_node_id: PublicKey, intercept_scid: u64,
	cltv_expiry_delta: u32, payment_size_msat: Option<u64>, description: &str, expiry_secs: u32,
) -> Result<Bolt11Invoice, ()> {
	// LSPS2 requires min_final_cltv_expiry_delta to be at least 2 more than usual.
	let min_final_cltv_expiry_delta = MIN_FINAL_CLTV_EXPIRY_DELTA + 2;
	let (payment_hash, payment_secret, _) = node
		.node
		.create_inbound_payment(None, expiry_secs, Some(min_final_cltv_expiry_delta), None)
		.map_err(|e| {
			log_error!(node.logger, "Failed to register inbound payment: {:?}", e);
		})?;

	let route_hint = RouteHint(vec![RouteHintHop {
		src_node_id: service_node_id,
		short_channel_id: intercept_scid,
		fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
		cltv_expiry_delta: cltv_expiry_delta as u16,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	}]);

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

	let raw_invoice = invoice_builder.build_raw().map_err(|e| {
		log_error!(node.inner.logger, "Failed to build raw invoice: {:?}", e);
	})?;

	let sign_fn =
		node.inner.keys_manager.sign_invoice(&raw_invoice, lightning::sign::Recipient::Node);

	let invoice = raw_invoice.sign(|_| sign_fn).and_then(|signed_raw| {
		Bolt11Invoice::from_signed(signed_raw).map_err(|e| {
			log_error!(node.inner.logger, "Failed to create invoice from signed raw: {:?}", e);
		})
	})?;

	Ok(invoice)
}

#[test]
fn invoice_generation_flow() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo {
		request_id,
		counterparty_node_id,
		token,
	}) = get_info_event
	{
		assert_eq!(request_id, get_info_request_id);
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(token, None);
	} else {
		panic!("Unexpected event");
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
			assert!(is_valid_opening_fee_params(
				&opening_fee_params,
				&promise_secret,
				&client_node_id
			));
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
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::BuyRequest {
		request_id,
		counterparty_node_id,
		opening_fee_params: ofp,
		payment_size_msat: psm,
	}) = buy_event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(opening_fee_params, ofp);
		assert_eq!(payment_size_msat, psm);
	} else {
		panic!("Unexpected event");
	}

	let user_channel_id = 42;
	let cltv_expiry_delta = 144;
	let intercept_scid = service_node.node.get_intercept_scid();
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
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::InvoiceParametersReady {
		request_id,
		counterparty_node_id,
		intercept_scid: iscid,
		cltv_expiry_delta: ced,
		payment_size_msat: psm,
	}) = invoice_params_event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(intercept_scid, iscid);
		assert_eq!(cltv_expiry_delta, ced);
		assert_eq!(payment_size_msat, psm);
	} else {
		panic!("Unexpected event");
	}

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

#[test]
fn channel_open_failed() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let _get_info_event = service_node.liquidity_manager.next_event().unwrap();

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

	let opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(1_000_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params.clone())
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id).unwrap();

	let _buy_event = service_node.liquidity_manager.next_event().unwrap();
	let user_channel_id = 42;
	let cltv_expiry_delta = 144;
	let intercept_scid = service_node.node.get_intercept_scid();
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
	let _invoice_params_event = client_node.liquidity_manager.next_event().unwrap();

	// Test calling channel_open_failed in invalid state (before HTLC interception)
	let result = service_handler.channel_open_failed(&client_node_id, user_channel_id);
	assert!(result.is_err());
	match result.unwrap_err() {
		APIError::APIMisuseError { err } => {
			assert!(err.contains("Channel is not in the PendingChannelOpen state."));
		},
		other => panic!("Unexpected error type: {:?}", other),
	}

	let htlc_amount_msat = 1_000_000;
	let intercept_id = InterceptId([0; 32]);
	let payment_hash = PaymentHash([1; 32]);

	// This should trigger an OpenChannel event
	service_handler
		.htlc_intercepted(
			intercept_scid,
			intercept_id,
			htlc_amount_msat,
			payment_hash,
			htlc_amount_msat,
		)
		.unwrap();

	let _ = match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			user_channel_id: channel_id,
			intercept_scid: scid,
			..
		}) => {
			assert_eq!(channel_id, user_channel_id);
			assert_eq!(scid, intercept_scid);
			true
		},
		_ => panic!("Expected OpenChannel event"),
	};

	service_handler.channel_open_failed(&client_node_id, user_channel_id).unwrap();

	// Verify we can restart the flow with another HTLC
	let new_intercept_id = InterceptId([1; 32]);
	service_handler
		.htlc_intercepted(
			intercept_scid,
			new_intercept_id,
			htlc_amount_msat,
			payment_hash,
			htlc_amount_msat,
		)
		.unwrap();

	// Should get another OpenChannel event which confirms the reset worked
	let _ = match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			user_channel_id: channel_id,
			intercept_scid: scid,
			..
		}) => {
			assert_eq!(channel_id, user_channel_id);
			assert_eq!(scid, intercept_scid);
			true
		},
		_ => panic!("Expected OpenChannel event after reset"),
	};
}

#[test]
fn channel_open_failed_releases_intercepted_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_config.accept_underpaying_htlcs = true;

	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(service_node_config), Some(client_node_config), None],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 42u128;
	let cltv_expiry_delta: u32 = 144;
	let payment_size_msat = Some(1_000_000);
	let fee_base_msat: u64 = 1_000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"channel-open-failed-cleanup",
		3600,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let intercept_id = match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash,
			expected_outbound_amount_msat,
			inbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);
			service_handler
				.htlc_intercepted(
					*requested_next_hop_scid,
					*intercept_id,
					*expected_outbound_amount_msat,
					*payment_hash,
					*inbound_amount_msat,
				)
				.unwrap();
			*intercept_id
		},
		other => panic!("Expected HTLCIntercepted, got {:?}", other),
	};

	match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel { .. }) => {},
		other => panic!("Unexpected event: {:?}", other),
	};

	service_handler.channel_open_failed(&client_node_id, user_channel_id).unwrap();

	let res = service_node.inner.node.fail_intercepted_htlc(intercept_id);
	assert!(
		res.is_err(),
		"channel_open_failed must release the intercepted HTLC via fail_intercepted_htlc, but the entry is still pending: {:?}",
		res,
	);

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::HTLCHandlingFailed {
			failure_type: HTLCHandlingFailureType::InvalidForward { requested_forward_scid },
			..
		} => assert_eq!(*requested_forward_scid, intercept_scid),
		other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
	}
}

/// An intercepted HTLC whose onion declares more than it delivered is failed back before
/// the JIT channel's state machine sees it, and the client's intercept SCID survives the attempt.
#[test]
fn htlc_declaring_more_than_delivered_is_failed_back() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_config.accept_underpaying_htlcs = true;

	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(service_node_config), Some(client_node_config), None],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 42u128;
	let cltv_expiry_delta: u32 = 144;
	let payment_size_msat = Some(1_000_000);
	let fee_base_msat: u64 = 1_000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"declared-more-than-delivered",
		3600,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (intercept_id, payment_hash, expected_outbound_amount_msat) = match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash,
			expected_outbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);
			(*intercept_id, *payment_hash, *expected_outbound_amount_msat)
		},
		other => panic!("Expected HTLCIntercepted, got {:?}", other),
	};

	// Report the HTLC as having delivered one msat less than its onion declares.
	let result = service_handler.htlc_intercepted(
		intercept_scid,
		intercept_id,
		expected_outbound_amount_msat,
		payment_hash,
		expected_outbound_amount_msat - 1,
	);
	match result {
		Err(APIError::APIMisuseError { err }) => {
			assert!(err.contains("declares"), "unexpected error: {}", err)
		},
		other => panic!("Expected APIMisuseError, got {:?}", other),
	}

	// The HTLC was failed back to the payer ...
	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::HTLCHandlingFailed {
			failure_type: HTLCHandlingFailureType::InvalidForward { requested_forward_scid, .. },
			..
		} => assert_eq!(*requested_forward_scid, intercept_scid),
		other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
	}
	// ... and is no longer pending with the channel manager ...
	assert!(service_node.inner.node.fail_intercepted_htlc(intercept_id).is_err());
	// ... and no channel open was requested.
	assert!(service_node.liquidity_manager.next_event().is_none());

	// The client's intercept SCID is still live: an honest HTLC on it opens the channel.
	service_handler
		.htlc_intercepted(
			intercept_scid,
			InterceptId([7; 32]),
			expected_outbound_amount_msat,
			payment_hash,
			expected_outbound_amount_msat,
		)
		.unwrap();
	match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			intercept_scid: scid,
			..
		}) => assert_eq!(scid, intercept_scid),
		other => panic!("Unexpected event: {:?}", other),
	};
}

/// Pays the given invoice from the payer, delivers the HTLC to the service node, and returns the
/// intercepted HTLC's id and payment hash.
fn intercept_payment_for_invoice(
	payer_node: &Node, service_node: &Node, invoice: &Bolt11Invoice, intercept_scid: u64,
	amount_msat: u64,
) -> (InterceptId, PaymentHash) {
	let payer_node_id = payer_node.node.get_our_node_id();
	payer_node
		.node
		.pay_for_bolt11_invoice(
			invoice,
			PaymentId(invoice.payment_hash().0),
			Some(amount_msat),
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(service_node, payer_node, &ev.commitment_msg, false, true);
	service_node.node.process_pending_htlc_forwards();

	let events = service_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash,
			expected_outbound_amount_msat,
			inbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);
			assert_eq!(*expected_outbound_amount_msat, amount_msat);
			assert_eq!(*inbound_amount_msat, amount_msat);
			(*intercept_id, *payment_hash)
		},
		other => panic!("Expected HTLCIntercepted, got {:?}", other),
	}
}

/// Takes the service node's pending forward of an intercepted HTLC to the client.
fn take_forward_to_client(service_node: &Node) -> SendEvent {
	{
		let mut added_monitors = service_node.chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		added_monitors.clear();
	}
	let mut msg_events = service_node.node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	SendEvent::from_event(msg_events.remove(0))
}

/// Fails a payment back from the service node to the payer and asserts the payer saw it fail.
fn propagate_failure_to_payer(service_node: &Node, payer_node: &Node, payment_hash: PaymentHash) {
	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.node.get_our_node_id();
	let fail_msgs = get_htlc_update_msgs(service_node, &payer_node_id);
	payer_node.node.handle_update_fail_htlc(service_node_id, &fail_msgs.update_fail_htlcs[0]);
	do_commitment_signed_dance(payer_node, service_node, &fail_msgs.commitment_signed, true, true);
	let events = payer_node.node.get_and_clear_pending_events();
	for ev in &events {
		if let Event::PaymentPathFailed { payment_hash: failed_payment_hash, .. } = ev {
			assert_eq!(*failed_payment_hash, payment_hash);
		}
	}
	assert!(events.iter().any(|ev| matches!(ev, Event::PaymentPathFailed { .. })));
}

/// Rewrites the persisted LSPS2 peer state for `counterparty_node_id`, replacing the payment
/// queue of the peer's single JIT channel awaiting a fee payment with `entries`, as a version
/// that admitted zero-value HTLCs could have persisted.
fn seed_persisted_payment_queue(
	kv_store: &TestStore, counterparty_node_id: &PublicKey,
	entries: &[(InterceptId, u64, PaymentHash)],
) {
	use lightning::util::persist::KVStoreSync;
	use lightning_liquidity::persist::{
		LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
		LSPS2_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
	};

	fn read_bigsize(bytes: &[u8], pos: &mut usize) -> u64 {
		let byte = bytes[*pos];
		*pos += 1;
		match byte {
			0xff => {
				let res = u64::from_be_bytes(bytes[*pos..*pos + 8].try_into().unwrap());
				*pos += 8;
				res
			},
			0xfe => {
				let res = u32::from_be_bytes(bytes[*pos..*pos + 4].try_into().unwrap());
				*pos += 4;
				u64::from(res)
			},
			0xfd => {
				let res = u16::from_be_bytes(bytes[*pos..*pos + 2].try_into().unwrap());
				*pos += 2;
				u64::from(res)
			},
			n => u64::from(n),
		}
	}

	fn write_bigsize(val: u64) -> Vec<u8> {
		match val {
			0..=0xfc => vec![val as u8],
			0xfd..=0xffff => {
				let mut out = vec![0xfdu8];
				out.extend_from_slice(&(val as u16).to_be_bytes());
				out
			},
			0x10000..=0xffffffff => {
				let mut out = vec![0xfeu8];
				out.extend_from_slice(&(val as u32).to_be_bytes());
				out
			},
			_ => {
				let mut out = vec![0xffu8];
				out.extend_from_slice(&val.to_be_bytes());
				out
			},
		}
	}

	struct TlvRecord {
		typ: u64,
		value: Vec<u8>,
	}

	fn read_tlv_stream(bytes: &[u8]) -> Vec<TlvRecord> {
		let mut pos = 0;
		let stream_len = read_bigsize(bytes, &mut pos) as usize;
		let end = pos + stream_len;
		let mut records = Vec::new();
		while pos < end {
			let typ = read_bigsize(bytes, &mut pos);
			let len = read_bigsize(bytes, &mut pos) as usize;
			records.push(TlvRecord { typ, value: bytes[pos..pos + len].to_vec() });
			pos += len;
		}
		assert_eq!(pos, end);
		records
	}

	fn write_tlv_stream(records: &[TlvRecord]) -> Vec<u8> {
		let body_len: usize = records
			.iter()
			.map(|r| {
				write_bigsize(r.typ).len()
					+ write_bigsize(r.value.len() as u64).len()
					+ r.value.len()
			})
			.sum();
		let mut out = write_bigsize(body_len as u64);
		for record in records {
			out.extend(write_bigsize(record.typ));
			out.extend(write_bigsize(record.value.len() as u64));
			out.extend_from_slice(&record.value);
		}
		out
	}

	let key = counterparty_node_id.to_string();
	let blob = kv_store
		.read(
			LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
			LSPS2_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
			&key,
		)
		.unwrap();

	// Walk down to the JIT channel's state: record 0 of the peer state holds the
	// `outbound_channels_by_intercept_scid` map, which holds a single channel keyed by its
	// intercept scid, whose state record holds the awaited fee payment.
	let peer_records = read_tlv_stream(&blob);
	let channel_map = &peer_records.iter().find(|r| r.typ == 0).unwrap().value;
	assert_eq!(u16::from_be_bytes(channel_map[0..2].try_into().unwrap()), 1);
	let intercept_scid = u64::from_be_bytes(channel_map[2..10].try_into().unwrap());
	let channel_records = read_tlv_stream(&channel_map[10..]);
	let state = &channel_records.iter().find(|r| r.typ == 0).unwrap().value;
	assert_eq!(state[0], 6, "Expected the JIT channel to await a fee payment");
	let state_records = read_tlv_stream(&state[1..]);

	// Serialize the entries the way `PaymentQueue`'s `optional_vec` would: a single record
	// holding the concatenated `PaymentQueueEntry` streams.
	let mut payments = Vec::new();
	for (intercept_id, expected_outbound_amount_msat, payment_hash) in entries {
		let htlc = write_tlv_stream(&[
			TlvRecord { typ: 0, value: intercept_id.0.to_vec() },
			TlvRecord { typ: 2, value: expected_outbound_amount_msat.to_be_bytes().to_vec() },
			TlvRecord { typ: 4, value: payment_hash.0.to_vec() },
		]);
		payments.extend_from_slice(&write_tlv_stream(&[
			TlvRecord { typ: 0, value: payment_hash.0.to_vec() },
			TlvRecord { typ: 2, value: htlc },
		]));
	}

	let new_queue = write_tlv_stream(&[TlvRecord { typ: 0, value: payments }]);
	let new_state_records = state_records
		.iter()
		.map(|r| {
			if r.typ == 0 {
				TlvRecord { typ: 0, value: new_queue.clone() }
			} else {
				TlvRecord { typ: r.typ, value: r.value.clone() }
			}
		})
		.collect::<Vec<_>>();
	let mut new_state = vec![6u8];
	new_state.extend_from_slice(&write_tlv_stream(&new_state_records));
	let new_channel_records = channel_records
		.iter()
		.map(|r| {
			if r.typ == 0 {
				TlvRecord { typ: 0, value: new_state.clone() }
			} else {
				TlvRecord { typ: r.typ, value: r.value.clone() }
			}
		})
		.collect::<Vec<_>>();
	let new_channel_map = [
		&[0u8, 1][..],
		&intercept_scid.to_be_bytes()[..],
		write_tlv_stream(&new_channel_records).as_slice(),
	]
	.concat();
	let new_peer_records = peer_records
		.iter()
		.map(|r| {
			if r.typ == 0 {
				TlvRecord { typ: 0, value: new_channel_map.clone() }
			} else {
				TlvRecord { typ: r.typ, value: r.value.clone() }
			}
		})
		.collect::<Vec<_>>();
	kv_store
		.write(
			LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
			LSPS2_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
			&key,
			write_tlv_stream(&new_peer_records),
		)
		.unwrap();
}

#[test]
fn zero_outgoing_retry_is_failed_back_and_order_preserved() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[Some(service_node_config), None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 45u128;
	let cltv_expiry_delta: u32 = 144;
	// A variable-size order on an offer whose fee parameters compute to a zero opening fee
	// accepts payments of any size.
	let payment_size_msat = None;
	let fee_base_msat: u64 = 0;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"zero-outgoing-retry",
		3600,
	)
	.unwrap();

	let initial_amount_msat = 1_000_000;
	let (intercept_id, payment_hash) = intercept_payment_for_invoice(
		&payer_node,
		&service_node.inner,
		&invoice,
		intercept_scid,
		initial_amount_msat,
	);
	service_handler
		.htlc_intercepted(
			intercept_scid,
			intercept_id,
			initial_amount_msat,
			payment_hash,
			initial_amount_msat,
		)
		.unwrap();

	// Open the JIT channel and forward the initial payment to the client.
	let (channel_id, _funding_tx) = create_channel_with_manual_broadcast(
		&service_node_id,
		&client_node_id,
		&service_node,
		&client_node,
		user_channel_id,
		&initial_amount_msat,
		true,
	);

	service_handler.channel_ready(user_channel_id, &channel_id, &client_node_id).unwrap();
	service_node.inner.node.process_pending_htlc_forwards();

	let pay_event = take_forward_to_client(&service_node.inner);
	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	match &client_events[0] {
		Event::PaymentClaimable { .. } => {},
		other => panic!("Expected PaymentClaimable, got {:?}", other),
	}

	// The client rejects the payment, failing it back over the JIT channel and leaving the
	// channel awaiting a retry payment.
	client_node.inner.node.fail_htlc_backwards(&payment_hash);
	client_node.inner.node.process_pending_htlc_forwards();
	check_added_monitors(&client_node.inner, 1);
	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	match &client_events[0] {
		Event::HTLCHandlingFailed {
			failure_type: HTLCHandlingFailureType::Receive { payment_hash: failed_payment_hash },
			..
		} => assert_eq!(*failed_payment_hash, payment_hash),
		other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
	}
	let fail_msgs = get_htlc_update_msgs(&client_node.inner, &service_node_id);
	assert_eq!(fail_msgs.update_fail_htlcs.len(), 1);
	service_node
		.inner
		.node
		.handle_update_fail_htlc(client_node_id, &fail_msgs.update_fail_htlcs[0]);
	do_commitment_signed_dance(
		&service_node.inner,
		&client_node.inner,
		&fail_msgs.commitment_signed,
		true,
		true,
	);

	let failure_type = {
		let events = service_node.inner.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events.into_iter().next().unwrap() {
			Event::HTLCHandlingFailed { failure_type, .. } => failure_type,
			other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
		}
	};
	match &failure_type {
		HTLCHandlingFailureType::Forward { channel_id: failed_channel_id, .. } => {
			assert_eq!(*failed_channel_id, channel_id)
		},
		other => panic!("Expected forward failure, got {:?}", other),
	}
	service_node.inner.node.process_pending_htlc_forwards();
	check_added_monitors(&service_node.inner, 1);
	propagate_failure_to_payer(&service_node.inner, &payer_node, payment_hash);
	service_handler.htlc_handling_failed(failure_type).unwrap();

	// A retry intercepted for the same SCID with a positive incoming amount but a zero
	// `amt_to_forward` in the payer's onion is failed back ...
	let retry_invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"zero-outgoing-retry-2",
		3600,
	)
	.unwrap();

	let retry_amount_msat = 600_000;
	let (retry_intercept_id, retry_payment_hash) = intercept_payment_for_invoice(
		&payer_node,
		&service_node.inner,
		&retry_invoice,
		intercept_scid,
		retry_amount_msat,
	);

	let result = service_handler.htlc_intercepted(
		intercept_scid,
		retry_intercept_id,
		0,
		retry_payment_hash,
		retry_amount_msat,
	);
	match result {
		Err(APIError::APIMisuseError { err }) => {
			assert!(err.contains("declares 0msat to forward"), "unexpected error: {}", err)
		},
		other => panic!("Expected APIMisuseError, got {:?}", other),
	}

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::HTLCHandlingFailed {
			failure_type: HTLCHandlingFailureType::InvalidForward { requested_forward_scid },
			..
		} => assert_eq!(*requested_forward_scid, intercept_scid),
		other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
	}
	assert!(service_node.inner.node.fail_intercepted_htlc(retry_intercept_id).is_err());
	service_node.inner.node.process_pending_htlc_forwards();
	check_added_monitors(&service_node.inner, 1);
	propagate_failure_to_payer(&service_node.inner, &payer_node, retry_payment_hash);

	// ... while the order is preserved: a subsequent honest retry is forwarded to the client.
	let honest_invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"zero-outgoing-retry-3",
		3600,
	)
	.unwrap();

	let honest_amount_msat = 800_000;
	let (honest_intercept_id, honest_payment_hash) = intercept_payment_for_invoice(
		&payer_node,
		&service_node.inner,
		&honest_invoice,
		intercept_scid,
		honest_amount_msat,
	);
	service_handler
		.htlc_intercepted(
			intercept_scid,
			honest_intercept_id,
			honest_amount_msat,
			honest_payment_hash,
			honest_amount_msat,
		)
		.unwrap();
	service_node.inner.node.process_pending_htlc_forwards();

	let pay_event = take_forward_to_client(&service_node.inner);
	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	match &client_events[0] {
		Event::PaymentClaimable { payment_hash: claimed_payment_hash, .. } => {
			assert_eq!(*claimed_payment_hash, honest_payment_hash);
		},
		other => panic!("Expected PaymentClaimable, got {:?}", other),
	}
}

#[test]
fn stale_zero_value_queue_entry_is_failed_back() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[Some(service_node_config), None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let service_kv_store = Arc::new(TestStore::new(false));
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer_and_kv_stores(
		nodes,
		Arc::clone(&service_kv_store),
		Arc::new(TestStore::new(false)),
	);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 45u128;
	let cltv_expiry_delta: u32 = 144;
	// A variable-size order on an offer whose fee parameters compute to a zero opening fee
	// accepts payments of any size.
	let payment_size_msat = None;
	let fee_base_msat: u64 = 0;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"stale-zero-entry",
		3600,
	)
	.unwrap();

	// The initial payment is forwarded to the client, who rejects it, leaving the JIT channel
	// awaiting a retry payment with an empty payment queue.
	let initial_amount_msat = 1_000_000;
	let (intercept_id, payment_hash) = intercept_payment_for_invoice(
		&payer_node,
		&service_node.inner,
		&invoice,
		intercept_scid,
		initial_amount_msat,
	);
	service_handler
		.htlc_intercepted(
			intercept_scid,
			intercept_id,
			initial_amount_msat,
			payment_hash,
			initial_amount_msat,
		)
		.unwrap();

	let (channel_id, _funding_tx) = create_channel_with_manual_broadcast(
		&service_node_id,
		&client_node_id,
		&service_node,
		&client_node,
		user_channel_id,
		&initial_amount_msat,
		true,
	);

	service_handler.channel_ready(user_channel_id, &channel_id, &client_node_id).unwrap();
	service_node.inner.node.process_pending_htlc_forwards();

	let pay_event = take_forward_to_client(&service_node.inner);
	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	match &client_events[0] {
		Event::PaymentClaimable { .. } => {},
		other => panic!("Expected PaymentClaimable, got {:?}", other),
	}

	client_node.inner.node.fail_htlc_backwards(&payment_hash);
	client_node.inner.node.process_pending_htlc_forwards();
	check_added_monitors(&client_node.inner, 1);
	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	match &client_events[0] {
		Event::HTLCHandlingFailed {
			failure_type: HTLCHandlingFailureType::Receive { payment_hash: failed_payment_hash },
			..
		} => assert_eq!(*failed_payment_hash, payment_hash),
		other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
	}
	let fail_msgs = get_htlc_update_msgs(&client_node.inner, &service_node_id);
	assert_eq!(fail_msgs.update_fail_htlcs.len(), 1);
	service_node
		.inner
		.node
		.handle_update_fail_htlc(client_node_id, &fail_msgs.update_fail_htlcs[0]);
	do_commitment_signed_dance(
		&service_node.inner,
		&client_node.inner,
		&fail_msgs.commitment_signed,
		true,
		true,
	);

	let failure_type = {
		let events = service_node.inner.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events.into_iter().next().unwrap() {
			Event::HTLCHandlingFailed { failure_type, .. } => failure_type,
			other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
		}
	};
	match &failure_type {
		HTLCHandlingFailureType::Forward { channel_id: failed_channel_id, .. } => {
			assert_eq!(*failed_channel_id, channel_id)
		},
		other => panic!("Expected forward failure, got {:?}", other),
	}
	service_node.inner.node.process_pending_htlc_forwards();
	check_added_monitors(&service_node.inner, 1);
	propagate_failure_to_payer(&service_node.inner, &payer_node, payment_hash);
	service_handler.htlc_handling_failed(failure_type).unwrap();
	service_node.liquidity_manager.persist().unwrap();

	// Two more payments are intercepted while the service is "down" for the restart below, so
	// the channel manager still holds them pending: a payment an older version could have
	// persisted as a zero-value queue entry, and an honest payment queued behind it.
	let stale_invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"stale-zero-entry-2",
		3600,
	)
	.unwrap();
	let stale_amount_msat = 600_000;
	let (stale_intercept_id, stale_payment_hash) = intercept_payment_for_invoice(
		&payer_node,
		&service_node.inner,
		&stale_invoice,
		intercept_scid,
		stale_amount_msat,
	);

	let honest_invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"stale-zero-entry-3",
		3600,
	)
	.unwrap();
	let honest_amount_msat = 700_000;
	let (honest_intercept_id, honest_payment_hash) = intercept_payment_for_invoice(
		&payer_node,
		&service_node.inner,
		&honest_invoice,
		intercept_scid,
		honest_amount_msat,
	);

	// Restart the service's liquidity manager against the same nodes, as an upgrade would, and
	// seed the persisted payment queue with the stale entry ahead of the honest one.
	let LSPSNodesWithPayer { service_node, client_node, payer_node } = lsps_nodes;
	let LiquidityNode { inner: service_inner, liquidity_manager: old_service_lm } = service_node;
	drop(old_service_lm);

	seed_persisted_payment_queue(
		&service_kv_store,
		&client_node_id,
		&[
			(stale_intercept_id, 0, stale_payment_hash),
			(honest_intercept_id, honest_amount_msat, honest_payment_hash),
		],
	);

	let (_, service_config, _) = build_lsps2_configs();
	let restarted_lm = LiquidityManagerSync::new_with_custom_time_provider(
		service_inner.keys_manager,
		service_inner.keys_manager,
		service_inner.node,
		Arc::clone(&service_kv_store),
		service_inner.tx_broadcaster,
		Some(service_config),
		None,
		Arc::new(DefaultTimeProvider),
	)
	.unwrap();
	let service_handler = restarted_lm.lsps2_service_handler().unwrap();

	// A retry intercepted for the same SCID pops the stale zero-value entry as the fee
	// payment. There is no fee to skim, so the HTLC is forwarded unskimmed, and the channel
	// manager fails the zero-value forward back instead of dividing by zero.
	let retry_invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"stale-zero-entry-4",
		3600,
	)
	.unwrap();
	let retry_amount_msat = 400_000;
	let (retry_intercept_id, retry_payment_hash) = intercept_payment_for_invoice(
		&payer_node,
		&service_inner,
		&retry_invoice,
		intercept_scid,
		retry_amount_msat,
	);
	service_handler
		.htlc_intercepted(
			intercept_scid,
			retry_intercept_id,
			retry_amount_msat,
			retry_payment_hash,
			retry_amount_msat,
		)
		.unwrap();
	service_inner.node.process_pending_htlc_forwards();

	let failure_type = {
		let events = service_inner.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events.into_iter().next().unwrap() {
			Event::HTLCHandlingFailed { failure_type, .. } => failure_type,
			other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
		}
	};
	match &failure_type {
		HTLCHandlingFailureType::Forward { channel_id: failed_channel_id, .. } => {
			assert_eq!(*failed_channel_id, channel_id)
		},
		other => panic!("Expected forward failure, got {:?}", other),
	}
	service_inner.node.process_pending_htlc_forwards();
	check_added_monitors(&service_inner, 1);
	propagate_failure_to_payer(&service_inner, &payer_node, stale_payment_hash);
	service_handler.htlc_handling_failed(failure_type).unwrap();

	// Fails the payment the client finds claimable back over the JIT channel, and fails it back
	// to the payer, so the handler can pop the next queued payment.
	let fail_back_from_client = |payment_hash: PaymentHash| -> HTLCHandlingFailureType {
		client_node.inner.node.fail_htlc_backwards(&payment_hash);
		client_node.inner.node.process_pending_htlc_forwards();
		check_added_monitors(&client_node.inner, 1);
		let client_events = client_node.inner.node.get_and_clear_pending_events();
		assert_eq!(client_events.len(), 1);
		match &client_events[0] {
			Event::HTLCHandlingFailed {
				failure_type: HTLCHandlingFailureType::Receive { payment_hash: failed_payment_hash },
				..
			} => assert_eq!(*failed_payment_hash, payment_hash),
			other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
		}
		let fail_msgs = get_htlc_update_msgs(&client_node.inner, &service_node_id);
		assert_eq!(fail_msgs.update_fail_htlcs.len(), 1);
		service_inner.node.handle_update_fail_htlc(client_node_id, &fail_msgs.update_fail_htlcs[0]);
		do_commitment_signed_dance(
			&service_inner,
			&client_node.inner,
			&fail_msgs.commitment_signed,
			true,
			true,
		);
		let failure_type = {
			let events = service_inner.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events.into_iter().next().unwrap() {
				Event::HTLCHandlingFailed { failure_type, .. } => failure_type,
				other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
			}
		};
		match &failure_type {
			HTLCHandlingFailureType::Forward { channel_id: failed_channel_id, .. } => {
				assert_eq!(*failed_channel_id, channel_id)
			},
			other => panic!("Expected forward failure, got {:?}", other),
		}
		service_inner.node.process_pending_htlc_forwards();
		check_added_monitors(&service_inner, 1);
		failure_type
	};

	// Forwards the payment the handler popped next to the client, which finds it claimable.
	let forward_to_client = |expected_payment_hash: PaymentHash| {
		service_inner.node.process_pending_htlc_forwards();
		let pay_event = take_forward_to_client(&service_inner);
		client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
		do_commitment_signed_dance(
			&client_node.inner,
			&service_inner,
			&pay_event.commitment_msg,
			false,
			true,
		);
		client_node.inner.node.process_pending_htlc_forwards();
		let client_events = client_node.inner.node.get_and_clear_pending_events();
		assert_eq!(client_events.len(), 1);
		match &client_events[0] {
			Event::PaymentClaimable { payment_hash: claimed_payment_hash, .. } => {
				assert_eq!(*claimed_payment_hash, expected_payment_hash);
			},
			other => panic!("Expected PaymentClaimable, got {:?}", other),
		}
	};

	// The honest payment queued behind the stale entry is forwarded in its place ...
	forward_to_client(honest_payment_hash);
	let failure_type = fail_back_from_client(honest_payment_hash);
	propagate_failure_to_payer(&service_inner, &payer_node, honest_payment_hash);
	service_handler.htlc_handling_failed(failure_type).unwrap();

	// ... and so is the retry that popped the stale entry. Failing it back, too, leaves the
	// channel `PendingPayment` again.
	forward_to_client(retry_payment_hash);
	let failure_type = fail_back_from_client(retry_payment_hash);
	propagate_failure_to_payer(&service_inner, &payer_node, retry_payment_hash);
	service_handler.htlc_handling_failed(failure_type).unwrap();

	// A later positive retry is forwarded as usual.
	let later_invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"stale-zero-entry-5",
		3600,
	)
	.unwrap();
	let later_amount_msat = 500_000;
	let (later_intercept_id, later_payment_hash) = intercept_payment_for_invoice(
		&payer_node,
		&service_inner,
		&later_invoice,
		intercept_scid,
		later_amount_msat,
	);
	service_handler
		.htlc_intercepted(
			intercept_scid,
			later_intercept_id,
			later_amount_msat,
			later_payment_hash,
			later_amount_msat,
		)
		.unwrap();
	forward_to_client(later_payment_hash);
}

#[test]
fn channel_open_failed_nonexistent_channel() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;

	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	// Call channel_open_failed with a nonexistent user_channel_id
	let nonexistent_user_channel_id = 999;
	let result = service_handler.channel_open_failed(&client_node_id, nonexistent_user_channel_id);

	assert!(result.is_err());
	match result.unwrap_err() {
		APIError::APIMisuseError { err } => {
			assert!(err.contains("No counterparty state for"));
		},
		other => panic!("Unexpected error type: {:?}", other),
	}
}

#[test]
fn channel_open_abandoned() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	// Set up a JIT channel
	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();
	let _get_info_event = service_node.liquidity_manager.next_event().unwrap();

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

	let opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(1_000_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params.clone())
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id).unwrap();

	let _buy_event = service_node.liquidity_manager.next_event().unwrap();
	let user_channel_id = 42;
	let cltv_expiry_delta = 144;
	let intercept_scid = service_node.node.get_intercept_scid();
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

	// Call channel_open_abandoned
	service_handler.channel_open_abandoned(&client_node_id, user_channel_id).unwrap();

	// Verify the channel is gone by trying to abandon it again, which should fail
	let result = service_handler.channel_open_abandoned(&client_node_id, user_channel_id);
	assert!(result.is_err());
}

#[test]
fn channel_open_abandoned_releases_intercepted_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_config.accept_underpaying_htlcs = true;

	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(service_node_config), Some(client_node_config), None],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 42u128;
	let cltv_expiry_delta: u32 = 144;
	let payment_size_msat = Some(1_000_000);
	let fee_base_msat: u64 = 1_000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"channel-open-abandoned-cleanup",
		3600,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let intercept_id = match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash,
			expected_outbound_amount_msat,
			inbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);
			service_handler
				.htlc_intercepted(
					*requested_next_hop_scid,
					*intercept_id,
					*expected_outbound_amount_msat,
					*payment_hash,
					*inbound_amount_msat,
				)
				.unwrap();
			*intercept_id
		},
		other => panic!("Expected HTLCIntercepted, got {:?}", other),
	};

	match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel { .. }) => {},
		other => panic!("Unexpected event: {:?}", other),
	};

	service_handler.channel_open_abandoned(&client_node_id, user_channel_id).unwrap();

	let res = service_node.inner.node.fail_intercepted_htlc(intercept_id);
	assert!(
		res.is_err(),
		"channel_open_abandoned must release the intercepted HTLC via fail_intercepted_htlc, but the entry is still pending: {:?}",
		res,
	);

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::HTLCHandlingFailed {
			failure_type: HTLCHandlingFailureType::InvalidForward { requested_forward_scid },
			..
		} => assert_eq!(*requested_forward_scid, intercept_scid),
		other => panic!("Expected HTLCHandlingFailed, got {:?}", other),
	}
}

#[test]
fn channel_open_abandoned_nonexistent_channel() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;

	let client_node_id = client_node.inner.node.get_our_node_id();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	// Call channel_open_abandoned with a nonexistent user_channel_id
	let nonexistent_user_channel_id = 999;
	let result =
		service_handler.channel_open_abandoned(&client_node_id, nonexistent_user_channel_id);
	assert!(result.is_err());
	match result.unwrap_err() {
		APIError::APIMisuseError { err } => {
			assert!(err.contains("No counterparty state for"));
		},
		other => panic!("Unexpected error type: {:?}", other),
	}
}

#[test]
fn max_pending_requests_per_peer_rejected() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	for _ in 0..MAX_PENDING_REQUESTS_PER_PEER {
		let _ = client_handler.request_opening_params(service_node_id, None);
		let req_msg = get_lsps_message!(client_node, service_node_id);
		let result = service_node.liquidity_manager.handle_custom_message(req_msg, client_node_id);
		assert!(result.is_ok());
		let event = service_node.liquidity_manager.next_event().unwrap();
		match event {
			LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { .. }) => {},
			_ => panic!("Unexpected event"),
		}
	}

	// Test per-peer limit: the next request should be rejected
	let rejected_req_id = client_handler.request_opening_params(service_node_id, None);
	let rejected_req_msg = get_lsps_message!(client_node, service_node_id);

	let result =
		service_node.liquidity_manager.handle_custom_message(rejected_req_msg, client_node_id);
	assert!(result.is_err(), "We should have hit the per-peer limit");

	let get_info_error_response = get_lsps_message!(service_node, client_node_id);
	let result = client_node
		.liquidity_manager
		.handle_custom_message(get_info_error_response, service_node_id);
	assert!(result.is_err());

	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::GetInfoFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = event
	{
		assert_eq!(request_id, rejected_req_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 1); // LSPS0_CLIENT_REJECTED_ERROR_CODE
	} else {
		panic!("Expected LSPS2ClientEvent::GetInfoFailed event");
	}
}

#[test]
fn max_total_requests_buy_rejected() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let secp = Secp256k1::new();

	let special_sk_bytes = [99u8; 32];
	let special_sk = SecretKey::from_slice(&special_sk_bytes).unwrap();
	let special_node_id = PublicKey::from_secret_key(&secp, &special_sk);

	let _ = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node
		.liquidity_manager
		.handle_custom_message(get_info_request, special_node_id)
		.unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { request_id, .. }) =
		get_info_event
	{
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
			.opening_fee_params_generated(&special_node_id, request_id, vec![raw_opening_params])
			.unwrap();
	} else {
		panic!("Unexpected event");
	}

	let get_info_response = get_lsps_message!(service_node, special_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let opening_params_event = client_node.liquidity_manager.next_event().unwrap();
	let opening_fee_params = match opening_params_event {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	// Now fill up the global limit with additional GetInfo requests from other peers
	let mut filled = 0;
	let mut peer_idx = 0;

	while filled < MAX_TOTAL_PENDING_REQUESTS {
		let sk_bytes = [peer_idx as u8 + 1; 32];
		let sk = SecretKey::from_slice(&sk_bytes).unwrap();
		let peer_node_id = PublicKey::from_secret_key(&secp, &sk);

		// Skip if this is our special node
		if peer_node_id == special_node_id {
			peer_idx += 1;
			continue;
		}

		for _ in 0..MAX_PENDING_REQUESTS_PER_PEER {
			if filled >= MAX_TOTAL_PENDING_REQUESTS {
				break;
			}

			let _ = client_handler.request_opening_params(service_node_id, None);
			let req_msg = get_lsps_message!(client_node, service_node_id);
			let result =
				service_node.liquidity_manager.handle_custom_message(req_msg, peer_node_id);
			assert!(result.is_ok());

			let event = service_node.liquidity_manager.next_event().unwrap();
			match event {
				LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { .. }) => {},
				_ => panic!("Unexpected event"),
			}

			filled += 1;
		}
		peer_idx += 1;
	}

	// Now try to send a Buy request with our special node, which should be rejected
	let payment_size_msat = Some(1_000_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params)
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);

	let result = service_node.liquidity_manager.handle_custom_message(buy_request, special_node_id);
	assert!(result.is_err(), "The Buy request should have been rejected");

	let buy_error_response = get_lsps_message!(service_node, special_node_id);
	let result =
		client_node.liquidity_manager.handle_custom_message(buy_error_response, service_node_id);
	assert!(result.is_err());

	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::BuyRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 1); // LSPS0_CLIENT_REJECTED_ERROR_CODE
	} else {
		panic!("Expected LSPS2ClientEvent::BuyRequestFailed event");
	}
}

#[test]
fn invalid_token_flow() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let token = Some("invalid_token".to_string());
	let get_info_request_id = client_handler.request_opening_params(service_node_id, token);
	let get_info_request = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo {
		request_id,
		counterparty_node_id,
		token,
	}) = get_info_event
	{
		assert_eq!(request_id, get_info_request_id);
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(token, Some("invalid_token".to_string()));

		// Service rejects the token as invalid
		service_handler.invalid_token_provided(&client_node_id, request_id.clone()).unwrap();

		// Attempt to respond to the same request again which should fail
		// because the request has been removed from pending_requests
		let raw_opening_params = LSPS2RawOpeningFeeParams {
			min_fee_msat: 100,
			proportional: 21,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 144,
			max_client_to_self_delay: 128,
			min_payment_size_msat: 1,
			max_payment_size_msat: 100_000_000,
		};

		let result = service_handler.opening_fee_params_generated(
			&client_node_id,
			request_id.clone(),
			vec![raw_opening_params],
		);

		assert!(result.is_err(), "Request should have been removed from pending_requests");
	} else {
		panic!("Unexpected event");
	}

	let get_info_error_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(get_info_error_response, service_node_id)
		.unwrap_err();

	let error_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::GetInfoFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = error_event
	{
		assert_eq!(request_id, get_info_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 200); // LSPS2_GET_INFO_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE
	} else {
		panic!("Expected LSPS2ClientEvent::GetInfoFailed event");
	}
}

#[test]
fn opening_fee_params_menu_is_sorted_by_spec() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let _ = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	let request_id = match get_info_event {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { request_id, .. }) => request_id,
		_ => panic!("Unexpected event"),
	};

	let raw_params_generator = |min_fee_msat: u64, proportional: u32| LSPS2RawOpeningFeeParams {
		min_fee_msat,
		proportional,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1,
		max_payment_size_msat: 100_000_000,
	};

	let raw_params = vec![
		raw_params_generator(200, 20), // Will be sorted to position 2
		raw_params_generator(100, 10), // Will be sorted to position 0 (lowest min_fee, lowest proportional)
		raw_params_generator(300, 30), // Will be sorted to position 4 (highest min_fee, highest proportional)
		raw_params_generator(100, 20), // Will be sorted to position 1 (same min_fee as 0, higher proportional)
		raw_params_generator(200, 30), // Will be sorted to position 3 (higher min_fee than 2, higher proportional)
	];

	service_handler
		.opening_fee_params_generated(&client_node_id, request_id.clone(), raw_params)
		.unwrap();

	let get_info_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
		opening_fee_params_menu,
		..
	}) = event
	{
		// The LSP, when ordering the opening_fee_params_menu array, MUST order by the following rules:
		// The 0th item MAY have any parameters.
		// Each succeeding item MUST, compared to the previous item, obey any one of the following:
		// Have a larger min_fee_msat, and equal proportional.
		// Have a larger proportional, and equal min_fee_msat.
		// Have a larger min_fee_msat, AND larger proportional.
		for (cur, next) in
			opening_fee_params_menu.iter().zip(opening_fee_params_menu.iter().skip(1))
		{
			let valid = (next.min_fee_msat > cur.min_fee_msat
				&& next.proportional == cur.proportional)
				|| (next.proportional > cur.proportional && next.min_fee_msat == cur.min_fee_msat)
				|| (next.min_fee_msat > cur.min_fee_msat && next.proportional > cur.proportional);
			assert!(valid, "Params not sorted as per spec");
		}
	} else {
		panic!("Unexpected event");
	}
}

#[test]
fn lsps2_service_handler_persistence_across_restarts() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create shared KV store for service node that will persist across restarts
	let service_kv_store = Arc::new(TestStore::new(false));
	let client_kv_store = Arc::new(TestStore::new(false));

	let promise_secret = [42; 32];
	let service_config = LiquidityServiceConfig {
		lsps1_service_config: None,
		lsps2_service_config: Some(LSPS2ServiceConfig { promise_secret }),
		lsps5_service_config: None,
		advertise_service: true,
	};
	let time_provider: Arc<dyn TimeProvider + Send + Sync> = Arc::new(DefaultTimeProvider);

	// Variables to carry state between scopes
	let user_channel_id = 42;
	let cltv_expiry_delta = 144;
	let intercept_scid;
	let client_node_id;

	// First scope: Setup, persistence, and dropping of all node objects
	{
		// Use the helper function with custom KV stores
		let (lsps_nodes, _) = setup_test_lsps2_nodes_with_kv_stores(
			nodes,
			Arc::clone(&service_kv_store),
			client_kv_store,
		);
		let LSPSNodes { service_node, client_node } = lsps_nodes;

		let service_node_id = service_node.inner.node.get_our_node_id();
		client_node_id = client_node.inner.node.get_our_node_id();

		let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
		let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

		// Set up a JIT channel request to create state that needs persistence
		let _get_info_request_id = client_handler.request_opening_params(service_node_id, None);
		let get_info_request = get_lsps_message!(client_node, service_node_id);
		service_node
			.liquidity_manager
			.handle_custom_message(get_info_request, client_node_id)
			.unwrap();

		let get_info_event = service_node.liquidity_manager.next_event().unwrap();
		let request_id = match get_info_event {
			LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { request_id, .. }) => {
				request_id
			},
			_ => panic!("Unexpected event"),
		};

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
				request_id.clone(),
				vec![raw_opening_params],
			)
			.unwrap();

		let get_info_response = get_lsps_message!(service_node, client_node_id);
		client_node
			.liquidity_manager
			.handle_custom_message(get_info_response, service_node_id)
			.unwrap();

		let opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
			LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
				opening_fee_params_menu,
				..
			}) => opening_fee_params_menu.first().unwrap().clone(),
			_ => panic!("Unexpected event"),
		};

		// Client makes a buy request
		let payment_size_msat = Some(1_000_000);
		let buy_request_id = client_handler
			.select_opening_params(service_node_id, payment_size_msat, opening_fee_params.clone())
			.unwrap();

		let buy_request = get_lsps_message!(client_node, service_node_id);
		service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id).unwrap();

		let buy_event = service_node.liquidity_manager.next_event().unwrap();
		if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::BuyRequest { request_id, .. }) =
			buy_event
		{
			assert_eq!(request_id, buy_request_id);
		} else {
			panic!("Unexpected event");
		}

		// Service responds with invoice parameters, creating persistent channel state
		intercept_scid = service_node.node.get_intercept_scid();
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

		let _invoice_params_event = client_node.liquidity_manager.next_event().unwrap();

		// Trigger persistence by calling persist
		service_node.liquidity_manager.persist().unwrap();

		// All node objects are dropped at the end of this scope
	}

	// Second scope: Recovery from persisted store and verification
	{
		// Create fresh node configurations for restart to avoid connection conflicts
		let node_chanmgrs_restart = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes_restart = create_network(2, &node_cfgs, &node_chanmgrs_restart);

		// Create a new LiquidityManager with the same configuration and KV store to simulate restart
		let transaction_broadcaster = Arc::new(TestBroadcaster::new(Network::Testnet));

		let restarted_service_lm = LiquidityManagerSync::new_with_custom_time_provider(
			nodes_restart[0].keys_manager,
			nodes_restart[0].keys_manager,
			nodes_restart[0].node,
			service_kv_store,
			transaction_broadcaster,
			Some(service_config),
			None,
			time_provider,
		)
		.unwrap();

		let restarted_service_handler = restarted_service_lm.lsps2_service_handler().unwrap();

		// Verify the state was properly restored by checking if the channel exists
		// We can do this by trying to call htlc_intercepted which should succeed if state was restored
		let htlc_amount_msat = 1_000_000;
		let intercept_id = InterceptId([0; 32]);
		let payment_hash = PaymentHash([1; 32]);

		let result = restarted_service_handler.htlc_intercepted(
			intercept_scid,
			intercept_id,
			htlc_amount_msat,
			payment_hash,
			htlc_amount_msat,
		);

		// This should succeed if the channel state was properly restored
		assert!(result.is_ok(), "HTLC interception should succeed with restored state");

		// Check that we get an OpenChannel event, confirming the state was restored correctly
		let event = restarted_service_lm.next_event();
		assert!(event.is_some(), "Should have an event after HTLC interception");

		if let Some(LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			user_channel_id: restored_channel_id,
			intercept_scid: restored_scid,
			max_client_to_self_delay: restored_max_client_to_self_delay,
			..
		})) = event
		{
			assert_eq!(restored_channel_id, user_channel_id);
			assert_eq!(restored_scid, intercept_scid);
			// The negotiated limit survives the restart via the persisted JIT channel state.
			assert_eq!(restored_max_client_to_self_delay, Some(128));
		} else {
			panic!("Expected OpenChannel event after restart");
		}
	}
}

#[test]
fn client_trusts_lsp_end_to_end_test() {
	// There are 3 nodes. Payer, service and client.
	// client_trusts_lsp=true, that means that funding transaction broadcast will need to happen manually
	// after the client claims the HTLC.
	//
	// 1. Create a channel between payer and service
	// 2. Do the LSPS2 ceremony between client and service, to prepare the service to intercept an htlc and eventually create a JIT channel
	// 3. Make the client create a JIT invoice and make the payer pay it
	// 4. Assert that the service intercepts the HTLC
	// 5. Assert that the service emits a LiquidityEvent::OpenChannel. This means that the intercepted HTLC was enough
	// and that it's ready to proceed with channel creation.
	// 6. Proceed with the JIT channel creation (we create it with funding_transaction_generated_manual_broadcast because
	// client_trusts_lsp=true).
	// 7. Call the service's channel_ready function
	// 8. The service will now forward the intercepted HTLC to the client on the new JIT channel
	// 9. The client will see the PaymentClaimable event
	// 10. Assert that the service has not broadcasted the funding transaction yet, because the client has not claimed the HTLC yet
	// 11. Make the client claim the HTLC
	// 12. Assert that the service has broadcasted the funding tx
	// 13. Assert that the payer received the PaymentSent event
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_config.accept_underpaying_htlcs = true;
	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(service_node_config), Some(client_node_config), None],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2000000, 100000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 42;
	let cltv_expiry_delta: u32 = 144;
	let payment_size_msat = Some(1_000_000);

	let fee_base_msat = 1000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"asdf",
		3600,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (payment_hash, expected_outbound_amount_msat) = match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash,
			expected_outbound_amount_msat,
			inbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);

			service_handler
				.htlc_intercepted(
					*requested_next_hop_scid,
					*intercept_id,
					*expected_outbound_amount_msat,
					*payment_hash,
					*inbound_amount_msat,
				)
				.unwrap();
			(*payment_hash, expected_outbound_amount_msat)
		},
		other => panic!("Expected HTLCIntercepted event, got: {:?}", other),
	};

	let open_channel_event = service_node.liquidity_manager.next_event().unwrap();

	match open_channel_event {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			their_network_key,
			amt_to_forward_msat,
			opening_fee_msat,
			user_channel_id,
			intercept_scid: iscd,
			max_client_to_self_delay,
		}) => {
			assert_eq!(their_network_key, client_node_id);
			assert_eq!(amt_to_forward_msat, payment_size_msat.unwrap() - fee_base_msat);
			assert_eq!(opening_fee_msat, fee_base_msat);
			assert_eq!(user_channel_id, 42);
			assert_eq!(iscd, intercept_scid);
			assert_eq!(max_client_to_self_delay, Some(128));
		},
		other => panic!("Expected OpenChannel event, got: {:?}", other),
	};

	let result =
		service_handler.channel_needs_manual_broadcast(user_channel_id, &client_node_id).unwrap();
	assert!(result, "Channel should require manual broadcast");

	let (channel_id, funding_tx) = create_channel_with_manual_broadcast(
		&service_node_id,
		&client_node_id,
		&service_node,
		&client_node,
		user_channel_id,
		expected_outbound_amount_msat,
		true,
	);

	service_handler.channel_ready(user_channel_id, &channel_id, &client_node_id).unwrap();

	service_node.inner.node.process_pending_htlc_forwards();

	let pay_event = {
		{
			let mut added_monitors =
				service_node.inner.chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}
		let mut events = service_node.inner.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	let preimage = match &client_events[0] {
		Event::PaymentClaimable { payment_hash: ph, purpose, .. } => {
			assert_eq!(*ph, payment_hash);
			purpose.preimage()
		},
		other => panic!("Expected PaymentClaimable event on client, got: {:?}", other),
	};

	// Check that before the client claims, the service node has not broadcasted anything
	let broadcasted = service_node.inner.tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert!(broadcasted.is_empty(), "There should be no broadcasted txs yet");
	drop(broadcasted);

	client_node.inner.node.claim_funds(preimage.unwrap());

	claim_and_assert_forwarded_only(
		&payer_node,
		&service_node.inner,
		&client_node.inner,
		preimage.unwrap(),
	);

	let service_events = service_node.node.get_and_clear_pending_events();
	assert_eq!(service_events.len(), 1);

	let total_fee_msat = match service_events[0].clone() {
		Event::PaymentForwarded {
			ref prev_htlcs,
			ref next_htlcs,
			skimmed_fee_msat,
			total_fee_earned_msat,
			..
		} => {
			assert_eq!(prev_htlcs[0].node_id, Some(payer_node_id));
			assert_eq!(next_htlcs[0].node_id, Some(client_node_id));
			service_handler.payment_forwarded(channel_id, skimmed_fee_msat.unwrap_or(0)).unwrap();
			Some(total_fee_earned_msat.unwrap() - skimmed_fee_msat.unwrap())
		},
		_ => panic!("Expected PaymentForwarded event, got: {:?}", service_events[0]),
	};

	let broadcasted = service_node.inner.tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert!(broadcasted.iter().any(|b| b.compute_txid() == funding_tx.compute_txid()));

	expect_payment_sent(&payer_node, preimage.unwrap(), Some(total_fee_msat), true, true);
}

// Checks that the negotiated `max_client_to_self_delay` carried by the `OpenChannel` event is
// enforced when applied to `create_channel`'s handshake limits: a client `accept_channel` delay
// above the negotiated maximum is rejected even when below the operator's global limit, a
// compliant delay is accepted, and a stricter operator limit still wins.
fn assert_negotiated_delay_limit_enforced(
	client_our_to_self_delay: u16, operator_their_to_self_delay: Option<u16>,
	expect_channel_open: bool,
) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_handshake_config.our_to_self_delay = client_our_to_self_delay;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(client_node_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { ref service_node, ref client_node } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 42u128;
	let payment_size_msat = Some(1_000_000);
	let fee_base_msat: u64 = 1_000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		144,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		200,
	);

	service_handler
		.htlc_intercepted(
			intercept_scid,
			InterceptId([0; 32]),
			payment_size_msat.unwrap(),
			PaymentHash([1; 32]),
			payment_size_msat.unwrap(),
		)
		.unwrap();

	let negotiated_limit = match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			max_client_to_self_delay,
			..
		}) => max_client_to_self_delay,
		other => panic!("Expected OpenChannel event, got: {:?}", other),
	};
	assert_eq!(negotiated_limit, Some(200));

	let mut override_config = test_default_channel_config();
	if let Some(operator_limit) = operator_their_to_self_delay {
		override_config.channel_handshake_limits.their_to_self_delay = operator_limit;
	}
	// Both limits are u16 while the negotiated offer is u32, so take the minimum in u32
	// arithmetic and convert back, rather than truncating either value.
	if let Some(negotiated) = negotiated_limit {
		let operator_limit = override_config.channel_handshake_limits.their_to_self_delay as u32;
		override_config.channel_handshake_limits.their_to_self_delay =
			u16::try_from(u32::min(operator_limit, negotiated)).unwrap();
	}

	service_node
		.node
		.create_channel(
			client_node_id,
			payment_size_msat.unwrap(),
			0,
			user_channel_id,
			None,
			Some(override_config),
		)
		.unwrap();
	let open_channel =
		get_event_msg!(service_node, MessageSendEvent::SendOpenChannel, client_node_id);
	client_node.node.handle_open_channel(service_node_id, &open_channel);

	let events = client_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let temporary_channel_id = match &events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => *temporary_channel_id,
		other => panic!("Unexpected event: {:?}", other),
	};
	client_node
		.node
		.accept_inbound_channel(&temporary_channel_id, &service_node_id, user_channel_id, None)
		.unwrap_or_else(|e| panic!("accept_inbound_channel failed: {:?}", e));

	let accept_channel =
		get_event_msg!(client_node, MessageSendEvent::SendAcceptChannel, service_node_id);
	service_node.node.handle_accept_channel(client_node_id, &accept_channel);

	let service_events = service_node.node.get_and_clear_pending_events();
	if expect_channel_open {
		assert!(
			!service_events.iter().any(|e| matches!(e, Event::ChannelClosed { .. })),
			"channel should have opened, got {:?}",
			service_events
		);
	} else {
		let msg_events = service_node.node.get_and_clear_pending_msg_events();
		assert!(
			msg_events.iter().all(|e| !matches!(e, MessageSendEvent::SendFundingCreated { .. })),
			"no funding should have been created, got {:?}",
			msg_events
		);
		assert_eq!(
			service_events.iter().filter(|e| matches!(e, Event::ChannelClosed { .. })).count(),
			1,
			"channel should have been rejected, got {:?}",
			service_events
		);
	}
}

#[test]
fn open_channel_event_delay_limit_rejects_delay_above_negotiated_maximum() {
	// 1000 is below the default global limit of 2016 but above the negotiated maximum of 200.
	assert_negotiated_delay_limit_enforced(1000, None, false);
}

#[test]
fn open_channel_event_delay_limit_accepts_compliant_delay() {
	assert_negotiated_delay_limit_enforced(150, None, true);
}

#[test]
fn open_channel_event_delay_limit_preserves_stricter_operator_limit() {
	// The operator's own limit of 32 is stricter than the negotiated maximum of 200 and must
	// not be loosened by the offer.
	assert_negotiated_delay_limit_enforced(150, Some(32), false);
}

fn execute_lsps2_dance(
	service_node: &LiquidityNode, client_node: &LiquidityNode, intercept_scid: u64,
	user_channel_id: u128, cltv_expiry_delta: u32, promise_secret: [u8; 32],
	payment_size_msat: Option<u64>, fee_base_msat: u64, max_client_to_self_delay: u32,
) {
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo {
		request_id,
		counterparty_node_id,
		token,
	}) = get_info_event
	{
		assert_eq!(request_id, get_info_request_id);
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(token, None);
	} else {
		panic!("Unexpected event");
	}

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: fee_base_msat,
		proportional: 0,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay,
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
			assert!(is_valid_opening_fee_params(
				&opening_fee_params,
				&promise_secret,
				&client_node_id
			));
			opening_fee_params
		},
		_ => panic!("Unexpected event"),
	};

	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params.clone())
		.unwrap();

	let buy_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id).unwrap();

	let buy_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::BuyRequest {
		request_id,
		counterparty_node_id,
		opening_fee_params: ofp,
		payment_size_msat: psm,
	}) = buy_event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(opening_fee_params, ofp);
		assert_eq!(payment_size_msat, psm);
	} else {
		panic!("Unexpected event");
	}

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
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::InvoiceParametersReady {
		request_id,
		counterparty_node_id,
		intercept_scid: iscid,
		cltv_expiry_delta: ced,
		payment_size_msat: psm,
	}) = invoice_params_event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(intercept_scid, iscid);
		assert_eq!(cltv_expiry_delta, ced);
		assert_eq!(payment_size_msat, psm);
	} else {
		panic!("Unexpected event");
	}
}

fn create_channel_with_manual_broadcast(
	service_node_id: &PublicKey, client_node_id: &PublicKey, service_node: &LiquidityNode,
	client_node: &LiquidityNode, user_channel_id: u128, expected_outbound_amount_msat: &u64,
	mark_broadcast_safe: bool,
) -> (ChannelId, bitcoin::Transaction) {
	assert!(service_node
		.node
		.create_channel(
			*client_node_id,
			*expected_outbound_amount_msat,
			0,
			user_channel_id,
			None,
			None
		)
		.is_ok());
	let open_channel =
		get_event_msg!(service_node, MessageSendEvent::SendOpenChannel, *client_node_id);

	client_node.node.handle_open_channel(*service_node_id, &open_channel);

	let events = client_node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			client_node
				.node
				.accept_inbound_channel_from_trusted_peer(
					&temporary_channel_id,
					&service_node_id,
					user_channel_id,
					TrustedChannelFeatures::ZeroConf,
					None,
				)
				.unwrap();
		},
		_ => panic!("Unexpected event"),
	};

	let accept_channel =
		get_event_msg!(client_node, MessageSendEvent::SendAcceptChannel, *service_node_id);
	assert_eq!(accept_channel.common_fields.minimum_depth, 0);

	service_node.node.handle_accept_channel(*client_node_id, &accept_channel);
	let (temp_channel_id, funding_tx, funding_outpoint) = create_funding_transaction(
		&service_node,
		&client_node_id,
		*expected_outbound_amount_msat,
		user_channel_id,
	);
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	service_handler
		.store_funding_transaction(user_channel_id, &client_node_id, funding_tx.clone())
		.unwrap();
	service_node
		.node
		.funding_transaction_generated_manual_broadcast(
			temp_channel_id,
			*client_node_id,
			funding_tx.clone(),
		)
		.unwrap();

	let funding_created =
		get_event_msg!(service_node, MessageSendEvent::SendFundingCreated, *client_node_id);
	client_node.node.handle_funding_created(*service_node_id, &funding_created);
	check_added_monitors(&client_node.inner, 1);

	let bs_signed_locked = client_node.node.get_and_clear_pending_msg_events();
	assert_eq!(bs_signed_locked.len(), 2);

	let as_channel_ready;
	match &bs_signed_locked[0] {
		MessageSendEvent::SendFundingSigned { node_id, msg } => {
			assert_eq!(*node_id, *service_node_id);
			service_node.node.handle_funding_signed(*client_node_id, &msg);
			let events = &service_node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 2);
			match &events[0] {
				Event::FundingTxBroadcastSafe {
					funding_txo,
					user_channel_id,
					counterparty_node_id,
					..
				} => {
					assert_eq!(funding_txo.txid, funding_outpoint.txid);
					assert_eq!(funding_txo.vout, funding_outpoint.index as u32);
					if mark_broadcast_safe {
						service_handler
							.set_funding_tx_broadcast_safe(*user_channel_id, counterparty_node_id)
							.unwrap();
					}
				},
				_ => panic!("Unexpected event"),
			};
			match &events[1] {
				Event::ChannelPending { counterparty_node_id, .. } => {
					assert_eq!(counterparty_node_id, client_node_id);
				},
				_ => panic!("Unexpected event"),
			}
			expect_channel_pending_event(&client_node, &service_node_id);
			check_added_monitors(&service_node.inner, 1);

			as_channel_ready =
				get_event_msg!(service_node, MessageSendEvent::SendChannelReady, *client_node_id);
		},
		_ => panic!("Unexpected event"),
	}

	match &bs_signed_locked[1] {
		MessageSendEvent::SendChannelReady { node_id, msg } => {
			assert_eq!(*node_id, *service_node_id);
			service_node.node.handle_channel_ready(*client_node_id, &msg);
			expect_channel_ready_event(&service_node, &client_node_id);
		},
		_ => panic!("Unexpected event"),
	}

	client_node.node.handle_channel_ready(*service_node_id, &as_channel_ready);
	expect_channel_ready_event(&client_node, &service_node_id);

	let as_channel_update =
		get_event_msg!(service_node, MessageSendEvent::SendChannelUpdate, *client_node_id);
	let bs_channel_update =
		get_event_msg!(client_node, MessageSendEvent::SendChannelUpdate, *service_node_id);

	service_node.node.handle_channel_update(*client_node_id, &bs_channel_update);
	client_node.node.handle_channel_update(*service_node_id, &as_channel_update);

	(as_channel_ready.channel_id, funding_tx)
}

#[test]
fn late_payment_forwarded_and_safe_after_force_close_does_not_broadcast() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_config.accept_underpaying_htlcs = true;

	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(service_node_config), Some(client_node_config), None],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 43u128;
	let cltv_expiry_delta: u32 = 144;
	let payment_size_msat = Some(1_000_000);
	let fee_base_msat: u64 = 10_000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"late-safe",
		3600,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash: _,
			expected_outbound_amount_msat,
			inbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);
			service_handler
				.htlc_intercepted(
					*requested_next_hop_scid,
					*intercept_id,
					*expected_outbound_amount_msat,
					invoice.payment_hash(),
					*inbound_amount_msat,
				)
				.unwrap();
		},
		other => panic!("Expected HTLCIntercepted, got {:?}", other),
	}

	// Create channel but DO NOT mark broadcast safe yet
	let (channel_id, funding_tx) = create_channel_with_manual_broadcast(
		&service_node_id,
		&client_node_id,
		&service_node,
		&client_node,
		user_channel_id,
		&(payment_size_msat.unwrap() - fee_base_msat),
		false,
	);

	service_handler.channel_ready(user_channel_id, &channel_id, &client_node_id).unwrap();
	service_node.inner.node.process_pending_htlc_forwards();

	// Run forward to client and let client claim. do not notify service handler yet.
	let pay_event = {
		{
			let mut added_monitors =
				service_node.inner.chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}
		let mut msg_events = service_node.inner.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		SendEvent::from_event(msg_events.remove(0))
	};

	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	let preimage = match &client_events[0] {
		Event::PaymentClaimable { purpose, .. } => purpose.preimage().unwrap(),
		other => panic!("Expected PaymentClaimable, got {:?}", other),
	};

	client_node.inner.node.claim_funds(preimage);
	claim_and_assert_forwarded_only(&payer_node, &service_node.inner, &client_node.inner, preimage);

	// Service now has PaymentForwarded. Record in JIT state but still not safe to broadcast.
	let events = service_node.node.get_and_clear_pending_events();
	let skimmed = match events[0].clone() {
		Event::PaymentForwarded { skimmed_fee_msat, .. } => skimmed_fee_msat.unwrap_or(0),
		other => panic!("Expected PaymentForwarded, got {:?}", other),
	};
	service_handler.payment_forwarded(channel_id, skimmed).unwrap();

	// Force-close the service->client channel
	service_node
		.inner
		.node
		.force_close_broadcasting_latest_txn(&channel_id, &client_node_id, "test fc".to_string())
		.unwrap();

	service_node.inner.node.get_and_clear_pending_msg_events();
	client_node.inner.node.get_and_clear_pending_msg_events();
	payer_node.node.get_and_clear_pending_msg_events();
	service_node.inner.node.get_and_clear_pending_events();
	client_node.inner.node.get_and_clear_pending_events();
	payer_node.node.get_and_clear_pending_events();
	service_node.inner.chain_monitor.added_monitors.lock().unwrap().clear();
	client_node.inner.chain_monitor.added_monitors.lock().unwrap().clear();
	payer_node.chain_monitor.added_monitors.lock().unwrap().clear();

	// Simulate late FundingTxBroadcastSafe arrival after close. ensure no broadcast of funding tx.
	service_handler.set_funding_tx_broadcast_safe(user_channel_id, &client_node_id).unwrap();
	{
		let broadcasted = service_node.inner.tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert!(
			broadcasted.iter().all(|tx| tx.compute_txid() != funding_tx.compute_txid()),
			"Funding tx must not be broadcast after close"
		);
	}

	// Also simulate re-storing the funding tx late. still must not broadcast.
	service_handler
		.store_funding_transaction(user_channel_id, &client_node_id, funding_tx.clone())
		.unwrap();
	{
		let broadcasted = service_node.inner.tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert!(
			broadcasted.iter().all(|tx| tx.compute_txid() != funding_tx.compute_txid()),
			"Funding tx must not be broadcast after close (late store)"
		);
	}
}

#[test]
fn htlc_timeout_before_client_claim_results_in_handling_failed() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_config.accept_underpaying_htlcs = true;

	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(service_node_config), Some(client_node_config), None],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 44u128;
	let cltv_expiry_delta: u32 = 144;
	let payment_size_msat = Some(1_000_000);
	let fee_base_msat: u64 = 10_000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"timeout-before-claim",
		3600,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash: _,
			expected_outbound_amount_msat,
			inbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);
			service_handler
				.htlc_intercepted(
					*requested_next_hop_scid,
					*intercept_id,
					*expected_outbound_amount_msat,
					invoice.payment_hash(),
					*inbound_amount_msat,
				)
				.unwrap();
		},
		other => panic!("Expected HTLCIntercepted, got {:?}", other),
	}

	// Create and mark broadcast safe so the channel is fully ready
	let expected_outbound_amount_msat = payment_size_msat.unwrap() - fee_base_msat;
	let (channel_id, _funding_tx) = create_channel_with_manual_broadcast(
		&service_node_id,
		&client_node_id,
		&service_node,
		&client_node,
		user_channel_id,
		&expected_outbound_amount_msat,
		true,
	);

	service_handler.channel_ready(user_channel_id, &channel_id, &client_node_id).unwrap();
	service_node.inner.node.process_pending_htlc_forwards();

	// Forward to client, but do not claim yet
	let pay_event = {
		{
			let mut added_monitors =
				service_node.inner.chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}
		let mut msg_events = service_node.inner.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		SendEvent::from_event(msg_events.remove(0))
	};

	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	let preimage = match &client_events[0] {
		Event::PaymentClaimable { purpose, .. } => purpose.preimage().unwrap(),
		other => panic!("Expected PaymentClaimable, got {:?}", other),
	};

	// Advance blocks past CLTV expiry before the client attempts to claim
	const SOME_EXTRA_BLOCKS: u32 = 3;
	let client_htlc_cltv_expiry = pay_event.msgs[0].cltv_expiry;
	let target_height = client_htlc_cltv_expiry.saturating_add(SOME_EXTRA_BLOCKS);
	let cur_height = service_node.inner.best_block_info().1;
	let d = target_height - cur_height;
	connect_blocks(&service_node.inner, d);
	connect_blocks(&client_node.inner, d);
	connect_blocks(&payer_node, d);

	service_node.inner.node.process_pending_htlc_forwards();
	client_node.inner.node.process_pending_htlc_forwards();

	// Service->client channel should close due to HTLC timeout
	let svc_events = service_node.inner.node.get_and_clear_pending_events();
	let closed_on_service = svc_events.iter().any(|ev| {
		matches!(ev, Event::ChannelClosed { reason: ClosureReason::HTLCsTimedOut { .. }, .. })
	});
	assert!(closed_on_service, "Expected service->client channel to close due to HTLC timeout");

	// Client tries to claim but should fail since HTLC timed out
	client_node.inner.node.claim_funds(preimage);
	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	match &client_events[0] {
		Event::HTLCHandlingFailed { failure_type, .. } => match failure_type {
			lightning::events::HTLCHandlingFailureType::Receive { payment_hash } => {
				assert_eq!(*payment_hash, invoice.payment_hash());
			},
			_ => panic!("Unexpected failure_type: {:?}", failure_type),
		},
		other => panic!("Expected HTLCHandlingFailed after timeout, got {:?}", other),
	}

	// Payer->service channel should remain open
	{
		let chans = service_node.inner.node.list_channels();
		assert!(chans
			.iter()
			.any(|cd| cd.counterparty.node_id == payer_node_id && cd.is_channel_ready));
	}

	service_node.inner.node.get_and_clear_pending_msg_events();
	client_node.inner.node.get_and_clear_pending_msg_events();
	payer_node.node.get_and_clear_pending_msg_events();
	service_node.inner.chain_monitor.added_monitors.lock().unwrap().clear();
	client_node.inner.chain_monitor.added_monitors.lock().unwrap().clear();
	payer_node.chain_monitor.added_monitors.lock().unwrap().clear();
}

fn claim_and_assert_forwarded_only<'a, 'b, 'c>(
	payer_node: &lightning::ln::functional_test_utils::Node<'a, 'b, 'c>,
	service_node: &lightning::ln::functional_test_utils::Node<'a, 'b, 'c>,
	client_node: &lightning::ln::functional_test_utils::Node<'a, 'b, 'c>,
	preimage: PaymentPreimage,
) {
	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.node.get_our_node_id();
	let client_node_id = client_node.node.get_our_node_id();

	let client_events = client_node.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	match &client_events[0] {
		Event::PaymentClaimed { purpose, .. } => {
			assert_eq!(purpose.preimage().unwrap(), preimage);
		},
		other => panic!("Expected PaymentClaimed, got {:?}", other),
	}

	let mut client_msg_events = client_node.node.get_and_clear_pending_msg_events();
	assert_eq!(client_msg_events.len(), 1);
	let (fulfill_msg, client_commitment_signed) = match client_msg_events.remove(0) {
		MessageSendEvent::UpdateHTLCs { node_id, updates, .. } => {
			assert_eq!(node_id, service_node_id);
			assert_eq!(updates.update_fulfill_htlcs.len(), 1);
			(updates.update_fulfill_htlcs[0].clone(), updates.commitment_signed.clone())
		},
		other => panic!("Unexpected client msg event: {:?}", other),
	};

	service_node.node.handle_update_fulfill_htlc(client_node_id, fulfill_msg);
	service_node
		.node
		.handle_commitment_signed_batch_test(client_node_id, &client_commitment_signed);
	service_node.chain_monitor.added_monitors.lock().unwrap().clear();

	let service_msg_events = service_node.node.get_and_clear_pending_msg_events();
	assert!(
		service_msg_events.len() >= 2 && service_msg_events.len() <= 3,
		"Unexpected service msg events len = {}",
		service_msg_events.len()
	);

	let mut revoke_and_ack_to_client = None;
	let mut upstream_updates = None;
	let mut client_commitment_update = None;

	for ev in service_msg_events {
		match ev {
			MessageSendEvent::SendRevokeAndACK { node_id, msg } => {
				assert_eq!(node_id, client_node_id);
				revoke_and_ack_to_client = Some(msg);
			},
			MessageSendEvent::UpdateHTLCs { node_id, updates, .. } => {
				if node_id == payer_node_id {
					assert_eq!(updates.update_fulfill_htlcs.len(), 1, "Expected upstream fulfill");
					upstream_updates = Some(updates);
				} else if node_id == client_node_id {
					assert!(updates.update_fulfill_htlcs.is_empty());
					client_commitment_update = Some(updates);
				} else {
					panic!("Unexpected UpdateHTLCs destination");
				}
			},
			other => panic!("Unexpected service msg event: {:?}", other),
		}
	}

	let revoke_and_ack_to_client =
		revoke_and_ack_to_client.expect("Missing RevokeAndACK to client");
	let upstream_updates = upstream_updates.expect("Missing upstream fulfill updates");

	client_node.node.handle_revoke_and_ack(service_node_id, &revoke_and_ack_to_client);
	client_node.chain_monitor.added_monitors.lock().unwrap().clear();

	if let Some(cu) = client_commitment_update {
		client_node
			.node
			.handle_commitment_signed_batch_test(service_node_id, &cu.commitment_signed);
		client_node.chain_monitor.added_monitors.lock().unwrap().clear();

		let raa_back =
			get_event_msg!(client_node, MessageSendEvent::SendRevokeAndACK, service_node_id);
		service_node.node.handle_revoke_and_ack(client_node_id, &raa_back);
		service_node.chain_monitor.added_monitors.lock().unwrap().clear();
	}

	payer_node.node.handle_update_fulfill_htlc(
		service_node_id,
		upstream_updates.update_fulfill_htlcs[0].clone(),
	);
	payer_node
		.node
		.handle_commitment_signed_batch_test(service_node_id, &upstream_updates.commitment_signed);
	payer_node.chain_monitor.added_monitors.lock().unwrap().clear();

	let payer_msg_events = payer_node.node.get_and_clear_pending_msg_events();

	for ev in payer_msg_events {
		match ev {
			MessageSendEvent::SendRevokeAndACK { node_id, msg } => {
				assert_eq!(node_id, service_node_id);
				service_node.node.handle_revoke_and_ack(payer_node_id, &msg);
				service_node.chain_monitor.added_monitors.lock().unwrap().clear();
			},
			MessageSendEvent::UpdateHTLCs { updates, .. } => {
				service_node
					.node
					.handle_commitment_signed_batch_test(payer_node_id, &updates.commitment_signed);
				service_node.chain_monitor.added_monitors.lock().unwrap().clear();
				let mut svc_resp = service_node.node.get_and_clear_pending_msg_events();
				for resp in svc_resp.drain(..) {
					match resp {
						MessageSendEvent::SendRevokeAndACK { msg, .. } => {
							payer_node.node.handle_revoke_and_ack(service_node_id, &msg);
							payer_node.chain_monitor.added_monitors.lock().unwrap().clear();
						},
						MessageSendEvent::UpdateHTLCs { updates, .. } => {
							payer_node.node.handle_commitment_signed_batch_test(
								service_node_id,
								&updates.commitment_signed,
							);
							payer_node.chain_monitor.added_monitors.lock().unwrap().clear();
							let maybe_final = payer_node.node.get_and_clear_pending_msg_events();
							for final_ev in maybe_final {
								if let MessageSendEvent::SendRevokeAndACK { msg, .. } = final_ev {
									service_node.node.handle_revoke_and_ack(payer_node_id, &msg);
									service_node
										.chain_monitor
										.added_monitors
										.lock()
										.unwrap()
										.clear();
								}
							}
						},
						_ => {},
					}
				}
			},
			other => panic!("Unexpected payer msg event: {:?}", other),
		}
	}
}

#[test]
fn client_trusts_lsp_partial_fee_does_not_trigger_broadcast() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_config.accept_underpaying_htlcs = true;

	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(service_node_config), Some(client_node_config), None],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 42;
	let cltv_expiry_delta: u32 = 144;
	let payment_size_msat = Some(1_000_000);

	let fee_base_msat: u64 = 10_000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"test partial fee",
		3600,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (payment_hash, expected_outbound_amount_msat) = match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash,
			expected_outbound_amount_msat,
			inbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);
			service_handler
				.htlc_intercepted(
					*requested_next_hop_scid,
					*intercept_id,
					*expected_outbound_amount_msat,
					*payment_hash,
					*inbound_amount_msat,
				)
				.unwrap();
			(*payment_hash, expected_outbound_amount_msat)
		},
		other => panic!("Expected HTLCIntercepted, got {:?}", other),
	};

	match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			their_network_key,
			amt_to_forward_msat,
			opening_fee_msat,
			user_channel_id: u,
			intercept_scid: sc,
			max_client_to_self_delay,
		}) => {
			assert_eq!(their_network_key, client_node_id);
			assert_eq!(u, user_channel_id);
			assert_eq!(sc, intercept_scid);
			assert_eq!(opening_fee_msat, fee_base_msat);
			assert_eq!(amt_to_forward_msat, payment_size_msat.unwrap() - fee_base_msat);
			assert_eq!(max_client_to_self_delay, Some(128));
		},
		other => panic!("Unexpected event: {:?}", other),
	};

	assert!(service_handler
		.channel_needs_manual_broadcast(user_channel_id, &client_node_id)
		.unwrap());

	let (channel_id, _) = create_channel_with_manual_broadcast(
		&service_node_id,
		&client_node_id,
		&service_node,
		&client_node,
		user_channel_id,
		expected_outbound_amount_msat,
		true,
	);

	service_handler.channel_ready(user_channel_id, &channel_id, &client_node_id).unwrap();

	service_node.inner.node.process_pending_htlc_forwards();

	let pay_event = {
		{
			let mut added_monitors =
				service_node.inner.chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}
		let mut msg_events = service_node.inner.node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		SendEvent::from_event(msg_events.remove(0))
	};

	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	match &client_events[0] {
		Event::PaymentClaimable { payment_hash: ph, .. } => assert_eq!(*ph, payment_hash),
		other => panic!("Expected PaymentClaimable, got {:?}", other),
	};

	assert!(service_node.liquidity_manager.get_and_clear_pending_events().is_empty());

	let partial_skim_msat = fee_base_msat - 1; // less than promised fee
	service_handler.payment_forwarded(channel_id, partial_skim_msat).unwrap();

	let broadcasted = service_node.inner.tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert!(broadcasted.is_empty(), "There should be no broadcasted txs yet");
	drop(broadcasted);

	// before mining blocks, service node should have 2 channels
	{
		let chans = service_node.inner.node.list_channels();
		assert_eq!(chans.len(), 2);
		assert!(chans.iter().any(|cd| cd.counterparty.node_id == payer_node_id));
		assert!(chans.iter().any(|cd| cd.counterparty.node_id == client_node_id));
	}

	const SOME_EXTRA_BLOCKS: u32 = 3;
	let client_htlc_cltv_expiry = pay_event.msgs[0].cltv_expiry;
	let target_height = client_htlc_cltv_expiry.saturating_add(SOME_EXTRA_BLOCKS);
	let cur_height = service_node.inner.best_block_info().1;
	let d = target_height - cur_height;
	connect_blocks(&service_node.inner, d);
	connect_blocks(&client_node.inner, d);
	connect_blocks(&payer_node, d);

	service_node.inner.node.process_pending_htlc_forwards();
	client_node.inner.node.process_pending_htlc_forwards();

	let svc_events = service_node.inner.node.get_and_clear_pending_events();
	let _ = client_node.inner.node.get_and_clear_pending_events();
	let closed_on_service = svc_events.iter().any(|ev| {
		matches!(ev, Event::ChannelClosed { reason: ClosureReason::HTLCsTimedOut { .. }, .. })
	});
	assert!(
		closed_on_service,
		"Expected service->client channel to be force-closed due to HTLC timeout. svc_events = {:?}",
		svc_events
	);

	// now check the service->payer channel
	{
		let chans = service_node.inner.node.list_channels();
		assert!(chans.len() == 1);
		assert!(
			chans.iter().any(|cd| cd.counterparty.node_id == payer_node_id && cd.is_channel_ready),
			"Expected payer->service channel to remain open. channels: {:?}",
			chans
		);
	}

	service_node.inner.node.get_and_clear_pending_msg_events();
	client_node.inner.node.get_and_clear_pending_msg_events();
	payer_node.node.get_and_clear_pending_msg_events();
	service_node.inner.chain_monitor.added_monitors.lock().unwrap().clear();
	client_node.inner.chain_monitor.added_monitors.lock().unwrap().clear();
	payer_node.chain_monitor.added_monitors.lock().unwrap().clear();
}

#[test]
fn client_trusts_lsp_broadcasts_despite_unforwardable_held_htlc() {
	// Once the opening fee has been paid, an HTLC held for the JIT channel that can no longer be
	// forwarded (e.g., because `ChannelManager` already timed it out) must not keep us from
	// broadcasting the funding transaction.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.htlc_interception_flags = HTLCInterceptionFlags::ToInterceptSCIDs as u8;

	let mut client_node_config = test_default_channel_config();
	client_node_config.channel_config.accept_underpaying_htlcs = true;

	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(service_node_config), Some(client_node_config), None],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes_with_payer(nodes);
	let LSPSNodesWithPayer { ref service_node, ref client_node, ref payer_node } = lsps_nodes;

	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2_000_000, 100_000);

	let intercept_scid = service_node.node.get_intercept_scid();
	let user_channel_id = 42u128;
	let cltv_expiry_delta: u32 = 144;
	let payment_size_msat = Some(1_000_000);
	let fee_base_msat: u64 = 10_000;

	execute_lsps2_dance(
		&service_node,
		&client_node,
		intercept_scid,
		user_channel_id,
		cltv_expiry_delta,
		promise_secret,
		payment_size_msat,
		fee_base_msat,
		128,
	);

	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		"test unforwardable held htlc",
		3600,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (payment_hash, expected_outbound_amount_msat) = match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash,
			expected_outbound_amount_msat,
			inbound_amount_msat,
			..
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);
			service_handler
				.htlc_intercepted(
					*requested_next_hop_scid,
					*intercept_id,
					*expected_outbound_amount_msat,
					*payment_hash,
					*inbound_amount_msat,
				)
				.unwrap();
			(*payment_hash, expected_outbound_amount_msat)
		},
		other => panic!("Expected HTLCIntercepted, got {:?}", other),
	};

	match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel { .. }) => {},
		other => panic!("Unexpected event: {:?}", other),
	};

	let (channel_id, funding_tx) = create_channel_with_manual_broadcast(
		&service_node_id,
		&client_node_id,
		&service_node,
		&client_node,
		user_channel_id,
		expected_outbound_amount_msat,
		true,
	);

	service_handler.channel_ready(user_channel_id, &channel_id, &client_node_id).unwrap();
	service_node.inner.node.process_pending_htlc_forwards();

	let pay_event = {
		{
			let mut added_monitors =
				service_node.inner.chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}
		let mut events = service_node.inner.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	let preimage = match &client_events[0] {
		Event::PaymentClaimable { payment_hash: ph, purpose, .. } => {
			assert_eq!(*ph, payment_hash);
			purpose.preimage().unwrap()
		},
		other => panic!("Expected PaymentClaimable event on client, got: {:?}", other),
	};

	// While the opening fee payment is in flight, another HTLC is held for the JIT channel.
	// `ChannelManager` doesn't know its intercept id, just as if it had timed it out already.
	let stale_intercept_id = InterceptId([42; 32]);
	service_handler
		.htlc_intercepted(
			intercept_scid,
			stale_intercept_id,
			100_000,
			PaymentHash([43; 32]),
			100_000,
		)
		.unwrap();

	client_node.inner.node.claim_funds(preimage);
	claim_and_assert_forwarded_only(&payer_node, &service_node.inner, &client_node.inner, preimage);

	let service_events = service_node.node.get_and_clear_pending_events();
	assert_eq!(service_events.len(), 1);
	let (skimmed_fee_msat, total_fee_msat) = match &service_events[0] {
		Event::PaymentForwarded { skimmed_fee_msat, total_fee_earned_msat, .. } => {
			(skimmed_fee_msat.unwrap(), total_fee_earned_msat.unwrap() - skimmed_fee_msat.unwrap())
		},
		other => panic!("Expected PaymentForwarded event, got: {:?}", other),
	};

	// Forwarding the held HTLC fails, which is reported back to us...
	match service_handler.payment_forwarded(channel_id, skimmed_fee_msat) {
		Err(APIError::APIMisuseError { err }) => {
			assert!(err.contains("not found"), "unexpected error: {}", err)
		},
		other => panic!("Expected APIMisuseError, got {:?}", other),
	}

	// ... but the paid-for channel still gets funded.
	let broadcasted = service_node.inner.tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert!(broadcasted.iter().any(|b| b.compute_txid() == funding_tx.compute_txid()));
	drop(broadcasted);

	expect_payment_sent(&payer_node, preimage, Some(Some(total_fee_msat)), true, true);
}
