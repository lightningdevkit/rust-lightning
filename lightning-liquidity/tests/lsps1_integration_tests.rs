#![cfg(all(test, feature = "time", lsps1_service))]

mod common;

use common::create_service_and_client_nodes_with_kv_stores;
use common::{get_lsps_message, LSPSNodes};

use lightning::ln::peer_handler::CustomMessageHandler;
use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps1::client::LSPS1ClientConfig;
use lightning_liquidity::lsps1::event::LSPS1ClientEvent;
use lightning_liquidity::lsps1::event::LSPS1ServiceEvent;
use lightning_liquidity::lsps1::msgs::{
	LSPS1OnchainPaymentInfo, LSPS1Options, LSPS1OrderParams, LSPS1PaymentInfo,
};
use lightning_liquidity::lsps1::service::LSPS1ServiceConfig;
use lightning_liquidity::utils::time::DefaultTimeProvider;
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};

use lightning::ln::functional_test_utils::{
	create_chanmon_cfgs, create_node_cfgs, create_node_chanmgrs,
};
use lightning::util::test_utils::TestStore;

use std::sync::Arc;

use lightning::ln::functional_test_utils::{create_network, Node};

fn build_lsps1_configs(
	supported_options: LSPS1Options,
) -> (LiquidityServiceConfig, LiquidityClientConfig) {
	let lsps1_service_config = LSPS1ServiceConfig { token: None, supported_options };
	let service_config = LiquidityServiceConfig {
		lsps1_service_config: Some(lsps1_service_config),
		lsps2_service_config: None,
		lsps5_service_config: None,
		advertise_service: true,
	};

	let lsps1_client_config = LSPS1ClientConfig { max_channel_fees_msat: None };
	let client_config = LiquidityClientConfig {
		lsps1_client_config: Some(lsps1_client_config),
		lsps2_client_config: None,
		lsps5_client_config: None,
	};

	(service_config, client_config)
}

fn setup_test_lsps1_nodes_with_kv_stores<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, service_kv_store: Arc<TestStore>,
	client_kv_store: Arc<TestStore>, supported_options: LSPS1Options,
) -> LSPSNodes<'a, 'b, 'c> {
	let (service_config, client_config) = build_lsps1_configs(supported_options);
	let lsps_nodes = create_service_and_client_nodes_with_kv_stores(
		nodes,
		service_config,
		client_config,
		Arc::new(DefaultTimeProvider),
		service_kv_store,
		client_kv_store,
	);
	lsps_nodes
}

fn setup_test_lsps1_nodes<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, supported_options: LSPS1Options,
) -> LSPSNodes<'a, 'b, 'c> {
	let service_kv_store = Arc::new(TestStore::new(false));
	let client_kv_store = Arc::new(TestStore::new(false));
	setup_test_lsps1_nodes_with_kv_stores(
		nodes,
		service_kv_store,
		client_kv_store,
		supported_options,
	)
}

#[test]
fn lsps1_happy_path() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let expected_options_supported = LSPS1Options {
		min_required_channel_confirmations: 0,
		min_funding_confirms_within_blocks: 6,
		supports_zero_channel_reserve: true,
		max_channel_expiry_blocks: 144,
		min_initial_client_balance_sat: 10_000_000,
		max_initial_client_balance_sat: 100_000_000,
		min_initial_lsp_balance_sat: 100_000,
		max_initial_lsp_balance_sat: 100_000_000,
		min_channel_balance_sat: 100_000,
		max_channel_balance_sat: 100_000_000,
	};

	let LSPSNodes { service_node, client_node } =
		setup_test_lsps1_nodes(nodes, expected_options_supported.clone());
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();
	let client_handler = client_node.liquidity_manager.lsps1_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps1_service_handler().unwrap();

	let request_supported_options_id = client_handler.request_supported_options(service_node_id);
	let request_supported_options = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(request_supported_options, client_node_id)
		.unwrap();

	let get_info_message = get_lsps_message!(service_node, client_node_id);

	client_node.liquidity_manager.handle_custom_message(get_info_message, service_node_id).unwrap();

	let get_info_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::SupportedOptionsReady {
		request_id,
		counterparty_node_id,
		supported_options,
	}) = get_info_event
	{
		assert_eq!(request_id, request_supported_options_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(expected_options_supported, supported_options);
	} else {
		panic!("Unexpected event");
	}

	let order_params = LSPS1OrderParams {
		lsp_balance_sat: 100_000,
		client_balance_sat: 10_000_000,
		required_channel_confirmations: 0,
		funding_confirms_within_blocks: 6,
		channel_expiry_blocks: 144,
		token: None,
		announce_channel: true,
	};

	let _create_order_id =
		client_handler.create_order(&service_node_id, order_params.clone(), None);
	let create_order = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(create_order, client_node_id).unwrap();

	let _request_for_payment_event = service_node.liquidity_manager.next_event().unwrap();

	if let LiquidityEvent::LSPS1Service(LSPS1ServiceEvent::RequestForPaymentDetails {
		request_id,
		counterparty_node_id,
		order,
	}) = _request_for_payment_event
	{
		assert_eq!(request_id, _create_order_id.clone());
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(order, order_params);
	} else {
		panic!("Unexpected event");
	}

	let json_str = r#"{
            "state": "EXPECT_PAYMENT",
            "expires_at": "2025-01-01T00:00:00Z",
            "fee_total_sat": "9999",
            "order_total_sat": "200999",
            "address": "bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr",
            "min_onchain_payment_confirmations": 1,
            "min_fee_for_0conf": 253
        }"#;

	let onchain: LSPS1OnchainPaymentInfo =
		serde_json::from_str(json_str).expect("Failed to parse JSON");
	let payment_info = LSPS1PaymentInfo { bolt11: None, bolt12: None, onchain: Some(onchain) };
	service_handler
		.send_payment_details(_create_order_id.clone(), client_node_id, payment_info.clone())
		.unwrap();

	let create_order_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(create_order_response, service_node_id)
		.unwrap();

	let order_created_event = client_node.liquidity_manager.next_event().unwrap();
	let expected_order_id = if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderCreated {
		request_id,
		counterparty_node_id,
		order_id,
		order,
		payment,
		channel,
	}) = order_created_event
	{
		assert_eq!(request_id, _create_order_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(order, order_params);
		assert_eq!(payment, payment_info);
		assert!(channel.is_none());
		order_id
	} else {
		panic!("Unexpected event");
	};

	let check_order_status_id =
		client_handler.check_order_status(&service_node_id, expected_order_id.clone());
	let check_order_status = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(check_order_status, client_node_id)
		.unwrap();

	let order_status_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(order_status_response, service_node_id)
		.unwrap();

	let order_status_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderStatus {
		request_id,
		counterparty_node_id,
		order_id,
		order,
		payment,
		channel,
	}) = order_status_event
	{
		assert_eq!(request_id, check_order_status_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(order, order_params);
		assert_eq!(payment, payment_info);
		assert!(channel.is_none());
		assert_eq!(order_id, expected_order_id);
	} else {
		panic!("Unexpected event");
	}
}
