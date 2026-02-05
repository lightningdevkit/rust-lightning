#![cfg(all(test, feature = "time"))]

mod common;

use common::create_service_and_client_nodes_with_kv_stores;
use common::{get_lsps_message, LSPSNodes};

use lightning::ln::peer_handler::CustomMessageHandler;
use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps1::client::LSPS1ClientConfig;
use lightning_liquidity::lsps1::event::LSPS1ClientEvent;
use lightning_liquidity::lsps1::event::LSPS1ServiceEvent;
use lightning_liquidity::lsps1::msgs::{
	LSPS1ChannelInfo, LSPS1OnchainPaymentInfo, LSPS1Options, LSPS1OrderParams, LSPS1PaymentInfo,
	LSPS1PaymentState,
};
use lightning_liquidity::lsps1::service::{LSPS1ServiceConfig, PaymentMethod};
use lightning_liquidity::utils::time::DefaultTimeProvider;
use lightning_liquidity::{LiquidityClientConfig, LiquidityManagerSync, LiquidityServiceConfig};

use lightning::ln::functional_test_utils::{
	create_chanmon_cfgs, create_node_cfgs, create_node_chanmgrs,
};
use lightning::util::test_utils::{TestBroadcaster, TestStore};

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, OutPoint};

use std::str::FromStr;
use std::sync::Arc;

use lightning::ln::functional_test_utils::{create_network, Node};
use lightning_liquidity::lsps1::msgs::LSPS1OrderId;
use lightning_liquidity::utils::time::TimeProvider;

fn build_lsps1_configs(
	supported_options: LSPS1Options,
) -> (LiquidityServiceConfig, LiquidityClientConfig) {
	let lsps1_service_config = LSPS1ServiceConfig { supported_options };
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

	let refund_onchain_address =
		Address::from_str("bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr")
			.unwrap()
			.assume_checked();
	let _create_order_id = client_handler.create_order(
		&service_node_id,
		order_params.clone(),
		Some(refund_onchain_address.clone()),
	);
	let create_order = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(create_order, client_node_id).unwrap();

	let _request_for_payment_event = service_node.liquidity_manager.next_event().unwrap();

	if let LiquidityEvent::LSPS1Service(LSPS1ServiceEvent::RequestForPaymentDetails {
		request_id,
		counterparty_node_id,
		order,
		refund_onchain_address: refund_addr,
		..
	}) = _request_for_payment_event
	{
		assert_eq!(request_id, _create_order_id.clone());
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(order, order_params);
		assert_eq!(refund_addr, Some(refund_onchain_address));
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

#[test]
fn lsps1_service_handler_persistence_across_restarts() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create shared KV store for service node that will persist across restarts
	let service_kv_store = Arc::new(TestStore::new(false));
	let client_kv_store = Arc::new(TestStore::new(false));

	let supported_options = LSPS1Options {
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

	let service_config = LiquidityServiceConfig {
		lsps1_service_config: Some(LSPS1ServiceConfig {
			supported_options: supported_options.clone(),
		}),
		lsps2_service_config: None,
		lsps5_service_config: None,
		advertise_service: true,
	};
	let time_provider: Arc<dyn TimeProvider + Send + Sync> = Arc::new(DefaultTimeProvider);

	// Variables to carry state between scopes
	let client_node_id: PublicKey;
	let expected_order_id: LSPS1OrderId;
	let order_params: LSPS1OrderParams;
	let payment_info: LSPS1PaymentInfo;

	// First scope: Setup, persistence, and dropping of all node objects
	{
		let LSPSNodes { service_node, client_node } = setup_test_lsps1_nodes_with_kv_stores(
			nodes,
			Arc::clone(&service_kv_store),
			client_kv_store,
			supported_options.clone(),
		);

		let service_node_id = service_node.inner.node.get_our_node_id();
		client_node_id = client_node.inner.node.get_our_node_id();

		let client_handler = client_node.liquidity_manager.lsps1_client_handler().unwrap();
		let service_handler = service_node.liquidity_manager.lsps1_service_handler().unwrap();

		// Request supported options
		let _request_supported_options_id =
			client_handler.request_supported_options(service_node_id);
		let request_supported_options = get_lsps_message!(client_node, service_node_id);

		service_node
			.liquidity_manager
			.handle_custom_message(request_supported_options, client_node_id)
			.unwrap();

		let get_info_message = get_lsps_message!(service_node, client_node_id);
		client_node
			.liquidity_manager
			.handle_custom_message(get_info_message, service_node_id)
			.unwrap();

		let _get_info_event = client_node.liquidity_manager.next_event().unwrap();

		// Create an order to establish persistent state
		order_params = LSPS1OrderParams {
			lsp_balance_sat: 100_000,
			client_balance_sat: 10_000_000,
			required_channel_confirmations: 0,
			funding_confirms_within_blocks: 6,
			channel_expiry_blocks: 144,
			token: None,
			announce_channel: true,
		};

		let refund_onchain_address =
			Address::from_str("bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr")
				.unwrap()
				.assume_checked();
		let create_order_id = client_handler.create_order(
			&service_node_id,
			order_params.clone(),
			Some(refund_onchain_address.clone()),
		);
		let create_order = get_lsps_message!(client_node, service_node_id);

		service_node.liquidity_manager.handle_custom_message(create_order, client_node_id).unwrap();

		let request_for_payment_event = service_node.liquidity_manager.next_event().unwrap();
		let request_id =
			if let LiquidityEvent::LSPS1Service(LSPS1ServiceEvent::RequestForPaymentDetails {
				request_id,
				..
			}) = request_for_payment_event
			{
				request_id
			} else {
				panic!("Unexpected event");
			};

		// Service sends payment details, creating persistent order state
		let json_str = r#"{
			"state": "EXPECT_PAYMENT",
			"expires_at": "2035-01-01T00:00:00Z",
			"fee_total_sat": "9999",
			"order_total_sat": "200999",
			"address": "bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr",
			"min_onchain_payment_confirmations": 1,
			"min_fee_for_0conf": 253
		}"#;

		let onchain: LSPS1OnchainPaymentInfo =
			serde_json::from_str(json_str).expect("Failed to parse JSON");
		payment_info = LSPS1PaymentInfo { bolt11: None, bolt12: None, onchain: Some(onchain) };
		service_handler
			.send_payment_details(request_id.clone(), client_node_id, payment_info.clone())
			.unwrap();

		let create_order_response = get_lsps_message!(service_node, client_node_id);

		client_node
			.liquidity_manager
			.handle_custom_message(create_order_response, service_node_id)
			.unwrap();

		let order_created_event = client_node.liquidity_manager.next_event().unwrap();
		expected_order_id = if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderCreated {
			request_id,
			order_id,
			..
		}) = order_created_event
		{
			assert_eq!(request_id, create_order_id);
			order_id
		} else {
			panic!("Unexpected event");
		};

		// Trigger persistence by calling persist
		service_node.liquidity_manager.persist().unwrap();

		// All node objects are dropped at the end of this scope
	}

	// Second scope: Recovery from persisted store and verification
	{
		// Create fresh node configurations for restart
		let node_chanmgrs_restart = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes_restart = create_network(2, &node_cfgs, &node_chanmgrs_restart);

		// Create a new LiquidityManager with the same configuration and KV store to simulate restart
		let service_transaction_broadcaster = Arc::new(TestBroadcaster::new(Network::Testnet));
		let client_transaction_broadcaster = Arc::new(TestBroadcaster::new(Network::Testnet));
		let client_kv_store_restart = Arc::new(TestStore::new(false));

		let restarted_service_lm = LiquidityManagerSync::new_with_custom_time_provider(
			nodes_restart[0].keys_manager,
			nodes_restart[0].keys_manager,
			nodes_restart[0].node,
			service_kv_store,
			service_transaction_broadcaster,
			Some(service_config),
			None,
			Arc::clone(&time_provider),
		)
		.unwrap();

		// Create a fresh client to query the restarted service
		let lsps1_client_config = LSPS1ClientConfig { max_channel_fees_msat: None };
		let client_config = LiquidityClientConfig {
			lsps1_client_config: Some(lsps1_client_config),
			lsps2_client_config: None,
			lsps5_client_config: None,
		};

		let client_lm = LiquidityManagerSync::new_with_custom_time_provider(
			nodes_restart[1].keys_manager,
			nodes_restart[1].keys_manager,
			nodes_restart[1].node,
			client_kv_store_restart,
			client_transaction_broadcaster,
			None,
			Some(client_config),
			time_provider,
		)
		.unwrap();

		let service_node_id = nodes_restart[0].node.get_our_node_id();
		let client_node_id_restart = nodes_restart[1].node.get_our_node_id();

		// Verify node IDs match (since we use same node_cfgs)
		assert_eq!(client_node_id_restart, client_node_id);

		// Use the client to send a GetOrder request
		let client_handler = client_lm.lsps1_client_handler().unwrap();
		let check_order_status_id =
			client_handler.check_order_status(&service_node_id, expected_order_id.clone());

		// Get the request message from client
		let pending_client_msgs = client_lm.get_and_clear_pending_msg();
		assert_eq!(pending_client_msgs.len(), 1);
		let (target_node_id, request_msg) = pending_client_msgs.into_iter().next().unwrap();
		assert_eq!(target_node_id, service_node_id);

		// Pass the request to the restarted service
		restarted_service_lm.handle_custom_message(request_msg, client_node_id).unwrap();

		// Get the response from the service
		let pending_service_msgs = restarted_service_lm.get_and_clear_pending_msg();
		assert_eq!(pending_service_msgs.len(), 1);
		let (target_node_id, response_msg) = pending_service_msgs.into_iter().next().unwrap();
		assert_eq!(target_node_id, client_node_id);

		// Pass the response to the client
		client_lm.handle_custom_message(response_msg, service_node_id).unwrap();

		// Verify the client receives the order status event with correct data
		let order_status_event = client_lm.next_event().unwrap();
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
			assert_eq!(order_id, expected_order_id);
			assert_eq!(order, order_params);
			assert_eq!(payment, payment_info);
			assert!(channel.is_none());
		} else {
			panic!("Expected OrderStatus event after restart, got: {:?}", order_status_event);
		}
	}
}

#[test]
fn lsps1_invalid_token_error() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let supported_options = LSPS1Options {
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
		setup_test_lsps1_nodes(nodes, supported_options.clone());
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();
	let client_handler = client_node.liquidity_manager.lsps1_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps1_service_handler().unwrap();

	// Create an order with an invalid token
	let order_params = LSPS1OrderParams {
		lsp_balance_sat: 100_000,
		client_balance_sat: 10_000_000,
		required_channel_confirmations: 0,
		funding_confirms_within_blocks: 6,
		channel_expiry_blocks: 144,
		token: Some("invalid_token".to_string()),
		announce_channel: true,
	};

	let refund_onchain_address =
		Address::from_str("bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr")
			.unwrap()
			.assume_checked();
	let create_order_id = client_handler.create_order(
		&service_node_id,
		order_params.clone(),
		Some(refund_onchain_address.clone()),
	);
	let create_order = get_lsps_message!(client_node, service_node_id);

	// Service receives the create_order request
	service_node.liquidity_manager.handle_custom_message(create_order, client_node_id).unwrap();

	// Service emits RequestForPaymentDetails event
	let request_for_payment_event = service_node.liquidity_manager.next_event().unwrap();
	let request_id =
		if let LiquidityEvent::LSPS1Service(LSPS1ServiceEvent::RequestForPaymentDetails {
			request_id,
			counterparty_node_id,
			order,
			refund_onchain_address: refund_addr,
			..
		}) = request_for_payment_event
		{
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(order, order_params);
			assert_eq!(refund_addr, Some(refund_onchain_address));
			request_id
		} else {
			panic!("Unexpected event: expected RequestForPaymentDetails");
		};

	// Service rejects the order due to invalid token
	service_handler.invalid_token_provided(client_node_id, request_id).unwrap();

	// Get the error response message
	let error_response = get_lsps_message!(service_node, client_node_id);

	// Client receives the error response
	client_node
		.liquidity_manager
		.handle_custom_message(error_response, service_node_id)
		.unwrap_err();

	// Client receives OrderRequestFailed event with error code 102
	let error_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = error_event
	{
		assert_eq!(request_id, create_order_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 102); // LSPS1_CREATE_ORDER_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE
	} else {
		panic!("Unexpected event: expected OrderRequestFailed");
	}
}

#[test]
fn lsps1_order_state_transitions() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let supported_options = LSPS1Options {
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
		setup_test_lsps1_nodes(nodes, supported_options.clone());
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();
	let client_handler = client_node.liquidity_manager.lsps1_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps1_service_handler().unwrap();

	// Create an order
	let order_params = LSPS1OrderParams {
		lsp_balance_sat: 100_000,
		client_balance_sat: 10_000_000,
		required_channel_confirmations: 0,
		funding_confirms_within_blocks: 6,
		channel_expiry_blocks: 144,
		token: None,
		announce_channel: true,
	};

	let refund_onchain_address =
		Address::from_str("bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr")
			.unwrap()
			.assume_checked();
	let create_order_id = client_handler.create_order(
		&service_node_id,
		order_params.clone(),
		Some(refund_onchain_address),
	);
	let create_order = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(create_order, client_node_id).unwrap();

	let request_for_payment_event = service_node.liquidity_manager.next_event().unwrap();
	let request_id =
		if let LiquidityEvent::LSPS1Service(LSPS1ServiceEvent::RequestForPaymentDetails {
			request_id,
			..
		}) = request_for_payment_event
		{
			request_id
		} else {
			panic!("Unexpected event");
		};

	// Send payment details with onchain payment option
	let json_str = r#"{
		"state": "EXPECT_PAYMENT",
		"expires_at": "2035-01-01T00:00:00Z",
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
		.send_payment_details(request_id.clone(), client_node_id, payment_info.clone())
		.unwrap();

	let create_order_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(create_order_response, service_node_id)
		.unwrap();

	let order_created_event = client_node.liquidity_manager.next_event().unwrap();
	let order_id = if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderCreated {
		request_id,
		order_id,
		payment,
		..
	}) = order_created_event
	{
		assert_eq!(request_id, create_order_id);
		// Initially, payment state should be ExpectPayment
		assert_eq!(payment.onchain.as_ref().unwrap().state, LSPS1PaymentState::ExpectPayment);
		order_id
	} else {
		panic!("Unexpected event");
	};

	// Test order_payment_received: mark the order as paid
	service_handler
		.order_payment_received(client_node_id, order_id.clone(), PaymentMethod::Onchain)
		.unwrap();

	// Client checks order status - should see payment state as Paid
	let _check_order_id = client_handler.check_order_status(&service_node_id, order_id.clone());
	let check_order = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(check_order, client_node_id).unwrap();
	let order_response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(order_response, service_node_id).unwrap();

	let order_status_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderStatus { payment, channel, .. }) =
		order_status_event
	{
		// Payment state should be Paid
		assert_eq!(payment.onchain.as_ref().unwrap().state, LSPS1PaymentState::Paid);
		// No channel info yet (order state is still Created internally)
		assert!(channel.is_none());
	} else {
		panic!("Unexpected event");
	}

	// Test order_channel_opened: mark the channel as opened
	let channel_info = LSPS1ChannelInfo {
		funded_at: LSPSDateTime::from_str("2035-01-01T00:00:00Z").unwrap(),
		funding_outpoint: OutPoint::from_str(
			"0301e0480b374b32851a9462db29dc19fe830a7f7d7a88b81612b9d42099c0ae:0",
		)
		.unwrap(),
		expires_at: LSPSDateTime::from_str("2036-01-01T00:00:00Z").unwrap(),
	};
	service_handler
		.order_channel_opened(client_node_id, order_id.clone(), channel_info.clone())
		.unwrap();

	// Client checks order status - should see Completed state with channel info
	let _check_order_id = client_handler.check_order_status(&service_node_id, order_id.clone());
	let check_order = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(check_order, client_node_id).unwrap();
	let order_response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(order_response, service_node_id).unwrap();

	let order_status_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderStatus { channel, .. }) =
		order_status_event
	{
		// Channel info should be present (indicates Completed state)
		assert_eq!(channel, Some(channel_info));
	} else {
		panic!("Unexpected event");
	}
}

#[test]
fn lsps1_order_failed_and_refunded() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let supported_options = LSPS1Options {
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
		setup_test_lsps1_nodes(nodes, supported_options.clone());
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();
	let client_handler = client_node.liquidity_manager.lsps1_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps1_service_handler().unwrap();

	// Create an order
	let order_params = LSPS1OrderParams {
		lsp_balance_sat: 100_000,
		client_balance_sat: 10_000_000,
		required_channel_confirmations: 0,
		funding_confirms_within_blocks: 6,
		channel_expiry_blocks: 144,
		token: None,
		announce_channel: true,
	};

	let refund_onchain_address =
		Address::from_str("bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr")
			.unwrap()
			.assume_checked();
	let create_order_id = client_handler.create_order(
		&service_node_id,
		order_params.clone(),
		Some(refund_onchain_address),
	);
	let create_order = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(create_order, client_node_id).unwrap();

	let request_for_payment_event = service_node.liquidity_manager.next_event().unwrap();
	let request_id =
		if let LiquidityEvent::LSPS1Service(LSPS1ServiceEvent::RequestForPaymentDetails {
			request_id,
			..
		}) = request_for_payment_event
		{
			request_id
		} else {
			panic!("Unexpected event");
		};

	// Send payment details
	let json_str = r#"{
		"state": "EXPECT_PAYMENT",
		"expires_at": "2035-01-01T00:00:00Z",
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
		.send_payment_details(request_id.clone(), client_node_id, payment_info.clone())
		.unwrap();

	let create_order_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(create_order_response, service_node_id)
		.unwrap();

	let order_created_event = client_node.liquidity_manager.next_event().unwrap();
	let order_id = if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderCreated {
		request_id,
		order_id,
		..
	}) = order_created_event
	{
		assert_eq!(request_id, create_order_id);
		order_id
	} else {
		panic!("Unexpected event");
	};

	// Test order_failed_and_refunded: mark the order as failed
	service_handler.order_failed_and_refunded(client_node_id, order_id.clone()).unwrap();

	// Client checks order status - should see Failed state with Refunded payment
	let _check_order_id = client_handler.check_order_status(&service_node_id, order_id.clone());
	let check_order = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(check_order, client_node_id).unwrap();
	let order_response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(order_response, service_node_id).unwrap();

	let order_status_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS1Client(LSPS1ClientEvent::OrderStatus { payment, channel, .. }) =
		order_status_event
	{
		// Payment state should be Refunded (indicates Failed state)
		assert_eq!(payment.onchain.as_ref().unwrap().state, LSPS1PaymentState::Refunded);
		// No channel info
		assert!(channel.is_none());
	} else {
		panic!("Unexpected event");
	}
}
