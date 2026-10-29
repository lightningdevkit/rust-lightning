#![cfg(all(test, feature = "time"))]

mod common;

use common::{create_service_and_client_nodes, get_lsps_message, LSPSNodes};

use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::event::LSPS0ClientEvent;
use lightning_liquidity::lsps0::ser::RawLSPSMessage;
use lightning_liquidity::lsps1::client::LSPS1ClientConfig;
use lightning_liquidity::lsps1::msgs::LSPS1Options;
use lightning_liquidity::lsps1::service::LSPS1ServiceConfig;
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig;
use lightning_liquidity::lsps5::client::LSPS5ClientConfig;
use lightning_liquidity::lsps5::service::LSPS5ServiceConfig;
use lightning_liquidity::utils::time::DefaultTimeProvider;
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};

use lightning::ln::functional_test_utils::{
	create_chanmon_cfgs, create_network, create_node_cfgs, create_node_chanmgrs,
};
use lightning::ln::peer_handler::CustomMessageHandler;

use std::sync::Arc;

fn lsps_service_and_client_configs() -> (LiquidityServiceConfig, LiquidityClientConfig) {
	let promise_secret = [42; 32];
	let lsps2_service_config = LSPS2ServiceConfig { promise_secret };
	let lsps1_service_config = {
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
		LSPS1ServiceConfig { supported_options }
	};
	let lsps5_service_config = LSPS5ServiceConfig::default();
	let service_config = LiquidityServiceConfig {
		lsps1_service_config: Some(lsps1_service_config),
		lsps2_service_config: Some(lsps2_service_config),
		lsps5_service_config: Some(lsps5_service_config),
		advertise_service: true,
	};

	let lsps2_client_config = LSPS2ClientConfig::default();
	let lsps1_client_config: LSPS1ClientConfig = LSPS1ClientConfig { max_channel_fees_msat: None };
	let lsps5_client_config = LSPS5ClientConfig::default();
	let client_config = LiquidityClientConfig {
		lsps1_client_config: Some(lsps1_client_config),
		lsps2_client_config: Some(lsps2_client_config),
		lsps5_client_config: Some(lsps5_client_config),
	};

	(service_config, client_config)
}

#[test]
fn list_protocols_integration_test() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (service_config, client_config) = lsps_service_and_client_configs();

	let service_node_id = nodes[0].node.get_our_node_id();
	let client_node_id = nodes[1].node.get_our_node_id();

	let LSPSNodes { service_node, client_node } = create_service_and_client_nodes(
		nodes,
		service_config,
		client_config,
		Arc::new(DefaultTimeProvider),
	);

	let client_handler = client_node.liquidity_manager.lsps0_client_handler();

	client_handler.list_protocols(&service_node_id);
	let list_protocols_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(list_protocols_request, client_node_id)
		.unwrap();

	let list_protocols_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(list_protocols_response, service_node_id)
		.unwrap();

	let list_protocols_event = client_node.liquidity_manager.next_event().unwrap();
	match list_protocols_event {
		LiquidityEvent::LSPS0Client(LSPS0ClientEvent::ListProtocolsResponse {
			counterparty_node_id,
			protocols,
		}) => {
			assert_eq!(counterparty_node_id, service_node_id);
			{
				assert!(protocols.contains(&1));
				assert!(protocols.contains(&2));
				assert!(protocols.contains(&5));
				assert_eq!(protocols.len(), 3);
			}
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn list_protocols_request_with_oversized_id_is_rejected() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (service_config, client_config) = lsps_service_and_client_configs();

	let client_node_id = nodes[1].node.get_our_node_id();

	let LSPSNodes { service_node, client_node: _ } = create_service_and_client_nodes(
		nodes,
		service_config,
		client_config,
		Arc::new(DefaultTimeProvider),
	);

	// An id just under the maximum custom message size would previously be
	// echoed back in a response exceeding the Lightning message size limit.
	let oversized_id = "a".repeat(65_000);
	let payload = format!(
		r#"{{"jsonrpc":"2.0","id":"{}","method":"lsps0.list_protocols","params":{{}}}}"#,
		oversized_id
	);

	let err = service_node
		.liquidity_manager
		.handle_custom_message(RawLSPSMessage { payload }, client_node_id)
		.unwrap_err();
	assert!(matches!(err.action, lightning::ln::msgs::ErrorAction::IgnoreAndLog(_)));

	// The service must not echo the oversized id back; it responds with a
	// parse error carrying a `null` id instead.
	let response = get_lsps_message!(service_node, client_node_id);
	let parsed_response: serde_json::Value = serde_json::from_str(&response.payload).unwrap();
	assert_eq!(parsed_response["id"], serde_json::Value::Null);
	assert_eq!(parsed_response["error"]["code"], -32700);

	// The peer sent an invalid message, so it is ignored from now on.
	assert!(service_node
		.liquidity_manager
		.handle_custom_message(
			RawLSPSMessage {
				payload: r#"{"jsonrpc":"2.0","id":"1","method":"lsps0.list_protocols"}"#
					.to_string()
			},
			client_node_id,
		)
		.is_err());
	assert_eq!(service_node.liquidity_manager.get_and_clear_pending_msg().len(), 0);
}

#[test]
fn response_from_other_peer_is_ignored() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (service_config, client_config) = lsps_service_and_client_configs();

	let service_node_id = nodes[0].node.get_our_node_id();
	let client_node_id = nodes[1].node.get_our_node_id();
	let other_peer_node_id = nodes[2].node.get_our_node_id();

	let LSPSNodes { service_node, client_node } = create_service_and_client_nodes(
		nodes,
		service_config,
		client_config,
		Arc::new(DefaultTimeProvider),
	);

	let client_handler = client_node.liquidity_manager.lsps0_client_handler();

	client_handler.list_protocols(&service_node_id);
	let list_protocols_request = get_lsps_message!(client_node, service_node_id);

	let request_json: serde_json::Value =
		serde_json::from_str(&list_protocols_request.payload).unwrap();
	let request_id = request_json["id"].as_str().unwrap().to_string();

	// A peer we never queried responds with the request id we sent to the service.
	// It must not be treated as a valid response, and it must not consume the
	// pending request tracked for the service.
	let bogus_payload =
		format!(r#"{{"jsonrpc":"2.0","id":"{}","result":{{"protocols":[1,2,5]}}}}"#, request_id);
	assert!(client_node
		.liquidity_manager
		.handle_custom_message(RawLSPSMessage { payload: bogus_payload }, other_peer_node_id,)
		.is_err());
	assert!(client_node.liquidity_manager.next_event().is_none());

	// The genuine response from the queried peer is still processed.
	service_node
		.liquidity_manager
		.handle_custom_message(list_protocols_request, client_node_id)
		.unwrap();

	let list_protocols_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(list_protocols_response, service_node_id)
		.unwrap();

	let list_protocols_event = client_node.liquidity_manager.next_event().unwrap();
	match list_protocols_event {
		LiquidityEvent::LSPS0Client(LSPS0ClientEvent::ListProtocolsResponse {
			counterparty_node_id,
			..
		}) => assert_eq!(counterparty_node_id, service_node_id),
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn unexpected_list_protocols_response_is_ignored() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (service_config, client_config) = lsps_service_and_client_configs();

	let service_node_id = nodes[0].node.get_our_node_id();
	let other_peer_node_id = nodes[2].node.get_our_node_id();

	let LSPSNodes { service_node: _, client_node } = create_service_and_client_nodes(
		nodes,
		service_config,
		client_config,
		Arc::new(DefaultTimeProvider),
	);

	// A response carrying an id we never sent, both from a peer we queried and
	// from one we didn't, must not surface a `ListProtocolsResponse` event.
	for sender_node_id in [service_node_id, other_peer_node_id] {
		let payload =
			r#"{"jsonrpc":"2.0","id":"never-sent","result":{"protocols":[1,2,5]}}"#.to_string();
		assert!(client_node
			.liquidity_manager
			.handle_custom_message(RawLSPSMessage { payload }, sender_node_id)
			.is_err());
		assert!(client_node.liquidity_manager.next_event().is_none());
	}
}
