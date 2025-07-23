#![cfg(all(test, feature = "std"))]

mod common;

use common::{create_service_and_client_nodes, get_lsps_message, LSPSNodes};

use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::event::LSPS0ClientEvent;
#[cfg(lsps1_service)]
use lightning_liquidity::lsps1::client::LSPS1ClientConfig;
#[cfg(lsps1_service)]
use lightning_liquidity::lsps1::service::LSPS1ServiceConfig;
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig;
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};

use lightning::ln::functional_test_utils::{
	create_chanmon_cfgs, create_network, create_node_cfgs, create_node_chanmgrs,
};
use lightning::ln::peer_handler::CustomMessageHandler;

#[test]
fn list_protocols_integration_test() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let promise_secret = [42; 32];
	let lsps2_service_config = LSPS2ServiceConfig { promise_secret };
	#[cfg(lsps1_service)]
	let lsps1_service_config = LSPS1ServiceConfig { supported_options: None, token: None };
	let service_config = LiquidityServiceConfig {
		#[cfg(lsps1_service)]
		lsps1_service_config: Some(lsps1_service_config),
		lsps2_service_config: Some(lsps2_service_config),
		advertise_service: true,
	};

	let lsps2_client_config = LSPS2ClientConfig::default();
	#[cfg(lsps1_service)]
	let lsps1_client_config: LSPS1ClientConfig = LSPS1ClientConfig { max_channel_fees_msat: None };
	let client_config = LiquidityClientConfig {
		#[cfg(lsps1_service)]
		lsps1_client_config: Some(lsps1_client_config),
		#[cfg(not(lsps1_service))]
		lsps1_client_config: None,
		lsps2_client_config: Some(lsps2_client_config),
	};

	let service_node_id = nodes[0].node.get_our_node_id();
	let client_node_id = nodes[1].node.get_our_node_id();

	let LSPSNodes { service_node, client_node, .. } =
		create_service_and_client_nodes(nodes, service_config, client_config);

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
		.handle_custom_message(list_protocols_response, client_node_id)
		.unwrap();

	let list_protocols_event = client_node.liquidity_manager.next_event().unwrap();
	match list_protocols_event {
		LiquidityEvent::LSPS0Client(LSPS0ClientEvent::ListProtocolsResponse {
			counterparty_node_id,
			protocols,
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			#[cfg(lsps1_service)]
			{
				assert!(protocols.contains(&1));
				assert!(protocols.contains(&2));
				assert_eq!(protocols.len(), 2);
			}

			#[cfg(not(lsps1_service))]
			assert_eq!(protocols, vec![2]);
		},
		_ => panic!("Unexpected event"),
	}
}
