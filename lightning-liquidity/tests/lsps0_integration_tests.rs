#![cfg(all(test, feature = "time"))]

mod common;

use std::sync::Arc;
use std::time::Duration;

use bitcoin::secp256k1::SecretKey;
use common::{create_service_and_client_nodes, get_lsps_message};

use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::event::LSPS0ClientEvent;
#[cfg(lsps1_service)]
use lightning_liquidity::lsps1::client::LSPS1ClientConfig;
#[cfg(lsps1_service)]
use lightning_liquidity::lsps1::service::LSPS1ServiceConfig;
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig;
use lightning_liquidity::lsps5::client::LSPS5ClientConfig;
use lightning_liquidity::lsps5::service::{DefaultTimeProvider, LSPS5ServiceConfig};
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};

use lightning::ln::peer_handler::CustomMessageHandler;

#[test]
fn list_protocols_integration_test() {
	let promise_secret = [42; 32];
	let lsps2_service_config = LSPS2ServiceConfig { promise_secret };
	#[cfg(lsps1_service)]
	let lsps1_service_config = LSPS1ServiceConfig { supported_options: None, token: None };
	let signing_key = SecretKey::from_slice(&[42; 32]).unwrap();
	let mut lsps5_service_config = LSPS5ServiceConfig {
		max_webhooks_per_client: 10,
		signing_key,
		notification_cooldown_hours: Duration::from_secs(3600),
	};
	lsps5_service_config.signing_key = signing_key;
	let service_config = LiquidityServiceConfig {
		#[cfg(lsps1_service)]
		lsps1_service_config: Some(lsps1_service_config),
		lsps2_service_config: Some(lsps2_service_config),
		lsps5_service_config: Some(lsps5_service_config),
		advertise_service: true,
	};

	let lsps2_client_config = LSPS2ClientConfig::default();
	#[cfg(lsps1_service)]
	let lsps1_client_config: LSPS1ClientConfig = LSPS1ClientConfig { max_channel_fees_msat: None };
	let lsps5_client_config = LSPS5ClientConfig::default();
	let client_config = LiquidityClientConfig {
		#[cfg(lsps1_service)]
		lsps1_client_config: Some(lsps1_client_config),
		#[cfg(not(lsps1_service))]
		lsps1_client_config: None,
		lsps2_client_config: Some(lsps2_client_config),
		lsps5_client_config: Some(lsps5_client_config),
	};

	let (service_node, client_node) = create_service_and_client_nodes(
		"list_protocols_integration_test",
		service_config,
		client_config,
		Arc::new(DefaultTimeProvider),
	);

	let service_node_id = service_node.channel_manager.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps0_client_handler();
	let client_node_id = client_node.channel_manager.get_our_node_id();

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
				assert!(protocols.contains(&5));
				assert_eq!(protocols.len(), 3);
			}

			#[cfg(not(lsps1_service))]
			assert_eq!(protocols, vec![2, 5]);
		},
		_ => panic!("Unexpected event"),
	}
}
