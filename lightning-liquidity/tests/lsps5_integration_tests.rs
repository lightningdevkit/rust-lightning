#![cfg(all(test, feature = "std", feature = "lsps5"))]

mod common;

use common::{create_service_and_client_nodes, get_lsps_message};

use lightning_liquidity::events::Event;
use lightning_liquidity::lsps5::client::LSPS5ClientConfig;
use lightning_liquidity::lsps5::event::LSPS5ClientEvent;
use lightning_liquidity::lsps5::service::LSPS5ServiceConfig;
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};

use lightning::ln::peer_handler::CustomMessageHandler;

#[test]
#[cfg(feature = "lsps5")]
fn webhook_management() {
	let lsps5_service_config =
		LSPS5ServiceConfig { max_webhooks: 5, supported_protocols: vec!["https".to_string()] };
	let service_config = LiquidityServiceConfig {
		#[cfg(lsps1_service)]
		lsps1_service_config: None,
		lsps2_service_config: None,
		lsps5_service_config: Some(lsps5_service_config),
		advertise_service: true,
	};

	let lsps5_client_config = LSPS5ClientConfig::default();
	let client_config = LiquidityClientConfig {
		lsps1_client_config: None,
		lsps2_client_config: None,
		lsps5_client_config: Some(lsps5_client_config),
	};

	let (service_node, client_node) =
		create_service_and_client_nodes("webhook_management", service_config, client_config);

	let _service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();
	let service_node_id = service_node.channel_manager.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let client_node_id = client_node.channel_manager.get_our_node_id();

	let set_webhook_request_id = client_handler.set_webhook(
		service_node_id,
		"test-app".to_string(),
		"https://example.com/webhook".to_string(),
	);
	let set_webhook_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_request, client_node_id)
		.unwrap();

	let set_webhook_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response, service_node_id)
		.unwrap();

	let webhook_set_event = client_node.liquidity_manager.next_event().unwrap();

	match webhook_set_event {
		Event::LSPS5Client(LSPS5ClientEvent::WebhookSet {
			request_id,
			counterparty_node_id,
			num_webhooks,
			max_webhooks,
			no_change,
		}) => {
			assert_eq!(request_id, set_webhook_request_id);
			assert_eq!(counterparty_node_id, service_node_id);
			assert_eq!(num_webhooks, 1);
			assert_eq!(max_webhooks, 5);
			assert_eq!(no_change, false);
		},
		_ => panic!("Unexpected event"),
	};

	let list_webhooks_request_id = client_handler.list_webhooks(service_node_id);
	let list_webhooks_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(list_webhooks_request, client_node_id)
		.unwrap();

	let list_webhooks_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(list_webhooks_response, service_node_id)
		.unwrap();

	let list_webhooks_event = client_node.liquidity_manager.next_event().unwrap();

	match list_webhooks_event {
		Event::LSPS5Client(LSPS5ClientEvent::ListWebhooks {
			request_id,
			counterparty_node_id,
			app_names,
			max_webhooks,
		}) => {
			assert_eq!(request_id, list_webhooks_request_id);
			assert_eq!(counterparty_node_id, service_node_id);
			assert_eq!(app_names, vec!["test-app".to_string()]);
			assert_eq!(max_webhooks, 5);
		},
		_ => panic!("Unexpected event"),
	};

	let remove_webhook_request_id =
		client_handler.remove_webhook(service_node_id, "test-app".to_string());
	let remove_webhook_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(remove_webhook_request, client_node_id)
		.unwrap();

	let remove_webhook_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(remove_webhook_response, service_node_id)
		.unwrap();

	let remove_webhook_event = client_node.liquidity_manager.next_event().unwrap();

	match remove_webhook_event {
		Event::LSPS5Client(LSPS5ClientEvent::WebhookRemoved {
			request_id,
			counterparty_node_id,
		}) => {
			assert_eq!(request_id, remove_webhook_request_id);
			assert_eq!(counterparty_node_id, service_node_id);
		},
		_ => panic!("Unexpected event"),
	};

	let list_webhooks_request_id = client_handler.list_webhooks(service_node_id);
	let list_webhooks_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(list_webhooks_request, client_node_id)
		.unwrap();

	let list_webhooks_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(list_webhooks_response, service_node_id)
		.unwrap();

	let list_webhooks_event = client_node.liquidity_manager.next_event().unwrap();

	match list_webhooks_event {
		Event::LSPS5Client(LSPS5ClientEvent::ListWebhooks {
			request_id,
			counterparty_node_id,
			app_names,
			max_webhooks,
		}) => {
			assert_eq!(request_id, list_webhooks_request_id);
			assert_eq!(counterparty_node_id, service_node_id);
			assert_eq!(app_names, Vec::<String>::new());
			assert_eq!(max_webhooks, 5);
		},
		_ => panic!("Unexpected event"),
	};
}
