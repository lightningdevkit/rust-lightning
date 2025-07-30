#![cfg(all(test, feature = "time"))]

mod common;

use common::{create_service_and_client_nodes, get_lsps_message, LSPSNodes};

use lightning::ln::functional_test_utils::{
	create_chanmon_cfgs, create_network, create_node_cfgs, create_node_chanmgrs, Node,
};
use lightning::ln::msgs::Init;
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::util::hash_tables::{HashMap, HashSet};
use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps5::client::LSPS5ClientConfig;
use lightning_liquidity::lsps5::event::{LSPS5ClientEvent, LSPS5ServiceEvent};
use lightning_liquidity::lsps5::msgs::{
	LSPS5AppName, LSPS5ClientError, LSPS5ProtocolError, LSPS5WebhookUrl, WebhookNotification,
	WebhookNotificationMethod,
};
use lightning_liquidity::lsps5::service::{
	LSPS5ServiceConfig, DEFAULT_MAX_WEBHOOKS_PER_CLIENT, DEFAULT_NOTIFICATION_COOLDOWN_HOURS,
};
use lightning_liquidity::lsps5::service::{
	MIN_WEBHOOK_RETENTION_DAYS, PRUNE_STALE_WEBHOOKS_INTERVAL_DAYS,
};
use lightning_liquidity::lsps5::validator::{LSPS5Validator, MAX_RECENT_SIGNATURES};
use lightning_liquidity::utils::time::{DefaultTimeProvider, TimeProvider};
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub(crate) fn lsps5_test_setup<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, time_provider: Arc<dyn TimeProvider + Send + Sync>,
) -> (LSPSNodes<'a, 'b, 'c>, LSPS5Validator) {
	let lsps5_service_config = LSPS5ServiceConfig::default();
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

	let lsps_nodes = create_service_and_client_nodes(
		nodes,
		service_config,
		client_config,
		Arc::clone(&time_provider),
	);

	let validator = LSPS5Validator::new();

	(lsps_nodes, validator)
}

struct MockTimeProvider {
	current_time: RwLock<Duration>,
}

impl MockTimeProvider {
	fn new(seconds_since_epoch: u64) -> Self {
		Self { current_time: RwLock::new(Duration::from_secs(seconds_since_epoch)) }
	}

	fn advance_time(&self, seconds: u64) {
		let mut time = self.current_time.write().unwrap();
		*time += Duration::from_secs(seconds);
	}
}

impl TimeProvider for MockTimeProvider {
	fn duration_since_epoch(&self) -> Duration {
		*self.current_time.read().unwrap()
	}
}

fn extract_ts_sig(headers: &HashMap<String, String>) -> (LSPSDateTime, String) {
	let timestamp = headers
		.get("x-lsps5-timestamp")
		.expect("missing x-lsps5-timestamp header")
		.parse::<LSPSDateTime>()
		.expect("failed to parse x-lsps5-timestamp header");

	let signature =
		headers.get("x-lsps5-signature").expect("missing x-lsps5-signature header").to_owned();
	(timestamp, signature)
}

#[test]
fn webhook_registration_flow() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();
	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();

	let raw_app_name = "My LSPS-Compliant Lightning Client";
	let app_name = LSPS5AppName::from_string(raw_app_name.to_string()).unwrap();
	let raw_webhook_url = "https://www.example.org/push?l=1234567890abcdefghijklmnopqrstuv&c=best";
	let webhook_url = LSPS5WebhookUrl::from_string(raw_webhook_url.to_string()).unwrap();

	let request_id = client_handler
		.set_webhook(service_node_id, raw_app_name.to_string(), raw_webhook_url.to_string())
		.expect("Failed to send set_webhook request");
	let set_webhook_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_request, client_node_id)
		.unwrap();

	let webhook_notification_event = service_node.liquidity_manager.next_event().unwrap();
	match webhook_notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			counterparty_node_id,
			app_name: an,
			url,
			notification,
			headers,
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(an, app_name.clone());
			assert_eq!(url, webhook_url);
			let (timestamp, signature) = extract_ts_sig(&headers);

			assert!(timestamp.to_rfc3339().len() > 0, "Timestamp should not be empty");
			assert!(signature.len() > 0, "Signature should not be empty");
			assert_eq!(
				headers.len(),
				3,
				"Should have 3 headers (Content-Type, timestamp, signature)"
			);
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5WebhookRegistered);
		},
		_ => panic!("Expected SendWebhookNotification event"),
	}
	let set_webhook_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response, service_node_id)
		.unwrap();

	let webhook_registered_event = client_node.liquidity_manager.next_event().unwrap();
	match webhook_registered_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRegistered {
			num_webhooks,
			max_webhooks,
			no_change,
			counterparty_node_id: lsp,
			app_name: an,
			url,
			request_id: req_id,
		}) => {
			assert_eq!(num_webhooks, 1);
			assert_eq!(max_webhooks, DEFAULT_MAX_WEBHOOKS_PER_CLIENT);
			assert_eq!(no_change, false);
			assert_eq!(lsp, service_node_id);
			assert_eq!(an, app_name.clone());
			assert_eq!(url, webhook_url);
			assert_eq!(req_id, request_id);
		},
		_ => panic!("Unexpected event"),
	}

	let list_request_id = client_handler.list_webhooks(service_node_id);
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

	let webhooks_list_event = client_node.liquidity_manager.next_event().unwrap();
	match webhooks_list_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhooksListed {
			counterparty_node_id: lsp,
			app_names,
			max_webhooks,
			request_id,
		}) => {
			assert_eq!(lsp, service_node_id);
			assert_eq!(app_names, vec![app_name.clone()]);
			assert_eq!(max_webhooks, DEFAULT_MAX_WEBHOOKS_PER_CLIENT);
			assert_eq!(request_id, list_request_id);
		},
		_ => panic!("Unexpected event"),
	}

	let raw_updated_webhook_url = "https://www.example.org/push?l=updatedtoken&c=best";
	let updated_webhook_url =
		LSPS5WebhookUrl::from_string(raw_updated_webhook_url.to_string()).unwrap();
	let _ = client_handler
		.set_webhook(service_node_id, raw_app_name.to_string(), raw_updated_webhook_url.to_string())
		.expect("Failed to send update webhook request");

	let set_webhook_update_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_update_request, client_node_id)
		.unwrap();

	let webhook_notification_event = service_node.liquidity_manager.next_event().unwrap();
	match webhook_notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			url, ..
		}) => {
			assert_eq!(url, updated_webhook_url);
		},
		_ => panic!("Expected SendWebhookNotification event"),
	}

	let set_webhook_update_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_update_response, service_node_id)
		.unwrap();

	let webhook_update_event = client_node.liquidity_manager.next_event().unwrap();
	match webhook_update_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRegistered {
			counterparty_node_id,
			app_name: an,
			url,
			..
		}) => {
			assert_eq!(counterparty_node_id, service_node_id);
			assert_eq!(an, app_name);
			assert_eq!(url, updated_webhook_url);
		},
		_ => panic!("Unexpected event"),
	}

	let remove_request_id = client_handler
		.remove_webhook(service_node_id, app_name.to_string())
		.expect("Failed to send remove_webhook request");
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

	let webhook_removed_event = client_node.liquidity_manager.next_event().unwrap();
	match webhook_removed_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRemoved {
			counterparty_node_id,
			app_name: an,
			request_id,
		}) => {
			assert_eq!(counterparty_node_id, service_node_id);
			assert_eq!(an, app_name);
			assert_eq!(request_id, remove_request_id);
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn webhook_error_handling_test() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();

	// TEST 1: URL too long error
	let app_name = "Error Test App";

	let long_url = format!("https://example.org/{}", "a".repeat(1024));

	let result = client_handler.set_webhook(service_node_id, app_name.to_string(), long_url);

	assert!(result.is_err(), "Expected error due to URL length");
	let error = result.unwrap_err();
	assert!(error == LSPS5ProtocolError::WebhookUrlTooLong.into());

	// TEST 2: Invalid URL format error
	let invalid_url = "not-a-valid-url";
	let result =
		client_handler.set_webhook(service_node_id, app_name.to_string(), invalid_url.to_string());
	assert!(result.is_err(), "Expected error due to invalid URL format");
	let error = result.unwrap_err();
	assert_eq!(error, LSPS5ProtocolError::UrlParse.into());

	// TEST 3: Unsupported protocol error (not HTTPS)
	let http_url = "http://example.org/webhook";
	let result =
		client_handler.set_webhook(service_node_id, app_name.to_string(), http_url.to_string());
	assert!(result.is_err(), "Expected error due to non-HTTPS protocol");
	let error = result.unwrap_err();
	assert_eq!(error, LSPS5ProtocolError::UnsupportedProtocol.into());

	// TEST 4: App name too long
	let long_app_name = "A".repeat(65);
	let valid_url = "https://example.org/webhook";
	let result = client_handler.set_webhook(service_node_id, long_app_name, valid_url.to_string());
	assert!(result.is_err(), "Expected error due to app name too long");
	let error = result.unwrap_err();
	assert!(error == LSPS5ProtocolError::AppNameTooLong.into());

	// TEST 5: Too many webhooks - register the max number and then try one more
	let valid_app_name_base = "Valid App";
	let valid_url = "https://example.org/webhook";
	for i in 0..DEFAULT_MAX_WEBHOOKS_PER_CLIENT {
		let app_name = format!("{} {}", valid_app_name_base, i);
		let _ = client_handler
			.set_webhook(service_node_id, app_name, valid_url.to_string())
			.expect("Should be able to register webhook");

		let request = get_lsps_message!(client_node, service_node_id);
		service_node.liquidity_manager.handle_custom_message(request, client_node_id).unwrap();

		let response = get_lsps_message!(service_node, client_node_id);
		client_node.liquidity_manager.handle_custom_message(response, service_node_id).unwrap();

		let _ = client_node.liquidity_manager.next_event().unwrap();
	}

	// Now try to add one more webhook - should fail with too many webhooks error
	let raw_one_too_many = format!("{} {}", valid_app_name_base, DEFAULT_MAX_WEBHOOKS_PER_CLIENT);
	let one_too_many = LSPS5AppName::from_string(raw_one_too_many.to_string()).unwrap();
	let _ = client_handler
		.set_webhook(service_node_id, raw_one_too_many.clone(), valid_url.to_string())
		.expect("Request should send but will receive error response");

	let request = get_lsps_message!(client_node, service_node_id);
	let result = service_node.liquidity_manager.handle_custom_message(request, client_node_id);
	assert!(result.is_err(), "Server should return an error for too many webhooks");

	let response = get_lsps_message!(service_node, client_node_id);

	client_node.liquidity_manager.handle_custom_message(response, service_node_id).unwrap();

	let event = client_node.liquidity_manager.next_event().unwrap();
	match event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRegistrationFailed {
			error,
			app_name,
			..
		}) => {
			let error_to_check = LSPS5ProtocolError::TooManyWebhooks;
			assert_eq!(error, error_to_check.into());
			assert_eq!(app_name, one_too_many);
		},
		_ => panic!("Expected WebhookRegistrationFailed event, got {:?}", event),
	}

	// TEST 6: Remove a non-existent webhook
	let raw_nonexistent_app = "NonexistentApp";
	let nonexistent_app = LSPS5AppName::from_string(raw_nonexistent_app.to_string()).unwrap();
	let _ = client_handler
		.remove_webhook(service_node_id, raw_nonexistent_app.to_string())
		.expect("Remove webhook request should send successfully");

	let request = get_lsps_message!(client_node, service_node_id);
	let result = service_node.liquidity_manager.handle_custom_message(request, client_node_id);
	assert!(result.is_err(), "Server should return an error for non-existent webhook");

	let response = get_lsps_message!(service_node, client_node_id);

	client_node.liquidity_manager.handle_custom_message(response, service_node_id).unwrap();

	let event = client_node.liquidity_manager.next_event().unwrap();
	match event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRemovalFailed {
			error,
			app_name,
			..
		}) => {
			assert_eq!(error, LSPS5ProtocolError::AppNameNotFound.into());
			assert_eq!(app_name, nonexistent_app);
		},
		_ => panic!("Expected WebhookRemovalFailed event, got {:?}", event),
	}
}

#[test]
fn webhook_notification_delivery_test() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, validator) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();

	let app_name = "Webhook Test App";
	let webhook_url = "https://www.example.org/push?token=test123";

	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Register webhook request should succeed");
	let set_webhook_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_request, client_node_id)
		.unwrap();

	let notification_event = service_node.liquidity_manager.next_event().unwrap();
	let (timestamp_value, signature_value, notification) = match notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			url,
			headers,
			notification,
			..
		}) => {
			let (timestamp, signature) = extract_ts_sig(&headers);
			assert_eq!(url.as_str(), webhook_url);
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5WebhookRegistered);
			(timestamp, signature, notification)
		},
		_ => panic!("Expected SendWebhookNotification event"),
	};

	let set_webhook_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response, service_node_id)
		.unwrap();

	let _ = client_node.liquidity_manager.next_event().unwrap();

	let result =
		validator.validate(service_node_id, &timestamp_value, &signature_value, &notification);
	assert!(
		result.is_ok(),
		"Client should be able to parse and validate the webhook_registered notification"
	);

	let _ = service_handler.notify_payment_incoming(client_node_id);

	let payment_notification_event = service_node.liquidity_manager.next_event().unwrap();
	let (payment_timestamp, payment_signature, notification) = match payment_notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			url,
			headers,
			notification,
			..
		}) => {
			let (timestamp, signature) = extract_ts_sig(&headers);
			assert_eq!(url.as_str(), webhook_url);
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5PaymentIncoming);
			(timestamp, signature, notification)
		},
		_ => panic!("Expected SendWebhookNotification event for payment_incoming"),
	};

	let result =
		validator.validate(service_node_id, &payment_timestamp, &payment_signature, &notification);
	assert!(
		result.is_ok(),
		"Client should be able to parse and validate the payment_incoming notification"
	);

	let _ = service_handler.notify_payment_incoming(client_node_id);

	assert!(
		service_node.liquidity_manager.next_event().is_none(),
		"No event should be emitted due to cooldown"
	);

	let timeout_block = 700000; // Some future block height
	let _ = service_handler.notify_expiry_soon(client_node_id, timeout_block);

	let expiry_notification_event = service_node.liquidity_manager.next_event().unwrap();
	match expiry_notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			notification,
			..
		}) => {
			assert!(matches!(
				notification.method,
				WebhookNotificationMethod::LSPS5ExpirySoon { timeout } if timeout == timeout_block
			));
		},
		_ => panic!("Expected SendWebhookNotification event for expiry_soon"),
	};
}

#[test]
fn multiple_webhooks_notification_test() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();

	let webhooks = vec![
		("Mobile App", "https://www.example.org/mobile-push?token=abc123"),
		("Desktop App", "https://www.example.org/desktop-push?token=def456"),
		("Web App", "https://www.example.org/web-push?token=ghi789"),
	];

	for (app_name, webhook_url) in &webhooks {
		let _ = client_handler
			.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
			.expect("Register webhook request should succeed");
		let set_webhook_request = get_lsps_message!(client_node, service_node_id);

		service_node
			.liquidity_manager
			.handle_custom_message(set_webhook_request, client_node_id)
			.unwrap();

		// Consume SendWebhookNotification event for webhook_registered
		let _ = service_node.liquidity_manager.next_event().unwrap();

		let set_webhook_response = get_lsps_message!(service_node, client_node_id);
		client_node
			.liquidity_manager
			.handle_custom_message(set_webhook_response, service_node_id)
			.unwrap();

		let _ = client_node.liquidity_manager.next_event().unwrap();
	}

	let _ = service_handler.notify_liquidity_management_request(client_node_id);

	let mut seen_webhooks = HashSet::default();

	for _ in 0..3 {
		let notification_event = service_node.liquidity_manager.next_event().unwrap();
		match notification_event {
			LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
				url,
				notification,
				..
			}) => {
				seen_webhooks.insert(url.as_str().to_string());

				assert_eq!(
					notification.method,
					WebhookNotificationMethod::LSPS5LiquidityManagementRequest
				);
			},
			_ => panic!("Expected SendWebhookNotification event"),
		}
	}

	for (_, webhook_url) in &webhooks {
		assert!(
			seen_webhooks.contains(*webhook_url),
			"Webhook URL {} should have been called",
			webhook_url
		);
	}

	let new_app = "New App";
	let new_webhook = "https://www.example.org/new-push?token=xyz789";

	let _ = client_handler
		.set_webhook(service_node_id, new_app.to_string(), new_webhook.to_string())
		.expect("Register new webhook request should succeed");
	let set_webhook_request = get_lsps_message!(client_node, service_node_id);
	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_request, client_node_id)
		.unwrap();

	let notification_event = service_node.liquidity_manager.next_event().unwrap();
	match notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			url,
			notification,
			..
		}) => {
			assert_eq!(url.as_str(), new_webhook);
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5WebhookRegistered);
		},
		_ => panic!("Expected SendWebhookNotification event"),
	}
}

#[test]
fn idempotency_set_webhook_test() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();

	let app_name = "Idempotency Test App";
	let webhook_url = "https://www.example.org/webhook?token=test123";

	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("First webhook registration should succeed");
	let set_webhook_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_request, client_node_id)
		.unwrap();

	let notification_event = service_node.liquidity_manager.next_event().unwrap();
	match notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification { .. }) => {},
		_ => panic!("Expected SendWebhookNotification event"),
	}

	let set_webhook_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response, service_node_id)
		.unwrap();

	let webhook_registered_event = client_node.liquidity_manager.next_event().unwrap();
	match webhook_registered_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRegistered { no_change, .. }) => {
			assert_eq!(no_change, false, "First registration should have no_change=false");
		},
		_ => panic!("Unexpected event"),
	}

	// Now register the SAME webhook AGAIN (should be idempotent)
	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Second identical webhook registration should succeed");
	let set_webhook_request_again = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_request_again, client_node_id)
		.unwrap();

	assert!(
		service_node.liquidity_manager.next_event().is_none(),
		"No notification should be sent for idempotent operation"
	);

	let set_webhook_response_again = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response_again, service_node_id)
		.unwrap();

	let webhook_registered_again_client_event = client_node.liquidity_manager.next_event().unwrap();
	match webhook_registered_again_client_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRegistered { no_change, .. }) => {
			assert_eq!(no_change, true, "Second identical registration should have no_change=true");
		},
		_ => panic!("Expected WebhookRegistered event for second registration"),
	}

	let updated_webhook_url = "https://www.example.org/webhook?token=updated456";

	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), updated_webhook_url.to_string())
		.expect("Update webhook request should succeed");
	let update_webhook_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(update_webhook_request, client_node_id)
		.unwrap();

	// For an update, a SendWebhookNotification event SHOULD be emitted
	let notification_update_event = service_node.liquidity_manager.next_event().unwrap();
	match notification_update_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			url, ..
		}) => {
			assert_eq!(url.as_str(), updated_webhook_url);
		},
		_ => panic!("Expected SendWebhookNotification event for update"),
	}
}

#[test]
fn replay_prevention_test() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, validator) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();

	let app_name = "Replay Prevention Test App";
	let webhook_url = "https://www.example.org/webhook?token=replay123";

	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Register webhook request should succeed");
	let request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(request, client_node_id).unwrap();

	// Consume initial SendWebhookNotification event
	let _ = service_node.liquidity_manager.next_event().unwrap();

	let response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(response, service_node_id).unwrap();

	let _ = client_node.liquidity_manager.next_event().unwrap();

	let _ = service_handler.notify_payment_incoming(client_node_id);

	let notification_event = service_node.liquidity_manager.next_event().unwrap();
	let (timestamp, signature, body) = match notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			headers,
			notification,
			..
		}) => {
			let (timestamp, signature) = extract_ts_sig(&headers);
			(timestamp, signature, notification)
		},
		_ => panic!("Expected SendWebhookNotification event"),
	};

	// First validation should succeed
	let result = validator.validate(service_node_id, &timestamp, &signature, &body);
	assert!(result.is_ok(), "First verification should succeed");

	// Replaying the same signature immediately should fail
	let replay_result = validator.validate(service_node_id, &timestamp, &signature, &body);
	assert!(replay_result.is_err(), "Immediate replay attack should be detected");
	assert_eq!(replay_result.unwrap_err(), LSPS5ClientError::ReplayAttack);

	// Fill up the validator's signature cache to push out the original signature.
	for i in 0..MAX_RECENT_SIGNATURES {
		let timeout_block = 700000 + i as u32;
		let _ = service_handler.notify_expiry_soon(client_node_id, timeout_block);
		let event = service_node.liquidity_manager.next_event().unwrap();
		if let LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			headers,
			notification,
			..
		}) = event
		{
			let (ts, sig) = extract_ts_sig(&headers);
			let res = validator.validate(service_node_id, &ts, &sig, &notification);
			assert!(res.is_ok(), "Validation of unique signature #{} should succeed", i);
		} else {
			panic!("Expected SendWebhookNotification event");
		}
	}

	// The original signature should now be evicted from the cache. Replaying it again should now succeed.
	let replay_after_eviction_result =
		validator.validate(service_node_id, &timestamp, &signature, &body);

	assert!(
		replay_after_eviction_result.is_ok(),
		"Replay attack should succeed after original signature is evicted from cache"
	);
}

#[test]
fn stale_webhooks() {
	let mock_time_provider = Arc::new(MockTimeProvider::new(1000));
	let time_provider = Arc::<MockTimeProvider>::clone(&mock_time_provider);
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = lsps5_test_setup(nodes, time_provider);
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();

	let raw_app_name = "StaleApp";
	let app_name = LSPS5AppName::from_string(raw_app_name.to_string()).unwrap();
	let raw_webhook_url = "https://example.org/stale";
	let _ = LSPS5WebhookUrl::from_string(raw_webhook_url.to_string()).unwrap();
	let _ = client_handler
		.set_webhook(service_node_id, raw_app_name.to_string(), raw_webhook_url.to_string())
		.unwrap();
	let req = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(req, client_node_id).unwrap();

	// consume initial SendWebhookNotification
	let _ = service_node.liquidity_manager.next_event().unwrap();

	let resp = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(resp, service_node_id).unwrap();
	let _ = client_node.liquidity_manager.next_event().unwrap();

	// LIST before prune -> should contain our webhook
	let _ = client_handler.list_webhooks(service_node_id);
	let list_req = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(list_req, client_node_id).unwrap();

	let list_resp = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(list_resp, service_node_id).unwrap();
	let list_cli = client_node.liquidity_manager.next_event().unwrap();
	match list_cli {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhooksListed { app_names, .. }) => {
			assert_eq!(app_names, vec![app_name.clone()]);
		},
		_ => panic!("Expected WebhooksListed before prune (client)"),
	}

	mock_time_provider.advance_time(
		MIN_WEBHOOK_RETENTION_DAYS.as_secs() + PRUNE_STALE_WEBHOOKS_INTERVAL_DAYS.as_secs(),
	);

	// LIST calls prune before executing -> should be empty after advancing time
	let _ = client_handler.list_webhooks(service_node_id);
	let list_req2 = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(list_req2, client_node_id).unwrap();

	let list_resp2 = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(list_resp2, service_node_id).unwrap();
	let list_cli2 = client_node.liquidity_manager.next_event().unwrap();
	match list_cli2 {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhooksListed { app_names, .. }) => {
			println!("App names after prune: {:?}", app_names);
			assert!(app_names.is_empty(), "Expected no webhooks after prune (client)");
		},
		_ => panic!("Expected WebhooksListed after prune (client)"),
	}
}

#[test]
fn test_all_notifications() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, validator) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();

	let app_name = "OnionApp";
	let webhook_url = "https://www.example.org/onion";
	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Register webhook request should succeed");
	let set_req = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(set_req, client_node_id).unwrap();

	// consume initial SendWebhookNotification
	let _ = service_node.liquidity_manager.next_event().unwrap();

	let _ = service_handler.notify_onion_message_incoming(client_node_id);
	let _ = service_handler.notify_payment_incoming(client_node_id);
	let _ = service_handler.notify_expiry_soon(client_node_id, 1000);
	let _ = service_handler.notify_liquidity_management_request(client_node_id);

	let expected_notifications = vec![
		WebhookNotificationMethod::LSPS5OnionMessageIncoming,
		WebhookNotificationMethod::LSPS5PaymentIncoming,
		WebhookNotificationMethod::LSPS5ExpirySoon { timeout: 1000 },
		WebhookNotificationMethod::LSPS5LiquidityManagementRequest,
	];

	for expected_method in expected_notifications {
		let event = service_node.liquidity_manager.next_event().unwrap();
		if let LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			url,
			headers,
			notification,
			..
		}) = event
		{
			assert_eq!(url.as_str(), webhook_url);
			assert_eq!(notification.method, expected_method);
			let (timestamp, signature) = extract_ts_sig(&headers);

			let parse_result =
				validator.validate(service_node_id, &timestamp, &signature, &notification);
			assert!(parse_result.is_ok(), "Failed to parse {:?} notification", expected_method);
		} else {
			panic!("Unexpected event: {:?}", event);
		}
	}
}

#[test]
fn test_tampered_notification() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, validator) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();

	let app_name = "OnionApp";
	let webhook_url = "https://www.example.org/onion";
	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Register webhook request should succeed");
	let set_req = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(set_req, client_node_id).unwrap();

	// consume initial SendWebhookNotification
	let _ = service_node.liquidity_manager.next_event().unwrap();

	let _ = service_handler.notify_expiry_soon(client_node_id, 700000);

	let event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
		url: _,
		headers,
		notification,
		..
	}) = event
	{
		let notification_json = serde_json::to_string(&notification).unwrap();
		let mut json_value: serde_json::Value = serde_json::from_str(&notification_json).unwrap();
		json_value["params"]["timeout"] = serde_json::json!(800000);
		let tampered_timeout_json = json_value.to_string();

		let tampered_notification: WebhookNotification =
			serde_json::from_str(&tampered_timeout_json).unwrap();
		let (timestamp, signature) = extract_ts_sig(&headers);
		let tampered_result =
			validator.validate(service_node_id, &timestamp, &signature, &tampered_notification);
		assert_eq!(tampered_result.unwrap_err(), LSPS5ClientError::InvalidSignature);
	} else {
		panic!("Unexpected event: {:?}", event);
	}

	assert!(client_node.liquidity_manager.next_event().is_none());
}

#[test]
fn test_bad_signature_notification() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, validator) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();

	let app_name = "OnionApp";
	let webhook_url = "https://www.example.org/onion";
	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.unwrap();
	let set_req = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(set_req, client_node_id).unwrap();

	// consume initial SendWebhookNotification
	let _ = service_node.liquidity_manager.next_event().unwrap();

	let _ = service_handler.notify_onion_message_incoming(client_node_id);

	let event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
		url: _,
		headers,
		notification,
		..
	}) = event
	{
		let (timestamp, _) = extract_ts_sig(&headers);

		let invalid_signature = "xdtk1zf63sfn81r6qteymy73mb1b7dspj5kwx46uxwd6c3pu7y3bto";
		let bad_signature_result =
			validator.validate(service_node_id, &timestamp, &invalid_signature, &notification);
		assert!(bad_signature_result.unwrap_err() == LSPS5ClientError::InvalidSignature);
	} else {
		panic!("Unexpected event: {:?}", event);
	}

	assert!(client_node.liquidity_manager.next_event().is_none());
}

#[test]
fn test_notify_without_webhooks_does_nothing() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = lsps5_test_setup(nodes, Arc::new(DefaultTimeProvider));
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let client_node_id = client_node.inner.node.get_our_node_id();

	let service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();

	// without ever registering a webhook -> both notifiers should early-return
	let _ = service_handler.notify_payment_incoming(client_node_id);
	assert!(service_node.liquidity_manager.next_event().is_none());

	let _ = service_handler.notify_onion_message_incoming(client_node_id);
	assert!(service_node.liquidity_manager.next_event().is_none());
}

#[test]
fn test_send_notifications_and_peer_connected_resets_cooldown() {
	let mock_time_provider = Arc::new(MockTimeProvider::new(1000));
	let time_provider = Arc::<MockTimeProvider>::clone(&mock_time_provider);
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = lsps5_test_setup(nodes, time_provider);
	let LSPSNodes { service_node, client_node } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps5_service_handler().unwrap();

	let app_name = "CooldownTestApp";
	let webhook_url = "https://www.example.org/cooldown";
	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Register webhook request should succeed");
	let set_req = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(set_req, client_node_id).unwrap();

	let _ = service_node.liquidity_manager.next_event().unwrap();

	let resp = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(resp, service_node_id).unwrap();
	let _ = client_node.liquidity_manager.next_event().unwrap();

	// 1. First notification should be sent
	let _ = service_handler.notify_payment_incoming(client_node_id);
	let event = service_node.liquidity_manager.next_event().unwrap();
	match event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			notification,
			..
		}) => {
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5PaymentIncoming);
		},
		_ => panic!("Expected SendWebhookNotification event"),
	}

	// 2. Second notification before cooldown should NOT be sent
	let _ = service_handler.notify_payment_incoming(client_node_id);
	assert!(
		service_node.liquidity_manager.next_event().is_none(),
		"Should not emit event due to cooldown"
	);

	// 3. Notification of a different method CAN be sent
	let timeout_block = 424242;
	let _ = service_handler.notify_expiry_soon(client_node_id, timeout_block);
	let event = service_node.liquidity_manager.next_event().unwrap();
	match event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			notification,
			..
		}) => {
			assert!(matches!(
				notification.method,
				WebhookNotificationMethod::LSPS5ExpirySoon { timeout } if timeout == timeout_block
			));
		},
		_ => panic!("Expected SendWebhookNotification event for expiry_soon"),
	}

	// 4. Advance time past cooldown and ensure payment_incoming can be sent again
	mock_time_provider.advance_time(DEFAULT_NOTIFICATION_COOLDOWN_HOURS.as_secs() + 1);

	let _ = service_handler.notify_payment_incoming(client_node_id);
	let event = service_node.liquidity_manager.next_event().unwrap();
	match event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			notification,
			..
		}) => {
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5PaymentIncoming);
		},
		_ => panic!("Expected SendWebhookNotification event after cooldown"),
	}

	// 5. Can't send payment_incoming notification again immediately after cooldown
	let _ = service_handler.notify_payment_incoming(client_node_id);
	assert!(
		service_node.liquidity_manager.next_event().is_none(),
		"Should not emit event due to cooldown"
	);

	// 6. After peer_connected, notification should be sent again immediately
	let init_msg = Init {
		features: lightning_types::features::InitFeatures::empty(),
		remote_network_address: None,
		networks: None,
	};
	service_node.liquidity_manager.peer_connected(client_node_id, &init_msg, false).unwrap();
	let _ = service_handler.notify_payment_incoming(client_node_id);
	let event = service_node.liquidity_manager.next_event().unwrap();
	match event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotification {
			notification,
			..
		}) => {
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5PaymentIncoming);
		},
		_ => panic!("Expected SendWebhookNotification event after peer_connected"),
	}
}
