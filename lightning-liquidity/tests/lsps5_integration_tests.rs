#![cfg(all(test, feature = "time"))]

mod common;

use common::{get_client_and_service, get_lsps_message};
use lightning::ln::msgs::LightningError;
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::util::hash_tables::HashSet;
use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps5::event::{LSPS5ClientEvent, LSPS5ServiceEvent};
use lightning_liquidity::lsps5::msgs::{
	LSPS5AppName, LSPS5WebhookUrl, WebhookNotification, WebhookNotificationMethod,
};
use lightning_liquidity::lsps5::service::LSPS5ServiceConfig;

#[test]
fn webhook_registration_flow() {
	let (client_handler, _, service_node_id, client_node_id, service_node, client_node) =
		get_client_and_service();

	let raw_app_name = "My LSPS-Compliant Lightning Client";
	let app_name = LSPS5AppName::new(raw_app_name.to_string()).unwrap();
	let raw_webhook_url = "https://www.example.org/push?l=1234567890abcdefghijklmnopqrstuv&c=best";
	let webhook_url = LSPS5WebhookUrl::new(raw_webhook_url.to_string()).unwrap();

	let request_id = client_handler
		.set_webhook(service_node_id, raw_app_name.to_string(), raw_webhook_url.to_string())
		.expect("Failed to send set_webhook request");
	let set_webhook_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_request, client_node_id)
		.unwrap();

	let set_webhook_event = service_node.liquidity_manager.next_event().unwrap();

	match set_webhook_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::WebhookRegistered {
			counterparty_node_id,
			app_name: an,
			url: wu,
			no_change,
			request_id: req_id,
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(an, app_name.clone());
			assert_eq!(wu, webhook_url);
			assert_eq!(no_change, false);
			assert_eq!(req_id, request_id);
		},
		_ => panic!("Unexpected event"),
	}

	let webhook_notification_event = service_node.liquidity_manager.next_event().unwrap();
	match webhook_notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
			counterparty_node_id,
			app_name: an,
			url,
			notification,
			timestamp,
			signature,
			headers,
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(an, app_name.clone());
			assert_eq!(url, webhook_url);
			assert!(timestamp.len() > 0, "Timestamp should not be empty");
			assert!(signature.len() > 0, "Signature should not be empty");
			assert_eq!(
				headers.len(),
				3,
				"Should have 3 headers (Content-Type, timestamp, signature)"
			);
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5WebhookRegistered);
		},
		_ => panic!("Expected SendWebhookNotifications event"),
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
			assert_eq!(max_webhooks, LSPS5ServiceConfig::default().max_webhooks_per_client);
			assert_eq!(no_change, false);
			assert_eq!(lsp, service_node_id);
			assert_eq!(an, app_name.clone());
			assert_eq!(url, webhook_url);
			assert_eq!(req_id, request_id);
		},
		_ => panic!("Unexpected event"),
	}

	let list_request_id = client_handler
		.list_webhooks(service_node_id)
		.expect("Failed to send list_webhooks request");
	let list_webhooks_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(list_webhooks_request, client_node_id)
		.unwrap();

	let list_webhooks_event = service_node.liquidity_manager.next_event().unwrap();

	match list_webhooks_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::WebhooksListed {
			app_names,
			counterparty_node_id,
			max_webhooks,
			request_id: req_id,
		}) => {
			assert_eq!(app_names, vec![app_name.clone()]);
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(max_webhooks, LSPS5ServiceConfig::default().max_webhooks_per_client);
			assert_eq!(req_id, list_request_id);
		},
		_ => panic!("Unexpected event"),
	}

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
			assert_eq!(max_webhooks, LSPS5ServiceConfig::default().max_webhooks_per_client);
			assert_eq!(request_id, list_request_id);
		},
		_ => panic!("Unexpected event"),
	}

	let raw_updated_webhook_url = "https://www.example.org/push?l=updatedtoken&c=best";
	let updated_webhook_url = LSPS5WebhookUrl::new(raw_updated_webhook_url.to_string()).unwrap();
	let update_request_id = client_handler
		.set_webhook(service_node_id, raw_app_name.to_string(), raw_updated_webhook_url.to_string())
		.expect("Failed to send update webhook request");

	let set_webhook_update_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_update_request, client_node_id)
		.unwrap();

	let set_webhook_update_event = service_node.liquidity_manager.next_event().unwrap();
	match set_webhook_update_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::WebhookRegistered {
			counterparty_node_id,
			app_name: an,
			url: wu,
			no_change,
			request_id: req_id,
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(an, app_name);
			assert_eq!(wu, updated_webhook_url);
			assert_eq!(no_change, false);
			assert_eq!(req_id, update_request_id);
		},
		_ => panic!("Unexpected event"),
	}

	let webhook_notification_event = service_node.liquidity_manager.next_event().unwrap();
	match webhook_notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
			url, ..
		}) => {
			assert_eq!(url, updated_webhook_url);
		},
		_ => panic!("Expected SendWebhookNotifications event"),
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

	let remove_webhook_event = service_node.liquidity_manager.next_event().unwrap();
	match remove_webhook_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::WebhookRemoved {
			counterparty_node_id,
			app_name: an,
			request_id: req_id,
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(an, app_name);
			assert_eq!(req_id, remove_request_id);
		},
		_ => panic!("Unexpected event"),
	}

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
	let (client_handler, _, service_node_id, client_node_id, service_node, client_node) =
		get_client_and_service();

	// TEST 1: URL too long error
	let app_name = "Error Test App";

	let long_url = format!("https://example.org/{}", "a".repeat(1024));

	let result = client_handler.set_webhook(service_node_id, app_name.to_string(), long_url);

	assert!(result.is_err(), "Expected error due to URL length");
	let err_message = result.unwrap_err().err;
	assert!(
		err_message.contains("exceeds maximum length"),
		"Error message should mention length: {}",
		err_message
	);

	// TEST 2: Invalid URL format error
	let invalid_url = "not-a-valid-url";
	let result =
		client_handler.set_webhook(service_node_id, app_name.to_string(), invalid_url.to_string());
	assert!(result.is_err(), "Expected error due to invalid URL format");
	let err_message = result.unwrap_err().err;
	assert!(
		err_message.contains("Error parsing URL"),
		"Error message should mention parse failure: {}",
		err_message
	);

	// TEST 3: Unsupported protocol error (not HTTPS)
	let http_url = "http://example.org/webhook";
	let result =
		client_handler.set_webhook(service_node_id, app_name.to_string(), http_url.to_string());
	assert!(result.is_err(), "Expected error due to non-HTTPS protocol");
	let err_message = result.unwrap_err().err;
	assert!(
		err_message.contains("Unsupported protocol"),
		"Error message should mention protocol: {}",
		err_message
	);

	// TEST 4: App name too long
	let long_app_name = "A".repeat(65);
	let valid_url = "https://example.org/webhook";
	let result = client_handler.set_webhook(service_node_id, long_app_name, valid_url.to_string());
	assert!(result.is_err(), "Expected error due to app name too long");
	let err_message = result.unwrap_err().err;
	assert!(
		err_message.contains("exceeds maximum length"),
		"Error message should mention length: {}",
		err_message
	);

	// TEST 5: Too many webhooks - register the max number and then try one more
	let valid_app_name_base = "Valid App";
	let valid_url = "https://example.org/webhook";

	for i in 0..LSPS5ServiceConfig::default().max_webhooks_per_client {
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
	let raw_one_too_many = format!(
		"{} {}",
		valid_app_name_base,
		LSPS5ServiceConfig::default().max_webhooks_per_client
	);
	let one_too_many = LSPS5AppName::new(raw_one_too_many.to_string()).unwrap();
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
			error_code,
			error_message,
			app_name,
			..
		}) => {
			// TOO_MANY_WEBHOOKS error code from spec
			assert_eq!(error_code, 503);
			assert_eq!(app_name, one_too_many);
			assert!(
				error_message.contains("Maximum of"),
				"Error message should mention max webhooks: {}",
				error_message
			);
		},
		_ => panic!("Expected WebhookRegistrationFailed event, got {:?}", event),
	}

	// TEST 6: Remove a non-existent webhook
	let raw_nonexistent_app = "NonexistentApp";
	let nonexistent_app = LSPS5AppName::new(raw_nonexistent_app.to_string()).unwrap();
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
			error_code,
			error_message,
			app_name,
			..
		}) => {
			assert_eq!(error_code, 1010);
			assert_eq!(app_name, nonexistent_app);
			assert!(
				error_message.contains("App name not found"),
				"Error message should mention app name not found: {}",
				error_message
			);
		},
		_ => panic!("Expected WebhookRemovalFailed event, got {:?}", event),
	}

	// TEST 7: URL with security issues (localhost)
	let localhost_url = "https://localhost/webhook";
	let result = client_handler.set_webhook(
		service_node_id,
		"Localhost App".to_string(),
		localhost_url.to_string(),
	);
	assert!(result.is_err(), "Expected error due to localhost URL");
	let err_message = result.unwrap_err().err;
	assert!(
		err_message.contains("localhost"),
		"Error message should mention localhost: {}",
		err_message
	);

	// TEST 8: URL with security issues (private IP)
	let private_ip_url = "https://192.168.1.1/webhook";
	let result = client_handler.set_webhook(
		service_node_id,
		"Private IP App".to_string(),
		private_ip_url.to_string(),
	);
	assert!(result.is_err(), "Expected error due to private IP URL");
	let err_message = result.unwrap_err().err;
	assert!(
		err_message.contains("private IP"),
		"Error message should mention private IP: {}",
		err_message
	);
}

#[test]
fn webhook_notification_delivery_test() {
	let (client_handler, _, service_node_id, client_node_id, service_node, client_node) =
		get_client_and_service();

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

	let _ = service_node.liquidity_manager.next_event().unwrap();

	let notification_event = service_node.liquidity_manager.next_event().unwrap();
	let (timestamp_value, signature_value, notification_json) = match notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
			url,
			timestamp,
			signature,
			headers: _,
			notification,
			..
		}) => {
			assert_eq!(url.as_str(), webhook_url);
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5WebhookRegistered);
			(timestamp, signature, serde_json::to_string(&notification).unwrap())
		},
		_ => panic!("Expected SendWebhookNotifications event"),
	};

	let set_webhook_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response, service_node_id)
		.unwrap();

	let _ = client_node.liquidity_manager.next_event().unwrap();

	let result = client_handler.parse_webhook_notification(
		service_node_id,
		&timestamp_value,
		&signature_value,
		&notification_json,
	);
	assert!(
		result.is_ok(),
		"Client should be able to parse and validate the webhook_registered notification"
	);

	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_payment_incoming(client_node_id)
		.is_ok());

	let payment_notification_event = service_node.liquidity_manager.next_event().unwrap();
	let (payment_timestamp, payment_signature, payment_json) = match payment_notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
			url,
			timestamp,
			signature,
			notification,
			..
		}) => {
			assert_eq!(url.as_str(), webhook_url);
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5PaymentIncoming);
			(timestamp, signature, serde_json::to_string(&notification).unwrap())
		},
		_ => panic!("Expected SendWebhookNotifications event for payment_incoming"),
	};

	let result = client_handler.parse_webhook_notification(
		service_node_id,
		&payment_timestamp,
		&payment_signature,
		&payment_json,
	);
	assert!(
		result.is_ok(),
		"Client should be able to parse and validate the payment_incoming notification"
	);

	let notification = result.unwrap();
	assert_eq!(
		notification.method,
		WebhookNotificationMethod::LSPS5PaymentIncoming,
		"Parsed notification should be payment_incoming"
	);

	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_payment_incoming(client_node_id)
		.is_ok());

	assert!(
		service_node.liquidity_manager.next_event().is_none(),
		"No event should be emitted due to cooldown"
	);

	let timeout_block = 700000; // Some future block height
	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_expiry_soon(client_node_id, timeout_block)
		.is_ok());

	let expiry_notification_event = service_node.liquidity_manager.next_event().unwrap();
	match expiry_notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
			notification,
			..
		}) => {
			assert!(matches!(
				notification.method,
				WebhookNotificationMethod::LSPS5ExpirySoon { timeout } if timeout == timeout_block
			));
		},
		_ => panic!("Expected SendWebhookNotifications event for expiry_soon"),
	};
}

#[test]
fn multiple_webhooks_notification_test() {
	let (client_handler, _, service_node_id, client_node_id, service_node, client_node) =
		get_client_and_service();

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

		// Consume WebhookRegistered event
		let _ = service_node.liquidity_manager.next_event().unwrap();
		// Consume SendWebhookNotifications event for webhook_registered
		let _ = service_node.liquidity_manager.next_event().unwrap();

		let set_webhook_response = get_lsps_message!(service_node, client_node_id);
		client_node
			.liquidity_manager
			.handle_custom_message(set_webhook_response, service_node_id)
			.unwrap();

		let _ = client_node.liquidity_manager.next_event().unwrap();
	}

	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_liquidity_management_request(client_node_id)
		.is_ok());

	let mut seen_webhooks = HashSet::default();

	for _ in 0..3 {
		let notification_event = service_node.liquidity_manager.next_event().unwrap();
		match notification_event {
			LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
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
			_ => panic!("Expected SendWebhookNotifications event"),
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

	let _ = service_node.liquidity_manager.next_event().unwrap();

	let notification_event = service_node.liquidity_manager.next_event().unwrap();
	match notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
			url,
			notification,
			..
		}) => {
			assert_eq!(url.as_str(), new_webhook);
			assert_eq!(notification.method, WebhookNotificationMethod::LSPS5WebhookRegistered);
		},
		_ => panic!("Expected SendWebhookNotifications event"),
	}
}

#[test]
fn idempotency_set_webhook_test() {
	let (client_handler, _, service_node_id, client_node_id, service_node, client_node) =
		get_client_and_service();

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

	let _ = service_node.liquidity_manager.next_event().unwrap();

	let notification_event = service_node.liquidity_manager.next_event().unwrap();
	match notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications { .. }) => {},
		_ => panic!("Expected SendWebhookNotifications event"),
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

	let webhook_registered_again_event = service_node.liquidity_manager.next_event().unwrap();
	match webhook_registered_again_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::WebhookRegistered {
			no_change, ..
		}) => {
			// Second registration with same parameters should be a no_change
			assert_eq!(no_change, true, "Second identical registration should have no_change=true");
		},
		_ => panic!("Unexpected event"),
	}

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

	let webhook_updated_event = service_node.liquidity_manager.next_event().unwrap();
	match webhook_updated_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::WebhookRegistered {
			no_change, ..
		}) => {
			assert_eq!(no_change, false, "Update with different URL should have no_change=false");
		},
		_ => panic!("Expected WebhookRegistered event for update"),
	}

	// For an update, a SendWebhookNotifications event SHOULD be emitted
	let notification_update_event = service_node.liquidity_manager.next_event().unwrap();
	match notification_update_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
			url, ..
		}) => {
			assert_eq!(url.as_str(), updated_webhook_url);
		},
		_ => panic!("Expected SendWebhookNotifications event for update"),
	}
}

#[test]
fn replay_prevention_test() {
	let (client_handler, _, service_node_id, client_node_id, service_node, client_node) =
		get_client_and_service();

	let app_name = "Replay Prevention Test App";
	let webhook_url = "https://www.example.org/webhook?token=replay123";

	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Register webhook request should succeed");
	let request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(request, client_node_id).unwrap();

	let _ = service_node.liquidity_manager.next_event().unwrap();
	let _ = service_node.liquidity_manager.next_event().unwrap();

	let response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(response, service_node_id).unwrap();

	let _ = client_node.liquidity_manager.next_event().unwrap();

	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_payment_incoming(client_node_id)
		.is_ok());

	let notification_event = service_node.liquidity_manager.next_event().unwrap();
	let (timestamp, signature, body) = match notification_event {
		LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::SendWebhookNotifications {
			timestamp,
			signature,
			notification,
			..
		}) => (timestamp, signature, serde_json::to_string(&notification).unwrap()),
		_ => panic!("Expected SendWebhookNotifications event"),
	};

	let result: Result<WebhookNotification, LightningError> =
		client_handler.parse_webhook_notification(service_node_id, &timestamp, &signature, &body);
	assert!(result.is_ok(), "First verification should succeed");

	// Try again with same timestamp and signature (simulate replay attack)
	let replay_result: Result<WebhookNotification, LightningError> =
		client_handler.parse_webhook_notification(service_node_id, &timestamp, &signature, &body);

	// This should now fail since we've implemented replay prevention
	assert!(replay_result.is_err(), "Replay attack should be detected and rejected");

	let err = replay_result.unwrap_err();
	assert!(
		err.err.contains("Replay attack detected")
			|| err.err.contains("signature has been used before"),
		"Error should mention replay detection: {}",
		err.err
	);
}
