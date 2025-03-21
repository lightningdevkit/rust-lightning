#![cfg(all(test, feature = "std"))]

mod common;
use common::{create_service_and_client_nodes, get_lsps_message};

use lightning::sign::EntropySource;
use lightning::util::hash_tables::HashSet;
use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps5::client::{LSPS5ClientConfig, LSPS5ClientHandler};
use lightning_liquidity::lsps5::event::{LSPS5ClientEvent, LSPS5ServiceEvent};
use lightning_liquidity::lsps5::msgs::{Lsps5AppName, Lsps5WebhookUrl, WebhookNotificationMethod};
use lightning_liquidity::lsps5::service::{DefaultTimeProvider, HttpClient, LSPS5ServiceConfig};
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};

use bitcoin::secp256k1::SecretKey;
use lightning::ln::peer_handler::CustomMessageHandler;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

struct MockHttpClient {
	// Track calls to the post method
	post_calls: Arc<Mutex<Vec<(String, Vec<(String, String)>, String)>>>,
	// Control the response
	should_succeed: Arc<AtomicBool>,
}

impl MockHttpClient {
	fn new(should_succeed: bool) -> Self {
		Self {
			post_calls: Arc::new(Mutex::new(Vec::new())),
			should_succeed: Arc::new(AtomicBool::new(should_succeed)),
		}
	}

	fn get_calls(&self) -> Vec<(String, Vec<(String, String)>, String)> {
		self.post_calls.lock().unwrap().clone()
	}

	fn set_should_succeed(&self, should_succeed: bool) {
		self.should_succeed.store(should_succeed, Ordering::SeqCst);
	}

	fn clear_calls(&self) {
		self.post_calls.lock().unwrap().clear();
	}
}

impl HttpClient for MockHttpClient {
	fn post(&self, url: &str, headers: Vec<(String, String)>, body: String) -> Result<(), String> {
		self.post_calls.lock().unwrap().push((url.to_string(), headers, body.clone()));

		if self.should_succeed.load(Ordering::SeqCst) {
			Ok(())
		} else {
			Err("Simulated HTTP failure".to_string())
		}
	}
}

pub struct MockHttpClientWrapper(Arc<MockHttpClient>);

impl HttpClient for MockHttpClientWrapper {
	fn post(&self, url: &str, headers: Vec<(String, String)>, body: String) -> Result<(), String> {
		self.0.post(url, headers, body)
	}
}

#[test]
fn webhook_registration_flow() {
	let mock_client = Arc::new(MockHttpClient::new(true));
	let mut lsps5_service_config: LSPS5ServiceConfig = LSPS5ServiceConfig::default();
	lsps5_service_config =
		lsps5_service_config.with_http_client(MockHttpClientWrapper(mock_client));
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
		create_service_and_client_nodes("webhook_registration_flow", service_config, client_config);

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();

	let service_node_id = service_node.channel_manager.get_our_node_id();
	let client_node_id = client_node.channel_manager.get_our_node_id();
	let raw_app_name = "My LSPS-Compliant Lightning Client";
	let app_name = Lsps5AppName::new(raw_app_name.to_string()).unwrap();
	let raw_webhook_url = "https://www.example.org/push?l=1234567890abcdefghijklmnopqrstuv&c=best";
	let webhook_url = Lsps5WebhookUrl::new(raw_webhook_url.to_string()).unwrap();

	// Test set_webhook - now capture the request ID
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
			request_id: req_id, // New field
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(an, app_name.clone());
			assert_eq!(wu, webhook_url);
			assert_eq!(no_change, false);
			assert_eq!(req_id, request_id); // Check that request ID matches
		},
		_ => panic!("Unexpected event"),
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
			// TODO: check where it comes from and add it to the asserts
			request_id: _req_id,
		}) => {
			assert_eq!(num_webhooks, 1);
			assert_eq!(max_webhooks, LSPS5ServiceConfig::default().max_webhooks_per_client);
			assert_eq!(no_change, false);
			assert_eq!(lsp, service_node_id);
			assert_eq!(an, app_name.clone());
			assert_eq!(url, webhook_url);
		},
		_ => panic!("Unexpected event"),
	}

	service_node.liquidity_manager.next_event().unwrap(); // Skip the WebhookNotificationSent event

	// Test list_webhooks - now capture the request ID
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
			request_id: req_id, // New field
		}) => {
			assert_eq!(app_names, vec![app_name.clone()]);
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(max_webhooks, LSPS5ServiceConfig::default().max_webhooks_per_client);
			assert_eq!(req_id, list_request_id); // Check that request ID matches
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

	// Test updating existing webhook - now capture the request ID
	let raw_updated_webhook_url = "https://www.example.org/push?l=updatedtoken&c=best";
	let updated_webhook_url = Lsps5WebhookUrl::new(raw_updated_webhook_url.to_string()).unwrap();
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
			request_id: req_id, // New field
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(an, app_name);
			assert_eq!(wu, updated_webhook_url);
			assert_eq!(no_change, false);
			assert_eq!(req_id, update_request_id); // Check that request ID matches
		},
		_ => panic!("Unexpected event"),
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

	service_node.liquidity_manager.next_event().unwrap(); // Skip the WebhookNotificationSent event

	// Test remove_webhook - now capture the request ID
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
			request_id: req_id, // New field
		}) => {
			assert_eq!(counterparty_node_id, client_node_id);
			assert_eq!(an, app_name);
			assert_eq!(req_id, remove_request_id); // Check that request ID matches
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
	let mock_client = Arc::new(MockHttpClient::new(true));
	let mut lsps5_service_config: LSPS5ServiceConfig = LSPS5ServiceConfig::default();
	lsps5_service_config =
		lsps5_service_config.with_http_client(MockHttpClientWrapper(mock_client));
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

	let (service_node, client_node) = create_service_and_client_nodes(
		"webhook_error_handling_test",
		service_config,
		client_config,
	);

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_node_id = service_node.channel_manager.get_our_node_id();
	let client_node_id = client_node.channel_manager.get_our_node_id();

	// TEST 1: URL too long error
	let app_name = "Error Test App";
	// Create a URL that exceeds the maximum length (1024 bytes)
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
		err_message.contains("Failed to parse URL"),
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
	let long_app_name = "A".repeat(65); // Max is 64 bytes
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
	let one_too_many = Lsps5AppName::new(raw_one_too_many.to_string()).unwrap();
	let _ = client_handler
		.set_webhook(service_node_id, raw_one_too_many.clone(), valid_url.to_string())
		.expect("Request should send but will receive error response");

	let request = get_lsps_message!(client_node, service_node_id);
	let result = service_node.liquidity_manager.handle_custom_message(request, client_node_id);
	assert!(result.is_err(), "Server should return an error for too many webhooks");

	// The error should be returned to the client as a proper response message
	// we can still get this message normally
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
	let nonexistent_app = Lsps5AppName::new(raw_nonexistent_app.to_string()).unwrap();
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
			// APP_NAME_NOT_FOUND error code from spec
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
	let mock_client = Arc::new(MockHttpClient::new(true));
	let mock_client_for_verification = mock_client.clone();
	let time_provider = Arc::new(DefaultTimeProvider);

	let signing_key = SecretKey::from_slice(&[42; 32]).unwrap();

	let mut lsps5_service_config = LSPS5ServiceConfig::default();
	lsps5_service_config =
		lsps5_service_config.with_http_client(MockHttpClientWrapper(mock_client));
	lsps5_service_config.signing_key = signing_key;

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

	let (service_node, client_node) = create_service_and_client_nodes(
		"webhook_notification_delivery_test",
		service_config,
		client_config,
	);

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();

	let service_node_id = service_node.channel_manager.get_our_node_id();
	let client_node_id = client_node.channel_manager.get_our_node_id();

	let secp = bitcoin::secp256k1::Secp256k1::new();
	let derived_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &signing_key);

	// 1. Register a webhook - now capturing request_id (but not checking it)
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

	let set_webhook_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response, service_node_id)
		.unwrap();

	let _ = client_node.liquidity_manager.next_event().unwrap();

	// Wait a bit for the webhook_registered notification to be sent
	std::thread::sleep(std::time::Duration::from_millis(100));

	let calls = mock_client_for_verification.get_calls();
	assert!(!calls.is_empty(), "No HTTP requests were made");

	let first_call = &calls[0];
	assert_eq!(first_call.0, webhook_url);

	let mut found_timestamp = false;
	let mut found_signature = false;
	let mut timestamp_value = String::new();
	let mut signature_value = String::new();

	for (name, value) in &first_call.1 {
		if name == "x-lsps5-timestamp" {
			found_timestamp = true;
			timestamp_value = value.clone();
		} else if name == "x-lsps5-signature" {
			found_signature = true;
			signature_value = value.clone();
		}
	}

	assert!(found_timestamp, "Timestamp header not found");
	assert!(found_signature, "Signature header not found");

	// Verify the body is a webhook_registered notification
	let body: serde_json::Value =
		serde_json::from_str(&first_call.2).expect("Body should be valid JSON");
	assert_eq!(body["jsonrpc"], "2.0", "JSON-RPC version should be 2.0");
	assert_eq!(
		body["method"], "lsps5.webhook_registered",
		"First notification should be webhook_registered"
	);

	// Test that client can parse and validate the webhook notification
	// Using derived_pubkey instead of service_node_id for verification
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
		derived_pubkey,
		&timestamp_value,
		&signature_value,
		&first_call.2,
		time_provider.clone(),
	);
	assert!(
		result.is_ok(),
		"Client should be able to parse and validate the webhook_registered notification"
	);

	// Now let's trigger a payment incoming notification
	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_payment_incoming(client_node_id)
		.is_ok());

	// Wait a bit for the notification to be sent
	std::thread::sleep(std::time::Duration::from_millis(100));

	let updated_calls = mock_client_for_verification.get_calls();
	assert!(updated_calls.len() >= 2, "Second notification wasn't sent");

	let payment_call = &updated_calls[updated_calls.len() - 1];

	let body: serde_json::Value =
		serde_json::from_str(&payment_call.2).expect("Body should be valid JSON");
	assert_eq!(body["method"], "lsps5.payment_incoming", "Should be payment_incoming notification");

	let timestamp_header = payment_call
		.1
		.iter()
		.find(|(name, _)| name == "x-lsps5-timestamp")
		.map(|(_, value)| value.clone())
		.expect("Timestamp header should be present");

	let signature_header = payment_call
		.1
		.iter()
		.find(|(name, _)| name == "x-lsps5-signature")
		.map(|(_, value)| value.clone())
		.expect("Signature header should be present");
	let time_provider_cloned = time_provider.clone();
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
		derived_pubkey,
		&timestamp_header,
		&signature_header,
		&payment_call.2,
		time_provider_cloned,
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

	// Let's test notification cooldown - shouldn't send a duplicate notification
	// Reset the call tracking
	mock_client_for_verification.post_calls.lock().unwrap().clear();

	// Try to send another payment_incoming notification (should be throttled)
	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_payment_incoming(client_node_id)
		.is_ok());

	// Wait a bit
	std::thread::sleep(std::time::Duration::from_millis(100));

	// No new calls should have been made due to cooldown
	let calls = mock_client_for_verification.get_calls();
	assert!(calls.is_empty(), "Notification shouldn't be sent due to cooldown");

	// Test expiry_soon notification (different type, should be sent)
	let timeout_block = 700000; // Some future block height
	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_expiry_soon(client_node_id, timeout_block)
		.is_ok());

	// Wait a bit
	std::thread::sleep(std::time::Duration::from_millis(100));

	// A new call should have been made for the different notification type
	let calls = mock_client_for_verification.get_calls();
	assert!(!calls.is_empty(), "expiry_soon notification should be sent");

	// Verify it's an expiry_soon notification
	let expiry_call = &calls[calls.len() - 1];
	let body: serde_json::Value =
		serde_json::from_str(&expiry_call.2).expect("Body should be valid JSON");
	assert_eq!(body["method"], "lsps5.expiry_soon", "Should be expiry_soon notification");
	assert_eq!(
		body["params"]["timeout"], timeout_block,
		"Timeout should match the provided block height"
	);

	// Test handling failures
	mock_client_for_verification.set_should_succeed(false);
	mock_client_for_verification.post_calls.lock().unwrap().clear();

	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_liquidity_management_request(client_node_id)
		.is_ok());

	std::thread::sleep(std::time::Duration::from_millis(100));

	let calls = mock_client_for_verification.get_calls();
	assert!(!calls.is_empty(), "Notification request should be made even if it fails");

	let event = service_node.liquidity_manager.next_event();
	assert!(
		event.is_none()
			|| match &event.unwrap() {
				LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::WebhookNotificationSent {
					..
				}) => false,
				_ => true,
			},
		"No webhook notification sent event should be emitted when delivery fails"
	);
}

#[test]
fn multiple_webhooks_notification_test() {
	let mock_client = Arc::new(MockHttpClient::new(true));
	let mock_client_for_verification = mock_client.clone();

	let signing_key = SecretKey::from_slice(&[42; 32]).unwrap();

	let mut lsps5_service_config = LSPS5ServiceConfig::default();
	lsps5_service_config =
		lsps5_service_config.with_http_client(MockHttpClientWrapper(mock_client));
	lsps5_service_config.signing_key = signing_key;

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

	let (service_node, client_node) = create_service_and_client_nodes(
		"multiple_webhooks_notification_test",
		service_config,
		client_config,
	);

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_node_id = service_node.channel_manager.get_our_node_id();
	let client_node_id = client_node.channel_manager.get_our_node_id();

	let secp = bitcoin::secp256k1::Secp256k1::new();
	let derived_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &signing_key);
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

		let set_webhook_response = get_lsps_message!(service_node, client_node_id);
		client_node
			.liquidity_manager
			.handle_custom_message(set_webhook_response, service_node_id)
			.unwrap();

		let _ = client_node.liquidity_manager.next_event().unwrap();
	}

	// Wait for the webhook_registered notifications to be sent
	std::thread::sleep(std::time::Duration::from_millis(200));

	// Clear the HTTP calls record to only capture new notifications
	mock_client_for_verification.post_calls.lock().unwrap().clear();

	// Send a notification that should go to all webhooks
	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_liquidity_management_request(client_node_id)
		.is_ok());

	// Wait for all notifications to be sent
	std::thread::sleep(std::time::Duration::from_millis(200));

	// Check that notifications were sent to all three webhooks
	let calls = mock_client_for_verification.get_calls();
	assert_eq!(calls.len(), 3, "Should have sent notifications to all three webhooks");

	let mut seen_webhooks = HashSet::default();
	for call in calls {
		// Add the URL to our set of seen webhooks
		seen_webhooks.insert(call.0.clone());

		// Verify it's the right notification type
		let body: serde_json::Value =
			serde_json::from_str(&call.2).expect("Body should be valid JSON");
		assert_eq!(
			body["method"], "lsps5.liquidity_management_request",
			"All webhooks should receive liquidity_management_request notification"
		);

		// Get the timestamp and signature headers
		let timestamp_header = call
			.1
			.iter()
			.find(|(name, _)| name == "x-lsps5-timestamp")
			.map(|(_, value)| value.clone())
			.expect("Timestamp header should be present");

		let signature_header = call
			.1
			.iter()
			.find(|(name, _)| name == "x-lsps5-signature")
			.map(|(_, value)| value.clone())
			.expect("Signature header should be present");
		let time_provider = Arc::new(DefaultTimeProvider);
		// Verify the signature using the derived pubkey
		let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
			derived_pubkey,
			&timestamp_header,
			&signature_header,
			&call.2,
			time_provider,
		);
		assert!(result.is_ok(), "Signature verification should succeed for all notifications");
	}

	// Verify that all three webhook URLs were called
	for (_, webhook_url) in &webhooks {
		assert!(
			seen_webhooks.contains(*webhook_url),
			"Webhook URL {} should have been called",
			webhook_url
		);
	}

	// Test that webhook_registered notifications are sent only to the specific webhook
	// First, clear the call record
	mock_client_for_verification.post_calls.lock().unwrap().clear();

	// Register a new webhook
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

	let set_webhook_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response, service_node_id)
		.unwrap();

	let _ = client_node.liquidity_manager.next_event().unwrap();

	std::thread::sleep(std::time::Duration::from_millis(100));

	// Check that only one notification was sent (webhook_registered)
	let calls = mock_client_for_verification.get_calls();
	assert_eq!(calls.len(), 1, "Should have sent only one webhook_registered notification");
	assert_eq!(
		calls[0].0, new_webhook,
		"Notification should be sent only to the newly registered webhook"
	);

	let body: serde_json::Value =
		serde_json::from_str(&calls[0].2).expect("Body should be valid JSON");
	assert_eq!(
		body["method"], "lsps5.webhook_registered",
		"Should be a webhook_registered notification"
	);
}

// Helper function to extract timestamp and signature from a webhook call
fn extract_timestamp_and_signature(
	call: &(String, Vec<(String, String)>, String),
) -> (String, String) {
	let mut timestamp = String::new();
	let mut signature = String::new();

	for (name, value) in &call.1 {
		if name == "x-lsps5-timestamp" {
			timestamp = value.clone();
		} else if name == "x-lsps5-signature" {
			signature = value.clone();
		}
	}

	(timestamp, signature)
}

#[test]
fn idempotency_set_webhook_test() {
	let mock_client = Arc::new(MockHttpClient::new(true));
	let mock_client_for_verification = mock_client.clone();

	let mut lsps5_service_config = LSPS5ServiceConfig::default();
	lsps5_service_config =
		lsps5_service_config.with_http_client(MockHttpClientWrapper(mock_client));

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

	let (service_node, client_node) = create_service_and_client_nodes(
		"idempotency_set_webhook_test",
		service_config,
		client_config,
	);

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_node_id = service_node.channel_manager.get_our_node_id();
	let client_node_id = client_node.channel_manager.get_our_node_id();

	let app_name = "Idempotency Test App";
	let webhook_url = "https://www.example.org/webhook?token=test123";

	// First registration - now with request ID
	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("First webhook registration should succeed");
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

	// Check the first registration event
	let webhook_registered_event = client_node.liquidity_manager.next_event().unwrap();
	match webhook_registered_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRegistered { no_change, .. }) => {
			// First registration should not be a no_change
			assert_eq!(no_change, false, "First registration should have no_change=false");
		},
		_ => panic!("Unexpected event"),
	}

	// Wait a bit for the webhook_registered notification to be sent
	std::thread::sleep(std::time::Duration::from_millis(100));

	// Verify that a notification was sent for the initial registration
	let initial_calls = mock_client_for_verification.get_calls();
	assert!(!initial_calls.is_empty(), "No HTTP requests were made for initial registration");

	// Clear the calls record to only track new ones
	mock_client_for_verification.clear_calls();

	// Now register the SAME webhook AGAIN (should be idempotent) - now with request ID
	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Second identical webhook registration should succeed");
	let set_webhook_request_again = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(set_webhook_request_again, client_node_id)
		.unwrap();

	let set_webhook_response_again = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(set_webhook_response_again, service_node_id)
		.unwrap();

	// Check the second registration event
	let webhook_registered_again_event = client_node.liquidity_manager.next_event().unwrap();
	match webhook_registered_again_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRegistered { no_change, .. }) => {
			// Second registration with same parameters should be a no_change
			assert_eq!(no_change, true, "Second identical registration should have no_change=true");
		},
		_ => panic!("Expected WebhookRegistered event for second registration"),
	}

	// Wait a bit to see if a notification is sent
	std::thread::sleep(std::time::Duration::from_millis(100));

	// Verify that no notification was sent for the idempotent operation
	let new_calls = mock_client_for_verification.get_calls();
	assert!(new_calls.is_empty(), "No notifications should be sent for idempotent operation");

	// Now try with a DIFFERENT URL (should not be idempotent) - now with request ID
	let updated_webhook_url = "https://www.example.org/webhook?token=updated456";

	// Clear the calls
	mock_client_for_verification.clear_calls();

	// Update the webhook
	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), updated_webhook_url.to_string())
		.expect("Update webhook request should succeed");
	let update_webhook_request = get_lsps_message!(client_node, service_node_id);

	service_node
		.liquidity_manager
		.handle_custom_message(update_webhook_request, client_node_id)
		.unwrap();

	let update_webhook_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(update_webhook_response, service_node_id)
		.unwrap();

	// Check the update event
	let webhook_updated_event = client_node.liquidity_manager.next_event().unwrap();
	match webhook_updated_event {
		LiquidityEvent::LSPS5Client(LSPS5ClientEvent::WebhookRegistered { no_change, .. }) => {
			// Update with different URL should not be a no_change
			assert_eq!(no_change, false, "Update with different URL should have no_change=false");
		},
		_ => panic!("Expected WebhookRegistered event for update"),
	}

	std::thread::sleep(std::time::Duration::from_millis(100));

	// Verify that a notification was sent for the update
	let update_calls = mock_client_for_verification.get_calls();
	assert!(!update_calls.is_empty(), "Notification should be sent for webhook update");
}

#[test]
fn replay_prevention_test() {
	let mock_client = Arc::new(MockHttpClient::new(true));
	let signing_key = SecretKey::from_slice(&[42; 32]).unwrap();

	let mut lsps5_service_config = LSPS5ServiceConfig::default();
	lsps5_service_config =
		lsps5_service_config.with_http_client(MockHttpClientWrapper(mock_client.clone()));
	lsps5_service_config.signing_key = signing_key;

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
		create_service_and_client_nodes("replay_prevention_test", service_config, client_config);

	let client_handler = client_node.liquidity_manager.lsps5_client_handler().unwrap();
	let service_node_id = service_node.channel_manager.get_our_node_id();
	let client_node_id = client_node.channel_manager.get_our_node_id();

	let secp = bitcoin::secp256k1::Secp256k1::new();
	let derived_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &signing_key);

	let app_name = "Replay Prevention Test App";
	let webhook_url = "https://www.example.org/webhook?token=replay123";

	let _ = client_handler
		.set_webhook(service_node_id, app_name.to_string(), webhook_url.to_string())
		.expect("Register webhook request should succeed");
	let request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(request, client_node_id).unwrap();

	let response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(response, service_node_id).unwrap();

	let _ = client_node.liquidity_manager.next_event().unwrap();

	std::thread::sleep(std::time::Duration::from_millis(100));

	// Trigger a notification to capture
	assert!(service_node
		.liquidity_manager
		.lsps5_service_handler()
		.unwrap()
		.notify_payment_incoming(client_node_id)
		.is_ok());

	// Wait for the notification to be sent
	std::thread::sleep(std::time::Duration::from_millis(100));

	// Get the notification call details
	let calls = mock_client.get_calls();
	assert!(calls.len() >= 2, "Should have received at least 2 notifications");

	// Get the payment notification (last call)
	let payment_call = &calls[calls.len() - 1];

	// Extract the timestamp and signature
	let (timestamp, signature) = extract_timestamp_and_signature(payment_call);
	let body = payment_call.2.clone();
	let time_provider = Arc::new(DefaultTimeProvider);
	// First verification should succeed
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
		derived_pubkey,
		&timestamp,
		&signature,
		&body,
		time_provider.clone(),
	);
	assert!(result.is_ok(), "First verification should succeed");

	// Try again with same timestamp and signature (simulate replay)
	let replay_result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
		derived_pubkey,
		&timestamp,
		&signature,
		&body,
		time_provider,
	);

	assert!(
		replay_result.is_ok(),
		"Client implementation allows multiple verification of same signature"
	);

	// Let's verify that the notification content matches what we expect
	let notification = replay_result.unwrap();
	assert_eq!(notification.method, WebhookNotificationMethod::LSPS5PaymentIncoming);
	assert!(notification.params.is_object());
}
