// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option. You may not use this file except in accordance with one or both of these
// licenses.

//! Client implementation for LSPS5 webhook registration

use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSMessage, LSPSProtocolMessageHandler, LSPSRequestId};
use crate::lsps5::event::LSPS5ClientEvent;
use crate::lsps5::msgs::{
	LSPS5Message, LSPS5Request, LSPS5Response, ListWebhooksRequest, RemoveWebhookRequest,
	SetWebhookRequest, WebhookNotification,
};
use crate::message_queue::MessageQueue;
use crate::prelude::*;

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::message_signing;

use crate::sync::{Arc, Mutex, RwLock};
use core::ops::Deref;

use crate::prelude::{new_hash_map, HashMap, String};

use super::msgs::{Lsps5AppName, Lsps5WebhookUrl};
#[cfg(feature = "std")]
use super::service::DefaultTimeProvider;
use super::service::{from_rfc3339, TimeProvider};
use super::url_utils::Url;
use core::time::Duration;
use lightning::sign::EntropySource;
use lightning::util::logger::Level;

/// Default maximum age in seconds for cached responses (1 hour)
pub const DEFAULT_RESPONSE_MAX_AGE_SECS: u64 = 3600;

/// Configuration options for LSPS5 client operations
#[derive(Clone)]
pub struct LSPS5ClientConfig {
	/// Maximum age in seconds for cached responses (default: 3600 - 1 hour)
	pub response_max_age_secs: u64,
	/// Time provider for LSPS5 service
	pub time_provider: Option<Arc<dyn TimeProvider>>,
}

impl Default for LSPS5ClientConfig {
	fn default() -> Self {
		Self {
			response_max_age_secs: DEFAULT_RESPONSE_MAX_AGE_SECS,
			#[cfg(feature = "std")]
			time_provider: Some(Arc::new(DefaultTimeProvider)),
			#[cfg(not(feature = "std"))]
			time_provider: None,
		}
	}
}

impl LSPS5ClientConfig {
	/// Set a custom time provider for the LSPS5 service
	pub fn with_time_provider(mut self, time_provider: impl TimeProvider + 'static) -> Self {
		self.time_provider = Some(Arc::new(time_provider));
		self
	}
}

struct PeerState {
	pending_set_webhook_requests: HashMap<LSPSRequestId, (Lsps5AppName, Lsps5WebhookUrl, Duration)>, // RequestId -> (app_name, webhook_url, timestamp)
	pending_list_webhooks_requests: HashMap<LSPSRequestId, Duration>, // RequestId -> timestamp
	pending_remove_webhook_requests: HashMap<LSPSRequestId, (Lsps5AppName, Duration)>, // RequestId -> (app_name, timestamp)
	// Last cleanup time for garbage collection
	last_cleanup: Duration, // Seconds since epoch
}

impl PeerState {
	fn new() -> Self {
		Self {
			pending_set_webhook_requests: new_hash_map(),
			pending_list_webhooks_requests: new_hash_map(),
			pending_remove_webhook_requests: new_hash_map(),
			last_cleanup: Duration::from_secs(0),
		}
	}

	/// Clean up expired responses based on max_age
	fn cleanup_expired_responses(
		&mut self, max_age_secs: u64, time_provider: Arc<dyn TimeProvider>,
	) {
		let now = time_provider.now();

		// Only run cleanup once per minute to avoid excessive processing
		if now.checked_sub(self.last_cleanup).unwrap() < Duration::from_secs(60) {
			return;
		}

		self.last_cleanup = now.clone();

		// Calculate the cutoff time for expired requests
		let cutoff =
			now.checked_sub(Duration::from_secs(max_age_secs.try_into().unwrap())).unwrap();

		// Remove expired set_webhook requests
		self.pending_set_webhook_requests.retain(|_, (_, _, timestamp)| *timestamp > cutoff);

		// Remove expired list_webhooks requests
		self.pending_list_webhooks_requests.retain(|_, timestamp| *timestamp > cutoff);

		// Remove expired remove_webhook requests
		self.pending_remove_webhook_requests.retain(|_, (_, timestamp)| *timestamp > cutoff);
	}
}

/// Client implementation for LSPS5 webhook registration
pub struct LSPS5ClientHandler<ES: Deref>
where
	ES::Target: EntropySource,
{
	/// Pending messages to be sent
	pending_messages: Arc<MessageQueue>,
	/// Event queue for emitting events
	pending_events: Arc<EventQueue>,
	/// Entropy source
	entropy_source: ES,
	/// Per peer state for tracking requests
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	/// Client configuration
	config: LSPS5ClientConfig,
	/// Time provider for LSPS5 service
	time_provider: Arc<dyn TimeProvider>,
}

impl<ES: Deref> LSPS5ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	/// Creates a new LSPS5 client handler with the provided entropy source, message queue,
	/// event queue, and LSPS5ClientConfig
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		mut config: LSPS5ClientConfig,
	) -> Self {
		let time_provider = config.time_provider.take().expect("Time provider should be present");
		Self {
			pending_messages,
			pending_events,
			entropy_source,
			per_peer_state: RwLock::new(new_hash_map()),
			config,
			time_provider,
		}
	}

	/// Helper method to get and lock peer state for a given counterparty
	fn with_peer_state<F, R>(&self, counterparty_node_id: PublicKey, f: F) -> R
	where
		F: FnOnce(&mut PeerState) -> R,
	{
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock =
			outer_state_lock.entry(counterparty_node_id).or_insert(Mutex::new(PeerState::new()));
		let mut peer_state_lock = inner_state_lock.lock().unwrap();

		// Clean up expired responses using configured max age
		peer_state_lock.cleanup_expired_responses(
			self.config.response_max_age_secs,
			self.time_provider.clone(),
		);

		// Execute the provided function with the locked peer state
		f(&mut *peer_state_lock)
	}

	/// Register a webhook with the LSP
	///
	/// Implements the `lsps5.set_webhook` method from BLIP-55.
	///
	/// # Parameters
	/// * `app_name` - A human-readable UTF-8 string that gives a name to the webhook (max 64 bytes)
	/// * `webhook` - The URL of the webhook that the LSP can use to push notifications (max 1024 chars)
	///
	/// # Returns
	/// * Success - the request ID that was used
	/// * Error - validation error or error sending the request
	///
	/// Response will be provided asynchronously through the event queue as a
	/// WebhookRegistered or WebhookRegistrationFailed event.
	pub fn set_webhook(
		&self, counterparty_node_id: PublicKey, app_name: String, webhook: String,
	) -> Result<LSPSRequestId, LightningError> {
		let app_name = match Lsps5AppName::new(app_name) {
			Ok(app_name) => app_name,
			Err(e) => return Err(e),
		};

		let webhook = match Lsps5WebhookUrl::new(webhook) {
			Ok(webhook) => webhook,
			Err(e) => return Err(e),
		};

		// Validate URL format and protocol according to spec
		let url = match Url::parse(&webhook.as_str()) {
			Ok(url) => url,
			Err(e) => {
				return Err(LightningError {
					err: format!("Failed to parse URL: {}", e),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});
			},
		};

		if url.scheme() != "https" {
			return Err(LightningError {
				err: format!("Unsupported protocol: {}. HTTPS is required.", url.scheme()),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			});
		}

		// Enhanced URL validation for security
		if let Err(e) = self.validate_url_security(&url) {
			return Err(e);
		}

		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		// Track this request with current timestamp
		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.pending_set_webhook_requests.insert(
				request_id.clone(),
				(app_name.clone(), webhook.clone(), self.time_provider.now()),
			);
		});

		// Create the request
		let request = LSPS5Request::SetWebhook(SetWebhookRequest { app_name, webhook });

		// Send request
		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		// Return the request ID for tracking
		Ok(request_id)
	}

	/// List all registered webhooks
	///
	/// Implements the `lsps5.list_webhooks` method from BLIP-55.
	///
	/// # Returns
	/// * Success - the request ID that was used
	/// * Error - error sending the request
	///
	/// Response will be provided asynchronously through the event queue as a
	/// WebhooksListed or WebhooksListFailed event.
	pub fn list_webhooks(
		&self, counterparty_node_id: PublicKey,
	) -> Result<LSPSRequestId, LightningError> {
		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		// Track this request with current timestamp
		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state
				.pending_list_webhooks_requests
				.insert(request_id.clone(), self.time_provider.now());
		});

		// Create the request
		let request = LSPS5Request::ListWebhooks(ListWebhooksRequest {});

		// Send request
		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		// Return the request ID for tracking
		Ok(request_id)
	}

	/// Remove a webhook by app_name
	///
	/// Implements the `lsps5.remove_webhook` method from BLIP-50.
	///
	/// # Parameters
	/// * `app_name` - The name of the webhook to remove
	///
	/// # Returns
	/// * Success - the request ID that was used
	/// * Error - error sending the request
	///
	/// Response will be provided asynchronously through the event queue as a
	/// WebhookRemoved or WebhookRemovalFailed event.
	pub fn remove_webhook(
		&self, counterparty_node_id: PublicKey, app_name: String,
	) -> Result<LSPSRequestId, LightningError> {
		let app_name = match Lsps5AppName::new(app_name) {
			Ok(app_name) => app_name,
			Err(e) => return Err(e),
		};

		// Generate a unique request ID
		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		// Track this request with current timestamp
		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state
				.pending_remove_webhook_requests
				.insert(request_id.clone(), (app_name.clone(), self.time_provider.now()));
		});

		let request = LSPS5Request::RemoveWebhook(RemoveWebhookRequest { app_name });

		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		Ok(request_id)
	}

	/// Enhanced URL validation for security
	fn validate_url_security(&self, url: &Url) -> Result<(), LightningError> {
		// Check that URL has a host
		if url.host().is_none() {
			return Err(LightningError {
				err: "URL must have a host".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			});
		}

		// Check for localhost and private IPs
		if let Some(host) = url.host_str() {
			if host == "localhost" || host.starts_with("127.") || host == "::1" {
				return Err(LightningError {
					err: "URL must not point to localhost".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});
			}

			if host.starts_with("10.")
				|| host.starts_with("192.168.")
				|| (host.starts_with("172.") && {
					if let Some(second_octet) = host.split('.').nth(1) {
						if let Ok(num) = second_octet.parse::<u8>() {
							(16..=31).contains(&num)
						} else {
							false
						}
					} else {
						false
					}
				}) {
				return Err(LightningError {
					err: "URL must not point to private IP ranges".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});
			}
		}

		Ok(())
	}

	/// Handle received messages from the LSP
	pub fn handle_message(
		&self, message: LSPS5Message, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		// Process response messages
		match message {
			LSPS5Message::Response(request_id, response) => {
				// Get mutable access to the peer state
				let mut result = Err(LightningError {
					err: format!(
						"Received LSPS5 response from unknown peer: {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});

				// Using with_peer_state for consistent access pattern
				self.with_peer_state(*counterparty_node_id, |peer_state| {
					// Check if this is a response to a set_webhook request
					if let Some((app_name, webhook_url, _)) =
						peer_state.pending_set_webhook_requests.remove(&request_id)
					{
						match response {
							LSPS5Response::SetWebhook(response) => {
								self.pending_events.enqueue(LSPS5ClientEvent::WebhookRegistered {
									counterparty_node_id: *counterparty_node_id,
									num_webhooks: response.num_webhooks,
									max_webhooks: response.max_webhooks,
									no_change: response.no_change,
									app_name,
									url: webhook_url,
									request_id,
								});
								result = Ok(());
							},
							LSPS5Response::SetWebhookError(error) => {
								self.pending_events.enqueue(
									LSPS5ClientEvent::WebhookRegistrationFailed {
										counterparty_node_id: *counterparty_node_id,
										error_code: error.code,
										error_message: error.message,
										app_name,
										url: webhook_url,
										request_id,
									},
								);
								result = Ok(());
							},
							_ => {
								result = Err(LightningError {
									err: "Unexpected response type for SetWebhook request"
										.to_string(),
									action: ErrorAction::IgnoreAndLog(Level::Error),
								});
							},
						}
					} else if peer_state
						.pending_list_webhooks_requests
						.remove(&request_id)
						.is_some()
					{
						// Process list_webhooks response
						match response {
							LSPS5Response::ListWebhooks(response) => {
								self.pending_events.enqueue(LSPS5ClientEvent::WebhooksListed {
									counterparty_node_id: *counterparty_node_id,
									app_names: response.app_names,
									max_webhooks: response.max_webhooks,
									request_id,
								});
								result = Ok(());
							},
							LSPS5Response::ListWebhooksError(error) => {
								self.pending_events.enqueue(LSPS5ClientEvent::WebhooksListFailed {
									counterparty_node_id: *counterparty_node_id,
									error_code: error.code,
									error_message: error.message,
									request_id,
								});
								result = Ok(());
							},
							_ => {
								result = Err(LightningError {
									err: "Unexpected response type for ListWebhooks request"
										.to_string(),
									action: ErrorAction::IgnoreAndLog(Level::Error),
								});
							},
						}
					} else if let Some((app_name, _)) =
						peer_state.pending_remove_webhook_requests.remove(&request_id)
					{
						// Process remove_webhook response
						match response {
							LSPS5Response::RemoveWebhook(_) => {
								// Emit event
								self.pending_events.enqueue(LSPS5ClientEvent::WebhookRemoved {
									counterparty_node_id: *counterparty_node_id,
									app_name,
									request_id,
								});
								result = Ok(());
							},
							LSPS5Response::RemoveWebhookError(error) => {
								self.pending_events.enqueue(
									LSPS5ClientEvent::WebhookRemovalFailed {
										counterparty_node_id: *counterparty_node_id,
										error_code: error.code,
										error_message: error.message,
										app_name,
										request_id,
									},
								);
								result = Ok(());
							},
							_ => {
								result = Err(LightningError {
									err: "Unexpected response type for RemoveWebhook request"
										.to_string(),
									action: ErrorAction::IgnoreAndLog(Level::Error),
								});
							},
						}
					} else {
						result = Err(LightningError {
							err: format!(
								"Received response for unknown request ID: {}",
								request_id.0
							),
							action: ErrorAction::IgnoreAndLog(Level::Info),
						});
					}
				});

				result
			},
			LSPS5Message::Request(_, _) => {
				// We're a client, so we don't expect to receive requests
				Err(LightningError {
					err: format!(
						"Received unexpected request message from {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})
			},
		}
	}

	/// Verify a webhook notification signature from an LSP
	///
	/// This can be used by a notification delivery service to verify
	/// the authenticity of notifications received from an LSP.
	///
	/// # Parameters
	/// * `timestamp` - The ISO8601 timestamp from the notification
	/// * `signature` - The signature string from the notification
	/// * `notification` - The webhook notification object
	///
	/// # Returns
	/// * On success: `true` if the signature is valid
	/// * On error: LightningError with error description
	pub fn verify_notification_signature(
		counterparty_node_id: PublicKey, timestamp: &str, signature: &str,
		notification: &WebhookNotification, time_provider: &Arc<dyn TimeProvider>,
	) -> Result<bool, LightningError> {
		// Check timestamp format
		match from_rfc3339(timestamp) {
			Ok(timestamp_dt) => {
				// Check timestamp is within 10 minutes of current time
				let now = time_provider.now();

				let diff = if now > timestamp_dt {
					now.checked_sub(timestamp_dt).unwrap()
				} else {
					timestamp_dt.checked_sub(now).unwrap()
				};
				if diff > Duration::from_secs(600) {
					// 10 minutes
					return Err(LightningError {
						err: format!(
							"Timestamp too far from current time: {:?} (diff: {:?} seconds)",
							now, diff
						),
						action: ErrorAction::IgnoreAndLog(Level::Error),
					});
				}
			},
			Err(_e) => {
				return Err(LightningError {
					err: format!("Invalid timestamp format: {}", timestamp),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});
			},
		}

		// Format the message that should have been signed
		let notification_json = match serde_json::to_string(notification) {
			Ok(json) => json,
			Err(e) => {
				return Err(LightningError {
					err: format!("Failed to serialize notification: {}", e),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});
			},
		};

		// Create the message in the same format as used in sign_notification
		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
			timestamp, notification_json
		);

		if message_signing::verify(message.as_bytes(), signature, &counterparty_node_id) {
			Ok(true)
		} else {
			Err(LightningError {
				err: "Invalid signature".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})
		}
	}

	/// Parse a webhook notification received from an LSP
	///
	/// This can be used by a client implementation to handle webhook
	/// notifications after they're delivered through a push notification
	/// system.
	///
	/// # Parameters
	/// * `timestamp` - The ISO8601 timestamp from the notification
	/// * `signature` - The signature from the notification
	/// * `notification_json` - The JSON string of the notification object
	///
	/// # Returns
	/// * On success: The parsed webhook notification
	/// * On error: LightningError with error description
	pub fn parse_webhook_notification(
		counterparty_node_id: PublicKey, timestamp: &str, signature: &str, notification_json: &str,
		time_provider: &Arc<dyn TimeProvider>,
	) -> Result<WebhookNotification, LightningError> {
		// Parse the notification JSON
		let notification: WebhookNotification = match serde_json::from_str(notification_json) {
			Ok(n) => n,
			Err(e) => {
				return Err(LightningError {
					err: format!("Failed to parse notification: {}", e),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});
			},
		};
		// Verify signature
		match Self::verify_notification_signature(
			counterparty_node_id,
			timestamp,
			signature,
			&notification,
			&time_provider,
		) {
			Ok(_) => Ok(notification),
			Err(e) => Err(e),
		}
	}
}

impl<ES: Deref> LSPSProtocolMessageHandler for LSPS5ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	type ProtocolMessage = LSPS5Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(5);

	fn handle_message(
		&self, message: Self::ProtocolMessage, lsp_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		self.handle_message(message, lsp_node_id)
	}
}

#[cfg(test)]
mod tests {
	#![cfg(all(test, feature = "std"))]
	use super::*;
	use crate::{
		lsps0::ser::LSPSRequestId, lsps5::msgs::SetWebhookResponse, tests::utils::TestEntropy,
	};
	use bitcoin::{key::Secp256k1, secp256k1::SecretKey};

	fn setup_test_client() -> (
		LSPS5ClientHandler<Arc<TestEntropy>>,
		Arc<MessageQueue>,
		Arc<EventQueue>,
		PublicKey,
		PublicKey,
	) {
		let test_entropy_source = Arc::new(TestEntropy {});
		let message_queue = Arc::new(MessageQueue::new());
		let event_queue = Arc::new(EventQueue::new());

		let client = LSPS5ClientHandler::new(
			test_entropy_source,
			message_queue.clone(),
			event_queue.clone(),
			LSPS5ClientConfig::default(),
		);

		// Create two separate peer node IDs for testing
		let secp = Secp256k1::new();
		let secret_key_1 = SecretKey::from_slice(&[42u8; 32]).unwrap();
		let secret_key_2 = SecretKey::from_slice(&[43u8; 32]).unwrap();
		let peer_1 = PublicKey::from_secret_key(&secp, &secret_key_1);
		let peer_2 = PublicKey::from_secret_key(&secp, &secret_key_2);

		(client, message_queue, event_queue, peer_1, peer_2)
	}

	#[test]
	fn test_per_peer_state_isolation() {
		let (client, _, _, peer_1, peer_2) = setup_test_client();

		// Request webhooks for both peers
		let req_id_1 = client
			.set_webhook(peer_1, "test-app-1".to_string(), "https://example.com/hook1".to_string())
			.unwrap();
		let req_id_2 = client
			.set_webhook(peer_2, "test-app-2".to_string(), "https://example.com/hook2".to_string())
			.unwrap();

		// Verify that each peer state is isolated and contains the correct pending requests
		{
			let outer_state_lock = client.per_peer_state.read().unwrap();

			// Check peer 1's state
			let peer_1_state = outer_state_lock.get(&peer_1).unwrap().lock().unwrap();
			assert!(peer_1_state.pending_set_webhook_requests.contains_key(&req_id_1));
			// We're using the TestEntropy which likely returns the same value each time,
			// so we can only verify that peer 1's state contains req_id_1

			// Check peer 2's state
			let peer_2_state = outer_state_lock.get(&peer_2).unwrap().lock().unwrap();
			// Only verify that peer 2's state contains req_id_2
			assert!(peer_2_state.pending_set_webhook_requests.contains_key(&req_id_2));
		}
	}

	#[test]
	fn test_pending_request_tracking() {
		let (client, _, _, peer, _) = setup_test_client();
		const APP_NAME: &str = "test-app";
		const WEBHOOK_URL: &str = "https://example.com/hook";
		let lsps5_app_name = Lsps5AppName::new(APP_NAME.to_string()).unwrap();
		let lsps5_webhook_url = Lsps5WebhookUrl::new(WEBHOOK_URL.to_string()).unwrap();
		// Create various requests
		let set_req_id =
			client.set_webhook(peer, APP_NAME.to_string(), WEBHOOK_URL.to_string()).unwrap();
		let list_req_id = client.list_webhooks(peer).unwrap();
		let remove_req_id = client.remove_webhook(peer, "test-app".to_string()).unwrap();

		// Verify all requests are correctly tracked
		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();

			// Check set_webhook tracking
			assert_eq!(
				peer_state.pending_set_webhook_requests.get(&set_req_id).unwrap(),
				&(
					lsps5_app_name.clone(),
					lsps5_webhook_url,
					peer_state.pending_set_webhook_requests.get(&set_req_id).unwrap().2.clone()
				)
			);

			// Check list_webhooks tracking
			assert!(peer_state.pending_list_webhooks_requests.contains_key(&list_req_id));

			// Check remove_webhook tracking
			assert_eq!(
				peer_state.pending_remove_webhook_requests.get(&remove_req_id).unwrap().0,
				lsps5_app_name
			);
		}
	}

	#[test]
	fn test_handle_response_clears_pending_state() {
		let (client, _, _, peer, _) = setup_test_client();

		// Setup request
		let req_id = client
			.set_webhook(peer, "test-app".to_string(), "https://example.com/hook".to_string())
			.unwrap();

		// Create a successful response
		let response = LSPS5Response::SetWebhook(SetWebhookResponse {
			num_webhooks: 1,
			max_webhooks: 5,
			no_change: false,
		});
		let response_msg = LSPS5Message::Response(req_id.clone(), response);

		// Verify request is tracked before handling
		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert!(peer_state.pending_set_webhook_requests.contains_key(&req_id));
		}

		// Handle the response
		client.handle_message(response_msg, &peer).unwrap();

		// Verify request is removed after handling
		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert!(!peer_state.pending_set_webhook_requests.contains_key(&req_id));
		}
	}

	#[test]
	fn test_cleanup_expired_responses() {
		// use DefaultTimeProvider
		let (client, _, _, _, _) = setup_test_client();
		let time_provider = &client.time_provider;
		const OLD_APP_NAME: &str = "test-app-old";
		const NEW_APP_NAME: &str = "test-app-new";
		const WEBHOOK_URL: &str = "https://example.com/hook";
		let lsps5_old_app_name = Lsps5AppName::new(OLD_APP_NAME.to_string()).unwrap();
		let lsps5_new_app_name = Lsps5AppName::new(NEW_APP_NAME.to_string()).unwrap();
		let lsps5_webhook_url = Lsps5WebhookUrl::new(WEBHOOK_URL.to_string()).unwrap();
		// The current time for setting request timestamps
		let now = time_provider.now();
		// Create a mock PeerState with a very old cleanup time
		let mut peer_state = PeerState::new();
		peer_state.last_cleanup = now.checked_sub(Duration::from_secs(120)).unwrap();

		// Add some test requests with different timestamps
		let old_request_id = LSPSRequestId("test:request:old".to_string());
		let new_request_id = LSPSRequestId("test:request:new".to_string());

		// Add an old request (should be removed during cleanup)
		peer_state.pending_set_webhook_requests.insert(
			old_request_id.clone(),
			(
				lsps5_old_app_name,
				lsps5_webhook_url.clone(),
				now.checked_sub(Duration::from_secs(7200)).unwrap(),
			), // 2 hours old
		);

		// Add a recent request (should be kept)
		peer_state.pending_set_webhook_requests.insert(
			new_request_id.clone(),
			(
				lsps5_new_app_name,
				lsps5_webhook_url,
				now.checked_sub(Duration::from_secs(600)).unwrap(),
			), // 10 minutes old
		);

		// Run cleanup with 30 minutes (1800 seconds) max age
		peer_state.cleanup_expired_responses(1800, time_provider.clone());

		// Verify old request is removed and new request is kept
		assert!(!peer_state.pending_set_webhook_requests.contains_key(&old_request_id));
		assert!(peer_state.pending_set_webhook_requests.contains_key(&new_request_id));

		// Verify last_cleanup was updated within the last 10 seconds
		let cleanup_age = time_provider.now().checked_sub(peer_state.last_cleanup).unwrap();
		assert!(cleanup_age < Duration::from_secs(10));
	}

	#[test]
	fn test_unknown_request_id_handling() {
		let (client, _message_queue, _, peer, _) = setup_test_client();

		// First, we need to make sure the peer state exists in the map
		// by making a valid request
		let _valid_req = client
			.set_webhook(peer, "test-app".to_string(), "https://example.com/hook".to_string())
			.unwrap();

		// Create a response with an unknown request ID
		let unknown_req_id = LSPSRequestId("unknown:request:id".to_string());
		let response = LSPS5Response::SetWebhook(SetWebhookResponse {
			num_webhooks: 1,
			max_webhooks: 5,
			no_change: false,
		});
		let response_msg = LSPS5Message::Response(unknown_req_id, response);

		// Handling should return an error for unknown request ID
		let result = client.handle_message(response_msg, &peer);
		assert!(result.is_err());
		let error = result.unwrap_err();
		// The error message contains "unknown request ID" (case insensitive)
		assert!(error.err.to_lowercase().contains("unknown request id"));
	}

	#[test]
	fn test_url_security_validation() {
		let (client, _, _, _, _) = setup_test_client();

		// Test valid HTTPS URL
		let valid_url = Url::parse("https://example.com/webhook").unwrap();
		assert!(client.validate_url_security(&valid_url).is_ok());

		// Test invalid schemes - These aren't caught in validate_url_security() but in set_webhook()
		// so we need to test the actual set_webhook method instead
		let peer = PublicKey::from_slice(&[2u8; 33]).unwrap();
		let result = client.set_webhook(
			peer,
			"test-app".to_string(),
			"http://example.com/webhook".to_string(),
		);
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert!(error.err.contains("HTTPS is required"));

		// Test localhost
		let localhost_url = Url::parse("https://localhost/webhook").unwrap();
		assert!(client.validate_url_security(&localhost_url).is_err());

		// Test private IP ranges
		let private_ip_urls = [
			"https://10.0.0.1/webhook",
			"https://192.168.1.1/webhook",
			"https://172.16.0.1/webhook",
			"https://172.31.255.255/webhook",
		];

		for url_str in private_ip_urls.iter() {
			let url = Url::parse(url_str).unwrap();
			assert!(client.validate_url_security(&url).is_err());
		}
	}
}
