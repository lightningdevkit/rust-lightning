// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option. You may not use this file except in accordance with one or both of these
// licenses.

//! Client implementation for LSPS5 webhook registration

use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSDateTime, LSPSMessage, LSPSProtocolMessageHandler, LSPSRequestId};
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

use super::msgs::{LSPS5AppName, LSPS5WebhookUrl};
#[cfg(feature = "time")]
use super::service::DefaultTimeProvider;
use super::service::TimeProvider;
use crate::utils::generate_request_id;
use core::str::FromStr;
use core::time::Duration;
use lightning::sign::EntropySource;
use lightning::util::logger::Level;

/// Default maximum age in seconds for cached responses (1 hour)
pub const DEFAULT_RESPONSE_MAX_AGE_SECS: u64 = 3600;

/// Default retention time for signatures in minutes (LSPS5 spec requires min 20 minutes)
pub const DEFAULT_SIGNATURE_RETENTION_MINUTES: u64 = 20;

/// Default maximum number of stored signatures
pub const DEFAULT_MAX_SIGNATURES: usize = 1000;

/// Configuration for signature storage
#[derive(Clone, Copy, Debug)]
pub struct SignatureStorageConfig {
	/// Maximum number of signatures to store
	pub max_signatures: usize,
	/// Retention time for signatures in minutes
	pub retention_minutes: u64,
}

impl Default for SignatureStorageConfig {
	fn default() -> Self {
		Self {
			max_signatures: DEFAULT_MAX_SIGNATURES,
			retention_minutes: DEFAULT_SIGNATURE_RETENTION_MINUTES,
		}
	}
}

#[derive(Clone)]
/// Configuration for the LSPS5 client
pub struct LSPS5ClientConfig {
	/// Maximum age in seconds for cached responses (default: 3600 - 1 hour)
	pub response_max_age_secs: u64,
	/// Configuration for signature storage
	pub signature_config: SignatureStorageConfig,
}

impl Default for LSPS5ClientConfig {
	fn default() -> Self {
		Self {
			response_max_age_secs: DEFAULT_RESPONSE_MAX_AGE_SECS,
			signature_config: SignatureStorageConfig::default(),
		}
	}
}

struct PeerState {
	pending_set_webhook_requests: HashMap<LSPSRequestId, (LSPS5AppName, LSPS5WebhookUrl, Duration)>, // RequestId -> (app_name, webhook_url, timestamp)
	pending_list_webhooks_requests: HashMap<LSPSRequestId, Duration>, // RequestId -> timestamp
	pending_remove_webhook_requests: HashMap<LSPSRequestId, (LSPS5AppName, Duration)>, // RequestId -> (app_name, timestamp)
	last_cleanup: Option<Duration>, // Seconds since epoch
}

impl PeerState {
	fn new() -> Self {
		Self {
			pending_set_webhook_requests: new_hash_map(),
			pending_list_webhooks_requests: new_hash_map(),
			pending_remove_webhook_requests: new_hash_map(),
			last_cleanup: None,
		}
	}
	fn cleanup_expired_responses(
		&mut self, max_age_secs: u64, time_provider: Arc<dyn TimeProvider>,
	) {
		let now = time_provider.duration_since_epoch();

		// Only run cleanup once per minute to avoid excessive processing
		if let Some(last_cleanup) = self.last_cleanup {
			match now.checked_sub(last_cleanup) {
				Some(elapsed) if elapsed < Duration::from_secs(60) => return,
				None => return,
				_ => {},
			}
		}

		self.last_cleanup = Some(now);

		let cutoff = match u64::try_into(max_age_secs) {
			Ok(secs) => match now.checked_sub(Duration::from_secs(secs)) {
				Some(time) => time,
				None => return,
			},
			Err(_) => {
				// If conversion fails, use a safe default
				match now.checked_sub(Duration::from_secs(3600)) {
					Some(time) => time,
					None => return,
				}
			},
		};

		self.pending_set_webhook_requests.retain(|_, (_, _, timestamp)| *timestamp > cutoff);
		self.pending_list_webhooks_requests.retain(|_, timestamp| *timestamp > cutoff);
		self.pending_remove_webhook_requests.retain(|_, (_, timestamp)| *timestamp > cutoff);
	}
}

/// LSPS5 client handler
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
	/// Map of recently used signatures to prevent replay attacks
	recent_signatures: Arc<Mutex<VecDeque<(String, Duration)>>>,
}

impl<ES: Deref> LSPS5ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	/// Creates a new LSPS5 client handler with the provided entropy source, message queue,
	/// event queue, and LSPS5ClientConfig
	#[cfg(feature = "time")]
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		config: LSPS5ClientConfig,
	) -> Option<Self> {
		let max_signatures = config.signature_config.max_signatures.clone();
		Some(Self {
			pending_messages,
			pending_events,
			entropy_source,
			per_peer_state: RwLock::new(new_hash_map()),
			config,
			time_provider: Arc::new(DefaultTimeProvider),
			recent_signatures: Arc::new(Mutex::new(VecDeque::with_capacity(max_signatures))),
		})
	}

	pub(crate) fn _new_with_custom_time_provider(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		config: LSPS5ClientConfig, time_provider: Option<Arc<dyn TimeProvider>>,
	) -> Option<Self> {
		let max_signatures = config.signature_config.max_signatures.clone();
		let time_provider = match time_provider {
			Some(provider) => provider,
			None => return None,
		};
		Some(Self {
			pending_messages,
			pending_events,
			entropy_source,
			per_peer_state: RwLock::new(new_hash_map()),
			config,
			time_provider,
			recent_signatures: Arc::new(Mutex::new(VecDeque::with_capacity(max_signatures))),
		})
	}

	fn with_peer_state<F, R>(
		&self, counterparty_node_id: PublicKey, f: F,
	) -> Result<R, LightningError>
	where
		F: FnOnce(&mut PeerState) -> R,
	{
		let mut outer_state_lock = self.per_peer_state.write().map_err(|_| LightningError {
			err: "Failed to execute write on per_peer_state".to_string(),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;
		let inner_state_lock =
			outer_state_lock.entry(counterparty_node_id).or_insert(Mutex::new(PeerState::new()));
		let mut peer_state_lock = inner_state_lock.lock().map_err(|_| LightningError {
			err: "Failed to lock inner_state_lock mutex".to_string(),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		peer_state_lock.cleanup_expired_responses(
			self.config.response_max_age_secs,
			Arc::clone(&self.time_provider),
		);

		Ok(f(&mut *peer_state_lock))
	}

	/// Register a webhook with the LSP
	///
	/// Implements the `lsps5.set_webhook` method from bLIP-55.
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
		&self, counterparty_node_id: PublicKey, app_name: String, webhook_url: String,
	) -> Result<LSPSRequestId, LightningError> {
		let app_name = LSPS5AppName::new(app_name).map_err(|e| LightningError {
			err: e.message,
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		let lsps_webhook_url = LSPS5WebhookUrl::new(webhook_url).map_err(|e| LightningError {
			err: e.message,
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		let request_id = generate_request_id(&self.entropy_source);

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.pending_set_webhook_requests.insert(
				request_id.clone(),
				(
					app_name.clone(),
					lsps_webhook_url.clone(),
					self.time_provider.duration_since_epoch(),
				),
			);
		})?;

		let request =
			LSPS5Request::SetWebhook(SetWebhookRequest { app_name, webhook: lsps_webhook_url });

		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		Ok(request_id)
	}

	/// List all registered webhooks
	///
	/// Implements the `lsps5.list_webhooks` method from bLIP-55.
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
		let request_id = generate_request_id(&self.entropy_source);
		let now = self.time_provider.duration_since_epoch();

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.pending_list_webhooks_requests.insert(request_id.clone(), now);
		})?;

		let request = LSPS5Request::ListWebhooks(ListWebhooksRequest {});
		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		Ok(request_id)
	}

	/// Remove a webhook by app_name
	///
	/// Implements the `lsps5.remove_webhook` method from bLIP-55.
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
		let app_name = LSPS5AppName::new(app_name).map_err(|e| LightningError {
			err: e.message,
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		let request_id = generate_request_id(&self.entropy_source);
		let now = self.time_provider.duration_since_epoch();

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state
				.pending_remove_webhook_requests
				.insert(request_id.clone(), (app_name.clone(), now));
		})?;

		let request = LSPS5Request::RemoveWebhook(RemoveWebhookRequest { app_name });
		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		Ok(request_id)
	}

	/// Handle received messages from the LSP
	pub fn handle_message(
		&self, message: LSPS5Message, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS5Message::Response(request_id, response) => {
				let mut result = Err(LightningError {
					err: format!(
						"Received LSPS5 response from unknown peer: {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});

				self.with_peer_state(*counterparty_node_id, |peer_state| {
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
						match response {
							LSPS5Response::RemoveWebhook(_) => {
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
				})?;

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
		&self, counterparty_node_id: PublicKey, timestamp: &str, signature: &str,
		notification: &WebhookNotification,
	) -> Result<bool, LightningError> {
		LSPSDateTime::from_str(timestamp)
			.map_err(|_| LightningError {
				err: format!("Invalid timestamp format: {}", timestamp),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})
			.and_then(|signature_timestamp| {
				let now = LSPSDateTime::from(self.time_provider.duration_since_epoch());
				let diff = signature_timestamp.abs_diff(&now);

				if diff > 600 {
					return Err(LightningError {
						err: format!("Timestamp too old: {}", timestamp),
						action: ErrorAction::IgnoreAndLog(Level::Error),
					});
				}

				Ok(())
			})?;

		let notification_json =
			serde_json::to_string(notification).map_err(|e| LightningError {
				err: format!("Failed to serialize notification: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})?;

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

	/// Check if a signature has been used before
	fn check_signature_exists(&self, signature: &str) -> Result<(), LightningError> {
		let recent_signatures = self.recent_signatures.lock().map_err(|_| LightningError {
			err: "Failed to lock recent_signatures mutex".to_string(),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		for (stored_sig, _) in recent_signatures.iter() {
			if stored_sig == signature {
				return Err(LightningError {
					err: "Replay attack detected: signature has been used before".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Warn),
				});
			}
		}

		Ok(())
	}

	/// Store a signature with timestamp for replay attack prevention
	fn store_signature(&self, signature: String) -> Result<(), LightningError> {
		let now = self.time_provider.duration_since_epoch();
		let mut recent_signatures = self.recent_signatures.lock().map_err(|_| LightningError {
			err: "Failed to lock recent_signatures mutex".to_string(),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		recent_signatures.push_back((signature, now));

		let retention_duration =
			Duration::from_secs(self.config.signature_config.retention_minutes * 60);
		while let Some((_, time)) = recent_signatures.front() {
			if now.checked_sub(*time).map_or(false, |duration| duration > retention_duration) {
				recent_signatures.pop_front();
			} else {
				break;
			}
		}

		while recent_signatures.len() > self.config.signature_config.max_signatures {
			recent_signatures.pop_front();
		}

		Ok(())
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
		&self, counterparty_node_id: PublicKey, timestamp: &str, signature: &str,
		notification_json: &str,
	) -> Result<WebhookNotification, LightningError> {
		let notification: WebhookNotification =
			serde_json::from_str(notification_json).map_err(|e| LightningError {
				err: format!("Failed to parse notification: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})?;

		self.check_signature_exists(signature)?;

		self.store_signature(signature.to_string())?;

		match self.verify_notification_signature(
			counterparty_node_id,
			timestamp,
			signature,
			&notification,
		) {
			Ok(signature_valid) => {
				self.pending_events.enqueue(LSPS5ClientEvent::WebhookNotificationReceived {
					counterparty_node_id,
					notification: notification.clone(),
					timestamp: timestamp.to_string(),
					signature_valid,
				});
				Ok(notification)
			},
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
	#![cfg(all(test, feature = "time"))]
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
		)
		.unwrap();

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

		let req_id_1 = client
			.set_webhook(peer_1, "test-app-1".to_string(), "https://example.com/hook1".to_string())
			.unwrap();
		let req_id_2 = client
			.set_webhook(peer_2, "test-app-2".to_string(), "https://example.com/hook2".to_string())
			.unwrap();

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();

			let peer_1_state = outer_state_lock.get(&peer_1).unwrap().lock().unwrap();
			assert!(peer_1_state.pending_set_webhook_requests.contains_key(&req_id_1));

			let peer_2_state = outer_state_lock.get(&peer_2).unwrap().lock().unwrap();
			assert!(peer_2_state.pending_set_webhook_requests.contains_key(&req_id_2));
		}
	}

	#[test]
	fn test_pending_request_tracking() {
		let (client, _, _, peer, _) = setup_test_client();
		const APP_NAME: &str = "test-app";
		const WEBHOOK_URL: &str = "https://example.com/hook";
		let lsps5_app_name = LSPS5AppName::new(APP_NAME.to_string()).unwrap();
		let lsps5_webhook_url = LSPS5WebhookUrl::new(WEBHOOK_URL.to_string()).unwrap();
		let set_req_id =
			client.set_webhook(peer, APP_NAME.to_string(), WEBHOOK_URL.to_string()).unwrap();
		let list_req_id = client.list_webhooks(peer).unwrap();
		let remove_req_id = client.remove_webhook(peer, "test-app".to_string()).unwrap();

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert_eq!(
				peer_state.pending_set_webhook_requests.get(&set_req_id).unwrap(),
				&(
					lsps5_app_name.clone(),
					lsps5_webhook_url,
					peer_state.pending_set_webhook_requests.get(&set_req_id).unwrap().2.clone()
				)
			);

			assert!(peer_state.pending_list_webhooks_requests.contains_key(&list_req_id));

			assert_eq!(
				peer_state.pending_remove_webhook_requests.get(&remove_req_id).unwrap().0,
				lsps5_app_name
			);
		}
	}

	#[test]
	fn test_handle_response_clears_pending_state() {
		let (client, _, _, peer, _) = setup_test_client();

		let req_id = client
			.set_webhook(peer, "test-app".to_string(), "https://example.com/hook".to_string())
			.unwrap();

		let response = LSPS5Response::SetWebhook(SetWebhookResponse {
			num_webhooks: 1,
			max_webhooks: 5,
			no_change: false,
		});
		let response_msg = LSPS5Message::Response(req_id.clone(), response);

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert!(peer_state.pending_set_webhook_requests.contains_key(&req_id));
		}

		client.handle_message(response_msg, &peer).unwrap();

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert!(!peer_state.pending_set_webhook_requests.contains_key(&req_id));
		}
	}

	#[test]
	fn test_cleanup_expired_responses() {
		let (client, _, _, _, _) = setup_test_client();
		let time_provider = &client.time_provider;
		const OLD_APP_NAME: &str = "test-app-old";
		const NEW_APP_NAME: &str = "test-app-new";
		const WEBHOOK_URL: &str = "https://example.com/hook";
		let lsps5_old_app_name = LSPS5AppName::new(OLD_APP_NAME.to_string()).unwrap();
		let lsps5_new_app_name = LSPS5AppName::new(NEW_APP_NAME.to_string()).unwrap();
		let lsps5_webhook_url = LSPS5WebhookUrl::new(WEBHOOK_URL.to_string()).unwrap();
		let now = time_provider.duration_since_epoch();
		let mut peer_state = PeerState::new();
		peer_state.last_cleanup = Some(now.checked_sub(Duration::from_secs(120)).unwrap());

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

		peer_state.cleanup_expired_responses(1800, time_provider.clone());

		assert!(!peer_state.pending_set_webhook_requests.contains_key(&old_request_id));
		let cleanup_age = if let Some(last_cleanup) = peer_state.last_cleanup {
			time_provider.duration_since_epoch().checked_sub(last_cleanup).unwrap()
		} else {
			Duration::from_secs(0)
		};
		assert!(cleanup_age < Duration::from_secs(10));
	}

	#[test]
	fn test_unknown_request_id_handling() {
		let (client, _message_queue, _, peer, _) = setup_test_client();

		let _valid_req = client
			.set_webhook(peer, "test-app".to_string(), "https://example.com/hook".to_string())
			.unwrap();

		let unknown_req_id = LSPSRequestId("unknown:request:id".to_string());
		let response = LSPS5Response::SetWebhook(SetWebhookResponse {
			num_webhooks: 1,
			max_webhooks: 5,
			no_change: false,
		});
		let response_msg = LSPS5Message::Response(unknown_req_id, response);

		let result = client.handle_message(response_msg, &peer);
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert!(error.err.to_lowercase().contains("unknown request id"));
	}
}
