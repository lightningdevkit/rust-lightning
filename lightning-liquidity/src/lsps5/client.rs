// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Client implementation for LSPS5 webhook registration.

use crate::alloc::string::ToString;
use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSDateTime, LSPSMessage, LSPSProtocolMessageHandler, LSPSRequestId};
use crate::lsps5::event::LSPS5ClientEvent;
use crate::lsps5::msgs::{
	LSPS5Message, LSPS5Request, LSPS5Response, ListWebhooksRequest, RemoveWebhookRequest,
	SetWebhookRequest, WebhookNotification,
};
use crate::message_queue::MessageQueue;
use crate::prelude::{new_hash_map, HashMap};
use crate::sync::{Arc, Mutex, RwLock};
use crate::utils::generate_request_id;

use super::msgs::{LSPS5AppName, LSPS5ClientError, LSPS5Error, LSPS5WebhookUrl};
use super::service::TimeProvider;

use bitcoin::secp256k1::PublicKey;

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;
use lightning::util::message_signing;

use alloc::collections::VecDeque;
use alloc::string::String;

use core::ops::Deref;
use core::time::Duration;

/// Default maximum age in seconds for cached responses (1 hour).
pub const DEFAULT_RESPONSE_MAX_AGE_SECS: u64 = 3600;

/// Default retention time for signatures in minutes (LSPS5 spec requires min 20 minutes).
pub const DEFAULT_SIGNATURE_RETENTION_MINUTES: u64 = 20;

/// Default maximum number of stored signatures.
pub const DEFAULT_MAX_SIGNATURES: usize = 1000;

/// Configuration for signature storage.
#[derive(Clone, Copy, Debug)]
pub struct SignatureStorageConfig {
	/// Maximum number of signatures to store.
	pub max_signatures: usize,
	/// Retention time for signatures in minutes.
	pub retention_minutes: Duration,
}

impl Default for SignatureStorageConfig {
	fn default() -> Self {
		Self {
			max_signatures: DEFAULT_MAX_SIGNATURES,
			retention_minutes: Duration::from_secs(DEFAULT_SIGNATURE_RETENTION_MINUTES * 60),
		}
	}
}

#[derive(Debug, Clone)]
/// Configuration for the LSPS5 client
pub struct LSPS5ClientConfig {
	/// Maximum age in seconds for cached responses (default: 3600 - 1 hour).
	pub response_max_age_secs: Duration,
	/// Configuration for signature storage.
	pub signature_config: SignatureStorageConfig,
}

impl Default for LSPS5ClientConfig {
	fn default() -> Self {
		Self {
			response_max_age_secs: Duration::from_secs(DEFAULT_RESPONSE_MAX_AGE_SECS),
			signature_config: SignatureStorageConfig::default(),
		}
	}
}

struct PeerState {
	pending_set_webhook_requests:
		HashMap<LSPSRequestId, (LSPS5AppName, LSPS5WebhookUrl, LSPSDateTime)>,
	pending_list_webhooks_requests: HashMap<LSPSRequestId, LSPSDateTime>,
	pending_remove_webhook_requests: HashMap<LSPSRequestId, (LSPS5AppName, LSPSDateTime)>,
	last_cleanup: Option<LSPSDateTime>,
	max_age_secs: Duration,
	time_provider: Arc<dyn TimeProvider>,
}

impl PeerState {
	fn new(max_age_secs: Duration, time_provider: Arc<dyn TimeProvider>) -> Self {
		Self {
			pending_set_webhook_requests: new_hash_map(),
			pending_list_webhooks_requests: new_hash_map(),
			pending_remove_webhook_requests: new_hash_map(),
			last_cleanup: None,
			max_age_secs,
			time_provider,
		}
	}

	fn cleanup_expired_responses(&mut self) {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		// Only run cleanup once per minute to avoid excessive processing
		const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
		if let Some(last_cleanup) = &self.last_cleanup {
			let time_since_last_cleanup = Duration::from_secs(now.abs_diff(last_cleanup.clone()));
			if time_since_last_cleanup < CLEANUP_INTERVAL {
				return;
			}
		}

		self.last_cleanup = Some(now.clone());

		self.pending_set_webhook_requests.retain(|_, (_, _, timestamp)| {
			Duration::from_secs(timestamp.abs_diff(now.clone())) < self.max_age_secs
		});
		self.pending_list_webhooks_requests.retain(|_, timestamp| {
			Duration::from_secs(timestamp.abs_diff(now.clone())) < self.max_age_secs
		});
		self.pending_remove_webhook_requests.retain(|_, (_, timestamp)| {
			Duration::from_secs(timestamp.abs_diff(now.clone())) < self.max_age_secs
		});
	}
}

/// Client-side handler for the LSPS5 (bLIP-55) webhook registration protocol.
///
/// `LSPS5ClientHandler` is the primary interface for LSP clients
/// to register, list, and remove webhook endpoints with an LSP, and to parse
/// and validate incoming signed notifications.
///
/// # Core Capabilities
///
///  - `set_webhook(peer, app_name, url)` -> register or update a webhook [`lsps5.set_webhook`]
///  - `list_webhooks(peer)` -> retrieve all registered webhooks [`lsps5.list_webhooks`]
///  - `remove_webhook(peer, name)` -> delete a webhook [`lsps5.remove_webhook`]
///  - `parse_webhook_notification(...)` -> verify signature, timestamp, replay, and emit event
///
/// [`bLIP-55 / LSPS5 specification`]: https://github.com/lightning/blips/pull/55/files
/// [`lsps5.set_webhook`]: super::msgs::LSPS5Request::SetWebhook
/// [`lsps5.list_webhooks`]: super::msgs::LSPS5Request::ListWebhooks
/// [`lsps5.remove_webhook`]: super::msgs::LSPS5Request::RemoveWebhook
pub struct LSPS5ClientHandler<ES: Deref>
where
	ES::Target: EntropySource,
{
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	entropy_source: ES,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	config: LSPS5ClientConfig,
	time_provider: Arc<dyn TimeProvider>,
	recent_signatures: Mutex<VecDeque<(String, LSPSDateTime)>>,
}

impl<ES: Deref> LSPS5ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	/// Constructs an `LSPS5ClientHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		config: LSPS5ClientConfig, time_provider: Arc<dyn TimeProvider>,
	) -> Self {
		let max_signatures = config.signature_config.max_signatures.clone();
		Self {
			pending_messages,
			pending_events,
			entropy_source,
			per_peer_state: RwLock::new(new_hash_map()),
			config,
			time_provider,
			recent_signatures: Mutex::new(VecDeque::with_capacity(max_signatures)),
		}
	}

	fn with_peer_state<F, R>(&self, counterparty_node_id: PublicKey, f: F) -> R
	where
		F: FnOnce(&mut PeerState) -> R,
	{
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock = outer_state_lock.entry(counterparty_node_id).or_insert(Mutex::new(
			PeerState::new(self.config.response_max_age_secs, Arc::clone(&self.time_provider)),
		));
		let mut peer_state_lock = inner_state_lock.lock().unwrap();

		peer_state_lock.cleanup_expired_responses();

		f(&mut *peer_state_lock)
	}

	/// Register or update a webhook endpoint under a human-readable name.
	///
	/// Sends a `lsps5.set_webhook` JSON-RPC request to the given LSP peer.
	///
	/// # Parameters
	/// - `counterparty_node_id`: The LSP node ID to contact.
	/// - `app_name`: A UTF-8 name for this webhook.
	/// - `webhook_url`: HTTPS URL for push notifications.
	///
	/// # Returns
	/// A unique `LSPSRequestId` for correlating the asynchronous response.
	///
	/// Response from the LSP peer will be provided asynchronously through a
	/// [`LSPS5Response::SetWebhook`] or [`LSPS5Response::SetWebhookError`] message, and this client
	/// will then enqueue either a [`WebhookRegistered`] or [`WebhookRegistrationFailed`] event.
	///
	/// **Note**: Ensure the app name is valid and its length does not exceed [`MAX_APP_NAME_LENGTH`].
	/// Also ensure the URL is valid, has HTTPS protocol, its length does not exceed [`MAX_WEBHOOK_URL_LENGTH`]
	/// and that the URL points to a public host.
	///
	/// [`MAX_WEBHOOK_URL_LENGTH`]: super::msgs::MAX_WEBHOOK_URL_LENGTH
	/// [`MAX_APP_NAME_LENGTH`]: super::msgs::MAX_APP_NAME_LENGTH
	/// [`WebhookRegistered`]: super::event::LSPS5ClientEvent::WebhookRegistered
	/// [`WebhookRegistrationFailed`]: super::event::LSPS5ClientEvent::WebhookRegistrationFailed
	/// [`LSPS5Response::SetWebhook`]: super::msgs::LSPS5Response::SetWebhook
	/// [`LSPS5Response::SetWebhookError`]: super::msgs::LSPS5Response::SetWebhookError
	pub fn set_webhook(
		&self, counterparty_node_id: PublicKey, app_name: String, webhook_url: String,
	) -> Result<LSPSRequestId, LSPS5Error> {
		let app_name = LSPS5AppName::from_string(app_name)?;

		let lsps_webhook_url = LSPS5WebhookUrl::from_string(webhook_url)?;

		let request_id = generate_request_id(&self.entropy_source);

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.pending_set_webhook_requests.insert(
				request_id.clone(),
				(
					app_name.clone(),
					lsps_webhook_url.clone(),
					LSPSDateTime::new_from_duration_since_epoch(
						self.time_provider.duration_since_epoch(),
					),
				),
			);
		});

		let request =
			LSPS5Request::SetWebhook(SetWebhookRequest { app_name, webhook: lsps_webhook_url });

		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		Ok(request_id)
	}

	/// List all webhook names currently registered with the LSP.
	///
	/// Sends a `lsps5.list_webhooks` JSON-RPC request to the peer.
	///
	/// # Parameters
	/// - `counterparty_node_id`: The LSP node ID to query.
	///
	/// # Returns
	/// A unique `LSPSRequestId` for correlating the asynchronous response.
	///
	/// Response from the LSP peer will be provided asynchronously through a
	/// [`LSPS5Response::ListWebhooks`] or [`LSPS5Response::ListWebhooksError`] message, and this client
	/// will then enqueue either a [`WebhooksListed`] or [`WebhooksListFailed`] event.
	///
	/// [`WebhooksListed`]: super::event::LSPS5ClientEvent::WebhooksListed
	/// [`WebhooksListFailed`]: super::event::LSPS5ClientEvent::WebhooksListFailed
	/// [`LSPS5Response::ListWebhooks`]: super::msgs::LSPS5Response::ListWebhooks
	/// [`LSPS5Response::ListWebhooksError`]: super::msgs::LSPS5Response::ListWebhooksError
	pub fn list_webhooks(&self, counterparty_node_id: PublicKey) -> LSPSRequestId {
		let request_id = generate_request_id(&self.entropy_source);
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.pending_list_webhooks_requests.insert(request_id.clone(), now);
		});

		let request = LSPS5Request::ListWebhooks(ListWebhooksRequest {});
		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		request_id
	}

	/// Remove a previously registered webhook by its name.
	///
	/// Sends a `lsps5.remove_webhook` JSON-RPC request to the peer.
	///
	/// # Parameters
	/// - `counterparty_node_id`: The LSP node ID to contact.
	/// - `app_name`: The name of the webhook to remove.
	///
	/// # Returns
	/// A unique `LSPSRequestId` for correlating the asynchronous response.
	///
	/// Response from the LSP peer will be provided asynchronously through a
	/// [`LSPS5Response::RemoveWebhook`] or [`LSPS5Response::RemoveWebhookError`] message, and this client
	/// will then enqueue either a [`WebhookRemoved`] or [`WebhookRemovalFailed`] event.
	///
	/// [`WebhookRemoved`]: super::event::LSPS5ClientEvent::WebhookRemoved
	/// [`WebhookRemovalFailed`]: super::event::LSPS5ClientEvent::WebhookRemovalFailed
	/// [`LSPS5Response::RemoveWebhook`]: super::msgs::LSPS5Response::RemoveWebhook
	/// [`LSPS5Response::RemoveWebhookError`]: super::msgs::LSPS5Response::RemoveWebhookError
	pub fn remove_webhook(
		&self, counterparty_node_id: PublicKey, app_name: String,
	) -> Result<LSPSRequestId, LSPS5Error> {
		let app_name = LSPS5AppName::from_string(app_name)?;

		let request_id = generate_request_id(&self.entropy_source);
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state
				.pending_remove_webhook_requests
				.insert(request_id.clone(), (app_name.clone(), now));
		});

		let request = LSPS5Request::RemoveWebhook(RemoveWebhookRequest { app_name });
		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		Ok(request_id)
	}

	fn handle_message(
		&self, message: LSPS5Message, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let (request_id, response) = match message {
			LSPS5Message::Request(_, _) => {
				return Err(LightningError {
					err: format!(
						"Received unexpected request message from {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			},
			LSPS5Message::Response(rid, resp) => (rid, resp),
		};
		let mut result: Result<(), LightningError> = Err(LightningError {
			err: format!("Received LSPS5 response from unknown peer: {}", counterparty_node_id),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		});
		let event_queue_notifier = self.pending_events.notifier();
		let handle_response = |peer_state: &mut PeerState| {
			if let Some((app_name, webhook_url, _)) =
				peer_state.pending_set_webhook_requests.remove(&request_id)
			{
				match &response {
					LSPS5Response::SetWebhook(r) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookRegistered {
							counterparty_node_id: *counterparty_node_id,
							num_webhooks: r.num_webhooks,
							max_webhooks: r.max_webhooks,
							no_change: r.no_change,
							app_name,
							url: webhook_url,
							request_id,
						});
						result = Ok(());
					},
					LSPS5Response::SetWebhookError(e) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookRegistrationFailed {
							counterparty_node_id: *counterparty_node_id,
							error: e.clone().into(),
							app_name,
							url: webhook_url,
							request_id,
						});
						result = Ok(());
					},
					_ => {
						result = Err(LightningError {
							err: "Unexpected response type for SetWebhook".to_string(),
							action: ErrorAction::IgnoreAndLog(Level::Error),
						});
					},
				}
			} else if peer_state.pending_list_webhooks_requests.remove(&request_id).is_some() {
				match &response {
					LSPS5Response::ListWebhooks(r) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhooksListed {
							counterparty_node_id: *counterparty_node_id,
							app_names: r.app_names.clone(),
							max_webhooks: r.max_webhooks,
							request_id,
						});
						result = Ok(());
					},
					LSPS5Response::ListWebhooksError(e) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhooksListFailed {
							counterparty_node_id: *counterparty_node_id,
							error: e.clone().into(),
							request_id,
						});
						result = Ok(());
					},
					_ => {
						result = Err(LightningError {
							err: "Unexpected response type for ListWebhooks".to_string(),
							action: ErrorAction::IgnoreAndLog(Level::Error),
						});
					},
				}
			} else if let Some((app_name, _)) =
				peer_state.pending_remove_webhook_requests.remove(&request_id)
			{
				match &response {
					LSPS5Response::RemoveWebhook(_) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookRemoved {
							counterparty_node_id: *counterparty_node_id,
							app_name,
							request_id,
						});
						result = Ok(());
					},
					LSPS5Response::RemoveWebhookError(e) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookRemovalFailed {
							counterparty_node_id: *counterparty_node_id,
							error: e.clone().into(),
							app_name,
							request_id,
						});
						result = Ok(());
					},
					_ => {
						result = Err(LightningError {
							err: "Unexpected response type for RemoveWebhook".to_string(),
							action: ErrorAction::IgnoreAndLog(Level::Error),
						});
					},
				}
			} else {
				result = Err(LightningError {
					err: format!("Received response for unknown request ID: {}", request_id.0),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			}
		};
		self.with_peer_state(*counterparty_node_id, handle_response);
		result
	}

	fn verify_notification_signature(
		&self, counterparty_node_id: PublicKey, signature_timestamp: &LSPSDateTime,
		signature: &str, notification: &WebhookNotification,
	) -> Result<bool, LSPS5ClientError> {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let diff = signature_timestamp.abs_diff(now);
		const MAX_TIMESTAMP_DRIFT_SECS: u64 = 600;
		if diff > MAX_TIMESTAMP_DRIFT_SECS {
			return Err(LSPS5ClientError::InvalidTimestamp);
		}

		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {:?}",
			signature_timestamp.to_rfc3339(),
			notification
		);

		if message_signing::verify(message.as_bytes(), signature, &counterparty_node_id) {
			Ok(true)
		} else {
			Err(LSPS5ClientError::InvalidSignature)
		}
	}

	fn check_signature_exists(&self, signature: &str) -> Result<(), LSPS5ClientError> {
		let recent_signatures = self.recent_signatures.lock().unwrap();

		for (stored_sig, _) in recent_signatures.iter() {
			if stored_sig == signature {
				return Err(LSPS5ClientError::ReplayAttack);
			}
		}

		Ok(())
	}

	fn store_signature(&self, signature: String) {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let mut recent_signatures = self.recent_signatures.lock().unwrap();

		recent_signatures.push_back((signature, now.clone()));

		let retention_secs = self.config.signature_config.retention_minutes.as_secs();
		recent_signatures.retain(|(_, ts)| now.abs_diff(ts.clone()) <= retention_secs);
		if recent_signatures.len() > self.config.signature_config.max_signatures {
			recent_signatures.truncate(self.config.signature_config.max_signatures);
		}
	}

	/// Parse and validate a webhook notification received from an LSP.
	///
	/// Implements the bLIP-55 / LSPS5 webhook delivery rules:
	/// 1. Parses `notification_json` into a `WebhookNotification` (JSON-RPC 2.0).
	/// 2. Checks that `timestamp` (from `x-lsps5-timestamp`) is within ±10 minutes of local time.
	/// 3. Ensures `signature` (from `x-lsps5-signature`) has not been replayed within the
	///    configured retention window.
	/// 4. Reconstructs the exact string
	///    `"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {timestamp} I notify {body}"`
	///    and verifies the zbase32 LN-style signature against the LSP's node ID.
	///
	/// # Parameters
	/// - `counterparty_node_id`: the LSP's public key, used to verify the signature.
	/// - `timestamp`: ISO8601 time when the LSP created the notification.
	/// - `signature`: the zbase32-encoded LN signature over timestamp+body.
	/// - `notification`: the [`WebhookNotification`] received from the LSP.
	///
	/// On success, emits [`LSPS5ClientEvent::WebhookNotificationReceived`].
	///
	/// Failure reasons include:
	/// - Timestamp too old (drift > 10 minutes)
	/// - Replay attack detected (signature reused)
	/// - Invalid signature (crypto check fails)
	///
	/// Clients should call this method upon receiving a [`LSPS5ServiceEvent::SendWebhookNotification`]
	/// event, before taking action on the notification. This guarantees that only authentic,
	/// non-replayed notifications reach your application.
	///
	/// [`LSPS5ClientEvent::WebhookNotificationReceived`]: super::event::LSPS5ClientEvent::WebhookNotificationReceived
	/// [`LSPS5ServiceEvent::SendWebhookNotification`]: super::event::LSPS5ServiceEvent::SendWebhookNotification
	/// [`WebhookNotification`]: super::msgs::WebhookNotification
	pub fn parse_webhook_notification(
		&self, counterparty_node_id: PublicKey, timestamp: &LSPSDateTime, signature: &str,
		notification: &WebhookNotification,
	) -> Result<(), LSPS5ClientError> {
		match self.verify_notification_signature(
			counterparty_node_id,
			timestamp,
			signature,
			&notification,
		) {
			Ok(signature_valid) => {
				let event_queue_notifier = self.pending_events.notifier();

				self.check_signature_exists(signature)?;

				self.store_signature(signature.to_string());

				event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookNotificationReceived {
					counterparty_node_id,
					notification: notification.clone(),
					timestamp: timestamp.clone(),
					signature_valid,
				});
				Ok(())
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
