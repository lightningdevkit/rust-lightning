// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Service implementation for LSPS5 webhook registration

use crate::events::EventQueue;
use crate::lsps0::ser::{
	LSPSDateTime, LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError,
};
use crate::lsps5::msgs::{
	ListWebhooksRequest, ListWebhooksResponse, RemoveWebhookRequest, RemoveWebhookResponse,
	SetWebhookRequest, SetWebhookResponse, WebhookNotification, WebhookNotificationMethod,
};
use crate::message_queue::MessageQueue;
use crate::prelude::*;
use core::time::Duration;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;
use lightning::util::message_signing;

use crate::sync::{Arc, Mutex};
use serde_json::json;

use super::event::LSPS5ServiceEvent;
use super::msgs::{
	LSPS5AppName, LSPS5Message, LSPS5Request, LSPS5Response, LSPS5WebhookUrl,
	LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE, LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE,
};

/// Minimum number of days to retain webhooks after a client's last channel is closed
pub const MIN_WEBHOOK_RETENTION_DAYS: u32 = 30;

/// A stored webhook
#[derive(Debug, Clone)]
struct StoredWebhook {
	/// App name identifier for this webhook
	_app_name: LSPS5AppName,
	/// The webhook URL
	url: LSPS5WebhookUrl,
	/// Client node ID
	_counterparty_node_id: PublicKey,
	/// Last time this webhook was used
	last_used: Duration,
	/// Map of notification methods to last time they were sent
	last_notification_sent: HashMap<WebhookNotificationMethod, Duration>,
}

/// Trait defining a time provider for LSPS5 service
/// This trait is used to provide the current time for LSPS5 service operations
/// and to convert between timestamps and durations
pub trait TimeProvider {
	/// Get the current time as a duration since the Unix epoch
	fn duration_since_epoch(&self) -> Duration;
}

/// Default time provider using the system clock
#[derive(Clone, Debug)]
#[cfg(feature = "time")]
pub struct DefaultTimeProvider;

#[cfg(feature = "time")]
impl TimeProvider for DefaultTimeProvider {
	fn duration_since_epoch(&self) -> Duration {
		use std::time::{SystemTime, UNIX_EPOCH};
		SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before Unix epoch")
	}
}

/// Configuration for LSPS5 service
#[derive(Clone)]
pub struct LSPS5ServiceConfig {
	/// Maximum number of webhooks allowed per client (default: 10)
	pub max_webhooks_per_client: u32,
	/// Signing key for LSP notifications
	pub signing_key: SecretKey,
	/// Minimum time between sending the same notification type in hours (default: 24)
	pub notification_cooldown_hours: u64,
}

impl Default for LSPS5ServiceConfig {
	fn default() -> Self {
		Self {
			max_webhooks_per_client: 10,
			signing_key: SecretKey::from_slice(&[1; 32]).expect("Static key should be valid"),
			notification_cooldown_hours: 24,
		}
	}
}

/// Service for handling LSPS5 webhook registration
pub struct LSPS5ServiceHandler {
	/// Configuration parameters
	config: LSPS5ServiceConfig,
	/// Map of client node IDs to their registered webhooks
	webhooks: Arc<Mutex<HashMap<PublicKey, HashMap<LSPS5AppName, StoredWebhook>>>>,
	/// Event queue for emitting events
	event_queue: Arc<EventQueue>,
	/// Message queue for sending responses
	pending_messages: Arc<MessageQueue>,
	/// Time provider for LSPS5 service
	time_provider: Arc<dyn TimeProvider>,
	/// Function for checking if a client has an open channel
	client_has_open_channel: Box<dyn Fn(&PublicKey) -> bool>,
	/// Last time the stale webhooks were pruned
	last_pruning: Arc<Mutex<Option<Duration>>>,
}

impl LSPS5ServiceHandler {
	/// Create a new LSPS5 service handler
	///
	/// # Arguments
	/// * `event_queue` - Event queue for emitting events
	/// * `pending_messages` - Message queue for sending responses
	/// * `client_has_open_channel` - Function that checks if a client has an open channel
	/// * `config` - Configuration for the LSPS5 service
	///
	/// # Panics
	/// Will panic if no HTTP client is provided and a default one cannot be created
	#[cfg(feature = "time")]
	pub(crate) fn new(
		event_queue: Arc<EventQueue>, pending_messages: Arc<MessageQueue>,
		client_has_open_channel: Box<dyn Fn(&PublicKey) -> bool>, config: LSPS5ServiceConfig,
	) -> Option<Self> {
		let time_provider = Arc::new(DefaultTimeProvider);
		Some(Self {
			config,
			webhooks: Arc::new(Mutex::new(new_hash_map())),
			event_queue,
			pending_messages,
			time_provider,
			client_has_open_channel,
			last_pruning: Arc::new(Mutex::new(None)),
		})
	}

	pub(crate) fn _new_with_custom_time_provider(
		event_queue: Arc<EventQueue>, pending_messages: Arc<MessageQueue>,
		client_has_open_channel: Box<dyn Fn(&PublicKey) -> bool>, config: LSPS5ServiceConfig,
		time_provider: Option<Arc<dyn TimeProvider>>,
	) -> Option<Self> {
		let time_provider = match time_provider {
			Some(provider) => provider,
			None => return None,
		};
		Some(Self {
			config,
			webhooks: Arc::new(Mutex::new(new_hash_map())),
			event_queue,
			pending_messages,
			time_provider,
			client_has_open_channel,
			last_pruning: Arc::new(Mutex::new(None)),
		})
	}

	fn check_prune_stale_webhooks(&self) -> Result<(), LightningError> {
		let now = self.time_provider.duration_since_epoch();
		let should_prune = {
			let mut last_pruning = self.last_pruning.lock().map_err(|_| LightningError {
				err: "Failed to lock last_pruning mutex".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})?;

			let should_run = match *last_pruning {
				Some(last_time) => now
					.checked_sub(last_time)
					.map_or(false, |elapsed| elapsed > Duration::from_secs(24 * 60 * 60)),
				None => true,
			};

			if should_run {
				*last_pruning = Some(now);
			}

			should_run
		};

		if should_prune {
			self.prune_stale_webhooks();
		}

		Ok(())
	}

	/// Handle a set_webhook request
	pub fn handle_set_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: SetWebhookRequest,
	) -> Result<(), LightningError> {
		self.check_prune_stale_webhooks()?;

		if let Err(e) = params.app_name.validate() {
			let msg = LSPS5Message::Response(request_id, LSPS5Response::SetWebhookError(e.clone()))
				.into();
			self.pending_messages.enqueue(&counterparty_node_id, msg);
			return Err(LightningError {
				err: e.message,
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		if let Err(e) = params.webhook.validate() {
			let msg = LSPS5Message::Response(request_id, LSPS5Response::SetWebhookError(e.clone()))
				.into();
			self.pending_messages.enqueue(&counterparty_node_id, msg);
			return Err(LightningError {
				err: format!("Error handling SetWebhook request: {}", e.message),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		let mut webhooks = self.webhooks.lock().map_err(|_| LightningError {
			err: "Failed to lock webhooks mutex".to_string(),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		let client_webhooks = webhooks.entry(counterparty_node_id).or_insert_with(new_hash_map);
		let now = self.time_provider.duration_since_epoch();

		let no_change = client_webhooks
			.get(&params.app_name)
			.map_or(false, |webhook| webhook.url == params.webhook);

		if !client_webhooks.contains_key(&params.app_name)
			&& client_webhooks.len() >= self.config.max_webhooks_per_client as usize
		{
			let message = format!(
				"Maximum of {} webhooks allowed per client",
				self.config.max_webhooks_per_client
			);
			let error_response = LSPSResponseError {
				code: LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE,
				message: message.clone(),
				data: Some(
					json!({ "max_webhooks": self.config.max_webhooks_per_client }).to_string(),
				),
			};
			let msg =
				LSPS5Message::Response(request_id, LSPS5Response::SetWebhookError(error_response))
					.into();
			self.pending_messages.enqueue(&counterparty_node_id, msg);
			return Err(LightningError {
				err: message,
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		// Add or replace the webhook
		let stored_webhook = StoredWebhook {
			_app_name: params.app_name.clone(),
			url: params.webhook.clone(),
			_counterparty_node_id: counterparty_node_id,
			last_used: now,
			last_notification_sent: new_hash_map(),
		};

		client_webhooks.insert(params.app_name.clone(), stored_webhook);

		let response = SetWebhookResponse {
			num_webhooks: client_webhooks.len() as u32,
			max_webhooks: self.config.max_webhooks_per_client,
			no_change,
		};
		self.event_queue.enqueue(LSPS5ServiceEvent::WebhookRegistered {
			counterparty_node_id,
			app_name: params.app_name.clone(),
			url: params.webhook.clone(),
			request_id: request_id.clone(),
			no_change,
		});

		// Send webhook_registered notification if needed
		// According to spec:
		// "The LSP MUST send this notification to this webhook before sending any other notifications to this webhook."
		if !no_change {
			self.send_webhook_registered_notification(
				counterparty_node_id,
				params.app_name.clone(),
				params.webhook.clone(),
			)?;
		}

		let msg = LSPS5Message::Response(request_id, LSPS5Response::SetWebhook(response)).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);
		Ok(())
	}

	/// Handle a list_webhooks request
	pub fn handle_list_webhooks(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		_params: ListWebhooksRequest,
	) -> Result<(), LightningError> {
		self.check_prune_stale_webhooks()?;

		let webhooks = self.webhooks.lock().map_err(|_| LightningError {
			err: "Failed to lock webhooks mutex".to_string(),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		let app_names = webhooks
			.get(&counterparty_node_id)
			.map(|client_webhooks| client_webhooks.keys().cloned().collect::<Vec<_>>())
			.unwrap_or_else(Vec::new);

		let max_webhooks = self.config.max_webhooks_per_client;

		self.event_queue.enqueue(LSPS5ServiceEvent::WebhooksListed {
			counterparty_node_id,
			app_names: app_names.clone(),
			max_webhooks,
			request_id: request_id.clone(),
		});

		let response = ListWebhooksResponse { app_names, max_webhooks };
		let msg = LSPS5Message::Response(request_id, LSPS5Response::ListWebhooks(response)).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		Ok(())
	}

	/// Handle a remove_webhook request
	pub fn handle_remove_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: RemoveWebhookRequest,
	) -> Result<(), LightningError> {
		// Check if we need to prune stale webhooks
		self.check_prune_stale_webhooks()?;

		let mut webhooks = self.webhooks.lock().map_err(|_| LightningError {
			err: "Failed to lock webhooks mutex".to_string(),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		if let Some(client_webhooks) = webhooks.get_mut(&counterparty_node_id) {
			if client_webhooks.remove(&params.app_name).is_some() {
				let response = RemoveWebhookResponse {};
				let msg = LSPS5Message::Response(
					request_id.clone(),
					LSPS5Response::RemoveWebhook(response),
				)
				.into();
				self.pending_messages.enqueue(&counterparty_node_id, msg);
				self.event_queue.enqueue(LSPS5ServiceEvent::WebhookRemoved {
					counterparty_node_id,
					app_name: params.app_name,
					request_id,
				});

				return Ok(());
			}
		}

		let error_message = format!("App name not found: {}", params.app_name);
		let error_response = LSPSResponseError {
			code: LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE,
			message: error_message.clone(),
			data: None,
		};

		let msg =
			LSPS5Message::Response(request_id, LSPS5Response::RemoveWebhookError(error_response))
				.into();

		self.pending_messages.enqueue(&counterparty_node_id, msg);
		return Err(LightningError {
			err: error_message,
			action: ErrorAction::IgnoreAndLog(Level::Info),
		});
	}

	/// Send a webhook_registered notification to a newly registered webhook
	///
	/// According to spec:
	/// "Only the newly-registered webhook is notified.
	/// Only the newly-registered webhook is contacted for this notification"
	fn send_webhook_registered_notification(
		&self, client_node_id: PublicKey, app_name: LSPS5AppName, url: LSPS5WebhookUrl,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::webhook_registered();
		self.send_notification(client_node_id, app_name.clone(), url.clone(), notification)
	}

	/// Send an incoming_payment notification to all of a client's webhooks
	pub fn notify_payment_incoming(&self, client_id: PublicKey) -> Result<(), LightningError> {
		let notification = WebhookNotification::payment_incoming();
		self.broadcast_notification(client_id, notification)
	}

	/// Send an expiry_soon notification to all of a client's webhooks
	pub fn notify_expiry_soon(
		&self, client_id: PublicKey, timeout: u32,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::expiry_soon(timeout);
		self.broadcast_notification(client_id, notification)
	}

	/// Send a liquidity_management_request notification to all of a client's webhooks
	pub fn notify_liquidity_management_request(
		&self, client_id: PublicKey,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::liquidity_management_request();
		self.broadcast_notification(client_id, notification)
	}

	/// Send an onion_message_incoming notification to all of a client's webhooks
	pub fn notify_onion_message_incoming(
		&self, client_id: PublicKey,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::onion_message_incoming();
		self.broadcast_notification(client_id, notification)
	}

	/// Broadcast a notification to all registered webhooks for a client
	///
	/// According to spec:
	/// "The LSP SHOULD contact all registered webhook URIs, if:
	/// * The client has registered at least one via `lsps5.set_webhook`.
	/// * *and* the client currently does not have a BOLT8 tunnel with the LSP.
	/// * *and* one of the specified events has occurred."
	fn broadcast_notification(
		&self, client_id: PublicKey, notification: WebhookNotification,
	) -> Result<(), LightningError> {
		let mut webhooks = self.webhooks.lock().map_err(|_| LightningError {
			err: "Failed to lock webhooks mutex".to_string(),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

		let client_webhooks = match webhooks.get_mut(&client_id) {
			Some(webhooks) if !webhooks.is_empty() => webhooks,
			_ => return Ok(()),
		};

		let now = self.time_provider.duration_since_epoch();
		let cooldown_duration = Duration::from_secs(self.config.notification_cooldown_hours * 3600);

		for (app_name, webhook) in client_webhooks.iter_mut() {
			if webhook
				.last_notification_sent
				.get(&notification.method)
				.and_then(|last_sent| now.checked_sub(*last_sent))
				.map_or(true, |duration| duration >= cooldown_duration)
			{
				webhook.last_notification_sent.insert(notification.method.clone(), now);
				webhook.last_used = now;

				self.send_notification(
					client_id,
					app_name.clone(),
					webhook.url.clone(),
					notification.clone(),
				)?;
			}
		}

		Ok(())
	}

	/// Send a notification to a webhook URL
	fn send_notification(
		&self, counterparty_node_id: PublicKey, app_name: LSPS5AppName, url: LSPS5WebhookUrl,
		notification: WebhookNotification,
	) -> Result<(), LightningError> {
		let timestamp = LSPSDateTime::from(self.time_provider.duration_since_epoch()).to_rfc3339();

		let notification_json =
			serde_json::to_string(&notification).map_err(|e| LightningError {
				err: format!("Failed to serialize notification: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})?;

		let signature_hex = self.sign_notification(&notification_json, &timestamp)?;

		let headers = vec![
			("Content-Type".to_string(), "application/json".to_string()),
			("x-lsps5-timestamp".to_string(), timestamp.clone()),
			("x-lsps5-signature".to_string(), signature_hex.clone()),
		];

		self.event_queue.enqueue(LSPS5ServiceEvent::SendWebhookNotifications {
			counterparty_node_id,
			app_name,
			url,
			notification,
			timestamp,
			signature: signature_hex,
			headers,
		});

		Ok(())
	}

	/// Sign a webhook notification with an LSP's signing key
	///
	/// This function takes a notification body and timestamp and returns a signature
	/// in the format required by the LSPS5 specification.
	///
	/// # Arguments
	///
	/// * `body` - The serialized notification JSON
	/// * `timestamp` - The ISO8601 timestamp string
	/// * `signing_key` - The LSP private key used for signing
	///
	/// # Returns
	///
	/// * The zbase32 encoded signature as specified in LSPS0, or an error if signing fails
	pub fn sign_notification(&self, body: &str, timestamp: &str) -> Result<String, LightningError> {
		// Create the message to sign
		// According to spec:
		// The message to be signed is: "LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
			timestamp, body
		);

		Ok(message_signing::sign(message.as_bytes(), &self.config.signing_key))
	}

	/// Clean up webhooks for clients with no channels that haven't been used in a while
	/// According to spec: "MUST remember all webhooks for at least 7 days after the last channel is closed"
	fn prune_stale_webhooks(&self) {
		let now = self.time_provider.duration_since_epoch();
		let webhooks_lock = match self.webhooks.lock() {
			Ok(guard) => guard,
			Err(_) => return,
		};
		let mut webhooks = webhooks_lock;
		let retention_period =
			Duration::from_secs(MIN_WEBHOOK_RETENTION_DAYS as u64 * 24 * 60 * 60);

		webhooks.retain(|client_id, client_webhooks| {
			if !(self.client_has_open_channel)(client_id) {
				client_webhooks.retain(|_, webhook| {
					now.checked_sub(webhook.last_used)
						.map_or(true, |duration| duration < retention_period)
				});
				!client_webhooks.is_empty()
			} else {
				true
			}
		});
	}
}

impl LSPSProtocolMessageHandler for LSPS5ServiceHandler {
	type ProtocolMessage = LSPS5Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(2);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS5Message::Request(request_id, request) => {
				let res = match request {
					LSPS5Request::SetWebhook(params) => {
						self.handle_set_webhook(*counterparty_node_id, request_id.clone(), params)
					},
					LSPS5Request::ListWebhooks(params) => {
						self.handle_list_webhooks(*counterparty_node_id, request_id.clone(), params)
					},
					LSPS5Request::RemoveWebhook(params) => self.handle_remove_webhook(
						*counterparty_node_id,
						request_id.clone(),
						params,
					),
				};
				res
			},
			_ => {
				debug_assert!(
					false,
					"Service handler received LSPS5 response message. This should never happen."
				);
				Err(LightningError {
                    err: format!("Service handler received LSPS5 response message from node {:?}. This should never happen.", counterparty_node_id),
                    action: ErrorAction::IgnoreAndLog(Level::Info)
                })
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::cell::RefCell;

	// Mock time provider for testing
	struct MockTimeProvider {
		current_time: RefCell<Duration>,
	}

	impl MockTimeProvider {
		fn new(seconds_since_epoch: u64) -> Self {
			Self { current_time: RefCell::new(Duration::from_secs(seconds_since_epoch)) }
		}

		fn advance_time(&self, seconds: u64) {
			let mut time = self.current_time.borrow_mut();
			*time += Duration::from_secs(seconds);
		}
	}

	impl TimeProvider for MockTimeProvider {
		fn duration_since_epoch(&self) -> Duration {
			*self.current_time.borrow()
		}
	}

	// Test for prune_stale_webhooks
	#[test]
	fn test_prune_stale_webhooks() {
		let event_queue = Arc::new(EventQueue::new());
		let pending_messages = Arc::new(MessageQueue::new());
		let config = LSPS5ServiceConfig::default();
		let time_provider = Arc::new(MockTimeProvider::new(1000)); // Starting time

		let mut client_keys = Vec::new();
		for i in 0..3 {
			let key = SecretKey::from_slice(&[i + 1; 32]).expect("Valid key slice");
			let pubkey = PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &key);
			client_keys.push(pubkey);
		}

		let nodes_with_channels = Arc::new(Mutex::new(new_hash_set()));

		let channels_for_closure = nodes_with_channels.clone();

		let client_has_open_channel = Box::new(move |pubkey: &PublicKey| -> bool {
			channels_for_closure.lock().unwrap().contains(pubkey)
		});

		let handler = LSPS5ServiceHandler::_new_with_custom_time_provider(
			event_queue,
			pending_messages,
			client_has_open_channel,
			config,
			Some(time_provider.clone()),
		)
		.unwrap();

		{
			let mut webhooks = handler.webhooks.lock().unwrap();
			for (i, pubkey) in client_keys.iter().enumerate() {
				let client_webhooks = webhooks.entry(*pubkey).or_insert_with(new_hash_map);
				for j in 0..2 {
					let app_name = LSPS5AppName::new(format!("app_{}_{}", i, j)).unwrap();
					let url =
						LSPS5WebhookUrl::new(format!("https://example.com/webhook_{}_{}", i, j))
							.unwrap();
					client_webhooks.insert(
						app_name.clone(),
						StoredWebhook {
							_app_name: app_name,
							url,
							_counterparty_node_id: *pubkey,
							last_used: time_provider.duration_since_epoch(),
							last_notification_sent: new_hash_map(),
						},
					);
				}
			}
		}

		for i in 0..2 {
			nodes_with_channels.lock().unwrap().insert(client_keys[i]);
		}

		time_provider.advance_time(15 * 24 * 60 * 60);

		handler.prune_stale_webhooks();

		{
			let webhooks = handler.webhooks.lock().unwrap();
			assert_eq!(webhooks.len(), 3);
		}

		time_provider.advance_time(20 * 24 * 60 * 60);

		handler.prune_stale_webhooks();

		{
			let webhooks = handler.webhooks.lock().unwrap();
			assert_eq!(webhooks.len(), 2);
			assert!(webhooks.contains_key(&client_keys[0]));
			assert!(webhooks.contains_key(&client_keys[1]));
			assert!(!webhooks.contains_key(&client_keys[2]));
		}

		{
			let mut channels = nodes_with_channels.lock().unwrap();
			channels.remove(&client_keys[1]);
		}

		time_provider.advance_time(40 * 24 * 60 * 60);

		handler.prune_stale_webhooks();

		{
			let webhooks = handler.webhooks.lock().unwrap();
			assert_eq!(webhooks.len(), 1);
			assert!(webhooks.contains_key(&client_keys[0]));
			assert!(!webhooks.contains_key(&client_keys[1]));
			assert!(!webhooks.contains_key(&client_keys[2]));
		}
	}
}
