// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Service implementation for LSPS5 webhook registration

use super::utils::sign_notification;
use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError};
use crate::lsps5::msgs::{
	ListWebhooksRequest, ListWebhooksResponse, RemoveWebhookRequest, RemoveWebhookResponse,
	SetWebhookRequest, SetWebhookResponse, WebhookNotification, WebhookNotificationMethod,
};
use crate::message_queue::MessageQueue;
use crate::prelude::*;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use chrono::{TimeZone, Utc};
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;

use reqwest;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::runtime::Runtime;

use super::event::LSPS5ServiceEvent;
use super::msgs::{
	LSPS5Message, LSPS5Request, LSPS5Response, LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE,
	LSPS5_TOO_LONG_ERROR_CODE, LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE,
	LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE, LSPS5_URL_PARSE_ERROR_CODE,
};
use super::{MAX_APP_NAME_LENGTH, MAX_WEBHOOK_URL_LENGTH};

/// Minimum number of days to retain webhooks after a client's last channel is closed
pub const MIN_WEBHOOK_RETENTION_DAYS: u32 = 30;

/// A stored webhook
#[derive(Debug, Clone)]
struct StoredWebhook {
	/// App name identifier for this webhook
	app_name: String,
	/// The webhook URL
	url: String,
	/// Client node ID
	client_id: PublicKey,
	/// Last time this webhook was used
	last_used: SystemTime,
	/// Map of notification methods to last time they were sent
	last_notification_sent: HashMap<WebhookNotificationMethod, SystemTime>,
}

/// Configuration for signature storage
#[derive(Clone, Copy, Debug)]
pub struct SignatureStorageConfig {
	/// Maximum number of signatures to store (default: 10000)
	pub max_signatures: usize,
	/// Retention time for signatures in minutes (default: 20)
	pub retention_minutes: u64,
}

impl Default for SignatureStorageConfig {
	fn default() -> Self {
		Self { max_signatures: 10000, retention_minutes: 20 }
	}
}

/// Trait defining HTTP client interface for LSPS5 webhook delivery
pub trait HttpClient: Send + Sync + 'static {
	/// Send a POST request to the webhook URL
	fn post(&self, url: &str, headers: Vec<(String, String)>, body: String) -> Result<(), String>;
}

/// Default HTTP client implementation using reqwest
pub struct DefaultHttpClient {
	client: reqwest::blocking::Client,
}

impl DefaultHttpClient {
	/// Create a new default HTTP client
	pub fn new() -> Self {
		Self {
			client: reqwest::blocking::Client::builder()
				.timeout(std::time::Duration::from_secs(10))
				.build()
				.expect("Failed to create HTTP client"),
		}
	}
}

impl Default for DefaultHttpClient {
	fn default() -> Self {
		Self::new()
	}
}

impl HttpClient for DefaultHttpClient {
	fn post(&self, url: &str, headers: Vec<(String, String)>, body: String) -> Result<(), String> {
		let mut request = self.client.post(url).body(body);

		// Add headers
		for (name, value) in headers {
			request = request.header(&name, value);
		}

		// Send the request
		match request.send() {
			Ok(response) if response.status().is_success() => Ok(()),
			Ok(response) => Err(format!("HTTP request failed with status: {}", response.status())),
			Err(e) => Err(format!("Failed to send HTTP request: {}", e)),
		}
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
	/// Configuration for signature storage
	pub signature_config: SignatureStorageConfig,
	/// Number of worker threads for webhook notification (default: 4)
	pub worker_threads: usize,
	/// HTTP client for webhook delivery
	#[doc(hidden)] // Hide from docs since it uses Arc and can't be directly created
	pub(crate) http_client: Option<Arc<dyn HttpClient>>,
}

impl std::fmt::Debug for LSPS5ServiceConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("LSPS5ServiceConfig")
			.field("max_webhooks_per_client", &self.max_webhooks_per_client)
			.field("signing_key", &"[redacted]")
			.field("notification_cooldown_hours", &self.notification_cooldown_hours)
			.field("signature_config", &self.signature_config)
			.field("worker_threads", &self.worker_threads)
			.field(
				"http_client",
				&if self.http_client.is_some() { "Some(HttpClient)" } else { "None" },
			)
			.finish()
	}
}

impl Default for LSPS5ServiceConfig {
	fn default() -> Self {
		Self {
			max_webhooks_per_client: 10,
			signing_key: SecretKey::from_slice(&[1; 32]).expect("Static key should be valid"),
			notification_cooldown_hours: 24,
			signature_config: SignatureStorageConfig::default(),
			worker_threads: 4,
			http_client: Some(Arc::new(DefaultHttpClient::new())),
		}
	}
}

impl LSPS5ServiceConfig {
	/// Set a custom HTTP client for webhook delivery
	pub fn with_http_client(mut self, http_client: impl HttpClient + 'static) -> Self {
		self.http_client = Some(Arc::new(http_client));
		self
	}
}

/// Service for handling LSPS5 webhook registration
pub struct LSPS5ServiceHandler {
	/// Configuration parameters
	config: LSPS5ServiceConfig,
	/// Map of client node IDs to their registered webhooks
	webhooks: Arc<Mutex<HashMap<PublicKey, HashMap<String, StoredWebhook>>>>,
	/// Map of client node IDs to their channel counts
	client_channel_counts: Arc<Mutex<HashMap<PublicKey, u32>>>,
	/// Tokio runtime for async webhook notifications
	runtime: Option<Runtime>,
	/// Map of recently used signatures to prevent replay attacks
	recent_signatures: Arc<Mutex<VecDeque<(String, SystemTime)>>>,
	/// Event queue for emitting events
	event_queue: Arc<EventQueue>,
	/// Message queue for sending responses
	pending_messages: Arc<MessageQueue>,
	/// HTTP client for webhook delivery
	http_client: Arc<dyn HttpClient>,
}

impl LSPS5ServiceHandler {
	/// Create a new LSPS5 service handler
	///
	/// # Arguments
	/// * `max_webhooks_per_client` - Maximum number of webhooks allowed per client
	/// * `signing_key` - LSP node signing key for notifications
	/// * `event_queue` - Event queue for emitting events
	/// * `notification_cooldown_hours` - Minimum time between sending the same notification type (default: 24)
	pub(crate) fn new(
		event_queue: Arc<EventQueue>, pending_messages: Arc<MessageQueue>,
		config: LSPS5ServiceConfig,
	) -> Self {
		let runtime = tokio::runtime::Builder::new_multi_thread()
			.worker_threads(config.worker_threads)
			.thread_name("lsps5-webhook")
			.enable_all()
			.build()
			.expect("Failed to create tokio runtime for webhook notifications");

		// Capture value before config is moved
		let max_signatures = config.signature_config.max_signatures;

		// Get the HTTP client from config or create a default one
		let http_client =
			config.http_client.clone().unwrap_or_else(|| Arc::new(DefaultHttpClient::new()));

		Self {
			config,
			webhooks: Arc::new(Mutex::new(HashMap::new())),
			client_channel_counts: Arc::new(Mutex::new(HashMap::new())),
			runtime: Some(runtime),
			recent_signatures: Arc::new(Mutex::new(VecDeque::with_capacity(max_signatures))),
			event_queue,
			pending_messages,
			http_client,
		}
	}

	/// Validates a webhook URL
	///
	/// Returns Ok if valid, or a LightningError if invalid
	fn validate_webhook_url(&self, webhook_url: &str) -> Result<reqwest::Url, LightningError> {
		// Validate URL length
		if webhook_url.len() > MAX_WEBHOOK_URL_LENGTH {
			return Err(LightningError {
				err: format!(
					"Webhook URL exceeds maximum length of {} bytes",
					MAX_WEBHOOK_URL_LENGTH
				),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			});
		}

		// Parse and validate URL format
		let url = match reqwest::Url::parse(webhook_url) {
			Ok(url) => url,
			Err(e) => {
				return Err(LightningError {
					err: format!("Failed to parse URL: {}", e),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});
			},
		};

		// Validate protocol is HTTPS
		if url.scheme() != "https" {
			return Err(LightningError {
				err: format!("Unsupported protocol: {}. HTTPS is required.", url.scheme()),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			});
		}

		Ok(url)
	}

	/// Convert a LightningError to LSPSResponseError for API responses
	fn lightning_error_to_response_error(&self, error: &LightningError) -> LSPSResponseError {
		// Match common error patterns and convert to appropriate LSPSResponseError
		if error.err.contains("too long") || error.err.contains("exceeds maximum length") {
			LSPSResponseError {
				code: LSPS5_TOO_LONG_ERROR_CODE,
				message: error.err.clone(),
				data: None,
			}
		} else if error.err.contains("Failed to parse URL") {
			LSPSResponseError {
				code: LSPS5_URL_PARSE_ERROR_CODE,
				message: error.err.clone(),
				data: None,
			}
		} else if error.err.contains("Unsupported protocol") {
			LSPSResponseError {
				code: LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE,
				message: error.err.clone(),
				data: None,
			}
		} else {
			// Generic error case
			LSPSResponseError {
				code: -1, // Generic error code
				message: error.err.clone(),
				data: None,
			}
		}
	}

	/// Handle a set_webhook request
	pub fn handle_set_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: SetWebhookRequest,
	) -> Result<SetWebhookResponse, LSPSResponseError> {
		// Validate app_name length
		if params.app_name.len() > MAX_APP_NAME_LENGTH {
			return Err(LSPSResponseError {
				code: LSPS5_TOO_LONG_ERROR_CODE,
				message: format!(
					"App name exceeds maximum length of {} bytes",
					MAX_APP_NAME_LENGTH
				),
				data: None,
			});
		}

		// Validate URL
		let _url = match self.validate_webhook_url(&params.webhook) {
			Ok(url) => url,
			Err(e) => return Err(self.lightning_error_to_response_error(&e)),
		};

		// Add or replace webhook
		let mut webhooks = self.webhooks.lock().unwrap();

		// Get client's webhooks or create new entry
		let client_webhooks = webhooks.entry(counterparty_node_id).or_insert_with(HashMap::new);

		// Check if we're replacing or adding a new webhook
		let no_change = client_webhooks
			.get(&params.app_name)
			.map_or(false, |webhook| webhook.url == params.webhook);

		// Check if adding would exceed the limit
		if !client_webhooks.contains_key(&params.app_name)
			&& client_webhooks.len() >= self.config.max_webhooks_per_client as usize
		{
			return Err(LSPSResponseError {
				code: LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE,
				message: format!(
					"Maximum of {} webhooks allowed per client",
					self.config.max_webhooks_per_client
				),
				data: Some(
					json!({ "max_webhooks": self.config.max_webhooks_per_client }).to_string(),
				),
			});
		}

		// Add or replace the webhook
		let stored_webhook = StoredWebhook {
			app_name: params.app_name.clone(),
			url: params.webhook.clone(),
			client_id: counterparty_node_id,
			last_used: SystemTime::now(),
			last_notification_sent: HashMap::new(),
		};

		client_webhooks.insert(params.app_name.clone(), stored_webhook);

		// Create response
		let response = SetWebhookResponse {
			num_webhooks: client_webhooks.len() as u32,
			max_webhooks: self.config.max_webhooks_per_client,
			no_change,
		};
		// Emit webhook registration event
		self.event_queue.enqueue(LSPS5ServiceEvent::WebhookRegistered {
			client: counterparty_node_id,
			app_name: params.app_name.clone(),
			url: params.webhook.clone(),
			request_id: request_id.clone(),
			no_change,
		});

		// Send webhook_registered notification if needed
		// According to spec:
		// "The LSP MUST send this notification to this webhook before sending any other notifications to this webhook."
		if !no_change {
			let _ = self.send_webhook_registered_notification(
				counterparty_node_id,
				params.app_name.clone(),
				params.webhook.clone(),
			);
		}

		Ok(response)
	}

	/// Handle a list_webhooks request
	pub fn handle_list_webhooks(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		_params: ListWebhooksRequest,
	) -> Result<ListWebhooksResponse, LSPSResponseError> {
		let webhooks = self.webhooks.lock().unwrap();

		// Get app names for this client
		let app_names = webhooks
			.get(&counterparty_node_id)
			.map(|client_webhooks| client_webhooks.keys().cloned().collect())
			.unwrap_or_else(Vec::new);

		// Emit webhook list event
		self.event_queue.enqueue(LSPS5ServiceEvent::WebhooksListed {
			client: counterparty_node_id,
			app_names: app_names.clone(),
			max_webhooks: self.config.max_webhooks_per_client,
			request_id: request_id.clone(),
		});

		Ok(ListWebhooksResponse { app_names, max_webhooks: self.config.max_webhooks_per_client })
	}

	/// Handle a remove_webhook request
	pub fn handle_remove_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: RemoveWebhookRequest,
	) -> Result<RemoveWebhookResponse, LSPSResponseError> {
		let mut webhooks = self.webhooks.lock().unwrap();

		// Check if this client has webhooks
		if let Some(client_webhooks) = webhooks.get_mut(&counterparty_node_id) {
			// Remove the webhook with the given app_name
			if client_webhooks.remove(&params.app_name).is_some() {
				self.event_queue.enqueue(LSPS5ServiceEvent::WebhookRemoved {
					client: counterparty_node_id,
					app_name: params.app_name,
					request_id: request_id.clone(),
				});

				return Ok(RemoveWebhookResponse {});
			}
		}

		// Webhook not found
		Err(LSPSResponseError {
			code: LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE,
			message: format!("App name not found: {}", params.app_name),
			data: None,
		})
	}

	/// Send a webhook_registered notification to a newly registered webhook
	///
	/// According to spec:
	/// "Only the newly-registered webhook is notified.
	/// Only the newly-registered webhook is contacted for this notification"
	fn send_webhook_registered_notification(
		&self, client_id: PublicKey, app_name: String, url: String,
	) -> Result<(), LightningError> {
		// Create the notification
		let notification = WebhookNotification::webhook_registered();

		// Send the notification
		self.send_notification(
			client_id,
			app_name.clone(),
			url.clone(),
			notification,
			WebhookNotificationMethod::WebhookRegistered,
		)
	}

	/// Send an incoming_payment notification to all of a client's webhooks
	pub fn notify_payment_incoming(&self, client_id: PublicKey) -> Result<(), LightningError> {
		let notification = WebhookNotification::payment_incoming();
		self.broadcast_notification(
			client_id,
			notification,
			WebhookNotificationMethod::PaymentIncoming,
		)
	}

	/// Send an expiry_soon notification to all of a client's webhooks
	pub fn notify_expiry_soon(
		&self, client_id: PublicKey, timeout: u32,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::expiry_soon(timeout);
		self.broadcast_notification(client_id, notification, WebhookNotificationMethod::ExpirySoon)
	}

	/// Send a liquidity_management_request notification to all of a client's webhooks
	pub fn notify_liquidity_management_request(
		&self, client_id: PublicKey,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::liquidity_management_request();
		self.broadcast_notification(
			client_id,
			notification,
			WebhookNotificationMethod::LiquidityManagementRequest,
		)
	}

	/// Send an onion_message_incoming notification to all of a client's webhooks
	pub fn notify_onion_message_incoming(
		&self, client_id: PublicKey,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::onion_message_incoming();
		self.broadcast_notification(
			client_id,
			notification,
			WebhookNotificationMethod::OnionMessageIncoming,
		)
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
		method: WebhookNotificationMethod,
	) -> Result<(), LightningError> {
		// Get all webhooks for this client
		let mut webhooks = self.webhooks.lock().unwrap();
		let client_webhooks = match webhooks.get_mut(&client_id) {
			Some(webhooks) => webhooks,
			None => {
				// No webhooks registered
				return Ok(());
			},
		};

		if client_webhooks.is_empty() {
			// Empty webhook list
			return Ok(());
		}

		// Get current time for cooldown checks
		let now = SystemTime::now();

		// Send to each webhook
		for (app_name, webhook) in client_webhooks.iter_mut() {
			// Check if this notification type was recently sent (cooldown period)
			if let Some(last_sent) = webhook.last_notification_sent.get(&method) {
				if let Ok(duration) = now.duration_since(*last_sent) {
					// Skip if notification was sent less than cooldown_hours ago
					// According to spec: "This timeout must be measurable in hours or days."
					if duration.as_secs() < self.config.notification_cooldown_hours * 3600 {
						// Skip this notification
						continue;
					}
				}
			}

			// Update the last sent time
			webhook.last_notification_sent.insert(method.clone(), now);
			webhook.last_used = now;

			// Send the notification - ignore errors here
			let _ = self.send_notification(
				client_id,
				app_name.clone(),
				webhook.url.clone(),
				notification.clone(),
				method.clone(),
			);
		}

		Ok(())
	}

	/// Send a notification to a webhook URL
	fn send_notification(
		&self, client_id: PublicKey, app_name: String, url: String,
		notification: WebhookNotification, method: WebhookNotificationMethod,
	) -> Result<(), LightningError> {
		// Create timestamp in ISO8601 format using chrono
		let timestamp = {
			let system_time = SystemTime::now();
			let duration_since_epoch =
				system_time.duration_since(std::time::UNIX_EPOCH).map_err(|e| LightningError {
					err: format!("SystemTime before UNIX epoch: {}", e),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})?;
			let secs = duration_since_epoch.as_secs() as i64;
			let nanos = duration_since_epoch.subsec_nanos();
			Utc.timestamp_opt(secs, nanos)
				.single()
				.ok_or_else(|| LightningError {
					err: "Invalid timestamp".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})?
				.format("%Y-%m-%dT%H:%M:%S%.3fZ")
				.to_string()
		};
		// Serialize the notification
		let notification_json =
			serde_json::to_string(&notification).map_err(|e| LightningError {
				err: format!("Failed to serialize notification: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})?;

		// Sign the notification using our utility function
		let signature_hex =
			sign_notification(&notification_json, &timestamp, &self.config.signing_key)?;

		// Store the signature to prevent replay attacks
		// According to spec: "MUST remember the signature for at least 20 minutes"
		self.store_signature(signature_hex.clone());

		// Get the runtime handle
		let runtime = match self.runtime.as_ref() {
			Some(rt) => rt,
			None => {
				return Err(LightningError {
					err: "Runtime not available for webhook notification".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				});
			},
		};

		// Clone what we need for the async task
		let event_queue = self.event_queue.clone();
		let http_client = self.http_client.clone();

		// Send the webhook notification asynchronously
		runtime.spawn(async move {
			// Create the headers
			let headers = vec![
				("Content-Type".to_string(), "application/json".to_string()),
				("x-lsps5-timestamp".to_string(), timestamp.clone()),
				("x-lsps5-signature".to_string(), signature_hex.clone()),
			];

			// Use the HTTP client to send the request
			let result = http_client.post(&url, headers, notification_json.clone());

			match result {
				Ok(()) => {
					event_queue.enqueue(LSPS5ServiceEvent::WebhookNotificationSent {
						client: client_id,
						app_name,
						url,
						method,
						timestamp,
						signature: signature_hex,
					});
				},
				Err(_) => {
					// Silently ignore errors per spec
				},
			}
		});

		Ok(())
	}

	/// Store a signature with timestamp for replay attack prevention
	fn store_signature(&self, signature: String) {
		let mut recent_signatures = self.recent_signatures.lock().unwrap();

		// Add the new signature
		recent_signatures.push_back((signature, SystemTime::now()));

		// Clean up old signatures (older than retention_minutes)
		let retention_duration =
			Duration::from_secs(self.config.signature_config.retention_minutes * 60);
		while let Some((_, time)) = recent_signatures.front() {
			match SystemTime::now().duration_since(*time) {
				Ok(duration) if duration > retention_duration => {
					recent_signatures.pop_front();
				},
				_ => break,
			}
		}

		// Limit the size of the signature store
		while recent_signatures.len() > self.config.signature_config.max_signatures {
			recent_signatures.pop_front();
		}
	}

	/// Update the number of channels for a client
	/// Should be called when channels are opened or closed with a client
	pub fn update_client_channel_count(&self, client_id: PublicKey, channel_count: u32) {
		let mut client_channel_counts = self.client_channel_counts.lock().unwrap();
		client_channel_counts.insert(client_id, channel_count);
	}

	/// Clean up webhooks for clients with no channels that haven't been used in a while
	/// According to spec: "MUST remember all webhooks for at least 7 days after the last channel is closed"
	pub fn prune_stale_webhooks(&self) {
		let now = SystemTime::now();
		let mut webhooks = self.webhooks.lock().unwrap();
		let client_channel_counts = self.client_channel_counts.lock().unwrap();

		// Filter out clients with no remaining webhooks
		webhooks.retain(|client_id, client_webhooks| {
			// Check if client has no channels
			if client_channel_counts.get(client_id).copied().unwrap_or(0) == 0 {
				// Filter out webhooks that haven't been used in at least MIN_WEBHOOK_RETENTION_DAYS
				client_webhooks.retain(|_, webhook| {
					if let Ok(duration) = now.duration_since(webhook.last_used) {
						if duration.as_secs() < (MIN_WEBHOOK_RETENTION_DAYS as u64) * 24 * 60 * 60 {
							// Keep webhook - not stale yet
							true
						} else {
							// Remove stale webhook
							false
						}
					} else {
						// Keep webhook - last_used time is in the future
						true
					}
				});

				// Keep client entry if it still has webhooks
				!client_webhooks.is_empty()
			} else {
				// Keep client entry - client has channels
				true
			}
		});
	}
}

impl Drop for LSPS5ServiceHandler {
	fn drop(&mut self) {
		if let Some(runtime) = self.runtime.take() {
			runtime.shutdown_timeout(std::time::Duration::from_secs(1));
		}
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
				match request {
					LSPS5Request::SetWebhook(params) => {
						match self.handle_set_webhook(
							*counterparty_node_id,
							request_id.clone(),
							params,
						) {
							Ok(response) => {
								let msg = LSPS5Message::Response(
									request_id,
									LSPS5Response::SetWebhook(response),
								)
								.into();
								self.pending_messages.enqueue(counterparty_node_id, msg);
							},
							Err(error) => {
								let error_message = error.message.clone();
								let msg = LSPS5Message::Response(
									request_id,
									LSPS5Response::SetWebhookError(error),
								)
								.into();
								self.pending_messages.enqueue(counterparty_node_id, msg);
								return Err(LightningError {
									err: format!(
										"Error handling SetWebhook request: {}",
										error_message
									),
									action: ErrorAction::IgnoreAndLog(Level::Info),
								});
							},
						}
					},
					LSPS5Request::ListWebhooks(params) => {
						match self.handle_list_webhooks(
							*counterparty_node_id,
							request_id.clone(),
							params,
						) {
							Ok(response) => {
								let msg = LSPS5Message::Response(
									request_id,
									LSPS5Response::ListWebhooks(response),
								)
								.into();
								self.pending_messages.enqueue(counterparty_node_id, msg);
							},
							Err(error) => {
								let error_message = error.message.clone();
								let msg = LSPS5Message::Response(
									request_id,
									LSPS5Response::ListWebhooksError(error),
								)
								.into();
								self.pending_messages.enqueue(counterparty_node_id, msg);
								return Err(LightningError {
									err: format!(
										"Error handling ListWebhooks request: {}",
										error_message
									),
									action: ErrorAction::IgnoreAndLog(Level::Info),
								});
							},
						}
					},
					LSPS5Request::RemoveWebhook(params) => {
						match self.handle_remove_webhook(
							*counterparty_node_id,
							request_id.clone(),
							params,
						) {
							Ok(response) => {
								let msg = LSPS5Message::Response(
									request_id,
									LSPS5Response::RemoveWebhook(response),
								)
								.into();
								self.pending_messages.enqueue(counterparty_node_id, msg);
							},
							Err(error) => {
								let error_message = error.message.clone();
								let msg = LSPS5Message::Response(
									request_id,
									LSPS5Response::RemoveWebhookError(error),
								)
								.into();
								self.pending_messages.enqueue(counterparty_node_id, msg);
								return Err(LightningError {
									err: format!(
										"Error handling RemoveWebhook request: {}",
										error_message
									),
									action: ErrorAction::IgnoreAndLog(Level::Info),
								});
							},
						}
					},
				}
				Ok(())
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
	use crate::events::LiquidityEvent;

	use super::*;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use std::sync::Arc;

	// Dummy HTTP client for testing
	struct DummyHttpClient;
	impl HttpClient for DummyHttpClient {
		fn post(
			&self, _url: &str, _headers: Vec<(String, String)>, _body: String,
		) -> Result<(), String> {
			Ok(())
		}
	}

	#[test]
	fn test_set_webhook_registers_event() {
		let secp = Secp256k1::new();

		let signing_key = SecretKey::from_slice(&[1; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &signing_key);

		let event_queue = Arc::new(EventQueue::new());
		let message_queue = Arc::new(MessageQueue::new());
		let config = LSPS5ServiceConfig {
			max_webhooks_per_client: 2,
			signing_key,
			notification_cooldown_hours: 24,
			signature_config: SignatureStorageConfig::default(),
			worker_threads: 1,
			http_client: Some(Arc::new(DummyHttpClient)),
		};

		let handler = LSPS5ServiceHandler::new(event_queue.clone(), message_queue, config);

		let request_id = LSPSRequestId("lsps5:webhook:123123123".to_owned());
		let params = SetWebhookRequest {
			app_name: "TestApp".to_string(),
			webhook: "https://example.com/webhook".to_string(),
		};

		let res = handler.handle_set_webhook(public_key, request_id.clone(), params.clone());
		assert!(res.is_ok());
		let resp = res.unwrap();
		assert_eq!(resp.num_webhooks, 1);
		assert_eq!(resp.max_webhooks, 2);
		assert_eq!(resp.no_change, false);

		// Verify that the event queue contains a WebhookRegistered event with the expected fields.
		let events = event_queue.get_and_clear_pending_events();
		let found = events.iter().any(|ev| {
			if let LiquidityEvent::LSPS5Service(LSPS5ServiceEvent::WebhookRegistered {
				client,
				app_name: event_app,
				url: event_url,
				request_id: event_req,
				no_change: event_no_change,
			}) = ev
			{
				client == &public_key
					&& event_app == &params.app_name
					&& event_url == &params.webhook
					&& event_req == &request_id
					&& *event_no_change == false
			} else {
				false
			}
		});

		assert!(found, "Expected WebhookRegistered event was not found");
	}
}
