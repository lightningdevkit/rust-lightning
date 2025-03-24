// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Service implementation for LSPS5 webhook registration

use core::time::Duration;

use super::url_utils::Url;
use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError};
use crate::lsps5::msgs::{
	ListWebhooksRequest, ListWebhooksResponse, RemoveWebhookRequest, RemoveWebhookResponse,
	SetWebhookRequest, SetWebhookResponse, WebhookNotification, WebhookNotificationMethod,
};
use crate::message_queue::MessageQueue;
use crate::prelude::*;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;
use lightning::util::message_signing;

use crate::sync::{Arc, Mutex};
use serde_json::json;

use super::event::LSPS5ServiceEvent;
use super::msgs::LSPS5Message;
use super::msgs::LSPS5Request;
use super::msgs::LSPS5Response;
use super::msgs::Lsps5AppName;
use super::msgs::Lsps5WebhookUrl;
use super::msgs::LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE;
use super::msgs::LSPS5_TOO_LONG_ERROR_CODE;
use super::msgs::LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE;
use super::msgs::LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE;
use super::msgs::LSPS5_URL_PARSE_ERROR_CODE;
use super::msgs::MAX_APP_NAME_LENGTH;
use super::msgs::MAX_WEBHOOK_URL_LENGTH;

/// Minimum number of days to retain webhooks after a client's last channel is closed
pub const MIN_WEBHOOK_RETENTION_DAYS: u32 = 30;

/// A stored webhook
#[derive(Debug, Clone)]
struct StoredWebhook {
	/// App name identifier for this webhook
	_app_name: Lsps5AppName,
	/// The webhook URL
	url: Lsps5WebhookUrl,
	/// Client node ID
	_counterparty_node_id: PublicKey,
	/// Last time this webhook was used
	last_used: Duration,
	/// Map of notification methods to last time they were sent
	last_notification_sent: HashMap<WebhookNotificationMethod, Duration>,
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
///
/// # Example Implementation
///
/// ```
/// use lightning_liquidity::lsps5::service::HttpClient;
///
/// // A simple HTTP client implementation
/// pub struct MyHttpClient {
///     // Your HTTP client internals go here
///     // While you can use any HTTP client library, here are some common patterns:
///
///     // - With **reqwest**: Implement using `reqwest::blocking::Client` with appropriate error handling
///     // - With **ureq**: Create requests with `ureq::post(url).set("header", "value").send_string(&body)`
///     // - With **hyper**: Use an executor for async requests or wrap in a blocking interface
///     // - With **curl**: Use the curl crate to make HTTP requests directly
/// }
///
/// impl MyHttpClient {
///     pub fn new() -> Self {
///         Self {
///             // Initialize your HTTP client here
///         }
///     }
/// }
///
/// impl HttpClient for MyHttpClient {
///     fn post(&self, url: &str, headers: Vec<(String, String)>, body: String) -> Result<(), String> {
///         // Example implementation steps:
///         // 1. Create a new POST request to the URL
///         // 2. Set the headers from the headers Vec
///         // 3. Set the body content
///         // 4. Send the request
///         // 5. Return Ok(()) for success or Err with message for failure
///         
///         println!("Sending webhook to: {}", url);
///         println!("With headers: {:?}", headers);
///         println!("And body: {}", body);
///         
///         // Replace this with actual implementation using your HTTP library of choice
///         Ok(())
///     }
/// }
///
/// // Usage in an LSP implementation:
/// fn example() {
///     let my_http_client = MyHttpClient::new();
///     let config = lightning_liquidity::lsps5::service::LSPS5ServiceConfig::default()
///         .with_http_client(my_http_client);
///     // Pass config when creating LSPS5ServiceHandler
/// }
/// ```
pub trait HttpClient: Send + Sync + 'static {
	/// Send a POST request to the webhook URL
	///
	/// # Arguments
	/// * `url` - The destination URL for the webhook notification
	/// * `headers` - A list of HTTP headers to include in the request
	/// * `body` - The JSON body to send in the request
	///
	/// # Returns
	/// * `Ok(())` if the notification was sent successfully
	/// * `Err(String)` with an error message if the notification failed
	fn post(&self, url: &str, headers: Vec<(String, String)>, body: String) -> Result<(), String>;
}

/// Trait defining a time provider for LSPS5 service
/// This trait is used to provide the current time for LSPS5 service operations
/// and to convert between timestamps and durations
pub trait TimeProvider: Send + Sync + 'static {
	/// Get the current time as a duration since the Unix epoch
	fn now(&self) -> Duration;
}

/// Default time provider using the system clock
#[derive(Clone, Debug)]
#[cfg(feature = "std")]
pub struct DefaultTimeProvider;

#[cfg(feature = "std")]
impl TimeProvider for DefaultTimeProvider {
	fn now(&self) -> Duration {
		use std::time::{SystemTime, UNIX_EPOCH};
		let now =
			SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before Unix epoch");
		Duration::from_secs(now.as_secs())
	}
}

/// Convert an RFC3339 timestamp string to a Duration
pub fn from_rfc3339(s: &str) -> Result<Duration, String> {
	use chrono::DateTime;
	let dt = DateTime::parse_from_rfc3339(s).map_err(|e| e.to_string())?;
	let now = dt.timestamp();
	Ok(Duration::from_secs(now as u64))
}

/// Convert a Duration to an RFC3339 timestamp string
pub fn to_rfc3339(duration: Duration) -> String {
	use chrono::DateTime;
	(DateTime::from_timestamp(duration.as_secs() as i64, duration.subsec_nanos()).unwrap())
		.to_rfc3339()
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
	/// Time provider for LSPS5 service
	pub time_provider: Option<Arc<dyn TimeProvider>>,
	/// HTTP client for webhook delivery
	#[doc(hidden)] // Hide from docs since it uses Arc and can't be directly created
	pub(crate) http_client: Option<Arc<dyn HttpClient>>,
}

impl Default for LSPS5ServiceConfig {
	fn default() -> Self {
		Self {
			max_webhooks_per_client: 10,
			signing_key: SecretKey::from_slice(&[1; 32]).expect("Static key should be valid"),
			notification_cooldown_hours: 24,
			signature_config: SignatureStorageConfig::default(),
			http_client: None,
			#[cfg(feature = "std")]
			time_provider: Some(Arc::new(DefaultTimeProvider)),
			#[cfg(not(feature = "std"))]
			time_provider: None,
		}
	}
}

impl LSPS5ServiceConfig {
	/// Set a custom HTTP client for webhook delivery
	pub fn with_http_client(mut self, http_client: impl HttpClient + 'static) -> Self {
		self.http_client = Some(Arc::new(http_client));
		self
	}

	/// Set a custom time provider for the LSPS5 service
	pub fn with_time_provider(mut self, time_provider: impl TimeProvider + 'static) -> Self {
		self.time_provider = Some(Arc::new(time_provider));
		self
	}
}

/// Service for handling LSPS5 webhook registration
pub struct LSPS5ServiceHandler {
	/// Configuration parameters
	config: LSPS5ServiceConfig,
	/// Map of client node IDs to their registered webhooks
	webhooks: Arc<Mutex<HashMap<PublicKey, HashMap<Lsps5AppName, StoredWebhook>>>>,
	/// Map of client node IDs to their channel counts
	client_channel_counts: Arc<Mutex<HashMap<PublicKey, u32>>>,
	/// Map of recently used signatures to prevent replay attacks
	recent_signatures: Arc<Mutex<VecDeque<(String, Duration)>>>,
	/// Event queue for emitting events
	event_queue: Arc<EventQueue>,
	/// Message queue for sending responses
	pending_messages: Arc<MessageQueue>,
	/// HTTP client for webhook delivery
	http_client: Arc<dyn HttpClient>,
	/// Time provider for LSPS5 service
	time_provider: Arc<dyn TimeProvider>,
}

impl LSPS5ServiceHandler {
	/// Create a new LSPS5 service handler
	///
	/// # Arguments
	/// * `event_queue` - Event queue for emitting events
	/// * `pending_messages` - Message queue for sending responses
	/// * `config` - Configuration for the LSPS5 service
	///
	/// # Panics
	/// Will panic if no HTTP client is provided and a default one cannot be created
	pub(crate) fn new(
		event_queue: Arc<EventQueue>, pending_messages: Arc<MessageQueue>,
		mut config: LSPS5ServiceConfig,
	) -> Self {
		// Verify we have an HTTP client
		if config.http_client.is_none() {
			panic!("No HTTP client provided in LSPS5ServiceConfig. Use config.with_http_client() to set one.");
		}

		// Extract the HTTP client
		let http_client: Arc<dyn HttpClient> =
			config.http_client.take().expect("HTTP client should be present");
		let max_signatures = config.signature_config.max_signatures.clone();
		let time_provider = config.time_provider.take().expect("Time provider should be present");
		Self {
			config,
			webhooks: Arc::new(Mutex::new(new_hash_map())),
			client_channel_counts: Arc::new(Mutex::new(new_hash_map())),
			recent_signatures: Arc::new(Mutex::new(VecDeque::with_capacity(max_signatures))),
			event_queue,
			pending_messages,
			http_client,
			time_provider,
		}
	}

	/// Validates a webhook URL
	///
	/// Returns Ok if valid, or a LightningError if invalid
	fn validate_webhook_url(&self, webhook_url: &Lsps5WebhookUrl) -> Result<(), LSPSResponseError> {
		// Validate URL length
		if webhook_url.len() > MAX_WEBHOOK_URL_LENGTH {
			return Err(LSPSResponseError {
				code: LSPS5_TOO_LONG_ERROR_CODE,
				message: format!(
					"Webhook URL exceeds maximum length of {} bytes",
					MAX_WEBHOOK_URL_LENGTH
				),
				data: None,
			});
		}

		// Parse and validate URL format
		let url = match Url::parse(webhook_url.as_str()) {
			Ok(url) => url,
			Err(e) => {
				return Err(LSPSResponseError {
					code: LSPS5_URL_PARSE_ERROR_CODE,
					message: format!("Failed to parse URL: {}", e),
					data: None,
				});
			},
		};

		// Validate protocol is HTTPS
		if url.scheme() != "https" {
			return Err(LSPSResponseError {
				code: LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE,
				message: format!("Unsupported protocol: {}. HTTPS is required.", url.scheme()),
				data: None,
			});
		}

		Ok(())
	}

	/// Handle a set_webhook request
	pub fn handle_set_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: SetWebhookRequest,
	) -> Result<(), LightningError> {
		// Validate app_name length
		if params.app_name.len() > MAX_APP_NAME_LENGTH {
			let error_message =
				format!("App name exceeds maximum length of {} bytes", MAX_APP_NAME_LENGTH);
			let msg = LSPS5Message::Response(
				request_id,
				LSPS5Response::SetWebhookError(LSPSResponseError {
					code: LSPS5_TOO_LONG_ERROR_CODE,
					message: error_message.clone(),
					data: None,
				}),
			)
			.into();
			self.pending_messages.enqueue(&counterparty_node_id, msg);
			return Err(LightningError {
				err: error_message.clone(),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		// Validate URL
		match self.validate_webhook_url(&params.webhook) {
			Ok(_) => (),
			Err(e) => {
				let error_message = e.message.clone();
				let msg =
					LSPS5Message::Response(request_id, LSPS5Response::SetWebhookError(e)).into();
				self.pending_messages.enqueue(&counterparty_node_id, msg);
				return Err(LightningError {
					err: format!("Error handling SetWebhook request: {}", error_message),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			},
		};

		// Add or replace webhook
		let mut webhooks = self.webhooks.lock().unwrap();

		// Get client's webhooks or create new entry
		let client_webhooks =
			webhooks.entry(counterparty_node_id).or_insert_with(|| new_hash_map());

		// Check if we're replacing or adding a new webhook
		let no_change = client_webhooks
			.get(&params.app_name)
			.map_or(false, |webhook| webhook.url == params.webhook);

		// Check if adding would exceed the limit
		if !client_webhooks.contains_key(&params.app_name)
			&& client_webhooks.len() >= self.config.max_webhooks_per_client as usize
		{
			let error_message = format!(
				"Maximum of {} webhooks allowed per client",
				self.config.max_webhooks_per_client
			);
			let msg = LSPS5Message::Response(
				request_id,
				LSPS5Response::SetWebhookError(LSPSResponseError {
					code: LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE,
					message: format!(
						"Maximum of {} webhooks allowed per client",
						self.config.max_webhooks_per_client
					),
					data: Some(
						json!({ "max_webhooks": self.config.max_webhooks_per_client }).to_string(),
					),
				}),
			)
			.into();
			self.pending_messages.enqueue(&counterparty_node_id, msg);
			return Err(LightningError {
				err: error_message,
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		// Add or replace the webhook
		let stored_webhook = StoredWebhook {
			_app_name: params.app_name.clone(),
			url: params.webhook.clone(),
			_counterparty_node_id: counterparty_node_id,
			last_used: self.time_provider.now(),
			last_notification_sent: new_hash_map(),
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
			let _ = self.send_webhook_registered_notification(
				counterparty_node_id,
				params.app_name,
				params.webhook,
			);
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
		let webhooks = self.webhooks.lock().unwrap();

		// Get app names for this client
		let app_names = webhooks
			.get(&counterparty_node_id)
			.map(|client_webhooks| client_webhooks.keys().cloned().collect())
			.unwrap_or_else(Vec::new);

		// Emit webhook list event
		self.event_queue.enqueue(LSPS5ServiceEvent::WebhooksListed {
			counterparty_node_id,
			app_names: app_names.clone(),
			max_webhooks: self.config.max_webhooks_per_client,
			request_id: request_id.clone(),
		});
		let response =
			ListWebhooksResponse { app_names, max_webhooks: self.config.max_webhooks_per_client };
		let msg = LSPS5Message::Response(request_id, LSPS5Response::ListWebhooks(response)).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		Ok(())
	}

	/// Handle a remove_webhook request
	pub fn handle_remove_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: RemoveWebhookRequest,
	) -> Result<(), LightningError> {
		let mut webhooks = self.webhooks.lock().unwrap();

		// Check if this client has webhooks
		if let Some(client_webhooks) = webhooks.get_mut(&counterparty_node_id) {
			// Remove the webhook with the given app_name
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
					request_id: request_id.clone(),
				});

				return Ok(());
			}
		}

		let error_message = format!("App name not found: {}", params.app_name);
		let msg = LSPS5Message::Response(
			request_id,
			LSPS5Response::RemoveWebhookError(LSPSResponseError {
				code: LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE,
				message: error_message.clone(),
				data: None,
			}),
		)
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
		&self, client_node_id: PublicKey, app_name: Lsps5AppName, url: Lsps5WebhookUrl,
	) -> Result<(), LightningError> {
		// Create the notification
		let notification = WebhookNotification::webhook_registered();

		// Send the notification
		self.send_notification(
			client_node_id,
			app_name.clone(),
			url.clone(),
			notification,
			WebhookNotificationMethod::LSPS5WebhookRegistered,
		)
	}

	/// Send an incoming_payment notification to all of a client's webhooks
	pub fn notify_payment_incoming(&self, client_id: PublicKey) -> Result<(), LightningError> {
		let notification = WebhookNotification::payment_incoming();
		self.broadcast_notification(
			client_id,
			notification,
			WebhookNotificationMethod::LSPS5PaymentIncoming,
		)
	}

	/// Send an expiry_soon notification to all of a client's webhooks
	pub fn notify_expiry_soon(
		&self, client_id: PublicKey, timeout: u32,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::expiry_soon(timeout);
		self.broadcast_notification(
			client_id,
			notification,
			WebhookNotificationMethod::LSPS5ExpirySoon,
		)
	}

	/// Send a liquidity_management_request notification to all of a client's webhooks
	pub fn notify_liquidity_management_request(
		&self, client_id: PublicKey,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::liquidity_management_request();
		self.broadcast_notification(
			client_id,
			notification,
			WebhookNotificationMethod::LSPS5LiquidityManagementRequest,
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
			WebhookNotificationMethod::LSPS5OnionMessageIncoming,
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
		let now = self.time_provider.now();

		// Send to each webhook
		for (app_name, webhook) in client_webhooks.iter_mut() {
			// Check if this notification type was recently sent (cooldown period)
			if let Some(last_sent) = webhook.last_notification_sent.get(&method) {
				let duration = now.checked_sub(*last_sent).unwrap();
				// Skip if notification was sent less than cooldown_hours ago
				// According to spec: "This timeout must be measurable in hours or days."
				if duration.as_secs() < self.config.notification_cooldown_hours * 3600 {
					// Skip this notification
					continue;
				}
			}

			// Update the last sent time
			webhook.last_notification_sent.insert(method.clone(), now.clone());
			webhook.last_used = now.clone();

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
		&self, counterparty_node_id: PublicKey, app_name: Lsps5AppName, url: Lsps5WebhookUrl,
		notification: WebhookNotification, method: WebhookNotificationMethod,
	) -> Result<(), LightningError> {
		// Create timestamp in ISO8601 format using chrono
		let timestamp = to_rfc3339(self.time_provider.now());

		// Serialize the notification
		let notification_json =
			serde_json::to_string(&notification).map_err(|e| LightningError {
				err: format!("Failed to serialize notification: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})?;

		// Sign the notification using our utility function
		let signature_hex =
			Self::sign_notification(&notification_json, &timestamp, &self.config.signing_key)?;

		// Store the signature to prevent replay attacks
		// According to spec: "MUST remember the signature for at least 20 minutes"
		self.store_signature(signature_hex.clone());

		// Create the headers
		let headers = vec![
			("Content-Type".to_string(), "application/json".to_string()),
			("x-lsps5-timestamp".to_string(), timestamp.clone()),
			("x-lsps5-signature".to_string(), signature_hex.clone()),
		];

		// Use the HTTP client to send the request synchronously
		let result = self.http_client.post(&url.as_str(), headers, notification_json);

		// Record successful notifications through event queue
		if result.is_ok() {
			self.event_queue.enqueue(LSPS5ServiceEvent::WebhookNotificationSent {
				counterparty_node_id,
				app_name,
				url,
				method,
				timestamp,
				signature: signature_hex,
			});
		}
		// Ignore errors per spec (just don't emit the event)

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
	pub fn sign_notification(
		body: &str, timestamp: &str, signing_key: &SecretKey,
	) -> Result<String, LightningError> {
		// Create the message to sign
		// According to spec:
		// The message to be signed is: "LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
			timestamp, body
		);

		// Use the canonical message signing implementation from lightning::util::message_signing
		let signature = message_signing::sign(message.as_bytes(), signing_key);

		Ok(signature)
	}

	/// Store a signature with timestamp for replay attack prevention
	fn store_signature(&self, signature: String) {
		let now = self.time_provider.now();
		let mut recent_signatures = self.recent_signatures.lock().unwrap();

		// Add the new signature
		recent_signatures.push_back((signature, now));

		// Clean up old signatures (older than retention_minutes)
		let retention_duration =
			Duration::from_secs(self.config.signature_config.retention_minutes * 60);
		while let Some((_, time)) = recent_signatures.front() {
			let duration = now - *time;
			if duration > retention_duration {
				recent_signatures.pop_front();
			} else {
				break;
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
		let now = self.time_provider.now();
		let mut webhooks = self.webhooks.lock().unwrap();
		let client_channel_counts = self.client_channel_counts.lock().unwrap();

		// Filter out clients with no remaining webhooks
		webhooks.retain(|client_id, client_webhooks| {
			// Check if client has no channels
			if client_channel_counts.get(client_id).copied().unwrap_or(0) == 0 {
				// Filter out webhooks that haven't been used in at least MIN_WEBHOOK_RETENTION_DAYS
				client_webhooks.retain(|_, webhook| {
					let duration = now.checked_sub(webhook.last_used).unwrap();
					if duration.as_secs() < (MIN_WEBHOOK_RETENTION_DAYS * 24 * 60 * 60).into() {
						// Keep webhook - not stale yet
						true
					} else {
						// Remove stale webhook
						false
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
