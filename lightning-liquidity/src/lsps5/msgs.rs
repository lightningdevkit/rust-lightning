// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LSPS5 message formats for webhook registration

use core::fmt;
use core::fmt::Display;

use crate::lsps0::ser::LSPSMessage;
use crate::lsps0::ser::LSPSRequestId;
use crate::lsps0::ser::LSPSResponseError;
use crate::prelude::*;
use lightning::ln::msgs::ErrorAction;
use lightning::ln::msgs::LightningError;
use lightning::util::logger::Level;
use serde::{Deserialize, Serialize};

/// Maximum allowed length for an app_name (in bytes)
pub const MAX_APP_NAME_LENGTH: usize = 64;

/// Maximum allowed length for a webhook URL (in characters)
pub const MAX_WEBHOOK_URL_LENGTH: usize = 1024;

pub(crate) const LSPS5_TOO_LONG_ERROR_CODE: i32 = 500;
pub(crate) const LSPS5_URL_PARSE_ERROR_CODE: i32 = 501;
pub(crate) const LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE: i32 = 502;
pub(crate) const LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE: i32 = 503;
pub(crate) const LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE: i32 = 1010;

pub(crate) const LSPS5_SET_WEBHOOK_METHOD_NAME: &str = "lsps5.set_webhook";
pub(crate) const LSPS5_LIST_WEBHOOKS_METHOD_NAME: &str = "lsps5.list_webhooks";
pub(crate) const LSPS5_REMOVE_WEBHOOK_METHOD_NAME: &str = "lsps5.remove_webhook";

pub(crate) const LSPS5_WEBHOOK_REGISTERED: &str = "lsps5.webhook_registered";
pub(crate) const LSPS5_PAYMENT_INCOMING: &str = "lsps5.payment_incoming";
pub(crate) const LSPS5_EXPIRY_SOON: &str = "lsps5.expiry_soon";
pub(crate) const LSPS5_LIQUIDITY_MANAGEMENT_REQUEST: &str = "lsps5.liquidity_management_request";
pub(crate) const LSPS5_ONION_MESSAGE_INCOMING: &str = "lsps5.onion_message_incoming";

/// Webhook notification methods defined in LSPS5
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WebhookNotificationMethod {
	/// Webhook has been successfully registered
	LSPS5WebhookRegistered,
	/// Client has payments pending to be received
	LSPS5PaymentIncoming,
	/// HTLC or time-bound contract is about to expire
	LSPS5ExpirySoon,
	/// LSP wants to take back some liquidity
	LSPS5LiquidityManagementRequest,
	/// Client has onion messages pending
	LSPS5OnionMessageIncoming,
}

impl Serialize for WebhookNotificationMethod {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		match self {
			Self::LSPS5WebhookRegistered => serializer.serialize_str(LSPS5_WEBHOOK_REGISTERED),
			Self::LSPS5PaymentIncoming => serializer.serialize_str(LSPS5_PAYMENT_INCOMING),
			Self::LSPS5ExpirySoon => serializer.serialize_str(LSPS5_EXPIRY_SOON),
			Self::LSPS5LiquidityManagementRequest => {
				serializer.serialize_str(LSPS5_LIQUIDITY_MANAGEMENT_REQUEST)
			},
			Self::LSPS5OnionMessageIncoming => {
				serializer.serialize_str(LSPS5_ONION_MESSAGE_INCOMING)
			},
		}
	}
}

impl<'de> Deserialize<'de> for WebhookNotificationMethod {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		match s.as_str() {
			LSPS5_WEBHOOK_REGISTERED => Ok(Self::LSPS5WebhookRegistered),
			LSPS5_PAYMENT_INCOMING => Ok(Self::LSPS5PaymentIncoming),
			LSPS5_EXPIRY_SOON => Ok(Self::LSPS5ExpirySoon),
			LSPS5_LIQUIDITY_MANAGEMENT_REQUEST => Ok(Self::LSPS5LiquidityManagementRequest),
			LSPS5_ONION_MESSAGE_INCOMING => Ok(Self::LSPS5OnionMessageIncoming),
			_ => {
				Err(serde::de::Error::custom(format!("Unknown webhook notification method: {}", s)))
			},
		}
	}
}

/// App name for LSPS5 webhooks (max 64 bytes UTF-8)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Lsps5AppName(String);

impl Lsps5AppName {
	/// Create a new app name, checking length constraints
	pub fn new(app_name: String) -> Result<Self, LightningError> {
		if app_name.len() > MAX_APP_NAME_LENGTH {
			return Err(LightningError {
				err: format!("App name exceeds maximum length of {} bytes", MAX_APP_NAME_LENGTH),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			});
		}
		Ok(Self(app_name))
	}

	/// Get the length of the app name
	pub fn len(&self) -> usize {
		self.0.len()
	}
}

impl Display for Lsps5AppName {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl Serialize for Lsps5AppName {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.0.serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for Lsps5AppName {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Self::new(s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
	}
}

impl AsRef<str> for Lsps5AppName {
	fn as_ref(&self) -> &str {
		&self.0
	}
}

impl From<Lsps5AppName> for String {
	fn from(app_name: Lsps5AppName) -> Self {
		app_name.0
	}
}

/// URL for LSPS5 webhooks (max 1024 ASCII chars)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Lsps5WebhookUrl(String);

impl Lsps5WebhookUrl {
	/// Create a new webhook URL, checking length and ASCII constraints
	pub fn new(url: String) -> Result<Self, LightningError> {
		if url.len() > MAX_WEBHOOK_URL_LENGTH {
			return Err(LightningError {
				err: format!(
					"Webhook URL exceeds maximum length of {} bytes",
					MAX_WEBHOOK_URL_LENGTH
				),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			});
		}
		if !url.is_ascii() {
			return Err(LightningError {
				err: "Webhook URL must be ASCII".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			});
		}
		Ok(Self(url))
	}

	/// Get the length of the URL
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Get the URL as a string
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl Serialize for Lsps5WebhookUrl {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.0.serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for Lsps5WebhookUrl {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Self::new(s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
	}
}

impl AsRef<str> for Lsps5WebhookUrl {
	fn as_ref(&self) -> &str {
		&self.0
	}
}

impl From<Lsps5WebhookUrl> for String {
	fn from(url: Lsps5WebhookUrl) -> Self {
		url.0
	}
}

/// Parameters for `lsps5.set_webhook` request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetWebhookRequest {
	/// Human-readable name for the webhook (max 64 bytes)
	pub app_name: Lsps5AppName,
	/// URL of the webhook (max 1024 ASCII chars)
	pub webhook: Lsps5WebhookUrl,
}

/// Response for `lsps5.set_webhook`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetWebhookResponse {
	/// Current number of webhooks registered for this client
	pub num_webhooks: u32,
	/// Maximum number of webhooks allowed by LSP
	pub max_webhooks: u32,
	/// Whether this is an unchanged registration
	pub no_change: bool,
}

/// Parameters for `lsps5.list_webhooks` request (empty)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ListWebhooksRequest {}

/// Response for `lsps5.list_webhooks`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListWebhooksResponse {
	/// List of app_names with registered webhooks
	pub app_names: Vec<Lsps5AppName>,
	/// Maximum number of webhooks allowed by LSP
	pub max_webhooks: u32,
}

/// Parameters for `lsps5.remove_webhook` request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveWebhookRequest {
	/// App name identifying the webhook to remove
	pub app_name: Lsps5AppName,
}

/// Response for `lsps5.remove_webhook` (empty)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RemoveWebhookResponse {}

/// Parameters for `lsps5.expiry_soon` webhook notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirySoonParams {
	/// Block height of the timeout
	pub timeout: u32,
}

/// Webhook notification payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookNotification {
	/// JSON-RPC version (must be "2.0")
	pub jsonrpc: String,
	/// Notification method
	pub method: WebhookNotificationMethod,
	/// Notification parameters
	pub params: serde_json::Value,
}

impl WebhookNotification {
	/// Create a new webhook notification
	pub fn new(method: WebhookNotificationMethod, params: serde_json::Value) -> Self {
		Self { jsonrpc: "2.0".to_string(), method, params }
	}

	/// Create `webhook_registered` notification (no params)
	pub fn webhook_registered() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5WebhookRegistered, serde_json::json!({}))
	}

	/// Create `payment_incoming` notification (no params)
	pub fn payment_incoming() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5PaymentIncoming, serde_json::json!({}))
	}

	/// Create `expiry_soon` notification
	pub fn expiry_soon(timeout: u32) -> Self {
		Self::new(
			WebhookNotificationMethod::LSPS5ExpirySoon,
			serde_json::json!({ "timeout": timeout }),
		)
	}

	/// Create `liquidity_management_request` notification (no params)
	pub fn liquidity_management_request() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5LiquidityManagementRequest, serde_json::json!({}))
	}

	/// Create `onion_message_incoming` notification (no params)
	pub fn onion_message_incoming() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5OnionMessageIncoming, serde_json::json!({}))
	}
}

/// An LSPS5 protocol request
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS5Request {
	/// Register or update a webhook
	SetWebhook(SetWebhookRequest),
	/// List all registered webhooks
	ListWebhooks(ListWebhooksRequest),
	/// Remove a webhook
	RemoveWebhook(RemoveWebhookRequest),
}

/// An LSPS5 protocol response
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS5Response {
	/// Response to [`SetWebhook`](SetWebhookRequest) request
	SetWebhook(SetWebhookResponse),
	/// Error response to [`SetWebhook`](SetWebhookRequest) request
	SetWebhookError(LSPSResponseError),
	/// Response to [`ListWebhooks`](ListWebhooksRequest) request
	ListWebhooks(ListWebhooksResponse),
	/// Error response to [`ListWebhooks`](ListWebhooksRequest) request
	ListWebhooksError(LSPSResponseError),
	/// Response to [`RemoveWebhook`](RemoveWebhookRequest) request
	RemoveWebhook(RemoveWebhookResponse),
	/// Error response to [`RemoveWebhook`](RemoveWebhookRequest) request
	RemoveWebhookError(LSPSResponseError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An LSPS5 protocol message
pub enum LSPS5Message {
	/// A request variant
	Request(LSPSRequestId, LSPS5Request),
	/// A response variant
	Response(LSPSRequestId, LSPS5Response),
}

impl TryFrom<LSPSMessage> for LSPS5Message {
	type Error = ();

	fn try_from(message: LSPSMessage) -> Result<Self, Self::Error> {
		match message {
			LSPSMessage::LSPS5(message) => Ok(message),
			_ => Err(()),
		}
	}
}

impl From<LSPS5Message> for LSPSMessage {
	fn from(message: LSPS5Message) -> Self {
		LSPSMessage::LSPS5(message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::alloc::string::ToString;

	#[test]
	fn webhook_notification_serialization() {
		let notification = WebhookNotification::webhook_registered();
		let json_str = r#"{"jsonrpc":"2.0","method":"lsps5.webhook_registered","params":{}}"#;
		assert_eq!(json_str, serde_json::json!(notification).to_string());

		let notification = WebhookNotification::expiry_soon(144);
		let json_str = r#"{"jsonrpc":"2.0","method":"lsps5.expiry_soon","params":{"timeout":144}}"#;
		assert_eq!(json_str, serde_json::json!(notification).to_string());
	}

	#[test]
	fn parse_set_webhook_request() {
		let json_str = r#"{"app_name":"my_app","webhook":"https://example.com/webhook"}"#;
		let request: SetWebhookRequest = serde_json::from_str(json_str).unwrap();
		assert_eq!(request.app_name, Lsps5AppName::new("my_app".to_string()).unwrap());
		assert_eq!(
			request.webhook,
			Lsps5WebhookUrl::new("https://example.com/webhook".to_string()).unwrap()
		);
	}

	#[test]
	fn parse_set_webhook_response() {
		let json_str = r#"{"num_webhooks":1,"max_webhooks":5,"no_change":false}"#;
		let response: SetWebhookResponse = serde_json::from_str(json_str).unwrap();
		assert_eq!(response.num_webhooks, 1);
		assert_eq!(response.max_webhooks, 5);
		assert_eq!(response.no_change, false);
	}

	#[test]
	fn parse_list_webhooks_response() {
		let json_str = r#"{"app_names":["app1","app2"],"max_webhooks":5}"#;
		let response: ListWebhooksResponse = serde_json::from_str(json_str).unwrap();
		let app1 = Lsps5AppName::new("app1".to_string()).unwrap();
		let app2 = Lsps5AppName::new("app2".to_string()).unwrap();
		assert_eq!(response.app_names, vec![app1, app2]);
		assert_eq!(response.max_webhooks, 5);
	}

	#[test]
	fn parse_empty_requests_responses() {
		let json_str = r#"{}"#;
		let _list_req: ListWebhooksRequest = serde_json::from_str(json_str).unwrap();
		let _remove_resp: RemoveWebhookResponse = serde_json::from_str(json_str).unwrap();
	}

	#[test]
	fn spec_example_set_webhook_request() {
		let json_str = r#"{"app_name":"My LSPS-Compliant Lightning Client","webhook":"https://www.example.org/push?l=1234567890abcdefghijklmnopqrstuv&c=best"}"#;
		let request: SetWebhookRequest = serde_json::from_str(json_str).unwrap();
		assert_eq!(
			request.app_name,
			Lsps5AppName::new("My LSPS-Compliant Lightning Client".to_string()).unwrap()
		);
		assert_eq!(
			request.webhook,
			Lsps5WebhookUrl::new(
				"https://www.example.org/push?l=1234567890abcdefghijklmnopqrstuv&c=best"
					.to_string()
			)
			.unwrap()
		);
	}

	#[test]
	fn spec_example_set_webhook_response() {
		let json_str = r#"{"num_webhooks":2,"max_webhooks":4,"no_change":false}"#;
		let response: SetWebhookResponse = serde_json::from_str(json_str).unwrap();
		assert_eq!(response.num_webhooks, 2);
		assert_eq!(response.max_webhooks, 4);
		assert_eq!(response.no_change, false);
	}

	#[test]
	fn spec_example_list_webhooks_response() {
		let json_str = r#"{"app_names":["My LSPS-Compliant Lightning Wallet","Another Wallet With The Same Signing Device"],"max_webhooks":42}"#;
		let response: ListWebhooksResponse = serde_json::from_str(json_str).unwrap();
		let app1 = Lsps5AppName::new("My LSPS-Compliant Lightning Wallet".to_string()).unwrap();
		let app2 =
			Lsps5AppName::new("Another Wallet With The Same Signing Device".to_string()).unwrap();
		assert_eq!(response.app_names, vec![app1, app2]);
		assert_eq!(response.max_webhooks, 42);
	}

	#[test]
	fn spec_example_remove_webhook_request() {
		let json_str = r#"{"app_name":"Another Wallet With The Same Signig Device"}"#;
		let request: RemoveWebhookRequest = serde_json::from_str(json_str).unwrap();
		assert_eq!(
			request.app_name,
			Lsps5AppName::new("Another Wallet With The Same Signig Device".to_string()).unwrap()
		);
	}

	#[test]
	fn spec_example_webhook_notifications() {
		// Test webhook_registered notification from spec
		let json_str = r#"{"jsonrpc":"2.0","method":"lsps5.webhook_registered","params":{}}"#;
		let notification: WebhookNotification = serde_json::from_str(json_str).unwrap();
		assert_eq!(notification.method, WebhookNotificationMethod::LSPS5WebhookRegistered);

		// Test all other notification types
		let notification = WebhookNotification::payment_incoming();
		let json_str = r#"{"jsonrpc":"2.0","method":"lsps5.payment_incoming","params":{}}"#;
		assert_eq!(json_str, serde_json::json!(notification).to_string());

		let notification = WebhookNotification::expiry_soon(144);
		let json_str = r#"{"jsonrpc":"2.0","method":"lsps5.expiry_soon","params":{"timeout":144}}"#;
		assert_eq!(json_str, serde_json::json!(notification).to_string());

		let notification = WebhookNotification::liquidity_management_request();
		let json_str =
			r#"{"jsonrpc":"2.0","method":"lsps5.liquidity_management_request","params":{}}"#;
		assert_eq!(json_str, serde_json::json!(notification).to_string());

		let notification = WebhookNotification::onion_message_incoming();
		let json_str = r#"{"jsonrpc":"2.0","method":"lsps5.onion_message_incoming","params":{}}"#;
		assert_eq!(json_str, serde_json::json!(notification).to_string());
	}
}
