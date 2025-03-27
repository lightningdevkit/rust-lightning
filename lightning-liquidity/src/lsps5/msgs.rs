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
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};

use super::url_utils::LSPSUrl;

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
	LSPS5ExpirySoon {
		/// Block height when timeout occurs and the LSP would be forced to close the channel
		timeout: u32,
	},
	/// LSP wants to take back some liquidity
	LSPS5LiquidityManagementRequest,
	/// Client has onion messages pending
	LSPS5OnionMessageIncoming,
}

impl WebhookNotificationMethod {
	/// Extract parameters for JSON serialization
	pub fn parameters_json_value(&self) -> serde_json::Value {
		match self {
			Self::LSPS5WebhookRegistered => serde_json::json!({}),
			Self::LSPS5PaymentIncoming => serde_json::json!({}),
			Self::LSPS5ExpirySoon { timeout } => serde_json::json!({ "timeout": timeout }),
			Self::LSPS5LiquidityManagementRequest => serde_json::json!({}),
			Self::LSPS5OnionMessageIncoming => serde_json::json!({}),
		}
	}
}

impl Serialize for WebhookNotificationMethod {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		match self {
			Self::LSPS5WebhookRegistered => serializer.serialize_str(LSPS5_WEBHOOK_REGISTERED),
			Self::LSPS5PaymentIncoming => serializer.serialize_str(LSPS5_PAYMENT_INCOMING),
			Self::LSPS5ExpirySoon { .. } => serializer.serialize_str(LSPS5_EXPIRY_SOON),
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
			LSPS5_EXPIRY_SOON => {
				// Default timeout when deserializing without params
				// The actual timeout will be set from the params field later
				Ok(Self::LSPS5ExpirySoon { timeout: 0 })
			},
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
pub struct LSPS5AppName(String);

impl LSPS5AppName {
	/// Create a new LSPS5 app name
	pub fn new(app_name: String) -> Result<Self, LSPSResponseError> {
		let lsps5_app_name = Self(app_name);

		match lsps5_app_name.validate() {
			Ok(()) => Ok(lsps5_app_name),
			Err(e) => Err(e),
		}
	}

	/// Validate the app name
	pub fn validate(&self) -> Result<(), LSPSResponseError> {
		if self.0.len() > MAX_APP_NAME_LENGTH {
			return Err(LSPSResponseError {
				code: LSPS5_TOO_LONG_ERROR_CODE,
				message: format!(
					"App name exceeds maximum length of {} bytes",
					MAX_APP_NAME_LENGTH
				),
				data: None,
			});
		}

		Ok(())
	}
}

impl Display for LSPS5AppName {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl Serialize for LSPS5AppName {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.0.serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for LSPS5AppName {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Self::new(s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
	}
}

impl AsRef<str> for LSPS5AppName {
	fn as_ref(&self) -> &str {
		&self.0
	}
}

impl From<LSPS5AppName> for String {
	fn from(app_name: LSPS5AppName) -> Self {
		app_name.0
	}
}

/// URL for LSPS5 webhooks (max 1024 ASCII chars)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LSPS5WebhookUrl(LSPSUrl);

impl LSPS5WebhookUrl {
	/// Create a new LSPS5 webhook URL
	pub fn new(url: String) -> Result<Self, LSPSResponseError> {
		let parsed_url = match LSPSUrl::parse(&url) {
			Ok(url) => url,
			Err(e) => {
				return Err(LSPSResponseError {
					code: LSPS5_URL_PARSE_ERROR_CODE,
					message: format!("Error parsing URL: {:?}", e),
					data: None,
				});
			},
		};

		let lsps5_webhook_url = Self(parsed_url);

		match lsps5_webhook_url.validate() {
			Ok(()) => Ok(lsps5_webhook_url),
			Err(e) => Err(e),
		}
	}

	/// Validate the URL
	pub fn validate(&self) -> Result<(), LSPSResponseError> {
		let url_str = self.0.url();

		if url_str.len() > MAX_WEBHOOK_URL_LENGTH {
			return Err(LSPSResponseError {
				code: LSPS5_TOO_LONG_ERROR_CODE,
				message: format!(
					"Webhook URL exceeds maximum length of {} bytes",
					MAX_WEBHOOK_URL_LENGTH
				),
				data: None,
			});
		}

		if !url_str.is_ascii() {
			return Err(LSPSResponseError {
				code: LSPS5_URL_PARSE_ERROR_CODE,
				message: "Webhook URL must be ASCII".to_string(),
				data: None,
			});
		}

		if self.0.scheme() != "https" {
			return Err(LSPSResponseError {
				code: LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE,
				message: format!("Unsupported protocol: {}. HTTPS is required.", self.0.scheme()),
				data: None,
			});
		}

		// Check that URL has a host
		if self.0.host().is_none() {
			return Err(LSPSResponseError {
				code: LSPS5_URL_PARSE_ERROR_CODE,
				message: "URL must have a host".to_string(),
				data: None,
			});
		}

		// Check for localhost and private IPs
		if let Some(host) = self.0.host_str() {
			if host == "localhost" || host.starts_with("127.") || host == "::1" {
				return Err(LSPSResponseError {
					code: LSPS5_URL_PARSE_ERROR_CODE,
					message: "URL must not point to localhost".to_string(),
					data: None,
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
				return Err(LSPSResponseError {
					code: LSPS5_URL_PARSE_ERROR_CODE,
					message: "URL must not point to private IP ranges".to_string(),
					data: None,
				});
			}
		}

		Ok(())
	}

	/// Get the URL as a string
	pub fn as_str(&self) -> &str {
		self.0.url()
	}
}

impl Serialize for LSPS5WebhookUrl {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(self.0.url())
	}
}

impl<'de> Deserialize<'de> for LSPS5WebhookUrl {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Self::new(s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
	}
}

impl AsRef<str> for LSPS5WebhookUrl {
	fn as_ref(&self) -> &str {
		self.0.url()
	}
}

impl From<LSPS5WebhookUrl> for String {
	fn from(url: LSPS5WebhookUrl) -> Self {
		url.0.url().to_string()
	}
}

/// Parameters for `lsps5.set_webhook` request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetWebhookRequest {
	/// Human-readable name for the webhook (max 64 bytes)
	pub app_name: LSPS5AppName,
	/// URL of the webhook (max 1024 ASCII chars)
	pub webhook: LSPS5WebhookUrl,
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
	pub app_names: Vec<LSPS5AppName>,
	/// Maximum number of webhooks allowed by LSP
	pub max_webhooks: u32,
}

/// Parameters for `lsps5.remove_webhook` request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveWebhookRequest {
	/// App name identifying the webhook to remove
	pub app_name: LSPS5AppName,
}

/// Response for `lsps5.remove_webhook` (empty)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RemoveWebhookResponse {}

/// Webhook notification payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookNotification {
	/// JSON-RPC version (must be "2.0")
	pub jsonrpc: String,
	/// Notification method with parameters
	pub method: WebhookNotificationMethod,
}

impl WebhookNotification {
	/// Create a new webhook notification
	pub fn new(method: WebhookNotificationMethod) -> Self {
		Self { jsonrpc: "2.0".to_string(), method }
	}

	/// Create a webhook_registered notification
	pub fn webhook_registered() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5WebhookRegistered)
	}

	/// Create a payment_incoming notification
	pub fn payment_incoming() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5PaymentIncoming)
	}

	/// Create an expiry_soon notification
	pub fn expiry_soon(timeout: u32) -> Self {
		Self::new(WebhookNotificationMethod::LSPS5ExpirySoon { timeout })
	}

	/// Create a liquidity_management_request notification
	pub fn liquidity_management_request() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5LiquidityManagementRequest)
	}

	/// Create an onion_message_incoming notification
	pub fn onion_message_incoming() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5OnionMessageIncoming)
	}
}

impl Serialize for WebhookNotification {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		let mut map = serializer.serialize_map(Some(3))?;
		map.serialize_entry("jsonrpc", &self.jsonrpc)?;
		map.serialize_entry("method", &self.method)?;
		map.serialize_entry("params", &self.method.parameters_json_value())?;
		map.end()
	}
}

impl<'de> Deserialize<'de> for WebhookNotification {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct Helper {
			jsonrpc: String,
			method: WebhookNotificationMethod,
			params: serde_json::Value,
		}

		let helper = Helper::deserialize(deserializer)?;

		// Now update the method with parameters from the params field
		let method = match helper.method {
			WebhookNotificationMethod::LSPS5ExpirySoon { .. } => {
				if let Some(timeout) = helper.params.get("timeout").and_then(|t| t.as_u64()) {
					WebhookNotificationMethod::LSPS5ExpirySoon { timeout: timeout as u32 }
				} else {
					return Err(serde::de::Error::custom(
						"Missing or invalid timeout parameter for expiry_soon notification",
					));
				}
			},
			other => other,
		};

		Ok(WebhookNotification { jsonrpc: helper.jsonrpc, method })
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
		assert_eq!(request.app_name, LSPS5AppName::new("my_app".to_string()).unwrap());
		assert_eq!(
			request.webhook,
			LSPS5WebhookUrl::new("https://example.com/webhook".to_string()).unwrap()
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
		let app1 = LSPS5AppName::new("app1".to_string()).unwrap();
		let app2 = LSPS5AppName::new("app2".to_string()).unwrap();
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
			LSPS5AppName::new("My LSPS-Compliant Lightning Client".to_string()).unwrap()
		);
		assert_eq!(
			request.webhook,
			LSPS5WebhookUrl::new(
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
		let app1 = LSPS5AppName::new("My LSPS-Compliant Lightning Wallet".to_string()).unwrap();
		let app2 =
			LSPS5AppName::new("Another Wallet With The Same Signing Device".to_string()).unwrap();
		assert_eq!(response.app_names, vec![app1, app2]);
		assert_eq!(response.max_webhooks, 42);
	}

	#[test]
	fn spec_example_remove_webhook_request() {
		let json_str = r#"{"app_name":"Another Wallet With The Same Signig Device"}"#;
		let request: RemoveWebhookRequest = serde_json::from_str(json_str).unwrap();
		assert_eq!(
			request.app_name,
			LSPS5AppName::new("Another Wallet With The Same Signig Device".to_string()).unwrap()
		);
	}

	#[test]
	fn spec_example_webhook_notifications() {
		let json_str = r#"{"jsonrpc":"2.0","method":"lsps5.webhook_registered","params":{}}"#;
		let notification: WebhookNotification = serde_json::from_str(json_str).unwrap();
		assert_eq!(notification.method, WebhookNotificationMethod::LSPS5WebhookRegistered);

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

	#[test]
	fn test_url_security_validation() {
		let urls_that_should_throw = [
			"https://10.0.0.1/webhook",
			"https://192.168.1.1/webhook",
			"https://172.16.0.1/webhook",
			"https://172.31.255.255/webhook",
			"https://localhost/webhook",
			"test-app",
			"http://example.com/webhook",
		];

		for url_str in urls_that_should_throw.iter() {
			match LSPS5WebhookUrl::new(url_str.to_string()) {
				Ok(_) => panic!("Expected error"),
				Err(e) => {
					// error is not null
					assert!(e.code != 0);
				},
			}
		}
	}

	#[test]
	fn test_webhook_notification_parameter_binding() {
		let notification = WebhookNotification::expiry_soon(144);
		if let WebhookNotificationMethod::LSPS5ExpirySoon { timeout } = notification.method {
			assert_eq!(timeout, 144);
		} else {
			panic!("Expected LSPS5ExpirySoon variant");
		}

		let json = serde_json::to_string(&notification).unwrap();
		assert_eq!(
			json,
			r#"{"jsonrpc":"2.0","method":"lsps5.expiry_soon","params":{"timeout":144}}"#
		);
		let deserialized: WebhookNotification = serde_json::from_str(&json).unwrap();
		if let WebhookNotificationMethod::LSPS5ExpirySoon { timeout } = deserialized.method {
			assert_eq!(timeout, 144);
		} else {
			panic!("Expected LSPS5ExpirySoon variant after deserialization");
		}
	}

	#[test]
	fn test_notification_method_parameter_extraction() {
		let method1 = WebhookNotificationMethod::LSPS5WebhookRegistered;
		let method2 = WebhookNotificationMethod::LSPS5ExpirySoon { timeout: 500 };

		assert_eq!(method1.parameters_json_value(), serde_json::json!({}));
		assert_eq!(method2.parameters_json_value(), serde_json::json!({"timeout": 500}));
	}

	#[test]
	fn test_missing_parameter_error() {
		let json_without_timeout = r#"{"jsonrpc":"2.0","method":"lsps5.expiry_soon","params":{}}"#;

		let result: Result<WebhookNotification, _> = serde_json::from_str(json_without_timeout);
		assert!(result.is_err(), "Should fail when timeout parameter is missing");

		let err = result.unwrap_err().to_string();
		assert!(
			err.contains("Missing or invalid timeout parameter"),
			"Error should mention missing parameter: {}",
			err
		);
	}

	#[test]
	fn test_notification_round_trip_all_types() {
		let notifications = vec![
			WebhookNotification::webhook_registered(),
			WebhookNotification::payment_incoming(),
			WebhookNotification::expiry_soon(123),
			WebhookNotification::liquidity_management_request(),
			WebhookNotification::onion_message_incoming(),
		];

		for original in notifications {
			let json = serde_json::to_string(&original).unwrap();
			let deserialized: WebhookNotification = serde_json::from_str(&json).unwrap();

			assert_eq!(original, deserialized);

			if let WebhookNotificationMethod::LSPS5ExpirySoon { timeout: original_timeout } =
				original.method
			{
				if let WebhookNotificationMethod::LSPS5ExpirySoon {
					timeout: deserialized_timeout,
				} = deserialized.method
				{
					assert_eq!(original_timeout, deserialized_timeout);
				} else {
					panic!("Expected LSPS5ExpirySoon after deserialization");
				}
			}
		}
	}
}
