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
use core::ops::Deref;

use crate::alloc::string::ToString;
use crate::lsps0::ser::LSPSMessage;
use crate::lsps0::ser::LSPSRequestId;
use crate::lsps0::ser::LSPSResponseError;
use alloc::string::String;
use alloc::vec::Vec;
use lightning_types::string::UntrustedString;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::ser::SerializeStruct;
use serde::Serializer;
use serde::{Deserialize, Serialize};

use super::url_utils::LSPSUrl;

/// Maximum allowed length for an `app_name` (in bytes).
pub const MAX_APP_NAME_LENGTH: usize = 64;

/// Maximum allowed length for a webhook URL (in characters).
pub const MAX_WEBHOOK_URL_LENGTH: usize = 1024;

pub(crate) const LSPS5_TOO_LONG_ERROR_CODE: i32 = 500;
pub(crate) const LSPS5_URL_PARSE_ERROR_CODE: i32 = 501;
pub(crate) const LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE: i32 = 502;
pub(crate) const LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE: i32 = 503;
pub(crate) const LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE: i32 = 1010;

pub(crate) const LSPS5_SET_WEBHOOK_METHOD_NAME: &str = "lsps5.set_webhook";
pub(crate) const LSPS5_LIST_WEBHOOKS_METHOD_NAME: &str = "lsps5.list_webhooks";
pub(crate) const LSPS5_REMOVE_WEBHOOK_METHOD_NAME: &str = "lsps5.remove_webhook";

pub(crate) const LSPS5_WEBHOOK_REGISTERED_NOTIFICATION: &str = "lsps5.webhook_registered";
pub(crate) const LSPS5_PAYMENT_INCOMING_NOTIFICATION: &str = "lsps5.payment_incoming";
pub(crate) const LSPS5_EXPIRY_SOON_NOTIFICATION: &str = "lsps5.expiry_soon";
pub(crate) const LSPS5_LIQUIDITY_MANAGEMENT_REQUEST_NOTIFICATION: &str =
	"lsps5.liquidity_management_request";
pub(crate) const LSPS5_ONION_MESSAGE_INCOMING_NOTIFICATION: &str = "lsps5.onion_message_incoming";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
/// Structured LSPS5 error
pub enum LSPS5Error {
	/// The provided input was too long.
	TooLong(String),
	/// The provided URL could not be parsed.
	UrlParse(String),
	/// The provided URL used an unsupported protocol.
	UnsupportedProtocol(String),
	/// The provided URL contained too many webhooks.
	TooManyWebhooks(String),
	/// The provided URL did not contain an app name.
	AppNameNotFound(String),
	/// The provided URL contained an app name that was not found.
	Other {
		/// Numeric code for matching legacy behaviors.
		code: i32,
		/// Human‐readable message.
		message: String,
	},
}

impl Serialize for LSPS5Error {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let mut m = serializer.serialize_struct("error", 3)?;
		m.serialize_field("code", &self.code())?;
		m.serialize_field("message", &self.message())?;
		m.serialize_field("data", &Option::<String>::None)?;
		m.end()
	}
}

impl LSPS5Error {
	/// Numeric code for matching legacy behaviors
	pub fn code(&self) -> i32 {
		match self {
			LSPS5Error::TooLong(_) => LSPS5_TOO_LONG_ERROR_CODE,
			LSPS5Error::UrlParse(_) => LSPS5_URL_PARSE_ERROR_CODE,
			LSPS5Error::UnsupportedProtocol(_) => LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE,
			LSPS5Error::TooManyWebhooks(_) => LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE,
			LSPS5Error::AppNameNotFound(_) => LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE,
			LSPS5Error::Other { code, .. } => *code,
		}
	}
	/// Human‐readable message
	pub fn message(&self) -> String {
		match self {
			LSPS5Error::TooLong(m)
			| LSPS5Error::UrlParse(m)
			| LSPS5Error::UnsupportedProtocol(m)
			| LSPS5Error::TooManyWebhooks(m)
			| LSPS5Error::AppNameNotFound(m) => m.clone(),
			LSPS5Error::Other { message, .. } => message.clone(),
		}
	}
}

/// Convert LSPSResponseError to LSPS5Error
impl From<LSPSResponseError> for LSPS5Error {
	fn from(err: LSPSResponseError) -> Self {
		match err.code {
			LSPS5_TOO_LONG_ERROR_CODE => LSPS5Error::TooLong(err.message),
			LSPS5_URL_PARSE_ERROR_CODE => LSPS5Error::UrlParse(err.message),
			LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE => LSPS5Error::UnsupportedProtocol(err.message),
			LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE => LSPS5Error::TooManyWebhooks(err.message),
			LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE => LSPS5Error::AppNameNotFound(err.message),
			code => LSPS5Error::Other { code, message: err.message },
		}
	}
}

/// Convert LSPS5Error to LSPSResponseError.
impl From<LSPS5Error> for LSPSResponseError {
	fn from(err: LSPS5Error) -> Self {
		LSPSResponseError { code: err.code(), message: err.message(), data: None }
	}
}

/// App name for LSPS5 webhooks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LSPS5AppName(UntrustedString);

impl LSPS5AppName {
	/// Create a new LSPS5 app name.
	pub fn new(app_name: UntrustedString) -> Result<Self, LSPS5Error> {
		if app_name.to_string().chars().count() > MAX_APP_NAME_LENGTH {
			return Err(LSPS5Error::TooLong(format!(
				"App name exceeds maximum length of {} bytes",
				MAX_APP_NAME_LENGTH
			)));
		}
		Ok(Self(app_name))
	}

	/// Create a new LSPS5 app name from a regular String.
	pub fn from_string(app_name: String) -> Result<Self, LSPS5Error> {
		Self::new(UntrustedString(app_name))
	}

	/// Get the app name as a string.
	pub fn as_str(&self) -> &str {
		self
	}
}

impl Deref for LSPS5AppName {
	type Target = str;

	fn deref(&self) -> &Self::Target {
		&self.0 .0
	}
}

impl Display for LSPS5AppName {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self)
	}
}

impl Serialize for LSPS5AppName {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(self)
	}
}

impl<'de> Deserialize<'de> for LSPS5AppName {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Self::new(UntrustedString(s)).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
	}
}

impl AsRef<str> for LSPS5AppName {
	fn as_ref(&self) -> &str {
		self
	}
}

impl From<LSPS5AppName> for String {
	fn from(app_name: LSPS5AppName) -> Self {
		app_name.to_string()
	}
}

/// URL for LSPS5 webhooks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LSPS5WebhookUrl(LSPSUrl);

impl LSPS5WebhookUrl {
	/// Create a new LSPS5 webhook URL.
	pub fn new(url: UntrustedString) -> Result<Self, LSPS5Error> {
		let parsed_url = LSPSUrl::parse(url.0.clone())
			.map_err(|_e| LSPS5Error::UrlParse(format!("Error parsing URL: {:?}", url)))?;
		if parsed_url.url_length() > MAX_WEBHOOK_URL_LENGTH {
			return Err(LSPS5Error::TooLong(format!(
				"Webhook URL exceeds maximum length of {} bytes",
				MAX_WEBHOOK_URL_LENGTH
			)));
		}
		if !parsed_url.is_https() {
			return Err(LSPS5Error::UnsupportedProtocol(
				"Unsupported protocol: HTTPS is required".to_string(),
			));
		}
		if !parsed_url.is_public() {
			return Err(LSPS5Error::UrlParse("Webhook URL must be a public URL".to_string()));
		}
		Ok(Self(parsed_url))
	}

	/// Create a new LSPS5 webhook URL from a regular String.
	pub fn from_string(url: String) -> Result<Self, LSPS5Error> {
		Self::new(UntrustedString(url))
	}

	/// Get the webhook URL as a string.
	pub fn as_str(&self) -> &str {
		self
	}
}

impl Deref for LSPS5WebhookUrl {
	type Target = str;

	fn deref(&self) -> &Self::Target {
		self.0.url()
	}
}

impl Display for LSPS5WebhookUrl {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self) // Using Deref
	}
}

impl Serialize for LSPS5WebhookUrl {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(self)
	}
}

impl<'de> Deserialize<'de> for LSPS5WebhookUrl {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Self::new(UntrustedString(s)).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
	}
}

impl AsRef<str> for LSPS5WebhookUrl {
	fn as_ref(&self) -> &str {
		self
	}
}

impl From<LSPS5WebhookUrl> for String {
	fn from(url: LSPS5WebhookUrl) -> Self {
		url.to_string()
	}
}

/// Parameters for `lsps5.set_webhook` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetWebhookRequest {
	/// Human-readable name for the webhook.
	pub app_name: LSPS5AppName,
	/// URL of the webhook.
	pub webhook: LSPS5WebhookUrl,
}

/// Response for `lsps5.set_webhook`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetWebhookResponse {
	/// Current number of webhooks registered for this client.
	pub num_webhooks: u32,
	/// Maximum number of webhooks allowed by LSP.
	pub max_webhooks: u32,
	/// Whether this is an unchanged registration.
	pub no_change: bool,
}

/// Parameters for `lsps5.list_webhooks` request.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ListWebhooksRequest {}

/// Response for `lsps5.list_webhooks`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListWebhooksResponse {
	/// List of app_names with registered webhooks.
	pub app_names: Vec<LSPS5AppName>,
	/// Maximum number of webhooks allowed by LSP.
	pub max_webhooks: u32,
}

/// Parameters for `lsps5.remove_webhook` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveWebhookRequest {
	/// App name identifying the webhook to remove.
	pub app_name: LSPS5AppName,
}

/// Response for `lsps5.remove_webhook`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RemoveWebhookResponse {}

/// Webhook notification methods defined in LSPS5.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WebhookNotificationMethod {
	/// Webhook has been successfully registered.
	LSPS5WebhookRegistered,
	/// Client has payments pending to be received.
	LSPS5PaymentIncoming,
	/// HTLC or time-bound contract is about to expire.
	LSPS5ExpirySoon {
		/// Block height when timeout occurs and the LSP would be forced to close the channel
		timeout: u32,
	},
	/// LSP wants to take back some liquidity.
	LSPS5LiquidityManagementRequest,
	/// Client has onion messages pending.
	LSPS5OnionMessageIncoming,
}

/// Webhook notification payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookNotification {
	/// Notification method with parameters.
	pub method: WebhookNotificationMethod,
}

impl WebhookNotification {
	/// Create a new webhook notification.
	pub fn new(method: WebhookNotificationMethod) -> Self {
		Self { method }
	}

	/// Create a webhook_registered notification.
	pub fn webhook_registered() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5WebhookRegistered)
	}

	/// Create a payment_incoming notification.
	pub fn payment_incoming() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5PaymentIncoming)
	}

	/// Create an expiry_soon notification.
	pub fn expiry_soon(timeout: u32) -> Self {
		Self::new(WebhookNotificationMethod::LSPS5ExpirySoon { timeout })
	}

	/// Create a liquidity_management_request notification.
	pub fn liquidity_management_request() -> Self {
		Self::new(WebhookNotificationMethod::LSPS5LiquidityManagementRequest)
	}

	/// Create an onion_message_incoming notification.
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
		map.serialize_entry("jsonrpc", "2.0")?;

		let method_name = match &self.method {
			WebhookNotificationMethod::LSPS5WebhookRegistered => {
				LSPS5_WEBHOOK_REGISTERED_NOTIFICATION
			},
			WebhookNotificationMethod::LSPS5PaymentIncoming => LSPS5_PAYMENT_INCOMING_NOTIFICATION,
			WebhookNotificationMethod::LSPS5ExpirySoon { .. } => LSPS5_EXPIRY_SOON_NOTIFICATION,
			WebhookNotificationMethod::LSPS5LiquidityManagementRequest => {
				LSPS5_LIQUIDITY_MANAGEMENT_REQUEST_NOTIFICATION
			},
			WebhookNotificationMethod::LSPS5OnionMessageIncoming => {
				LSPS5_ONION_MESSAGE_INCOMING_NOTIFICATION
			},
		};
		map.serialize_entry("method", &method_name)?;

		let params = match &self.method {
			WebhookNotificationMethod::LSPS5WebhookRegistered => serde_json::json!({}),
			WebhookNotificationMethod::LSPS5PaymentIncoming => serde_json::json!({}),
			WebhookNotificationMethod::LSPS5ExpirySoon { timeout } => {
				serde_json::json!({ "timeout": timeout })
			},
			WebhookNotificationMethod::LSPS5LiquidityManagementRequest => serde_json::json!({}),
			WebhookNotificationMethod::LSPS5OnionMessageIncoming => serde_json::json!({}),
		};
		map.serialize_entry("params", &params)?;

		map.end()
	}
}

impl<'de> Deserialize<'de> for WebhookNotification {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct WebhookNotificationVisitor;

		impl<'de> Visitor<'de> for WebhookNotificationVisitor {
			type Value = WebhookNotification;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("a valid LSPS5 WebhookNotification object")
			}

			fn visit_map<V>(self, mut map: V) -> Result<WebhookNotification, V::Error>
			where
				V: MapAccess<'de>,
			{
				let mut jsonrpc: Option<String> = None;
				let mut method: Option<String> = None;
				let mut params: Option<serde_json::Value> = None;

				while let Some(key) = map.next_key::<&str>()? {
					match key {
						"jsonrpc" => jsonrpc = Some(map.next_value()?),
						"method" => method = Some(map.next_value()?),
						"params" => params = Some(map.next_value()?),
						_ => {
							let _: serde::de::IgnoredAny = map.next_value()?;
						},
					}
				}

				let jsonrpc = jsonrpc.ok_or_else(|| de::Error::missing_field("jsonrpc"))?;
				if jsonrpc != "2.0" {
					return Err(de::Error::custom("Invalid jsonrpc version"));
				}
				let method = method.ok_or_else(|| de::Error::missing_field("method"))?;
				let params = params.ok_or_else(|| de::Error::missing_field("params"))?;

				let method = match method.as_str() {
					LSPS5_WEBHOOK_REGISTERED_NOTIFICATION => {
						WebhookNotificationMethod::LSPS5WebhookRegistered
					},
					LSPS5_PAYMENT_INCOMING_NOTIFICATION => {
						WebhookNotificationMethod::LSPS5PaymentIncoming
					},
					LSPS5_EXPIRY_SOON_NOTIFICATION => {
						if let Some(timeout) = params.get("timeout").and_then(|t| t.as_u64()) {
							WebhookNotificationMethod::LSPS5ExpirySoon { timeout: timeout as u32 }
						} else {
							return Err(de::Error::custom(
								"Missing or invalid timeout parameter for expiry_soon notification",
							));
						}
					},
					LSPS5_LIQUIDITY_MANAGEMENT_REQUEST_NOTIFICATION => {
						WebhookNotificationMethod::LSPS5LiquidityManagementRequest
					},
					LSPS5_ONION_MESSAGE_INCOMING_NOTIFICATION => {
						WebhookNotificationMethod::LSPS5OnionMessageIncoming
					},
					_ => return Err(de::Error::custom(format!("Unknown method: {}", method))),
				};

				Ok(WebhookNotification { method })
			}
		}

		deserializer.deserialize_map(WebhookNotificationVisitor)
	}
}

/// An LSPS5 protocol request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS5Request {
	/// Register or update a webhook.
	SetWebhook(SetWebhookRequest),
	/// List all registered webhooks.
	ListWebhooks(ListWebhooksRequest),
	/// Remove a webhook.
	RemoveWebhook(RemoveWebhookRequest),
}

/// An LSPS5 protocol response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS5Response {
	/// Response to [`SetWebhook`](SetWebhookRequest) request.
	SetWebhook(SetWebhookResponse),
	/// Error response to [`SetWebhook`](SetWebhookRequest) request.
	SetWebhookError(LSPS5Error),
	/// Response to [`ListWebhooks`](ListWebhooksRequest) request.
	ListWebhooks(ListWebhooksResponse),
	/// Error response to [`ListWebhooks`](ListWebhooksRequest) request.
	ListWebhooksError(LSPS5Error),
	/// Response to [`RemoveWebhook`](RemoveWebhookRequest) request.
	RemoveWebhook(RemoveWebhookResponse),
	/// Error response to [`RemoveWebhook`](RemoveWebhookRequest) request.
	RemoveWebhookError(LSPS5Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An LSPS5 protocol message.
pub enum LSPS5Message {
	/// A request variant.
	Request(LSPSRequestId, LSPS5Request),
	/// A response variant.
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
		assert_eq!(
			request.app_name,
			LSPS5AppName::new(UntrustedString("my_app".to_string())).unwrap()
		);
		assert_eq!(
			request.webhook,
			LSPS5WebhookUrl::new(UntrustedString("https://example.com/webhook".to_string()))
				.unwrap()
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
		let app1 = LSPS5AppName::new(UntrustedString("app1".to_string())).unwrap();
		let app2 = LSPS5AppName::new(UntrustedString("app2".to_string())).unwrap();
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
			LSPS5AppName::new(UntrustedString("My LSPS-Compliant Lightning Client".to_string()))
				.unwrap()
		);
		assert_eq!(
			request.webhook,
			LSPS5WebhookUrl::new(UntrustedString(
				"https://www.example.org/push?l=1234567890abcdefghijklmnopqrstuv&c=best"
					.to_string()
			))
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
		let app1 =
			LSPS5AppName::new(UntrustedString("My LSPS-Compliant Lightning Wallet".to_string()))
				.unwrap();
		let app2 = LSPS5AppName::new(UntrustedString(
			"Another Wallet With The Same Signing Device".to_string(),
		))
		.unwrap();
		assert_eq!(response.app_names, vec![app1, app2]);
		assert_eq!(response.max_webhooks, 42);
	}

	#[test]
	fn spec_example_remove_webhook_request() {
		let json_str = r#"{"app_name":"Another Wallet With The Same Signig Device"}"#;
		let request: RemoveWebhookRequest = serde_json::from_str(json_str).unwrap();
		assert_eq!(
			request.app_name,
			LSPS5AppName::new(UntrustedString(
				"Another Wallet With The Same Signig Device".to_string()
			))
			.unwrap()
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
			match LSPS5WebhookUrl::new(UntrustedString(url_str.to_string())) {
				Ok(_) => panic!("Expected error"),
				Err(e) => {
					// error is not null
					assert!(e.code() != 0);
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
