// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LSPS5 message formats for webhook registration

use crate::{
	lsps0::ser::{LSPSMessage, LSPSRequestId, LSPSResponseError},
	prelude::*,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(crate) const LSPS5_TOO_LONG_ERROR_CODE: i32 = 500;
pub(crate) const LSPS5_URL_PARSE_ERROR_CODE: i32 = 501;
pub(crate) const LSPS5_UNSUPPORTED_PROTOCOL_ERROR_CODE: i32 = 502;
pub(crate) const LSPS5_TOO_MANY_WEBHOOKS_ERROR_CODE: i32 = 503;
pub(crate) const LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE: i32 = 1010;

pub(crate) const LSPS5_SET_WEBHOOK_METHOD_NAME: &str = "lsps5.set_webhook";
pub(crate) const LSPS5_LIST_WEBHOOKS_METHOD_NAME: &str = "lsps5.list_webhooks";
pub(crate) const LSPS5_REMOVE_WEBHOOK_METHOD_NAME: &str = "lsps5.remove_webhook";

/// Webhook notification methods defined in LSPS5
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookNotificationMethod {
	/// Webhook has been successfully registered
	#[serde(rename = "lsps5.webhook_registered")]
	WebhookRegistered,
	/// Client has payments pending to be received
	#[serde(rename = "lsps5.payment_incoming")]
	PaymentIncoming,
	/// HTLC or time-bound contract is about to expire
	#[serde(rename = "lsps5.expiry_soon")]
	ExpirySoon,
	/// LSP wants to take back some liquidity
	#[serde(rename = "lsps5.liquidity_management_request")]
	LiquidityManagementRequest,
	/// Client has onion messages pending
	#[serde(rename = "lsps5.onion_message_incoming")]
	OnionMessageIncoming,
}

/// Parameters for lsps5.set_webhook request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetWebhookRequest {
	/// Human-readable name for the webhook (max 64 bytes)
	pub app_name: String,
	/// URL of the webhook (max 1024 ASCII chars)
	pub webhook: String,
}

/// Response for lsps5.set_webhook
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetWebhookResponse {
	/// Current number of webhooks registered for this client
	pub num_webhooks: u32,
	/// Maximum number of webhooks allowed by LSP
	pub max_webhooks: u32,
	/// Whether this is an unchanged registration
	pub no_change: bool,
}

/// Parameters for lsps5.list_webhooks request (empty)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ListWebhooksRequest {}

/// Response for lsps5.list_webhooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListWebhooksResponse {
	/// List of app_names with registered webhooks
	pub app_names: Vec<String>,
	/// Maximum number of webhooks allowed by LSP
	pub max_webhooks: u32,
}

/// Parameters for lsps5.remove_webhook request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveWebhookRequest {
	/// App name identifying the webhook to remove
	pub app_name: String,
}

/// Response for lsps5.remove_webhook (empty)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RemoveWebhookResponse {}

/// Parameters for lsps5.expiry_soon webhook notification
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
	pub params: Value,
}

impl WebhookNotification {
	/// Create a new webhook notification
	pub fn new(method: WebhookNotificationMethod, params: Value) -> Self {
		Self { jsonrpc: "2.0".to_string(), method, params }
	}

	/// Create webhook_registered notification (no params)
	pub fn webhook_registered() -> Self {
		Self::new(WebhookNotificationMethod::WebhookRegistered, json!({}))
	}

	/// Create payment_incoming notification (no params)
	pub fn payment_incoming() -> Self {
		Self::new(WebhookNotificationMethod::PaymentIncoming, json!({}))
	}

	/// Create expiry_soon notification
	pub fn expiry_soon(timeout: u32) -> Self {
		Self::new(WebhookNotificationMethod::ExpirySoon, json!({ "timeout": timeout }))
	}

	/// Create liquidity_management_request notification (no params)
	pub fn liquidity_management_request() -> Self {
		Self::new(WebhookNotificationMethod::LiquidityManagementRequest, json!({}))
	}

	/// Create onion_message_incoming notification (no params)
	pub fn onion_message_incoming() -> Self {
		Self::new(WebhookNotificationMethod::OnionMessageIncoming, json!({}))
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
	/// Response to SetWebhook request
	SetWebhook(SetWebhookResponse),
	/// Error response to SetWebhook request
	SetWebhookError(LSPSResponseError),
	/// Response to ListWebhooks request
	ListWebhooks(ListWebhooksResponse),
	/// Error response to ListWebhooks request
	ListWebhooksError(LSPSResponseError),
	/// Response to RemoveWebhook request
	RemoveWebhook(RemoveWebhookResponse),
	/// Error response to RemoveWebhook request
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
		assert_eq!(request.app_name, "my_app");
		assert_eq!(request.webhook, "https://example.com/webhook");
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
		assert_eq!(response.app_names, vec!["app1".to_string(), "app2".to_string()]);
		assert_eq!(response.max_webhooks, 5);
	}

	#[test]
	fn parse_empty_requests_responses() {
		let json_str = r#"{}"#;
		let _list_req: ListWebhooksRequest = serde_json::from_str(json_str).unwrap();
		let _remove_resp: RemoveWebhookResponse = serde_json::from_str(json_str).unwrap();
	}
}
