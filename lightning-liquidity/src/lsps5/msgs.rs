//! Message, request, and other primitive types used to implement LSPS5.

use core::convert::TryFrom;
use serde::{Deserialize, Serialize};

use crate::lsps0::ser::{LSPSMessage, RequestId, ResponseError};
use crate::prelude::{String, Vec};

use super::notifications::LSPS5Notification;

pub(crate) const LSPS5_SET_WEBHOOK_METHOD_NAME: &str = "lsps5.set_webhook";
pub(crate) const LSPS5_LIST_WEBHOOKS_METHOD_NAME: &str = "lsps5.list_webhooks";
pub(crate) const LSPS5_REMOVE_WEBHOOK_METHOD_NAME: &str = "lsps5.remove_webhook";

pub(crate) const LSPS5_SET_WEBHOOK_REQUEST_TOO_LONG_ERROR_CODE: i32 = 1000;
pub(crate) const LSPS5_SET_WEBHOOK_REQUEST_UNSUPPORTED_PROTOCOL_ERROR_CODE: i32 = 1001;
pub(crate) const LSPS5_SET_WEBHOOK_REQUEST_TOO_MANY_WEBHOOKS_ERROR_CODE: i32 = 1002;

pub(crate) const LSPS5_REMOVE_WEBHOOK_REQUEST_APP_NAME_NOT_FOUND_ERROR_CODE: i32 = 1010;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
/// A request to specify the URI that the LSP should contact in order to send a push notification to the client user.
pub struct SetWebhookRequest {
	/// a human-readable UTF-8 string that gives a name to the webhook.
	pub app_name: String,
	///  the URL of the webhook that the LSP can use to push a notification to the client
	pub webhook: String,
}

/// A response to a [`SetWebhookRequest`]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SetWebhookResponse {
	/// The number of webhooks already registered, including this one if it added a new webhook.
	pub num_webhooks: u32,
	/// The maximum number of webhooks the LSP allows per client.
	pub max_webhooks: u32,
	/// True if the exact app_name and webhook have already been set.
	pub no_change: bool,
}

/// A request to learn all app_names that have webhooks registered for the client.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ListWebhooksRequest {}

/// A response to a [`ListWebhooksRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ListWebhooksResponse {
	/// List of app names that have webhooks registered for the client.
	pub app_names: Vec<String>,
	/// The maximum number of webhooks the LSP allows per client.
	pub max_webhooks: u32,
}

/// A request to learn all app_names that have webhooks registered for the client.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RemoveWebhookRequest {
	/// the app_name of the webhook to remove.
	pub app_name: String,
}

/// A response to a [`RemoveWebhookRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RemoveWebhookResponse {}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An enum that captures all the valid JSON-RPC requests in the LSPS5 protocol.
pub enum LSPS5Request {
	/// A request to set a webhook for an app.
	SetWebhook(SetWebhookRequest),
	/// A request to list all registered webhooks.
	ListWebhooks(ListWebhooksRequest),
	/// A request to remove a specific webhook.
	RemoveWebhook(RemoveWebhookRequest),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An enum that captures all the valid JSON-RPC responses in the LSPS5 protocol.
pub enum LSPS5Response {
	/// A successful response to a [`LSPS5Request::SetWebhook`] request.
	SetWebhook(SetWebhookResponse),
	/// An error response to a [`LSPS5Request::SetWebhook`] request.
	SetWebhookError(ResponseError),
	/// A successful response to a [`LSPS5Request::ListWebhooks`] request.
	ListWebhooks(ListWebhooksResponse),
	/// An successfull response to a [`LSPS5Request::RemoveWebhook`] request.
	RemoveWebhook(RemoveWebhookResponse),
	/// An error response to a [`LSPS5Request::RemoveWebhook`] request.
	RemoveWebhookError(ResponseError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An enum that captures all valid JSON-RPC messages in the LSPS5 protocol.
pub enum LSPS5Message {
	/// An LSPS5 JSON-RPC request.
	Request(RequestId, LSPS5Request),
	/// An LSPS5 JSON-RPC response.
	Response(RequestId, LSPS5Response),
	/// An LSPS5 JSON-RPC notification.
	Notification(LSPS5Notification),
}

impl TryFrom<LSPSMessage> for LSPS5Message {
	type Error = ();

	fn try_from(message: LSPSMessage) -> Result<Self, Self::Error> {
		if let LSPSMessage::LSPS5(message) = message {
			return Ok(message);
		}

		Err(())
	}
}

impl From<LSPS5Message> for LSPSMessage {
	fn from(message: LSPS5Message) -> Self {
		LSPSMessage::LSPS5(message)
	}
}
