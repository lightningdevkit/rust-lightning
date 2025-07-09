// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains bLIP-55 / LSPS5 event types

use crate::lsps0::ser::LSPSRequestId;
use alloc::string::String;
use alloc::vec::Vec;
use bitcoin::secp256k1::PublicKey;
use lightning::util::hash_tables::HashMap;

use super::msgs::LSPS5AppName;
use super::msgs::LSPS5Error;
use super::msgs::LSPS5WebhookUrl;
use super::msgs::WebhookNotification;

/// An event which an bLIP-55 / LSPS5 server should take some action in response to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LSPS5ServiceEvent {
	/// A notification needs to be sent to a client.
	///
	/// This event is triggered when the LSP needs to notify a client about an event
	/// via their registered webhook.
	///
	/// The LSP should send an HTTP POST to the [`url`], using the
	/// JSON-serialized [`notification`] as the body and including the `headers`.
	/// If the HTTP request fails, the LSP may implement a retry policy according to its
	/// implementation preferences, but must respect rate-limiting as defined in
	/// [`notification_cooldown_hours`].
	///
	/// The notification is signed using the LSP's node ID to ensure authenticity
	/// when received by the client. The client verifies this signature using
	/// [`parse_webhook_notification`], which guards against replay attacks and tampering.
	///
	/// [`parse_webhook_notification`]: super::client::LSPS5ClientHandler::parse_webhook_notification
	/// [`notification_cooldown_hours`]: super::service::LSPS5ServiceConfig::notification_cooldown_hours
	/// [`url`]: super::msgs::LSPS5WebhookUrl
	/// [`notification`]: super::msgs::WebhookNotification
	SendWebhookNotification {
		/// Client node ID to be notified.
		counterparty_node_id: PublicKey,
		/// [`App name`] to be notified.
		///
		/// This identifies which webhook registration should be notified.
		///
		/// [`App name`]: super::msgs::LSPS5AppName
		app_name: LSPS5AppName,
		/// URL to be called.
		///
		/// This is the [`webhook URL`] provided by the client during registration.
		///
		/// [`webhook URL`]: super::msgs::LSPS5WebhookUrl
		url: LSPS5WebhookUrl,
		/// Notification method with its parameters.
		///
		/// This contains the type of notification and any associated data to be sent to the client.
		notification: WebhookNotification,
		/// Headers to be included in the HTTP POST request.
		///
		/// This is a map of HTTP header key-value pairs. It will include:
		/// - `"Content-Type"`: with a value like `"application/json"`.
		/// - `"x-lsps5-timestamp"`: with the timestamp in RFC3339 format (`"YYYY-MM-DDThh:mm:ss.uuuZ"`).
		/// - `"x-lsps5-signature"`: with the signature of the notification payload, signed using the LSP's node ID.
		/// Other custom headers may also be included as needed.
		headers: HashMap<String, String>,
	},
}

/// An event which an LSPS5 client should take some action in response to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LSPS5ClientEvent {
	/// A webhook was successfully registered with the LSP.
	///
	/// This event is triggered when the LSP confirms successful registration
	/// of a webhook via [`lsps5.set_webhook`].
	///
	/// If `no_change` is `false` (indicating the registered webhook is a new registration),
	/// the LSP will also emit a [`SendWebhookNotification`] event with a [`webhook_registered`] notification
	/// to notify the client about this registration.
	///
	/// [`lsps5.set_webhook`]: super::msgs::LSPS5Request::SetWebhook
	/// [`SendWebhookNotification`]: super::event::LSPS5ServiceEvent::SendWebhookNotification
	/// [`webhook_registered`]: super::msgs::WebhookNotificationMethod::LSPS5WebhookRegistered
	WebhookRegistered {
		/// The node id of the LSP that confirmed the registration.
		counterparty_node_id: PublicKey,
		/// Current number of webhooks registered for this client.
		num_webhooks: u32,
		/// Maximum number of webhooks allowed by LSP.
		max_webhooks: u32,
		/// Whether this was an unchanged registration (same app_name and URL).
		/// If true, the LSP didn't send a webhook notification for this registration.
		no_change: bool,
		/// The app name that was registered.
		app_name: LSPS5AppName,
		/// The webhook URL that was registered.
		url: LSPS5WebhookUrl,
		/// The identifier of the issued bLIP-55 / LSPS5 webhook registration request.
		///
		/// This can be used to track which request this event corresponds to.
		request_id: LSPSRequestId,
	},

	/// A webhook registration attempt failed.
	///
	/// This event is triggered when the LSP rejects a webhook registration
	/// via [`lsps5.set_webhook`].
	///
	/// Possible errors:
	/// - The [`app_name`] exceeds [`MAX_APP_NAME_LENGTH`] (error [`AppNameTooLong`]).
	/// - The [`url`] exceeds [`MAX_WEBHOOK_URL_LENGTH`] (error [`WebhookUrlTooLong`]).
	/// - The [`url`] uses an unsupported protocol. HTTPS is required (error [`UnsupportedProtocol`]).
	/// - Maximum number of webhooks per client has been reached (error [`TooManyWebhooks`]). Remove a webhook before
	///  registering a new one.
	///
	/// [`lsps5.set_webhook`]: super::msgs::LSPS5Request::SetWebhook
	/// [`app_name`]: super::msgs::LSPS5AppName
	/// [`url`]: super::msgs::LSPS5WebhookUrl
	/// [`MAX_APP_NAME_LENGTH`]: super::msgs::MAX_APP_NAME_LENGTH
	/// [`MAX_WEBHOOK_URL_LENGTH`]: super::msgs::MAX_WEBHOOK_URL_LENGTH
	/// [`AppNameTooLong`]: super::msgs::LSPS5ProtocolError::AppNameTooLong
	/// [`WebhookUrlTooLong`]: super::msgs::LSPS5ProtocolError::WebhookUrlTooLong
	/// [`UnsupportedProtocol`]: super::msgs::LSPS5ProtocolError::UnsupportedProtocol
	/// [`TooManyWebhooks`]: super::msgs::LSPS5ProtocolError::TooManyWebhooks
	WebhookRegistrationFailed {
		/// The node id of the LSP that rejected the registration.
		counterparty_node_id: PublicKey,
		/// Error from the LSP.
		error: LSPS5Error,
		/// The app name that was attempted.
		app_name: LSPS5AppName,
		/// The webhook URL that was attempted.
		url: LSPS5WebhookUrl,
		/// The identifier of the issued bLIP-55 / LSPS5 webhook registration request.
		///
		/// This can be used to track which request this event corresponds to.
		request_id: LSPSRequestId,
	},

	/// The list of registered webhooks was successfully retrieved.
	///
	/// This event is triggered when the LSP responds to a
	/// [`lsps5.list_webhooks`] request.
	///
	/// [`lsps5.list_webhooks`]: super::msgs::LSPS5Request::ListWebhooks
	WebhooksListed {
		/// The node id of the LSP that provided the list.
		counterparty_node_id: PublicKey,
		/// List of app names with registered webhooks.
		app_names: Vec<LSPS5AppName>,
		/// Maximum number of webhooks allowed by LSP.
		max_webhooks: u32,
		/// The identifier of the issued bLIP-55 / LSPS5 list webhooks request.
		///
		/// This can be used to track which request this event corresponds to.
		request_id: LSPSRequestId,
	},

	/// A webhook was successfully removed.
	///
	/// This event is triggered when the LSP confirms successful removal
	/// of a webhook via [`lsps5.remove_webhook`]. The webhook registration
	/// has been deleted from the LSP's system and will no longer receive
	/// notifications.
	///
	/// After this event, the app_name is free to be reused for a new webhook
	/// registration if desired.
	///
	/// [`lsps5.remove_webhook`]: super::msgs::LSPS5Request::RemoveWebhook
	WebhookRemoved {
		/// The node id of the LSP that confirmed the removal.
		counterparty_node_id: PublicKey,
		/// The app name that was removed.
		app_name: LSPS5AppName,
		/// The identifier of the issued bLIP-55 / LSPS5 remove webhook request.
		///
		/// This can be used to track which request this event corresponds to.
		request_id: LSPSRequestId,
	},

	/// A webhook removal attempt failed.
	///
	/// This event is triggered when the LSP rejects a webhook removal
	/// via [`lsps5.remove_webhook`].
	///
	/// The most common error is [`LSPS5ProtocolError::AppNameNotFound`]
	/// (error code [`LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE`]), which indicates
	/// the given [`app_name`] was not found in the LSP's registration database.
	///
	/// [`lsps5.remove_webhook`]: super::msgs::LSPS5Request::RemoveWebhook
	/// [`AppNameNotFound`]: super::msgs::LSPS5ProtocolError::AppNameNotFound
	/// [`LSPS5ProtocolError::AppNameNotFound`]: super::msgs::LSPS5ProtocolError::AppNameNotFound
	/// [`LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE`]: super::msgs::LSPS5_APP_NAME_NOT_FOUND_ERROR_CODE
	/// [`app_name`]: super::msgs::LSPS5AppName
	WebhookRemovalFailed {
		/// The node id of the LSP that rejected the removal.
		counterparty_node_id: PublicKey,
		/// Error from the LSP.
		error: LSPS5Error,
		/// The app name that was attempted to be removed.
		app_name: LSPS5AppName,
		/// The identifier of the issued bLIP-55 / LSPS5 remove webhook request.
		///
		/// This can be used to track which request this event corresponds to.
		request_id: LSPSRequestId,
	},
}
