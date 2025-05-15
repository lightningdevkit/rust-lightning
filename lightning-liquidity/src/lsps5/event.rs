// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains bLIP-55 / LSPS5 event types

use crate::lsps0::ser::LSPSDateTime;
use crate::lsps0::ser::LSPSRequestId;
use alloc::string::String;
use alloc::vec::Vec;
use bitcoin::secp256k1::PublicKey;

use super::msgs::LSPS5AppName;
use super::msgs::LSPS5Error;
use super::msgs::LSPS5WebhookUrl;
use super::msgs::WebhookNotification;

/// An event which an bLIP-55 / LSPS5 server should take some action in response to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LSPS5ServiceEvent {
	/// A webhook was registered by a client.
	///
	/// This event is triggered when a client successfully registers or updates a webhook
	/// via [`lsps5.set_webhook`]. The LSP should store this webhook information for future
	/// notifications to this client.
	///
	/// When this event occurs, the LSP should:
	/// 1. Store the webhook information for the client
	/// 2. If `no_change` is `false` (i.e., this is a new registration or an update with changes),
	///    send an initial [`lsps5.webhook_registered`] notification to verify the webhook works.
	///
	/// [`lsps5.set_webhook`]: super::msgs::LSPS5Request::SetWebhook
	/// [`lsps5.webhook_registered`]: super::msgs::WebhookNotificationMethod::LSPS5WebhookRegistered
	WebhookRegistered {
		/// Client node ID that registered the webhook.
		counterparty_node_id: PublicKey,
		/// App name provided by the client.
		///
		/// This app name is used to identify the webhook registration.
		///
		/// **Note**: Ensure the app name is valid and its length does not exceed [`MAX_APP_NAME_LENGTH`].
		///
		/// [`MAX_APP_NAME_LENGTH`]: super::msgs::MAX_APP_NAME_LENGTH
		app_name: LSPS5AppName,
		/// Webhook URL (HTTPS) to be contacted for notifying the client.
		///
		/// This URL is used by the LSP to send notifications.
		///
		/// **Note**: Ensure the URL is valid and its length does not exceed [`MAX_WEBHOOK_URL_LENGTH`].
		/// Also ensure that the URL points to a public host.
		///
		/// [`MAX_WEBHOOK_URL_LENGTH`]: super::msgs::MAX_WEBHOOK_URL_LENGTH
		url: LSPS5WebhookUrl,
		/// The identifier of the issued bLIP-55 / LSPS5 webhook registration request.
		///
		/// This can be used to track which request this event corresponds to.
		request_id: LSPSRequestId,
		/// Whether this was a new registration or an update to existing one with no changes.
		/// If false, a notification should be sent to the registered webhook.
		no_change: bool,
	},

	/// Webhooks were listed for a client.
	///
	/// This event is triggered when a client successfully requests their registered webhooks
	/// via [`lsps5.list_webhooks`]. The LSP has responded with the list of app names that
	/// have registered webhooks for this client.
	///
	/// When this event occurs, it indicates that:
	/// 1. The LSP has successfully fetched all registered webhook names for this client
	/// 2. The LSP has sent a response containing the list and maximum allowed webhooks
	/// 3. The client is now aware of all their currently registered webhooks
	///
	/// This event is primarily informational and doesn't typically require further action.
	///
	/// [`lsps5.list_webhooks`]: super::msgs::LSPS5Request::ListWebhooks
	WebhooksListed {
		/// Client node ID that requested their webhooks.
		counterparty_node_id: PublicKey,
		/// App names with registered webhooks for this client.
		///
		/// Each [`app_name`] in this list corresponds to a registered webhook.
		///
		/// [`app_name`]: super::msgs::LSPS5AppName
		app_names: Vec<LSPS5AppName>,
		/// The identifier of the issued bLIP-55 / LSPS5 webhook listing request.
		///
		/// This can be used to track which request this event corresponds to.
		request_id: LSPSRequestId,
		/// Maximum number of webhooks allowed by LSP per client.
		///
		/// This is the value defined in [`max_webhooks_per_client`] within the service configuration.
		///
		/// [`max_webhooks_per_client`]: super::service::LSPS5ServiceConfig::max_webhooks_per_client
		max_webhooks: u32,
	},

	/// A webhook was removed by a client.
	///
	/// This event is triggered when a client successfully removes a webhook via
	/// [`lsps5.remove_webhook`]. The LSP has deleted the specified webhook registration from
	/// its storage and will no longer send notifications to this webhook URL.
	///
	/// When this event occurs, the LSP should:
	/// 1. Confirm the webhook has been completely removed from all internal data structures
	/// 2. If there are any pending notifications for this webhook, cancel them
	/// 3. Update any related metrics or logs to reflect the webhook removal
	///
	/// Note that if a client attempts to remove a webhook that doesn't exist, a
	/// [`LSPS5ProtocolError::AppNameNotFound`] error is returned instead, and this event
	/// will not be triggered.
	///
	/// [`lsps5.remove_webhook`]: super::msgs::LSPS5Request::RemoveWebhook
	/// [`LSPS5ProtocolError::AppNameNotFound`]: super::msgs::LSPS5ProtocolError::AppNameNotFound
	WebhookRemoved {
		/// Client node ID that removed the webhook.
		counterparty_node_id: PublicKey,
		/// App name that was removed.
		///
		/// This identifies the webhook that was removed.
		///
		/// **Note**: The [`app_name`] must have been previously registered via [`lsps5.set_webhook`].
		///
		/// [`app_name`]: super::msgs::LSPS5AppName
		/// [`lsps5.set_webhook`]: super::msgs::LSPS5Request::SetWebhook
		app_name: LSPS5AppName,
		/// The identifier of the issued bLIP-55 / LSPS5 webhook removal request.
		///
		/// This can be used to track which request this event corresponds to.
		request_id: LSPSRequestId,
	},

	/// A notification needs to be sent to a client's webhook.
	///
	/// This event is triggered when the LSP needs to notify a client about an event
	/// via their registered webhook. The LSP must make an HTTP POST request to the
	/// provided URL with the specified headers and notification content.
	///
	/// When this event occurs, the LSP should:
	/// 1. Send an HTTP POST request to the specified webhook URL
	/// 2. Include all provided headers, especially the timestamp and signature headers
	/// 3. Send the JSON-serialized notification as the request body
	/// 4. Handle any HTTP errors according to the LSP's retry policy
	///
	/// The notification is signed using the LSP's node ID to ensure authenticity
	/// when received by the client. The client verifies this signature using
	/// [`parse_webhook_notification`], which guards against replay attacks and tampering.
	///
	/// If the HTTP request fails, the LSP may implement a retry policy according to its
	/// implementation preferences, but must respect rate-limiting as defined in
	/// [`notification_cooldown_hours`].
	///
	/// [`parse_webhook_notification`]: super::client::LSPS5ClientHandler::parse_webhook_notification
	/// [`notification_cooldown_hours`]: super::service::LSPS5ServiceConfig::notification_cooldown_hours
	SendWebhookNotification {
		/// Client node ID to be notified.
		counterparty_node_id: PublicKey,
		/// App name to be notified.
		///
		/// This identifies which webhook registration should be notified.
		///
		/// **Note**: The [`app_name`] must have been previously registered via [`lsps5.set_webhook`].
		///
		/// [`app_name`]: super::msgs::LSPS5AppName
		/// [`lsps5.set_webhook`]: super::msgs::LSPS5Request::SetWebhook
		app_name: LSPS5AppName,
		/// URL that to be contacted.
		///
		/// This is the webhook URL (HTTPS) provided by the client during registration.
		///
		/// **Note**: The URL must be a valid HTTPS URL that points to a public host.
		///
		/// [`url`]: super::msgs::LSPS5WebhookUrl
		url: LSPS5WebhookUrl,
		/// Notification method with its parameters.
		///
		/// This contains the type of notification and any associated data to be sent to the client.
		notification: WebhookNotification,
		///  Timestamp of the notification.
		///
		/// This timestamp is used for signing the notification and must be within 10 minutes
		/// of the client's local time for the signature to be accepted.
		timestamp: LSPSDateTime,
		/// Signature of the notification using the LSP's node ID.
		///
		/// This signature helps the client verify that the notification was sent by the LSP.
		signature: String,
		/// Headers to be included in the HTTP POST request.
		///
		/// Headers should include:
		/// - Content-Type (application/json)
		/// - x-lsps5-timestamp (timestamp in RFC3339 format, e.g., "YYYY-MM-DDThh:mm:ss.uuuZ")
		/// - x-lsps5-signature (signature of the notification using the LSP's node ID)
		headers: Vec<(String, String)>,
	},
}

/// An event which an LSPS5 client should take some action in response to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LSPS5ClientEvent {
	/// A webhook was successfully registered with the LSP.
	///
	/// This event is triggered when the LSP confirms successful registration
	/// of a webhook via [`lsps5.set_webhook`]. The client has received a successful
	/// response with information about the total number of webhooks registered and limits.
	///
	/// When this event occurs, the client should:
	/// 1. Update any UI to reflect the successful registration
	/// 2. Store the webhook registration details if needed locally
	/// 3. Prepare to receive notifications at the registered webhook URL
	/// 4. Note that if `no_change` is `true`, the LSP did not send a test notification
	///
	/// The [`app_name`] and [`url`] both must respect maximum lengths of
	/// [`MAX_APP_NAME_LENGTH`] and [`MAX_WEBHOOK_URL_LENGTH`] respectively, and the
	/// [`url`] must use HTTPS.
	///
	/// [`lsps5.set_webhook`]: super::msgs::LSPS5Request::SetWebhook
	/// [`app_name`]: super::msgs::LSPS5AppName
	/// [`url`]: super::msgs::LSPS5WebhookUrl
	/// [`MAX_APP_NAME_LENGTH`]: super::msgs::MAX_APP_NAME_LENGTH
	/// [`MAX_WEBHOOK_URL_LENGTH`]: super::msgs::MAX_WEBHOOK_URL_LENGTH
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
	/// via [`lsps5.set_webhook`]. This failure can occur for several reasons:
	///
	/// When this event occurs, the client should:
	/// 1. Present an appropriate error message to the user
	/// 2. Consider retry strategies based on the specific error
	/// 3. If the error is due to reaching webhook limits, prompt the user to remove
	///    unused webhooks before trying again
	///
	/// Common error cases include:
	/// - The [`app_name`] exceeds [`MAX_APP_NAME_LENGTH`] (error [`AppNameTooLong`])
	/// - The [`url`] exceeds [`MAX_WEBHOOK_URL_LENGTH`] (error [`WebhookUrlTooLong`])
	/// - The [`url`] uses an unsupported protocol; HTTPS is required (error [`UnsupportedProtocol`])
	/// - Maximum number of webhooks per client has been reached (error [`TooManyWebhooks`])
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
	/// [`lsps5.list_webhooks`] request. The client now has an up-to-date
	/// list of all registered webhook app names.
	///
	/// When this event occurs, the client should:
	/// 1. Update any UI to display the list of registered webhooks
	/// 2. Update any local cache or state about registered webhooks
	/// 3. Check if the number of webhooks approaches the maximum allowed limit
	///
	/// This listing only provides the app names; to get the URLs, the client would
	/// need to maintain its own records from registration events.
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

	/// The attempt to list webhooks failed.
	///
	/// This event is triggered when the LSP rejects a
	/// [`lsps5.list_webhooks`] request. This is uncommon but might occur
	/// due to temporary server issues or authentication problems.
	///
	/// When this event occurs, the client should:
	/// 1. Present an appropriate error message to the user
	/// 2. Consider implementing a retry mechanism with backoff
	/// 3. If persistent, check connectivity to the LSP node
	///
	/// The error details provided can help diagnose the specific issue.
	///
	/// [`lsps5.list_webhooks`]: super::msgs::LSPS5Request::ListWebhooks
	WebhooksListFailed {
		/// The node id of the LSP that rejected the request.
		counterparty_node_id: PublicKey,
		/// Error from the LSP.
		error: LSPS5Error,
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
	/// When this event occurs, the client should:
	/// 1. Update any UI to reflect the webhook removal
	/// 2. Remove the webhook from any local storage or cache
	/// 3. Update counters or indicators showing the number of registered webhooks
	/// 4. Take any application-specific cleanup actions for the removed webhook
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
	/// via [`lsps5.remove_webhook`]. The most common scenario is attempting
	/// to remove a webhook that doesn't exist or was already removed.
	///
	/// When this event occurs, the client should:
	/// 1. Present an appropriate error message to the user
	/// 2. If the error is [`AppNameNotFound`], update any local state to
	///    reflect that the webhook does not exist on the server
	/// 3. Consider refreshing the webhook list to ensure local state
	///    matches server state
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

	/// A webhook notification was received from the LSP.
	///
	/// This event is triggered when the client receives and successfully
	/// verifies a webhook notification from the LSP. This represents an
	/// asynchronous event that the LSP is notifying the client about.
	///
	/// When this event occurs, the client should:
	/// 1. Check `signature_valid` to confirm the notification is authentic
	/// 2. Examine the `notification.method` to determine the type of notification
	/// 3. Process the notification according to its method and parameters
	/// 4. Update any UI or take actions based on the notification type
	///
	/// Common notification methods include:
	/// - [`LSPS5WebhookRegistered`] - Initial test notification after registration
	/// - [`LSPS5PaymentIncoming`] - Client has pending incoming payments
	/// - [`LSPS5ExpirySoon`] - An HTLC or contract will expire soon
	/// - [`LSPS5LiquidityManagementRequest`] - LSP needs to manage liquidity
	/// - [`LSPS5OnionMessageIncoming`] - Client has pending onion messages
	///
	/// The client should reject notifications with invalid signatures or timestamps
	/// more than 10 minutes from the current time.
	///
	/// [`LSPS5WebhookRegistered`]: super::msgs::WebhookNotificationMethod::LSPS5WebhookRegistered
	/// [`LSPS5PaymentIncoming`]: super::msgs::WebhookNotificationMethod::LSPS5PaymentIncoming
	/// [`LSPS5ExpirySoon`]: super::msgs::WebhookNotificationMethod::LSPS5ExpirySoon
	/// [`LSPS5LiquidityManagementRequest`]: super::msgs::WebhookNotificationMethod::LSPS5LiquidityManagementRequest
	/// [`LSPS5OnionMessageIncoming`]: super::msgs::WebhookNotificationMethod::LSPS5OnionMessageIncoming
	WebhookNotificationReceived {
		/// LSP node ID that sent the notification.
		counterparty_node_id: PublicKey,
		/// The notification with its method and parameters.
		notification: WebhookNotification,
		/// Timestamp of the notification.
		timestamp: LSPSDateTime,
		/// Whether the LSP's signature was successfully verified.
		signature_valid: bool,
	},
}
