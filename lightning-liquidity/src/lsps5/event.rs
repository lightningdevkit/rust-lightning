// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains LSPS5 event types

use crate::lsps0::ser::RequestId;
use crate::prelude::{String, Vec};

use bitcoin::secp256k1::PublicKey;

/// An event which an LSPS5 client should take some action in response to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS5ClientEvent {
	/// Confirmation that a webhook has been registered with the LSP.
	WebhookSet {
		/// The identifier of the issued LSPS5 `set_webhook` request, as returned by
		/// [`LSPS5ClientHandler::set_webhook`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS5ClientHandler::set_webhook`]: crate::lsps2::client::LSPS5ClientHandler::set_webhook
		request_id: RequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
		/// The number of webhooks already registered, including this one if it added a new webhook.
		num_webhooks: u32,
		/// The maximum number of webhooks the LSP allows per client.
		max_webhooks: u32,
		/// True if the exact app_name and webhook have already been set.
		no_change: bool,
	},
	/// The list of webhooks registered with the LSP.
	ListWebhooks {
		/// The identifier of the issued LSPS5 `list_webhooks` request, as returned by
		/// [`LSPS5ClientHandler::list_webhooks`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS5ClientHandler::list_webhooks`]: crate::lsps2::client::LSPS5ClientHandler::list_webhooks
		request_id: RequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
		/// List of app names that have webhooks registered for the client.
		app_names: Vec<String>,
		/// The maximum number of webhooks the LSP allows per client.
		max_webhooks: u32,
	},
	/// Confirmation that the webhook as been removed.
	WebhookRemoved {
		/// The identifier of the issued LSPS5 `remove_webhook` request, as returned by
		/// [`LSPS5ClientHandler::remove_webhook`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS5ClientHandler::remove_webhook`]: crate::lsps2::client::LSPS5ClientHandler::remove_webhook
		request_id: RequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
	},
}

/// An event which an LSPS5 server should take some action in response to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS5ServiceEvent {}
