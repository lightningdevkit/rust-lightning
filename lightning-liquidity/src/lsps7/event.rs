// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains bLIP-57 / LSPS7 event types

use super::msgs::{LSPS7ExtendableChannel, LSPS7OrderId, LSPS7OrderState};

use crate::lsps0::ser::{LSPSRequestId, LSPSResponseError};
use crate::lsps1::msgs::LSPS1PaymentInfo;

use bitcoin::secp256k1::PublicKey;

use alloc::vec::Vec;

/// An event which a bLIP-57 / LSPS7 client should take some action in response to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS7ClientEvent {
	/// A request previously issued via [`LSPS7ClientHandler::request_extendable_channels`]
	/// succeeded as the LSP returned the list of extendable channels.
	///
	/// You must check the channels and then call
	/// [`LSPS7ClientHandler::create_order`] to place an extension order.
	///
	/// **Note:** This event will *not* be persisted across restarts.
	///
	/// [`LSPS7ClientHandler::request_extendable_channels`]: crate::lsps7::client::LSPS7ClientHandler::request_extendable_channels
	/// [`LSPS7ClientHandler::create_order`]: crate::lsps7::client::LSPS7ClientHandler::create_order
	ExtendableChannelsReady {
		/// The identifier of the issued bLIP-57 / LSPS7 `get_extendable_channels` request, as
		/// returned by [`LSPS7ClientHandler::request_extendable_channels`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS7ClientHandler::request_extendable_channels`]: crate::lsps7::client::LSPS7ClientHandler::request_extendable_channels
		request_id: LSPSRequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
		/// The list of channels eligible for extension.
		extendable_channels: Vec<LSPS7ExtendableChannel>,
	},
	/// A request previously issued via [`LSPS7ClientHandler::request_extendable_channels`]
	/// failed as the LSP returned an error response.
	///
	/// **Note:** This event will *not* be persisted across restarts.
	///
	/// [`LSPS7ClientHandler::request_extendable_channels`]: crate::lsps7::client::LSPS7ClientHandler::request_extendable_channels
	ExtendableChannelsRequestFailed {
		/// The identifier of the issued bLIP-57 / LSPS7 `get_extendable_channels` request, as
		/// returned by [`LSPS7ClientHandler::request_extendable_channels`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS7ClientHandler::request_extendable_channels`]: crate::lsps7::client::LSPS7ClientHandler::request_extendable_channels
		request_id: LSPSRequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
		/// The error that was returned.
		error: LSPSResponseError,
	},
	/// Confirmation from the LSP about the extension order created by the client.
	///
	/// When the payment is confirmed, the LSP will extend the channel lease.
	///
	/// You must pay the invoice or onchain address if you want to continue and then
	/// call [`LSPS7ClientHandler::check_order_status`] with the order id
	/// to get information from LSP about progress of the order.
	///
	/// **Note:** This event will *not* be persisted across restarts.
	///
	/// [`LSPS7ClientHandler::check_order_status`]: crate::lsps7::client::LSPS7ClientHandler::check_order_status
	OrderCreated {
		/// The identifier of the issued bLIP-57 / LSPS7 `create_order` request, as returned by
		/// [`LSPS7ClientHandler::create_order`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS7ClientHandler::create_order`]: crate::lsps7::client::LSPS7ClientHandler::create_order
		request_id: LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The id of the extension order.
		order_id: LSPS7OrderId,
		/// The current state of the order.
		order_state: LSPS7OrderState,
		/// The number of blocks the channel lease will be extended by.
		channel_extension_expiry_blocks: u32,
		/// The new expiration block of the channel lease after extension.
		new_channel_expiry_block: u32,
		/// The details regarding payment of the order.
		payment: LSPS1PaymentInfo,
		/// The channel being extended.
		channel: LSPS7ExtendableChannel,
	},
	/// Information from the LSP about the status of a previously created extension order.
	///
	/// Will be emitted in response to calling [`LSPS7ClientHandler::check_order_status`].
	///
	/// **Note:** This event will *not* be persisted across restarts.
	///
	/// [`LSPS7ClientHandler::check_order_status`]: crate::lsps7::client::LSPS7ClientHandler::check_order_status
	OrderStatus {
		/// The identifier of the issued bLIP-57 / LSPS7 `get_order` request, as returned by
		/// [`LSPS7ClientHandler::check_order_status`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS7ClientHandler::check_order_status`]: crate::lsps7::client::LSPS7ClientHandler::check_order_status
		request_id: LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The id of the extension order.
		order_id: LSPS7OrderId,
		/// The current state of the order.
		order_state: LSPS7OrderState,
		/// The number of blocks the channel lease will be extended by.
		channel_extension_expiry_blocks: u32,
		/// The new expiration block of the channel lease after extension.
		new_channel_expiry_block: u32,
		/// The details regarding payment of the order.
		payment: LSPS1PaymentInfo,
		/// The channel being extended.
		channel: LSPS7ExtendableChannel,
	},
	/// A request previously issued via [`LSPS7ClientHandler::create_order`] or
	/// [`LSPS7ClientHandler::check_order_status`] failed as the LSP returned an error response.
	///
	/// **Note:** This event will *not* be persisted across restarts.
	///
	/// [`LSPS7ClientHandler::create_order`]: crate::lsps7::client::LSPS7ClientHandler::create_order
	/// [`LSPS7ClientHandler::check_order_status`]: crate::lsps7::client::LSPS7ClientHandler::check_order_status
	OrderRequestFailed {
		/// The identifier of the issued LSPS7 `create_order` or `get_order` request, as returned by
		/// [`LSPS7ClientHandler::create_order`] or [`LSPS7ClientHandler::check_order_status`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS7ClientHandler::create_order`]: crate::lsps7::client::LSPS7ClientHandler::create_order
		/// [`LSPS7ClientHandler::check_order_status`]: crate::lsps7::client::LSPS7ClientHandler::check_order_status
		request_id: LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The error that was returned.
		error: LSPSResponseError,
	},
}
