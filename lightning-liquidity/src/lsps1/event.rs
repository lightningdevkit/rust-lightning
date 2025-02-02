// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains bLIP-51 / LSPS1 event types

use super::msgs::LSPS1OrderId;
use super::msgs::{LSPS1ChannelInfo, LSPS1Options, LSPS1OrderParams, LSPS1PaymentInfo};

use crate::lsps0::ser::{RequestId, ResponseError};

use bitcoin::secp256k1::PublicKey;

/// An event which an bLIP-51 / LSPS1 client should take some action in response to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS1ClientEvent {
	/// A request previously issued via [`LSPS1ClientHandler::request_supported_options`]
	/// succeeded as the LSP returned the options it supports.
	///
	/// You must check whether LSP supports the parameters the client wants and then call
	/// [`LSPS1ClientHandler::create_order`] to place an order.
	///
	/// [`LSPS1ClientHandler::request_supported_options`]: crate::lsps1::client::LSPS1ClientHandler::request_supported_options
	/// [`LSPS1ClientHandler::create_order`]: crate::lsps1::client::LSPS1ClientHandler::create_order
	SupportedOptionsReady {
		/// The identifier of the issued bLIP-51 / LSPS1 `get_info` request, as returned by
		/// [`LSPS1ClientHandler::request_supported_options`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::request_supported_options`]: crate::lsps1::client::LSPS1ClientHandler::request_supported_options
		request_id: RequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
		/// All options supported by the LSP.
		supported_options: LSPS1Options,
	},
	/// A request previously issued via [`LSPS1ClientHandler::request_supported_options`]
	/// failed as the LSP returned an error response.
	///
	/// [`LSPS1ClientHandler::request_supported_options`]: crate::lsps1::client::LSPS1ClientHandler::request_supported_options
	SupportedOptionsRequestFailed {
		/// The identifier of the issued bLIP-51 / LSPS1 `get_info` request, as returned by
		/// [`LSPS1ClientHandler::request_supported_options`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::request_supported_options`]: crate::lsps1::client::LSPS1ClientHandler::request_supported_options
		request_id: RequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
		/// The error that was returned.
		error: ResponseError,
	},
	/// Confirmation from the LSP about the order created by the client.
	///
	/// When the payment is confirmed, the LSP will open a channel to you
	/// with the below agreed upon parameters.
	///
	/// You must pay the invoice or onchain address if you want to continue and then
	/// call [`LSPS1ClientHandler::check_order_status`] with the order id
	/// to get information from LSP about progress of the order.
	///
	/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
	OrderCreated {
		/// The identifier of the issued bLIP-51 / LSPS1 `create_order` request, as returned by
		/// [`LSPS1ClientHandler::create_order`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::create_order`]: crate::lsps1::client::LSPS1ClientHandler::create_order
		request_id: RequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The id of the channel order.
		order_id: LSPS1OrderId,
		/// The order created by client and approved by LSP.
		order: LSPS1OrderParams,
		/// The details regarding payment of the order
		payment: LSPS1PaymentInfo,
		/// The details regarding state of the channel ordered.
		channel: Option<LSPS1ChannelInfo>,
	},
	/// Information from the LSP about the status of a previously created order.
	///
	/// Will be emitted in response to calling [`LSPS1ClientHandler::check_order_status`].
	///
	/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
	OrderStatus {
		/// The identifier of the issued bLIP-51 / LSPS1 `get_order` request, as returned by
		/// [`LSPS1ClientHandler::check_order_status`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
		request_id: RequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The id of the channel order.
		order_id: LSPS1OrderId,
		/// The order created by client and approved by LSP.
		order: LSPS1OrderParams,
		/// The details regarding payment of the order
		payment: LSPS1PaymentInfo,
		/// The details regarding state of the channel ordered.
		channel: Option<LSPS1ChannelInfo>,
	},
	/// A request previously issued via [`LSPS1ClientHandler::create_order`] or [`LSPS1ClientHandler::check_order_status`].
	/// failed as the LSP returned an error response.
	///
	/// [`LSPS1ClientHandler::create_order`]: crate::lsps1::client::LSPS1ClientHandler::create_order
	/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
	OrderRequestFailed {
		/// The identifier of the issued LSPS1 `create_order` or `get_order` request, as returned by
		/// [`LSPS1ClientHandler::create_order`] or [`LSPS1ClientHandler::check_order_status`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS1ClientHandler::create_order`]: crate::lsps1::client::LSPS1ClientHandler::create_order
		/// [`LSPS1ClientHandler::check_order_status`]: crate::lsps1::client::LSPS1ClientHandler::check_order_status
		request_id: RequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The error that was returned.
		error: ResponseError,
	},
}

/// An event which an LSPS1 server should take some action in response to.
#[cfg(lsps1_service)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS1ServiceEvent {
	/// A client has selected the parameters to use from the supported options of the LSP
	/// and would like to open a channel with the given payment parameters.
	///
	/// You must call [`LSPS1ServiceHandler::send_payment_details`] to
	/// send order parameters including the details regarding the
	/// payment and order id for this order for the client.
	///
	/// [`LSPS1ServiceHandler::send_payment_details`]: crate::lsps1::service::LSPS1ServiceHandler::send_payment_details
	RequestForPaymentDetails {
		/// An identifier that must be passed to [`LSPS1ServiceHandler::send_payment_details`].
		///
		/// [`LSPS1ServiceHandler::send_payment_details`]: crate::lsps1::service::LSPS1ServiceHandler::send_payment_details
		request_id: RequestId,
		/// The node id of the client making the information request.
		counterparty_node_id: PublicKey,
		/// The order requested by the client.
		order: LSPS1OrderParams,
	},
	/// A request from client to check the status of the payment.
	///
	/// An event to poll for checking payment status either onchain or lightning.
	///
	/// You must call [`LSPS1ServiceHandler::update_order_status`] to update the client
	/// regarding the status of the payment and order.
	///
	/// [`LSPS1ServiceHandler::update_order_status`]: crate::lsps1::service::LSPS1ServiceHandler::update_order_status
	CheckPaymentConfirmation {
		/// An identifier that must be passed to [`LSPS1ServiceHandler::update_order_status`].
		///
		/// [`LSPS1ServiceHandler::update_order_status`]: crate::lsps1::service::LSPS1ServiceHandler::update_order_status
		request_id: RequestId,
		/// The node id of the client making the information request.
		counterparty_node_id: PublicKey,
		/// The order id of order with pending payment.
		order_id: LSPS1OrderId,
	},
	/// If error is encountered, refund the amount if paid by the client.
	Refund {
		/// An identifier.
		request_id: RequestId,
		/// The node id of the client making the information request.
		counterparty_node_id: PublicKey,
		/// The order id of the refunded order.
		order_id: LSPS1OrderId,
	},
}
