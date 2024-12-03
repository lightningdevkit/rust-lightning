// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains LSPS2 event types

use super::msgs::OpeningFeeParams;
use crate::lsps0::ser::RequestId;
use crate::prelude::{String, Vec};

use bitcoin::secp256k1::PublicKey;

/// An event which an LSPS2 client should take some action in response to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS2ClientEvent {
	/// Information from the LSP about their current fee rates and channel parameters.
	///
	/// You must call [`LSPS2ClientHandler::select_opening_params`] with the fee parameter
	/// you want to use if you wish to proceed opening a channel.
	///
	/// [`LSPS2ClientHandler::select_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::select_opening_params
	OpeningParametersReady {
		/// The identifier of the issued LSPS2 `get_info` request, as returned by
		/// [`LSPS2ClientHandler::request_opening_params`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS2ClientHandler::request_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::request_opening_params
		request_id: RequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
		/// The menu of fee parameters the LSP is offering at this time.
		/// You must select one of these if you wish to proceed.
		opening_fee_params_menu: Vec<OpeningFeeParams>,
	},
	/// Provides the necessary information to generate a payable invoice that then may be given to
	/// the payer.
	///
	/// When the invoice is paid, the LSP will open a channel with the previously agreed upon
	/// parameters to you.
	InvoiceParametersReady {
		/// The identifier of the issued LSPS2 `buy` request, as returned by
		/// [`LSPS2ClientHandler::select_opening_params`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS2ClientHandler::select_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::select_opening_params
		request_id: RequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The intercept short channel id to use in the route hint.
		intercept_scid: u64,
		/// The `cltv_expiry_delta` to use in the route hint.
		cltv_expiry_delta: u32,
		/// The initial payment size you specified.
		payment_size_msat: Option<u64>,
	},
}

/// An event which an LSPS2 server should take some action in response to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS2ServiceEvent {
	/// A request from a client for information about JIT Channel parameters.
	///
	/// You must calculate the parameters for this client and pass them to
	/// [`LSPS2ServiceHandler::opening_fee_params_generated`].
	///
	/// If an unrecognized or stale token is provided you can use
	/// `[LSPS2ServiceHandler::invalid_token_provided`] to error the request.
	///
	/// [`LSPS2ServiceHandler::opening_fee_params_generated`]: crate::lsps2::service::LSPS2ServiceHandler::opening_fee_params_generated
	/// [`LSPS2ServiceHandler::invalid_token_provided`]: crate::lsps2::service::LSPS2ServiceHandler::invalid_token_provided
	GetInfo {
		/// An identifier that must be passed to [`LSPS2ServiceHandler::opening_fee_params_generated`].
		///
		/// [`LSPS2ServiceHandler::opening_fee_params_generated`]: crate::lsps2::service::LSPS2ServiceHandler::opening_fee_params_generated
		request_id: RequestId,
		/// The node id of the client making the information request.
		counterparty_node_id: PublicKey,
		/// An optional token that can be used as an API key, coupon code, etc.
		token: Option<String>,
	},
	/// A client has selected a opening fee parameter to use and would like to
	/// purchase a channel with an optional initial payment size.
	///
	/// If `payment_size_msat` is [`Option::Some`] then the payer is allowed to use MPP.
	/// If `payment_size_msat` is [`Option::None`] then the payer cannot use MPP.
	///
	/// You must generate an intercept scid and `cltv_expiry_delta` for them to use
	/// and call [`LSPS2ServiceHandler::invoice_parameters_generated`].
	///
	/// [`LSPS2ServiceHandler::invoice_parameters_generated`]: crate::lsps2::service::LSPS2ServiceHandler::invoice_parameters_generated
	BuyRequest {
		/// An identifier that must be passed into [`LSPS2ServiceHandler::invoice_parameters_generated`].
		///
		/// [`LSPS2ServiceHandler::invoice_parameters_generated`]: crate::lsps2::service::LSPS2ServiceHandler::invoice_parameters_generated
		request_id: RequestId,
		/// The client node id that is making this request.
		counterparty_node_id: PublicKey,
		/// The channel parameters they have selected.
		opening_fee_params: OpeningFeeParams,
		/// The size of the initial payment they would like to receive.
		payment_size_msat: Option<u64>,
	},
	/// You should open a channel using [`ChannelManager::create_channel`].
	///
	/// [`ChannelManager::create_channel`]: lightning::ln::channelmanager::ChannelManager::create_channel
	OpenChannel {
		/// The node to open channel with.
		their_network_key: PublicKey,
		/// The amount to forward after fees.
		amt_to_forward_msat: u64,
		/// The fee earned for opening the channel.
		opening_fee_msat: u64,
		/// A user specified id used to track channel open.
		user_channel_id: u128,
		/// The intercept short channel id to use in the route hint.
		intercept_scid: u64,
	},
}
