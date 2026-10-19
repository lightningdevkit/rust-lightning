// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains bLIP-52 / LSPS2 event types

use super::msgs::LSPS2OpeningFeeParams;
use crate::lsps0::ser::{LSPSRequestId, LSPSResponseError};
use alloc::string::String;
use alloc::vec::Vec;

use bitcoin::secp256k1::PublicKey;

use lightning::impl_ser_tlv_based_enum;

/// An event which an LSPS2 client should take some action in response to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS2ClientEvent {
	/// Information from the LSP about their current fee rates and channel parameters.
	///
	/// You must call [`LSPS2ClientHandler::select_opening_params`] with the fee parameter
	/// you want to use if you wish to proceed opening a channel.
	///
	/// **Note: ** This event will *not* be persisted across restarts.
	///
	/// [`LSPS2ClientHandler::select_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::select_opening_params
	OpeningParametersReady {
		/// The identifier of the issued bLIP-52 / LSPS2 `get_info` request, as returned by
		/// [`LSPS2ClientHandler::request_opening_params`]
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS2ClientHandler::request_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::request_opening_params
		request_id: LSPSRequestId,
		/// The node id of the LSP that provided this response.
		counterparty_node_id: PublicKey,
		/// The menu of fee parameters the LSP is offering at this time.
		/// You must select one of these if you wish to proceed.
		opening_fee_params_menu: Vec<LSPS2OpeningFeeParams>,
	},
	/// Provides the necessary information to generate a payable invoice that then may be given to
	/// the payer.
	///
	/// When the invoice is paid, the LSP will open a channel with the previously agreed upon
	/// parameters to you.
	///
	/// **Note: ** This event will *not* be persisted across restarts.
	InvoiceParametersReady {
		/// The identifier of the issued bLIP-52 / LSPS2 `buy` request, as returned by
		/// [`LSPS2ClientHandler::select_opening_params`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS2ClientHandler::select_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::select_opening_params
		request_id: LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The intercept short channel id to use in the route hint.
		intercept_scid: u64,
		/// The `cltv_expiry_delta` to use in the route hint.
		cltv_expiry_delta: u32,
		/// The initial payment size you specified.
		payment_size_msat: Option<u64>,
	},
	/// A request previously issued via [`LSPS2ClientHandler::request_opening_params`]
	/// failed as the LSP returned an error response.
	///
	/// **Note: ** This event will *not* be persisted across restarts.
	///
	/// [`LSPS2ClientHandler::request_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::request_opening_params
	GetInfoFailed {
		/// The identifier of the issued LSPS2 `get_info` request, as returned by
		/// [`LSPS2ClientHandler::request_opening_params`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS2ClientHandler::request_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::request_opening_params
		request_id: LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The error that was returned.
		error: LSPSResponseError,
	},
	/// A request previously issued via [`LSPS2ClientHandler::select_opening_params`]
	/// failed as the LSP returned an error response.
	///
	/// **Note: ** This event will *not* be persisted across restarts.
	///
	/// [`LSPS2ClientHandler::select_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::select_opening_params
	BuyRequestFailed {
		/// The identifier of the issued LSPS2 `buy` request, as returned by
		/// [`LSPS2ClientHandler::select_opening_params`].
		///
		/// This can be used to track which request this event corresponds to.
		///
		/// [`LSPS2ClientHandler::select_opening_params`]: crate::lsps2::client::LSPS2ClientHandler::select_opening_params
		request_id: LSPSRequestId,
		/// The node id of the LSP.
		counterparty_node_id: PublicKey,
		/// The error that was returned.
		error: LSPSResponseError,
	},
}

/// An event which an bLIP-52 / LSPS2 server should take some action in response to.
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
	/// **Note: ** This event will *not* be persisted across restarts.
	///
	/// [`LSPS2ServiceHandler::opening_fee_params_generated`]: crate::lsps2::service::LSPS2ServiceHandler::opening_fee_params_generated
	/// [`LSPS2ServiceHandler::invalid_token_provided`]: crate::lsps2::service::LSPS2ServiceHandler::invalid_token_provided
	GetInfo {
		/// An identifier that must be passed to [`LSPS2ServiceHandler::opening_fee_params_generated`].
		///
		/// [`LSPS2ServiceHandler::opening_fee_params_generated`]: crate::lsps2::service::LSPS2ServiceHandler::opening_fee_params_generated
		request_id: LSPSRequestId,
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
	/// You must generate a `cltv_expiry_delta` and obtain an intercept scid using
	/// [`ChannelManager::get_intercept_scid`] for them to use and then call
	/// [`LSPS2ServiceHandler::invoice_parameters_generated`].
	///
	/// **Note: ** This event will *not* be persisted across restarts.
	///
	/// [`ChannelManager::get_intercept_scid`]: lightning::ln::channelmanager::ChannelManager::get_intercept_scid
	///
	/// [`LSPS2ServiceHandler::invoice_parameters_generated`]: crate::lsps2::service::LSPS2ServiceHandler::invoice_parameters_generated
	BuyRequest {
		/// An identifier that must be passed into [`LSPS2ServiceHandler::invoice_parameters_generated`].
		///
		/// [`LSPS2ServiceHandler::invoice_parameters_generated`]: crate::lsps2::service::LSPS2ServiceHandler::invoice_parameters_generated
		request_id: LSPSRequestId,
		/// The client node id that is making this request.
		counterparty_node_id: PublicKey,
		/// The channel parameters they have selected.
		opening_fee_params: LSPS2OpeningFeeParams,
		/// The size of the initial payment they would like to receive.
		payment_size_msat: Option<u64>,
	},
	/// You should open a channel using [`ChannelManager::create_channel`].
	///
	/// You must ensure the client's `to_self_delay` does not exceed the maximum agreed upon in
	/// the selected opening fee parameters. To do so, set
	/// `override_config.channel_handshake_limits.their_to_self_delay` to the minimum of
	/// `max_client_to_self_delay` and any stricter limit of your own (in `u32` arithmetic to
	/// avoid truncation) before calling [`ChannelManager::create_channel`].
	///
	/// **Note: ** As this event is persisted and might get replayed after restart, you'll need to
	/// ensure channel creation idempotency. I.e., please check if you already created a
	/// corresponding channel based on the given `their_network_key` and `user_channel_id` and
	/// ignore this event in case you did.
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
		/// The maximum number of blocks the client is allowed to set its `to_self_delay`
		/// parameter to, as agreed upon in the selected opening fee parameters.
		///
		/// This is [`Option::None`] for events that were persisted before this field was
		/// introduced. For such events, recover the agreed-upon limit from the corresponding
		/// persisted JIT channel state if possible, or apply an explicit conservative limit of
		/// your own (or fail the channel open). Do not fall back to a default such as 2016, as
		/// that may exceed what was actually negotiated with the client.
		max_client_to_self_delay: Option<u32>,
	},
}

impl_ser_tlv_based_enum!(LSPS2ServiceEvent,
	(0, GetInfo) => {
		(0, request_id, required),
		(2, counterparty_node_id, required),
		(4, token, option),
	},
	(2, BuyRequest) => {
		(0, request_id, required),
		(2, counterparty_node_id, required),
		(4, opening_fee_params, required),
		(6, payment_size_msat, option),
	},
	(4, OpenChannel) => {
		(0, their_network_key, required),
		(2, amt_to_forward_msat, required),
		(4, opening_fee_msat, required),
		(6, user_channel_id, required),
		(8, intercept_scid, required),
		(9, max_client_to_self_delay, option),
	}
);

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::secp256k1::Secp256k1;
	use lightning::io::Cursor;
	use lightning::util::ser::{BigSize, Readable, Writeable};

	fn sample_open_channel(max_client_to_self_delay: Option<u32>) -> LSPS2ServiceEvent {
		let secp = Secp256k1::new();
		let mut key_bytes = [2u8; 32];
		key_bytes[31] = 1;
		let key = bitcoin::secp256k1::PublicKey::from_secret_key(
			&secp,
			&bitcoin::secp256k1::SecretKey::from_slice(&key_bytes).unwrap(),
		);
		LSPS2ServiceEvent::OpenChannel {
			their_network_key: key,
			amt_to_forward_msat: 90_000_000,
			opening_fee_msat: 10_000_000,
			user_channel_id: 42,
			intercept_scid: 0x0f9f_9f9f_9f9f_9f9f,
			max_client_to_self_delay,
		}
	}

	#[test]
	fn open_channel_event_round_trips_with_negotiated_limit() {
		let event = sample_open_channel(Some(128));
		let encoded = event.encode();
		assert_eq!(
			<LSPS2ServiceEvent as Readable>::read(&mut Cursor::new(&encoded)).unwrap(),
			event
		);
	}

	#[test]
	fn open_channel_event_round_trips_without_negotiated_limit() {
		let event = sample_open_channel(None);
		let encoded = event.encode();
		assert_eq!(
			<LSPS2ServiceEvent as Readable>::read(&mut Cursor::new(&encoded)).unwrap(),
			event
		);
	}

	// Events persisted by versions that did not serialize the negotiated limit carry no TLV
	// field 9 and must still decode, with the limit left as `None`.
	#[test]
	fn open_channel_event_without_negotiated_limit_field_decodes() {
		// Encoded as an `OpenChannel` event with `max_client_to_self_delay: None`, i.e., the
		// format written before the field existed: variant id 4 followed by the required TLV
		// fields 0, 2, 4, 6 and 8 only.
		let old_encoded: Vec<u8> = vec![
			4, 83, 0, 33, 3, 188, 1, 30, 108, 181, 21, 89, 67, 199, 54, 91, 241, 238, 234, 158, 47,
			11, 110, 198, 134, 142, 212, 185, 130, 49, 160, 188, 66, 237, 158, 148, 11, 2, 8, 0, 0,
			0, 0, 5, 93, 74, 128, 4, 8, 0, 0, 0, 0, 0, 152, 150, 128, 6, 16, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 42, 8, 8, 15, 159, 159, 159, 159, 159, 159, 159,
		];
		let decoded =
			<LSPS2ServiceEvent as Readable>::read(&mut Cursor::new(&old_encoded)).unwrap();
		assert_eq!(decoded, sample_open_channel(None));
	}

	// Readers of the old schema do not know TLV field 9; they skip it as an unknown odd field
	// and remain compatible, though they do not acquire enforcement of the limit.
	#[test]
	fn open_channel_event_unknown_odd_field_is_skipped() {
		let mut encoded = sample_open_channel(None).encode();
		// Append an unknown odd field (type 11, length 4) to the TLV stream, before the
		// length prefix. Rebuild the stream with the extra field and an updated length.
		let mut stream = encoded[2..].to_vec();
		stream.extend_from_slice(&[11, 4, 1, 2, 3, 4]);
		let mut new_encoded = vec![encoded[0]];
		BigSize(stream.len() as u64).write(&mut new_encoded).unwrap();
		new_encoded.extend_from_slice(&stream);
		encoded = new_encoded;

		let decoded = <LSPS2ServiceEvent as Readable>::read(&mut Cursor::new(&encoded)).unwrap();
		assert_eq!(decoded, sample_open_channel(None));
	}
}
