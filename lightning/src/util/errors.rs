// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Error types live here.

use crate::ln::script::ShutdownScript;

#[allow(unused_imports)]
use crate::prelude::*;

use core::fmt;

/// Indicates an error on the client's part (usually some variant of attempting to use too-low or
/// too-high values)
#[derive(Clone, PartialEq, Eq)]
pub enum APIError {
	/// Indicates the API was wholly misused (see err for more). Cases where these can be returned
	/// are documented, but generally indicates some precondition of a function was violated.
	APIMisuseError {
		/// A human-readable error message
		err: String,
	},
	/// Due to a high feerate, we were unable to complete the request.
	/// For example, this may be returned if the feerate implies we cannot open a channel at the
	/// requested value, but opening a larger channel would succeed.
	FeeRateTooHigh {
		/// A human-readable error message
		err: String,
		/// The feerate which was too high.
		feerate: u32,
	},
	/// A malformed Route was provided (eg overflowed value, node id mismatch, overly-looped route,
	/// too-many-hops, etc).
	InvalidRoute {
		/// A human-readable error message
		err: String,
	},
	/// We were unable to complete the request as the Channel required to do so is unable to
	/// complete the request (or was not found). This can take many forms, including disconnected
	/// peer, channel at capacity, channel shutting down, etc.
	ChannelUnavailable {
		/// A human-readable error message
		err: String,
	},
	/// An attempt to call [`chain::Watch::watch_channel`]/[`chain::Watch::update_channel`]
	/// returned a [`ChannelMonitorUpdateStatus::InProgress`] indicating the persistence of a
	/// monitor update is awaiting async resolution. Once it resolves the attempted action should
	/// complete automatically.
	///
	/// [`chain::Watch::watch_channel`]: crate::chain::Watch::watch_channel
	/// [`chain::Watch::update_channel`]: crate::chain::Watch::update_channel
	/// [`ChannelMonitorUpdateStatus::InProgress`]: crate::chain::ChannelMonitorUpdateStatus::InProgress
	MonitorUpdateInProgress,
	/// [`SignerProvider::get_shutdown_scriptpubkey`] returned a shutdown scriptpubkey incompatible
	/// with the channel counterparty as negotiated in [`InitFeatures`].
	///
	/// Using a SegWit v0 script should resolve this issue. If you cannot, you won't be able to open
	/// a channel or cooperatively close one with this peer (and will have to force-close instead).
	///
	/// [`SignerProvider::get_shutdown_scriptpubkey`]: crate::sign::SignerProvider::get_shutdown_scriptpubkey
	/// [`InitFeatures`]: crate::ln::features::InitFeatures
	IncompatibleShutdownScript {
		/// The incompatible shutdown script.
		script: ShutdownScript,
	},
}

impl fmt::Debug for APIError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			APIError::APIMisuseError { ref err } => write!(f, "Misuse error: {}", err),
			APIError::FeeRateTooHigh { ref err, ref feerate } => {
				write!(f, "{} feerate: {}", err, feerate)
			},
			APIError::InvalidRoute { ref err } => write!(f, "Invalid route provided: {}", err),
			APIError::ChannelUnavailable { ref err } => write!(f, "Channel unavailable: {}", err),
			APIError::MonitorUpdateInProgress => f.write_str(
				"Client indicated a channel monitor update is in progress but not yet complete",
			),
			APIError::IncompatibleShutdownScript { ref script } => {
				write!(f, "Provided a scriptpubkey format not accepted by peer: {}", script)
			},
		}
	}
}

impl_writeable_tlv_based_enum_upgradable!(APIError,
	(0, APIMisuseError) => { (0, err, required), },
	(2, FeeRateTooHigh) => {
		(0, err, required),
		(2, feerate, required),
	},
	(4, InvalidRoute) => { (0, err, required), },
	(6, ChannelUnavailable) => { (0, err, required), },
	(8, MonitorUpdateInProgress) => {},
	(10, IncompatibleShutdownScript) => { (0, script, required), },
);

#[inline]
pub(crate) fn get_onion_debug_field(error_code: u16) -> (&'static str, usize) {
	match error_code & 0xff {
		4 | 5 | 6 => ("sha256_of_onion", 32),
		11 | 12 => ("htlc_msat", 8),
		13 | 18 => ("cltv_expiry", 4),
		19 => ("incoming_htlc_msat", 8),
		20 => ("flags", 2),
		_ => ("", 0),
	}
}

#[inline]
pub(crate) fn get_onion_error_description(error_code: u16) -> (&'static str, &'static str) {
	const BADONION: u16 = 0x8000;
	const PERM: u16 = 0x4000;
	const NODE: u16 = 0x2000;
	const UPDATE: u16 = 0x1000;
	match error_code {
		_c if _c == PERM|1 => ("The realm byte was not understood by the processing node", "invalid_realm"),
		_c if _c == NODE|2 => ("Node indicated temporary node failure", "temporary_node_failure"),
		_c if _c == PERM|NODE|2 => ("Node indicated permanent node failure", "permanent_node_failure"),
		_c if _c == PERM|NODE|3 => ("Node indicated the required node feature is missing in the onion", "required_node_feature_missing"),
		_c if _c == BADONION|PERM|4 => ("Node indicated the version by is not understood", "invalid_onion_version"),
		_c if _c == BADONION|PERM|5  => ("Node indicated the HMAC of the onion is incorrect", "invalid_onion_hmac"),
		_c if _c == BADONION|PERM|6 => ("Node indicated the ephemeral public keys is not parseable", "invalid_onion_key"),
		_c if _c == UPDATE|7 => ("Node indicated the outgoing channel is unable to handle the HTLC temporarily", "temporary_channel_failure"),
		_c if _c == PERM|8 => ("Node indicated the outgoing channel is unable to handle the HTLC peramanently", "permanent_channel_failure"),
		_c if _c == PERM|9 => ("Node indicated the required feature for the outgoing channel is not satisfied", "required_channel_feature_missing"),
		_c if _c == PERM|10 => ("Node indicated the outbound channel is not found for the specified short_channel_id in the onion packet", "unknown_next_peer"),
		_c if _c == UPDATE|11 => ("Node indicated the HTLC amount was below the required minmum for the outbound channel", "amount_below_minimum"),
		_c if _c == UPDATE|12 => ("Node indicated the fee amount does not meet the required level", "fee_insufficient"),
		_c if _c == UPDATE|13 => ("Node indicated the cltv_expiry does not comply with the cltv_expiry_delta required by the outgoing channel", "incorrect_cltv_expiry"),
		_c if _c == UPDATE|14 => ("Node indicated the CLTV expiry too close to the current block height for safe handling", "expiry_too_soon"),
		_c if _c == PERM|15 => ("The final node indicated the payment hash is unknown or amount is incorrect", "incorrect_or_unknown_payment_details"),
		_c if _c == PERM|16 => ("The final node indicated the payment amount is incorrect", "incorrect_payment_amount"),
		_c if _c == 17 => ("The final node indicated the CLTV expiry is too close to the current block height for safe handling", "final_expiry_too_soon"),
		_c if _c == 18 => ("The final node indicated the CLTV expiry in the HTLC does not match the value in the onion", "final_incorrect_cltv_expiry"),
		_c if _c == 19 => ("The final node indicated the amount in the HTLC does not match the value in the onion", "final_incorrect_htlc_amount"),
		_c if _c == UPDATE|20 => ("Node indicated the outbound channel has been disabled", "channel_disabled"),
		_c if _c == 21 => ("Node indicated the CLTV expiry in the HTLC is too far in the future", "expiry_too_far"),
		_c if _c == PERM|22 => ("Node indicated that the decrypted onion per-hop payload was not understood by it or is incomplete", "invalid_onion_payload"),
		_c if _c == 23 => ("The final node indicated the complete amount of the multi-part payment was not received within a reasonable time", "mpp_timeout"),
		_ => ("Unknown", ""),
	}
}
