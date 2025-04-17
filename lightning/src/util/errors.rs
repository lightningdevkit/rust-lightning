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
	/// [`InitFeatures`]: crate::types::features::InitFeatures
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
