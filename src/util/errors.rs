//! Error types live here.

use std::fmt;

/// Indicates an error on the client's part (usually some variant of attempting to use too-low or
/// too-high values)
pub enum APIError {
	/// Indicates the API was wholly misused (see err for more). Cases where these can be returned
	/// are documented, but generally indicates some precondition of a function was violated.
	APIMisuseError {
		/// A human-readable error message
		err: &'static str
	},
	/// Due to a high feerate, we were unable to complete the request.
	/// For example, this may be returned if the feerate implies we cannot open a channel at the
	/// requested value, but opening a larger channel would succeed.
	FeeRateTooHigh {
		/// A human-readable error message
		err: String,
		/// The feerate which was too high.
		feerate: u64
	},
	/// A malformed Route was provided (eg overflowed value, node id mismatch, overly-looped route,
	/// too-many-hops, etc).
	RouteError {
		/// A human-readable error message
		err: &'static str
	},
	/// We were unable to complete the request as the Channel required to do so is unable to
	/// complete the request (or was not found). This can take many forms, including disconnected
	/// peer, channel at capacity, channel shutting down, etc.
	ChannelUnavailable {
		/// A human-readable error message
		err: &'static str
	}
}

impl fmt::Debug for APIError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			APIError::APIMisuseError {ref err} => f.write_str(err),
			APIError::FeeRateTooHigh {ref err, ref feerate} => write!(f, "{} feerate: {}", err, feerate),
			APIError::RouteError {ref err} => f.write_str(err),
			APIError::ChannelUnavailable {ref err} => f.write_str(err),
		}
	}
}
