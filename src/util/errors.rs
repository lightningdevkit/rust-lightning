use std::fmt;

/// Indicates an error on the client's part (usually some variant of attempting to use too-low or
/// too-high values)
pub enum APIError {
	/// Indicates the API was wholly misused (see err for more). Cases where these can be returned
	/// are documented, but generally indicates some precondition of a function was violated.
	APIMisuseError {err: &'static str},
	/// Due to a high feerate, we were unable to complete the request.
	/// For example, this may be returned if the feerate implies we cannot open a channel at the
	/// requested value, but opening a larger channel would succeed.
	FeeRateTooHigh {err: String, feerate: u64},

	/// Invalid route or parameters (cltv_delta, fee, pubkey) was specified
	RouteError {err: &'static str},
}

impl fmt::Debug for APIError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			APIError::APIMisuseError {ref err} => f.write_str(err),
			APIError::FeeRateTooHigh {ref err, ref feerate} => write!(f, "{} feerate: {}", err, feerate),
			APIError::RouteError {ref err} => f.write_str(err),
		}
	}
}
