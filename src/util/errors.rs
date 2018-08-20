use std::fmt;

pub enum APIError {
	APIMisuseError {err: &'static str},
	FeeRateTooHigh {err: String, feerate: u64},
}

impl APIError {
	#[inline]
	pub fn misuse(err: &'static str) -> APIError {
		APIError::APIMisuseError { err: err }
	}

	#[inline]
	pub fn feerate_too_high<E>(err: E, feerate: u64 ) -> APIError
	where
	    E: ToString,
	{
		APIError::FeeRateTooHigh { err: err.to_string(), feerate: feerate }
	}
}

impl fmt::Debug for APIError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			APIError::APIMisuseError {ref err} => f.write_str(err),
			APIError::FeeRateTooHigh {ref err, ref feerate} => write!(f, "{} feerate: {}", err, feerate)
		}
  }
}
