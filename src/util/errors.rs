use std::fmt;

pub enum APIError {
	APIMisuseError {err: &'static str},
	FeeRateTooHigh {err: String, feerate: u64},
}

impl fmt::Debug for APIError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			APIError::APIMisuseError {ref err} => f.write_str(err),
			APIError::FeeRateTooHigh {ref err, ref feerate} => write!(f, "{} feerate: {}", err, feerate)
		}
  }
}
