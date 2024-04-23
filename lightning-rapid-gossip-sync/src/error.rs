use core::fmt::Debug;
use core::fmt::Formatter;
use lightning::ln::msgs::{DecodeError, LightningError};

/// All-encompassing standard error type that processing can return
pub enum GraphSyncError {
	/// Error trying to read the update data, typically due to an erroneous data length indication
	/// that is greater than the actual amount of data provided
	DecodeError(DecodeError),
	/// Error applying the patch to the network graph, usually the result of updates that are too
	/// old or missing prerequisite data to the application of updates out of order
	LightningError(LightningError),
}

impl From<lightning::io::Error> for GraphSyncError {
	fn from(error: lightning::io::Error) -> Self {
		Self::DecodeError(DecodeError::Io(error.kind()))
	}
}

impl From<DecodeError> for GraphSyncError {
	fn from(error: DecodeError) -> Self {
		Self::DecodeError(error)
	}
}

impl From<LightningError> for GraphSyncError {
	fn from(error: LightningError) -> Self {
		Self::LightningError(error)
	}
}

impl Debug for GraphSyncError {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		match self {
			GraphSyncError::DecodeError(e) => f.write_fmt(format_args!("DecodeError: {:?}", e)),
			GraphSyncError::LightningError(e) => f.write_fmt(format_args!("LightningError: {:?}", e))
		}
	}
}
