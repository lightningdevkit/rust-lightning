use std::fmt;

#[derive(Debug)]
/// An error that possibly needs to be handled by the user.
pub enum TxSyncError {
	/// A transaction sync failed and needs to be retried eventually.
	Failed,
}

impl std::error::Error for TxSyncError {}

impl fmt::Display for TxSyncError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Self::Failed => write!(f, "Failed to conduct transaction sync."),
		}
	}
}

#[derive(Debug)]
pub(crate) enum InternalError {
	/// A transaction sync failed and needs to be retried eventually.
	Failed,
	/// An inconsistency was encountered during transaction sync.
	Inconsistency,
}

impl fmt::Display for InternalError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Self::Failed => write!(f, "Failed to conduct transaction sync."),
			Self::Inconsistency => {
				write!(f, "Encountered an inconsistency during transaction sync.")
			},
		}
	}
}

impl std::error::Error for InternalError {}

impl From<InternalError> for TxSyncError {
	fn from(_e: InternalError) -> Self {
		Self::Failed
	}
}

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
impl From<esplora_client::Error> for TxSyncError {
	fn from(_e: esplora_client::Error) -> Self {
		Self::Failed
	}
}

#[cfg(any(feature = "esplora-blocking", feature = "esplora-async"))]
impl From<esplora_client::Error> for InternalError {
	fn from(_e: esplora_client::Error) -> Self {
		Self::Failed
	}
}

#[cfg(feature = "electrum")]
impl From<electrum_client::Error> for InternalError {
	fn from(_e: electrum_client::Error) -> Self {
		Self::Failed
	}
}

#[cfg(feature = "electrum")]
impl From<electrum_client::Error> for TxSyncError {
	fn from(_e: electrum_client::Error) -> Self {
		Self::Failed
	}
}
