//! Utilities for time handling in LSPS5 service.

use core::time::Duration;

/// Trait defining a time provider for LSPS5 service.
///
/// This trait is used to provide the current time for LSPS5 service operations
/// and to convert between timestamps and durations.
pub trait TimeProvider {
	/// Get the current time as a duration since the Unix epoch.
	fn duration_since_epoch(&self) -> Duration;
}

/// Default time provider using the system clock.
#[derive(Clone, Debug)]
#[cfg(feature = "time")]
pub struct DefaultTimeProvider;

#[cfg(feature = "time")]
impl TimeProvider for DefaultTimeProvider {
	fn duration_since_epoch(&self) -> Duration {
		use std::time::{SystemTime, UNIX_EPOCH};
		SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before Unix epoch")
	}
}
