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
///
/// You likely don't need to use this directly, it is used automatically with
/// [`LiquidityManager::new`]
///
/// [`LiquidityManager::new`]: crate::manager::LiquidityManager::new
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
#[cfg(feature = "time")]
impl core::ops::Deref for DefaultTimeProvider {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
