// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! [`Time`] trait and different implementations. Currently, it's mainly used in tests so we can
//! manually advance time.
//! Other crates may symlink this file to use it while [`Time`] trait is sealed here.

use core::ops::Sub;
use core::time::Duration;

/// A measurement of time.
pub trait Time: Copy + Sub<Duration, Output = Self> where Self: Sized {
	/// Returns an instance corresponding to the current moment.
	fn now() -> Self;

	/// Returns the amount of time elapsed since `self` was created.
	fn elapsed(&self) -> Duration;

	/// Returns the amount of time passed between `earlier` and `self`.
	fn duration_since(&self, earlier: Self) -> Duration;

	/// Returns the amount of time passed since the beginning of [`Time`].
	///
	/// Used during (de-)serialization.
	fn duration_since_epoch() -> Duration;
}

/// A state in which time has no meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eternity;

impl Time for Eternity {
	fn now() -> Self {
		Self
	}

	fn duration_since(&self, _earlier: Self) -> Duration {
		Duration::from_secs(0)
	}

	fn duration_since_epoch() -> Duration {
		Duration::from_secs(0)
	}

	fn elapsed(&self) -> Duration {
		Duration::from_secs(0)
	}
}

impl Sub<Duration> for Eternity {
	type Output = Self;

	fn sub(self, _other: Duration) -> Self {
		self
	}
}

#[cfg(not(feature = "no-std"))]
impl Time for std::time::Instant {
	fn now() -> Self {
		std::time::Instant::now()
	}

	fn duration_since(&self, earlier: Self) -> Duration {
		// On rust prior to 1.60 `Instant::duration_since` will panic if time goes backwards.
		// However, we support rust versions prior to 1.60 and some users appear to have "monotonic
		// clocks" that go backwards in practice (likely relatively ancient kernels/etc). Thus, we
		// manually check for time going backwards here and return a duration of zero in that case.
		let now = Self::now();
		if now > earlier { now - earlier } else { Duration::from_secs(0) }
	}

	fn duration_since_epoch() -> Duration {
		use std::time::SystemTime;
		SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()
	}
	fn elapsed(&self) -> Duration {
		std::time::Instant::elapsed(self)
	}
}

#[cfg(test)]
pub mod tests {
	use super::{Time, Eternity};

	use core::time::Duration;
	use core::ops::Sub;
	use core::cell::Cell;

	/// Time that can be advanced manually in tests.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	pub struct SinceEpoch(Duration);

	impl SinceEpoch {
		thread_local! {
			static ELAPSED: Cell<Duration> = core::cell::Cell::new(Duration::from_secs(0));
		}

		pub fn advance(duration: Duration) {
			Self::ELAPSED.with(|elapsed| elapsed.set(elapsed.get() + duration))
		}
	}

	impl Time for SinceEpoch {
		fn now() -> Self {
			Self(Self::duration_since_epoch())
		}

		fn duration_since(&self, earlier: Self) -> Duration {
			self.0 - earlier.0
		}

		fn duration_since_epoch() -> Duration {
			Self::ELAPSED.with(|elapsed| elapsed.get())
		}

		fn elapsed(&self) -> Duration {
			Self::duration_since_epoch() - self.0
		}
	}

	impl Sub<Duration> for SinceEpoch {
		type Output = Self;

		fn sub(self, other: Duration) -> Self {
			Self(self.0 - other)
		}
	}

	#[test]
	fn time_passes_when_advanced() {
		let now = SinceEpoch::now();
		assert_eq!(now.elapsed(), Duration::from_secs(0));

		SinceEpoch::advance(Duration::from_secs(1));
		SinceEpoch::advance(Duration::from_secs(1));

		let elapsed = now.elapsed();
		let later = SinceEpoch::now();

		assert_eq!(elapsed, Duration::from_secs(2));
		assert_eq!(later - elapsed, now);
	}

	#[test]
	fn time_never_passes_in_an_eternity() {
		let now = Eternity::now();
		let elapsed = now.elapsed();
		let later = Eternity::now();

		assert_eq!(now.elapsed(), Duration::from_secs(0));
		assert_eq!(later - elapsed, now);
	}
}
