// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A simple module which either re-exports [`std::time::Instant`] or a mocked version of it for
//! tests.

#[cfg(not(test))]
pub use std::time::Instant;
#[cfg(test)]
pub use test::Instant;

#[cfg(test)]
mod test {
	use core::cell::Cell;
	use core::ops::Sub;
	use core::time::Duration;

	/// Time that can be advanced manually in tests.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	pub struct Instant(Duration);

	impl Instant {
		thread_local! {
			static ELAPSED: Cell<Duration> = core::cell::Cell::new(Duration::from_secs(0));
		}

		pub fn advance(duration: Duration) {
			Self::ELAPSED.with(|elapsed| elapsed.set(elapsed.get() + duration))
		}

		pub fn now() -> Self {
			Self(Self::ELAPSED.with(|elapsed| elapsed.get()))
		}

		pub fn duration_since(&self, earlier: Self) -> Duration {
			self.0 - earlier.0
		}
	}

	impl Sub<Duration> for Instant {
		type Output = Self;

		fn sub(self, other: Duration) -> Self {
			Self(self.0 - other)
		}
	}

	#[test]
	fn time_passes_when_advanced() {
		let now = Instant::now();

		Instant::advance(Duration::from_secs(1));
		Instant::advance(Duration::from_secs(1));

		let later = Instant::now();

		assert_eq!(now.0 + Duration::from_secs(2), later.0);
	}
}
