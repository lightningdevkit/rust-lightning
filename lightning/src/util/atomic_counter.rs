//! A simple atomic counter that uses AtomicUsize to give a u64 counter.

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!(
	"We need at least 32-bit pointers for atomic counter (and to have enough memory to run LDK)"
);

use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub(crate) struct AtomicCounter {
	// Usize needs to be at least 32 bits to avoid overflowing both low and high. If usize is 64
	// bits we will never realistically count into high:
	counter_low: AtomicUsize,
	counter_high: AtomicUsize,
}

impl AtomicCounter {
	pub(crate) fn new() -> Self {
		Self { counter_low: AtomicUsize::new(0), counter_high: AtomicUsize::new(0) }
	}
	pub(crate) fn get_increment(&self) -> u64 {
		let low = self.counter_low.fetch_add(1, Ordering::AcqRel) as u64;
		let high = if low == 0 {
			self.counter_high.fetch_add(1, Ordering::AcqRel) as u64
		} else {
			self.counter_high.load(Ordering::Acquire) as u64
		};
		(high << 32) | low
	}
}
