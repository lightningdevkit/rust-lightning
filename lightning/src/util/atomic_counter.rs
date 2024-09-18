//! A simple atomic counter that uses mutexes if the platform doesn't support atomic u64s.

#[cfg(not(target_has_atomic = "64"))]
use crate::sync::Mutex;
#[cfg(target_has_atomic = "64")]
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct AtomicCounter {
	#[cfg(target_has_atomic = "64")]
	counter: AtomicU64,
	#[cfg(not(target_has_atomic = "64"))]
	counter: Mutex<u64>,
}

impl AtomicCounter {
	pub(crate) fn new() -> Self {
		Self {
			#[cfg(target_has_atomic = "64")]
			counter: AtomicU64::new(0),
			#[cfg(not(target_has_atomic = "64"))]
			counter: Mutex::new(0),
		}
	}
	pub(crate) fn next(&self) -> u64 {
		#[cfg(target_has_atomic = "64")]
		{
			self.counter.fetch_add(1, Ordering::AcqRel)
		}
		#[cfg(not(target_has_atomic = "64"))]
		{
			let mut mtx = self.counter.lock().unwrap();
			*mtx += 1;
			*mtx - 1
		}
	}
	#[cfg(test)]
	pub(crate) fn set_counter(&self, count: u64) {
		#[cfg(target_has_atomic = "64")]
		{
			self.counter.store(count, Ordering::Release);
		}
		#[cfg(not(target_has_atomic = "64"))]
		{
			let mut mtx = self.counter.lock().unwrap();
			*mtx = count;
		}
	}
}
