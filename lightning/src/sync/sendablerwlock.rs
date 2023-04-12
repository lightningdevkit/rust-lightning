#[cfg(test)]
use super::{LockTestExt, LockHeldState};
use crate::sync::{Condvar, Mutex};

/// A write-preferring readers/writer lock whose RAII guard types are `Send`.
///
/// Unfortunately the guard types of `std::sync::RwLock` are not `Send` and therefore cannot be
/// held over `.await` boundaries in multi-threaded async runtime environments. This is in
/// particular painful in case of [`ChannelManager`]'s `total_consistency_lock` as it prohibits
/// holding the lock during [`ChannelManager::process_pending_events_async`].
///
/// This type implements a readers/writer lock that can be used as a drop-in replacement for
/// `total_consistency_lock`. In order not to unecessarily complicate the logic and avoid `unsafe`
/// code, the lock currently doesn't actually hold any data.
///
/// The implementation follows the algorithm given in
/// Buttlar, Dick, Jacqueline Farrell, and Bradford Nichols. Pthreads programming: A POSIX standard
/// for better multiprocessing. O'Reilly, 1996, pp. 86-89.
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`ChannelManager::process_pending_events_async`]: crate::ln::channelmanager::ChannelManager::process_pending_events_async
pub struct SendableRwLock {
	inner: Mutex<LockState>,
	notifier: Condvar,
}

struct LockState {
	readers_active: usize,
	writers_waiting: usize,
	writer_is_active: bool,
}

impl SendableRwLock {
	pub fn new(_: ()) -> Self {
		let inner = Mutex::new(LockState{
			readers_active: 0,
			writers_waiting: 0,
			writer_is_active: false,
		});
		let notifier = Condvar::new();
		Self { inner, notifier }
	}

	pub fn read(&self) -> Result<SendableRwLockReadGuard, ()> {
		let mut guard = self.inner.lock().map_err(|_| ())?;

		guard = self.notifier.wait_while(guard, |state| state.writers_waiting > 0 ||
			state.writer_is_active).map_err(|_| ())?;
		guard.readers_active += 1;

		Ok(SendableRwLockReadGuard::new(&self.inner, &self.notifier))
	}

	pub fn write(&self) -> Result<SendableRwLockWriteGuard, ()> {
		let mut guard = self.inner.lock().map_err(|_| ())?;
		guard.writers_waiting += 1;

		guard = self.notifier.wait_while(guard, |state| state.readers_active > 0 ||
			state.writer_is_active).map_err(|_| ())?;

		guard.writers_waiting = guard.writers_waiting.checked_sub(1)
			.expect("Read/write lock accounting is off.");

		debug_assert!(!guard.writer_is_active);
		guard.writer_is_active = true;

		Ok(SendableRwLockWriteGuard::new(&self.inner, &self.notifier))
	}

	pub fn try_write(&self) -> Result<SendableRwLockWriteGuard, ()> {
		let mut guard = self.inner.try_lock().map_err(|_| ())?;

		if guard.readers_active > 0 || guard.writer_is_active
		{
			return Err(());
		}

		debug_assert!(!guard.writer_is_active);
		guard.writer_is_active = true;

		Ok(SendableRwLockWriteGuard::new(&self.inner, &self.notifier))
	}
}

#[cfg(test)]
impl<'a> LockTestExt<'a> for SendableRwLock {
	#[inline]
	fn held_by_thread(&self) -> LockHeldState {
		match self.inner.lock() {
			Ok(guard) => {
				if guard.writer_is_active {
					LockHeldState::HeldByThread
				} else {
					LockHeldState::NotHeldByThread
				}
			}
			Err(_) => LockHeldState::HeldByThread,
		}
	}

	type ExclLock = SendableRwLockWriteGuard<'a>;

	#[inline]
	fn unsafe_well_ordered_double_lock_self(&'a self) -> SendableRwLockWriteGuard<'a> {
		self.write().unwrap()
	}
}

#[must_use]
pub struct SendableRwLockReadGuard<'a> {
	lock: &'a Mutex<LockState>,
	notifier: &'a Condvar,
}

impl<'a> SendableRwLockReadGuard<'a> {
	fn new(lock: &'a Mutex<LockState>, notifier: &'a Condvar,
	) -> Self {
		Self { lock, notifier }
	}
}

impl<'a> Drop for SendableRwLockReadGuard<'a> {
	fn drop(&mut self) {
		let notify = {
			let mut guard = self.lock.lock().unwrap();
			guard.readers_active = guard.readers_active.checked_sub(1)
				.expect("Read/write lock accounting is off.");
			guard.readers_active == 0
		};

		if notify {
			// We were the last reader.
			self.notifier.notify_all();
		}
	}
}

#[must_use]
pub struct SendableRwLockWriteGuard<'a> {
	lock: &'a Mutex<LockState>,
	notifier: &'a Condvar,
}

impl<'a> SendableRwLockWriteGuard<'a> {
	fn new(
		lock: &'a Mutex<LockState>, notifier: &'a Condvar,
	) -> Self {
		Self { lock, notifier }
	}
}

impl<'a> Drop for SendableRwLockWriteGuard<'a> {
	fn drop(&mut self) {
		{
			let mut guard = self.lock.lock().unwrap();

			debug_assert!(guard.writer_is_active);
			guard.writer_is_active = false;
		}

		self.notifier.notify_all();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sync::Arc;

	#[test]
	#[cfg(feature = "std")]
	fn writers_are_preferred() {
		use core::time::Duration;
		use std::sync::Mutex;

		#[derive(Debug, PartialEq, Eq)]
		enum AccessType {
			Read,
			Write,
		}

		let rw_lock = Arc::new(SendableRwLock::new(()));
		let results = Arc::new(Mutex::new(Vec::new()));
		let mut handles = Vec::new();

		// Take an initial write guard that acts as a barrier.
		let guard = rw_lock.write().unwrap();

		// Spawn some threads that block to get the read guard.
		for _ in 0..20 {
			let rw_lock = Arc::clone(&rw_lock);
			let results = Arc::clone(&results);
			let handle = std::thread::spawn(move || {
				let _read_guard = rw_lock.read().unwrap();
				results.lock().unwrap().push(AccessType::Read);
			});
			handles.push(handle);
		}

		// Spawn some threads that block to get the write guard.
		for _ in 0..20 {
			let rw_lock = Arc::clone(&rw_lock);
			let results = Arc::clone(&results);
			let handle = std::thread::spawn(move || {
				// Add some sleep to ensure they run slightly delayed from the reader threads.
				std::thread::sleep(Duration::from_millis(1));
				let _write_guard = rw_lock.write().unwrap();
				results.lock().unwrap().push(AccessType::Write);
			});
			handles.push(handle);
		}

		// Spawn some threads that block to get the read guard.
		for _ in 0..20 {
			let rw_lock = Arc::clone(&rw_lock);
			let results = Arc::clone(&results);
			let handle = std::thread::spawn(move || {
				// Add some sleep to ensure they run slightly delayed from the prior threads.
				std::thread::sleep(Duration::from_millis(1));
				std::thread::sleep(Duration::from_millis(1));
				let _read_guard = rw_lock.read().unwrap();
				results.lock().unwrap().push(AccessType::Read);
			});
			handles.push(handle);
		}

		// Wait a bit for all threads to come up.
		std::thread::sleep(Duration::from_secs(1));

		// Now drop the barrier, the race begins.
		drop(guard);

		for h in handles {
			h.join().unwrap();
		}

		// Assert that all writers came first, then all readers.
		let locked_results = results.lock().unwrap();

		assert_eq!(locked_results.len(), 60);

		for i in 0..locked_results.len() {
			if i < 20 {
				assert_eq!(locked_results[i], AccessType::Write);
			} else {
				assert_eq!(locked_results[i], AccessType::Read);
			}
		}
	}
}
