// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities which allow users to block on some future notification from LDK. These are
//! specifically used by [`ChannelManager`] to allow waiting until the [`ChannelManager`] needs to
//! be re-persisted.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager

use core::mem;
use core::time::Duration;
use sync::{Condvar, Mutex};

#[cfg(any(test, feature = "std"))]
use std::time::Instant;

/// Used to signal to the ChannelManager persister that the manager needs to be re-persisted to
/// disk/backups, through `await_persistable_update_timeout` and `await_persistable_update`.
pub(crate) struct PersistenceNotifier {
	/// Users won't access the persistence_lock directly, but rather wait on its bool using
	/// `wait_timeout` and `wait`.
	persistence_lock: (Mutex<bool>, Condvar),
}

impl PersistenceNotifier {
	pub(crate) fn new() -> Self {
		Self {
			persistence_lock: (Mutex::new(false), Condvar::new()),
		}
	}

	pub(crate) fn wait(&self) {
		loop {
			let &(ref mtx, ref cvar) = &self.persistence_lock;
			let mut guard = mtx.lock().unwrap();
			if *guard {
				*guard = false;
				return;
			}
			guard = cvar.wait(guard).unwrap();
			let result = *guard;
			if result {
				*guard = false;
				return
			}
		}
	}

	#[cfg(any(test, feature = "std"))]
	pub(crate) fn wait_timeout(&self, max_wait: Duration) -> bool {
		let current_time = Instant::now();
		loop {
			let &(ref mtx, ref cvar) = &self.persistence_lock;
			let mut guard = mtx.lock().unwrap();
			if *guard {
				*guard = false;
				return true;
			}
			guard = cvar.wait_timeout(guard, max_wait).unwrap().0;
			// Due to spurious wakeups that can happen on `wait_timeout`, here we need to check if the
			// desired wait time has actually passed, and if not then restart the loop with a reduced wait
			// time. Note that this logic can be highly simplified through the use of
			// `Condvar::wait_while` and `Condvar::wait_timeout_while`, if and when our MSRV is raised to
			// 1.42.0.
			let elapsed = current_time.elapsed();
			let result = *guard;
			if result || elapsed >= max_wait {
				*guard = false;
				return result;
			}
			match max_wait.checked_sub(elapsed) {
				None => return result,
				Some(_) => continue
			}
		}
	}

	/// Wake waiters, tracking that persistence needs to occur.
	pub(crate) fn notify(&self) {
		let &(ref persist_mtx, ref cnd) = &self.persistence_lock;
		let mut persistence_lock = persist_mtx.lock().unwrap();
		*persistence_lock = true;
		mem::drop(persistence_lock);
		cnd.notify_all();
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn needs_persist(&self) -> bool {
		let &(ref mtx, _) = &self.persistence_lock;
		let guard = mtx.lock().unwrap();
		*guard
	}
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "std")]
	#[test]
	fn test_wait_timeout() {
		use super::*;
		use sync::Arc;
		use core::sync::atomic::{AtomicBool, Ordering};
		use std::thread;

		let persistence_notifier = Arc::new(PersistenceNotifier::new());
		let thread_notifier = Arc::clone(&persistence_notifier);

		let exit_thread = Arc::new(AtomicBool::new(false));
		let exit_thread_clone = exit_thread.clone();
		thread::spawn(move || {
			loop {
				let &(ref persist_mtx, ref cnd) = &thread_notifier.persistence_lock;
				let mut persistence_lock = persist_mtx.lock().unwrap();
				*persistence_lock = true;
				cnd.notify_all();

				if exit_thread_clone.load(Ordering::SeqCst) {
					break
				}
			}
		});

		// Check that we can block indefinitely until updates are available.
		let _ = persistence_notifier.wait();

		// Check that the PersistenceNotifier will return after the given duration if updates are
		// available.
		loop {
			if persistence_notifier.wait_timeout(Duration::from_millis(100)) {
				break
			}
		}

		exit_thread.store(true, Ordering::SeqCst);

		// Check that the PersistenceNotifier will return after the given duration even if no updates
		// are available.
		loop {
			if !persistence_notifier.wait_timeout(Duration::from_millis(100)) {
				break
			}
		}
	}
}
