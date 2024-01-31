#[allow(dead_code)] // Depending on the compilation flags some variants are never used
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LockHeldState {
	HeldByThread,
	NotHeldByThread,
	#[cfg(any(ldk_bench, not(test)))]
	Unsupported,
}

pub(crate) trait LockTestExt<'a> {
	fn held_by_thread(&self) -> LockHeldState;
	type ExclLock;
	/// If two instances of the same mutex are being taken at the same time, it's very easy to have
	/// a lockorder inversion and risk deadlock. Thus, we default to disabling such locks.
	///
	/// However, sometimes they cannot be avoided. In such cases, this method exists to take a
	/// mutex while avoiding a test failure. It is deliberately verbose and includes the term
	/// "unsafe" to indicate that special care needs to be taken to ensure no deadlocks are
	/// possible.
	fn unsafe_well_ordered_double_lock_self(&'a self) -> Self::ExclLock;
}

#[cfg(all(feature = "std", not(ldk_bench), test))]
mod debug_sync;
#[cfg(all(feature = "std", not(ldk_bench), test))]
pub use debug_sync::*;
#[cfg(all(feature = "std", not(ldk_bench), test))]
// Note that to make debug_sync's regex work this must not contain `debug_string` in the module name
mod test_lockorder_checks;

#[cfg(all(feature = "std", any(ldk_bench, not(test))))]
pub(crate) mod fairrwlock;
#[cfg(all(feature = "std", any(ldk_bench, not(test))))]
pub use {
	fairrwlock::FairRwLock,
	std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

#[cfg(all(feature = "std", any(ldk_bench, not(test))))]
mod ext_impl {
	use super::*;
	impl<'a, T: 'a> LockTestExt<'a> for Mutex<T> {
		#[inline]
		fn held_by_thread(&self) -> LockHeldState {
			LockHeldState::Unsupported
		}
		type ExclLock = MutexGuard<'a, T>;
		#[inline]
		fn unsafe_well_ordered_double_lock_self(&'a self) -> MutexGuard<T> {
			self.lock().unwrap()
		}
	}
	impl<'a, T: 'a> LockTestExt<'a> for RwLock<T> {
		#[inline]
		fn held_by_thread(&self) -> LockHeldState {
			LockHeldState::Unsupported
		}
		type ExclLock = RwLockWriteGuard<'a, T>;
		#[inline]
		fn unsafe_well_ordered_double_lock_self(&'a self) -> RwLockWriteGuard<T> {
			self.write().unwrap()
		}
	}
}

#[cfg(not(feature = "std"))]
mod nostd_sync;
#[cfg(not(feature = "std"))]
pub use nostd_sync::*;
