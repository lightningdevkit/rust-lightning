#[allow(dead_code)] // Depending on the compilation flags some variants are never used
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LockHeldState {
	HeldByThread,
	NotHeldByThread,
	#[cfg(any(feature = "_bench_unstable", not(test)))]
	Unsupported,
}

pub(crate) trait LockTestExt {
	fn held_by_thread(&self) -> LockHeldState;
}

#[cfg(all(feature = "std", not(feature = "_bench_unstable"), test))]
mod debug_sync;
#[cfg(all(feature = "std", not(feature = "_bench_unstable"), test))]
pub use debug_sync::*;
#[cfg(all(feature = "std", not(feature = "_bench_unstable"), test))]
// Note that to make debug_sync's regex work this must not contain `debug_string` in the module name
mod test_lockorder_checks;

#[cfg(all(feature = "std", any(feature = "_bench_unstable", not(test))))]
pub(crate) mod fairrwlock;
#[cfg(all(feature = "std", any(feature = "_bench_unstable", not(test))))]
pub use {std::sync::{Arc, Mutex, Condvar, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard}, fairrwlock::FairRwLock};

#[cfg(all(feature = "std", any(feature = "_bench_unstable", not(test))))]
mod ext_impl {
	use super::*;
	impl<T> LockTestExt for Mutex<T> {
		#[inline]
		fn held_by_thread(&self) -> LockHeldState { LockHeldState::Unsupported }
	}
	impl<T> LockTestExt for RwLock<T> {
		#[inline]
		fn held_by_thread(&self) -> LockHeldState { LockHeldState::Unsupported }
	}
}

#[cfg(not(feature = "std"))]
mod nostd_sync;
#[cfg(not(feature = "std"))]
pub use nostd_sync::*;
