use super::{LockHeldState, LockTestExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LockResult, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockResult};

/// Rust libstd's RwLock does not provide any fairness guarantees (and, in fact, when used on
/// Linux with pthreads under the hood, readers trivially and completely starve writers).
/// Because we often hold read locks while doing message processing in multiple threads which
/// can use significant CPU time, with write locks being time-sensitive but relatively small in
/// CPU time, we can end up with starvation completely blocking incoming connections or pings,
/// especially during initial graph sync.
///
/// Thus, we need to block readers when a writer is pending, which we do with a trivial RwLock
/// wrapper here. Its not particularly optimized, but provides some reasonable fairness by
/// blocking readers (by taking the write lock) if there are writers pending when we go to take
/// a read lock.
pub struct FairRwLock<T> {
	lock: RwLock<T>,
	waiting_writers: AtomicUsize,
}

impl<T> FairRwLock<T> {
	pub fn new(t: T) -> Self {
		Self { lock: RwLock::new(t), waiting_writers: AtomicUsize::new(0) }
	}

	// Note that all atomic accesses are relaxed, as we do not rely on the atomics here for any
	// ordering at all, instead relying on the underlying RwLock to provide ordering of unrelated
	// memory.
	pub fn write(&self) -> LockResult<RwLockWriteGuard<T>> {
		self.waiting_writers.fetch_add(1, Ordering::Relaxed);
		let res = self.lock.write();
		self.waiting_writers.fetch_sub(1, Ordering::Relaxed);
		res
	}

	pub fn read(&self) -> LockResult<RwLockReadGuard<T>> {
		if self.waiting_writers.load(Ordering::Relaxed) != 0 {
			let _write_queue_lock = self.lock.write();
		}
		// Note that we don't consider ensuring that an underlying RwLock allowing writers to
		// starve readers doesn't exhibit the same behavior here. I'm not aware of any
		// libstd-backing RwLock which exhibits this behavior, and as documented in the
		// struct-level documentation, it shouldn't pose a significant issue for our current
		// codebase.
		self.lock.read()
	}

	#[allow(dead_code)]
	pub fn try_write(&self) -> TryLockResult<RwLockWriteGuard<'_, T>> {
		self.lock.try_write()
	}
}

impl<'a, T: 'a> LockTestExt<'a> for FairRwLock<T> {
	#[inline]
	fn held_by_thread(&self) -> LockHeldState {
		// fairrwlock is only built in non-test modes, so we should never support tests.
		LockHeldState::Unsupported
	}
	type ExclLock = RwLockWriteGuard<'a, T>;
	#[inline]
	fn unsafe_well_ordered_double_lock_self(&'a self) -> RwLockWriteGuard<'a, T> {
		self.write().unwrap()
	}
}
