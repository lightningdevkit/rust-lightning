pub use ::alloc::sync::Arc;
use core::ops::{Deref, DerefMut};
use core::time::Duration;

use std::collections::HashSet;
use std::cell::RefCell;

use std::sync::atomic::{AtomicUsize, Ordering};

use std::sync::Mutex as StdMutex;
use std::sync::MutexGuard as StdMutexGuard;
use std::sync::RwLock as StdRwLock;
use std::sync::RwLockReadGuard as StdRwLockReadGuard;
use std::sync::RwLockWriteGuard as StdRwLockWriteGuard;
use std::sync::Condvar as StdCondvar;

#[cfg(feature = "backtrace")]
use backtrace::Backtrace;

pub type LockResult<Guard> = Result<Guard, ()>;

pub struct Condvar {
	inner: StdCondvar,
}

impl Condvar {
	pub fn new() -> Condvar {
		Condvar { inner: StdCondvar::new() }
	}

	pub fn wait<'a, T>(&'a self, guard: MutexGuard<'a, T>) -> LockResult<MutexGuard<'a, T>> {
		let mutex: &'a Mutex<T> = guard.mutex;
		self.inner.wait(guard.into_inner()).map(|lock| MutexGuard { mutex, lock }).map_err(|_| ())
	}

	#[allow(unused)]
	pub fn wait_timeout<'a, T>(&'a self, guard: MutexGuard<'a, T>, dur: Duration) -> LockResult<(MutexGuard<'a, T>, ())> {
		let mutex = guard.mutex;
		self.inner.wait_timeout(guard.into_inner(), dur).map(|(lock, _)| (MutexGuard { mutex, lock }, ())).map_err(|_| ())
	}

	pub fn notify_all(&self) { self.inner.notify_all(); }
}

thread_local! {
	/// We track the set of locks currently held by a reference to their `MutexMetadata`
	static MUTEXES_HELD: RefCell<HashSet<Arc<MutexMetadata>>> = RefCell::new(HashSet::new());
}
static MUTEX_IDX: AtomicUsize = AtomicUsize::new(0);

/// Metadata about a single mutex, by id, the set of things locked-before it, and the backtrace of
/// when the Mutex itself was constructed.
struct MutexMetadata {
	mutex_idx: u64,
	locked_before: StdMutex<HashSet<Arc<MutexMetadata>>>,
	#[cfg(feature = "backtrace")]
	mutex_construction_bt: Backtrace,
}
impl PartialEq for MutexMetadata {
	fn eq(&self, o: &MutexMetadata) -> bool { self.mutex_idx == o.mutex_idx }
}
impl Eq for MutexMetadata {}
impl std::hash::Hash for MutexMetadata {
	fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) { hasher.write_u64(self.mutex_idx); }
}

pub struct Mutex<T: Sized> {
	inner: StdMutex<T>,
	deps: Arc<MutexMetadata>,
}

#[must_use = "if unused the Mutex will immediately unlock"]
pub struct MutexGuard<'a, T: Sized + 'a> {
	mutex: &'a Mutex<T>,
	lock: StdMutexGuard<'a, T>,
}

impl<'a, T: Sized> MutexGuard<'a, T> {
	fn into_inner(self) -> StdMutexGuard<'a, T> {
		// Somewhat unclear why we cannot move out of self.lock, but doing so gets E0509.
		unsafe {
			let v: StdMutexGuard<'a, T> = std::ptr::read(&self.lock);
			std::mem::forget(self);
			v
		}
	}
}

impl<T: Sized> Drop for MutexGuard<'_, T> {
	fn drop(&mut self) {
		MUTEXES_HELD.with(|held| {
			held.borrow_mut().remove(&self.mutex.deps);
		});
	}
}

impl<T: Sized> Deref for MutexGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.lock.deref()
	}
}

impl<T: Sized> DerefMut for MutexGuard<'_, T> {
	fn deref_mut(&mut self) -> &mut T {
		self.lock.deref_mut()
	}
}

impl<T> Mutex<T> {
	pub fn new(inner: T) -> Mutex<T> {
		Mutex {
			inner: StdMutex::new(inner),
			deps: Arc::new(MutexMetadata {
				locked_before: StdMutex::new(HashSet::new()),
				mutex_idx: MUTEX_IDX.fetch_add(1, Ordering::Relaxed) as u64,
				#[cfg(feature = "backtrace")]
				mutex_construction_bt: Backtrace::new(),
			}),
		}
	}

	pub fn lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
		MUTEXES_HELD.with(|held| {
			// For each mutex which is currently locked, check that no mutex's locked-before
			// set includes the mutex we're about to lock, which would imply a lockorder
			// inversion.
			for locked in held.borrow().iter() {
				for locked_dep in locked.locked_before.lock().unwrap().iter() {
					if *locked_dep == self.deps {
						#[cfg(feature = "backtrace")]
						panic!("Tried to violate existing lockorder.\nMutex that should be locked after the current lock was created at the following backtrace.\nNote that to get a backtrace for the lockorder violation, you should set RUST_BACKTRACE=1\n{:?}", locked.mutex_construction_bt);
						#[cfg(not(feature = "backtrace"))]
						panic!("Tried to violate existing lockorder. Build with the backtrace feature for more info.");
					}
				}
				// Insert any already-held mutexes in our locked-before set.
				self.deps.locked_before.lock().unwrap().insert(Arc::clone(locked));
			}
			held.borrow_mut().insert(Arc::clone(&self.deps));
		});
		self.inner.lock().map(|lock| MutexGuard { mutex: self, lock }).map_err(|_| ())
	}

	pub fn try_lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
		let res = self.inner.try_lock().map(|lock| MutexGuard { mutex: self, lock }).map_err(|_| ());
		if res.is_ok() {
			MUTEXES_HELD.with(|held| {
				// Since a try-lock will simply fail if the lock is held already, we do not
				// consider try-locks to ever generate lockorder inversions. However, if a try-lock
				// succeeds, we do consider it to have created lockorder dependencies.
				for locked in held.borrow().iter() {
					self.deps.locked_before.lock().unwrap().insert(Arc::clone(locked));
				}
				held.borrow_mut().insert(Arc::clone(&self.deps));
			});
		}
		res
	}
}

pub struct RwLock<T: ?Sized> {
	inner: StdRwLock<T>
}

pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
	lock: StdRwLockReadGuard<'a, T>,
}

pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
	lock: StdRwLockWriteGuard<'a, T>,
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.lock.deref()
	}
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.lock.deref()
	}
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
	fn deref_mut(&mut self) -> &mut T {
		self.lock.deref_mut()
	}
}

impl<T> RwLock<T> {
	pub fn new(inner: T) -> RwLock<T> {
		RwLock { inner: StdRwLock::new(inner) }
	}

	pub fn read<'a>(&'a self) -> LockResult<RwLockReadGuard<'a, T>> {
		self.inner.read().map(|lock| RwLockReadGuard { lock }).map_err(|_| ())
	}

	pub fn write<'a>(&'a self) -> LockResult<RwLockWriteGuard<'a, T>> {
		self.inner.write().map(|lock| RwLockWriteGuard { lock }).map_err(|_| ())
	}

	pub fn try_write<'a>(&'a self) -> LockResult<RwLockWriteGuard<'a, T>> {
		self.inner.try_write().map(|lock| RwLockWriteGuard { lock }).map_err(|_| ())
	}
}
