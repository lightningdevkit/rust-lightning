pub use ::alloc::sync::Arc;
use core::ops::{Deref, DerefMut};
use core::time::Duration;

use std::cell::RefCell;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex as StdMutex;
use std::sync::MutexGuard as StdMutexGuard;
use std::sync::RwLock as StdRwLock;
use std::sync::RwLockReadGuard as StdRwLockReadGuard;
use std::sync::RwLockWriteGuard as StdRwLockWriteGuard;
use std::sync::Condvar as StdCondvar;

use prelude::HashMap;

#[cfg(feature = "backtrace")]
use {prelude::hash_map, backtrace::Backtrace, std::sync::Once};

#[cfg(not(feature = "backtrace"))]
struct Backtrace{}
#[cfg(not(feature = "backtrace"))]
impl Backtrace { fn new() -> Backtrace { Backtrace {} } }

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
	/// We track the set of locks currently held by a reference to their `LockMetadata`
	static LOCKS_HELD: RefCell<HashMap<u64, Arc<LockMetadata>>> = RefCell::new(HashMap::new());
}
static LOCK_IDX: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "backtrace")]
static mut LOCKS: Option<StdMutex<HashMap<String, Arc<LockMetadata>>>> = None;
#[cfg(feature = "backtrace")]
static LOCKS_INIT: Once = Once::new();

/// Metadata about a single lock, by id, the set of things locked-before it, and the backtrace of
/// when the Mutex itself was constructed.
struct LockMetadata {
	lock_idx: u64,
	locked_before: StdMutex<HashMap<u64, LockDep>>,
	_lock_construction_bt: Backtrace,
}

struct LockDep {
	lock: Arc<LockMetadata>,
	/// lockdep_trace is unused unless we're building with `backtrace`, so we mark it _
	_lockdep_trace: Backtrace,
}

#[cfg(feature = "backtrace")]
fn get_construction_location(backtrace: &Backtrace) -> String {
	// Find the first frame that is after `debug_sync` (or that is in our tests) and use
	// that as the mutex construction site. Note that the first few frames may be in
	// the `backtrace` crate, so we have to ignore those.
	let sync_mutex_constr_regex = regex::Regex::new(r"lightning.*debug_sync.*new").unwrap();
	let mut found_debug_sync = false;
	for frame in backtrace.frames() {
		for symbol in frame.symbols() {
			let symbol_name = symbol.name().unwrap().as_str().unwrap();
			if !sync_mutex_constr_regex.is_match(symbol_name) {
				if found_debug_sync {
					if let Some(col) = symbol.colno() {
						return format!("{}:{}:{}", symbol.filename().unwrap().display(), symbol.lineno().unwrap(), col);
					} else {
						// Windows debug symbols don't support column numbers, so fall back to
						// line numbers only if no `colno` is available
						return format!("{}:{}", symbol.filename().unwrap().display(), symbol.lineno().unwrap());
					}
				}
			} else { found_debug_sync = true; }
		}
	}
	panic!("Couldn't find mutex construction callsite");
}

impl LockMetadata {
	fn new() -> Arc<LockMetadata> {
		let backtrace = Backtrace::new();
		let lock_idx = LOCK_IDX.fetch_add(1, Ordering::Relaxed) as u64;

		let res = Arc::new(LockMetadata {
			locked_before: StdMutex::new(HashMap::new()),
			lock_idx,
			_lock_construction_bt: backtrace,
		});

		#[cfg(feature = "backtrace")]
		{
			let lock_constr_location = get_construction_location(&res._lock_construction_bt);
			LOCKS_INIT.call_once(|| { unsafe { LOCKS = Some(StdMutex::new(HashMap::new())); } });
			let mut locks = unsafe { LOCKS.as_ref() }.unwrap().lock().unwrap();
			match locks.entry(lock_constr_location) {
				hash_map::Entry::Occupied(e) => return Arc::clone(e.get()),
				hash_map::Entry::Vacant(e) => { e.insert(Arc::clone(&res)); },
			}
		}
		res
	}

	// Returns whether we were a recursive lock (only relevant for read)
	fn _pre_lock(this: &Arc<LockMetadata>, read: bool) -> bool {
		let mut inserted = false;
		LOCKS_HELD.with(|held| {
			// For each lock which is currently locked, check that no lock's locked-before
			// set includes the lock we're about to lock, which would imply a lockorder
			// inversion.
			for (locked_idx, _locked) in held.borrow().iter() {
				if read && *locked_idx == this.lock_idx {
					// Recursive read locks are explicitly allowed
					return;
				}
			}
			for (locked_idx, locked) in held.borrow().iter() {
				if !read && *locked_idx == this.lock_idx {
					// With `feature = "backtrace"` set, we may be looking at different instances
					// of the same lock.
					debug_assert!(cfg!(feature = "backtrace"), "Tried to acquire a lock while it was held!");
				}
				for (locked_dep_idx, _locked_dep) in locked.locked_before.lock().unwrap().iter() {
					if *locked_dep_idx == this.lock_idx && *locked_dep_idx != locked.lock_idx {
						#[cfg(feature = "backtrace")]
						panic!("Tried to violate existing lockorder.\nMutex that should be locked after the current lock was created at the following backtrace.\nNote that to get a backtrace for the lockorder violation, you should set RUST_BACKTRACE=1\nLock being taken constructed at: {} ({}):\n{:?}\nLock constructed at: {} ({})\n{:?}\n\nLock dep created at:\n{:?}\n\n",
							get_construction_location(&this._lock_construction_bt), this.lock_idx, this._lock_construction_bt,
							get_construction_location(&locked._lock_construction_bt), locked.lock_idx, locked._lock_construction_bt,
							_locked_dep._lockdep_trace);
						#[cfg(not(feature = "backtrace"))]
						panic!("Tried to violate existing lockorder. Build with the backtrace feature for more info.");
					}
				}
				// Insert any already-held locks in our locked-before set.
				let mut locked_before = this.locked_before.lock().unwrap();
				if !locked_before.contains_key(&locked.lock_idx) {
					let lockdep = LockDep { lock: Arc::clone(locked), _lockdep_trace: Backtrace::new() };
					locked_before.insert(lockdep.lock.lock_idx, lockdep);
				}
			}
			held.borrow_mut().insert(this.lock_idx, Arc::clone(this));
			inserted = true;
		});
		inserted
	}

	fn pre_lock(this: &Arc<LockMetadata>) { Self::_pre_lock(this, false); }
	fn pre_read_lock(this: &Arc<LockMetadata>) -> bool { Self::_pre_lock(this, true) }

	fn try_locked(this: &Arc<LockMetadata>) {
		LOCKS_HELD.with(|held| {
			// Since a try-lock will simply fail if the lock is held already, we do not
			// consider try-locks to ever generate lockorder inversions. However, if a try-lock
			// succeeds, we do consider it to have created lockorder dependencies.
			let mut locked_before = this.locked_before.lock().unwrap();
			for (locked_idx, locked) in held.borrow().iter() {
				if !locked_before.contains_key(locked_idx) {
					let lockdep = LockDep { lock: Arc::clone(locked), _lockdep_trace: Backtrace::new() };
					locked_before.insert(*locked_idx, lockdep);
				}
			}
			held.borrow_mut().insert(this.lock_idx, Arc::clone(this));
		});
	}
}

pub struct Mutex<T: Sized> {
	inner: StdMutex<T>,
	deps: Arc<LockMetadata>,
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
		LOCKS_HELD.with(|held| {
			held.borrow_mut().remove(&self.mutex.deps.lock_idx);
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
		Mutex { inner: StdMutex::new(inner), deps: LockMetadata::new() }
	}

	pub fn lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
		LockMetadata::pre_lock(&self.deps);
		self.inner.lock().map(|lock| MutexGuard { mutex: self, lock }).map_err(|_| ())
	}

	pub fn try_lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
		let res = self.inner.try_lock().map(|lock| MutexGuard { mutex: self, lock }).map_err(|_| ());
		if res.is_ok() {
			LockMetadata::try_locked(&self.deps);
		}
		res
	}
}

pub struct RwLock<T: Sized> {
	inner: StdRwLock<T>,
	deps: Arc<LockMetadata>,
}

pub struct RwLockReadGuard<'a, T: Sized + 'a> {
	lock: &'a RwLock<T>,
	first_lock: bool,
	guard: StdRwLockReadGuard<'a, T>,
}

pub struct RwLockWriteGuard<'a, T: Sized + 'a> {
	lock: &'a RwLock<T>,
	guard: StdRwLockWriteGuard<'a, T>,
}

impl<T: Sized> Deref for RwLockReadGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.guard.deref()
	}
}

impl<T: Sized> Drop for RwLockReadGuard<'_, T> {
	fn drop(&mut self) {
		if !self.first_lock {
			// Note that its not strictly true that the first taken read lock will get unlocked
			// last, but in practice our locks are always taken as RAII, so it should basically
			// always be true.
			return;
		}
		LOCKS_HELD.with(|held| {
			held.borrow_mut().remove(&self.lock.deps.lock_idx);
		});
	}
}

impl<T: Sized> Deref for RwLockWriteGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.guard.deref()
	}
}

impl<T: Sized> Drop for RwLockWriteGuard<'_, T> {
	fn drop(&mut self) {
		LOCKS_HELD.with(|held| {
			held.borrow_mut().remove(&self.lock.deps.lock_idx);
		});
	}
}

impl<T: Sized> DerefMut for RwLockWriteGuard<'_, T> {
	fn deref_mut(&mut self) -> &mut T {
		self.guard.deref_mut()
	}
}

impl<T> RwLock<T> {
	pub fn new(inner: T) -> RwLock<T> {
		RwLock { inner: StdRwLock::new(inner), deps: LockMetadata::new() }
	}

	pub fn read<'a>(&'a self) -> LockResult<RwLockReadGuard<'a, T>> {
		let first_lock = LockMetadata::pre_read_lock(&self.deps);
		self.inner.read().map(|guard| RwLockReadGuard { lock: self, guard, first_lock }).map_err(|_| ())
	}

	pub fn write<'a>(&'a self) -> LockResult<RwLockWriteGuard<'a, T>> {
		LockMetadata::pre_lock(&self.deps);
		self.inner.write().map(|guard| RwLockWriteGuard { lock: self, guard }).map_err(|_| ())
	}

	pub fn try_write<'a>(&'a self) -> LockResult<RwLockWriteGuard<'a, T>> {
		let res = self.inner.try_write().map(|guard| RwLockWriteGuard { lock: self, guard }).map_err(|_| ());
		if res.is_ok() {
			LockMetadata::try_locked(&self.deps);
		}
		res
	}
}

pub type FairRwLock<T> = RwLock<T>;

mod tests {
	use super::{RwLock, Mutex};

	#[test]
	#[should_panic]
	#[cfg(not(feature = "backtrace"))]
	fn recursive_lock_fail() {
		let mutex = Mutex::new(());
		let _a = mutex.lock().unwrap();
		let _b = mutex.lock().unwrap();
	}

	#[test]
	fn recursive_read() {
		let lock = RwLock::new(());
		let _a = lock.read().unwrap();
		let _b = lock.read().unwrap();
	}

	#[test]
	#[should_panic]
	fn lockorder_fail() {
		let a = Mutex::new(());
		let b = Mutex::new(());
		{
			let _a = a.lock().unwrap();
			let _b = b.lock().unwrap();
		}
		{
			let _b = b.lock().unwrap();
			let _a = a.lock().unwrap();
		}
	}

	#[test]
	#[should_panic]
	fn write_lockorder_fail() {
		let a = RwLock::new(());
		let b = RwLock::new(());
		{
			let _a = a.write().unwrap();
			let _b = b.write().unwrap();
		}
		{
			let _b = b.write().unwrap();
			let _a = a.write().unwrap();
		}
	}

	#[test]
	#[should_panic]
	fn read_lockorder_fail() {
		let a = RwLock::new(());
		let b = RwLock::new(());
		{
			let _a = a.read().unwrap();
			let _b = b.read().unwrap();
		}
		{
			let _b = b.read().unwrap();
			let _a = a.read().unwrap();
		}
	}

	#[test]
	fn read_recursive_no_lockorder() {
		// Like the above, but note that no lockorder is implied when we recursively read-lock a
		// RwLock, causing this to pass just fine.
		let a = RwLock::new(());
		let b = RwLock::new(());
		let _outer = a.read().unwrap();
		{
			let _a = a.read().unwrap();
			let _b = b.read().unwrap();
		}
		{
			let _b = b.read().unwrap();
			let _a = a.read().unwrap();
		}
	}

	#[test]
	#[should_panic]
	fn read_write_lockorder_fail() {
		let a = RwLock::new(());
		let b = RwLock::new(());
		{
			let _a = a.write().unwrap();
			let _b = b.read().unwrap();
		}
		{
			let _b = b.read().unwrap();
			let _a = a.write().unwrap();
		}
	}
}
