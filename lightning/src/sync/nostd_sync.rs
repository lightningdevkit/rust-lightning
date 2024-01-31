use super::{LockHeldState, LockTestExt};
pub use ::alloc::sync::Arc;
use core::cell::{Ref, RefCell, RefMut};
use core::ops::{Deref, DerefMut};

pub type LockResult<Guard> = Result<Guard, ()>;

pub struct Mutex<T: ?Sized> {
	inner: RefCell<T>,
}

#[must_use = "if unused the Mutex will immediately unlock"]
pub struct MutexGuard<'a, T: ?Sized + 'a> {
	lock: RefMut<'a, T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.lock.deref()
	}
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
	fn deref_mut(&mut self) -> &mut T {
		self.lock.deref_mut()
	}
}

impl<T> Mutex<T> {
	pub fn new(inner: T) -> Mutex<T> {
		Mutex { inner: RefCell::new(inner) }
	}

	pub fn lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
		Ok(MutexGuard { lock: self.inner.borrow_mut() })
	}

	pub fn into_inner(self) -> LockResult<T> {
		Ok(self.inner.into_inner())
	}
}

impl<'a, T: 'a> LockTestExt<'a> for Mutex<T> {
	#[inline]
	fn held_by_thread(&self) -> LockHeldState {
		if self.inner.try_borrow_mut().is_err() {
			return LockHeldState::HeldByThread;
		} else {
			return LockHeldState::NotHeldByThread;
		}
	}
	type ExclLock = MutexGuard<'a, T>;
	#[inline]
	fn unsafe_well_ordered_double_lock_self(&'a self) -> MutexGuard<T> {
		self.lock().unwrap()
	}
}

pub struct RwLock<T: ?Sized> {
	inner: RefCell<T>,
}

pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
	lock: Ref<'a, T>,
}

pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
	lock: RefMut<'a, T>,
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
		RwLock { inner: RefCell::new(inner) }
	}

	pub fn read<'a>(&'a self) -> LockResult<RwLockReadGuard<'a, T>> {
		Ok(RwLockReadGuard { lock: self.inner.borrow() })
	}

	pub fn write<'a>(&'a self) -> LockResult<RwLockWriteGuard<'a, T>> {
		Ok(RwLockWriteGuard { lock: self.inner.borrow_mut() })
	}

	pub fn try_write<'a>(&'a self) -> LockResult<RwLockWriteGuard<'a, T>> {
		match self.inner.try_borrow_mut() {
			Ok(lock) => Ok(RwLockWriteGuard { lock }),
			Err(_) => Err(()),
		}
	}
}

impl<'a, T: 'a> LockTestExt<'a> for RwLock<T> {
	#[inline]
	fn held_by_thread(&self) -> LockHeldState {
		if self.inner.try_borrow_mut().is_err() {
			return LockHeldState::HeldByThread;
		} else {
			return LockHeldState::NotHeldByThread;
		}
	}
	type ExclLock = RwLockWriteGuard<'a, T>;
	#[inline]
	fn unsafe_well_ordered_double_lock_self(&'a self) -> RwLockWriteGuard<T> {
		self.write().unwrap()
	}
}

pub type FairRwLock<T> = RwLock<T>;
