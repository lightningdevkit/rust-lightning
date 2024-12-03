#![allow(dead_code)]
//! This file was copied from `rust-lightning`.
pub use ::alloc::sync::Arc;
use core::cell::{Ref, RefCell, RefMut};
use core::fmt;
use core::ops::{Deref, DerefMut};

pub type LockResult<Guard> = Result<Guard, ()>;

pub struct Mutex<T: ?Sized> {
	inner: RefCell<T>,
}

impl<T: fmt::Debug> fmt::Debug for Mutex<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let t = self.lock().unwrap();
		fmt::Debug::fmt(t.deref(), f)
	}
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

	pub fn try_lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
		Ok(MutexGuard { lock: self.inner.borrow_mut() })
	}

	pub fn into_inner(self) -> LockResult<T> {
		Ok(self.inner.into_inner())
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
