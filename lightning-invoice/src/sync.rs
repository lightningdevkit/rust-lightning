use core::cell::{RefCell, RefMut};
use core::ops::{Deref, DerefMut};

pub type LockResult<Guard> = Result<Guard, ()>;

pub struct Mutex<T: ?Sized> {
	inner: RefCell<T>
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
}
