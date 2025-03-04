//! A settable global variable.
//!
//! Used for testing purposes only.

use std::sync::Mutex;

/// A global variable that can be set exactly once.
pub struct MutGlobal<T> {
	value: Mutex<Option<T>>,
	default_fn: fn() -> T,
}

impl<T: Clone> MutGlobal<T> {
	/// Create a new `MutGlobal` with no value set.
	///
	/// default_fn will be called to get the default value if the value is unset
	/// at the time the first call to `get` is made.
	pub const fn new(default_fn: fn() -> T) -> Self {
		Self { value: Mutex::new(None), default_fn }
	}

	/// Set the value of the global variable.
	pub fn set(&self, value: T) {
		let mut lock = self.value.lock().unwrap();
		*lock = Some(value);
	}

	/// Get the value of the global variable, or the default if unset.
	pub fn get(&self) -> T {
		let mut lock = self.value.lock().unwrap();
		if let Some(value) = &*lock {
			value.clone()
		} else {
			let value = (self.default_fn)();
			*lock = Some(value.clone());
			value
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test() {
		let v = MutGlobal::<u8>::new(|| 0);
		assert_eq!(v.get(), 0);
		v.set(42);
		assert_eq!(v.get(), 42);
		v.set(43);
		assert_eq!(v.get(), 43);
	}

	static G: MutGlobal<u8> = MutGlobal::new(|| 0);

	#[test]
	fn test_global() {
		G.set(42);
		assert_eq!(G.get(), 42);
		G.set(43);
		assert_eq!(G.get(), 43);
	}
}
