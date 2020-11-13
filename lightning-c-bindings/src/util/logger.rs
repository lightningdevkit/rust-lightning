//! Log traits live here, which are called throughout the library to provide useful information for
//! debugging purposes.
//!
//! There is currently 2 ways to filter log messages. First one, by using compilation features, e.g \"max_level_off\".
//! The second one, client-side by implementing check against Record Level field.
//! Each module may have its own Logger or share one.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// An enum representing the available verbosity levels of the logger.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum Level {
	///Designates logger being silent
	Off,
	/// Designates very serious errors
	Error,
	/// Designates hazardous situations
	Warn,
	/// Designates useful information
	Info,
	/// Designates lower priority information
	Debug,
	/// Designates very low priority, often extremely verbose, information
	Trace,
}
use lightning::util::logger::Level as nativeLevel;
impl Level {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLevel {
		match self {
			Level::Off => nativeLevel::Off,
			Level::Error => nativeLevel::Error,
			Level::Warn => nativeLevel::Warn,
			Level::Info => nativeLevel::Info,
			Level::Debug => nativeLevel::Debug,
			Level::Trace => nativeLevel::Trace,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLevel {
		match self {
			Level::Off => nativeLevel::Off,
			Level::Error => nativeLevel::Error,
			Level::Warn => nativeLevel::Warn,
			Level::Info => nativeLevel::Info,
			Level::Debug => nativeLevel::Debug,
			Level::Trace => nativeLevel::Trace,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeLevel) -> Self {
		match native {
			nativeLevel::Off => Level::Off,
			nativeLevel::Error => Level::Error,
			nativeLevel::Warn => Level::Warn,
			nativeLevel::Info => Level::Info,
			nativeLevel::Debug => Level::Debug,
			nativeLevel::Trace => Level::Trace,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLevel) -> Self {
		match native {
			nativeLevel::Off => Level::Off,
			nativeLevel::Error => Level::Error,
			nativeLevel::Warn => Level::Warn,
			nativeLevel::Info => Level::Info,
			nativeLevel::Debug => Level::Debug,
			nativeLevel::Trace => Level::Trace,
		}
	}
}
#[no_mangle]
pub extern "C" fn Level_clone(orig: &Level) -> Level {
	orig.clone()
}
/// Returns the most verbose logging level.
#[must_use]
#[no_mangle]
pub extern "C" fn Level_max() -> crate::util::logger::Level {
	let mut ret = lightning::util::logger::Level::max();
	crate::util::logger::Level::native_into(ret)
}

/// A trait encapsulating the operations required of a logger
#[repr(C)]
pub struct Logger {
	pub this_arg: *mut c_void,
	/// Logs the `Record`
	pub log: extern "C" fn (this_arg: *const c_void, record: *const std::os::raw::c_char),
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Sync for Logger {}
unsafe impl Send for Logger {}

use lightning::util::logger::Logger as rustLogger;
impl rustLogger for Logger {
	fn log(&self, record: &lightning::util::logger::Record) {
		let mut local_record = std::ffi::CString::new(format!("{}", record.args)).unwrap();
		(self.log)(self.this_arg, local_record.as_ptr())
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Logger {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Logger_free(this_ptr: Logger) { }
impl Drop for Logger {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
