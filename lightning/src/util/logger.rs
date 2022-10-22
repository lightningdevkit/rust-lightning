// Pruned copy of crate rust log, without global logger
// https://github.com/rust-lang-nursery/log #7a60286
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Log traits live here, which are called throughout the library to provide useful information for
//! debugging purposes.
//!
//! There is currently 2 ways to filter log messages. First one, by using compilation features, e.g "max_level_off".
//! The second one, client-side by implementing check against Record Level field.
//! Each module may have its own Logger or share one.

use bitcoin::secp256k1::PublicKey;

use core::cmp;
use core::fmt;

#[cfg(c_bindings)]
use crate::prelude::*; // Needed for String

static LOG_LEVEL_NAMES: [&'static str; 6] = ["GOSSIP", "TRACE", "DEBUG", "INFO", "WARN", "ERROR"];

/// An enum representing the available verbosity levels of the logger.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum Level {
	/// Designates extremely verbose information, including gossip-induced messages
	Gossip,
	/// Designates very low priority, often extremely verbose, information
	Trace,
	/// Designates lower priority information
	Debug,
	/// Designates useful information
	Info,
	/// Designates hazardous situations
	Warn,
	/// Designates very serious errors
	Error,
}

impl PartialOrd for Level {
	#[inline]
	fn partial_cmp(&self, other: &Level) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}

	#[inline]
	fn lt(&self, other: &Level) -> bool {
		(*self as usize) < *other as usize
	}

	#[inline]
	fn le(&self, other: &Level) -> bool {
		*self as usize <= *other as usize
	}

	#[inline]
	fn gt(&self, other: &Level) -> bool {
		*self as usize > *other as usize
	}

	#[inline]
	fn ge(&self, other: &Level) -> bool {
		*self as usize >= *other as usize
	}
}

impl Ord for Level {
	#[inline]
	fn cmp(&self, other: &Level) -> cmp::Ordering {
		(*self as usize).cmp(&(*other as usize))
	}
}

impl fmt::Display for Level {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		fmt.pad(LOG_LEVEL_NAMES[*self as usize])
	}
}

impl Level {
	/// Returns the most verbose logging level.
	#[inline]
	pub fn max() -> Level {
		Level::Gossip
	}
}

/// A Record, unit of logging output with Metadata to enable filtering
/// Module_path, file, line to inform on log's source
#[derive(Clone, Debug)]
pub struct Record<'a> {
	/// The verbosity level of the message.
	pub level: Level,
	#[cfg(not(c_bindings))]
	/// The message body.
	pub args: fmt::Arguments<'a>,
	#[cfg(c_bindings)]
	/// The message body.
	pub args: String,
	/// The module path of the message.
	pub module_path: &'static str,
	/// The source file containing the message.
	pub file: &'static str,
	/// The line containing the message.
	pub line: u32,

	#[cfg(c_bindings)]
	/// We don't actually use the lifetime parameter in C bindings (as there is no good way to
	/// communicate a lifetime to a C, or worse, Java user).
	_phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> Record<'a> {
	/// Returns a new Record.
	/// (C-not exported) as fmt can't be used in C
	#[inline]
	pub fn new(level: Level, args: fmt::Arguments<'a>, module_path: &'static str, file: &'static str, line: u32) -> Record<'a> {
		Record {
			level,
			#[cfg(not(c_bindings))]
			args,
			#[cfg(c_bindings)]
			args: format!("{}", args),
			module_path,
			file,
			line,
			#[cfg(c_bindings)]
			_phantom: core::marker::PhantomData,
		}
	}
}

/// A trait encapsulating the operations required of a logger
pub trait Logger {
	/// Logs the `Record`
	fn log(&self, record: &Record);
}

/// Wrapper for logging a [`PublicKey`] in hex format.
/// (C-not exported) as fmt can't be used in C
#[doc(hidden)]
pub struct DebugPubKey<'a>(pub &'a PublicKey);
impl<'a> core::fmt::Display for DebugPubKey<'a> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		for i in self.0.serialize().iter() {
			write!(f, "{:02x}", i)?;
		}
		Ok(())
	}
}

/// Wrapper for logging byte slices in hex format.
/// (C-not exported) as fmt can't be used in C
#[doc(hidden)]
pub struct DebugBytes<'a>(pub &'a [u8]);
impl<'a> core::fmt::Display for DebugBytes<'a> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		for i in self.0 {
			write!(f, "{:02x}", i)?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use crate::util::logger::{Logger, Level};
	use crate::util::test_utils::TestLogger;
	use crate::sync::Arc;

	#[test]
	fn test_level_show() {
		assert_eq!("INFO", Level::Info.to_string());
		assert_eq!("ERROR", Level::Error.to_string());
		assert_ne!("WARN", Level::Error.to_string());
	}

	struct WrapperLog {
		logger: Arc<Logger>
	}

	impl WrapperLog {
		fn new(logger: Arc<Logger>) -> WrapperLog {
			WrapperLog {
				logger,
			}
		}

		fn call_macros(&self) {
			log_error!(self.logger, "This is an error");
			log_warn!(self.logger, "This is a warning");
			log_info!(self.logger, "This is an info");
			log_debug!(self.logger, "This is a debug");
			log_trace!(self.logger, "This is a trace");
			log_gossip!(self.logger, "This is a gossip");
		}
	}

	#[test]
	fn test_logging_macros() {
		let mut logger = TestLogger::new();
		logger.enable(Level::Gossip);
		let logger : Arc<Logger> = Arc::new(logger);
		let wrapper = WrapperLog::new(Arc::clone(&logger));
		wrapper.call_macros();
	}

	#[test]
	fn test_log_ordering() {
		assert!(Level::Error > Level::Warn);
		assert!(Level::Error >= Level::Warn);
		assert!(Level::Error >= Level::Error);
		assert!(Level::Warn > Level::Info);
		assert!(Level::Warn >= Level::Info);
		assert!(Level::Warn >= Level::Warn);
		assert!(Level::Info > Level::Debug);
		assert!(Level::Info >= Level::Debug);
		assert!(Level::Info >= Level::Info);
		assert!(Level::Debug > Level::Trace);
		assert!(Level::Debug >= Level::Trace);
		assert!(Level::Debug >= Level::Debug);
		assert!(Level::Trace > Level::Gossip);
		assert!(Level::Trace >= Level::Gossip);
		assert!(Level::Trace >= Level::Trace);
		assert!(Level::Gossip >= Level::Gossip);

		assert!(Level::Error <= Level::Error);
		assert!(Level::Warn < Level::Error);
		assert!(Level::Warn <= Level::Error);
		assert!(Level::Warn <= Level::Warn);
		assert!(Level::Info < Level::Warn);
		assert!(Level::Info <= Level::Warn);
		assert!(Level::Info <= Level::Info);
		assert!(Level::Debug < Level::Info);
		assert!(Level::Debug <= Level::Info);
		assert!(Level::Debug <= Level::Debug);
		assert!(Level::Trace < Level::Debug);
		assert!(Level::Trace <= Level::Debug);
		assert!(Level::Trace <= Level::Trace);
		assert!(Level::Gossip < Level::Trace);
		assert!(Level::Gossip <= Level::Trace);
		assert!(Level::Gossip <= Level::Gossip);
	}
}
