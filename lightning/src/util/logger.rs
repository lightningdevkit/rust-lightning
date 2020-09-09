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

use std::cmp;
use std::fmt;

static LOG_LEVEL_NAMES: [&'static str; 6] = ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

/// An enum representing the available verbosity levels of the logger.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
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
		Level::Trace
	}
}

/// A Record, unit of logging output with Metadata to enable filtering
/// Module_path, file, line to inform on log's source
/// (C-not exported) - we convert to a const char* instead
#[derive(Clone,Debug)]
pub struct Record<'a> {
	/// The verbosity level of the message.
	pub level: Level,
	/// The message body.
	pub args: fmt::Arguments<'a>,
	/// The module path of the message.
	pub module_path: &'a str,
	/// The source file containing the message.
	pub file: &'a str,
	/// The line containing the message.
	pub line: u32,
}

impl<'a> Record<'a> {
	/// Returns a new Record.
	/// (C-not exported) as fmt can't be used in C
	#[inline]
	pub fn new(level: Level, args: fmt::Arguments<'a>, module_path: &'a str, file: &'a str, line: u32) -> Record<'a> {
		Record {
			level,
			args,
			module_path,
			file,
			line
		}
	}
}

/// A trait encapsulating the operations required of a logger
pub trait Logger: Sync + Send {
	/// Logs the `Record`
	fn log(&self, record: &Record);
}

#[cfg(test)]
mod tests {
	use util::logger::{Logger, Level};
	use util::test_utils::TestLogger;
	use std::sync::Arc;

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
		}
	}

	#[test]
	fn test_logging_macros() {
		let mut logger = TestLogger::new();
		logger.enable(Level::Trace);
		let logger : Arc<Logger> = Arc::new(logger);
		let wrapper = WrapperLog::new(Arc::clone(&logger));
		wrapper.call_macros();
	}
}
