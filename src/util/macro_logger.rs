use util::logger::Record;

macro_rules! log_internal {
	($self: ident, $lvl:expr, $($arg:tt)+) => (
		&$self.logger.log(&Record::new($lvl, format_args!($($arg)+), module_path!(), file!(), line!()));
	);
}

macro_rules! log_error {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off")))]
		log_internal!($self, $crate::util::logger::Level::Error, $($arg)*);
	)
}

macro_rules! log_warn {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error")))]
		log_internal!($self, $crate::util::logger::Level::Warn, $($arg)*);
	)
}

macro_rules! log_info {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn")))]
		log_internal!($self, $crate::util::logger::Level::Info, $($arg)*);
	)
}

macro_rules! log_debug {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info")))]
		log_internal!($self, $crate::util::logger::Level::Debug, $($arg)*);
	)
}

macro_rules! log_trace {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info", feature = "max_level_debug")))]
		log_internal!($self, $crate::util::logger::Level::Trace, $($arg)*);
	)
}
