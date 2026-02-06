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
//! Log messages should be filtered client-side by implementing check against a given [`Record`]'s
//! [`Level`] field. Each module may have its own Logger or share one.

use bitcoin::secp256k1::PublicKey;

#[cfg(all(feature = "std", test))]
use core::cell::RefCell;
use core::cmp;
use core::fmt;
use core::fmt::Display;
use core::fmt::Write;
use core::ops::Deref;

use crate::ln::channelmanager::PaymentId;
use crate::ln::types::ChannelId;
#[cfg(c_bindings)]
use crate::prelude::*;
use crate::types::payment::PaymentHash;

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

macro_rules! impl_record {
	($($args: lifetime)?, $($nonstruct_args: lifetime)?) => {
/// A Record, unit of logging output with Metadata to enable filtering
/// Module_path, file, line to inform on log's source
#[derive(Clone, Debug)]
pub struct Record<$($args)?> {
	/// The verbosity level of the message.
	pub level: Level,
	/// The node id of the peer pertaining to the logged record. Since peer_id is not repeated in the message body,
	/// include it in the log output so entries remain clear.
	///
	/// Note that in some cases a [`Self::channel_id`] may be filled in but this may still be
	/// `None`, depending on if the peer information is readily available in LDK when the log is
	/// generated.
	pub peer_id: Option<PublicKey>,
	/// The channel id of the channel pertaining to the logged record. May be a temporary id before
	/// the channel has been funded. Since channel_id is not repeated in the message body,
	/// include it in the log output so entries remain clear.
	pub channel_id: Option<ChannelId>,
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
	/// The payment hash.
	///
	/// Since payment_hash is generally not repeated in the message body, you should ensure you log
	/// it so that entries remain clear.
	///
	/// Note that payments don't always have a [`PaymentHash`] immediately - when paying BOLT 12
	/// offers the [`PaymentHash`] is only selected a ways into the payment process. Thus, when
	/// searching your logs for specific payments you should also search for the relevant
	/// [`Self::payment_id`].
	pub payment_hash: Option<PaymentHash>,
	/// The payment id if the log pertained to a payment with an ID.
	pub payment_id: Option<PaymentId>,
}

impl<$($args)?> Record<$($args)?> {
	/// Returns a new Record.
	///
	/// This is not exported to bindings users as fmt can't be used in C
	#[inline]
	pub fn new<$($nonstruct_args)?>(
		level: Level, args: fmt::Arguments<'a>, module_path: &'static str, file: &'static str,
		line: u32,
	) -> Record<$($args)?> {
		Record {
			level,
			peer_id: None,
			channel_id: None,
			#[cfg(not(c_bindings))]
			args,
			#[cfg(c_bindings)]
			args: format!("{}", args),
			module_path,
			file,
			line,
			payment_hash: None,
			payment_id: None,
		}
	}
}

impl<$($args)?> Display for Record<$($args)?> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut context_formatter = SubstringFormatter::new(48, f);
		write!(&mut context_formatter, "{:<5} [{}:{}]", self.level, self.module_path, self.line)?;
		context_formatter.pad_remaining()?;

		let mut channel_formatter = SubstringFormatter::new(9, f);
		if let Some(channel_id) = self.channel_id {
			write!(channel_formatter, "ch:{}", channel_id)?;
		}
		channel_formatter.pad_remaining()?;

		#[cfg(not(test))]
		{
			let mut peer_formatter = SubstringFormatter::new(9, f);
			if let Some(peer_id) = self.peer_id {
				write!(peer_formatter, " p:{}", peer_id)?;
			}
			peer_formatter.pad_remaining()?;

			let mut payment_formatter = SubstringFormatter::new(9, f);
			if let Some(payment_hash) = self.payment_hash {
				write!(payment_formatter, " h:{}", payment_hash)?;
			}
			payment_formatter.pad_remaining()?;

			write!(f, " {}", self.args)
		}

		#[cfg(test)]
		{
			// Read spans from TLS and format them before the message
			#[cfg(feature = "std")]
			{
				let spans: Vec<&'static str> = TLS_LOGGER
					.with(|cell| cell.borrow().iter().map(|span| *span).collect());
				if !spans.is_empty() {
					write!(f, " [{}]", spans.join("->"))?;
				}
			}

			write!(f, " {}", self.args)?;

			let mut open_bracket_written = false;
			if let Some(peer_id) = self.peer_id {
				write!(f, " [")?;
				open_bracket_written = true;
				let mut peer_formatter = SubstringFormatter::new(8, f);
				write!(peer_formatter, "p:{}", peer_id)?;
			}

			if let Some(payment_hash) = self.payment_hash {
				if !open_bracket_written {
					write!(f, " [")?;
					open_bracket_written = true;
				} else {
					write!(f, " ")?;
				}

				let mut payment_formatter = SubstringFormatter::new(8, f);
				write!(payment_formatter, "h:{}", payment_hash)?;
			}

			if open_bracket_written {
				write!(f, "]")?;
			}

			Ok(())
		}
	}
}
} }
#[cfg(not(c_bindings))]
impl_record!('a, );
#[cfg(c_bindings)]
impl_record!(, 'a);

// Writes only up to a certain number of unicode characters to the underlying formatter. This handles multi-byte Unicode
// characters safely.
struct SubstringFormatter<'fmt: 'r, 'r> {
	remaining_chars: usize,
	fmt: &'r mut fmt::Formatter<'fmt>,
}

impl<'fmt: 'r, 'r> SubstringFormatter<'fmt, 'r> {
	fn new(length: usize, formatter: &'r mut fmt::Formatter<'fmt>) -> Self {
		debug_assert!(length <= 100);
		SubstringFormatter { remaining_chars: length, fmt: formatter }
	}

	// Pads the underlying formatter with spaces until the remaining character count.
	fn pad_remaining(&mut self) -> fmt::Result {
		// Use a constant string to avoid allocations.
		const PAD100: &str = "                                                                                                    "; // 100 spaces

		self.fmt.write_str(&PAD100[..self.remaining_chars])?;
		self.remaining_chars = 0;

		Ok(())
	}
}

impl<'fmt: 'r, 'r> Write for SubstringFormatter<'fmt, 'r> {
	fn write_str(&mut self, s: &str) -> fmt::Result {
		let mut char_count = 0;
		let mut next_char_byte_pos = 0;

		// Iterate over the unicode character boundaries in `s`. We take one more than the number of remaining
		// characters so we can find the byte boundary where we should stop writing.
		for (pos, _) in s.char_indices().take(self.remaining_chars + 1) {
			char_count += 1;
			next_char_byte_pos = pos;
		}

		// Determine where to split the string.
		let at_cut_off_point = char_count == self.remaining_chars + 1;
		let split_pos = if at_cut_off_point {
			self.remaining_chars = 0;
			next_char_byte_pos
		} else {
			// Not enough characters in this chunk.
			self.remaining_chars -= char_count;
			s.len()
		};

		// Write only the substring up to the split position into the formatter.
		self.fmt.write_str(&s[..split_pos])
	}
}

/// A trait encapsulating the operations required of a logger. Keep in mind that log messages might not be entirely
/// self-explanatory and may need accompanying context fields to be fully understood.
pub trait Logger {
	/// Logs the [`Record`]. Since [`Record::channel_id`], [`Record::peer_id`] and [`Record::payment_hash`] are not
	/// embedded in the message body, log implementations should print those alongside the message to keep entries
	/// clear.
	fn log(&self, record: Record);
}

impl<T: Logger + ?Sized, L: Deref<Target = T>> Logger for L {
	fn log(&self, record: Record) {
		self.deref().log(record)
	}
}

/// Adds relevant context to a [`Record`] before passing it to the wrapped [`Logger`].
///
/// This is not exported to bindings users as lifetimes are problematic and there's little reason
/// for this to be used downstream anyway.
pub struct WithContext<'a, L: Logger> {
	logger: &'a L,
	peer_id: Option<PublicKey>,
	channel_id: Option<ChannelId>,
	payment_hash: Option<PaymentHash>,
	payment_id: Option<PaymentId>,
}

impl<'a, L: Logger> Logger for WithContext<'a, L> {
	fn log(&self, mut record: Record) {
		if self.peer_id.is_some() && record.peer_id.is_none() {
			record.peer_id = self.peer_id
		};
		if self.channel_id.is_some() && record.channel_id.is_none() {
			record.channel_id = self.channel_id;
		}
		if self.payment_hash.is_some() && record.payment_hash.is_none() {
			record.payment_hash = self.payment_hash;
		}
		if self.payment_id.is_some() && record.payment_id.is_none() {
			record.payment_id = self.payment_id;
		}
		self.logger.log(record)
	}
}

impl<'a, L: Logger> WithContext<'a, L> {
	/// Wraps the given logger, providing additional context to any logged records.
	pub fn from(
		logger: &'a L, peer_id: Option<PublicKey>, channel_id: Option<ChannelId>,
		payment_hash: Option<PaymentHash>,
	) -> Self {
		WithContext { logger, peer_id, channel_id, payment_hash, payment_id: None }
	}

	/// Wraps the given logger, providing additional context to any logged records.
	pub fn for_payment(
		logger: &'a L, peer_id: Option<PublicKey>, channel_id: Option<ChannelId>,
		payment_hash: Option<PaymentHash>, payment_id: PaymentId,
	) -> Self {
		let payment_id = Some(payment_id);
		WithContext { logger, peer_id, channel_id, payment_hash, payment_id }
	}
}

/// Wrapper for logging a [`PublicKey`] in hex format.
///
/// This is not exported to bindings users as fmt can't be used in C
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
///
/// This is not exported to bindings users as fmt can't be used in C
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

/// Wrapper for logging `Iterator`s.
///
/// This is not exported to bindings users as fmt can't be used in C
#[doc(hidden)]
pub struct DebugIter<T: fmt::Display, I: core::iter::Iterator<Item = T> + Clone>(pub I);
impl<T: fmt::Display, I: core::iter::Iterator<Item = T> + Clone> fmt::Display for DebugIter<T, I> {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		write!(f, "[")?;
		let mut iter = self.0.clone();
		if let Some(item) = iter.next() {
			write!(f, "{}", item)?;
		}
		for item in iter {
			write!(f, ", {}", item)?;
		}
		write!(f, "]")?;
		Ok(())
	}
}

#[cfg(all(feature = "std", test))]
thread_local! {
	/// The thread-local stack of span names.
	pub static TLS_LOGGER: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

/// A scope which pushes a span name on a thread-local stack for the duration of the scope.
/// In non-test builds, this is a no-op.
pub struct LoggerScope<'a> {
	_marker: core::marker::PhantomData<&'a ()>,
}

impl<'a> LoggerScope<'a> {
	/// Pushes a span name onto the thread-local span stack.
	/// In non-test builds, this is a no-op.
	pub fn new(span: &'static str) -> Self {
		#[cfg(all(feature = "std", test))]
		TLS_LOGGER.with(|cell| {
			let mut stack = cell.borrow_mut();
			stack.push(span);
		});
		#[cfg(not(all(feature = "std", test)))]
		let _ = span;

		LoggerScope { _marker: core::marker::PhantomData }
	}
}

impl<'a> Drop for LoggerScope<'a> {
	fn drop(&mut self) {
		#[cfg(all(feature = "std", test))]
		// Use try_with to avoid panicking if TLS is being destroyed
		let _ = TLS_LOGGER.try_with(|cell| {
			let mut stack = cell.borrow_mut();
			stack.pop();
		});
	}
}

#[cfg(test)]
mod tests {
	use crate::ln::types::ChannelId;
	use crate::sync::Arc;
	use crate::types::payment::PaymentHash;
	use crate::util::logger::{Level, Logger, LoggerScope, WithContext};
	use crate::util::test_utils::TestLogger;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use lightning_macros::log_scope;

	#[test]
	fn logger_scope() {
		let logger = TestLogger::new();
		let _scope = LoggerScope::new("test_logger_scope");
		log_info!(logger, "Info");
		logger.assert_log_formatted_contains("[test_logger_scope]", 1);
	}

	#[test]
	#[log_scope(name = "test_logger_scope_proc_macro")]
	fn logger_scope_proc_macro() {
		let logger = TestLogger::new();
		log_info!(logger, "Info");
		logger.assert_log_formatted_contains("[test_logger_scope_proc_macro]", 1);
	}

	#[test]
	#[log_scope]
	fn logger_scope_proc_macro_no_name() {
		let logger = TestLogger::new();
		log_info!(logger, "Info");
		logger.assert_log_formatted_contains("[logger_scope_proc_macro_no_name]", 1);
	}

	#[test]
	fn test_level_show() {
		assert_eq!("INFO", Level::Info.to_string());
		assert_eq!("ERROR", Level::Error.to_string());
		assert_ne!("WARN", Level::Error.to_string());
	}

	struct WrapperLog {
		logger: Arc<dyn Logger>,
	}

	impl WrapperLog {
		fn new(logger: Arc<dyn Logger>) -> WrapperLog {
			WrapperLog { logger }
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
		let logger = TestLogger::new();
		let logger: Arc<dyn Logger> = Arc::new(logger);
		let wrapper = WrapperLog::new(Arc::clone(&logger));
		wrapper.call_macros();
	}

	#[test]
	fn test_logging_with_context() {
		let logger = &TestLogger::new();
		let secp_ctx = Secp256k1::new();
		let pk = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let payment_hash = PaymentHash([0; 32]);
		let context_logger =
			WithContext::from(&logger, Some(pk), Some(ChannelId([0; 32])), Some(payment_hash));
		log_error!(context_logger, "This is an error");
		log_warn!(context_logger, "This is an error");
		log_debug!(context_logger, "This is an error");
		log_trace!(context_logger, "This is an error");
		log_gossip!(context_logger, "This is an error");
		log_info!(context_logger, "This is an error");
		logger.assert_log_context_contains(
			"lightning::util::logger::tests",
			Some(pk),
			Some(ChannelId([0; 32])),
			6,
		);
	}

	#[test]
	fn test_logging_with_multiple_wrapped_context() {
		let logger = &TestLogger::new();
		let secp_ctx = Secp256k1::new();
		let pk = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let payment_hash = PaymentHash([0; 32]);
		let context_logger =
			&WithContext::from(&logger, None, Some(ChannelId([0; 32])), Some(payment_hash));
		let full_context_logger = WithContext::from(&context_logger, Some(pk), None, None);
		log_error!(full_context_logger, "This is an error");
		log_warn!(full_context_logger, "This is an error");
		log_debug!(full_context_logger, "This is an error");
		log_trace!(full_context_logger, "This is an error");
		log_gossip!(full_context_logger, "This is an error");
		log_info!(full_context_logger, "This is an error");
		logger.assert_log_context_contains(
			"lightning::util::logger::tests",
			Some(pk),
			Some(ChannelId([0; 32])),
			6,
		);
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
