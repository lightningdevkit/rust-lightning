// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::ln::types::ChannelId;
use crate::sign::SpendableOutputDescriptor;

use bitcoin::transaction::Transaction;

use crate::ln::chan_utils::HTLCClaim;
use crate::routing::router::Route;

macro_rules! log_iter {
	($obj: expr) => {
		$crate::util::logger::DebugIter($obj)
	};
}

/// Logs a pubkey in hex format.
#[macro_export]
macro_rules! log_pubkey {
	($obj: expr) => {
		$crate::util::logger::DebugPubKey(&$obj)
	};
}

/// Logs a byte slice in hex format.
#[macro_export]
macro_rules! log_bytes {
	($obj: expr) => {
		$crate::util::logger::DebugBytes(&$obj)
	};
}

pub(crate) struct DebugFundingInfo<'a>(pub &'a ChannelId);
impl<'a> core::fmt::Display for DebugFundingInfo<'a> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.0.fmt(f)
	}
}
macro_rules! log_funding_info {
	($key_storage: expr) => {
		$crate::util::macro_logger::DebugFundingInfo(&$key_storage.channel_id())
	};
}

pub(crate) struct DebugRoute<'a>(pub &'a Route);
impl<'a> core::fmt::Display for DebugRoute<'a> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		for (idx, p) in self.0.paths.iter().enumerate() {
			writeln!(f, "path {}:", idx)?;
			for h in p.hops.iter() {
				writeln!(
					f,
					" node_id: {}, short_channel_id: {}, fee_msat: {}, cltv_expiry_delta: {}",
					log_pubkey!(h.pubkey),
					h.short_channel_id,
					h.fee_msat,
					h.cltv_expiry_delta
				)?;
			}
			writeln!(f, " blinded_tail: {:?}", p.blinded_tail)?;
		}
		Ok(())
	}
}
macro_rules! log_route {
	($obj: expr) => {
		$crate::util::macro_logger::DebugRoute(&$obj)
	};
}

pub(crate) struct DebugTx<'a>(pub &'a Transaction);
impl<'a> core::fmt::Display for DebugTx<'a> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		if self.0.input.len() >= 1 && self.0.input.iter().any(|i| !i.witness.is_empty()) {
			let first_input = &self.0.input[0];
			let witness_script_len = first_input.witness.last().unwrap_or(&[]).len();
			if self.0.input.len() == 1
				&& witness_script_len == 71
				&& (first_input.sequence.0 >> 8 * 3) as u8 == 0x80
			{
				write!(f, "commitment tx ")?;
			} else if self.0.input.len() == 1 && witness_script_len == 71 {
				write!(f, "closing tx ")?;
			} else if self.0.input.len() == 1
				&& HTLCClaim::from_witness(&first_input.witness) == Some(HTLCClaim::OfferedTimeout)
			{
				write!(f, "HTLC-timeout tx ")?;
			} else if self.0.input.len() == 1
				&& HTLCClaim::from_witness(&first_input.witness)
					== Some(HTLCClaim::AcceptedPreimage)
			{
				write!(f, "HTLC-success tx ")?;
			} else {
				let mut num_preimage = 0;
				let mut num_timeout = 0;
				let mut num_revoked = 0;
				for inp in &self.0.input {
					let htlc_claim = HTLCClaim::from_witness(&inp.witness);
					match htlc_claim {
						Some(HTLCClaim::AcceptedPreimage) | Some(HTLCClaim::OfferedPreimage) => {
							num_preimage += 1
						},
						Some(HTLCClaim::AcceptedTimeout) | Some(HTLCClaim::OfferedTimeout) => {
							num_timeout += 1
						},
						Some(HTLCClaim::Revocation) => num_revoked += 1,
						None => continue,
					}
				}
				if num_preimage > 0 || num_timeout > 0 || num_revoked > 0 {
					write!(
						f,
						"HTLC claim tx ({} preimage, {} timeout, {} revoked) ",
						num_preimage, num_timeout, num_revoked
					)?;
				}
			}
		} else {
			debug_assert!(false, "We should never generate unknown transaction types");
			write!(f, "unknown tx type ").unwrap();
		}
		write!(f, "with txid {}", self.0.compute_txid())?;
		Ok(())
	}
}

macro_rules! log_tx {
	($obj: expr) => {
		$crate::util::macro_logger::DebugTx(&$obj)
	};
}

pub(crate) struct DebugSpendable<'a>(pub &'a SpendableOutputDescriptor);
impl<'a> core::fmt::Display for DebugSpendable<'a> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		match self.0 {
			&SpendableOutputDescriptor::StaticOutput { ref outpoint, .. } => {
				write!(f, "StaticOutput {}:{} marked for spending", outpoint.txid, outpoint.index)?;
			},
			&SpendableOutputDescriptor::DelayedPaymentOutput(ref descriptor) => {
				write!(
					f,
					"DelayedPaymentOutput {}:{} marked for spending",
					descriptor.outpoint.txid, descriptor.outpoint.index
				)?;
			},
			&SpendableOutputDescriptor::StaticPaymentOutput(ref descriptor) => {
				write!(
					f,
					"StaticPaymentOutput {}:{} marked for spending",
					descriptor.outpoint.txid, descriptor.outpoint.index
				)?;
			},
		}
		Ok(())
	}
}

macro_rules! log_spendable {
	($obj: expr) => {
		$crate::util::macro_logger::DebugSpendable(&$obj)
	};
}

/// Create a new Record and log it. You probably don't want to use this macro directly,
/// but it needs to be exported so `log_trace` etc can use it in external crates.
#[doc(hidden)]
#[macro_export]
macro_rules! log_internal {
	($logger: expr, $lvl:expr, $($arg:tt)+) => (
		$logger.log($crate::util::logger::Record::new($lvl, None, None, format_args!($($arg)+), module_path!(), file!(), line!(), None))
	);
}

/// Logs an entry at the given level.
#[doc(hidden)]
#[macro_export]
macro_rules! log_given_level {
	($logger: expr, $lvl:expr, $($arg:tt)+) => (
		match $lvl {
			#[cfg(not(any(feature = "max_level_off")))]
			$crate::util::logger::Level::Error => $crate::log_internal!($logger, $lvl, $($arg)*),
			#[cfg(not(any(feature = "max_level_off", feature = "max_level_error")))]
			$crate::util::logger::Level::Warn => $crate::log_internal!($logger, $lvl, $($arg)*),
			#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn")))]
			$crate::util::logger::Level::Info => $crate::log_internal!($logger, $lvl, $($arg)*),
			#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info")))]
			$crate::util::logger::Level::Debug => $crate::log_internal!($logger, $lvl, $($arg)*),
			#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info", feature = "max_level_debug")))]
			$crate::util::logger::Level::Trace => $crate::log_internal!($logger, $lvl, $($arg)*),
			#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info", feature = "max_level_debug", feature = "max_level_trace")))]
			$crate::util::logger::Level::Gossip => $crate::log_internal!($logger, $lvl, $($arg)*),

			#[cfg(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info", feature = "max_level_debug", feature = "max_level_trace"))]
			_ => {
				// The level is disabled at compile-time
			},
		}
	);
}

/// Log at the `ERROR` level.
#[macro_export]
macro_rules! log_error {
	($logger: expr, $($arg:tt)*) => (
		$crate::log_given_level!($logger, $crate::util::logger::Level::Error, $($arg)*);
	)
}

/// Log at the `WARN` level.
#[macro_export]
macro_rules! log_warn {
	($logger: expr, $($arg:tt)*) => (
		$crate::log_given_level!($logger, $crate::util::logger::Level::Warn, $($arg)*);
	)
}

/// Log at the `INFO` level.
#[macro_export]
macro_rules! log_info {
	($logger: expr, $($arg:tt)*) => (
		$crate::log_given_level!($logger, $crate::util::logger::Level::Info, $($arg)*);
	)
}

/// Log at the `DEBUG` level.
#[macro_export]
macro_rules! log_debug {
	($logger: expr, $($arg:tt)*) => (
		$crate::log_given_level!($logger, $crate::util::logger::Level::Debug, $($arg)*);
	)
}

/// Log at the `TRACE` level.
#[macro_export]
macro_rules! log_trace {
	($logger: expr, $($arg:tt)*) => (
		$crate::log_given_level!($logger, $crate::util::logger::Level::Trace, $($arg)*)
	)
}

/// Log at the `GOSSIP` level.
#[macro_export]
macro_rules! log_gossip {
	($logger: expr, $($arg:tt)*) => (
		$crate::log_given_level!($logger, $crate::util::logger::Level::Gossip, $($arg)*);
	)
}
