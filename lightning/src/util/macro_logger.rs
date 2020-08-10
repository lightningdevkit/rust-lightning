// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use chain::transaction::OutPoint;
use chain::keysinterface::SpendableOutputDescriptor;

use bitcoin::hash_types::Txid;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1::key::PublicKey;

use routing::router::Route;
use ln::chan_utils::HTLCType;

use std;

pub(crate) struct DebugPubKey<'a>(pub &'a PublicKey);
impl<'a> std::fmt::Display for DebugPubKey<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		for i in self.0.serialize().iter() {
			write!(f, "{:02x}", i)?;
		}
		Ok(())
	}
}
macro_rules! log_pubkey {
	($obj: expr) => {
		::util::macro_logger::DebugPubKey(&$obj)
	}
}

pub(crate) struct DebugBytes<'a>(pub &'a [u8]);
impl<'a> std::fmt::Display for DebugBytes<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		for i in self.0 {
			write!(f, "{:02x}", i)?;
		}
		Ok(())
	}
}
macro_rules! log_bytes {
	($obj: expr) => {
		::util::macro_logger::DebugBytes(&$obj)
	}
}

pub(crate) struct DebugFundingChannelId<'a>(pub &'a Txid, pub u16);
impl<'a> std::fmt::Display for DebugFundingChannelId<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		for i in (OutPoint { txid: self.0.clone(), index: self.1 }).to_channel_id().iter() {
			write!(f, "{:02x}", i)?;
		}
		Ok(())
	}
}
macro_rules! log_funding_channel_id {
	($funding_txid: expr, $funding_txo: expr) => {
		::util::macro_logger::DebugFundingChannelId(&$funding_txid, $funding_txo)
	}
}

pub(crate) struct DebugFundingInfo<'a, T: 'a>(pub &'a (OutPoint, T));
impl<'a, T> std::fmt::Display for DebugFundingInfo<'a, T> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		DebugBytes(&(self.0).0.to_channel_id()[..]).fmt(f)
	}
}
macro_rules! log_funding_info {
	($key_storage: expr) => {
		::util::macro_logger::DebugFundingInfo(&$key_storage.funding_info)
	}
}

pub(crate) struct DebugRoute<'a>(pub &'a Route);
impl<'a> std::fmt::Display for DebugRoute<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		for (idx, p) in self.0.paths.iter().enumerate() {
			write!(f, "path {}:\n", idx)?;
			for h in p.iter() {
				write!(f, " node_id: {}, short_channel_id: {}, fee_msat: {}, cltv_expiry_delta: {}\n", log_pubkey!(h.pubkey), h.short_channel_id, h.fee_msat, h.cltv_expiry_delta)?;
			}
		}
		Ok(())
	}
}
macro_rules! log_route {
	($obj: expr) => {
		::util::macro_logger::DebugRoute(&$obj)
	}
}

pub(crate) struct DebugTx<'a>(pub &'a Transaction);
impl<'a> std::fmt::Display for DebugTx<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		if self.0.input.len() >= 1 && self.0.input.iter().any(|i| !i.witness.is_empty()) {
			if self.0.input.len() == 1 && self.0.input[0].witness.last().unwrap().len() == 71 &&
					(self.0.input[0].sequence >> 8*3) as u8 == 0x80 {
				write!(f, "commitment tx")?;
			} else if self.0.input.len() == 1 && self.0.input[0].witness.last().unwrap().len() == 71 {
				write!(f, "closing tx")?;
			} else if self.0.input.len() == 1 && HTLCType::scriptlen_to_htlctype(self.0.input[0].witness.last().unwrap().len()) == Some(HTLCType::OfferedHTLC) &&
					self.0.input[0].witness.len() == 5 {
				write!(f, "HTLC-timeout tx")?;
			} else if self.0.input.len() == 1 && HTLCType::scriptlen_to_htlctype(self.0.input[0].witness.last().unwrap().len()) == Some(HTLCType::AcceptedHTLC) &&
					self.0.input[0].witness.len() == 5 {
				write!(f, "HTLC-success tx")?;
			} else {
				for inp in &self.0.input {
					if !inp.witness.is_empty() {
						if HTLCType::scriptlen_to_htlctype(inp.witness.last().unwrap().len()) == Some(HTLCType::OfferedHTLC) { write!(f, "preimage-")?; break }
						else if HTLCType::scriptlen_to_htlctype(inp.witness.last().unwrap().len()) == Some(HTLCType::AcceptedHTLC) { write!(f, "timeout-")?; break }
					}
				}
				write!(f, "tx")?;
			}
		} else {
			write!(f, "INVALID TRANSACTION")?;
		}
		Ok(())
	}
}

macro_rules! log_tx {
	($obj: expr) => {
		::util::macro_logger::DebugTx(&$obj)
	}
}

pub(crate) struct DebugSpendable<'a>(pub &'a SpendableOutputDescriptor);
impl<'a> std::fmt::Display for DebugSpendable<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		match self.0 {
			&SpendableOutputDescriptor::StaticOutput { ref outpoint, .. } => {
				write!(f, "StaticOutput {}:{} marked for spending", outpoint.txid, outpoint.vout)?;
			}
			&SpendableOutputDescriptor::DynamicOutputP2WSH { ref outpoint, .. } => {
				write!(f, "DynamicOutputP2WSH {}:{} marked for spending", outpoint.txid, outpoint.vout)?;
			}
			&SpendableOutputDescriptor::StaticOutputRemotePayment { ref outpoint, .. } => {
				write!(f, "DynamicOutputP2WPKH {}:{} marked for spending", outpoint.txid, outpoint.vout)?;
			}
		}
		Ok(())
	}
}

macro_rules! log_spendable {
	($obj: expr) => {
		::util::macro_logger::DebugSpendable(&$obj)
	}
}

macro_rules! log_internal {
	($logger: expr, $lvl:expr, $($arg:tt)+) => (
		$logger.log(&::util::logger::Record::new($lvl, format_args!($($arg)+), module_path!(), file!(), line!()));
	);
}

macro_rules! log_error {
	($logger: expr, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off")))]
		log_internal!($logger, $crate::util::logger::Level::Error, $($arg)*);
	)
}

macro_rules! log_warn {
	($logger: expr, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error")))]
		log_internal!($logger, $crate::util::logger::Level::Warn, $($arg)*);
	)
}

macro_rules! log_info {
	($logger: expr, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn")))]
		log_internal!($logger, $crate::util::logger::Level::Info, $($arg)*);
	)
}

macro_rules! log_debug {
	($logger: expr, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info")))]
		log_internal!($logger, $crate::util::logger::Level::Debug, $($arg)*);
	)
}

macro_rules! log_trace {
	($logger: expr, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info", feature = "max_level_debug")))]
		log_internal!($logger, $crate::util::logger::Level::Trace, $($arg)*);
	)
}
