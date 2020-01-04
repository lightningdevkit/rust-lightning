use chain::transaction::OutPoint;

use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin::blockdata::transaction::Transaction;
use secp256k1::key::PublicKey;

use ln::router::Route;
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

pub(crate) struct DebugFundingChannelId<'a>(pub &'a Sha256dHash, pub u16);
impl<'a> std::fmt::Display for DebugFundingChannelId<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		for i in OutPoint::new(self.0.clone(), self.1).to_channel_id().iter() {
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

pub(crate) struct DebugFundingInfo<'a, T: 'a>(pub &'a Option<(OutPoint, T)>);
impl<'a, T> std::fmt::Display for DebugFundingInfo<'a, T> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		match self.0.as_ref() {
			Some(&(ref funding_output, _)) => DebugBytes(&funding_output.to_channel_id()[..]).fmt(f),
			None => write!(f, "without funding output set"),
		}
	}
}
macro_rules! log_funding_info {
	($key_storage: expr) => {
		match $key_storage {
			Storage::Local { ref funding_info, .. } => {
				::util::macro_logger::DebugFundingInfo(&funding_info)
			},
			Storage::Watchtower { .. } => {
				::util::macro_logger::DebugFundingInfo(&None)
			}
		}
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

macro_rules! log_internal {
	($self: ident, $lvl:expr, $($arg:tt)+) => (
		&$self.logger.log(&::util::logger::Record::new($lvl, format_args!($($arg)+), module_path!(), file!(), line!()));
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
