use chain::transaction::OutPoint;

use bitcoin::util::hash::Sha256dHash;
use secp256k1::key::PublicKey;

use ln::router::Route;

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

pub(crate) struct DebugBytes<'a>(pub &'a [u8; 32]);
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

#[allow(dead_code)]
pub(crate) struct DebugRoute<'a>(pub &'a Route);
impl<'a> std::fmt::Display for DebugRoute<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		for (i,h) in self.0.hops.iter().enumerate() {
			write!(f, "Hop {}\n pubkey {}\n short_channel_id {}\n fee_msat {}\n cltv_expiry_delta {}\n\n", i, log_pubkey!(h.pubkey), h.short_channel_id, h.fee_msat, h.cltv_expiry_delta)?;
		}
		Ok(())
	}
}
#[allow(unused_macros)]
macro_rules! log_route {
	($obj: expr) => {
		::util::macro_logger::DebugRoute(&$obj)
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
