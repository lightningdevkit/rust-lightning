//! Utilities for LSPS5 service.

use alloc::string::String;
use core::fmt::Write;

use lightning::sign::EntropySource;
use lightning::util::scid_utils;

use crate::lsps0::ser::LSPSRequestId;

#[allow(dead_code)]
#[allow(unused_imports)]
pub(crate) mod async_poll;
pub mod time;

/// Converts a human-readable string representation of a short channel ID (SCID)
pub fn scid_from_human_readable_string(human_readable_scid: &str) -> Result<u64, ()> {
	let mut parts = human_readable_scid.split('x');

	let block: u64 = parts.next().ok_or(())?.parse().map_err(|_e| ())?;
	let tx_index: u64 = parts.next().ok_or(())?.parse().map_err(|_e| ())?;
	let vout_index: u64 = parts.next().ok_or(())?.parse().map_err(|_e| ())?;

	if parts.next().is_some() {
		return Err(());
	}

	scid_utils::scid_from_parts(block, tx_index, vout_index).map_err(|_e| ())
}

pub(crate) fn generate_request_id<ES: EntropySource>(entropy_source: &ES) -> LSPSRequestId {
	let bytes = entropy_source.get_secure_random_bytes();
	LSPSRequestId(hex_str(&bytes[0..16]))
}

#[inline]
/// Converts a byte slice to a hexadecimal string representation.
pub fn hex_str(value: &[u8]) -> String {
	let mut res = String::with_capacity(2 * value.len());
	for v in value {
		write!(&mut res, "{:02x}", v).expect("Unable to write");
	}
	res
}

#[cfg(test)]
mod tests {
	use super::*;
	use lightning::util::scid_utils::{block_from_scid, tx_index_from_scid, vout_from_scid};

	#[test]
	fn parses_human_readable_scid_correctly() {
		let block = 140;
		let tx_index = 123;
		let vout = 22;

		let human_readable_scid = format!("{}x{}x{}", block, tx_index, vout);

		let scid = scid_from_human_readable_string(&human_readable_scid).unwrap();

		assert_eq!(block_from_scid(scid), block);
		assert_eq!(tx_index_from_scid(scid), tx_index);
		assert_eq!(vout_from_scid(scid), vout);
	}

	#[test]
	fn parses_maximum_human_readable_scid_correctly() {
		let block = 0x00ff_ffff;
		let tx_index = 0x00ff_ffff;
		let vout = 0xffff;

		let scid =
			scid_from_human_readable_string(&format!("{}x{}x{}", block, tx_index, vout)).unwrap();

		assert_eq!(block_from_scid(scid), block);
		assert_eq!(tx_index_from_scid(scid), tx_index);
		assert_eq!(vout_from_scid(scid), vout);
	}

	#[test]
	fn rejects_human_readable_scids_with_overflowing_fields() {
		// Each field is one bit wider than it can hold.
		assert!(scid_from_human_readable_string("16777216x0x0").is_err());
		assert!(scid_from_human_readable_string("0x16777216x0").is_err());
		assert!(scid_from_human_readable_string("0x0x65536").is_err());
	}

	#[test]
	fn rejects_human_readable_scids_with_too_many_parts() {
		assert!(scid_from_human_readable_string("1x2x3x4").is_err());
	}
}
