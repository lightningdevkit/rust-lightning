//! Utilities for LSPS5 service.

use alloc::string::String;
use core::{fmt::Write, ops::Deref};

use lightning::sign::EntropySource;

use crate::lsps0::ser::LSPSRequestId;

pub mod time;

/// Converts a human-readable string representation of a short channel ID (SCID)
pub fn scid_from_human_readable_string(human_readable_scid: &str) -> Result<u64, ()> {
	let mut parts = human_readable_scid.split('x');

	let block: u64 = parts.next().ok_or(())?.parse().map_err(|_e| ())?;
	let tx_index: u64 = parts.next().ok_or(())?.parse().map_err(|_e| ())?;
	let vout_index: u64 = parts.next().ok_or(())?.parse().map_err(|_e| ())?;

	Ok((block << 40) | (tx_index << 16) | vout_index)
}

pub(crate) fn generate_request_id<ES: Deref>(entropy_source: &ES) -> LSPSRequestId
where
	ES::Target: EntropySource,
{
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
}
