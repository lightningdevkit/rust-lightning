// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

/// Maximum block height that can be used in a `short_channel_id`. This
/// value is based on the 3-bytes available for block height.
pub const MAX_SCID_BLOCK: u64 = 0x00ffffff;

/// Maximum transaction index that can be used in a `short_channel_id`.
/// This value is based on the 3-bytes available for tx index.
pub const MAX_SCID_TX_INDEX: u64 = 0x00ffffff;

/// Maximum vout index that can be used in a `short_channel_id`. This
/// value is based on the 2-bytes available for the vout index.
pub const MAX_SCID_VOUT_INDEX: u64 = 0xffff;

/// A `short_channel_id` construction error
#[derive(Debug, PartialEq)]
pub enum ShortChannelIdError {
	BlockOverflow,
	TxIndexOverflow,
	VoutIndexOverflow,
}

/// Extracts the block height (most significant 3-bytes) from the `short_channel_id`
pub fn block_from_scid(short_channel_id: &u64) -> u32 {
	return (short_channel_id >> 40) as u32;
}

/// Extracts the tx index (bytes [2..4]) from the `short_channel_id`
pub fn tx_index_from_scid(short_channel_id: &u64) -> u32 {
	return ((short_channel_id >> 16) & MAX_SCID_TX_INDEX) as u32;
}

/// Extracts the vout (bytes [0..2]) from the `short_channel_id`
pub fn vout_from_scid(short_channel_id: &u64) -> u16 {
	return ((short_channel_id) & MAX_SCID_VOUT_INDEX) as u16;
}

/// Constructs a `short_channel_id` using the components pieces. Results in an error
/// if the block height, tx index, or vout index overflow the maximum sizes.
pub fn scid_from_parts(block: u64, tx_index: u64, vout_index: u64) -> Result<u64, ShortChannelIdError> {
	if block > MAX_SCID_BLOCK {
		return Err(ShortChannelIdError::BlockOverflow);
	}

	if tx_index > MAX_SCID_TX_INDEX {
		return Err(ShortChannelIdError::TxIndexOverflow);
	}

	if vout_index > MAX_SCID_VOUT_INDEX {
		return Err(ShortChannelIdError::VoutIndexOverflow);
	}

	Ok((block << 40) | (tx_index << 16) | vout_index)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_block_from_scid() {
		assert_eq!(block_from_scid(&0x000000_000000_0000), 0);
		assert_eq!(block_from_scid(&0x000001_000000_0000), 1);
		assert_eq!(block_from_scid(&0x000001_ffffff_ffff), 1);
		assert_eq!(block_from_scid(&0x800000_ffffff_ffff), 0x800000);
		assert_eq!(block_from_scid(&0xffffff_ffffff_ffff), 0xffffff);
	}

	#[test]
	fn test_tx_index_from_scid() {
		assert_eq!(tx_index_from_scid(&0x000000_000000_0000), 0);
		assert_eq!(tx_index_from_scid(&0x000000_000001_0000), 1);
		assert_eq!(tx_index_from_scid(&0xffffff_000001_ffff), 1);
		assert_eq!(tx_index_from_scid(&0xffffff_800000_ffff), 0x800000);
		assert_eq!(tx_index_from_scid(&0xffffff_ffffff_ffff), 0xffffff);
	}

	#[test]
	fn test_vout_from_scid() {
		assert_eq!(vout_from_scid(&0x000000_000000_0000), 0);
		assert_eq!(vout_from_scid(&0x000000_000000_0001), 1);
		assert_eq!(vout_from_scid(&0xffffff_ffffff_0001), 1);
		assert_eq!(vout_from_scid(&0xffffff_ffffff_8000), 0x8000);
		assert_eq!(vout_from_scid(&0xffffff_ffffff_ffff), 0xffff);
	}

	#[test]
	fn test_scid_from_parts() {
		assert_eq!(scid_from_parts(0x00000000, 0x00000000, 0x0000).unwrap(), 0x000000_000000_0000);
		assert_eq!(scid_from_parts(0x00000001, 0x00000002, 0x0003).unwrap(), 0x000001_000002_0003);
		assert_eq!(scid_from_parts(0x00111111, 0x00222222, 0x3333).unwrap(), 0x111111_222222_3333);
		assert_eq!(scid_from_parts(0x00ffffff, 0x00ffffff, 0xffff).unwrap(), 0xffffff_ffffff_ffff);
		assert_eq!(scid_from_parts(0x01ffffff, 0x00000000, 0x0000).err().unwrap(), ShortChannelIdError::BlockOverflow);
		assert_eq!(scid_from_parts(0x00000000, 0x01ffffff, 0x0000).err().unwrap(), ShortChannelIdError::TxIndexOverflow);
		assert_eq!(scid_from_parts(0x00000000, 0x00000000, 0x010000).err().unwrap(), ShortChannelIdError::VoutIndexOverflow);
	}
}
