// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

/// A `short_channel_id` construction error
#[derive(Debug, PartialEq)]
pub enum ShortChannelIdError {
	BlockOverflow,
	TxIndexOverflow,
}

/// Extracts the block height (most significant 3-bytes) from the `short_channel_id`
#[allow(dead_code)]
pub fn block_from_scid(short_channel_id: &u64) -> u32 {
	return (short_channel_id >> 40) as u32;
}

/// Constructs a `short_channel_id` using the components pieces. Results in an error
/// if the block height or tx index overflow the 3-bytes for each component.
#[allow(dead_code)]
pub fn scid_from_parts(block: u32, tx_index: u32, vout_index: u16) -> Result<u64, ShortChannelIdError> {
	if block > 0x00ffffff {
		return Err(ShortChannelIdError::BlockOverflow);
	}

	if	tx_index > 0x00ffffff {
		return Err(ShortChannelIdError::TxIndexOverflow);
	}

	Ok(((block as u64) << 40) | ((tx_index as u64) << 16) | (vout_index as u64))
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
	fn test_scid_from_parts() {
		assert_eq!(scid_from_parts(0x00000000, 0x00000000, 0x0000).unwrap(), 0x000000_000000_0000);
		assert_eq!(scid_from_parts(0x00000001, 0x00000002, 0x0003).unwrap(), 0x000001_000002_0003);
		assert_eq!(scid_from_parts(0x00111111, 0x00222222, 0x3333).unwrap(), 0x111111_222222_3333);
		assert_eq!(scid_from_parts(0x00ffffff, 0x00ffffff, 0xffff).unwrap(), 0xffffff_ffffff_ffff);
		assert_eq!(scid_from_parts(0x01ffffff, 0x00000000, 0x0000).err().unwrap(), ShortChannelIdError::BlockOverflow);
		assert_eq!(scid_from_parts(0x00000000, 0x01ffffff, 0x0000).err().unwrap(), ShortChannelIdError::TxIndexOverflow);
	}
}
