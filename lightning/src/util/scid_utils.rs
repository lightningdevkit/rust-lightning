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
#[derive(Debug, PartialEq, Eq)]
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

/// LDK has multiple reasons to generate fake short channel ids:
/// 1) outbound SCID aliases we use for private channels
/// 2) phantom node payments, to get an scid for the phantom node's phantom channel
/// 3) payments intended to be intercepted will route using a fake scid (this is typically used so
///    the forwarding node can open a JIT channel to the next hop)
pub(crate) mod fake_scid {
	use bitcoin::hash_types::BlockHash;
	use bitcoin::hashes::hex::FromHex;
	use crate::chain::keysinterface::EntropySource;
	use crate::util::chacha20::ChaCha20;
	use crate::util::scid_utils;

	use core::convert::TryInto;
	use core::ops::Deref;

	const TEST_SEGWIT_ACTIVATION_HEIGHT: u32 = 1;
	const MAINNET_SEGWIT_ACTIVATION_HEIGHT: u32 = 481_824;
	const MAX_TX_INDEX: u32 = 2_500;
	const MAX_NAMESPACES: u8 = 8; // We allocate 3 bits for the namespace identifier.
	const NAMESPACE_ID_BITMASK: u8 = 0b111;

	const BLOCKS_PER_MONTH: u32 = 144 /* blocks per day */ * 30 /* days per month */;
	pub(crate) const MAX_SCID_BLOCKS_FROM_NOW: u32 = BLOCKS_PER_MONTH;


	/// Fake scids are divided into namespaces, with each namespace having its own identifier between
	/// [0..7]. This allows us to identify what namespace a fake scid corresponds to upon HTLC
	/// receipt, and handle the HTLC accordingly. The namespace identifier is encrypted when encoded
	/// into the fake scid.
	#[derive(Copy, Clone)]
	pub(crate) enum Namespace {
		Phantom,
		OutboundAlias,
		Intercept
	}

	impl Namespace {
		/// We generate "realistic-looking" random scids here, meaning the scid's block height is
		/// between segwit activation and the current best known height, and the tx index and output
		/// index are also selected from a "reasonable" range. We add this logic because it makes it
		/// non-obvious at a glance that the scid is fake, e.g. if it appears in invoice route hints.
		pub(crate) fn get_fake_scid<ES: Deref>(&self, highest_seen_blockheight: u32, genesis_hash: &BlockHash, fake_scid_rand_bytes: &[u8; 32], entropy_source: &ES) -> u64
			where ES::Target: EntropySource,
		{
			// Ensure we haven't created a namespace that doesn't fit into the 3 bits we've allocated for
			// namespaces.
			assert!((*self as u8) < MAX_NAMESPACES);
			let rand_bytes = entropy_source.get_secure_random_bytes();

			let segwit_activation_height = segwit_activation_height(genesis_hash);
			let mut blocks_since_segwit_activation = highest_seen_blockheight.saturating_sub(segwit_activation_height);

			// We want to ensure that this fake channel won't conflict with any transactions we haven't
			// seen yet, in case `highest_seen_blockheight` is updated before we get full information
			// about transactions confirmed in the given block.
			blocks_since_segwit_activation = blocks_since_segwit_activation.saturating_sub(MAX_SCID_BLOCKS_FROM_NOW);

			let rand_for_height = u32::from_be_bytes(rand_bytes[..4].try_into().unwrap());
			let fake_scid_height = segwit_activation_height + rand_for_height % (blocks_since_segwit_activation + 1);

			let rand_for_tx_index = u32::from_be_bytes(rand_bytes[4..8].try_into().unwrap());
			let fake_scid_tx_index = rand_for_tx_index % MAX_TX_INDEX;

			// Put the scid in the given namespace.
			let fake_scid_vout = self.get_encrypted_vout(fake_scid_height, fake_scid_tx_index, fake_scid_rand_bytes);
			scid_utils::scid_from_parts(fake_scid_height as u64, fake_scid_tx_index as u64, fake_scid_vout as u64).unwrap()
		}

		/// We want to ensure that a 3rd party can't identify a payment as belong to a given
		/// `Namespace`. Therefore, we encrypt it using a random bytes provided by `ChannelManager`.
		fn get_encrypted_vout(&self, block_height: u32, tx_index: u32, fake_scid_rand_bytes: &[u8; 32]) -> u8 {
			let mut salt = [0 as u8; 8];
			let block_height_bytes = block_height.to_be_bytes();
			salt[0..4].copy_from_slice(&block_height_bytes);
			let tx_index_bytes = tx_index.to_be_bytes();
			salt[4..8].copy_from_slice(&tx_index_bytes);

			let mut chacha = ChaCha20::new(fake_scid_rand_bytes, &salt);
			let mut vout_byte = [*self as u8];
			chacha.process_in_place(&mut vout_byte);
			vout_byte[0] & NAMESPACE_ID_BITMASK
		}
	}

	fn segwit_activation_height(genesis: &BlockHash) -> u32 {
		const MAINNET_GENESIS_STR: &'static str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
		if BlockHash::from_hex(MAINNET_GENESIS_STR).unwrap() == *genesis {
			MAINNET_SEGWIT_ACTIVATION_HEIGHT
		} else {
			TEST_SEGWIT_ACTIVATION_HEIGHT
		}
	}

	/// Returns whether the given fake scid falls into the phantom namespace.
	pub fn is_valid_phantom(fake_scid_rand_bytes: &[u8; 32], scid: u64, genesis_hash: &BlockHash) -> bool {
		let block_height = scid_utils::block_from_scid(&scid);
		let tx_index = scid_utils::tx_index_from_scid(&scid);
		let namespace = Namespace::Phantom;
		let valid_vout = namespace.get_encrypted_vout(block_height, tx_index, fake_scid_rand_bytes);
		block_height >= segwit_activation_height(genesis_hash)
			&& valid_vout == scid_utils::vout_from_scid(&scid) as u8
	}

	/// Returns whether the given fake scid falls into the intercept namespace.
	pub fn is_valid_intercept(fake_scid_rand_bytes: &[u8; 32], scid: u64, genesis_hash: &BlockHash) -> bool {
		let block_height = scid_utils::block_from_scid(&scid);
		let tx_index = scid_utils::tx_index_from_scid(&scid);
		let namespace = Namespace::Intercept;
		let valid_vout = namespace.get_encrypted_vout(block_height, tx_index, fake_scid_rand_bytes);
		block_height >= segwit_activation_height(genesis_hash)
			&& valid_vout == scid_utils::vout_from_scid(&scid) as u8
	}

	#[cfg(test)]
	mod tests {
		use bitcoin::blockdata::constants::genesis_block;
		use bitcoin::network::constants::Network;
		use crate::util::scid_utils::fake_scid::{is_valid_intercept, is_valid_phantom, MAINNET_SEGWIT_ACTIVATION_HEIGHT, MAX_TX_INDEX, MAX_NAMESPACES, Namespace, NAMESPACE_ID_BITMASK, segwit_activation_height, TEST_SEGWIT_ACTIVATION_HEIGHT};
		use crate::util::scid_utils;
		use crate::util::test_utils;
		use crate::sync::Arc;

		#[test]
		fn namespace_identifier_is_within_range() {
			let phantom_namespace = Namespace::Phantom;
			assert!((phantom_namespace as u8) < MAX_NAMESPACES);
			assert!((phantom_namespace as u8) <= NAMESPACE_ID_BITMASK);

			let intercept_namespace = Namespace::Intercept;
			assert!((intercept_namespace as u8) < MAX_NAMESPACES);
			assert!((intercept_namespace as u8) <= NAMESPACE_ID_BITMASK);
		}

		#[test]
		fn test_segwit_activation_height() {
			let mainnet_genesis = genesis_block(Network::Bitcoin).header.block_hash();
			assert_eq!(segwit_activation_height(&mainnet_genesis), MAINNET_SEGWIT_ACTIVATION_HEIGHT);

			let testnet_genesis = genesis_block(Network::Testnet).header.block_hash();
			assert_eq!(segwit_activation_height(&testnet_genesis), TEST_SEGWIT_ACTIVATION_HEIGHT);

			let signet_genesis = genesis_block(Network::Signet).header.block_hash();
			assert_eq!(segwit_activation_height(&signet_genesis), TEST_SEGWIT_ACTIVATION_HEIGHT);

			let regtest_genesis = genesis_block(Network::Regtest).header.block_hash();
			assert_eq!(segwit_activation_height(&regtest_genesis), TEST_SEGWIT_ACTIVATION_HEIGHT);
		}

		#[test]
		fn test_is_valid_phantom() {
			let namespace = Namespace::Phantom;
			let fake_scid_rand_bytes = [0; 32];
			let testnet_genesis = genesis_block(Network::Testnet).header.block_hash();
			let valid_encrypted_vout = namespace.get_encrypted_vout(0, 0, &fake_scid_rand_bytes);
			let valid_fake_scid = scid_utils::scid_from_parts(1, 0, valid_encrypted_vout as u64).unwrap();
			assert!(is_valid_phantom(&fake_scid_rand_bytes, valid_fake_scid, &testnet_genesis));
			let invalid_fake_scid = scid_utils::scid_from_parts(1, 0, 12).unwrap();
			assert!(!is_valid_phantom(&fake_scid_rand_bytes, invalid_fake_scid, &testnet_genesis));
		}

		#[test]
		fn test_is_valid_intercept() {
			let namespace = Namespace::Intercept;
			let fake_scid_rand_bytes = [0; 32];
			let testnet_genesis = genesis_block(Network::Testnet).header.block_hash();
			let valid_encrypted_vout = namespace.get_encrypted_vout(0, 0, &fake_scid_rand_bytes);
			let valid_fake_scid = scid_utils::scid_from_parts(1, 0, valid_encrypted_vout as u64).unwrap();
			assert!(is_valid_intercept(&fake_scid_rand_bytes, valid_fake_scid, &testnet_genesis));
			let invalid_fake_scid = scid_utils::scid_from_parts(1, 0, 12).unwrap();
			assert!(!is_valid_intercept(&fake_scid_rand_bytes, invalid_fake_scid, &testnet_genesis));
		}

		#[test]
		fn test_get_fake_scid() {
			let mainnet_genesis = genesis_block(Network::Bitcoin).header.block_hash();
			let seed = [0; 32];
			let fake_scid_rand_bytes = [1; 32];
			let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&seed, Network::Testnet));
			let namespace = Namespace::Phantom;
			let fake_scid = namespace.get_fake_scid(500_000, &mainnet_genesis, &fake_scid_rand_bytes, &keys_manager);

			let fake_height = scid_utils::block_from_scid(&fake_scid);
			assert!(fake_height >= MAINNET_SEGWIT_ACTIVATION_HEIGHT);
			assert!(fake_height <= 500_000);

			let fake_tx_index = scid_utils::tx_index_from_scid(&fake_scid);
			assert!(fake_tx_index <= MAX_TX_INDEX);

			let fake_vout = scid_utils::vout_from_scid(&fake_scid);
			assert!(fake_vout < MAX_NAMESPACES as u16);
		}
	}
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
