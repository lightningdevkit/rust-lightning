use crate::{AsyncBlockSourceResult, BlockHeaderData, BlockSourceError, BlockSourceResult};

use bitcoin::blockdata::block::Block;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;

/// The `Poll` trait defines behavior for polling block sources for a chain tip and retrieving
/// related chain data. It serves as an adapter for `BlockSource`.
pub trait Poll {
	/// Returns a chain tip in terms of its relationship to the provided chain tip.
	fn poll_chain_tip<'a>(&'a mut self, best_known_chain_tip: ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ChainTip>;

	/// Returns the header that preceded the given header in the chain.
	fn look_up_previous_header<'a>(&'a mut self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlockHeader>;

	/// Returns the block associated with the given header.
	fn fetch_block<'a>(&'a mut self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlock>;
}

/// A chain tip relative to another chain tip in terms of block hash and chainwork.
#[derive(Clone, Debug, PartialEq)]
pub enum ChainTip {
	/// A chain tip with the same hash as another chain's tip.
	Common,

	/// A chain tip with more chainwork than another chain's tip.
	Better(ValidatedBlockHeader),

	/// A chain tip with less or equal chainwork than another chain's tip. In either case, the
	/// hashes of each tip will be different.
	Worse(ValidatedBlockHeader),
}

/// The `Validate` trait defines behavior for validating chain data.
pub(crate) trait Validate {
	/// The validated data wrapper which can be dereferenced to obtain the validated data.
	type T: std::ops::Deref<Target = Self>;

	/// Validates the chain data against the given block hash and any criteria needed to ensure that
	/// it is internally consistent.
	fn validate(self, block_hash: BlockHash) -> BlockSourceResult<Self::T>;
}

impl Validate for BlockHeaderData {
	type T = ValidatedBlockHeader;

	fn validate(self, block_hash: BlockHash) -> BlockSourceResult<Self::T> {
		self.header
			.validate_pow(&self.header.target())
			.or_else(|e| Err(BlockSourceError::persistent(e)))?;

		// TODO: Use the result of validate_pow instead of recomputing the block hash once upstream.
		if self.header.block_hash() != block_hash {
			return Err(BlockSourceError::persistent("invalid block hash"));
		}

		Ok(ValidatedBlockHeader { block_hash, inner: self })
	}
}

impl Validate for Block {
	type T = ValidatedBlock;

	fn validate(self, block_hash: BlockHash) -> BlockSourceResult<Self::T> {
		self.header
			.validate_pow(&self.header.target())
			.or_else(|e| Err(BlockSourceError::persistent(e)))?;

		// TODO: Use the result of validate_pow instead of recomputing the block hash once upstream.
		if self.block_hash() != block_hash {
			return Err(BlockSourceError::persistent("invalid block hash"));
		}

		if !self.check_merkle_root() {
			return Err(BlockSourceError::persistent("invalid merkle root"));
		}

		if !self.check_witness_commitment() {
			return Err(BlockSourceError::persistent("invalid witness commitment"));
		}

		Ok(ValidatedBlock { block_hash, inner: self })
	}
}

/// A block header with validated proof of work and corresponding block hash.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ValidatedBlockHeader {
	block_hash: BlockHash,
	inner: BlockHeaderData,
}

impl std::ops::Deref for ValidatedBlockHeader {
	type Target = BlockHeaderData;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

impl ValidatedBlockHeader {
	/// Checks that the header correctly builds on previous_header: the claimed work differential
	/// matches the actual PoW and the difficulty transition is possible, i.e., within 4x.
	fn check_builds_on(&self, previous_header: &ValidatedBlockHeader, network: Network) -> BlockSourceResult<()> {
		if self.header.prev_blockhash != previous_header.block_hash {
			return Err(BlockSourceError::persistent("invalid previous block hash"));
		}

		if self.height != previous_header.height + 1 {
			return Err(BlockSourceError::persistent("invalid block height"));
		}

		let work = self.header.work();
		if self.chainwork != previous_header.chainwork + work {
			return Err(BlockSourceError::persistent("invalid chainwork"));
		}

		if let Network::Bitcoin = network {
			if self.height % 2016 == 0 {
				let previous_work = previous_header.header.work();
				if work > (previous_work << 2) || work < (previous_work >> 2) {
					return Err(BlockSourceError::persistent("invalid difficulty transition"))
				}
			} else if self.header.bits != previous_header.header.bits {
				return Err(BlockSourceError::persistent("invalid difficulty"))
			}
		}

		Ok(())
	}
}

/// A block with validated data against its transaction list and corresponding block hash.
pub struct ValidatedBlock {
	block_hash: BlockHash,
	inner: Block,
}

impl std::ops::Deref for ValidatedBlock {
	type Target = Block;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}
