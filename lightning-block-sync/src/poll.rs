//! Adapters that make one or more [`BlockSource`]s simpler to poll for new chain tip transitions.

use crate::{AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, BlockSourceError, BlockSourceResult};

use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;
use lightning::chain::BestBlock;

use std::ops::Deref;

/// The `Poll` trait defines behavior for polling block sources for a chain tip and retrieving
/// related chain data. It serves as an adapter for `BlockSource`.
///
/// [`ChainPoller`] adapts a single `BlockSource`, while any other implementations of `Poll` are
/// required to be built in terms of it to ensure chain data validity.
///
/// [`ChainPoller`]: ../struct.ChainPoller.html
pub trait Poll {
	/// Returns a chain tip in terms of its relationship to the provided chain tip.
	fn poll_chain_tip<'a>(&'a self, best_known_chain_tip: ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ChainTip>;

	/// Returns the header that preceded the given header in the chain.
	fn look_up_previous_header<'a>(&'a self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlockHeader>;

	/// Returns the block associated with the given header.
	fn fetch_block<'a>(&'a self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlock>;
}

/// A chain tip relative to another chain tip in terms of block hash and chainwork.
#[derive(Clone, Debug, PartialEq, Eq)]
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
///
/// This trait is sealed and not meant to be implemented outside of this crate.
pub trait Validate: sealed::Validate {
	/// The validated data wrapper which can be dereferenced to obtain the validated data.
	type T: std::ops::Deref<Target = Self>;

	/// Validates the chain data against the given block hash and any criteria needed to ensure that
	/// it is internally consistent.
	fn validate(self, block_hash: BlockHash) -> BlockSourceResult<Self::T>;
}

impl Validate for BlockHeaderData {
	type T = ValidatedBlockHeader;

	fn validate(self, block_hash: BlockHash) -> BlockSourceResult<Self::T> {
		let pow_valid_block_hash = self.header
			.validate_pow(&self.header.target())
			.or_else(|e| Err(BlockSourceError::persistent(e)))?;

		if pow_valid_block_hash != block_hash {
			return Err(BlockSourceError::persistent("invalid block hash"));
		}

		Ok(ValidatedBlockHeader { block_hash, inner: self })
	}
}

impl Validate for BlockData {
	type T = ValidatedBlock;

	fn validate(self, block_hash: BlockHash) -> BlockSourceResult<Self::T> {
		let header = match &self {
			BlockData::FullBlock(block) => &block.header,
			BlockData::HeaderOnly(header) => header,
		};

		let pow_valid_block_hash = header
			.validate_pow(&header.target())
			.or_else(|e| Err(BlockSourceError::persistent(e)))?;

		if pow_valid_block_hash != block_hash {
			return Err(BlockSourceError::persistent("invalid block hash"));
		}

		if let BlockData::FullBlock(block) = &self {
			if !block.check_merkle_root() {
				return Err(BlockSourceError::persistent("invalid merkle root"));
			}

			if !block.check_witness_commitment() {
				return Err(BlockSourceError::persistent("invalid witness commitment"));
			}
		}

		Ok(ValidatedBlock { block_hash, inner: self })
	}
}

/// A block header with validated proof of work and corresponding block hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedBlockHeader {
	pub(crate) block_hash: BlockHash,
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

    /// Returns the [`BestBlock`] corresponding to this validated block header, which can be passed
    /// into [`ChannelManager::new`] as part of its [`ChainParameters`]. Useful for ensuring that
    /// the [`SpvClient`] and [`ChannelManager`] are initialized to the same block during a fresh
    /// start.
    ///
    /// [`SpvClient`]: crate::SpvClient
    /// [`ChainParameters`]: lightning::ln::channelmanager::ChainParameters
    /// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
    /// [`ChannelManager::new`]: lightning::ln::channelmanager::ChannelManager::new
    pub fn to_best_block(&self) -> BestBlock {
        BestBlock::new(self.block_hash, self.inner.height)
    }
}

/// A block with validated data against its transaction list and corresponding block hash.
pub struct ValidatedBlock {
	pub(crate) block_hash: BlockHash,
	inner: BlockData,
}

impl std::ops::Deref for ValidatedBlock {
	type Target = BlockData;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

mod sealed {
	/// Used to prevent implementing [`super::Validate`] outside the crate but still allow its use.
	pub trait Validate {}

	impl Validate for crate::BlockHeaderData {}
	impl Validate for crate::BlockData {}
}

/// The canonical `Poll` implementation used for a single `BlockSource`.
///
/// Other `Poll` implementations should be built using `ChainPoller` as it provides the simplest way
/// of validating chain data and checking consistency.
pub struct ChainPoller<B: Deref<Target=T> + Sized + Send + Sync, T: BlockSource + ?Sized> {
	block_source: B,
	network: Network,
}

impl<B: Deref<Target=T> + Sized + Send + Sync, T: BlockSource + ?Sized> ChainPoller<B, T> {
	/// Creates a new poller for the given block source.
	///
	/// If the `network` parameter is mainnet, then the difficulty between blocks is checked for
	/// validity.
	pub fn new(block_source: B, network: Network) -> Self {
		Self { block_source, network }
	}
}

impl<B: Deref<Target=T> + Sized + Send + Sync, T: BlockSource + ?Sized> Poll for ChainPoller<B, T> {
	fn poll_chain_tip<'a>(&'a self, best_known_chain_tip: ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ChainTip>
	{
		Box::pin(async move {
			let (block_hash, height) = self.block_source.get_best_block().await?;
			if block_hash == best_known_chain_tip.header.block_hash() {
				return Ok(ChainTip::Common);
			}

			let chain_tip = self.block_source
				.get_header(&block_hash, height).await?
				.validate(block_hash)?;
			if chain_tip.chainwork > best_known_chain_tip.chainwork {
				Ok(ChainTip::Better(chain_tip))
			} else {
				Ok(ChainTip::Worse(chain_tip))
			}
		})
	}

	fn look_up_previous_header<'a>(&'a self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlockHeader>
	{
		Box::pin(async move {
			if header.height == 0 {
				return Err(BlockSourceError::persistent("genesis block reached"));
			}

			let previous_hash = &header.header.prev_blockhash;
			let height = header.height - 1;
			let previous_header = self.block_source
				.get_header(previous_hash, Some(height)).await?
				.validate(*previous_hash)?;
			header.check_builds_on(&previous_header, self.network)?;

			Ok(previous_header)
		})
	}

	fn fetch_block<'a>(&'a self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlock>
	{
		Box::pin(async move {
			self.block_source
				.get_block(&header.block_hash).await?
				.validate(header.block_hash)
		})
	}
}

#[cfg(test)]
mod tests {
	use crate::*;
	use crate::test_utils::Blockchain;
	use super::*;
	use bitcoin::util::uint::Uint256;

	#[tokio::test]
	async fn poll_empty_chain() {
		let mut chain = Blockchain::default().with_height(0);
		let best_known_chain_tip = chain.tip();
		chain.disconnect_tip();

		let poller = ChainPoller::new(&chain, Network::Bitcoin);
		match poller.poll_chain_tip(best_known_chain_tip).await {
			Err(e) => {
				assert_eq!(e.kind(), BlockSourceErrorKind::Transient);
				assert_eq!(e.into_inner().as_ref().to_string(), "empty chain");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_without_headers() {
		let chain = Blockchain::default().with_height(1).without_headers();
		let best_known_chain_tip = chain.at_height(0);

		let poller = ChainPoller::new(&chain, Network::Bitcoin);
		match poller.poll_chain_tip(best_known_chain_tip).await {
			Err(e) => {
				assert_eq!(e.kind(), BlockSourceErrorKind::Persistent);
				assert_eq!(e.into_inner().as_ref().to_string(), "header not found");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_invalid_pow() {
		let mut chain = Blockchain::default().with_height(1);
		let best_known_chain_tip = chain.at_height(0);

		// Invalidate the tip by changing its target.
		chain.blocks.last_mut().unwrap().header.bits =
			BlockHeader::compact_target_from_u256(&Uint256::from_be_bytes([0; 32]));

		let poller = ChainPoller::new(&chain, Network::Bitcoin);
		match poller.poll_chain_tip(best_known_chain_tip).await {
			Err(e) => {
				assert_eq!(e.kind(), BlockSourceErrorKind::Persistent);
				assert_eq!(e.into_inner().as_ref().to_string(), "block target correct but not attained");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_malformed_headers() {
		let chain = Blockchain::default().with_height(1).malformed_headers();
		let best_known_chain_tip = chain.at_height(0);

		let poller = ChainPoller::new(&chain, Network::Bitcoin);
		match poller.poll_chain_tip(best_known_chain_tip).await {
			Err(e) => {
				assert_eq!(e.kind(), BlockSourceErrorKind::Persistent);
				assert_eq!(e.into_inner().as_ref().to_string(), "invalid block hash");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_common_tip() {
		let chain = Blockchain::default().with_height(0);
		let best_known_chain_tip = chain.tip();

		let poller = ChainPoller::new(&chain, Network::Bitcoin);
		match poller.poll_chain_tip(best_known_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tip) => assert_eq!(tip, ChainTip::Common),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_uncommon_tip_but_equal_chainwork() {
		let mut chain = Blockchain::default().with_height(1);
		let best_known_chain_tip = chain.tip();

		// Change the nonce to get a different block hash with the same chainwork.
		chain.blocks.last_mut().unwrap().header.nonce += 1;
		let worse_chain_tip = chain.tip();
		assert_eq!(best_known_chain_tip.chainwork, worse_chain_tip.chainwork);

		let poller = ChainPoller::new(&chain, Network::Bitcoin);
		match poller.poll_chain_tip(best_known_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tip) => assert_eq!(tip, ChainTip::Worse(worse_chain_tip)),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_worse_tip() {
		let mut chain = Blockchain::default().with_height(1);
		let best_known_chain_tip = chain.tip();

		chain.disconnect_tip();
		let worse_chain_tip = chain.tip();

		let poller = ChainPoller::new(&chain, Network::Bitcoin);
		match poller.poll_chain_tip(best_known_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tip) => assert_eq!(tip, ChainTip::Worse(worse_chain_tip)),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_better_tip() {
		let chain = Blockchain::default().with_height(1);
		let best_known_chain_tip = chain.at_height(0);

		let better_chain_tip = chain.tip();

		let poller = ChainPoller::new(&chain, Network::Bitcoin);
		match poller.poll_chain_tip(best_known_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tip) => assert_eq!(tip, ChainTip::Better(better_chain_tip)),
		}
	}
}
