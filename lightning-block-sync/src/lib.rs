//! A lightweight client for keeping in sync with chain activity.
//!
//! Defines a [`BlockSource`] trait, which is an asynchronous interface for retrieving block headers
//! and data.
//!
//! Enabling feature `rest-client` or `rpc-client` allows configuring the client to fetch blocks
//! using Bitcoin Core's REST or RPC interface, respectively.
//!
//! Both features support either blocking I/O using `std::net::TcpStream` or, with feature `tokio`,
//! non-blocking I/O using `tokio::net::TcpStream` from inside a Tokio runtime.
//!
//! [`BlockSource`]: trait.BlockSource.html

#[cfg(any(feature = "rest-client", feature = "rpc-client"))]
pub mod http;

pub mod poll;

#[cfg(feature = "rest-client")]
pub mod rest;

#[cfg(feature = "rpc-client")]
pub mod rpc;

#[cfg(any(feature = "rest-client", feature = "rpc-client"))]
mod convert;

#[cfg(test)]
mod test_utils;

#[cfg(any(feature = "rest-client", feature = "rpc-client"))]
mod utils;

use crate::poll::{Poll, ValidatedBlockHeader};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::hash_types::BlockHash;
use bitcoin::util::uint::Uint256;

use std::future::Future;
use std::pin::Pin;

/// Abstract type for retrieving block headers and data.
pub trait BlockSource : Sync + Send {
	/// Returns the header for a given hash. A height hint may be provided in case a block source
	/// cannot easily find headers based on a hash. This is merely a hint and thus the returned
	/// header must have the same hash as was requested. Otherwise, an error must be returned.
	///
	/// Implementations that cannot find headers based on the hash should return a `Transient` error
	/// when `height_hint` is `None`.
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData>;

	/// Returns the block for a given hash. A headers-only block source should return a `Transient`
	/// error.
	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block>;

	// TODO: Phrase in terms of `Poll` once added.
	/// Returns the hash of the best block and, optionally, its height. When polling a block source,
	/// the height is passed to `get_header` to allow for a more efficient lookup.
	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)>;
}

/// Result type for `BlockSource` requests.
type BlockSourceResult<T> = Result<T, BlockSourceError>;

// TODO: Replace with BlockSourceResult once `async` trait functions are supported. For details,
// see: https://areweasyncyet.rs.
/// Result type for asynchronous `BlockSource` requests.
type AsyncBlockSourceResult<'a, T> = Pin<Box<dyn Future<Output = BlockSourceResult<T>> + 'a + Send>>;

/// Error type for `BlockSource` requests.
///
/// Transient errors may be resolved when re-polling, but no attempt will be made to re-poll on
/// persistent errors.
#[derive(Debug)]
pub struct BlockSourceError {
	kind: BlockSourceErrorKind,
	error: Box<dyn std::error::Error + Send + Sync>,
}

/// The kind of `BlockSourceError`, either persistent or transient.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BlockSourceErrorKind {
	/// Indicates an error that won't resolve when retrying a request (e.g., invalid data).
	Persistent,

	/// Indicates an error that may resolve when retrying a request (e.g., unresponsive).
	Transient,
}

impl BlockSourceError {
	/// Creates a new persistent error originated from the given error.
	pub fn persistent<E>(error: E) -> Self
	where E: Into<Box<dyn std::error::Error + Send + Sync>> {
		Self {
			kind: BlockSourceErrorKind::Persistent,
			error: error.into(),
		}
	}

	/// Creates a new transient error originated from the given error.
	pub fn transient<E>(error: E) -> Self
	where E: Into<Box<dyn std::error::Error + Send + Sync>> {
		Self {
			kind: BlockSourceErrorKind::Transient,
			error: error.into(),
		}
	}

	/// Returns the kind of error.
	pub fn kind(&self) -> BlockSourceErrorKind {
		self.kind
	}

	/// Converts the error into the underlying error.
	pub fn into_inner(self) -> Box<dyn std::error::Error + Send + Sync> {
		self.error
	}
}

/// A block header and some associated data. This information should be available from most block
/// sources (and, notably, is available in Bitcoin Core's RPC and REST interfaces).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BlockHeaderData {
	/// The block header itself.
	pub header: BlockHeader,

	/// The block height where the genesis block has height 0.
	pub height: u32,

	/// The total chain work in expected number of double-SHA256 hashes required to build a chain
	/// of equivalent weight.
	pub chainwork: Uint256,
}

/// Adaptor used for notifying when blocks have been connected or disconnected from the chain.
///
/// Used when needing to replay chain data upon startup or as new chain events occur.
pub trait ChainListener {
	/// Notifies the listener that a block was added at the given height.
	fn block_connected(&mut self, block: &Block, height: u32);

	/// Notifies the listener that a block was removed at the given height.
	fn block_disconnected(&mut self, header: &BlockHeader, height: u32);
}

/// The `Cache` trait defines behavior for managing a block header cache, where block headers are
/// keyed by block hash.
///
/// Used by [`ChainNotifier`] to store headers along the best chain, which is important for ensuring
/// that blocks can be disconnected if they are no longer accessible from a block source (e.g., if
/// the block source does not store stale forks indefinitely).
///
/// Implementations may define how long to retain headers such that it's unlikely they will ever be
/// needed to disconnect a block.  In cases where block sources provide access to headers on stale
/// forks reliably, caches may be entirely unnecessary.
///
/// [`ChainNotifier`]: struct.ChainNotifier.html
pub trait Cache {
	/// Retrieves the block header keyed by the given block hash.
	fn look_up(&self, block_hash: &BlockHash) -> Option<&ValidatedBlockHeader>;

	/// Called when a block has been connected to the best chain to ensure it is available to be
	/// disconnected later if needed.
	fn block_connected(&mut self, block_hash: BlockHash, block_header: ValidatedBlockHeader);

	/// Called when a block has been disconnected from the best chain. Once disconnected, a block's
	/// header is no longer needed and thus can be removed.
	fn block_disconnected(&mut self, block_hash: &BlockHash) -> Option<ValidatedBlockHeader>;
}

/// Unbounded cache of block headers keyed by block hash.
pub type UnboundedCache = std::collections::HashMap<BlockHash, ValidatedBlockHeader>;

impl Cache for UnboundedCache {
	fn look_up(&self, block_hash: &BlockHash) -> Option<&ValidatedBlockHeader> {
		self.get(block_hash)
	}

	fn block_connected(&mut self, block_hash: BlockHash, block_header: ValidatedBlockHeader) {
		self.insert(block_hash, block_header);
	}

	fn block_disconnected(&mut self, block_hash: &BlockHash) -> Option<ValidatedBlockHeader> {
		self.remove(block_hash)
	}
}

/// Notifies [listeners] of blocks that have been connected or disconnected from the chain.
///
/// [listeners]: trait.ChainListener.html
struct ChainNotifier<C: Cache> {
	/// Cache for looking up headers before fetching from a block source.
	header_cache: C,
}

/// Changes made to the chain between subsequent polls that transformed it from having one chain tip
/// to another.
///
/// Blocks are given in height-descending order. Therefore, blocks are first disconnected in order
/// before new blocks are connected in reverse order.
struct ChainDifference {
	/// Blocks that were disconnected from the chain since the last poll.
	disconnected_blocks: Vec<ValidatedBlockHeader>,

	/// Blocks that were connected to the chain since the last poll.
	connected_blocks: Vec<ValidatedBlockHeader>,
}

impl<C: Cache> ChainNotifier<C> {
	/// Finds the fork point between `new_header` and `old_header`, disconnecting blocks from
	/// `old_header` to get to that point and then connecting blocks until `new_header`.
	///
	/// Validates headers along the transition path, but doesn't fetch blocks until the chain is
	/// disconnected to the fork point. Thus, this may return an `Err` that includes where the tip
	/// ended up which may not be `new_header`. Note that the returned `Err` contains `Some` header
	/// if and only if the transition from `old_header` to `new_header` is valid.
	async fn synchronize_listener<L: ChainListener, P: Poll>(
		&mut self,
		new_header: ValidatedBlockHeader,
		old_header: &ValidatedBlockHeader,
		chain_poller: &mut P,
		chain_listener: &mut L,
	) -> Result<(), (BlockSourceError, Option<ValidatedBlockHeader>)> {
		let mut difference = self.find_difference(new_header, old_header, chain_poller).await
			.map_err(|e| (e, None))?;

		let mut new_tip = *old_header;
		for header in difference.disconnected_blocks.drain(..) {
			if let Some(cached_header) = self.header_cache.block_disconnected(&header.block_hash) {
				assert_eq!(cached_header, header);
			}
			chain_listener.block_disconnected(&header.header, header.height);
			new_tip = header;
		}

		for header in difference.connected_blocks.drain(..).rev() {
			let block = chain_poller
				.fetch_block(&header).await
				.or_else(|e| Err((e, Some(new_tip))))?;
			debug_assert_eq!(block.block_hash, header.block_hash);

			self.header_cache.block_connected(header.block_hash, header);
			chain_listener.block_connected(&block, header.height);
			new_tip = header;
		}

		Ok(())
	}

	/// Returns the changes needed to produce the chain with `current_header` as its tip from the
	/// chain with `prev_header` as its tip.
	///
	/// Walks backwards from `current_header` and `prev_header`, finding the common ancestor.
	async fn find_difference<P: Poll>(
		&self,
		current_header: ValidatedBlockHeader,
		prev_header: &ValidatedBlockHeader,
		chain_poller: &mut P,
	) -> BlockSourceResult<ChainDifference> {
		let mut disconnected_blocks = Vec::new();
		let mut connected_blocks = Vec::new();
		let mut current = current_header;
		let mut previous = *prev_header;
		loop {
			// Found the common ancestor.
			if current.block_hash == previous.block_hash {
				break;
			}

			// Walk back the chain, finding blocks needed to connect and disconnect. Only walk back
			// the header with the greater height, or both if equal heights.
			let current_height = current.height;
			let previous_height = previous.height;
			if current_height <= previous_height {
				disconnected_blocks.push(previous);
				previous = self.look_up_previous_header(chain_poller, &previous).await?;
			}
			if current_height >= previous_height {
				connected_blocks.push(current);
				current = self.look_up_previous_header(chain_poller, &current).await?;
			}
		}

		Ok(ChainDifference { disconnected_blocks, connected_blocks })
	}

	/// Returns the previous header for the given header, either by looking it up in the cache or
	/// fetching it if not found.
	async fn look_up_previous_header<P: Poll>(
		&self,
		chain_poller: &mut P,
		header: &ValidatedBlockHeader,
	) -> BlockSourceResult<ValidatedBlockHeader> {
		match self.header_cache.look_up(&header.header.prev_blockhash) {
			Some(prev_header) => Ok(*prev_header),
			None => chain_poller.look_up_previous_header(header).await,
		}
	}
}

#[cfg(test)]
mod chain_notifier_tests {
	use crate::test_utils::{Blockchain, MockChainListener};
	use super::*;

	use bitcoin::network::constants::Network;

	#[tokio::test]
	async fn sync_from_same_chain() {
		let mut chain = Blockchain::default().with_height(3);

		let new_tip = chain.tip();
		let old_tip = chain.at_height(1);
		let mut listener = MockChainListener::new()
			.expect_block_connected(*chain.at_height(2))
			.expect_block_connected(*new_tip);
		let mut notifier = ChainNotifier { header_cache: chain.header_cache(0..=1) };
		let mut poller = poll::ChainPoller::new(&mut chain, Network::Testnet);
		match notifier.synchronize_listener(new_tip, &old_tip, &mut poller, &mut listener).await {
			Err((e, _)) => panic!("Unexpected error: {:?}", e),
			Ok(_) => {},
		}
	}

	#[tokio::test]
	async fn sync_from_different_chains() {
		let mut test_chain = Blockchain::with_network(Network::Testnet).with_height(1);
		let main_chain = Blockchain::with_network(Network::Bitcoin).with_height(1);

		let new_tip = test_chain.tip();
		let old_tip = main_chain.tip();
		let mut listener = MockChainListener::new();
		let mut notifier = ChainNotifier { header_cache: main_chain.header_cache(0..=1) };
		let mut poller = poll::ChainPoller::new(&mut test_chain, Network::Testnet);
		match notifier.synchronize_listener(new_tip, &old_tip, &mut poller, &mut listener).await {
			Err((e, _)) => {
				assert_eq!(e.kind(), BlockSourceErrorKind::Persistent);
				assert_eq!(e.into_inner().as_ref().to_string(), "genesis block reached");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn sync_from_equal_length_fork() {
		let main_chain = Blockchain::default().with_height(2);
		let mut fork_chain = main_chain.fork_at_height(1);

		let new_tip = fork_chain.tip();
		let old_tip = main_chain.tip();
		let mut listener = MockChainListener::new()
			.expect_block_disconnected(*old_tip)
			.expect_block_connected(*new_tip);
		let mut notifier = ChainNotifier { header_cache: main_chain.header_cache(0..=2) };
		let mut poller = poll::ChainPoller::new(&mut fork_chain, Network::Testnet);
		match notifier.synchronize_listener(new_tip, &old_tip, &mut poller, &mut listener).await {
			Err((e, _)) => panic!("Unexpected error: {:?}", e),
			Ok(_) => {},
		}
	}

	#[tokio::test]
	async fn sync_from_shorter_fork() {
		let main_chain = Blockchain::default().with_height(3);
		let mut fork_chain = main_chain.fork_at_height(1);
		fork_chain.disconnect_tip();

		let new_tip = fork_chain.tip();
		let old_tip = main_chain.tip();
		let mut listener = MockChainListener::new()
			.expect_block_disconnected(*old_tip)
			.expect_block_disconnected(*main_chain.at_height(2))
			.expect_block_connected(*new_tip);
		let mut notifier = ChainNotifier { header_cache: main_chain.header_cache(0..=3) };
		let mut poller = poll::ChainPoller::new(&mut fork_chain, Network::Testnet);
		match notifier.synchronize_listener(new_tip, &old_tip, &mut poller, &mut listener).await {
			Err((e, _)) => panic!("Unexpected error: {:?}", e),
			Ok(_) => {},
		}
	}

	#[tokio::test]
	async fn sync_from_longer_fork() {
		let mut main_chain = Blockchain::default().with_height(3);
		let mut fork_chain = main_chain.fork_at_height(1);
		main_chain.disconnect_tip();

		let new_tip = fork_chain.tip();
		let old_tip = main_chain.tip();
		let mut listener = MockChainListener::new()
			.expect_block_disconnected(*old_tip)
			.expect_block_connected(*fork_chain.at_height(2))
			.expect_block_connected(*new_tip);
		let mut notifier = ChainNotifier { header_cache: main_chain.header_cache(0..=2) };
		let mut poller = poll::ChainPoller::new(&mut fork_chain, Network::Testnet);
		match notifier.synchronize_listener(new_tip, &old_tip, &mut poller, &mut listener).await {
			Err((e, _)) => panic!("Unexpected error: {:?}", e),
			Ok(_) => {},
		}
	}

	#[tokio::test]
	async fn sync_from_chain_without_headers() {
		let mut chain = Blockchain::default().with_height(3).without_headers();

		let new_tip = chain.tip();
		let old_tip = chain.at_height(1);
		let mut listener = MockChainListener::new();
		let mut notifier = ChainNotifier { header_cache: chain.header_cache(0..=1) };
		let mut poller = poll::ChainPoller::new(&mut chain, Network::Testnet);
		match notifier.synchronize_listener(new_tip, &old_tip, &mut poller, &mut listener).await {
			Err((_, tip)) => assert_eq!(tip, None),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn sync_from_chain_without_any_new_blocks() {
		let mut chain = Blockchain::default().with_height(3).without_blocks(2..);

		let new_tip = chain.tip();
		let old_tip = chain.at_height(1);
		let mut listener = MockChainListener::new();
		let mut notifier = ChainNotifier { header_cache: chain.header_cache(0..=3) };
		let mut poller = poll::ChainPoller::new(&mut chain, Network::Testnet);
		match notifier.synchronize_listener(new_tip, &old_tip, &mut poller, &mut listener).await {
			Err((_, tip)) => assert_eq!(tip, Some(old_tip)),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn sync_from_chain_without_some_new_blocks() {
		let mut chain = Blockchain::default().with_height(3).without_blocks(3..);

		let new_tip = chain.tip();
		let old_tip = chain.at_height(1);
		let mut listener = MockChainListener::new()
			.expect_block_connected(*chain.at_height(2));
		let mut notifier = ChainNotifier { header_cache: chain.header_cache(0..=3) };
		let mut poller = poll::ChainPoller::new(&mut chain, Network::Testnet);
		match notifier.synchronize_listener(new_tip, &old_tip, &mut poller, &mut listener).await {
			Err((_, tip)) => assert_eq!(tip, Some(chain.at_height(2))),
			Ok(_) => panic!("Expected error"),
		}
	}
}
