//! An implementation of a simple SPV client which can interrogate abstract block sources to keep
//! lightning objects on the best chain.
//!
//! With feature `rpc-client` we provide a client which can fetch blocks from Bitcoin Core's RPC
//! interface.
//!
//! With feature `rest-client` we provide a client which can fetch blocks from Bitcoin Core's REST
//! interface.
//!
//! Both provided clients support either blocking TCP reads from std::net::TcpStream or, with
//! feature `tokio`, tokio::net::TcpStream inside a Tokio runtime.

#[cfg(any(feature = "rest-client", feature = "rpc-client"))]
pub mod http_clients;

#[cfg(any(feature = "rest-client", feature = "rpc-client"))]
pub mod http_endpoint;

pub mod poller;

#[cfg(test)]
mod test_utils;

#[cfg(any(feature = "rest-client", feature = "rpc-client"))]
mod utils;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::hex::ToHex;
use bitcoin::network::constants::Network;
use bitcoin::util::uint::Uint256;

use lightning::chain;
use lightning::chain::{chaininterface, keysinterface};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::ln::channelmanager::SimpleArcChannelManager;
use lightning::util::logger;

use std::future::Future;
use std::pin::Pin;
use std::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq)]
/// A block header and some associated data. This information should be available from most block
/// sources (and, notably, is available in Bitcoin Core's RPC and REST interfaces).
pub struct BlockHeaderData {
	/// The total chain work, in expected number of double-SHA256 hashes required to build a chain
	/// of equivalent weight
	pub chainwork: Uint256,
	/// The block height, with the genesis block heigh set to 0
	pub height: u32,
	/// The block header itself
	pub header: BlockHeader
}

/// Result type for `BlockSource` requests.
type BlockSourceResult<T> = Result<T, BlockSourceError>;

/// Result type for asynchronous `BlockSource` requests.
///
/// TODO: Replace with BlockSourceResult once async trait functions are supported. For details, see:
/// https://areweasyncyet.rs.
type AsyncBlockSourceResult<'a, T> = Pin<Box<dyn Future<Output = BlockSourceResult<T>> + 'a + Send>>;

/// Error type for requests made to a `BlockSource`.
///
/// Transient errors may be resolved when re-polling, but no attempt will be made to re-poll on
/// persistent errors.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BlockSourceError {
	/// Indicates an error that won't resolve when retrying a request (e.g., invalid data).
	Persistent,
	/// Indicates an error that may resolve when retrying a request (e.g., unresponsive).
	Transient,
}

/// Abstract type for a source of block header and block data.
pub trait BlockSource : Sync + Send {
	/// Gets the header for a given hash. The height the header should be at is provided, though
	/// note that you must return either the header with the requested hash, or an Err, not a
	/// different header with the same eight.
	///
	/// For sources which cannot find headers based on the hash, returning Transient when
	/// height_hint is None is fine, though get_best_block() should never return a None for height
	/// on the same source. Such a source should never be used in init_sync_chain_monitor as it
	/// doesn't have any initial height information.
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData>;

	/// Gets the block for a given hash. BlockSources may be headers-only, in which case they
	/// should always return Err(BlockSourceError::Transient) here.
	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block>;

	/// Gets the best block hash and, optionally, its height.
	/// Including the height doesn't impact the chain-scannling algorithm, but it is passed to
	/// get_header() which may allow some BlockSources to more effeciently find the target header.
	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)>;
}

/// The `Poll` trait defines behavior for polling block sources for a chain tip and retrieving
/// related chain data. It serves as an adapter for `BlockSource`.
pub trait Poll {
	/// Returns a chain tip in terms of its relationship to the provided chain tip.
	fn poll_chain_tip<'a>(&'a mut self, best_chain_tip: ValidatedBlockHeader) ->
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
trait Validate {
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
			.or(Err(BlockSourceError::Persistent))?;

		if self.header.block_hash() != block_hash {
			return Err(BlockSourceError::Persistent);
		}

		Ok(ValidatedBlockHeader { block_hash, inner: self })
	}
}

impl Validate for Block {
	type T = ValidatedBlock;

	fn validate(self, block_hash: BlockHash) -> BlockSourceResult<Self::T> {
		if self.block_hash() != block_hash {
			return Err(BlockSourceError::Persistent);
		}

		if !self.check_merkle_root() || !self.check_witness_commitment() {
			return Err(BlockSourceError::Persistent);
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
	/// Checks that the header correctly builds on previous_header - the claimed work differential
	/// matches the actual PoW in child_header and the difficulty transition is possible, ie within 4x.
	fn check_builds_on(&self, previous_header: &ValidatedBlockHeader, network: Network) -> BlockSourceResult<()> {
		if self.header.prev_blockhash != previous_header.block_hash {
			return Err(BlockSourceError::Persistent);
		}

		if self.height != previous_header.height + 1 {
			return Err(BlockSourceError::Persistent);
		}

		let work = self.header.work();
		if self.chainwork != previous_header.chainwork + work {
			return Err(BlockSourceError::Persistent);
		}

		if let Network::Bitcoin = network {
			if self.height % 2016 == 0 {
				let previous_work = previous_header.header.work();
				if work > previous_work << 2 || work < previous_work >> 2 {
					return Err(BlockSourceError::Persistent)
				}
			} else if self.header.bits != previous_header.header.bits {
				return Err(BlockSourceError::Persistent)
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

async fn look_up_prev_header<P: Poll>(chain_poller: &mut P, header: &ValidatedBlockHeader, cache: &HeaderCache) -> BlockSourceResult<ValidatedBlockHeader> {
	match cache.get(&header.header.prev_blockhash) {
		Some(prev_header) => Ok(*prev_header),
		None => chain_poller.look_up_previous_header(header).await,
	}
}

enum ForkStep {
	ForkPoint(ValidatedBlockHeader),
	DisconnectBlock(ValidatedBlockHeader),
	ConnectBlock(ValidatedBlockHeader),
}

/// Walks backwards from `current_header` and `prev_header`, finding the common ancestor. Returns
/// the steps needed to produce the chain with `current_header` as its tip from the chain with
/// `prev_header` as its tip. There is no ordering guarantee between different ForkStep types, but
/// `DisconnectBlock` and `ConnectBlock` are each returned in height-descending order.
async fn find_fork<P: Poll>(current_header: ValidatedBlockHeader, prev_header: &ValidatedBlockHeader, chain_poller: &mut P, cache: &HeaderCache) -> BlockSourceResult<Vec<ForkStep>> {
	let mut steps = Vec::new();
	let mut current = current_header;
	let mut previous = *prev_header;
	loop {
		// Found the parent block.
		if current.height == previous.height + 1 &&
				current.header.prev_blockhash == previous.block_hash {
			steps.push(ForkStep::ConnectBlock(current));
			break;
		}

		// Found a chain fork.
		if current.header.prev_blockhash == previous.header.prev_blockhash {
			let fork_point = look_up_prev_header(chain_poller, &previous, cache).await?;
			steps.push(ForkStep::DisconnectBlock(previous));
			steps.push(ForkStep::ConnectBlock(current));
			steps.push(ForkStep::ForkPoint(fork_point));
			break;
		}

		// Walk back the chain, finding blocks needed to connect and disconnect. Only walk back the
		// header with the greater height, or both if equal heights.
		let current_height = current.height;
		let previous_height = previous.height;
		if current_height <= previous_height {
			steps.push(ForkStep::DisconnectBlock(previous));
			previous = look_up_prev_header(chain_poller, &previous, cache).await?;
		}
		if current_height >= previous_height {
			steps.push(ForkStep::ConnectBlock(current));
			current = look_up_prev_header(chain_poller, &current, cache).await?;
		}
	}

	Ok(steps)
}

/// Adaptor used for notifying when blocks have been connected or disconnected from the chain.
/// Useful for replaying chain data upon deserialization.
pub trait ChainListener {
	fn block_connected(&mut self, block: &Block, height: u32);
	fn block_disconnected(&mut self, header: &BlockHeader, height: u32);
}

impl<M, B, F, L> ChainListener for &SimpleArcChannelManager<M, B, F, L>
		where M: chain::Watch<Keys=keysinterface::InMemoryChannelKeys>,
		      B: chaininterface::BroadcasterInterface,
		      F: chaininterface::FeeEstimator,
		      L: logger::Logger {
	fn block_connected(&mut self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		(**self).block_connected(&block.header, &txdata, height);
	}
	fn block_disconnected(&mut self, header: &BlockHeader, _height: u32) {
		(**self).block_disconnected(header);
	}
}

impl<CS, B, F, L> ChainListener for (&mut ChannelMonitor<CS>, &B, &F, &L)
		where CS: keysinterface::ChannelKeys,
		      B: chaininterface::BroadcasterInterface,
		      F: chaininterface::FeeEstimator,
		      L: logger::Logger {
	fn block_connected(&mut self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		self.0.block_connected(&block.header, &txdata, height, self.1, self.2, self.3);
	}
	fn block_disconnected(&mut self, header: &BlockHeader, height: u32) {
		self.0.block_disconnected(header, height, self.1, self.2, self.3);
	}
}

/// Finds the fork point between new_header and old_header, disconnecting blocks from old_header to
/// get to that point and then connecting blocks until we get to new_header.
///
/// We validate the headers along the transition path, but don't fetch blocks until we've
/// disconnected to the fork point. Thus, we may return an Err() that includes where our tip ended
/// up which may not be new_header. Note that iff the returned Err has a BlockHeaderData, the
/// header transition from old_header to new_header is valid.
async fn sync_chain_monitor<CL: ChainListener + Sized, P: Poll>(new_header: ValidatedBlockHeader, old_header: &ValidatedBlockHeader, chain_poller: &mut P, chain_notifier: &mut CL, header_cache: &mut HeaderCache)
		-> Result<(), (BlockSourceError, Option<ValidatedBlockHeader>)> {
	let mut events = find_fork(new_header, old_header, chain_poller, header_cache).await.map_err(|e| (e, None))?;

	let mut last_disconnect_tip = None;
	let mut new_tip = None;
	for event in events.iter() {
		match &event {
			&ForkStep::DisconnectBlock(ref header) => {
				let block_hash = header.header.block_hash();
				println!("Disconnecting block {}", block_hash);
				if let Some(cached_head) = header_cache.remove(&block_hash) {
					assert_eq!(cached_head, *header);
				}
				chain_notifier.block_disconnected(&header.header, header.height);
				last_disconnect_tip = Some(header.header.prev_blockhash);
			},
			&ForkStep::ForkPoint(ref header) => {
				new_tip = Some(*header);
			},
			_ => {},
		}
	}

	// If we disconnected any blocks, we should have new tip data available. If we didn't disconnect
	// any blocks we shouldn't have set a ForkPoint as there is no fork.
	assert_eq!(last_disconnect_tip.is_some(), new_tip.is_some());
	if let &Some(ref tip_header) = &new_tip {
		debug_assert_eq!(tip_header.header.block_hash(), *last_disconnect_tip.as_ref().unwrap());
	} else {
		// Set new_tip to indicate that we got a valid header chain we wanted to connect to, but
		// failed
		new_tip = Some(*old_header);
	}

	for event in events.drain(..).rev() {
		if let ForkStep::ConnectBlock(header) = event {
			let block = chain_poller
				.fetch_block(&header).await
				.or_else(|e| Err((e, new_tip)))?;
			debug_assert_eq!(block.block_hash, header.block_hash);
			println!("Connecting block {}", header.block_hash.to_hex());
			chain_notifier.block_connected(&block, header.height);
			header_cache.insert(header.block_hash, header);
			new_tip = Some(header);
		}
	}
	Ok(())
}

/// Do a one-time sync of a chain listener from a single *trusted* block source bringing its view
/// of the latest chain tip from old_block to new_block. This is useful on startup when you need
/// to bring each ChannelMonitor, as well as the overall ChannelManager, into sync with each other.
///
/// Once you have them all at the same block, you should switch to using MicroSPVClient.
pub async fn init_sync_chain_monitor<CL: ChainListener + Sized, B: BlockSource>(new_block: BlockHash, old_block: BlockHash, block_source: &mut B, network: Network, chain_notifier: &mut CL) {
	if &old_block[..] == &[0; 32] { return; }
	if old_block == new_block { return; }

	let new_header = block_source
		.get_header(&new_block, None).await.unwrap()
		.validate(new_block).unwrap();
	let old_header = block_source
		.get_header(&old_block, None).await.unwrap()
		.validate(old_block).unwrap();
	let mut chain_poller = poller::ChainPoller::new(block_source as &mut dyn BlockSource, network);
	sync_chain_monitor(new_header, &old_header, &mut chain_poller, chain_notifier, &mut HeaderCache::new()).await.unwrap();
}

/// Unbounded cache of header data keyed by block hash.
pub(crate) type HeaderCache = std::collections::HashMap<BlockHash, ValidatedBlockHeader>;

/// Keep the chain that a chain listener knows about up-to-date with the best chain from any of the
/// given block_sources.
///
/// This implements a pretty bare-bones SPV client, checking all relevant commitments and finding
/// the heaviest chain, but not storing the full header chain, leading to some important
/// limitations.
///
/// TODO: Update comment to reflect this is now the responsibility of chain_poller.
/// While we never check full difficulty transition logic, the mainnet option enables checking that
/// difficulty transitions only happen every two weeks and never shift difficulty more than 4x in
/// either direction, which is sufficient to prevent most minority hashrate attacks.
///
/// TODO: Update comment as headers are removed from cache when blocks are disconnected.
/// We cache any headers which we connect until every block source is in agreement on the best tip.
/// This prevents one block source from being able to orphan us on a fork of its own creation by
/// not responding to requests for old headers on that fork. However, if one block source is
/// unreachable this may result in our memory usage growing in accordance with the chain.
pub struct MicroSPVClient<P, CL>
where P: Poll,
	  CL: ChainListener + Sized {
	chain_tip: ValidatedBlockHeader,
	chain_poller: P,
	header_cache: HeaderCache,
	chain_notifier: CL,
}

impl<P, CL> MicroSPVClient<P, CL>
where P: Poll,
	  CL: ChainListener + Sized {

	/// Creates a new `MicroSPVClient` with a chain poller for polling one or more block sources and
	/// a chain listener for receiving updates of the new chain tip.
	///
	/// At least one of the polled `BlockSource`s must provide the necessary headers to disconnect
	/// from the given `chain_tip` back to its common ancestor with the best chain assuming that its
	/// height, hash, and chainwork are correct.
	///
	/// `backup_block_sources` are never queried unless we learned, via some `block_sources` source
	/// that there exists a better, valid header chain but we failed to fetch the blocks. This is
	/// useful when you have a block source which is more censorship-resistant than others but
	/// which only provides headers. In this case, we can use such source(s) to learn of a censorship
	/// attack without giving up privacy by querying a privacy-losing block sources.
	pub fn init(chain_tip: ValidatedBlockHeader, chain_poller: P, chain_notifier: CL) -> Self {
		let header_cache = HeaderCache::new();
		Self { chain_tip, chain_poller, header_cache, chain_notifier }
	}

	/// Check each source for a new best tip and update the chain listener accordingly.
	/// Returns true if some blocks were [dis]connected, false otherwise.
	pub async fn poll_best_tip(&mut self) -> BlockSourceResult<(ChainTip, bool)> {
		macro_rules! sync_chain_monitor {
			($new_header: expr) => { {
				let mut blocks_connected = false;
				match sync_chain_monitor(*$new_header, &self.chain_tip, &mut self.chain_poller, &mut self.chain_notifier, &mut self.header_cache).await {
					Err((_, latest_tip)) => {
						if let Some(latest_tip) = latest_tip {
							let latest_tip_hash = latest_tip.header.block_hash();
							if latest_tip_hash != self.chain_tip.block_hash {
								self.chain_tip = latest_tip;
								blocks_connected = true;
							}
						}
					},
					Ok(_) => {
						self.chain_tip = *$new_header;
						blocks_connected = true;
					},
				}
				blocks_connected
			} }
		}

		let chain_tip = self.chain_poller.poll_chain_tip(self.chain_tip).await?;
		let blocks_connected = match &chain_tip {
			ChainTip::Common => false,
			ChainTip::Better(chain_tip) => {
				debug_assert_ne!(chain_tip.block_hash, self.chain_tip.block_hash);
				debug_assert!(chain_tip.chainwork > self.chain_tip.chainwork);
				sync_chain_monitor!(chain_tip)
			},
			ChainTip::Worse(chain_tip) => {
				debug_assert_ne!(chain_tip.block_hash, self.chain_tip.block_hash);
				debug_assert!(chain_tip.chainwork <= self.chain_tip.chainwork);
				false
			},
		};
		Ok((chain_tip, blocks_connected))
	}
}

#[cfg(test)]
mod sync_tests {
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
		let mut cache = chain.header_cache(0..=1);
		let mut poller = poller::ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Testnet);
		match sync_chain_monitor(new_tip, &old_tip, &mut poller, &mut listener, &mut cache).await {
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
		let mut cache = main_chain.header_cache(0..=1);
		let mut poller = poller::ChainPoller::new(&mut test_chain as &mut dyn BlockSource, Network::Testnet);
		match sync_chain_monitor(new_tip, &old_tip, &mut poller, &mut listener, &mut cache).await {
			Err((e, _)) => assert_eq!(e, BlockSourceError::Persistent),
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
		let mut cache = main_chain.header_cache(0..=2);
		let mut poller = poller::ChainPoller::new(&mut fork_chain as &mut dyn BlockSource, Network::Testnet);
		match sync_chain_monitor(new_tip, &old_tip, &mut poller, &mut listener, &mut cache).await {
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
		let mut cache = main_chain.header_cache(0..=3);
		let mut poller = poller::ChainPoller::new(&mut fork_chain as &mut dyn BlockSource, Network::Testnet);
		match sync_chain_monitor(new_tip, &old_tip, &mut poller, &mut listener, &mut cache).await {
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
		let mut cache = main_chain.header_cache(0..=2);
		let mut poller = poller::ChainPoller::new(&mut fork_chain as &mut dyn BlockSource, Network::Testnet);
		match sync_chain_monitor(new_tip, &old_tip, &mut poller, &mut listener, &mut cache).await {
			Err((e, _)) => panic!("Unexpected error: {:?}", e),
			Ok(_) => {},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::blockdata::block::{Block, BlockHeader};
	use bitcoin::util::uint::Uint256;
	use std::collections::HashMap;
	use std::sync::{Arc, Mutex};

	struct TestChainListener {
		blocks_connected: Mutex<Vec<(BlockHash, u32)>>,
		blocks_disconnected: Mutex<Vec<(BlockHash, u32)>>,
	}
	impl ChainListener for Arc<TestChainListener> {
		fn block_connected(&mut self, block: &Block, height: u32) {
			self.blocks_connected.lock().unwrap().push((block.header.block_hash(), height));
		}
		fn block_disconnected(&mut self, header: &BlockHeader, height: u32) {
			self.blocks_disconnected.lock().unwrap().push((header.block_hash(), height));
		}
	}

	#[derive(Clone)]
	struct BlockData {
		block: Block,
		chainwork: Uint256,
		height: u32,
	}
	struct Blockchain {
		blocks: Mutex<HashMap<BlockHash, BlockData>>,
		best_block: Mutex<(BlockHash, Option<u32>)>,
		headers_only: bool,
		disallowed: Mutex<bool>,
	}
	impl BlockSource for &Blockchain {
		fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
			if *self.disallowed.lock().unwrap() { unreachable!(); }
			Box::pin(async move {
				match self.blocks.lock().unwrap().get(header_hash) {
					Some(block) => {
						assert_eq!(Some(block.height), height_hint);
						Ok(BlockHeaderData {
							chainwork: block.chainwork,
							height: block.height,
							header: block.block.header.clone(),
						})
					},
					None => Err(BlockSourceError::Transient),
				}
			})
		}
		fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
			if *self.disallowed.lock().unwrap() { unreachable!(); }
			Box::pin(async move {
				if self.headers_only {
					Err(BlockSourceError::Transient)
				} else {
					match self.blocks.lock().unwrap().get(header_hash) {
						Some(block) => Ok(block.block.clone()),
						None => Err(BlockSourceError::Transient),
					}
				}
			})
		}
		fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
			if *self.disallowed.lock().unwrap() { unreachable!(); }
			Box::pin(async move { Ok(self.best_block.lock().unwrap().clone()) })
		}
	}

	#[tokio::test]
	async fn simple_block_connect() {
		let genesis = BlockData {
			block: bitcoin::blockdata::constants::genesis_block(bitcoin::network::constants::Network::Bitcoin),
			chainwork: Uint256::from_u64(0).unwrap(),
			height: 0,
		};

		// Build a chain based on genesis 1a, 2a, 3a, and 4a
		let block_1a = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: genesis.block.block_hash(),
					merkle_root: Default::default(), time: 0,
					bits: genesis.block.header.bits,
					nonce: 647569994,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833).unwrap(),
			height: 1
		};
		let block_1a_hash = block_1a.block.header.block_hash();
		let block_2a = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_1a.block.block_hash(),
					merkle_root: Default::default(), time: 4,
					bits: genesis.block.header.bits,
					nonce: 1185103332,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 2).unwrap(),
			height: 2
		};
		let block_2a_hash = block_2a.block.header.block_hash();
		let block_3a = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_2a.block.block_hash(),
					merkle_root: Default::default(), time: 6,
					bits: genesis.block.header.bits,
					nonce: 198739431,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 3).unwrap(),
			height: 3
		};
		let block_3a_hash = block_3a.block.header.block_hash();
		let block_4a = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_3a.block.block_hash(),
					merkle_root: Default::default(), time: 0,
					bits: genesis.block.header.bits,
					nonce: 590371681,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 4).unwrap(),
			height: 4
		};
		let block_4a_hash = block_4a.block.header.block_hash();

		// Build a second chain based on genesis 1b, 2b, and 3b
		let block_1b = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: genesis.block.block_hash(),
					merkle_root: Default::default(), time: 6,
					bits: genesis.block.header.bits,
					nonce: 1347696353,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833).unwrap(),
			height: 1
		};
		let block_1b_hash = block_1b.block.header.block_hash();
		let block_2b = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_1b.block.block_hash(),
					merkle_root: Default::default(), time: 5,
					bits: genesis.block.header.bits,
					nonce: 144775545,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 2).unwrap(),
			height: 2
		};
		let block_2b_hash = block_2b.block.header.block_hash();

		// Build a second chain based on 3a: 4c and 5c.
		let block_4c = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_3a.block.block_hash(),
					merkle_root: Default::default(), time: 17,
					bits: genesis.block.header.bits,
					nonce: 316634915,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 4).unwrap(),
			height: 4
		};
		let block_4c_hash = block_4c.block.header.block_hash();
		let block_5c = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_4c.block.block_hash(),
					merkle_root: Default::default(), time: 3,
					bits: genesis.block.header.bits,
					nonce: 218413871,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 5).unwrap(),
			height: 5
		};
		let block_5c_hash = block_5c.block.header.block_hash();

		// Create four block sources:
		// * chain_one and chain_two are general purpose block sources which we use to test reorgs,
		// * headers_chain only provides headers,
		// * and backup_chain is a backup which should not receive any queries (ie disallowed is
		//   false) until the headers_chain gets ahead of chain_one and chain_two.
		let mut blocks_one = HashMap::new();
		blocks_one.insert(genesis.block.header.block_hash(), genesis.clone());
		blocks_one.insert(block_1a_hash, block_1a.clone());
		blocks_one.insert(block_1b_hash, block_1b);
		blocks_one.insert(block_2b_hash, block_2b);
		let chain_one = Blockchain {
			blocks: Mutex::new(blocks_one), best_block: Mutex::new((block_2b_hash, Some(2))),
			headers_only: false, disallowed: Mutex::new(false)
		};

		let mut blocks_two = HashMap::new();
		blocks_two.insert(genesis.block.header.block_hash(), genesis.clone());
		blocks_two.insert(block_1a_hash, block_1a.clone());
		let chain_two = Blockchain {
			blocks: Mutex::new(blocks_two), best_block: Mutex::new((block_1a_hash, Some(1))),
			headers_only: false, disallowed: Mutex::new(false)
		};

		let mut blocks_three = HashMap::new();
		blocks_three.insert(genesis.block.header.block_hash(), genesis.clone());
		blocks_three.insert(block_1a_hash, block_1a.clone());
		let header_chain = Blockchain {
			blocks: Mutex::new(blocks_three), best_block: Mutex::new((block_1a_hash, Some(1))),
			headers_only: true, disallowed: Mutex::new(false)
		};

		let mut blocks_four = HashMap::new();
		blocks_four.insert(genesis.block.header.block_hash(), genesis);
		blocks_four.insert(block_1a_hash, block_1a);
		blocks_four.insert(block_2a_hash, block_2a.clone());
		blocks_four.insert(block_3a_hash, block_3a.clone());
		let backup_chain = Blockchain {
			blocks: Mutex::new(blocks_four), best_block: Mutex::new((block_3a_hash, Some(3))),
			headers_only: false, disallowed: Mutex::new(true)
		};

		// Stand up a client at block_1a with all four sources:
		let chain_notifier = Arc::new(TestChainListener {
			blocks_connected: Mutex::new(Vec::new()), blocks_disconnected: Mutex::new(Vec::new())
		});
		let mut source_one = &chain_one;
		let mut source_two = &chain_two;
		let mut source_three = &header_chain;
		let mut source_four = &backup_chain;
		let mut client = MicroSPVClient::init(
			(&chain_one).get_header(&block_1a_hash, Some(1)).await.unwrap().validate(block_1a_hash).unwrap(),
			poller::ChainMultiplexer::new(
				vec![&mut source_one as &mut dyn BlockSource, &mut source_two as &mut dyn BlockSource, &mut source_three as &mut dyn BlockSource],
				vec![&mut source_four as &mut dyn BlockSource],
				Network::Bitcoin),
			Arc::clone(&chain_notifier));

		// Test that we will reorg onto 2b because chain_one knows about 1b + 2b
		match client.poll_best_tip().await {
			Ok((ChainTip::Better(chain_tip), blocks_connected)) => {
				assert_eq!(chain_tip.block_hash, block_2b_hash);
				assert!(blocks_connected);
			},
			_ => panic!("Expected better chain tip"),
		}
		assert_eq!(&chain_notifier.blocks_disconnected.lock().unwrap()[..], &[(block_1a_hash, 1)][..]);
		assert_eq!(&chain_notifier.blocks_connected.lock().unwrap()[..], &[(block_1b_hash, 1), (block_2b_hash, 2)][..]);
		assert_eq!(client.header_cache.len(), 2);
		assert!(client.header_cache.contains_key(&block_1b_hash));
		assert!(client.header_cache.contains_key(&block_2b_hash));

		// Test that even if chain_one (which we just got blocks from) stops responding to block or
		// header requests we can still reorg back because we never wiped our block cache as
		// chain_two always considered the "a" chain to contain the tip. We do this by simply
		// wiping the blocks chain_one knows about:
		chain_one.blocks.lock().unwrap().clear();
		chain_notifier.blocks_connected.lock().unwrap().clear();
		chain_notifier.blocks_disconnected.lock().unwrap().clear();

		// First test that nothing happens if nothing changes:
		match client.poll_best_tip().await {
			Ok((ChainTip::Common, blocks_connected)) => {
				assert!(!blocks_connected);
			},
			_ => panic!("Expected common chain tip"),
		}
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert!(chain_notifier.blocks_connected.lock().unwrap().is_empty());

		// Now add block 2a and 3a to chain_two and test that we reorg appropriately:
		chain_two.blocks.lock().unwrap().insert(block_2a_hash, block_2a.clone());
		chain_two.blocks.lock().unwrap().insert(block_3a_hash, block_3a.clone());
		*chain_two.best_block.lock().unwrap() = (block_3a_hash, Some(3));

		match client.poll_best_tip().await {
			Ok((ChainTip::Better(chain_tip), blocks_connected)) => {
				assert_eq!(chain_tip.block_hash, block_3a_hash);
				assert!(blocks_connected);
			},
			_ => panic!("Expected better chain tip"),
		}
		assert_eq!(&chain_notifier.blocks_disconnected.lock().unwrap()[..], &[(block_2b_hash, 2), (block_1b_hash, 1)][..]);
		assert_eq!(&chain_notifier.blocks_connected.lock().unwrap()[..], &[(block_1a_hash, 1), (block_2a_hash, 2), (block_3a_hash, 3)][..]);

		// Note that blocks_past_common_tip is not wiped as chain_one still returns 2a as its tip
		// (though a smarter MicroSPVClient may wipe 1a and 2a from the set eventually.
		assert_eq!(client.header_cache.len(), 3);
		assert!(client.header_cache.contains_key(&block_1a_hash));
		assert!(client.header_cache.contains_key(&block_2a_hash));
		assert!(client.header_cache.contains_key(&block_3a_hash));

		chain_notifier.blocks_connected.lock().unwrap().clear();
		chain_notifier.blocks_disconnected.lock().unwrap().clear();

		// Test that after chain_one and header_chain consider 3a as their tip that we won't wipe
		// the block header cache.
		*chain_one.best_block.lock().unwrap() = (block_3a_hash, Some(3));
		*header_chain.best_block.lock().unwrap() = (block_3a_hash, Some(3));
		match client.poll_best_tip().await {
			Ok((ChainTip::Common, blocks_connected)) => {
				assert!(!blocks_connected);
			},
			_ => panic!("Expected common chain tip"),
		}
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert!(chain_notifier.blocks_connected.lock().unwrap().is_empty());

		assert_eq!(client.header_cache.len(), 3);

		// Test that setting the header chain to 4a does...almost nothing (though backup_chain
		// should now be queried) since we can't get the blocks from anywhere.
		header_chain.blocks.lock().unwrap().insert(block_2a_hash, block_2a);
		header_chain.blocks.lock().unwrap().insert(block_3a_hash, block_3a);
		header_chain.blocks.lock().unwrap().insert(block_4a_hash, block_4a.clone());
		*header_chain.best_block.lock().unwrap() = (block_4a_hash, Some(4));
		*backup_chain.disallowed.lock().unwrap() = false;

		match client.poll_best_tip().await {
			Ok((ChainTip::Better(chain_tip), blocks_connected)) => {
				assert_eq!(chain_tip.block_hash, block_4a_hash);
				assert!(!blocks_connected);
			},
			_ => panic!("Expected better chain tip"),
		}
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert!(chain_notifier.blocks_connected.lock().unwrap().is_empty());
		assert_eq!(client.header_cache.len(), 3);

		// But if backup_chain *also* has 4a, we'll fetch it from there:
		backup_chain.blocks.lock().unwrap().insert(block_4a_hash, block_4a);
		*backup_chain.best_block.lock().unwrap() = (block_4a_hash, Some(4));

		match client.poll_best_tip().await {
			Ok((ChainTip::Better(chain_tip), blocks_connected)) => {
				assert_eq!(chain_tip.block_hash, block_4a_hash);
				assert!(blocks_connected);
			},
			_ => panic!("Expected better chain tip"),
		}
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert_eq!(&chain_notifier.blocks_connected.lock().unwrap()[..], &[(block_4a_hash, 4)][..]);
		assert_eq!(client.header_cache.len(), 4);
		assert!(client.header_cache.contains_key(&block_4a_hash));

		chain_notifier.blocks_connected.lock().unwrap().clear();
		chain_notifier.blocks_disconnected.lock().unwrap().clear();

		// Note that if only headers_chain has a reorg, we'll end up in a somewhat pessimal case
		// where we will disconnect and reconnect at each poll. We should fix this at some point by
		// making sure we can at least fetch one block before we disconnect, but short of using a
		// ton more memory there isn't much we can do in the case of two disconnects. We check that
		// the disconnect happens here on a one-block-disconnected reorg, even though its
		// non-normative behavior, as a good test of failing to reorg and returning back to the
		// best chain.
		header_chain.blocks.lock().unwrap().insert(block_4c_hash, block_4c);
		header_chain.blocks.lock().unwrap().insert(block_5c_hash, block_5c);
		*header_chain.best_block.lock().unwrap() = (block_5c_hash, Some(5));
		// We'll check the backup chain last, so don't give it 4a, as otherwise we'll connect it:
		*backup_chain.best_block.lock().unwrap() = (block_3a_hash, Some(3));

		match client.poll_best_tip().await {
			Ok((ChainTip::Better(chain_tip), blocks_disconnected)) => {
				assert_eq!(chain_tip.block_hash, block_5c_hash);
				assert!(blocks_disconnected);
			},
			_ => panic!("Expected better chain tip"),
		}
		assert_eq!(&chain_notifier.blocks_disconnected.lock().unwrap()[..], &[(block_4a_hash, 4)][..]);
		assert!(chain_notifier.blocks_connected.lock().unwrap().is_empty());

		chain_notifier.blocks_disconnected.lock().unwrap().clear();

		// Now reset the headers chain to 4a and test that we end up back there.
		*backup_chain.best_block.lock().unwrap() = (block_4a_hash, Some(4));
		*header_chain.best_block.lock().unwrap() = (block_4a_hash, Some(4));
		match client.poll_best_tip().await {
			Ok((ChainTip::Better(chain_tip), blocks_connected)) => {
				assert_eq!(chain_tip.block_hash, block_4a_hash);
				assert!(blocks_connected);
			},
			_ => panic!("Expected better chain tip"),
		}
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert_eq!(&chain_notifier.blocks_connected.lock().unwrap()[..], &[(block_4a_hash, 4)][..]);
	}
}
