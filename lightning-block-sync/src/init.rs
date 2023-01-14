//! Utilities to assist in the initial sync required to initialize or reload Rust-Lightning objects
//! from disk.

use crate::{BlockSource, BlockSourceResult, Cache, ChainNotifier};
use crate::poll::{ChainPoller, Validate, ValidatedBlockHeader};

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;

use lightning::chain;

use std::ops::Deref;

/// Returns a validated block header of the source's best chain tip.
///
/// Upon success, the returned header can be used to initialize [`SpvClient`]. Useful during a fresh
/// start when there are no chain listeners to sync yet.
///
/// [`SpvClient`]: crate::SpvClient
pub async fn validate_best_block_header<B: Deref>(block_source: B) ->
BlockSourceResult<ValidatedBlockHeader> where B::Target: BlockSource {
	let (best_block_hash, best_block_height) = block_source.get_best_block().await?;
	block_source
		.get_header(&best_block_hash, best_block_height).await?
		.validate(best_block_hash)
}

/// Performs a one-time sync of chain listeners using a single *trusted* block source, bringing each
/// listener's view of the chain from its paired block hash to `block_source`'s best chain tip.
///
/// Upon success, the returned header can be used to initialize [`SpvClient`]. In the case of
/// failure, each listener may be left at a different block hash than the one it was originally
/// paired with.
///
/// Useful during startup to bring the [`ChannelManager`] and each [`ChannelMonitor`] in sync before
/// switching to [`SpvClient`]. For example:
///
/// ```
/// use bitcoin::hash_types::BlockHash;
/// use bitcoin::network::constants::Network;
///
/// use lightning::chain;
/// use lightning::chain::Watch;
/// use lightning::chain::chainmonitor;
/// use lightning::chain::chainmonitor::ChainMonitor;
/// use lightning::chain::channelmonitor::ChannelMonitor;
/// use lightning::chain::chaininterface::BroadcasterInterface;
/// use lightning::chain::chaininterface::FeeEstimator;
/// use lightning::chain::keysinterface;
/// use lightning::chain::keysinterface::{EntropySource, NodeSigner, SignerProvider};
/// use lightning::ln::channelmanager::{ChannelManager, ChannelManagerReadArgs};
/// use lightning::routing::router::Router;
/// use lightning::util::config::UserConfig;
/// use lightning::util::logger::Logger;
/// use lightning::util::ser::ReadableArgs;
///
/// use lightning_block_sync::*;
///
/// use std::io::Cursor;
///
/// async fn init_sync<
/// 	B: BlockSource,
/// 	ES: EntropySource,
/// 	NS: NodeSigner,
/// 	SP: SignerProvider,
/// 	T: BroadcasterInterface,
/// 	F: FeeEstimator,
/// 	R: Router,
/// 	L: Logger,
/// 	C: chain::Filter,
/// 	P: chainmonitor::Persist<SP::Signer>,
/// >(
/// 	block_source: &B,
/// 	chain_monitor: &ChainMonitor<SP::Signer, &C, &T, &F, &L, &P>,
/// 	config: UserConfig,
/// 	entropy_source: &ES,
/// 	node_signer: &NS,
/// 	signer_provider: &SP,
/// 	tx_broadcaster: &T,
/// 	fee_estimator: &F,
/// 	router: &R,
/// 	logger: &L,
/// 	persister: &P,
/// ) {
/// 	// Read a serialized channel monitor paired with the block hash when it was persisted.
/// 	let serialized_monitor = "...";
/// 	let (monitor_block_hash, mut monitor) = <(BlockHash, ChannelMonitor<SP::Signer>)>::read(
/// 		&mut Cursor::new(&serialized_monitor), (entropy_source, signer_provider)).unwrap();
///
/// 	// Read the channel manager paired with the block hash when it was persisted.
/// 	let serialized_manager = "...";
/// 	let (manager_block_hash, mut manager) = {
/// 		let read_args = ChannelManagerReadArgs::new(
/// 			entropy_source,
/// 			node_signer,
/// 			signer_provider,
/// 			fee_estimator,
/// 			chain_monitor,
/// 			tx_broadcaster,
/// 			router,
/// 			logger,
/// 			config,
/// 			vec![&mut monitor],
/// 		);
/// 		<(BlockHash, ChannelManager<&ChainMonitor<SP::Signer, &C, &T, &F, &L, &P>, &T, &ES, &NS, &SP, &F, &R, &L>)>::read(
/// 			&mut Cursor::new(&serialized_manager), read_args).unwrap()
/// 	};
///
/// 	// Synchronize any channel monitors and the channel manager to be on the best block.
/// 	let mut cache = UnboundedCache::new();
/// 	let mut monitor_listener = (monitor, &*tx_broadcaster, &*fee_estimator, &*logger);
/// 	let listeners = vec![
/// 		(monitor_block_hash, &monitor_listener as &dyn chain::Listen),
/// 		(manager_block_hash, &manager as &dyn chain::Listen),
/// 	];
/// 	let chain_tip = init::synchronize_listeners(
/// 		block_source, Network::Bitcoin, &mut cache, listeners).await.unwrap();
///
/// 	// Allow the chain monitor to watch any channels.
/// 	let monitor = monitor_listener.0;
/// 	chain_monitor.watch_channel(monitor.get_funding_txo().0, monitor);
///
/// 	// Create an SPV client to notify the chain monitor and channel manager of block events.
/// 	let chain_poller = poll::ChainPoller::new(block_source, Network::Bitcoin);
/// 	let mut chain_listener = (chain_monitor, &manager);
/// 	let spv_client = SpvClient::new(chain_tip, chain_poller, &mut cache, &chain_listener);
/// }
/// ```
///
/// [`SpvClient`]: crate::SpvClient
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
/// [`ChannelMonitor`]: lightning::chain::channelmonitor::ChannelMonitor
pub async fn synchronize_listeners<B: Deref + Sized + Send + Sync, C: Cache, L: chain::Listen + ?Sized>(
	block_source: B,
	network: Network,
	header_cache: &mut C,
	mut chain_listeners: Vec<(BlockHash, &L)>,
) -> BlockSourceResult<ValidatedBlockHeader> where B::Target: BlockSource {
	let best_header = validate_best_block_header(&*block_source).await?;

	// Fetch the header for the block hash paired with each listener.
	let mut chain_listeners_with_old_headers = Vec::new();
	for (old_block_hash, chain_listener) in chain_listeners.drain(..) {
		let old_header = match header_cache.look_up(&old_block_hash) {
			Some(header) => *header,
			None => block_source
				.get_header(&old_block_hash, None).await?
				.validate(old_block_hash)?
		};
		chain_listeners_with_old_headers.push((old_header, chain_listener))
	}

	// Find differences and disconnect blocks for each listener individually.
	let mut chain_poller = ChainPoller::new(block_source, network);
	let mut chain_listeners_at_height = Vec::new();
	let mut most_common_ancestor = None;
	let mut most_connected_blocks = Vec::new();
	for (old_header, chain_listener) in chain_listeners_with_old_headers.drain(..) {
		// Disconnect any stale blocks, but keep them in the cache for the next iteration.
		let header_cache = &mut ReadOnlyCache(header_cache);
		let (common_ancestor, connected_blocks) = {
			let chain_listener = &DynamicChainListener(chain_listener);
			let mut chain_notifier = ChainNotifier { header_cache, chain_listener };
			let difference =
				chain_notifier.find_difference(best_header, &old_header, &mut chain_poller).await?;
			chain_notifier.disconnect_blocks(difference.disconnected_blocks);
			(difference.common_ancestor, difference.connected_blocks)
		};

		// Keep track of the most common ancestor and all blocks connected across all listeners.
		chain_listeners_at_height.push((common_ancestor.height, chain_listener));
		if connected_blocks.len() > most_connected_blocks.len() {
			most_common_ancestor = Some(common_ancestor);
			most_connected_blocks = connected_blocks;
		}
	}

	// Connect new blocks for all listeners at once to avoid re-fetching blocks.
	if let Some(common_ancestor) = most_common_ancestor {
		let chain_listener = &ChainListenerSet(chain_listeners_at_height);
		let mut chain_notifier = ChainNotifier { header_cache, chain_listener };
		chain_notifier.connect_blocks(common_ancestor, most_connected_blocks, &mut chain_poller)
			.await.or_else(|(e, _)| Err(e))?;
	}

	Ok(best_header)
}

/// A wrapper to make a cache read-only.
///
/// Used to prevent losing headers that may be needed to disconnect blocks common to more than one
/// listener.
struct ReadOnlyCache<'a, C: Cache>(&'a mut C);

impl<'a, C: Cache> Cache for ReadOnlyCache<'a, C> {
	fn look_up(&self, block_hash: &BlockHash) -> Option<&ValidatedBlockHeader> {
		self.0.look_up(block_hash)
	}

	fn block_connected(&mut self, _block_hash: BlockHash, _block_header: ValidatedBlockHeader) {
		unreachable!()
	}

	fn block_disconnected(&mut self, _block_hash: &BlockHash) -> Option<ValidatedBlockHeader> {
		None
	}
}

/// Wrapper for supporting dynamically sized chain listeners.
struct DynamicChainListener<'a, L: chain::Listen + ?Sized>(&'a L);

impl<'a, L: chain::Listen + ?Sized> chain::Listen for DynamicChainListener<'a, L> {
	fn filtered_block_connected(&self, _header: &BlockHeader, _txdata: &chain::transaction::TransactionData, _height: u32) {
		unreachable!()
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		self.0.block_disconnected(header, height)
	}
}

/// A set of dynamically sized chain listeners, each paired with a starting block height.
struct ChainListenerSet<'a, L: chain::Listen + ?Sized>(Vec<(u32, &'a L)>);

impl<'a, L: chain::Listen + ?Sized> chain::Listen for ChainListenerSet<'a, L> {
	// Needed to differentiate test expectations.
	#[cfg(test)]
	fn block_connected(&self, block: &bitcoin::Block, height: u32) {
		for (starting_height, chain_listener) in self.0.iter() {
			if height > *starting_height {
				chain_listener.block_connected(block, height);
			}
		}
	}

	fn filtered_block_connected(&self, header: &BlockHeader, txdata: &chain::transaction::TransactionData, height: u32) {
		for (starting_height, chain_listener) in self.0.iter() {
			if height > *starting_height {
				chain_listener.filtered_block_connected(header, txdata, height);
			}
		}
	}

	fn block_disconnected(&self, _header: &BlockHeader, _height: u32) {
		unreachable!()
	}
}

#[cfg(test)]
mod tests {
	use crate::test_utils::{Blockchain, MockChainListener};
	use super::*;

	use bitcoin::network::constants::Network;

	#[tokio::test]
	async fn sync_from_same_chain() {
		let chain = Blockchain::default().with_height(4);

		let listener_1 = MockChainListener::new()
			.expect_block_connected(*chain.at_height(2))
			.expect_block_connected(*chain.at_height(3))
			.expect_block_connected(*chain.at_height(4));
		let listener_2 = MockChainListener::new()
			.expect_block_connected(*chain.at_height(3))
			.expect_block_connected(*chain.at_height(4));
		let listener_3 = MockChainListener::new()
			.expect_block_connected(*chain.at_height(4));

		let listeners = vec![
			(chain.at_height(1).block_hash, &listener_1 as &dyn chain::Listen),
			(chain.at_height(2).block_hash, &listener_2 as &dyn chain::Listen),
			(chain.at_height(3).block_hash, &listener_3 as &dyn chain::Listen),
		];
		let mut cache = chain.header_cache(0..=4);
		match synchronize_listeners(&chain, Network::Bitcoin, &mut cache, listeners).await {
			Ok(header) => assert_eq!(header, chain.tip()),
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[tokio::test]
	async fn sync_from_different_chains() {
		let main_chain = Blockchain::default().with_height(4);
		let fork_chain_1 = main_chain.fork_at_height(1);
		let fork_chain_2 = main_chain.fork_at_height(2);
		let fork_chain_3 = main_chain.fork_at_height(3);

		let listener_1 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_1.at_height(4))
			.expect_block_disconnected(*fork_chain_1.at_height(3))
			.expect_block_disconnected(*fork_chain_1.at_height(2))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let listener_2 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_2.at_height(4))
			.expect_block_disconnected(*fork_chain_2.at_height(3))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let listener_3 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_3.at_height(4))
			.expect_block_connected(*main_chain.at_height(4));

		let listeners = vec![
			(fork_chain_1.tip().block_hash, &listener_1 as &dyn chain::Listen),
			(fork_chain_2.tip().block_hash, &listener_2 as &dyn chain::Listen),
			(fork_chain_3.tip().block_hash, &listener_3 as &dyn chain::Listen),
		];
		let mut cache = fork_chain_1.header_cache(2..=4);
		cache.extend(fork_chain_2.header_cache(3..=4));
		cache.extend(fork_chain_3.header_cache(4..=4));
		match synchronize_listeners(&main_chain, Network::Bitcoin, &mut cache, listeners).await {
			Ok(header) => assert_eq!(header, main_chain.tip()),
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[tokio::test]
	async fn sync_from_overlapping_chains() {
		let main_chain = Blockchain::default().with_height(4);
		let fork_chain_1 = main_chain.fork_at_height(1);
		let fork_chain_2 = fork_chain_1.fork_at_height(2);
		let fork_chain_3 = fork_chain_2.fork_at_height(3);

		let listener_1 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_1.at_height(4))
			.expect_block_disconnected(*fork_chain_1.at_height(3))
			.expect_block_disconnected(*fork_chain_1.at_height(2))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let listener_2 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_2.at_height(4))
			.expect_block_disconnected(*fork_chain_2.at_height(3))
			.expect_block_disconnected(*fork_chain_2.at_height(2))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let listener_3 = MockChainListener::new()
			.expect_block_disconnected(*fork_chain_3.at_height(4))
			.expect_block_disconnected(*fork_chain_3.at_height(3))
			.expect_block_disconnected(*fork_chain_3.at_height(2))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));

		let listeners = vec![
			(fork_chain_1.tip().block_hash, &listener_1 as &dyn chain::Listen),
			(fork_chain_2.tip().block_hash, &listener_2 as &dyn chain::Listen),
			(fork_chain_3.tip().block_hash, &listener_3 as &dyn chain::Listen),
		];
		let mut cache = fork_chain_1.header_cache(2..=4);
		cache.extend(fork_chain_2.header_cache(3..=4));
		cache.extend(fork_chain_3.header_cache(4..=4));
		match synchronize_listeners(&main_chain, Network::Bitcoin, &mut cache, listeners).await {
			Ok(header) => assert_eq!(header, main_chain.tip()),
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[tokio::test]
	async fn cache_connected_and_keep_disconnected_blocks() {
		let main_chain = Blockchain::default().with_height(2);
		let fork_chain = main_chain.fork_at_height(1);
		let new_tip = main_chain.tip();
		let old_tip = fork_chain.tip();

		let listener = MockChainListener::new()
			.expect_block_disconnected(*old_tip)
			.expect_block_connected(*new_tip);

		let listeners = vec![(old_tip.block_hash, &listener as &dyn chain::Listen)];
		let mut cache = fork_chain.header_cache(2..=2);
		match synchronize_listeners(&main_chain, Network::Bitcoin, &mut cache, listeners).await {
			Ok(_) => {
				assert!(cache.contains_key(&new_tip.block_hash));
				assert!(cache.contains_key(&old_tip.block_hash));
			},
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}
}
