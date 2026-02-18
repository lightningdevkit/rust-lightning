//! Utilities to assist in the initial sync required to initialize or reload Rust-Lightning objects
//! from disk.

use crate::async_poll::{MultiResultFuturePoller, ResultFuture};
use crate::poll::{ChainPoller, Poll, Validate, ValidatedBlockHeader};
use crate::{BlockData, BlockSource, BlockSourceResult, Cache, ChainNotifier, HeaderCache};

use bitcoin::block::Header;
use bitcoin::network::Network;

use lightning::chain;
use lightning::chain::BestBlock;

use std::ops::Deref;

/// Returns a validated block header of the source's best chain tip.
///
/// Upon success, the returned header can be used to initialize [`SpvClient`]. Useful during a fresh
/// start when there are no chain listeners to sync yet.
///
/// [`SpvClient`]: crate::SpvClient
pub async fn validate_best_block_header<B: Deref>(
	block_source: B,
) -> BlockSourceResult<ValidatedBlockHeader>
where
	B::Target: BlockSource,
{
	let (best_block_hash, best_block_height) = block_source.get_best_block().await?;
	block_source.get_header(&best_block_hash, best_block_height).await?.validate(best_block_hash)
}

/// Performs a one-time sync of chain listeners using a single *trusted* block source, bringing each
/// listener's view of the chain from its paired block hash to `block_source`'s best chain tip.
///
/// Upon success, the returned header and header cache can be used to initialize [`SpvClient`]. In
/// the case of failure, each listener may be left at a different block hash than the one it was
/// originally paired with.
///
/// Useful during startup to bring the [`ChannelManager`] and each [`ChannelMonitor`] in sync before
/// switching to [`SpvClient`]. For example:
///
/// ```
/// use bitcoin::network::Network;
///
/// use lightning::chain;
/// use lightning::chain::{BestBlock, Watch};
/// use lightning::chain::chainmonitor;
/// use lightning::chain::chainmonitor::ChainMonitor;
/// use lightning::chain::channelmonitor::ChannelMonitor;
/// use lightning::chain::chaininterface::BroadcasterInterface;
/// use lightning::chain::chaininterface::FeeEstimator;
/// use lightning::ln::channelmanager::{ChannelManager, ChannelManagerReadArgs};
/// use lightning::onion_message::messenger::MessageRouter;
/// use lightning::routing::router::Router;
/// use lightning::sign;
/// use lightning::sign::{EntropySource, NodeSigner, SignerProvider};
/// use lightning::util::config::UserConfig;
/// use lightning::util::logger::Logger;
/// use lightning::util::ser::ReadableArgs;
///
/// use lightning_block_sync::*;
///
/// use lightning::io::Cursor;
///
/// async fn init_sync<
/// 	B: BlockSource,
/// 	ES: EntropySource,
/// 	NS: NodeSigner,
/// 	SP: SignerProvider,
/// 	T: BroadcasterInterface,
/// 	F: FeeEstimator,
/// 	R: Router,
/// 	MR: MessageRouter,
/// 	L: Logger,
/// 	C: chain::Filter,
/// 	P: chainmonitor::Persist<SP::EcdsaSigner>,
/// >(
/// 	block_source: &B,
/// 	chain_monitor: &ChainMonitor<SP::EcdsaSigner, &C, &T, &F, &L, &P, &ES>,
/// 	config: UserConfig,
/// 	entropy_source: &ES,
/// 	node_signer: &NS,
/// 	signer_provider: &SP,
/// 	tx_broadcaster: &T,
/// 	fee_estimator: &F,
/// 	router: &R,
/// 	message_router: &MR,
/// 	logger: &L,
/// 	persister: &P,
/// ) {
/// 	// Read a serialized channel monitor paired with the best block when it was persisted.
/// 	let serialized_monitor = "...";
/// 	let (monitor_best_block, mut monitor) = <(BestBlock, ChannelMonitor<SP::EcdsaSigner>)>::read(
/// 		&mut Cursor::new(&serialized_monitor), (entropy_source, signer_provider)).unwrap();
///
/// 	// Read the channel manager paired with the best block when it was persisted.
/// 	let serialized_manager = "...";
/// 	let (manager_best_block, mut manager) = {
/// 		let read_args = ChannelManagerReadArgs::new(
/// 			entropy_source,
/// 			node_signer,
/// 			signer_provider,
/// 			fee_estimator,
/// 			chain_monitor,
/// 			tx_broadcaster,
/// 			router,
/// 			message_router,
/// 			logger,
/// 			config,
/// 			vec![&mut monitor],
/// 		);
/// 		<(BestBlock, ChannelManager<&ChainMonitor<SP::EcdsaSigner, &C, &T, &F, &L, &P, &ES>, &T, &ES, &NS, &SP, &F, &R, &MR, &L>)>::read(
/// 			&mut Cursor::new(&serialized_manager), read_args).unwrap()
/// 	};
///
/// 	// Synchronize any channel monitors and the channel manager to be on the best block.
/// 	let mut monitor_listener = (monitor, &*tx_broadcaster, &*fee_estimator, &*logger);
/// 	let listeners = vec![
/// 		(monitor_best_block, &monitor_listener as &dyn chain::Listen),
/// 		(manager_best_block, &manager as &dyn chain::Listen),
/// 	];
/// 	let (chain_cache, chain_tip) = init::synchronize_listeners(
/// 		block_source, Network::Bitcoin, listeners).await.unwrap();
///
/// 	// Allow the chain monitor to watch any channels.
/// 	let monitor = monitor_listener.0;
/// 	chain_monitor.watch_channel(monitor.channel_id(), monitor);
///
/// 	// Create an SPV client to notify the chain monitor and channel manager of block events.
/// 	let chain_poller = poll::ChainPoller::new(block_source, Network::Bitcoin);
/// 	let mut chain_listener = (chain_monitor, &manager);
/// 	let spv_client = SpvClient::new(chain_tip, chain_poller, chain_cache, &chain_listener);
/// }
/// ```
///
/// [`SpvClient`]: crate::SpvClient
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
/// [`ChannelMonitor`]: lightning::chain::channelmonitor::ChannelMonitor
pub async fn synchronize_listeners<B: Deref + Sized + Send + Sync, L: chain::Listen + ?Sized>(
	block_source: B, network: Network, mut chain_listeners: Vec<(BestBlock, &L)>,
) -> BlockSourceResult<(HeaderCache, ValidatedBlockHeader)>
where
	B::Target: BlockSource,
{
	let best_header = validate_best_block_header(&*block_source).await?;

	// Find differences and disconnect blocks for each listener individually.
	let mut chain_poller = ChainPoller::new(block_source, network);
	let mut chain_listeners_at_height = Vec::new();
	let mut most_connected_blocks = Vec::new();
	let mut header_cache = HeaderCache::new();
	for (old_best_block, chain_listener) in chain_listeners.drain(..) {
		// Disconnect any stale blocks, but keep them in the cache for the next iteration.
		let (common_ancestor, connected_blocks) = {
			let chain_listener = &DynamicChainListener(chain_listener);
			let mut cache_wrapper = HeaderCacheNoDisconnect(&mut header_cache);
			let mut chain_notifier =
				ChainNotifier { header_cache: &mut cache_wrapper, chain_listener };
			let difference = chain_notifier
				.find_difference_from_best_block(best_header, old_best_block, &mut chain_poller)
				.await?;
			if difference.common_ancestor.block_hash != old_best_block.block_hash {
				chain_notifier.disconnect_blocks(difference.common_ancestor);
			}
			(difference.common_ancestor, difference.connected_blocks)
		};

		// Keep track of the most common ancestor and all blocks connected across all listeners.
		chain_listeners_at_height.push((common_ancestor.height, chain_listener));
		if connected_blocks.len() > most_connected_blocks.len() {
			most_connected_blocks = connected_blocks;
		}
	}

	while !most_connected_blocks.is_empty() {
		#[cfg(not(test))]
		const MAX_BLOCKS_AT_ONCE: usize = 6 * 6; // Six hours of blocks, 144MiB encoded
		#[cfg(test)]
		const MAX_BLOCKS_AT_ONCE: usize = 2;

		let mut fetch_block_futures =
			Vec::with_capacity(core::cmp::min(MAX_BLOCKS_AT_ONCE, most_connected_blocks.len()));
		for header in most_connected_blocks.iter().rev().take(MAX_BLOCKS_AT_ONCE) {
			let fetch_future = chain_poller.fetch_block(header);
			fetch_block_futures
				.push(ResultFuture::Pending(Box::pin(async move { (header, fetch_future.await) })));
		}
		let results = MultiResultFuturePoller::new(fetch_block_futures).await.into_iter();

		const NO_BLOCK: Option<(u32, crate::poll::ValidatedBlock)> = None;
		let mut fetched_blocks = [NO_BLOCK; MAX_BLOCKS_AT_ONCE];
		for ((header, block_res), result) in results.into_iter().zip(fetched_blocks.iter_mut()) {
			let block = block_res?;
			header_cache.block_connected(header.block_hash, *header);
			*result = Some((header.height, block));
		}
		debug_assert!(fetched_blocks.iter().take(most_connected_blocks.len()).all(|r| r.is_some()));
		// TODO: When our MSRV is 1.82, use is_sorted_by_key
		debug_assert!(fetched_blocks.windows(2).all(|blocks| {
			if let (Some(a), Some(b)) = (&blocks[0], &blocks[1]) {
				a.0 < b.0
			} else {
				// Any non-None blocks have to come before any None entries
				blocks[1].is_none()
			}
		}));

		for (listener_height, listener) in chain_listeners_at_height.iter() {
			// Connect blocks for this listener.
			for result in fetched_blocks.iter() {
				if let Some((height, block_data)) = result {
					if *height > *listener_height {
						match &**block_data {
							BlockData::FullBlock(block) => {
								listener.block_connected(&block, *height);
							},
							BlockData::HeaderOnly(header_data) => {
								listener.filtered_block_connected(&header_data, &[], *height);
							},
						}
					}
				}
			}
		}

		most_connected_blocks
			.truncate(most_connected_blocks.len().saturating_sub(MAX_BLOCKS_AT_ONCE));
	}

	Ok((header_cache, best_header))
}

/// Wrapper for supporting dynamically sized chain listeners.
struct DynamicChainListener<'a, L: chain::Listen + ?Sized>(&'a L);

impl<'a, L: chain::Listen + ?Sized> chain::Listen for DynamicChainListener<'a, L> {
	fn filtered_block_connected(
		&self, _header: &Header, _txdata: &chain::transaction::TransactionData, _height: u32,
	) {
		unreachable!()
	}

	fn blocks_disconnected(&self, fork_point: BestBlock) {
		self.0.blocks_disconnected(fork_point)
	}
}

/// Wrapper around HeaderCache that ignores `blocks_disconnected` calls, retaining disconnected
/// blocks in the cache. This is useful during initial sync to keep headers available across
/// multiple listeners.
struct HeaderCacheNoDisconnect<'a>(&'a mut HeaderCache);

impl<'a> crate::Cache for &mut HeaderCacheNoDisconnect<'a> {
	fn look_up(&self, block_hash: &bitcoin::hash_types::BlockHash) -> Option<&ValidatedBlockHeader> {
		self.0.look_up(block_hash)
	}

	fn insert_during_diff(&mut self, block_hash: bitcoin::hash_types::BlockHash, block_header: ValidatedBlockHeader) {
		self.0.insert_during_diff(block_hash, block_header);
	}

	fn block_connected(&mut self, block_hash: bitcoin::hash_types::BlockHash, block_header: ValidatedBlockHeader) {
		self.0.block_connected(block_hash, block_header);
	}

	fn blocks_disconnected(&mut self, _fork_point: &ValidatedBlockHeader) {
		// Intentionally ignore disconnections to retain blocks in cache
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_utils::{Blockchain, MockChainListener};
	use crate::Cache;

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
		let listener_3 = MockChainListener::new().expect_block_connected(*chain.at_height(4));

		let listeners = vec![
			(chain.best_block_at_height(1), &listener_1 as &dyn chain::Listen),
			(chain.best_block_at_height(2), &listener_2 as &dyn chain::Listen),
			(chain.best_block_at_height(3), &listener_3 as &dyn chain::Listen),
		];
		match synchronize_listeners(&chain, Network::Bitcoin, listeners).await {
			Ok((cache, header)) => {
				assert_eq!(header, chain.tip());
				assert!(cache.look_up(&chain.at_height(1).block_hash).is_some());
				assert!(cache.look_up(&chain.at_height(2).block_hash).is_some());
				assert!(cache.look_up(&chain.at_height(3).block_hash).is_some());
				assert!(cache.look_up(&chain.at_height(4).block_hash).is_some());
			},
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
			.expect_blocks_disconnected(*fork_chain_1.at_height(1))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let listener_2 = MockChainListener::new()
			.expect_blocks_disconnected(*fork_chain_2.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let listener_3 = MockChainListener::new()
			.expect_blocks_disconnected(*fork_chain_3.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));

		let listeners = vec![
			(fork_chain_1.best_block(), &listener_1 as &dyn chain::Listen),
			(fork_chain_2.best_block(), &listener_2 as &dyn chain::Listen),
			(fork_chain_3.best_block(), &listener_3 as &dyn chain::Listen),
		];
		match synchronize_listeners(&main_chain, Network::Bitcoin, listeners).await {
			Ok((cache, header)) => {
				assert_eq!(header, main_chain.tip());
				assert!(cache.look_up(&main_chain.at_height(1).block_hash).is_some());
				assert!(cache.look_up(&main_chain.at_height(2).block_hash).is_some());
				assert!(cache.look_up(&main_chain.at_height(3).block_hash).is_some());
				assert!(cache.look_up(&fork_chain_1.at_height(2).block_hash).is_none());
				assert!(cache.look_up(&fork_chain_2.at_height(3).block_hash).is_none());
				assert!(cache.look_up(&fork_chain_3.at_height(4).block_hash).is_none());
			},
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
			.expect_blocks_disconnected(*fork_chain_1.at_height(1))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let listener_2 = MockChainListener::new()
			.expect_blocks_disconnected(*fork_chain_2.at_height(1))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));
		let listener_3 = MockChainListener::new()
			.expect_blocks_disconnected(*fork_chain_3.at_height(1))
			.expect_block_connected(*main_chain.at_height(2))
			.expect_block_connected(*main_chain.at_height(3))
			.expect_block_connected(*main_chain.at_height(4));

		let listeners = vec![
			(fork_chain_1.best_block(), &listener_1 as &dyn chain::Listen),
			(fork_chain_2.best_block(), &listener_2 as &dyn chain::Listen),
			(fork_chain_3.best_block(), &listener_3 as &dyn chain::Listen),
		];
		match synchronize_listeners(&main_chain, Network::Bitcoin, listeners).await {
			Ok((cache, header)) => {
				assert_eq!(header, main_chain.tip());
				assert!(cache.look_up(&main_chain.at_height(1).block_hash).is_some());
				assert!(cache.look_up(&main_chain.at_height(2).block_hash).is_some());
				assert!(cache.look_up(&main_chain.at_height(3).block_hash).is_some());
				assert!(cache.look_up(&main_chain.at_height(4).block_hash).is_some());
				assert!(cache.look_up(&fork_chain_1.at_height(2).block_hash).is_none());
				assert!(cache.look_up(&fork_chain_1.at_height(3).block_hash).is_none());
				assert!(cache.look_up(&fork_chain_1.at_height(4).block_hash).is_none());
			},
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}
}
