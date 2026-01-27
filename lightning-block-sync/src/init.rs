//! Utilities to assist in the initial sync required to initialize or reload Rust-Lightning objects
//! from disk.

use crate::poll::{ChainPoller, Validate, ValidatedBlockHeader};
use crate::{BlockSource, BlockSourceResult, Cache, ChainNotifier, UnboundedCache};

use bitcoin::block::Header;
use bitcoin::hash_types::BlockHash;
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
) -> BlockSourceResult<(UnboundedCache, ValidatedBlockHeader)>
where
	B::Target: BlockSource,
{
	let best_header = validate_best_block_header(&*block_source).await?;

	// Find differences and disconnect blocks for each listener individually.
	let mut chain_poller = ChainPoller::new(block_source, network);
	let mut chain_listeners_at_height = Vec::new();
	let mut most_common_ancestor = None;
	let mut most_connected_blocks = Vec::new();
	let mut header_cache = UnboundedCache::new();
	for (old_best_block, chain_listener) in chain_listeners.drain(..) {
		// Disconnect any stale blocks, but keep them in the cache for the next iteration.
		let (common_ancestor, connected_blocks) = {
			let chain_listener = &DynamicChainListener(chain_listener);
			let mut chain_notifier =
				ChainNotifier { header_cache: &mut header_cache, chain_listener };
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
			most_common_ancestor = Some(common_ancestor);
			most_connected_blocks = connected_blocks;
		}
	}

	// Connect new blocks for all listeners at once to avoid re-fetching blocks.
	if let Some(common_ancestor) = most_common_ancestor {
		let chain_listener = &ChainListenerSet(chain_listeners_at_height);
		let mut chain_notifier = ChainNotifier { header_cache: &mut header_cache, chain_listener };
		chain_notifier
			.connect_blocks(common_ancestor, most_connected_blocks, &mut chain_poller)
			.await
			.map_err(|(e, _)| e)?;
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

/// A set of dynamically sized chain listeners, each paired with a starting block height.
struct ChainListenerSet<'a, L: chain::Listen + ?Sized>(Vec<(u32, &'a L)>);

impl<'a, L: chain::Listen + ?Sized> chain::Listen for ChainListenerSet<'a, L> {
	fn block_connected(&self, block: &bitcoin::Block, height: u32) {
		for (starting_height, chain_listener) in self.0.iter() {
			if height > *starting_height {
				chain_listener.block_connected(block, height);
			}
		}
	}

	fn filtered_block_connected(
		&self, header: &Header, txdata: &chain::transaction::TransactionData, height: u32,
	) {
		for (starting_height, chain_listener) in self.0.iter() {
			if height > *starting_height {
				chain_listener.filtered_block_connected(header, txdata, height);
			}
		}
	}

	fn blocks_disconnected(&self, _fork_point: BestBlock) {
		unreachable!()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_utils::{Blockchain, MockChainListener};

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
			Ok((_, header)) => assert_eq!(header, chain.tip()),
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
			Ok((_, header)) => assert_eq!(header, main_chain.tip()),
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
			Ok((_, header)) => assert_eq!(header, main_chain.tip()),
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}
}
