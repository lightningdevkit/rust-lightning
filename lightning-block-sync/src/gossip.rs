//! When fetching gossip from peers, lightning nodes need to validate that gossip against the
//! current UTXO set. This module defines an implementation of the LDK API required to do so
//! against a [`BlockSource`] which implements a few additional methods for accessing the UTXO set.

use crate::{AsyncBlockSourceResult, BlockData, BlockSource, BlockSourceError};

use bitcoin::block::Block;
use bitcoin::constants::ChainHash;
use bitcoin::hash_types::BlockHash;
use bitcoin::transaction::{OutPoint, TxOut};

use lightning::ln::peer_handler::APeerManager;

use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::utxo::{UtxoFuture, UtxoLookup, UtxoLookupError, UtxoResult};

use lightning::util::logger::Logger;

use std::collections::VecDeque;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

/// A trait which extends [`BlockSource`] and can be queried to fetch the block at a given height
/// as well as whether a given output is unspent (i.e. a member of the current UTXO set).
///
/// Note that while this is implementable for a [`BlockSource`] which returns filtered block data
/// (i.e. [`BlockData::HeaderOnly`] for [`BlockSource::get_block`] requests), such an
/// implementation will reject all gossip as it is not fully able to verify the UTXOs referenced.
pub trait UtxoSource: BlockSource + 'static {
	/// Fetches the block hash of the block at the given height.
	///
	/// This will, in turn, be passed to to [`BlockSource::get_block`] to fetch the block needed
	/// for gossip validation.
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> AsyncBlockSourceResult<'a, BlockHash>;

	/// Returns true if the given output has *not* been spent, i.e. is a member of the current UTXO
	/// set.
	fn is_output_unspent<'a>(&'a self, outpoint: OutPoint) -> AsyncBlockSourceResult<'a, bool>;
}

/// A generic trait which is able to spawn futures in the background.
///
/// If the `tokio` feature is enabled, this is implemented on `TokioSpawner` struct which
/// delegates to `tokio::spawn()`.
pub trait FutureSpawner: Send + Sync + 'static {
	/// Spawns the given future as a background task.
	///
	/// This method MUST NOT block on the given future immediately.
	fn spawn<T: Future<Output = ()> + Send + 'static>(&self, future: T);
}

#[cfg(feature = "tokio")]
/// A trivial [`FutureSpawner`] which delegates to `tokio::spawn`.
pub struct TokioSpawner;
#[cfg(feature = "tokio")]
impl FutureSpawner for TokioSpawner {
	fn spawn<T: Future<Output = ()> + Send + 'static>(&self, future: T) {
		tokio::spawn(future);
	}
}

/// A trivial future which joins two other futures and polls them at the same time, returning only
/// once both complete.
pub(crate) struct Joiner<
	A: Future<Output = Result<(BlockHash, Option<u32>), BlockSourceError>> + Unpin,
	B: Future<Output = Result<BlockHash, BlockSourceError>> + Unpin,
> {
	pub a: A,
	pub b: B,
	a_res: Option<(BlockHash, Option<u32>)>,
	b_res: Option<BlockHash>,
}

impl<
		A: Future<Output = Result<(BlockHash, Option<u32>), BlockSourceError>> + Unpin,
		B: Future<Output = Result<BlockHash, BlockSourceError>> + Unpin,
	> Joiner<A, B>
{
	fn new(a: A, b: B) -> Self {
		Self { a, b, a_res: None, b_res: None }
	}
}

impl<
		A: Future<Output = Result<(BlockHash, Option<u32>), BlockSourceError>> + Unpin,
		B: Future<Output = Result<BlockHash, BlockSourceError>> + Unpin,
	> Future for Joiner<A, B>
{
	type Output = Result<((BlockHash, Option<u32>), BlockHash), BlockSourceError>;
	fn poll(mut self: Pin<&mut Self>, ctx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
		if self.a_res.is_none() {
			match Pin::new(&mut self.a).poll(ctx) {
				Poll::Ready(res) => {
					if let Ok(ok) = res {
						self.a_res = Some(ok);
					} else {
						return Poll::Ready(Err(res.unwrap_err()));
					}
				},
				Poll::Pending => {},
			}
		}
		if self.b_res.is_none() {
			match Pin::new(&mut self.b).poll(ctx) {
				Poll::Ready(res) => {
					if let Ok(ok) = res {
						self.b_res = Some(ok);
					} else {
						return Poll::Ready(Err(res.unwrap_err()));
					}
				},
				Poll::Pending => {},
			}
		}
		if let Some(b_res) = self.b_res {
			if let Some(a_res) = self.a_res {
				return Poll::Ready(Ok((a_res, b_res)));
			}
		}
		Poll::Pending
	}
}

/// A struct which wraps a [`UtxoSource`] and a few LDK objects and implements the LDK
/// [`UtxoLookup`] trait.
///
/// Note that if you're using this against a Bitcoin Core REST or RPC server, you likely wish to
/// increase the `rpcworkqueue` setting in Bitcoin Core as LDK attempts to parallelize requests (a
/// value of 1024 should more than suffice), and ensure you have sufficient file descriptors
/// available on both Bitcoin Core and your LDK application for each request to hold its own
/// connection.
pub struct GossipVerifier<
	S: FutureSpawner,
	Blocks: Deref + Send + Sync + 'static + Clone,
	L: Deref + Send + Sync + 'static,
> where
	Blocks::Target: UtxoSource,
	L::Target: Logger,
{
	source: Blocks,
	peer_manager_wake: Arc<dyn Fn() + Send + Sync>,
	gossiper: Arc<P2PGossipSync<Arc<NetworkGraph<L>>, Self, L>>,
	spawn: S,
	block_cache: Arc<Mutex<VecDeque<(u32, Block)>>>,
}

const BLOCK_CACHE_SIZE: usize = 5;

impl<S: FutureSpawner, Blocks: Deref + Send + Sync + Clone, L: Deref + Send + Sync>
	GossipVerifier<S, Blocks, L>
where
	Blocks::Target: UtxoSource,
	L::Target: Logger,
{
	/// Constructs a new [`GossipVerifier`].
	///
	/// This is expected to be given to a [`P2PGossipSync`] (initially constructed with `None` for
	/// the UTXO lookup) via [`P2PGossipSync::add_utxo_lookup`].
	pub fn new<APM: Deref + Send + Sync + Clone + 'static>(
		source: Blocks, spawn: S, gossiper: Arc<P2PGossipSync<Arc<NetworkGraph<L>>, Self, L>>,
		peer_manager: APM,
	) -> Self
	where
		APM::Target: APeerManager,
	{
		let peer_manager_wake = Arc::new(move || peer_manager.as_ref().process_events());
		Self {
			source,
			spawn,
			gossiper,
			peer_manager_wake,
			block_cache: Arc::new(Mutex::new(VecDeque::with_capacity(BLOCK_CACHE_SIZE))),
		}
	}

	async fn retrieve_utxo(
		source: Blocks, block_cache: Arc<Mutex<VecDeque<(u32, Block)>>>, short_channel_id: u64,
	) -> Result<TxOut, UtxoLookupError> {
		let block_height = (short_channel_id >> 5 * 8) as u32; // block height is most significant three bytes
		let transaction_index = ((short_channel_id >> 2 * 8) & 0xffffff) as u32;
		let output_index = (short_channel_id & 0xffff) as u16;

		let (outpoint, output);

		'tx_found: loop {
			macro_rules! process_block {
				($block: expr) => {{
					if transaction_index as usize >= $block.txdata.len() {
						return Err(UtxoLookupError::UnknownTx);
					}
					let transaction = &$block.txdata[transaction_index as usize];
					if output_index as usize >= transaction.output.len() {
						return Err(UtxoLookupError::UnknownTx);
					}

					outpoint = OutPoint::new(transaction.txid(), output_index.into());
					output = transaction.output[output_index as usize].clone();
				}};
			}
			{
				let recent_blocks = block_cache.lock().unwrap();
				for (height, block) in recent_blocks.iter() {
					if *height == block_height {
						process_block!(block);
						break 'tx_found;
					}
				}
			}

			let ((_, tip_height_opt), block_hash) =
				Joiner::new(source.get_best_block(), source.get_block_hash_by_height(block_height))
					.await
					.map_err(|_| UtxoLookupError::UnknownTx)?;
			if let Some(tip_height) = tip_height_opt {
				// If the block doesn't yet have five confirmations, error out.
				//
				// The BOLT spec requires nodes wait for six confirmations before announcing a
				// channel, and we give them one block of headroom in case we're delayed seeing a
				// block.
				if block_height + 5 > tip_height {
					return Err(UtxoLookupError::UnknownTx);
				}
			}
			let block_data =
				source.get_block(&block_hash).await.map_err(|_| UtxoLookupError::UnknownTx)?;
			let block = match block_data {
				BlockData::HeaderOnly(_) => return Err(UtxoLookupError::UnknownTx),
				BlockData::FullBlock(block) => block,
			};
			process_block!(block);
			{
				let mut recent_blocks = block_cache.lock().unwrap();
				let mut insert = true;
				for (height, _) in recent_blocks.iter() {
					if *height == block_height {
						insert = false;
					}
				}
				if insert {
					if recent_blocks.len() >= BLOCK_CACHE_SIZE {
						recent_blocks.pop_front();
					}
					recent_blocks.push_back((block_height, block));
				}
			}
			break 'tx_found;
		}
		let outpoint_unspent =
			source.is_output_unspent(outpoint).await.map_err(|_| UtxoLookupError::UnknownTx)?;
		if outpoint_unspent {
			Ok(output)
		} else {
			Err(UtxoLookupError::UnknownTx)
		}
	}
}

impl<S: FutureSpawner, Blocks: Deref + Send + Sync + Clone, L: Deref + Send + Sync> Deref
	for GossipVerifier<S, Blocks, L>
where
	Blocks::Target: UtxoSource,
	L::Target: Logger,
{
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}

impl<S: FutureSpawner, Blocks: Deref + Send + Sync + Clone, L: Deref + Send + Sync> UtxoLookup
	for GossipVerifier<S, Blocks, L>
where
	Blocks::Target: UtxoSource,
	L::Target: Logger,
{
	fn get_utxo(&self, _chain_hash: &ChainHash, short_channel_id: u64) -> UtxoResult {
		let res = UtxoFuture::new();
		let fut = res.clone();
		let source = self.source.clone();
		let gossiper = Arc::clone(&self.gossiper);
		let block_cache = Arc::clone(&self.block_cache);
		let pmw = Arc::clone(&self.peer_manager_wake);
		self.spawn.spawn(async move {
			let res = Self::retrieve_utxo(source, block_cache, short_channel_id).await;
			fut.resolve(gossiper.network_graph(), &*gossiper, res);
			(pmw)();
		});
		UtxoResult::Async(res)
	}
}
