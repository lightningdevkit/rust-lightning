//! When fetching gossip from peers, lightning nodes need to validate that gossip against the
//! current UTXO set. This module defines an implementation of the LDK API required to do so
//! against a [`BlockSource`] which implements a few additional methods for accessing the UTXO set.

use crate::{BlockSource, BlockSourceResult};

use bitcoin::constants::ChainHash;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::transaction::{OutPoint, TxOut};

use lightning::routing::utxo::{UtxoFuture, UtxoLookup, UtxoLookupError, UtxoResult};
use lightning::util::native_async::FutureSpawner;
use lightning::util::wakers::Notifier;

use std::collections::VecDeque;
use std::future::Future;
use std::ops::Deref;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// A trait which extends [`BlockSource`] and can be queried to fetch the txids of the
/// transactions in a block as well as outputs which are members of the current UTXO set.
pub trait UtxoSource: BlockSource + 'static {
	/// Fetches the block hash of the block at the given height.
	///
	/// This will, in turn, be passed to [`Self::get_block_txids`] to fetch the txids of the block
	/// needed for gossip validation.
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> impl Future<Output = BlockSourceResult<BlockHash>> + Send + 'a;

	/// Fetches the txids of all transactions in the block with the given hash, in the order the
	/// transactions appear in the block.
	fn get_block_txids<'a>(
		&'a self, block_hash: &'a BlockHash,
	) -> impl Future<Output = BlockSourceResult<Vec<Txid>>> + Send + 'a;

	/// Returns the output at the given outpoint if it has *not* been spent, i.e. is a member of
	/// the current UTXO set, or `None` otherwise.
	fn get_unspent_txout<'a>(
		&'a self, outpoint: OutPoint,
	) -> impl Future<Output = BlockSourceResult<Option<TxOut>>> + Send + 'a;
}

#[cfg(feature = "tokio")]
/// A trivial [`FutureSpawner`] which delegates to `tokio::spawn`.
pub struct TokioSpawner;
#[cfg(feature = "tokio")]
impl FutureSpawner for TokioSpawner {
	type E = tokio::task::JoinError;
	type SpawnedFutureResult<O> = tokio::task::JoinHandle<O>;
	fn spawn<O: Send + 'static, F: Future<Output = O> + Send + 'static>(
		&self, future: F,
	) -> Self::SpawnedFutureResult<O> {
		tokio::spawn(future)
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
pub struct GossipVerifier<S: FutureSpawner, Blocks: Deref + Send + Sync + 'static + Clone>
where
	Blocks::Target: UtxoSource,
{
	source: Blocks,
	spawn: S,
	txid_cache: Arc<Mutex<VecDeque<(u32, Vec<Txid>)>>>,
	latest_tip_height: Arc<AtomicU32>,
}

const TXID_CACHE_SIZE: usize = 50;

impl<S: FutureSpawner, Blocks: Deref + Send + Sync + Clone> GossipVerifier<S, Blocks>
where
	Blocks::Target: UtxoSource,
{
	/// Constructs a new [`GossipVerifier`] for use in a [`P2PGossipSync`].
	///
	/// [`P2PGossipSync`]: lightning::routing::gossip::P2PGossipSync
	pub fn new(source: Blocks, spawn: S) -> Self {
		Self {
			source,
			spawn,
			txid_cache: Arc::new(Mutex::new(VecDeque::with_capacity(TXID_CACHE_SIZE))),
			latest_tip_height: Arc::new(AtomicU32::new(0)),
		}
	}

	async fn retrieve_utxo(
		source: Blocks, txid_cache: Arc<Mutex<VecDeque<(u32, Vec<Txid>)>>>,
		latest_tip_height: Arc<AtomicU32>, short_channel_id: u64,
	) -> Result<TxOut, UtxoLookupError> {
		let block_height = (short_channel_id >> 5 * 8) as u32; // block height is most significant three bytes
		let transaction_index = ((short_channel_id >> 2 * 8) & 0xffffff) as u32;
		let output_index = (short_channel_id & 0xffff) as u16;

		let mut cached_txid = None;
		{
			let recent_blocks = txid_cache.lock().unwrap();
			for (height, txids) in recent_blocks.iter() {
				if *height == block_height {
					if transaction_index as usize >= txids.len() {
						return Err(UtxoLookupError::UnknownTx);
					}
					cached_txid = Some(txids[transaction_index as usize]);
					break;
				}
			}
		}

		let txid = if let Some(txid) = cached_txid {
			txid
		} else {
			// If the block doesn't yet have five confirmations, error out.
			//
			// The BOLT spec requires nodes wait for six confirmations before announcing a
			// channel, and we give them one block of headroom in case we're delayed seeing a
			// block.
			//
			// Only fetch the current tip if the most recent one we've seen doesn't already bury
			// the block deeply enough, as the tip we fetch can only be higher.
			if block_height + 5 > latest_tip_height.load(Ordering::Relaxed) {
				let (_, tip_height_opt) =
					source.get_best_block().await.map_err(|_| UtxoLookupError::UnknownTx)?;
				if let Some(tip_height) = tip_height_opt {
					latest_tip_height.fetch_max(tip_height, Ordering::Relaxed);
					if block_height + 5 > tip_height {
						return Err(UtxoLookupError::UnknownTx);
					}
				}
			}
			let block_hash = source
				.get_block_hash_by_height(block_height)
				.await
				.map_err(|_| UtxoLookupError::UnknownTx)?;
			let txids = source
				.get_block_txids(&block_hash)
				.await
				.map_err(|_| UtxoLookupError::UnknownTx)?;
			if transaction_index as usize >= txids.len() {
				return Err(UtxoLookupError::UnknownTx);
			}
			let txid = txids[transaction_index as usize];
			{
				let mut recent_blocks = txid_cache.lock().unwrap();
				if !recent_blocks.iter().any(|(height, _)| *height == block_height) {
					if recent_blocks.len() >= TXID_CACHE_SIZE {
						recent_blocks.pop_front();
					}
					recent_blocks.push_back((block_height, txids));
				}
			}
			txid
		};

		let outpoint = OutPoint::new(txid, output_index.into());
		let txout =
			source.get_unspent_txout(outpoint).await.map_err(|_| UtxoLookupError::UnknownTx)?;
		txout.ok_or(UtxoLookupError::UnknownTx)
	}
}

impl<S: FutureSpawner, Blocks: Deref + Send + Sync + Clone> UtxoLookup for GossipVerifier<S, Blocks>
where
	Blocks::Target: UtxoSource,
{
	fn get_utxo(&self, _chain_hash: &ChainHash, scid: u64, notifier: Arc<Notifier>) -> UtxoResult {
		let res = UtxoFuture::new(notifier);
		let fut = res.clone();
		let source = self.source.clone();
		let txid_cache = Arc::clone(&self.txid_cache);
		let latest_tip_height = Arc::clone(&self.latest_tip_height);
		let _not_polled = self.spawn.spawn(async move {
			let res = Self::retrieve_utxo(source, txid_cache, latest_tip_height, scid).await;
			fut.resolve(res);
		});
		UtxoResult::Async(res)
	}
}
