//! When fetching gossip from peers, lightning nodes need to validate that gossip against the
//! current UTXO set. This module defines an implementation of the LDK API required to do so
//! against a [`BlockSource`] which implements a few additional methods for accessing the UTXO set.

use crate::{AsyncBlockSourceResult, BlockData, BlockSource};

use bitcoin::blockdata::transaction::{TxOut, OutPoint};
use bitcoin::hash_types::BlockHash;

use lightning::sign::NodeSigner;

use lightning::ln::peer_handler::{CustomMessageHandler, PeerManager, SocketDescriptor};
use lightning::ln::msgs::{ChannelMessageHandler, OnionMessageHandler};

use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::utxo::{UtxoFuture, UtxoLookup, UtxoResult, UtxoLookupError};

use lightning::util::logger::Logger;

use std::sync::Arc;
use std::future::Future;
use std::ops::Deref;

/// A trait which extends [`BlockSource`] and can be queried to fetch the block at a given height
/// as well as whether a given output is unspent (i.e. a member of the current UTXO set).
///
/// Note that while this is implementable for a [`BlockSource`] which returns filtered block data
/// (i.e. [`BlockData::HeaderOnly`] for [`BlockSource::get_block`] requests), such an
/// implementation will reject all gossip as it is not fully able to verify the UTXOs referenced.
///
/// For efficiency, an implementation may consider caching some set of blocks, as many redundant
/// calls may be made.
pub trait UtxoSource : BlockSource + 'static {
	/// Fetches the block hash of the block at the given height.
	///
	/// This will, in turn, be passed to to [`BlockSource::get_block`] to fetch the block needed
	/// for gossip validation.
	fn get_block_hash_by_height<'a>(&'a self, block_height: u32) -> AsyncBlockSourceResult<'a, BlockHash>;

	/// Returns true if the given output has *not* been spent, i.e. is a member of the current UTXO
	/// set.
	fn is_output_unspent<'a>(&'a self, outpoint: OutPoint) -> AsyncBlockSourceResult<'a, bool>;
}

/// A generic trait which is able to spawn futures in the background.
///
/// If the `tokio` feature is enabled, this is implemented on `TokioSpawner` struct which
/// delegates to `tokio::spawn()`.
pub trait FutureSpawner : Send + Sync + 'static {
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

/// A struct which wraps a [`UtxoSource`] and a few LDK objects and implements the LDK
/// [`UtxoLookup`] trait.
///
/// Note that if you're using this against a Bitcoin Core REST or RPC server, you likely wish to
/// increase the `rpcworkqueue` setting in Bitcoin Core as LDK attempts to parallelize requests (a
/// value of 1024 should more than suffice), and ensure you have sufficient file descriptors
/// available on both Bitcoin Core and your LDK application for each request to hold its own
/// connection.
pub struct GossipVerifier<S: FutureSpawner,
	Blocks: Deref + Send + Sync + 'static + Clone,
	L: Deref + Send + Sync + 'static,
	Descriptor: SocketDescriptor + Send + Sync + 'static,
	CM: Deref + Send + Sync + 'static,
	OM: Deref + Send + Sync + 'static,
	CMH: Deref + Send + Sync + 'static,
	NS: Deref + Send + Sync + 'static,
> where
	Blocks::Target: UtxoSource,
	L::Target: Logger,
	CM::Target: ChannelMessageHandler,
	OM::Target: OnionMessageHandler,
	CMH::Target: CustomMessageHandler,
	NS::Target: NodeSigner,
{
	source: Blocks,
	peer_manager: Arc<PeerManager<Descriptor, CM, Arc<P2PGossipSync<Arc<NetworkGraph<L>>, Self, L>>, OM, L, CMH, NS>>,
	gossiper: Arc<P2PGossipSync<Arc<NetworkGraph<L>>, Self, L>>,
	spawn: S,
}

impl<S: FutureSpawner,
	Blocks: Deref + Send + Sync + Clone,
	L: Deref + Send + Sync,
	Descriptor: SocketDescriptor + Send + Sync,
	CM: Deref + Send + Sync,
	OM: Deref + Send + Sync,
	CMH: Deref + Send + Sync,
	NS: Deref + Send + Sync,
> GossipVerifier<S, Blocks, L, Descriptor, CM, OM, CMH, NS> where
	Blocks::Target: UtxoSource,
	L::Target: Logger,
	CM::Target: ChannelMessageHandler,
	OM::Target: OnionMessageHandler,
	CMH::Target: CustomMessageHandler,
	NS::Target: NodeSigner,
{
	/// Constructs a new [`GossipVerifier`].
	///
	/// This is expected to be given to a [`P2PGossipSync`] (initially constructed with `None` for
	/// the UTXO lookup) via [`P2PGossipSync::add_utxo_lookup`].
	pub fn new(source: Blocks, spawn: S, gossiper: Arc<P2PGossipSync<Arc<NetworkGraph<L>>, Self, L>>, peer_manager: Arc<PeerManager<Descriptor, CM, Arc<P2PGossipSync<Arc<NetworkGraph<L>>, Self, L>>, OM, L, CMH, NS>>) -> Self {
		Self { source, spawn, gossiper, peer_manager }
	}

	async fn retrieve_utxo(source: Blocks, short_channel_id: u64) -> Result<TxOut, UtxoLookupError> {
		let block_height = (short_channel_id >> 5 * 8) as u32; // block height is most significant three bytes
		let transaction_index = ((short_channel_id >> 2 * 8) & 0xffffff) as u32;
		let output_index = (short_channel_id & 0xffff) as u16;

		let block_hash = source.get_block_hash_by_height(block_height).await
			.map_err(|_| UtxoLookupError::UnknownTx)?;
		let block_data = source.get_block(&block_hash).await
			.map_err(|_| UtxoLookupError::UnknownTx)?;
		let mut block = match block_data {
			BlockData::HeaderOnly(_) => return Err(UtxoLookupError::UnknownTx),
			BlockData::FullBlock(block) => block,
		};
		if transaction_index as usize >= block.txdata.len() {
			return Err(UtxoLookupError::UnknownTx);
		}
		let mut transaction = block.txdata.swap_remove(transaction_index as usize);
		if output_index as usize >= transaction.output.len() {
			return Err(UtxoLookupError::UnknownTx);
		}
		let outpoint_unspent =
			source.is_output_unspent(OutPoint::new(transaction.txid(), output_index.into())).await
				.map_err(|_| UtxoLookupError::UnknownTx)?;
		if outpoint_unspent {
			Ok(transaction.output.swap_remove(output_index as usize))
		} else {
			Err(UtxoLookupError::UnknownTx)
		}
	}
}

impl<S: FutureSpawner,
	Blocks: Deref + Send + Sync + Clone,
	L: Deref + Send + Sync,
	Descriptor: SocketDescriptor + Send + Sync,
	CM: Deref + Send + Sync,
	OM: Deref + Send + Sync,
	CMH: Deref + Send + Sync,
	NS: Deref + Send + Sync,
> Deref for GossipVerifier<S, Blocks, L, Descriptor, CM, OM, CMH, NS> where
	Blocks::Target: UtxoSource,
	L::Target: Logger,
	CM::Target: ChannelMessageHandler,
	OM::Target: OnionMessageHandler,
	CMH::Target: CustomMessageHandler,
	NS::Target: NodeSigner,
{
	type Target = Self;
	fn deref(&self) -> &Self { self }
}


impl<S: FutureSpawner,
	Blocks: Deref + Send + Sync + Clone,
	L: Deref + Send + Sync,
	Descriptor: SocketDescriptor + Send + Sync,
	CM: Deref + Send + Sync,
	OM: Deref + Send + Sync,
	CMH: Deref + Send + Sync,
	NS: Deref + Send + Sync,
> UtxoLookup for GossipVerifier<S, Blocks, L, Descriptor, CM, OM, CMH, NS> where
	Blocks::Target: UtxoSource,
	L::Target: Logger,
	CM::Target: ChannelMessageHandler,
	OM::Target: OnionMessageHandler,
	CMH::Target: CustomMessageHandler,
	NS::Target: NodeSigner,
{
	fn get_utxo(&self, _genesis_hash: &BlockHash, short_channel_id: u64) -> UtxoResult {
		let res = UtxoFuture::new();
		let fut = res.clone();
		let source = self.source.clone();
		let gossiper = Arc::clone(&self.gossiper);
		let pm = Arc::clone(&self.peer_manager);
		self.spawn.spawn(async move {
			let res = Self::retrieve_utxo(source, short_channel_id).await;
			fut.resolve(gossiper.network_graph(), &*gossiper, res);
			pm.process_events();
		});
		UtxoResult::Async(res)
	}
}
