// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Structs and traits which allow other parts of rust-lightning to interact with the blockchain.

use bitcoin::block::{Block, Header};
use bitcoin::constants::genesis_block;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::network::Network;
use bitcoin::script::{Script, ScriptBuf};
use bitcoin::secp256k1::PublicKey;

use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, MonitorEvent};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::impl_writeable_tlv_based;
use crate::ln::types::ChannelId;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::HTLCDescriptor;

use core::ops::Deref;

#[allow(unused_imports)]
use crate::prelude::*;

pub mod chaininterface;
pub mod chainmonitor;
pub mod channelmonitor;
pub mod deferred;
pub(crate) mod onchaintx;
pub(crate) mod package;
pub mod transaction;

/// The best known block as identified by its hash and height.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct BestBlock {
	/// The block's hash
	pub block_hash: BlockHash,
	/// The height at which the block was confirmed.
	pub height: u32,
}

impl BestBlock {
	/// Constructs a `BestBlock` that represents the genesis block at height 0 of the given
	/// network.
	pub fn from_network(network: Network) -> Self {
		BestBlock { block_hash: genesis_block(network).header.block_hash(), height: 0 }
	}

	/// Returns a `BestBlock` as identified by the given block hash and height.
	///
	/// This is not exported to bindings users directly as the bindings auto-generate an
	/// equivalent `new`.
	pub fn new(block_hash: BlockHash, height: u32) -> Self {
		BestBlock { block_hash, height }
	}
}

impl_writeable_tlv_based!(BestBlock, {
	(0, block_hash, required),
	(2, height, required),
});

/// The `Listen` trait is used to notify when blocks have been connected or disconnected from the
/// chain.
///
/// Useful when needing to replay chain data upon startup or as new chain events occur. Clients
/// sourcing chain data using a block-oriented API should prefer this interface over [`Confirm`].
/// Such clients fetch the entire header chain whereas clients using [`Confirm`] only fetch headers
/// when needed.
///
/// By using [`Listen::filtered_block_connected`] this interface supports clients fetching the
/// entire header chain and only blocks with matching transaction data using BIP 157 filters or
/// other similar filtering.
///
/// # Requirements
///
/// Each block must be connected in chain order with one call to either
/// [`Listen::block_connected`] or [`Listen::filtered_block_connected`]. If a call to the
/// [`Filter`] interface was made during block processing and further transaction(s) from the same
/// block now match the filter, a second call to [`Listen::filtered_block_connected`] should be
/// made immediately for the same block (prior to any other calls to the [`Listen`] interface).
///
/// In case of a reorg, you must call [`Listen::blocks_disconnected`] once with information on the
/// "fork point" block, i.e. the highest block that is in both forks. You may call
/// [`Listen::blocks_disconnected`] multiple times as you walk the chain backwards, but each must
/// include a fork point block that is before the last.
///
/// # Object Birthday
///
/// Note that most implementations take a [`BestBlock`] on construction and blocks only need to be
/// applied starting from that point.
pub trait Listen {
	/// Notifies the listener that a block was added at the given height, with the transaction data
	/// possibly filtered.
	fn filtered_block_connected(&self, header: &Header, txdata: &TransactionData, height: u32);

	/// Notifies the listener that a block was added at the given height.
	fn block_connected(&self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		self.filtered_block_connected(&block.header, &txdata, height);
	}

	/// Notifies the listener that one or more blocks were removed in anticipation of a reorg.
	///
	/// The provided [`BestBlock`] is the new best block after disconnecting blocks in the reorg
	/// but before connecting new ones (i.e. the "fork point" block). For backwards compatibility,
	/// you may instead walk the chain backwards, calling `blocks_disconnected` for each block
	/// that is disconnected in a reorg.
	fn blocks_disconnected(&self, fork_point_block: BestBlock);
}

/// The `Confirm` trait is used to notify LDK when relevant transactions have been confirmed on
/// chain or unconfirmed during a chain reorganization.
///
/// Clients sourcing chain data using a transaction-oriented API should prefer this interface over
/// [`Listen`]. For instance, an Electrum-based transaction sync implementation may implement
/// [`Filter`] to subscribe to relevant transactions and unspent outputs it should monitor for
/// on-chain activity. Then, it needs to notify LDK via this interface upon observing any changes
/// with reference to the confirmation status of the monitored objects.
///
/// # Use
/// The intended use is as follows:
/// - Call [`transactions_confirmed`] to notify LDK whenever any of the registered transactions or
///   outputs are, respectively, confirmed or spent on chain.
/// - Call [`transaction_unconfirmed`] to notify LDK whenever any transaction returned by
///   [`get_relevant_txids`] is no longer confirmed in the block with the given block hash.
/// - Call [`best_block_updated`] to notify LDK whenever a new chain tip becomes available.
///
/// # Order
///
/// Clients must call these methods in chain order. Specifically:
/// - Transactions which are confirmed in a particular block must be given before transactions
///   confirmed in a later block.
/// - Dependent transactions within the same block must be given in topological order, possibly in
///   separate calls.
/// - All unconfirmed transactions must be given after the original confirmations and before *any*
///   reconfirmations, i.e., [`transactions_confirmed`] and [`transaction_unconfirmed`] calls should
///   never be interleaved, but always conduced *en bloc*.
/// - Any reconfirmed transactions need to be explicitly unconfirmed before they are reconfirmed
///   in regard to the new block.
///
/// See individual method documentation for further details.
///
/// [`transactions_confirmed`]: Self::transactions_confirmed
/// [`transaction_unconfirmed`]: Self::transaction_unconfirmed
/// [`best_block_updated`]: Self::best_block_updated
/// [`get_relevant_txids`]: Self::get_relevant_txids
pub trait Confirm {
	/// Notifies LDK of transactions confirmed in a block with a given header and height.
	///
	/// Must be called for any transactions registered by [`Filter::register_tx`] or any
	/// transactions spending an output registered by [`Filter::register_output`]. Such transactions
	/// appearing in the same block do not need to be included in the same call; instead, multiple
	/// calls with additional transactions may be made so long as they are made in [chain order].
	///
	/// May be called before or after [`best_block_updated`] for the corresponding block. However,
	/// in the event of a chain reorganization, it must not be called with a `header` that is no
	/// longer in the chain as of the last call to [`best_block_updated`].
	///
	/// [chain order]: Confirm#order
	/// [`best_block_updated`]: Self::best_block_updated
	fn transactions_confirmed(&self, header: &Header, txdata: &TransactionData, height: u32);
	/// Notifies LDK of a transaction that is no longer confirmed as result of a chain reorganization.
	///
	/// Must be called for any transaction returned by [`get_relevant_txids`] if it has been
	/// reorganized out of the best chain or if it is no longer confirmed in the block with the
	/// given block hash. Once called, the given transaction will not be returned
	/// by [`get_relevant_txids`], unless it has been reconfirmed via [`transactions_confirmed`].
	///
	/// [`get_relevant_txids`]: Self::get_relevant_txids
	/// [`transactions_confirmed`]: Self::transactions_confirmed
	fn transaction_unconfirmed(&self, txid: &Txid);
	/// Notifies LDK of an update to the best header connected at the given height.
	///
	/// Must be called whenever a new chain tip becomes available. May be skipped for intermediary
	/// blocks.
	fn best_block_updated(&self, header: &Header, height: u32);
	/// Returns transactions that must be monitored for reorganization out of the chain along
	/// with the height and the hash of the block as part of which it had been previously confirmed.
	///
	/// Note that the returned `Option<BlockHash>` might be `None` for channels created with LDK
	/// 0.0.112 and prior, in which case you need to manually track previous confirmations.
	///
	/// Will include any transactions passed to [`transactions_confirmed`] that have insufficient
	/// confirmations to be safe from a chain reorganization. Will not include any transactions
	/// passed to [`transaction_unconfirmed`], unless later reconfirmed.
	///
	/// Must be called to determine the subset of transactions that must be monitored for
	/// reorganization. Will be idempotent between calls but may change as a result of calls to the
	/// other interface methods. Thus, this is useful to determine which transactions must be
	/// given to [`transaction_unconfirmed`].
	///
	/// If any of the returned transactions are confirmed in a block other than the one with the
	/// given hash at the given height, they need to be unconfirmed and reconfirmed via
	/// [`transaction_unconfirmed`] and [`transactions_confirmed`], respectively.
	///
	/// [`transactions_confirmed`]: Self::transactions_confirmed
	/// [`transaction_unconfirmed`]: Self::transaction_unconfirmed
	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)>;
}

/// An enum representing the status of a channel monitor update persistence.
///
/// These are generally used as the return value for an implementation of [`Persist`] which is used
/// as the storage layer for a [`ChainMonitor`]. See the docs on [`Persist`] for a high-level
/// explanation of how to handle different cases.
///
/// While `UnrecoverableError` is provided as a failure variant, it is not truly "handled" on the
/// calling side, and generally results in an immediate panic. For those who prefer to avoid
/// panics, `InProgress` can be used and you can retry the update operation in the background or
/// shut down cleanly.
///
/// Note that channels should generally *not* be force-closed after a persistence failure.
/// Force-closing with the latest [`ChannelMonitorUpdate`] applied may result in a transaction
/// being broadcast which can only be spent by the latest [`ChannelMonitor`]! Thus, if the
/// latest [`ChannelMonitor`] is not durably persisted anywhere and exists only in memory, naively
/// calling [`ChannelManager::force_close_broadcasting_latest_txn`] *may result in loss of funds*!
///
/// [`Persist`]: chainmonitor::Persist
/// [`ChainMonitor`]: chainmonitor::ChainMonitor
/// [`ChannelManager::force_close_broadcasting_latest_txn`]: crate::ln::channelmanager::ChannelManager::force_close_broadcasting_latest_txn
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelMonitorUpdateStatus {
	/// The update has been durably persisted and all copies of the relevant [`ChannelMonitor`]
	/// have been updated.
	///
	/// This includes performing any `fsync()` calls required to ensure the update is guaranteed to
	/// be available on restart even if the application crashes.
	///
	/// If you return this variant, you cannot later return [`InProgress`] from the same instance of
	/// [`Persist`]/[`Watch`] without first restarting.
	///
	/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
	/// [`Persist`]: chainmonitor::Persist
	Completed,
	/// Indicates that the update will happen asynchronously in the background or that a transient
	/// failure occurred which is being retried in the background and will eventually complete.
	///
	/// This will "freeze" a channel, preventing us from revoking old states or submitting a new
	/// commitment transaction to the counterparty. Once the update(s) which are `InProgress` have
	/// been completed, a [`MonitorEvent::Completed`] can be used to restore the channel to an
	/// operational state.
	///
	/// Even when a channel has been "frozen", updates to the [`ChannelMonitor`] can continue to
	/// occur (e.g. if an inbound HTLC which we forwarded was claimed upstream, resulting in us
	/// attempting to claim it on this channel) and those updates must still be persisted.
	///
	/// No updates to the channel will be made which could invalidate other [`ChannelMonitor`]s
	/// until a [`MonitorEvent::Completed`] is provided, even if you return no error on a later
	/// monitor update for the same channel.
	///
	/// For deployments where a copy of [`ChannelMonitor`]s and other local state are backed up in
	/// a remote location (with local copies persisted immediately), it is anticipated that all
	/// updates will return [`InProgress`] until the remote copies could be updated.
	///
	/// Note that while fully asynchronous persistence of [`ChannelMonitor`] data is generally
	/// reliable, this feature is considered beta, and a handful of edge-cases remain. Until the
	/// remaining cases are fixed, in rare cases, *using this feature may lead to funds loss*.
	///
	/// If you return this variant, you cannot later return [`Completed`] from the same instance of
	/// [`Persist`]/[`Watch`] without first restarting.
	///
	/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
	/// [`Completed`]: ChannelMonitorUpdateStatus::Completed
	/// [`Persist`]: chainmonitor::Persist
	InProgress,
	/// Indicates that an update has failed and will not complete at any point in the future.
	///
	/// Currently returning this variant will cause LDK to immediately panic to encourage immediate
	/// shutdown. In the future this may be updated to disconnect peers and refuse to continue
	/// normal operation without a panic.
	///
	/// Applications which wish to perform an orderly shutdown after failure should consider
	/// returning [`InProgress`] instead and simply shut down without ever marking the update
	/// complete.
	///
	/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
	UnrecoverableError,
}

/// The `Watch` trait defines behavior for watching on-chain activity pertaining to channels as
/// blocks are connected and disconnected.
///
/// Each channel is associated with a [`ChannelMonitor`]. Implementations of this trait are
/// responsible for maintaining a set of monitors such that they can be updated as channel state
/// changes. On each update, *all copies* of a [`ChannelMonitor`] must be updated and the update
/// persisted to disk to ensure that the latest [`ChannelMonitor`] state can be reloaded if the
/// application crashes.
///
/// See method documentation and [`ChannelMonitorUpdateStatus`] for specific requirements.
pub trait Watch<ChannelSigner: EcdsaChannelSigner> {
	/// Watches a channel identified by `channel_id` using `monitor`.
	///
	/// Implementations are responsible for watching the chain for the funding transaction along
	/// with any spends of outputs returned by [`get_outputs_to_watch`]. In practice, this means
	/// calling [`block_connected`] and [`blocks_disconnected`] on the monitor.
	///
	/// A return of `Err(())` indicates that the channel should immediately be force-closed without
	/// broadcasting the funding transaction.
	///
	/// If the given `channel_id` has previously been registered via `watch_channel`, `Err(())`
	/// must be returned.
	///
	/// [`get_outputs_to_watch`]: channelmonitor::ChannelMonitor::get_outputs_to_watch
	/// [`block_connected`]: channelmonitor::ChannelMonitor::block_connected
	/// [`blocks_disconnected`]: channelmonitor::ChannelMonitor::blocks_disconnected
	fn watch_channel(
		&self, channel_id: ChannelId, monitor: ChannelMonitor<ChannelSigner>,
	) -> Result<ChannelMonitorUpdateStatus, ()>;

	/// Updates a channel identified by `channel_id` by applying `update` to its monitor.
	///
	/// Implementations must call [`ChannelMonitor::update_monitor`] with the given update. This
	/// may fail (returning an `Err(())`), in which case this should return
	/// [`ChannelMonitorUpdateStatus::InProgress`] (and the update should never complete). This
	/// generally implies the channel has been closed (either by the funding outpoint being spent
	/// on-chain or the [`ChannelMonitor`] having decided to do so and broadcasted a transaction),
	/// and the [`ChannelManager`] state will be updated once it sees the funding spend on-chain.
	///
	/// In general, persistence failures should be retried after returning
	/// [`ChannelMonitorUpdateStatus::InProgress`] and eventually complete. If a failure truly
	/// cannot be retried, the node should shut down immediately after returning
	/// [`ChannelMonitorUpdateStatus::UnrecoverableError`], see its documentation for more info.
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	fn update_channel(
		&self, channel_id: ChannelId, update: &ChannelMonitorUpdate,
	) -> ChannelMonitorUpdateStatus;

	/// Returns any monitor events since the last call. Subsequent calls must only return new
	/// events.
	///
	/// Note that after any block- or transaction-connection calls to a [`ChannelMonitor`], no
	/// further events may be returned here until the [`ChannelMonitor`] has been fully persisted
	/// to disk.
	///
	/// For details on asynchronous [`ChannelMonitor`] updating and returning
	/// [`MonitorEvent::Completed`] here, see [`ChannelMonitorUpdateStatus::InProgress`].
	fn release_pending_monitor_events(
		&self,
	) -> Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, PublicKey)>;
}

impl<ChannelSigner: EcdsaChannelSigner, T: Watch<ChannelSigner> + ?Sized, W: Deref<Target = T>>
	Watch<ChannelSigner> for W
{
	fn watch_channel(
		&self, channel_id: ChannelId, monitor: ChannelMonitor<ChannelSigner>,
	) -> Result<ChannelMonitorUpdateStatus, ()> {
		self.deref().watch_channel(channel_id, monitor)
	}

	fn update_channel(
		&self, channel_id: ChannelId, update: &ChannelMonitorUpdate,
	) -> ChannelMonitorUpdateStatus {
		self.deref().update_channel(channel_id, update)
	}

	fn release_pending_monitor_events(
		&self,
	) -> Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, PublicKey)> {
		self.deref().release_pending_monitor_events()
	}
}

/// The `Filter` trait defines behavior for indicating chain activity of interest pertaining to
/// channels.
///
/// This is useful in order to have a [`Watch`] implementation convey to a chain source which
/// transactions to be notified of. Notification may take the form of pre-filtering blocks or, in
/// the case of [BIP 157]/[BIP 158], only fetching a block if the compact filter matches. If
/// receiving full blocks from a chain source, any further filtering is unnecessary.
///
/// After an output has been registered, subsequent block retrievals from the chain source must not
/// exclude any transactions matching the new criteria nor any in-block descendants of such
/// transactions.
///
/// Note that use as part of a [`Watch`] implementation involves reentrancy. Therefore, the `Filter`
/// should not block on I/O. Implementations should instead queue the newly monitored data to be
/// processed later. Then, in order to block until the data has been processed, any [`Watch`]
/// invocation that has called the `Filter` must return [`InProgress`].
///
/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
/// [BIP 157]: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
/// [BIP 158]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
pub trait Filter {
	/// Registers interest in a transaction with `txid` and having an output with `script_pubkey` as
	/// a spending condition.
	///
	/// This may be used, for example, to monitor for when a funding transaction confirms.
	///
	/// The `script_pubkey` is provided for informational purposes and may be useful for block
	/// sources which only support filtering on scripts.
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script);

	/// Registers interest in spends of a transaction output.
	///
	/// Note that this method might be called during processing of a new block. You therefore need
	/// to ensure that also dependent output spents within an already connected block are correctly
	/// handled, e.g., by re-scanning the block in question whenever new outputs have been
	/// registered mid-processing.
	///
	/// This may be used, for example, to monitor for when a funding output is spent (by any
	/// transaction).
	fn register_output(&self, output: WatchedOutput);
}

impl<T: Filter + ?Sized, F: Deref<Target = T>> Filter for F {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.deref().register_tx(txid, script_pubkey)
	}

	fn register_output(&self, output: WatchedOutput) {
		self.deref().register_output(output)
	}
}

/// A transaction output watched by a [`ChannelMonitor`] for spends on-chain.
///
/// Used to convey to a [`Filter`] such an output with a given spending condition. Any transaction
/// spending the output must be given to [`ChannelMonitor::block_connected`] either directly or via
/// [`Confirm::transactions_confirmed`].
///
/// If `block_hash` is `Some`, this indicates the output was created in the corresponding block and
/// may have been spent there. See [`Filter::register_output`] for details.
///
/// Depending on your block source, you may need one or both of either [`Self::outpoint`] or
/// [`Self::script_pubkey`].
///
/// [`ChannelMonitor`]: channelmonitor::ChannelMonitor
/// [`ChannelMonitor::block_connected`]: channelmonitor::ChannelMonitor::block_connected
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WatchedOutput {
	/// First block where the transaction output may have been spent.
	pub block_hash: Option<BlockHash>,

	/// Outpoint identifying the transaction output.
	pub outpoint: OutPoint,

	/// Spending condition of the transaction output.
	pub script_pubkey: ScriptBuf,
}

impl<T: Listen> Listen for dyn core::ops::Deref<Target = T> {
	fn filtered_block_connected(&self, header: &Header, txdata: &TransactionData, height: u32) {
		(**self).filtered_block_connected(header, txdata, height);
	}

	fn blocks_disconnected(&self, fork_point: BestBlock) {
		(**self).blocks_disconnected(fork_point);
	}
}

impl<T: core::ops::Deref, U: core::ops::Deref> Listen for (T, U)
where
	T::Target: Listen,
	U::Target: Listen,
{
	fn filtered_block_connected(&self, header: &Header, txdata: &TransactionData, height: u32) {
		self.0.filtered_block_connected(header, txdata, height);
		self.1.filtered_block_connected(header, txdata, height);
	}

	fn blocks_disconnected(&self, fork_point: BestBlock) {
		self.0.blocks_disconnected(fork_point);
		self.1.blocks_disconnected(fork_point);
	}
}

/// A unique identifier to track each pending output claim within a [`ChannelMonitor`].
///
/// This is not exported to bindings users as we just use [u8; 32] directly.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ClaimId(pub [u8; 32]);

impl ClaimId {
	pub(crate) fn from_htlcs(htlcs: &[HTLCDescriptor]) -> ClaimId {
		let mut engine = Sha256::engine();
		for htlc in htlcs {
			engine.input(&htlc.commitment_txid.to_byte_array());
			engine.input(&htlc.htlc.transaction_output_index.unwrap().to_be_bytes());
		}
		ClaimId(Sha256::from_engine(engine).to_byte_array())
	}
	pub(crate) fn step_with_bytes(&self, bytes: &[u8]) -> ClaimId {
		let mut engine = Sha256::engine();
		engine.input(&self.0);
		engine.input(bytes);
		ClaimId(Sha256::from_engine(engine).to_byte_array())
	}
}
