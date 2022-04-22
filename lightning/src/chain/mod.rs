// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Structs and traits which allow other parts of rust-lightning to interact with the blockchain.

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::network::constants::Network;

use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, MonitorEvent};
use chain::keysinterface::Sign;
use chain::transaction::{OutPoint, TransactionData};

use prelude::*;

pub mod chaininterface;
pub mod chainmonitor;
pub mod channelmonitor;
pub mod transaction;
pub mod keysinterface;
pub(crate) mod onchaintx;
pub(crate) mod package;

/// The best known block as identified by its hash and height.
#[derive(Clone, Copy, PartialEq)]
pub struct BestBlock {
	block_hash: BlockHash,
	height: u32,
}

impl BestBlock {
	/// Constructs a `BestBlock` that represents the genesis block at height 0 of the given
	/// network.
	pub fn from_genesis(network: Network) -> Self {
		BestBlock {
			block_hash: genesis_block(network).header.block_hash(),
			height: 0,
		}
	}

	/// Returns a `BestBlock` as identified by the given block hash and height.
	pub fn new(block_hash: BlockHash, height: u32) -> Self {
		BestBlock { block_hash, height }
	}

	/// Returns the best block hash.
	pub fn block_hash(&self) -> BlockHash { self.block_hash }

	/// Returns the best block height.
	pub fn height(&self) -> u32 { self.height }
}

/// An error when accessing the chain via [`Access`].
#[derive(Clone)]
pub enum AccessError {
	/// The requested chain is unknown.
	UnknownChain,

	/// The requested transaction doesn't exist or hasn't confirmed.
	UnknownTx,
}

/// The `Access` trait defines behavior for accessing chain data and state, such as blocks and
/// UTXOs.
pub trait Access {
	/// Returns the transaction output of a funding transaction encoded by [`short_channel_id`].
	/// Returns an error if `genesis_hash` is for a different chain or if such a transaction output
	/// is unknown.
	///
	/// [`short_channel_id`]: https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	fn get_utxo(&self, genesis_hash: &BlockHash, short_channel_id: u64) -> Result<TxOut, AccessError>;
}

/// The `Listen` trait is used to notify when blocks have been connected or disconnected from the
/// chain.
///
/// Useful when needing to replay chain data upon startup or as new chain events occur. Clients
/// sourcing chain data using a block-oriented API should prefer this interface over [`Confirm`].
/// Such clients fetch the entire header chain whereas clients using [`Confirm`] only fetch headers
/// when needed.
pub trait Listen {
	/// Notifies the listener that a block was added at the given height.
	fn block_connected(&self, block: &Block, height: u32);

	/// Notifies the listener that a block was removed at the given height.
	fn block_disconnected(&self, header: &BlockHeader, height: u32);
}

/// The `Confirm` trait is used to notify when transactions have been confirmed on chain or
/// unconfirmed during a chain reorganization.
///
/// Clients sourcing chain data using a transaction-oriented API should prefer this interface over
/// [`Listen`]. For instance, an Electrum client may implement [`Filter`] by subscribing to activity
/// related to registered transactions and outputs. Upon notification, it would pass along the
/// matching transactions using this interface.
///
/// # Use
///
/// The intended use is as follows:
/// - Call [`transactions_confirmed`] to process any on-chain activity of interest.
/// - Call [`transaction_unconfirmed`] to process any transaction returned by [`get_relevant_txids`]
///   that has been reorganized out of the chain.
/// - Call [`best_block_updated`] whenever a new chain tip becomes available.
///
/// # Order
///
/// Clients must call these methods in chain order. Specifically:
/// - Transactions confirmed in a block must be given before transactions confirmed in a later
///   block.
/// - Dependent transactions within the same block must be given in topological order, possibly in
///   separate calls.
/// - Unconfirmed transactions must be given after the original confirmations and before any
///   reconfirmation.
///
/// See individual method documentation for further details.
///
/// [`transactions_confirmed`]: Self::transactions_confirmed
/// [`transaction_unconfirmed`]: Self::transaction_unconfirmed
/// [`best_block_updated`]: Self::best_block_updated
/// [`get_relevant_txids`]: Self::get_relevant_txids
pub trait Confirm {
	/// Processes transactions confirmed in a block with a given header and height.
	///
	/// Should be called for any transactions registered by [`Filter::register_tx`] or any
	/// transactions spending an output registered by [`Filter::register_output`]. Such transactions
	/// appearing in the same block do not need to be included in the same call; instead, multiple
	/// calls with additional transactions may be made so long as they are made in [chain order].
	///
	/// May be called before or after [`best_block_updated`] for the corresponding block. However,
	/// in the event of a chain reorganization, it must not be called with a `header` that is no
	/// longer in the chain as of the last call to [`best_block_updated`].
	///
	/// [chain order]: Confirm#Order
	/// [`best_block_updated`]: Self::best_block_updated
	fn transactions_confirmed(&self, header: &BlockHeader, txdata: &TransactionData, height: u32);

	/// Processes a transaction that is no longer confirmed as result of a chain reorganization.
	///
	/// Should be called for any transaction returned by [`get_relevant_txids`] if it has been
	/// reorganized out of the best chain. Once called, the given transaction should not be returned
	/// by [`get_relevant_txids`] unless it has been reconfirmed via [`transactions_confirmed`].
	///
	/// [`get_relevant_txids`]: Self::get_relevant_txids
	/// [`transactions_confirmed`]: Self::transactions_confirmed
	fn transaction_unconfirmed(&self, txid: &Txid);

	/// Processes an update to the best header connected at the given height.
	///
	/// Should be called when a new header is available but may be skipped for intermediary blocks
	/// if they become available at the same time.
	fn best_block_updated(&self, header: &BlockHeader, height: u32);

	/// Returns transactions that should be monitored for reorganization out of the chain.
	///
	/// Should include any transactions passed to [`transactions_confirmed`] that have insufficient
	/// confirmations to be safe from a chain reorganization. Should not include any transactions
	/// passed to [`transaction_unconfirmed`] unless later reconfirmed.
	///
	/// May be called to determine the subset of transactions that must still be monitored for
	/// reorganization. Will be idempotent between calls but may change as a result of calls to the
	/// other interface methods. Thus, this is useful to determine which transactions may need to be
	/// given to [`transaction_unconfirmed`].
	///
	/// [`transactions_confirmed`]: Self::transactions_confirmed
	/// [`transaction_unconfirmed`]: Self::transaction_unconfirmed
	fn get_relevant_txids(&self) -> Vec<Txid>;
}

/// An error enum representing a failure to persist a channel monitor update.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChannelMonitorUpdateErr {
	/// Used to indicate a temporary failure (eg connection to a watchtower or remote backup of
	/// our state failed, but is expected to succeed at some point in the future).
	///
	/// Such a failure will "freeze" a channel, preventing us from revoking old states or
	/// submitting new commitment transactions to the counterparty. Once the update(s) that failed
	/// have been successfully applied, a [`MonitorEvent::UpdateCompleted`] event should be returned
	/// via [`Watch::release_pending_monitor_events`] which will then restore the channel to an
	/// operational state.
	///
	/// Note that a given ChannelManager will *never* re-generate a given ChannelMonitorUpdate. If
	/// you return a TemporaryFailure you must ensure that it is written to disk safely before
	/// writing out the latest ChannelManager state.
	///
	/// Even when a channel has been "frozen" updates to the ChannelMonitor can continue to occur
	/// (eg if an inbound HTLC which we forwarded was claimed upstream resulting in us attempting
	/// to claim it on this channel) and those updates must be applied wherever they can be. At
	/// least one such updated ChannelMonitor must be persisted otherwise PermanentFailure should
	/// be returned to get things on-chain ASAP using only the in-memory copy. Obviously updates to
	/// the channel which would invalidate previous ChannelMonitors are not made when a channel has
	/// been "frozen".
	///
	/// Note that even if updates made after TemporaryFailure succeed you must still provide a
	/// [`MonitorEvent::UpdateCompleted`] to ensure you have the latest monitor and re-enable
	/// normal channel operation. Note that this is normally generated through a call to
	/// [`ChainMonitor::channel_monitor_updated`].
	///
	/// Note that the update being processed here will not be replayed for you when you return a
	/// [`MonitorEvent::UpdateCompleted`] event via [`Watch::release_pending_monitor_events`], so
	/// you must store the update itself on your own local disk prior to returning a
	/// TemporaryFailure. You may, of course, employ a journaling approach, storing only the
	/// ChannelMonitorUpdate on disk without updating the monitor itself, replaying the journal at
	/// reload-time.
	///
	/// For deployments where a copy of ChannelMonitors and other local state are backed up in a
	/// remote location (with local copies persisted immediately), it is anticipated that all
	/// updates will return TemporaryFailure until the remote copies could be updated.
	///
	/// [`ChainMonitor::channel_monitor_updated`]: chainmonitor::ChainMonitor::channel_monitor_updated
	TemporaryFailure,
	/// Used to indicate no further channel monitor updates will be allowed (eg we've moved on to a
	/// different watchtower and cannot update with all watchtowers that were previously informed
	/// of this channel).
	///
	/// At reception of this error, ChannelManager will force-close the channel and return at
	/// least a final ChannelMonitorUpdate::ChannelForceClosed which must be delivered to at
	/// least one ChannelMonitor copy. Revocation secret MUST NOT be released and offchain channel
	/// update must be rejected.
	///
	/// This failure may also signal a failure to update the local persisted copy of one of
	/// the channel monitor instance.
	///
	/// Note that even when you fail a holder commitment transaction update, you must store the
	/// update to ensure you can claim from it in case of a duplicate copy of this ChannelMonitor
	/// broadcasts it (e.g distributed channel-monitor deployment)
	///
	/// In case of distributed watchtowers deployment, the new version must be written to disk, as
	/// state may have been stored but rejected due to a block forcing a commitment broadcast. This
	/// storage is used to claim outputs of rejected state confirmed onchain by another watchtower,
	/// lagging behind on block processing.
	PermanentFailure,
}

/// The `Watch` trait defines behavior for watching on-chain activity pertaining to channels as
/// blocks are connected and disconnected.
///
/// Each channel is associated with a [`ChannelMonitor`]. Implementations of this trait are
/// responsible for maintaining a set of monitors such that they can be updated accordingly as
/// channel state changes and HTLCs are resolved. See method documentation for specific
/// requirements.
///
/// Implementations **must** ensure that updates are successfully applied and persisted upon method
/// completion. If an update fails with a [`PermanentFailure`], then it must immediately shut down
/// without taking any further action such as persisting the current state.
///
/// If an implementation maintains multiple instances of a channel's monitor (e.g., by storing
/// backup copies), then it must ensure that updates are applied across all instances. Otherwise, it
/// could result in a revoked transaction being broadcast, allowing the counterparty to claim all
/// funds in the channel. See [`ChannelMonitorUpdateErr`] for more details about how to handle
/// multiple instances.
///
/// [`PermanentFailure`]: ChannelMonitorUpdateErr::PermanentFailure
pub trait Watch<ChannelSigner: Sign> {
	/// Watches a channel identified by `funding_txo` using `monitor`.
	///
	/// Implementations are responsible for watching the chain for the funding transaction along
	/// with any spends of outputs returned by [`get_outputs_to_watch`]. In practice, this means
	/// calling [`block_connected`] and [`block_disconnected`] on the monitor.
	///
	/// Note: this interface MUST error with `ChannelMonitorUpdateErr::PermanentFailure` if
	/// the given `funding_txo` has previously been registered via `watch_channel`.
	///
	/// [`get_outputs_to_watch`]: channelmonitor::ChannelMonitor::get_outputs_to_watch
	/// [`block_connected`]: channelmonitor::ChannelMonitor::block_connected
	/// [`block_disconnected`]: channelmonitor::ChannelMonitor::block_disconnected
	fn watch_channel(&self, funding_txo: OutPoint, monitor: ChannelMonitor<ChannelSigner>) -> Result<(), ChannelMonitorUpdateErr>;

	/// Updates a channel identified by `funding_txo` by applying `update` to its monitor.
	///
	/// Implementations must call [`update_monitor`] with the given update. See
	/// [`ChannelMonitorUpdateErr`] for invariants around returning an error.
	///
	/// [`update_monitor`]: channelmonitor::ChannelMonitor::update_monitor
	fn update_channel(&self, funding_txo: OutPoint, update: ChannelMonitorUpdate) -> Result<(), ChannelMonitorUpdateErr>;

	/// Returns any monitor events since the last call. Subsequent calls must only return new
	/// events.
	///
	/// Note that after any block- or transaction-connection calls to a [`ChannelMonitor`], no
	/// further events may be returned here until the [`ChannelMonitor`] has been fully persisted
	/// to disk.
	///
	/// For details on asynchronous [`ChannelMonitor`] updating and returning
	/// [`MonitorEvent::UpdateCompleted`] here, see [`ChannelMonitorUpdateErr::TemporaryFailure`].
	fn release_pending_monitor_events(&self) -> Vec<(OutPoint, Vec<MonitorEvent>)>;
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
/// invocation that has called the `Filter` must return [`TemporaryFailure`].
///
/// [`TemporaryFailure`]: ChannelMonitorUpdateErr::TemporaryFailure
/// [BIP 157]: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
/// [BIP 158]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
pub trait Filter {
	/// Registers interest in a transaction with `txid` and having an output with `script_pubkey` as
	/// a spending condition.
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script);

	/// Registers interest in spends of a transaction output.
	///
	/// Optionally, when `output.block_hash` is set, should return any transaction spending the
	/// output that is found in the corresponding block along with its index.
	///
	/// This return value is useful for Electrum clients in order to supply in-block descendant
	/// transactions which otherwise were not included. This is not necessary for other clients if
	/// such descendant transactions were already included (e.g., when a BIP 157 client provides the
	/// full block).
	fn register_output(&self, output: WatchedOutput) -> Option<(usize, Transaction)>;
}

/// A transaction output watched by a [`ChannelMonitor`] for spends on-chain.
///
/// Used to convey to a [`Filter`] such an output with a given spending condition. Any transaction
/// spending the output must be given to [`ChannelMonitor::block_connected`] either directly or via
/// the return value of [`Filter::register_output`].
///
/// If `block_hash` is `Some`, this indicates the output was created in the corresponding block and
/// may have been spent there. See [`Filter::register_output`] for details.
///
/// [`ChannelMonitor`]: channelmonitor::ChannelMonitor
/// [`ChannelMonitor::block_connected`]: channelmonitor::ChannelMonitor::block_connected
#[derive(Clone, PartialEq, Hash)]
pub struct WatchedOutput {
	/// First block where the transaction output may have been spent.
	pub block_hash: Option<BlockHash>,

	/// Outpoint identifying the transaction output.
	pub outpoint: OutPoint,

	/// Spending condition of the transaction output.
	pub script_pubkey: Script,
}

impl<T: Listen> Listen for core::ops::Deref<Target = T> {
	fn block_connected(&self, block: &Block, height: u32) {
		(**self).block_connected(block, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		(**self).block_disconnected(header, height);
	}
}

impl<T: core::ops::Deref, U: core::ops::Deref> Listen for (T, U)
where
	T::Target: Listen,
	U::Target: Listen,
{
	fn block_connected(&self, block: &Block, height: u32) {
		self.0.block_connected(block, height);
		self.1.block_connected(block, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		self.0.block_disconnected(header, height);
		self.1.block_disconnected(header, height);
	}
}
