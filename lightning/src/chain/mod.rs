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
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::TxOut;
use bitcoin::hash_types::{BlockHash, Txid};

use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr, MonitorEvent};
use chain::keysinterface::Sign;
use chain::transaction::OutPoint;

pub mod chaininterface;
pub mod chainmonitor;
pub mod channelmonitor;
pub mod transaction;
pub mod keysinterface;

/// An error when accessing the chain via [`Access`].
///
/// [`Access`]: trait.Access.html
#[derive(Clone)]
pub enum AccessError {
	/// The requested chain is unknown.
	UnknownChain,

	/// The requested transaction doesn't exist or hasn't confirmed.
	UnknownTx,
}

/// The `Access` trait defines behavior for accessing chain data and state, such as blocks and
/// UTXOs.
pub trait Access: Send + Sync {
	/// Returns the transaction output of a funding transaction encoded by [`short_channel_id`].
	/// Returns an error if `genesis_hash` is for a different chain or if such a transaction output
	/// is unknown.
	///
	/// [`short_channel_id`]: https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	fn get_utxo(&self, genesis_hash: &BlockHash, short_channel_id: u64) -> Result<TxOut, AccessError>;
}

/// The `Listen` trait is used to be notified of when blocks have been connected or disconnected
/// from the chain.
///
/// Useful when needing to replay chain data upon startup or as new chain events occur.
pub trait Listen {
	/// Notifies the listener that a block was added at the given height.
	fn block_connected(&self, block: &Block, height: u32);

	/// Notifies the listener that a block was removed at the given height.
	fn block_disconnected(&self, header: &BlockHeader, height: u32);
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
/// [`ChannelMonitor`]: channelmonitor/struct.ChannelMonitor.html
/// [`ChannelMonitorUpdateErr`]: channelmonitor/enum.ChannelMonitorUpdateErr.html
/// [`PermanentFailure`]: channelmonitor/enum.ChannelMonitorUpdateErr.html#variant.PermanentFailure
pub trait Watch<ChannelSigner: Sign>: Send + Sync {
	/// Watches a channel identified by `funding_txo` using `monitor`.
	///
	/// Implementations are responsible for watching the chain for the funding transaction along
	/// with any spends of outputs returned by [`get_outputs_to_watch`]. In practice, this means
	/// calling [`block_connected`] and [`block_disconnected`] on the monitor.
	///
	/// [`get_outputs_to_watch`]: channelmonitor/struct.ChannelMonitor.html#method.get_outputs_to_watch
	/// [`block_connected`]: channelmonitor/struct.ChannelMonitor.html#method.block_connected
	/// [`block_disconnected`]: channelmonitor/struct.ChannelMonitor.html#method.block_disconnected
	fn watch_channel(&self, funding_txo: OutPoint, monitor: ChannelMonitor<ChannelSigner>) -> Result<(), ChannelMonitorUpdateErr>;

	/// Updates a channel identified by `funding_txo` by applying `update` to its monitor.
	///
	/// Implementations must call [`update_monitor`] with the given update. See
	/// [`ChannelMonitorUpdateErr`] for invariants around returning an error.
	///
	/// [`update_monitor`]: channelmonitor/struct.ChannelMonitor.html#method.update_monitor
	/// [`ChannelMonitorUpdateErr`]: channelmonitor/enum.ChannelMonitorUpdateErr.html
	fn update_channel(&self, funding_txo: OutPoint, update: ChannelMonitorUpdate) -> Result<(), ChannelMonitorUpdateErr>;

	/// Returns any monitor events since the last call. Subsequent calls must only return new
	/// events.
	fn release_pending_monitor_events(&self) -> Vec<MonitorEvent>;
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
/// processed later. Then, in order to block until the data has been processed, any `Watch`
/// invocation that has called the `Filter` must return [`TemporaryFailure`].
///
/// [`Watch`]: trait.Watch.html
/// [`TemporaryFailure`]: channelmonitor/enum.ChannelMonitorUpdateErr.html#variant.TemporaryFailure
/// [BIP 157]: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
/// [BIP 158]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
pub trait Filter: Send + Sync {
	/// Registers interest in a transaction with `txid` and having an output with `script_pubkey` as
	/// a spending condition.
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script);

	/// Registers interest in spends of a transaction output identified by `outpoint` having
	/// `script_pubkey` as the spending condition.
	fn register_output(&self, outpoint: &OutPoint, script_pubkey: &Script);
}

impl<T: Listen> Listen for std::ops::Deref<Target = T> {
	fn block_connected(&self, block: &Block, height: u32) {
		(**self).block_connected(block, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		(**self).block_disconnected(header, height);
	}
}

impl<T: std::ops::Deref, U: std::ops::Deref> Listen for (T, U)
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
