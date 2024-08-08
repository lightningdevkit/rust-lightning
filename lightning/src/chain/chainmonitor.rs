// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Logic to connect off-chain channel management with on-chain transaction monitoring.
//!
//! [`ChainMonitor`] is an implementation of [`chain::Watch`] used both to process blocks and to
//! update [`ChannelMonitor`]s accordingly. If any on-chain events need further processing, it will
//! make those available as [`MonitorEvent`]s to be consumed.
//!
//! [`ChainMonitor`] is parameterized by an optional chain source, which must implement the
//! [`chain::Filter`] trait. This provides a mechanism to signal new relevant outputs back to light
//! clients, such that transactions spending those outputs are included in block data.
//!
//! [`ChainMonitor`] may be used directly to monitor channels locally or as a part of a distributed
//! setup to monitor channels remotely. In the latter case, a custom [`chain::Watch`] implementation
//! would be responsible for routing each update to a remote server and for retrieving monitor
//! events. The remote server would make use of [`ChainMonitor`] for block processing and for
//! servicing [`ChannelMonitor`] updates from the client.

use bitcoin::block::Header;
use bitcoin::hash_types::{Txid, BlockHash};

use crate::chain;
use crate::chain::{ChannelMonitorUpdateStatus, Filter, WatchedOutput};
use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, Balance, MonitorEvent, TransactionOutputs, WithChannelMonitor};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::ln::types::ChannelId;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::events::{self, Event, EventHandler, ReplayEvent};
use crate::util::logger::{Logger, WithContext};
use crate::util::errors::APIError;
use crate::util::wakers::{Future, Notifier};
use crate::ln::channel_state::ChannelDetails;

use crate::prelude::*;
use crate::sync::{RwLock, RwLockReadGuard, Mutex, MutexGuard};
use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;

/// `Persist` defines behavior for persisting channel monitors: this could mean
/// writing once to disk, and/or uploading to one or more backup services.
///
/// Persistence can happen in one of two ways - synchronously completing before the trait method
/// calls return or asynchronously in the background.
///
/// # For those implementing synchronous persistence
///
///  * If persistence completes fully (including any relevant `fsync()` calls), the implementation
///    should return [`ChannelMonitorUpdateStatus::Completed`], indicating normal channel operation
///    should continue.
///
///  * If persistence fails for some reason, implementations should consider returning
///    [`ChannelMonitorUpdateStatus::InProgress`] and retry all pending persistence operations in
///    the background with [`ChainMonitor::list_pending_monitor_updates`] and
///    [`ChainMonitor::get_monitor`].
///
///    Once a full [`ChannelMonitor`] has been persisted, all pending updates for that channel can
///    be marked as complete via [`ChainMonitor::channel_monitor_updated`].
///
///    If at some point no further progress can be made towards persisting the pending updates, the
///    node should simply shut down.
///
///  * If the persistence has failed and cannot be retried further (e.g. because of an outage),
///    [`ChannelMonitorUpdateStatus::UnrecoverableError`] can be used, though this will result in
///    an immediate panic and future operations in LDK generally failing.
///
/// # For those implementing asynchronous persistence
///
///  All calls should generally spawn a background task and immediately return
///  [`ChannelMonitorUpdateStatus::InProgress`]. Once the update completes,
///  [`ChainMonitor::channel_monitor_updated`] should be called with the corresponding
///  [`ChannelMonitor::get_latest_update_id`] or [`ChannelMonitorUpdate::update_id`].
///
///  Note that unlike the direct [`chain::Watch`] interface,
///  [`ChainMonitor::channel_monitor_updated`] must be called once for *each* update which occurs.
///
///  If at some point no further progress can be made towards persisting a pending update, the node
///  should simply shut down. Until then, the background task should either loop indefinitely, or
///  persistence should be regularly retried with [`ChainMonitor::list_pending_monitor_updates`]
///  and [`ChainMonitor::get_monitor`] (note that if a full monitor is persisted all pending
///  monitor updates may be marked completed).
///
/// # Using remote watchtowers
///
/// Watchtowers may be updated as a part of an implementation of this trait, utilizing the async
/// update process described above while the watchtower is being updated. The following methods are
/// provided for bulding transactions for a watchtower:
/// [`ChannelMonitor::initial_counterparty_commitment_tx`],
/// [`ChannelMonitor::counterparty_commitment_txs_from_update`],
/// [`ChannelMonitor::sign_to_local_justice_tx`], [`TrustedCommitmentTransaction::revokeable_output_index`],
/// [`TrustedCommitmentTransaction::build_to_local_justice_tx`].
///
/// [`TrustedCommitmentTransaction::revokeable_output_index`]: crate::ln::chan_utils::TrustedCommitmentTransaction::revokeable_output_index
/// [`TrustedCommitmentTransaction::build_to_local_justice_tx`]: crate::ln::chan_utils::TrustedCommitmentTransaction::build_to_local_justice_tx
pub trait Persist<ChannelSigner: EcdsaChannelSigner> {
	/// Persist a new channel's data in response to a [`chain::Watch::watch_channel`] call. This is
	/// called by [`ChannelManager`] for new channels, or may be called directly, e.g. on startup.
	///
	/// The data can be stored any way you want, but the identifier provided by LDK is the
	/// channel's outpoint (and it is up to you to maintain a correct mapping between the outpoint
	/// and the stored channel data). Note that you **must** persist every new monitor to disk.
	///
	/// The [`ChannelMonitor::get_latest_update_id`] uniquely links this call to [`ChainMonitor::channel_monitor_updated`].
	/// For [`Persist::persist_new_channel`], it is only necessary to call [`ChainMonitor::channel_monitor_updated`]
	/// when you return [`ChannelMonitorUpdateStatus::InProgress`].
	///
	/// See [`Writeable::write`] on [`ChannelMonitor`] for writing out a `ChannelMonitor`
	/// and [`ChannelMonitorUpdateStatus`] for requirements when returning errors.
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`Writeable::write`]: crate::util::ser::Writeable::write
	fn persist_new_channel(&self, channel_funding_outpoint: OutPoint, monitor: &ChannelMonitor<ChannelSigner>) -> ChannelMonitorUpdateStatus;

	/// Update one channel's data. The provided [`ChannelMonitor`] has already applied the given
	/// update.
	///
	/// Note that on every update, you **must** persist either the [`ChannelMonitorUpdate`] or the
	/// updated monitor itself to disk/backups. See the [`Persist`] trait documentation for more
	/// details.
	///
	/// During blockchain synchronization operations, and in some rare cases, this may be called with
	/// no [`ChannelMonitorUpdate`], in which case the full [`ChannelMonitor`] needs to be persisted.
	/// Note that after the full [`ChannelMonitor`] is persisted any previous
	/// [`ChannelMonitorUpdate`]s which were persisted should be discarded - they can no longer be
	/// applied to the persisted [`ChannelMonitor`] as they were already applied.
	///
	/// If an implementer chooses to persist the updates only, they need to make
	/// sure that all the updates are applied to the `ChannelMonitors` *before*
	/// the set of channel monitors is given to the `ChannelManager`
	/// deserialization routine. See [`ChannelMonitor::update_monitor`] for
	/// applying a monitor update to a monitor. If full `ChannelMonitors` are
	/// persisted, then there is no need to persist individual updates.
	///
	/// Note that there could be a performance tradeoff between persisting complete
	/// channel monitors on every update vs. persisting only updates and applying
	/// them in batches. The size of each monitor grows `O(number of state updates)`
	/// whereas updates are small and `O(1)`.
	///
	/// The [`ChannelMonitorUpdate::update_id`] or [`ChannelMonitor::get_latest_update_id`] uniquely
	/// links this call to [`ChainMonitor::channel_monitor_updated`].
	/// For [`Persist::update_persisted_channel`], it is only necessary to call [`ChainMonitor::channel_monitor_updated`]
	/// when a [`ChannelMonitorUpdate`] is provided and when you return [`ChannelMonitorUpdateStatus::InProgress`].
	///
	/// See [`Writeable::write`] on [`ChannelMonitor`] for writing out a `ChannelMonitor`,
	/// [`Writeable::write`] on [`ChannelMonitorUpdate`] for writing out an update, and
	/// [`ChannelMonitorUpdateStatus`] for requirements when returning errors.
	///
	/// [`Writeable::write`]: crate::util::ser::Writeable::write
	fn update_persisted_channel(&self, channel_funding_outpoint: OutPoint, monitor_update: Option<&ChannelMonitorUpdate>, monitor: &ChannelMonitor<ChannelSigner>) -> ChannelMonitorUpdateStatus;
	/// Prevents the channel monitor from being loaded on startup.
	///
	/// Archiving the data in a backup location (rather than deleting it fully) is useful for
	/// hedging against data loss in case of unexpected failure.
	fn archive_persisted_channel(&self, channel_funding_outpoint: OutPoint);
}

struct MonitorHolder<ChannelSigner: EcdsaChannelSigner> {
	monitor: ChannelMonitor<ChannelSigner>,
	/// The full set of pending monitor updates for this Channel.
	///
	/// Note that this lock must be held from [`ChannelMonitor::update_monitor`] through to
	/// [`Persist::update_persisted_channel`] to prevent a race where we call
	/// [`Persist::update_persisted_channel`], the user returns a
	/// [`ChannelMonitorUpdateStatus::InProgress`], and then calls
	/// [`ChainMonitor::channel_monitor_updated`] immediately, racing our insertion of the pending
	/// update into the contained Vec.
	///
	/// This also avoids a race where we update a [`ChannelMonitor`], then while connecting a block
	/// persist a full [`ChannelMonitor`] prior to persisting the [`ChannelMonitorUpdate`]. This
	/// could cause users to have a full [`ChannelMonitor`] on disk as well as a
	/// [`ChannelMonitorUpdate`] which was already applied. While this isn't an issue for the
	/// LDK-provided update-based [`Persist`], it is somewhat surprising for users so we avoid it.
	pending_monitor_updates: Mutex<Vec<u64>>,
}

impl<ChannelSigner: EcdsaChannelSigner> MonitorHolder<ChannelSigner> {
	fn has_pending_updates(&self, pending_monitor_updates_lock: &MutexGuard<Vec<u64>>) -> bool {
		!pending_monitor_updates_lock.is_empty()
	}
}

/// A read-only reference to a current ChannelMonitor.
///
/// Note that this holds a mutex in [`ChainMonitor`] and may block other events until it is
/// released.
pub struct LockedChannelMonitor<'a, ChannelSigner: EcdsaChannelSigner> {
	lock: RwLockReadGuard<'a, HashMap<OutPoint, MonitorHolder<ChannelSigner>>>,
	funding_txo: OutPoint,
}

impl<ChannelSigner: EcdsaChannelSigner> Deref for LockedChannelMonitor<'_, ChannelSigner> {
	type Target = ChannelMonitor<ChannelSigner>;
	fn deref(&self) -> &ChannelMonitor<ChannelSigner> {
		&self.lock.get(&self.funding_txo).expect("Checked at construction").monitor
	}
}

/// An implementation of [`chain::Watch`] for monitoring channels.
///
/// Connected and disconnected blocks must be provided to `ChainMonitor` as documented by
/// [`chain::Watch`]. May be used in conjunction with [`ChannelManager`] to monitor channels locally
/// or used independently to monitor channels remotely. See the [module-level documentation] for
/// details.
///
/// Note that `ChainMonitor` should regularly trigger rebroadcasts/fee bumps of pending claims from
/// a force-closed channel. This is crucial in preventing certain classes of pinning attacks,
/// detecting substantial mempool feerate changes between blocks, and ensuring reliability if
/// broadcasting fails. We recommend invoking this every 30 seconds, or lower if running in an
/// environment with spotty connections, like on mobile.
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [module-level documentation]: crate::chain::chainmonitor
/// [`rebroadcast_pending_claims`]: Self::rebroadcast_pending_claims
pub struct ChainMonitor<ChannelSigner: EcdsaChannelSigner, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref>
	where C::Target: chain::Filter,
        T::Target: BroadcasterInterface,
        F::Target: FeeEstimator,
        L::Target: Logger,
        P::Target: Persist<ChannelSigner>,
{
	monitors: RwLock<HashMap<OutPoint, MonitorHolder<ChannelSigner>>>,
	chain_source: Option<C>,
	broadcaster: T,
	logger: L,
	fee_estimator: F,
	persister: P,
	/// "User-provided" (ie persistence-completion/-failed) [`MonitorEvent`]s. These came directly
	/// from the user and not from a [`ChannelMonitor`].
	pending_monitor_events: Mutex<Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, Option<PublicKey>)>>,
	/// The best block height seen, used as a proxy for the passage of time.
	highest_chain_height: AtomicUsize,

	/// A [`Notifier`] used to wake up the background processor in case we have any [`Event`]s for
	/// it to give to users (or [`MonitorEvent`]s for `ChannelManager` to process).
	event_notifier: Notifier,
}

impl<ChannelSigner: EcdsaChannelSigner, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref> ChainMonitor<ChannelSigner, C, T, F, L, P>
where C::Target: chain::Filter,
	    T::Target: BroadcasterInterface,
	    F::Target: FeeEstimator,
	    L::Target: Logger,
	    P::Target: Persist<ChannelSigner>,
{
	/// Dispatches to per-channel monitors, which are responsible for updating their on-chain view
	/// of a channel and reacting accordingly based on transactions in the given chain data. See
	/// [`ChannelMonitor::block_connected`] for details. Any HTLCs that were resolved on chain will
	/// be returned by [`chain::Watch::release_pending_monitor_events`].
	///
	/// Calls back to [`chain::Filter`] if any monitor indicated new outputs to watch. Subsequent
	/// calls must not exclude any transactions matching the new outputs nor any in-block
	/// descendants of such transactions. It is not necessary to re-fetch the block to obtain
	/// updated `txdata`.
	///
	/// Calls which represent a new blockchain tip height should set `best_height`.
	fn process_chain_data<FN>(&self, header: &Header, best_height: Option<u32>, txdata: &TransactionData, process: FN)
	where
		FN: Fn(&ChannelMonitor<ChannelSigner>, &TransactionData) -> Vec<TransactionOutputs>
	{
		let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
		let funding_outpoints = hash_set_from_iter(self.monitors.read().unwrap().keys().cloned());
		let channel_count = funding_outpoints.len();
		for funding_outpoint in funding_outpoints.iter() {
			let monitor_lock = self.monitors.read().unwrap();
			if let Some(monitor_state) = monitor_lock.get(funding_outpoint) {
				if self.update_monitor_with_chain_data(header, best_height, txdata, &process, funding_outpoint, &monitor_state, channel_count).is_err() {
					// Take the monitors lock for writing so that we poison it and any future
					// operations going forward fail immediately.
					core::mem::drop(monitor_lock);
					let _poison = self.monitors.write().unwrap();
					log_error!(self.logger, "{}", err_str);
					panic!("{}", err_str);
				}
			}
		}

		// do some followup cleanup if any funding outpoints were added in between iterations
		let monitor_states = self.monitors.write().unwrap();
		for (funding_outpoint, monitor_state) in monitor_states.iter() {
			if !funding_outpoints.contains(funding_outpoint) {
				if self.update_monitor_with_chain_data(header, best_height, txdata, &process, funding_outpoint, &monitor_state, channel_count).is_err() {
					log_error!(self.logger, "{}", err_str);
					panic!("{}", err_str);
				}
			}
		}

		if let Some(height) = best_height {
			// If the best block height is being updated, update highest_chain_height under the
			// monitors write lock.
			let old_height = self.highest_chain_height.load(Ordering::Acquire);
			let new_height = height as usize;
			if new_height > old_height {
				self.highest_chain_height.store(new_height, Ordering::Release);
			}
		}
	}

	fn update_monitor_with_chain_data<FN>(
		&self, header: &Header, best_height: Option<u32>, txdata: &TransactionData, process: FN, funding_outpoint: &OutPoint,
		monitor_state: &MonitorHolder<ChannelSigner>, channel_count: usize,
	) -> Result<(), ()> where FN: Fn(&ChannelMonitor<ChannelSigner>, &TransactionData) -> Vec<TransactionOutputs> {
		let monitor = &monitor_state.monitor;
		let logger = WithChannelMonitor::from(&self.logger, &monitor, None);

		let mut txn_outputs = process(monitor, txdata);

		let get_partition_key = |funding_outpoint: &OutPoint| {
			let funding_txid_hash = funding_outpoint.txid.to_raw_hash();
			let funding_txid_hash_bytes = funding_txid_hash.as_byte_array();
			let funding_txid_u32 = u32::from_be_bytes([funding_txid_hash_bytes[0], funding_txid_hash_bytes[1], funding_txid_hash_bytes[2], funding_txid_hash_bytes[3]]);
			funding_txid_u32.wrapping_add(best_height.unwrap_or_default())
		};

		let partition_factor = if channel_count < 15 {
			5
		} else {
			50 // ~ 8hours
		};

		let has_pending_claims = monitor_state.monitor.has_pending_claims();
		if has_pending_claims || get_partition_key(funding_outpoint) % partition_factor == 0 {
			log_trace!(logger, "Syncing Channel Monitor for channel {}", log_funding_info!(monitor));
			// Even though we don't track monitor updates from chain-sync as pending, we still want
			// updates per-channel to be well-ordered so that users don't see a
			// `ChannelMonitorUpdate` after a channel persist for a channel with the same
			// `latest_update_id`.
			let _pending_monitor_updates = monitor_state.pending_monitor_updates.lock().unwrap();
			match self.persister.update_persisted_channel(*funding_outpoint, None, monitor) {
				ChannelMonitorUpdateStatus::Completed =>
					log_trace!(logger, "Finished syncing Channel Monitor for channel {} for block-data",
						log_funding_info!(monitor)
					),
				ChannelMonitorUpdateStatus::InProgress => {
					log_trace!(logger, "Channel Monitor sync for channel {} in progress.", log_funding_info!(monitor));
				}
				ChannelMonitorUpdateStatus::UnrecoverableError => {
					return Err(());
				}
			}
		}

		// Register any new outputs with the chain source for filtering, storing any dependent
		// transactions from within the block that previously had not been included in txdata.
		if let Some(ref chain_source) = self.chain_source {
			let block_hash = header.block_hash();
			for (txid, mut outputs) in txn_outputs.drain(..) {
				for (idx, output) in outputs.drain(..) {
					// Register any new outputs with the chain source for filtering
					let output = WatchedOutput {
						block_hash: Some(block_hash),
						outpoint: OutPoint { txid, index: idx as u16 },
						script_pubkey: output.script_pubkey,
					};
					log_trace!(logger, "Adding monitoring for spends of outpoint {} to the filter", output.outpoint);
					chain_source.register_output(output);
				}
			}
		}
		Ok(())
	}

	/// Creates a new `ChainMonitor` used to watch on-chain activity pertaining to channels.
	///
	/// When an optional chain source implementing [`chain::Filter`] is provided, the chain monitor
	/// will call back to it indicating transactions and outputs of interest. This allows clients to
	/// pre-filter blocks or only fetch blocks matching a compact filter. Otherwise, clients may
	/// always need to fetch full blocks absent another means for determining which blocks contain
	/// transactions relevant to the watched channels.
	pub fn new(chain_source: Option<C>, broadcaster: T, logger: L, feeest: F, persister: P) -> Self {
		Self {
			monitors: RwLock::new(new_hash_map()),
			chain_source,
			broadcaster,
			logger,
			fee_estimator: feeest,
			persister,
			pending_monitor_events: Mutex::new(Vec::new()),
			highest_chain_height: AtomicUsize::new(0),
			event_notifier: Notifier::new(),
		}
	}

	/// Gets the balances in the contained [`ChannelMonitor`]s which are claimable on-chain or
	/// claims which are awaiting confirmation.
	///
	/// Includes the balances from each [`ChannelMonitor`] *except* those included in
	/// `ignored_channels`, allowing you to filter out balances from channels which are still open
	/// (and whose balance should likely be pulled from the [`ChannelDetails`]).
	///
	/// See [`ChannelMonitor::get_claimable_balances`] for more details on the exact criteria for
	/// inclusion in the return value.
	pub fn get_claimable_balances(&self, ignored_channels: &[&ChannelDetails]) -> Vec<Balance> {
		let mut ret = Vec::new();
		let monitor_states = self.monitors.read().unwrap();
		for (_, monitor_state) in monitor_states.iter().filter(|(funding_outpoint, _)| {
			for chan in ignored_channels {
				if chan.funding_txo.as_ref() == Some(funding_outpoint) {
					return false;
				}
			}
			true
		}) {
			ret.append(&mut monitor_state.monitor.get_claimable_balances());
		}
		ret
	}

	/// Gets the [`LockedChannelMonitor`] for a given funding outpoint, returning an `Err` if no
	/// such [`ChannelMonitor`] is currently being monitored for.
	///
	/// Note that the result holds a mutex over our monitor set, and should not be held
	/// indefinitely.
	pub fn get_monitor(&self, funding_txo: OutPoint) -> Result<LockedChannelMonitor<'_, ChannelSigner>, ()> {
		let lock = self.monitors.read().unwrap();
		if lock.get(&funding_txo).is_some() {
			Ok(LockedChannelMonitor { lock, funding_txo })
		} else {
			Err(())
		}
	}

	/// Lists the funding outpoint and channel ID of each [`ChannelMonitor`] being monitored.
	///
	/// Note that [`ChannelMonitor`]s are not removed when a channel is closed as they are always
	/// monitoring for on-chain state resolutions.
	pub fn list_monitors(&self) -> Vec<(OutPoint, ChannelId)> {
		self.monitors.read().unwrap().iter().map(|(outpoint, monitor_holder)| {
			let channel_id = monitor_holder.monitor.channel_id();
			(*outpoint, channel_id)
		}).collect()
	}

	#[cfg(not(c_bindings))]
	/// Lists the pending updates for each [`ChannelMonitor`] (by `OutPoint` being monitored).
	/// Each `Vec<u64>` contains `update_id`s from [`ChannelMonitor::get_latest_update_id`] for updates
	/// that have not yet been fully persisted. Note that if a full monitor is persisted all the pending
	/// monitor updates must be individually marked completed by calling [`ChainMonitor::channel_monitor_updated`].
	pub fn list_pending_monitor_updates(&self) -> HashMap<OutPoint, Vec<u64>> {
		hash_map_from_iter(self.monitors.read().unwrap().iter().map(|(outpoint, holder)| {
			(*outpoint, holder.pending_monitor_updates.lock().unwrap().clone())
		}))
	}

	#[cfg(c_bindings)]
	/// Lists the pending updates for each [`ChannelMonitor`] (by `OutPoint` being monitored).
	/// Each `Vec<u64>` contains `update_id`s from [`ChannelMonitor::get_latest_update_id`] for updates
	/// that have not yet been fully persisted. Note that if a full monitor is persisted all the pending
	/// monitor updates must be individually marked completed by calling [`ChainMonitor::channel_monitor_updated`].
	pub fn list_pending_monitor_updates(&self) -> Vec<(OutPoint, Vec<u64>)> {
		self.monitors.read().unwrap().iter().map(|(outpoint, holder)| {
			(*outpoint, holder.pending_monitor_updates.lock().unwrap().clone())
		}).collect()
	}


	#[cfg(test)]
	pub fn remove_monitor(&self, funding_txo: &OutPoint) -> ChannelMonitor<ChannelSigner> {
		self.monitors.write().unwrap().remove(funding_txo).unwrap().monitor
	}

	/// Indicates the persistence of a [`ChannelMonitor`] has completed after
	/// [`ChannelMonitorUpdateStatus::InProgress`] was returned from an update operation.
	///
	/// Thus, the anticipated use is, at a high level:
	///  1) This [`ChainMonitor`] calls [`Persist::update_persisted_channel`] which stores the
	///     update to disk and begins updating any remote (e.g. watchtower/backup) copies,
	///     returning [`ChannelMonitorUpdateStatus::InProgress`],
	///  2) once all remote copies are updated, you call this function with [`ChannelMonitor::get_latest_update_id`]
	///     or [`ChannelMonitorUpdate::update_id`] as the `completed_update_id`, and once all pending
	///     updates have completed the channel will be re-enabled.
	///
	/// It is only necessary to call [`ChainMonitor::channel_monitor_updated`] when you return [`ChannelMonitorUpdateStatus::InProgress`]
	/// from [`Persist`] and either:
	///   1. A new [`ChannelMonitor`] was added in [`Persist::persist_new_channel`], or
	///   2. A [`ChannelMonitorUpdate`] was provided as part of [`Persist::update_persisted_channel`].
	/// Note that we don't care about calls to [`Persist::update_persisted_channel`] where no
	/// [`ChannelMonitorUpdate`] was provided.
	///
	/// Returns an [`APIError::APIMisuseError`] if `funding_txo` does not match any currently
	/// registered [`ChannelMonitor`]s.
	pub fn channel_monitor_updated(&self, funding_txo: OutPoint, completed_update_id: u64) -> Result<(), APIError> {
		let monitors = self.monitors.read().unwrap();
		let monitor_data = if let Some(mon) = monitors.get(&funding_txo) { mon } else {
			return Err(APIError::APIMisuseError { err: format!("No ChannelMonitor matching funding outpoint {:?} found", funding_txo) });
		};
		let mut pending_monitor_updates = monitor_data.pending_monitor_updates.lock().unwrap();
		pending_monitor_updates.retain(|update_id| *update_id != completed_update_id);

		// Note that we only check for pending non-chainsync monitor updates and we don't track monitor
		// updates resulting from chainsync in `pending_monitor_updates`.
		let monitor_is_pending_updates = monitor_data.has_pending_updates(&pending_monitor_updates);
		log_debug!(self.logger, "Completed off-chain monitor update {} for channel with funding outpoint {:?}, {}",
			completed_update_id,
			funding_txo,
			if monitor_is_pending_updates {
				"still have pending off-chain updates"
			} else {
				"all off-chain updates complete, returning a MonitorEvent"
			});
		if monitor_is_pending_updates {
			// If there are still monitor updates pending, we cannot yet construct a
			// Completed event.
			return Ok(());
		}
		let channel_id = monitor_data.monitor.channel_id();
		self.pending_monitor_events.lock().unwrap().push((funding_txo, channel_id, vec![MonitorEvent::Completed {
			funding_txo, channel_id,
			monitor_update_id: monitor_data.monitor.get_latest_update_id(),
		}], monitor_data.monitor.get_counterparty_node_id()));

		self.event_notifier.notify();
		Ok(())
	}

	/// This wrapper avoids having to update some of our tests for now as they assume the direct
	/// chain::Watch API wherein we mark a monitor fully-updated by just calling
	/// channel_monitor_updated once with the highest ID.
	#[cfg(any(test, fuzzing))]
	pub fn force_channel_monitor_updated(&self, funding_txo: OutPoint, monitor_update_id: u64) {
		let monitors = self.monitors.read().unwrap();
		let (counterparty_node_id, channel_id) = if let Some(m) = monitors.get(&funding_txo) {
			(m.monitor.get_counterparty_node_id(), m.monitor.channel_id())
		} else {
			(None, ChannelId::v1_from_funding_outpoint(funding_txo))
		};
		self.pending_monitor_events.lock().unwrap().push((funding_txo, channel_id, vec![MonitorEvent::Completed {
			funding_txo,
			channel_id,
			monitor_update_id,
		}], counterparty_node_id));
		self.event_notifier.notify();
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		use crate::events::EventsProvider;
		let events = core::cell::RefCell::new(Vec::new());
		let event_handler = |event: events::Event| Ok(events.borrow_mut().push(event));
		self.process_pending_events(&event_handler);
		events.into_inner()
	}

	/// Processes any events asynchronously in the order they were generated since the last call
	/// using the given event handler.
	///
	/// See the trait-level documentation of [`EventsProvider`] for requirements.
	///
	/// [`EventsProvider`]: crate::events::EventsProvider
	pub async fn process_pending_events_async<Future: core::future::Future<Output = Result<(), ReplayEvent>>, H: Fn(Event) -> Future>(
		&self, handler: H
	) {
		// Sadly we can't hold the monitors read lock through an async call. Thus we have to do a
		// crazy dance to process a monitor's events then only remove them once we've done so.
		let mons_to_process = self.monitors.read().unwrap().keys().cloned().collect::<Vec<_>>();
		for funding_txo in mons_to_process {
			let mut ev;
			match super::channelmonitor::process_events_body!(
				self.monitors.read().unwrap().get(&funding_txo).map(|m| &m.monitor), ev, handler(ev).await) {
				Ok(()) => {},
				Err(ReplayEvent ()) => {
					self.event_notifier.notify();
				}
			}
		}
	}

	/// Gets a [`Future`] that completes when an event is available either via
	/// [`chain::Watch::release_pending_monitor_events`] or
	/// [`EventsProvider::process_pending_events`].
	///
	/// Note that callbacks registered on the [`Future`] MUST NOT call back into this
	/// [`ChainMonitor`] and should instead register actions to be taken later.
	///
	/// [`EventsProvider::process_pending_events`]: crate::events::EventsProvider::process_pending_events
	pub fn get_update_future(&self) -> Future {
		self.event_notifier.get_future()
	}

	/// Triggers rebroadcasts/fee-bumps of pending claims from a force-closed channel. This is
	/// crucial in preventing certain classes of pinning attacks, detecting substantial mempool
	/// feerate changes between blocks, and ensuring reliability if broadcasting fails. We recommend
	/// invoking this every 30 seconds, or lower if running in an environment with spotty
	/// connections, like on mobile.
	pub fn rebroadcast_pending_claims(&self) {
		let monitors = self.monitors.read().unwrap();
		for (_, monitor_holder) in &*monitors {
			monitor_holder.monitor.rebroadcast_pending_claims(
				&*self.broadcaster, &*self.fee_estimator, &self.logger
			)
		}
	}

	/// Triggers rebroadcasts of pending claims from force-closed channels after a transaction
	/// signature generation failure.
	///
	/// `monitor_opt` can be used as a filter to only trigger them for a specific channel monitor.
	pub fn signer_unblocked(&self, monitor_opt: Option<OutPoint>) {
		let monitors = self.monitors.read().unwrap();
		if let Some(funding_txo) = monitor_opt {
			if let Some(monitor_holder) = monitors.get(&funding_txo) {
				monitor_holder.monitor.signer_unblocked(
					&*self.broadcaster, &*self.fee_estimator, &self.logger
				)
			}
		} else {
			for (_, monitor_holder) in &*monitors {
				monitor_holder.monitor.signer_unblocked(
					&*self.broadcaster, &*self.fee_estimator, &self.logger
				)
			}
		}
	}

	/// Archives fully resolved channel monitors by calling [`Persist::archive_persisted_channel`].
	///
	/// This is useful for pruning fully resolved monitors from the monitor set and primary
	/// storage so they are not kept in memory and reloaded on restart.
	///
	/// Should be called occasionally (once every handful of blocks or on startup).
	///
	/// Depending on the implementation of [`Persist::archive_persisted_channel`] the monitor
	/// data could be moved to an archive location or removed entirely.
	pub fn archive_fully_resolved_channel_monitors(&self) {
		let mut have_monitors_to_prune = false;
		for (_, monitor_holder) in self.monitors.read().unwrap().iter() {
			let logger = WithChannelMonitor::from(&self.logger, &monitor_holder.monitor, None);
			if monitor_holder.monitor.is_fully_resolved(&logger) {
				have_monitors_to_prune = true;
			}
		}
		if have_monitors_to_prune {
			let mut monitors = self.monitors.write().unwrap();
			monitors.retain(|funding_txo, monitor_holder| {
				let logger = WithChannelMonitor::from(&self.logger, &monitor_holder.monitor, None);
				if monitor_holder.monitor.is_fully_resolved(&logger) {
					log_info!(logger,
						"Archiving fully resolved ChannelMonitor for funding txo {}",
						funding_txo
					);
					self.persister.archive_persisted_channel(*funding_txo);
					false
				} else {
					true
				}
			});
		}
	}
}

impl<ChannelSigner: EcdsaChannelSigner, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref>
chain::Listen for ChainMonitor<ChannelSigner, C, T, F, L, P>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
{
	fn filtered_block_connected(&self, header: &Header, txdata: &TransactionData, height: u32) {
		log_debug!(self.logger, "New best block {} at height {} provided via block_connected", header.block_hash(), height);
		self.process_chain_data(header, Some(height), &txdata, |monitor, txdata| {
			monitor.block_connected(
				header, txdata, height, &*self.broadcaster, &*self.fee_estimator, &self.logger)
		});
		// Assume we may have some new events and wake the event processor
		self.event_notifier.notify();
	}

	fn block_disconnected(&self, header: &Header, height: u32) {
		let monitor_states = self.monitors.read().unwrap();
		log_debug!(self.logger, "Latest block {} at height {} removed via block_disconnected", header.block_hash(), height);
		for monitor_state in monitor_states.values() {
			monitor_state.monitor.block_disconnected(
				header, height, &*self.broadcaster, &*self.fee_estimator, &self.logger);
		}
	}
}

impl<ChannelSigner: EcdsaChannelSigner, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref>
chain::Confirm for ChainMonitor<ChannelSigner, C, T, F, L, P>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
{
	fn transactions_confirmed(&self, header: &Header, txdata: &TransactionData, height: u32) {
		log_debug!(self.logger, "{} provided transactions confirmed at height {} in block {}", txdata.len(), height, header.block_hash());
		self.process_chain_data(header, None, txdata, |monitor, txdata| {
			monitor.transactions_confirmed(
				header, txdata, height, &*self.broadcaster, &*self.fee_estimator, &self.logger)
		});
		// Assume we may have some new events and wake the event processor
		self.event_notifier.notify();
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		log_debug!(self.logger, "Transaction {} reorganized out of chain", txid);
		let monitor_states = self.monitors.read().unwrap();
		for monitor_state in monitor_states.values() {
			monitor_state.monitor.transaction_unconfirmed(txid, &*self.broadcaster, &*self.fee_estimator, &self.logger);
		}
	}

	fn best_block_updated(&self, header: &Header, height: u32) {
		log_debug!(self.logger, "New best block {} at height {} provided via best_block_updated", header.block_hash(), height);
		self.process_chain_data(header, Some(height), &[], |monitor, txdata| {
			// While in practice there shouldn't be any recursive calls when given empty txdata,
			// it's still possible if a chain::Filter implementation returns a transaction.
			debug_assert!(txdata.is_empty());
			monitor.best_block_updated(
				header, height, &*self.broadcaster, &*self.fee_estimator, &self.logger
			)
		});
		// Assume we may have some new events and wake the event processor
		self.event_notifier.notify();
	}

	fn get_relevant_txids(&self) -> Vec<(Txid, u32, Option<BlockHash>)> {
		let mut txids = Vec::new();
		let monitor_states = self.monitors.read().unwrap();
		for monitor_state in monitor_states.values() {
			txids.append(&mut monitor_state.monitor.get_relevant_txids());
		}

		txids.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
		txids.dedup_by_key(|(txid, _, _)| *txid);
		txids
	}
}

impl<ChannelSigner: EcdsaChannelSigner, C: Deref , T: Deref , F: Deref , L: Deref , P: Deref >
chain::Watch<ChannelSigner> for ChainMonitor<ChannelSigner, C, T, F, L, P>
where C::Target: chain::Filter,
	    T::Target: BroadcasterInterface,
	    F::Target: FeeEstimator,
	    L::Target: Logger,
	    P::Target: Persist<ChannelSigner>,
{
	fn watch_channel(&self, funding_outpoint: OutPoint, monitor: ChannelMonitor<ChannelSigner>) -> Result<ChannelMonitorUpdateStatus, ()> {
		let logger = WithChannelMonitor::from(&self.logger, &monitor, None);
		let mut monitors = self.monitors.write().unwrap();
		let entry = match monitors.entry(funding_outpoint) {
			hash_map::Entry::Occupied(_) => {
				log_error!(logger, "Failed to add new channel data: channel monitor for given outpoint is already present");
				return Err(());
			},
			hash_map::Entry::Vacant(e) => e,
		};
		log_trace!(logger, "Got new ChannelMonitor for channel {}", log_funding_info!(monitor));
		let update_id = monitor.get_latest_update_id();
		let mut pending_monitor_updates = Vec::new();
		let persist_res = self.persister.persist_new_channel(funding_outpoint, &monitor);
		match persist_res {
			ChannelMonitorUpdateStatus::InProgress => {
				log_info!(logger, "Persistence of new ChannelMonitor for channel {} in progress", log_funding_info!(monitor));
				pending_monitor_updates.push(update_id);
			},
			ChannelMonitorUpdateStatus::Completed => {
				log_info!(logger, "Persistence of new ChannelMonitor for channel {} completed", log_funding_info!(monitor));
			},
			ChannelMonitorUpdateStatus::UnrecoverableError => {
				let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
				log_error!(logger, "{}", err_str);
				panic!("{}", err_str);
			},
		}
		if let Some(ref chain_source) = self.chain_source {
			monitor.load_outputs_to_watch(chain_source , &self.logger);
		}
		entry.insert(MonitorHolder {
			monitor,
			pending_monitor_updates: Mutex::new(pending_monitor_updates),
		});
		Ok(persist_res)
	}

	fn update_channel(&self, funding_txo: OutPoint, update: &ChannelMonitorUpdate) -> ChannelMonitorUpdateStatus {
		// `ChannelMonitorUpdate`'s `channel_id` is `None` prior to 0.0.121 and all channels in those
		// versions are V1-established. For 0.0.121+ the `channel_id` fields is always `Some`.
		let channel_id = update.channel_id.unwrap_or(ChannelId::v1_from_funding_outpoint(funding_txo));
		// Update the monitor that watches the channel referred to by the given outpoint.
		let monitors = self.monitors.read().unwrap();
		match monitors.get(&funding_txo) {
			None => {
				let logger = WithContext::from(&self.logger, update.counterparty_node_id, Some(channel_id), None);
				log_error!(logger, "Failed to update channel monitor: no such monitor registered");

				// We should never ever trigger this from within ChannelManager. Technically a
				// user could use this object with some proxying in between which makes this
				// possible, but in tests and fuzzing, this should be a panic.
				#[cfg(debug_assertions)]
				panic!("ChannelManager generated a channel update for a channel that was not yet registered!");
				#[cfg(not(debug_assertions))]
				ChannelMonitorUpdateStatus::InProgress
			},
			Some(monitor_state) => {
				let monitor = &monitor_state.monitor;
				let logger = WithChannelMonitor::from(&self.logger, &monitor, None);
				log_trace!(logger, "Updating ChannelMonitor to id {} for channel {}", update.update_id, log_funding_info!(monitor));

				// We hold a `pending_monitor_updates` lock through `update_monitor` to ensure we
				// have well-ordered updates from the users' point of view. See the
				// `pending_monitor_updates` docs for more.
				let mut pending_monitor_updates = monitor_state.pending_monitor_updates.lock().unwrap();
				let update_res = monitor.update_monitor(update, &self.broadcaster, &self.fee_estimator, &self.logger);

				let update_id = update.update_id;
				let persist_res = if update_res.is_err() {
					// Even if updating the monitor returns an error, the monitor's state will
					// still be changed. Therefore, we should persist the updated monitor despite the error.
					// We don't want to persist a `monitor_update` which results in a failure to apply later
					// while reading `channel_monitor` with updates from storage. Instead, we should persist
					// the entire `channel_monitor` here.
					log_warn!(logger, "Failed to update ChannelMonitor for channel {}. Going ahead and persisting the entire ChannelMonitor", log_funding_info!(monitor));
					self.persister.update_persisted_channel(funding_txo, None, monitor)
				} else {
					self.persister.update_persisted_channel(funding_txo, Some(update), monitor)
				};
				match persist_res {
					ChannelMonitorUpdateStatus::InProgress => {
						pending_monitor_updates.push(update_id);
						log_debug!(logger,
							"Persistence of ChannelMonitorUpdate id {:?} for channel {} in progress",
							update_id,
							log_funding_info!(monitor)
						);
					},
					ChannelMonitorUpdateStatus::Completed => {
						log_debug!(logger,
							"Persistence of ChannelMonitorUpdate id {:?} for channel {} completed",
							update_id,
							log_funding_info!(monitor)
						);
					},
					ChannelMonitorUpdateStatus::UnrecoverableError => {
						// Take the monitors lock for writing so that we poison it and any future
						// operations going forward fail immediately.
						core::mem::drop(pending_monitor_updates);
						core::mem::drop(monitors);
						let _poison = self.monitors.write().unwrap();
						let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
						log_error!(logger, "{}", err_str);
						panic!("{}", err_str);
					},
				}
				if update_res.is_err() {
					ChannelMonitorUpdateStatus::InProgress
				} else {
					persist_res
				}
			}
		}
	}

	fn release_pending_monitor_events(&self) -> Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, Option<PublicKey>)> {
		let mut pending_monitor_events = self.pending_monitor_events.lock().unwrap().split_off(0);
		for monitor_state in self.monitors.read().unwrap().values() {
			let monitor_events = monitor_state.monitor.get_and_clear_pending_monitor_events();
			if monitor_events.len() > 0 {
				let monitor_outpoint = monitor_state.monitor.get_funding_txo().0;
				let monitor_channel_id = monitor_state.monitor.channel_id();
				let counterparty_node_id = monitor_state.monitor.get_counterparty_node_id();
				pending_monitor_events.push((monitor_outpoint, monitor_channel_id, monitor_events, counterparty_node_id));
			}
		}
		pending_monitor_events
	}
}

impl<ChannelSigner: EcdsaChannelSigner, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref> events::EventsProvider for ChainMonitor<ChannelSigner, C, T, F, L, P>
	where C::Target: chain::Filter,
	      T::Target: BroadcasterInterface,
	      F::Target: FeeEstimator,
	      L::Target: Logger,
	      P::Target: Persist<ChannelSigner>,
{
	/// Processes [`SpendableOutputs`] events produced from each [`ChannelMonitor`] upon maturity.
	///
	/// For channels featuring anchor outputs, this method will also process [`BumpTransaction`]
	/// events produced from each [`ChannelMonitor`] while there is a balance to claim onchain
	/// within each channel. As the confirmation of a commitment transaction may be critical to the
	/// safety of funds, we recommend invoking this every 30 seconds, or lower if running in an
	/// environment with spotty connections, like on mobile.
	///
	/// An [`EventHandler`] may safely call back to the provider, though this shouldn't be needed in
	/// order to handle these events.
	///
	/// [`SpendableOutputs`]: events::Event::SpendableOutputs
	/// [`BumpTransaction`]: events::Event::BumpTransaction
	fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler {
		for monitor_state in self.monitors.read().unwrap().values() {
			match monitor_state.monitor.process_pending_events(&handler) {
				Ok(()) => {},
				Err(ReplayEvent ()) => {
					self.event_notifier.notify();
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::{check_added_monitors, check_closed_event};
	use crate::{expect_payment_path_successful, get_event_msg};
	use crate::{get_htlc_update_msgs, get_revoke_commit_msgs};
	use crate::chain::{ChannelMonitorUpdateStatus, Watch};
	use crate::chain::channelmonitor::ANTI_REORG_DELAY;
	use crate::events::{ClosureReason, Event, MessageSendEvent, MessageSendEventsProvider};
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs::ChannelMessageHandler;

	const CHAINSYNC_MONITOR_PARTITION_FACTOR: u32 = 5;

	#[test]
	fn test_async_ooo_offchain_updates() {
		// Test that if we have multiple offchain updates being persisted and they complete
		// out-of-order, the ChainMonitor waits until all have completed before informing the
		// ChannelManager.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);

		// Route two payments to be claimed at the same time.
		let (payment_preimage_1, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		let (payment_preimage_2, payment_hash_2, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

		chanmon_cfgs[1].persister.offchain_monitor_updates.lock().unwrap().clear();
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

		nodes[1].node.claim_funds(payment_preimage_1);
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.claim_funds(payment_preimage_2);
		check_added_monitors!(nodes[1], 1);

		let persistences = chanmon_cfgs[1].persister.offchain_monitor_updates.lock().unwrap().clone();
		assert_eq!(persistences.len(), 1);
		let (funding_txo, updates) = persistences.iter().next().unwrap();
		assert_eq!(updates.len(), 2);

		// Note that updates is a HashMap so the ordering here is actually random. This shouldn't
		// fail either way but if it fails intermittently it's depending on the ordering of updates.
		let mut update_iter = updates.iter();
		let next_update = update_iter.next().unwrap().clone();
		// Should contain next_update when pending updates listed.
		#[cfg(not(c_bindings))]
		assert!(nodes[1].chain_monitor.chain_monitor.list_pending_monitor_updates().get(funding_txo)
			.unwrap().contains(&next_update));
		#[cfg(c_bindings)]
		assert!(nodes[1].chain_monitor.chain_monitor.list_pending_monitor_updates().iter()
			.find(|(txo, _)| txo == funding_txo).unwrap().1.contains(&next_update));
		nodes[1].chain_monitor.chain_monitor.channel_monitor_updated(*funding_txo, next_update.clone()).unwrap();
		// Should not contain the previously pending next_update when pending updates listed.
		#[cfg(not(c_bindings))]
		assert!(!nodes[1].chain_monitor.chain_monitor.list_pending_monitor_updates().get(funding_txo)
			.unwrap().contains(&next_update));
		#[cfg(c_bindings)]
		assert!(!nodes[1].chain_monitor.chain_monitor.list_pending_monitor_updates().iter()
			.find(|(txo, _)| txo == funding_txo).unwrap().1.contains(&next_update));
		assert!(nodes[1].chain_monitor.release_pending_monitor_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		nodes[1].chain_monitor.chain_monitor.channel_monitor_updated(*funding_txo, update_iter.next().unwrap().clone()).unwrap();

		let claim_events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(claim_events.len(), 2);
		match claim_events[0] {
			Event::PaymentClaimed { ref payment_hash, amount_msat: 1_000_000, .. } => {
				assert_eq!(payment_hash_1, *payment_hash);
			},
			_ => panic!("Unexpected event"),
		}
		match claim_events[1] {
			Event::PaymentClaimed { ref payment_hash, amount_msat: 1_000_000, .. } => {
				assert_eq!(payment_hash_2, *payment_hash);
			},
			_ => panic!("Unexpected event"),
		}

		// Now manually walk the commitment signed dance - because we claimed two payments
		// back-to-back it doesn't fit into the neat walk commitment_signed_dance does.

		let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
		expect_payment_sent(&nodes[0], payment_preimage_1, None, false, false);
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &updates.commitment_signed);
		check_added_monitors!(nodes[0], 1);
		let (as_first_raa, as_first_update) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_first_raa);
		check_added_monitors!(nodes[1], 1);
		let bs_second_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_first_update);
		check_added_monitors!(nodes[1], 1);
		let bs_first_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_second_updates.update_fulfill_htlcs[0]);
		expect_payment_sent(&nodes[0], payment_preimage_2, None, false, false);
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_updates.commitment_signed);
		check_added_monitors!(nodes[0], 1);
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
		expect_payment_path_successful!(nodes[0]);
		check_added_monitors!(nodes[0], 1);
		let (as_second_raa, as_second_update) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_update);
		check_added_monitors!(nodes[1], 1);
		let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa);
		expect_payment_path_successful!(nodes[0]);
		check_added_monitors!(nodes[0], 1);
	}

	#[test]
	fn test_chainsync_triggers_distributed_monitor_persistence() {
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
		let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

		// Use FullBlockViaListen to avoid duplicate calls to process_chain_data and skips_blocks() in
		// case of other connect_styles.
		*nodes[0].connect_style.borrow_mut() = ConnectStyle::FullBlockViaListen;
		*nodes[1].connect_style.borrow_mut() = ConnectStyle::FullBlockViaListen;
		*nodes[2].connect_style.borrow_mut() = ConnectStyle::FullBlockViaListen;

		let _channel_1 = create_announced_chan_between_nodes(&nodes, 0, 1).2;
		let channel_2 = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0).2;

		chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().clear();
		chanmon_cfgs[1].persister.chain_sync_monitor_persistences.lock().unwrap().clear();
		chanmon_cfgs[2].persister.chain_sync_monitor_persistences.lock().unwrap().clear();

		connect_blocks(&nodes[0], CHAINSYNC_MONITOR_PARTITION_FACTOR * 2);
		connect_blocks(&nodes[1], CHAINSYNC_MONITOR_PARTITION_FACTOR * 2);
		connect_blocks(&nodes[2], CHAINSYNC_MONITOR_PARTITION_FACTOR * 2);

		// Connecting [`DEFAULT_CHAINSYNC_PARTITION_FACTOR`] * 2 blocks should trigger only 2 writes
		// per monitor/channel.
		assert_eq!(2 * 2, chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().len());
		assert_eq!(2, chanmon_cfgs[1].persister.chain_sync_monitor_persistences.lock().unwrap().len());
		assert_eq!(2, chanmon_cfgs[2].persister.chain_sync_monitor_persistences.lock().unwrap().len());

		// Test that monitors with pending_claims are persisted on every block.
		// Now, close channel_2 i.e. b/w node-0 and node-2 to create pending_claim in node[0].
		nodes[0].node.force_close_broadcasting_latest_txn(&channel_2, &nodes[2].node.get_our_node_id(), "Channel force-closed".to_string()).unwrap();
		check_closed_event!(&nodes[0], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, false,
			[nodes[2].node.get_our_node_id()], 1000000);
		check_closed_broadcast(&nodes[0], 1, true);
		let close_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(close_tx.len(), 1);

		mine_transaction(&nodes[2], &close_tx[0]);
		check_added_monitors(&nodes[2], 1);
		check_closed_broadcast(&nodes[2], 1, true);
		check_closed_event!(&nodes[2], 1, ClosureReason::CommitmentTxConfirmed, false,
			[nodes[0].node.get_our_node_id()], 1000000);

		chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().clear();
		chanmon_cfgs[2].persister.chain_sync_monitor_persistences.lock().unwrap().clear();

		// For channel_2, there should be a monitor write for every block connection.
		// We connect [`DEFAULT_CHAINSYNC_MONITOR_PARTITION_FACTOR`] blocks since we don't know when
		// channel_1 monitor persistence will occur, with [`DEFAULT_CHAINSYNC_MONITOR_PARTITION_FACTOR`]
		// it will be persisted exactly once.
		connect_blocks(&nodes[0], CHAINSYNC_MONITOR_PARTITION_FACTOR);
		connect_blocks(&nodes[2], CHAINSYNC_MONITOR_PARTITION_FACTOR);

		// DEFAULT_CHAINSYNC_MONITOR_PARTITION_FACTOR writes for channel_2 due to pending_claim, 1 for
		// channel_1
		assert_eq!((CHAINSYNC_MONITOR_PARTITION_FACTOR + 1) as usize, chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().len());
		// For node[2], there is no pending_claim
		assert_eq!(1, chanmon_cfgs[2].persister.chain_sync_monitor_persistences.lock().unwrap().len());

		// Confirm claim for node[0] with ANTI_REORG_DELAY and reset monitor write counter.
		mine_transaction(&nodes[0], &close_tx[0]);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		check_added_monitors(&nodes[0], 1);
		chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().clear();

		// Again connect 1 full cycle of DEFAULT_CHAINSYNC_MONITOR_PARTITION_FACTOR blocks, it should only
		// result in 1 write per monitor/channel.
		connect_blocks(&nodes[0], CHAINSYNC_MONITOR_PARTITION_FACTOR);
		assert_eq!(2, chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().len());
	}

	#[test]
	#[cfg(feature = "std")]
	fn update_during_chainsync_poisons_channel() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		*nodes[0].connect_style.borrow_mut() = ConnectStyle::FullBlockViaListen;

		chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::UnrecoverableError);

		assert!(std::panic::catch_unwind(|| {
			// Returning an UnrecoverableError should always panic immediately
			// Connecting [`DEFAULT_CHAINSYNC_PARTITION_FACTOR`] blocks so that we trigger some persistence
			// after accounting for block-height based partitioning/distribution.
			connect_blocks(&nodes[0], CHAINSYNC_MONITOR_PARTITION_FACTOR);
		}).is_err());
		assert!(std::panic::catch_unwind(|| {
			// ...and also poison our locks causing later use to panic as well
			core::mem::drop(nodes);
		}).is_err());
	}
}

