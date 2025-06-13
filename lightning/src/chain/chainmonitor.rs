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
use bitcoin::hash_types::{BlockHash, Txid};
use types::features::{InitFeatures, NodeFeatures};

use crate::chain;
use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::channelmonitor::{
	Balance, ChannelMonitor, ChannelMonitorUpdate, MonitorEvent, TransactionOutputs,
	WithChannelMonitor,
};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::chain::{ChannelMonitorUpdateStatus, Filter, WatchedOutput};
use crate::events::{self, Event, EventHandler, ReplayEvent};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::msgs::{self, BaseMessageHandler, Init, MessageSendEvent};
use crate::ln::our_peer_storage::DecryptedOurPeerStorage;
use crate::ln::types::ChannelId;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::{EntropySource, PeerStorageKey};
use crate::sync::Arc;
use crate::util::async_poll::{poll_or_spawn, AsyncResult, AsyncVoid, FutureSpawner};
use crate::util::errors::APIError;
use crate::util::logger::{Logger, WithContext};
use crate::util::persist::MonitorName;
use crate::util::wakers::{Future, Notifier};

use crate::prelude::*;
use crate::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard};
use bitcoin::secp256k1::PublicKey;
use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};

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
	/// called by [`ChannelManager`] for new channels, or may be called directly, e.g. on startup,
	/// with the `monitor_name` returned by [`ChannelMonitor::persistence_key`].
	///
	/// The data can be stored any way you want, so long as `monitor_name` is used to maintain a
	/// correct mapping with the stored channel data (i.e., calls to `update_persisted_channel` with
	/// the same `monitor_name` must be applied to or overwrite this data). Note that you **must**
	/// persist every new monitor to disk.
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
	fn persist_new_channel(
		&self, monitor_name: MonitorName, monitor: &ChannelMonitor<ChannelSigner>,
	) -> AsyncResult<'static, ()>;

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
	/// deserialization routine. If there are any gaps in the persisted [`ChannelMonitorUpdate`]s,
	/// implementer can safely ignore [`ChannelMonitorUpdate`]s after the gap and load without them.
	/// See [`ChannelMonitor::update_monitor`] for
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
	fn update_persisted_channel(
		&self, monitor_name: MonitorName, monitor_update: Option<&ChannelMonitorUpdate>,
		monitor: &ChannelMonitor<ChannelSigner>,
	) -> AsyncResult<'static, ()>;
	/// Prevents the channel monitor from being loaded on startup.
	///
	/// Archiving the data in a backup location (rather than deleting it fully) is useful for
	/// hedging against data loss in case of unexpected failure.
	///
	/// Note that if a crash occurs during the archiving process, and its implementation is not
	/// atomic, a state may emerge with the archival operation only being partially complete. In
	/// that scenario, the monitor may still be loaded on startup pending successful completion of
	/// the archive process. Additionally, because the archive operation could be retried on
	/// restart, this method must in that case be idempotent, ensuring it can handle scenarios where
	/// the monitor already exists in the archive.
	fn archive_persisted_channel(&self, monitor_name: MonitorName) -> AsyncVoid;
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
	lock: RwLockReadGuard<'a, HashMap<ChannelId, MonitorHolder<ChannelSigner>>>,
	channel_id: ChannelId,
}

impl<ChannelSigner: EcdsaChannelSigner> Deref for LockedChannelMonitor<'_, ChannelSigner> {
	type Target = ChannelMonitor<ChannelSigner>;
	fn deref(&self) -> &ChannelMonitor<ChannelSigner> {
		&self.lock.get(&self.channel_id).expect("Checked at construction").monitor
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
pub struct ChainMonitor<
	ChannelSigner: EcdsaChannelSigner,
	C: Deref,
	T: Deref,
	F: Deref,
	L: Deref,
	P: Deref,
	ES: Deref,
	FS: FutureSpawner,
> where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
	ES::Target: EntropySource,
{
	monitors: Arc<RwLock<HashMap<ChannelId, MonitorHolder<ChannelSigner>>>>,
	chain_source: Option<C>,
	broadcaster: T,
	logger: L,
	fee_estimator: F,
	persister: P,
	entropy_source: ES,
	/// "User-provided" (ie persistence-completion/-failed) [`MonitorEvent`]s. These came directly
	/// from the user and not from a [`ChannelMonitor`].
	pending_monitor_events: Arc<Mutex<Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, PublicKey)>>>,
	/// The best block height seen, used as a proxy for the passage of time.
	highest_chain_height: AtomicUsize,

	/// A [`Notifier`] used to wake up the background processor in case we have any [`Event`]s for
	/// it to give to users (or [`MonitorEvent`]s for `ChannelManager` to process).
	event_notifier: Arc<Notifier>,

	/// Messages to send to the peer. This is currently used to distribute PeerStorage to channel partners.
	pending_send_only_events: Mutex<Vec<MessageSendEvent>>,

	our_peerstorage_encryption_key: PeerStorageKey,

	future_spawner: Arc<FS>,
}

/// A synchronous wrapper around [`ChainMonitor`].
pub struct ChainMonitorSync<
	ChannelSigner: EcdsaChannelSigner,
	C: Deref,
	T: Deref,
	F: Deref,
	L: Deref,
	P: Deref,
	ES: Deref,
	FS: FutureSpawner,
>(ChainMonitor<ChannelSigner, C, T, F, L, PersistSyncWrapper<P>, ES, FS>)
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: PersistSync<ChannelSigner>,
	ES::Target: EntropySource;

impl<
		ChannelSigner: EcdsaChannelSigner + 'static,
		C: Deref,
		T: Deref,
		F: Deref,
		L: Deref,
		P: Deref,
		ES: Deref,
		FS: FutureSpawner,
	> ChainMonitorSync<ChannelSigner, C, T, F, L, P, ES, FS>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: PersistSync<ChannelSigner>,
	ES::Target: EntropySource,
{
	fn new(
		chain_source: Option<C>, broadcaster: T, logger: L, feeest: F, persister: P,
		entropy_source: ES, our_peerstorage_encryption_key: PeerStorageKey, future_spawner: FS,
	) -> Self {
		let persister = PersistSyncWrapper(persister);

		Self(ChainMonitor::new(
			chain_source,
			broadcaster,
			logger,
			feeest,
			persister,
			entropy_source,
			our_peerstorage_encryption_key,
			future_spawner,
		))
	}

	/// See [`ChainMonitor::rebroadcast_pending_claims`].
	pub fn rebroadcast_pending_claims(&self) {
		self.0.rebroadcast_pending_claims();
	}

	/// See [`ChainMonitor::get_update_future`].
	pub fn get_update_future(&self) -> Future {
		self.0.get_update_future()
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner + 'static,
		C: Deref,
		T: Deref,
		F: Deref,
		L: Deref,
		P: Deref,
		ES: Deref,
		FS: FutureSpawner,
	> events::EventsProvider for ChainMonitorSync<ChannelSigner, C, T, F, L, P, ES, FS>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: PersistSync<ChannelSigner>,
	ES::Target: EntropySource,
{
	fn process_pending_events<H: Deref>(&self, handler: H)
	where
		H::Target: EventHandler,
	{
		self.0.process_pending_events(handler)
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner + 'static,
		C: Deref,
		T: Deref,
		F: Deref,
		L: Deref,
		P: Deref,
		ES: Deref,
		FS: FutureSpawner,
	> ChainMonitor<ChannelSigner, C, T, F, L, P, ES, FS>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
	ES::Target: EntropySource,
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
	fn process_chain_data<FN>(
		&self, header: &Header, best_height: Option<u32>, txdata: &TransactionData, process: FN,
	) where
		FN: Fn(&ChannelMonitor<ChannelSigner>, &TransactionData) -> Vec<TransactionOutputs>,
	{
		let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
		let channel_ids = hash_set_from_iter(self.monitors.read().unwrap().keys().cloned());
		let channel_count = channel_ids.len();
		for channel_id in channel_ids.iter() {
			let monitor_lock = self.monitors.read().unwrap();
			if let Some(monitor_state) = monitor_lock.get(channel_id) {
				if self
					.update_monitor_with_chain_data(
						header,
						best_height,
						txdata,
						&process,
						channel_id,
						&monitor_state,
						channel_count,
					)
					.is_err()
				{
					// Take the monitors lock for writing so that we poison it and any future
					// operations going forward fail immediately.
					core::mem::drop(monitor_lock);
					let _poison = self.monitors.write().unwrap();
					log_error!(self.logger, "{}", err_str);
					panic!("{}", err_str);
				}
			}
		}

		// Do another pass to handle any monitors added in between iterations.
		let monitor_states = self.monitors.write().unwrap();
		for (channel_id, monitor_state) in monitor_states.iter() {
			if !channel_ids.contains(channel_id) {
				if self
					.update_monitor_with_chain_data(
						header,
						best_height,
						txdata,
						&process,
						channel_id,
						&monitor_state,
						channel_count,
					)
					.is_err()
				{
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
		&self, header: &Header, best_height: Option<u32>, txdata: &TransactionData, process: FN,
		channel_id: &ChannelId, monitor_state: &MonitorHolder<ChannelSigner>, channel_count: usize,
	) -> Result<(), ()>
	where
		FN: Fn(&ChannelMonitor<ChannelSigner>, &TransactionData) -> Vec<TransactionOutputs>,
	{
		let monitor = &monitor_state.monitor;
		let logger = WithChannelMonitor::from(&self.logger, &monitor, None);

		let mut txn_outputs = process(monitor, txdata);

		let get_partition_key = |channel_id: &ChannelId| {
			let channel_id_bytes = channel_id.0;
			let channel_id_u32 = u32::from_be_bytes([
				channel_id_bytes[0],
				channel_id_bytes[1],
				channel_id_bytes[2],
				channel_id_bytes[3],
			]);
			channel_id_u32.wrapping_add(best_height.unwrap_or_default())
		};

		let partition_factor = if channel_count < 15 {
			5
		} else {
			50 // ~ 8hours
		};

		let has_pending_claims = monitor_state.monitor.has_pending_claims();
		if has_pending_claims || get_partition_key(channel_id) % partition_factor == 0 {
			log_trace!(
				logger,
				"Syncing Channel Monitor for channel {}",
				log_funding_info!(monitor)
			);
			// Even though we don't track monitor updates from chain-sync as pending, we still want
			// updates per-channel to be well-ordered so that users don't see a
			// `ChannelMonitorUpdate` after a channel persist for a channel with the same
			// `latest_update_id`.
			let _pending_monitor_updates = monitor_state.pending_monitor_updates.lock().unwrap();
			let max_update_id = _pending_monitor_updates.iter().copied().max().unwrap_or(0);

			let persist_res =
				self.persister.update_persisted_channel(monitor.persistence_key(), None, monitor);

			let monitors = self.monitors.clone();
			let pending_monitor_updates_cb = self.pending_monitor_events.clone();
			let event_notifier = self.event_notifier.clone();
			let future_spawner = self.future_spawner.clone();
			let channel_id = *channel_id;

			match poll_or_spawn(
				persist_res,
				move || {
					// TODO: Log error if the monitor is not persisted.
					let _ = ChainMonitor::<ChannelSigner, C, T, F, L, P, ES, FS>::channel_monitor_updated_internal(&monitors, &pending_monitor_updates_cb, &event_notifier,
						channel_id, max_update_id);
				},
				future_spawner.deref(),
			) {
				Ok(true) => {
					// log
				},
				Ok(false) => {
					// log
				},
				Err(_) => {
					return Err(());
				},
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
					log_trace!(
						logger,
						"Adding monitoring for spends of outpoint {} to the filter",
						output.outpoint
					);
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
	///
	/// # Note
	/// `our_peerstorage_encryption_key` must be obtained from [`NodeSigner::get_peer_storage_key`].
	/// This key is used to encrypt peer storage backups.
	///
	/// **Important**: This key should not be set arbitrarily or changed after initialization. The same key
	/// is obtained by the [`ChannelManager`] through [`NodeSigner`] to decrypt peer backups.
	/// Using an inconsistent or incorrect key will result in the inability to decrypt previously encrypted backups.
	///
	/// [`NodeSigner`]: crate::sign::NodeSigner
	/// [`NodeSigner::get_peer_storage_key`]: crate::sign::NodeSigner::get_peer_storage_key
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	pub fn new(
		chain_source: Option<C>, broadcaster: T, logger: L, feeest: F, persister: P,
		entropy_source: ES, our_peerstorage_encryption_key: PeerStorageKey, future_spawner: FS,
	) -> Self {
		Self {
			monitors: Arc::new(RwLock::new(new_hash_map())),
			chain_source,
			broadcaster,
			logger,
			fee_estimator: feeest,
			persister,
			entropy_source,
			pending_monitor_events: Arc::new(Mutex::new(Vec::new())),
			highest_chain_height: AtomicUsize::new(0),
			event_notifier: Arc::new(Notifier::new()),
			pending_send_only_events: Mutex::new(Vec::new()),
			our_peerstorage_encryption_key,
			future_spawner: Arc::new(future_spawner),
		}
	}

	/// Gets the balances in the contained [`ChannelMonitor`]s which are claimable on-chain or
	/// claims which are awaiting confirmation.
	///
	/// Includes the balances from each [`ChannelMonitor`] *except* those included in
	/// `ignored_channels`.
	///
	/// See [`ChannelMonitor::get_claimable_balances`] for more details on the exact criteria for
	/// inclusion in the return value.
	pub fn get_claimable_balances(&self, ignored_channels: &[&ChannelDetails]) -> Vec<Balance> {
		let mut ret = Vec::new();
		let monitor_states = self.monitors.read().unwrap();
		for (_, monitor_state) in monitor_states.iter().filter(|(channel_id, _)| {
			for chan in ignored_channels {
				if chan.channel_id == **channel_id {
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
	pub fn get_monitor(
		&self, channel_id: ChannelId,
	) -> Result<LockedChannelMonitor<'_, ChannelSigner>, ()> {
		let lock = self.monitors.read().unwrap();
		if lock.get(&channel_id).is_some() {
			Ok(LockedChannelMonitor { lock, channel_id })
		} else {
			Err(())
		}
	}

	/// Lists the funding outpoint and channel ID of each [`ChannelMonitor`] being monitored.
	///
	/// Note that [`ChannelMonitor`]s are not removed when a channel is closed as they are always
	/// monitoring for on-chain state resolutions.
	pub fn list_monitors(&self) -> Vec<ChannelId> {
		self.monitors.read().unwrap().keys().copied().collect()
	}

	#[cfg(not(c_bindings))]
	/// Lists the pending updates for each [`ChannelMonitor`] (by `ChannelId` being monitored).
	/// Each `Vec<u64>` contains `update_id`s from [`ChannelMonitor::get_latest_update_id`] for updates
	/// that have not yet been fully persisted. Note that if a full monitor is persisted all the pending
	/// monitor updates must be individually marked completed by calling [`ChainMonitor::channel_monitor_updated`].
	pub fn list_pending_monitor_updates(&self) -> HashMap<ChannelId, Vec<u64>> {
		hash_map_from_iter(self.monitors.read().unwrap().iter().map(|(channel_id, holder)| {
			(*channel_id, holder.pending_monitor_updates.lock().unwrap().clone())
		}))
	}

	#[cfg(c_bindings)]
	/// Lists the pending updates for each [`ChannelMonitor`] (by `ChannelId` being monitored).
	/// Each `Vec<u64>` contains `update_id`s from [`ChannelMonitor::get_latest_update_id`] for updates
	/// that have not yet been fully persisted. Note that if a full monitor is persisted all the pending
	/// monitor updates must be individually marked completed by calling [`ChainMonitor::channel_monitor_updated`].
	pub fn list_pending_monitor_updates(&self) -> Vec<(ChannelId, Vec<u64>)> {
		let monitors = self.monitors.read().unwrap().iter();
		monitors
			.map(|(channel_id, holder)| {
				(*channel_id, holder.pending_monitor_updates.lock().unwrap().clone())
			})
			.collect()
	}

	#[cfg(any(test, feature = "_test_utils"))]
	pub fn remove_monitor(&self, channel_id: &ChannelId) -> ChannelMonitor<ChannelSigner> {
		self.monitors.write().unwrap().remove(channel_id).unwrap().monitor
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
	pub fn channel_monitor_updated(
		&self, channel_id: ChannelId, completed_update_id: u64,
	) -> Result<(), APIError> {
		let monitors = self.monitors.read().unwrap();
		let monitor_data = if let Some(mon) = monitors.get(&channel_id) {
			mon
		} else {
			return Err(APIError::APIMisuseError {
				err: format!("No ChannelMonitor matching channel ID {} found", channel_id),
			});
		};
		let mut pending_monitor_updates = monitor_data.pending_monitor_updates.lock().unwrap();
		pending_monitor_updates.retain(|update_id| *update_id != completed_update_id);

		// Note that we only check for pending non-chainsync monitor updates and we don't track monitor
		// updates resulting from chainsync in `pending_monitor_updates`.
		let monitor_is_pending_updates = monitor_data.has_pending_updates(&pending_monitor_updates);
		log_debug!(
			self.logger,
			"Completed off-chain monitor update {} for channel with channel ID {}, {}",
			completed_update_id,
			channel_id,
			if monitor_is_pending_updates {
				"still have pending off-chain updates"
			} else {
				"all off-chain updates complete, returning a MonitorEvent"
			}
		);
		if monitor_is_pending_updates {
			// If there are still monitor updates pending, we cannot yet construct a
			// Completed event.
			return Ok(());
		}
		let funding_txo = monitor_data.monitor.get_funding_txo();
		self.pending_monitor_events.lock().unwrap().push((
			funding_txo,
			channel_id,
			vec![MonitorEvent::Completed {
				funding_txo,
				channel_id,
				monitor_update_id: monitor_data.monitor.get_latest_update_id(),
			}],
			monitor_data.monitor.get_counterparty_node_id(),
		));

		self.event_notifier.notify();
		Ok(())
	}

	fn channel_monitor_updated_internal(
		monitors: &RwLock<HashMap<ChannelId, MonitorHolder<ChannelSigner>>>,
		pending_monitor_events: &Mutex<Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, PublicKey)>>,
		event_notifier: &Notifier, channel_id: ChannelId, completed_update_id: u64,
	) -> Result<(), APIError> {
		let monitors = monitors.read().unwrap();
		let monitor_data = if let Some(mon) = monitors.get(&channel_id) {
			mon
		} else {
			return Err(APIError::APIMisuseError {
				err: format!("No ChannelMonitor matching channel ID {} found", channel_id),
			});
		};
		let mut pending_monitor_updates = monitor_data.pending_monitor_updates.lock().unwrap();
		pending_monitor_updates.retain(|update_id| *update_id != completed_update_id);

		// Note that we only check for pending non-chainsync monitor updates and we don't track monitor
		// updates resulting from chainsync in `pending_monitor_updates`.
		let monitor_is_pending_updates = monitor_data.has_pending_updates(&pending_monitor_updates);

		// TODO: Add logger

		if monitor_is_pending_updates {
			// If there are still monitor updates pending, we cannot yet construct a
			// Completed event.
			return Ok(());
		}
		let funding_txo = monitor_data.monitor.get_funding_txo();
		pending_monitor_events.lock().unwrap().push((
			funding_txo,
			channel_id,
			vec![MonitorEvent::Completed {
				funding_txo,
				channel_id,
				monitor_update_id: monitor_data.monitor.get_latest_update_id(),
			}],
			monitor_data.monitor.get_counterparty_node_id(),
		));

		event_notifier.notify();
		Ok(())
	}

	/// This wrapper avoids having to update some of our tests for now as they assume the direct
	/// chain::Watch API wherein we mark a monitor fully-updated by just calling
	/// channel_monitor_updated once with the highest ID.
	#[cfg(any(test, fuzzing))]
	pub fn force_channel_monitor_updated(&self, channel_id: ChannelId, monitor_update_id: u64) {
		let monitors = self.monitors.read().unwrap();
		let monitor = &monitors.get(&channel_id).unwrap().monitor;
		let counterparty_node_id = monitor.get_counterparty_node_id();
		let funding_txo = monitor.get_funding_txo();
		self.pending_monitor_events.lock().unwrap().push((
			funding_txo,
			channel_id,
			vec![MonitorEvent::Completed { funding_txo, channel_id, monitor_update_id }],
			counterparty_node_id,
		));
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
	pub async fn process_pending_events_async<
		Future: core::future::Future<Output = Result<(), ReplayEvent>>,
		H: Fn(Event) -> Future,
	>(
		&self, handler: H,
	) {
		// Sadly we can't hold the monitors read lock through an async call. Thus we have to do a
		// crazy dance to process a monitor's events then only remove them once we've done so.
		let mons_to_process = self.monitors.read().unwrap().keys().cloned().collect::<Vec<_>>();
		for channel_id in mons_to_process {
			let mut ev;
			match super::channelmonitor::process_events_body!(
				self.monitors.read().unwrap().get(&channel_id).map(|m| &m.monitor),
				self.logger,
				ev,
				handler(ev).await
			) {
				Ok(()) => {},
				Err(ReplayEvent()) => {
					self.event_notifier.notify();
				},
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
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			)
		}
	}

	/// Triggers rebroadcasts of pending claims from force-closed channels after a transaction
	/// signature generation failure.
	///
	/// `monitor_opt` can be used as a filter to only trigger them for a specific channel monitor.
	pub fn signer_unblocked(&self, monitor_opt: Option<ChannelId>) {
		let monitors = self.monitors.read().unwrap();
		if let Some(channel_id) = monitor_opt {
			if let Some(monitor_holder) = monitors.get(&channel_id) {
				monitor_holder.monitor.signer_unblocked(
					&*self.broadcaster,
					&*self.fee_estimator,
					&self.logger,
				)
			}
		} else {
			for (_, monitor_holder) in &*monitors {
				monitor_holder.monitor.signer_unblocked(
					&*self.broadcaster,
					&*self.fee_estimator,
					&self.logger,
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
	pub async fn archive_fully_resolved_channel_monitors(&self) {
		let mut have_monitors_to_prune = false;
		for monitor_holder in self.monitors.read().unwrap().values() {
			let logger = WithChannelMonitor::from(&self.logger, &monitor_holder.monitor, None);
			let (is_fully_resolved, needs_persistence) =
				monitor_holder.monitor.check_and_update_full_resolution_status(&logger);
			if is_fully_resolved {
				have_monitors_to_prune = true;
			}
			if needs_persistence {
				self.persister
					.update_persisted_channel(
						monitor_holder.monitor.persistence_key(),
						None,
						&monitor_holder.monitor,
					)
					.await;
			}
		}
		if have_monitors_to_prune {
			let mut monitors = self.monitors.write().unwrap();

			let mut to_remove = Vec::new();
			for (channel_id, monitor_holder) in monitors.iter() {
				let logger = WithChannelMonitor::from(&self.logger, &monitor_holder.monitor, None);
				let (is_fully_resolved, _) =
					monitor_holder.monitor.check_and_update_full_resolution_status(&logger);
				if is_fully_resolved {
					log_info!(
						logger,
						"Archiving fully resolved ChannelMonitor for channel ID {}",
						channel_id
					);
					self.persister
						.archive_persisted_channel(monitor_holder.monitor.persistence_key())
						.await;
					to_remove.push(channel_id.clone());
				}
			}

			for channel_id in to_remove {
				monitors.remove(&channel_id);
			}
		}
	}

	/// This function collects the counterparty node IDs from all monitors into a `HashSet`,
	/// ensuring unique IDs are returned.
	fn all_counterparty_node_ids(&self) -> HashSet<PublicKey> {
		let mon = self.monitors.read().unwrap();
		mon.values().map(|monitor| monitor.monitor.get_counterparty_node_id()).collect()
	}

	fn send_peer_storage(&self, their_node_id: PublicKey) {
		// TODO: Serialize `ChannelMonitor`s inside `our_peer_storage`.

		let random_bytes = self.entropy_source.get_secure_random_bytes();
		let serialised_channels = Vec::new();
		let our_peer_storage = DecryptedOurPeerStorage::new(serialised_channels);
		let cipher = our_peer_storage.encrypt(&self.our_peerstorage_encryption_key, &random_bytes);

		log_debug!(self.logger, "Sending Peer Storage to {}", log_pubkey!(their_node_id));
		let send_peer_storage_event = MessageSendEvent::SendPeerStorage {
			node_id: their_node_id,
			msg: msgs::PeerStorage { data: cipher.into_vec() },
		};

		self.pending_send_only_events.lock().unwrap().push(send_peer_storage_event)
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner + 'static,
		C: Deref,
		T: Deref,
		F: Deref,
		L: Deref,
		P: Deref,
		ES: Deref,
		FS: FutureSpawner,
	> BaseMessageHandler for ChainMonitor<ChannelSigner, C, T, F, L, P, ES, FS>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
	ES::Target: EntropySource,
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		let mut pending_events = self.pending_send_only_events.lock().unwrap();
		core::mem::take(&mut *pending_events)
	}

	fn peer_disconnected(&self, _their_node_id: PublicKey) {}

	fn provided_node_features(&self) -> NodeFeatures {
		NodeFeatures::empty()
	}

	fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
		InitFeatures::empty()
	}

	fn peer_connected(
		&self, _their_node_id: PublicKey, _msg: &Init, _inbound: bool,
	) -> Result<(), ()> {
		Ok(())
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner + 'static,
		C: Deref,
		T: Deref,
		F: Deref,
		L: Deref,
		P: Deref,
		ES: Deref,
		FS: FutureSpawner,
	> chain::Listen for ChainMonitor<ChannelSigner, C, T, F, L, P, ES, FS>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
	ES::Target: EntropySource,
{
	fn filtered_block_connected(&self, header: &Header, txdata: &TransactionData, height: u32) {
		log_debug!(
			self.logger,
			"New best block {} at height {} provided via block_connected",
			header.block_hash(),
			height
		);
		self.process_chain_data(header, Some(height), &txdata, |monitor, txdata| {
			monitor.block_connected(
				header,
				txdata,
				height,
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			)
		});

		// Send peer storage everytime a new block arrives.
		for node_id in self.all_counterparty_node_ids() {
			self.send_peer_storage(node_id);
		}

		// Assume we may have some new events and wake the event processor
		self.event_notifier.notify();
	}

	fn block_disconnected(&self, header: &Header, height: u32) {
		let monitor_states = self.monitors.read().unwrap();
		log_debug!(
			self.logger,
			"Latest block {} at height {} removed via block_disconnected",
			header.block_hash(),
			height
		);
		for monitor_state in monitor_states.values() {
			monitor_state.monitor.block_disconnected(
				header,
				height,
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			);
		}
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner + 'static,
		C: Deref,
		T: Deref,
		F: Deref,
		L: Deref,
		P: Deref,
		ES: Deref,
		FS: FutureSpawner,
	> chain::Confirm for ChainMonitor<ChannelSigner, C, T, F, L, P, ES, FS>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
	ES::Target: EntropySource,
{
	fn transactions_confirmed(&self, header: &Header, txdata: &TransactionData, height: u32) {
		log_debug!(
			self.logger,
			"{} provided transactions confirmed at height {} in block {}",
			txdata.len(),
			height,
			header.block_hash()
		);
		self.process_chain_data(header, None, txdata, |monitor, txdata| {
			monitor.transactions_confirmed(
				header,
				txdata,
				height,
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			)
		});
		// Assume we may have some new events and wake the event processor
		self.event_notifier.notify();
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		log_debug!(self.logger, "Transaction {} reorganized out of chain", txid);
		let monitor_states = self.monitors.read().unwrap();
		for monitor_state in monitor_states.values() {
			monitor_state.monitor.transaction_unconfirmed(
				txid,
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			);
		}
	}

	fn best_block_updated(&self, header: &Header, height: u32) {
		log_debug!(
			self.logger,
			"New best block {} at height {} provided via best_block_updated",
			header.block_hash(),
			height
		);
		self.process_chain_data(header, Some(height), &[], |monitor, txdata| {
			// While in practice there shouldn't be any recursive calls when given empty txdata,
			// it's still possible if a chain::Filter implementation returns a transaction.
			debug_assert!(txdata.is_empty());
			monitor.best_block_updated(
				header,
				height,
				&*self.broadcaster,
				&*self.fee_estimator,
				&self.logger,
			)
		});

		// Send peer storage everytime a new block arrives.
		for node_id in self.all_counterparty_node_ids() {
			self.send_peer_storage(node_id);
		}

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

impl<
		ChannelSigner: EcdsaChannelSigner + 'static,
		C: Deref,
		T: Deref,
		F: Deref,
		L: Deref,
		P: Deref,
		ES: Deref,
		FS: FutureSpawner + Clone,
	> chain::Watch<ChannelSigner> for ChainMonitor<ChannelSigner, C, T, F, L, P, ES, FS>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
	ES::Target: EntropySource,
{
	fn watch_channel(
		&self, channel_id: ChannelId, monitor: ChannelMonitor<ChannelSigner>,
	) -> Result<ChannelMonitorUpdateStatus, ()> {
		let logger = WithChannelMonitor::from(&self.logger, &monitor, None);
		let mut monitors = self.monitors.write().unwrap();
		let entry = match monitors.entry(channel_id) {
			hash_map::Entry::Occupied(_) => {
				log_error!(logger, "Failed to add new channel data: channel monitor for given channel ID is already present");
				return Err(());
			},
			hash_map::Entry::Vacant(e) => e,
		};
		log_trace!(logger, "Got new ChannelMonitor for channel {}", log_funding_info!(monitor));
		let update_id = monitor.get_latest_update_id();
		let mut pending_monitor_updates = Vec::new();
		let persist_res = self.persister.persist_new_channel(monitor.persistence_key(), &monitor);

		let update_status;
		let monitors = self.monitors.clone();
		let pending_monitor_updates_cb = self.pending_monitor_events.clone();
		let event_notifier = self.event_notifier.clone();
		let future_spawner = self.future_spawner.clone();

		match poll_or_spawn(
			persist_res,
			move || {
				// TODO: Log error if the monitor is not persisted.
				let _ = ChainMonitor::<ChannelSigner, C, T, F, L, P, ES, FS>::channel_monitor_updated_internal(&monitors, &pending_monitor_updates_cb, &event_notifier,
				channel_id, update_id);
			},
			future_spawner.deref(),
		) {
			Ok(true) => {
				log_info!(
					logger,
					"Persistence of new ChannelMonitor for channel {} completed",
					log_funding_info!(monitor)
				);
				update_status = ChannelMonitorUpdateStatus::Completed;
			},
			Ok(false) => {
				log_info!(
					logger,
					"Persistence of new ChannelMonitor for channel {} in progress",
					log_funding_info!(monitor)
				);
				pending_monitor_updates.push(update_id);
				update_status = ChannelMonitorUpdateStatus::InProgress;
			},
			Err(_) => {
				let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
				log_error!(logger, "{}", err_str);
				panic!("{}", err_str);
			},
		}
		if let Some(ref chain_source) = self.chain_source {
			monitor.load_outputs_to_watch(chain_source, &self.logger);
		}
		entry.insert(MonitorHolder {
			monitor,
			pending_monitor_updates: Mutex::new(pending_monitor_updates),
		});
		Ok(update_status)
	}

	fn update_channel(
		&self, channel_id: ChannelId, update: &ChannelMonitorUpdate,
	) -> ChannelMonitorUpdateStatus {
		// `ChannelMonitorUpdate`'s `channel_id` is `None` prior to 0.0.121 and all channels in those
		// versions are V1-established. For 0.0.121+ the `channel_id` fields is always `Some`.
		debug_assert_eq!(update.channel_id.unwrap(), channel_id);
		// Update the monitor that watches the channel referred to by the given outpoint.
		let monitors = self.monitors.read().unwrap();
		match monitors.get(&channel_id) {
			None => {
				let logger = WithContext::from(&self.logger, None, Some(channel_id), None);
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
				log_trace!(
					logger,
					"Updating ChannelMonitor to id {} for channel {}",
					update.update_id,
					log_funding_info!(monitor)
				);

				// We hold a `pending_monitor_updates` lock through `update_monitor` to ensure we
				// have well-ordered updates from the users' point of view. See the
				// `pending_monitor_updates` docs for more.
				let mut pending_monitor_updates =
					monitor_state.pending_monitor_updates.lock().unwrap();
				let update_res = monitor.update_monitor(
					update,
					&self.broadcaster,
					&self.fee_estimator,
					&self.logger,
				);

				let update_id = update.update_id;
				let persist_res = if update_res.is_err() {
					// Even if updating the monitor returns an error, the monitor's state will
					// still be changed. Therefore, we should persist the updated monitor despite the error.
					// We don't want to persist a `monitor_update` which results in a failure to apply later
					// while reading `channel_monitor` with updates from storage. Instead, we should persist
					// the entire `channel_monitor` here.
					log_warn!(logger, "Failed to update ChannelMonitor for channel {}. Going ahead and persisting the entire ChannelMonitor", log_funding_info!(monitor));
					self.persister.update_persisted_channel(
						monitor.persistence_key(),
						None,
						monitor,
					)
				} else {
					self.persister.update_persisted_channel(
						monitor.persistence_key(),
						Some(update),
						monitor,
					)
				};

				let monitors = self.monitors.clone();
				let pending_monitor_updates_cb = self.pending_monitor_events.clone();
				let event_notifier = self.event_notifier.clone();
				let future_spawner = self.future_spawner.clone();

				let update_status;
				match poll_or_spawn(
					persist_res,
					move || {
						// TODO: Log error if the monitor is not persisted.
						let _ = ChainMonitor::<ChannelSigner, C, T, F, L, P, ES, FS>::channel_monitor_updated_internal(&monitors, &pending_monitor_updates_cb, &event_notifier,
						channel_id, update_id);
					},
					future_spawner.deref(),
				) {
					Ok(true) => {
						log_debug!(
							logger,
							"Persistence of ChannelMonitorUpdate id {:?} for channel {} completed",
							update_id,
							log_funding_info!(monitor)
						);
						update_status = ChannelMonitorUpdateStatus::Completed;
					},
					Ok(false) => {
						log_debug!(logger,
							"Persistence of ChannelMonitorUpdate id {:?} for channel {} in progress",
							update_id,
							log_funding_info!(monitor)
						);
						pending_monitor_updates.push(update_id);
						update_status = ChannelMonitorUpdateStatus::InProgress;
					},
					Err(_) => {
						// Take the monitors lock for writing so that we poison it and any future
						// operations going forward fail immediately.
						core::mem::drop(pending_monitor_updates);
						// core::mem::drop(monitors);
						let _poison = self.monitors.write().unwrap();
						let err_str = "ChannelMonitor[Update] persistence failed unrecoverably. This indicates we cannot continue normal operation and must shut down.";
						log_error!(logger, "{}", err_str);
						panic!("{}", err_str);
					},
				}
				if update_res.is_err() {
					ChannelMonitorUpdateStatus::InProgress
				} else {
					update_status
				}
			},
		}
	}

	fn release_pending_monitor_events(
		&self,
	) -> Vec<(OutPoint, ChannelId, Vec<MonitorEvent>, PublicKey)> {
		let mut pending_monitor_events = self.pending_monitor_events.lock().unwrap().split_off(0);
		for monitor_state in self.monitors.read().unwrap().values() {
			let monitor_events = monitor_state.monitor.get_and_clear_pending_monitor_events();
			if monitor_events.len() > 0 {
				let monitor_funding_txo = monitor_state.monitor.get_funding_txo();
				let monitor_channel_id = monitor_state.monitor.channel_id();
				let counterparty_node_id = monitor_state.monitor.get_counterparty_node_id();
				pending_monitor_events.push((
					monitor_funding_txo,
					monitor_channel_id,
					monitor_events,
					counterparty_node_id,
				));
			}
		}
		pending_monitor_events
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		C: Deref,
		T: Deref,
		F: Deref,
		L: Deref,
		P: Deref,
		ES: Deref,
		FS: FutureSpawner,
	> events::EventsProvider for ChainMonitor<ChannelSigner, C, T, F, L, P, ES, FS>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
	ES::Target: EntropySource,
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
	fn process_pending_events<H: Deref>(&self, handler: H)
	where
		H::Target: EventHandler,
	{
		for monitor_state in self.monitors.read().unwrap().values() {
			match monitor_state.monitor.process_pending_events(&handler, &self.logger) {
				Ok(()) => {},
				Err(ReplayEvent()) => {
					self.event_notifier.notify();
				},
			}
		}
	}
}

/// A synchronous version of [`Persist`].
pub trait PersistSync<ChannelSigner: EcdsaChannelSigner> {
	/// A synchronous version of [`Persist::persist_new_channel`].
	fn persist_new_channel(
		&self, monitor_name: MonitorName, monitor: &ChannelMonitor<ChannelSigner>,
	) -> Result<(), ()>;

	/// A synchronous version of [`Persist::update_persisted_channel`].
	fn update_persisted_channel(
		&self, monitor_name: MonitorName, monitor_update: Option<&ChannelMonitorUpdate>,
		monitor: &ChannelMonitor<ChannelSigner>,
	) -> Result<(), ()>;

	/// A synchronous version of [`Persist::archive_persisted_channel`].
	fn archive_persisted_channel(&self, monitor_name: MonitorName);
}

struct PersistSyncWrapper<P: Deref>(P);

impl<T: Deref> Deref for PersistSyncWrapper<T> {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}

impl<ChannelSigner: EcdsaChannelSigner, P: Deref> Persist<ChannelSigner> for PersistSyncWrapper<P>
where
	P::Target: PersistSync<ChannelSigner>,
{
	fn persist_new_channel(
		&self, monitor_name: MonitorName, monitor: &ChannelMonitor<ChannelSigner>,
	) -> AsyncResult<'static, ()> {
		let res = self.0.persist_new_channel(monitor_name, monitor);

		Box::pin(async move { res })
	}

	fn update_persisted_channel(
		&self, monitor_name: MonitorName, monitor_update: Option<&ChannelMonitorUpdate>,
		monitor: &ChannelMonitor<ChannelSigner>,
	) -> AsyncResult<'static, ()> {
		let res = self.0.update_persisted_channel(monitor_name, monitor_update, monitor);
		Box::pin(async move { res })
	}

	fn archive_persisted_channel(&self, monitor_name: MonitorName) -> AsyncVoid {
		self.0.archive_persisted_channel(monitor_name);

		Box::pin(async move {})
	}
}

#[cfg(test)]
mod tests {
	use crate::chain::channelmonitor::ANTI_REORG_DELAY;
	use crate::chain::{ChannelMonitorUpdateStatus, Watch};
	use crate::events::{ClosureReason, Event};
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
	use crate::{check_added_monitors, check_closed_event};
	use crate::{expect_payment_path_successful, get_event_msg};
	use crate::{get_htlc_update_msgs, get_revoke_commit_msgs};

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
		let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

		// Route two payments to be claimed at the same time.
		let (payment_preimage_1, payment_hash_1, ..) =
			route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		let (payment_preimage_2, payment_hash_2, ..) =
			route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

		chanmon_cfgs[1].persister.offchain_monitor_updates.lock().unwrap().clear();
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

		nodes[1].node.claim_funds(payment_preimage_1);
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.claim_funds(payment_preimage_2);
		check_added_monitors!(nodes[1], 1);

		let persistences =
			chanmon_cfgs[1].persister.offchain_monitor_updates.lock().unwrap().clone();
		assert_eq!(persistences.len(), 1);
		let (_, updates) = persistences.iter().next().unwrap();
		assert_eq!(updates.len(), 2);

		// Note that updates is a HashMap so the ordering here is actually random. This shouldn't
		// fail either way but if it fails intermittently it's depending on the ordering of updates.
		let mut update_iter = updates.iter();
		let next_update = update_iter.next().unwrap().clone();
		// Should contain next_update when pending updates listed.
		#[cfg(not(c_bindings))]
		assert!(nodes[1]
			.chain_monitor
			.chain_monitor
			.list_pending_monitor_updates()
			.get(&channel_id)
			.unwrap()
			.contains(&next_update));
		#[cfg(c_bindings)]
		assert!(nodes[1]
			.chain_monitor
			.chain_monitor
			.list_pending_monitor_updates()
			.iter()
			.find(|(chan_id, _)| *chan_id == channel_id)
			.unwrap()
			.1
			.contains(&next_update));
		nodes[1]
			.chain_monitor
			.chain_monitor
			.channel_monitor_updated(channel_id, next_update.clone())
			.unwrap();
		// Should not contain the previously pending next_update when pending updates listed.
		#[cfg(not(c_bindings))]
		assert!(!nodes[1]
			.chain_monitor
			.chain_monitor
			.list_pending_monitor_updates()
			.get(&channel_id)
			.unwrap()
			.contains(&next_update));
		#[cfg(c_bindings)]
		assert!(!nodes[1]
			.chain_monitor
			.chain_monitor
			.list_pending_monitor_updates()
			.iter()
			.find(|(chan_id, _)| *chan_id == channel_id)
			.unwrap()
			.1
			.contains(&next_update));
		assert!(nodes[1].chain_monitor.release_pending_monitor_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
		nodes[1]
			.chain_monitor
			.chain_monitor
			.channel_monitor_updated(channel_id, update_iter.next().unwrap().clone())
			.unwrap();

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
		nodes[0].node.handle_update_fulfill_htlc(
			nodes[1].node.get_our_node_id(),
			&updates.update_fulfill_htlcs[0],
		);
		expect_payment_sent(&nodes[0], payment_preimage_1, None, false, false);
		nodes[0].node.handle_commitment_signed_batch_test(
			nodes[1].node.get_our_node_id(),
			&updates.commitment_signed,
		);
		check_added_monitors!(nodes[0], 1);
		let (as_first_raa, as_first_update) =
			get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(nodes[0].node.get_our_node_id(), &as_first_raa);
		check_added_monitors!(nodes[1], 1);
		let bs_second_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[1]
			.node
			.handle_commitment_signed_batch_test(nodes[0].node.get_our_node_id(), &as_first_update);
		check_added_monitors!(nodes[1], 1);
		let bs_first_raa = get_event_msg!(
			nodes[1],
			MessageSendEvent::SendRevokeAndACK,
			nodes[0].node.get_our_node_id()
		);

		nodes[0].node.handle_update_fulfill_htlc(
			nodes[1].node.get_our_node_id(),
			&bs_second_updates.update_fulfill_htlcs[0],
		);
		expect_payment_sent(&nodes[0], payment_preimage_2, None, false, false);
		nodes[0].node.handle_commitment_signed_batch_test(
			nodes[1].node.get_our_node_id(),
			&bs_second_updates.commitment_signed,
		);
		check_added_monitors!(nodes[0], 1);
		nodes[0].node.handle_revoke_and_ack(nodes[1].node.get_our_node_id(), &bs_first_raa);
		expect_payment_path_successful!(nodes[0]);
		check_added_monitors!(nodes[0], 1);
		let (as_second_raa, as_second_update) =
			get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

		nodes[1].node.handle_revoke_and_ack(nodes[0].node.get_our_node_id(), &as_second_raa);
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.handle_commitment_signed_batch_test(
			nodes[0].node.get_our_node_id(),
			&as_second_update,
		);
		check_added_monitors!(nodes[1], 1);
		let bs_second_raa = get_event_msg!(
			nodes[1],
			MessageSendEvent::SendRevokeAndACK,
			nodes[0].node.get_our_node_id()
		);

		nodes[0].node.handle_revoke_and_ack(nodes[1].node.get_our_node_id(), &bs_second_raa);
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
		let channel_2 =
			create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0).2;

		chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().clear();
		chanmon_cfgs[1].persister.chain_sync_monitor_persistences.lock().unwrap().clear();
		chanmon_cfgs[2].persister.chain_sync_monitor_persistences.lock().unwrap().clear();

		connect_blocks(&nodes[0], CHAINSYNC_MONITOR_PARTITION_FACTOR * 2);
		connect_blocks(&nodes[1], CHAINSYNC_MONITOR_PARTITION_FACTOR * 2);
		connect_blocks(&nodes[2], CHAINSYNC_MONITOR_PARTITION_FACTOR * 2);

		// Connecting [`DEFAULT_CHAINSYNC_PARTITION_FACTOR`] * 2 blocks should trigger only 2 writes
		// per monitor/channel.
		assert_eq!(
			2 * 2,
			chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().len()
		);
		assert_eq!(
			2,
			chanmon_cfgs[1].persister.chain_sync_monitor_persistences.lock().unwrap().len()
		);
		assert_eq!(
			2,
			chanmon_cfgs[2].persister.chain_sync_monitor_persistences.lock().unwrap().len()
		);

		// Test that monitors with pending_claims are persisted on every block.
		// Now, close channel_2 i.e. b/w node-0 and node-2 to create pending_claim in node[0].
		nodes[0]
			.node
			.force_close_broadcasting_latest_txn(
				&channel_2,
				&nodes[2].node.get_our_node_id(),
				"Channel force-closed".to_string(),
			)
			.unwrap();
		check_closed_event!(
			&nodes[0],
			1,
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) },
			false,
			[nodes[2].node.get_our_node_id()],
			1000000
		);
		check_closed_broadcast(&nodes[0], 1, true);
		let close_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(close_tx.len(), 1);

		mine_transaction(&nodes[2], &close_tx[0]);
		check_added_monitors(&nodes[2], 1);
		check_closed_broadcast(&nodes[2], 1, true);
		check_closed_event!(
			&nodes[2],
			1,
			ClosureReason::CommitmentTxConfirmed,
			false,
			[nodes[0].node.get_our_node_id()],
			1000000
		);

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
		assert_eq!(
			(CHAINSYNC_MONITOR_PARTITION_FACTOR + 1) as usize,
			chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().len()
		);
		// For node[2], there is no pending_claim
		assert_eq!(
			1,
			chanmon_cfgs[2].persister.chain_sync_monitor_persistences.lock().unwrap().len()
		);

		// Confirm claim for node[0] with ANTI_REORG_DELAY and reset monitor write counter.
		mine_transaction(&nodes[0], &close_tx[0]);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		check_added_monitors(&nodes[0], 1);
		chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().clear();

		// Again connect 1 full cycle of DEFAULT_CHAINSYNC_MONITOR_PARTITION_FACTOR blocks, it should only
		// result in 1 write per monitor/channel.
		connect_blocks(&nodes[0], CHAINSYNC_MONITOR_PARTITION_FACTOR);
		assert_eq!(
			2,
			chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().len()
		);
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
		})
		.is_err());
		assert!(std::panic::catch_unwind(|| {
			// ...and also poison our locks causing later use to panic as well
			core::mem::drop(nodes);
		})
		.is_err());
	}
}
