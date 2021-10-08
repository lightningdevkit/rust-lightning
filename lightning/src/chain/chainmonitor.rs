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

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::hash_types::Txid;

use chain;
use chain::{ChannelMonitorUpdateErr, Filter, WatchedOutput};
use chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, Balance, MonitorEvent, TransactionOutputs};
use chain::transaction::{OutPoint, TransactionData};
use chain::keysinterface::Sign;
use util::logger::Logger;
use util::events;
use util::events::EventHandler;
use ln::channelmanager::ChannelDetails;

use prelude::*;
use sync::{RwLock, RwLockReadGuard};
use core::ops::Deref;

/// `Persist` defines behavior for persisting channel monitors: this could mean
/// writing once to disk, and/or uploading to one or more backup services.
///
/// Note that for every new monitor, you **must** persist the new `ChannelMonitor`
/// to disk/backups. And, on every update, you **must** persist either the
/// `ChannelMonitorUpdate` or the updated monitor itself. Otherwise, there is risk
/// of situations such as revoking a transaction, then crashing before this
/// revocation can be persisted, then unintentionally broadcasting a revoked
/// transaction and losing money. This is a risk because previous channel states
/// are toxic, so it's important that whatever channel state is persisted is
/// kept up-to-date.
pub trait Persist<ChannelSigner: Sign> {
	/// Persist a new channel's data. The data can be stored any way you want, but
	/// the identifier provided by Rust-Lightning is the channel's outpoint (and
	/// it is up to you to maintain a correct mapping between the outpoint and the
	/// stored channel data). Note that you **must** persist every new monitor to
	/// disk. See the `Persist` trait documentation for more details.
	///
	/// See [`Writeable::write`] on [`ChannelMonitor`] for writing out a `ChannelMonitor`
	/// and [`ChannelMonitorUpdateErr`] for requirements when returning errors.
	///
	/// [`Writeable::write`]: crate::util::ser::Writeable::write
	fn persist_new_channel(&self, id: OutPoint, data: &ChannelMonitor<ChannelSigner>) -> Result<(), ChannelMonitorUpdateErr>;

	/// Update one channel's data. The provided `ChannelMonitor` has already
	/// applied the given update.
	///
	/// Note that on every update, you **must** persist either the
	/// `ChannelMonitorUpdate` or the updated monitor itself to disk/backups. See
	/// the `Persist` trait documentation for more details.
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
	/// See [`Writeable::write`] on [`ChannelMonitor`] for writing out a `ChannelMonitor`,
	/// [`Writeable::write`] on [`ChannelMonitorUpdate`] for writing out an update, and
	/// [`ChannelMonitorUpdateErr`] for requirements when returning errors.
	///
	/// [`Writeable::write`]: crate::util::ser::Writeable::write
	fn update_persisted_channel(&self, id: OutPoint, update: &ChannelMonitorUpdate, data: &ChannelMonitor<ChannelSigner>) -> Result<(), ChannelMonitorUpdateErr>;
}

struct MonitorHolder<ChannelSigner: Sign> {
	monitor: ChannelMonitor<ChannelSigner>,
}

/// A read-only reference to a current ChannelMonitor.
///
/// Note that this holds a mutex in [`ChainMonitor`] and may block other events until it is
/// released.
pub struct LockedChannelMonitor<'a, ChannelSigner: Sign> {
	lock: RwLockReadGuard<'a, HashMap<OutPoint, MonitorHolder<ChannelSigner>>>,
	funding_txo: OutPoint,
}

impl<ChannelSigner: Sign> Deref for LockedChannelMonitor<'_, ChannelSigner> {
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
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [module-level documentation]: crate::chain::chainmonitor
pub struct ChainMonitor<ChannelSigner: Sign, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref>
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
}

impl<ChannelSigner: Sign, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref> ChainMonitor<ChannelSigner, C, T, F, L, P>
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
	fn process_chain_data<FN>(&self, header: &BlockHeader, txdata: &TransactionData, process: FN)
	where
		FN: Fn(&ChannelMonitor<ChannelSigner>, &TransactionData) -> Vec<TransactionOutputs>
	{
		let mut dependent_txdata = Vec::new();
		let monitor_states = self.monitors.read().unwrap();
		for monitor_state in monitor_states.values() {
			let mut txn_outputs = process(&monitor_state.monitor, txdata);

			// Register any new outputs with the chain source for filtering, storing any dependent
			// transactions from within the block that previously had not been included in txdata.
			if let Some(ref chain_source) = self.chain_source {
				let block_hash = header.block_hash();
				for (txid, mut outputs) in txn_outputs.drain(..) {
					for (idx, output) in outputs.drain(..) {
						// Register any new outputs with the chain source for filtering and recurse
						// if it indicates that there are dependent transactions within the block
						// that had not been previously included in txdata.
						let output = WatchedOutput {
							block_hash: Some(block_hash),
							outpoint: OutPoint { txid, index: idx as u16 },
							script_pubkey: output.script_pubkey,
						};
						if let Some(tx) = chain_source.register_output(output) {
							dependent_txdata.push(tx);
						}
					}
				}
			}
		}

		// Recursively call for any dependent transactions that were identified by the chain source.
		if !dependent_txdata.is_empty() {
			dependent_txdata.sort_unstable_by_key(|(index, _tx)| *index);
			dependent_txdata.dedup_by_key(|(index, _tx)| *index);
			let txdata: Vec<_> = dependent_txdata.iter().map(|(index, tx)| (*index, tx)).collect();
			self.process_chain_data(header, &txdata, process);
		}
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
			monitors: RwLock::new(HashMap::new()),
			chain_source,
			broadcaster,
			logger,
			fee_estimator: feeest,
			persister,
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

	/// Lists the funding outpoint of each [`ChannelMonitor`] being monitored.
	///
	/// Note that [`ChannelMonitor`]s are not removed when a channel is closed as they are always
	/// monitoring for on-chain state resolutions.
	pub fn list_monitors(&self) -> Vec<OutPoint> {
		self.monitors.read().unwrap().keys().map(|outpoint| *outpoint).collect()
	}

	#[cfg(test)]
	pub fn remove_monitor(&self, funding_txo: &OutPoint) -> ChannelMonitor<ChannelSigner> {
		self.monitors.write().unwrap().remove(funding_txo).unwrap().monitor
	}

	#[cfg(any(test, feature = "fuzztarget", feature = "_test_utils"))]
	pub fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
		use util::events::EventsProvider;
		let events = core::cell::RefCell::new(Vec::new());
		let event_handler = |event: &events::Event| events.borrow_mut().push(event.clone());
		self.process_pending_events(&event_handler);
		events.into_inner()
	}
}

impl<ChannelSigner: Sign, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref>
chain::Listen for ChainMonitor<ChannelSigner, C, T, F, L, P>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
{
	fn block_connected(&self, block: &Block, height: u32) {
		let header = &block.header;
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		log_debug!(self.logger, "New best block {} at height {} provided via block_connected", header.block_hash(), height);
		self.process_chain_data(header, &txdata, |monitor, txdata| {
			monitor.block_connected(
				header, txdata, height, &*self.broadcaster, &*self.fee_estimator, &*self.logger)
		});
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		let monitor_states = self.monitors.read().unwrap();
		log_debug!(self.logger, "Latest block {} at height {} removed via block_disconnected", header.block_hash(), height);
		for monitor_state in monitor_states.values() {
			monitor_state.monitor.block_disconnected(
				header, height, &*self.broadcaster, &*self.fee_estimator, &*self.logger);
		}
	}
}

impl<ChannelSigner: Sign, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref>
chain::Confirm for ChainMonitor<ChannelSigner, C, T, F, L, P>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: Persist<ChannelSigner>,
{
	fn transactions_confirmed(&self, header: &BlockHeader, txdata: &TransactionData, height: u32) {
		log_debug!(self.logger, "{} provided transactions confirmed at height {} in block {}", txdata.len(), height, header.block_hash());
		self.process_chain_data(header, txdata, |monitor, txdata| {
			monitor.transactions_confirmed(
				header, txdata, height, &*self.broadcaster, &*self.fee_estimator, &*self.logger)
		});
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		log_debug!(self.logger, "Transaction {} reorganized out of chain", txid);
		let monitor_states = self.monitors.read().unwrap();
		for monitor_state in monitor_states.values() {
			monitor_state.monitor.transaction_unconfirmed(txid, &*self.broadcaster, &*self.fee_estimator, &*self.logger);
		}
	}

	fn best_block_updated(&self, header: &BlockHeader, height: u32) {
		log_debug!(self.logger, "New best block {} at height {} provided via best_block_updated", header.block_hash(), height);
		self.process_chain_data(header, &[], |monitor, txdata| {
			// While in practice there shouldn't be any recursive calls when given empty txdata,
			// it's still possible if a chain::Filter implementation returns a transaction.
			debug_assert!(txdata.is_empty());
			monitor.best_block_updated(
				header, height, &*self.broadcaster, &*self.fee_estimator, &*self.logger)
		});
	}

	fn get_relevant_txids(&self) -> Vec<Txid> {
		let mut txids = Vec::new();
		let monitor_states = self.monitors.read().unwrap();
		for monitor_state in monitor_states.values() {
			txids.append(&mut monitor_state.monitor.get_relevant_txids());
		}

		txids.sort_unstable();
		txids.dedup();
		txids
	}
}

impl<ChannelSigner: Sign, C: Deref , T: Deref , F: Deref , L: Deref , P: Deref >
chain::Watch<ChannelSigner> for ChainMonitor<ChannelSigner, C, T, F, L, P>
where C::Target: chain::Filter,
	    T::Target: BroadcasterInterface,
	    F::Target: FeeEstimator,
	    L::Target: Logger,
	    P::Target: Persist<ChannelSigner>,
{
	/// Adds the monitor that watches the channel referred to by the given outpoint.
	///
	/// Calls back to [`chain::Filter`] with the funding transaction and outputs to watch.
	///
	/// Note that we persist the given `ChannelMonitor` while holding the `ChainMonitor`
	/// monitors lock.
	fn watch_channel(&self, funding_outpoint: OutPoint, monitor: ChannelMonitor<ChannelSigner>) -> Result<(), ChannelMonitorUpdateErr> {
		let mut monitors = self.monitors.write().unwrap();
		let entry = match monitors.entry(funding_outpoint) {
			hash_map::Entry::Occupied(_) => {
				log_error!(self.logger, "Failed to add new channel data: channel monitor for given outpoint is already present");
				return Err(ChannelMonitorUpdateErr::PermanentFailure)},
			hash_map::Entry::Vacant(e) => e,
		};
		if let Err(e) = self.persister.persist_new_channel(funding_outpoint, &monitor) {
			log_error!(self.logger, "Failed to persist new channel data");
			return Err(e);
		}
		{
			let funding_txo = monitor.get_funding_txo();
			log_trace!(self.logger, "Got new Channel Monitor for channel {}", log_bytes!(funding_txo.0.to_channel_id()[..]));

			if let Some(ref chain_source) = self.chain_source {
				monitor.load_outputs_to_watch(chain_source);
			}
		}
		entry.insert(MonitorHolder { monitor });
		Ok(())
	}

	/// Note that we persist the given `ChannelMonitor` update while holding the
	/// `ChainMonitor` monitors lock.
	fn update_channel(&self, funding_txo: OutPoint, update: ChannelMonitorUpdate) -> Result<(), ChannelMonitorUpdateErr> {
		// Update the monitor that watches the channel referred to by the given outpoint.
		let monitors = self.monitors.read().unwrap();
		match monitors.get(&funding_txo) {
			None => {
				log_error!(self.logger, "Failed to update channel monitor: no such monitor registered");

				// We should never ever trigger this from within ChannelManager. Technically a
				// user could use this object with some proxying in between which makes this
				// possible, but in tests and fuzzing, this should be a panic.
				#[cfg(any(test, feature = "fuzztarget"))]
				panic!("ChannelManager generated a channel update for a channel that was not yet registered!");
				#[cfg(not(any(test, feature = "fuzztarget")))]
				Err(ChannelMonitorUpdateErr::PermanentFailure)
			},
			Some(monitor_state) => {
				let monitor = &monitor_state.monitor;
				log_trace!(self.logger, "Updating Channel Monitor for channel {}", log_funding_info!(monitor));
				let update_res = monitor.update_monitor(&update, &self.broadcaster, &self.fee_estimator, &self.logger);
				if let Err(e) = &update_res {
					log_error!(self.logger, "Failed to update channel monitor: {:?}", e);
				}
				// Even if updating the monitor returns an error, the monitor's state will
				// still be changed. So, persist the updated monitor despite the error.
				let persist_res = self.persister.update_persisted_channel(funding_txo, &update, monitor);
				if let Err(ref e) = persist_res {
					log_error!(self.logger, "Failed to persist channel monitor update: {:?}", e);
				}
				if update_res.is_err() {
					Err(ChannelMonitorUpdateErr::PermanentFailure)
				} else {
					persist_res
				}
			}
		}
	}

	fn release_pending_monitor_events(&self) -> Vec<MonitorEvent> {
		let mut pending_monitor_events = Vec::new();
		for monitor_state in self.monitors.read().unwrap().values() {
			pending_monitor_events.append(&mut monitor_state.monitor.get_and_clear_pending_monitor_events());
		}
		pending_monitor_events
	}
}

impl<ChannelSigner: Sign, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref> events::EventsProvider for ChainMonitor<ChannelSigner, C, T, F, L, P>
	where C::Target: chain::Filter,
	      T::Target: BroadcasterInterface,
	      F::Target: FeeEstimator,
	      L::Target: Logger,
	      P::Target: Persist<ChannelSigner>,
{
	/// Processes [`SpendableOutputs`] events produced from each [`ChannelMonitor`] upon maturity.
	///
	/// An [`EventHandler`] may safely call back to the provider, though this shouldn't be needed in
	/// order to handle these events.
	///
	/// [`SpendableOutputs`]: events::Event::SpendableOutputs
	fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler {
		let mut pending_events = Vec::new();
		for monitor_state in self.monitors.read().unwrap().values() {
			pending_events.append(&mut monitor_state.monitor.get_and_clear_pending_events());
		}
		for event in pending_events.drain(..) {
			handler.handle_event(&event);
		}
	}
}

#[cfg(test)]
mod tests {
	use ::{check_added_monitors, get_local_commitment_txn};
	use ln::features::InitFeatures;
	use ln::functional_test_utils::*;
	use util::events::MessageSendEventsProvider;
	use util::test_utils::{OnRegisterOutput, TxOutReference};

	/// Tests that in-block dependent transactions are processed by `block_connected` when not
	/// included in `txdata` but returned by [`chain::Filter::register_output`]. For instance,
	/// a (non-anchor) commitment transaction's HTLC output may be spent in the same block as the
	/// commitment transaction itself. An Electrum client may filter the commitment transaction but
	/// needs to return the HTLC transaction so it can be processed.
	#[test]
	fn connect_block_checks_dependent_transactions() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let channel = create_announced_chan_between_nodes(
			&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

		// Send a payment, saving nodes[0]'s revoked commitment and HTLC-Timeout transactions.
		let (commitment_tx, htlc_tx) = {
			let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 5_000_000).0;
			let mut txn = get_local_commitment_txn!(nodes[0], channel.2);
			claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage);

			assert_eq!(txn.len(), 2);
			(txn.remove(0), txn.remove(0))
		};

		// Set expectations on nodes[1]'s chain source to return dependent transactions.
		let htlc_output = TxOutReference(commitment_tx.clone(), 0);
		let to_local_output = TxOutReference(commitment_tx.clone(), 1);
		let htlc_timeout_output = TxOutReference(htlc_tx.clone(), 0);
		nodes[1].chain_source
			.expect(OnRegisterOutput { with: htlc_output, returns: Some((1, htlc_tx)) })
			.expect(OnRegisterOutput { with: to_local_output, returns: None })
			.expect(OnRegisterOutput { with: htlc_timeout_output, returns: None });

		// Notify nodes[1] that nodes[0]'s revoked commitment transaction was mined. The chain
		// source should return the dependent HTLC transaction when the HTLC output is registered.
		mine_transaction(&nodes[1], &commitment_tx);

		// Clean up so uninteresting assertions don't fail.
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.get_and_clear_pending_msg_events();
		nodes[1].node.get_and_clear_pending_events();
	}
}
