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
use chain::{Filter, WatchedOutput};
use chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use chain::channelmonitor;
use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr, MonitorEvent, Persist, TransactionOutputs};
use chain::transaction::{OutPoint, TransactionData};
use chain::keysinterface::Sign;
use util::logger::Logger;
use util::events;
use util::events::Event;

use std::collections::{HashMap, hash_map};
use std::sync::RwLock;
use core::ops::Deref;

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
        P::Target: channelmonitor::Persist<ChannelSigner>,
{
	/// The monitors
	pub monitors: RwLock<HashMap<OutPoint, ChannelMonitor<ChannelSigner>>>,
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
	    P::Target: channelmonitor::Persist<ChannelSigner>,
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
		let monitors = self.monitors.read().unwrap();
		for monitor in monitors.values() {
			let mut txn_outputs = process(monitor, txdata);

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
}

impl<ChannelSigner: Sign, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref>
chain::Listen for ChainMonitor<ChannelSigner, C, T, F, L, P>
where
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: channelmonitor::Persist<ChannelSigner>,
{
	fn block_connected(&self, block: &Block, height: u32) {
		let header = &block.header;
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		self.process_chain_data(header, &txdata, |monitor, txdata| {
			monitor.block_connected(
				header, txdata, height, &*self.broadcaster, &*self.fee_estimator, &*self.logger)
		});
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		let monitors = self.monitors.read().unwrap();
		for monitor in monitors.values() {
			monitor.block_disconnected(
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
	P::Target: channelmonitor::Persist<ChannelSigner>,
{
	fn transactions_confirmed(&self, header: &BlockHeader, txdata: &TransactionData, height: u32) {
		self.process_chain_data(header, txdata, |monitor, txdata| {
			monitor.transactions_confirmed(
				header, txdata, height, &*self.broadcaster, &*self.fee_estimator, &*self.logger)
		});
	}

	fn transaction_unconfirmed(&self, txid: &Txid) {
		let monitors = self.monitors.read().unwrap();
		for monitor in monitors.values() {
			monitor.transaction_unconfirmed(txid, &*self.broadcaster, &*self.fee_estimator, &*self.logger);
		}
	}

	fn best_block_updated(&self, header: &BlockHeader, height: u32) {
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
		let monitors = self.monitors.read().unwrap();
		for monitor in monitors.values() {
			txids.append(&mut monitor.get_relevant_txids());
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
	    P::Target: channelmonitor::Persist<ChannelSigner>,
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
		entry.insert(monitor);
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
			Some(monitor) => {
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
		for monitor in self.monitors.read().unwrap().values() {
			pending_monitor_events.append(&mut monitor.get_and_clear_pending_monitor_events());
		}
		pending_monitor_events
	}
}

impl<ChannelSigner: Sign, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref> events::EventsProvider for ChainMonitor<ChannelSigner, C, T, F, L, P>
	where C::Target: chain::Filter,
	      T::Target: BroadcasterInterface,
	      F::Target: FeeEstimator,
	      L::Target: Logger,
	      P::Target: channelmonitor::Persist<ChannelSigner>,
{
	fn get_and_clear_pending_events(&self) -> Vec<Event> {
		let mut pending_events = Vec::new();
		for monitor in self.monitors.read().unwrap().values() {
			pending_events.append(&mut monitor.get_and_clear_pending_events());
		}
		pending_events
	}
}

#[cfg(test)]
mod tests {
	use ::{check_added_monitors, get_local_commitment_txn};
	use ln::features::InitFeatures;
	use ln::functional_test_utils::*;
	use util::events::EventsProvider;
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
