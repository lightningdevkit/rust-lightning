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
//! `ChainMonitor` is parameterized by an optional chain source, which must implement the
//! [`chain::Filter`] trait. This provides a mechanism to signal new relevant outputs back to light
//! clients, such that transactions spending those outputs are included in block data.
//!
//! `ChainMonitor` may be used directly to monitor channels locally or as a part of a distributed
//! setup to monitor channels remotely. In the latter case, a custom `chain::Watch` implementation
//! would be responsible for routing each update to a remote server and for retrieving monitor
//! events. The remote server would make use of `ChainMonitor` for block processing and for
//! servicing `ChannelMonitor` updates from the client.
//!
//! [`ChainMonitor`]: struct.ChainMonitor.html
//! [`chain::Filter`]: ../trait.Filter.html
//! [`chain::Watch`]: ../trait.Watch.html
//! [`ChannelMonitor`]: ../channelmonitor/struct.ChannelMonitor.html
//! [`MonitorEvent`]: ../channelmonitor/enum.MonitorEvent.html

use bitcoin::blockdata::block::{Block, BlockHeader};

use chain;
use chain::Filter;
use chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use chain::channelmonitor;
use chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr, MonitorEvent, Persist};
use chain::transaction::{OutPoint, TransactionData};
use chain::keysinterface::Sign;
use util::logger::Logger;
use util::events;
use util::events::Event;

use std::collections::{HashMap, hash_map};
use std::sync::Mutex;
use std::ops::Deref;

/// An implementation of [`chain::Watch`] for monitoring channels.
///
/// Connected and disconnected blocks must be provided to `ChainMonitor` as documented by
/// [`chain::Watch`]. May be used in conjunction with [`ChannelManager`] to monitor channels locally
/// or used independently to monitor channels remotely. See the [module-level documentation] for
/// details.
///
/// [`chain::Watch`]: ../trait.Watch.html
/// [`ChannelManager`]: ../../ln/channelmanager/struct.ChannelManager.html
/// [module-level documentation]: index.html
pub struct ChainMonitor<ChannelSigner: Sign, C: Deref, T: Deref, F: Deref, L: Deref, P: Deref>
	where C::Target: chain::Filter,
        T::Target: BroadcasterInterface,
        F::Target: FeeEstimator,
        L::Target: Logger,
        P::Target: channelmonitor::Persist<ChannelSigner>,
{
	/// The monitors
	pub monitors: Mutex<HashMap<OutPoint, ChannelMonitor<ChannelSigner>>>,
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
	/// of a channel and reacting accordingly based on transactions in the connected block. See
	/// [`ChannelMonitor::block_connected`] for details. Any HTLCs that were resolved on chain will
	/// be returned by [`chain::Watch::release_pending_monitor_events`].
	///
	/// Calls back to [`chain::Filter`] if any monitor indicated new outputs to watch. Subsequent
	/// calls must not exclude any transactions matching the new outputs nor any in-block
	/// descendants of such transactions. It is not necessary to re-fetch the block to obtain
	/// updated `txdata`.
	///
	/// [`ChannelMonitor::block_connected`]: ../channelmonitor/struct.ChannelMonitor.html#method.block_connected
	/// [`chain::Watch::release_pending_monitor_events`]: ../trait.Watch.html#tymethod.release_pending_monitor_events
	/// [`chain::Filter`]: ../trait.Filter.html
	pub fn block_connected(&self, header: &BlockHeader, txdata: &TransactionData, height: u32) {
		let mut monitors = self.monitors.lock().unwrap();
		for monitor in monitors.values_mut() {
			let mut txn_outputs = monitor.block_connected(header, txdata, height, &*self.broadcaster, &*self.fee_estimator, &*self.logger);

			if let Some(ref chain_source) = self.chain_source {
				for (txid, outputs) in txn_outputs.drain(..) {
					for (idx, output) in outputs.iter() {
						chain_source.register_output(&OutPoint { txid, index: *idx as u16 }, &output.script_pubkey);
					}
				}
			}
		}
	}

	/// Dispatches to per-channel monitors, which are responsible for updating their on-chain view
	/// of a channel based on the disconnected block. See [`ChannelMonitor::block_disconnected`] for
	/// details.
	///
	/// [`ChannelMonitor::block_disconnected`]: ../channelmonitor/struct.ChannelMonitor.html#method.block_disconnected
	pub fn block_disconnected(&self, header: &BlockHeader, disconnected_height: u32) {
		let mut monitors = self.monitors.lock().unwrap();
		for monitor in monitors.values_mut() {
			monitor.block_disconnected(header, disconnected_height, &*self.broadcaster, &*self.fee_estimator, &*self.logger);
		}
	}

	/// Creates a new `ChainMonitor` used to watch on-chain activity pertaining to channels.
	///
	/// When an optional chain source implementing [`chain::Filter`] is provided, the chain monitor
	/// will call back to it indicating transactions and outputs of interest. This allows clients to
	/// pre-filter blocks or only fetch blocks matching a compact filter. Otherwise, clients may
	/// always need to fetch full blocks absent another means for determining which blocks contain
	/// transactions relevant to the watched channels.
	///
	/// [`chain::Filter`]: ../trait.Filter.html
	pub fn new(chain_source: Option<C>, broadcaster: T, logger: L, feeest: F, persister: P) -> Self {
		Self {
			monitors: Mutex::new(HashMap::new()),
			chain_source,
			broadcaster,
			logger,
			fee_estimator: feeest,
			persister,
		}
	}
}

impl<ChannelSigner: Sign, C: Deref + Send + Sync, T: Deref + Send + Sync, F: Deref + Send + Sync, L: Deref + Send + Sync, P: Deref + Send + Sync>
chain::Listen for ChainMonitor<ChannelSigner, C, T, F, L, P>
where
	ChannelSigner: Sign,
	C::Target: chain::Filter,
	T::Target: BroadcasterInterface,
	F::Target: FeeEstimator,
	L::Target: Logger,
	P::Target: channelmonitor::Persist<ChannelSigner>,
{
	fn block_connected(&self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		ChainMonitor::block_connected(self, &block.header, &txdata, height);
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		ChainMonitor::block_disconnected(self, header, height);
	}
}

impl<ChannelSigner: Sign, C: Deref + Sync + Send, T: Deref + Sync + Send, F: Deref + Sync + Send, L: Deref + Sync + Send, P: Deref + Sync + Send>
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
	///
	/// [`chain::Filter`]: ../trait.Filter.html
	fn watch_channel(&self, funding_outpoint: OutPoint, monitor: ChannelMonitor<ChannelSigner>) -> Result<(), ChannelMonitorUpdateErr> {
		let mut monitors = self.monitors.lock().unwrap();
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
				chain_source.register_tx(&funding_txo.0.txid, &funding_txo.1);
				for (txid, outputs) in monitor.get_outputs_to_watch().iter() {
					for (idx, script_pubkey) in outputs.iter() {
						chain_source.register_output(&OutPoint { txid: *txid, index: *idx as u16 }, script_pubkey);
					}
				}
			}
		}
		entry.insert(monitor);
		Ok(())
	}

	/// Note that we persist the given `ChannelMonitor` update while holding the
	/// `ChainMonitor` monitors lock.
	fn update_channel(&self, funding_txo: OutPoint, update: ChannelMonitorUpdate) -> Result<(), ChannelMonitorUpdateErr> {
		// Update the monitor that watches the channel referred to by the given outpoint.
		let mut monitors = self.monitors.lock().unwrap();
		match monitors.get_mut(&funding_txo) {
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
			Some(orig_monitor) => {
				log_trace!(self.logger, "Updating Channel Monitor for channel {}", log_funding_info!(orig_monitor));
				let update_res = orig_monitor.update_monitor(&update, &self.broadcaster, &self.fee_estimator, &self.logger);
				if let Err(e) = &update_res {
					log_error!(self.logger, "Failed to update channel monitor: {:?}", e);
				}
				// Even if updating the monitor returns an error, the monitor's state will
				// still be changed. So, persist the updated monitor despite the error.
				let persist_res = self.persister.update_persisted_channel(funding_txo, &update, orig_monitor);
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
		for chan in self.monitors.lock().unwrap().values_mut() {
			pending_monitor_events.append(&mut chan.get_and_clear_pending_monitor_events());
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
		for chan in self.monitors.lock().unwrap().values_mut() {
			pending_events.append(&mut chan.get_and_clear_pending_events());
		}
		pending_events
	}
}
