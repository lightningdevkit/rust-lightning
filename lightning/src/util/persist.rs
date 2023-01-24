// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains a simple key-value store trait KVStorePersister that
//! allows one to implement the persistence for [`ChannelManager`], [`NetworkGraph`],
//! and [`ChannelMonitor`] all in one place.

use core::ops::Deref;
use bitcoin::hashes::hex::ToHex;
use crate::io;
use crate::routing::scoring::WriteableScore;

use crate::chain;
use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::chainmonitor::{Persist, MonitorUpdateId};
use crate::chain::keysinterface::{EntropySource, NodeSigner, WriteableEcdsaChannelSigner, SignerProvider};
use crate::chain::transaction::OutPoint;
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use crate::ln::channelmanager::ChannelManager;
use crate::routing::router::Router;
use crate::routing::gossip::NetworkGraph;
use super::{logger::Logger, ser::Writeable};

/// Trait for a key-value store for persisting some writeable object at some key
/// Implementing `KVStorePersister` provides auto-implementations for [`Persister`]
/// and [`Persist`] traits.  It uses "manager", "network_graph",
/// and "monitors/{funding_txo_id}_{funding_txo_index}" for keys.
pub trait KVStorePersister {
	/// Persist the given writeable using the provided key
	fn persist<W: Writeable>(&self, key: &str, object: &W) -> io::Result<()>;
}

/// Trait that handles persisting a [`ChannelManager`], [`NetworkGraph`], and [`WriteableScore`] to disk.
pub trait Persister<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref, S: WriteableScore<'a>>
	where M::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: 'static + BroadcasterInterface,
		ES::Target: 'static + EntropySource,
		NS::Target: 'static + NodeSigner,
		SP::Target: 'static + SignerProvider,
		F::Target: 'static + FeeEstimator,
		R::Target: 'static + Router,
		L::Target: 'static + Logger,
{
	/// Persist the given ['ChannelManager'] to disk, returning an error if persistence failed.
	fn persist_manager(&self, channel_manager: &ChannelManager<M, T, ES, NS, SP, F, R, L>) -> Result<(), io::Error>;

	/// Persist the given [`NetworkGraph`] to disk, returning an error if persistence failed.
	fn persist_graph(&self, network_graph: &NetworkGraph<L>) -> Result<(), io::Error>;

	/// Persist the given [`WriteableScore`] to disk, returning an error if persistence failed.
	fn persist_scorer(&self, scorer: &S) -> Result<(), io::Error>;
}

impl<'a, A: KVStorePersister, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref, S: WriteableScore<'a>> Persister<'a, M, T, ES, NS, SP, F, R, L, S> for A
	where M::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::Signer>,
		T::Target: 'static + BroadcasterInterface,
		ES::Target: 'static + EntropySource,
		NS::Target: 'static + NodeSigner,
		SP::Target: 'static + SignerProvider,
		F::Target: 'static + FeeEstimator,
		R::Target: 'static + Router,
		L::Target: 'static + Logger,
{
	/// Persist the given ['ChannelManager'] to disk with the name "manager", returning an error if persistence failed.
	fn persist_manager(&self, channel_manager: &ChannelManager<M, T, ES, NS, SP, F, R, L>) -> Result<(), io::Error> {
		self.persist("manager", channel_manager)
	}

	/// Persist the given [`NetworkGraph`] to disk with the name "network_graph", returning an error if persistence failed.
	fn persist_graph(&self, network_graph: &NetworkGraph<L>) -> Result<(), io::Error> {
		self.persist("network_graph", network_graph)
	}

	/// Persist the given [`WriteableScore`] to disk with name "scorer", returning an error if persistence failed.
	fn persist_scorer(&self, scorer: &S) -> Result<(), io::Error> {
		self.persist("scorer", &scorer)
	}
}

impl<ChannelSigner: WriteableEcdsaChannelSigner, K: KVStorePersister> Persist<ChannelSigner> for K {
	// TODO: We really need a way for the persister to inform the user that its time to crash/shut
	// down once these start returning failure.
	// A PermanentFailure implies we should probably just shut down the node since we're
	// force-closing channels without even broadcasting!

	fn persist_new_channel(&self, funding_txo: OutPoint, monitor: &ChannelMonitor<ChannelSigner>, _update_id: MonitorUpdateId) -> chain::ChannelMonitorUpdateStatus {
		let key = format!("monitors/{}_{}", funding_txo.txid.to_hex(), funding_txo.index);
		match self.persist(&key, monitor) {
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(_) => chain::ChannelMonitorUpdateStatus::PermanentFailure,
		}
	}

	fn update_persisted_channel(&self, funding_txo: OutPoint, _update: Option<&ChannelMonitorUpdate>, monitor: &ChannelMonitor<ChannelSigner>, _update_id: MonitorUpdateId) -> chain::ChannelMonitorUpdateStatus {
		let key = format!("monitors/{}_{}", funding_txo.txid.to_hex(), funding_txo.index);
		match self.persist(&key, monitor) {
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(_) => chain::ChannelMonitorUpdateStatus::PermanentFailure,
		}
	}
}
