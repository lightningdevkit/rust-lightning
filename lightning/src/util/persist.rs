// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains a simple key-value store trait [`KVStore`] that
//! allows one to implement the persistence for [`ChannelManager`], [`NetworkGraph`],
//! and [`ChannelMonitor`] all in one place.

use core::cmp;
use core::convert::{TryFrom, TryInto};
use core::ops::Deref;
use core::str::FromStr;
use bitcoin::{BlockHash, Txid};

use crate::{io, log_error};
use crate::alloc::string::ToString;
use crate::prelude::*;

use crate::chain;
use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::chainmonitor::{Persist, MonitorUpdateId};
use crate::sign::{EntropySource, NodeSigner, ecdsa::WriteableEcdsaChannelSigner, SignerProvider};
use crate::chain::transaction::OutPoint;
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, CLOSED_CHANNEL_UPDATE_ID};
use crate::ln::channelmanager::ChannelManager;
use crate::routing::router::Router;
use crate::routing::gossip::NetworkGraph;
use crate::routing::scoring::WriteableScore;
use crate::util::logger::Logger;
use crate::util::ser::{Readable, ReadableArgs, Writeable};

/// The alphabet of characters allowed for namespaces and keys.
pub const KVSTORE_NAMESPACE_KEY_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

/// The maximum number of characters namespaces and keys may have.
pub const KVSTORE_NAMESPACE_KEY_MAX_LEN: usize = 120;

/// The primary namespace under which the [`ChannelManager`] will be persisted.
pub const CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE: &str = "";
/// The secondary namespace under which the [`ChannelManager`] will be persisted.
pub const CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The key under which the [`ChannelManager`] will be persisted.
pub const CHANNEL_MANAGER_PERSISTENCE_KEY: &str = "manager";

/// The primary namespace under which [`ChannelMonitor`]s will be persisted.
pub const CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE: &str = "monitors";
/// The secondary namespace under which [`ChannelMonitor`]s will be persisted.
pub const CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The primary namespace under which [`ChannelMonitorUpdate`]s will be persisted.
pub const CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE: &str = "monitor_updates";

/// The primary namespace under which the [`NetworkGraph`] will be persisted.
pub const NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE: &str = "";
/// The secondary namespace under which the [`NetworkGraph`] will be persisted.
pub const NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The key under which the [`NetworkGraph`] will be persisted.
pub const NETWORK_GRAPH_PERSISTENCE_KEY: &str = "network_graph";

/// The primary namespace under which the [`WriteableScore`] will be persisted.
pub const SCORER_PERSISTENCE_PRIMARY_NAMESPACE: &str = "";
/// The secondary namespace under which the [`WriteableScore`] will be persisted.
pub const SCORER_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The key under which the [`WriteableScore`] will be persisted.
pub const SCORER_PERSISTENCE_KEY: &str = "scorer";

/// A sentinel value to be prepended to monitors persisted by the [`MonitorUpdatingPersister`].
///
/// This serves to prevent someone from accidentally loading such monitors (which may need
/// updates applied to be current) with another implementation.
pub const MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL: &[u8] = &[0xFF; 2];

/// Provides an interface that allows storage and retrieval of persisted values that are associated
/// with given keys.
///
/// In order to avoid collisions the key space is segmented based on the given `primary_namespace`s
/// and `secondary_namespace`s. Implementations of this trait are free to handle them in different
/// ways, as long as per-namespace key uniqueness is asserted.
///
/// Keys and namespaces are required to be valid ASCII strings in the range of
/// [`KVSTORE_NAMESPACE_KEY_ALPHABET`] and no longer than [`KVSTORE_NAMESPACE_KEY_MAX_LEN`]. Empty
/// primary namespaces and secondary namespaces (`""`) are assumed to be a valid, however, if
/// `primary_namespace` is empty, `secondary_namespace` is required to be empty, too. This means
/// that concerns should always be separated by primary namespace first, before secondary
/// namespaces are used. While the number of primary namespaces will be relatively small and is
/// determined at compile time, there may be many secondary namespaces per primary namespace. Note
/// that per-namespace uniqueness needs to also hold for keys *and* namespaces in any given
/// namespace, i.e., conflicts between keys and equally named
/// primary namespaces/secondary namespaces must be avoided.
///
/// **Note:** Users migrating custom persistence backends from the pre-v0.0.117 `KVStorePersister`
/// interface can use a concatenation of `[{primary_namespace}/[{secondary_namespace}/]]{key}` to
/// recover a `key` compatible with the data model previously assumed by `KVStorePersister::persist`.
pub trait KVStore {
	/// Returns the data stored for the given `primary_namespace`, `secondary_namespace`, and
	/// `key`.
	///
	/// Returns an [`ErrorKind::NotFound`] if the given `key` could not be found in the given
	/// `primary_namespace` and `secondary_namespace`.
	///
	/// [`ErrorKind::NotFound`]: io::ErrorKind::NotFound
	fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> Result<Vec<u8>, io::Error>;
	/// Persists the given data under the given `key`.
	///
	/// Will create the given `primary_namespace` and `secondary_namespace` if not already present
	/// in the store.
	fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: &[u8]) -> Result<(), io::Error>;
	/// Removes any data that had previously been persisted under the given `key`.
	///
	/// If the `lazy` flag is set to `true`, the backend implementation might choose to lazily
	/// remove the given `key` at some point in time after the method returns, e.g., as part of an
	/// eventual batch deletion of multiple keys. As a consequence, subsequent calls to
	/// [`KVStore::list`] might include the removed key until the changes are actually persisted.
	///
	/// Note that while setting the `lazy` flag reduces the I/O burden of multiple subsequent
	/// `remove` calls, it also influences the atomicity guarantees as lazy `remove`s could
	/// potentially get lost on crash after the method returns. Therefore, this flag should only be
	/// set for `remove` operations that can be safely replayed at a later time.
	///
	/// Returns successfully if no data will be stored for the given `primary_namespace`,
	/// `secondary_namespace`, and `key`, independently of whether it was present before its
	/// invokation or not.
	fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool) -> Result<(), io::Error>;
	/// Returns a list of keys that are stored under the given `secondary_namespace` in
	/// `primary_namespace`.
	///
	/// Returns the keys in arbitrary order, so users requiring a particular order need to sort the
	/// returned keys. Returns an empty list if `primary_namespace` or `secondary_namespace` is unknown.
	fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> Result<Vec<String>, io::Error>;
}

/// Trait that handles persisting a [`ChannelManager`], [`NetworkGraph`], and [`WriteableScore`] to disk.
pub trait Persister<'a, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref, S: WriteableScore<'a>>
	where M::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
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


impl<'a, A: KVStore, M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, L: Deref, S: WriteableScore<'a>> Persister<'a, M, T, ES, NS, SP, F, R, L, S> for A
	where M::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
		T::Target: 'static + BroadcasterInterface,
		ES::Target: 'static + EntropySource,
		NS::Target: 'static + NodeSigner,
		SP::Target: 'static + SignerProvider,
		F::Target: 'static + FeeEstimator,
		R::Target: 'static + Router,
		L::Target: 'static + Logger,
{
	/// Persist the given [`ChannelManager`] to disk, returning an error if persistence failed.
	fn persist_manager(&self, channel_manager: &ChannelManager<M, T, ES, NS, SP, F, R, L>) -> Result<(), io::Error> {
		self.write(CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
			CHANNEL_MANAGER_PERSISTENCE_KEY,
			&channel_manager.encode())
	}

	/// Persist the given [`NetworkGraph`] to disk, returning an error if persistence failed.
	fn persist_graph(&self, network_graph: &NetworkGraph<L>) -> Result<(), io::Error> {
		self.write(NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
			NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
			NETWORK_GRAPH_PERSISTENCE_KEY,
			&network_graph.encode())
	}

	/// Persist the given [`WriteableScore`] to disk, returning an error if persistence failed.
	fn persist_scorer(&self, scorer: &S) -> Result<(), io::Error> {
		self.write(SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
			SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
			SCORER_PERSISTENCE_KEY,
			&scorer.encode())
	}
}

impl<ChannelSigner: WriteableEcdsaChannelSigner, K: KVStore> Persist<ChannelSigner> for K {
	// TODO: We really need a way for the persister to inform the user that its time to crash/shut
	// down once these start returning failure.
	// Then we should return InProgress rather than UnrecoverableError, implying we should probably
	// just shut down the node since we're not retrying persistence!

	fn persist_new_channel(&self, funding_txo: OutPoint, monitor: &ChannelMonitor<ChannelSigner>, _update_id: MonitorUpdateId) -> chain::ChannelMonitorUpdateStatus {
		let key = format!("{}_{}", funding_txo.txid.to_string(), funding_txo.index);
		match self.write(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			&key, &monitor.encode())
		{
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(_) => chain::ChannelMonitorUpdateStatus::UnrecoverableError
		}
	}

	fn update_persisted_channel(&self, funding_txo: OutPoint, _update: Option<&ChannelMonitorUpdate>, monitor: &ChannelMonitor<ChannelSigner>, _update_id: MonitorUpdateId) -> chain::ChannelMonitorUpdateStatus {
		let key = format!("{}_{}", funding_txo.txid.to_string(), funding_txo.index);
		match self.write(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			&key, &monitor.encode())
		{
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(_) => chain::ChannelMonitorUpdateStatus::UnrecoverableError
		}
	}
}

/// Read previously persisted [`ChannelMonitor`]s from the store.
pub fn read_channel_monitors<K: Deref, ES: Deref, SP: Deref>(
	kv_store: K, entropy_source: ES, signer_provider: SP,
) -> Result<Vec<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>, io::Error>
where
	K::Target: KVStore,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
{
	let mut res = Vec::new();

	for stored_key in kv_store.list(
		CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE)?
	{
		if stored_key.len() < 66 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"Stored key has invalid length"));
		}

		let txid = Txid::from_str(stored_key.split_at(64).0).map_err(|_| {
			io::Error::new(io::ErrorKind::InvalidData, "Invalid tx ID in stored key")
		})?;

		let index: u16 = stored_key.split_at(65).1.parse().map_err(|_| {
			io::Error::new(io::ErrorKind::InvalidData, "Invalid tx index in stored key")
		})?;

		match <(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>::read(
			&mut io::Cursor::new(
				kv_store.read(CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE, &stored_key)?),
			(&*entropy_source, &*signer_provider),
		) {
			Ok((block_hash, channel_monitor)) => {
				if channel_monitor.get_funding_txo().0.txid != txid
					|| channel_monitor.get_funding_txo().0.index != index
				{
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"ChannelMonitor was stored under the wrong key",
					));
				}
				res.push((block_hash, channel_monitor));
			}
			Err(_) => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"Failed to read ChannelMonitor"
				))
			}
		}
	}
	Ok(res)
}

/// Implements [`Persist`] in a way that writes and reads both [`ChannelMonitor`]s and
/// [`ChannelMonitorUpdate`]s.
///
/// # Overview
///
/// The main benefit this provides over the [`KVStore`]'s [`Persist`] implementation is decreased
/// I/O bandwidth and storage churn, at the expense of more IOPS (including listing, reading, and
/// deleting) and complexity. This is because it writes channel monitor differential updates,
/// whereas the other (default) implementation rewrites the entire monitor on each update. For
/// routing nodes, updates can happen many times per second to a channel, and monitors can be tens
/// of megabytes (or more). Updates can be as small as a few hundred bytes.
///
/// Note that monitors written with `MonitorUpdatingPersister` are _not_ backward-compatible with
/// the default [`KVStore`]'s [`Persist`] implementation. They have a prepended byte sequence,
/// [`MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL`], applied to prevent deserialization with other
/// persisters. This is because monitors written by this struct _may_ have unapplied updates. In
/// order to downgrade, you must ensure that all updates are applied to the monitor, and remove the
/// sentinel bytes.
///
/// # Storing monitors
///
/// Monitors are stored by implementing the [`Persist`] trait, which has two functions:
///
///   - [`Persist::persist_new_channel`], which persists whole [`ChannelMonitor`]s.
///   - [`Persist::update_persisted_channel`], which persists only a [`ChannelMonitorUpdate`]
///
/// Whole [`ChannelMonitor`]s are stored in the [`CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE`],
/// using the familiar encoding of an [`OutPoint`] (for example, `[SOME-64-CHAR-HEX-STRING]_1`).
///
/// Each [`ChannelMonitorUpdate`] is stored in a dynamic secondary namespace, as follows:
///
///   - primary namespace: [`CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE`]
///   - secondary namespace: [the monitor's encoded outpoint name]
///
/// Under that secondary namespace, each update is stored with a number string, like `21`, which
/// represents its `update_id` value.
///
/// For example, consider this channel, named for its transaction ID and index, or [`OutPoint`]:
///
///   - Transaction ID: `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
///   - Index: `1`
///
/// Full channel monitors would be stored at a single key:
///
/// `[CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1`
///
/// Updates would be stored as follows (with `/` delimiting primary_namespace/secondary_namespace/key):
///
/// ```text
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/1
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/2
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/3
/// ```
/// ... and so on.
///
/// # Reading channel state from storage
///
/// Channel state can be reconstructed by calling
/// [`MonitorUpdatingPersister::read_all_channel_monitors_with_updates`]. Alternatively, users can
/// list channel monitors themselves and load channels individually using
/// [`MonitorUpdatingPersister::read_channel_monitor_with_updates`].
///
/// ## EXTREMELY IMPORTANT
///
/// It is extremely important that your [`KVStore::read`] implementation uses the
/// [`io::ErrorKind::NotFound`] variant correctly: that is, when a file is not found, and _only_ in
/// that circumstance (not when there is really a permissions error, for example). This is because
/// neither channel monitor reading function lists updates. Instead, either reads the monitor, and
/// using its stored `update_id`, synthesizes update storage keys, and tries them in sequence until
/// one is not found. All _other_ errors will be bubbled up in the function's [`Result`].
///
/// # Pruning stale channel updates
///
/// Stale updates are pruned when the consolidation threshold is reached according to `maximum_pending_updates`.
/// Monitor updates in the range between the latest `update_id` and `update_id - maximum_pending_updates`
/// are deleted.
/// The `lazy` flag is used on the [`KVStore::remove`] method, so there are no guarantees that the deletions
/// will complete. However, stale updates are not a problem for data integrity, since updates are
/// only read that are higher than the stored [`ChannelMonitor`]'s `update_id`.
///
/// If you have many stale updates stored (such as after a crash with pending lazy deletes), and
/// would like to get rid of them, consider using the
/// [`MonitorUpdatingPersister::cleanup_stale_updates`] function.
pub struct MonitorUpdatingPersister<K: Deref, L: Deref, ES: Deref, SP: Deref>
where
	K::Target: KVStore,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
{
	kv_store: K,
	logger: L,
	maximum_pending_updates: u64,
	entropy_source: ES,
	signer_provider: SP,
}

#[allow(dead_code)]
impl<K: Deref, L: Deref, ES: Deref, SP: Deref>
	MonitorUpdatingPersister<K, L, ES, SP>
where
	K::Target: KVStore,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
{
	/// Constructs a new [`MonitorUpdatingPersister`].
	///
	/// The `maximum_pending_updates` parameter controls how many updates may be stored before a
	/// [`MonitorUpdatingPersister`] consolidates updates by writing a full monitor. Note that
	/// consolidation will frequently occur with fewer updates than what you set here; this number
	/// is merely the maximum that may be stored. When setting this value, consider that for higher
	/// values of `maximum_pending_updates`:
	///
	///   - [`MonitorUpdatingPersister`] will tend to write more [`ChannelMonitorUpdate`]s than
	/// [`ChannelMonitor`]s, approaching one [`ChannelMonitor`] write for every
	/// `maximum_pending_updates` [`ChannelMonitorUpdate`]s.
	///   - [`MonitorUpdatingPersister`] will issue deletes differently. Lazy deletes will come in
	/// "waves" for each [`ChannelMonitor`] write. A larger `maximum_pending_updates` means bigger,
	/// less frequent "waves."
	///   - [`MonitorUpdatingPersister`] will potentially have more listing to do if you need to run
	/// [`MonitorUpdatingPersister::cleanup_stale_updates`].
	pub fn new(
		kv_store: K, logger: L, maximum_pending_updates: u64, entropy_source: ES,
		signer_provider: SP,
	) -> Self {
		MonitorUpdatingPersister {
			kv_store,
			logger,
			maximum_pending_updates,
			entropy_source,
			signer_provider,
		}
	}

	/// Reads all stored channel monitors, along with any stored updates for them.
	///
	/// It is extremely important that your [`KVStore::read`] implementation uses the
	/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
	/// documentation for [`MonitorUpdatingPersister`].
	pub fn read_all_channel_monitors_with_updates<B: Deref, F: Deref>(
		&self, broadcaster: &B, fee_estimator: &F,
	) -> Result<Vec<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>, io::Error>
	where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
	{
		let monitor_list = self.kv_store.list(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
		)?;
		let mut res = Vec::with_capacity(monitor_list.len());
		for monitor_key in monitor_list {
			res.push(self.read_channel_monitor_with_updates(
				broadcaster,
				fee_estimator,
				monitor_key,
			)?)
		}
		Ok(res)
	}

	/// Read a single channel monitor, along with any stored updates for it.
	///
	/// It is extremely important that your [`KVStore::read`] implementation uses the
	/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
	/// documentation for [`MonitorUpdatingPersister`].
	///
	/// For `monitor_key`, channel storage keys be the channel's transaction ID and index, or
	/// [`OutPoint`], with an underscore `_` between them. For example, given:
	///
	///   - Transaction ID: `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
	///   - Index: `1`
	///
	/// The correct `monitor_key` would be:
	/// `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1`
	///
	/// Loading a large number of monitors will be faster if done in parallel. You can use this
	/// function to accomplish this. Take care to limit the number of parallel readers.
	pub fn read_channel_monitor_with_updates<B: Deref, F: Deref>(
		&self, broadcaster: &B, fee_estimator: &F, monitor_key: String,
	) -> Result<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>), io::Error>
	where
		B::Target: BroadcasterInterface,
		F::Target: FeeEstimator,
	{
		let monitor_name = MonitorName::new(monitor_key)?;
		let (block_hash, monitor) = self.read_monitor(&monitor_name)?;
		let mut current_update_id = monitor.get_latest_update_id();
		loop {
			current_update_id = match current_update_id.checked_add(1) {
				Some(next_update_id) => next_update_id,
				None => break,
			};
			let update_name = UpdateName::from(current_update_id);
			let update = match self.read_monitor_update(&monitor_name, &update_name) {
				Ok(update) => update,
				Err(err) if err.kind() == io::ErrorKind::NotFound => {
					// We can't find any more updates, so we are done.
					break;
				}
				Err(err) => return Err(err),
			};

			monitor.update_monitor(&update, broadcaster, fee_estimator, &self.logger)
				.map_err(|e| {
					log_error!(
						self.logger,
						"Monitor update failed. monitor: {} update: {} reason: {:?}",
						monitor_name.as_str(),
						update_name.as_str(),
						e
					);
					io::Error::new(io::ErrorKind::Other, "Monitor update failed")
				})?;
		}
		Ok((block_hash, monitor))
	}

	/// Read a channel monitor.
	fn read_monitor(
		&self, monitor_name: &MonitorName,
	) -> Result<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>), io::Error> {
		let outpoint: OutPoint = monitor_name.try_into()?;
		let mut monitor_cursor = io::Cursor::new(self.kv_store.read(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			monitor_name.as_str(),
		)?);
		// Discard the sentinel bytes if found.
		if monitor_cursor.get_ref().starts_with(MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL) {
			monitor_cursor.set_position(MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL.len() as u64);
		}
		match <(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>::read(
			&mut monitor_cursor,
			(&*self.entropy_source, &*self.signer_provider),
		) {
			Ok((blockhash, channel_monitor)) => {
				if channel_monitor.get_funding_txo().0.txid != outpoint.txid
					|| channel_monitor.get_funding_txo().0.index != outpoint.index
				{
					log_error!(
						self.logger,
						"ChannelMonitor {} was stored under the wrong key!",
						monitor_name.as_str()
					);
					Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"ChannelMonitor was stored under the wrong key",
					))
				} else {
					Ok((blockhash, channel_monitor))
				}
			}
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to read ChannelMonitor {}, reason: {}",
					monitor_name.as_str(),
					e,
				);
				Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to read ChannelMonitor"))
			}
		}
	}

	/// Read a channel monitor update.
	fn read_monitor_update(
		&self, monitor_name: &MonitorName, update_name: &UpdateName,
	) -> Result<ChannelMonitorUpdate, io::Error> {
		let update_bytes = self.kv_store.read(
			CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
			monitor_name.as_str(),
			update_name.as_str(),
		)?;
		ChannelMonitorUpdate::read(&mut io::Cursor::new(update_bytes)).map_err(|e| {
			log_error!(
				self.logger,
				"Failed to read ChannelMonitorUpdate {}/{}/{}, reason: {}",
				CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
				monitor_name.as_str(),
				update_name.as_str(),
				e,
			);
			io::Error::new(io::ErrorKind::InvalidData, "Failed to read ChannelMonitorUpdate")
		})
	}

	/// Cleans up stale updates for all monitors.
	///
	/// This function works by first listing all monitors, and then for each of them, listing all
	/// updates. The updates that have an `update_id` less than or equal to than the stored monitor
	/// are deleted. The deletion can either be lazy or non-lazy based on the `lazy` flag; this will
	/// be passed to [`KVStore::remove`].
	pub fn cleanup_stale_updates(&self, lazy: bool) -> Result<(), io::Error> {
		let monitor_keys = self.kv_store.list(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
		)?;
		for monitor_key in monitor_keys {
			let monitor_name = MonitorName::new(monitor_key)?;
			let (_, current_monitor) = self.read_monitor(&monitor_name)?;
			let updates = self
				.kv_store
				.list(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE, monitor_name.as_str())?;
			for update in updates {
				let update_name = UpdateName::new(update)?;
				// if the update_id is lower than the stored monitor, delete
				if update_name.0 <= current_monitor.get_latest_update_id() {
					self.kv_store.remove(
						CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
						monitor_name.as_str(),
						update_name.as_str(),
						lazy,
					)?;
				}
			}
		}
		Ok(())
	}
}

impl<ChannelSigner: WriteableEcdsaChannelSigner, K: Deref, L: Deref, ES: Deref, SP: Deref>
	Persist<ChannelSigner> for MonitorUpdatingPersister<K, L, ES, SP>
where
	K::Target: KVStore,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
{
	/// Persists a new channel. This means writing the entire monitor to the
	/// parametrized [`KVStore`].
	fn persist_new_channel(
		&self, funding_txo: OutPoint, monitor: &ChannelMonitor<ChannelSigner>,
		_monitor_update_call_id: MonitorUpdateId,
	) -> chain::ChannelMonitorUpdateStatus {
		// Determine the proper key for this monitor
		let monitor_name = MonitorName::from(funding_txo);
		// Serialize and write the new monitor
		let mut monitor_bytes = Vec::with_capacity(
			MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL.len() + monitor.serialized_length(),
		);
		monitor_bytes.extend_from_slice(MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL);
		monitor.write(&mut monitor_bytes).unwrap();
		match self.kv_store.write(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			monitor_name.as_str(),
			&monitor_bytes,
		) {
			Ok(_) => {
				chain::ChannelMonitorUpdateStatus::Completed
			}
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to write ChannelMonitor {}/{}/{} reason: {}",
					CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
					CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
					monitor_name.as_str(),
					e
				);
				chain::ChannelMonitorUpdateStatus::UnrecoverableError
			}
		}
	}

	/// Persists a channel update, writing only the update to the parameterized [`KVStore`] if possible.
	///
	/// In some cases, this will forward to [`MonitorUpdatingPersister::persist_new_channel`]:
	///
	///   - No full monitor is found in [`KVStore`]
	///   - The number of pending updates exceeds `maximum_pending_updates` as given to [`Self::new`]
	///   - LDK commands re-persisting the entire monitor through this function, specifically when
	///     `update` is `None`.
	///   - The update is at [`CLOSED_CHANNEL_UPDATE_ID`]
	fn update_persisted_channel(
		&self, funding_txo: OutPoint, update: Option<&ChannelMonitorUpdate>,
		monitor: &ChannelMonitor<ChannelSigner>, monitor_update_call_id: MonitorUpdateId,
	) -> chain::ChannelMonitorUpdateStatus {
		// IMPORTANT: monitor_update_call_id: MonitorUpdateId is not to be confused with
		// ChannelMonitorUpdate's update_id.
		if let Some(update) = update {
			if update.update_id != CLOSED_CHANNEL_UPDATE_ID
				&& update.update_id % self.maximum_pending_updates != 0
			{
				let monitor_name = MonitorName::from(funding_txo);
				let update_name = UpdateName::from(update.update_id);
				match self.kv_store.write(
					CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
					monitor_name.as_str(),
					update_name.as_str(),
					&update.encode(),
				) {
					Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
					Err(e) => {
						log_error!(
							self.logger,
							"Failed to write ChannelMonitorUpdate {}/{}/{} reason: {}",
							CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
							monitor_name.as_str(),
							update_name.as_str(),
							e
						);
						chain::ChannelMonitorUpdateStatus::UnrecoverableError
					}
				}
			} else {
				let monitor_name = MonitorName::from(funding_txo);
				// In case of channel-close monitor update, we need to read old monitor before persisting
				// the new one in order to determine the cleanup range.
				let maybe_old_monitor = match monitor.get_latest_update_id() {
					CLOSED_CHANNEL_UPDATE_ID => self.read_monitor(&monitor_name).ok(),
					_ => None
				};

				// We could write this update, but it meets criteria of our design that calls for a full monitor write.
				let monitor_update_status = self.persist_new_channel(funding_txo, monitor, monitor_update_call_id);

				if let chain::ChannelMonitorUpdateStatus::Completed = monitor_update_status {
					let cleanup_range = if monitor.get_latest_update_id() == CLOSED_CHANNEL_UPDATE_ID {
						// If there is an error while reading old monitor, we skip clean up.
						maybe_old_monitor.map(|(_, ref old_monitor)| {
							let start = old_monitor.get_latest_update_id();
							// We never persist an update with update_id = CLOSED_CHANNEL_UPDATE_ID
							let end = cmp::min(
								start.saturating_add(self.maximum_pending_updates),
								CLOSED_CHANNEL_UPDATE_ID - 1,
							);
							(start, end)
						})
					} else {
						let end = monitor.get_latest_update_id();
						let start = end.saturating_sub(self.maximum_pending_updates);
						Some((start, end))
					};

					if let Some((start, end)) = cleanup_range {
						self.cleanup_in_range(monitor_name, start, end);
					}
				}

				monitor_update_status
			}
		} else {
			// There is no update given, so we must persist a new monitor.
			self.persist_new_channel(funding_txo, monitor, monitor_update_call_id)
		}
	}
}

impl<K: Deref, L: Deref, ES: Deref, SP: Deref> MonitorUpdatingPersister<K, L, ES, SP>
where
	ES::Target: EntropySource + Sized,
	K::Target: KVStore,
	L::Target: Logger,
	SP::Target: SignerProvider + Sized
{
	// Cleans up monitor updates for given monitor in range `start..=end`.
	fn cleanup_in_range(&self, monitor_name: MonitorName, start: u64, end: u64) {
		for update_id in start..=end {
			let update_name = UpdateName::from(update_id);
			if let Err(e) = self.kv_store.remove(
				CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
				monitor_name.as_str(),
				update_name.as_str(),
				true,
			) {
				log_error!(
					self.logger,
					"Failed to clean up channel monitor updates for monitor {}, reason: {}",
					monitor_name.as_str(),
					e
				);
			};
		}
	}
}

/// A struct representing a name for a monitor.
#[derive(Debug)]
struct MonitorName(String);

impl MonitorName {
	/// Constructs a [`MonitorName`], after verifying that an [`OutPoint`] can
	/// be formed from the given `name`.
	pub fn new(name: String) -> Result<Self, io::Error> {
		MonitorName::do_try_into_outpoint(&name)?;
		Ok(Self(name))
	}
	/// Convert this monitor name to a str.
	pub fn as_str(&self) -> &str {
		&self.0
	}
	/// Attempt to form a valid [`OutPoint`] from a given name string.
	fn do_try_into_outpoint(name: &str) -> Result<OutPoint, io::Error> {
		let mut parts = name.splitn(2, '_');
		let txid = if let Some(part) = parts.next() {
			Txid::from_str(part).map_err(|_| {
				io::Error::new(io::ErrorKind::InvalidData, "Invalid tx ID in stored key")
			})?
		} else {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"Stored monitor key is not a splittable string",
			));
		};
		let index = if let Some(part) = parts.next() {
			part.parse().map_err(|_| {
				io::Error::new(io::ErrorKind::InvalidData, "Invalid tx index in stored key")
			})?
		} else {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"No tx index value found after underscore in stored key",
			));
		};
		Ok(OutPoint { txid, index })
	}
}

impl TryFrom<&MonitorName> for OutPoint {
	type Error = io::Error;

	fn try_from(value: &MonitorName) -> Result<Self, io::Error> {
		MonitorName::do_try_into_outpoint(&value.0)
	}
}

impl From<OutPoint> for MonitorName {
	fn from(value: OutPoint) -> Self {
		MonitorName(format!("{}_{}", value.txid.to_string(), value.index))
	}
}

/// A struct representing a name for an update.
#[derive(Debug)]
struct UpdateName(u64, String);

impl UpdateName {
	/// Constructs an [`UpdateName`], after verifying that an update sequence ID
	/// can be derived from the given `name`.
	pub fn new(name: String) -> Result<Self, io::Error> {
		match name.parse::<u64>() {
			Ok(u) => Ok(u.into()),
			Err(_) => {
				Err(io::Error::new(io::ErrorKind::InvalidData, "cannot parse u64 from update name"))
			}
		}
	}

	/// Convert this monitor update name to a &str
	pub fn as_str(&self) -> &str {
		&self.1
	}
}

impl From<u64> for UpdateName {
	fn from(value: u64) -> Self {
		Self(value, value.to_string())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::chain::chainmonitor::Persist;
	use crate::chain::ChannelMonitorUpdateStatus;
	use crate::events::{ClosureReason, MessageSendEventsProvider};
	use crate::ln::functional_test_utils::*;
	use crate::util::test_utils::{self, TestLogger, TestStore};
	use crate::{check_added_monitors, check_closed_broadcast};

	const EXPECTED_UPDATES_PER_PAYMENT: u64 = 5;

	#[test]
	fn converts_u64_to_update_name() {
		assert_eq!(UpdateName::from(0).as_str(), "0");
		assert_eq!(UpdateName::from(21).as_str(), "21");
		assert_eq!(UpdateName::from(u64::MAX).as_str(), "18446744073709551615");
	}

	#[test]
	fn bad_update_name_fails() {
		assert!(UpdateName::new("deadbeef".to_string()).is_err());
		assert!(UpdateName::new("-1".to_string()).is_err());
	}

	#[test]
	fn monitor_from_outpoint_works() {
		let monitor_name1 = MonitorName::from(OutPoint {
			txid: Txid::from_str("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap(),
			index: 1,
		});
		assert_eq!(monitor_name1.as_str(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1");

		let monitor_name2 = MonitorName::from(OutPoint {
			txid: Txid::from_str("f33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeef").unwrap(),
			index: u16::MAX,
		});
		assert_eq!(monitor_name2.as_str(), "f33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeef_65535");
	}

	#[test]
	fn bad_monitor_string_fails() {
		assert!(MonitorName::new("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()).is_err());
		assert!(MonitorName::new("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_65536".to_string()).is_err());
		assert!(MonitorName::new("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_21".to_string()).is_err());
	}

	// Exercise the `MonitorUpdatingPersister` with real channels and payments.
	#[test]
	fn persister_with_real_monitors() {
		// This value is used later to limit how many iterations we perform.
		let persister_0_max_pending_updates = 7;
		// Intentionally set this to a smaller value to test a different alignment.
		let persister_1_max_pending_updates = 3;
		let chanmon_cfgs = create_chanmon_cfgs(4);
		let persister_0 = MonitorUpdatingPersister {
			kv_store: &TestStore::new(false),
			logger: &TestLogger::new(),
			maximum_pending_updates: persister_0_max_pending_updates,
			entropy_source: &chanmon_cfgs[0].keys_manager,
			signer_provider: &chanmon_cfgs[0].keys_manager,
		};
		let persister_1 = MonitorUpdatingPersister {
			kv_store: &TestStore::new(false),
			logger: &TestLogger::new(),
			maximum_pending_updates: persister_1_max_pending_updates,
			entropy_source: &chanmon_cfgs[1].keys_manager,
			signer_provider: &chanmon_cfgs[1].keys_manager,
		};
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(
			Some(&chanmon_cfgs[0].chain_source),
			&chanmon_cfgs[0].tx_broadcaster,
			&chanmon_cfgs[0].logger,
			&chanmon_cfgs[0].fee_estimator,
			&persister_0,
			&chanmon_cfgs[0].keys_manager,
		);
		let chain_mon_1 = test_utils::TestChainMonitor::new(
			Some(&chanmon_cfgs[1].chain_source),
			&chanmon_cfgs[1].tx_broadcaster,
			&chanmon_cfgs[1].logger,
			&chanmon_cfgs[1].fee_estimator,
			&persister_1,
			&chanmon_cfgs[1].keys_manager,
		);
		node_cfgs[0].chain_monitor = chain_mon_0;
		node_cfgs[1].chain_monitor = chain_mon_1;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let broadcaster_0 = &chanmon_cfgs[2].tx_broadcaster;
		let broadcaster_1 = &chanmon_cfgs[3].tx_broadcaster;

		// Check that the persisted channel data is empty before any channels are
		// open.
		let mut persisted_chan_data_0 = persister_0.read_all_channel_monitors_with_updates(
			&broadcaster_0, &&chanmon_cfgs[0].fee_estimator).unwrap();
		assert_eq!(persisted_chan_data_0.len(), 0);
		let mut persisted_chan_data_1 = persister_1.read_all_channel_monitors_with_updates(
			&broadcaster_1, &&chanmon_cfgs[1].fee_estimator).unwrap();
		assert_eq!(persisted_chan_data_1.len(), 0);

		// Helper to make sure the channel is on the expected update ID.
		macro_rules! check_persisted_data {
			($expected_update_id: expr) => {
				persisted_chan_data_0 = persister_0.read_all_channel_monitors_with_updates(
					&broadcaster_0, &&chanmon_cfgs[0].fee_estimator).unwrap();
				// check that we stored only one monitor
				assert_eq!(persisted_chan_data_0.len(), 1);
				for (_, mon) in persisted_chan_data_0.iter() {
					// check that when we read it, we got the right update id
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);

					// if the CM is at consolidation threshold, ensure no updates are stored.
					let monitor_name = MonitorName::from(mon.get_funding_txo().0);
					if mon.get_latest_update_id() % persister_0_max_pending_updates == 0
							|| mon.get_latest_update_id() == CLOSED_CHANNEL_UPDATE_ID {
						assert_eq!(
							persister_0.kv_store.list(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
								monitor_name.as_str()).unwrap().len(),
							0,
							"updates stored when they shouldn't be in persister 0"
						);
					}
				}
				persisted_chan_data_1 = persister_1.read_all_channel_monitors_with_updates(
					&broadcaster_1, &&chanmon_cfgs[1].fee_estimator).unwrap();
				assert_eq!(persisted_chan_data_1.len(), 1);
				for (_, mon) in persisted_chan_data_1.iter() {
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);
					let monitor_name = MonitorName::from(mon.get_funding_txo().0);
					// if the CM is at consolidation threshold, ensure no updates are stored.
					if mon.get_latest_update_id() % persister_1_max_pending_updates == 0
							|| mon.get_latest_update_id() == CLOSED_CHANNEL_UPDATE_ID {
						assert_eq!(
							persister_1.kv_store.list(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
								monitor_name.as_str()).unwrap().len(),
							0,
							"updates stored when they shouldn't be in persister 1"
						);
					}
				}
			};
		}

		// Create some initial channel and check that a channel was persisted.
		let _ = create_announced_chan_between_nodes(&nodes, 0, 1);
		check_persisted_data!(0);

		// Send a few payments and make sure the monitors are updated to the latest.
		send_payment(&nodes[0], &vec![&nodes[1]][..], 8_000_000);
		check_persisted_data!(EXPECTED_UPDATES_PER_PAYMENT);
		send_payment(&nodes[1], &vec![&nodes[0]][..], 4_000_000);
		check_persisted_data!(2 * EXPECTED_UPDATES_PER_PAYMENT);

		// Send a few more payments to try all the alignments of max pending updates with
		// updates for a payment sent and received.
		let mut sender = 0;
		for i in 3..=persister_0_max_pending_updates * 2 {
			let receiver;
			if sender == 0 {
				sender = 1;
				receiver = 0;
			} else {
				sender = 0;
				receiver = 1;
			}
			send_payment(&nodes[sender], &vec![&nodes[receiver]][..], 21_000);
			check_persisted_data!(i * EXPECTED_UPDATES_PER_PAYMENT);
		}

		// Force close because cooperative close doesn't result in any persisted
		// updates.
		nodes[0].node.force_close_broadcasting_latest_txn(&nodes[0].node.list_channels()[0].channel_id, &nodes[1].node.get_our_node_id()).unwrap();

		check_closed_event(&nodes[0], 1, ClosureReason::HolderForceClosed, false, &[nodes[1].node.get_our_node_id()], 100000);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors!(nodes[0], 1);

		let node_txn = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(node_txn.len(), 1);

		connect_block(&nodes[1], &create_dummy_block(nodes[0].best_block_hash(), 42, vec![node_txn[0].clone(), node_txn[0].clone()]));

		check_closed_broadcast!(nodes[1], true);
		check_closed_event(&nodes[1], 1, ClosureReason::CommitmentTxConfirmed, false, &[nodes[0].node.get_our_node_id()], 100000);
		check_added_monitors!(nodes[1], 1);

		// Make sure everything is persisted as expected after close.
		check_persisted_data!(CLOSED_CHANNEL_UPDATE_ID);

		// Make sure the expected number of stale updates is present.
		let persisted_chan_data = persister_0.read_all_channel_monitors_with_updates(&broadcaster_0, &&chanmon_cfgs[0].fee_estimator).unwrap();
		let (_, monitor) = &persisted_chan_data[0];
		let monitor_name = MonitorName::from(monitor.get_funding_txo().0);
		// The channel should have 0 updates, as it wrote a full monitor and consolidated.
		assert_eq!(persister_0.kv_store.list(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE, monitor_name.as_str()).unwrap().len(), 0);
		assert_eq!(persister_1.kv_store.list(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE, monitor_name.as_str()).unwrap().len(), 0);
	}

	// Test that if the `MonitorUpdatingPersister`'s can't actually write, trying to persist a
	// monitor or update with it results in the persister returning an UnrecoverableError status.
	#[test]
	fn unrecoverable_error_on_write_failure() {
		// Set up a dummy channel and force close. This will produce a monitor
		// that we can then use to test persistence.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		nodes[1].node.force_close_broadcasting_latest_txn(&chan.2, &nodes[0].node.get_our_node_id()).unwrap();
		check_closed_event(&nodes[1], 1, ClosureReason::HolderForceClosed, false, &[nodes[0].node.get_our_node_id()], 100000);
		{
			let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
			let update_map = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap();
			let update_id = update_map.get(&added_monitors[0].0.to_channel_id()).unwrap();
			let cmu_map = nodes[1].chain_monitor.monitor_updates.lock().unwrap();
			let cmu = &cmu_map.get(&added_monitors[0].0.to_channel_id()).unwrap()[0];
			let test_txo = OutPoint { txid: Txid::from_str("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(), index: 0 };

			let ro_persister = MonitorUpdatingPersister {
				kv_store: &TestStore::new(true),
				logger: &TestLogger::new(),
				maximum_pending_updates: 11,
				entropy_source: node_cfgs[0].keys_manager,
				signer_provider: node_cfgs[0].keys_manager,
			};
			match ro_persister.persist_new_channel(test_txo, &added_monitors[0].1, update_id.2) {
				ChannelMonitorUpdateStatus::UnrecoverableError => {
					// correct result
				}
				ChannelMonitorUpdateStatus::Completed => {
					panic!("Completed persisting new channel when shouldn't have")
				}
				ChannelMonitorUpdateStatus::InProgress => {
					panic!("Returned InProgress when shouldn't have")
				}
			}
			match ro_persister.update_persisted_channel(test_txo, Some(cmu), &added_monitors[0].1, update_id.2) {
				ChannelMonitorUpdateStatus::UnrecoverableError => {
					// correct result
				}
				ChannelMonitorUpdateStatus::Completed => {
					panic!("Completed persisting new channel when shouldn't have")
				}
				ChannelMonitorUpdateStatus::InProgress => {
					panic!("Returned InProgress when shouldn't have")
				}
			}
			added_monitors.clear();
		}
		nodes[1].node.get_and_clear_pending_msg_events();
	}

	// Confirm that the `clean_stale_updates` function finds and deletes stale updates.
	#[test]
	fn clean_stale_updates_works() {
		let test_max_pending_updates = 7;
		let chanmon_cfgs = create_chanmon_cfgs(3);
		let persister_0 = MonitorUpdatingPersister {
			kv_store: &TestStore::new(false),
			logger: &TestLogger::new(),
			maximum_pending_updates: test_max_pending_updates,
			entropy_source: &chanmon_cfgs[0].keys_manager,
			signer_provider: &chanmon_cfgs[0].keys_manager,
		};
		let persister_1 = MonitorUpdatingPersister {
			kv_store: &TestStore::new(false),
			logger: &TestLogger::new(),
			maximum_pending_updates: test_max_pending_updates,
			entropy_source: &chanmon_cfgs[1].keys_manager,
			signer_provider: &chanmon_cfgs[1].keys_manager,
		};
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(
			Some(&chanmon_cfgs[0].chain_source),
			&chanmon_cfgs[0].tx_broadcaster,
			&chanmon_cfgs[0].logger,
			&chanmon_cfgs[0].fee_estimator,
			&persister_0,
			&chanmon_cfgs[0].keys_manager,
		);
		let chain_mon_1 = test_utils::TestChainMonitor::new(
			Some(&chanmon_cfgs[1].chain_source),
			&chanmon_cfgs[1].tx_broadcaster,
			&chanmon_cfgs[1].logger,
			&chanmon_cfgs[1].fee_estimator,
			&persister_1,
			&chanmon_cfgs[1].keys_manager,
		);
		node_cfgs[0].chain_monitor = chain_mon_0;
		node_cfgs[1].chain_monitor = chain_mon_1;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let broadcaster_0 = &chanmon_cfgs[2].tx_broadcaster;

		// Check that the persisted channel data is empty before any channels are
		// open.
		let persisted_chan_data = persister_0.read_all_channel_monitors_with_updates(&broadcaster_0, &&chanmon_cfgs[0].fee_estimator).unwrap();
		assert_eq!(persisted_chan_data.len(), 0);

		// Create some initial channel
		let _ = create_announced_chan_between_nodes(&nodes, 0, 1);

		// Send a few payments to advance the updates a bit
		send_payment(&nodes[0], &vec![&nodes[1]][..], 8_000_000);
		send_payment(&nodes[1], &vec![&nodes[0]][..], 4_000_000);

		// Get the monitor and make a fake stale update at update_id=1 (lowest height of an update possible)
		let persisted_chan_data = persister_0.read_all_channel_monitors_with_updates(&broadcaster_0, &&chanmon_cfgs[0].fee_estimator).unwrap();
		let (_, monitor) = &persisted_chan_data[0];
		let monitor_name = MonitorName::from(monitor.get_funding_txo().0);
		persister_0
			.kv_store
			.write(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE, monitor_name.as_str(), UpdateName::from(1).as_str(), &[0u8; 1])
			.unwrap();

		// Do the stale update cleanup
		persister_0.cleanup_stale_updates(false).unwrap();

		// Confirm the stale update is unreadable/gone
		assert!(persister_0
			.kv_store
			.read(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE, monitor_name.as_str(), UpdateName::from(1).as_str())
			.is_err());

		// Force close.
		nodes[0].node.force_close_broadcasting_latest_txn(&nodes[0].node.list_channels()[0].channel_id, &nodes[1].node.get_our_node_id()).unwrap();
		check_closed_event(&nodes[0], 1, ClosureReason::HolderForceClosed, false, &[nodes[1].node.get_our_node_id()], 100000);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors!(nodes[0], 1);

		// Write an update near u64::MAX
		persister_0
			.kv_store
			.write(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE, monitor_name.as_str(), UpdateName::from(u64::MAX - 1).as_str(), &[0u8; 1])
			.unwrap();

		// Do the stale update cleanup
		persister_0.cleanup_stale_updates(false).unwrap();

		// Confirm the stale update is unreadable/gone
		assert!(persister_0
			.kv_store
			.read(CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE, monitor_name.as_str(), UpdateName::from(u64::MAX - 1).as_str())
			.is_err());
	}
}
