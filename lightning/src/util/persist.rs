// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains a simple key-value store trait [`KVStoreSync`] that
//! allows one to implement the persistence for [`ChannelManager`], [`NetworkGraph`],
//! and [`ChannelMonitor`] all in one place.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`NetworkGraph`]: crate::routing::gossip::NetworkGraph

use alloc::sync::Arc;

use bitcoin::hashes::hex::FromHex;
use bitcoin::{BlockHash, Txid};

use core::future::Future;
use core::mem;
use core::ops::Deref;
use core::pin::Pin;
use core::str::FromStr;
use core::task;

use crate::prelude::*;
use crate::{io, log_error};

use crate::chain;
use crate::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use crate::chain::chainmonitor::Persist;
use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use crate::chain::transaction::OutPoint;
use crate::ln::types::ChannelId;
use crate::sign::{ecdsa::EcdsaChannelSigner, EntropySource, SignerProvider};
use crate::sync::Mutex;
use crate::util::async_poll::{dummy_waker, AsyncResult, MaybeSend, MaybeSync};
use crate::util::logger::Logger;
use crate::util::native_async::FutureSpawner;
use crate::util::ser::{Readable, ReadableArgs, Writeable};

/// The alphabet of characters allowed for namespaces and keys.
pub const KVSTORE_NAMESPACE_KEY_ALPHABET: &str =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

/// The maximum number of characters namespaces and keys may have.
pub const KVSTORE_NAMESPACE_KEY_MAX_LEN: usize = 120;

/// The primary namespace under which the [`ChannelManager`] will be persisted.
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
pub const CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE: &str = "";
/// The secondary namespace under which the [`ChannelManager`] will be persisted.
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
pub const CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The key under which the [`ChannelManager`] will be persisted.
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
pub const CHANNEL_MANAGER_PERSISTENCE_KEY: &str = "manager";

/// The primary namespace under which [`ChannelMonitor`]s will be persisted.
pub const CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE: &str = "monitors";
/// The secondary namespace under which [`ChannelMonitor`]s will be persisted.
pub const CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The primary namespace under which [`ChannelMonitorUpdate`]s will be persisted.
pub const CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE: &str = "monitor_updates";

/// The primary namespace under which archived [`ChannelMonitor`]s will be persisted.
pub const ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE: &str = "archived_monitors";
/// The secondary namespace under which archived [`ChannelMonitor`]s will be persisted.
pub const ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";

/// The primary namespace under which the [`NetworkGraph`] will be persisted.
///
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
pub const NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE: &str = "";
/// The secondary namespace under which the [`NetworkGraph`] will be persisted.
///
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
pub const NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The key under which the [`NetworkGraph`] will be persisted.
///
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
pub const NETWORK_GRAPH_PERSISTENCE_KEY: &str = "network_graph";

/// The primary namespace under which the [`WriteableScore`] will be persisted.
///
/// [`WriteableScore`]: crate::routing::scoring::WriteableScore
pub const SCORER_PERSISTENCE_PRIMARY_NAMESPACE: &str = "";
/// The secondary namespace under which the [`WriteableScore`] will be persisted.
///
/// [`WriteableScore`]: crate::routing::scoring::WriteableScore
pub const SCORER_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The key under which the [`WriteableScore`] will be persisted.
///
/// [`WriteableScore`]: crate::routing::scoring::WriteableScore
pub const SCORER_PERSISTENCE_KEY: &str = "scorer";

/// The primary namespace under which [`OutputSweeper`] state will be persisted.
///
/// [`OutputSweeper`]: crate::util::sweep::OutputSweeper
pub const OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE: &str = "";
/// The secondary namespace under which [`OutputSweeper`] state will be persisted.
///
/// [`OutputSweeper`]: crate::util::sweep::OutputSweeper
pub const OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";
/// The secondary namespace under which [`OutputSweeper`] state will be persisted.
/// The key under which [`OutputSweeper`] state will be persisted.
///
/// [`OutputSweeper`]: crate::util::sweep::OutputSweeper
pub const OUTPUT_SWEEPER_PERSISTENCE_KEY: &str = "output_sweeper";

/// A sentinel value to be prepended to monitors persisted by the [`MonitorUpdatingPersister`].
///
/// This serves to prevent someone from accidentally loading such monitors (which may need
/// updates applied to be current) with another implementation.
pub const MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL: &[u8] = &[0xFF; 2];

/// A synchronous version of the [`KVStore`] trait.
pub trait KVStoreSync {
	/// A synchronous version of the [`KVStore::read`] method.
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Result<Vec<u8>, io::Error>;
	/// A synchronous version of the [`KVStore::write`] method.
	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> Result<(), io::Error>;
	/// A synchronous version of the [`KVStore::remove`] method.
	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Result<(), io::Error>;
	/// A synchronous version of the [`KVStore::list`] method.
	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> Result<Vec<String>, io::Error>;
}

/// A wrapper around a [`KVStoreSync`] that implements the [`KVStore`] trait. It is not necessary to use this type
/// directly.
#[derive(Clone)]
pub struct KVStoreSyncWrapper<K: Deref>(pub K)
where
	K::Target: KVStoreSync;

impl<K: Deref> Deref for KVStoreSyncWrapper<K>
where
	K::Target: KVStoreSync,
{
	type Target = Self;
	fn deref(&self) -> &Self::Target {
		self
	}
}

impl<K: Deref> KVStore for KVStoreSyncWrapper<K>
where
	K::Target: KVStoreSync,
{
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> AsyncResult<'static, Vec<u8>, io::Error> {
		let res = self.0.read(primary_namespace, secondary_namespace, key);

		Box::pin(async move { res })
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> AsyncResult<'static, (), io::Error> {
		let res = self.0.write(primary_namespace, secondary_namespace, key, buf);

		Box::pin(async move { res })
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> AsyncResult<'static, (), io::Error> {
		let res = self.0.remove(primary_namespace, secondary_namespace, key);

		Box::pin(async move { res })
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> AsyncResult<'static, Vec<String>, io::Error> {
		let res = self.0.list(primary_namespace, secondary_namespace);

		Box::pin(async move { res })
	}
}

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
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> AsyncResult<'static, Vec<u8>, io::Error>;
	/// Persists the given data under the given `key`.
	///
	/// The order of multiple writes to the same key needs to be retained while persisting
	/// asynchronously. In other words, if two writes to the same key occur, the state (as seen by
	/// [`Self::read`]) must either see the first write then the second, or only ever the second,
	/// no matter when the futures complete (and must always contain the second write once the
	/// second future completes). The state should never contain the first write after the second
	/// write's future completes, nor should it contain the second write, then contain the first
	/// write at any point thereafter (even if the second write's future hasn't yet completed).
	///
	/// One way to ensure this requirement is met is by assigning a version number to each write
	/// before returning the future, and then during asynchronous execution, ensuring that the
	/// writes are executed in the correct order.
	///
	/// Note that no ordering requirements exist for writes to different keys.
	///
	/// Will create the given `primary_namespace` and `secondary_namespace` if not already present in the store.
	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> AsyncResult<'static, (), io::Error>;
	/// Removes any data that had previously been persisted under the given `key`.
	///
	/// Returns successfully if no data will be stored for the given `primary_namespace`,
	/// `secondary_namespace`, and `key`, independently of whether it was present before its
	/// invokation or not.
	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> AsyncResult<'static, (), io::Error>;
	/// Returns a list of keys that are stored under the given `secondary_namespace` in
	/// `primary_namespace`.
	///
	/// Returns the keys in arbitrary order, so users requiring a particular order need to sort the
	/// returned keys. Returns an empty list if `primary_namespace` or `secondary_namespace` is unknown.
	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> AsyncResult<'static, Vec<String>, io::Error>;
}

/// Provides additional interface methods that are required for [`KVStore`]-to-[`KVStore`]
/// data migration.
pub trait MigratableKVStore: KVStoreSync {
	/// Returns *all* known keys as a list of `primary_namespace`, `secondary_namespace`, `key` tuples.
	///
	/// This is useful for migrating data from [`KVStoreSync`] implementation to [`KVStoreSync`]
	/// implementation.
	///
	/// Must exhaustively return all entries known to the store to ensure no data is missed, but
	/// may return the items in arbitrary order.
	fn list_all_keys(&self) -> Result<Vec<(String, String, String)>, io::Error>;
}

/// Migrates all data from one store to another.
///
/// This operation assumes that `target_store` is empty, i.e., any data present under copied keys
/// might get overriden. User must ensure `source_store` is not modified during operation,
/// otherwise no consistency guarantees can be given.
///
/// Will abort and return an error if any IO operation fails. Note that in this case the
/// `target_store` might get left in an intermediate state.
pub fn migrate_kv_store_data<S: MigratableKVStore, T: MigratableKVStore>(
	source_store: &mut S, target_store: &mut T,
) -> Result<(), io::Error> {
	let keys_to_migrate = source_store.list_all_keys()?;

	for (primary_namespace, secondary_namespace, key) in &keys_to_migrate {
		let data = source_store.read(primary_namespace, secondary_namespace, key)?;
		target_store.write(primary_namespace, secondary_namespace, key, data)?;
	}

	Ok(())
}

impl<ChannelSigner: EcdsaChannelSigner, K: KVStoreSync + ?Sized> Persist<ChannelSigner> for K {
	// TODO: We really need a way for the persister to inform the user that its time to crash/shut
	// down once these start returning failure.
	// Then we should return InProgress rather than UnrecoverableError, implying we should probably
	// just shut down the node since we're not retrying persistence!

	fn persist_new_channel(
		&self, monitor_name: MonitorName, monitor: &ChannelMonitor<ChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		match self.write(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			&monitor_name.to_string(),
			monitor.encode(),
		) {
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(_) => chain::ChannelMonitorUpdateStatus::UnrecoverableError,
		}
	}

	fn update_persisted_channel(
		&self, monitor_name: MonitorName, _update: Option<&ChannelMonitorUpdate>,
		monitor: &ChannelMonitor<ChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		match self.write(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			&monitor_name.to_string(),
			monitor.encode(),
		) {
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(_) => chain::ChannelMonitorUpdateStatus::UnrecoverableError,
		}
	}

	fn archive_persisted_channel(&self, monitor_name: MonitorName) {
		let monitor_key = monitor_name.to_string();
		let monitor = match self.read(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			monitor_key.as_str(),
		) {
			Ok(monitor) => monitor,
			Err(_) => return,
		};
		match self.write(
			ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			monitor_key.as_str(),
			monitor,
		) {
			Ok(()) => {},
			Err(_e) => return,
		};
		let _ = self.remove(
			CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			monitor_key.as_str(),
		);
	}
}

/// Read previously persisted [`ChannelMonitor`]s from the store.
pub fn read_channel_monitors<K: Deref, ES: Deref, SP: Deref>(
	kv_store: K, entropy_source: ES, signer_provider: SP,
) -> Result<Vec<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>, io::Error>
where
	K::Target: KVStoreSync,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
{
	let mut res = Vec::new();

	for stored_key in kv_store.list(
		CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
	)? {
		match <Option<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>>::read(
			&mut io::Cursor::new(kv_store.read(
				CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
				&stored_key,
			)?),
			(&*entropy_source, &*signer_provider),
		) {
			Ok(Some((block_hash, channel_monitor))) => {
				let monitor_name = MonitorName::from_str(&stored_key)?;
				if channel_monitor.persistence_key() != monitor_name {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"ChannelMonitor was stored under the wrong key",
					));
				}

				res.push((block_hash, channel_monitor));
			},
			Ok(None) => {},
			Err(_) => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"Failed to read ChannelMonitor",
				))
			},
		}
	}
	Ok(res)
}

struct PanicingSpawner;
impl FutureSpawner for PanicingSpawner {
	fn spawn<T: Future<Output = ()> + MaybeSend + 'static>(&self, _: T) {
		unreachable!();
	}
}

fn poll_sync_future<F: Future>(future: F) -> F::Output {
	let mut waker = dummy_waker();
	let mut ctx = task::Context::from_waker(&mut waker);
	// TODO A future MSRV bump to 1.68 should allow for the pin macro
	match Pin::new(&mut Box::pin(future)).poll(&mut ctx) {
		task::Poll::Ready(result) => result,
		task::Poll::Pending => {
			// In a sync context, we can't wait for the future to complete.
			unreachable!("Sync KVStore-derived futures can not be pending in a sync context");
		},
	}
}

/// Implements [`Persist`] in a way that writes and reads both [`ChannelMonitor`]s and
/// [`ChannelMonitorUpdate`]s.
///
/// # Overview
///
/// The main benefit this provides over the [`KVStoreSync`]'s [`Persist`] implementation is decreased
/// I/O bandwidth and storage churn, at the expense of more IOPS (including listing, reading, and
/// deleting) and complexity. This is because it writes channel monitor differential updates,
/// whereas the other (default) implementation rewrites the entire monitor on each update. For
/// routing nodes, updates can happen many times per second to a channel, and monitors can be tens
/// of megabytes (or more). Updates can be as small as a few hundred bytes.
///
/// Note that monitors written with `MonitorUpdatingPersister` are _not_ backward-compatible with
/// the default [`KVStoreSync`]'s [`Persist`] implementation. They have a prepended byte sequence,
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
/// using the familiar encoding of an [`OutPoint`] (e.g., `[SOME-64-CHAR-HEX-STRING]_1`) for v1
/// channels or a [`ChannelId`] (e.g., `[SOME-64-CHAR-HEX-STRING]`) for v2 channels.
///
/// Each [`ChannelMonitorUpdate`] is stored in a dynamic secondary namespace, as follows:
///
///   - primary namespace: [`CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE`]
///   - secondary namespace: [the monitor's encoded outpoint or channel id name]
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
/// It is extremely important that your [`KVStoreSync::read`] implementation uses the
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
/// are deleted. If you have many stale updates stored and would like to get rid of them, consider using the
/// [`MonitorUpdatingPersister::cleanup_stale_updates`] function.
pub struct MonitorUpdatingPersister<K: Deref, L: Deref, ES: Deref, SP: Deref, BI: Deref, FE: Deref>(
	MonitorUpdatingPersisterAsync<KVStoreSyncWrapper<K>, PanicingSpawner, L, ES, SP, BI, FE>,
)
where
	K::Target: KVStoreSync,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
	BI::Target: BroadcasterInterface,
	FE::Target: FeeEstimator;

impl<K: Deref, L: Deref, ES: Deref, SP: Deref, BI: Deref, FE: Deref>
	MonitorUpdatingPersister<K, L, ES, SP, BI, FE>
where
	K::Target: KVStoreSync,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
	BI::Target: BroadcasterInterface,
	FE::Target: FeeEstimator,
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
	///
	/// Note that you can disable the update-writing entirely by setting `maximum_pending_updates`
	/// to zero, causing this [`Persist`] implementation to behave like the blanket [`Persist`]
	/// implementation for all [`KVStoreSync`]s.
	pub fn new(
		kv_store: K, logger: L, maximum_pending_updates: u64, entropy_source: ES,
		signer_provider: SP, broadcaster: BI, fee_estimator: FE,
	) -> Self {
		// Note that calling the spawner only happens in the `pub(crate)` `spawn_*` methods defined
		// with additional bounds on `MonitorUpdatingPersisterAsync`. Thus its safe to provide a
		// dummy always-panic implementation here.
		MonitorUpdatingPersister(MonitorUpdatingPersisterAsync::new(
			KVStoreSyncWrapper(kv_store),
			PanicingSpawner,
			logger,
			maximum_pending_updates,
			entropy_source,
			signer_provider,
			broadcaster,
			fee_estimator,
		))
	}

	/// Reads all stored channel monitors, along with any stored updates for them.
	///
	/// It is extremely important that your [`KVStoreSync::read`] implementation uses the
	/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
	/// documentation for [`MonitorUpdatingPersister`].
	pub fn read_all_channel_monitors_with_updates(
		&self,
	) -> Result<
		Vec<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>,
		io::Error,
	> {
		poll_sync_future(self.0.read_all_channel_monitors_with_updates())
	}

	/// Read a single channel monitor, along with any stored updates for it.
	///
	/// It is extremely important that your [`KVStoreSync::read`] implementation uses the
	/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
	/// documentation for [`MonitorUpdatingPersister`].
	///
	/// For `monitor_key`, channel storage keys can be the channel's funding [`OutPoint`], with an
	/// underscore `_` between txid and index for v1 channels. For example, given:
	///
	///   - Transaction ID: `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
	///   - Index: `1`
	///
	/// The correct `monitor_key` would be:
	/// `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1`
	///
	/// For v2 channels, the hex-encoded [`ChannelId`] is used directly for `monitor_key` instead.
	///
	/// Loading a large number of monitors will be faster if done in parallel. You can use this
	/// function to accomplish this. Take care to limit the number of parallel readers.
	pub fn read_channel_monitor_with_updates(
		&self, monitor_key: &str,
	) -> Result<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>), io::Error>
	{
		poll_sync_future(self.0.read_channel_monitor_with_updates(monitor_key))
	}

	/// Cleans up stale updates for all monitors.
	///
	/// This function works by first listing all monitors, and then for each of them, listing all
	/// updates. The updates that have an `update_id` less than or equal to than the stored monitor
	/// are deleted.
	pub fn cleanup_stale_updates(&self) -> Result<(), io::Error> {
		poll_sync_future(self.0.cleanup_stale_updates())
	}
}

impl<
		ChannelSigner: EcdsaChannelSigner,
		K: Deref,
		L: Deref,
		ES: Deref,
		SP: Deref,
		BI: Deref,
		FE: Deref,
	> Persist<ChannelSigner> for MonitorUpdatingPersister<K, L, ES, SP, BI, FE>
where
	K::Target: KVStoreSync,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
	BI::Target: BroadcasterInterface,
	FE::Target: FeeEstimator,
{
	/// Persists a new channel. This means writing the entire monitor to the
	/// parametrized [`KVStoreSync`].
	fn persist_new_channel(
		&self, monitor_name: MonitorName, monitor: &ChannelMonitor<ChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		let res = poll_sync_future(self.0 .0.persist_new_channel(monitor_name, monitor));
		match res {
			Ok(_) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(e) => {
				log_error!(
					self.0 .0.logger,
					"Failed to write ChannelMonitor {}/{}/{} reason: {}",
					CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
					CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
					monitor_name,
					e
				);
				chain::ChannelMonitorUpdateStatus::UnrecoverableError
			},
		}
	}

	/// Persists a channel update, writing only the update to the parameterized [`KVStoreSync`] if possible.
	///
	/// In some cases, this will forward to [`MonitorUpdatingPersister::persist_new_channel`]:
	///
	///   - No full monitor is found in [`KVStoreSync`]
	///   - The number of pending updates exceeds `maximum_pending_updates` as given to [`Self::new`]
	///   - LDK commands re-persisting the entire monitor through this function, specifically when
	///	    `update` is `None`.
	///   - The update is at [`u64::MAX`], indicating an update generated by pre-0.1 LDK.
	fn update_persisted_channel(
		&self, monitor_name: MonitorName, update: Option<&ChannelMonitorUpdate>,
		monitor: &ChannelMonitor<ChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		let inner = Arc::clone(&self.0 .0);
		let res = poll_sync_future(inner.update_persisted_channel(monitor_name, update, monitor));
		match res {
			Ok(()) => chain::ChannelMonitorUpdateStatus::Completed,
			Err(e) => {
				log_error!(
					self.0 .0.logger,
					"Failed to write ChannelMonitorUpdate {} id {} reason: {}",
					monitor_name,
					update.as_ref().map(|upd| upd.update_id).unwrap_or(0),
					e
				);
				chain::ChannelMonitorUpdateStatus::UnrecoverableError
			},
		}
	}

	fn archive_persisted_channel(&self, monitor_name: MonitorName) {
		poll_sync_future(self.0 .0.archive_persisted_channel(monitor_name));
	}
}

/// A variant of the [`MonitorUpdatingPersister`] which utilizes the async [`KVStore`] and offers
/// async versions of the public accessors.
///
/// Note that async monitor updating is considered beta, and bugs may be triggered by its use.
///
/// Unlike [`MonitorUpdatingPersister`], this does not implement [`Persist`], but is instead used
/// directly by the [`ChainMonitor`] via [`ChainMonitor::new_async_beta`].
///
/// [`ChainMonitor`]: crate::chain::chainmonitor::ChainMonitor
/// [`ChainMonitor::new_async_beta`]: crate::chain::chainmonitor::ChainMonitor::new_async_beta
pub struct MonitorUpdatingPersisterAsync<
	K: Deref,
	S: FutureSpawner,
	L: Deref,
	ES: Deref,
	SP: Deref,
	BI: Deref,
	FE: Deref,
>(Arc<MonitorUpdatingPersisterAsyncInner<K, S, L, ES, SP, BI, FE>>)
where
	K::Target: KVStore,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
	BI::Target: BroadcasterInterface,
	FE::Target: FeeEstimator;

struct MonitorUpdatingPersisterAsyncInner<
	K: Deref,
	S: FutureSpawner,
	L: Deref,
	ES: Deref,
	SP: Deref,
	BI: Deref,
	FE: Deref,
> where
	K::Target: KVStore,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
	BI::Target: BroadcasterInterface,
	FE::Target: FeeEstimator,
{
	kv_store: K,
	async_completed_updates: Mutex<Vec<(ChannelId, u64)>>,
	future_spawner: S,
	logger: L,
	maximum_pending_updates: u64,
	entropy_source: ES,
	signer_provider: SP,
	broadcaster: BI,
	fee_estimator: FE,
}

impl<K: Deref, S: FutureSpawner, L: Deref, ES: Deref, SP: Deref, BI: Deref, FE: Deref>
	MonitorUpdatingPersisterAsync<K, S, L, ES, SP, BI, FE>
where
	K::Target: KVStore,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
	BI::Target: BroadcasterInterface,
	FE::Target: FeeEstimator,
{
	/// Constructs a new [`MonitorUpdatingPersisterAsync`].
	///
	/// See [`MonitorUpdatingPersister::new`] for more info.
	pub fn new(
		kv_store: K, future_spawner: S, logger: L, maximum_pending_updates: u64,
		entropy_source: ES, signer_provider: SP, broadcaster: BI, fee_estimator: FE,
	) -> Self {
		MonitorUpdatingPersisterAsync(Arc::new(MonitorUpdatingPersisterAsyncInner {
			kv_store,
			async_completed_updates: Mutex::new(Vec::new()),
			future_spawner,
			logger,
			maximum_pending_updates,
			entropy_source,
			signer_provider,
			broadcaster,
			fee_estimator,
		}))
	}

	/// Reads all stored channel monitors, along with any stored updates for them.
	///
	/// It is extremely important that your [`KVStore::read`] implementation uses the
	/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
	/// documentation for [`MonitorUpdatingPersister`].
	pub async fn read_all_channel_monitors_with_updates(
		&self,
	) -> Result<
		Vec<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>,
		io::Error,
	> {
		let primary = CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE;
		let secondary = CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE;
		let monitor_list = self.0.kv_store.list(primary, secondary).await?;
		let mut res = Vec::with_capacity(monitor_list.len());
		for monitor_key in monitor_list {
			let result =
				self.0.maybe_read_channel_monitor_with_updates(monitor_key.as_str()).await?;
			if let Some(read_res) = result {
				res.push(read_res);
			}
		}
		Ok(res)
	}

	/// Read a single channel monitor, along with any stored updates for it.
	///
	/// It is extremely important that your [`KVStoreSync::read`] implementation uses the
	/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
	/// documentation for [`MonitorUpdatingPersister`].
	///
	/// For `monitor_key`, channel storage keys can be the channel's funding [`OutPoint`], with an
	/// underscore `_` between txid and index for v1 channels. For example, given:
	///
	///   - Transaction ID: `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
	///   - Index: `1`
	///
	/// The correct `monitor_key` would be:
	/// `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1`
	///
	/// For v2 channels, the hex-encoded [`ChannelId`] is used directly for `monitor_key` instead.
	///
	/// Loading a large number of monitors will be faster if done in parallel. You can use this
	/// function to accomplish this. Take care to limit the number of parallel readers.
	pub async fn read_channel_monitor_with_updates(
		&self, monitor_key: &str,
	) -> Result<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>), io::Error>
	{
		self.0.read_channel_monitor_with_updates(monitor_key).await
	}

	/// Cleans up stale updates for all monitors.
	///
	/// This function works by first listing all monitors, and then for each of them, listing all
	/// updates. The updates that have an `update_id` less than or equal to than the stored monitor
	/// are deleted.
	pub async fn cleanup_stale_updates(&self) -> Result<(), io::Error> {
		self.0.cleanup_stale_updates().await
	}
}

impl<
		K: Deref + MaybeSend + MaybeSync + 'static,
		S: FutureSpawner,
		L: Deref + MaybeSend + MaybeSync + 'static,
		ES: Deref + MaybeSend + MaybeSync + 'static,
		SP: Deref + MaybeSend + MaybeSync + 'static,
		BI: Deref + MaybeSend + MaybeSync + 'static,
		FE: Deref + MaybeSend + MaybeSync + 'static,
	> MonitorUpdatingPersisterAsync<K, S, L, ES, SP, BI, FE>
where
	K::Target: KVStore + MaybeSync,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
	BI::Target: BroadcasterInterface,
	FE::Target: FeeEstimator,
	<SP::Target as SignerProvider>::EcdsaSigner: MaybeSend + 'static,
{
	pub(crate) fn spawn_async_persist_new_channel(
		&self, monitor_name: MonitorName,
		monitor: &ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>,
	) {
		let inner = Arc::clone(&self.0);
		// Note that `persist_new_channel` is a sync method which calls all the way through to the
		// sync KVStore::write method (which returns a future) to ensure writes are well-ordered.
		let future = inner.persist_new_channel(monitor_name, monitor);
		let channel_id = monitor.channel_id();
		let completion = (monitor.channel_id(), monitor.get_latest_update_id());
		self.0.future_spawner.spawn(async move {
			match future.await {
				Ok(()) => inner.async_completed_updates.lock().unwrap().push(completion),
				Err(e) => {
					log_error!(
						inner.logger,
						"Failed to persist new ChannelMonitor {channel_id}: {e}. The node will now likely stall as this channel will not be able to make progress. You should restart as soon as possible.",
					);
				},
			}
		});
	}

	pub(crate) fn spawn_async_update_persisted_channel(
		&self, monitor_name: MonitorName, update: Option<&ChannelMonitorUpdate>,
		monitor: &ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>,
	) {
		let inner = Arc::clone(&self.0);
		// Note that `update_persisted_channel` is a sync method which calls all the way through to
		// the sync KVStore::write method (which returns a future) to ensure writes are well-ordered
		let future = inner.update_persisted_channel(monitor_name, update, monitor);
		let channel_id = monitor.channel_id();
		let completion = if let Some(update) = update {
			Some((monitor.channel_id(), update.update_id))
		} else {
			None
		};
		let inner = Arc::clone(&self.0);
		self.0.future_spawner.spawn(async move {
			match future.await {
				Ok(()) => if let Some(completion) = completion {
					inner.async_completed_updates.lock().unwrap().push(completion);
				},
				Err(e) => {
					log_error!(
						inner.logger,
						"Failed to persist new ChannelMonitor {channel_id}: {e}. The node will now likely stall as this channel will not be able to make progress. You should restart as soon as possible.",
					);
				},
			}
		});
	}

	pub(crate) fn spawn_async_archive_persisted_channel(&self, monitor_name: MonitorName) {
		let inner = Arc::clone(&self.0);
		self.0.future_spawner.spawn(async move {
			inner.archive_persisted_channel(monitor_name).await;
		});
	}

	pub(crate) fn get_and_clear_completed_updates(&self) -> Vec<(ChannelId, u64)> {
		mem::take(&mut *self.0.async_completed_updates.lock().unwrap())
	}
}

impl<K: Deref, S: FutureSpawner, L: Deref, ES: Deref, SP: Deref, BI: Deref, FE: Deref>
	MonitorUpdatingPersisterAsyncInner<K, S, L, ES, SP, BI, FE>
where
	K::Target: KVStore,
	L::Target: Logger,
	ES::Target: EntropySource + Sized,
	SP::Target: SignerProvider + Sized,
	BI::Target: BroadcasterInterface,
	FE::Target: FeeEstimator,
{
	pub async fn read_channel_monitor_with_updates(
		&self, monitor_key: &str,
	) -> Result<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>), io::Error>
	{
		match self.maybe_read_channel_monitor_with_updates(monitor_key).await? {
			Some(res) => Ok(res),
			None => Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"ChannelMonitor was stale, with no updates since LDK 0.0.118. \
						It cannot be read by modern versions of LDK, though also does not contain any funds left to sweep. \
						You should manually delete it instead",
			)),
		}
	}

	async fn maybe_read_channel_monitor_with_updates(
		&self, monitor_key: &str,
	) -> Result<
		Option<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>,
		io::Error,
	> {
		let monitor_name = MonitorName::from_str(monitor_key)?;
		let read_res = self.maybe_read_monitor(&monitor_name, monitor_key).await?;
		let (block_hash, monitor) = match read_res {
			Some(res) => res,
			None => return Ok(None),
		};
		let mut current_update_id = monitor.get_latest_update_id();
		// TODO: Parallelize this loop by speculatively reading a batch of updates
		loop {
			current_update_id = match current_update_id.checked_add(1) {
				Some(next_update_id) => next_update_id,
				None => break,
			};
			let update_name = UpdateName::from(current_update_id);
			let update = match self.read_monitor_update(monitor_key, &update_name).await {
				Ok(update) => update,
				Err(err) if err.kind() == io::ErrorKind::NotFound => {
					// We can't find any more updates, so we are done.
					break;
				},
				Err(err) => return Err(err),
			};

			monitor
				.update_monitor(&update, &self.broadcaster, &self.fee_estimator, &self.logger)
				.map_err(|e| {
				log_error!(
					self.logger,
					"Monitor update failed. monitor: {} update: {} reason: {:?}",
					monitor_key,
					update_name.as_str(),
					e
				);
				io::Error::new(io::ErrorKind::Other, "Monitor update failed")
			})?;
		}
		Ok(Some((block_hash, monitor)))
	}

	/// Read a channel monitor.
	async fn maybe_read_monitor(
		&self, monitor_name: &MonitorName, monitor_key: &str,
	) -> Result<
		Option<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>,
		io::Error,
	> {
		let primary = CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE;
		let secondary = CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE;
		let monitor_bytes = self.kv_store.read(primary, secondary, monitor_key).await?;
		let mut monitor_cursor = io::Cursor::new(monitor_bytes);
		// Discard the sentinel bytes if found.
		if monitor_cursor.get_ref().starts_with(MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL) {
			monitor_cursor.set_position(MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL.len() as u64);
		}
		match <Option<(BlockHash, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>)>>::read(
			&mut monitor_cursor,
			(&*self.entropy_source, &*self.signer_provider),
		) {
			Ok(None) => Ok(None),
			Ok(Some((blockhash, channel_monitor))) => {
				if channel_monitor.persistence_key() != *monitor_name {
					log_error!(
						self.logger,
						"ChannelMonitor {} was stored under the wrong key!",
						monitor_key,
					);
					Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"ChannelMonitor was stored under the wrong key",
					))
				} else {
					Ok(Some((blockhash, channel_monitor)))
				}
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to read ChannelMonitor {}, reason: {}",
					monitor_key,
					e,
				);
				Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to read ChannelMonitor"))
			},
		}
	}

	/// Read a channel monitor update.
	async fn read_monitor_update(
		&self, monitor_key: &str, update_name: &UpdateName,
	) -> Result<ChannelMonitorUpdate, io::Error> {
		let primary = CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE;
		let update_bytes = self.kv_store.read(primary, monitor_key, update_name.as_str()).await?;
		ChannelMonitorUpdate::read(&mut &update_bytes[..]).map_err(|e| {
			log_error!(
				self.logger,
				"Failed to read ChannelMonitorUpdate {}/{}/{}, reason: {}",
				CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
				monitor_key,
				update_name.as_str(),
				e,
			);
			io::Error::new(io::ErrorKind::InvalidData, "Failed to read ChannelMonitorUpdate")
		})
	}

	async fn cleanup_stale_updates(&self) -> Result<(), io::Error> {
		let primary = CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE;
		let secondary = CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE;
		let monitor_keys = self.kv_store.list(primary, secondary).await?;
		for monitor_key in monitor_keys {
			let monitor_name = MonitorName::from_str(&monitor_key)?;
			let maybe_monitor = self.maybe_read_monitor(&monitor_name, &monitor_key).await?;
			if let Some((_, current_monitor)) = maybe_monitor {
				let latest_update_id = current_monitor.get_latest_update_id();
				self.cleanup_stale_updates_for_monitor_to(&monitor_key, latest_update_id).await?;
			} else {
				// TODO: Also clean up super stale monitors (created pre-0.0.110 and last updated
				// pre-0.0.119).
			}
		}
		Ok(())
	}

	async fn cleanup_stale_updates_for_monitor_to(
		&self, monitor_key: &str, latest_update_id: u64,
	) -> Result<(), io::Error> {
		let primary = CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE;
		let updates = self.kv_store.list(primary, monitor_key).await?;
		for update in updates {
			let update_name = UpdateName::new(update)?;
			// if the update_id is lower than the stored monitor, delete
			if update_name.0 <= latest_update_id {
				self.kv_store.remove(primary, monitor_key, update_name.as_str()).await?;
			}
		}
		Ok(())
	}

	fn persist_new_channel<ChannelSigner: EcdsaChannelSigner>(
		&self, monitor_name: MonitorName, monitor: &ChannelMonitor<ChannelSigner>,
	) -> impl Future<Output = Result<(), io::Error>> {
		// Determine the proper key for this monitor
		let monitor_key = monitor_name.to_string();
		// Serialize and write the new monitor
		let mut monitor_bytes = Vec::with_capacity(
			MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL.len() + monitor.serialized_length(),
		);
		// If `maximum_pending_updates` is zero, we aren't actually writing monitor updates at all.
		// Thus, there's no need to add the sentinel prefix as the monitor can be read directly
		// from disk without issue.
		if self.maximum_pending_updates != 0 {
			monitor_bytes.extend_from_slice(MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL);
		}
		monitor.write(&mut monitor_bytes).unwrap();
		// Note that this is NOT an async function, but rather calls the *sync* KVStore write
		// method, allowing it to do its queueing immediately, and then return a future for the
		// completion of the write. This ensures monitor persistence ordering is preserved.
		let primary = CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE;
		let secondary = CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE;
		self.kv_store.write(primary, secondary, monitor_key.as_str(), monitor_bytes)
	}

	fn update_persisted_channel<'a, ChannelSigner: EcdsaChannelSigner + 'a>(
		self: Arc<Self>, monitor_name: MonitorName, update: Option<&ChannelMonitorUpdate>,
		monitor: &ChannelMonitor<ChannelSigner>,
	) -> impl Future<Output = Result<(), io::Error>> + 'a
	where
		Self: 'a,
	{
		const LEGACY_CLOSED_CHANNEL_UPDATE_ID: u64 = u64::MAX;
		let mut res_a = None;
		let mut res_b = None;
		let mut res_c = None;
		if let Some(update) = update {
			let persist_update = update.update_id != LEGACY_CLOSED_CHANNEL_UPDATE_ID
				&& self.maximum_pending_updates != 0
				&& update.update_id % self.maximum_pending_updates != 0;
			if persist_update {
				let monitor_key = monitor_name.to_string();
				let update_name = UpdateName::from(update.update_id);
				let primary = CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE;
				// Note that this is NOT an async function, but rather calls the *sync* KVStore
				// write method, allowing it to do its queueing immediately, and then return a
				// future for the completion of the write. This ensures monitor persistence
				// ordering is preserved.
				res_a = Some(self.kv_store.write(
					primary,
					&monitor_key,
					update_name.as_str(),
					update.encode(),
				));
			} else {
				// We could write this update, but it meets criteria of our design that calls for a full monitor write.
				// Note that this is NOT an async function, but rather calls the *sync* KVStore
				// write method, allowing it to do its queueing immediately, and then return a
				// future for the completion of the write. This ensures monitor persistence
				// ordering is preserved. This, thus, must happen before any await we do below.
				let write_fut = self.persist_new_channel(monitor_name, monitor);
				let latest_update_id = monitor.get_latest_update_id();

				res_b = Some(async move {
					let write_status = write_fut.await;
					if let Ok(()) = write_status {
						if latest_update_id == LEGACY_CLOSED_CHANNEL_UPDATE_ID {
							let monitor_key = monitor_name.to_string();
							self.cleanup_stale_updates_for_monitor_to(
								&monitor_key,
								latest_update_id,
							)
							.await?;
						} else {
							let end = latest_update_id;
							let start = end.saturating_sub(self.maximum_pending_updates);
							self.cleanup_in_range(monitor_name, start, end).await;
						}
					}

					write_status
				});
			}
		} else {
			// There is no update given, so we must persist a new monitor.
			// Note that this is NOT an async function, but rather calls the *sync* KVStore write
			// method, allowing it to do its queueing immediately, and then return a future for the
			// completion of the write. This ensures monitor persistence ordering is preserved.
			res_c = Some(self.persist_new_channel(monitor_name, monitor));
		}
		async move {
			// Complete any pending future(s). Note that to keep one return type we have to end
			// with a single async move block that we return, rather than trying to return the
			// individual futures themselves.
			if let Some(a) = res_a {
				a.await?;
			}
			if let Some(b) = res_b {
				b.await?;
			}
			if let Some(c) = res_c {
				c.await?;
			}
			Ok(())
		}
	}

	async fn archive_persisted_channel(&self, monitor_name: MonitorName) {
		let monitor_key = monitor_name.to_string();
		let monitor = match self.read_channel_monitor_with_updates(&monitor_key).await {
			Ok((_block_hash, monitor)) => monitor,
			Err(_) => return,
		};
		let primary = ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE;
		let secondary = ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE;
		match self.kv_store.write(primary, secondary, &monitor_key, monitor.encode()).await {
			Ok(()) => {},
			Err(_e) => return,
		};
		let primary = CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE;
		let secondary = CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE;
		let _ = self.kv_store.remove(primary, secondary, &monitor_key).await;
	}

	// Cleans up monitor updates for given monitor in range `start..=end`.
	async fn cleanup_in_range(&self, monitor_name: MonitorName, start: u64, end: u64) {
		let monitor_key = monitor_name.to_string();
		for update_id in start..=end {
			let update_name = UpdateName::from(update_id);
			let primary = CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE;
			let res = self.kv_store.remove(primary, &monitor_key, update_name.as_str()).await;
			if let Err(e) = res {
				log_error!(
					self.logger,
					"Failed to clean up channel monitor updates for monitor {}, reason: {}",
					monitor_key.as_str(),
					e
				);
			};
		}
	}
}

/// A struct representing a name for a channel monitor.
///
/// `MonitorName` is primarily used within the [`MonitorUpdatingPersister`]
/// in functions that store or retrieve [`ChannelMonitor`] snapshots.
/// It provides a consistent way to generate a unique key for channel
/// monitors based on the channel's funding [`OutPoint`] for v1 channels or
/// [`ChannelId`] for v2 channels. Use [`ChannelMonitor::persistence_key`] to
/// obtain the correct `MonitorName`.
///
/// While users of the Lightning Dev Kit library generally won't need
/// to interact with [`MonitorName`] directly, it can be useful for:
/// - Custom persistence implementations
/// - Debugging or logging channel monitor operations
/// - Extending the functionality of the `MonitorUpdatingPersister`
///
/// # Examples
///
/// ```
/// use std::str::FromStr;
///
/// use bitcoin::Txid;
/// use bitcoin::hashes::hex::FromHex;
///
/// use lightning::util::persist::MonitorName;
/// use lightning::chain::transaction::OutPoint;
/// use lightning::ln::types::ChannelId;
///
/// // v1 channel
/// let outpoint = OutPoint {
///	 txid: Txid::from_str("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap(),
///	 index: 1,
/// };
/// let monitor_name = MonitorName::V1Channel(outpoint);
/// assert_eq!(&monitor_name.to_string(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1");
///
/// // v2 channel
/// let channel_id = ChannelId(<[u8; 32]>::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap());
/// let monitor_name = MonitorName::V2Channel(channel_id);
/// assert_eq!(&monitor_name.to_string(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
///
/// // Using MonitorName to generate a storage key
/// let storage_key = format!("channel_monitors/{}", monitor_name);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MonitorName {
	/// The outpoint of the channel's funding transaction.
	V1Channel(OutPoint),

	/// The id of the channel produced by [`ChannelId::v2_from_revocation_basepoints`].
	V2Channel(ChannelId),
}

impl MonitorName {
	/// Attempts to construct a `MonitorName` from a storage key returned by [`KVStoreSync::list`].
	///
	/// This is useful when you need to reconstruct the original data the key represents.
	fn from_str(monitor_key: &str) -> Result<Self, io::Error> {
		let mut parts = monitor_key.splitn(2, '_');
		let id = parts
			.next()
			.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty stored key"))?;

		if let Some(part) = parts.next() {
			let txid = Txid::from_str(id).map_err(|_| {
				io::Error::new(io::ErrorKind::InvalidData, "Invalid tx ID in stored key")
			})?;
			let index: u16 = part.parse().map_err(|_| {
				io::Error::new(io::ErrorKind::InvalidData, "Invalid tx index in stored key")
			})?;
			let outpoint = OutPoint { txid, index };
			Ok(MonitorName::V1Channel(outpoint))
		} else {
			let bytes = <[u8; 32]>::from_hex(id).map_err(|_| {
				io::Error::new(io::ErrorKind::InvalidData, "Invalid channel ID in stored key")
			})?;
			Ok(MonitorName::V2Channel(ChannelId(bytes)))
		}
	}
}

impl core::fmt::Display for MonitorName {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		match self {
			MonitorName::V1Channel(outpoint) => {
				write!(f, "{}_{}", outpoint.txid, outpoint.index)
			},
			MonitorName::V2Channel(channel_id) => {
				write!(f, "{}", channel_id)
			},
		}
	}
}

/// A struct representing a name for a channel monitor update.
///
/// [`UpdateName`] is primarily used within the [`MonitorUpdatingPersister`] in
/// functions that store or retrieve partial updates to channel monitors. It
/// provides a consistent way to generate and parse unique identifiers for
/// monitor updates based on their sequence number.
///
/// The name is derived from the update's sequence ID, which is a monotonically
/// increasing u64 value. This format allows for easy ordering of updates and
/// efficient storage and retrieval in key-value stores.
///
/// # Usage
///
/// While users of the Lightning Dev Kit library generally won't need to
/// interact with `UpdateName` directly, it still can be useful for custom
/// persistence implementations. The u64 value is the update_id that can be
/// compared with [ChannelMonitor::get_latest_update_id] to check if this update
/// has been applied to the channel monitor or not, which is useful for pruning
/// stale channel monitor updates off persistence.
///
/// # Examples
///
/// ```
/// use lightning::util::persist::UpdateName;
///
/// let update_id: u64 = 42;
/// let update_name = UpdateName::from(update_id);
/// assert_eq!(update_name.as_str(), "42");
///
/// // Using UpdateName to generate a storage key
/// let monitor_name = "some_monitor_name";
/// let storage_key = format!("channel_monitor_updates/{}/{}", monitor_name, update_name.as_str());
/// ```
#[derive(Debug)]
pub struct UpdateName(pub u64, String);

impl UpdateName {
	/// Constructs an [`UpdateName`], after verifying that an update sequence ID
	/// can be derived from the given `name`.
	pub fn new(name: String) -> Result<Self, io::Error> {
		match name.parse::<u64>() {
			Ok(u) => Ok(u.into()),
			Err(_) => {
				Err(io::Error::new(io::ErrorKind::InvalidData, "cannot parse u64 from update name"))
			},
		}
	}

	/// Convert this update name to a string slice.
	///
	/// This method is particularly useful when you need to use the update name
	/// as part of a key in a key-value store or when logging.
	///
	/// # Examples
	///
	/// ```
	/// use lightning::util::persist::UpdateName;
	///
	/// let update_name = UpdateName::from(42);
	/// assert_eq!(update_name.as_str(), "42");
	/// ```
	pub fn as_str(&self) -> &str {
		&self.1
	}
}

impl From<u64> for UpdateName {
	/// Creates an `UpdateName` from a `u64`.
	///
	/// This is typically used when you need to generate a storage key or
	/// identifier
	/// for a new channel monitor update.
	///
	/// # Examples
	///
	/// ```
	/// use lightning::util::persist::UpdateName;
	///
	/// let update_id: u64 = 42;
	/// let update_name = UpdateName::from(update_id);
	/// assert_eq!(update_name.as_str(), "42");
	/// ```
	fn from(value: u64) -> Self {
		Self(value, value.to_string())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::chain::ChannelMonitorUpdateStatus;
	use crate::events::ClosureReason;
	use crate::ln::functional_test_utils::*;
	use crate::ln::msgs::BaseMessageHandler;
	use crate::sync::Arc;
	use crate::util::test_channel_signer::TestChannelSigner;
	use crate::util::test_utils::{self, TestStore};
	use crate::{check_added_monitors, check_closed_broadcast};
	use bitcoin::hashes::hex::FromHex;
	use core::cmp;

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
	fn creates_monitor_from_outpoint() {
		let monitor_name = MonitorName::V1Channel(OutPoint {
			txid: Txid::from_str(
				"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			)
			.unwrap(),
			index: 1,
		});
		assert_eq!(
			&monitor_name.to_string(),
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1"
		);

		let monitor_name = MonitorName::V1Channel(OutPoint {
			txid: Txid::from_str(
				"f33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeef",
			)
			.unwrap(),
			index: u16::MAX,
		});
		assert_eq!(
			&monitor_name.to_string(),
			"f33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeeff33dbeef_65535"
		);
	}

	#[test]
	fn creates_monitor_from_channel_id() {
		let monitor_name = MonitorName::V2Channel(ChannelId(
			<[u8; 32]>::from_hex(
				"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			)
			.unwrap(),
		));
		assert_eq!(
			&monitor_name.to_string(),
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		);
	}

	#[test]
	fn fails_parsing_monitor_name() {
		assert!(MonitorName::from_str(
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_"
		)
		.is_err());
		assert!(MonitorName::from_str(
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_65536"
		)
		.is_err());
		assert!(MonitorName::from_str(
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_21"
		)
		.is_err());
	}

	// Exercise the `MonitorUpdatingPersister` with real channels and payments.
	fn do_persister_with_real_monitors(max_pending_updates_0: u64, max_pending_updates_1: u64) {
		let chanmon_cfgs = create_chanmon_cfgs(4);
		let kv_store_0 = TestStore::new(false);
		let persister_0 = MonitorUpdatingPersister::new(
			&kv_store_0,
			&chanmon_cfgs[0].logger,
			max_pending_updates_0,
			&chanmon_cfgs[0].keys_manager,
			&chanmon_cfgs[0].keys_manager,
			&chanmon_cfgs[0].tx_broadcaster,
			&chanmon_cfgs[0].fee_estimator,
		);
		let kv_store_1 = TestStore::new(false);
		let persister_1 = MonitorUpdatingPersister::new(
			&kv_store_1,
			&chanmon_cfgs[1].logger,
			max_pending_updates_1,
			&chanmon_cfgs[1].keys_manager,
			&chanmon_cfgs[1].keys_manager,
			&chanmon_cfgs[1].tx_broadcaster,
			&chanmon_cfgs[1].fee_estimator,
		);
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

		// Check that the persisted channel data is empty before any channels are
		// open.
		let mut persisted_chan_data_0 =
			persister_0.read_all_channel_monitors_with_updates().unwrap();
		assert_eq!(persisted_chan_data_0.len(), 0);
		let mut persisted_chan_data_1 =
			persister_1.read_all_channel_monitors_with_updates().unwrap();
		assert_eq!(persisted_chan_data_1.len(), 0);

		// Helper to make sure the channel is on the expected update ID.
		macro_rules! check_persisted_data {
			($expected_update_id: expr) => {
				persisted_chan_data_0 =
					persister_0.read_all_channel_monitors_with_updates().unwrap();
				// check that we stored only one monitor
				assert_eq!(persisted_chan_data_0.len(), 1);
				for (_, mon) in persisted_chan_data_0.iter() {
					// check that when we read it, we got the right update id
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);

					let monitor_name = mon.persistence_key();
					let expected_updates = if max_pending_updates_0 == 0 {
						0
					} else {
						mon.get_latest_update_id() % max_pending_updates_0
					};
					let update_list = KVStoreSync::list(
						&kv_store_0,
						CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
						&monitor_name.to_string(),
					);
					assert_eq!(update_list.unwrap().len() as u64, expected_updates, "persister 0");
				}
				persisted_chan_data_1 =
					persister_1.read_all_channel_monitors_with_updates().unwrap();
				assert_eq!(persisted_chan_data_1.len(), 1);
				for (_, mon) in persisted_chan_data_1.iter() {
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);
					let monitor_name = mon.persistence_key();
					let expected_updates = if max_pending_updates_1 == 0 {
						0
					} else {
						mon.get_latest_update_id() % max_pending_updates_1
					};
					let update_list = KVStoreSync::list(
						&kv_store_1,
						CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
						&monitor_name.to_string(),
					);
					assert_eq!(update_list.unwrap().len() as u64, expected_updates, "persister 1");
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
		for i in 3..=max_pending_updates_0 * 2 {
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

		let node_id_1 = nodes[1].node.get_our_node_id();
		let chan_id = nodes[0].node.list_channels()[0].channel_id;
		let message = "Channel force-closed".to_owned();
		nodes[0]
			.node
			.force_close_broadcasting_latest_txn(&chan_id, &node_id_1, message.clone())
			.unwrap();

		let reason =
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[0], 1, reason, false, &[node_id_1], 100000);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors!(nodes[0], 1);

		let node_txn = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(node_txn.len(), 1);
		let txn = vec![node_txn[0].clone(), node_txn[0].clone()];
		let dummy_block = create_dummy_block(nodes[0].best_block_hash(), 42, txn);
		connect_block(&nodes[1], &dummy_block);

		check_closed_broadcast!(nodes[1], true);
		let reason = ClosureReason::CommitmentTxConfirmed;
		let node_id_0 = nodes[0].node.get_our_node_id();
		check_closed_event(&nodes[1], 1, reason, false, &[node_id_0], 100000);
		check_added_monitors!(nodes[1], 1);

		// Make sure everything is persisted as expected after close.
		// We always send at least two payments, and loop up to max_pending_updates_0 * 2.
		check_persisted_data!(
			cmp::max(2, max_pending_updates_0 * 2) * EXPECTED_UPDATES_PER_PAYMENT + 1
		);
	}

	#[test]
	fn persister_with_real_monitors() {
		do_persister_with_real_monitors(7, 3);
		do_persister_with_real_monitors(0, 1);
		do_persister_with_real_monitors(4, 2);
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

		let message = "Channel force-closed".to_owned();
		let node_id_0 = nodes[0].node.get_our_node_id();
		nodes[1]
			.node
			.force_close_broadcasting_latest_txn(&chan.2, &node_id_0, message.clone())
			.unwrap();
		let reason =
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[1], 1, reason, false, &[node_id_0], 100000);

		{
			let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
			let cmu_map = nodes[1].chain_monitor.monitor_updates.lock().unwrap();
			let cmu = &cmu_map.get(&added_monitors[0].1.channel_id()).unwrap()[0];

			let store = TestStore::new(true);
			let ro_persister = MonitorUpdatingPersister::new(
				&store,
				node_cfgs[0].logger,
				11,
				node_cfgs[0].keys_manager,
				node_cfgs[0].keys_manager,
				node_cfgs[0].tx_broadcaster,
				node_cfgs[0].fee_estimator,
			);
			let monitor_name = added_monitors[0].1.persistence_key();
			match ro_persister.persist_new_channel(monitor_name, &added_monitors[0].1) {
				ChannelMonitorUpdateStatus::UnrecoverableError => {
					// correct result
				},
				ChannelMonitorUpdateStatus::Completed => {
					panic!("Completed persisting new channel when shouldn't have")
				},
				ChannelMonitorUpdateStatus::InProgress => {
					panic!("Returned InProgress when shouldn't have")
				},
			}
			match ro_persister.update_persisted_channel(
				monitor_name,
				Some(cmu),
				&added_monitors[0].1,
			) {
				ChannelMonitorUpdateStatus::UnrecoverableError => {
					// correct result
				},
				ChannelMonitorUpdateStatus::Completed => {
					panic!("Completed persisting new channel when shouldn't have")
				},
				ChannelMonitorUpdateStatus::InProgress => {
					panic!("Returned InProgress when shouldn't have")
				},
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
		let kv_store_0 = TestStore::new(false);
		let persister_0 = MonitorUpdatingPersister::new(
			&kv_store_0,
			&chanmon_cfgs[0].logger,
			test_max_pending_updates,
			&chanmon_cfgs[0].keys_manager,
			&chanmon_cfgs[0].keys_manager,
			&chanmon_cfgs[0].tx_broadcaster,
			&chanmon_cfgs[0].fee_estimator,
		);
		let kv_store_1 = TestStore::new(false);
		let persister_1 = MonitorUpdatingPersister::new(
			&kv_store_1,
			&chanmon_cfgs[1].logger,
			test_max_pending_updates,
			&chanmon_cfgs[1].keys_manager,
			&chanmon_cfgs[1].keys_manager,
			&chanmon_cfgs[1].tx_broadcaster,
			&chanmon_cfgs[1].fee_estimator,
		);
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

		// Check that the persisted channel data is empty before any channels are
		// open.
		let persisted_chan_data = persister_0.read_all_channel_monitors_with_updates().unwrap();
		assert_eq!(persisted_chan_data.len(), 0);

		// Create some initial channel
		let _ = create_announced_chan_between_nodes(&nodes, 0, 1);

		// Send a few payments to advance the updates a bit
		send_payment(&nodes[0], &vec![&nodes[1]][..], 8_000_000);
		send_payment(&nodes[1], &vec![&nodes[0]][..], 4_000_000);

		// Get the monitor and make a fake stale update at update_id=1 (lowest height of an update possible)
		let persisted_chan_data = persister_0.read_all_channel_monitors_with_updates().unwrap();
		let (_, monitor) = &persisted_chan_data[0];
		let monitor_name = monitor.persistence_key();
		KVStoreSync::write(
			&kv_store_0,
			CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
			&monitor_name.to_string(),
			UpdateName::from(1).as_str(),
			vec![0u8; 1],
		)
		.unwrap();

		// Do the stale update cleanup
		persister_0.cleanup_stale_updates().unwrap();

		// Confirm the stale update is unreadable/gone
		assert!(KVStoreSync::read(
			&kv_store_0,
			CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
			&monitor_name.to_string(),
			UpdateName::from(1).as_str()
		)
		.is_err());
	}

	fn persist_fn<P: Deref, ChannelSigner: EcdsaChannelSigner>(_persist: P) -> bool
	where
		P::Target: Persist<ChannelSigner>,
	{
		true
	}

	#[test]
	fn kvstore_trait_object_usage() {
		let store: Arc<dyn KVStoreSync + Send + Sync> = Arc::new(TestStore::new(false));
		assert!(persist_fn::<_, TestChannelSigner>(Arc::clone(&store)));
	}
}
