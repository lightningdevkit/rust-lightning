//! Objects related to [`FilesystemStore`] live here.
use crate::fs_store::common::FilesystemStoreState;

use lightning::util::persist::{KVStoreSync, MigratableKVStoreSync};

use std::path::PathBuf;

#[cfg(feature = "tokio")]
use core::future::Future;
#[cfg(feature = "tokio")]
use lightning::util::persist::KVStore;

/// A [`KVStore`] and [`KVStoreSync`] implementation that writes to and reads from the file system.
///
/// [`KVStore`]: lightning::util::persist::KVStore
pub struct FilesystemStore {
	state: FilesystemStoreState,
}

impl FilesystemStore {
	/// Constructs a new [`FilesystemStore`].
	pub fn new(data_dir: PathBuf) -> Self {
		Self { state: FilesystemStoreState::new(data_dir) }
	}

	/// Returns the data directory.
	pub fn get_data_dir(&self) -> PathBuf {
		self.state.get_data_dir()
	}

	#[cfg(any(all(feature = "tokio", test), fuzzing))]
	/// Returns the size of the async state.
	pub fn state_size(&self) -> usize {
		self.state.state_size()
	}
}

impl KVStoreSync for FilesystemStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Result<Vec<u8>, lightning::io::Error> {
		self.state.read_impl(primary_namespace, secondary_namespace, key, false)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> Result<(), lightning::io::Error> {
		self.state.write_impl(primary_namespace, secondary_namespace, key, buf, false)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> Result<(), lightning::io::Error> {
		self.state.remove_impl(primary_namespace, secondary_namespace, key, lazy, false)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> Result<Vec<String>, lightning::io::Error> {
		self.state.list_impl(primary_namespace, secondary_namespace, false)
	}
}

#[cfg(feature = "tokio")]
impl KVStore for FilesystemStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> impl Future<Output = Result<Vec<u8>, lightning::io::Error>> + 'static + Send {
		self.state.read_async(primary_namespace, secondary_namespace, key, false)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		self.state.write_async(primary_namespace, secondary_namespace, key, buf, false)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		self.state.remove_async(primary_namespace, secondary_namespace, key, lazy, false)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> impl Future<Output = Result<Vec<String>, lightning::io::Error>> + 'static + Send {
		self.state.list_async(primary_namespace, secondary_namespace, false)
	}
}

impl MigratableKVStoreSync for FilesystemStore {
	fn list_all_keys(&self) -> Result<Vec<(String, String, String)>, lightning::io::Error> {
		self.state.list_all_keys_impl(false)
	}
}

#[cfg(feature = "tokio")]
impl lightning::util::persist::MigratableKVStore for FilesystemStore {
	fn list_all_keys(
		&self,
	) -> impl Future<Output = Result<Vec<(String, String, String)>, lightning::io::Error>> + 'static + Send
	{
		self.state.list_all_keys_async(false)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[cfg(feature = "tokio")]
	use crate::test_utils::do_test_data_migration_async;
	use crate::test_utils::{
		do_list_error_propagation, do_read_write_remove_list_persist, do_test_data_migration,
		do_test_store,
	};

	use lightning::chain::chainmonitor::Persist;
	use lightning::chain::ChannelMonitorUpdateStatus;
	use lightning::events::ClosureReason;
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::BaseMessageHandler;
	use lightning::util::persist::read_channel_monitors;
	use lightning::util::test_utils;

	use std::fs;

	impl Drop for FilesystemStore {
		fn drop(&mut self) {
			// We test for invalid directory names, so it's OK if directory removal
			// fails.
			match fs::remove_dir_all(&self.get_data_dir()) {
				Err(e) => println!("Failed to remove test persister directory: {}", e),
				_ => {},
			}
		}
	}

	#[test]
	fn read_write_remove_list_persist() {
		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_read_write_remove_list_persist");
		let fs_store = FilesystemStore::new(temp_path);
		do_read_write_remove_list_persist(&fs_store);
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn read_write_remove_list_persist_async() {
		use lightning::util::persist::KVStore;
		use std::sync::Arc;

		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_read_write_remove_list_persist_async");
		let fs_store = Arc::new(FilesystemStore::new(temp_path));
		assert_eq!(fs_store.state_size(), 0);

		let async_fs_store = Arc::clone(&fs_store);

		let data1 = vec![42u8; 32];
		let data2 = vec![43u8; 32];

		let primary = "testspace";
		let secondary = "testsubspace";
		let key = "testkey";

		// Test writing the same key twice with different data. Execute the asynchronous part out of order to ensure
		// that eventual consistency works.
		let fut1 = KVStore::write(&*async_fs_store, primary, secondary, key, data1);
		assert_eq!(fs_store.state_size(), 1);

		let fut2 = KVStore::remove(&*async_fs_store, primary, secondary, key, false);
		assert_eq!(fs_store.state_size(), 1);

		let fut3 = KVStore::write(&*async_fs_store, primary, secondary, key, data2.clone());
		assert_eq!(fs_store.state_size(), 1);

		fut3.await.unwrap();
		assert_eq!(fs_store.state_size(), 1);

		fut2.await.unwrap();
		assert_eq!(fs_store.state_size(), 1);

		fut1.await.unwrap();
		assert_eq!(fs_store.state_size(), 0);

		// Test list.
		let listed_keys = KVStore::list(&*async_fs_store, primary, secondary).await.unwrap();
		assert_eq!(listed_keys.len(), 1);
		assert_eq!(listed_keys[0], key);

		// Test read. We expect to read data2, as the write call was initiated later.
		let read_data = KVStore::read(&*async_fs_store, primary, secondary, key).await.unwrap();
		assert_eq!(data2, &*read_data);

		// Test remove.
		KVStore::remove(&*async_fs_store, primary, secondary, key, false).await.unwrap();

		let listed_keys = KVStore::list(&*async_fs_store, primary, secondary).await.unwrap();
		assert_eq!(listed_keys.len(), 0);
	}

	#[test]
	fn list_error_propagation() {
		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_list_error_propagation");
		let fs_store = FilesystemStore::new(temp_path.clone());
		do_list_error_propagation(&fs_store, &temp_path);
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn list_error_propagation_async() {
		use crate::test_utils::do_list_error_propagation_async;
		use lightning::util::persist::KVStore;

		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_list_error_propagation_async");
		let fs_store = FilesystemStore::new(temp_path.clone());

		// A missing data directory or namespace lists as empty.
		assert!(KVStore::list(&fs_store, "missingprimary", "missingsecondary")
			.await
			.unwrap()
			.is_empty());

		do_list_error_propagation_async(&fs_store, &temp_path).await;
	}

	#[test]
	fn list_all_keys_skips_leftover_store_artifacts() {
		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_list_all_keys_skips_leftover_store_artifacts");
		let fs_store = FilesystemStore::new(temp_path.clone());
		KVStoreSync::write(&fs_store, "primary", "secondary", "key", vec![1]).unwrap();

		fs::write(temp_path.join("top_level.0.tmp"), b"stale").unwrap();
		fs::write(temp_path.join("top_level.0.trash"), b"stale").unwrap();

		let primary_path = temp_path.join("primary");
		fs::write(primary_path.join("primary_level.0.tmp"), b"stale").unwrap();
		fs::write(primary_path.join("primary_level.0.trash"), b"stale").unwrap();

		let secondary_path = primary_path.join("secondary");
		fs::write(secondary_path.join("secondary_level.0.tmp"), b"stale").unwrap();
		fs::write(secondary_path.join("secondary_level.0.trash"), b"stale").unwrap();

		let keys = fs_store.list_all_keys().unwrap();
		assert_eq!(keys, vec![("primary".to_string(), "secondary".to_string(), "key".to_string())]);
	}

	#[test]
	fn test_data_migration() {
		let mut source_temp_path = std::env::temp_dir();
		source_temp_path.push("test_data_migration_source");
		let mut source_store = FilesystemStore::new(source_temp_path);

		let mut target_temp_path = std::env::temp_dir();
		target_temp_path.push("test_data_migration_target");
		let mut target_store = FilesystemStore::new(target_temp_path);

		do_test_data_migration(&mut source_store, &mut target_store);
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_data_migration_async() {
		let mut source_temp_path = std::env::temp_dir();
		source_temp_path.push("test_data_migration_source_async");
		let source_store = FilesystemStore::new(source_temp_path);

		let mut target_temp_path = std::env::temp_dir();
		target_temp_path.push("test_data_migration_target_async");
		let target_store = FilesystemStore::new(target_temp_path);

		do_test_data_migration_async(&source_store, &target_store).await;
	}

	#[test]
	fn test_if_monitors_is_not_dir() {
		let store = FilesystemStore::new("test_monitors_is_not_dir".into());

		fs::create_dir_all(&store.get_data_dir()).unwrap();
		let mut path = std::path::PathBuf::from(&store.get_data_dir());
		path.push("monitors");
		fs::File::create(path).unwrap();

		let chanmon_cfgs = create_chanmon_cfgs(1);
		let mut node_cfgs = create_node_cfgs(1, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(
			Some(&chanmon_cfgs[0].chain_source),
			&chanmon_cfgs[0].tx_broadcaster,
			&chanmon_cfgs[0].logger,
			&chanmon_cfgs[0].fee_estimator,
			&store,
			node_cfgs[0].keys_manager,
		);
		node_cfgs[0].chain_monitor = chain_mon_0;
		let node_chanmgrs = create_node_chanmgrs(1, &node_cfgs, &[None]);
		let nodes = create_network(1, &node_cfgs, &node_chanmgrs);

		// Check that read_channel_monitors() returns error if monitors/ is not a
		// directory.
		assert!(
			read_channel_monitors(&store, nodes[0].keys_manager, nodes[0].keys_manager).is_err()
		);
	}

	// Test that recovery of a stored monitor propagates a failure to enumerate its
	// stored updates, rather than treating the namespace as empty and silently
	// recovering an outdated monitor. Windows ignores the read-only flag for
	// directories, so this test is Unix-only.
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn monitor_recovery_fails_when_update_listing_fails() {
		use lightning::util::persist::MonitorUpdatingPersister;
		use std::os::unix::fs::PermissionsExt;

		// Use a path in the system temporary directory, so that a failure partway
		// through this test does not leave a directory with restricted permissions
		// behind in the working tree.
		let mut data_dir = std::env::temp_dir();
		data_dir.push("test_monitor_recovery_update_listing_failure");
		let store = FilesystemStore::new(data_dir);
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let persister = MonitorUpdatingPersister::new(
			&store,
			&chanmon_cfgs[0].logger,
			11,
			&chanmon_cfgs[0].keys_manager,
			&chanmon_cfgs[0].keys_manager,
			&chanmon_cfgs[0].tx_broadcaster,
			&chanmon_cfgs[0].fee_estimator,
		);
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(
			Some(&chanmon_cfgs[0].chain_source),
			&chanmon_cfgs[0].tx_broadcaster,
			&chanmon_cfgs[0].logger,
			&chanmon_cfgs[0].fee_estimator,
			&persister,
			node_cfgs[0].keys_manager,
		);
		node_cfgs[0].chain_monitor = chain_mon_0;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let _ = create_announced_chan_between_nodes(&nodes, 0, 1);
		send_payment(&nodes[0], &vec![&nodes[1]][..], 8_000_000);

		// The stored monitor recovers, applying its stored differential updates.
		let monitors = persister.read_all_channel_monitors_with_updates().unwrap();
		assert_eq!(monitors.len(), 1);
		let latest_update_id = monitors[0].1.get_latest_update_id();
		assert!(latest_update_id > 0);
		let monitor_key = monitors[0].1.persistence_key().to_string();

		// The base monitor remains readable, but looking up the namespace holding its
		// stored updates fails, which recovery must propagate rather than treat as an
		// empty update list.
		let updates_path = store.get_data_dir().join("monitor_updates");
		let restore_paths = [&updates_path];
		let _restore_permissions = crate::test_utils::RestorePermissions(&restore_paths);
		fs::set_permissions(&updates_path, fs::Permissions::from_mode(0o0)).unwrap();
		if fs::read_dir(updates_path.join(&monitor_key)).is_ok() {
			// The effective privileges (e.g., running as root) bypass the permission
			// check, so the failure case cannot be exercised; restore access and skip it.
			fs::set_permissions(&updates_path, fs::Permissions::from_mode(0o755)).unwrap();
			return;
		}
		assert!(persister.read_all_channel_monitors_with_updates().is_err());

		// With access restored, recovery again succeeds and applies the updates.
		fs::set_permissions(&updates_path, fs::Permissions::from_mode(0o755)).unwrap();
		let monitors = persister.read_all_channel_monitors_with_updates().unwrap();
		assert_eq!(monitors[0].1.get_latest_update_id(), latest_update_id);
	}

	#[test]
	fn test_filesystem_store() {
		// Create the nodes, giving them FilesystemStores for data stores.
		let store_0 = FilesystemStore::new("test_filesystem_store_0".into());
		let store_1 = FilesystemStore::new("test_filesystem_store_1".into());
		do_test_store(&store_0, &store_1)
	}

	// Test that if the store's path to channel data is read-only, writing a
	// monitor to it results in the store returning an UnrecoverableError.
	// Windows ignores the read-only flag for folders, so this test is Unix-only.
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn test_readonly_dir_perm_failure() {
		let store = FilesystemStore::new("test_readonly_dir_perm_failure".into());
		fs::create_dir_all(&store.get_data_dir()).unwrap();

		// Set up a dummy channel and force close. This will produce a monitor
		// that we can then use to test persistence.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let node_a_id = nodes[0].node.get_our_node_id();

		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

		let message = "Channel force-closed".to_owned();
		nodes[1]
			.node
			.force_close_broadcasting_latest_txn(&chan.2, &node_a_id, message.clone())
			.unwrap();
		let reason =
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();

		// Set the store's directory to read-only, which should result in
		// returning an unrecoverable failure when we then attempt to persist a
		// channel update.
		let path = &store.get_data_dir();
		let mut perms = fs::metadata(path).unwrap().permissions();
		perms.set_readonly(true);
		fs::set_permissions(path, perms).unwrap();

		let monitor_name = added_monitors[0].1.persistence_key();
		match store.persist_new_channel(monitor_name, &added_monitors[0].1) {
			ChannelMonitorUpdateStatus::UnrecoverableError => {},
			_ => panic!("unexpected result from persisting new channel"),
		}

		nodes[1].node.get_and_clear_pending_msg_events();
		added_monitors.clear();
	}

	// Test that if a store's directory name is invalid, monitor persistence
	// will fail.
	#[cfg(target_os = "windows")]
	#[test]
	fn test_fail_on_open() {
		// Set up a dummy channel and force close. This will produce a monitor
		// that we can then use to test persistence.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		let node_a_id = nodes[0].node.get_our_node_id();

		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

		let message = "Channel force-closed".to_owned();
		nodes[1]
			.node
			.force_close_broadcasting_latest_txn(&chan.2, &node_a_id, message.clone())
			.unwrap();
		let reason =
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		let update_map = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap();
		let update_id = update_map.get(&added_monitors[0].1.channel_id()).unwrap();

		// Create the store with an invalid directory name and test that the
		// channel fails to open because the directories fail to be created. There
		// don't seem to be invalid filename characters on Unix that Rust doesn't
		// handle, hence why the test is Windows-only.
		let store = FilesystemStore::new(":<>/".into());

		let monitor_name = added_monitors[0].1.persistence_key();
		match store.persist_new_channel(monitor_name, &added_monitors[0].1) {
			ChannelMonitorUpdateStatus::UnrecoverableError => {},
			_ => panic!("unexpected result from persisting new channel"),
		}

		nodes[1].node.get_and_clear_pending_msg_events();
		added_monitors.clear();
	}
}

#[cfg(ldk_bench)]
/// Benches
pub mod bench {
	use criterion::Criterion;

	/// Bench!
	pub fn bench_sends(bench: &mut Criterion) {
		let store_a = super::FilesystemStore::new("bench_filesystem_store_a".into());
		let store_b = super::FilesystemStore::new("bench_filesystem_store_b".into());
		lightning::ln::channelmanager::bench::bench_two_sends(
			bench,
			"bench_filesystem_persisted_sends",
			store_a,
			store_b,
		);
	}
}
