use lightning::events::ClosureReason;
use lightning::ln::functional_test_utils::*;
use lightning::util::persist::{
	migrate_kv_store_data, read_channel_monitors, KVStoreSync, MigratableKVStoreSync,
	KVSTORE_NAMESPACE_KEY_ALPHABET, KVSTORE_NAMESPACE_KEY_MAX_LEN,
};
use lightning::util::test_utils;

use std::panic::RefUnwindSafe;

pub(crate) fn do_read_write_remove_list_persist<K: KVStoreSync + RefUnwindSafe>(kv_store: &K) {
	let data = vec![42u8; 32];

	let primary_namespace = "testspace";
	let secondary_namespace = "testsubspace";
	let key = "testkey";

	// Test the basic KVStore operations.
	kv_store.write(primary_namespace, secondary_namespace, key, data.clone()).unwrap();

	// Test empty primary_namespace/secondary_namespace is allowed, but not empty primary_namespace
	// and non-empty secondary_namespace, and not empty key.
	kv_store.write("", "", key, data.clone()).unwrap();
	let res =
		std::panic::catch_unwind(|| kv_store.write("", secondary_namespace, key, data.clone()));
	assert!(res.is_err());
	let res = std::panic::catch_unwind(|| {
		kv_store.write(primary_namespace, secondary_namespace, "", data.clone())
	});
	assert!(res.is_err());

	let listed_keys = kv_store.list(primary_namespace, secondary_namespace).unwrap();
	assert_eq!(listed_keys.len(), 1);
	assert_eq!(listed_keys[0], key);

	let read_data = kv_store.read(primary_namespace, secondary_namespace, key).unwrap();
	assert_eq!(data, &*read_data);

	kv_store.remove(primary_namespace, secondary_namespace, key, false).unwrap();

	let listed_keys = kv_store.list(primary_namespace, secondary_namespace).unwrap();
	assert_eq!(listed_keys.len(), 0);

	// Ensure we have no issue operating with primary_namespace/secondary_namespace/key being
	// KVSTORE_NAMESPACE_KEY_MAX_LEN
	let max_chars = "A".repeat(KVSTORE_NAMESPACE_KEY_MAX_LEN);
	kv_store.write(&max_chars, &max_chars, &max_chars, data.clone()).unwrap();

	let listed_keys = kv_store.list(&max_chars, &max_chars).unwrap();
	assert_eq!(listed_keys.len(), 1);
	assert_eq!(listed_keys[0], max_chars);

	let read_data = kv_store.read(&max_chars, &max_chars, &max_chars).unwrap();
	assert_eq!(data, &*read_data);

	kv_store.remove(&max_chars, &max_chars, &max_chars, false).unwrap();

	let listed_keys = kv_store.list(&max_chars, &max_chars).unwrap();
	assert_eq!(listed_keys.len(), 0);
}

fn data_migration_test_keys() -> Vec<(String, String, String)> {
	let num_primary_namespaces = 3;
	let num_secondary_namespaces = 3;
	let num_keys = 3;
	let mut keys = Vec::new();
	for i in 0..num_primary_namespaces {
		let primary_namespace = if i == 0 {
			String::new()
		} else {
			format!("testspace{}", KVSTORE_NAMESPACE_KEY_ALPHABET.chars().nth(i).unwrap())
		};
		for j in 0..num_secondary_namespaces {
			let secondary_namespace = if i == 0 || j == 0 {
				String::new()
			} else {
				format!("testsubspace{}", KVSTORE_NAMESPACE_KEY_ALPHABET.chars().nth(j).unwrap())
			};
			for k in 0..num_keys {
				let key =
					format!("testkey{}", KVSTORE_NAMESPACE_KEY_ALPHABET.chars().nth(k).unwrap());
				keys.push((primary_namespace.clone(), secondary_namespace.clone(), key));
			}
		}
	}

	keys
}

pub(crate) fn do_test_data_migration<S: MigratableKVStoreSync, T: MigratableKVStoreSync>(
	source_store: &mut S, target_store: &mut T,
) {
	// We fill the source with some bogus keys.
	let dummy_data = vec![42u8; 32];
	let mut expected_keys = data_migration_test_keys();
	for (primary_namespace, secondary_namespace, key) in &expected_keys {
		source_store
			.write(primary_namespace, secondary_namespace, key, dummy_data.clone())
			.unwrap();
	}
	expected_keys.sort();
	expected_keys.dedup();

	let mut source_list = source_store.list_all_keys().unwrap();
	source_list.sort();
	assert_eq!(source_list, expected_keys);

	migrate_kv_store_data(source_store, target_store).unwrap();

	let mut target_list = target_store.list_all_keys().unwrap();
	target_list.sort();
	assert_eq!(target_list, expected_keys);

	for (p, s, k) in expected_keys.iter() {
		assert_eq!(target_store.read(p, s, k).unwrap(), dummy_data.clone());
	}
}

#[cfg(feature = "tokio")]
pub(crate) async fn do_test_data_migration_async<
	S: lightning::util::persist::MigratableKVStore,
	T: lightning::util::persist::MigratableKVStore,
>(
	source_store: &S, target_store: &T,
) {
	use lightning::util::persist::{migrate_kv_store_data_async, KVStore, MigratableKVStore};

	// We fill the source with some bogus keys.
	let dummy_data = vec![42u8; 32];
	let mut expected_keys = data_migration_test_keys();
	for (primary_namespace, secondary_namespace, key) in &expected_keys {
		KVStore::write(
			source_store,
			primary_namespace,
			secondary_namespace,
			key,
			dummy_data.clone(),
		)
		.await
		.unwrap();
	}
	expected_keys.sort();
	expected_keys.dedup();

	let mut source_list = MigratableKVStore::list_all_keys(source_store).await.unwrap();
	source_list.sort();
	assert_eq!(source_list, expected_keys);

	migrate_kv_store_data_async(source_store, target_store).await.unwrap();

	let mut target_list = MigratableKVStore::list_all_keys(target_store).await.unwrap();
	target_list.sort();
	assert_eq!(target_list, expected_keys);

	for (p, s, k) in expected_keys.iter() {
		assert_eq!(KVStore::read(target_store, p, s, k).await.unwrap(), dummy_data.clone());
	}
}

// Restores read, write, and execute permissions on the given paths when dropped, so
// that a test failing partway through does not leave inaccessible directories behind.
#[cfg(not(target_os = "windows"))]
pub(crate) struct RestorePermissions<'a, P: AsRef<std::path::Path>>(pub(crate) &'a [P]);

#[cfg(not(target_os = "windows"))]
impl<P: AsRef<std::path::Path>> Drop for RestorePermissions<'_, P> {
	fn drop(&mut self) {
		use std::fs;
		use std::os::unix::fs::PermissionsExt;

		for path in self.0 {
			let _ = fs::set_permissions(path.as_ref(), fs::Permissions::from_mode(0o755));
		}
	}
}

// Check that listing a missing namespace succeeds with an empty result, while listing a
// populated namespace, a non-directory namespace path, and a namespace that cannot be
// looked up or enumerated behave as documented.
pub(crate) fn do_list_error_propagation<K: KVStoreSync + MigratableKVStoreSync>(
	kv_store: &K, data_dir: &std::path::Path,
) {
	use std::fs;

	// A missing data directory or namespace lists as empty.
	assert!(kv_store.list("missingprimary", "missingsecondary").unwrap().is_empty());
	assert!(kv_store.list_all_keys().unwrap().is_empty());

	// A populated namespace lists its keys through both listing paths.
	kv_store.write("primary", "secondary", "key", vec![1]).unwrap();
	assert_eq!(kv_store.list("primary", "secondary").unwrap(), vec!["key".to_string()]);
	assert_eq!(
		kv_store.list_all_keys().unwrap(),
		vec![("primary".to_string(), "secondary".to_string(), "key".to_string())]
	);

	// A namespace path that is not a directory fails to list rather than listing as empty.
	let primary_path = data_dir.join("notdirprimary");
	fs::create_dir_all(&primary_path).unwrap();
	fs::write(primary_path.join("notdirsecondary"), b"").unwrap();
	kv_store.list("notdirprimary", "notdirsecondary").unwrap_err();

	// A namespace whose lookup or enumeration fails fails to list rather than
	// listing as empty. Windows ignores the read-only flag for directories, so
	// this is Unix-only.
	#[cfg(not(target_os = "windows"))]
	{
		use std::os::unix::fs::PermissionsExt;

		let primary_path = data_dir.join("permprimary");
		let secondary_path = primary_path.join("permsecondary");
		kv_store.write("permprimary", "permsecondary", "key", vec![1]).unwrap();
		let restore_paths = [&primary_path, &secondary_path];
		let _restore_permissions = RestorePermissions(&restore_paths);

		// With the primary namespace inaccessible, listing the secondary namespace
		// fails to look the latter up.
		fs::set_permissions(&primary_path, fs::Permissions::from_mode(0o0)).unwrap();
		if fs::read_dir(&secondary_path).is_ok() {
			// The effective privileges (e.g., running as root) bypass the permission
			// check, so the failure case cannot be exercised; restore access and skip it.
			fs::set_permissions(&primary_path, fs::Permissions::from_mode(0o755)).unwrap();
		} else {
			kv_store.list("permprimary", "permsecondary").unwrap_err();

			// With the secondary namespace itself inaccessible, enumerating it fails,
			// both when listing it directly and as part of listing all keys.
			fs::set_permissions(&primary_path, fs::Permissions::from_mode(0o755)).unwrap();
			fs::set_permissions(&secondary_path, fs::Permissions::from_mode(0o0)).unwrap();
			kv_store.list("permprimary", "permsecondary").unwrap_err();
			kv_store.list_all_keys().unwrap_err();

			fs::set_permissions(&secondary_path, fs::Permissions::from_mode(0o755)).unwrap();
			assert!(kv_store.list("permprimary", "permsecondary").is_ok());
			assert!(kv_store.list_all_keys().is_ok());
		}
	}
}

#[cfg(feature = "tokio")]
pub(crate) async fn do_list_error_propagation_async<K: lightning::util::persist::KVStore>(
	kv_store: &K, data_dir: &std::path::Path,
) {
	use lightning::util::persist::KVStore;
	use std::fs;

	// A missing data directory or namespace lists as empty.
	assert!(KVStore::list(kv_store, "missingprimary", "missingsecondary")
		.await
		.unwrap()
		.is_empty());

	// A populated namespace lists its keys.
	KVStore::write(kv_store, "primary", "secondary", "key", vec![1]).await.unwrap();
	assert_eq!(
		KVStore::list(kv_store, "primary", "secondary").await.unwrap(),
		vec!["key".to_string()]
	);

	// A namespace path that is not a directory fails to list rather than listing as empty.
	let primary_path = data_dir.join("notdirprimaryasync");
	fs::create_dir_all(&primary_path).unwrap();
	fs::write(primary_path.join("notdirsecondary"), b"").unwrap();
	KVStore::list(kv_store, "notdirprimaryasync", "notdirsecondary").await.unwrap_err();

	// A namespace whose lookup or enumeration fails fails to list rather than
	// listing as empty. Windows ignores the read-only flag for directories, so
	// this is Unix-only.
	#[cfg(not(target_os = "windows"))]
	{
		use std::os::unix::fs::PermissionsExt;

		let primary_path = data_dir.join("permprimaryasync");
		let secondary_path = primary_path.join("permsecondary");
		KVStore::write(kv_store, "permprimaryasync", "permsecondary", "key", vec![1])
			.await
			.unwrap();
		let restore_paths = [&primary_path, &secondary_path];
		let _restore_permissions = RestorePermissions(&restore_paths);

		// With the primary namespace inaccessible, listing the secondary namespace
		// fails to look the latter up.
		fs::set_permissions(&primary_path, fs::Permissions::from_mode(0o0)).unwrap();
		if fs::read_dir(&secondary_path).is_ok() {
			// The effective privileges (e.g., running as root) bypass the permission
			// check, so the failure case cannot be exercised; restore access and skip it.
			fs::set_permissions(&primary_path, fs::Permissions::from_mode(0o755)).unwrap();
		} else {
			KVStore::list(kv_store, "permprimaryasync", "permsecondary").await.unwrap_err();

			// With the secondary namespace itself inaccessible, enumerating it fails.
			fs::set_permissions(&primary_path, fs::Permissions::from_mode(0o755)).unwrap();
			fs::set_permissions(&secondary_path, fs::Permissions::from_mode(0o0)).unwrap();
			KVStore::list(kv_store, "permprimaryasync", "permsecondary").await.unwrap_err();

			fs::set_permissions(&secondary_path, fs::Permissions::from_mode(0o755)).unwrap();
			assert!(KVStore::list(kv_store, "permprimaryasync", "permsecondary").await.is_ok());
		}
	}
}

// Integration-test the given KVStore implementation. Test relaying a few payments and check that
// the persisted data is updated the appropriate number of times.
pub(crate) fn do_test_store<K: KVStoreSync + Sync>(store_0: &K, store_1: &K) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let chain_mon_0 = test_utils::TestChainMonitor::new(
		Some(&chanmon_cfgs[0].chain_source),
		&chanmon_cfgs[0].tx_broadcaster,
		&chanmon_cfgs[0].logger,
		&chanmon_cfgs[0].fee_estimator,
		store_0,
		node_cfgs[0].keys_manager,
	);
	let chain_mon_1 = test_utils::TestChainMonitor::new(
		Some(&chanmon_cfgs[1].chain_source),
		&chanmon_cfgs[1].tx_broadcaster,
		&chanmon_cfgs[1].logger,
		&chanmon_cfgs[1].fee_estimator,
		store_1,
		node_cfgs[1].keys_manager,
	);
	node_cfgs[0].chain_monitor = chain_mon_0;
	node_cfgs[1].chain_monitor = chain_mon_1;
	let legacy_cfg = test_legacy_channel_config();
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(legacy_cfg.clone()), Some(legacy_cfg)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	// Check that the persisted channel data is empty before any channels are
	// open.
	let mut persisted_chan_data_0 =
		read_channel_monitors(store_0, nodes[0].keys_manager, nodes[0].keys_manager).unwrap();
	assert_eq!(persisted_chan_data_0.len(), 0);
	let mut persisted_chan_data_1 =
		read_channel_monitors(store_1, nodes[1].keys_manager, nodes[1].keys_manager).unwrap();
	assert_eq!(persisted_chan_data_1.len(), 0);

	// Helper to make sure the channel is on the expected update ID.
	macro_rules! check_persisted_data {
		($expected_update_id: expr) => {
			persisted_chan_data_0 =
				read_channel_monitors(store_0, nodes[0].keys_manager, nodes[0].keys_manager)
					.unwrap();
			assert_eq!(persisted_chan_data_0.len(), 1);
			for (_, mon) in persisted_chan_data_0.iter() {
				assert_eq!(mon.get_latest_update_id(), $expected_update_id);
			}
			persisted_chan_data_1 =
				read_channel_monitors(store_1, nodes[1].keys_manager, nodes[1].keys_manager)
					.unwrap();
			assert_eq!(persisted_chan_data_1.len(), 1);
			for (_, mon) in persisted_chan_data_1.iter() {
				assert_eq!(mon.get_latest_update_id(), $expected_update_id);
			}
		};
	}

	// Create some initial channel and check that a channel was persisted.
	let _ = create_announced_chan_between_nodes(&nodes, 0, 1);
	check_persisted_data!(0);

	// Send a few payments and make sure the monitors are updated to the latest.
	send_payment(&nodes[0], &vec![&nodes[1]][..], 8000000);
	check_persisted_data!(5);
	send_payment(&nodes[1], &vec![&nodes[0]][..], 4000000);
	check_persisted_data!(10);

	// Force close because cooperative close doesn't result in any persisted
	// updates.
	let message = "Channel force-closed".to_owned();
	let chan_id = nodes[0].node.list_channels()[0].channel_id;
	nodes[0]
		.node
		.force_close_broadcasting_latest_txn(&chan_id, &node_b_id, message.clone())
		.unwrap();
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);

	connect_block(
		&nodes[1],
		&create_dummy_block(
			nodes[0].best_block_hash(),
			42,
			vec![node_txn[0].clone(), node_txn[0].clone()],
		),
	);
	check_closed_broadcast(&nodes[1], 1, true);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[nodes[0].node.get_our_node_id()], 100000);
	check_added_monitors(&nodes[1], 1);

	// Make sure everything is persisted as expected after close.
	check_persisted_data!(11);
}
