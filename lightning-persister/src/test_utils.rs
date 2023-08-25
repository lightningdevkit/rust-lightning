use crate::fs_store::FilesystemStore;
use crate::sqlite_store::SqliteStore;

use lightning::util::persist::{KVStore, KVSTORE_NAMESPACE_KEY_MAX_LEN, read_channel_monitors};
use lightning::ln::functional_test_utils::{connect_block, create_announced_chan_between_nodes,
	create_chanmon_cfgs, create_dummy_block, create_network, create_node_cfgs, create_node_chanmgrs,
	send_payment};

use lightning::chain::channelmonitor::CLOSED_CHANNEL_UPDATE_ID;
use lightning::util::test_utils::{self, TestStore};
use lightning::{check_closed_broadcast, check_closed_event, check_added_monitors};
use lightning::events::ClosureReason;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use std::panic::RefUnwindSafe;
use std::path::PathBuf;

pub fn random_storage_path() -> PathBuf {
	let mut temp_path = std::env::temp_dir();
	let mut rng = thread_rng();
	let rand_dir: String = (0..7).map(|_| rng.sample(Alphanumeric) as char).collect();
	temp_path.push(rand_dir);
	temp_path
}

pub(crate) fn do_read_write_remove_list_persist<K: KVStore + RefUnwindSafe>(kv_store: &K) {
	let data = [42u8; 32];

	let primary_namespace = "testspace";
	let secondary_namespace = "testsubspace";
	let key = "testkey";

	// Test the basic KVStore operations.
	kv_store.write(primary_namespace, secondary_namespace, key, &data).unwrap();

	// Test empty primary_namespace/secondary_namespace is allowed, but not empty primary_namespace
	// and non-empty secondary_namespace, and not empty key.
	kv_store.write("", "", key, &data).unwrap();
	let res = std::panic::catch_unwind(|| kv_store.write("", secondary_namespace, key, &data));
	assert!(res.is_err());
	let res = std::panic::catch_unwind(|| kv_store.write(primary_namespace, secondary_namespace, "", &data));
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
	let max_chars: String = std::iter::repeat('A').take(KVSTORE_NAMESPACE_KEY_MAX_LEN).collect();
	kv_store.write(&max_chars, &max_chars, &max_chars, &data).unwrap();

	let listed_keys = kv_store.list(&max_chars, &max_chars).unwrap();
	assert_eq!(listed_keys.len(), 1);
	assert_eq!(listed_keys[0], max_chars);

	let read_data = kv_store.read(&max_chars, &max_chars, &max_chars).unwrap();
	assert_eq!(data, &*read_data);

	kv_store.remove(&max_chars, &max_chars, &max_chars, false).unwrap();

	let listed_keys = kv_store.list(&max_chars, &max_chars).unwrap();
	assert_eq!(listed_keys.len(), 0);
}

// Integration-test the given KVStore implementation. Test relaying a few payments and check that
// the persisted data is updated the appropriate number of times.
pub(crate) fn do_test_store<K: KVStore>(store_0: &K, store_1: &K) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let chain_mon_0 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, store_0, node_cfgs[0].keys_manager);
	let chain_mon_1 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[1].chain_source), &chanmon_cfgs[1].tx_broadcaster, &chanmon_cfgs[1].logger, &chanmon_cfgs[1].fee_estimator, store_1, node_cfgs[1].keys_manager);
	node_cfgs[0].chain_monitor = chain_mon_0;
	node_cfgs[1].chain_monitor = chain_mon_1;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Check that the persisted channel data is empty before any channels are
	// open.
	let mut persisted_chan_data_0 = read_channel_monitors(store_0, nodes[0].keys_manager, nodes[0].keys_manager).unwrap();
	assert_eq!(persisted_chan_data_0.len(), 0);
	let mut persisted_chan_data_1 = read_channel_monitors(store_1, nodes[1].keys_manager, nodes[1].keys_manager).unwrap();
	assert_eq!(persisted_chan_data_1.len(), 0);

	// Helper to make sure the channel is on the expected update ID.
	macro_rules! check_persisted_data {
		($expected_update_id: expr) => {
			persisted_chan_data_0 = read_channel_monitors(store_0, nodes[0].keys_manager, nodes[0].keys_manager).unwrap();
			assert_eq!(persisted_chan_data_0.len(), 1);
			for (_, mon) in persisted_chan_data_0.iter() {
				assert_eq!(mon.get_latest_update_id(), $expected_update_id);
			}
			persisted_chan_data_1 = read_channel_monitors(store_1, nodes[1].keys_manager, nodes[1].keys_manager).unwrap();
			assert_eq!(persisted_chan_data_1.len(), 1);
			for (_, mon) in persisted_chan_data_1.iter() {
				assert_eq!(mon.get_latest_update_id(), $expected_update_id);
			}
		}
	}

	// Create some initial channel and check that a channel was persisted.
	let _ = create_announced_chan_between_nodes(&nodes, 0, 1);
	check_persisted_data!(0);

	// Send a few payments and make sure the monitors are updated to the latest.
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);
	check_persisted_data!(5);
	send_payment(&nodes[1], &vec!(&nodes[0])[..], 4000000);
	check_persisted_data!(10);

	// Force close because cooperative close doesn't result in any persisted
	// updates.
	nodes[0].node.force_close_broadcasting_latest_txn(&nodes[0].node.list_channels()[0].channel_id, &nodes[1].node.get_our_node_id()).unwrap();
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);

	connect_block(&nodes[1], &create_dummy_block(nodes[0].best_block_hash(), 42, vec![node_txn[0].clone(), node_txn[0].clone()]));
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 100000);
	check_added_monitors!(nodes[1], 1);

	// Make sure everything is persisted as expected after close.
	check_persisted_data!(CLOSED_CHANNEL_UPDATE_ID);
}

// A `KVStore` impl for testing purposes that wraps all our `KVStore`s and asserts their synchronicity.
pub(crate) struct TestSyncStore {
	test_store: TestStore,
	fs_store: FilesystemStore,
	sqlite_store: SqliteStore,
}

impl TestSyncStore {
	pub(crate) fn new(dest_dir: PathBuf) -> Self {
		let fs_store = FilesystemStore::new(dest_dir.clone());
		let sqlite_store = SqliteStore::new(dest_dir,
			Some("test_sync_db".to_string()), Some("test_sync_table".to_string())).unwrap();
		let test_store = TestStore::new(false);
		Self { fs_store, sqlite_store, test_store }
	}
}

impl KVStore for TestSyncStore {
	fn read(&self, namespace: &str, sub_namespace: &str, key: &str) -> std::io::Result<Vec<u8>> {
		let fs_res = self.fs_store.read(namespace, sub_namespace, key);
		let sqlite_res = self.sqlite_store.read(namespace, sub_namespace, key);
		let test_res = self.test_store.read(namespace, sub_namespace, key);

		match fs_res {
			Ok(read) => {
				assert_eq!(read, sqlite_res.unwrap());
				assert_eq!(read, test_res.unwrap());
				Ok(read)
			}
			Err(e) => {
				assert!(sqlite_res.is_err());
				assert_eq!(e.kind(), unsafe { sqlite_res.unwrap_err_unchecked().kind() });
				assert!(test_res.is_err());
				assert_eq!(e.kind(), unsafe { test_res.unwrap_err_unchecked().kind() });
				Err(e)
			}
		}
	}

	fn write(&self, namespace: &str, sub_namespace: &str, key: &str, buf: &[u8]) -> std::io::Result<()> {
		let fs_res = self.fs_store.write(namespace, sub_namespace, key, buf);
		let sqlite_res = self.sqlite_store.write(namespace, sub_namespace, key, buf);
		let test_res = self.test_store.write(namespace, sub_namespace, key, buf);

		assert!(self.list(namespace, sub_namespace).unwrap().contains(&key.to_string()));

		match fs_res {
			Ok(()) => {
				assert!(sqlite_res.is_ok());
				assert!(test_res.is_ok());
				Ok(())
			}
			Err(e) => {
				assert!(sqlite_res.is_err());
				assert!(test_res.is_err());
				Err(e)
			}
		}
	}

	fn remove(&self, namespace: &str, sub_namespace: &str, key: &str, lazy: bool) -> std::io::Result<()> {
		let fs_res = self.fs_store.remove(namespace, sub_namespace, key, lazy);
		let sqlite_res = self.sqlite_store.remove(namespace, sub_namespace, key, lazy);
		let test_res = self.test_store.remove(namespace, sub_namespace, key, lazy);

		assert!(!self.list(namespace, sub_namespace).unwrap().contains(&key.to_string()));

		match fs_res {
			Ok(()) => {
				assert!(sqlite_res.is_ok());
				assert!(test_res.is_ok());
				Ok(())
			}
			Err(e) => {
				assert!(sqlite_res.is_err());
				assert!(test_res.is_err());
				Err(e)
			}
		}
	}

	fn list(&self, namespace: &str, sub_namespace: &str) -> std::io::Result<Vec<String>> {
		let fs_res = self.fs_store.list(namespace, sub_namespace);
		let sqlite_res = self.sqlite_store.list(namespace, sub_namespace);
		let test_res = self.test_store.list(namespace, sub_namespace);

		match fs_res {
			Ok(mut list) => {
				list.sort();

				let mut sqlite_list = sqlite_res.unwrap();
				sqlite_list.sort();
				assert_eq!(list, sqlite_list);

				let mut test_list = test_res.unwrap();
				test_list.sort();
				assert_eq!(list, test_list);

				Ok(list)
			}
			Err(e) => {
				assert!(sqlite_res.is_err());
				assert!(test_res.is_err());
				Err(e)
			}
		}
	}
}
