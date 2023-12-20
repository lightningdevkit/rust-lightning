//! Objects related to [`FilesystemStore`] live here.
use crate::utils::{check_namespace_key_validity, is_valid_kvstore_str};

use lightning::util::persist::KVStore;
use lightning::util::string::PrintableString;

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[cfg(target_os = "windows")]
use {std::ffi::OsStr, std::os::windows::ffi::OsStrExt};

#[cfg(target_os = "windows")]
macro_rules! call {
	($e: expr) => {
		if $e != 0 {
			Ok(())
		} else {
			Err(std::io::Error::last_os_error())
		}
	};
}

#[cfg(target_os = "windows")]
fn path_to_windows_str<T: AsRef<OsStr>>(path: &T) -> Vec<u16> {
	path.as_ref().encode_wide().chain(Some(0)).collect()
}

// The number of read/write/remove/list operations after which we clean up our `locks` HashMap.
const GC_LOCK_INTERVAL: usize = 25;

/// A [`KVStore`] implementation that writes to and reads from the file system.
pub struct FilesystemStore {
	data_dir: PathBuf,
	tmp_file_counter: AtomicUsize,
	gc_counter: AtomicUsize,
	locks: Mutex<HashMap<PathBuf, Arc<RwLock<()>>>>,
}

impl FilesystemStore {
	/// Constructs a new [`FilesystemStore`].
	pub fn new(data_dir: PathBuf) -> Self {
		let locks = Mutex::new(HashMap::new());
		let tmp_file_counter = AtomicUsize::new(0);
		let gc_counter = AtomicUsize::new(1);
		Self { data_dir, tmp_file_counter, gc_counter, locks }
	}

	/// Returns the data directory.
	pub fn get_data_dir(&self) -> PathBuf {
		self.data_dir.clone()
	}

	fn garbage_collect_locks(&self) {
		let gc_counter = self.gc_counter.fetch_add(1, Ordering::AcqRel);

		if gc_counter % GC_LOCK_INTERVAL == 0 {
			// Take outer lock for the cleanup.
			let mut outer_lock = self.locks.lock().unwrap();

			// Garbage collect all lock entries that are not referenced anymore.
			outer_lock.retain(|_, v| Arc::strong_count(&v) > 1);
		}
	}

	fn get_dest_dir_path(&self, primary_namespace: &str, secondary_namespace: &str) -> std::io::Result<PathBuf> {
		let mut dest_dir_path = {
			#[cfg(target_os = "windows")]
			{
				let data_dir = self.data_dir.clone();
				fs::create_dir_all(data_dir.clone())?;
				fs::canonicalize(data_dir)?
			}
			#[cfg(not(target_os = "windows"))]
			{
				self.data_dir.clone()
			}
		};

		dest_dir_path.push(primary_namespace);
		if !secondary_namespace.is_empty() {
			dest_dir_path.push(secondary_namespace);
		}

		Ok(dest_dir_path)
	}
}

impl KVStore for FilesystemStore {
	fn read(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> std::io::Result<Vec<u8>> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "read")?;

		let mut dest_file_path = self.get_dest_dir_path(primary_namespace, secondary_namespace)?;
		dest_file_path.push(key);

		let mut buf = Vec::new();
		{
			let inner_lock_ref = {
				let mut outer_lock = self.locks.lock().unwrap();
				Arc::clone(&outer_lock.entry(dest_file_path.clone()).or_default())
			};
			let _guard = inner_lock_ref.read().unwrap();

			let mut f = fs::File::open(dest_file_path)?;
			f.read_to_end(&mut buf)?;
		}

		self.garbage_collect_locks();

		Ok(buf)
	}

	fn write(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: &[u8]) -> std::io::Result<()> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "write")?;

		let mut dest_file_path = self.get_dest_dir_path(primary_namespace, secondary_namespace)?;
		dest_file_path.push(key);

		let parent_directory = dest_file_path
			.parent()
			.ok_or_else(|| {
				let msg =
					format!("Could not retrieve parent directory of {}.", dest_file_path.display());
				std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
			})?;
		fs::create_dir_all(&parent_directory)?;

		// Do a crazy dance with lots of fsync()s to be overly cautious here...
		// We never want to end up in a state where we've lost the old data, or end up using the
		// old data on power loss after we've returned.
		// The way to atomically write a file on Unix platforms is:
		// open(tmpname), write(tmpfile), fsync(tmpfile), close(tmpfile), rename(), fsync(dir)
		let mut tmp_file_path = dest_file_path.clone();
		let tmp_file_ext = format!("{}.tmp", self.tmp_file_counter.fetch_add(1, Ordering::AcqRel));
		tmp_file_path.set_extension(tmp_file_ext);

		{
			let mut tmp_file = fs::File::create(&tmp_file_path)?;
			tmp_file.write_all(&buf)?;
			tmp_file.sync_all()?;
		}

		let res = {
			let inner_lock_ref = {
				let mut outer_lock = self.locks.lock().unwrap();
				Arc::clone(&outer_lock.entry(dest_file_path.clone()).or_default())
			};
			let _guard = inner_lock_ref.write().unwrap();

			#[cfg(not(target_os = "windows"))]
			{
				fs::rename(&tmp_file_path, &dest_file_path)?;
				let dir_file = fs::OpenOptions::new().read(true).open(&parent_directory)?;
				dir_file.sync_all()?;
				Ok(())
			}

			#[cfg(target_os = "windows")]
			{
				let res = if dest_file_path.exists() {
					call!(unsafe {
						windows_sys::Win32::Storage::FileSystem::ReplaceFileW(
							path_to_windows_str(&dest_file_path).as_ptr(),
							path_to_windows_str(&tmp_file_path).as_ptr(),
							std::ptr::null(),
							windows_sys::Win32::Storage::FileSystem::REPLACEFILE_IGNORE_MERGE_ERRORS,
							std::ptr::null_mut() as *const core::ffi::c_void,
							std::ptr::null_mut() as *const core::ffi::c_void,
							)
					})
				} else {
					call!(unsafe {
						windows_sys::Win32::Storage::FileSystem::MoveFileExW(
							path_to_windows_str(&tmp_file_path).as_ptr(),
							path_to_windows_str(&dest_file_path).as_ptr(),
							windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH
							| windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING,
							)
					})
				};

				match res {
					Ok(()) => {
						// We fsync the dest file in hopes this will also flush the metadata to disk.
						let dest_file = fs::OpenOptions::new().read(true).write(true)
							.open(&dest_file_path)?;
						dest_file.sync_all()?;
						Ok(())
					}
					Err(e) => Err(e),
				}
			}
		};

		self.garbage_collect_locks();

		res
	}

	fn remove(&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool) -> std::io::Result<()> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "remove")?;

		let mut dest_file_path = self.get_dest_dir_path(primary_namespace, secondary_namespace)?;
		dest_file_path.push(key);

		if !dest_file_path.is_file() {
			return Ok(());
		}

		{
			let inner_lock_ref = {
				let mut outer_lock = self.locks.lock().unwrap();
				Arc::clone(&outer_lock.entry(dest_file_path.clone()).or_default())
			};
			let _guard = inner_lock_ref.write().unwrap();

			if lazy {
				// If we're lazy we just call remove and be done with it.
				fs::remove_file(&dest_file_path)?;
			} else {
				// If we're not lazy we try our best to persist the updated metadata to ensure
				// atomicity of this call.
				#[cfg(not(target_os = "windows"))]
				{
					fs::remove_file(&dest_file_path)?;

					let parent_directory = dest_file_path.parent().ok_or_else(|| {
						let msg =
							format!("Could not retrieve parent directory of {}.", dest_file_path.display());
						std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
					})?;
					let dir_file = fs::OpenOptions::new().read(true).open(parent_directory)?;
					// The above call to `fs::remove_file` corresponds to POSIX `unlink`, whose changes
					// to the inode might get cached (and hence possibly lost on crash), depending on
					// the target platform and file system.
					//
					// In order to assert we permanently removed the file in question we therefore
					// call `fsync` on the parent directory on platforms that support it.
					dir_file.sync_all()?;
				}

				#[cfg(target_os = "windows")]
				{
					// Since Windows `DeleteFile` API is not persisted until the last open file handle
					// is dropped, and there seemingly is no reliable way to flush the directory
					// metadata, we here fall back to use a 'recycling bin' model, i.e., first move the
					// file to be deleted to a temporary trash file and remove the latter file
					// afterwards.
					//
					// This should be marginally better, as, according to the documentation,
					// `MoveFileExW` APIs should offer stronger persistence guarantees,
					// at least if `MOVEFILE_WRITE_THROUGH`/`MOVEFILE_REPLACE_EXISTING` is set.
					// However, all this is partially based on assumptions and local experiments, as
					// Windows API is horribly underdocumented.
					let mut trash_file_path = dest_file_path.clone();
					let trash_file_ext = format!("{}.trash",
						self.tmp_file_counter.fetch_add(1, Ordering::AcqRel));
					trash_file_path.set_extension(trash_file_ext);

					call!(unsafe {
						windows_sys::Win32::Storage::FileSystem::MoveFileExW(
							path_to_windows_str(&dest_file_path).as_ptr(),
							path_to_windows_str(&trash_file_path).as_ptr(),
							windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH
							| windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING,
							)
					})?;

					{
						// We fsync the trash file in hopes this will also flush the original's file
						// metadata to disk.
						let trash_file = fs::OpenOptions::new().read(true).write(true)
							.open(&trash_file_path.clone())?;
						trash_file.sync_all()?;
					}

					// We're fine if this remove would fail as the trash file will be cleaned up in
					// list eventually.
					fs::remove_file(trash_file_path).ok();
				}
			}
		}

		self.garbage_collect_locks();

		Ok(())
	}

	fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> std::io::Result<Vec<String>> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, None, "list")?;

		let prefixed_dest = self.get_dest_dir_path(primary_namespace, secondary_namespace)?;
		let mut keys = Vec::new();

		if !Path::new(&prefixed_dest).exists() {
			return Ok(Vec::new());
		}

		for entry in fs::read_dir(&prefixed_dest)? {
			let entry = entry?;
			let p = entry.path();

			if let Some(ext) = p.extension() {
				#[cfg(target_os = "windows")]
				{
					// Clean up any trash files lying around.
					if ext == "trash" {
						fs::remove_file(p).ok();
						continue;
					}
				}
				if ext == "tmp" {
					continue;
				}
			}

			let metadata = p.metadata()?;

			// We allow the presence of directories in the empty primary namespace and just skip them.
			if metadata.is_dir() {
				continue;
			}

			// If we otherwise don't find a file at the given path something went wrong.
			if !metadata.is_file() {
				debug_assert!(false, "Failed to list keys of {}/{}: file couldn't be accessed.",
					PrintableString(primary_namespace), PrintableString(secondary_namespace));
				let msg = format!("Failed to list keys of {}/{}: file couldn't be accessed.",
					PrintableString(primary_namespace), PrintableString(secondary_namespace));
				return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
			}

			match p.strip_prefix(&prefixed_dest) {
				Ok(stripped_path) => {
					if let Some(relative_path) = stripped_path.to_str() {
						if is_valid_kvstore_str(relative_path) {
							keys.push(relative_path.to_string())
						}
					} else {
						debug_assert!(false, "Failed to list keys of {}/{}: file path is not valid UTF-8",
							PrintableString(primary_namespace), PrintableString(secondary_namespace));
						let msg = format!("Failed to list keys of {}/{}: file path is not valid UTF-8",
							PrintableString(primary_namespace), PrintableString(secondary_namespace));
						return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
					}
				}
				Err(e) => {
					debug_assert!(false, "Failed to list keys of {}/{}: {}",
						PrintableString(primary_namespace), PrintableString(secondary_namespace), e);
					let msg = format!("Failed to list keys of {}/{}: {}",
						PrintableString(primary_namespace), PrintableString(secondary_namespace), e);
					return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
				}
			}
		}

		self.garbage_collect_locks();

		Ok(keys)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_utils::{do_read_write_remove_list_persist, do_test_store};

	use bitcoin::Txid;

	use lightning::chain::ChannelMonitorUpdateStatus;
	use lightning::chain::chainmonitor::Persist;
	use lightning::chain::transaction::OutPoint;
	use lightning::check_closed_event;
	use lightning::events::{ClosureReason, MessageSendEventsProvider};
	use lightning::ln::functional_test_utils::*;
	use lightning::util::test_utils;
	use lightning::util::persist::read_channel_monitors;
	use std::fs;
	use std::str::FromStr;

	impl Drop for FilesystemStore {
		fn drop(&mut self) {
			// We test for invalid directory names, so it's OK if directory removal
			// fails.
			match fs::remove_dir_all(&self.data_dir) {
				Err(e) => println!("Failed to remove test persister directory: {}", e),
				_ => {}
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

	#[test]
	fn test_if_monitors_is_not_dir() {
		let store = FilesystemStore::new("test_monitors_is_not_dir".into());

		fs::create_dir_all(&store.get_data_dir()).unwrap();
		let mut path = std::path::PathBuf::from(&store.get_data_dir());
		path.push("monitors");
		fs::File::create(path).unwrap();

		let chanmon_cfgs = create_chanmon_cfgs(1);
		let mut node_cfgs = create_node_cfgs(1, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, &store, node_cfgs[0].keys_manager);
		node_cfgs[0].chain_monitor = chain_mon_0;
		let node_chanmgrs = create_node_chanmgrs(1, &node_cfgs, &[None]);
		let nodes = create_network(1, &node_cfgs, &node_chanmgrs);

		// Check that read_channel_monitors() returns error if monitors/ is not a
		// directory.
		assert!(read_channel_monitors(&store, nodes[0].keys_manager, nodes[0].keys_manager).is_err());
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
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		nodes[1].node.force_close_broadcasting_latest_txn(&chan.2, &nodes[0].node.get_our_node_id()).unwrap();
		check_closed_event!(nodes[1], 1, ClosureReason::HolderForceClosed, [nodes[0].node.get_our_node_id()], 100000);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		let update_map = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap();
		let update_id = update_map.get(&added_monitors[0].0.to_channel_id()).unwrap();

		// Set the store's directory to read-only, which should result in
		// returning an unrecoverable failure when we then attempt to persist a
		// channel update.
		let path = &store.get_data_dir();
		let mut perms = fs::metadata(path).unwrap().permissions();
		perms.set_readonly(true);
		fs::set_permissions(path, perms).unwrap();

		let test_txo = OutPoint {
			txid: Txid::from_str("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(),
			index: 0
		};
		match store.persist_new_channel(test_txo, &added_monitors[0].1, update_id.2) {
			ChannelMonitorUpdateStatus::UnrecoverableError => {},
			_ => panic!("unexpected result from persisting new channel")
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
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
		nodes[1].node.force_close_broadcasting_latest_txn(&chan.2, &nodes[0].node.get_our_node_id()).unwrap();
		check_closed_event!(nodes[1], 1, ClosureReason::HolderForceClosed, [nodes[0].node.get_our_node_id()], 100000);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		let update_map = nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap();
		let update_id = update_map.get(&added_monitors[0].0.to_channel_id()).unwrap();

		// Create the store with an invalid directory name and test that the
		// channel fails to open because the directories fail to be created. There
		// don't seem to be invalid filename characters on Unix that Rust doesn't
		// handle, hence why the test is Windows-only.
		let store = FilesystemStore::new(":<>/".into());

		let test_txo = OutPoint {
			txid: Txid::from_str("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(),
			index: 0
		};
		match store.persist_new_channel(test_txo, &added_monitors[0].1, update_id.2) {
			ChannelMonitorUpdateStatus::UnrecoverableError => {},
			_ => panic!("unexpected result from persisting new channel")
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
			bench, "bench_filesystem_persisted_sends", store_a, store_b);
	}
}
