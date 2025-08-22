use lightning::util::persist::{KVStore, KVStoreSync};
use lightning_persister::fs_store::FilesystemStore;
use std::fs;
use tokio::runtime::Runtime;
use uuid::Uuid;

use crate::utils::test_logger;

struct TempFilesystemStore {
	temp_path: std::path::PathBuf,
	inner: FilesystemStore,
}

impl TempFilesystemStore {
	fn new() -> Self {
		let mut temp_path = std::env::temp_dir();
		let random_folder_name = format!("fs_store_fuzz_{}", Uuid::new_v4());
		temp_path.push(random_folder_name);

		let inner = FilesystemStore::new(temp_path.clone());
		TempFilesystemStore { inner, temp_path }
	}
}

impl Drop for TempFilesystemStore {
	fn drop(&mut self) {
		_ = fs::remove_dir_all(&self.temp_path)
	}
}

/// Actual fuzz test, method signature and name are fixed
fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let rt = Runtime::new().unwrap();
	rt.block_on(do_test_internal(data, out));
}

async fn do_test_internal<Out: test_logger::Output>(data: &[u8], _out: Out) {
	let mut read_pos = 0;
	macro_rules! get_slice {
		($len: expr) => {{
			let slice_len = $len as usize;
			if data.len() < read_pos + slice_len {
				return;
			}
			read_pos += slice_len;
			&data[read_pos - slice_len..read_pos]
		}};
	}

	let temp_fs_store = TempFilesystemStore::new();
	let fs_store = &temp_fs_store.inner;

	let primary_namespace = "primary";
	let secondary_namespace = "secondary";
	let key = "key";

	// Remove the key in case something was left over from a previous run.
	_ = KVStoreSync::remove(fs_store, primary_namespace, secondary_namespace, key, false);

	let mut next_data_value = 0u64;
	let mut get_next_data_value = || {
		let data_value = next_data_value.to_be_bytes().to_vec();
		next_data_value += 1;

		data_value
	};

	let mut current_data = None;

	let mut futures = Vec::new();
	loop {
		let v = get_slice!(1)[0];
		match v {
			// Sync write
			0x00 => {
				let data_value = get_next_data_value();

				KVStoreSync::write(
					fs_store,
					primary_namespace,
					secondary_namespace,
					key,
					data_value.clone(),
				)
				.unwrap();

				current_data = Some(data_value);
			},
			// Sync remove
			0x01 => {
				KVStoreSync::remove(fs_store, primary_namespace, secondary_namespace, key, false)
					.unwrap();

				current_data = None;
			},
			// Sync list
			0x02 => {
				KVStoreSync::list(fs_store, primary_namespace, secondary_namespace).unwrap();
			},
			// Sync read
			0x03 => {
				_ = KVStoreSync::read(fs_store, primary_namespace, secondary_namespace, key);
			},
			// Async write
			0x04 => {
				let data_value = get_next_data_value();

				let fut = KVStore::write(
					fs_store,
					primary_namespace,
					secondary_namespace,
					key,
					data_value.clone(),
				);

				// Already set the current_data, even though writing hasn't finished yet. This supports the call-time
				// ordering semantics.
				current_data = Some(data_value);

				// Store the future for later completion.
				futures.push(fut);
				if futures.len() > 10 {
					return;
				}
			},
			// Async write completion
			0x10..=0x19 => {
				let fut_idx = (v - 0x10) as usize;
				if fut_idx >= futures.len() {
					return;
				}

				let fut = futures.remove(fut_idx);

				fut.await.unwrap();
			},
			_ => {
				return;
			},
		}

		// If no more writes are pending, we can reliably see if the data is consistent.
		if futures.is_empty() {
			let data_value =
				KVStoreSync::read(fs_store, primary_namespace, secondary_namespace, key).ok();
			assert_eq!(data_value, current_data);

			let list = KVStoreSync::list(fs_store, primary_namespace, secondary_namespace).unwrap();
			assert_eq!(list.is_empty(), current_data.is_none());

			assert_eq!(0, fs_store.state_size());
		}
	}
}

/// Method that needs to be added manually, {name}_test
pub fn fs_store_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

/// Method that needs to be added manually, {name}_run
#[no_mangle]
pub extern "C" fn fs_store_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
