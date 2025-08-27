use core::hash::{BuildHasher, Hasher};
use lightning::util::persist::{KVStore, KVStoreSync};
use lightning_persister::fs_store::FilesystemStore;
use std::fs;
use tokio::runtime::Runtime;

use crate::utils::test_logger;

struct TempFilesystemStore {
	temp_path: std::path::PathBuf,
	inner: FilesystemStore,
}

impl TempFilesystemStore {
	fn new() -> Self {
		const SHM_PATH: &str = "/dev/shm";
		let mut temp_path = if std::path::Path::new(SHM_PATH).exists() {
			std::path::PathBuf::from(SHM_PATH)
		} else {
			std::env::temp_dir()
		};

		let random_number = std::collections::hash_map::RandomState::new().build_hasher().finish();
		let random_folder_name = format!("fs_store_fuzz_{:016x}", random_number);
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
				None
			} else {
				read_pos += slice_len;
				Some(&data[read_pos - slice_len..read_pos])
			}
		}};
	}

	let temp_fs_store = TempFilesystemStore::new();
	let fs_store = &temp_fs_store.inner;

	let primary_namespace = "primary";
	let secondary_namespace = "secondary";
	let key = "key";

	let mut next_data_value = 0u64;
	let mut get_next_data_value = || {
		let data_value = next_data_value.to_be_bytes().to_vec();
		next_data_value += 1;

		data_value
	};

	let mut current_data = None;

	let mut handles = Vec::new();
	loop {
		let v = match get_slice!(1) {
			Some(b) => b[0],
			None => break,
		};
		match v % 13 {
			// Sync write
			0 => {
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
			1 => {
				KVStoreSync::remove(fs_store, primary_namespace, secondary_namespace, key, false)
					.unwrap();

				current_data = None;
			},
			// Sync list
			2 => {
				KVStoreSync::list(fs_store, primary_namespace, secondary_namespace).unwrap();
			},
			// Sync read
			3 => {
				_ = KVStoreSync::read(fs_store, primary_namespace, secondary_namespace, key);
			},
			// Async write. Bias writes a bit.
			4..=9 => {
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

				let handle = tokio::task::spawn(fut);

				// Store the handle to later await the result.
				handles.push(handle);
			},
			// Async remove
			10 | 11 => {
				let lazy = v == 10;
				let fut =
					KVStore::remove(fs_store, primary_namespace, secondary_namespace, key, lazy);

				// Already set the current_data, even though writing hasn't finished yet. This supports the call-time
				// ordering semantics.
				current_data = None;

				let handle = tokio::task::spawn(fut);
				handles.push(handle);
			},
			// Join tasks.
			12 => {
				for handle in handles.drain(..) {
					let _ = handle.await.unwrap();
				}
			},
			_ => unreachable!(),
		}

		// If no more writes are pending, we can reliably see if the data is consistent.
		if handles.is_empty() {
			let data_value =
				KVStoreSync::read(fs_store, primary_namespace, secondary_namespace, key).ok();
			assert_eq!(data_value, current_data);

			let list = KVStoreSync::list(fs_store, primary_namespace, secondary_namespace).unwrap();
			assert_eq!(list.is_empty(), current_data.is_none());

			assert_eq!(0, fs_store.state_size());
		}
	}

	// Always make sure that all async tasks are completed before returning. Otherwise the temporary storage dir could
	// be removed, and then again recreated by unfinished tasks.
	for handle in handles.drain(..) {
		let _ = handle.await.unwrap();
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
