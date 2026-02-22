//! Objects related to [`FilesystemStoreV2`] live here.
use crate::fs_store::common::{get_key_from_dir_entry_path, FilesystemStoreState};

use lightning::util::persist::{
	KVStoreSync, MigratableKVStore, PageToken, PaginatedKVStoreSync, PaginatedListResponse,
};

use std::fs;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

#[cfg(feature = "tokio")]
use core::future::Future;
#[cfg(feature = "tokio")]
use lightning::util::persist::{KVStore, PaginatedKVStore};
use std::sync::Arc;

/// A [`KVStore`] and [`KVStoreSync`] implementation that writes to and reads from the file system.
///
/// This is version 2 of the filesystem store which provides:
/// - Consistent directory structure using `[empty]` for empty namespaces
/// - File modification times for creation-order pagination
/// - Support for [`PaginatedKVStoreSync`] with newest-first ordering
///
/// ## Directory Structure
///
/// Files are stored with a consistent two-level namespace hierarchy:
/// ```text
/// data_dir/
///   [empty]/                      # empty primary namespace
///     [empty]/                    # empty secondary namespace
///       {key}
///   primary_ns/
///     [empty]/                    # empty secondary namespace
///       {key}
///     secondary_ns/
///       {key}
/// ```
///
/// ## File Ordering
///
/// Files are ordered by their modification time (mtime). When a file is created, it gets
/// the current time. When updated, the original creation time is preserved by setting
/// the mtime of the new file to match the original before the atomic rename.
///
/// [`KVStore`]: lightning::util::persist::KVStore
pub struct FilesystemStoreV2 {
	inner: Arc<FilesystemStoreState>,
}

impl FilesystemStoreV2 {
	/// Constructs a new [`FilesystemStoreV2`].
	///
	/// Returns an error if the data directory already exists and contains files at the top level,
	/// which would indicate it was previously used by a [`FilesystemStore`] (v1). The v2 store
	/// expects only directories (namespaces) at the top level.
	///
	/// [`FilesystemStore`]: crate::fs_store::v1::FilesystemStore
	pub fn new(data_dir: PathBuf) -> std::io::Result<Self> {
		if data_dir.exists() {
			for entry in fs::read_dir(&data_dir)? {
				let entry = entry?;
				if entry.file_type()?.is_file() {
					return Err(std::io::Error::new(
						std::io::ErrorKind::InvalidData,
						format!(
							"Found file `{}` in the top-level data directory. \
							This indicates the directory was previously used by FilesystemStore (v1). \
							Please migrate your data or use a different directory.",
							entry.path().display()
						),
					));
				}
			}
		}

		Ok(Self { inner: Arc::new(FilesystemStoreState::new(data_dir)) })
	}

	/// Returns the data directory.
	pub fn get_data_dir(&self) -> PathBuf {
		self.inner.get_data_dir()
	}

	#[cfg(any(all(feature = "tokio", test), fuzzing))]
	/// Returns the size of the async state.
	pub fn state_size(&self) -> usize {
		self.inner.state_size()
	}
}

/// The fixed page size for paginated listing operations.
pub(crate) const PAGE_SIZE: usize = 50;

/// The length of the timestamp in a page token (milliseconds since epoch as 16-digit decimal).
const PAGE_TOKEN_TIMESTAMP_LEN: usize = 16;

impl FilesystemStoreState {
	fn list_paginated_impl(
		&self, prefixed_dest: PathBuf, page_token: Option<PageToken>,
	) -> Result<PaginatedListResponse, lightning::io::Error> {
		if !prefixed_dest.exists() {
			return Ok(PaginatedListResponse { keys: Vec::new(), next_page_token: None });
		}

		// Collect all entries with their modification times
		let mut entries: Vec<(u64, String)> = Vec::new();
		for dir_entry in fs::read_dir(&prefixed_dest)? {
			let dir_entry = dir_entry?;

			let key =
				get_key_from_dir_entry_path(&dir_entry.path(), prefixed_dest.as_path(), false)?;
			// Get modification time as millis since epoch
			let mtime_millis = dir_entry
				.metadata()
				.ok()
				.and_then(|m| m.modified().ok())
				.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
				.map(|d| d.as_millis() as u64)
				.unwrap_or(0);

			entries.push((mtime_millis, key));
		}

		// Sort by mtime descending (newest first), then by key descending for same mtime
		entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

		// Find starting position based on page token
		let start_idx = if let Some(token) = page_token {
			let (token_mtime, token_key) = parse_page_token(token.as_str())?;

			// Find entries that come after the token (older entries = lower mtime)
			// or same mtime but lexicographically smaller key (since we sort descending)
			entries
				.iter()
				.position(|(mtime, key)| {
					*mtime < token_mtime
						|| (*mtime == token_mtime && key.as_str() < token_key.as_str())
				})
				.unwrap_or(entries.len())
		} else {
			0
		};

		// Take PAGE_SIZE entries starting from start_idx
		let page_entries: Vec<_> =
			entries.iter().skip(start_idx).take(PAGE_SIZE).cloned().collect();

		let keys: Vec<String> = page_entries.iter().map(|(_, key)| key.clone()).collect();

		// Determine next page token
		let next_page_token = if start_idx + PAGE_SIZE < entries.len() {
			page_entries.last().map(|(mtime, key)| PageToken::new(format_page_token(*mtime, key)))
		} else {
			None
		};

		Ok(PaginatedListResponse { keys, next_page_token })
	}
}

impl KVStoreSync for FilesystemStoreV2 {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Result<Vec<u8>, lightning::io::Error> {
		self.inner.read_impl(primary_namespace, secondary_namespace, key, true)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> Result<(), lightning::io::Error> {
		self.inner.write_impl(primary_namespace, secondary_namespace, key, buf, true)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> Result<(), lightning::io::Error> {
		self.inner.remove_impl(primary_namespace, secondary_namespace, key, lazy, true)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> Result<Vec<String>, lightning::io::Error> {
		self.inner.list_impl(primary_namespace, secondary_namespace, true)
	}
}

impl PaginatedKVStoreSync for FilesystemStoreV2 {
	fn list_paginated(
		&self, primary_namespace: &str, secondary_namespace: &str, page_token: Option<PageToken>,
	) -> Result<PaginatedListResponse, lightning::io::Error> {
		let prefixed_dest = self.inner.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			None,
			"list_paginated",
			true,
		)?;
		self.inner.list_paginated_impl(prefixed_dest, page_token)
	}
}

#[cfg(feature = "tokio")]
impl KVStore for FilesystemStoreV2 {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> impl Future<Output = Result<Vec<u8>, lightning::io::Error>> + 'static + Send {
		self.inner.read_async(primary_namespace, secondary_namespace, key, true)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		self.inner.write_async(primary_namespace, secondary_namespace, key, buf, true)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		self.inner.remove_async(primary_namespace, secondary_namespace, key, lazy, true)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> impl Future<Output = Result<Vec<String>, lightning::io::Error>> + 'static + Send {
		self.inner.list_async(primary_namespace, secondary_namespace, true)
	}
}

#[cfg(feature = "tokio")]
impl PaginatedKVStore for FilesystemStoreV2 {
	fn list_paginated(
		&self, primary_namespace: &str, secondary_namespace: &str, page_token: Option<PageToken>,
	) -> impl Future<Output = Result<PaginatedListResponse, lightning::io::Error>> + 'static + Send
	{
		let this = Arc::clone(&self.inner);

		let path = this.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			None,
			"list_paginated",
			true,
		);

		async move {
			let path = match path {
				Ok(path) => path,
				Err(e) => return Err(e),
			};
			tokio::task::spawn_blocking(move || this.list_paginated_impl(path, page_token))
				.await
				.unwrap_or_else(|e| {
					Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e))
				})
		}
	}
}

impl MigratableKVStore for FilesystemStoreV2 {
	fn list_all_keys(&self) -> Result<Vec<(String, String, String)>, lightning::io::Error> {
		self.inner.list_all_keys_impl(true)
	}
}

/// Formats a page token from mtime (millis since epoch) and key.
pub(crate) fn format_page_token(mtime_millis: u64, key: &str) -> String {
	format!("{mtime_millis:016}:{key}")
}

/// Parses a page token into mtime (millis since epoch) and key.
pub(crate) fn parse_page_token(token: &str) -> lightning::io::Result<(u64, String)> {
	if token.as_bytes().get(PAGE_TOKEN_TIMESTAMP_LEN) != Some(&b':') {
		return Err(lightning::io::Error::new(
			lightning::io::ErrorKind::InvalidInput,
			"Invalid page token format",
		));
	}

	let mtime = token[..PAGE_TOKEN_TIMESTAMP_LEN].parse::<u64>().map_err(|_| {
		lightning::io::Error::new(
			lightning::io::ErrorKind::InvalidInput,
			"Invalid page token timestamp",
		)
	})?;

	let key = token[PAGE_TOKEN_TIMESTAMP_LEN + 1..].to_string();

	Ok((mtime, key))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::fs_store::common::EMPTY_NAMESPACE_DIR;
	use crate::test_utils::{
		do_read_write_remove_list_persist, do_test_data_migration, do_test_store,
	};
	use std::fs::FileTimes;
	use std::time::UNIX_EPOCH;

	impl Drop for FilesystemStoreV2 {
		fn drop(&mut self) {
			// We test for invalid directory names, so it's OK if directory removal
			// fails.
			match fs::remove_dir_all(&self.inner.get_data_dir()) {
				Err(e) => println!("Failed to remove test persister directory: {}", e),
				_ => {},
			}
		}
	}

	#[test]
	fn read_write_remove_list_persist() {
		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_read_write_remove_list_persist_v2");
		let fs_store = FilesystemStoreV2::new(temp_path).unwrap();
		do_read_write_remove_list_persist(&fs_store);
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn read_write_remove_list_persist_async() {
		use lightning::util::persist::KVStore;
		use std::sync::Arc;

		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_read_write_remove_list_persist_async_v2");
		let fs_store = Arc::new(FilesystemStoreV2::new(temp_path).unwrap());
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
	fn test_data_migration() {
		let mut source_temp_path = std::env::temp_dir();
		source_temp_path.push("test_data_migration_source_v2");
		let mut source_store = FilesystemStoreV2::new(source_temp_path).unwrap();

		let mut target_temp_path = std::env::temp_dir();
		target_temp_path.push("test_data_migration_target_v2");
		let mut target_store = FilesystemStoreV2::new(target_temp_path).unwrap();

		do_test_data_migration(&mut source_store, &mut target_store);
	}

	#[test]
	fn test_filesystem_store_v2() {
		// Create the nodes, giving them FilesystemStoreV2s for data stores.
		let store_0 = FilesystemStoreV2::new("test_filesystem_store_v2_0".into()).unwrap();
		let store_1 = FilesystemStoreV2::new("test_filesystem_store_v2_1".into()).unwrap();
		do_test_store(&store_0, &store_1)
	}

	#[test]
	fn test_page_token_format() {
		let mtime: u64 = 1706500000000;
		let key = "test_key";
		let token = format_page_token(mtime, key);
		assert_eq!(token, "0001706500000000:test_key");

		let parsed = parse_page_token(&token).unwrap();
		assert_eq!(parsed, (mtime, key.to_string()));

		// Test invalid tokens
		assert!(parse_page_token("invalid").is_err());
		assert!(parse_page_token("0001706500000000_key").is_err()); // wrong separator
		assert!(parse_page_token("0001706500000000").is_err()); // no separator and key
		assert!(parse_page_token("1706500000000:key").is_err()); // too short timestamp
	}

	#[test]
	fn test_directory_structure() {
		use lightning::util::persist::KVStoreSync;

		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_directory_structure_v2");
		let fs_store = FilesystemStoreV2::new(temp_path.clone()).unwrap();

		let data = vec![42u8; 32];

		// Write with empty namespaces
		KVStoreSync::write(&fs_store, "", "", "key1", data.clone()).unwrap();
		assert!(temp_path.join(EMPTY_NAMESPACE_DIR).join(EMPTY_NAMESPACE_DIR).exists());

		// Write with non-empty primary, empty secondary
		KVStoreSync::write(&fs_store, "primary", "", "key2", data.clone()).unwrap();
		assert!(temp_path.join("primary").join(EMPTY_NAMESPACE_DIR).exists());

		// Write with both non-empty
		KVStoreSync::write(&fs_store, "primary", "secondary", "key3", data.clone()).unwrap();
		assert!(temp_path.join("primary").join("secondary").exists());

		// Verify we can read them back
		assert_eq!(KVStoreSync::read(&fs_store, "", "", "key1").unwrap(), data);
		assert_eq!(KVStoreSync::read(&fs_store, "primary", "", "key2").unwrap(), data);
		assert_eq!(KVStoreSync::read(&fs_store, "primary", "secondary", "key3").unwrap(), data);

		// Verify files are named just by key (no timestamp prefix)
		assert!(temp_path
			.join(EMPTY_NAMESPACE_DIR)
			.join(EMPTY_NAMESPACE_DIR)
			.join("key1")
			.exists());
		assert!(temp_path.join("primary").join(EMPTY_NAMESPACE_DIR).join("key2").exists());
		assert!(temp_path.join("primary").join("secondary").join("key3").exists());
	}

	#[test]
	fn test_update_preserves_mtime() {
		use lightning::util::persist::KVStoreSync;

		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_update_preserves_mtime_v2");
		let fs_store = FilesystemStoreV2::new(temp_path.clone()).unwrap();

		let data1 = vec![42u8; 32];
		let data2 = vec![43u8; 32];

		// Write initial data
		KVStoreSync::write(&fs_store, "ns", "sub", "key", data1).unwrap();

		// Get the original mtime
		let file_path = temp_path.join("ns").join("sub").join("key");
		let original_mtime = fs::metadata(&file_path).unwrap().modified().unwrap();

		// Sleep briefly to ensure different timestamp if not preserved
		std::thread::sleep(std::time::Duration::from_millis(50));

		// Update with new data
		KVStoreSync::write(&fs_store, "ns", "sub", "key", data2.clone()).unwrap();

		// Verify mtime is preserved
		let updated_mtime = fs::metadata(&file_path).unwrap().modified().unwrap();
		assert_eq!(original_mtime, updated_mtime);

		// Verify data was updated
		assert_eq!(KVStoreSync::read(&fs_store, "ns", "sub", "key").unwrap(), data2);
	}

	#[test]
	fn test_paginated_listing() {
		use lightning::util::persist::{KVStoreSync, PaginatedKVStoreSync};

		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_paginated_listing_v2");
		let fs_store = FilesystemStoreV2::new(temp_path).unwrap();

		let data = vec![42u8; 32];

		// Write several keys with small delays to ensure different mtimes
		let keys: Vec<String> = (0..5).map(|i| format!("key{}", i)).collect();
		for key in &keys {
			KVStoreSync::write(&fs_store, "ns", "sub", key, data.clone()).unwrap();
			std::thread::sleep(std::time::Duration::from_millis(10));
		}

		// List paginated - should return newest first
		let response = PaginatedKVStoreSync::list_paginated(&fs_store, "ns", "sub", None).unwrap();
		assert_eq!(response.keys.len(), 5);
		// Newest key (key4) should be first
		assert_eq!(response.keys[0], "key4");
		assert_eq!(response.keys[4], "key0");
		assert!(response.next_page_token.is_none()); // Less than PAGE_SIZE items
	}

	#[test]
	fn test_paginated_listing_with_pagination() {
		use lightning::util::persist::{KVStoreSync, PaginatedKVStoreSync};

		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_paginated_listing_with_pagination_v2");
		let fs_store = FilesystemStoreV2::new(temp_path).unwrap();

		let data = vec![42u8; 32];

		// Write more than PAGE_SIZE keys
		let num_keys = PAGE_SIZE + 50;
		for i in 0..num_keys {
			let key = format!("key{:04}", i);
			KVStoreSync::write(&fs_store, "ns", "sub", &key, data.clone()).unwrap();
			// Small delay to ensure ordering
			if i % 10 == 0 {
				std::thread::sleep(std::time::Duration::from_millis(1));
			}
		}

		// First page
		let response1 = PaginatedKVStoreSync::list_paginated(&fs_store, "ns", "sub", None).unwrap();
		assert_eq!(response1.keys.len(), PAGE_SIZE);
		assert!(response1.next_page_token.is_some());

		// Second page
		let response2 =
			PaginatedKVStoreSync::list_paginated(&fs_store, "ns", "sub", response1.next_page_token)
				.unwrap();
		assert_eq!(response2.keys.len(), 50);
		assert!(response2.next_page_token.is_none());

		// Verify no duplicates between pages
		let all_keys: std::collections::HashSet<_> =
			response1.keys.iter().chain(response2.keys.iter()).collect();
		assert_eq!(all_keys.len(), num_keys);
	}

	#[test]
	fn test_page_token_after_deletion() {
		use lightning::util::persist::{KVStoreSync, PaginatedKVStoreSync};

		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_page_token_after_deletion_v2");
		let fs_store = FilesystemStoreV2::new(temp_path).unwrap();

		let data = vec![42u8; 32];

		// Write keys
		for i in 0..10 {
			let key = format!("key{}", i);
			KVStoreSync::write(&fs_store, "ns", "sub", &key, data.clone()).unwrap();
			std::thread::sleep(std::time::Duration::from_millis(10));
		}

		// Verify initial listing
		let response1 = PaginatedKVStoreSync::list_paginated(&fs_store, "ns", "sub", None).unwrap();
		assert_eq!(response1.keys.len(), 10);

		// Delete some keys
		KVStoreSync::remove(&fs_store, "ns", "sub", "key5", false).unwrap();
		KVStoreSync::remove(&fs_store, "ns", "sub", "key3", false).unwrap();

		// List again - should work fine with deleted keys
		let response2 = PaginatedKVStoreSync::list_paginated(&fs_store, "ns", "sub", None).unwrap();
		assert_eq!(response2.keys.len(), 8); // 10 - 2 deleted
	}

	#[test]
	fn test_same_mtime_sorted_by_key() {
		use lightning::util::persist::PaginatedKVStoreSync;
		use std::time::Duration;

		// Create files directly on disk first with the same mtime
		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_same_mtime_sorted_by_key_v2");
		let _ = fs::remove_dir_all(&temp_path);

		let data = vec![42u8; 32];
		let dir = temp_path.join("ns").join("sub");
		fs::create_dir_all(&dir).unwrap();

		// Write files with the same mtime but different keys
		let keys = vec!["zebra", "apple", "mango", "banana"];
		let fixed_time = UNIX_EPOCH + Duration::from_secs(1706500000);

		for key in &keys {
			let file_path = dir.join(key);
			let file = fs::File::create(&file_path).unwrap();
			std::io::Write::write_all(&mut &file, &data).unwrap();
			file.set_times(FileTimes::new().set_modified(fixed_time)).unwrap();
		}

		// Open the store
		let fs_store = FilesystemStoreV2::new(temp_path.clone()).unwrap();

		// List paginated - should return keys sorted by key in reverse order
		// (for same mtime, keys are sorted reverse alphabetically)
		let response = PaginatedKVStoreSync::list_paginated(&fs_store, "ns", "sub", None).unwrap();
		assert_eq!(response.keys.len(), 4);

		// Same mtime means sorted by key in reverse order (z > m > b > a)
		assert_eq!(response.keys[0], "zebra");
		assert_eq!(response.keys[1], "mango");
		assert_eq!(response.keys[2], "banana");
		assert_eq!(response.keys[3], "apple");
	}

	#[test]
	fn test_rejects_v1_data_directory() {
		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_rejects_v1_data_directory");
		let _ = fs::remove_dir_all(&temp_path);
		fs::create_dir_all(&temp_path).unwrap();

		// Create a file at the top level, as v1 would for an empty primary namespace
		fs::write(temp_path.join("some_key"), b"data").unwrap();

		// V2 construction should fail
		match FilesystemStoreV2::new(temp_path.clone()) {
			Err(err) => {
				assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
				assert!(err.to_string().contains("FilesystemStore (v1)"));
			},
			Ok(_) => panic!("Expected error for directory with top-level files"),
		}

		// Clean up
		let _ = fs::remove_dir_all(&temp_path);

		// An empty directory should succeed
		fs::create_dir_all(&temp_path).unwrap();
		let result = FilesystemStoreV2::new(temp_path.clone());
		assert!(result.is_ok());

		// A directory with only subdirectories should succeed
		fs::create_dir_all(temp_path.join("some_namespace")).unwrap();
		let result = FilesystemStoreV2::new(temp_path);
		assert!(result.is_ok());
	}
}
