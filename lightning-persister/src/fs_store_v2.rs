//! Objects related to [`FilesystemStoreV2`] live here.
use crate::fs_store_common::{prepare_atomic_write, FilesystemStoreState, WriteOptions};
use crate::utils::{check_namespace_key_validity, is_valid_kvstore_str};

use lightning::util::persist::{
	KVStoreSync, MigratableKVStore, PageToken, PaginatedKVStoreSync, PaginatedListResponse,
};

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "tokio")]
use core::future::Future;
#[cfg(feature = "tokio")]
use lightning::util::persist::{KVStore, PaginatedKVStore};

#[cfg(not(target_os = "windows"))]
use crate::fs_store_common::finalize_atomic_write_unix;
#[cfg(target_os = "windows")]
use crate::fs_store_common::finalize_atomic_write_windows;
#[cfg(not(target_os = "windows"))]
use crate::fs_store_common::remove_file_unix;
#[cfg(target_os = "windows")]
use crate::fs_store_common::remove_file_windows;

/// The fixed page size for paginated listing operations.
const PAGE_SIZE: usize = 50;

/// The directory name used for empty namespaces.
/// Uses brackets which are not in KVSTORE_NAMESPACE_KEY_ALPHABET, preventing collisions
/// with valid namespace names.
const EMPTY_NAMESPACE_DIR: &str = "[empty]";

/// The length of the timestamp in a page token (milliseconds since epoch as 16-digit decimal).
const PAGE_TOKEN_TIMESTAMP_LEN: usize = 16;

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

	// Version counter to ensure that writes are applied in the correct order. It is assumed that read and list
	// operations aren't sensitive to the order of execution.
	next_version: AtomicU64,
}

impl FilesystemStoreV2 {
	/// Constructs a new [`FilesystemStoreV2`].
	pub fn new(data_dir: PathBuf) -> std::io::Result<Self> {
		Ok(Self {
			inner: Arc::new(FilesystemStoreState::new(data_dir)),
			next_version: AtomicU64::new(1),
		})
	}

	/// Returns the data directory.
	pub fn get_data_dir(&self) -> PathBuf {
		self.inner.data_dir.clone()
	}

	fn get_new_version_and_lock_ref(&self, lock_key: PathBuf) -> (Arc<RwLock<u64>>, u64) {
		let version = self.next_version.fetch_add(1, Ordering::Relaxed);
		if version == u64::MAX {
			panic!("FilesystemStoreV2 version counter overflowed");
		}

		// Get a reference to the inner lock. We do this early so that the arc can double as an in-flight counter for
		// cleaning up unused locks.
		let inner_lock_ref = self.inner.get_inner_lock_ref(lock_key);

		(inner_lock_ref, version)
	}

	#[cfg(any(all(feature = "tokio", test), fuzzing))]
	/// Returns the size of the async state.
	pub fn state_size(&self) -> usize {
		let outer_lock = self.inner.locks.lock().unwrap();
		outer_lock.len()
	}

	fn get_dest_dir_path(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> std::io::Result<PathBuf> {
		let mut dest_dir_path = self.inner.get_base_dir_path()?;

		// Use [empty] for empty namespaces to ensure consistent directory depth
		let primary_dir =
			if primary_namespace.is_empty() { EMPTY_NAMESPACE_DIR } else { primary_namespace };
		let secondary_dir =
			if secondary_namespace.is_empty() { EMPTY_NAMESPACE_DIR } else { secondary_namespace };

		dest_dir_path.push(primary_dir);
		dest_dir_path.push(secondary_dir);

		Ok(dest_dir_path)
	}

	/// Returns the file path for a given namespace/key combination.
	fn get_file_path(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> std::io::Result<PathBuf> {
		let dir = self.get_dest_dir_path(primary_namespace, secondary_namespace)?;
		Ok(dir.join(key))
	}

	fn read_impl(&self, dest_file_path: PathBuf) -> lightning::io::Result<Vec<u8>> {
		let mut buf = Vec::new();

		self.inner.execute_locked_read(dest_file_path.clone(), || {
			let mut f = fs::File::open(&dest_file_path)?;
			f.read_to_end(&mut buf)?;
			Ok(())
		})?;

		Ok(buf)
	}

	/// Writes a specific version of a key to the filesystem. If a newer version has been written already, this function
	/// returns early without writing.
	/// If `preserve_mtime` is Some, the file's modification time will be set to that value to preserve creation order.
	/// Returns `Ok(true)` if the write was performed, `Ok(false)` if skipped due to staleness.
	fn write_version(
		&self, inner_lock_ref: Arc<RwLock<u64>>, dest_file_path: PathBuf, buf: Vec<u8>,
		preserve_mtime: Option<SystemTime>, version: u64,
	) -> lightning::io::Result<bool> {
		let options = WriteOptions { preserve_mtime };
		let tmp_file_path = prepare_atomic_write(&self.inner, &dest_file_path, &buf, &options)?;

		self.inner.execute_locked_write(inner_lock_ref, dest_file_path.clone(), version, || {
			#[cfg(not(target_os = "windows"))]
			{
				finalize_atomic_write_unix(&tmp_file_path, &dest_file_path)
			}

			#[cfg(target_os = "windows")]
			{
				finalize_atomic_write_windows(&tmp_file_path, &dest_file_path, &options)
			}
		})
	}

	/// Removes a specific version of a key from the filesystem. If a newer version has been written already, this function
	/// returns early without removing.
	/// Returns `Ok(true)` if the remove was performed, `Ok(false)` if skipped due to staleness.
	fn remove_version(
		&self, inner_lock_ref: Arc<RwLock<u64>>, lock_key: PathBuf, dest_file_path: PathBuf,
		lazy: bool, version: u64,
	) -> lightning::io::Result<bool> {
		self.inner.execute_locked_write(inner_lock_ref, lock_key, version, || {
			if !dest_file_path.is_file() {
				return Ok(());
			}

			if lazy {
				// If we're lazy we just call remove and be done with it.
				fs::remove_file(&dest_file_path)?;
			} else {
				// If we're not lazy we try our best to persist the updated metadata to ensure
				// atomicity of this call.
				#[cfg(not(target_os = "windows"))]
				{
					remove_file_unix(&dest_file_path)?;
				}

				#[cfg(target_os = "windows")]
				{
					remove_file_windows(&self.inner, &dest_file_path)?;
				}
			}

			Ok(())
		})
	}

	fn list_impl(&self, prefixed_dest: PathBuf) -> lightning::io::Result<Vec<String>> {
		if !Path::new(&prefixed_dest).exists() {
			return Ok(Vec::new());
		}

		let mut keys = Vec::new();
		for entry in fs::read_dir(&prefixed_dest)? {
			let entry = entry?;
			let path = entry.path();

			if let Some(key) = entry_to_key(&path) {
				keys.push(key);
			}
		}

		Ok(keys)
	}

	fn list_paginated_impl(
		&self, prefixed_dest: PathBuf, page_token: Option<PageToken>,
	) -> lightning::io::Result<PaginatedListResponse> {
		if !Path::new(&prefixed_dest).exists() {
			return Ok(PaginatedListResponse { keys: Vec::new(), next_page_token: None });
		}

		// Collect all entries with their modification times
		let mut entries: Vec<(u64, String)> = Vec::new();
		for entry in fs::read_dir(&prefixed_dest)? {
			let entry = entry?;
			let path = entry.path();

			if let Some(key) = entry_to_key(&path) {
				// Get modification time as millis since epoch
				let mtime_millis = entry
					.metadata()
					.ok()
					.and_then(|m| m.modified().ok())
					.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
					.map(|d| d.as_millis() as u64)
					.unwrap_or(0);

				entries.push((mtime_millis, key));
			}
		}

		// Sort by mtime descending (newest first), then by key descending for same mtime
		entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

		// Find starting position based on page token
		let start_idx = if let Some(token) = page_token {
			let (token_mtime, token_key) = parse_page_token(&token.0)?;

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
			page_entries.last().map(|(mtime, key)| PageToken(format_page_token(*mtime, key)))
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
		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "read")?;

		let file_path = self.get_file_path(primary_namespace, secondary_namespace, key)?;
		self.read_impl(file_path)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> Result<(), lightning::io::Error> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "write")?;

		let dest_file_path = self.get_file_path(primary_namespace, secondary_namespace, key)?;

		// Get the existing file's mtime if it exists (to preserve creation order on update)
		let existing_mtime = fs::metadata(&dest_file_path).ok().and_then(|m| m.modified().ok());

		let (inner_lock_ref, version) = self.get_new_version_and_lock_ref(dest_file_path.clone());
		self.write_version(inner_lock_ref, dest_file_path, buf, existing_mtime, version).map(|_| ())
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> Result<(), lightning::io::Error> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "remove")?;

		let file_path = self.get_file_path(primary_namespace, secondary_namespace, key)?;

		if !file_path.exists() {
			// File doesn't exist, nothing to remove
			return Ok(());
		}

		let (inner_lock_ref, version) = self.get_new_version_and_lock_ref(file_path.clone());
		self.remove_version(inner_lock_ref, file_path.clone(), file_path, lazy, version).map(|_| ())
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> Result<Vec<String>, lightning::io::Error> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, None, "list")?;

		let dest_dir_path = self.get_dest_dir_path(primary_namespace, secondary_namespace)?;
		self.list_impl(dest_dir_path)
	}
}

impl PaginatedKVStoreSync for FilesystemStoreV2 {
	fn list_paginated(
		&self, primary_namespace: &str, secondary_namespace: &str, page_token: Option<PageToken>,
	) -> Result<PaginatedListResponse, lightning::io::Error> {
		check_namespace_key_validity(
			primary_namespace,
			secondary_namespace,
			None,
			"list_paginated",
		)?;

		let dest_dir_path = self.get_dest_dir_path(primary_namespace, secondary_namespace)?;
		self.list_paginated_impl(dest_dir_path, page_token)
	}
}

/// Extracts key from a path if it's a valid key file.
fn entry_to_key(path: &Path) -> Option<String> {
	if let Some(ext) = path.extension() {
		#[cfg(target_os = "windows")]
		{
			// Clean up any trash files lying around.
			if ext == "trash" {
				fs::remove_file(path).ok();
				return None;
			}
		}
		if ext == "tmp" {
			return None;
		}
	}

	if !path.is_file() {
		return None;
	}

	path.file_name().and_then(|n| n.to_str()).and_then(|key| {
		if is_valid_kvstore_str(key) {
			Some(key.to_string())
		} else {
			None
		}
	})
}

/// Formats a page token from mtime (millis since epoch) and key.
fn format_page_token(mtime_millis: u64, key: &str) -> String {
	format!("{:016}:{}", mtime_millis, key)
}

/// Parses a page token into mtime (millis since epoch) and key.
fn parse_page_token(token: &str) -> lightning::io::Result<(u64, String)> {
	let colon_pos = token.find(':').ok_or_else(|| {
		lightning::io::Error::new(
			lightning::io::ErrorKind::InvalidInput,
			"Invalid page token format",
		)
	})?;

	if colon_pos != PAGE_TOKEN_TIMESTAMP_LEN {
		return Err(lightning::io::Error::new(
			lightning::io::ErrorKind::InvalidInput,
			"Invalid page token format",
		));
	}

	let mtime = token[..colon_pos].parse::<u64>().map_err(|_| {
		lightning::io::Error::new(
			lightning::io::ErrorKind::InvalidInput,
			"Invalid page token timestamp",
		)
	})?;

	let key = token[colon_pos + 1..].to_string();

	Ok((mtime, key))
}

#[cfg(feature = "tokio")]
impl KVStore for FilesystemStoreV2 {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> impl Future<Output = Result<Vec<u8>, lightning::io::Error>> + 'static + Send {
		let this = Arc::clone(&self.inner);
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key = key.to_string();
		let validation = check_namespace_key_validity(
			&primary_namespace,
			&secondary_namespace,
			Some(&key),
			"read",
		);
		let file_path = self.get_file_path(&primary_namespace, &secondary_namespace, &key);

		async move {
			validation?;
			let file_path = file_path
				.map_err(|e| lightning::io::Error::new(lightning::io::ErrorKind::Other, e))?;

			tokio::task::spawn_blocking(move || {
				let mut buf = Vec::new();
				this.execute_locked_read(file_path.clone(), || {
					let mut f = fs::File::open(&file_path)?;
					f.read_to_end(&mut buf)?;
					Ok(())
				})?;
				Ok(buf)
			})
			.await
			.unwrap_or_else(|e| Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e)))
		}
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		let this = Arc::clone(&self.inner);
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key_str = key.to_string();
		let validation = check_namespace_key_validity(
			&primary_namespace,
			&secondary_namespace,
			Some(&key_str),
			"write",
		);

		let dest_file_path = self.get_file_path(&primary_namespace, &secondary_namespace, &key_str);
		let (inner_lock_ref, version) = match &dest_file_path {
			Ok(path) => self.get_new_version_and_lock_ref(path.clone()),
			Err(_) => {
				// We'll error out below, but we need placeholder values
				(Arc::new(RwLock::new(0)), 0)
			},
		};

		async move {
			validation?;
			let dest_file_path = dest_file_path
				.map_err(|e| lightning::io::Error::new(lightning::io::ErrorKind::Other, e))?;

			tokio::task::spawn_blocking(move || {
				// Get the existing file's mtime if it exists (to preserve creation order on update)
				let existing_mtime =
					fs::metadata(&dest_file_path).ok().and_then(|m| m.modified().ok());

				let options = WriteOptions { preserve_mtime: existing_mtime };
				let tmp_file_path = prepare_atomic_write(&this, &dest_file_path, &buf, &options)?;

				this.execute_locked_write(inner_lock_ref, dest_file_path.clone(), version, || {
					#[cfg(not(target_os = "windows"))]
					{
						finalize_atomic_write_unix(&tmp_file_path, &dest_file_path)
					}

					#[cfg(target_os = "windows")]
					{
						finalize_atomic_write_windows(&tmp_file_path, &dest_file_path, &options)
					}
				})
				.map(|_| ())
			})
			.await
			.unwrap_or_else(|e| Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e)))
		}
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		let this = Arc::clone(&self.inner);
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key_str = key.to_string();
		let validation = check_namespace_key_validity(
			&primary_namespace,
			&secondary_namespace,
			Some(&key_str),
			"remove",
		);

		let file_path = self.get_file_path(&primary_namespace, &secondary_namespace, &key_str);
		let (inner_lock_ref, version) = match &file_path {
			Ok(path) => self.get_new_version_and_lock_ref(path.clone()),
			Err(_) => (Arc::new(RwLock::new(0)), 0),
		};

		async move {
			validation?;
			let file_path = file_path
				.map_err(|e| lightning::io::Error::new(lightning::io::ErrorKind::Other, e))?;

			tokio::task::spawn_blocking(move || {
				if !file_path.exists() {
					// File doesn't exist, but we still need to clean up the lock
					this.clean_locks(&inner_lock_ref, file_path);
					return Ok(());
				}

				this.execute_locked_write(inner_lock_ref, file_path.clone(), version, || {
					if !file_path.is_file() {
						return Ok(());
					}

					if lazy {
						fs::remove_file(&file_path)?;
					} else {
						#[cfg(not(target_os = "windows"))]
						{
							remove_file_unix(&file_path)?;
						}

						#[cfg(target_os = "windows")]
						{
							remove_file_windows(&this, &file_path)?;
						}
					}

					Ok(())
				})
				.map(|_| ())
			})
			.await
			.unwrap_or_else(|e| Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e)))
		}
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> impl Future<Output = Result<Vec<String>, lightning::io::Error>> + 'static + Send {
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let validation =
			check_namespace_key_validity(&primary_namespace, &secondary_namespace, None, "list");
		let dest_dir_path = self.get_dest_dir_path(&primary_namespace, &secondary_namespace);

		async move {
			validation?;
			let path = dest_dir_path
				.map_err(|e| lightning::io::Error::new(lightning::io::ErrorKind::Other, e))?;

			tokio::task::spawn_blocking(move || {
				if !Path::new(&path).exists() {
					return Ok(Vec::new());
				}

				let mut keys = Vec::new();
				for entry in fs::read_dir(&path)? {
					let entry = entry?;
					let entry_path = entry.path();

					if let Some(key) = entry_to_key(&entry_path) {
						keys.push(key);
					}
				}

				Ok(keys)
			})
			.await
			.unwrap_or_else(|e| Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e)))
		}
	}
}

#[cfg(feature = "tokio")]
impl PaginatedKVStore for FilesystemStoreV2 {
	fn list_paginated(
		&self, primary_namespace: &str, secondary_namespace: &str, page_token: Option<PageToken>,
	) -> impl Future<Output = Result<PaginatedListResponse, lightning::io::Error>> + 'static + Send
	{
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let validation = check_namespace_key_validity(
			&primary_namespace,
			&secondary_namespace,
			None,
			"list_paginated",
		);
		let dest_dir_path = self.get_dest_dir_path(&primary_namespace, &secondary_namespace);

		async move {
			validation?;
			let path = dest_dir_path
				.map_err(|e| lightning::io::Error::new(lightning::io::ErrorKind::Other, e))?;

			tokio::task::spawn_blocking(move || {
				if !Path::new(&path).exists() {
					return Ok(PaginatedListResponse { keys: Vec::new(), next_page_token: None });
				}

				// Collect all entries with their modification times
				let mut entries: Vec<(u64, String)> = Vec::new();
				for entry in fs::read_dir(&path)? {
					let entry = entry?;
					let entry_path = entry.path();

					if let Some(key) = entry_to_key(&entry_path) {
						let mtime_millis = entry
							.metadata()
							.ok()
							.and_then(|m| m.modified().ok())
							.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
							.map(|d| d.as_millis() as u64)
							.unwrap_or(0);

						entries.push((mtime_millis, key));
					}
				}

				// Sort by mtime descending (newest first), then by key descending for same mtime
				entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

				// Find starting position based on page token
				let start_idx = if let Some(token) = page_token {
					let (token_mtime, token_key) = parse_page_token(&token.0)?;

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
					page_entries
						.last()
						.map(|(mtime, key)| PageToken(format_page_token(*mtime, key)))
				} else {
					None
				};

				Ok(PaginatedListResponse { keys, next_page_token })
			})
			.await
			.unwrap_or_else(|e| Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e)))
		}
	}
}

impl MigratableKVStore for FilesystemStoreV2 {
	fn list_all_keys(&self) -> Result<Vec<(String, String, String)>, lightning::io::Error> {
		let prefixed_dest = &self.inner.data_dir;
		if !prefixed_dest.exists() {
			return Ok(Vec::new());
		}

		let mut keys = Vec::new();

		for primary_entry in fs::read_dir(prefixed_dest)? {
			let primary_entry = primary_entry?;
			let primary_path = primary_entry.path();

			if !primary_path.is_dir() {
				// Skip non-directory entries at the root level
				continue;
			}

			let primary_namespace = match primary_path.file_name().and_then(|n| n.to_str()) {
				Some(EMPTY_NAMESPACE_DIR) => String::new(),
				Some(name) if is_valid_kvstore_str(name) => name.to_string(),
				_ => continue,
			};

			for secondary_entry in fs::read_dir(&primary_path)? {
				let secondary_entry = secondary_entry?;
				let secondary_path = secondary_entry.path();

				if !secondary_path.is_dir() {
					// Skip non-directory entries at the secondary level
					continue;
				}

				let secondary_namespace = match secondary_path.file_name().and_then(|n| n.to_str())
				{
					Some(EMPTY_NAMESPACE_DIR) => String::new(),
					Some(name) if is_valid_kvstore_str(name) => name.to_string(),
					_ => continue,
				};

				// Read all key files in this namespace
				for key_entry in fs::read_dir(&secondary_path)? {
					let key_entry = key_entry?;
					let key_path = key_entry.path();

					if let Some(key) = entry_to_key(&key_path) {
						keys.push((primary_namespace.clone(), secondary_namespace.clone(), key));
					}
				}
			}
		}

		Ok(keys)
	}
}

/// Migrates all data from a [`FilesystemStore`] (v1) to a [`FilesystemStoreV2`].
///
/// This function reads all keys from the source v1 store and writes them to the target v2 store.
/// The v2 store will use the new directory structure with `[empty]` markers for empty namespaces.
///
/// # Arguments
///
/// * `source` - The source v1 filesystem store to migrate from
/// * `target` - The target v2 filesystem store to migrate to
///
/// # Errors
///
/// Returns an error if any read or write operation fails. Note that in case of an error,
/// the target store may be left in a partially migrated state.
///
/// # Example
///
/// ```no_run
/// use lightning_persister::fs_store::FilesystemStore;
/// use lightning_persister::fs_store_v2::{FilesystemStoreV2, migrate_v1_to_v2};
/// use std::path::PathBuf;
///
/// let v1_store = FilesystemStore::new(PathBuf::from("/path/to/v1/data"));
/// let v2_store = FilesystemStoreV2::new(PathBuf::from("/path/to/v2/data"))
///     .expect("Failed to open v2 store");
///
/// migrate_v1_to_v2(&v1_store, &v2_store).expect("Migration failed");
/// ```
///
/// [`FilesystemStore`]: crate::fs_store::FilesystemStore
pub fn migrate_v1_to_v2<S: MigratableKVStore>(
	source: &S, target: &FilesystemStoreV2,
) -> Result<(), lightning::io::Error> {
	let keys_to_migrate = source.list_all_keys()?;

	for (primary_namespace, secondary_namespace, key) in &keys_to_migrate {
		let data = source.read(primary_namespace, secondary_namespace, key)?;
		KVStoreSync::write(target, primary_namespace, secondary_namespace, key, data)?;
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_utils::{
		do_read_write_remove_list_persist, do_test_data_migration, do_test_store,
	};
	use std::fs::FileTimes;

	impl Drop for FilesystemStoreV2 {
		fn drop(&mut self) {
			// We test for invalid directory names, so it's OK if directory removal
			// fails.
			match fs::remove_dir_all(&self.inner.data_dir) {
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
	fn test_v1_to_v2_migration() {
		use crate::fs_store::FilesystemStore;
		use lightning::util::persist::KVStoreSync;

		// Create v1 store and populate with test data
		let mut v1_path = std::env::temp_dir();
		v1_path.push("test_v1_to_v2_migration_source");
		let v1_store = FilesystemStore::new(v1_path.clone());

		let data = vec![42u8; 32];

		// Write data with various namespace combinations
		KVStoreSync::write(&v1_store, "", "", "root_key", data.clone()).unwrap();
		KVStoreSync::write(&v1_store, "primary", "", "primary_key", data.clone()).unwrap();
		KVStoreSync::write(&v1_store, "primary", "secondary", "nested_key", data.clone()).unwrap();

		// Create v2 store
		let mut v2_path = std::env::temp_dir();
		v2_path.push("test_v1_to_v2_migration_target");
		let v2_store = FilesystemStoreV2::new(v2_path.clone()).unwrap();

		// Migrate
		migrate_v1_to_v2(&v1_store, &v2_store).unwrap();

		// Verify all data was migrated correctly
		assert_eq!(KVStoreSync::read(&v2_store, "", "", "root_key").unwrap(), data);
		assert_eq!(KVStoreSync::read(&v2_store, "primary", "", "primary_key").unwrap(), data);
		assert_eq!(
			KVStoreSync::read(&v2_store, "primary", "secondary", "nested_key").unwrap(),
			data
		);

		// Verify v2 directory structure uses [empty] for empty namespaces
		assert!(v2_path.join(EMPTY_NAMESPACE_DIR).join(EMPTY_NAMESPACE_DIR).exists());
		assert!(v2_path.join("primary").join(EMPTY_NAMESPACE_DIR).exists());
		assert!(v2_path.join("primary").join("secondary").exists());

		// Verify list_all_keys works on the migrated data
		let mut all_keys = v2_store.list_all_keys().unwrap();
		all_keys.sort();
		assert_eq!(all_keys.len(), 3);
		assert!(all_keys.contains(&("".to_string(), "".to_string(), "root_key".to_string())));
		assert!(all_keys.contains(&(
			"primary".to_string(),
			"".to_string(),
			"primary_key".to_string()
		)));
		assert!(all_keys.contains(&(
			"primary".to_string(),
			"secondary".to_string(),
			"nested_key".to_string()
		)));
	}

	#[test]
	fn test_v1_to_v2_migration_empty_store() {
		use crate::fs_store::FilesystemStore;

		// Create empty v1 store
		let mut v1_path = std::env::temp_dir();
		v1_path.push("test_v1_to_v2_migration_empty_source");
		let v1_store = FilesystemStore::new(v1_path);

		// Create v2 store
		let mut v2_path = std::env::temp_dir();
		v2_path.push("test_v1_to_v2_migration_empty_target");
		let v2_store = FilesystemStoreV2::new(v2_path).unwrap();

		// Migrate empty store should succeed
		migrate_v1_to_v2(&v1_store, &v2_store).unwrap();

		// Verify no keys exist
		let all_keys = v2_store.list_all_keys().unwrap();
		assert_eq!(all_keys.len(), 0);
	}

	#[test]
	fn test_v1_to_v2_migration_data_integrity() {
		use crate::fs_store::FilesystemStore;
		use lightning::util::persist::KVStoreSync;

		// Create v1 store with different data for each key
		let mut v1_path = std::env::temp_dir();
		v1_path.push("test_v1_to_v2_migration_integrity_source");
		let v1_store = FilesystemStore::new(v1_path);

		// Write unique data for each key
		let data1 = vec![1u8; 100];
		let data2 = vec![2u8; 200];
		let data3 = vec![3u8; 50];
		let data4 = (0..255u8).collect::<Vec<_>>(); // All byte values

		KVStoreSync::write(&v1_store, "", "", "key1", data1.clone()).unwrap();
		KVStoreSync::write(&v1_store, "ns1", "", "key2", data2.clone()).unwrap();
		KVStoreSync::write(&v1_store, "ns1", "ns2", "key3", data3.clone()).unwrap();
		KVStoreSync::write(&v1_store, "ns1", "ns2", "key4", data4.clone()).unwrap();

		// Create v2 store and migrate
		let mut v2_path = std::env::temp_dir();
		v2_path.push("test_v1_to_v2_migration_integrity_target");
		let v2_store = FilesystemStoreV2::new(v2_path).unwrap();

		migrate_v1_to_v2(&v1_store, &v2_store).unwrap();

		// Verify each key has exactly the right data
		assert_eq!(KVStoreSync::read(&v2_store, "", "", "key1").unwrap(), data1);
		assert_eq!(KVStoreSync::read(&v2_store, "ns1", "", "key2").unwrap(), data2);
		assert_eq!(KVStoreSync::read(&v2_store, "ns1", "ns2", "key3").unwrap(), data3);
		assert_eq!(KVStoreSync::read(&v2_store, "ns1", "ns2", "key4").unwrap(), data4);
	}

	#[test]
	fn test_v1_to_v2_migration_many_keys() {
		use crate::fs_store::FilesystemStore;
		use lightning::util::persist::{KVStoreSync, PaginatedKVStoreSync};

		// Create v1 store with many keys
		let mut v1_path = std::env::temp_dir();
		v1_path.push("test_v1_to_v2_migration_many_source");
		let v1_store = FilesystemStore::new(v1_path);

		let num_keys = 75; // More than one page (PAGE_SIZE = 50)
		for i in 0..num_keys {
			let key = format!("key_{:04}", i);
			let data = vec![i as u8; 32];
			KVStoreSync::write(&v1_store, "bulk", "test", &key, data).unwrap();
		}

		// Create v2 store and migrate
		let mut v2_path = std::env::temp_dir();
		v2_path.push("test_v1_to_v2_migration_many_target");
		let v2_store = FilesystemStoreV2::new(v2_path).unwrap();

		migrate_v1_to_v2(&v1_store, &v2_store).unwrap();

		// Verify all keys migrated
		let keys = KVStoreSync::list(&v2_store, "bulk", "test").unwrap();
		assert_eq!(keys.len(), num_keys);

		// Verify pagination works on migrated data
		let page1 = PaginatedKVStoreSync::list_paginated(&v2_store, "bulk", "test", None).unwrap();
		assert_eq!(page1.keys.len(), PAGE_SIZE);
		assert!(page1.next_page_token.is_some());

		let page2 =
			PaginatedKVStoreSync::list_paginated(&v2_store, "bulk", "test", page1.next_page_token)
				.unwrap();
		assert_eq!(page2.keys.len(), num_keys - PAGE_SIZE);
		assert!(page2.next_page_token.is_none());

		// Verify data integrity for a few random keys
		for i in [0, 25, 50, 74] {
			let key = format!("key_{:04}", i);
			let expected_data = vec![i as u8; 32];
			assert_eq!(KVStoreSync::read(&v2_store, "bulk", "test", &key).unwrap(), expected_data);
		}
	}

	#[test]
	fn test_v1_to_v2_migration_post_migration_operations() {
		use crate::fs_store::FilesystemStore;
		use lightning::util::persist::KVStoreSync;

		// Create v1 store with some data
		let mut v1_path = std::env::temp_dir();
		v1_path.push("test_v1_to_v2_migration_post_ops_source");
		let v1_store = FilesystemStore::new(v1_path);

		let original_data = vec![42u8; 32];
		KVStoreSync::write(&v1_store, "ns", "sub", "existing_key", original_data.clone()).unwrap();

		// Create v2 store and migrate
		let mut v2_path = std::env::temp_dir();
		v2_path.push("test_v1_to_v2_migration_post_ops_target");
		let v2_store = FilesystemStoreV2::new(v2_path).unwrap();

		migrate_v1_to_v2(&v1_store, &v2_store).unwrap();

		// Test that we can write new keys after migration
		let new_data = vec![43u8; 32];
		KVStoreSync::write(&v2_store, "ns", "sub", "new_key", new_data.clone()).unwrap();

		// Test that we can update migrated keys
		let updated_data = vec![44u8; 32];
		KVStoreSync::write(&v2_store, "ns", "sub", "existing_key", updated_data.clone()).unwrap();

		// Verify reads work correctly
		assert_eq!(
			KVStoreSync::read(&v2_store, "ns", "sub", "existing_key").unwrap(),
			updated_data
		);
		assert_eq!(KVStoreSync::read(&v2_store, "ns", "sub", "new_key").unwrap(), new_data);

		// Verify list includes both old and new keys
		let mut keys = KVStoreSync::list(&v2_store, "ns", "sub").unwrap();
		keys.sort();
		assert_eq!(keys, vec!["existing_key", "new_key"]);

		// Test removal works
		KVStoreSync::remove(&v2_store, "ns", "sub", "existing_key", false).unwrap();
		let keys = KVStoreSync::list(&v2_store, "ns", "sub").unwrap();
		assert_eq!(keys, vec!["new_key"]);
	}

	#[test]
	fn test_v1_to_v2_migration_max_length_names() {
		use crate::fs_store::FilesystemStore;
		use lightning::util::persist::{KVStoreSync, KVSTORE_NAMESPACE_KEY_MAX_LEN};

		// Create v1 store with maximum length names
		let mut v1_path = std::env::temp_dir();
		v1_path.push("test_v1_to_v2_migration_max_len_source");
		let v1_store = FilesystemStore::new(v1_path);

		let max_name = "A".repeat(KVSTORE_NAMESPACE_KEY_MAX_LEN);
		let data = vec![42u8; 32];

		KVStoreSync::write(&v1_store, &max_name, &max_name, &max_name, data.clone()).unwrap();

		// Create v2 store and migrate
		let mut v2_path = std::env::temp_dir();
		v2_path.push("test_v1_to_v2_migration_max_len_target");
		let v2_store = FilesystemStoreV2::new(v2_path).unwrap();

		migrate_v1_to_v2(&v1_store, &v2_store).unwrap();

		// Verify the key was migrated correctly
		assert_eq!(KVStoreSync::read(&v2_store, &max_name, &max_name, &max_name).unwrap(), data);

		// Verify list works
		let keys = KVStoreSync::list(&v2_store, &max_name, &max_name).unwrap();
		assert_eq!(keys, vec![max_name.clone()]);
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
}
