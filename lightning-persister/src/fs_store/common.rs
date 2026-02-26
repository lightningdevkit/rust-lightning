//! Common utilities shared between [`FilesystemStore`] and [`FilesystemStoreV2`] implementations.
//!
//! [`FilesystemStore`]: crate::fs_store::v1::FilesystemStore
//! [`FilesystemStoreV2`]: crate::fs_store::v2::FilesystemStoreV2

use crate::utils::{check_namespace_key_validity, is_valid_kvstore_str};

use lightning::types::string::PrintableString;

use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(feature = "tokio")]
use std::future::Future;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

/// Calls a Windows API function and returns Ok(()) on success or the last OS error on failure.
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
use call;

/// Converts a path to a null-terminated wide string for Windows API calls.
#[cfg(target_os = "windows")]
fn path_to_windows_str<T: AsRef<OsStr>>(path: &T) -> Vec<u16> {
	path.as_ref().encode_wide().chain(Some(0)).collect()
}

// The number of times we retry listing keys in `FilesystemStore::list` before we give up reaching
// a consistent view and error out.
const LIST_DIR_CONSISTENCY_RETRIES: usize = 10;

// The directory name used for empty namespaces in v2.
// Uses brackets which are not in KVSTORE_NAMESPACE_KEY_ALPHABET, preventing collisions
// with valid namespace names.
pub(crate) const EMPTY_NAMESPACE_DIR: &str = "[empty]";

/// Inner state shared between sync and async operations for filesystem stores.
///
/// This struct manages the data directory, temporary file counter, and per-path locks
/// that ensure we don't have concurrent writes to the same file.
struct FilesystemStoreInner {
	data_dir: PathBuf,
	tmp_file_counter: AtomicUsize,

	// Per path lock that ensures that we don't have concurrent writes to the same file. The lock also encapsulates the
	// latest written version per key.
	locks: Mutex<HashMap<PathBuf, Arc<RwLock<u64>>>>,
}

pub(crate) struct FilesystemStoreState {
	inner: Arc<FilesystemStoreInner>,

	// Version counter to ensure that writes are applied in the correct order. It is assumed that read and list
	// operations aren't sensitive to the order of execution.
	next_version: AtomicU64,
}

impl FilesystemStoreState {
	/// Creates a new [`FilesystemStoreInner`] with the given data directory.
	pub(crate) fn new(data_dir: PathBuf) -> Self {
		Self {
			inner: Arc::new(FilesystemStoreInner {
				data_dir,
				tmp_file_counter: AtomicUsize::new(0),
				locks: Mutex::new(HashMap::new()),
			}),
			next_version: AtomicU64::new(1),
		}
	}

	/// Returns the data directory.
	pub fn get_data_dir(&self) -> PathBuf {
		self.inner.data_dir.clone()
	}

	fn get_new_version_and_lock_ref(&self, dest_file_path: PathBuf) -> (Arc<RwLock<u64>>, u64) {
		let version = self.next_version.fetch_add(1, Ordering::Relaxed);
		if version == u64::MAX {
			panic!("FilesystemStore version counter overflowed");
		}

		// Get a reference to the inner lock. We do this early so that the arc can double as an in-flight counter for
		// cleaning up unused locks.
		let inner_lock_ref = self.inner.get_inner_lock_ref(dest_file_path);

		(inner_lock_ref, version)
	}

	#[cfg(any(all(feature = "tokio", test), fuzzing))]
	/// Returns the size of the async state.
	pub fn state_size(&self) -> usize {
		let outer_lock = self.inner.locks.lock().unwrap();
		outer_lock.len()
	}

	pub(crate) fn get_checked_dest_file_path(
		&self, primary_namespace: &str, secondary_namespace: &str, key: Option<&str>,
		operation: &str, use_empty_ns_dir: bool,
	) -> lightning::io::Result<PathBuf> {
		self.inner.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			key,
			operation,
			use_empty_ns_dir,
		)
	}
}

impl FilesystemStoreInner {
	fn get_inner_lock_ref(&self, path: PathBuf) -> Arc<RwLock<u64>> {
		let mut outer_lock = self.locks.lock().unwrap();
		Arc::clone(&outer_lock.entry(path).or_default())
	}

	fn get_dest_dir_path(
		&self, primary_namespace: &str, secondary_namespace: &str, use_empty_ns_dir: bool,
	) -> std::io::Result<PathBuf> {
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

		if use_empty_ns_dir {
			dest_dir_path.push(if primary_namespace.is_empty() {
				EMPTY_NAMESPACE_DIR
			} else {
				primary_namespace
			});
			dest_dir_path.push(if secondary_namespace.is_empty() {
				EMPTY_NAMESPACE_DIR
			} else {
				secondary_namespace
			});
		} else {
			dest_dir_path.push(primary_namespace);
			if !secondary_namespace.is_empty() {
				dest_dir_path.push(secondary_namespace);
			}
		}

		Ok(dest_dir_path)
	}

	fn get_checked_dest_file_path(
		&self, primary_namespace: &str, secondary_namespace: &str, key: Option<&str>,
		operation: &str, use_empty_ns_dir: bool,
	) -> lightning::io::Result<PathBuf> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, key, operation)?;

		let mut dest_file_path =
			self.get_dest_dir_path(primary_namespace, secondary_namespace, use_empty_ns_dir)?;
		if let Some(key) = key {
			dest_file_path.push(key);
		}

		Ok(dest_file_path)
	}

	fn read(&self, dest_file_path: PathBuf) -> lightning::io::Result<Vec<u8>> {
		let mut buf = Vec::new();

		self.execute_locked_read(dest_file_path.clone(), || {
			let mut f = fs::File::open(dest_file_path)?;
			f.read_to_end(&mut buf)?;
			Ok(())
		})?;

		Ok(buf)
	}

	fn execute_locked_write<F: FnOnce() -> Result<(), lightning::io::Error>>(
		&self, inner_lock_ref: Arc<RwLock<u64>>, dest_file_path: PathBuf, version: u64, callback: F,
	) -> Result<(), lightning::io::Error> {
		let res = {
			let mut last_written_version = inner_lock_ref.write().unwrap();

			// Check if we already have a newer version written/removed. This is used in async contexts to realize eventual
			// consistency.
			let is_stale_version = version <= *last_written_version;

			// If the version is not stale, we execute the callback. Otherwise we can and must skip writing.
			if is_stale_version {
				Ok(())
			} else {
				callback().map(|_| {
					*last_written_version = version;
				})
			}
		};

		self.clean_locks(&inner_lock_ref, dest_file_path);

		res
	}

	fn execute_locked_read<F: FnOnce() -> Result<(), lightning::io::Error>>(
		&self, dest_file_path: PathBuf, callback: F,
	) -> Result<(), lightning::io::Error> {
		let inner_lock_ref = self.get_inner_lock_ref(dest_file_path.clone());
		let res = {
			let _guard = inner_lock_ref.read().unwrap();
			callback()
		};
		self.clean_locks(&inner_lock_ref, dest_file_path);
		res
	}

	fn clean_locks(&self, inner_lock_ref: &Arc<RwLock<u64>>, dest_file_path: PathBuf) {
		// If there no arcs in use elsewhere, this means that there are no in-flight writes. We can remove the map entry
		// to prevent leaking memory. The two arcs that are expected are the one in the map and the one held here in
		// inner_lock_ref. The outer lock is obtained first, to avoid a new arc being cloned after we've already
		// counted.
		let mut outer_lock = self.locks.lock().unwrap();

		let strong_count = Arc::strong_count(&inner_lock_ref);
		debug_assert!(strong_count >= 2, "Unexpected FilesystemStore strong count");

		if strong_count == 2 {
			outer_lock.remove(&dest_file_path);
		}
	}

	/// Writes a specific version of a key to the filesystem. If a newer version has been written already, this function
	/// returns early without writing.
	fn write_version(
		&self, inner_lock_ref: Arc<RwLock<u64>>, dest_file_path: PathBuf, buf: Vec<u8>,
		version: u64, preserve_mtime: bool,
	) -> lightning::io::Result<()> {
		let mtime = if preserve_mtime {
			match fs::metadata(&dest_file_path) {
				Err(e) if e.kind() == ErrorKind::NotFound => None,
				Err(e) => return Err(e.into()),
				Ok(m) => Some(m.modified()?),
			}
		} else {
			None
		};
		let parent_directory = dest_file_path.parent().ok_or_else(|| {
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

			// If we need to preserve the original mtime (for updates), set it before fsync.
			if let Some(mtime) = mtime {
				let times = fs::FileTimes::new().set_modified(mtime);
				tmp_file.set_times(times)?;
			}

			tmp_file.sync_all()?;
		}

		self.execute_locked_write(inner_lock_ref, dest_file_path.clone(), version, || {
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
						let dest_file =
							fs::OpenOptions::new().read(true).write(true).open(&dest_file_path)?;
						dest_file.sync_all()?;
						Ok(())
					},
					Err(e) => Err(e.into()),
				}
			}
		})
	}

	fn remove_version(
		&self, inner_lock_ref: Arc<RwLock<u64>>, dest_file_path: PathBuf, lazy: bool, version: u64,
	) -> lightning::io::Result<()> {
		self.execute_locked_write(inner_lock_ref, dest_file_path.clone(), version, || {
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
					fs::remove_file(&dest_file_path)?;

					let parent_directory = dest_file_path.parent().ok_or_else(|| {
						let msg = format!(
							"Could not retrieve parent directory of {}.",
							dest_file_path.display()
						);
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
					let trash_file_ext =
						format!("{}.trash", self.tmp_file_counter.fetch_add(1, Ordering::AcqRel));
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
						let trash_file = fs::OpenOptions::new()
							.read(true)
							.write(true)
							.open(&trash_file_path.clone())?;
						trash_file.sync_all()?;
					}

					// We're fine if this remove would fail as the trash file will be cleaned up in
					// list eventually.
					fs::remove_file(trash_file_path).ok();
				}
			}

			Ok(())
		})
	}

	fn list(&self, prefixed_dest: PathBuf, is_v2: bool) -> lightning::io::Result<Vec<String>> {
		if !Path::new(&prefixed_dest).exists() {
			return Ok(Vec::new());
		}

		let mut keys;
		let mut retries = if is_v2 { 0 } else { LIST_DIR_CONSISTENCY_RETRIES };

		'retry_list: loop {
			keys = Vec::new();
			'skip_entry: for entry in fs::read_dir(&prefixed_dest)? {
				let entry = entry?;
				let p = entry.path();

				let res = dir_entry_is_key(&entry);
				match res {
					Ok(true) => {
						let key = get_key_from_dir_entry_path(&p, &prefixed_dest, false)?;
						keys.push(key);
					},
					Ok(false) => {
						// We didn't error, but the entry is not a valid key (e.g., a directory,
						// or a temp file).
						continue 'skip_entry;
					},
					Err(e) => {
						// In version 2 if a file has been deleted between the `read_dir` and our attempt
						// to access it, we should just add it to the list to give a more consistent view.
						if is_v2 {
							let key = get_key_from_dir_entry_path(&p, &prefixed_dest, false)?;
							keys.push(key);
							continue 'skip_entry;
						}

						if e.kind() == lightning::io::ErrorKind::NotFound && retries > 0 {
							// We had found the entry in `read_dir` above, so some race happend.
							// Retry the `read_dir` to get a consistent view.
							retries -= 1;
							continue 'retry_list;
						} else {
							// For all errors or if we exhausted retries, bubble up.
							return Err(e.into());
						}
					},
				}
			}
			break 'retry_list;
		}

		Ok(keys)
	}
}

impl FilesystemStoreState {
	pub(crate) fn read_impl(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
		use_empty_ns_dir: bool,
	) -> Result<Vec<u8>, lightning::io::Error> {
		let path = self.inner.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			Some(key),
			"read",
			use_empty_ns_dir,
		)?;
		self.inner.read(path)
	}

	pub(crate) fn write_impl(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
		use_empty_ns_dir: bool,
	) -> Result<(), lightning::io::Error> {
		let path = self.inner.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			Some(key),
			"write",
			use_empty_ns_dir,
		)?;
		let (inner_lock_ref, version) = self.get_new_version_and_lock_ref(path.clone());
		self.inner.write_version(inner_lock_ref, path, buf, version, use_empty_ns_dir)
	}

	pub(crate) fn remove_impl(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
		use_empty_ns_dir: bool,
	) -> Result<(), lightning::io::Error> {
		let path = self.inner.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			Some(key),
			"remove",
			use_empty_ns_dir,
		)?;
		let (inner_lock_ref, version) = self.get_new_version_and_lock_ref(path.clone());
		self.inner.remove_version(inner_lock_ref, path, lazy, version)
	}

	pub(crate) fn list_impl(
		&self, primary_namespace: &str, secondary_namespace: &str, use_empty_ns_dir: bool,
	) -> Result<Vec<String>, lightning::io::Error> {
		let path = self.inner.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			None,
			"list",
			use_empty_ns_dir,
		)?;
		self.inner.list(path, use_empty_ns_dir)
	}

	#[cfg(feature = "tokio")]
	pub(crate) fn read_async(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
		use_empty_ns_dir: bool,
	) -> impl Future<Output = Result<Vec<u8>, lightning::io::Error>> + 'static + Send {
		let this = Arc::clone(&self.inner);
		let path = this.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			Some(key),
			"read",
			use_empty_ns_dir,
		);

		async move {
			let path = match path {
				Ok(path) => path,
				Err(e) => return Err(e),
			};
			tokio::task::spawn_blocking(move || this.read(path)).await.unwrap_or_else(|e| {
				Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e))
			})
		}
	}

	#[cfg(feature = "tokio")]
	pub(crate) fn write_async(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
		use_empty_ns_dir: bool,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		let this = Arc::clone(&self.inner);
		let path = this
			.get_checked_dest_file_path(
				primary_namespace,
				secondary_namespace,
				Some(key),
				"write",
				use_empty_ns_dir,
			)
			.map(|path| (self.get_new_version_and_lock_ref(path.clone()), path));

		async move {
			let ((inner_lock_ref, version), path) = match path {
				Ok(res) => res,
				Err(e) => return Err(e),
			};
			tokio::task::spawn_blocking(move || {
				this.write_version(inner_lock_ref, path, buf, version, use_empty_ns_dir)
			})
			.await
			.unwrap_or_else(|e| Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e)))
		}
	}

	#[cfg(feature = "tokio")]
	pub(crate) fn remove_async(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
		use_empty_ns_dir: bool,
	) -> impl Future<Output = Result<(), lightning::io::Error>> + 'static + Send {
		let this = Arc::clone(&self.inner);
		let path = this
			.get_checked_dest_file_path(
				primary_namespace,
				secondary_namespace,
				Some(key),
				"remove",
				use_empty_ns_dir,
			)
			.map(|path| (self.get_new_version_and_lock_ref(path.clone()), path));

		async move {
			let ((inner_lock_ref, version), path) = match path {
				Ok(res) => res,
				Err(e) => return Err(e),
			};
			tokio::task::spawn_blocking(move || {
				this.remove_version(inner_lock_ref, path, lazy, version)
			})
			.await
			.unwrap_or_else(|e| Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e)))
		}
	}

	#[cfg(feature = "tokio")]
	pub(crate) fn list_async(
		&self, primary_namespace: &str, secondary_namespace: &str, use_empty_ns_dir: bool,
	) -> impl Future<Output = Result<Vec<String>, lightning::io::Error>> + 'static + Send {
		let this = Arc::clone(&self.inner);

		let path = this.get_checked_dest_file_path(
			primary_namespace,
			secondary_namespace,
			None,
			"list",
			use_empty_ns_dir,
		);

		async move {
			let path = match path {
				Ok(path) => path,
				Err(e) => return Err(e),
			};
			tokio::task::spawn_blocking(move || this.list(path, use_empty_ns_dir))
				.await
				.unwrap_or_else(|e| {
					Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, e))
				})
		}
	}

	pub(crate) fn list_all_keys_impl(
		&self, use_empty_ns_dir: bool,
	) -> Result<Vec<(String, String, String)>, lightning::io::Error> {
		let prefixed_dest = &self.inner.data_dir;
		if !prefixed_dest.exists() {
			return Ok(Vec::new());
		}

		let mut keys = Vec::new();

		'primary_loop: for primary_entry in fs::read_dir(prefixed_dest)? {
			let primary_entry = primary_entry?;
			let primary_path = primary_entry.path();

			if dir_entry_is_key(&primary_entry)? {
				let primary_namespace = String::new();
				let secondary_namespace = String::new();
				let key = get_key_from_dir_entry_path(&primary_path, prefixed_dest, false)?;
				keys.push((primary_namespace, secondary_namespace, key));
				continue 'primary_loop;
			}

			// The primary_entry is actually also a directory.
			'secondary_loop: for secondary_entry in fs::read_dir(&primary_path)? {
				let secondary_entry = secondary_entry?;
				let secondary_path = secondary_entry.path();

				if dir_entry_is_key(&secondary_entry)? {
					let primary_namespace = get_key_from_dir_entry_path(
						&primary_path,
						prefixed_dest,
						use_empty_ns_dir,
					)?;
					let secondary_namespace = String::new();
					let key = get_key_from_dir_entry_path(&secondary_path, &primary_path, false)?;
					keys.push((primary_namespace, secondary_namespace, key));
					continue 'secondary_loop;
				}

				// The secondary_entry is actually also a directory.
				for tertiary_entry in fs::read_dir(&secondary_path)? {
					let tertiary_entry = tertiary_entry?;
					let tertiary_path = tertiary_entry.path();

					if dir_entry_is_key(&tertiary_entry)? {
						let primary_namespace = get_key_from_dir_entry_path(
							&primary_path,
							prefixed_dest,
							use_empty_ns_dir,
						)?;
						let secondary_namespace = get_key_from_dir_entry_path(
							&secondary_path,
							&primary_path,
							use_empty_ns_dir,
						)?;
						let key =
							get_key_from_dir_entry_path(&tertiary_path, &secondary_path, false)?;
						keys.push((primary_namespace, secondary_namespace, key));
					} else {
						debug_assert!(
							false,
							"Failed to list keys of path {}: only two levels of namespaces are supported",
							PrintableString(tertiary_path.to_str().unwrap_or_default())
						);
						let msg = format!(
							"Failed to list keys of path {}: only two levels of namespaces are supported",
							PrintableString(tertiary_path.to_str().unwrap_or_default())
						);
						return Err(lightning::io::Error::new(
							lightning::io::ErrorKind::Other,
							msg,
						));
					}
				}
			}
		}
		Ok(keys)
	}
}

fn dir_entry_is_key(dir_entry: &fs::DirEntry) -> Result<bool, lightning::io::Error> {
	let p = dir_entry.path();
	if let Some(ext) = p.extension() {
		#[cfg(target_os = "windows")]
		{
			// Clean up any trash files lying around.
			if ext == "trash" {
				fs::remove_file(p).ok();
				return Ok(false);
			}
		}
		if ext == "tmp" {
			return Ok(false);
		}
	}

	let file_type = dir_entry.file_type()?;

	// We allow the presence of directories in the empty primary namespace and just skip them.
	if file_type.is_dir() {
		return Ok(false);
	}

	// If we otherwise don't find a file at the given path something went wrong.
	if !file_type.is_file() {
		debug_assert!(
			false,
			"Failed to list keys at path {}: file couldn't be accessed.",
			PrintableString(p.to_str().unwrap_or_default())
		);
		let msg = format!(
			"Failed to list keys at path {}: file couldn't be accessed.",
			PrintableString(p.to_str().unwrap_or_default())
		);
		return Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, msg));
	}

	Ok(true)
}

/// Gets the key from a directory entry path by stripping the base path and validating the result.
/// If `map_empty_ns_dir` is true, treats entries with the name of `EMPTY_NAMESPACE_DIR` as an empty string.
/// `map_empty_ns_dir` should always be false when reading keys and only be true when listing namespaces.
pub(crate) fn get_key_from_dir_entry_path(
	p: &Path, base_path: &Path, map_empty_ns_dir: bool,
) -> Result<String, lightning::io::Error> {
	match p.strip_prefix(&base_path) {
		Ok(stripped_path) => {
			if let Some(relative_path) = stripped_path.to_str() {
				if map_empty_ns_dir && relative_path == EMPTY_NAMESPACE_DIR {
					return Ok(String::new());
				}
				if is_valid_kvstore_str(relative_path) {
					return Ok(relative_path.to_string());
				} else {
					debug_assert!(
						false,
						"Failed to list keys of path {}: file path is not valid key",
						PrintableString(p.to_str().unwrap_or_default())
					);
					let msg = format!(
						"Failed to list keys of path {}: file path is not valid key",
						PrintableString(p.to_str().unwrap_or_default())
					);
					return Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, msg));
				}
			} else {
				debug_assert!(
					false,
					"Failed to list keys of path {}: file path is not valid UTF-8",
					PrintableString(p.to_str().unwrap_or_default())
				);
				let msg = format!(
					"Failed to list keys of path {}: file path is not valid UTF-8",
					PrintableString(p.to_str().unwrap_or_default())
				);
				return Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, msg));
			}
		},
		Err(e) => {
			debug_assert!(
				false,
				"Failed to list keys of path {}: {}",
				PrintableString(p.to_str().unwrap_or_default()),
				e
			);
			let msg = format!(
				"Failed to list keys of path {}: {}",
				PrintableString(p.to_str().unwrap_or_default()),
				e
			);
			return Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, msg));
		},
	}
}
