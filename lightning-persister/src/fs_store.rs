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
fn path_to_windows_str<T: AsRef<OsStr>>(path: T) -> Vec<u16> {
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

	fn get_dest_dir_path(&self, namespace: &str, sub_namespace: &str) -> std::io::Result<PathBuf> {
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

		dest_dir_path.push(namespace);
		if !sub_namespace.is_empty() {
			dest_dir_path.push(sub_namespace);
		}

		Ok(dest_dir_path)
	}
}

impl KVStore for FilesystemStore {
	fn read(&self, namespace: &str, sub_namespace: &str, key: &str) -> std::io::Result<Vec<u8>> {
		check_namespace_key_validity(namespace, sub_namespace, Some(key), "read")?;

		let mut dest_file_path = self.get_dest_dir_path(namespace, sub_namespace)?;
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

	fn write(&self, namespace: &str, sub_namespace: &str, key: &str, buf: &[u8]) -> std::io::Result<()> {
		check_namespace_key_validity(namespace, sub_namespace, Some(key), "write")?;

		let mut dest_file_path = self.get_dest_dir_path(namespace, sub_namespace)?;
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
							path_to_windows_str(dest_file_path.clone()).as_ptr(),
							path_to_windows_str(tmp_file_path).as_ptr(),
							std::ptr::null(),
							windows_sys::Win32::Storage::FileSystem::REPLACEFILE_IGNORE_MERGE_ERRORS,
							std::ptr::null_mut() as *const core::ffi::c_void,
							std::ptr::null_mut() as *const core::ffi::c_void,
							)
					})
				} else {
					call!(unsafe {
						windows_sys::Win32::Storage::FileSystem::MoveFileExW(
							path_to_windows_str(tmp_file_path).as_ptr(),
							path_to_windows_str(dest_file_path.clone()).as_ptr(),
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

	fn remove(&self, namespace: &str, sub_namespace: &str, key: &str, lazy: bool) -> std::io::Result<()> {
		check_namespace_key_validity(namespace, sub_namespace, Some(key), "remove")?;

		let mut dest_file_path = self.get_dest_dir_path(namespace, sub_namespace)?;
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
							path_to_windows_str(dest_file_path).as_ptr(),
							path_to_windows_str(trash_file_path.clone()).as_ptr(),
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

	fn list(&self, namespace: &str, sub_namespace: &str) -> std::io::Result<Vec<String>> {
		check_namespace_key_validity(namespace, sub_namespace, None, "list")?;

		let prefixed_dest = self.get_dest_dir_path(namespace, sub_namespace)?;
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

			// We allow the presence of directories in the empty namespace and just skip them.
			if metadata.is_dir() {
				continue;
			}

			// If we otherwise don't find a file at the given path something went wrong.
			if !metadata.is_file() {
				debug_assert!(false, "Failed to list keys of {}/{}: file couldn't be accessed.",
					PrintableString(namespace), PrintableString(sub_namespace));
				let msg = format!("Failed to list keys of {}/{}: file couldn't be accessed.",
					PrintableString(namespace), PrintableString(sub_namespace));
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
							PrintableString(namespace), PrintableString(sub_namespace));
						let msg = format!("Failed to list keys of {}/{}: file path is not valid UTF-8",
							PrintableString(namespace), PrintableString(sub_namespace));
						return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
					}
				}
				Err(e) => {
					debug_assert!(false, "Failed to list keys of {}/{}: {}",
						PrintableString(namespace), PrintableString(sub_namespace), e);
					let msg = format!("Failed to list keys of {}/{}: {}",
						PrintableString(namespace), PrintableString(sub_namespace), e);
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
	use crate::test_utils::do_read_write_remove_list_persist;

	#[test]
	fn read_write_remove_list_persist() {
		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_read_write_remove_list_persist");
		let fs_store = FilesystemStore::new(temp_path);
		do_read_write_remove_list_persist(&fs_store);
	}
}
