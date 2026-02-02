//! Common utilities shared between [`FilesystemStore`] and [`FilesystemStoreV2`].
//!
//! [`FilesystemStore`]: crate::fs_store::FilesystemStore
//! [`FilesystemStoreV2`]: crate::fs_store_v2::FilesystemStoreV2

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
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
pub(crate) use call;

/// Converts a path to a null-terminated wide string for Windows API calls.
#[cfg(target_os = "windows")]
pub(crate) fn path_to_windows_str<T: AsRef<OsStr>>(path: &T) -> Vec<u16> {
	path.as_ref().encode_wide().chain(Some(0)).collect()
}

/// Inner state shared between sync and async operations for filesystem stores.
///
/// This struct manages the data directory, temporary file counter, and per-path locks
/// that ensure we don't have concurrent writes to the same file.
pub(crate) struct FilesystemStoreState {
	pub(crate) data_dir: PathBuf,
	pub(crate) tmp_file_counter: AtomicUsize,
	/// Per path lock that ensures that we don't have concurrent writes to the same file.
	/// The lock also encapsulates the latest written version per key.
	pub(crate) locks: Mutex<HashMap<PathBuf, Arc<RwLock<u64>>>>,
}

impl FilesystemStoreState {
	/// Creates a new `FilesystemStoreState` with the given data directory.
	pub(crate) fn new(data_dir: PathBuf) -> Self {
		Self { data_dir, tmp_file_counter: AtomicUsize::new(0), locks: Mutex::new(HashMap::new()) }
	}

	/// Gets or creates a lock reference for the given path.
	pub(crate) fn get_inner_lock_ref(&self, path: PathBuf) -> Arc<RwLock<u64>> {
		let mut outer_lock = self.locks.lock().unwrap();
		Arc::clone(&outer_lock.entry(path).or_default())
	}

	/// Cleans up unused locks to prevent memory leaks.
	///
	/// If there are no arcs in use elsewhere (besides the map entry and the provided reference),
	/// we can remove the map entry to prevent leaking memory.
	pub(crate) fn clean_locks(&self, inner_lock_ref: &Arc<RwLock<u64>>, dest_file_path: PathBuf) {
		let mut outer_lock = self.locks.lock().unwrap();

		let strong_count = Arc::strong_count(inner_lock_ref);
		debug_assert!(strong_count >= 2, "Unexpected FilesystemStore strong count");

		if strong_count == 2 {
			outer_lock.remove(&dest_file_path);
		}
	}

	/// Executes a read operation while holding the read lock for the given path.
	pub(crate) fn execute_locked_read<F: FnOnce() -> Result<(), lightning::io::Error>>(
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

	/// Executes a write operation with version tracking.
	///
	/// Returns `Ok(true)` if the callback was executed, `Ok(false)` if skipped due to staleness.
	pub(crate) fn execute_locked_write<F: FnOnce() -> Result<(), lightning::io::Error>>(
		&self, inner_lock_ref: Arc<RwLock<u64>>, lock_key: PathBuf, version: u64, callback: F,
	) -> Result<bool, lightning::io::Error> {
		let res = {
			let mut last_written_version = inner_lock_ref.write().unwrap();

			// Check if we already have a newer version written/removed. This is used in async
			// contexts to realize eventual consistency.
			let is_stale_version = version <= *last_written_version;

			// If the version is not stale, we execute the callback. Otherwise we can and must skip.
			if is_stale_version {
				Ok(false)
			} else {
				callback().map(|_| {
					*last_written_version = version;
					true
				})
			}
		};

		self.clean_locks(&inner_lock_ref, lock_key);

		res
	}

	/// Returns the base directory path for a namespace combination.
	///
	/// On Windows, this canonicalizes the path after creating the data directory.
	pub(crate) fn get_base_dir_path(&self) -> std::io::Result<PathBuf> {
		#[cfg(target_os = "windows")]
		{
			let data_dir = self.data_dir.clone();
			fs::create_dir_all(data_dir.clone())?;
			fs::canonicalize(data_dir)
		}
		#[cfg(not(target_os = "windows"))]
		{
			Ok(self.data_dir.clone())
		}
	}

	/// Generates a unique temporary file path based on the destination path.
	pub(crate) fn get_tmp_file_path(&self, dest_file_path: &PathBuf) -> PathBuf {
		let mut tmp_file_path = dest_file_path.clone();
		let tmp_file_ext = format!("{}.tmp", self.tmp_file_counter.fetch_add(1, Ordering::AcqRel));
		tmp_file_path.set_extension(tmp_file_ext);
		tmp_file_path
	}

	/// Generates a unique trash file path for Windows deletion operations.
	#[cfg(target_os = "windows")]
	pub(crate) fn get_trash_file_path(&self, dest_file_path: &PathBuf) -> PathBuf {
		let mut trash_file_path = dest_file_path.clone();
		let trash_file_ext =
			format!("{}.trash", self.tmp_file_counter.fetch_add(1, Ordering::AcqRel));
		trash_file_path.set_extension(trash_file_ext);
		trash_file_path
	}
}

/// Options for writing a file atomically.
#[derive(Default)]
pub(crate) struct WriteOptions {
	/// If set, the file's modification time will be set to this value.
	pub(crate) preserve_mtime: Option<std::time::SystemTime>,
}

/// Writes data to a temporary file and prepares it for atomic rename.
///
/// This handles:
/// - Creating the parent directory
/// - Writing to a temporary file
/// - Setting mtime if requested (for FilesystemStoreV2)
/// - Syncing the temp file
///
/// Returns the temporary file path that should be renamed to the destination.
pub(crate) fn prepare_atomic_write(
	state: &FilesystemStoreState, dest_file_path: &PathBuf, buf: &[u8], options: &WriteOptions,
) -> lightning::io::Result<PathBuf> {
	let parent_directory = dest_file_path.parent().ok_or_else(|| {
		let msg = format!("Could not retrieve parent directory of {}.", dest_file_path.display());
		std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
	})?;
	fs::create_dir_all(parent_directory)?;

	let tmp_file_path = state.get_tmp_file_path(dest_file_path);

	{
		let tmp_file = fs::File::create(&tmp_file_path)?;
		let mut writer = std::io::BufWriter::new(&tmp_file);
		writer.write_all(buf)?;
		writer.flush()?;

		// If we need to preserve the original mtime (for updates), set it before fsync.
		if let Some(mtime) = options.preserve_mtime {
			let times = std::fs::FileTimes::new().set_modified(mtime);
			tmp_file.set_times(times)?;
		}

		tmp_file.sync_all()?;
	}

	Ok(tmp_file_path)
}

/// Performs the atomic rename from temp file to destination on Unix.
#[cfg(not(target_os = "windows"))]
pub(crate) fn finalize_atomic_write_unix(
	tmp_file_path: &PathBuf, dest_file_path: &PathBuf,
) -> lightning::io::Result<()> {
	fs::rename(tmp_file_path, dest_file_path)?;

	let parent_directory = dest_file_path.parent().ok_or_else(|| {
		let msg = format!("Could not retrieve parent directory of {}.", dest_file_path.display());
		std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
	})?;

	let dir_file = fs::OpenOptions::new().read(true).open(parent_directory)?;
	dir_file.sync_all()?;
	Ok(())
}

/// Performs the atomic rename from temp file to destination on Windows.
#[cfg(target_os = "windows")]
pub(crate) fn finalize_atomic_write_windows(
	tmp_file_path: &PathBuf, dest_file_path: &PathBuf, options: &WriteOptions,
) -> lightning::io::Result<()> {
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
			// Open the destination file to fsync it and set mtime if needed.
			let dest_file = fs::OpenOptions::new().read(true).write(true).open(dest_file_path)?;

			// On Windows, ReplaceFileW/MoveFileExW may not preserve the mtime we set
			// on the tmp file, so we explicitly set it again here.
			if let Some(mtime) = options.preserve_mtime {
				let times = std::fs::FileTimes::new().set_modified(mtime);
				dest_file.set_times(times)?;
			}

			dest_file.sync_all()?;
			Ok(())
		},
		Err(e) => Err(e.into()),
	}
}

/// Removes a file atomically on Unix with fsync on the parent directory.
#[cfg(not(target_os = "windows"))]
pub(crate) fn remove_file_unix(dest_file_path: &PathBuf) -> lightning::io::Result<()> {
	fs::remove_file(dest_file_path)?;

	let parent_directory = dest_file_path.parent().ok_or_else(|| {
		let msg = format!("Could not retrieve parent directory of {}.", dest_file_path.display());
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
	Ok(())
}

/// Removes a file on Windows using the trash file approach for durability.
#[cfg(target_os = "windows")]
pub(crate) fn remove_file_windows(
	state: &FilesystemStoreState, dest_file_path: &PathBuf,
) -> lightning::io::Result<()> {
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
	let trash_file_path = state.get_trash_file_path(dest_file_path);

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
		let trash_file = fs::OpenOptions::new().read(true).write(true).open(&trash_file_path)?;
		trash_file.sync_all()?;
	}

	// We're fine if this remove would fail as the trash file will be cleaned up in
	// list eventually.
	fs::remove_file(trash_file_path).ok();

	Ok(())
}
