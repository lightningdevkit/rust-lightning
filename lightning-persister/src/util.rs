#[cfg(target_os = "windows")]
extern crate winapi;

use std::fs;
use std::path::PathBuf;
use std::io::BufWriter;

#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;

use lightning::util::ser::Writeable;

#[cfg(target_os = "windows")]
use {
	std::ffi::OsStr,
	std::os::windows::ffi::OsStrExt
};

#[cfg(target_os = "windows")]
macro_rules! call {
	($e: expr) => (
		if $e != 0 {
			return Ok(())
		} else {
			return Err(std::io::Error::last_os_error())
		}
	)
}

#[cfg(target_os = "windows")]
fn path_to_windows_str<T: AsRef<OsStr>>(path: T) -> Vec<winapi::shared::ntdef::WCHAR> {
	path.as_ref().encode_wide().chain(Some(0)).collect()
}

#[allow(bare_trait_objects)]
pub(crate) fn write_to_file<W: Writeable>(dest_file: PathBuf, data: &W) -> std::io::Result<()> {
	let mut tmp_file = dest_file.clone();
	tmp_file.set_extension("tmp");

	let parent_directory = dest_file.parent().unwrap();
	fs::create_dir_all(parent_directory)?;
	// Do a crazy dance with lots of fsync()s to be overly cautious here...
	// We never want to end up in a state where we've lost the old data, or end up using the
	// old data on power loss after we've returned.
	// The way to atomically write a file on Unix platforms is:
	// open(tmpname), write(tmpfile), fsync(tmpfile), close(tmpfile), rename(), fsync(dir)
	{
		// Note that going by rust-lang/rust@d602a6b, on MacOS it is only safe to use
		// rust stdlib 1.36 or higher.
		let mut buf = BufWriter::new(fs::File::create(&tmp_file)?);
		data.write(&mut buf)?;
		buf.into_inner()?.sync_all()?;
	}
	// Fsync the parent directory on Unix.
	#[cfg(not(target_os = "windows"))]
	{
		fs::rename(&tmp_file, &dest_file)?;
		let dir_file = fs::OpenOptions::new().read(true).open(parent_directory)?;
		unsafe { libc::fsync(dir_file.as_raw_fd()); }
	}
	#[cfg(target_os = "windows")]
	{
		if dest_file.exists() {
			unsafe {winapi::um::winbase::ReplaceFileW(
				path_to_windows_str(dest_file).as_ptr(), path_to_windows_str(tmp_file).as_ptr(), std::ptr::null(),
				winapi::um::winbase::REPLACEFILE_IGNORE_MERGE_ERRORS,
				std::ptr::null_mut() as *mut winapi::ctypes::c_void,
				std::ptr::null_mut() as *mut winapi::ctypes::c_void
			)};
		} else {
			call!(unsafe {winapi::um::winbase::MoveFileExW(
				path_to_windows_str(tmp_file).as_ptr(), path_to_windows_str(dest_file).as_ptr(),
				winapi::um::winbase::MOVEFILE_WRITE_THROUGH | winapi::um::winbase::MOVEFILE_REPLACE_EXISTING
			)});
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use lightning::util::ser::{Writer, Writeable};

	use super::{write_to_file};
	use std::fs;
	use std::io;
	use std::path::PathBuf;

	struct TestWriteable{}
	impl Writeable for TestWriteable {
		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
			writer.write_all(&[42; 1])
		}
	}

	// Test that if the persister's path to channel data is read-only, writing
	// data to it fails. Windows ignores the read-only flag for folders, so this
	// test is Unix-only.
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn test_readonly_dir() {
		let test_writeable = TestWriteable{};
		let filename = "test_readonly_dir_persister_filename".to_string();
		let path = "test_readonly_dir_persister_dir";
		fs::create_dir_all(path.to_string()).unwrap();
		let mut perms = fs::metadata(path.to_string()).unwrap().permissions();
		perms.set_readonly(true);
		fs::set_permissions(path.to_string(), perms).unwrap();
		let mut dest_file = PathBuf::from(path);
		dest_file.push(filename);
		match write_to_file(dest_file, &test_writeable) {
			Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
			_ => panic!("Unexpected error message")
		}
	}

	// Test failure to rename in the process of atomically creating a channel
	// monitor's file. We induce this failure by making the `tmp` file a
	// directory.
	// Explanation: given "from" = the file being renamed, "to" = the destination
	// file that already exists: Unix should fail because if "from" is a file,
	// then "to" is also required to be a file.
	// TODO: ideally try to make this work on Windows again
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn test_rename_failure() {
		let test_writeable = TestWriteable{};
		let filename = "test_rename_failure_filename";
		let path = "test_rename_failure_dir";
		let mut dest_file = PathBuf::from(path);
		dest_file.push(filename);
		// Create the channel data file and make it a directory.
		fs::create_dir_all(dest_file.clone()).unwrap();
		match write_to_file(dest_file, &test_writeable) {
			Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EISDIR)),
			_ => panic!("Unexpected Ok(())")
		}
		fs::remove_dir_all(path).unwrap();
	}

	#[test]
	fn test_diskwriteable_failure() {
		struct FailingWriteable {}
		impl Writeable for FailingWriteable {
			fn write<W: Writer>(&self, _writer: &mut W) -> Result<(), std::io::Error> {
				Err(std::io::Error::new(std::io::ErrorKind::Other, "expected failure"))
			}
		}

		let filename = "test_diskwriteable_failure";
		let path = "test_diskwriteable_failure_dir";
		let test_writeable = FailingWriteable{};
		let mut dest_file = PathBuf::from(path);
		dest_file.push(filename);
		match write_to_file(dest_file, &test_writeable) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected failure");
			},
			_ => panic!("unexpected result")
		}
		fs::remove_dir_all(path).unwrap();
	}

	// Test failure to create the temporary file in the persistence process.
	// We induce this failure by having the temp file already exist and be a
	// directory.
	#[test]
	fn test_tmp_file_creation_failure() {
		let test_writeable = TestWriteable{};
		let filename = "test_tmp_file_creation_failure_filename".to_string();
		let path = "test_tmp_file_creation_failure_dir";
		let mut dest_file = PathBuf::from(path);
		dest_file.push(filename);
		let mut tmp_file = dest_file.clone();
		tmp_file.set_extension("tmp");
		fs::create_dir_all(tmp_file).unwrap();
		match write_to_file(dest_file, &test_writeable) {
			Err(e) => {
				#[cfg(not(target_os = "windows"))]
				assert_eq!(e.raw_os_error(), Some(libc::EISDIR));
				#[cfg(target_os = "windows")]
				assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
			}
			_ => panic!("Unexpected error message")
		}
	}
}
