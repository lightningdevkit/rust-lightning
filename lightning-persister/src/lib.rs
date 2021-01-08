extern crate lightning;
extern crate bitcoin;
extern crate libc;

use bitcoin::hashes::hex::ToHex;
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateErr};
use lightning::chain::channelmonitor;
use lightning::chain::keysinterface::ChannelKeys;
use lightning::chain::transaction::OutPoint;
use lightning::util::ser::Writeable;
use std::fs;
use std::io::Error;
use std::path::{Path, PathBuf};

#[cfg(test)]
use {
	lightning::chain::keysinterface::KeysInterface,
	lightning::util::ser::ReadableArgs,
	bitcoin::{BlockHash, Txid},
	bitcoin::hashes::hex::FromHex,
	std::collections::HashMap,
	std::io::Cursor
};

#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;

/// FilesystemPersister persists channel data on disk, where each channel's
/// data is stored in a file named after its funding outpoint.
///
/// Warning: this module does the best it can with calls to persist data, but it
/// can only guarantee that the data is passed to the drive. It is up to the
/// drive manufacturers to do the actual persistence properly, which they often
/// don't (especially on consumer-grade hardware). Therefore, it is up to the
/// user to validate their entire storage stack, to ensure the writes are
/// persistent.
/// Corollary: especially when dealing with larger amounts of money, it is best
/// practice to have multiple channel data backups and not rely only on one
/// FilesystemPersister.
pub struct FilesystemPersister {
	path_to_channel_data: String,
}

trait DiskWriteable {
	fn write(&self, writer: &mut fs::File) -> Result<(), Error>;
}

impl<ChanSigner: ChannelKeys> DiskWriteable for ChannelMonitor<ChanSigner> {
	fn write(&self, writer: &mut fs::File) -> Result<(), Error> {
		Writeable::write(self, writer)
	}
}

impl FilesystemPersister {
	/// Initialize a new FilesystemPersister and set the path to the individual channels'
	/// files.
	pub fn new(path_to_channel_data: String) -> Self {
		return Self {
			path_to_channel_data,
		}
	}

	fn get_full_filepath(&self, funding_txo: OutPoint) -> String {
		let mut path = PathBuf::from(&self.path_to_channel_data);
		path.push(format!("{}_{}", funding_txo.txid.to_hex(), funding_txo.index));
		path.to_str().unwrap().to_string()
	}

	// Utility to write a file to disk.
	fn write_channel_data(&self, funding_txo: OutPoint, monitor: &dyn DiskWriteable) -> std::io::Result<()> {
		fs::create_dir_all(&self.path_to_channel_data)?;
		// Do a crazy dance with lots of fsync()s to be overly cautious here...
		// We never want to end up in a state where we've lost the old data, or end up using the
		// old data on power loss after we've returned.
		// The way to atomically write a file on Unix platforms is:
		// open(tmpname), write(tmpfile), fsync(tmpfile), close(tmpfile), rename(), fsync(dir)
		let filename = self.get_full_filepath(funding_txo);
		let tmp_filename = format!("{}.tmp", filename.clone());

		{
			// Note that going by rust-lang/rust@d602a6b, on MacOS it is only safe to use
			// rust stdlib 1.36 or higher.
			let mut f = fs::File::create(&tmp_filename)?;
			monitor.write(&mut f)?;
			f.sync_all()?;
		}
		fs::rename(&tmp_filename, &filename)?;
		// Fsync the parent directory on Unix.
		#[cfg(not(target_os = "windows"))]
		{
			let path = Path::new(&filename).parent().unwrap();
			let dir_file = fs::OpenOptions::new().read(true).open(path)?;
			unsafe { libc::fsync(dir_file.as_raw_fd()); }
		}
		Ok(())
	}

	#[cfg(test)]
	fn load_channel_data<Keys: KeysInterface>(&self, keys: &Keys) ->
		Result<HashMap<OutPoint, ChannelMonitor<Keys::ChanKeySigner>>, ChannelMonitorUpdateErr> {
		if let Err(_) = fs::create_dir_all(&self.path_to_channel_data) {
			return Err(ChannelMonitorUpdateErr::PermanentFailure);
		}
		let mut res = HashMap::new();
		for file_option in fs::read_dir(&self.path_to_channel_data).unwrap() {
			let file = file_option.unwrap();
			let owned_file_name = file.file_name();
			let filename = owned_file_name.to_str();
			if !filename.is_some() || !filename.unwrap().is_ascii() || filename.unwrap().len() < 65 {
				return Err(ChannelMonitorUpdateErr::PermanentFailure);
			}

			let txid = Txid::from_hex(filename.unwrap().split_at(64).0);
			if txid.is_err() { return Err(ChannelMonitorUpdateErr::PermanentFailure); }

			let index = filename.unwrap().split_at(65).1.split('.').next().unwrap().parse();
			if index.is_err() { return Err(ChannelMonitorUpdateErr::PermanentFailure); }

			let contents = fs::read(&file.path());
			if contents.is_err() { return Err(ChannelMonitorUpdateErr::PermanentFailure); }

			if let Ok((_, loaded_monitor)) =
				<(BlockHash, ChannelMonitor<Keys::ChanKeySigner>)>::read(&mut Cursor::new(&contents.unwrap()), keys) {
				res.insert(OutPoint { txid: txid.unwrap(), index: index.unwrap() }, loaded_monitor);
			} else {
				return Err(ChannelMonitorUpdateErr::PermanentFailure);
			}
		}
		Ok(res)
	}
}

impl<ChanSigner: ChannelKeys + Send + Sync> channelmonitor::Persist<ChanSigner> for FilesystemPersister {
	fn persist_new_channel(&self, funding_txo: OutPoint, monitor: &ChannelMonitor<ChanSigner>) -> Result<(), ChannelMonitorUpdateErr> {
		self.write_channel_data(funding_txo, monitor)
		  .map_err(|_| ChannelMonitorUpdateErr::PermanentFailure)
	}

	fn update_persisted_channel(&self, funding_txo: OutPoint, _update: &ChannelMonitorUpdate, monitor: &ChannelMonitor<ChanSigner>) -> Result<(), ChannelMonitorUpdateErr> {
		self.write_channel_data(funding_txo, monitor)
		  .map_err(|_| ChannelMonitorUpdateErr::PermanentFailure)
	}
}

#[cfg(test)]
impl Drop for FilesystemPersister {
	fn drop(&mut self) {
		// We test for invalid directory names, so it's OK if directory removal
		// fails.
		match fs::remove_dir_all(&self.path_to_channel_data) {
			Err(e) => println!("Failed to remove test persister directory: {}", e),
			_ => {}
		}
	}
}

#[cfg(test)]
mod tests {
	extern crate lightning;
	extern crate bitcoin;
	use crate::FilesystemPersister;
	use bitcoin::blockdata::block::{Block, BlockHeader};
	use bitcoin::hashes::hex::FromHex;
	use bitcoin::Txid;
	use DiskWriteable;
	use Error;
	use lightning::chain::channelmonitor::{Persist, ChannelMonitorUpdateErr};
	use lightning::chain::transaction::OutPoint;
	use lightning::{check_closed_broadcast, check_added_monitors};
	use lightning::ln::features::InitFeatures;
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::ErrorAction;
	use lightning::util::events::{MessageSendEventsProvider, MessageSendEvent};
	use lightning::util::ser::Writer;
	use lightning::util::test_utils;
	use std::fs;
	use std::io;
	#[cfg(target_os = "windows")]
	use {
		lightning::get_event_msg,
		lightning::ln::msgs::ChannelMessageHandler,
	};

	struct TestWriteable{}
	impl DiskWriteable for TestWriteable {
		fn write(&self, writer: &mut fs::File) -> Result<(), Error> {
			writer.write_all(&[42; 1])
		}
	}

	// Integration-test the FilesystemPersister. Test relaying a few payments
	// and check that the persisted data is updated the appropriate number of
	// times.
	#[test]
	fn test_filesystem_persister() {
		// Create the nodes, giving them FilesystemPersisters for data persisters.
		let persister_0 = FilesystemPersister::new("test_filesystem_persister_0".to_string());
		let persister_1 = FilesystemPersister::new("test_filesystem_persister_1".to_string());
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let chain_mon_0 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, &persister_0);
		let chain_mon_1 = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[1].chain_source), &chanmon_cfgs[1].tx_broadcaster, &chanmon_cfgs[1].logger, &chanmon_cfgs[1].fee_estimator, &persister_1);
		node_cfgs[0].chain_monitor = chain_mon_0;
		node_cfgs[1].chain_monitor = chain_mon_1;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		// Check that the persisted channel data is empty before any channels are
		// open.
		let mut persisted_chan_data_0 = persister_0.load_channel_data(nodes[0].keys_manager).unwrap();
		assert_eq!(persisted_chan_data_0.keys().len(), 0);
		let mut persisted_chan_data_1 = persister_1.load_channel_data(nodes[1].keys_manager).unwrap();
		assert_eq!(persisted_chan_data_1.keys().len(), 0);

		// Helper to make sure the channel is on the expected update ID.
		macro_rules! check_persisted_data {
			($expected_update_id: expr) => {
				persisted_chan_data_0 = persister_0.load_channel_data(nodes[0].keys_manager).unwrap();
				assert_eq!(persisted_chan_data_0.keys().len(), 1);
				for mon in persisted_chan_data_0.values() {
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);
				}
				persisted_chan_data_1 = persister_1.load_channel_data(nodes[1].keys_manager).unwrap();
				assert_eq!(persisted_chan_data_1.keys().len(), 1);
				for mon in persisted_chan_data_1.values() {
					assert_eq!(mon.get_latest_update_id(), $expected_update_id);
				}
			}
		}

		// Create some initial channel and check that a channel was persisted.
		let _ = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
		check_persisted_data!(0);

		// Send a few payments and make sure the monitors are updated to the latest.
		send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);
		check_persisted_data!(5);
		send_payment(&nodes[1], &vec!(&nodes[0])[..], 4000000, 4_000_000);
		check_persisted_data!(10);

		// Force close because cooperative close doesn't result in any persisted
		// updates.
		nodes[0].node.force_close_channel(&nodes[0].node.list_channels()[0].channel_id);
		check_closed_broadcast!(nodes[0], false);
		check_added_monitors!(nodes[0], 1);

		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[0].clone(), node_txn[0].clone()]}, 1);
		check_closed_broadcast!(nodes[1], false);
		check_added_monitors!(nodes[1], 1);

		// Make sure everything is persisted as expected after close.
		check_persisted_data!(11);
	}

	// Test that if the persister's path to channel data is read-only, writing
	// data to it fails. Windows ignores the read-only flag for folders, so this
	// test is Unix-only.
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn test_readonly_dir() {
		let persister = FilesystemPersister::new("test_readonly_dir_persister".to_string());
		let test_writeable = TestWriteable{};
		let test_txo = OutPoint {
			txid: Txid::from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(),
			index: 0
		};
		// Create the persister's directory and set it to read-only.
		let path = &persister.path_to_channel_data;
		fs::create_dir_all(path).unwrap();
		let mut perms = fs::metadata(path).unwrap().permissions();
		perms.set_readonly(true);
		fs::set_permissions(path, perms).unwrap();
		match persister.write_channel_data(test_txo, &test_writeable) {
			Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
			_ => panic!("Unexpected error message")
		}
	}

	// Test failure to rename in the process of atomically creating a channel
	// monitor's file. We induce this failure by making the `tmp` file a
	// directory.
	// Explanation: given "from" = the file being renamed, "to" = the
	// renamee that already exists: Windows should fail because it'll fail
	// whenever "to" is a directory, and Unix should fail because if "from" is a
	// file, then "to" is also required to be a file.
	#[test]
	fn test_rename_failure() {
		let persister = FilesystemPersister::new("test_rename_failure".to_string());
		let test_writeable = TestWriteable{};
		let txid_hex = "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be";
		let outp_idx = 0;
		let test_txo = OutPoint {
			txid: Txid::from_hex(txid_hex).unwrap(),
			index: outp_idx,
		};
		// Create the channel data file and make it a directory.
		let path = &persister.path_to_channel_data;
		fs::create_dir_all(format!("{}/{}_{}", path, txid_hex, outp_idx)).unwrap();
		match persister.write_channel_data(test_txo, &test_writeable) {
			Err(e) => {
				#[cfg(not(target_os = "windows"))]
				assert_eq!(e.kind(), io::ErrorKind::Other);
				#[cfg(target_os = "windows")]
				assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
			}
			_ => panic!("Unexpected error message")
		}
	}

	// Test failure to create the temporary file in the persistence process.
	// We induce this failure by having the temp file already exist and be a
	// directory.
	#[test]
	fn test_tmp_file_creation_failure() {
		let persister = FilesystemPersister::new("test_tmp_file_creation_failure".to_string());
		let test_writeable = TestWriteable{};
		let txid_hex = "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be";
		let outp_idx = 0;
		let test_txo = OutPoint {
			txid: Txid::from_hex(txid_hex).unwrap(),
			index: outp_idx,
		};
		// Create the tmp file and make it a directory.
		let path = &persister.path_to_channel_data;
		fs::create_dir_all(format!("{}/{}_{}.tmp", path, txid_hex, outp_idx)).unwrap();
		match persister.write_channel_data(test_txo, &test_writeable) {
			Err(e) => {
				#[cfg(not(target_os = "windows"))]
				assert_eq!(e.kind(), io::ErrorKind::Other);
				#[cfg(target_os = "windows")]
				assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
			}
			_ => panic!("Unexpected error message")
		}
	}

	// Test that if the persister's path to channel data is read-only, writing a
	// monitor to it results in the persister returning a PermanentFailure.
	// Windows ignores the read-only flag for folders, so this test is Unix-only.
	#[cfg(not(target_os = "windows"))]
	#[test]
	fn test_readonly_dir_perm_failure() {
		let persister = FilesystemPersister::new("test_readonly_dir_perm_failure".to_string());
		fs::create_dir_all(&persister.path_to_channel_data).unwrap();

		// Set up a dummy channel and force close. This will produce a monitor
		// that we can then use to test persistence.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
		nodes[1].node.force_close_channel(&chan.2);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();

		// Set the persister's directory to read-only, which should result in
		// returning a permanent failure when we then attempt to persist a
		// channel update.
		let path = &persister.path_to_channel_data;
		let mut perms = fs::metadata(path).unwrap().permissions();
		perms.set_readonly(true);
		fs::set_permissions(path, perms).unwrap();

		let test_txo = OutPoint {
			txid: Txid::from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(),
			index: 0
		};
		match persister.persist_new_channel(test_txo, &added_monitors[0].1) {
			Err(ChannelMonitorUpdateErr::PermanentFailure) => {},
			_ => panic!("unexpected result from persisting new channel")
		}

		nodes[1].node.get_and_clear_pending_msg_events();
		added_monitors.clear();
	}

	// Test that if a persister's directory name is invalid, monitor persistence
	// will fail.
	#[cfg(target_os = "windows")]
	#[test]
	fn test_fail_on_open() {
		// Set up a dummy channel and force close. This will produce a monitor
		// that we can then use to test persistence.
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
		nodes[1].node.force_close_channel(&chan.2);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();

		// Create the persister with an invalid directory name and test that the
		// channel fails to open because the directories fail to be created. There
		// don't seem to be invalid filename characters on Unix that Rust doesn't
		// handle, hence why the test is Windows-only.
		let persister = FilesystemPersister::new(":<>/".to_string());

		let test_txo = OutPoint {
			txid: Txid::from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be").unwrap(),
			index: 0
		};
		match persister.persist_new_channel(test_txo, &added_monitors[0].1) {
			Err(ChannelMonitorUpdateErr::PermanentFailure) => {},
			_ => panic!("unexpected result from persisting new channel")
		}

		nodes[1].node.get_and_clear_pending_msg_events();
		added_monitors.clear();
	}
}
