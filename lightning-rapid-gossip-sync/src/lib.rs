// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(unused_variables)]
#![deny(unused_imports)]
//! This crate exposes client functionality to rapidly sync gossip data, aimed primarily at mobile
//! devices.
//!
//! The rapid gossip sync server will provide a compressed response containing differential gossip
//! data. The gossip data is formatted compactly, omitting signatures and opportunistically
//! incremental where previous channel updates are known. This mechanism is enabled when the
//! timestamp of the last known channel update is communicated. A reference server implementation
//! can be found [on Github](https://github.com/lightningdevkit/rapid-gossip-sync-server).
//!
//! The primary benefit of this syncing mechanism is that it allows a low-powered client to offload
//! the validation of gossip signatures to a semi-trusted server. This enables the client to
//! privately calculate routes for payments, and to do so much faster than requiring a full
//! peer-to-peer gossip sync to complete.
//!
//! The server calculates its response on the basis of a client-provided `latest_seen` timestamp,
//! i.e., the server will return all rapid gossip sync data it has seen after the given timestamp.
//!
//! # Getting Started
//! Firstly, the data needs to be retrieved from the server. For example, you could use the server
//! at <https://rapidsync.lightningdevkit.org> with the following request format:
//!
//! ```shell
//! curl -o rapid_sync.lngossip https://rapidsync.lightningdevkit.org/snapshot/<last_sync_timestamp>
//! ```
//! Note that the first ever rapid sync should use `0` for `last_sync_timestamp`.
//!
//! After the gossip data snapshot has been downloaded, one of the client's graph processing
//! functions needs to be called. In this example, we process the update by reading its contents
//! from disk, which we do by calling [`RapidGossipSync::update_network_graph`]:
//!
//! ```
//! use bitcoin::blockdata::constants::genesis_block;
//! use bitcoin::Network;
//! use lightning::routing::gossip::NetworkGraph;
//! use lightning_rapid_gossip_sync::RapidGossipSync;
//!
//! # use lightning::util::logger::{Logger, Record};
//! # struct FakeLogger {}
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # let logger = FakeLogger {};
//!
//! let network_graph = NetworkGraph::new(Network::Bitcoin, &logger);
//! let rapid_sync = RapidGossipSync::new(&network_graph, &logger);
//! let snapshot_contents: &[u8] = &[0; 0];
//! let new_last_sync_timestamp_result = rapid_sync.update_network_graph(snapshot_contents);
//! ```

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

// Allow and import test features for benching
#![cfg_attr(all(test, feature = "_bench_unstable"), feature(test))]
#[cfg(all(test, feature = "_bench_unstable"))]
extern crate test;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
use std::fs::File;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, Ordering};

use lightning::io;
use lightning::routing::gossip::NetworkGraph;
use lightning::util::logger::Logger;

pub use crate::error::GraphSyncError;

/// Error types that these functions can return
mod error;

/// Core functionality of this crate
mod processing;

/// The main Rapid Gossip Sync object.
///
/// See [crate-level documentation] for usage.
///
/// [crate-level documentation]: crate
pub struct RapidGossipSync<NG: Deref<Target=NetworkGraph<L>>, L: Deref>
where L::Target: Logger {
	network_graph: NG,
	logger: L,
	is_initial_sync_complete: AtomicBool
}

impl<NG: Deref<Target=NetworkGraph<L>>, L: Deref> RapidGossipSync<NG, L> where L::Target: Logger {
	/// Instantiate a new [`RapidGossipSync`] instance.
	pub fn new(network_graph: NG, logger: L) -> Self {
		Self {
			network_graph,
			logger,
			is_initial_sync_complete: AtomicBool::new(false)
		}
	}

	/// Sync gossip data from a file.
	/// Returns the last sync timestamp to be used the next time rapid sync data is queried.
	///
	/// `network_graph`: The network graph to apply the updates to
	///
	/// `sync_path`: Path to the file where the gossip update data is located
	///
	#[cfg(feature = "std")]
	pub fn sync_network_graph_with_file_path(
		&self,
		sync_path: &str,
	) -> Result<u32, GraphSyncError> {
		let mut file = File::open(sync_path)?;
		self.update_network_graph_from_byte_stream(&mut file)
	}

	/// Update network graph from binary data.
	/// Returns the last sync timestamp to be used the next time rapid sync data is queried.
	///
	/// `update_data`: `&[u8]` binary stream that comprises the update data
	pub fn update_network_graph(&self, update_data: &[u8]) -> Result<u32, GraphSyncError> {
		let mut read_cursor = io::Cursor::new(update_data);
		self.update_network_graph_from_byte_stream(&mut read_cursor)
	}

	/// Update network graph from binary data.
	/// Returns the last sync timestamp to be used the next time rapid sync data is queried.
	///
	/// `update_data`: `&[u8]` binary stream that comprises the update data
	/// `current_time_unix`: `Option<u64>` optional current timestamp to verify data age
	pub fn update_network_graph_no_std(&self, update_data: &[u8], current_time_unix: Option<u64>) -> Result<u32, GraphSyncError> {
		let mut read_cursor = io::Cursor::new(update_data);
		self.update_network_graph_from_byte_stream_no_std(&mut read_cursor, current_time_unix)
	}

	/// Gets a reference to the underlying [`NetworkGraph`] which was provided in
	/// [`RapidGossipSync::new`].
	///
	/// (C-not exported) as bindings don't support a reference-to-a-reference yet
	pub fn network_graph(&self) -> &NG {
		&self.network_graph
	}

	/// Returns whether a rapid gossip sync has completed at least once.
	pub fn is_initial_sync_complete(&self) -> bool {
		self.is_initial_sync_complete.load(Ordering::Acquire)
	}
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
	use std::fs;

	use bitcoin::Network;

	use lightning::ln::msgs::DecodeError;
	use lightning::routing::gossip::NetworkGraph;
	use lightning::util::test_utils::TestLogger;
	use crate::RapidGossipSync;

	#[test]
	fn test_sync_from_file() {
		struct FileSyncTest {
			directory: String,
		}

		impl FileSyncTest {
			fn new(tmp_directory: &str, valid_response: &[u8]) -> FileSyncTest {
				let test = FileSyncTest { directory: tmp_directory.to_owned() };

				let graph_sync_test_directory = test.get_test_directory();
				fs::create_dir_all(graph_sync_test_directory).unwrap();

				let graph_sync_test_file = test.get_test_file_path();
				fs::write(&graph_sync_test_file, valid_response).unwrap();

				test
			}
			fn get_test_directory(&self) -> String {
				let graph_sync_test_directory = self.directory.clone() + "/graph-sync-tests";
				graph_sync_test_directory
			}
			fn get_test_file_path(&self) -> String {
				let graph_sync_test_directory = self.get_test_directory();
				let graph_sync_test_file = graph_sync_test_directory.to_owned() + "/test_data.lngossip";
				graph_sync_test_file
			}
		}

		impl Drop for FileSyncTest {
			fn drop(&mut self) {
				fs::remove_dir_all(self.directory.clone()).unwrap();
			}
		}

		// same as incremental_only_update_fails_without_prior_same_direction_updates
		let valid_response = vec![
			76, 68, 75, 1, 111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247,
			79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0, 97, 227, 98, 218,
			0, 0, 0, 4, 2, 22, 7, 207, 206, 25, 164, 197, 231, 230, 231, 56, 102, 61, 250, 251,
			187, 172, 38, 46, 79, 247, 108, 44, 155, 48, 219, 238, 252, 53, 192, 6, 67, 2, 36, 125,
			157, 176, 223, 175, 234, 116, 94, 248, 201, 225, 97, 235, 50, 47, 115, 172, 63, 136,
			88, 216, 115, 11, 111, 217, 114, 84, 116, 124, 231, 107, 2, 158, 1, 242, 121, 152, 106,
			204, 131, 186, 35, 93, 70, 216, 10, 237, 224, 183, 89, 95, 65, 3, 83, 185, 58, 138,
			181, 64, 187, 103, 127, 68, 50, 2, 201, 19, 17, 138, 136, 149, 185, 226, 156, 137, 175,
			110, 32, 237, 0, 217, 90, 31, 100, 228, 149, 46, 219, 175, 168, 77, 4, 143, 38, 128,
			76, 97, 0, 0, 0, 2, 0, 0, 255, 8, 153, 192, 0, 2, 27, 0, 0, 0, 1, 0, 0, 255, 2, 68,
			226, 0, 6, 11, 0, 1, 2, 3, 0, 0, 0, 2, 0, 40, 0, 0, 0, 0, 0, 0, 3, 232, 0, 0, 3, 232,
			0, 0, 0, 1, 0, 0, 0, 0, 58, 85, 116, 216, 255, 8, 153, 192, 0, 2, 27, 0, 0, 25, 0, 0,
			0, 1, 0, 0, 0, 125, 255, 2, 68, 226, 0, 6, 11, 0, 1, 5, 0, 0, 0, 0, 29, 129, 25, 192,
		];

		let tmp_directory = "./rapid-gossip-sync-tests-tmp";
		let sync_test = FileSyncTest::new(tmp_directory, &valid_response);
		let graph_sync_test_file = sync_test.get_test_file_path();

		let logger = TestLogger::new();
		let network_graph = NetworkGraph::new(Network::Bitcoin, &logger);

		assert_eq!(network_graph.read_only().channels().len(), 0);

		let rapid_sync = RapidGossipSync::new(&network_graph, &logger);
		let sync_result = rapid_sync.sync_network_graph_with_file_path(&graph_sync_test_file);

		if sync_result.is_err() {
			panic!("Unexpected sync result: {:?}", sync_result)
		}

		assert_eq!(network_graph.read_only().channels().len(), 2);
		let after = network_graph.to_string();
		assert!(
			after.contains("021607cfce19a4c5e7e6e738663dfafbbbac262e4ff76c2c9b30dbeefc35c00643")
		);
		assert!(
			after.contains("02247d9db0dfafea745ef8c9e161eb322f73ac3f8858d8730b6fd97254747ce76b")
		);
		assert!(
			after.contains("029e01f279986acc83ba235d46d80aede0b7595f410353b93a8ab540bb677f4432")
		);
		assert!(
			after.contains("02c913118a8895b9e29c89af6e20ed00d95a1f64e4952edbafa84d048f26804c61")
		);
		assert!(after.contains("619737530008010752"));
		assert!(after.contains("783241506229452801"));
	}

	#[test]
	fn measure_native_read_from_file() {
		let logger = TestLogger::new();
		let network_graph = NetworkGraph::new(Network::Bitcoin, &logger);

		assert_eq!(network_graph.read_only().channels().len(), 0);

		let rapid_sync = RapidGossipSync::new(&network_graph, &logger);
		let start = std::time::Instant::now();
		let sync_result = rapid_sync
			.sync_network_graph_with_file_path("./res/full_graph.lngossip");
		if let Err(crate::error::GraphSyncError::DecodeError(DecodeError::Io(io_error))) = &sync_result {
			let error_string = format!("Input file lightning-rapid-gossip-sync/res/full_graph.lngossip is missing! Download it from https://bitcoin.ninja/ldk-compressed_graph-285cb27df79-2022-07-21.bin\n\n{:?}", io_error);
			#[cfg(not(require_route_graph_test))]
			{
				println!("{}", error_string);
				return;
			}
			#[cfg(require_route_graph_test)]
			panic!("{}", error_string);
		}
		let elapsed = start.elapsed();
		println!("initialization duration: {:?}", elapsed);
		if sync_result.is_err() {
			panic!("Unexpected sync result: {:?}", sync_result)
		}
	}
}

#[cfg(all(test, feature = "_bench_unstable"))]
pub mod bench {
	use test::Bencher;

	use bitcoin::Network;

	use lightning::ln::msgs::DecodeError;
	use lightning::routing::gossip::NetworkGraph;
	use lightning::util::test_utils::TestLogger;

	use crate::RapidGossipSync;

	#[bench]
	fn bench_reading_full_graph_from_file(b: &mut Bencher) {
		let logger = TestLogger::new();
		b.iter(|| {
			let network_graph = NetworkGraph::new(Network::Bitcoin, &logger);
			let rapid_sync = RapidGossipSync::new(&network_graph, &logger);
			let sync_result = rapid_sync.sync_network_graph_with_file_path("./res/full_graph.lngossip");
			if let Err(crate::error::GraphSyncError::DecodeError(DecodeError::Io(io_error))) = &sync_result {
				let error_string = format!("Input file lightning-rapid-gossip-sync/res/full_graph.lngossip is missing! Download it from https://bitcoin.ninja/ldk-compressed_graph-bc08df7542-2022-05-05.bin\n\n{:?}", io_error);
				#[cfg(not(require_route_graph_test))]
				{
					println!("{}", error_string);
					return;
				}
				#[cfg(require_route_graph_test)]
				panic!("{}", error_string);
			}
			assert!(sync_result.is_ok())
		});
	}
}
