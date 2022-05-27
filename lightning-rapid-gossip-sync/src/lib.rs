#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(broken_intra_doc_links)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(unused_variables)]
#![deny(unused_imports)]
//! This crate exposes functionality to rapidly sync gossip data, aimed primarily at mobile
//! devices.
//!
//! The server sends a compressed response containing differential gossip data. The gossip data is
//! formatted compactly, omitting signatures and opportunistically incremental where previous
//! channel updates are known (a mechanism that is enabled when the timestamp of the last known
//! channel update is communicated). A reference server implementation can be found
//! [here](https://github.com/lightningdevkit/rapid-gossip-sync-server).
//!
//! An example server request could look as simple as the following. Note that the first ever rapid
//! sync should use `0` for `last_sync_timestamp`:
//!
//! ```shell
//! curl -o rapid_sync.lngossip https://rapidsync.lightningdevkit.org/snapshot/<last_sync_timestamp>
//! ```
//!
//! Then, call the network processing function. In this example, we process the update by reading
//! its contents from disk, which we do by calling the `sync_network_graph_with_file_path` method:
//!
//! ```
//! use bitcoin::blockdata::constants::genesis_block;
//! use bitcoin::Network;
//! use lightning::routing::network_graph::NetworkGraph;
//!
//! let block_hash = genesis_block(Network::Bitcoin).header.block_hash();
//! let network_graph = NetworkGraph::new(block_hash);
//! let new_last_sync_timestamp_result = lightning_rapid_gossip_sync::sync_network_graph_with_file_path(&network_graph, "./rapid_sync.lngossip");
//! ```
//!
//! The primary benefit this syncing mechanism provides is that given a trusted server, a
//! low-powered client can offload the validation of gossip signatures. This enables a client to
//! privately calculate routes for payments, and do so much faster and earlier than requiring a full
//! peer-to-peer gossip sync to complete.
//!
//! The reason the rapid sync server requires trust is that it could provide bogus data, though at
//! worst, all that would result in is a fake network topology, which wouldn't enable the server to
//! steal or siphon off funds. It could, however, reduce the client's privacy by forcing all
//! payments to be routed via channels the server controls.
//!
//! The way a server is meant to calculate this rapid gossip sync data is by using a `latest_seen`
//! timestamp provided by the client. It's not included in either channel announcement or update,
//! (not least due to announcements not including any timestamps at all, but only a block height)
//! but rather, it's a timestamp of when the server saw a particular message.

// Allow and import test features for benching
#![cfg_attr(all(test, feature = "_bench_unstable"), feature(test))]
#[cfg(all(test, feature = "_bench_unstable"))]
extern crate test;

use std::fs::File;

use lightning::routing::network_graph;

use crate::error::GraphSyncError;

/// Error types that these functions can return
pub mod error;

/// Core functionality of this crate
pub mod processing;

/// Sync gossip data from a file
/// Returns the last sync timestamp to be used the next time rapid sync data is queried.
///
/// `network_graph`: The network graph to apply the updates to
///
/// `sync_path`: Path to the file where the gossip update data is located
///
pub fn sync_network_graph_with_file_path(
	network_graph: &network_graph::NetworkGraph,
	sync_path: &str,
) -> Result<u32, GraphSyncError> {
	let mut file = File::open(sync_path)?;
	processing::update_network_graph_from_byte_stream(&network_graph, &mut file)
}

#[cfg(test)]
mod tests {
	use std::fs;

	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::Network;

	use lightning::ln::msgs::DecodeError;
	use lightning::routing::network_graph::NetworkGraph;

	use crate::sync_network_graph_with_file_path;

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

		let block_hash = genesis_block(Network::Bitcoin).block_hash();
		let network_graph = NetworkGraph::new(block_hash);

		assert_eq!(network_graph.read_only().channels().len(), 0);

		let sync_result = sync_network_graph_with_file_path(&network_graph, &graph_sync_test_file);

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
		let block_hash = genesis_block(Network::Bitcoin).block_hash();
		let network_graph = NetworkGraph::new(block_hash);

		assert_eq!(network_graph.read_only().channels().len(), 0);

		let start = std::time::Instant::now();
		let sync_result =
			sync_network_graph_with_file_path(&network_graph, "./res/full_graph.lngossip");
		if let Err(crate::error::GraphSyncError::DecodeError(DecodeError::Io(io_error))) = &sync_result {
			let error_string = format!("Input file lightning-graph-sync/res/full_graph.lngossip is missing! Download it from https://bitcoin.ninja/ldk-compressed_graph-bc08df7542-2022-05-05.bin\n\n{:?}", io_error);
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

	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::Network;

	use lightning::ln::msgs::DecodeError;
	use lightning::routing::network_graph::NetworkGraph;

	use crate::sync_network_graph_with_file_path;

	#[bench]
	fn bench_reading_full_graph_from_file(b: &mut Bencher) {
		let block_hash = genesis_block(Network::Bitcoin).block_hash();
		b.iter(|| {
			let network_graph = NetworkGraph::new(block_hash);
			let sync_result = sync_network_graph_with_file_path(
				&network_graph,
				"./res/full_graph.lngossip",
			);
			if let Err(crate::error::GraphSyncError::DecodeError(DecodeError::Io(io_error))) = &sync_result {
				let error_string = format!("Input file lightning-graph-sync/res/full_graph.lngossip is missing! Download it from https://bitcoin.ninja/ldk-compressed_graph-bc08df7542-2022-05-05.bin\n\n{:?}", io_error);
				#[cfg(not(require_route_graph_test))]
				{
					println!("{}", error_string);
					return;
				}
				panic!("{}", error_string);
			}
			assert!(sync_result.is_ok())
		});
	}
}
