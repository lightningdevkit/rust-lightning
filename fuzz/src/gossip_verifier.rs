// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::block::{Block, Header, Version};
use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::network::Network;
use bitcoin::transaction::{OutPoint, Transaction, TxOut};
use bitcoin::{Amount, CompactTarget, TxMerkleNode};

use lightning::ln::msgs;
use lightning::ln::msgs::BaseMessageHandler;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::util::ser::LengthReadable;

use lightning_block_sync::gossip::{GossipVerifier, TokioSpawner, UtxoSource};
use lightning_block_sync::{BlockData, BlockHeaderData, BlockSource, BlockSourceError};

use crate::utils::test_logger;

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::runtime::Runtime;

#[inline]
pub fn slice_to_be16(v: &[u8]) -> u16 {
	((v[0] as u16) << 8) | (v[1] as u16)
}

struct InputData {
	data: Vec<u8>,
	read_pos: AtomicUsize,
}
impl InputData {
	fn get_slice(&self, len: usize) -> Option<&[u8]> {
		let old_pos = self.read_pos.fetch_add(len, Ordering::AcqRel);
		if self.data.len() < old_pos + len {
			return None;
		}
		Some(&self.data[old_pos..old_pos + len])
	}
	fn get_slice_nonadvancing(&self, len: usize) -> Option<&[u8]> {
		let old_pos = self.read_pos.load(Ordering::Acquire);
		if self.data.len() < old_pos + len {
			return None;
		}
		Some(&self.data[old_pos..old_pos + len])
	}
}

fn dummy_header() -> Header {
	Header {
		version: Version::ONE,
		prev_blockhash: BlockHash::all_zeros(),
		merkle_root: TxMerkleNode::all_zeros(),
		time: 0,
		bits: CompactTarget::from_consensus(0),
		nonce: 0,
	}
}

/// A `BlockSource` + `UtxoSource` driven by fuzz input. Each async call consumes one byte from
/// the input to decide its behavior (success with various shapes, or persistent/transient error).
struct FuzzBlockSource {
	input: Arc<InputData>,
}

impl BlockSource for FuzzBlockSource {
	fn get_header<'a>(
		&'a self, _header_hash: &'a BlockHash, _height_hint: Option<u32>,
	) -> impl Future<Output = Result<BlockHeaderData, BlockSourceError>> + Send + 'a {
		async move {
			// Not called by retrieve_utxo, but required by the trait.
			Err(BlockSourceError::transient("not implemented"))
		}
	}

	fn get_block<'a>(
		&'a self, _header_hash: &'a BlockHash,
	) -> impl Future<Output = Result<BlockData, BlockSourceError>> + Send + 'a {
		let action = self.input.get_slice(1).map(|s| s[0]);
		async move {
			match action {
				None | Some(0) => Err(BlockSourceError::persistent("eof/persistent")),
				Some(1) => Err(BlockSourceError::transient("transient")),
				Some(2) => Ok(BlockData::HeaderOnly(dummy_header())),
				Some(b) => {
					// Build a block with a configurable number of transactions (1..=4),
					// each with a configurable number of outputs (1..=4).
					let num_txs = ((b >> 2) % 4) as usize + 1;
					let num_outputs = ((b >> 4) % 4) as usize + 1;
					let txdata: Vec<Transaction> = (0..num_txs)
						.map(|_| Transaction {
							version: bitcoin::transaction::Version::ONE,
							lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
							input: vec![],
							output: (0..num_outputs)
								.map(|_| TxOut {
									value: Amount::from_sat(1_000_000),
									script_pubkey: bitcoin::ScriptBuf::new(),
								})
								.collect(),
						})
						.collect();

					Ok(BlockData::FullBlock(Block { header: dummy_header(), txdata }))
				},
			}
		}
	}

	fn get_best_block<'a>(
		&'a self,
	) -> impl Future<Output = Result<(BlockHash, Option<u32>), BlockSourceError>> + Send + 'a {
		let action = self.input.get_slice(1).map(|s| s[0]);
		async move {
			match action {
				None | Some(0) => Err(BlockSourceError::persistent("eof/persistent")),
				Some(1) => Err(BlockSourceError::transient("transient")),
				// Return no height (skips the confirmation check)
				Some(2) => Ok((BlockHash::all_zeros(), None)),
				// Return a very high tip so confirmation check passes
				Some(3) => Ok((BlockHash::all_zeros(), Some(1_000_000))),
				// Return a low tip so confirmation check fails for most SCIDs
				Some(_) => Ok((BlockHash::all_zeros(), Some(5))),
			}
		}
	}
}

impl UtxoSource for FuzzBlockSource {
	fn get_block_hash_by_height<'a>(
		&'a self, _block_height: u32,
	) -> impl Future<Output = Result<BlockHash, BlockSourceError>> + Send + 'a {
		let action = self.input.get_slice(1).map(|s| s[0]);
		async move {
			match action {
				None | Some(0) => Err(BlockSourceError::persistent("eof/persistent")),
				Some(1) => Err(BlockSourceError::transient("transient")),
				Some(_) => Ok(BlockHash::all_zeros()),
			}
		}
	}

	fn is_output_unspent<'a>(
		&'a self, _outpoint: OutPoint,
	) -> impl Future<Output = Result<bool, BlockSourceError>> + Send + 'a {
		let action = self.input.get_slice(1).map(|s| s[0]);
		async move {
			match action {
				None | Some(0) => Err(BlockSourceError::persistent("eof/persistent")),
				Some(1) => Err(BlockSourceError::transient("transient")),
				Some(2) => Ok(false), // spent
				Some(_) => Ok(true),  // unspent
			}
		}
	}
}

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let rt = Runtime::new().unwrap();
	rt.block_on(do_test_async(data, out));
}

async fn do_test_async<Out: test_logger::Output>(data: &[u8], out: Out) {
	let input = Arc::new(InputData { data: data.to_vec(), read_pos: AtomicUsize::new(0) });

	macro_rules! get_slice_nonadvancing {
		($len: expr) => {
			match input.get_slice_nonadvancing($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		};
	}
	macro_rules! get_slice {
		($len: expr) => {
			match input.get_slice($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		};
	}

	macro_rules! decode_msg {
		($MsgType: path, $len: expr) => {{
			let data = get_slice!($len);
			let mut reader = &data[..];
			match <$MsgType>::read_from_fixed_length_buffer(&mut reader) {
				Ok(msg) => {
					assert!(reader.is_empty());
					msg
				},
				Err(e) => match e {
					msgs::DecodeError::UnknownVersion => return,
					msgs::DecodeError::UnknownRequiredFeature => return,
					msgs::DecodeError::InvalidValue => return,
					msgs::DecodeError::BadLengthDescriptor => return,
					msgs::DecodeError::ShortRead => panic!("We picked the length..."),
					msgs::DecodeError::Io(e) => panic!("{:?}", e),
					msgs::DecodeError::UnsupportedCompression => return,
					msgs::DecodeError::DangerousValue => return,
				},
			}
		}};
	}

	macro_rules! decode_msg_with_len16 {
		($MsgType: path, $excess: expr) => {{
			let extra_len = slice_to_be16(get_slice_nonadvancing!(2));
			decode_msg!($MsgType, 2 + (extra_len as usize) + $excess)
		}};
	}

	let logger = test_logger::TestLogger::new("".to_owned(), out);
	let net_graph = NetworkGraph::new(Network::Bitcoin, &logger);
	let block_source = Arc::new(FuzzBlockSource { input: Arc::clone(&input) });
	let gossip_verifier = GossipVerifier::new(Arc::clone(&block_source), TokioSpawner);
	let gossip_sync = P2PGossipSync::new(&net_graph, Some(&gossip_verifier), &logger);

	loop {
		match get_slice!(1)[0] % 5 {
			// Channel announcement via GossipVerifier (exercises retrieve_utxo)
			0 => {
				let msg = decode_msg_with_len16!(
					msgs::UnsignedChannelAnnouncement,
					32 + 8 + 33 * 4
				);
				let _ = net_graph
					.update_channel_from_unsigned_announcement(&msg, &Some(&gossip_verifier));
				// Yield to let spawned tokio tasks complete.
				tokio::task::yield_now().await;
			},
			// Node announcement
			1 => {
				let start_len = slice_to_be16(&get_slice_nonadvancing!(2)[0..2]) as usize;
				let addr_len = slice_to_be16(
					&get_slice_nonadvancing!(start_len + 2 + 74)
						[start_len + 2 + 72..start_len + 2 + 74],
				);
				if addr_len > (37 + 1) * 4 {
					return;
				}
				let msg = decode_msg_with_len16!(msgs::UnsignedNodeAnnouncement, 288);
				let _ = net_graph.update_node_from_unsigned_announcement(&msg);
			},
			// Channel update
			2 => {
				let msg = decode_msg!(msgs::UnsignedChannelUpdate, 72);
				let _ = net_graph.update_channel_unsigned(&msg);
			},
			// Process completed checks (triggers check_resolved_futures)
			3 => {
				// Yield first so any in-flight tokio tasks can resolve their futures.
				tokio::task::yield_now().await;
				gossip_sync.get_and_clear_pending_msg_events();
			},
			// Channel announcement without UTXO lookup
			4 | _ => {
				let msg = decode_msg_with_len16!(
					msgs::UnsignedChannelAnnouncement,
					32 + 8 + 33 * 4
				);
				let _ = net_graph.update_channel_from_unsigned_announcement::<
					&GossipVerifier<TokioSpawner, Arc<FuzzBlockSource>>,
				>(&msg, &None);
			},
		}
	}
}

pub fn gossip_verifier_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn gossip_verifier_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
