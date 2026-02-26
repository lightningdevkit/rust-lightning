// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::amount::Amount;
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::script::Builder;
use bitcoin::transaction::TxOut;

use lightning::ln::msgs;
use lightning::ln::msgs::BaseMessageHandler;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::utxo::{UtxoFuture, UtxoLookup, UtxoLookupError, UtxoResult};
use lightning::util::ser::LengthReadable;
use lightning::util::wakers::Notifier;

use crate::utils::test_logger;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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

struct FuzzChainSource {
	input: Arc<InputData>,
	pending_futures: Arc<Mutex<Vec<UtxoFuture>>>,
}

impl UtxoLookup for FuzzChainSource {
	fn get_utxo(
		&self, _chain_hash: &ChainHash, _scid: u64, notifier: Arc<Notifier>,
	) -> UtxoResult {
		let input_slice = match self.input.get_slice(2) {
			Some(s) => s,
			None => return UtxoResult::Sync(Err(UtxoLookupError::UnknownTx)),
		};
		let txo_res = TxOut {
			value: Amount::from_sat(1_000_000),
			script_pubkey: Builder::new()
				.push_int(input_slice[1] as i64)
				.into_script()
				.to_p2wsh(),
		};
		match input_slice[0] % 6 {
			0 => UtxoResult::Sync(Err(UtxoLookupError::UnknownChain)),
			1 => UtxoResult::Sync(Err(UtxoLookupError::UnknownTx)),
			2 => UtxoResult::Sync(Ok(txo_res)),
			3 => {
				// Async, resolve immediately with success
				let future = UtxoFuture::new(notifier);
				future.resolve(Ok(txo_res));
				UtxoResult::Async(future)
			},
			4 => {
				// Async, resolve immediately with error
				let future = UtxoFuture::new(notifier);
				future.resolve(Err(UtxoLookupError::UnknownTx));
				UtxoResult::Async(future)
			},
			5 | _ => {
				// Async, deferred resolution - store for later
				let future = UtxoFuture::new(notifier);
				self.pending_futures.lock().unwrap().push(future.clone());
				UtxoResult::Async(future)
			},
		}
	}
}

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
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
	let pending_futures: Arc<Mutex<Vec<UtxoFuture>>> = Arc::new(Mutex::new(Vec::new()));
	let chain_source =
		FuzzChainSource { input: Arc::clone(&input), pending_futures: Arc::clone(&pending_futures) };
	// Create a P2PGossipSync so we can call get_and_clear_pending_msg_events to trigger
	// check_resolved_futures processing.
	let gossip_sync =
		P2PGossipSync::new(&net_graph, None::<&FuzzChainSource>, &logger);

	loop {
		match get_slice!(1)[0] % 8 {
			// Channel announcement with UTXO lookup
			0 => {
				let msg = decode_msg_with_len16!(
					msgs::UnsignedChannelAnnouncement,
					32 + 8 + 33 * 4
				);
				let _ = net_graph
					.update_channel_from_unsigned_announcement(&msg, &Some(&chain_source));
			},
			// Channel announcement without UTXO lookup
			1 => {
				let msg = decode_msg_with_len16!(
					msgs::UnsignedChannelAnnouncement,
					32 + 8 + 33 * 4
				);
				let _ = net_graph
					.update_channel_from_unsigned_announcement::<&FuzzChainSource>(&msg, &None);
			},
			// Node announcement
			2 => {
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
			3 => {
				let msg = decode_msg!(msgs::UnsignedChannelUpdate, 72);
				let _ = net_graph.update_channel_unsigned(&msg);
			},
			// Resolve a pending future with success
			4 => {
				let mut futures = pending_futures.lock().unwrap();
				if !futures.is_empty() {
					let idx_byte = get_slice!(1)[0] as usize;
					let idx = idx_byte % futures.len();
					let future = futures.remove(idx);
					let script_byte = get_slice!(1)[0];
					let txo = TxOut {
						value: Amount::from_sat(1_000_000),
						script_pubkey: Builder::new()
							.push_int(script_byte as i64)
							.into_script()
							.to_p2wsh(),
					};
					future.resolve(Ok(txo));
				}
			},
			// Resolve a pending future with error
			5 => {
				let mut futures = pending_futures.lock().unwrap();
				if !futures.is_empty() {
					let idx_byte = get_slice!(1)[0] as usize;
					let idx = idx_byte % futures.len();
					let future = futures.remove(idx);
					future.resolve(Err(UtxoLookupError::UnknownTx));
				}
			},
			// Process completed checks (triggers check_resolved_futures)
			6 => {
				gossip_sync.get_and_clear_pending_msg_events();
			},
			// Drop a pending future without resolving
			7 | _ => {
				let mut futures = pending_futures.lock().unwrap();
				if !futures.is_empty() {
					let idx_byte = get_slice!(1)[0] as usize;
					let idx = idx_byte % futures.len();
					futures.remove(idx);
				}
			},
		}
	}
}

pub fn utxo_validation_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn utxo_validation_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
