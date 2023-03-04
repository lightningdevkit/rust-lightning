// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::TxOut;
use bitcoin::hash_types::BlockHash;

use lightning::chain::transaction::OutPoint;
use lightning::ln::channelmanager::{self, ChannelDetails, ChannelCounterparty};
use lightning::ln::msgs;
use lightning::routing::gossip::{NetworkGraph, RoutingFees};
use lightning::routing::utxo::{UtxoFuture, UtxoLookup, UtxoLookupError, UtxoResult};
use lightning::routing::router::{find_route, PaymentParameters, RouteHint, RouteHintHop, RouteParameters};
use lightning::routing::scoring::ProbabilisticScorer;
use lightning::util::config::UserConfig;
use lightning::util::ser::Readable;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::network::constants::Network;

use crate::utils::test_logger;

use std::convert::TryInto;
use hashbrown::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[inline]
pub fn slice_to_be16(v: &[u8]) -> u16 {
	((v[0] as u16) << 8*1) |
	((v[1] as u16) << 8*0)
}

#[inline]
pub fn slice_to_be32(v: &[u8]) -> u32 {
	((v[0] as u32) << 8*3) |
	((v[1] as u32) << 8*2) |
	((v[2] as u32) << 8*1) |
	((v[3] as u32) << 8*0)
}

#[inline]
pub fn slice_to_be64(v: &[u8]) -> u64 {
	((v[0] as u64) << 8*7) |
	((v[1] as u64) << 8*6) |
	((v[2] as u64) << 8*5) |
	((v[3] as u64) << 8*4) |
	((v[4] as u64) << 8*3) |
	((v[5] as u64) << 8*2) |
	((v[6] as u64) << 8*1) |
	((v[7] as u64) << 8*0)
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

struct FuzzChainSource<'a, 'b, Out: test_logger::Output> {
	input: Arc<InputData>,
	net_graph: &'a NetworkGraph<&'b test_logger::TestLogger<Out>>,
}
impl<Out: test_logger::Output> UtxoLookup for FuzzChainSource<'_, '_, Out> {
	fn get_utxo(&self, _genesis_hash: &BlockHash, _short_channel_id: u64) -> UtxoResult {
		let input_slice = self.input.get_slice(2);
		if input_slice.is_none() { return UtxoResult::Sync(Err(UtxoLookupError::UnknownTx)); }
		let input_slice = input_slice.unwrap();
		let txo_res = TxOut {
			value: if input_slice[0] % 2 == 0 { 1_000_000 } else { 1_000 },
			script_pubkey: Builder::new().push_int(input_slice[1] as i64).into_script().to_v0_p2wsh(),
		};
		match input_slice {
			&[0, _] => UtxoResult::Sync(Err(UtxoLookupError::UnknownChain)),
			&[1, _] => UtxoResult::Sync(Err(UtxoLookupError::UnknownTx)),
			&[2, _] => {
				let future = UtxoFuture::new();
				future.resolve_without_forwarding(self.net_graph, Ok(txo_res));
				UtxoResult::Async(future.clone())
			},
			&[3, _] => {
				let future = UtxoFuture::new();
				future.resolve_without_forwarding(self.net_graph, Err(UtxoLookupError::UnknownTx));
				UtxoResult::Async(future.clone())
			},
			&[4, _] => {
				UtxoResult::Async(UtxoFuture::new()) // the future will never resolve
			},
			&[..] => UtxoResult::Sync(Ok(txo_res)),
		}
	}
}

#[inline]
pub fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let input = Arc::new(InputData {
		data: data.to_vec(),
		read_pos: AtomicUsize::new(0),
	});
	macro_rules! get_slice_nonadvancing {
		($len: expr) => {
			match input.get_slice_nonadvancing($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		}
	}
	macro_rules! get_slice {
		($len: expr) => {
			match input.get_slice($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		}
	}

	macro_rules! decode_msg {
		($MsgType: path, $len: expr) => {{
			let mut reader = ::std::io::Cursor::new(get_slice!($len));
			match <$MsgType>::read(&mut reader) {
				Ok(msg) => {
					assert_eq!(reader.position(), $len as u64);
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
				}
			}
		}}
	}

	macro_rules! decode_msg_with_len16 {
		($MsgType: path, $excess: expr) => {
			{
				let extra_len = slice_to_be16(get_slice_nonadvancing!(2));
				decode_msg!($MsgType, 2 + (extra_len as usize) + $excess)
			}
		}
	}

	macro_rules! get_pubkey_from_node_id {
		($node_id: expr ) => {
			match PublicKey::from_slice($node_id.as_slice()) {
				Ok(pk) => pk,
				Err(_) => return,
			}
		}
	}

	macro_rules! get_pubkey {
		() => {
			match PublicKey::from_slice(get_slice!(33)) {
				Ok(key) => key,
				Err(_) => return,
			}
		}
	}

	let logger = test_logger::TestLogger::new("".to_owned(), out);

	let our_pubkey = get_pubkey!();
	let net_graph = NetworkGraph::new(Network::Bitcoin, &logger);
	let chain_source = FuzzChainSource {
		input: Arc::clone(&input),
		net_graph: &net_graph,
	};

	let mut node_pks = HashSet::new();
	let mut scid = 42;

	loop {
		match get_slice!(1)[0] {
			0 => {
				let start_len = slice_to_be16(&get_slice_nonadvancing!(2)[0..2]) as usize;
				let addr_len = slice_to_be16(&get_slice_nonadvancing!(start_len+2 + 74)[start_len+2 + 72..start_len+2 + 74]);
				if addr_len > (37+1)*4 {
					return;
				}
				let msg = decode_msg_with_len16!(msgs::UnsignedNodeAnnouncement, 288);
				node_pks.insert(get_pubkey_from_node_id!(msg.node_id));
				let _ = net_graph.update_node_from_unsigned_announcement(&msg);
			},
			1 => {
				let msg = decode_msg_with_len16!(msgs::UnsignedChannelAnnouncement, 32+8+33*4);
				node_pks.insert(get_pubkey_from_node_id!(msg.node_id_1));
				node_pks.insert(get_pubkey_from_node_id!(msg.node_id_2));
				let _ = net_graph.update_channel_from_unsigned_announcement::
					<&FuzzChainSource<'_, '_, Out>>(&msg, &None);
			},
			2 => {
				let msg = decode_msg_with_len16!(msgs::UnsignedChannelAnnouncement, 32+8+33*4);
				node_pks.insert(get_pubkey_from_node_id!(msg.node_id_1));
				node_pks.insert(get_pubkey_from_node_id!(msg.node_id_2));
				let _ = net_graph.update_channel_from_unsigned_announcement(&msg, &Some(&chain_source));
			},
			3 => {
				let _ = net_graph.update_channel_unsigned(&decode_msg!(msgs::UnsignedChannelUpdate, 72));
			},
			4 => {
				let short_channel_id = slice_to_be64(get_slice!(8));
				net_graph.channel_failed(short_channel_id, false);
			},
			_ if node_pks.is_empty() => {},
			_ => {
				let mut first_hops_vec = Vec::new();
				let first_hops = match get_slice!(1)[0] {
					0 => None,
					count => {
						for _ in 0..count {
							scid += 1;
							let rnid = node_pks.iter().skip(u16::from_be_bytes(get_slice!(2).try_into().unwrap()) as usize % node_pks.len()).next().unwrap();
							let capacity = u64::from_be_bytes(get_slice!(8).try_into().unwrap());
							first_hops_vec.push(ChannelDetails {
								channel_id: [0; 32],
								counterparty: ChannelCounterparty {
									node_id: *rnid,
									features: channelmanager::provided_init_features(&UserConfig::default()),
									unspendable_punishment_reserve: 0,
									forwarding_info: None,
									outbound_htlc_minimum_msat: None,
									outbound_htlc_maximum_msat: None,
								},
								funding_txo: Some(OutPoint { txid: bitcoin::Txid::from_slice(&[0; 32]).unwrap(), index: 0 }),
								channel_type: None,
								short_channel_id: Some(scid),
								inbound_scid_alias: None,
								outbound_scid_alias: None,
								channel_value_satoshis: capacity,
								user_channel_id: 0, inbound_capacity_msat: 0,
								unspendable_punishment_reserve: None,
								confirmations_required: None,
								confirmations: None,
								force_close_spend_delay: None,
								is_outbound: true, is_channel_ready: true,
								is_usable: true, is_public: true,
								balance_msat: 0,
								outbound_capacity_msat: capacity.saturating_mul(1000),
								next_outbound_htlc_limit_msat: capacity.saturating_mul(1000),
								inbound_htlc_minimum_msat: None,
								inbound_htlc_maximum_msat: None,
								config: None,
							});
						}
						Some(&first_hops_vec[..])
					},
				};
				let mut last_hops = Vec::new();
				{
					let count = get_slice!(1)[0];
					for _ in 0..count {
						scid += 1;
						let rnid = node_pks.iter().skip(slice_to_be16(get_slice!(2))as usize % node_pks.len()).next().unwrap();
						last_hops.push(RouteHint(vec![RouteHintHop {
							src_node_id: *rnid,
							short_channel_id: scid,
							fees: RoutingFees {
								base_msat: slice_to_be32(get_slice!(4)),
								proportional_millionths: slice_to_be32(get_slice!(4)),
							},
							cltv_expiry_delta: slice_to_be16(get_slice!(2)),
							htlc_minimum_msat: Some(slice_to_be64(get_slice!(8))),
							htlc_maximum_msat: None,
						}]));
					}
				}
				let scorer = ProbabilisticScorer::new(Default::default(), &net_graph, &logger);
				let random_seed_bytes: [u8; 32] = [get_slice!(1)[0]; 32];
				for target in node_pks.iter() {
					let final_value_msat = slice_to_be64(get_slice!(8));
					let final_cltv_expiry_delta = slice_to_be32(get_slice!(4));
					let route_params = RouteParameters {
						payment_params: PaymentParameters::from_node_id(*target, final_cltv_expiry_delta)
							.with_route_hints(last_hops.clone()),
						final_value_msat,
					};
					let _ = find_route(&our_pubkey, &route_params, &net_graph,
						first_hops.map(|c| c.iter().collect::<Vec<_>>()).as_ref().map(|a| a.as_slice()),
						&logger, &scorer, &random_seed_bytes);
				}
			},
		}
	}
}

pub fn router_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn router_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
