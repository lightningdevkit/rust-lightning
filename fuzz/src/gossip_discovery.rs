// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Test that no series of gossip messages received from peers can result in a crash. We do this
//! by standing up a `P2PGossipSync` with a `NetworkGraph` and a mock UTXO lookup, then reading
//! bytes from the fuzz input to denote actions such as feeding channel announcements, node
//! announcements, channel updates, query messages, and pruning channels and nodes. Both valid
//! and malformed messages are generated to exercise error paths.

use bitcoin::amount::Amount;
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::PublicKey;
use bitcoin::TxOut;

use lightning::ln::chan_utils::make_funding_redeemscript;
use lightning::ln::msgs::{self, BaseMessageHandler, MessageSendEvent, RoutingMessageHandler};
use lightning::routing::gossip::{NetworkGraph, NetworkUpdate, NodeId, P2PGossipSync};
use lightning::routing::utxo::{UtxoLookup, UtxoLookupError, UtxoResult};
use lightning::util::ser::LengthReadable;
use lightning::util::wakers::Notifier;

use crate::utils::test_logger;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct FuzzUtxoLookup {
	utxos: Mutex<HashMap<u64, TxOut>>,
}

impl FuzzUtxoLookup {
	fn new() -> Arc<Self> {
		Arc::new(Self { utxos: Mutex::new(HashMap::new()) })
	}

	fn register(&self, scid: u64, txout: TxOut) {
		self.utxos.lock().unwrap().insert(scid, txout);
	}
}

impl UtxoLookup for FuzzUtxoLookup {
	fn get_utxo(
		&self, _chain_hash: &ChainHash, short_channel_id: u64,
		_async_completion_notifier: Arc<Notifier>,
	) -> UtxoResult {
		let utxos = self.utxos.lock().unwrap();
		match utxos.get(&short_channel_id) {
			Some(txout) => UtxoResult::Sync(Ok(txout.clone())),
			None => UtxoResult::Sync(Err(UtxoLookupError::UnknownTx)),
		}
	}
}

#[inline]
fn do_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let logger = Arc::new(test_logger::TestLogger::new("".to_owned(), out));

	let network = Network::Bitcoin;
	let network_graph = Arc::new(NetworkGraph::new(network, Arc::clone(&logger)));
	let utxo_lookup = FuzzUtxoLookup::new();
	let gossip = Arc::new(P2PGossipSync::new(
		Arc::clone(&network_graph),
		Some(Arc::clone(&utxo_lookup)),
		Arc::clone(&logger),
	));

	let mut read_pos = 0;
	macro_rules! get_slice {
		($len: expr) => {{
			let slice_len = $len as usize;
			if data.len() < read_pos + slice_len {
				return;
			}
			read_pos += slice_len;
			&data[read_pos - slice_len..read_pos]
		}};
	}

	macro_rules! get_pubkey {
		() => {
			match PublicKey::from_slice(get_slice!(33)) {
				Ok(key) => key,
				Err(_) => continue,
			}
		};
	}

	macro_rules! decode_msg {
		($MsgType: path) => {{
			let len_bytes = get_slice!(2);
			let msg_len = u16::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
			if msg_len == 0 {
				continue;
			}
			let msg_data = get_slice!(msg_len);
			let mut reader = &msg_data[..];
			match <$MsgType>::read_from_fixed_length_buffer(&mut reader) {
				Ok(msg) => {
					assert!(reader.is_empty());
					msg
				},
				Err(e) => match e {
					msgs::DecodeError::UnknownVersion => continue,
					msgs::DecodeError::UnknownRequiredFeature => continue,
					msgs::DecodeError::InvalidValue => continue,
					msgs::DecodeError::BadLengthDescriptor => continue,
					msgs::DecodeError::ShortRead => continue,
					msgs::DecodeError::Io(e) => panic!("{:?}", e),
					msgs::DecodeError::UnsupportedCompression => continue,
					msgs::DecodeError::DangerousValue => continue,
				},
			}
		}};
	}

	loop {
		match get_slice!(1)[0] % 7 {
			// Handle a node announcement.
			0 => {
				let node_ann = decode_msg!(msgs::NodeAnnouncement);
				let Ok(peer_node_id) = node_ann.contents.node_id.as_pubkey() else {
					continue;
				};

				match gossip.handle_node_announcement(Some(peer_node_id), &node_ann) {
					Ok(_) => {
						let graph = network_graph.read_only();
						let node = graph.node(&node_ann.contents.node_id).unwrap();
						let info = node.announcement_info.as_ref().unwrap();
						assert_eq!(info.last_update(), node_ann.contents.timestamp);
					},
					Err(_) => {},
				}
			},
			// Handle a channel announcement.
			1 => {
				let chan_ann = decode_msg!(msgs::ChannelAnnouncement);
				let scid = chan_ann.contents.short_channel_id;
				let Ok(peer_node_id) = chan_ann.contents.node_id_1.as_pubkey() else {
					continue;
				};
				let Ok(btc_key1) = chan_ann.contents.bitcoin_key_1.as_pubkey() else {
					continue;
				};
				let Ok(btc_key2) = chan_ann.contents.bitcoin_key_2.as_pubkey() else {
					continue;
				};

				// We conditionally register the funding script in the UTXO set so that valid funding
				// script cases are also validated.
				if (get_slice!(1)[0] & 1) != 0 {
					let script_pubkey = make_funding_redeemscript(&btc_key1, &btc_key2).to_p2wsh();
					utxo_lookup.register(
						scid,
						TxOut { value: Amount::from_sat(1_000_000), script_pubkey },
					);
				}

				match gossip.handle_channel_announcement(Some(peer_node_id), &chan_ann) {
					Ok(_) => {
						let graph = network_graph.read_only();
						let chan = graph.channel(scid).unwrap();
						assert_eq!(chan.node_one, chan_ann.contents.node_id_1);
						assert_eq!(chan.node_two, chan_ann.contents.node_id_2);

						assert!(graph.node(&chan_ann.contents.node_id_1).is_some());
						assert!(graph.node(&chan_ann.contents.node_id_2).is_some());
					},
					Err(_) => {},
				}
			},
			// Handle a channel update.
			2 => {
				let chan_upd = decode_msg!(msgs::ChannelUpdate);
				let peer_node_id = get_pubkey!();

				match gossip.handle_channel_update(Some(peer_node_id), &chan_upd) {
					Ok(_) => {
						let graph = network_graph.read_only();
						let chan = graph.channel(chan_upd.contents.short_channel_id).unwrap();
						let info =
							chan.get_directional_info(chan_upd.contents.channel_flags).unwrap();
						assert_eq!(info.last_update, chan_upd.contents.timestamp);
					},
					Err(_) => {},
				}
			},
			// Handle query channel range.
			3 => {
				let query = decode_msg!(msgs::QueryChannelRange);
				let peer_node_id = get_pubkey!();

				let _ = gossip.handle_query_channel_range(peer_node_id, query);

				// handle_query_channel_range always enqueues at least one
				// SendReplyChannelRange event regardless of success or failure.
				let events = gossip.get_and_clear_pending_msg_events();
				assert!(!events.is_empty());
				for event in &events {
					match event {
						MessageSendEvent::SendReplyChannelRange { node_id, msg } => {
							assert_eq!(*node_id, peer_node_id);
							assert!(msg.sync_complete || events.len() > 1);
						},
						_ => panic!("Expected SendReplyChannelRange event"),
					}
				}
				// The last reply must have sync_complete set.
				match events.last().unwrap() {
					MessageSendEvent::SendReplyChannelRange { msg, .. } => {
						assert!(msg.sync_complete);
					},
					_ => panic!("Expected SendReplyChannelRange event"),
				}
			},
			// Handle channel failure network update.
			4 => {
				let scid = u64::from_be_bytes(get_slice!(8).try_into().unwrap());

				network_graph.handle_network_update(&NetworkUpdate::ChannelFailure {
					short_channel_id: scid,
					is_permanent: true,
				});

				assert!(network_graph.read_only().channel(scid).is_none());
			},
			// Handle node failure network update.
			5 => {
				let peer_node_id = get_pubkey!();

				network_graph.handle_network_update(&NetworkUpdate::NodeFailure {
					node_id: peer_node_id,
					is_permanent: true,
				});

				assert!(network_graph
					.read_only()
					.node(&NodeId::from_pubkey(&peer_node_id))
					.is_none());
			},
			// Remove stale channels and tracking.
			6 => {
				let time_unix = u64::from_be_bytes(get_slice!(8).try_into().unwrap());
				network_graph.remove_stale_channels_and_tracking_with_time(time_unix);
			},
			_ => unreachable!(),
		}
	}
}

pub fn gossip_discovery_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	do_test(data, out);
}

#[no_mangle]
pub extern "C" fn gossip_discovery_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, test_logger::DevNull {});
}
