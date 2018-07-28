extern crate bitcoin;
extern crate crypto;
extern crate lightning;
extern crate secp256k1;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::Script;
use bitcoin::network::constants::Network;
use bitcoin::network::serialize::{serialize, BitcoinHash};
use bitcoin::util::hash::Sha256dHash;

use crypto::sha2::Sha256;
use crypto::digest::Digest;

use lightning::chain::chaininterface::{BroadcasterInterface,ConfirmationTarget,ChainListener,FeeEstimator,ChainWatchInterfaceUtil};
use lightning::chain::transaction::OutPoint;
use lightning::ln::channelmonitor;
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::peer_handler::{MessageHandler,PeerManager,SocketDescriptor};
use lightning::ln::router::Router;
use lightning::util::events::{EventsProvider,Event};
use lightning::util::reset_rng_state;

use secp256k1::key::{PublicKey,SecretKey};
use secp256k1::Secp256k1;

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize,Ordering};

#[inline]
pub fn slice_to_be16(v: &[u8]) -> u16 {
	((v[0] as u16) << 8*1) |
	((v[1] as u16) << 8*0)
}

#[inline]
pub fn slice_to_be24(v: &[u8]) -> u32 {
	((v[0] as u32) << 8*2) |
	((v[1] as u32) << 8*1) |
	((v[2] as u32) << 8*0)
}

#[inline]
pub fn slice_to_be32(v: &[u8]) -> u32 {
	((v[0] as u32) << 8*3) |
	((v[1] as u32) << 8*2) |
	((v[2] as u32) << 8*1) |
	((v[3] as u32) << 8*0)
}

#[inline]
pub fn be64_to_array(u: u64) -> [u8; 8] {
	let mut v = [0; 8];
	v[0] = ((u >> 8*7) & 0xff) as u8;
	v[1] = ((u >> 8*6) & 0xff) as u8;
	v[2] = ((u >> 8*5) & 0xff) as u8;
	v[3] = ((u >> 8*4) & 0xff) as u8;
	v[4] = ((u >> 8*3) & 0xff) as u8;
	v[5] = ((u >> 8*2) & 0xff) as u8;
	v[6] = ((u >> 8*1) & 0xff) as u8;
	v[7] = ((u >> 8*0) & 0xff) as u8;
	v
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
}

struct FuzzEstimator {
	input: Arc<InputData>,
}
impl FeeEstimator for FuzzEstimator {
	fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u64 {
		//TODO: We should actually be testing at least much more than 64k...
		match self.input.get_slice(2) {
			Some(slice) => slice_to_be16(slice) as u64 * 250,
			None => 0
		}
	}
}

struct TestChannelMonitor {}
impl channelmonitor::ManyChannelMonitor for TestChannelMonitor {
	fn add_update_monitor(&self, _funding_txo: OutPoint, _monitor: channelmonitor::ChannelMonitor) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		//TODO!
		Ok(())
	}
}

struct TestBroadcaster {}
impl BroadcasterInterface for TestBroadcaster {
	fn broadcast_transaction(&self, _tx: &Transaction) {}
}

#[derive(Clone)]
struct Peer<'a> {
	id: u8,
	peers_connected: &'a RefCell<[bool; 256]>,
}
impl<'a> SocketDescriptor for Peer<'a> {
	fn send_data(&mut self, data: &Vec<u8>, write_offset: usize, _resume_read: bool) -> usize {
		assert!(write_offset < data.len());
		data.len() - write_offset
	}
	fn disconnect_socket(&mut self) {
		assert!(self.peers_connected.borrow()[self.id as usize]);
		self.peers_connected.borrow_mut()[self.id as usize] = false;
	}
}
impl<'a> PartialEq for Peer<'a> {
	fn eq(&self, other: &Self) -> bool {
		self.id == other.id
	}
}
impl<'a> Eq for Peer<'a> {}
impl<'a> Hash for Peer<'a> {
	fn hash<H : std::hash::Hasher>(&self, h: &mut H) {
		self.id.hash(h)
	}
}

#[inline]
pub fn do_test(data: &[u8]) {
	reset_rng_state();

	let input = Arc::new(InputData {
		data: data.to_vec(),
		read_pos: AtomicUsize::new(0),
	});
	let fee_est = Arc::new(FuzzEstimator {
		input: input.clone(),
	});

	macro_rules! get_slice {
		($len: expr) => {
			match input.get_slice($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		}
	}

	let secp_ctx = Secp256k1::new();
	macro_rules! get_pubkey {
		() => {
			match PublicKey::from_slice(&secp_ctx, get_slice!(33)) {
				Ok(key) => key,
				Err(_) => return,
			}
		}
	}

	let our_network_key = match SecretKey::from_slice(&secp_ctx, get_slice!(32)) {
		Ok(key) => key,
		Err(_) => return,
	};

	let monitor = Arc::new(TestChannelMonitor{});
	let watch = Arc::new(ChainWatchInterfaceUtil::new());
	let broadcast = Arc::new(TestBroadcaster{});

	let channelmanager = ChannelManager::new(our_network_key, slice_to_be32(get_slice!(4)), get_slice!(1)[0] != 0, Network::Bitcoin, fee_est.clone(), monitor.clone(), watch.clone(), broadcast.clone()).unwrap();
	let router = Arc::new(Router::new(PublicKey::from_secret_key(&secp_ctx, &our_network_key).unwrap()));

	let peers = RefCell::new([false; 256]);
	let handler = PeerManager::new(MessageHandler {
		chan_handler: channelmanager.clone(),
		route_handler: router.clone(),
	}, our_network_key);

	let mut should_forward = false;
	let mut payments_received = Vec::new();
	let mut payments_sent = 0;
	let mut pending_funding_generation: Vec<([u8; 32], u64, Script)> = Vec::new();
	let mut pending_funding_signatures = HashMap::new();
	let mut pending_funding_relay = Vec::new();

	loop {
		match get_slice!(1)[0] {
			0 => {
				let mut new_id = 0;
				for i in 1..256 {
					if !peers.borrow()[i-1] {
						new_id = i;
						break;
					}
				}
				if new_id == 0 { return; }
				peers.borrow_mut()[new_id - 1] = true;
				handler.new_outbound_connection(get_pubkey!(), Peer{id: (new_id - 1) as u8, peers_connected: &peers}).unwrap();
			},
			1 => {
				let mut new_id = 0;
				for i in 1..256 {
					if !peers.borrow()[i-1] {
						new_id = i;
						break;
					}
				}
				if new_id == 0 { return; }
				peers.borrow_mut()[new_id - 1] = true;
				handler.new_inbound_connection(Peer{id: (new_id - 1) as u8, peers_connected: &peers}).unwrap();
			},
			2 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] { return; }
				peers.borrow_mut()[peer_id as usize] = false;
				handler.disconnect_event(&Peer{id: peer_id, peers_connected: &peers});
			},
			3 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] { return; }
				match handler.read_event(&mut Peer{id: peer_id, peers_connected: &peers}, get_slice!(get_slice!(1)[0]).to_vec()) {
					Ok(res) => assert!(!res),
					Err(_) => { peers.borrow_mut()[peer_id as usize] = false; }
				}
			},
			4 => {
				let value = slice_to_be24(get_slice!(3)) as u64;
				let route = match router.get_route(&get_pubkey!(), None, &Vec::new(), value, 42) {
					Ok(route) => route,
					Err(_) => return,
				};
				let mut payment_hash = [0; 32];
				payment_hash[0..8].copy_from_slice(&be64_to_array(payments_sent));
				let mut sha = Sha256::new();
				sha.input(&payment_hash);
				sha.result(&mut payment_hash);
				for i in 1..32 { payment_hash[i] = 0; }
				payments_sent += 1;
				match channelmanager.send_payment(route, payment_hash) {
					Ok(_) => {},
					Err(_) => return,
				}
			},
			5 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] { return; }
				let their_key = get_pubkey!();
				let chan_value = slice_to_be24(get_slice!(3)) as u64;
				if channelmanager.create_channel(their_key, chan_value, 0).is_err() { return; }
			},
			6 => {
				let mut channels = channelmanager.list_channels();
				let channel_id = get_slice!(1)[0] as usize;
				if channel_id >= channels.len() { return; }
				channels.sort_by(|a, b| { a.channel_id.cmp(&b.channel_id) });
				if channelmanager.close_channel(&channels[channel_id].channel_id).is_err() { return; }
			},
			7 => {
				if should_forward {
					channelmanager.process_pending_htlc_forwards();
					handler.process_events();
					should_forward = false;
				}
			},
			8 => {
				for payment in payments_received.drain(..) {
					let mut payment_preimage = None;
					for i in 0..payments_sent {
						let mut payment_hash = [0; 32];
						payment_hash[0..8].copy_from_slice(&be64_to_array(i));
						let mut sha = Sha256::new();
						sha.input(&payment_hash);
						sha.result(&mut payment_hash);
						for i in 1..32 { payment_hash[i] = 0; }
						if payment_hash == payment {
							payment_hash = [0; 32];
							payment_hash[0..8].copy_from_slice(&be64_to_array(i));
							payment_preimage = Some(payment_hash);
							break;
						}
					}
					channelmanager.claim_funds(payment_preimage.unwrap());
				}
			},
			9 => {
				for payment in payments_received.drain(..) {
					channelmanager.fail_htlc_backwards(&payment);
				}
			},
			10 => {
				for funding_generation in  pending_funding_generation.drain(..) {
					let mut tx = Transaction { version: 0, lock_time: 0, input: Vec::new(), output: vec![TxOut {
							value: funding_generation.1, script_pubkey: funding_generation.2,
						}] };
					let funding_output = OutPoint::new(Sha256dHash::from_data(&serialize(&tx).unwrap()[..]), 0);
					channelmanager.funding_transaction_generated(&funding_generation.0, funding_output.clone());
					pending_funding_signatures.insert(funding_output, tx);
				}
			},
			11 => {
				if !pending_funding_relay.is_empty() {
					let mut txn = Vec::with_capacity(pending_funding_relay.len());
					let mut txn_idxs = Vec::with_capacity(pending_funding_relay.len());
					for (idx, tx) in pending_funding_relay.iter().enumerate() {
						txn.push(tx);
						txn_idxs.push(idx as u32 + 1);
					}

					let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
					channelmanager.block_connected(&header, 1, &txn[..], &txn_idxs[..]);
					txn.clear();
					txn_idxs.clear();
					for i in 2..100 {
						header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
						channelmanager.block_connected(&header, i, &txn[..], &txn_idxs[..]);
					}
				}
				pending_funding_relay.clear();
			},
			_ => return,
		}
		for event in handler.get_and_clear_pending_events() {
			match event {
				Event::FundingGenerationReady { temporary_channel_id, channel_value_satoshis, output_script, .. } => {
					pending_funding_generation.push((temporary_channel_id, channel_value_satoshis, output_script));
				},
				Event::FundingBroadcastSafe { funding_txo, .. } => {
					pending_funding_relay.push(pending_funding_signatures.remove(&funding_txo).unwrap());
				},
				Event::PaymentReceived { payment_hash, .. } => {
					payments_received.push(payment_hash);
				},
				Event::PaymentSent {..} => {},
				Event::PaymentFailed {..} => {},

				Event::PendingHTLCsForwardable {..} => {
					should_forward = true;
				},
				_ => panic!("Unknown event"),
			}
		}
	}
}

#[cfg(feature = "afl")]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	afl::read_stdio_bytes(|data| {
		do_test(&data);
	});
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

extern crate hex;
#[cfg(test)]
mod tests {
	#[test]
	fn duplicate_crash() {
		super::do_test(&::hex::decode("00").unwrap());
	}
}
