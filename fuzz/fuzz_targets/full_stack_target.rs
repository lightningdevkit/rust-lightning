//! Test that no series of bytes received over the wire/connections created/payments sent can
//! result in a crash. We do this by standing up a node and then reading bytes from input to denote
//! actions such as creating new inbound/outbound connections, bytes to be read from a connection,
//! or payments to send/ways to handle events generated.
//! This test has been very useful, though due to its complexity good starting inputs are critical.

//Uncomment this for libfuzzer builds:
//#![no_main]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate lightning;
extern crate secp256k1;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::consensus::encode::deserialize;
use bitcoin::network::constants::Network;
use bitcoin::util::hash::BitcoinHash;

use bitcoin_hashes::Hash as TraitImport;
use bitcoin_hashes::HashEngine as TraitImportEngine;
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::hash160::Hash as Hash160;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;

use lightning::chain::chaininterface::{BroadcasterInterface,ConfirmationTarget,ChainListener,FeeEstimator,ChainWatchInterfaceUtil};
use lightning::chain::transaction::OutPoint;
use lightning::chain::keysinterface::{ChannelKeys, KeysInterface};
use lightning::ln::channelmonitor;
use lightning::ln::channelmanager::{ChannelManager, PaymentHash, PaymentPreimage};
use lightning::ln::peer_handler::{MessageHandler,PeerManager,SocketDescriptor};
use lightning::ln::router::Router;
use lightning::util::events::{EventsProvider,Event};
use lightning::util::logger::Logger;
use lightning::util::config::UserConfig;

mod utils;

use utils::test_logger;

use secp256k1::key::{PublicKey,SecretKey};
use secp256k1::Secp256k1;

use std::cell::RefCell;
use std::collections::{HashMap, hash_map};
use std::cmp;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64,AtomicUsize,Ordering};

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
			Some(slice) => cmp::max(slice_to_be16(slice) as u64, 253),
			None => 0
		}
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
	fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
		data.len()
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

struct MoneyLossDetector<'a> {
	manager: Arc<ChannelManager>,
	monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint>>,
	handler: PeerManager<Peer<'a>>,

	peers: &'a RefCell<[bool; 256]>,
	funding_txn: Vec<Transaction>,
	txids_confirmed: HashMap<Sha256dHash, usize>,
	header_hashes: Vec<Sha256dHash>,
	height: usize,
	max_height: usize,
	blocks_connected: u32,
}
impl<'a> MoneyLossDetector<'a> {
	pub fn new(peers: &'a RefCell<[bool; 256]>, manager: Arc<ChannelManager>, monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint>>, handler: PeerManager<Peer<'a>>) -> Self {
		MoneyLossDetector {
			manager,
			monitor,
			handler,

			peers,
			funding_txn: Vec::new(),
			txids_confirmed: HashMap::new(),
			header_hashes: vec![Default::default()],
			height: 0,
			max_height: 0,
			blocks_connected: 0,
		}
	}

	fn connect_block(&mut self, all_txn: &[Transaction]) {
		let mut txn = Vec::with_capacity(all_txn.len());
		let mut txn_idxs = Vec::with_capacity(all_txn.len());
		for (idx, tx) in all_txn.iter().enumerate() {
			let txid = tx.txid();
			match self.txids_confirmed.entry(txid) {
				hash_map::Entry::Vacant(e) => {
					e.insert(self.height);
					txn.push(tx);
					txn_idxs.push(idx as u32 + 1);
				},
				_ => {},
			}
		}

		let header = BlockHeader { version: 0x20000000, prev_blockhash: self.header_hashes[self.height], merkle_root: Default::default(), time: self.blocks_connected, bits: 42, nonce: 42 };
		self.height += 1;
		self.blocks_connected += 1;
		self.manager.block_connected(&header, self.height as u32, &txn[..], &txn_idxs[..]);
		(*self.monitor).block_connected(&header, self.height as u32, &txn[..], &txn_idxs[..]);
		if self.header_hashes.len() > self.height {
			self.header_hashes[self.height] = header.bitcoin_hash();
		} else {
			assert_eq!(self.header_hashes.len(), self.height);
			self.header_hashes.push(header.bitcoin_hash());
		}
		self.max_height = cmp::max(self.height, self.max_height);
	}

	fn disconnect_block(&mut self) {
		if self.height > 0 && (self.max_height < 6 || self.height >= self.max_height - 6) {
			self.height -= 1;
			let header = BlockHeader { version: 0x20000000, prev_blockhash: self.header_hashes[self.height], merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			self.manager.block_disconnected(&header, self.height as u32);
			self.monitor.block_disconnected(&header, self.height as u32);
			let removal_height = self.height;
			self.txids_confirmed.retain(|_, height| {
				removal_height != *height
			});
		}
	}
}

impl<'a> Drop for MoneyLossDetector<'a> {
	fn drop(&mut self) {
		if !::std::thread::panicking() {
			// Disconnect all peers
			for (idx, peer) in self.peers.borrow().iter().enumerate() {
				if *peer {
					self.handler.disconnect_event(&Peer{id: idx as u8, peers_connected: &self.peers});
				}
			}

			// Force all channels onto the chain (and time out claim txn)
			self.manager.force_close_all_channels();
		}
	}
}

struct KeyProvider {
	node_secret: SecretKey,
	counter: AtomicU64,
}
impl KeysInterface for KeyProvider {
	fn get_node_secret(&self) -> SecretKey {
		self.node_secret.clone()
	}

	fn get_destination_script(&self) -> Script {
		let secp_ctx = Secp256k1::signing_only();
		let channel_monitor_claim_key = SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap();
		let our_channel_monitor_claim_key_hash = <Hash160 as bitcoin_hashes::Hash>::hash(&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize());
		Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script()
	}

	fn get_shutdown_pubkey(&self) -> PublicKey {
		let secp_ctx = Secp256k1::signing_only();
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap())
	}

	fn get_channel_keys(&self, inbound: bool) -> ChannelKeys {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed) as u8;
		if inbound {
			ChannelKeys {
				funding_key:               SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, ctr]).unwrap(),
				revocation_base_key:       SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, ctr]).unwrap(),
				payment_base_key:          SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, ctr]).unwrap(),
				delayed_payment_base_key:  SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, ctr]).unwrap(),
				htlc_base_key:             SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, ctr]).unwrap(),
				commitment_seed: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, ctr],
			}
		} else {
			ChannelKeys {
				funding_key:               SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, ctr]).unwrap(),
				revocation_base_key:       SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, ctr]).unwrap(),
				payment_base_key:          SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, ctr]).unwrap(),
				delayed_payment_base_key:  SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, ctr]).unwrap(),
				htlc_base_key:             SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, ctr]).unwrap(),
				commitment_seed: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, ctr],
			}
		}
	}

	fn get_session_key(&self) -> SecretKey {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed) as u8;
		SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, ctr]).unwrap()
	}

	fn get_channel_id(&self) -> [u8; 32] {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		(ctr >> 8*7) as u8, (ctr >> 8*6) as u8, (ctr >> 8*5) as u8, (ctr >> 8*4) as u8, (ctr >> 8*3) as u8, (ctr >> 8*2) as u8, (ctr >> 8*1) as u8, 14, (ctr >> 8*0) as u8]
	}
}

#[inline]
pub fn do_test(data: &[u8], logger: &Arc<Logger>) {
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

	macro_rules! get_pubkey {
		() => {
			match PublicKey::from_slice(get_slice!(33)) {
				Ok(key) => key,
				Err(_) => return,
			}
		}
	}

	let our_network_key = match SecretKey::from_slice(get_slice!(32)) {
		Ok(key) => key,
		Err(_) => return,
	};

	let watch = Arc::new(ChainWatchInterfaceUtil::new(Network::Bitcoin, Arc::clone(&logger)));
	let broadcast = Arc::new(TestBroadcaster{});
	let monitor = channelmonitor::SimpleManyChannelMonitor::new(watch.clone(), broadcast.clone(), Arc::clone(&logger), fee_est.clone());

	let keys_manager = Arc::new(KeyProvider { node_secret: our_network_key.clone(), counter: AtomicU64::new(0) });
	let mut config = UserConfig::new();
	config.channel_options.fee_proportional_millionths =  slice_to_be32(get_slice!(4));
	config.channel_options.announced_channel = get_slice!(1)[0] != 0;
	config.peer_channel_config_limits.min_dust_limit_satoshis = 0;
	let channelmanager = ChannelManager::new(Network::Bitcoin, fee_est.clone(), monitor.clone(), watch.clone(), broadcast.clone(), Arc::clone(&logger), keys_manager.clone(), config).unwrap();
	let router = Arc::new(Router::new(PublicKey::from_secret_key(&Secp256k1::signing_only(), &keys_manager.get_node_secret()), watch.clone(), Arc::clone(&logger)));

	let peers = RefCell::new([false; 256]);
	let mut loss_detector = MoneyLossDetector::new(&peers, channelmanager.clone(), monitor.clone(), PeerManager::new(MessageHandler {
		chan_handler: channelmanager.clone(),
		route_handler: router.clone(),
	}, our_network_key, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0], Arc::clone(&logger)));

	let mut should_forward = false;
	let mut payments_received: Vec<PaymentHash> = Vec::new();
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
				loss_detector.handler.new_outbound_connection(get_pubkey!(), Peer{id: (new_id - 1) as u8, peers_connected: &peers}).unwrap();
				peers.borrow_mut()[new_id - 1] = true;
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
				loss_detector.handler.new_inbound_connection(Peer{id: (new_id - 1) as u8, peers_connected: &peers}).unwrap();
				peers.borrow_mut()[new_id - 1] = true;
			},
			2 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] { return; }
				loss_detector.handler.disconnect_event(&Peer{id: peer_id, peers_connected: &peers});
				peers.borrow_mut()[peer_id as usize] = false;
			},
			3 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] { return; }
				match loss_detector.handler.read_event(&mut Peer{id: peer_id, peers_connected: &peers}, get_slice!(get_slice!(1)[0]).to_vec()) {
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
				let mut payment_hash = PaymentHash([0; 32]);
				payment_hash.0[0..8].copy_from_slice(&be64_to_array(payments_sent));
				let mut sha = Sha256::engine();
				sha.input(&payment_hash.0[..]);
				payment_hash.0 = Sha256::from_engine(sha).into_inner();
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
				let push_msat_value = slice_to_be24(get_slice!(3)) as u64;
				if channelmanager.create_channel(their_key, chan_value, push_msat_value, 0).is_err() { return; }
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
					should_forward = false;
				}
			},
			8 => {
				for payment in payments_received.drain(..) {
					// SHA256 is defined as XOR of all input bytes placed in the first byte, and 0s
					// for the remaining bytes. Thus, if not all remaining bytes are 0s we cannot
					// fulfill this HTLC, but if they are, we can just take the first byte and
					// place that anywhere in our preimage.
					if &payment.0[1..] != &[0; 31] {
						channelmanager.fail_htlc_backwards(&payment);
					} else {
						let mut payment_preimage = PaymentPreimage([0; 32]);
						payment_preimage.0[0] = payment.0[0];
						channelmanager.claim_funds(payment_preimage);
					}
				}
			},
			9 => {
				for payment in payments_received.drain(..) {
					channelmanager.fail_htlc_backwards(&payment);
				}
			},
			10 => {
				'outer_loop: for funding_generation in pending_funding_generation.drain(..) {
					let mut tx = Transaction { version: 0, lock_time: 0, input: Vec::new(), output: vec![TxOut {
							value: funding_generation.1, script_pubkey: funding_generation.2,
						}] };
					let funding_output = 'search_loop: loop {
						let funding_txid = tx.txid();
						if let None = loss_detector.txids_confirmed.get(&funding_txid) {
							let outpoint = OutPoint::new(funding_txid, 0);
							for chan in channelmanager.list_channels() {
								if chan.channel_id == outpoint.to_channel_id() {
									tx.version += 1;
									continue 'search_loop;
								}
							}
							break outpoint;
						}
						tx.version += 1;
						if tx.version > 0xff {
							continue 'outer_loop;
						}
					};
					channelmanager.funding_transaction_generated(&funding_generation.0, funding_output.clone());
					pending_funding_signatures.insert(funding_output, tx);
				}
			},
			11 => {
				if !pending_funding_relay.is_empty() {
					loss_detector.connect_block(&pending_funding_relay[..]);
					for _ in 2..100 {
						loss_detector.connect_block(&[]);
					}
				}
				for tx in pending_funding_relay.drain(..) {
					loss_detector.funding_txn.push(tx);
				}
			},
			12 => {
				let txlen = slice_to_be16(get_slice!(2));
				if txlen == 0 {
					loss_detector.connect_block(&[]);
				} else {
					let txres: Result<Transaction, _> = deserialize(get_slice!(txlen));
					if let Ok(tx) = txres {
						loss_detector.connect_block(&[tx]);
					} else {
						return;
					}
				}
			},
			13 => {
				loss_detector.disconnect_block();
			},
			14 => {
				let mut channels = channelmanager.list_channels();
				let channel_id = get_slice!(1)[0] as usize;
				if channel_id >= channels.len() { return; }
				channels.sort_by(|a, b| { a.channel_id.cmp(&b.channel_id) });
				channelmanager.force_close_channel(&channels[channel_id].channel_id);
			},
			_ => return,
		}
		loss_detector.handler.process_events();
		for event in loss_detector.manager.get_and_clear_pending_events() {
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
				Event::SpendableOutputs {..} => {},
			}
		}
	}
}

#[cfg(feature = "afl")]
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	fuzz!(|data| {
		let logger: Arc<Logger> = Arc::new(test_logger::TestLogger::new("".to_owned()));
		do_test(data, &logger);
	});
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
	loop {
		fuzz!(|data| {
			let logger: Arc<Logger> = Arc::new(test_logger::TestLogger::new("".to_owned()));
			do_test(data, &logger);
		});
	}
}

#[cfg(feature = "libfuzzer_fuzz")]
#[macro_use] extern crate libfuzzer_sys;
#[cfg(feature = "libfuzzer_fuzz")]
fuzz_target!(|data: &[u8]| {
	let logger: Arc<Logger> = Arc::new(test_logger::TestLogger::new("".to_owned()));
	do_test(data, &logger);
});

extern crate hex;
#[cfg(test)]
mod tests {
	use utils::test_logger;
	use lightning::util::logger::{Logger, Record};
	use std::collections::HashMap;
	use std::sync::{Arc, Mutex};

	#[test]
	fn duplicate_crash() {
		let logger: Arc<Logger> = Arc::new(test_logger::TestLogger::new("".to_owned()));
		super::do_test(&::hex::decode("00").unwrap(), &logger);
	}

	struct TrackingLogger {
		/// (module, message) -> count
		pub lines: Mutex<HashMap<(String, String), usize>>,
	}
	impl Logger for TrackingLogger {
		fn log(&self, record: &Record) {
			*self.lines.lock().unwrap().entry((record.module_path.to_string(), format!("{}", record.args))).or_insert(0) += 1;
			println!("{:<5} [{} : {}, {}] {}", record.level.to_string(), record.module_path, record.file, record.line, record.args);
		}
	}

	#[test]
	fn test_no_existing_test_breakage() {
		// To avoid accidentally causing all existing fuzz test cases to be useless by making minor
		// changes (such as requesting feerate info in a new place), we run a pretty full
		// step-through with two peers and HTLC forwarding here. Obviously this is pretty finicky,
		// so this should be updated pretty liberally, but at least we'll know when changes occur.
		// If nothing else, this test serves as a pretty great initial full_stack_target seed.

		// What each byte represents is broken down below, and then everything is concatenated into
		// one large test at the end (you want %s/ -.*//g %s/\n\| \|\t\|\///g).

		// Following BOLT 8, lightning message on the wire are: 2-byte encrypted message length + 
		// 16-byte MAC of the encrypted message length + encrypted Lightning message + 16-byte MAC
		// of the Lightning message
		// I.e 2nd inbound read, len 18 : 0006 (encrypted message length) + 03000000000000000000000000000000 (MAC of the encrypted message length)
		// Len 22 : 0010 00000000 (encrypted lightning message) + 03000000000000000000000000000000 (MAC of the Lightning message)

		// 0000000000000000000000000000000000000000000000000000000000000000 - our network key
		// 00000000 - fee_proportional_millionths
		// 01 - announce_channels_publicly
		//
		// 00 - new outbound connection with id 0
		// 030000000000000000000000000000000000000000000000000000000000000000 - peer's pubkey
		// 030032 - inbound read from peer id 0 of len 50
		// 00 030000000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - noise act two (0||pubkey||mac)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0006 03000000000000000000000000000000 - message header indicating message length 6
		// 030016 - inbound read from peer id 0 of len 22
		// 0010 00000000 03000000000000000000000000000000 - init message with no features (type 16) and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0141 03000000000000000000000000000000 - message header indicating message length 321
		// 0300fe - inbound read from peer id 0 of len 254
		// 0020 7500000000000000000000000000000000000000000000000000000000000000 ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679 000000000000c350 0000000000000000 0000000000000222 ffffffffffffffff 0000000000000222 0000000000000000 000000fd 0006 01e3 030000000000000000000000000000000000000000000000000000000000000001 030000000000000000000000000000000000000000000000000000000000000002 030000000000000000000000000000000000000000000000000000000000000003 030000000000000000000000000000000000000000000000000000000000000004 - beginning of open_channel message
		// 030053 - inbound read from peer id 0 of len 83
		// 030000000000000000000000000000000000000000000000000000000000000005 030000000000000000000000000000000000000000000000000000000000000000 01 03000000000000000000000000000000 - rest of open_channel and mac
		//
		// 00fd00fd00fd - Three feerate requests (all returning min feerate, which our open_channel also uses) (gonna be ingested by FuzzEstimator)
		// - client should now respond with accept_channel (CHECK 1: type 33 to peer 03000000)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0084 03000000000000000000000000000000 - message header indicating message length 132
		// 030094 - inbound read from peer id 0 of len 148
		// 0022 ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679 3d00000000000000000000000000000000000000000000000000000000000000 0000 5c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 03000000000000000000000000000000 - funding_created and mac
		// - client should now respond with funding_signed (CHECK 2: type 35 to peer 03000000)
		//
		// 0c005e - connect a block with one transaction of len 94
		// 020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0150c3000000000000220020ae0000000000000000000000000000000000000000000000000000000000000000000000 - the funding transaction
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// - by now client should have sent a funding_locked (CHECK 3: SendFundingLocked to 03000000 for chan 3d000000)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0043 03000000000000000000000000000000 - message header indicating message length 67
		// 030053 - inbound read from peer id 0 of len 83
		// 0024 3d00000000000000000000000000000000000000000000000000000000000000 030100000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - funding_locked and mac
		//
		// 01 - new inbound connection with id 1
		// 030132 - inbound read from peer id 1 of len 50
		// 0003000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000 - inbound noise act 1
		// 030142 - inbound read from peer id 1 of len 66
		// 000302000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003000000000000000000000000000000 - inbound noise act 3
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0006 01000000000000000000000000000000 - message header indicating message length 6
		// 030116 - inbound read from peer id 1 of len 22
		// 0010 00000000 01000000000000000000000000000000 - init message with no features (type 16)
		//
		// 05 01 030200000000000000000000000000000000000000000000000000000000000000 00c350 0003e8 - create outbound channel to peer 1 for 50k sat
		// 00fd00fd00fd - Three feerate requests (all returning min feerate) (gonna be ingested by FuzzEstimator)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0110 01000000000000000000000000000000 - message header indicating message length 272
		// 0301ff - inbound read from peer id 1 of len 255
		// 0021 0000000000000000000000000000000000000000000000000000000000000e02 000000000000001a 00000000004c4b40 00000000000003e8 00000000000003e8 00000002 03f0 0005 030000000000000000000000000000000000000000000000000000000000000100 030000000000000000000000000000000000000000000000000000000000000200 030000000000000000000000000000000000000000000000000000000000000300 030000000000000000000000000000000000000000000000000000000000000400 030000000000000000000000000000000000000000000000000000000000000500 03000000000000000000000000000000 - beginning of accept_channel
		// 030121 - inbound read from peer id 1 of len 33
		// 0000000000000000000000000000000000 01000000000000000000000000000000 - rest of accept_channel and mac
		//
		// 0a - create the funding transaction (client should send funding_created now)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0062 01000000000000000000000000000000 - message header indicating message length 98
		// 030172 - inbound read from peer id 1 of len 114
		// 0023 3900000000000000000000000000000000000000000000000000000000000000 f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 01000000000000000000000000000000 - funding_signed message and mac
		//
		// 0b - broadcast funding transaction
		// - by now client should have sent a funding_locked (CHECK 4: SendFundingLocked to 03020000 for chan 3f000000)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0043 01000000000000000000000000000000 - message header indicating message length 67
		// 030153 - inbound read from peer id 1 of len 83
		// 0024 3900000000000000000000000000000000000000000000000000000000000000 030100000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - funding_locked and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 05ac 03000000000000000000000000000000 - message header indicating message length 1452
		// 0300ff - inbound read from peer id 0 of len 255
		// 0080 3d00000000000000000000000000000000000000000000000000000000000000 0000000000000000 0000000000003e80 ff00000000000000000000000000000000000000000000000000000000000000 00000121 00 030000000000000000000000000000000000000000000000000000000000000555 0000000e000001000000000000000003e8000000010000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - beginning of update_add_htlc from 0 to 1 via client
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300c1 - inbound read from peer id 0 of len 193
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff ef00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - end of update_add_htlc from 0 to 1 via client and mac
		//
		// 00fd - A feerate request (returning min feerate, which our open_channel also uses) (gonna be ingested by FuzzEstimator)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0064 03000000000000000000000000000000 - message header indicating message length 100
		// 030074 - inbound read from peer id 0 of len 116
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 4d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 0000 03000000000000000000000000000000 - commitment_signed and mac
		// - client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6: types 133 and 132 to peer 03000000)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000 030200000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 1 update_add_htlc and commitment_signed (CHECK 7: SendHTLCs event for node 03020000 with 1 HTLCs for channel 3f000000)
		//
		// - we respond with commitment_signed then revoke_and_ack (a weird, but valid, order)
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3900000000000000000000000000000000000000000000000000000000000000 f1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3900000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000 030200000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 004a 01000000000000000000000000000000 - message header indicating message length 74
		// 03015a - inbound read from peer id 1 of len 90
		// 0082 3900000000000000000000000000000000000000000000000000000000000000 0000000000000000 ff00888888888888888888888888888888888888888888888888888888888888 01000000000000000000000000000000 - update_fulfill_htlc and mac
		// - client should immediately claim the pending HTLC from peer 0 (CHECK 8: SendFulfillHTLCs for node 03000000 with preimage ff00888888 for channel 3d000000)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3900000000000000000000000000000000000000000000000000000000000000 fd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3900000000000000000000000000000000000000000000000000000000000000 0100000000000000000000000000000000000000000000000000000000000000 030300000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// - before responding to the commitment_signed generated above, send a new HTLC
		// 030012 - inbound read from peer id 0 of len 18
		// 05ac 03000000000000000000000000000000 - message header indicating message length 1452
		// 0300ff - inbound read from peer id 0 of len 255
		// 0080 3d00000000000000000000000000000000000000000000000000000000000000 0000000000000001 0000000000003e80 ff00000000000000000000000000000000000000000000000000000000000000 00000121 00 030000000000000000000000000000000000000000000000000000000000000555 0000000e000001000000000000000003e8000000010000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - beginning of update_add_htlc from 0 to 1 via client
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300c1 - inbound read from peer id 0 of len 193
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff ef00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - end of update_add_htlc from 0 to 1 via client and mac
		//
		// 00fd - A feerate request (returning min feerate, which our open_channel also uses) (gonna be ingested by FuzzEstimator)
		//
		// - now respond to the update_fulfill_htlc+commitment_signed messages the client sent to peer 0
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0100000000000000000000000000000000000000000000000000000000000000 030300000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		// - client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6 duplicates)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0064 03000000000000000000000000000000 - message header indicating message length 100
		// 030074 - inbound read from peer id 0 of len 116
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 be000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 0000 03000000000000000000000000000000 - commitment_signed and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0200000000000000000000000000000000000000000000000000000000000000 030400000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 1 update_add_htlc and commitment_signed (CHECK 7 duplicate)
		// - we respond with revoke_and_ack, then commitment_signed, then update_fail_htlc
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3900000000000000000000000000000000000000000000000000000000000000 fc000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3900000000000000000000000000000000000000000000000000000000000000 0200000000000000000000000000000000000000000000000000000000000000 030400000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 002c 01000000000000000000000000000000 - message header indicating message length 44
		// 03013c - inbound read from peer id 1 of len 60
		// 0083 3900000000000000000000000000000000000000000000000000000000000000 0000000000000001 0000 01000000000000000000000000000000 - update_fail_htlc and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3900000000000000000000000000000000000000000000000000000000000000 fb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3900000000000000000000000000000000000000000000000000000000000000 0300000000000000000000000000000000000000000000000000000000000000 030500000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 0 update_fail_htlc and commitment_signed (CHECK 9)
		// - now respond to the update_fail_htlc+commitment_signed messages the client sent to peer 0
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0300000000000000000000000000000000000000000000000000000000000000 030500000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0064 03000000000000000000000000000000 - message header indicating message length 100
		// 030074 - inbound read from peer id 0 of len 116
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 4f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 0000 03000000000000000000000000000000 - commitment_signed and mac
		// - client should now respond with revoke_and_ack (CHECK 5 duplicate)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 05ac 03000000000000000000000000000000 - message header indicating message length 1452
		// 0300ff - inbound read from peer id 0 of len 255
		// 0080 3d00000000000000000000000000000000000000000000000000000000000000 0000000000000002 00000000000b0838 ff00000000000000000000000000000000000000000000000000000000000000 00000121 00 030000000000000000000000000000000000000000000000000000000000000555 0000000e0000010000000000000003e800000000010000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - beginning of update_add_htlc from 0 to 1 via client
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300c1 - inbound read from peer id 0 of len 193
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff ef00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - end of update_add_htlc from 0 to 1 via client and mac
		//
		// 00fd - A feerate request (returning min feerate, which our open_channel also uses) (gonna be ingested by FuzzEstimator)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 00a4 03000000000000000000000000000000 - message header indicating message length 164
		// 0300b4 - inbound read from peer id 0 of len 180
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 07000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 0001 c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f00000000000000 03000000000000000000000000000000 - commitment_signed and mac
		// - client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6 duplicates)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0400000000000000000000000000000000000000000000000000000000000000 030600000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 1 update_add_htlc and commitment_signed (CHECK 7 duplicate)
		//
		// 0c007d - connect a block with one transaction of len 125
		// 0200000001390000000000000000000000000000000000000000000000000000000000000000000000000000008002000100000000000022002090000000000000000000000000000000000000000000000000000000000000006cc10000000000001600145c0000000000000000000000000000000000000005000020 - the commitment transaction for channel 3f00000000000000000000000000000000000000000000000000000000000000
		// 00fd - A feerate request (returning min feerate, which our open_channel also uses) (gonna be ingested by FuzzEstimator)
		// 00fd - A feerate request (returning min feerate, which our open_channel also uses) (gonna be ingested by FuzzEstimator)
		// 0c005e - connect a block with one transaction of len 94
		// 0200000001fd00000000000000000000000000000000000000000000000000000000000000000000000000000000014f00000000000000220020f60000000000000000000000000000000000000000000000000000000000000000000000 - the funding transaction
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		//
		// 07 - process the now-pending HTLC forward
		// - client now fails the HTLC backwards as it was unable to extract the payment preimage (CHECK 9 duplicate and CHECK 10)

		let logger = Arc::new(TrackingLogger { lines: Mutex::new(HashMap::new()) });
		super::do_test(&::hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000001000300000000000000000000000000000000000000000000000000000000000000000300320003000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000030012000603000000000000000000000000000000030016001000000000030000000000000000000000000000000300120141030000000000000000000000000000000300fe00207500000000000000000000000000000000000000000000000000000000000000ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679000000000000c35000000000000000000000000000000222ffffffffffffffff00000000000002220000000000000000000000fd000601e3030000000000000000000000000000000000000000000000000000000000000001030000000000000000000000000000000000000000000000000000000000000002030000000000000000000000000000000000000000000000000000000000000003030000000000000000000000000000000000000000000000000000000000000004030053030000000000000000000000000000000000000000000000000000000000000005030000000000000000000000000000000000000000000000000000000000000000010300000000000000000000000000000000fd00fd00fd0300120084030000000000000000000000000000000300940022ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb1819096793d0000000000000000000000000000000000000000000000000000000000000000005c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001030000000000000000000000000000000c005e020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0150c3000000000000220020ae00000000000000000000000000000000000000000000000000000000000000000000000c00000c00000c00000c00000c00000c00000c00000c00000c00000c00000c00000c000003001200430300000000000000000000000000000003005300243d000000000000000000000000000000000000000000000000000000000000000301000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001030132000300000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003014200030200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000300000000000000000000000000000003011200060100000000000000000000000000000003011600100000000001000000000000000000000000000000050103020000000000000000000000000000000000000000000000000000000000000000c3500003e800fd00fd00fd0301120110010000000000000000000000000000000301ff00210000000000000000000000000000000000000000000000000000000000000e02000000000000001a00000000004c4b4000000000000003e800000000000003e80000000203f00005030000000000000000000000000000000000000000000000000000000000000100030000000000000000000000000000000000000000000000000000000000000200030000000000000000000000000000000000000000000000000000000000000300030000000000000000000000000000000000000000000000000000000000000400030000000000000000000000000000000000000000000000000000000000000500030000000000000000000000000000000301210000000000000000000000000000000000010000000000000000000000000000000a03011200620100000000000000000000000000000003017200233900000000000000000000000000000000000000000000000000000000000000f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100010000000000000000000000000000000b030112004301000000000000000000000000000000030153002439000000000000000000000000000000000000000000000000000000000000000301000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000003001205ac030000000000000000000000000000000300ff00803d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e80ff0000000000000000000000000000000000000000000000000000000000000000000121000300000000000000000000000000000000000000000000000000000000000005550000000e000001000000000000000003e8000000010000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000fd03001200640300000000000000000000000000000003007400843d000000000000000000000000000000000000000000000000000000000000004d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000300000000000000000000000000000003001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000703011200640100000000000000000000000000000003017400843900000000000000000000000000000000000000000000000000000000000000f100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000030112004a0100000000000000000000000000000003015a008239000000000000000000000000000000000000000000000000000000000000000000000000000000ff008888888888888888888888888888888888888888888888888888888888880100000000000000000000000000000003011200640100000000000000000000000000000003017400843900000000000000000000000000000000000000000000000000000000000000fd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000010000000000000000000000000000000301120063010000000000000000000000000000000301730085390000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000303000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000003001205ac030000000000000000000000000000000300ff00803d0000000000000000000000000000000000000000000000000000000000000000000000000000010000000000003e80ff0000000000000000000000000000000000000000000000000000000000000000000121000300000000000000000000000000000000000000000000000000000000000005550000000e000001000000000000000003e8000000010000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000fd03001200630300000000000000000000000000000003007300853d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000303000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200640300000000000000000000000000000003007400843d00000000000000000000000000000000000000000000000000000000000000be00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000300000000000000000000000000000003001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000030400000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000703011200640100000000000000000000000000000003017400843900000000000000000000000000000000000000000000000000000000000000fc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853900000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003040000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000030112002c0100000000000000000000000000000003013c00833900000000000000000000000000000000000000000000000000000000000000000000000000000100000100000000000000000000000000000003011200640100000000000000000000000000000003017400843900000000000000000000000000000000000000000000000000000000000000fb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000000000000000000000000000030112006301000000000000000000000000000000030173008539000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000030500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000703001200630300000000000000000000000000000003007300853d0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000305000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200640300000000000000000000000000000003007400843d000000000000000000000000000000000000000000000000000000000000004f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000300000000000000000000000000000003001205ac030000000000000000000000000000000300ff00803d00000000000000000000000000000000000000000000000000000000000000000000000000000200000000000b0838ff0000000000000000000000000000000000000000000000000000000000000000000121000300000000000000000000000000000000000000000000000000000000000005550000000e0000010000000000000003e800000000010000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000fd03001200a4030000000000000000000000000000000300b400843d00000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f000000000000000300000000000000000000000000000003001200630300000000000000000000000000000003007300853d00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000003060000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000070c007d0200000001390000000000000000000000000000000000000000000000000000000000000000000000000000008002000100000000000022002090000000000000000000000000000000000000000000000000000000000000006cc10000000000001600145c000000000000000000000000000000000000000500002000fd00fd0c005e0200000001fd00000000000000000000000000000000000000000000000000000000000000000000000000000000014f00000000000000220020f600000000000000000000000000000000000000000000000000000000000000000000000c00000c00000c00000c00000c000007").unwrap(), &(Arc::clone(&logger) as Arc<Logger>));

		let log_entries = logger.lines.lock().unwrap();
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendAcceptChannel event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 for channel ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679".to_string())), Some(&1)); // 1
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendFundingSigned event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 2
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendFundingLocked event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 3
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendFundingLocked event in peer_handler for node 030200000000000000000000000000000000000000000000000000000000000000 for channel 3900000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 4
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendRevokeAndACK event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&4)); // 5
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 with 0 adds, 0 fulfills, 0 fails for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&3)); // 6
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030200000000000000000000000000000000000000000000000000000000000000 with 1 adds, 0 fulfills, 0 fails for channel 3900000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&3)); // 7
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 with 0 adds, 1 fulfills, 0 fails for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 8
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 with 0 adds, 0 fulfills, 1 fails for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&2)); // 9
		assert_eq!(log_entries.get(&("lightning::ln::channelmonitor".to_string(), "Input spending remote commitment tx (00000000000000000000000000000000000000000000000000000000000000fd:0) in 0000000000000000000000000000000000000000000000000000000000000044 resolves outbound HTLC with payment hash ff00000000000000000000000000000000000000000000000000000000000000 with timeout".to_string())), Some(&1)); // 10
	}
}
