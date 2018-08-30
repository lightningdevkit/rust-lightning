extern crate bitcoin;
extern crate crypto;
extern crate lightning;
extern crate secp256k1;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::Script;
use bitcoin::network::constants::Network;
use bitcoin::network::serialize::{deserialize, serialize, BitcoinHash};
use bitcoin::util::hash::Sha256dHash;

use crypto::digest::Digest;

use lightning::chain::chaininterface::{BroadcasterInterface,ConfirmationTarget,ChainListener,FeeEstimator,ChainWatchInterfaceUtil};
use lightning::chain::transaction::OutPoint;
use lightning::ln::channelmonitor;
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::peer_handler::{MessageHandler,PeerManager,SocketDescriptor};
use lightning::ln::router::Router;
use lightning::util::events::{EventsProvider,Event};
use lightning::util::reset_rng_state;
use lightning::util::logger::Logger;
use lightning::util::sha2::Sha256;

mod utils;

use utils::test_logger;

use secp256k1::key::{PublicKey,SecretKey};
use secp256k1::Secp256k1;

use std::cell::RefCell;
use std::collections::HashMap;
use std::cmp;
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

struct MoneyLossDetector<'a> {
	manager: Arc<ChannelManager>,
	monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint>>,
	handler: PeerManager<Peer<'a>>,

	peers: &'a RefCell<[bool; 256]>,
	funding_txn: Vec<Transaction>,
	header_hashes: Vec<Sha256dHash>,
	height: usize,
	max_height: usize,

}
impl<'a> MoneyLossDetector<'a> {
	pub fn new(peers: &'a RefCell<[bool; 256]>, manager: Arc<ChannelManager>, monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint>>, handler: PeerManager<Peer<'a>>) -> Self {
		MoneyLossDetector {
			manager,
			monitor,
			handler,

			peers,
			funding_txn: Vec::new(),
			header_hashes: vec![Default::default()],
			height: 0,
			max_height: 0,
		}
	}

	fn connect_block(&mut self, txn: &[&Transaction], txn_idxs: &[u32]) {
		let header = BlockHeader { version: 0x20000000, prev_blockhash: self.header_hashes[self.height], merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		self.height += 1;
		self.manager.block_connected(&header, self.height as u32, txn, txn_idxs);
		(*self.monitor).block_connected(&header, self.height as u32, txn, txn_idxs);
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
			self.manager.block_disconnected(&header);
			self.monitor.block_disconnected(&header);
		}
	}
}

impl<'a> Drop for MoneyLossDetector<'a> {
	fn drop(&mut self) {
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

#[inline]
pub fn do_test(data: &[u8], logger: &Arc<Logger>) {
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

	let watch = Arc::new(ChainWatchInterfaceUtil::new(Network::Bitcoin, Arc::clone(&logger)));
	let broadcast = Arc::new(TestBroadcaster{});
	let monitor = channelmonitor::SimpleManyChannelMonitor::new(watch.clone(), broadcast.clone());

	let channelmanager = ChannelManager::new(our_network_key, slice_to_be32(get_slice!(4)), get_slice!(1)[0] != 0, Network::Bitcoin, fee_est.clone(), monitor.clone(), watch.clone(), broadcast.clone(), Arc::clone(&logger)).unwrap();
	let router = Arc::new(Router::new(PublicKey::from_secret_key(&secp_ctx, &our_network_key), watch.clone(), Arc::clone(&logger)));

	let peers = RefCell::new([false; 256]);
	let mut loss_detector = MoneyLossDetector::new(&peers, channelmanager.clone(), monitor.clone(), PeerManager::new(MessageHandler {
		chan_handler: channelmanager.clone(),
		route_handler: router.clone(),
	}, our_network_key, Arc::clone(&logger)));

	let mut should_forward = false;
	let mut payments_received: Vec<[u8; 32]> = Vec::new();
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
				let mut payment_hash = [0; 32];
				payment_hash[0..8].copy_from_slice(&be64_to_array(payments_sent));
				let mut sha = Sha256::new();
				sha.input(&payment_hash);
				sha.result(&mut payment_hash);
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
					if &payment[1..] != &[0; 31] {
						channelmanager.fail_htlc_backwards(&payment);
					} else {
						let mut payment_preimage = [0; 32];
						payment_preimage[0] = payment[0];
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
				for funding_generation in pending_funding_generation.drain(..) {
					let mut tx = Transaction { version: 0, lock_time: 0, input: Vec::new(), output: vec![TxOut {
							value: funding_generation.1, script_pubkey: funding_generation.2,
						}] };
					let funding_output = OutPoint::new(Sha256dHash::from_data(&serialize(&tx).unwrap()[..]), 0);
					let mut found_duplicate_txo = false;
					for chan in channelmanager.list_channels() {
						if chan.channel_id == funding_output.to_channel_id() {
							found_duplicate_txo = true;
						}
					}
					if !found_duplicate_txo {
						channelmanager.funding_transaction_generated(&funding_generation.0, funding_output.clone());
						pending_funding_signatures.insert(funding_output, tx);
					}
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

					loss_detector.connect_block(&txn[..], &txn_idxs[..]);
					txn_idxs.clear();
					for _ in 2..100 {
						loss_detector.connect_block(&txn[..], &txn_idxs[..]);
					}
				}
				for tx in pending_funding_relay.drain(..) {
					loss_detector.funding_txn.push(tx);
				}
			},
			12 => {
				let txlen = slice_to_be16(get_slice!(2));
				if txlen == 0 {
					loss_detector.connect_block(&[], &[]);
				} else {
					let txres: Result<Transaction, _> = deserialize(get_slice!(txlen));
					if let Ok(tx) = txres {
						loss_detector.connect_block(&[&tx], &[1]);
					} else {
						return;
					}
				}
			},
			13 => {
				loss_detector.disconnect_block();
			},
			_ => return,
		}
		loss_detector.handler.process_events();
		for event in loss_detector.handler.get_and_clear_pending_events() {
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
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	fuzz!(|data| {
		let logger: Arc<Logger> = Arc::new(test_logger::TestLogger{});
		do_test(data, &logger);
	});
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
	loop {
		fuzz!(|data| {
			let logger: Arc<Logger> = Arc::new(test_logger::TestLogger{});
			do_test(data, &logger);
		});
	}
}

extern crate hex;
#[cfg(test)]
mod tests {
	use utils::test_logger;
	use lightning::util::logger::{Logger, Record};
	use std::collections::HashMap;
	use std::sync::{Arc, Mutex};

	#[test]
	fn duplicate_crash() {
		let logger: Arc<Logger> = Arc::new(test_logger::TestLogger{});
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
		// 0010 00000000 03000000000000000000000000000000 - init message with no features (type 16)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0141 03000000000000000000000000000000 - message header indicating message length 321
		// 0300ff - inbound read from peer id 0 of len 255
		// 0020 7500000000000000000000000000000000000000000000000000000000000000ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679000000000000c35000000000000000000000000000000222ffffffffffffffff00000000000002220000000000000000000000fd000601e303000000000000000000000000000000000000000000000000000000000000000103000000000000000000000000000000000000000000000000000000000000000203000000000000000000000000000000000000000000000000000000000000000303000000000000000000000000000000000000000000000000000000000000000403 - beginning of open_channel message
		// 030052 - inbound read from peer id 0 of len 82
		// 0000000000000000000000000000000000000000000000000000000000000005 030100000000000000000000000000000000000000000000000000000000000000 01 03000000000000000000000000000000 - rest of open_channel and mac
		//
		// 00fd00fd00fd - Three feerate requests (all returning min feerate, which our open_channel also uses)
		// - client should now respond with accept_channel (CHECK 1: type 33 to peer 03000000)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0084 03000000000000000000000000000000 - message header indicating message length 132
		// 030094 - inbound read from peer id 0 of len 148
		// 0022 ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb1819096793d00000000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 03000000000000000000000000000000 - funding_created and mac
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
		// 0024 3d00000000000000000000000000000000000000000000000000000000000000 030000000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - funding_locked and mac
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
		// 00fd00fd00fd - Three feerate requests (all returning min feerate)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0110 01000000000000000000000000000000 - message header indicating message length 272
		// 0301ff - inbound read from peer id 1 of len 255
		// 0021 0200000000000000020000000000000002000000000000000200000000000000000000000000001a00000000004c4b4000000000000003e800000000000003e80000000203f0000503000000000000000000000000000000000000000000000000000000000000010003000000000000000000000000000000000000000000000000000000000000020003000000000000000000000000000000000000000000000000000000000000030003000000000000000000000000000000000000000000000000000000000000040003000000000000000000000000000000000000000000000000000000000000050003000000000000000000000000000000 - beginning of accept_channel
		// 030121 - inbound read from peer id 1 of len 33
		// 0000000000000000000000000000000000 01000000000000000000000000000000 - rest of accept_channel and mac
		//
		// 0a - create the funding transaction (client should send funding_created now)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0062 01000000000000000000000000000000 - message header indicating message length 98
		// 030172 - inbound read from peer id 1 of len 114
		// 0023 3f00000000000000000000000000000000000000000000000000000000000000f6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 01000000000000000000000000000000 - funding_signed message and mac
		//
		// 0b - broadcast funding transaction
		// - by now client should have sent a funding_locked (CHECK 4: SendFundingLocked to 03020000 for chan 3f000000)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0043 01000000000000000000000000000000 - message header indicating message length 67
		// 030153 - inbound read from peer id 1 of len 83
		// 0024 3f00000000000000000000000000000000000000000000000000000000000000 030100777777777777777777777777777777777777777777777777777777777777 01000000000000000000000000000000 - funding_locked and mac
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
		// 00fd - A feerate request (returning min feerate, which our open_channel also uses)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0064 03000000000000000000000000000000 - message header indicating message length 100
		// 030074 - inbound read from peer id 0 of len 116
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 27000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 0000 03000000000000000000000000000000 - commitment_signed and mac
		// - client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6: types 133 and 132 to peer 03000000)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0100000000000000000000000000000000000000000000000000000000000000 031111111111111111111111111111111111111111111111111111111111111111 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 1 update_add_htlc and commitment_signed (CHECK 7: SendHTLCs event for node 03020000 with 1 HTLCs for channel 3f000000)
		//
		// - we respond with commitment_signed then revoke_and_ack (a weird, but valid, order)
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3f00000000000000000000000000000000000000000000000000000000000000 f7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3f00000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000 032222222222222222222222222222222222222222222222222222222222222222 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 004a 01000000000000000000000000000000 - message header indicating message length 74
		// 03015a - inbound read from peer id 1 of len 90
		// 0082 3f00000000000000000000000000000000000000000000000000000000000000 0000000000000000 ff00888888888888888888888888888888888888888888888888888888888888 01000000000000000000000000000000 - update_fulfill_htlc and mac
		// - client should immediately claim the pending HTLC from peer 0 (CHECK 8: SendFulfillHTLCs for node 03000000 with preimage ff00888888 for channel 3d000000)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3f00000000000000000000000000000000000000000000000000000000000000 fb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3f00000000000000000000000000000000000000000000000000000000000000 0100777777777777777777777777777777777777777777777777777777777777 033333333333333333333333333333333333333333333333333333333333333333 01000000000000000000000000000000 - revoke_and_ack and mac
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
		// 00fd - A feerate request (returning min feerate, which our open_channel also uses)
		//
		// - now respond to the update_fulfill_htlc+commitment_signed messages the client sent to peer 0
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000 034444444444444444444444444444444444444444444444444444444444444444 03000000000000000000000000000000 - revoke_and_ack and mac
		// - client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6 duplicates)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0064 03000000000000000000000000000000 - message header indicating message length 100
		// 030074 - inbound read from peer id 0 of len 116
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 d4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001 0000 03000000000000000000000000000000 - commitment_signed and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 1111111111111111111111111111111111111111111111111111111111111111035555555555555555555555555555555555555555555555555555555555555555 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 1 update_add_htlc and commitment_signed (CHECK 7 duplicate)
		// - we respond with revoke_and_ack, then commitment_signed, then update_fail_htlc
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3f00000000000000000000000000000000000000000000000000000000000000 f5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3f00000000000000000000000000000000000000000000000000000000000000 2222222222222222222222222222222222222222222222222222222222222222 036666666666666666666666666666666666666666666666666666666666666666 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 002c 01000000000000000000000000000000 - message header indicating message length 44
		// 03013c - inbound read from peer id 1 of len 60
		// 0083 3f00000000000000000000000000000000000000000000000000000000000000 0000000000000001 0000 01000000000000000000000000000000 - update_fail_htlc and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3f00000000000000000000000000000000000000000000000000000000000000 f2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// - TODO: update_fail_htlc from peer 1

		let logger = Arc::new(TrackingLogger { lines: Mutex::new(HashMap::new()) });
		super::do_test(&::hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000001000300000000000000000000000000000000000000000000000000000000000000000300320003000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000030012000603000000000000000000000000000000030016001000000000030000000000000000000000000000000300120141030000000000000000000000000000000300ff00207500000000000000000000000000000000000000000000000000000000000000ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679000000000000c35000000000000000000000000000000222ffffffffffffffff00000000000002220000000000000000000000fd000601e3030000000000000000000000000000000000000000000000000000000000000001030000000000000000000000000000000000000000000000000000000000000002030000000000000000000000000000000000000000000000000000000000000003030000000000000000000000000000000000000000000000000000000000000004030300520000000000000000000000000000000000000000000000000000000000000005030100000000000000000000000000000000000000000000000000000000000000010300000000000000000000000000000000fd00fd00fd0300120084030000000000000000000000000000000300940022ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb1819096793d00000000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001030000000000000000000000000000000c005e020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0150c3000000000000220020ae00000000000000000000000000000000000000000000000000000000000000000000000c00000c00000c00000c00000c00000c00000c00000c00000c00000c00000c00000c000003001200430300000000000000000000000000000003005300243d000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001030132000300000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003014200030200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000300000000000000000000000000000003011200060100000000000000000000000000000003011600100000000001000000000000000000000000000000050103020000000000000000000000000000000000000000000000000000000000000000c3500003e800fd00fd00fd0301120110010000000000000000000000000000000301ff00210200000000000000020000000000000002000000000000000200000000000000000000000000001a00000000004c4b4000000000000003e800000000000003e80000000203f00005030000000000000000000000000000000000000000000000000000000000000100030000000000000000000000000000000000000000000000000000000000000200030000000000000000000000000000000000000000000000000000000000000300030000000000000000000000000000000000000000000000000000000000000400030000000000000000000000000000000000000000000000000000000000000500030000000000000000000000000000000301210000000000000000000000000000000000010000000000000000000000000000000a03011200620100000000000000000000000000000003017200233f00000000000000000000000000000000000000000000000000000000000000f6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100010000000000000000000000000000000b03011200430100000000000000000000000000000003015300243f000000000000000000000000000000000000000000000000000000000000000301007777777777777777777777777777777777777777777777777777777777770100000000000000000000000000000003001205ac030000000000000000000000000000000300ff00803d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e80ff0000000000000000000000000000000000000000000000000000000000000000000121000300000000000000000000000000000000000000000000000000000000000005550000000e000001000000000000000003e8000000010000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000fd03001200640300000000000000000000000000000003007400843d000000000000000000000000000000000000000000000000000000000000002700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000300000000000000000000000000000003001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000031111111111111111111111111111111111111111111111111111111111111111030000000000000000000000000000000703011200640100000000000000000000000000000003017400843f00000000000000000000000000000000000000000000000000000000000000f700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003222222222222222222222222222222222222222222222222222222222222222201000000000000000000000000000000030112004a0100000000000000000000000000000003015a00823f000000000000000000000000000000000000000000000000000000000000000000000000000000ff008888888888888888888888888888888888888888888888888888888888880100000000000000000000000000000003011200640100000000000000000000000000000003017400843f00000000000000000000000000000000000000000000000000000000000000fb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853f0000000000000000000000000000000000000000000000000000000000000001007777777777777777777777777777777777777777777777777777777777770333333333333333333333333333333333333333333333333333333333333333330100000000000000000000000000000003001205ac030000000000000000000000000000000300ff00803d0000000000000000000000000000000000000000000000000000000000000000000000000000010000000000003e80ff0000000000000000000000000000000000000000000000000000000000000000000121000300000000000000000000000000000000000000000000000000000000000005550000000e000001000000000000000003e8000000010000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000fd03001200630300000000000000000000000000000003007300853d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000344444444444444444444444444444444444444444444444444444444444444440300000000000000000000000000000003001200640300000000000000000000000000000003007400843d00000000000000000000000000000000000000000000000000000000000000d400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000300000000000000000000000000000003001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111035555555555555555555555555555555555555555555555555555555555555555030000000000000000000000000000000703011200640100000000000000000000000000000003017400843f00000000000000000000000000000000000000000000000000000000000000f500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853f00000000000000000000000000000000000000000000000000000000000000222222222222222222222222222222222222222222222222222222222222222203666666666666666666666666666666666666666666666666666666666666666601000000000000000000000000000000030112002c0100000000000000000000000000000003013c00833f00000000000000000000000000000000000000000000000000000000000000000000000000000100000100000000000000000000000000000003011200640100000000000000000000000000000003017400843f00000000000000000000000000000000000000000000000000000000000000f2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000000000000000000000000000").unwrap(), &(Arc::clone(&logger) as Arc<Logger>));

		let log_entries = logger.lines.lock().unwrap();
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Encoding and sending message of type 33 to 030000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 1
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Encoding and sending message of type 35 to 030000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 2
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendFundingLocked event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 3
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendFundingLocked event in peer_handler for node 030200000000000000000000000000000000000000000000000000000000000000 for channel 3f00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 4
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Encoding and sending message of type 133 to 030000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&2)); // 5
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Encoding and sending message of type 132 to 030000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&2)); // 6
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030200000000000000000000000000000000000000000000000000000000000000 with 1 adds, 0 fulfills, 0 fails for channel 3f00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&2)); // 7
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000000 with 0 adds, 1 fulfills, 0 fails for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 8
	}
}
