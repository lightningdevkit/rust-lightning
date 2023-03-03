// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Test that no series of bytes received over the wire/connections created/payments sent can
//! result in a crash. We do this by standing up a node and then reading bytes from input to denote
//! actions such as creating new inbound/outbound connections, bytes to be read from a connection,
//! or payments to send/ways to handle events generated.
//! This test has been very useful, though due to its complexity good starting inputs are critical.

use bitcoin::TxMerkleNode;
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::locktime::PackedLockTime;
use bitcoin::consensus::encode::deserialize;
use bitcoin::network::constants::Network;

use bitcoin::hashes::Hash as TraitImport;
use bitcoin::hashes::HashEngine as TraitImportEngine;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hash_types::{Txid, BlockHash, WPubkeyHash};

use lightning::chain;
use lightning::chain::{BestBlock, ChannelMonitorUpdateStatus, Confirm, Listen};
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::chainmonitor;
use lightning::chain::transaction::OutPoint;
use lightning::chain::keysinterface::{InMemorySigner, Recipient, KeyMaterial, EntropySource, NodeSigner, SignerProvider};
use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::ln::channelmanager::{ChainParameters, ChannelDetails, ChannelManager, PaymentId};
use lightning::ln::peer_handler::{MessageHandler,PeerManager,SocketDescriptor,IgnoringMessageHandler};
use lightning::ln::msgs::{self, DecodeError};
use lightning::ln::script::ShutdownScript;
use lightning::routing::gossip::{P2PGossipSync, NetworkGraph};
use lightning::routing::utxo::UtxoLookup;
use lightning::routing::router::{find_route, InFlightHtlcs, PaymentParameters, Route, RouteParameters, Router};
use lightning::routing::scoring::FixedPenaltyScorer;
use lightning::util::config::UserConfig;
use lightning::util::errors::APIError;
use lightning::util::events::Event;
use lightning::util::enforcing_trait_impls::{EnforcingSigner, EnforcementState};
use lightning::util::logger::Logger;
use lightning::util::ser::{Readable, Writeable};

use crate::utils::test_logger;
use crate::utils::test_persister::TestPersister;

use bitcoin::secp256k1::{Message, PublicKey, SecretKey, Scalar, Secp256k1};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};

use std::cell::RefCell;
use hashbrown::{HashMap, hash_map};
use std::convert::TryInto;
use std::cmp;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64,AtomicUsize,Ordering};
use bitcoin::bech32::u5;

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
	fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u32 {
		//TODO: We should actually be testing at least much more than 64k...
		match self.input.get_slice(2) {
			Some(slice) => cmp::max(slice_to_be16(slice) as u32, 253),
			None => 253
		}
	}
}

struct FuzzRouter {}

impl Router for FuzzRouter {
	fn find_route(
		&self, _payer: &PublicKey, _params: &RouteParameters, _first_hops: Option<&[&ChannelDetails]>,
		_inflight_htlcs: &InFlightHtlcs
	) -> Result<Route, msgs::LightningError> {
		Err(msgs::LightningError {
			err: String::from("Not implemented"),
			action: msgs::ErrorAction::IgnoreError
		})
	}
}

struct TestBroadcaster {
	txn_broadcasted: Mutex<Vec<Transaction>>,
}
impl BroadcasterInterface for TestBroadcaster {
	fn broadcast_transaction(&self, tx: &Transaction) {
		self.txn_broadcasted.lock().unwrap().push(tx.clone());
	}
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
impl<'a> std::hash::Hash for Peer<'a> {
	fn hash<H : std::hash::Hasher>(&self, h: &mut H) {
		self.id.hash(h)
	}
}

type ChannelMan<'a> = ChannelManager<
	Arc<chainmonitor::ChainMonitor<EnforcingSigner, Arc<dyn chain::Filter>, Arc<TestBroadcaster>, Arc<FuzzEstimator>, Arc<dyn Logger>, Arc<TestPersister>>>,
	Arc<TestBroadcaster>, Arc<KeyProvider>, Arc<KeyProvider>, Arc<KeyProvider>, Arc<FuzzEstimator>, &'a FuzzRouter, Arc<dyn Logger>>;
type PeerMan<'a> = PeerManager<Peer<'a>, Arc<ChannelMan<'a>>, Arc<P2PGossipSync<Arc<NetworkGraph<Arc<dyn Logger>>>, Arc<dyn UtxoLookup>, Arc<dyn Logger>>>, IgnoringMessageHandler, Arc<dyn Logger>, IgnoringMessageHandler, Arc<KeyProvider>>;

struct MoneyLossDetector<'a> {
	manager: Arc<ChannelMan<'a>>,
	monitor: Arc<chainmonitor::ChainMonitor<EnforcingSigner, Arc<dyn chain::Filter>, Arc<TestBroadcaster>, Arc<FuzzEstimator>, Arc<dyn Logger>, Arc<TestPersister>>>,
	handler: PeerMan<'a>,

	peers: &'a RefCell<[bool; 256]>,
	funding_txn: Vec<Transaction>,
	txids_confirmed: HashMap<Txid, usize>,
	header_hashes: Vec<(BlockHash, u32)>,
	height: usize,
	max_height: usize,
	blocks_connected: u32,
}
impl<'a> MoneyLossDetector<'a> {
	pub fn new(peers: &'a RefCell<[bool; 256]>,
	           manager: Arc<ChannelMan<'a>>,
	           monitor: Arc<chainmonitor::ChainMonitor<EnforcingSigner, Arc<dyn chain::Filter>, Arc<TestBroadcaster>, Arc<FuzzEstimator>, Arc<dyn Logger>, Arc<TestPersister>>>,
	           handler: PeerMan<'a>) -> Self {
		MoneyLossDetector {
			manager,
			monitor,
			handler,

			peers,
			funding_txn: Vec::new(),
			txids_confirmed: HashMap::new(),
			header_hashes: vec![(genesis_block(Network::Bitcoin).block_hash(), 0)],
			height: 0,
			max_height: 0,
			blocks_connected: 0,
		}
	}

	fn connect_block(&mut self, all_txn: &[Transaction]) {
		let mut txdata = Vec::with_capacity(all_txn.len());
		for (idx, tx) in all_txn.iter().enumerate() {
			let txid = tx.txid();
			match self.txids_confirmed.entry(txid) {
				hash_map::Entry::Vacant(e) => {
					e.insert(self.height);
					txdata.push((idx + 1, tx));
				},
				_ => {},
			}
		}

		self.blocks_connected += 1;
		let header = BlockHeader { version: 0x20000000, prev_blockhash: self.header_hashes[self.height].0, merkle_root: TxMerkleNode::all_zeros(), time: self.blocks_connected, bits: 42, nonce: 42 };
		self.height += 1;
		self.manager.transactions_confirmed(&header, &txdata, self.height as u32);
		self.manager.best_block_updated(&header, self.height as u32);
		(*self.monitor).transactions_confirmed(&header, &txdata, self.height as u32);
		(*self.monitor).best_block_updated(&header, self.height as u32);
		if self.header_hashes.len() > self.height {
			self.header_hashes[self.height] = (header.block_hash(), self.blocks_connected);
		} else {
			assert_eq!(self.header_hashes.len(), self.height);
			self.header_hashes.push((header.block_hash(), self.blocks_connected));
		}
		self.max_height = cmp::max(self.height, self.max_height);
	}

	fn disconnect_block(&mut self) {
		if self.height > 0 && (self.max_height < 6 || self.height >= self.max_height - 6) {
			let header = BlockHeader { version: 0x20000000, prev_blockhash: self.header_hashes[self.height - 1].0, merkle_root: TxMerkleNode::all_zeros(), time: self.header_hashes[self.height].1, bits: 42, nonce: 42 };
			self.manager.block_disconnected(&header, self.height as u32);
			self.monitor.block_disconnected(&header, self.height as u32);
			self.height -= 1;
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
					self.handler.socket_disconnected(&Peer{id: idx as u8, peers_connected: &self.peers});
				}
			}

			// Force all channels onto the chain (and time out claim txn)
			self.manager.force_close_all_channels_broadcasting_latest_txn();
		}
	}
}

struct KeyProvider {
	node_secret: SecretKey,
	inbound_payment_key: KeyMaterial,
	counter: AtomicU64,
	signer_state: RefCell<HashMap<u8, (bool, Arc<Mutex<EnforcementState>>)>>
}

impl EntropySource for KeyProvider {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			(ctr >> 8*7) as u8, (ctr >> 8*6) as u8, (ctr >> 8*5) as u8, (ctr >> 8*4) as u8, (ctr >> 8*3) as u8, (ctr >> 8*2) as u8, (ctr >> 8*1) as u8, 14, (ctr >> 8*0) as u8]
	}
}

impl NodeSigner for KeyProvider {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(())
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(())
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.inbound_payment_key.clone()
	}

	fn sign_invoice(&self, _hrp_bytes: &[u8], _invoice_data: &[u5], _recipient: Recipient) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn sign_gossip_message(&self, msg: lightning::ln::msgs::UnsignedGossipMessage) -> Result<Signature, ()> {
		let msg_hash = Message::from_slice(&Sha256dHash::hash(&msg.encode()[..])[..]).map_err(|_| ())?;
		let secp_ctx = Secp256k1::signing_only();
		Ok(secp_ctx.sign_ecdsa(&msg_hash, &self.node_secret))
	}
}

impl SignerProvider for KeyProvider {
	type Signer = EnforcingSigner;

	fn generate_channel_keys_id(&self, inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32] {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed) as u8;
		self.signer_state.borrow_mut().insert(ctr, (inbound, Arc::new(Mutex::new(EnforcementState::new()))));
		[ctr; 32]
	}

	fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> Self::Signer {
		let secp_ctx = Secp256k1::signing_only();
		let ctr = channel_keys_id[0];
		let (inbound, state) = self.signer_state.borrow().get(&ctr).unwrap().clone();
		EnforcingSigner::new_with_revoked(if inbound {
			InMemorySigner::new(
				&secp_ctx,
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, ctr]).unwrap(),
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, ctr]).unwrap(),
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, ctr]).unwrap(),
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, ctr]).unwrap(),
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, ctr]).unwrap(),
				[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, ctr],
				channel_value_satoshis,
				channel_keys_id,
			)
		} else {
			InMemorySigner::new(
				&secp_ctx,
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, ctr]).unwrap(),
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, ctr]).unwrap(),
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, ctr]).unwrap(),
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, ctr]).unwrap(),
				SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, ctr]).unwrap(),
				[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, ctr],
				channel_value_satoshis,
				channel_keys_id,
			)
		}, state, false)
	}

	fn read_chan_signer(&self, mut data: &[u8]) -> Result<EnforcingSigner, DecodeError> {
		let inner: InMemorySigner = Readable::read(&mut data)?;
		let state = Arc::new(Mutex::new(EnforcementState::new()));

		Ok(EnforcingSigner::new_with_revoked(
			inner,
			state,
			false
		))
	}

	fn get_destination_script(&self) -> Script {
		let secp_ctx = Secp256k1::signing_only();
		let channel_monitor_claim_key = SecretKey::from_slice(&hex::decode("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()[..]).unwrap();
		let our_channel_monitor_claim_key_hash = WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize());
		Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0).push_slice(&our_channel_monitor_claim_key_hash[..]).into_script()
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		let secp_ctx = Secp256k1::signing_only();
		let secret_key = SecretKey::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
		let pubkey_hash = WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &secret_key).serialize());
		ShutdownScript::new_p2wpkh(&pubkey_hash)
	}
}

#[inline]
pub fn do_test(data: &[u8], logger: &Arc<dyn Logger>) {
	let input = Arc::new(InputData {
		data: data.to_vec(),
		read_pos: AtomicUsize::new(0),
	});
	let fee_est = Arc::new(FuzzEstimator {
		input: input.clone(),
	});
	let router = FuzzRouter {};

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

	let inbound_payment_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42];

	let broadcast = Arc::new(TestBroadcaster{ txn_broadcasted: Mutex::new(Vec::new()) });
	let monitor = Arc::new(chainmonitor::ChainMonitor::new(None, broadcast.clone(), Arc::clone(&logger), fee_est.clone(),
		Arc::new(TestPersister { update_ret: Mutex::new(ChannelMonitorUpdateStatus::Completed) })));

	let keys_manager = Arc::new(KeyProvider {
		node_secret: our_network_key.clone(),
		inbound_payment_key: KeyMaterial(inbound_payment_key.try_into().unwrap()),
		counter: AtomicU64::new(0),
		signer_state: RefCell::new(HashMap::new())
	});
	let mut config = UserConfig::default();
	config.channel_config.forwarding_fee_proportional_millionths =  slice_to_be32(get_slice!(4));
	config.channel_handshake_config.announced_channel = get_slice!(1)[0] != 0;
	let network = Network::Bitcoin;
	let params = ChainParameters {
		network,
		best_block: BestBlock::from_network(network),
	};
	let channelmanager = Arc::new(ChannelManager::new(fee_est.clone(), monitor.clone(), broadcast.clone(), &router, Arc::clone(&logger), keys_manager.clone(), keys_manager.clone(), keys_manager.clone(), config, params));
	// Adding new calls to `EntropySource::get_secure_random_bytes` during startup can change all the
	// keys subsequently generated in this test. Rather than regenerating all the messages manually,
	// it's easier to just increment the counter here so the keys don't change.
	keys_manager.counter.fetch_sub(3, Ordering::AcqRel);
	let our_id = &keys_manager.get_node_id(Recipient::Node).unwrap();
	let network_graph = Arc::new(NetworkGraph::new(network, Arc::clone(&logger)));
	let gossip_sync = Arc::new(P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger)));
	let scorer = FixedPenaltyScorer::with_penalty(0);

	let peers = RefCell::new([false; 256]);
	let mut loss_detector = MoneyLossDetector::new(&peers, channelmanager.clone(), monitor.clone(), PeerManager::new(MessageHandler {
		chan_handler: channelmanager.clone(),
		route_handler: gossip_sync.clone(),
		onion_message_handler: IgnoringMessageHandler {},
	}, 0, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0], Arc::clone(&logger), IgnoringMessageHandler{}, keys_manager.clone()));

	let mut should_forward = false;
	let mut payments_received: Vec<PaymentHash> = Vec::new();
	let mut payments_sent = 0;
	let mut pending_funding_generation: Vec<([u8; 32], PublicKey, u64, Script)> = Vec::new();
	let mut pending_funding_signatures = HashMap::new();

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
				loss_detector.handler.new_outbound_connection(get_pubkey!(), Peer{id: (new_id - 1) as u8, peers_connected: &peers}, None).unwrap();
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
				loss_detector.handler.new_inbound_connection(Peer{id: (new_id - 1) as u8, peers_connected: &peers}, None).unwrap();
				peers.borrow_mut()[new_id - 1] = true;
			},
			2 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] { return; }
				loss_detector.handler.socket_disconnected(&Peer{id: peer_id, peers_connected: &peers});
				peers.borrow_mut()[peer_id as usize] = false;
			},
			3 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] { return; }
				match loss_detector.handler.read_event(&mut Peer{id: peer_id, peers_connected: &peers}, get_slice!(get_slice!(1)[0])) {
					Ok(res) => assert!(!res),
					Err(_) => { peers.borrow_mut()[peer_id as usize] = false; }
				}
			},
			4 => {
				let final_value_msat = slice_to_be24(get_slice!(3)) as u64;
				let payment_params = PaymentParameters::from_node_id(get_pubkey!(), 42);
				let params = RouteParameters {
					payment_params,
					final_value_msat,
				};
				let random_seed_bytes: [u8; 32] = keys_manager.get_secure_random_bytes();
				let route = match find_route(&our_id, &params, &network_graph, None, Arc::clone(&logger), &scorer, &random_seed_bytes) {
					Ok(route) => route,
					Err(_) => return,
				};
				let mut payment_hash = PaymentHash([0; 32]);
				payment_hash.0[0..8].copy_from_slice(&be64_to_array(payments_sent));
				let mut sha = Sha256::engine();
				sha.input(&payment_hash.0[..]);
				payment_hash.0 = Sha256::from_engine(sha).into_inner();
				payments_sent += 1;
				match channelmanager.send_payment(&route, payment_hash, &None, PaymentId(payment_hash.0)) {
					Ok(_) => {},
					Err(_) => return,
				}
			},
			15 => {
				let final_value_msat = slice_to_be24(get_slice!(3)) as u64;
				let payment_params = PaymentParameters::from_node_id(get_pubkey!(), 42);
				let params = RouteParameters {
					payment_params,
					final_value_msat,
				};
				let random_seed_bytes: [u8; 32] = keys_manager.get_secure_random_bytes();
				let mut route = match find_route(&our_id, &params, &network_graph, None, Arc::clone(&logger), &scorer, &random_seed_bytes) {
					Ok(route) => route,
					Err(_) => return,
				};
				route.paths.push(route.paths[0].clone());
				let mut payment_hash = PaymentHash([0; 32]);
				payment_hash.0[0..8].copy_from_slice(&be64_to_array(payments_sent));
				let mut sha = Sha256::engine();
				sha.input(&payment_hash.0[..]);
				payment_hash.0 = Sha256::from_engine(sha).into_inner();
				payments_sent += 1;
				let mut payment_secret = PaymentSecret([0; 32]);
				payment_secret.0[0..8].copy_from_slice(&be64_to_array(payments_sent));
				payments_sent += 1;
				match channelmanager.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)) {
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
				if channelmanager.create_channel(their_key, chan_value, push_msat_value, 0, None).is_err() { return; }
			},
			6 => {
				let mut channels = channelmanager.list_channels();
				let channel_id = get_slice!(1)[0] as usize;
				if channel_id >= channels.len() { return; }
				channels.sort_by(|a, b| { a.channel_id.cmp(&b.channel_id) });
				if channelmanager.close_channel(&channels[channel_id].channel_id, &channels[channel_id].counterparty.node_id).is_err() { return; }
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
			16 => {
				let payment_preimage = PaymentPreimage(keys_manager.get_secure_random_bytes());
				let mut sha = Sha256::engine();
				sha.input(&payment_preimage.0[..]);
				let payment_hash = PaymentHash(Sha256::from_engine(sha).into_inner());
				// Note that this may fail - our hashes may collide and we'll end up trying to
				// double-register the same payment_hash.
				let _ = channelmanager.create_inbound_payment_for_hash(payment_hash, None, 1, None);
			},
			9 => {
				for payment in payments_received.drain(..) {
					channelmanager.fail_htlc_backwards(&payment);
				}
			},
			10 => {
				'outer_loop: for funding_generation in pending_funding_generation.drain(..) {
					let mut tx = Transaction { version: 0, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: vec![TxOut {
							value: funding_generation.2, script_pubkey: funding_generation.3,
						}] };
					let funding_output = 'search_loop: loop {
						let funding_txid = tx.txid();
						if let None = loss_detector.txids_confirmed.get(&funding_txid) {
							let outpoint = OutPoint { txid: funding_txid, index: 0 };
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
					if let Err(e) = channelmanager.funding_transaction_generated(&funding_generation.0, &funding_generation.1, tx.clone()) {
						// It's possible the channel has been closed in the mean time, but any other
						// failure may be a bug.
						if let APIError::ChannelUnavailable { .. } = e { } else { panic!(); }
					}
					pending_funding_signatures.insert(funding_output, tx);
				}
			},
			11 => {
				let mut txn = broadcast.txn_broadcasted.lock().unwrap().split_off(0);
				if !txn.is_empty() {
					loss_detector.connect_block(&txn[..]);
					for _ in 2..100 {
						loss_detector.connect_block(&[]);
					}
				}
				for tx in txn.drain(..) {
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
						let mut output_val = 0;
						for out in tx.output.iter() {
							if out.value > 21_000_000_0000_0000 { return; }
							output_val += out.value;
							if output_val > 21_000_000_0000_0000 { return; }
						}
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
				channelmanager.force_close_broadcasting_latest_txn(&channels[channel_id].channel_id, &channels[channel_id].counterparty.node_id).unwrap();
			},
			// 15 is above
			_ => return,
		}
		loss_detector.handler.process_events();
		for event in loss_detector.manager.get_and_clear_pending_events() {
			match event {
				Event::FundingGenerationReady { temporary_channel_id, counterparty_node_id, channel_value_satoshis, output_script, .. } => {
					pending_funding_generation.push((temporary_channel_id, counterparty_node_id, channel_value_satoshis, output_script));
				},
				Event::PaymentClaimable { payment_hash, .. } => {
					//TODO: enhance by fetching random amounts from fuzz input?
					payments_received.push(payment_hash);
				},
				Event::PendingHTLCsForwardable {..} => {
					should_forward = true;
				},
				_ => {},
			}
		}
	}
}

pub fn full_stack_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new("".to_owned(), out));
	do_test(data, &logger);
}

#[no_mangle]
pub extern "C" fn full_stack_run(data: *const u8, datalen: usize) {
	let logger: Arc<dyn Logger> = Arc::new(test_logger::TestLogger::new("".to_owned(), test_logger::DevNull {}));
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, &logger);
}

#[cfg(test)]
mod tests {
	use lightning::util::logger::{Logger, Record};
	use std::collections::HashMap;
	use std::sync::{Arc, Mutex};

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

		// Writing new code generating transactions and see a new failure ? Don't forget to add input for the FuzzEstimator !

		// 0100000000000000000000000000000000000000000000000000000000000000 - our network key
		// 00000000 - fee_proportional_millionths
		// 01 - announce_channels_publicly
		//
		// 00 - new outbound connection with id 0
		// 030000000000000000000000000000000000000000000000000000000000000002 - peer's pubkey
		// 030032 - inbound read from peer id 0 of len 50
		// 00 030000000000000000000000000000000000000000000000000000000000000002 03000000000000000000000000000000 - noise act two (0||pubkey||mac)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 000a 03000000000000000000000000000000 - message header indicating message length 10
		// 03001a - inbound read from peer id 0 of len 26
		// 0010 00022000 00022000 03000000000000000000000000000000 - init message (type 16) with static_remotekey (0x2000) and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0141 03000000000000000000000000000000 - message header indicating message length 321
		// 0300fe - inbound read from peer id 0 of len 254
		// 0020 7500000000000000000000000000000000000000000000000000000000000000 ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679 000000000000c350 0000000000000000 0000000000000162 ffffffffffffffff 0000000000000222 0000000000000000 000000fd 0006 01e3 030000000000000000000000000000000000000000000000000000000000000001 030000000000000000000000000000000000000000000000000000000000000002 030000000000000000000000000000000000000000000000000000000000000003 030000000000000000000000000000000000000000000000000000000000000004 - beginning of open_channel message
		// 030053 - inbound read from peer id 0 of len 83
		// 030000000000000000000000000000000000000000000000000000000000000005 020900000000000000000000000000000000000000000000000000000000000000 01 03000000000000000000000000000000 - rest of open_channel and mac
		//
		// 00fd00fd - Two feerate requests (all returning min feerate, which our open_channel also uses) (gonna be ingested by FuzzEstimator)
		// - client should now respond with accept_channel (CHECK 1: type 33 to peer 03000000)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0084 03000000000000000000000000000000 - message header indicating message length 132
		// 030094 - inbound read from peer id 0 of len 148
		// 0022 ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679 3d00000000000000000000000000000000000000000000000000000000000000 0000 00000000000000000000000000000000000000000000000000000000000000210100000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - funding_created and mac
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
		// - by now client should have sent a channel_ready (CHECK 3: SendChannelReady to 03000000 for chan 3d000000)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0043 03000000000000000000000000000000 - message header indicating message length 67
		// 030053 - inbound read from peer id 0 of len 83
		// 0024 3d00000000000000000000000000000000000000000000000000000000000000 020800000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - channel_ready and mac
		//
		// 01 - new inbound connection with id 1
		// 030132 - inbound read from peer id 1 of len 50
		// 0003000000000000000000000000000000000000000000000000000000000000000703000000000000000000000000000000 - inbound noise act 1
		// 030142 - inbound read from peer id 1 of len 66
		// 000302000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003000000000000000000000000000000 - inbound noise act 3
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 000a 01000000000000000000000000000000 - message header indicating message length 10
		// 03011a - inbound read from peer id 1 of len 26
		// 0010 00022000 00022000 01000000000000000000000000000000 - init message (type 16) with static_remotekey (0x2000) and mac
		//
		// 05 01 030200000000000000000000000000000000000000000000000000000000000000 00c350 0003e8 - create outbound channel to peer 1 for 50k sat
		// 00fd - One feerate requests (all returning min feerate) (gonna be ingested by FuzzEstimator)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0110 01000000000000000000000000000000 - message header indicating message length 272
		// 0301ff - inbound read from peer id 1 of len 255
		// 0021 0000000000000000000000000000000000000000000000000000000000000e05 0000000000000162 00000000004c4b40 00000000000003e8 00000000000003e8 00000002 03f0 0005 030000000000000000000000000000000000000000000000000000000000000100 030000000000000000000000000000000000000000000000000000000000000200 030000000000000000000000000000000000000000000000000000000000000300 030000000000000000000000000000000000000000000000000000000000000400 030000000000000000000000000000000000000000000000000000000000000500 02660000000000000000000000000000 - beginning of accept_channel
		// 030121 - inbound read from peer id 1 of len 33
		// 0000000000000000000000000000000000 01000000000000000000000000000000 - rest of accept_channel and mac
		//
		// 0a - create the funding transaction (client should send funding_created now)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0062 01000000000000000000000000000000 - message header indicating message length 98
		// 030172 - inbound read from peer id 1 of len 114
		// 0023 3a00000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000007c0001000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - funding_signed message and mac
		//
		// 0b - broadcast funding transaction
		// - by now client should have sent a channel_ready (CHECK 4: SendChannelReady to 03020000 for chan 3f000000)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0043 01000000000000000000000000000000 - message header indicating message length 67
		// 030153 - inbound read from peer id 1 of len 83
		// 0024 3a00000000000000000000000000000000000000000000000000000000000000 026700000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - channel_ready and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 05ac 03000000000000000000000000000000 - message header indicating message length 1452
		// 0300ff - inbound read from peer id 0 of len 255
		// 0080 3d00000000000000000000000000000000000000000000000000000000000000 0000000000000000 0000000000003e80 ff00000000000000000000000000000000000000000000000000000000000000 000003f0 00 030000000000000000000000000000000000000000000000000000000000000555 11 020203e8 0401a0 060800000e0000010000 0a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - beginning of update_add_htlc from 0 to 1 via client
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300c1 - inbound read from peer id 0 of len 193
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff ab00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - end of update_add_htlc from 0 to 1 via client and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0064 03000000000000000000000000000000 - message header indicating message length 100
		// 030074 - inbound read from peer id 0 of len 116
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000300100000000000000000000000000000000000000000000000000000000000000 0000 03000000000000000000000000000000 - commitment_signed and mac
		// - client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6: types 133 and 132 to peer 03000000)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0900000000000000000000000000000000000000000000000000000000000000 020b00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 1 update_add_htlc and commitment_signed (CHECK 7: SendHTLCs event for node 03020000 with 1 HTLCs for channel 3f000000)
		//
		// - we respond with commitment_signed then revoke_and_ack (a weird, but valid, order)
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3a00000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000006a0001000000000000000000000000000000000000000000000000000000000000 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3a00000000000000000000000000000000000000000000000000000000000000 6600000000000000000000000000000000000000000000000000000000000000 026400000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 004a 01000000000000000000000000000000 - message header indicating message length 74
		// 03015a - inbound read from peer id 1 of len 90
		// 0082 3a00000000000000000000000000000000000000000000000000000000000000 0000000000000000 ff00888888888888888888888888888888888888888888888888888888888888 01000000000000000000000000000000 - update_fulfill_htlc and mac
		// - client should immediately claim the pending HTLC from peer 0 (CHECK 8: SendFulfillHTLCs for node 03000000 with preimage ff00888888 for channel 3d000000)
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3a00000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000100001000000000000000000000000000000000000000000000000000000000000 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3a00000000000000000000000000000000000000000000000000000000000000 6700000000000000000000000000000000000000000000000000000000000000 026500000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// - before responding to the commitment_signed generated above, send a new HTLC
		// 030012 - inbound read from peer id 0 of len 18
		// 05ac 03000000000000000000000000000000 - message header indicating message length 1452
		// 0300ff - inbound read from peer id 0 of len 255
		// 0080 3d00000000000000000000000000000000000000000000000000000000000000 0000000000000001 0000000000003e80 ff00000000000000000000000000000000000000000000000000000000000000 000003f0 00 030000000000000000000000000000000000000000000000000000000000000555 11 020203e8 0401a0 060800000e0000010000 0a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - beginning of update_add_htlc from 0 to 1 via client
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300c1 - inbound read from peer id 0 of len 193
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff ab00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - end of update_add_htlc from 0 to 1 via client and mac
		//
		// - now respond to the update_fulfill_htlc+commitment_signed messages the client sent to peer 0
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0800000000000000000000000000000000000000000000000000000000000000 020a00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		// - client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6 duplicates)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0064 03000000000000000000000000000000 - message header indicating message length 100
		// 030074 - inbound read from peer id 0 of len 116
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000c30100000000000000000000000000000000000000000000000000000000000000 0000 03000000000000000000000000000000 - commitment_signed and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0b00000000000000000000000000000000000000000000000000000000000000 020d00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 1 update_add_htlc and commitment_signed (CHECK 7 duplicate)
		// - we respond with revoke_and_ack, then commitment_signed, then update_fail_htlc
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3a00000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000390001000000000000000000000000000000000000000000000000000000000000 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3a00000000000000000000000000000000000000000000000000000000000000 6400000000000000000000000000000000000000000000000000000000000000 027000000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 002c 01000000000000000000000000000000 - message header indicating message length 44
		// 03013c - inbound read from peer id 1 of len 60
		// 0083 3a00000000000000000000000000000000000000000000000000000000000000 0000000000000001 0000 01000000000000000000000000000000 - update_fail_htlc and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0064 01000000000000000000000000000000 - message header indicating message length 100
		// 030174 - inbound read from peer id 1 of len 116
		// 0084 3a00000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000390001000000000000000000000000000000000000000000000000000000000000 0000 01000000000000000000000000000000 - commitment_signed and mac
		//
		// 030112 - inbound read from peer id 1 of len 18
		// 0063 01000000000000000000000000000000 - message header indicating message length 99
		// 030173 - inbound read from peer id 1 of len 115
		// 0085 3a00000000000000000000000000000000000000000000000000000000000000 6500000000000000000000000000000000000000000000000000000000000000 027100000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 0 update_fail_htlc and commitment_signed (CHECK 9)
		// - now respond to the update_fail_htlc+commitment_signed messages the client sent to peer 0
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0a00000000000000000000000000000000000000000000000000000000000000 020c00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0064 03000000000000000000000000000000 - message header indicating message length 100
		// 030074 - inbound read from peer id 0 of len 116
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000320100000000000000000000000000000000000000000000000000000000000000 0000 03000000000000000000000000000000 - commitment_signed and mac
		// - client should now respond with revoke_and_ack (CHECK 5 duplicate)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 05ac 03000000000000000000000000000000 - message header indicating message length 1452
		// 0300ff - inbound read from peer id 0 of len 255
		// 0080 3d00000000000000000000000000000000000000000000000000000000000000 0000000000000002 00000000000b0838 ff00000000000000000000000000000000000000000000000000000000000000 000003f0 00 030000000000000000000000000000000000000000000000000000000000000555 12 02030927c0 0401a0 060800000e0000010000 0a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - beginning of update_add_htlc from 0 to 1 via client
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300ff - inbound read from peer id 0 of len 255
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
		// 0300c1 - inbound read from peer id 0 of len 193
		// ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 5300000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - end of update_add_htlc from 0 to 1 via client and mac
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 00a4 03000000000000000000000000000000 - message header indicating message length 164
		// 0300b4 - inbound read from peer id 0 of len 180
		// 0084 3d00000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000750100000000000000000000000000000000000000000000000000000000000000 0001 00000000000000000000000000000000000000000000000000000000000000670500000000000000000000000000000000000000000000000000000000000006 03000000000000000000000000000000 - commitment_signed and mac
		// - client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6 duplicates)
		//
		// 030012 - inbound read from peer id 0 of len 18
		// 0063 03000000000000000000000000000000 - message header indicating message length 99
		// 030073 - inbound read from peer id 0 of len 115
		// 0085 3d00000000000000000000000000000000000000000000000000000000000000 0d00000000000000000000000000000000000000000000000000000000000000 020f00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000 - revoke_and_ack and mac
		//
		// 07 - process the now-pending HTLC forward
		// - client now sends id 1 update_add_htlc and commitment_signed (CHECK 7 duplicate)
		//
		// 0c007d - connect a block with one transaction of len 125
		// 02000000013a000000000000000000000000000000000000000000000000000000000000000000000000000000800258020000000000002200204b0000000000000000000000000000000000000000000000000000000000000014c0000000000000160014280000000000000000000000000000000000000005000020 - the commitment transaction for channel 3f00000000000000000000000000000000000000000000000000000000000000
		//
		// 0c005e - connect a block with one transaction of len 94
		// 0200000001730000000000000000000000000000000000000000000000000000000000000000000000000000000001a701000000000000220020b20000000000000000000000000000000000000000000000000000000000000000000000 - the HTLC timeout transaction
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		// 0c0000 - connect a block with no transactions
		//
		// 07 - process the now-pending HTLC forward
		// - client now fails the HTLC backwards as it was unable to extract the payment preimage (CHECK 9 duplicate and CHECK 10)

		let logger = Arc::new(TrackingLogger { lines: Mutex::new(HashMap::new()) });
		super::do_test(&::hex::decode("01000000000000000000000000000000000000000000000000000000000000000000000001000300000000000000000000000000000000000000000000000000000000000000020300320003000000000000000000000000000000000000000000000000000000000000000203000000000000000000000000000000030012000a0300000000000000000000000000000003001a00100002200000022000030000000000000000000000000000000300120141030000000000000000000000000000000300fe00207500000000000000000000000000000000000000000000000000000000000000ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679000000000000c35000000000000000000000000000000162ffffffffffffffff00000000000002220000000000000000000000fd000601e3030000000000000000000000000000000000000000000000000000000000000001030000000000000000000000000000000000000000000000000000000000000002030000000000000000000000000000000000000000000000000000000000000003030000000000000000000000000000000000000000000000000000000000000004030053030000000000000000000000000000000000000000000000000000000000000005020900000000000000000000000000000000000000000000000000000000000000010300000000000000000000000000000000fd00fd0300120084030000000000000000000000000000000300940022ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb1819096793d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000210100000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000c005e020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0150c3000000000000220020ae00000000000000000000000000000000000000000000000000000000000000000000000c00000c00000c00000c00000c00000c00000c00000c00000c00000c00000c00000c000003001200430300000000000000000000000000000003005300243d0000000000000000000000000000000000000000000000000000000000000002080000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000010301320003000000000000000000000000000000000000000000000000000000000000000703000000000000000000000000000000030142000302000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003000000000000000000000000000000030112000a0100000000000000000000000000000003011a0010000220000002200001000000000000000000000000000000050103020000000000000000000000000000000000000000000000000000000000000000c3500003e800fd0301120110010000000000000000000000000000000301ff00210000000000000000000000000000000000000000000000000000000000000e05000000000000016200000000004c4b4000000000000003e800000000000003e80000000203f00005030000000000000000000000000000000000000000000000000000000000000100030000000000000000000000000000000000000000000000000000000000000200030000000000000000000000000000000000000000000000000000000000000300030000000000000000000000000000000000000000000000000000000000000400030000000000000000000000000000000000000000000000000000000000000500026600000000000000000000000000000301210000000000000000000000000000000000010000000000000000000000000000000a03011200620100000000000000000000000000000003017200233a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007c0001000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000b03011200430100000000000000000000000000000003015300243a000000000000000000000000000000000000000000000000000000000000000267000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000003001205ac030000000000000000000000000000000300ff00803d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e80ff00000000000000000000000000000000000000000000000000000000000000000003f00003000000000000000000000000000000000000000000000000000000000000055511020203e80401a0060800000e00000100000a00000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffab000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200640300000000000000000000000000000003007400843d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030010000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000000900000000000000000000000000000000000000000000000000000000000000020b00000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000703011200640100000000000000000000000000000003017400843a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853a00000000000000000000000000000000000000000000000000000000000000660000000000000000000000000000000000000000000000000000000000000002640000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000030112004a0100000000000000000000000000000003015a00823a000000000000000000000000000000000000000000000000000000000000000000000000000000ff008888888888888888888888888888888888888888888888888888888888880100000000000000000000000000000003011200640100000000000000000000000000000003017400843a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853a0000000000000000000000000000000000000000000000000000000000000067000000000000000000000000000000000000000000000000000000000000000265000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000003001205ac030000000000000000000000000000000300ff00803d0000000000000000000000000000000000000000000000000000000000000000000000000000010000000000003e80ff00000000000000000000000000000000000000000000000000000000000000000003f00003000000000000000000000000000000000000000000000000000000000000055511020203e80401a0060800000e00000100000a00000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffab000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000020a000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200640300000000000000000000000000000003007400843d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c3010000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000020d00000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000703011200640100000000000000000000000000000003017400843a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000039000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853a00000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000002700000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000030112002c0100000000000000000000000000000003013c00833a00000000000000000000000000000000000000000000000000000000000000000000000000000100000100000000000000000000000000000003011200640100000000000000000000000000000003017400843a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000039000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000003011200630100000000000000000000000000000003017300853a000000000000000000000000000000000000000000000000000000000000006500000000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000703001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000020c000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200640300000000000000000000000000000003007400843d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032010000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001205ac030000000000000000000000000000000300ff00803d00000000000000000000000000000000000000000000000000000000000000000000000000000200000000000b0838ff00000000000000000000000000000000000000000000000000000000000000000003f0000300000000000000000000000000000000000000000000000000000000000005551202030927c00401a0060800000e00000100000a00000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0300c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff53000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003001200a4030000000000000000000000000000000300b400843d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007501000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006705000000000000000000000000000000000000000000000000000000000000060300000000000000000000000000000003001200630300000000000000000000000000000003007300853d000000000000000000000000000000000000000000000000000000000000000d00000000000000000000000000000000000000000000000000000000000000020f0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000070c007d02000000013a000000000000000000000000000000000000000000000000000000000000000000000000000000800258020000000000002200204b0000000000000000000000000000000000000000000000000000000000000014c00000000000001600142800000000000000000000000000000000000000050000200c005e0200000001730000000000000000000000000000000000000000000000000000000000000000000000000000000001a701000000000000220020b200000000000000000000000000000000000000000000000000000000000000000000000c00000c00000c00000c00000c000007").unwrap(), &(Arc::clone(&logger) as Arc<dyn Logger>));

		let log_entries = logger.lines.lock().unwrap();
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendAcceptChannel event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 for channel ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679".to_string())), Some(&1)); // 1
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendFundingSigned event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 2
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendChannelReady event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 3
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendChannelReady event in peer_handler for node 030200000000000000000000000000000000000000000000000000000000000000 for channel 3a00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 4
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendRevokeAndACK event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&4)); // 5
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 with 0 adds, 0 fulfills, 0 fails for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&3)); // 6
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030200000000000000000000000000000000000000000000000000000000000000 with 1 adds, 0 fulfills, 0 fails for channel 3a00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&3)); // 7
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 with 0 adds, 1 fulfills, 0 fails for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1)); // 8
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 with 0 adds, 0 fulfills, 1 fails for channel 3d00000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&2)); // 9
		assert_eq!(log_entries.get(&("lightning::chain::channelmonitor".to_string(), "Input spending counterparty commitment tx (0000000000000000000000000000000000000000000000000000000000000073:0) in 0000000000000000000000000000000000000000000000000000000000000067 resolves outbound HTLC with payment hash ff00000000000000000000000000000000000000000000000000000000000000 with timeout".to_string())), Some(&1)); // 10
	}
}
