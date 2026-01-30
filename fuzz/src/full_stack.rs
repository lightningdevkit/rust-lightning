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

use bitcoin::amount::Amount;
use bitcoin::consensus::encode::deserialize;
use bitcoin::constants::genesis_block;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::network::Network;
use bitcoin::opcodes;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::transaction::Version;
use bitcoin::transaction::{Transaction, TxOut};

use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::FromHex;
use bitcoin::WPubkeyHash;

use lightning::blinded_path::message::{BlindedMessagePath, MessageContext, MessageForwardNode};
use lightning::blinded_path::payment::{BlindedPaymentPath, ReceiveTlvs};
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::chainmonitor;
use lightning::chain::transaction::OutPoint;
use lightning::chain::{BestBlock, ChannelMonitorUpdateStatus, Confirm, Listen};
use lightning::events::Event;
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{
	ChainParameters, ChannelManager, InterceptId, PaymentId, RecipientOnionFields, Retry,
};
use lightning::ln::functional_test_utils::*;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::ln::peer_handler::{
	IgnoringMessageHandler, MessageHandler, PeerManager, SocketDescriptor,
};
use lightning::ln::script::ShutdownScript;
use lightning::ln::types::ChannelId;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::onion_message::messenger::{Destination, MessageRouter, OnionMessagePath};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::router::{
	InFlightHtlcs, PaymentParameters, Route, RouteParameters, Router,
};
use lightning::routing::utxo::UtxoLookup;
use lightning::sign::{
	EntropySource, InMemorySigner, NodeSigner, PeerStorageKey, ReceiveAuthKey, Recipient,
	SignerProvider,
};
use lightning::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::util::config::{ChannelConfig, UserConfig};
use lightning::util::errors::APIError;
use lightning::util::hash_tables::*;
use lightning::util::logger::Logger;
use lightning::util::ser::{Readable, Writeable};
use lightning::util::test_channel_signer::{EnforcementState, TestChannelSigner};

use lightning_invoice::RawBolt11Invoice;

use crate::utils::test_logger;
use crate::utils::test_persister::TestPersister;

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{self, Message, PublicKey, Scalar, Secp256k1, SecretKey};

use lightning::util::dyn_signer::DynSigner;

use std::cell::RefCell;
use std::cmp;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[inline]
#[rustfmt::skip]
pub fn slice_to_be16(v: &[u8]) -> u16 {
	((v[0] as u16) << 8*1) |
	((v[1] as u16) << 8*0)
}

#[inline]
pub fn be16_to_array(u: u16) -> [u8; 2] {
	let mut v = [0; 2];
	v[0] = ((u >> 8 * 1) & 0xff) as u8;
	v[1] = ((u >> 8 * 0) & 0xff) as u8;
	v
}

#[inline]
#[rustfmt::skip]
pub fn slice_to_be24(v: &[u8]) -> u32 {
	((v[0] as u32) << 8*2) |
	((v[1] as u32) << 8*1) |
	((v[2] as u32) << 8*0)
}

struct InputData {
	data: Vec<u8>,
	read_pos: AtomicUsize,
	fee_estimates: Mutex<VecDeque<u32>>,
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
impl lightning::io::Read for &InputData {
	fn read(&mut self, buf: &mut [u8]) -> lightning::io::Result<usize> {
		if let Some(sl) = self.get_slice(buf.len()) {
			buf.copy_from_slice(sl);
			Ok(buf.len())
		} else {
			Ok(0)
		}
	}
}

struct FuzzEstimator {
	input: Arc<InputData>,
}
impl FeeEstimator for FuzzEstimator {
	fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u32 {
		if let Some(val) = self.input.fee_estimates.lock().unwrap().pop_front() {
			return val;
		}
		return 253;
	}
}

struct FuzzRouter {}

impl Router for FuzzRouter {
	fn find_route(
		&self, _payer: &PublicKey, _params: &RouteParameters,
		_first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, &'static str> {
		Err("Not implemented")
	}

	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, _recipient: PublicKey, _local_node_receive_key: ReceiveAuthKey,
		_first_hops: Vec<ChannelDetails>, _tlvs: ReceiveTlvs, _amount_msats: Option<u64>,
		_secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		unreachable!()
	}
}

impl MessageRouter for FuzzRouter {
	fn find_path(
		&self, _sender: PublicKey, _peers: Vec<PublicKey>, _destination: Destination,
	) -> Result<OnionMessagePath, ()> {
		unreachable!()
	}

	fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, _recipient: PublicKey, _local_node_receive_key: ReceiveAuthKey,
		_context: MessageContext, _peers: Vec<MessageForwardNode>, _secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		unreachable!()
	}
}

struct TestBroadcaster {
	txn_broadcasted: Mutex<Vec<Transaction>>,
}
impl BroadcasterInterface for TestBroadcaster {
	fn broadcast_transactions(&self, txs: &[&Transaction]) {
		let owned_txs: Vec<Transaction> = txs.iter().map(|tx| (*tx).clone()).collect();
		self.txn_broadcasted.lock().unwrap().extend(owned_txs);
	}
}

#[derive(Clone)]
struct Peer<'a> {
	id: u8,
	peers_connected: &'a RefCell<[bool; 256]>,
}
impl<'a> SocketDescriptor for Peer<'a> {
	fn send_data(&mut self, data: &[u8], _continue_read: bool) -> usize {
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
	fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
		self.id.hash(h)
	}
}

type ChannelMan<'a> = ChannelManager<
	Arc<
		chainmonitor::ChainMonitor<
			TestChannelSigner,
			Arc<dyn chain::Filter>,
			Arc<TestBroadcaster>,
			Arc<FuzzEstimator>,
			Arc<dyn Logger>,
			Arc<TestPersister>,
			Arc<KeyProvider>,
		>,
	>,
	Arc<TestBroadcaster>,
	Arc<KeyProvider>,
	Arc<KeyProvider>,
	Arc<KeyProvider>,
	Arc<FuzzEstimator>,
	&'a FuzzRouter,
	&'a FuzzRouter,
	Arc<dyn Logger>,
>;
type PeerMan<'a> = PeerManager<
	Peer<'a>,
	Arc<ChannelMan<'a>>,
	Arc<P2PGossipSync<Arc<NetworkGraph<Arc<dyn Logger>>>, Arc<dyn UtxoLookup>, Arc<dyn Logger>>>,
	IgnoringMessageHandler,
	Arc<dyn Logger>,
	IgnoringMessageHandler,
	Arc<KeyProvider>,
	IgnoringMessageHandler,
>;

struct MoneyLossDetector<'a> {
	manager: Arc<ChannelMan<'a>>,
	monitor: Arc<
		chainmonitor::ChainMonitor<
			TestChannelSigner,
			Arc<dyn chain::Filter>,
			Arc<TestBroadcaster>,
			Arc<FuzzEstimator>,
			Arc<dyn Logger>,
			Arc<TestPersister>,
			Arc<KeyProvider>,
		>,
	>,
	handler: PeerMan<'a>,

	peers: &'a RefCell<[bool; 256]>,
	funding_txn: Vec<Transaction>,
	txids_confirmed: HashMap<Txid, usize>,
	header_hashes: Vec<(BlockHash, u32)>,
	height: usize,
	max_height: usize,
	blocks_connected: u32,
	error_message: String,
}
impl<'a> MoneyLossDetector<'a> {
	pub fn new(
		peers: &'a RefCell<[bool; 256]>, manager: Arc<ChannelMan<'a>>,
		monitor: Arc<
			chainmonitor::ChainMonitor<
				TestChannelSigner,
				Arc<dyn chain::Filter>,
				Arc<TestBroadcaster>,
				Arc<FuzzEstimator>,
				Arc<dyn Logger>,
				Arc<TestPersister>,
				Arc<KeyProvider>,
			>,
		>,
		handler: PeerMan<'a>,
	) -> Self {
		MoneyLossDetector {
			manager,
			monitor,
			handler,

			peers,
			funding_txn: Vec::new(),
			txids_confirmed: new_hash_map(),
			header_hashes: vec![(genesis_block(Network::Bitcoin).block_hash(), 0)],
			height: 0,
			max_height: 0,
			blocks_connected: 0,
			error_message: "Channel force-closed".to_string(),
		}
	}

	fn connect_block(&mut self, all_txn: &[Transaction]) {
		if self.blocks_connected > 50_000 {
			// Connecting blocks is relatively slow, and some commands can connect many blocks.
			// This can inflate the total runtime substantially, leading to spurious timeouts.
			// Instead, because block connection rate is expected to be limited by PoW, simply
			// start ignoring blocks after the first 50k.
			return;
		}

		let mut txdata = Vec::with_capacity(all_txn.len());
		for (idx, tx) in all_txn.iter().enumerate() {
			let txid = tx.compute_txid();
			self.txids_confirmed.entry(txid).or_insert_with(|| {
				txdata.push((idx + 1, tx));
				self.height
			});
		}

		self.blocks_connected += 1;
		let header = create_dummy_header(self.header_hashes[self.height].0, self.blocks_connected);
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
			let header = create_dummy_header(
				self.header_hashes[self.height - 1].0,
				self.header_hashes[self.height].1,
			);
			let best_block = BestBlock::new(header.prev_blockhash, self.height as u32 - 1);
			self.manager.blocks_disconnected(best_block);
			self.monitor.blocks_disconnected(best_block);
			self.height -= 1;
			let removal_height = self.height;
			self.txids_confirmed.retain(|_, height| removal_height != *height);
		}
	}
}

impl<'a> Drop for MoneyLossDetector<'a> {
	fn drop(&mut self) {
		if !::std::thread::panicking() {
			// Disconnect all peers
			for (idx, peer) in self.peers.borrow().iter().enumerate() {
				if *peer {
					self.handler
						.socket_disconnected(&Peer { id: idx as u8, peers_connected: &self.peers });
				}
			}

			// Force all channels onto the chain (and time out claim txn)
			self.manager
				.force_close_all_channels_broadcasting_latest_txn(self.error_message.to_string());
		}
	}
}

struct KeyProvider {
	node_secret: SecretKey,
	inbound_payment_key: ExpandedKey,
	counter: AtomicU64,
	signer_state: RefCell<HashMap<u8, (bool, Arc<Mutex<EnforcementState>>)>>,
	rng_output: RefCell<[u8; 32]>,
}

impl EntropySource for KeyProvider {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		*self.rng_output.borrow()
	}
}

impl NodeSigner for KeyProvider {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(()),
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(()),
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_expanded_key(&self) -> ExpandedKey {
		self.inbound_payment_key
	}

	fn sign_invoice(
		&self, _invoice: &RawBolt11Invoice, _recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn sign_bolt12_invoice(
		&self, _invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		unreachable!()
	}

	fn sign_gossip_message(
		&self, msg: lightning::ln::msgs::UnsignedGossipMessage,
	) -> Result<Signature, ()> {
		let msg_hash = Message::from_digest(Sha256dHash::hash(&msg.encode()[..]).to_byte_array());
		let secp_ctx = Secp256k1::signing_only();
		Ok(secp_ctx.sign_ecdsa(&msg_hash, &self.node_secret))
	}

	fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
		Ok(lightning::util::message_signing::sign(msg, &self.node_secret))
	}

	fn get_peer_storage_key(&self) -> PeerStorageKey {
		PeerStorageKey { inner: [42; 32] }
	}

	fn get_receive_auth_key(&self) -> ReceiveAuthKey {
		ReceiveAuthKey([41; 32])
	}
}

impl SignerProvider for KeyProvider {
	type EcdsaSigner = TestChannelSigner;
	#[cfg(taproot)]
	type TaprootSigner = TestChannelSigner;

	fn generate_channel_keys_id(&self, inbound: bool, _user_channel_id: u128) -> [u8; 32] {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed) as u8;
		self.signer_state
			.borrow_mut()
			.insert(ctr, (inbound, Arc::new(Mutex::new(EnforcementState::new()))));
		[ctr; 32]
	}

	fn derive_channel_signer(&self, keys_id: [u8; 32]) -> Self::EcdsaSigner {
		let ctr = keys_id[0];
		let (inbound, state) = self.signer_state.borrow().get(&ctr).unwrap().clone();

		let (a, b, c, d, e, f);
		let mut key = [0; 32];
		key[31] = ctr;
		key[30] = 1 + if inbound { 0 } else { 6 };
		a = SecretKey::from_slice(&key).unwrap();
		key[30] = 2 + if inbound { 0 } else { 6 };
		b = SecretKey::from_slice(&key).unwrap();
		key[30] = 3 + if inbound { 0 } else { 6 };
		c = SecretKey::from_slice(&key).unwrap();
		key[30] = 4 + if inbound { 0 } else { 6 };
		d = SecretKey::from_slice(&key).unwrap();
		key[30] = 5 + if inbound { 0 } else { 6 };
		e = SecretKey::from_slice(&key).unwrap();
		key[30] = 6 + if inbound { 0 } else { 6 };
		f = key;
		// We leave both the v1 and v2 derivation to_remote keys the same as there's not any real
		// reason to fuzz differences here, and it keeps us consistent with past behavior.
		let signer = InMemorySigner::new(a, b, c, c, true, d, e, f, keys_id, keys_id);

		TestChannelSigner::new_with_revoked(DynSigner::new(signer), state, false, false)
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		let secp_ctx = Secp256k1::signing_only();
		let channel_monitor_claim_key = SecretKey::from_slice(
			&<Vec<u8>>::from_hex(
				"0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			)
			.unwrap()[..],
		)
		.unwrap();
		let our_channel_monitor_claim_key_hash = WPubkeyHash::hash(
			&PublicKey::from_secret_key(&secp_ctx, &channel_monitor_claim_key).serialize(),
		);
		Ok(Builder::new()
			.push_opcode(opcodes::all::OP_PUSHBYTES_0)
			.push_slice(our_channel_monitor_claim_key_hash)
			.into_script())
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		let secp_ctx = Secp256k1::signing_only();
		let secret_key = SecretKey::from_slice(&[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 1,
		])
		.unwrap();
		let pubkey_hash =
			WPubkeyHash::hash(&PublicKey::from_secret_key(&secp_ctx, &secret_key).serialize());
		Ok(ShutdownScript::new_p2wpkh(&pubkey_hash))
	}
}

#[inline]
pub fn do_test(mut data: &[u8], logger: &Arc<dyn Logger>) {
	if data.len() < 32 {
		return;
	}

	let our_network_key = match SecretKey::from_slice(&data[..32]) {
		Ok(key) => key,
		Err(_) => return,
	};
	data = &data[32..];

	let config: UserConfig = if let Ok(config) = Readable::read(&mut data) {
		config
	} else {
		return;
	};

	let input = Arc::new(InputData {
		data: data.to_vec(),
		read_pos: AtomicUsize::new(0),
		fee_estimates: Mutex::new(VecDeque::new()),
	});
	let fee_est = Arc::new(FuzzEstimator { input: input.clone() });
	let router = FuzzRouter {};

	macro_rules! get_slice {
		($len: expr) => {
			match input.get_slice($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		};
	}

	macro_rules! get_bytes {
		($len: expr) => {{
			let mut res = [0; $len];
			match input.get_slice($len as usize) {
				Some(slice) => res.copy_from_slice(slice),
				None => return,
			}
			res
		}};
	}

	macro_rules! get_pubkey {
		() => {
			match PublicKey::from_slice(get_slice!(33)) {
				Ok(key) => key,
				Err(_) => return,
			}
		};
	}

	let inbound_payment_key = [
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 42,
	];

	let broadcast = Arc::new(TestBroadcaster { txn_broadcasted: Mutex::new(Vec::new()) });

	let keys_manager = Arc::new(KeyProvider {
		node_secret: our_network_key.clone(),
		inbound_payment_key: ExpandedKey::new(inbound_payment_key),
		counter: AtomicU64::new(0),
		signer_state: RefCell::new(new_hash_map()),
		rng_output: RefCell::new([42; 32]),
	});

	let monitor = Arc::new(chainmonitor::ChainMonitor::new(
		None,
		broadcast.clone(),
		Arc::clone(&logger),
		fee_est.clone(),
		Arc::new(TestPersister { update_ret: Mutex::new(ChannelMonitorUpdateStatus::Completed) }),
		Arc::clone(&keys_manager),
		keys_manager.get_peer_storage_key(),
	));

	let network = Network::Bitcoin;
	let best_block_timestamp = genesis_block(network).header.time;
	let params = ChainParameters { network, best_block: BestBlock::from_network(network) };
	let channelmanager = Arc::new(ChannelManager::new(
		fee_est.clone(),
		monitor.clone(),
		broadcast.clone(),
		&router,
		&router,
		Arc::clone(&logger),
		keys_manager.clone(),
		keys_manager.clone(),
		keys_manager.clone(),
		config,
		params,
		best_block_timestamp,
	));
	// Adding new calls to `EntropySource::get_secure_random_bytes` during startup can change all the
	// keys subsequently generated in this test. Rather than regenerating all the messages manually,
	// it's easier to just increment the counter here so the keys don't change.
	keys_manager.counter.fetch_sub(4, Ordering::AcqRel);
	let network_graph = Arc::new(NetworkGraph::new(network, Arc::clone(&logger)));
	let gossip_sync =
		Arc::new(P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger)));

	let peers = RefCell::new([false; 256]);
	let message_handler = MessageHandler {
		chan_handler: channelmanager.clone(),
		route_handler: gossip_sync.clone(),
		onion_message_handler: IgnoringMessageHandler {},
		custom_message_handler: IgnoringMessageHandler {},
		send_only_message_handler: IgnoringMessageHandler {},
	};
	let random_data = [
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		15, 0,
	];
	let peer_manager = PeerManager::new(
		message_handler,
		0,
		&random_data,
		Arc::clone(&logger),
		keys_manager.clone(),
	);
	let mut loss_detector =
		MoneyLossDetector::new(&peers, channelmanager.clone(), monitor.clone(), peer_manager);

	let mut payments_received: Vec<PaymentHash> = Vec::new();
	let mut intercepted_htlcs: Vec<InterceptId> = Vec::new();
	let mut payments_sent: u16 = 0;
	let mut pending_funding_generation: Vec<(ChannelId, PublicKey, u64, ScriptBuf)> = Vec::new();
	let mut pending_funding_signatures = new_hash_map();

	loop {
		match get_slice!(1)[0] {
			0 => {
				let mut new_id = 0;
				for i in 1..256 {
					if !peers.borrow()[i - 1] {
						new_id = i;
						break;
					}
				}
				if new_id == 0 {
					return;
				}
				let peer = Peer { id: (new_id - 1) as u8, peers_connected: &peers };
				loss_detector.handler.new_outbound_connection(get_pubkey!(), peer, None).unwrap();
				peers.borrow_mut()[new_id - 1] = true;
			},
			1 => {
				let mut new_id = 0;
				for i in 1..256 {
					if !peers.borrow()[i - 1] {
						new_id = i;
						break;
					}
				}
				if new_id == 0 {
					return;
				}
				let peer = Peer { id: (new_id - 1) as u8, peers_connected: &peers };
				loss_detector.handler.new_inbound_connection(peer, None).unwrap();
				peers.borrow_mut()[new_id - 1] = true;
			},
			2 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] {
					return;
				}
				let peer = Peer { id: peer_id, peers_connected: &peers };
				loss_detector.handler.socket_disconnected(&peer);
				peers.borrow_mut()[peer_id as usize] = false;
			},
			3 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] {
					return;
				}
				let mut peer = Peer { id: peer_id, peers_connected: &peers };
				match loss_detector.handler.read_event(&mut peer, get_slice!(get_slice!(1)[0])) {
					Ok(()) => {},
					Err(_) => {
						peers.borrow_mut()[peer_id as usize] = false;
					},
				}
			},
			4 => {
				let final_value_msat = slice_to_be24(get_slice!(3)) as u64;
				let payment_params = PaymentParameters::from_node_id(get_pubkey!(), 42);
				let params = RouteParameters::from_payment_params_and_value(
					payment_params,
					final_value_msat,
				);
				let mut payment_hash = PaymentHash([0; 32]);
				payment_hash.0[0..2].copy_from_slice(&be16_to_array(payments_sent));
				payment_hash.0 = Sha256::hash(&payment_hash.0[..]).to_byte_array();
				payments_sent += 1;
				let _ = channelmanager.send_payment(
					payment_hash,
					RecipientOnionFields::spontaneous_empty(),
					PaymentId(payment_hash.0),
					params,
					Retry::Attempts(2),
				);
			},
			15 => {
				let final_value_msat = slice_to_be24(get_slice!(3)) as u64;
				let payment_params = PaymentParameters::from_node_id(get_pubkey!(), 42);
				let params = RouteParameters::from_payment_params_and_value(
					payment_params,
					final_value_msat,
				);
				let mut payment_hash = PaymentHash([0; 32]);
				payment_hash.0[0..2].copy_from_slice(&be16_to_array(payments_sent));
				payment_hash.0 = Sha256::hash(&payment_hash.0[..]).to_byte_array();
				payments_sent += 1;
				let mut payment_secret = PaymentSecret([0; 32]);
				payment_secret.0[0..2].copy_from_slice(&be16_to_array(payments_sent));
				payments_sent += 1;
				let _ = channelmanager.send_payment(
					payment_hash,
					RecipientOnionFields::secret_only(payment_secret),
					PaymentId(payment_hash.0),
					params,
					Retry::Attempts(2),
				);
			},
			17 => {
				let final_value_msat = slice_to_be24(get_slice!(3)) as u64;
				let payment_params = PaymentParameters::from_node_id(get_pubkey!(), 42);
				let params = RouteParameters::from_payment_params_and_value(
					payment_params,
					final_value_msat,
				);
				let _ = channelmanager.send_preflight_probes(params, None);
			},
			18 => {
				let idx = u16::from_be_bytes(get_bytes!(2)) % cmp::max(payments_sent, 1);
				let mut payment_id = PaymentId([0; 32]);
				payment_id.0[0..2].copy_from_slice(&idx.to_be_bytes());
				channelmanager.abandon_payment(payment_id);
			},
			5 => {
				let peer_id = get_slice!(1)[0];
				if !peers.borrow()[peer_id as usize] {
					return;
				}
				let their_key = get_pubkey!();
				let chan_value = slice_to_be24(get_slice!(3)) as u64;
				let push_msat_value = slice_to_be24(get_slice!(3)) as u64;
				if channelmanager
					.create_channel(their_key, chan_value, push_msat_value, 0, None, None)
					.is_err()
				{
					return;
				}
			},
			6 => {
				let mut channels = channelmanager.list_channels();
				let channel_id = get_slice!(1)[0] as usize;
				if channel_id >= channels.len() {
					return;
				}
				channels.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));
				if channelmanager
					.close_channel(
						&channels[channel_id].channel_id,
						&channels[channel_id].counterparty.node_id,
					)
					.is_err()
				{
					return;
				}
			},
			7 => {
				channelmanager.process_pending_htlc_forwards();
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
				let payment_hash =
					PaymentHash(Sha256::hash(&payment_preimage.0[..]).to_byte_array());
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
				let mut tx = Transaction {
					version: Version(0),
					lock_time: LockTime::ZERO,
					input: Vec::new(),
					output: Vec::new(),
				};
				let mut channels = Vec::new();
				for funding_generation in pending_funding_generation.drain(..) {
					let txout = TxOut {
						value: Amount::from_sat(funding_generation.2),
						script_pubkey: funding_generation.3,
					};
					if !tx.output.contains(&txout) {
						tx.output.push(txout);
						channels.push((funding_generation.0, funding_generation.1));
					}
				}
				// Once we switch to V2 channel opens we should be able to drop this entirely as
				// channel_ids no longer change when we set the funding tx.
				'search_loop: loop {
					if tx.version.0 > 0xff {
						break;
					}
					let funding_txid = tx.compute_txid();
					if loss_detector.txids_confirmed.get(&funding_txid).is_none() {
						let outpoint = OutPoint { txid: funding_txid, index: 0 };
						for chan in channelmanager.list_channels() {
							if chan.channel_id == ChannelId::v1_from_funding_outpoint(outpoint) {
								tx.version = Version(tx.version.0 + 1);
								continue 'search_loop;
							}
						}
						break;
					}
					tx.version = Version(tx.version.0 + 1);
				}
				if tx.version.0 <= 0xff && !channels.is_empty() {
					let chans = channels.iter().map(|(a, b)| (a, b)).collect::<Vec<_>>();
					let res =
						channelmanager.batch_funding_transaction_generated(&chans, tx.clone());
					if res.is_ok() {
						let funding_txid = tx.compute_txid();
						for idx in 0..tx.output.len() {
							let outpoint = OutPoint { txid: funding_txid, index: idx as u16 };
							pending_funding_signatures.insert(outpoint, tx.clone());
						}
					}
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
				let txlen = u16::from_be_bytes(get_bytes!(2));
				if txlen == 0 {
					loss_detector.connect_block(&[]);
				} else {
					let txres: Result<Transaction, _> = deserialize(get_slice!(txlen));
					if let Ok(tx) = txres {
						let mut output_val = Amount::ZERO;
						for out in tx.output.iter() {
							if out.value > Amount::MAX_MONEY {
								return;
							}
							output_val += out.value;
							if output_val > Amount::MAX_MONEY {
								return;
							}
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
				let error_message = "Channel force-closed";
				if channel_id >= channels.len() {
					return;
				}
				channels.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));
				channelmanager
					.force_close_broadcasting_latest_txn(
						&channels[channel_id].channel_id,
						&channels[channel_id].counterparty.node_id,
						error_message.to_string(),
					)
					.unwrap();
			},
			// 15, 16, 17, 18 is above
			19 => {
				let mut list = loss_detector.handler.list_peers();
				list.sort_by_key(|v| v.counterparty_node_id);
				if let Some(peer_details) = list.get(0) {
					loss_detector.handler.disconnect_by_node_id(peer_details.counterparty_node_id);
				}
			},
			20 => loss_detector.handler.disconnect_all_peers(),
			21 => loss_detector.handler.timer_tick_occurred(),
			22 => loss_detector.handler.broadcast_node_announcement([42; 3], [43; 32], Vec::new()),
			32 => channelmanager.timer_tick_occurred(),
			33 => {
				for id in intercepted_htlcs.drain(..) {
					channelmanager.fail_intercepted_htlc(id).unwrap();
				}
			},
			34 => {
				let amt = u64::from_be_bytes(get_bytes!(8));
				let chans = channelmanager.list_channels();
				for id in intercepted_htlcs.drain(..) {
					if chans.is_empty() {
						channelmanager.fail_intercepted_htlc(id).unwrap();
					} else {
						let chan = &chans[amt as usize % chans.len()];
						channelmanager
							.forward_intercepted_htlc(
								id,
								&chan.channel_id,
								chan.counterparty.node_id,
								amt,
							)
							.unwrap();
					}
				}
			},
			35 => {
				let config: ChannelConfig = if let Ok(c) = Readable::read(&mut &*input) {
					c
				} else {
					return;
				};
				let chans = channelmanager.list_channels();
				if let Some(chan) = chans.get(0) {
					let _ = channelmanager.update_channel_config(
						&chan.counterparty.node_id,
						&[chan.channel_id],
						&config,
					);
				}
			},
			48 => {
				let fee = u32::from_le_bytes(get_slice!(4).try_into().unwrap());
				input.fee_estimates.lock().unwrap().push_back(fee);
			},
			49 => {
				let mut rng_output = [0; 32];
				rng_output.copy_from_slice(&get_slice!(32));
				*keys_manager.rng_output.borrow_mut() = rng_output;
			},
			_ => return,
		}
		loss_detector.handler.process_events();
		for event in loss_detector.manager.get_and_clear_pending_events() {
			match event {
				Event::FundingGenerationReady {
					temporary_channel_id,
					counterparty_node_id,
					channel_value_satoshis,
					output_script,
					..
				} => {
					pending_funding_generation.push((
						temporary_channel_id,
						counterparty_node_id,
						channel_value_satoshis,
						output_script,
					));
				},
				Event::PaymentClaimable { payment_hash, .. } => {
					//TODO: enhance by fetching random amounts from fuzz input?
					payments_received.push(payment_hash);
				},
				Event::HTLCIntercepted { intercept_id, .. } => {
					if !intercepted_htlcs.contains(&intercept_id) {
						intercepted_htlcs.push(intercept_id);
					}
				},
				Event::OpenChannelRequest {
					temporary_channel_id, counterparty_node_id, ..
				} => {
					let _ = loss_detector.manager.accept_inbound_channel(
						&temporary_channel_id,
						&counterparty_node_id,
						0,
						None,
					);
					loss_detector.handler.process_events();
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
	let logger: Arc<dyn Logger> =
		Arc::new(test_logger::TestLogger::new("".to_owned(), test_logger::DevNull {}));
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, &logger);
}

fn ext_from_hex(hex_with_spaces: &str, out: &mut Vec<u8>) {
	for hex in hex_with_spaces.split(" ") {
		out.append(&mut <Vec<u8>>::from_hex(hex).unwrap());
	}
}

fn two_peer_forwarding_seed() -> Vec<u8> {
	// Following BOLT 8, lightning message on the wire are: 2-byte encrypted message length +
	// 16-byte MAC of the encrypted message length + encrypted Lightning message + 16-byte MAC
	// of the Lightning message
	// I.e 2nd inbound read, len 18 : 0006 (encrypted message length) + 03000000000000000000000000000000 (MAC of the encrypted message length)
	// Len 22 : 0010 00000000 (encrypted lightning message) + 03000000000000000000000000000000 (MAC of the Lightning message)

	// Writing new code generating transactions and see a new failure ? Don't forget to add input for the FuzzEstimator !

	let mut test = Vec::new();
	// our network key
	ext_from_hex("0100000000000000000000000000000000000000000000000000000000000000", &mut test);
	// config
	ext_from_hex("000000000090000000000000000064000100000000000100ffff0000000000000000ffffffffffffffffffffffffffffffff0000000000000000ffffffffffffffff000000ffffffff00ffff1a000400010000020400000000040200000a08ffffffffffffffff0001000000000000", &mut test);

	// new outbound connection with id 0
	ext_from_hex("00", &mut test);
	// peer's pubkey
	ext_from_hex("030000000000000000000000000000000000000000000000000000000000000002", &mut test);
	// inbound read from peer id 0 of len 50
	ext_from_hex("030032", &mut test);
	// noise act two (0||pubkey||mac)
	ext_from_hex("00 030000000000000000000000000000000000000000000000000000000000000002 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 16
	ext_from_hex("0010 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 32
	ext_from_hex("030020", &mut test);
	// init message (type 16) with static_remotekey required, no anchors/taproot, and other bits optional and mac
	ext_from_hex("0010 00021aaa 0008aaa210aa2a0a9aaa 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 327
	ext_from_hex("0147 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 254
	ext_from_hex("0300fe", &mut test);
	// beginning of open_channel message
	ext_from_hex("0020 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000 ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679 000000000000c350 0000000000000000 0000000000000162 ffffffffffffffff 0000000000000222 0000000000000000 000000fd 0006 01e3 030000000000000000000000000000000000000000000000000000000000000001 030000000000000000000000000000000000000000000000000000000000000002 030000000000000000000000000000000000000000000000000000000000000003 030000000000000000000000000000000000000000000000000000000000000004", &mut test);
	// inbound read from peer id 0 of len 89
	ext_from_hex("030059", &mut test);
	// rest of open_channel and mac
	ext_from_hex("030000000000000000000000000000000000000000000000000000000000000005 020900000000000000000000000000000000000000000000000000000000000000 01 0000 01021000 03000000000000000000000000000000", &mut test);

	// client should now respond with accept_channel (CHECK 1: type 33 to peer 03000000)

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 132
	ext_from_hex("0084 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 148
	ext_from_hex("030094", &mut test);
	// funding_created and mac
	ext_from_hex("0022 ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679 c000000000000000000000000000000000000000000000000000000000000000 0000 00000000000000000000000000000000000000000000000000000000000000dc0100000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);
	// client should now respond with funding_signed (CHECK 2: type 35 to peer 03000000)

	// connect a block with one transaction of len 94
	ext_from_hex("0c005e", &mut test);
	// the funding transaction
	ext_from_hex("020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0150c3000000000000220020530000000000000000000000000000000000000000000000000000000000000000000000", &mut test);
	// connect a block with no transactions, one per line
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	ext_from_hex("0c0000", &mut test);
	// by now client should have sent a channel_ready (CHECK 3: SendChannelReady to 03000000 for chan c0000000)

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 67
	ext_from_hex("0043 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 83
	ext_from_hex("030053", &mut test);
	// channel_ready and mac
	ext_from_hex("0024 c000000000000000000000000000000000000000000000000000000000000000 020800000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	// new inbound connection with id 1
	ext_from_hex("01", &mut test);
	// inbound read from peer id 1 of len 50
	ext_from_hex("030132", &mut test);
	// inbound noise act 1
	ext_from_hex("0003000000000000000000000000000000000000000000000000000000000000000703000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 66
	ext_from_hex("030142", &mut test);
	// inbound noise act 3
	ext_from_hex("000302000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003000000000000000000000000000000", &mut test);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 16
	ext_from_hex("0010 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 32
	ext_from_hex("030120", &mut test);
	// init message (type 16) with static_remotekey required, no anchors/taproot, and other bits optional and mac
	ext_from_hex("0010 00021aaa 0008aaa210aa2a0a9aaa 01000000000000000000000000000000", &mut test);

	// create outbound channel to peer 1 for 50k sat
	ext_from_hex(
		"05 01 030200000000000000000000000000000000000000000000000000000000000000 00c350 0003e8",
		&mut test,
	);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 278
	ext_from_hex("0116 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 255
	ext_from_hex("0301ff", &mut test);
	// beginning of accept_channel
	ext_from_hex("0021 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a 0000000000000162 00000000004c4b40 00000000000003e8 00000000000003e8 00000002 03f0 0005 030000000000000000000000000000000000000000000000000000000000000100 030000000000000000000000000000000000000000000000000000000000000200 030000000000000000000000000000000000000000000000000000000000000300 030000000000000000000000000000000000000000000000000000000000000400 030000000000000000000000000000000000000000000000000000000000000500 02660000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 39
	ext_from_hex("030127", &mut test);
	// rest of accept_channel and mac
	ext_from_hex(
		"0000000000000000000000000000000000 0000 01021000 01000000000000000000000000000000",
		&mut test,
	);

	// create the funding transaction (client should send funding_created now)
	ext_from_hex("0a", &mut test);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 98
	ext_from_hex("0062 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 114
	ext_from_hex("030172", &mut test);
	// funding_signed message and mac
	ext_from_hex("0023 c400000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000310001000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000", &mut test);

	// broadcast funding transaction
	ext_from_hex("0b", &mut test);
	// by now client should have sent a channel_ready (CHECK 4: SendChannelReady to 03020000 for chan 2f000000)

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 67
	ext_from_hex("0043 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 83
	ext_from_hex("030153", &mut test);
	// channel_ready and mac
	ext_from_hex("0024 c400000000000000000000000000000000000000000000000000000000000000 026700000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 1452
	ext_from_hex("05ac 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	// beginning of update_add_htlc from 0 to 1 via client
	ext_from_hex("0080 c000000000000000000000000000000000000000000000000000000000000000 0000000000000000 0000000000003e80 ff00000000000000000000000000000000000000000000000000000000000000 000003f0 00 030000000000000000000000000000000000000000000000000000000000000555 11 020203e8 0401a0 060800000e0000010000 0a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 193
	ext_from_hex("0300c1", &mut test);
	// end of update_add_htlc from 0 to 1 via client and mac
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff ab00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 100
	ext_from_hex("0064 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 116
	ext_from_hex("030074", &mut test);
	// commitment_signed and mac
	ext_from_hex("0084 c000000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000cd0100000000000000000000000000000000000000000000000000000000000000 0000 03000000000000000000000000000000", &mut test);
	// client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6: types 133 and 132 to peer 03000000)

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 115
	ext_from_hex("030073", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c000000000000000000000000000000000000000000000000000000000000000 0900000000000000000000000000000000000000000000000000000000000000 020b00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	// process the now-pending HTLC forward
	ext_from_hex("07", &mut test);
	// client now sends id 1 update_add_htlc and commitment_signed (CHECK 7: UpdateHTLCs event for node 03020000 with 1 HTLCs for channel 2f000000)

	// we respond with commitment_signed then revoke_and_ack (a weird, but valid, order)
	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 100
	ext_from_hex("0064 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 116
	ext_from_hex("030174", &mut test);
	// commitment_signed and mac
	ext_from_hex("0084 c400000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000720001000000000000000000000000000000000000000000000000000000000000 0000 01000000000000000000000000000000", &mut test);
	//
	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 115
	ext_from_hex("030173", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c400000000000000000000000000000000000000000000000000000000000000 6600000000000000000000000000000000000000000000000000000000000000 026400000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000", &mut test);
	//
	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 74
	ext_from_hex("004a 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 90
	ext_from_hex("03015a", &mut test);
	// update_fulfill_htlc and mac
	ext_from_hex("0082 c400000000000000000000000000000000000000000000000000000000000000 0000000000000000 ff00888888888888888888888888888888888888888888888888888888888888 01000000000000000000000000000000", &mut test);
	// client should immediately claim the pending HTLC from peer 0 (CHECK 8: SendFulfillHTLCs for node 03000000 with preimage ff00888888 for channel c0000000)

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 100
	ext_from_hex("0064 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 116
	ext_from_hex("030174", &mut test);
	// commitment_signed and mac
	ext_from_hex("0084 c400000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000700001000000000000000000000000000000000000000000000000000000000000 0000 01000000000000000000000000000000", &mut test);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 115
	ext_from_hex("030173", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c400000000000000000000000000000000000000000000000000000000000000 6700000000000000000000000000000000000000000000000000000000000000 026500000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000", &mut test);

	// before responding to the commitment_signed generated above, send a new HTLC
	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 1452
	ext_from_hex("05ac 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	// beginning of update_add_htlc from 0 to 1 via client
	ext_from_hex("0080 c000000000000000000000000000000000000000000000000000000000000000 0000000000000001 0000000000003e80 ff00000000000000000000000000000000000000000000000000000000000000 000003f0 00 030000000000000000000000000000000000000000000000000000000000000555 11 020203e8 0401a0 060800000e0000010000 0a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 193
	ext_from_hex("0300c1", &mut test);
	// end of update_add_htlc from 0 to 1 via client and mac
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff ab00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	// now respond to the update_fulfill_htlc+commitment_signed messages the client sent to peer 0
	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 115
	ext_from_hex("030073", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c000000000000000000000000000000000000000000000000000000000000000 0800000000000000000000000000000000000000000000000000000000000000 020a00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);
	// client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6 duplicates)

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 100
	ext_from_hex("0064 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 116
	ext_from_hex("030074", &mut test);
	// commitment_signed and mac
	ext_from_hex("0084 c000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000003e0100000000000000000000000000000000000000000000000000000000000000 0000 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 115
	ext_from_hex("030073", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c000000000000000000000000000000000000000000000000000000000000000 0b00000000000000000000000000000000000000000000000000000000000000 020d00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	// process the now-pending HTLC forward
	ext_from_hex("07", &mut test);

	// client now sends id 1 update_add_htlc and commitment_signed (CHECK 7 duplicate)
	// we respond with revoke_and_ack, then commitment_signed, then update_fail_htlc

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 100
	ext_from_hex("0064 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 116
	ext_from_hex("030174", &mut test);
	// commitment_signed and mac
	ext_from_hex("0084 c400000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000007e0001000000000000000000000000000000000000000000000000000000000000 0000 01000000000000000000000000000000", &mut test);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 115
	ext_from_hex("030173", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c400000000000000000000000000000000000000000000000000000000000000 6400000000000000000000000000000000000000000000000000000000000000 027000000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000", &mut test);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 44
	ext_from_hex("002c 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 60
	ext_from_hex("03013c", &mut test);
	// update_fail_htlc and mac
	ext_from_hex("0083 c400000000000000000000000000000000000000000000000000000000000000 0000000000000001 0000 01000000000000000000000000000000", &mut test);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 100
	ext_from_hex("0064 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 116
	ext_from_hex("030174", &mut test);
	// commitment_signed and mac
	ext_from_hex("0084 c400000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000410001000000000000000000000000000000000000000000000000000000000000 0000 01000000000000000000000000000000", &mut test);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 115
	ext_from_hex("030173", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c400000000000000000000000000000000000000000000000000000000000000 6500000000000000000000000000000000000000000000000000000000000000 027100000000000000000000000000000000000000000000000000000000000000 01000000000000000000000000000000", &mut test);

	// process the now-pending HTLC forward
	ext_from_hex("07", &mut test);
	// client now sends id 0 update_fail_htlc and commitment_signed (CHECK 9)
	// now respond to the update_fail_htlc+commitment_signed messages the client sent to peer 0

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 115
	ext_from_hex("030073", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c000000000000000000000000000000000000000000000000000000000000000 0a00000000000000000000000000000000000000000000000000000000000000 020c00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 100
	ext_from_hex("0064 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 116
	ext_from_hex("030074", &mut test);
	// commitment_signed and mac
	ext_from_hex("0084 c000000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000cf0100000000000000000000000000000000000000000000000000000000000000 0000 03000000000000000000000000000000", &mut test);
	// client should now respond with revoke_and_ack (CHECK 5 duplicate)

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 1452
	ext_from_hex("05ac 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	// beginning of update_add_htlc from 0 to 1 via client
	ext_from_hex("0080 c000000000000000000000000000000000000000000000000000000000000000 0000000000000002 00000000000b0838 ff00000000000000000000000000000000000000000000000000000000000000 000003f0 00 030000000000000000000000000000000000000000000000000000000000000555 12 02030927c1 0401a0 060800000e0000010000 0a00000000000000000000000000000000000000000000000000000000000000 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", &mut test);
	// inbound read from peer id 0 of len 193
	ext_from_hex("0300c1", &mut test);
	// end of update_add_htlc from 0 to 1 via client and mac
	ext_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 5200000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 164
	ext_from_hex("00a4 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 180
	ext_from_hex("0300b4", &mut test);
	// commitment_signed and mac
	ext_from_hex("0084 c000000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000000000000000000000f60100000000000000000000000000000000000000000000000000000000000000 0001 000000000000000000000000000000000000000000000000000000000000009b05000000000000000000000000000000000000000000000000000000000000fb 03000000000000000000000000000000", &mut test);
	// client should now respond with revoke_and_ack and commitment_signed (CHECK 5/6 duplicates)

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 99
	ext_from_hex("0063 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 115
	ext_from_hex("030073", &mut test);
	// revoke_and_ack and mac
	ext_from_hex("0085 c000000000000000000000000000000000000000000000000000000000000000 0d00000000000000000000000000000000000000000000000000000000000000 020f00000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	// process the now-pending HTLC forward
	ext_from_hex("07", &mut test);
	// client now sends id 1 update_add_htlc and commitment_signed (CHECK 7 duplicate)

	// connect a block with one transaction of len 125
	ext_from_hex("0c007d", &mut test);
	// the commitment transaction for channel c400000000000000000000000000000000000000000000000000000000000000
	ext_from_hex("0200000001c400000000000000000000000000000000000000000000000000000000000000000000000000000080025802000000000000220020940000000000000000000000000000000000000000000000000000000000000013c0000000000000160014d60000000000000000000000000000000000000005000020", &mut test);
	//
	// connect a block with one transaction of len 94
	ext_from_hex("0c005e", &mut test);
	// the HTLC timeout transaction
	ext_from_hex("0200000001ab0000000000000000000000000000000000000000000000000000000000000000000000000000000001a7010000000000002200206c0000000000000000000000000000000000000000000000000000000000000000000000", &mut test);
	// connect a block with no transactions
	ext_from_hex("0c0000", &mut test);
	// connect a block with no transactions
	ext_from_hex("0c0000", &mut test);
	// connect a block with no transactions
	ext_from_hex("0c0000", &mut test);
	// connect a block with no transactions
	ext_from_hex("0c0000", &mut test);
	// connect a block with no transactions
	ext_from_hex("0c0000", &mut test);

	// process the now-pending HTLC forward
	ext_from_hex("07", &mut test);
	// client now fails the HTLC backwards as it was unable to extract the payment preimage (CHECK 9 duplicate and CHECK 10)

	test
}

fn gossip_exchange_seed() -> Vec<u8> {
	// Following BOLT 8, lightning message on the wire are: 2-byte encrypted message length +
	// 16-byte MAC of the encrypted message length + encrypted Lightning message + 16-byte MAC
	// of the Lightning message
	// I.e 2nd inbound read, len 18 : 0006 (encrypted message length) + 03000000000000000000000000000000 (MAC of the encrypted message length)
	// Len 22 : 0010 00000000 (encrypted lightning message) + 03000000000000000000000000000000 (MAC of the Lightning message)

	// Writing new code generating transactions and see a new failure ? Don't forget to add input for the FuzzEstimator !

	let mut test = Vec::new();

	// our network key
	ext_from_hex("0100000000000000000000000000000000000000000000000000000000000000", &mut test);
	// config
	ext_from_hex("000000000090000000000000000064000100000000000100ffff0000000000000000ffffffffffffffffffffffffffffffff0000000000000000ffffffffffffffff000000ffffffff00ffff1a000400010000020400000000040200000a08ffffffffffffffff0001000000000000", &mut test);

	// new outbound connection with id 0
	ext_from_hex("00", &mut test);
	// peer's pubkey
	ext_from_hex("030000000000000000000000000000000000000000000000000000000000000002", &mut test);
	// inbound read from peer id 0 of len 50
	ext_from_hex("030032", &mut test);
	// noise act two (0||pubkey||mac)
	ext_from_hex("00 030000000000000000000000000000000000000000000000000000000000000002 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 16
	ext_from_hex("0010 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 32
	ext_from_hex("030020", &mut test);
	// init message (type 16) with static_remotekey required, no anchors/taproot, and other bits optional and mac
	ext_from_hex("0010 00021aaa 0008aaa210aa2a0a9aaa 03000000000000000000000000000000", &mut test);

	// new inbound connection with id 1
	ext_from_hex("01", &mut test);
	// inbound read from peer id 1 of len 50
	ext_from_hex("030132", &mut test);
	// inbound noise act 1
	ext_from_hex("0003000000000000000000000000000000000000000000000000000000000000000703000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 66
	ext_from_hex("030142", &mut test);
	// inbound noise act 3
	ext_from_hex("000302000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000003000000000000000000000000000000", &mut test);

	// inbound read from peer id 1 of len 18
	ext_from_hex("030112", &mut test);
	// message header indicating message length 16
	ext_from_hex("0010 01000000000000000000000000000000", &mut test);
	// inbound read from peer id 1 of len 32
	ext_from_hex("030120", &mut test);
	// init message (type 16) with static_remotekey required, no anchors/taproot, and other bits optional and mac
	ext_from_hex("0010 00021aaa 0008aaa210aa2a0a9aaa 01000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 432
	ext_from_hex("01b0 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 255
	ext_from_hex("0300ff", &mut test);
	// First part of channel_announcement (type 256)
	ext_from_hex("0100 00000000000000000000000000000000000000000000000000000000000000b20303030303030303030303030303030303030303030303030303030303030303 00000000000000000000000000000000000000000000000000000000000000b20202020202020202020202020202020202020202020202020202020202020202 00000000000000000000000000000000000000000000000000000000000000b20303030303030303030303030303030303030303030303030303030303030303 00000000000000000000000000000000000000000000000000000000000000b20202020202020202020202020202020202020202020202020202020202", &mut test);
	// inbound read from peer id 0 of len 193
	ext_from_hex("0300c1", &mut test);
	// Last part of channel_announcement and mac
	ext_from_hex("020202 00006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000000000000000002a030303030303030303030303030303030303030303030303030303030303030303020202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030303020202020202020202020202020202020202020202020202020202020202020202 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 138
	ext_from_hex("008a 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 154
	ext_from_hex("03009a", &mut test);
	// channel_update (type 258) and mac
	ext_from_hex("0102 00000000000000000000000000000000000000000000000000000000000000a60303030303030303030303030303030303030303030303030303030303030303 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000 000000000000002a0000002c01000028000000000000000000000000000000000000000005f5e100 03000000000000000000000000000000", &mut test);

	// inbound read from peer id 0 of len 18
	ext_from_hex("030012", &mut test);
	// message header indicating message length 142
	ext_from_hex("008e 03000000000000000000000000000000", &mut test);
	// inbound read from peer id 0 of len 158
	ext_from_hex("03009e", &mut test);
	// node_announcement (type 257) and mac
	ext_from_hex("0101 00000000000000000000000000000000000000000000000000000000000000280303030303030303030303030303030303030303030303030303030303030303 00000000002b03030303030303030303030303030303030303030303030303030303030303030300000000000000000000000000000000000000000000000000000000000000000000000000 03000000000000000000000000000000", &mut test);

	test
}

pub fn write_fst_seeds(path: &str) {
	use std::fs::File;
	use std::io::Write;

	let mut f = File::create(path.to_owned() + "/two_peer_forwarding_seed").unwrap();
	let two_peer_forwarding = two_peer_forwarding_seed();
	f.write_all(&two_peer_forwarding).unwrap();

	let mut f = File::create(path.to_owned() + "/gossip_exchange_seed").unwrap();
	let gossip_exchange = gossip_exchange_seed();
	f.write_all(&gossip_exchange).unwrap();
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
		fn log(&self, record: Record) {
			*self
				.lines
				.lock()
				.unwrap()
				.entry((record.module_path.to_string(), format!("{}", record.args)))
				.or_insert(0) += 1;
			println!("{}", record);
		}
	}

	#[test]
	fn test_no_existing_test_breakage() {
		// To avoid accidentally causing all existing fuzz test cases to be useless by making minor
		// changes, we run a pretty full step-through with two peers and HTLC forwarding here.
		// Obviously this can be somewhat finicky, so this should be updated pretty liberally, but
		// at least we'll know when changes occur. If nothing else, this test serves as a pretty
		// great initial full_stack_target seed.

		let test = super::two_peer_forwarding_seed();

		let logger = Arc::new(TrackingLogger { lines: Mutex::new(HashMap::new()) });
		super::do_test(&test, &(Arc::clone(&logger) as Arc<dyn Logger>));

		let log_entries = logger.lines.lock().unwrap();
		// 1
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendAcceptChannel event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 for channel ff4f00f805273c1b203bb5ebf8436bfde57b3be8c2f5e95d9491dbb181909679".to_string())), Some(&1));
		// 2
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendFundingSigned event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 for channel c000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1));
		// 3
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendChannelReady event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 for channel c000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1));
		// 4
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendChannelReady event in peer_handler for node 030200000000000000000000000000000000000000000000000000000000000000 for channel c400000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1));
		// 5
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling SendRevokeAndACK event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 for channel c000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&4));
		// 6
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 with 0 adds, 0 fulfills, 0 fails, 1 commits for channel c000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&3));
		// 7
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030200000000000000000000000000000000000000000000000000000000000000 with 1 adds, 0 fulfills, 0 fails, 1 commits for channel c400000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&3));
		// 8
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 with 0 adds, 1 fulfills, 0 fails, 1 commits for channel c000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&1));
		// 9
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Handling UpdateHTLCs event in peer_handler for node 030000000000000000000000000000000000000000000000000000000000000002 with 0 adds, 0 fulfills, 1 fails, 1 commits for channel c000000000000000000000000000000000000000000000000000000000000000".to_string())), Some(&2));
		// 10
		assert_eq!(log_entries.get(&("lightning::chain::channelmonitor".to_string(), "Input spending counterparty commitment tx (00000000000000000000000000000000000000000000000000000000000000ab:0) in 0000000000000000000000000000000000000000000000000000000000000061 resolves outbound HTLC with payment hash ff00000000000000000000000000000000000000000000000000000000000000 with timeout".to_string())), Some(&1));
	}

	#[test]
	fn test_gossip_exchange_breakage() {
		// To avoid accidentally causing all existing fuzz test cases to be useless by making minor
		// changes, we exchange some gossip messages. Obviously this is somewhat finicky, so this
		// should be updated pretty liberally, but at least we'll know when changes occur.
		// This test serves as a helpful additional full_stack_target seed.

		let test = super::gossip_exchange_seed();

		let logger = Arc::new(TrackingLogger { lines: Mutex::new(HashMap::new()) });
		super::do_test(&test, &(Arc::clone(&logger) as Arc<dyn Logger>));

		let log_entries = logger.lines.lock().unwrap();
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Sending message to all peers except Some(PublicKey(0000000000000000000000000000000000000000000000000000000000000002ff00000000000000000000000000000000000000000000000000000000000002)) or the announced channel's counterparties: ChannelAnnouncement { node_signature_1: 3026020200b202200303030303030303030303030303030303030303030303030303030303030303, node_signature_2: 3026020200b202200202020202020202020202020202020202020202020202020202020202020202, bitcoin_signature_1: 3026020200b202200303030303030303030303030303030303030303030303030303030303030303, bitcoin_signature_2: 3026020200b202200202020202020202020202020202020202020202020202020202020202020202, contents: UnsignedChannelAnnouncement { features: [], chain_hash: 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000, short_channel_id: 42, node_id_1: NodeId(030303030303030303030303030303030303030303030303030303030303030303), node_id_2: NodeId(020202020202020202020202020202020202020202020202020202020202020202), bitcoin_key_1: NodeId(030303030303030303030303030303030303030303030303030303030303030303), bitcoin_key_2: NodeId(020202020202020202020202020202020202020202020202020202020202020202), excess_data: [] } }".to_string())), Some(&1));
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Sending message to all peers except Some(PublicKey(0000000000000000000000000000000000000000000000000000000000000002ff00000000000000000000000000000000000000000000000000000000000002)): ChannelUpdate { signature: 3026020200a602200303030303030303030303030303030303030303030303030303030303030303, contents: UnsignedChannelUpdate { chain_hash: 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000, short_channel_id: 42, timestamp: 44, message_flags: 1, channel_flags: 0, cltv_expiry_delta: 40, htlc_minimum_msat: 0, htlc_maximum_msat: 100000000, fee_base_msat: 0, fee_proportional_millionths: 0, excess_data: [] } }".to_string())), Some(&1));
		assert_eq!(log_entries.get(&("lightning::ln::peer_handler".to_string(), "Sending message to all peers except Some(PublicKey(0000000000000000000000000000000000000000000000000000000000000002ff00000000000000000000000000000000000000000000000000000000000002)) or the announced node: NodeAnnouncement { signature: 302502012802200303030303030303030303030303030303030303030303030303030303030303, contents: UnsignedNodeAnnouncement { features: [], timestamp: 43, node_id: NodeId(030303030303030303030303030303030303030303030303030303030303030303), rgb: [0, 0, 0], alias: NodeAlias([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), addresses: [], excess_address_data: [], excess_data: [] } }".to_string())), Some(&1));
	}
}
