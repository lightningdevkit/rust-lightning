// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use chain;
use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use chain::chainmonitor;
use chain::channelmonitor;
use chain::channelmonitor::MonitorEvent;
use chain::transaction::OutPoint;
use chain::keysinterface;
use ln::features::{ChannelFeatures, InitFeatures};
use ln::msgs;
use ln::msgs::OptionalField;
use util::enforcing_trait_impls::{EnforcingSigner, INITIAL_REVOKED_COMMITMENT_NUMBER};
use util::events;
use util::logger::{Logger, Level, Record};
use util::ser::{Readable, ReadableArgs, Writer, Writeable};

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;
use bitcoin::hash_types::{BlockHash, Txid};

use bitcoin::secp256k1::{SecretKey, PublicKey, Secp256k1, Signature};

use regex;

use std::time::Duration;
use std::sync::{Mutex, Arc};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{cmp, mem};
use std::collections::{HashMap, HashSet};
use chain::keysinterface::InMemorySigner;

pub struct TestVecWriter(pub Vec<u8>);
impl Writer for TestVecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
	fn size_hint(&mut self, size: usize) {
		self.0.reserve_exact(size);
	}
}

pub struct TestFeeEstimator {
	pub sat_per_kw: u32,
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, _confirmation_target: ConfirmationTarget) -> u32 {
		self.sat_per_kw
	}
}

pub struct OnlyReadsKeysInterface {}
impl keysinterface::KeysInterface for OnlyReadsKeysInterface {
	type Signer = EnforcingSigner;

	fn get_node_secret(&self) -> SecretKey { unreachable!(); }
	fn get_destination_script(&self) -> Script { unreachable!(); }
	fn get_shutdown_pubkey(&self) -> PublicKey { unreachable!(); }
	fn get_channel_signer(&self, _inbound: bool, _channel_value_satoshis: u64) -> EnforcingSigner { unreachable!(); }
	fn get_secure_random_bytes(&self) -> [u8; 32] { [0; 32] }

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, msgs::DecodeError> {
		EnforcingSigner::read(&mut std::io::Cursor::new(reader))
	}
}

pub struct TestChainMonitor<'a> {
	pub added_monitors: Mutex<Vec<(OutPoint, channelmonitor::ChannelMonitor<EnforcingSigner>)>>,
	pub latest_monitor_update_id: Mutex<HashMap<[u8; 32], (OutPoint, u64)>>,
	pub chain_monitor: chainmonitor::ChainMonitor<EnforcingSigner, &'a TestChainSource, &'a chaininterface::BroadcasterInterface, &'a TestFeeEstimator, &'a TestLogger, &'a channelmonitor::Persist<EnforcingSigner>>,
	pub keys_manager: &'a TestKeysInterface,
	pub update_ret: Mutex<Option<Result<(), channelmonitor::ChannelMonitorUpdateErr>>>,
	// If this is set to Some(), after the next return, we'll always return this until update_ret
	// is changed:
	pub next_update_ret: Mutex<Option<Result<(), channelmonitor::ChannelMonitorUpdateErr>>>,
}
impl<'a> TestChainMonitor<'a> {
	pub fn new(chain_source: Option<&'a TestChainSource>, broadcaster: &'a chaininterface::BroadcasterInterface, logger: &'a TestLogger, fee_estimator: &'a TestFeeEstimator, persister: &'a channelmonitor::Persist<EnforcingSigner>, keys_manager: &'a TestKeysInterface) -> Self {
		Self {
			added_monitors: Mutex::new(Vec::new()),
			latest_monitor_update_id: Mutex::new(HashMap::new()),
			chain_monitor: chainmonitor::ChainMonitor::new(chain_source, broadcaster, logger, fee_estimator, persister),
			keys_manager,
			update_ret: Mutex::new(None),
			next_update_ret: Mutex::new(None),
		}
	}
}
impl<'a> chain::Watch<EnforcingSigner> for TestChainMonitor<'a> {
	fn watch_channel(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor<EnforcingSigner>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let mut w = TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<EnforcingSigner>)>::read(
			&mut ::std::io::Cursor::new(&w.0), self.keys_manager).unwrap().1;
		assert!(new_monitor == monitor);
		self.latest_monitor_update_id.lock().unwrap().insert(funding_txo.to_channel_id(), (funding_txo, monitor.get_latest_update_id()));
		self.added_monitors.lock().unwrap().push((funding_txo, monitor));
		let watch_res = self.chain_monitor.watch_channel(funding_txo, new_monitor);

		let ret = self.update_ret.lock().unwrap().clone();
		if let Some(next_ret) = self.next_update_ret.lock().unwrap().take() {
			*self.update_ret.lock().unwrap() = Some(next_ret);
		}
		if ret.is_some() {
			assert!(watch_res.is_ok());
			return ret.unwrap();
		}
		watch_res
	}

	fn update_channel(&self, funding_txo: OutPoint, update: channelmonitor::ChannelMonitorUpdate) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		// Every monitor update should survive roundtrip
		let mut w = TestVecWriter(Vec::new());
		update.write(&mut w).unwrap();
		assert!(channelmonitor::ChannelMonitorUpdate::read(
				&mut ::std::io::Cursor::new(&w.0)).unwrap() == update);

		self.latest_monitor_update_id.lock().unwrap().insert(funding_txo.to_channel_id(), (funding_txo, update.update_id));
		let update_res = self.chain_monitor.update_channel(funding_txo, update);
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let monitors = self.chain_monitor.monitors.read().unwrap();
		let monitor = monitors.get(&funding_txo).unwrap();
		w.0.clear();
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<EnforcingSigner>)>::read(
			&mut ::std::io::Cursor::new(&w.0), self.keys_manager).unwrap().1;
		assert!(new_monitor == *monitor);
		self.added_monitors.lock().unwrap().push((funding_txo, new_monitor));

		let ret = self.update_ret.lock().unwrap().clone();
		if let Some(next_ret) = self.next_update_ret.lock().unwrap().take() {
			*self.update_ret.lock().unwrap() = Some(next_ret);
		}
		if ret.is_some() {
			assert!(update_res.is_ok());
			return ret.unwrap();
		}
		update_res
	}

	fn release_pending_monitor_events(&self) -> Vec<MonitorEvent> {
		return self.chain_monitor.release_pending_monitor_events();
	}
}

pub struct TestPersister {
	pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>
}
impl TestPersister {
	pub fn new() -> Self {
		Self {
			update_ret: Mutex::new(Ok(()))
		}
	}

	pub fn set_update_ret(&self, ret: Result<(), channelmonitor::ChannelMonitorUpdateErr>) {
		*self.update_ret.lock().unwrap() = ret;
	}
}
impl channelmonitor::Persist<EnforcingSigner> for TestPersister {
	fn persist_new_channel(&self, _funding_txo: OutPoint, _data: &channelmonitor::ChannelMonitor<EnforcingSigner>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		self.update_ret.lock().unwrap().clone()
	}

	fn update_persisted_channel(&self, _funding_txo: OutPoint, _update: &channelmonitor::ChannelMonitorUpdate, _data: &channelmonitor::ChannelMonitor<EnforcingSigner>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		self.update_ret.lock().unwrap().clone()
	}
}

pub struct TestBroadcaster {
	pub txn_broadcasted: Mutex<Vec<Transaction>>,
}
impl chaininterface::BroadcasterInterface for TestBroadcaster {
	fn broadcast_transaction(&self, tx: &Transaction) {
		self.txn_broadcasted.lock().unwrap().push(tx.clone());
	}
}

pub struct TestChannelMessageHandler {
	pub pending_events: Mutex<Vec<events::MessageSendEvent>>,
}

impl TestChannelMessageHandler {
	pub fn new() -> Self {
		TestChannelMessageHandler {
			pending_events: Mutex::new(Vec::new()),
		}
	}
}

impl msgs::ChannelMessageHandler for TestChannelMessageHandler {
	fn handle_open_channel(&self, _their_node_id: &PublicKey, _their_features: InitFeatures, _msg: &msgs::OpenChannel) {}
	fn handle_accept_channel(&self, _their_node_id: &PublicKey, _their_features: InitFeatures, _msg: &msgs::AcceptChannel) {}
	fn handle_funding_created(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingCreated) {}
	fn handle_funding_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingSigned) {}
	fn handle_funding_locked(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingLocked) {}
	fn handle_shutdown(&self, _their_node_id: &PublicKey, _their_features: &InitFeatures, _msg: &msgs::Shutdown) {}
	fn handle_closing_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::ClosingSigned) {}
	fn handle_update_add_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateAddHTLC) {}
	fn handle_update_fulfill_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFulfillHTLC) {}
	fn handle_update_fail_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailHTLC) {}
	fn handle_update_fail_malformed_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailMalformedHTLC) {}
	fn handle_commitment_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::CommitmentSigned) {}
	fn handle_revoke_and_ack(&self, _their_node_id: &PublicKey, _msg: &msgs::RevokeAndACK) {}
	fn handle_update_fee(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFee) {}
	fn handle_announcement_signatures(&self, _their_node_id: &PublicKey, _msg: &msgs::AnnouncementSignatures) {}
	fn handle_channel_reestablish(&self, _their_node_id: &PublicKey, _msg: &msgs::ChannelReestablish) {}
	fn peer_disconnected(&self, _their_node_id: &PublicKey, _no_connection_possible: bool) {}
	fn peer_connected(&self, _their_node_id: &PublicKey, _msg: &msgs::Init) {}
	fn handle_error(&self, _their_node_id: &PublicKey, _msg: &msgs::ErrorMessage) {}
}

impl events::MessageSendEventsProvider for TestChannelMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
		let mut pending_events = self.pending_events.lock().unwrap();
		let mut ret = Vec::new();
		mem::swap(&mut ret, &mut *pending_events);
		ret
	}
}

fn get_dummy_channel_announcement(short_chan_id: u64) -> msgs::ChannelAnnouncement {
	use bitcoin::secp256k1::ffi::Signature as FFISignature;
	let secp_ctx = Secp256k1::new();
	let network = Network::Testnet;
	let node_1_privkey = SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = SecretKey::from_slice(&[41; 32]).unwrap();
	let node_1_btckey = SecretKey::from_slice(&[40; 32]).unwrap();
	let node_2_btckey = SecretKey::from_slice(&[39; 32]).unwrap();
	let unsigned_ann = msgs::UnsignedChannelAnnouncement {
		features: ChannelFeatures::known(),
		chain_hash: genesis_block(network).header.block_hash(),
		short_channel_id: short_chan_id,
		node_id_1: PublicKey::from_secret_key(&secp_ctx, &node_1_privkey),
		node_id_2: PublicKey::from_secret_key(&secp_ctx, &node_2_privkey),
		bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, &node_1_btckey),
		bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, &node_2_btckey),
		excess_data: Vec::new(),
	};

	unsafe {
		msgs::ChannelAnnouncement {
			node_signature_1: Signature::from(FFISignature::new()),
			node_signature_2: Signature::from(FFISignature::new()),
			bitcoin_signature_1: Signature::from(FFISignature::new()),
			bitcoin_signature_2: Signature::from(FFISignature::new()),
			contents: unsigned_ann,
		}
	}
}

fn get_dummy_channel_update(short_chan_id: u64) -> msgs::ChannelUpdate {
	use bitcoin::secp256k1::ffi::Signature as FFISignature;
	let network = Network::Testnet;
	msgs::ChannelUpdate {
		signature: Signature::from(unsafe { FFISignature::new() }),
		contents: msgs::UnsignedChannelUpdate {
			chain_hash: genesis_block(network).header.block_hash(),
			short_channel_id: short_chan_id,
			timestamp: 0,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: vec![],
		}
	}
}

pub struct TestRoutingMessageHandler {
	pub chan_upds_recvd: AtomicUsize,
	pub chan_anns_recvd: AtomicUsize,
	pub chan_anns_sent: AtomicUsize,
	pub request_full_sync: AtomicBool,
}

impl TestRoutingMessageHandler {
	pub fn new() -> Self {
		TestRoutingMessageHandler {
			chan_upds_recvd: AtomicUsize::new(0),
			chan_anns_recvd: AtomicUsize::new(0),
			chan_anns_sent: AtomicUsize::new(0),
			request_full_sync: AtomicBool::new(false),
		}
	}
}
impl msgs::RoutingMessageHandler for TestRoutingMessageHandler {
	fn handle_node_announcement(&self, _msg: &msgs::NodeAnnouncement) -> Result<bool, msgs::LightningError> {
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_announcement(&self, _msg: &msgs::ChannelAnnouncement) -> Result<bool, msgs::LightningError> {
		self.chan_anns_recvd.fetch_add(1, Ordering::AcqRel);
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_update(&self, _msg: &msgs::ChannelUpdate) -> Result<bool, msgs::LightningError> {
		self.chan_upds_recvd.fetch_add(1, Ordering::AcqRel);
		Err(msgs::LightningError { err: "".to_owned(), action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_htlc_fail_channel_update(&self, _update: &msgs::HTLCFailChannelUpdate) {}
	fn get_next_channel_announcements(&self, starting_point: u64, batch_amount: u8) -> Vec<(msgs::ChannelAnnouncement, Option<msgs::ChannelUpdate>, Option<msgs::ChannelUpdate>)> {
		let mut chan_anns = Vec::new();
		const TOTAL_UPDS: u64 = 100;
		let end: u64 = cmp::min(starting_point + batch_amount as u64, TOTAL_UPDS - self.chan_anns_sent.load(Ordering::Acquire) as u64);
		for i in starting_point..end {
			let chan_upd_1 = get_dummy_channel_update(i);
			let chan_upd_2 = get_dummy_channel_update(i);
			let chan_ann = get_dummy_channel_announcement(i);

			chan_anns.push((chan_ann, Some(chan_upd_1), Some(chan_upd_2)));
		}

		self.chan_anns_sent.fetch_add(chan_anns.len(), Ordering::AcqRel);
		chan_anns
	}

	fn get_next_node_announcements(&self, _starting_point: Option<&PublicKey>, _batch_amount: u8) -> Vec<msgs::NodeAnnouncement> {
		Vec::new()
	}

	fn sync_routing_table(&self, _their_node_id: &PublicKey, _init_msg: &msgs::Init) {}

	fn handle_reply_channel_range(&self, _their_node_id: &PublicKey, _msg: msgs::ReplyChannelRange) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_reply_short_channel_ids_end(&self, _their_node_id: &PublicKey, _msg: msgs::ReplyShortChannelIdsEnd) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_query_channel_range(&self, _their_node_id: &PublicKey, _msg: msgs::QueryChannelRange) -> Result<(), msgs::LightningError> {
		Ok(())
	}

	fn handle_query_short_channel_ids(&self, _their_node_id: &PublicKey, _msg: msgs::QueryShortChannelIds) -> Result<(), msgs::LightningError> {
		Ok(())
	}
}

impl events::MessageSendEventsProvider for TestRoutingMessageHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<events::MessageSendEvent> {
		vec![]
	}
}

pub struct TestLogger {
	level: Level,
	id: String,
	pub lines: Mutex<HashMap<(String, String), usize>>,
}

impl TestLogger {
	pub fn new() -> TestLogger {
		Self::with_id("".to_owned())
	}
	pub fn with_id(id: String) -> TestLogger {
		TestLogger {
			level: Level::Trace,
			id,
			lines: Mutex::new(HashMap::new())
		}
	}
	pub fn enable(&mut self, level: Level) {
		self.level = level;
	}
	pub fn assert_log(&self, module: String, line: String, count: usize) {
		let log_entries = self.lines.lock().unwrap();
		assert_eq!(log_entries.get(&(module, line)), Some(&count));
	}

	/// Search for the number of occurrence of the logged lines which
	/// 1. belongs to the specified module and
	/// 2. contains `line` in it.
	/// And asserts if the number of occurrences is the same with the given `count`
	pub fn assert_log_contains(&self, module: String, line: String, count: usize) {
		let log_entries = self.lines.lock().unwrap();
		let l: usize = log_entries.iter().filter(|&(&(ref m, ref l), _c)| {
			m == &module && l.contains(line.as_str())
		}).map(|(_, c) | { c }).sum();
		assert_eq!(l, count)
	}

    /// Search for the number of occurrences of logged lines which
    /// 1. belong to the specified module and
    /// 2. match the given regex pattern.
    /// Assert that the number of occurrences equals the given `count`
	pub fn assert_log_regex(&self, module: String, pattern: regex::Regex, count: usize) {
		let log_entries = self.lines.lock().unwrap();
		let l: usize = log_entries.iter().filter(|&(&(ref m, ref l), _c)| {
			m == &module && pattern.is_match(&l)
		}).map(|(_, c) | { c }).sum();
		assert_eq!(l, count)
	}
}

impl Logger for TestLogger {
	fn log(&self, record: &Record) {
		*self.lines.lock().unwrap().entry((record.module_path.to_string(), format!("{}", record.args))).or_insert(0) += 1;
		if self.level >= record.level {
			println!("{:<5} {} [{} : {}, {}] {}", record.level.to_string(), self.id, record.module_path, record.file, record.line, record.args);
		}
	}
}

pub struct TestKeysInterface {
	pub backing: keysinterface::KeysManager,
	pub override_session_priv: Mutex<Option<[u8; 32]>>,
	pub override_channel_id_priv: Mutex<Option<[u8; 32]>>,
	pub disable_revocation_policy_check: bool,
	revoked_commitments: Mutex<HashMap<[u8;32], Arc<Mutex<u64>>>>,
}

impl keysinterface::KeysInterface for TestKeysInterface {
	type Signer = EnforcingSigner;

	fn get_node_secret(&self) -> SecretKey { self.backing.get_node_secret() }
	fn get_destination_script(&self) -> Script { self.backing.get_destination_script() }
	fn get_shutdown_pubkey(&self) -> PublicKey { self.backing.get_shutdown_pubkey() }
	fn get_channel_signer(&self, inbound: bool, channel_value_satoshis: u64) -> EnforcingSigner {
		let keys = self.backing.get_channel_signer(inbound, channel_value_satoshis);
		let revoked_commitment = self.make_revoked_commitment_cell(keys.commitment_seed);
		EnforcingSigner::new_with_revoked(keys, revoked_commitment, self.disable_revocation_policy_check)
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let override_channel_id = self.override_channel_id_priv.lock().unwrap();
		let override_session_key = self.override_session_priv.lock().unwrap();
		if override_channel_id.is_some() && override_session_key.is_some() {
			panic!("We don't know which override key to use!");
		}
		if let Some(key) = &*override_channel_id {
			return *key;
		}
		if let Some(key) = &*override_session_key {
			return *key;
		}
		self.backing.get_secure_random_bytes()
	}

	fn read_chan_signer(&self, buffer: &[u8]) -> Result<Self::Signer, msgs::DecodeError> {
		let mut reader = std::io::Cursor::new(buffer);

		let inner: InMemorySigner = Readable::read(&mut reader)?;
		let revoked_commitment = self.make_revoked_commitment_cell(inner.commitment_seed);

		let last_commitment_number = Readable::read(&mut reader)?;

		Ok(EnforcingSigner {
			inner,
			last_commitment_number: Arc::new(Mutex::new(last_commitment_number)),
			revoked_commitment,
			disable_revocation_policy_check: self.disable_revocation_policy_check,
		})
	}
}


impl TestKeysInterface {
	pub fn new(seed: &[u8; 32], network: Network) -> Self {
		let now = Duration::from_secs(genesis_block(network).header.time as u64);
		Self {
			backing: keysinterface::KeysManager::new(seed, now.as_secs(), now.subsec_nanos()),
			override_session_priv: Mutex::new(None),
			override_channel_id_priv: Mutex::new(None),
			disable_revocation_policy_check: false,
			revoked_commitments: Mutex::new(HashMap::new()),
		}
	}
	pub fn derive_channel_keys(&self, channel_value_satoshis: u64, id: &[u8; 32]) -> EnforcingSigner {
		let keys = self.backing.derive_channel_keys(channel_value_satoshis, id);
		let revoked_commitment = self.make_revoked_commitment_cell(keys.commitment_seed);
		EnforcingSigner::new_with_revoked(keys, revoked_commitment, self.disable_revocation_policy_check)
	}

	fn make_revoked_commitment_cell(&self, commitment_seed: [u8; 32]) -> Arc<Mutex<u64>> {
		let mut revoked_commitments = self.revoked_commitments.lock().unwrap();
		if !revoked_commitments.contains_key(&commitment_seed) {
			revoked_commitments.insert(commitment_seed, Arc::new(Mutex::new(INITIAL_REVOKED_COMMITMENT_NUMBER)));
		}
		let cell = revoked_commitments.get(&commitment_seed).unwrap();
		Arc::clone(cell)
	}
}

pub struct TestChainSource {
	pub genesis_hash: BlockHash,
	pub utxo_ret: Mutex<Result<TxOut, chain::AccessError>>,
	pub watched_txn: Mutex<HashSet<(Txid, Script)>>,
	pub watched_outputs: Mutex<HashSet<(OutPoint, Script)>>,
}

impl TestChainSource {
	pub fn new(network: Network) -> Self {
		let script_pubkey = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
		Self {
			genesis_hash: genesis_block(network).block_hash(),
			utxo_ret: Mutex::new(Ok(TxOut { value: u64::max_value(), script_pubkey })),
			watched_txn: Mutex::new(HashSet::new()),
			watched_outputs: Mutex::new(HashSet::new()),
		}
	}
}

impl chain::Access for TestChainSource {
	fn get_utxo(&self, genesis_hash: &BlockHash, _short_channel_id: u64) -> Result<TxOut, chain::AccessError> {
		if self.genesis_hash != *genesis_hash {
			return Err(chain::AccessError::UnknownChain);
		}

		self.utxo_ret.lock().unwrap().clone()
	}
}

impl chain::Filter for TestChainSource {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.watched_txn.lock().unwrap().insert((*txid, script_pubkey.clone()));
	}

	fn register_output(&self, outpoint: &OutPoint, script_pubkey: &Script) {
		self.watched_outputs.lock().unwrap().insert((*outpoint, script_pubkey.clone()));
	}
}
