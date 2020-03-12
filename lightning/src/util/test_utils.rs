use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use chain::transaction::OutPoint;
use chain::keysinterface;
use ln::channelmonitor;
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::LightningError;
use ln::channelmonitor::HTLCUpdate;
use util::enforcing_trait_impls::EnforcingChannelKeys;
use util::events;
use util::logger::{Logger, Level, Record};
use util::ser::{Readable, ReadableArgs, Writer, Writeable};

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin::network::constants::Network;

use secp256k1::{SecretKey, PublicKey};

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Arc,Mutex};
use std::{mem};
use std::collections::HashMap;

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
	pub sat_per_kw: u64,
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, _confirmation_target: ConfirmationTarget) -> u64 {
		self.sat_per_kw
	}
}

pub struct TestChannelMonitor<'a> {
	pub added_monitors: Mutex<Vec<(OutPoint, channelmonitor::ChannelMonitor<EnforcingChannelKeys>)>>,
	pub latest_monitor_update_id: Mutex<HashMap<[u8; 32], (OutPoint, u64)>>,
	pub simple_monitor: channelmonitor::SimpleManyChannelMonitor<OutPoint, EnforcingChannelKeys, &'a chaininterface::BroadcasterInterface, &'a TestFeeEstimator>,
	pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
}
impl<'a> TestChannelMonitor<'a> {
	pub fn new(chain_monitor: Arc<chaininterface::ChainWatchInterface>, broadcaster: &'a chaininterface::BroadcasterInterface, logger: Arc<Logger>, fee_estimator: &'a TestFeeEstimator) -> Self {
		Self {
			added_monitors: Mutex::new(Vec::new()),
			latest_monitor_update_id: Mutex::new(HashMap::new()),
			simple_monitor: channelmonitor::SimpleManyChannelMonitor::new(chain_monitor, broadcaster, logger, fee_estimator),
			update_ret: Mutex::new(Ok(())),
		}
	}
}
impl<'a> channelmonitor::ManyChannelMonitor<EnforcingChannelKeys> for TestChannelMonitor<'a> {
	fn add_monitor(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor<EnforcingChannelKeys>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let mut w = TestVecWriter(Vec::new());
		monitor.write_for_disk(&mut w).unwrap();
		let new_monitor = <(Sha256dHash, channelmonitor::ChannelMonitor<EnforcingChannelKeys>)>::read(
				&mut ::std::io::Cursor::new(&w.0), Arc::new(TestLogger::new())).unwrap().1;
		assert!(new_monitor == monitor);
		w.0.clear();
		monitor.write_for_watchtower(&mut w).unwrap(); // This at least shouldn't crash...
		self.latest_monitor_update_id.lock().unwrap().insert(funding_txo.to_channel_id(), (funding_txo, monitor.get_latest_update_id()));
		self.added_monitors.lock().unwrap().push((funding_txo, monitor));
		assert!(self.simple_monitor.add_monitor(funding_txo, new_monitor).is_ok());
		self.update_ret.lock().unwrap().clone()
	}

	fn update_monitor(&self, funding_txo: OutPoint, update: channelmonitor::ChannelMonitorUpdate) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		// Every monitor update should survive roundtrip
		let mut w = TestVecWriter(Vec::new());
		update.write(&mut w).unwrap();
		assert!(channelmonitor::ChannelMonitorUpdate::read(
				&mut ::std::io::Cursor::new(&w.0)).unwrap() == update);

		self.latest_monitor_update_id.lock().unwrap().insert(funding_txo.to_channel_id(), (funding_txo, update.update_id));
		assert!(self.simple_monitor.update_monitor(funding_txo, update).is_ok());
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let monitors = self.simple_monitor.monitors.lock().unwrap();
		let monitor = monitors.get(&funding_txo).unwrap();
		w.0.clear();
		monitor.write_for_disk(&mut w).unwrap();
		let new_monitor = <(Sha256dHash, channelmonitor::ChannelMonitor<EnforcingChannelKeys>)>::read(
				&mut ::std::io::Cursor::new(&w.0), Arc::new(TestLogger::new())).unwrap().1;
		assert!(new_monitor == *monitor);
		w.0.clear();
		monitor.write_for_watchtower(&mut w).unwrap(); // This at least shouldn't crash...
		self.added_monitors.lock().unwrap().push((funding_txo, new_monitor));
		self.update_ret.lock().unwrap().clone()
	}

	fn get_and_clear_pending_htlcs_updated(&self) -> Vec<HTLCUpdate> {
		return self.simple_monitor.get_and_clear_pending_htlcs_updated();
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
	fn handle_shutdown(&self, _their_node_id: &PublicKey, _msg: &msgs::Shutdown) {}
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

pub struct TestRoutingMessageHandler {}

impl TestRoutingMessageHandler {
	pub fn new() -> Self {
		TestRoutingMessageHandler {}
	}
}
impl msgs::RoutingMessageHandler for TestRoutingMessageHandler {
	fn handle_node_announcement(&self, _msg: &msgs::NodeAnnouncement) -> Result<bool, LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_announcement(&self, _msg: &msgs::ChannelAnnouncement) -> Result<bool, LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_update(&self, _msg: &msgs::ChannelUpdate) -> Result<bool, LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_htlc_fail_channel_update(&self, _update: &msgs::HTLCFailChannelUpdate) {}
	fn get_next_channel_announcements(&self, _starting_point: u64, _batch_amount: u8) -> Vec<(msgs::ChannelAnnouncement, msgs::ChannelUpdate,msgs::ChannelUpdate)> {
		Vec::new()
	}
	fn get_next_node_announcements(&self, _starting_point: Option<&PublicKey>, _batch_amount: u8) -> Vec<msgs::NodeAnnouncement> {
		Vec::new()
	}
	fn should_request_full_sync(&self, _node_id: &PublicKey) -> bool {
		true
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
	backing: keysinterface::KeysManager,
	pub override_session_priv: Mutex<Option<SecretKey>>,
	pub override_channel_id_priv: Mutex<Option<[u8; 32]>>,
}

impl keysinterface::KeysInterface for TestKeysInterface {
	type ChanKeySigner = EnforcingChannelKeys;

	fn get_node_secret(&self) -> SecretKey { self.backing.get_node_secret() }
	fn get_destination_script(&self) -> Script { self.backing.get_destination_script() }
	fn get_shutdown_pubkey(&self) -> PublicKey { self.backing.get_shutdown_pubkey() }
	fn get_channel_keys(&self, inbound: bool, channel_value_satoshis: u64) -> EnforcingChannelKeys {
		EnforcingChannelKeys::new(self.backing.get_channel_keys(inbound, channel_value_satoshis))
	}

	fn get_onion_rand(&self) -> (SecretKey, [u8; 32]) {
		match *self.override_session_priv.lock().unwrap() {
			Some(key) => (key.clone(), [0; 32]),
			None => self.backing.get_onion_rand()
		}
	}

	fn get_channel_id(&self) -> [u8; 32] {
		match *self.override_channel_id_priv.lock().unwrap() {
			Some(key) => key.clone(),
			None => self.backing.get_channel_id()
		}
	}
}

impl TestKeysInterface {
	pub fn new(seed: &[u8; 32], network: Network, logger: Arc<Logger>) -> Self {
		let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
		Self {
			backing: keysinterface::KeysManager::new(seed, network, logger, now.as_secs(), now.subsec_nanos()),
			override_session_priv: Mutex::new(None),
			override_channel_id_priv: Mutex::new(None),
		}
	}
}
