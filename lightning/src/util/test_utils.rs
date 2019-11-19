use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use chain::transaction::OutPoint;
use chain::keysinterface;
use ln::channelmonitor;
use ln::msgs;
use ln::msgs::LocalFeatures;
use ln::msgs::{LightningError};
use ln::channelmonitor::HTLCUpdate;
use util::events;
use util::logger::{Logger, Level, Record};
use util::ser::{ReadableArgs, Writer};

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin::network::constants::Network;

use secp256k1::{SecretKey, PublicKey};

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Arc,Mutex};
use std::{mem};

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

pub struct TestChannelMonitor {
	pub added_monitors: Mutex<Vec<(OutPoint, channelmonitor::ChannelMonitor)>>,
	pub simple_monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint>>,
	pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
}
impl TestChannelMonitor {
	pub fn new(chain_monitor: Arc<chaininterface::ChainWatchInterface>, broadcaster: Arc<chaininterface::BroadcasterInterface>, logger: Arc<Logger>, fee_estimator: Arc<chaininterface::FeeEstimator>) -> Self {
		Self {
			added_monitors: Mutex::new(Vec::new()),
			simple_monitor: channelmonitor::SimpleManyChannelMonitor::new(chain_monitor, broadcaster, logger, fee_estimator),
			update_ret: Mutex::new(Ok(())),
		}
	}
}
impl channelmonitor::ManyChannelMonitor for TestChannelMonitor {
	fn add_update_monitor(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let mut w = TestVecWriter(Vec::new());
		monitor.write_for_disk(&mut w).unwrap();
		assert!(<(Sha256dHash, channelmonitor::ChannelMonitor)>::read(
				&mut ::std::io::Cursor::new(&w.0), Arc::new(TestLogger::new())).unwrap().1 == monitor);
		w.0.clear();
		monitor.write_for_watchtower(&mut w).unwrap(); // This at least shouldn't crash...
		self.added_monitors.lock().unwrap().push((funding_txo, monitor.clone()));
		assert!(self.simple_monitor.add_update_monitor(funding_txo, monitor).is_ok());
		self.update_ret.lock().unwrap().clone()
	}

	fn fetch_pending_htlc_updated(&self) -> Vec<HTLCUpdate> {
		return self.simple_monitor.fetch_pending_htlc_updated();
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
	fn handle_open_channel(&self, _their_node_id: &PublicKey, _their_local_features: LocalFeatures, _msg: &msgs::OpenChannel) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_accept_channel(&self, _their_node_id: &PublicKey, _their_local_features: LocalFeatures, _msg: &msgs::AcceptChannel) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_funding_created(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingCreated) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_funding_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingSigned) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_funding_locked(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingLocked) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_shutdown(&self, _their_node_id: &PublicKey, _msg: &msgs::Shutdown) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_closing_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::ClosingSigned) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_update_add_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateAddHTLC) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_update_fulfill_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFulfillHTLC) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_update_fail_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailHTLC) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_update_fail_malformed_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_commitment_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::CommitmentSigned) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_revoke_and_ack(&self, _their_node_id: &PublicKey, _msg: &msgs::RevokeAndACK) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_update_fee(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFee) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_announcement_signatures(&self, _their_node_id: &PublicKey, _msg: &msgs::AnnouncementSignatures) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn handle_channel_reestablish(&self, _their_node_id: &PublicKey, _msg: &msgs::ChannelReestablish) -> Result<(), LightningError> {
		Err(LightningError { err: "", action: msgs::ErrorAction::IgnoreError })
	}
	fn peer_disconnected(&self, _their_node_id: &PublicKey, _no_connection_possible: bool) {}
	fn peer_connected(&self, _their_node_id: &PublicKey) {}
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
}

pub struct TestLogger {
	level: Level,
	id: String,
}

impl TestLogger {
	pub fn new() -> TestLogger {
		Self::with_id("".to_owned())
	}
	pub fn with_id(id: String) -> TestLogger {
		TestLogger {
			level: Level::Trace,
			id,
		}
	}
	pub fn enable(&mut self, level: Level) {
		self.level = level;
	}
}

impl Logger for TestLogger {
	fn log(&self, record: &Record) {
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
	fn get_node_secret(&self) -> SecretKey { self.backing.get_node_secret() }
	fn get_destination_script(&self) -> Script { self.backing.get_destination_script() }
	fn get_shutdown_pubkey(&self) -> PublicKey { self.backing.get_shutdown_pubkey() }
	fn get_channel_keys(&self, inbound: bool) -> keysinterface::ChannelKeys { self.backing.get_channel_keys(inbound) }

	fn get_session_key(&self) -> SecretKey {
		match *self.override_session_priv.lock().unwrap() {
			Some(key) => key.clone(),
			None => self.backing.get_session_key()
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
