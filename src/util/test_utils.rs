use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use chain::transaction::OutPoint;
use ln::channelmonitor;
use ln::msgs;
use ln::msgs::{HandleError};
use util::events;
use util::logger::{Logger, Level, Record};
use util::ser::{ReadableArgs, Writer};

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::util::hash::Sha256dHash;

use secp256k1::PublicKey;

use std::sync::{Arc,Mutex};
use std::{mem};

struct VecWriter(Vec<u8>);
impl Writer for VecWriter {
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
	pub fn new(chain_monitor: Arc<chaininterface::ChainWatchInterface>, broadcaster: Arc<chaininterface::BroadcasterInterface>, logger: Arc<Logger>) -> Self {
		Self {
			added_monitors: Mutex::new(Vec::new()),
			simple_monitor: channelmonitor::SimpleManyChannelMonitor::new(chain_monitor, broadcaster, logger),
			update_ret: Mutex::new(Ok(())),
		}
	}
}
impl channelmonitor::ManyChannelMonitor for TestChannelMonitor {
	fn add_update_monitor(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		let mut w = VecWriter(Vec::new());
		monitor.write_for_disk(&mut w).unwrap();
		assert!(<(Sha256dHash, channelmonitor::ChannelMonitor)>::read(
				&mut ::std::io::Cursor::new(&w.0), Arc::new(TestLogger::new())).unwrap().1 == monitor);
		w.0.clear();
		monitor.write_for_watchtower(&mut w).unwrap(); // This at least shouldn't crash...
		self.added_monitors.lock().unwrap().push((funding_txo, monitor.clone()));
		assert!(self.simple_monitor.add_update_monitor(funding_txo, monitor).is_ok());
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
	fn handle_open_channel(&self, _their_node_id: &PublicKey, _msg: &msgs::OpenChannel) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_accept_channel(&self, _their_node_id: &PublicKey, _msg: &msgs::AcceptChannel) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_funding_created(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingCreated) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_funding_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingSigned) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_funding_locked(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingLocked) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_shutdown(&self, _their_node_id: &PublicKey, _msg: &msgs::Shutdown) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_closing_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::ClosingSigned) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_add_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateAddHTLC) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_fulfill_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFulfillHTLC) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_fail_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailHTLC) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_fail_malformed_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_commitment_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::CommitmentSigned) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_revoke_and_ack(&self, _their_node_id: &PublicKey, _msg: &msgs::RevokeAndACK) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_fee(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFee) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_announcement_signatures(&self, _their_node_id: &PublicKey, _msg: &msgs::AnnouncementSignatures) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_channel_reestablish(&self, _their_node_id: &PublicKey, _msg: &msgs::ChannelReestablish) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
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
	fn handle_node_announcement(&self, _msg: &msgs::NodeAnnouncement) -> Result<bool, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_channel_announcement(&self, _msg: &msgs::ChannelAnnouncement) -> Result<bool, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_channel_update(&self, _msg: &msgs::ChannelUpdate) -> Result<bool, HandleError> {
		Err(HandleError { err: "", action: None })
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
}

impl TestLogger {
	pub fn new() -> TestLogger {
		TestLogger {
			level: Level::Trace,
		}
	}
	pub fn enable(&mut self, level: Level) {
		self.level = level;
	}
}

impl Logger for TestLogger {
	fn log(&self, record: &Record) {
		if self.level >= record.level {
			println!("{:<5} [{} : {}, {}] {}", record.level.to_string(), record.module_path, record.file, record.line, record.args);
		}
	}
}
