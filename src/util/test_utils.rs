use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use chain::transaction::OutPoint;
use ln::channelmonitor;
use ln::msgs;
use ln::msgs::{HandleError};
use util::events;

use bitcoin::blockdata::transaction::Transaction;

use secp256k1::PublicKey;

use std::sync::{Arc,Mutex};
use std::{mem};

pub struct TestFeeEstimator {
	pub sat_per_vbyte: u64,
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_vbyte(&self, _confirmation_target: ConfirmationTarget) -> u64 {
		self.sat_per_vbyte
	}
}

pub struct TestChannelMonitor {
	pub added_monitors: Mutex<Vec<(OutPoint, channelmonitor::ChannelMonitor)>>,
	pub simple_monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint>>,
}
impl TestChannelMonitor {
	pub fn new(chain_monitor: Arc<chaininterface::ChainWatchInterface>, broadcaster: Arc<chaininterface::BroadcasterInterface>) -> Self {
		Self {
			added_monitors: Mutex::new(Vec::new()),
			simple_monitor: channelmonitor::SimpleManyChannelMonitor::new(chain_monitor, broadcaster),
		}
	}
}
impl channelmonitor::ManyChannelMonitor for TestChannelMonitor {
	fn add_update_monitor(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		// At every point where we get a monitor update, we should be able to send a useful monitor
		// to a watchtower and disk...
		assert!(channelmonitor::ChannelMonitor::deserialize(&monitor.serialize_for_disk()[..]).unwrap() == monitor);
		monitor.serialize_for_watchtower(); // This at least shouldn't crash...
		self.added_monitors.lock().unwrap().push((funding_txo, monitor.clone()));
		self.simple_monitor.add_update_monitor(funding_txo, monitor)
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
	pub pending_events: Mutex<Vec<events::Event>>,
}

impl TestChannelMessageHandler {
	pub fn new() -> Self {
		TestChannelMessageHandler {
			pending_events: Mutex::new(Vec::new()),
		}
	}
}

impl msgs::ChannelMessageHandler for TestChannelMessageHandler {

	fn handle_open_channel(&self, _their_node_id: &PublicKey, _msg: &msgs::OpenChannel) -> Result<msgs::AcceptChannel, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_accept_channel(&self, _their_node_id: &PublicKey, _msg: &msgs::AcceptChannel) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_funding_created(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingCreated) -> Result<msgs::FundingSigned, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_funding_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingSigned) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_funding_locked(&self, _their_node_id: &PublicKey, _msg: &msgs::FundingLocked) -> Result<Option<msgs::AnnouncementSignatures>, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_shutdown(&self, _their_node_id: &PublicKey, _msg: &msgs::Shutdown) -> Result<(Option<msgs::Shutdown>, Option<msgs::ClosingSigned>), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_closing_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::ClosingSigned) -> Result<Option<msgs::ClosingSigned>, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_add_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateAddHTLC) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_fulfill_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFulfillHTLC) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_fail_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailHTLC) -> Result<Option<msgs::HTLCFailChannelUpdate>, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_fail_malformed_htlc(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFailMalformedHTLC) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_commitment_signed(&self, _their_node_id: &PublicKey, _msg: &msgs::CommitmentSigned) -> Result<(msgs::RevokeAndACK, Option<msgs::CommitmentSigned>), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_revoke_and_ack(&self, _their_node_id: &PublicKey, _msg: &msgs::RevokeAndACK) -> Result<Option<msgs::CommitmentUpdate>, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_update_fee(&self, _their_node_id: &PublicKey, _msg: &msgs::UpdateFee) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_announcement_signatures(&self, _their_node_id: &PublicKey, _msg: &msgs::AnnouncementSignatures) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn peer_disconnected(&self, _their_node_id: &PublicKey, _no_connection_possible: bool) {}
}

impl events::EventsProvider for TestChannelMessageHandler {
	fn get_and_clear_pending_events(&self) -> Vec<events::Event> {
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
	fn handle_node_announcement(&self, _msg: &msgs::NodeAnnouncement) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_channel_announcement(&self, _msg: &msgs::ChannelAnnouncement) -> Result<bool, HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_channel_update(&self, _msg: &msgs::ChannelUpdate) -> Result<(), HandleError> {
		Err(HandleError { err: "", action: None })
	}
	fn handle_htlc_fail_channel_update(&self, _update: &msgs::HTLCFailChannelUpdate) {}
}
