use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use ln::channelmonitor;
use ln::msgs::HandleError;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::util::hash::Sha256dHash;

use std::sync::{Arc,Mutex};

pub struct TestFeeEstimator {
	pub sat_per_vbyte: u64,
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_vbyte(&self, _confirmation_target: ConfirmationTarget) -> u64 {
		self.sat_per_vbyte
	}
}

pub struct TestChannelMonitor {
	pub added_monitors: Mutex<Vec<((Sha256dHash, u16), channelmonitor::ChannelMonitor)>>,
	pub simple_monitor: Arc<channelmonitor::SimpleManyChannelMonitor<(Sha256dHash, u16)>>,
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
	fn add_update_monitor(&self, funding_txo: (Sha256dHash, u16), monitor: channelmonitor::ChannelMonitor) -> Result<(), HandleError> {
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
