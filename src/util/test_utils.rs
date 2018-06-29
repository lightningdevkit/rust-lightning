use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use chain::transaction::OutPoint;
use ln::channelmonitor;

use bitcoin::blockdata::transaction::Transaction;

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
