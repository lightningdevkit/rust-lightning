use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use ln::channelmonitor;
use ln::msgs::HandleError;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::util::hash::Sha256dHash;

use std::sync::Mutex;

pub struct TestFeeEstimator {
	pub sat_per_vbyte: u64,
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_vbyte(&self, _confirmation_target: ConfirmationTarget) -> u64 {
		self.sat_per_vbyte
	}
}

pub struct TestChannelMonitor {

}
impl channelmonitor::ManyChannelMonitor for TestChannelMonitor {
	fn add_update_monitor(&self, _funding_txo: (Sha256dHash, u16), _monitor: channelmonitor::ChannelMonitor) -> Result<(), HandleError> {
		//TODO!
		Ok(())
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
