use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use ln::channelmonitor;
use ln::msgs::HandleError;

use bitcoin::util::hash::Sha256dHash;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;

use std::sync::Weak;

pub struct TestFeeEstimator {
	pub sat_per_vbyte: u64,
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_vbyte(&self, _confirmation_target: ConfirmationTarget) -> u64 {
		self.sat_per_vbyte
	}
}

pub struct TestWatchInterface {
	pub watch_util: chaininterface::ChainWatchInterfaceUtil,
}
impl chaininterface::ChainWatchInterface for TestWatchInterface {
	fn install_watch_script(&self, _script_pub_key: Script) {
		unimplemented!();
	}
	fn install_watch_outpoint(&self, _outpoint: (Sha256dHash, u32)) {
		unimplemented!();
	}
	fn watch_all_txn(&self) {
		unimplemented!();
	}
	fn broadcast_transaction(&self, _tx: &Transaction) {
		unimplemented!();
	}
	fn register_listener(&self, listener: Weak<chaininterface::ChainListener>) {
		self.watch_util.register_listener(listener);
	}
}
impl TestWatchInterface {
	pub fn new() -> TestWatchInterface {
		TestWatchInterface {
			watch_util: chaininterface::ChainWatchInterfaceUtil::new(),
		}
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
