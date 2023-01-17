use lightning::chain;
use lightning::chain::{chainmonitor, channelmonitor};
use lightning::chain::chainmonitor::MonitorUpdateId;
use lightning::chain::transaction::OutPoint;
use lightning::util::enforcing_trait_impls::EnforcingSigner;

use std::sync::Mutex;

pub struct TestPersister {
	pub update_ret: Mutex<chain::ChannelMonitorUpdateStatus>,
}
impl chainmonitor::Persist<EnforcingSigner> for TestPersister {
	fn persist_new_channel(&self, _funding_txo: OutPoint, _data: &channelmonitor::ChannelMonitor<EnforcingSigner>, _update_id: MonitorUpdateId) -> chain::ChannelMonitorUpdateStatus {
		self.update_ret.lock().unwrap().clone()
	}

	fn update_persisted_channel(&self, _funding_txo: OutPoint, _update: Option<&channelmonitor::ChannelMonitorUpdate>, _data: &channelmonitor::ChannelMonitor<EnforcingSigner>, _update_id: MonitorUpdateId) -> chain::ChannelMonitorUpdateStatus {
		self.update_ret.lock().unwrap().clone()
	}
}
