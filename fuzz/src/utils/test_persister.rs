use lightning::chain;
use lightning::chain::{chainmonitor, channelmonitor};
use lightning::util::persist::MonitorName;
use lightning::util::test_channel_signer::TestChannelSigner;

use std::sync::Mutex;

pub struct TestPersister {
	pub update_ret: Mutex<chain::ChannelMonitorUpdateStatus>,
}
impl chainmonitor::Persist<TestChannelSigner> for TestPersister {
	fn persist_new_channel(
		&self, _monitor_name: MonitorName,
		_data: &channelmonitor::ChannelMonitor<TestChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		self.update_ret.lock().unwrap().clone()
	}

	fn update_persisted_channel(
		&self, _monitor_name: MonitorName, _update: Option<&channelmonitor::ChannelMonitorUpdate>,
		_data: &channelmonitor::ChannelMonitor<TestChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		self.update_ret.lock().unwrap().clone()
	}

	fn archive_persisted_channel(&self, _monitor_name: MonitorName) {}
}
