use lightning::chain;
use lightning::chain::{chainmonitor, channelmonitor};
use lightning::ln::types::ChannelId;
use lightning::util::persist::MonitorName;
use lightning::util::test_channel_signer::TestChannelSigner;

use std::collections::HashMap;
use std::sync::Mutex;

pub struct TestPersister {
	pub update_ret: Mutex<chain::ChannelMonitorUpdateStatus>,
	latest_monitors: Mutex<HashMap<ChannelId, channelmonitor::ChannelMonitor<TestChannelSigner>>>,
}
impl TestPersister {
	pub fn new(update_ret: chain::ChannelMonitorUpdateStatus) -> Self {
		Self {
			update_ret: Mutex::new(update_ret),
			latest_monitors: Mutex::new(HashMap::new()),
		}
	}

	pub fn take_latest_monitor(
		&self, channel_id: &ChannelId,
	) -> channelmonitor::ChannelMonitor<TestChannelSigner> {
		self.latest_monitors.lock().unwrap().remove(channel_id)
			.expect("Persister should have monitor for channel")
	}
}
impl chainmonitor::Persist<TestChannelSigner> for TestPersister {
	fn persist_new_channel(
		&self, _monitor_name: MonitorName,
		data: &channelmonitor::ChannelMonitor<TestChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		self.latest_monitors.lock().unwrap().insert(data.channel_id(), data.clone());
		self.update_ret.lock().unwrap().clone()
	}

	fn update_persisted_channel(
		&self, _monitor_name: MonitorName, _update: Option<&channelmonitor::ChannelMonitorUpdate>,
		data: &channelmonitor::ChannelMonitor<TestChannelSigner>,
	) -> chain::ChannelMonitorUpdateStatus {
		self.latest_monitors.lock().unwrap().insert(data.channel_id(), data.clone());
		self.update_ret.lock().unwrap().clone()
	}

	fn archive_persisted_channel(&self, _monitor_name: MonitorName) {}
}
