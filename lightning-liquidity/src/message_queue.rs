//! Holds types and traits used to implement message queues for [`LSPSMessage`]s.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::lsps0::ser::LSPSMessage;
use crate::sync::{Mutex, RwLock};

use bitcoin::secp256k1::PublicKey;

/// The default [`MessageQueue`] Implementation used by [`LiquidityManager`].
///
/// [`LiquidityManager`]: crate::LiquidityManager
pub struct MessageQueue {
	queue: Mutex<VecDeque<(PublicKey, LSPSMessage)>>,
	process_msgs_callback: RwLock<Option<Box<dyn ProcessMessagesCallback>>>,
}

impl MessageQueue {
	pub(crate) fn new() -> Self {
		let queue = Mutex::new(VecDeque::new());
		let process_msgs_callback = RwLock::new(None);
		Self { queue, process_msgs_callback }
	}

	pub(crate) fn set_process_msgs_callback(&self, callback: Box<dyn ProcessMessagesCallback>) {
		*self.process_msgs_callback.write().unwrap() = Some(callback);
	}

	pub(crate) fn get_and_clear_pending_msgs(&self) -> Vec<(PublicKey, LSPSMessage)> {
		self.queue.lock().unwrap().drain(..).collect()
	}

	pub(crate) fn enqueue(&self, counterparty_node_id: &PublicKey, msg: LSPSMessage) {
		{
			let mut queue = self.queue.lock().unwrap();
			queue.push_back((*counterparty_node_id, msg));
		}

		if let Some(process_msgs_callback) = self.process_msgs_callback.read().unwrap().as_ref() {
			process_msgs_callback.call()
		}
	}
}

macro_rules! define_callback { ($($bounds: path),*) => {
/// A callback which will be called to trigger network message processing.
///
/// Usually, this should call [`PeerManager::process_events`].
///
/// [`PeerManager::process_events`]: lightning::ln::peer_handler::PeerManager::process_events
pub trait ProcessMessagesCallback : $($bounds +)* {
	/// The method which is called.
	fn call(&self);
}

impl<F: Fn() $(+ $bounds)*> ProcessMessagesCallback for F {
	fn call(&self) { (self)(); }
}
} }

#[cfg(feature = "std")]
define_callback!(Send, Sync);
#[cfg(not(feature = "std"))]
define_callback!();
