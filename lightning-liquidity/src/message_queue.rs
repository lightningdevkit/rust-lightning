//! Holds types and traits used to implement message queues for [`LSPSMessage`]s.

use crate::lsps0::ser::LSPSMessage;
use crate::prelude::{Box, Vec, VecDeque};
use crate::sync::{Mutex, RwLock};

use bitcoin::secp256k1::PublicKey;

/// The default [`MessageQueue`] Implementation used by [`LiquidityManager`].
///
/// [`LiquidityManager`]: crate::LiquidityManager
pub struct MessageQueue {
	queue: Mutex<VecDeque<(PublicKey, LSPSMessage)>>,
	#[cfg(feature = "std")]
	process_msgs_callback: RwLock<Option<Box<dyn Fn() + Send + Sync + 'static>>>,
	#[cfg(feature = "no-std")]
	process_msgs_callback: RwLock<Option<Box<dyn Fn() + 'static>>>,
}

impl MessageQueue {
	pub(crate) fn new() -> Self {
		let queue = Mutex::new(VecDeque::new());
		let process_msgs_callback = RwLock::new(None);
		Self { queue, process_msgs_callback }
	}

	#[cfg(feature = "std")]
	pub(crate) fn set_process_msgs_callback(&self, callback: impl Fn() + Send + Sync + 'static) {
		*self.process_msgs_callback.write().unwrap() = Some(Box::new(callback));
	}

	#[cfg(feature = "no-std")]
	pub(crate) fn set_process_msgs_callback(&self, callback: impl Fn() + 'static) {
		*self.process_msgs_callback.write().unwrap() = Some(Box::new(callback));
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
			(process_msgs_callback)()
		}
	}
}
