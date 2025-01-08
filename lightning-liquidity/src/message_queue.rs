//! Holds types and traits used to implement message queues for [`LSPSMessage`]s.

use crate::lsps0::ser::LSPSMessage;
use crate::prelude::{Box, Vec, VecDeque};
use crate::sync::{Arc, Mutex, RwLock};

use core::sync::atomic::{AtomicBool, Ordering};

use bitcoin::secp256k1::PublicKey;

/// The default [`MessageQueue`] Implementation used by [`LiquidityManager`].
///
/// [`LiquidityManager`]: crate::LiquidityManager
pub struct MessageQueue {
	queue: Mutex<VecDeque<(PublicKey, LSPSMessage)>>,
	#[cfg(feature = "std")]
	process_msgs_callback: Arc<RwLock<Option<Box<dyn Fn() + Send + Sync + 'static>>>>,
	#[cfg(not(feature = "std"))]
	process_msgs_callback: Arc<RwLock<Option<Box<dyn Fn() + 'static>>>>,
	needs_processing: Arc<AtomicBool>,
}

impl MessageQueue {
	pub(crate) fn new() -> Self {
		let queue = Mutex::new(VecDeque::new());
		let process_msgs_callback = Arc::new(RwLock::new(None));
		let needs_processing = Arc::new(AtomicBool::new(false));
		Self { queue, process_msgs_callback, needs_processing }
	}

	#[cfg(feature = "std")]
	pub(crate) fn set_process_msgs_callback(&self, callback: impl Fn() + Send + Sync + 'static) {
		*self.process_msgs_callback.write().unwrap() = Some(Box::new(callback));
	}

	#[cfg(not(feature = "std"))]
	pub(crate) fn set_process_msgs_callback(&self, callback: impl Fn() + 'static) {
		*self.process_msgs_callback.write().unwrap() = Some(Box::new(callback));
	}

	pub(crate) fn get_and_clear_pending_msgs(&self) -> Vec<(PublicKey, LSPSMessage)> {
		self.queue.lock().unwrap().drain(..).collect()
	}

	pub(crate) fn enqueue(&self, counterparty_node_id: &PublicKey, msg: LSPSMessage) {
		let mut queue = self.queue.lock().unwrap();
		queue.push_back((*counterparty_node_id, msg));
		self.needs_processing.store(true, Ordering::Release);
	}

	// Returns a [`MessageQueueNotifierGuard`] that will call `process_msgs_callback` when dropped.
	pub(crate) fn notifier(&self) -> MessageQueueNotifierGuard {
		MessageQueueNotifierGuard {
			process_msgs_callback: Arc::clone(&self.process_msgs_callback),
			needs_processing: Arc::clone(&self.needs_processing),
		}
	}
}

// A guard type that will call the `process_msgs_callback` when dropped.
#[must_use]
pub(crate) struct MessageQueueNotifierGuard {
	#[cfg(feature = "std")]
	process_msgs_callback: Arc<RwLock<Option<Box<dyn Fn() + Send + Sync + 'static>>>>,
	#[cfg(not(feature = "std"))]
	process_msgs_callback: Arc<RwLock<Option<Box<dyn Fn() + 'static>>>>,
	needs_processing: Arc<AtomicBool>,
}

impl Drop for MessageQueueNotifierGuard {
	fn drop(&mut self) {
		if self
			.needs_processing
			.compare_exchange(true, false, Ordering::Acquire, Ordering::Relaxed)
			.is_ok()
		{
			if let Some(process_msgs_callback) = self.process_msgs_callback.read().unwrap().as_ref()
			{
				(process_msgs_callback)()
			}
		}
	}
}
