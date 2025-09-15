//! Contains the main bLIP-50 / LSPS0 client-side object, [`LSPS0ClientHandler`].
//!
//! Please refer to the [bLIP-50 / LSPS0
//! specifcation](https://github.com/lightning/blips/blob/master/blip-0050.md) for more
//! information.

use crate::events::EventQueue;
use crate::lsps0::event::LSPS0ClientEvent;
use crate::lsps0::msgs::{
	LSPS0ListProtocolsRequest, LSPS0ListProtocolsResponse, LSPS0Message, LSPS0Request,
	LSPS0Response,
};
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSResponseError};
use crate::message_queue::MessageQueue;
use crate::sync::Arc;
use crate::utils;

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;
use lightning::util::persist::KVStore;

use bitcoin::secp256k1::PublicKey;

use core::ops::Deref;

/// A message handler capable of sending and handling bLIP-50 / LSPS0 messages.
pub struct LSPS0ClientHandler<ES: Deref, K: Deref + Clone>
where
	ES::Target: EntropySource,
	K::Target: KVStore,
{
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
}

impl<ES: Deref, K: Deref + Clone> LSPS0ClientHandler<ES, K>
where
	ES::Target: EntropySource,
	K::Target: KVStore,
{
	/// Returns a new instance of [`LSPS0ClientHandler`].
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue<K>>,
	) -> Self {
		Self { entropy_source, pending_messages, pending_events }
	}

	/// Calls bLIP-50 / LSPS0's `list_protocols`.
	///
	/// Please refer to the [bLIP-50 / LSPS0
	/// specifcation](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
	/// for more information.
	pub fn list_protocols(&self, counterparty_node_id: &PublicKey) {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let msg = LSPS0Message::Request(
			utils::generate_request_id(&self.entropy_source),
			LSPS0Request::ListProtocols(LSPS0ListProtocolsRequest {}),
		);

		message_queue_notifier.enqueue(counterparty_node_id, msg.into());
	}

	fn handle_response(
		&self, response: LSPS0Response, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		match response {
			LSPS0Response::ListProtocols(LSPS0ListProtocolsResponse { protocols }) => {
				event_queue_notifier.enqueue(LSPS0ClientEvent::ListProtocolsResponse {
					counterparty_node_id: *counterparty_node_id,
					protocols,
				});
				Ok(())
			},
			LSPS0Response::ListProtocolsError(LSPSResponseError {
				code, message, data, ..
			}) => Err(LightningError {
				err: format!(
					"ListProtocols error received. code = {}, message = {}, data = {:?}",
					code, message, data
				),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			}),
		}
	}
}

impl<ES: Deref, K: Deref + Clone> LSPSProtocolMessageHandler for LSPS0ClientHandler<ES, K>
where
	ES::Target: EntropySource,
	K::Target: KVStore,
{
	type ProtocolMessage = LSPS0Message;
	const PROTOCOL_NUMBER: Option<u16> = None;

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS0Message::Response(_, response) => {
				self.handle_response(response, counterparty_node_id)
			},
			LSPS0Message::Request(..) => {
				debug_assert!(
					false,
					"Client handler received LSPS0 request message. This should never happen."
				);
				Err(LightningError { err: format!("Client handler received LSPS0 request message from node {:?}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use alloc::collections::VecDeque;
	use alloc::string::ToString;
	use alloc::sync::Arc;

	use lightning::util::persist::KVStoreSyncWrapper;
	use lightning::util::test_utils::TestStore;
	use lightning::util::wakers::Notifier;

	use crate::lsps0::ser::{LSPSMessage, LSPSRequestId};
	use crate::tests::utils::{self, TestEntropy};

	use super::*;

	#[test]
	fn test_list_protocols() {
		let notifier = Arc::new(Notifier::new());
		let pending_messages = Arc::new(MessageQueue::new(notifier));
		let entropy_source = Arc::new(TestEntropy {});
		let kv_store = Arc::new(KVStoreSyncWrapper(Arc::new(TestStore::new(false))));
		let persist_notifier = Arc::new(Notifier::new());
		let event_queue = Arc::new(EventQueue::new(VecDeque::new(), kv_store, persist_notifier));

		let lsps0_handler = Arc::new(LSPS0ClientHandler::new(
			entropy_source,
			Arc::clone(&pending_messages),
			event_queue,
		));

		let counterparty_node_id = utils::parse_pubkey(
			"027100442c3b79f606f80f322d98d499eefcb060599efc5d4ecb00209c2cb54190",
		)
		.unwrap();

		lsps0_handler.list_protocols(&counterparty_node_id);
		let pending_messages = pending_messages.get_and_clear_pending_msgs();

		assert_eq!(pending_messages.len(), 1);

		let (pubkey, message) = &pending_messages[0];

		assert_eq!(*pubkey, counterparty_node_id);
		assert_eq!(
			*message,
			LSPSMessage::LSPS0(LSPS0Message::Request(
				LSPSRequestId("00000000000000000000000000000000".to_string()),
				LSPS0Request::ListProtocols(LSPS0ListProtocolsRequest {})
			))
		);
	}
}
