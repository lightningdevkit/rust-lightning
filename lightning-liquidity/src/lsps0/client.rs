//! Contains the main LSPS2 client-side object, [`LSPS0ClientHandler`].
//!
//! Please refer to the [LSPS0
//! specifcation](https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS0) for more
//! information.

use crate::events::{Event, EventQueue};
use crate::lsps0::event::LSPS0ClientEvent;
use crate::lsps0::msgs::{
	LSPS0Message, LSPS0Request, LSPS0Response, ListProtocolsRequest, ListProtocolsResponse,
};
use crate::lsps0::ser::{ProtocolMessageHandler, ResponseError};
use crate::message_queue::MessageQueue;
use crate::sync::Arc;
use crate::utils;

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;

use bitcoin::secp256k1::PublicKey;

use core::ops::Deref;

/// A message handler capable of sending and handling LSPS0 messages.
pub struct LSPS0ClientHandler<ES: Deref>
where
	ES::Target: EntropySource,
{
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
}

impl<ES: Deref> LSPS0ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	/// Returns a new instance of [`LSPS0ClientHandler`].
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
	) -> Self {
		Self { entropy_source, pending_messages, pending_events }
	}

	/// Calls LSPS0's `list_protocols`.
	///
	/// Please refer to the [LSPS0
	/// specifcation](https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS0#lsps-specification-support-query)
	/// for more information.
	pub fn list_protocols(&self, counterparty_node_id: &PublicKey) {
		let msg = LSPS0Message::Request(
			utils::generate_request_id(&self.entropy_source),
			LSPS0Request::ListProtocols(ListProtocolsRequest {}),
		);

		self.pending_messages.enqueue(counterparty_node_id, msg.into());
	}

	fn handle_response(
		&self, response: LSPS0Response, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match response {
			LSPS0Response::ListProtocols(ListProtocolsResponse { protocols }) => {
				self.pending_events.enqueue(Event::LSPS0Client(
					LSPS0ClientEvent::ListProtocolsResponse {
						counterparty_node_id: *counterparty_node_id,
						protocols,
					},
				));
				Ok(())
			},
			LSPS0Response::ListProtocolsError(ResponseError { code, message, data, .. }) => {
				Err(LightningError {
					err: format!(
						"ListProtocols error received. code = {}, message = {}, data = {:?}",
						code, message, data
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})
			},
		}
	}
}

impl<ES: Deref> ProtocolMessageHandler for LSPS0ClientHandler<ES>
where
	ES::Target: EntropySource,
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

	use alloc::string::ToString;
	use alloc::sync::Arc;

	use crate::lsps0::ser::{LSPSMessage, RequestId};
	use crate::tests::utils::{self, TestEntropy};

	use super::*;

	#[test]
	fn test_list_protocols() {
		let pending_messages = Arc::new(MessageQueue::new());
		let entropy_source = Arc::new(TestEntropy {});
		let event_queue = Arc::new(EventQueue::new());

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
				RequestId("00000000000000000000000000000000".to_string()),
				LSPS0Request::ListProtocols(ListProtocolsRequest {})
			))
		);
	}
}
