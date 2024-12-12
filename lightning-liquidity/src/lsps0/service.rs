// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main LSPS0 server-side object, [`LSPS0ServiceHandler`].
//!
//! Please refer to the [LSPS0
//! specifcation](https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS0) for more
//! information.

use crate::lsps0::msgs::{LSPS0Message, LSPS0Request, LSPS0Response, ListProtocolsResponse};
use crate::lsps0::ser::{ProtocolMessageHandler, RequestId};
use crate::message_queue::MessageQueue;
use crate::prelude::Vec;
use crate::sync::Arc;

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;

use bitcoin::secp256k1::PublicKey;

/// The main server-side object allowing to send and receive LSPS0 messages.
pub struct LSPS0ServiceHandler {
	pending_messages: Arc<MessageQueue>,
	protocols: Vec<u16>,
}

impl LSPS0ServiceHandler {
	/// Returns a new instance of [`LSPS0ServiceHandler`].
	pub(crate) fn new(protocols: Vec<u16>, pending_messages: Arc<MessageQueue>) -> Self {
		Self { protocols, pending_messages }
	}

	fn handle_request(
		&self, request_id: RequestId, request: LSPS0Request, counterparty_node_id: &PublicKey,
	) -> Result<(), lightning::ln::msgs::LightningError> {
		match request {
			LSPS0Request::ListProtocols(_) => {
				let msg = LSPS0Message::Response(
					request_id,
					LSPS0Response::ListProtocols(ListProtocolsResponse {
						protocols: self.protocols.clone(),
					}),
				);
				self.pending_messages.enqueue(counterparty_node_id, msg.into());
				Ok(())
			},
		}
	}
}

impl ProtocolMessageHandler for LSPS0ServiceHandler {
	type ProtocolMessage = LSPS0Message;
	const PROTOCOL_NUMBER: Option<u16> = None;

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS0Message::Request(request_id, request) => {
				self.handle_request(request_id, request, counterparty_node_id)
			},
			LSPS0Message::Response(..) => {
				debug_assert!(
					false,
					"Service handler received LSPS0 response message. This should never happen."
				);
				Err(LightningError { err: format!("Service handler received LSPS0 response message from node {:?}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
			},
		}
	}
}

#[cfg(test)]
mod tests {

	use crate::lsps0::msgs::ListProtocolsRequest;
	use crate::lsps0::ser::LSPSMessage;
	use crate::tests::utils;
	use alloc::string::ToString;
	use alloc::sync::Arc;

	use super::*;

	#[test]
	fn test_handle_list_protocols_request() {
		let protocols: Vec<u16> = vec![];
		let pending_messages = Arc::new(MessageQueue::new());

		let lsps0_handler = Arc::new(LSPS0ServiceHandler::new(protocols, pending_messages.clone()));

		let list_protocols_request = LSPS0Message::Request(
			RequestId("xyz123".to_string()),
			LSPS0Request::ListProtocols(ListProtocolsRequest {}),
		);
		let counterparty_node_id = utils::parse_pubkey(
			"027100442c3b79f606f80f322d98d499eefcb060599efc5d4ecb00209c2cb54190",
		)
		.unwrap();

		lsps0_handler.handle_message(list_protocols_request, &counterparty_node_id).unwrap();
		let pending_messages = pending_messages.get_and_clear_pending_msgs();

		assert_eq!(pending_messages.len(), 1);

		let (pubkey, message) = &pending_messages[0];

		assert_eq!(*pubkey, counterparty_node_id);
		assert_eq!(
			*message,
			LSPSMessage::LSPS0(LSPS0Message::Response(
				RequestId("xyz123".to_string()),
				LSPS0Response::ListProtocols(ListProtocolsResponse { protocols: vec![] })
			))
		);
	}
}
