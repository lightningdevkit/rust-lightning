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
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError};
use crate::message_queue::MessageQueue;
use crate::prelude::{new_hash_map, new_hash_set, HashMap, HashSet};
use crate::sync::{Arc, Mutex, RwLock};
use crate::utils;

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;
use lightning::util::persist::KVStore;

use bitcoin::secp256k1::PublicKey;

struct PeerState {
	pending_list_protocols_requests: HashSet<LSPSRequestId>,
}

impl PeerState {
	fn new() -> Self {
		let pending_list_protocols_requests = new_hash_set();
		Self { pending_list_protocols_requests }
	}
}

/// A message handler capable of sending and handling bLIP-50 / LSPS0 messages.
pub struct LSPS0ClientHandler<ES: EntropySource, K: KVStore + Clone> {
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
}

impl<ES: EntropySource, K: KVStore + Clone> LSPS0ClientHandler<ES, K> {
	/// Returns a new instance of [`LSPS0ClientHandler`].
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue<K>>,
	) -> Self {
		Self {
			entropy_source,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
		}
	}

	/// Calls bLIP-50 / LSPS0's `list_protocols`.
	///
	/// Please refer to the [bLIP-50 / LSPS0
	/// specifcation](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
	/// for more information.
	pub fn list_protocols(&self, counterparty_node_id: &PublicKey) {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let request_id = utils::generate_request_id(&self.entropy_source);

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(*counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_list_protocols_requests.insert(request_id.clone());
		}

		let msg = LSPS0Message::Request(
			request_id,
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

impl<ES: EntropySource, K: KVStore + Clone> LSPSProtocolMessageHandler
	for LSPS0ClientHandler<ES, K>
{
	type ProtocolMessage = LSPS0Message;
	const PROTOCOL_NUMBER: Option<u16> = None;

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS0Message::Response(request_id, response) => {
				{
					let outer_state_lock = self.per_peer_state.read().unwrap();
					match outer_state_lock.get(counterparty_node_id) {
						Some(inner_state_lock) => {
							let mut peer_state = inner_state_lock.lock().unwrap();
							if !peer_state.pending_list_protocols_requests.remove(&request_id) {
								return Err(LightningError {
									err: format!(
										"Received list_protocols response for an unknown request: {:?}",
										request_id
									),
									action: ErrorAction::IgnoreAndLog(Level::Debug),
								});
							}
						},
						None => {
							return Err(LightningError {
								err: format!(
									"Received list_protocols response from unknown peer: {}",
									counterparty_node_id
								),
								action: ErrorAction::IgnoreAndLog(Level::Debug),
							})
						},
					}
				}
				self.handle_response(response, counterparty_node_id)
			},
			LSPS0Message::Request(..) => {
				debug_assert!(
					false,
					"Client handler received LSPS0 request message. This should never happen."
				);
				Err(LightningError { err: format!("Client handler received LSPS0 request message from node {}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
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

	use crate::events::LiquidityEvent;
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

	fn setup_handler() -> (
		Arc<LSPS0ClientHandler<Arc<TestEntropy>, Arc<KVStoreSyncWrapper<Arc<TestStore>>>>>,
		Arc<EventQueue<Arc<KVStoreSyncWrapper<Arc<TestStore>>>>>,
		PublicKey,
		PublicKey,
	) {
		let notifier = Arc::new(Notifier::new());
		let pending_messages = Arc::new(MessageQueue::new(notifier));
		let entropy_source = Arc::new(TestEntropy {});
		let kv_store = Arc::new(KVStoreSyncWrapper(Arc::new(TestStore::new(false))));
		let persist_notifier = Arc::new(Notifier::new());
		let event_queue = Arc::new(EventQueue::new(VecDeque::new(), kv_store, persist_notifier));

		let handler = Arc::new(LSPS0ClientHandler::new(
			entropy_source,
			Arc::clone(&pending_messages),
			Arc::clone(&event_queue),
		));

		let counterparty_node_id = utils::parse_pubkey(
			"027100442c3b79f606f80f322d98d499eefcb060599efc5d4ecb00209c2cb54190",
		)
		.unwrap();
		let other_node_id = utils::parse_pubkey(
			"02c0ded160a4a70d71058509b647949a938924d3a6e109c6eb6aee8e2bb27dc79c",
		)
		.unwrap();

		(handler, event_queue, counterparty_node_id, other_node_id)
	}

	fn list_protocols_response(request_id: LSPSRequestId) -> LSPS0Message {
		LSPS0Message::Response(
			request_id,
			LSPS0Response::ListProtocols(LSPS0ListProtocolsResponse { protocols: vec![1, 2, 5] }),
		)
	}

	#[test]
	fn response_from_unqueried_peer_is_ignored() {
		let (handler, event_queue, counterparty_node_id, other_node_id) = setup_handler();

		handler.list_protocols(&counterparty_node_id);

		// The unqueried peer never saw the request, so its response must be rejected
		// even though it carries a request id pending for the queried peer.
		assert!(handler
			.handle_message(
				list_protocols_response(LSPSRequestId(
					"00000000000000000000000000000000".to_string()
				)),
				&other_node_id,
			)
			.is_err());
		assert!(event_queue.get_and_clear_pending_events().is_empty());
	}

	#[test]
	fn response_with_unknown_request_id_is_ignored() {
		let (handler, event_queue, counterparty_node_id, _) = setup_handler();

		handler.list_protocols(&counterparty_node_id);

		assert!(handler
			.handle_message(
				list_protocols_response(LSPSRequestId("unknown-id".to_string())),
				&counterparty_node_id,
			)
			.is_err());
		assert!(event_queue.get_and_clear_pending_events().is_empty());

		// The pending request is still tracked, so the genuine response is processed.
		assert!(handler
			.handle_message(
				list_protocols_response(LSPSRequestId(
					"00000000000000000000000000000000".to_string()
				)),
				&counterparty_node_id,
			)
			.is_ok());

		match event_queue.get_and_clear_pending_events().as_slice() {
			[LiquidityEvent::LSPS0Client(LSPS0ClientEvent::ListProtocolsResponse {
				counterparty_node_id: event_peer,
				..
			})] => assert_eq!(*event_peer, counterparty_node_id),
			_ => panic!("Unexpected event"),
		}
	}
}
