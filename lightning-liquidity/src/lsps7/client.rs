// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main bLIP-57 / LSPS7 client object, [`LSPS7ClientHandler`].

use super::event::LSPS7ClientEvent;
use super::msgs::{
	LSPS7CreateOrderRequest, LSPS7CreateOrderResponse, LSPS7GetExtendableChannelsRequest,
	LSPS7GetExtendableChannelsResponse, LSPS7GetOrderRequest, LSPS7Message, LSPS7OrderId,
	LSPS7Request, LSPS7Response,
};
use crate::message_queue::MessageQueue;

use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError};
use crate::prelude::{new_hash_map, HashMap, HashSet};
use crate::sync::{Arc, Mutex, RwLock};

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;
use lightning::util::persist::KVStore;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Address;

use alloc::string::String;

/// Client-side configuration options for bLIP-57 / LSPS7 channel lease extensions.
#[derive(Clone, Debug)]
pub struct LSPS7ClientConfig {}

#[derive(Default)]
struct PeerState {
	pending_get_extendable_channels_requests: HashSet<LSPSRequestId>,
	pending_create_order_requests: HashSet<LSPSRequestId>,
	pending_get_order_requests: HashSet<LSPSRequestId>,
}

/// The main object allowing to send and receive bLIP-57 / LSPS7 messages.
pub struct LSPS7ClientHandler<ES: EntropySource, K: KVStore + Clone> {
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	_config: LSPS7ClientConfig,
}

impl<ES: EntropySource, K: KVStore + Clone> LSPS7ClientHandler<ES, K> {
	/// Constructs an `LSPS7ClientHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>,
		pending_events: Arc<EventQueue<K>>, config: LSPS7ClientConfig,
	) -> Self {
		Self {
			entropy_source,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
			_config: config,
		}
	}

	/// Request the list of channels eligible for lease extension from the LSP.
	///
	/// The user will receive the LSP's response via an [`ExtendableChannelsReady`] event.
	///
	/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
	///
	/// Returns the used [`LSPSRequestId`], which will be returned via [`ExtendableChannelsReady`].
	///
	/// [`ExtendableChannelsReady`]: crate::lsps7::event::LSPS7ClientEvent::ExtendableChannelsReady
	pub fn request_extendable_channels(&self, counterparty_node_id: PublicKey) -> LSPSRequestId {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let request_id = crate::utils::generate_request_id(&self.entropy_source);
		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::default()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_get_extendable_channels_requests.insert(request_id.clone());
		}

		let request = LSPS7Request::GetExtendableChannels(LSPS7GetExtendableChannelsRequest {});
		let msg = LSPS7Message::Request(request_id.clone(), request).into();
		message_queue_notifier.enqueue(&counterparty_node_id, msg);
		request_id
	}

	fn handle_get_extendable_channels_response(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		result: LSPS7GetExtendableChannelsResponse,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.write().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if !peer_state_lock.pending_get_extendable_channels_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_extendable_channels response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				event_queue_notifier.enqueue(LSPS7ClientEvent::ExtendableChannelsReady {
					counterparty_node_id: *counterparty_node_id,
					extendable_channels: result.extendable_channels,
					request_id,
				});
				Ok(())
			},
			None => Err(LightningError {
				err: format!(
					"Received get_extendable_channels response from unknown peer: {}",
					counterparty_node_id
				),
				action: ErrorAction::IgnoreAndLog(Level::Debug),
			}),
		}
	}

	fn handle_get_extendable_channels_error(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		error: LSPSResponseError,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if !peer_state_lock.pending_get_extendable_channels_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_extendable_channels error for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				event_queue_notifier.enqueue(LSPS7ClientEvent::ExtendableChannelsRequestFailed {
					request_id: request_id.clone(),
					counterparty_node_id: *counterparty_node_id,
					error: error.clone(),
				});

				Err(LightningError {
					err: format!(
						"Received get_extendable_channels error response for request {:?}: {:?}",
						request_id, error
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received get_extendable_channels error response from an unknown counterparty {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}
	}

	/// Creates a channel lease extension order with the connected LSP given its
	/// `counterparty_node_id`.
	///
	/// The client agrees to paying the extension fees according to the provided parameters.
	pub fn create_order(
		&self, counterparty_node_id: &PublicKey, short_channel_id: String,
		channel_extension_expiry_blocks: u32, token: Option<String>,
		refund_onchain_address: Option<Address>,
	) -> LSPSRequestId {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock = outer_state_lock
			.entry(*counterparty_node_id)
			.or_insert(Mutex::new(PeerState::default()));
		let mut peer_state_lock = inner_state_lock.lock().unwrap();

		let request_id = crate::utils::generate_request_id(&self.entropy_source);
		let request = LSPS7Request::CreateOrder(LSPS7CreateOrderRequest {
			short_channel_id,
			channel_extension_expiry_blocks,
			token,
			refund_onchain_address,
		});
		let msg = LSPS7Message::Request(request_id.clone(), request).into();
		peer_state_lock.pending_create_order_requests.insert(request_id.clone());

		message_queue_notifier.enqueue(&counterparty_node_id, msg);

		request_id
	}

	fn handle_create_order_response(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		response: LSPS7CreateOrderResponse,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if !peer_state_lock.pending_create_order_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received create_order response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				event_queue_notifier.enqueue(LSPS7ClientEvent::OrderCreated {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					order_id: response.order_id,
					order_state: response.order_state,
					channel_extension_expiry_blocks: response.channel_extension_expiry_blocks,
					new_channel_expiry_block: response.new_channel_expiry_block,
					payment: response.payment,
					channel: response.channel,
				});
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received create_order response from unknown peer: {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				})
			},
		}

		Ok(())
	}

	fn handle_create_order_error(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		error: LSPSResponseError,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if !peer_state_lock.pending_create_order_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received create order error for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				event_queue_notifier.enqueue(LSPS7ClientEvent::OrderRequestFailed {
					request_id: request_id.clone(),
					counterparty_node_id: *counterparty_node_id,
					error: error.clone(),
				});

				Err(LightningError {
					err: format!(
						"Received create_order error response for request {:?}: {:?}",
						request_id, error
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received error response for a create order request from an unknown counterparty {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}
	}

	/// Queries the status of a pending extension order.
	///
	/// Upon success an [`LSPS7ClientEvent::OrderStatus`] event will be emitted.
	///
	/// [`LSPS7ClientEvent::OrderStatus`]: crate::lsps7::event::LSPS7ClientEvent::OrderStatus
	pub fn check_order_status(
		&self, counterparty_node_id: &PublicKey, order_id: LSPS7OrderId,
	) -> LSPSRequestId {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock = outer_state_lock
			.entry(*counterparty_node_id)
			.or_insert(Mutex::new(PeerState::default()));
		let mut peer_state_lock = inner_state_lock.lock().unwrap();

		let request_id = crate::utils::generate_request_id(&self.entropy_source);
		peer_state_lock.pending_get_order_requests.insert(request_id.clone());

		let request = LSPS7Request::GetOrder(LSPS7GetOrderRequest { order_id: order_id.clone() });
		let msg = LSPS7Message::Request(request_id.clone(), request).into();

		message_queue_notifier.enqueue(&counterparty_node_id, msg);

		request_id
	}

	fn handle_get_order_response(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		response: LSPS7CreateOrderResponse,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if !peer_state_lock.pending_get_order_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_order response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				event_queue_notifier.enqueue(LSPS7ClientEvent::OrderStatus {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					order_id: response.order_id,
					order_state: response.order_state,
					channel_extension_expiry_blocks: response.channel_extension_expiry_blocks,
					new_channel_expiry_block: response.new_channel_expiry_block,
					payment: response.payment,
					channel: response.channel,
				});
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received get_order response from unknown peer: {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				})
			},
		}

		Ok(())
	}

	fn handle_get_order_error(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		error: LSPSResponseError,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if !peer_state_lock.pending_get_order_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get order error for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				event_queue_notifier.enqueue(LSPS7ClientEvent::OrderRequestFailed {
					request_id: request_id.clone(),
					counterparty_node_id: *counterparty_node_id,
					error: error.clone(),
				});

				Err(LightningError {
					err: format!(
						"Received get_order error response for request {:?}: {:?}",
						request_id, error
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received error response for a get order request from an unknown counterparty ({:?})",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}
	}
}

impl<ES: EntropySource, K: KVStore + Clone> LSPSProtocolMessageHandler
	for LSPS7ClientHandler<ES, K>
{
	type ProtocolMessage = LSPS7Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(7);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS7Message::Response(request_id, response) => match response {
				LSPS7Response::GetExtendableChannels(params) => self
					.handle_get_extendable_channels_response(
						request_id,
						counterparty_node_id,
						params,
					),
				LSPS7Response::GetExtendableChannelsError(error) => self
					.handle_get_extendable_channels_error(request_id, counterparty_node_id, error),
				LSPS7Response::CreateOrder(params) => {
					self.handle_create_order_response(request_id, counterparty_node_id, params)
				},
				LSPS7Response::CreateOrderError(error) => {
					self.handle_create_order_error(request_id, counterparty_node_id, error)
				},
				LSPS7Response::GetOrder(params) => {
					self.handle_get_order_response(request_id, counterparty_node_id, params)
				},
				LSPS7Response::GetOrderError(error) => {
					self.handle_get_order_error(request_id, counterparty_node_id, error)
				},
			},
			_ => {
				debug_assert!(
					false,
					"Client handler received LSPS7 request message. This should never happen."
				);
				Err(LightningError {
					err: format!(
						"Client handler received LSPS7 request message from node {:?}. This should never happen.",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})
			},
		}
	}
}
