// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main bLIP-51 / LSPS1 client object, [`LSPS1ClientHandler`].

use super::event::LSPS1ClientEvent;
use super::msgs::{
	LSPS1CreateOrderRequest, LSPS1CreateOrderResponse, LSPS1GetInfoRequest, LSPS1GetInfoResponse,
	LSPS1GetOrderRequest, LSPS1Message, LSPS1OrderId, LSPS1OrderParams, LSPS1Request,
	LSPS1Response,
};
use crate::message_queue::MessageQueue;

use crate::events::EventQueue;
use crate::lsps0::ser::{ProtocolMessageHandler, RequestId, ResponseError};
use crate::prelude::{new_hash_map, HashMap, HashSet};
use crate::sync::{Arc, Mutex, RwLock};

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Address;

use core::ops::Deref;

/// Client-side configuration options for bLIP-51 / LSPS1 channel requests.
#[derive(Clone, Debug)]
pub struct LSPS1ClientConfig {
	/// The maximally allowed channel fees.
	pub max_channel_fees_msat: Option<u64>,
}

#[derive(Default)]
struct PeerState {
	pending_get_info_requests: HashSet<RequestId>,
	pending_create_order_requests: HashSet<RequestId>,
	pending_get_order_requests: HashSet<RequestId>,
}

/// The main object allowing to send and receive bLIP-51 / LSPS1 messages.
pub struct LSPS1ClientHandler<ES: Deref>
where
	ES::Target: EntropySource,
{
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	_config: LSPS1ClientConfig,
}

impl<ES: Deref> LSPS1ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	/// Constructs an `LSPS1ClientHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		config: LSPS1ClientConfig,
	) -> Self {
		Self {
			entropy_source,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
			_config: config,
		}
	}

	/// Request the supported options from the LSP.
	///
	/// The user will receive the LSP's response via an [`SupportedOptionsReady`] event.
	///
	/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
	///
	/// Returns the used [`RequestId`], which will be returned via [`SupportedOptionsReady`].
	///
	/// [`SupportedOptionsReady`]: crate::lsps1::event::LSPS1ClientEvent::SupportedOptionsReady
	pub fn request_supported_options(&self, counterparty_node_id: PublicKey) -> RequestId {
		let request_id = crate::utils::generate_request_id(&self.entropy_source);
		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::default()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_get_info_requests.insert(request_id.clone());
		}

		let request = LSPS1Request::GetInfo(LSPS1GetInfoRequest {});
		let msg = LSPS1Message::Request(request_id.clone(), request).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);
		request_id
	}

	fn handle_get_info_response(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey,
		result: LSPS1GetInfoResponse,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.write().unwrap();

		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if !peer_state_lock.pending_get_info_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_info response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				self.pending_events.enqueue(LSPS1ClientEvent::SupportedOptionsReady {
					counterparty_node_id: *counterparty_node_id,
					supported_options: result.options,
					request_id,
				});
				Ok(())
			},
			None => Err(LightningError {
				err: format!(
					"Received get_info response from unknown peer: {:?}",
					counterparty_node_id
				),
				action: ErrorAction::IgnoreAndLog(Level::Debug),
			}),
		}
	}

	fn handle_get_info_error(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, error: ResponseError,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if !peer_state_lock.pending_get_info_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_info error for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				self.pending_events.enqueue(LSPS1ClientEvent::SupportedOptionsRequestFailed {
					request_id: request_id.clone(),
					counterparty_node_id: *counterparty_node_id,
					error: error.clone(),
				});

				Err(LightningError {
					err: format!(
						"Received get_info error response for request {:?}: {:?}",
						request_id, error
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received get_info error response from an unknown counterparty ({:?})",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}
	}

	/// Places an order with the connected LSP given its `counterparty_node_id`.
	///
	/// The client agrees to paying channel fees according to the provided parameters.
	pub fn create_order(
		&self, counterparty_node_id: &PublicKey, order: LSPS1OrderParams,
		refund_onchain_address: Option<Address>,
	) -> RequestId {
		let (request_id, request_msg) = {
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(*counterparty_node_id)
				.or_insert(Mutex::new(PeerState::default()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();

			let request_id = crate::utils::generate_request_id(&self.entropy_source);
			let request = LSPS1Request::CreateOrder(LSPS1CreateOrderRequest {
				order,
				refund_onchain_address,
			});
			let msg = LSPS1Message::Request(request_id.clone(), request).into();
			peer_state_lock.pending_create_order_requests.insert(request_id.clone());

			(request_id, Some(msg))
		};

		if let Some(msg) = request_msg {
			self.pending_messages.enqueue(&counterparty_node_id, msg);
		}

		request_id
	}

	fn handle_create_order_response(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey,
		response: LSPS1CreateOrderResponse,
	) -> Result<(), LightningError> {
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

				self.pending_events.enqueue(LSPS1ClientEvent::OrderCreated {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					order_id: response.order_id,
					order: response.order,
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
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, error: ResponseError,
	) -> Result<(), LightningError> {
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

				self.pending_events.enqueue(LSPS1ClientEvent::OrderRequestFailed {
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
						"Received error response for a create order request from an unknown counterparty ({:?})",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}
	}

	/// Queries the status of a pending payment, i.e., whether a payment has been received by the LSP.
	///
	/// Upon success an [`LSPS1ClientEvent::OrderStatus`] event will be emitted.
	///
	/// [`LSPS1ClientEvent::OrderStatus`]: crate::lsps1::event::LSPS1ClientEvent::OrderStatus
	pub fn check_order_status(
		&self, counterparty_node_id: &PublicKey, order_id: LSPS1OrderId,
	) -> RequestId {
		let (request_id, request_msg) = {
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(*counterparty_node_id)
				.or_insert(Mutex::new(PeerState::default()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();

			let request_id = crate::utils::generate_request_id(&self.entropy_source);
			peer_state_lock.pending_get_order_requests.insert(request_id.clone());

			let request =
				LSPS1Request::GetOrder(LSPS1GetOrderRequest { order_id: order_id.clone() });
			let msg = LSPS1Message::Request(request_id.clone(), request).into();

			(request_id, Some(msg))
		};

		if let Some(msg) = request_msg {
			self.pending_messages.enqueue(&counterparty_node_id, msg);
		}

		request_id
	}

	fn handle_get_order_response(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey,
		response: LSPS1CreateOrderResponse,
	) -> Result<(), LightningError> {
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

				self.pending_events.enqueue(LSPS1ClientEvent::OrderStatus {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					order_id: response.order_id,
					order: response.order,
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
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, error: ResponseError,
	) -> Result<(), LightningError> {
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

				self.pending_events.enqueue(LSPS1ClientEvent::OrderRequestFailed {
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

impl<ES: Deref> ProtocolMessageHandler for LSPS1ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	type ProtocolMessage = LSPS1Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(1);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS1Message::Response(request_id, response) => match response {
				LSPS1Response::GetInfo(params) => {
					self.handle_get_info_response(request_id, counterparty_node_id, params)
				},
				LSPS1Response::GetInfoError(error) => {
					self.handle_get_info_error(request_id, counterparty_node_id, error)
				},
				LSPS1Response::CreateOrder(params) => {
					self.handle_create_order_response(request_id, counterparty_node_id, params)
				},
				LSPS1Response::CreateOrderError(error) => {
					self.handle_create_order_error(request_id, counterparty_node_id, error)
				},
				LSPS1Response::GetOrder(params) => {
					self.handle_get_order_response(request_id, counterparty_node_id, params)
				},
				LSPS1Response::GetOrderError(error) => {
					self.handle_get_order_error(request_id, counterparty_node_id, error)
				},
			},
			_ => {
				debug_assert!(
					false,
					"Client handler received LSPS1 request message. This should never happen."
				);
				Err(LightningError {
					err: format!(
						"Client handler received LSPS1 request message from node {:?}. This should never happen.",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})
			},
		}
	}
}
