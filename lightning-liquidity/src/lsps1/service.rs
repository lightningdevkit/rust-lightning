// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main bLIP-51 / LSPS1 server object, [`LSPS1ServiceHandler`].

use alloc::string::String;

use core::ops::Deref;

use super::event::LSPS1ServiceEvent;
use super::msgs::{
	LSPS1ChannelInfo, LSPS1CreateOrderRequest, LSPS1CreateOrderResponse, LSPS1GetInfoResponse,
	LSPS1GetOrderRequest, LSPS1Message, LSPS1Options, LSPS1OrderId, LSPS1OrderParams,
	LSPS1OrderState, LSPS1PaymentInfo, LSPS1Request, LSPS1Response,
	LSPS1_CREATE_ORDER_REQUEST_ORDER_MISMATCH_ERROR_CODE,
};
use super::peer_state::PeerState;
use crate::message_queue::MessageQueue;

use crate::events::EventQueue;
use crate::lsps0::ser::{
	LSPSDateTime, LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError,
};
use crate::prelude::{new_hash_map, HashMap};
use crate::sync::{Arc, Mutex, RwLock};
use crate::utils;
use crate::utils::time::TimeProvider;

use lightning::ln::channelmanager::AChannelManager;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::errors::APIError;
use lightning::util::logger::Level;
use lightning::util::persist::KVStore;

use bitcoin::secp256k1::PublicKey;

/// Server-side configuration options for bLIP-51 / LSPS1 channel requests.
#[derive(Clone, Debug)]
pub struct LSPS1ServiceConfig {
	/// A token to be send with each channel request.
	pub token: Option<String>,
	/// The options supported by the LSP.
	pub supported_options: LSPS1Options,
}

/// The main object allowing to send and receive bLIP-51 / LSPS1 messages.
pub struct LSPS1ServiceHandler<
	ES: EntropySource,
	CM: Deref + Clone,
	K: KVStore + Clone,
	TP: Deref + Clone,
> where
	CM::Target: AChannelManager,
	TP::Target: TimeProvider,
{
	entropy_source: ES,
	_channel_manager: CM,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	time_provider: TP,
	config: LSPS1ServiceConfig,
}

impl<ES: EntropySource, CM: Deref + Clone, K: KVStore + Clone, TP: Deref + Clone>
	LSPS1ServiceHandler<ES, CM, K, TP>
where
	CM::Target: AChannelManager,
	TP::Target: TimeProvider,
{
	/// Constructs a `LSPS1ServiceHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>,
		pending_events: Arc<EventQueue<K>>, channel_manager: CM, time_provider: TP,
		config: LSPS1ServiceConfig,
	) -> Self {
		Self {
			entropy_source,
			_channel_manager: channel_manager,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
			time_provider,
			config,
		}
	}

	/// Returns a reference to the used config.
	pub fn config(&self) -> &LSPS1ServiceConfig {
		&self.config
	}

	/// Returns whether the peer currently has any active LSPS1 order flows.
	///
	/// An order is considered active only after we have validated the client's
	/// `CreateOrder` request and replied with a `CreateOrder` response containing
	/// an `order_id`.
	/// Pending requests that are still awaiting our response are deliberately NOT counted.
	pub(crate) fn has_active_requests(&self, counterparty_node_id: &PublicKey) -> bool {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		outer_state_lock.get(counterparty_node_id).map_or(false, |inner| {
			let peer_state = inner.lock().unwrap();
			peer_state.has_active_requests()
		})
	}

	fn handle_get_info_request(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let response = LSPS1Response::GetInfo(LSPS1GetInfoResponse {
			options: self.config.supported_options.clone(),
		});

		let msg = LSPS1Message::Response(request_id, response).into();
		message_queue_notifier.enqueue(counterparty_node_id, msg);
		Ok(())
	}

	fn handle_create_order_request(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		params: LSPS1CreateOrderRequest,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();
		let event_queue_notifier = self.pending_events.notifier();

		if !is_valid(&params.order, &self.config.supported_options) {
			let response = LSPS1Response::CreateOrderError(LSPSResponseError {
				code: LSPS1_CREATE_ORDER_REQUEST_ORDER_MISMATCH_ERROR_CODE,
				message: format!("Order does not match options supported by LSP server"),
				data: Some(format!("Supported options are {:?}", &self.config.supported_options)),
			});
			let msg = LSPS1Message::Response(request_id, response).into();
			message_queue_notifier.enqueue(counterparty_node_id, msg);
			return Err(LightningError {
				err: format!(
					"Client order does not match any supported options: {:?}",
					params.order
				),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();

			let inner_state_lock = outer_state_lock
				.entry(*counterparty_node_id)
				.or_insert(Mutex::new(PeerState::default()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();

			let request = LSPS1Request::CreateOrder(params.clone());
			peer_state_lock.register_request(request_id.clone(), request).map_err(|e| {
				let err = format!("Failed to handle request due to: {}", e);
				let action = ErrorAction::IgnoreAndLog(Level::Error);
				LightningError { err, action }
			})?;
		}

		event_queue_notifier.enqueue(LSPS1ServiceEvent::RequestForPaymentDetails {
			request_id,
			counterparty_node_id: *counterparty_node_id,
			order: params.order,
		});

		Ok(())
	}

	/// Used by LSP to send response containing details regarding the channel fees and payment information.
	///
	/// Should be called in response to receiving a [`LSPS1ServiceEvent::RequestForPaymentDetails`] event.
	///
	/// [`LSPS1ServiceEvent::RequestForPaymentDetails`]: crate::lsps1::event::LSPS1ServiceEvent::RequestForPaymentDetails
	pub fn send_payment_details(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		payment_details: LSPS1PaymentInfo,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				let request = peer_state_lock.remove_request(&request_id).map_err(|e| {
					debug_assert!(false, "Failed to send response due to: {}", e);
					let err = format!("Failed to send response due to: {}", e);
					APIError::APIMisuseError { err }
				})?;

				match request {
					LSPS1Request::CreateOrder(params) => {
						let order_id = self.generate_order_id();
						let created_at = LSPSDateTime::new_from_duration_since_epoch(
							self.time_provider.duration_since_epoch(),
						);
						let order = peer_state_lock.new_order(
							order_id.clone(),
							params.order,
							created_at,
							payment_details,
						);

						let response = LSPS1Response::CreateOrder(LSPS1CreateOrderResponse {
							order: order.order_params,
							order_id,

							order_state: order.order_state,
							created_at: order.created_at,
							payment: order.payment_details,
							channel: order.channel_details,
						});
						let msg = LSPS1Message::Response(request_id, response).into();
						message_queue_notifier.enqueue(counterparty_node_id, msg);
						Ok(())
					},
					t => {
						debug_assert!(
							false,
							"Failed to send response due to unexpected request type: {:?}",
							t
						);
						let err = format!(
							"Failed to send response due to unexpected request type: {:?}",
							t
						);
						return Err(APIError::APIMisuseError { err });
					},
				}
			},
			None => Err(APIError::APIMisuseError {
				err: format!("No state for the counterparty exists: {}", counterparty_node_id),
			}),
		}
	}

	fn handle_get_order_request(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		params: LSPS1GetOrderRequest,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				let request = LSPS1Request::GetOrder(params.clone());
				peer_state_lock.register_request(request_id.clone(), request).map_err(|e| {
					let err = format!("Failed to handle request due to: {}", e);
					let action = ErrorAction::IgnoreAndLog(Level::Error);
					LightningError { err, action }
				})?;

				event_queue_notifier.enqueue(LSPS1ServiceEvent::CheckPaymentConfirmation {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					order_id: params.order_id,
				});
			},
			None => {
				return Err(LightningError {
					err: format!("Received error response for a create order request from an unknown counterparty ({:?})", counterparty_node_id),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			},
		}

		Ok(())
	}

	/// Used by LSP to give details to client regarding the status of channel opening.
	/// Called to respond to client's GetOrder request.
	/// The LSP continously polls for checking payment confirmation on-chain or lighting
	/// and then responds to client request.
	///
	/// Should be called in response to receiving a [`LSPS1ServiceEvent::CheckPaymentConfirmation`] event.
	///
	/// [`LSPS1ServiceEvent::CheckPaymentConfirmation`]: crate::lsps1::event::LSPS1ServiceEvent::CheckPaymentConfirmation
	pub fn update_order_status(
		&self, request_id: LSPSRequestId, counterparty_node_id: PublicKey, order_id: LSPS1OrderId,
		order_state: LSPS1OrderState, channel_details: Option<LSPS1ChannelInfo>,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();

		match outer_state_lock.get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				let order = peer_state_lock
					.update_order(&order_id, order_state, channel_details)
					.map_err(|e| APIError::APIMisuseError {
					err: format!("Failed to update order: {:?}", e),
				})?;

				let response = LSPS1Response::GetOrder(LSPS1CreateOrderResponse {
					order_id,
					order: order.order_params.clone(),
					order_state: order.order_state.clone(),
					created_at: order.created_at.clone(),
					payment: order.payment_details.clone(),
					channel: order.channel_details.clone(),
				});
				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);
				Ok(())
			},
			None => Err(APIError::APIMisuseError {
				err: format!("No existing state with counterparty {}", counterparty_node_id),
			}),
		}
	}

	fn generate_order_id(&self) -> LSPS1OrderId {
		let bytes = self.entropy_source.get_secure_random_bytes();
		LSPS1OrderId(utils::hex_str(&bytes[0..16]))
	}
}

impl<ES: EntropySource, CM: Deref + Clone, K: KVStore + Clone, TP: Deref + Clone>
	LSPSProtocolMessageHandler for LSPS1ServiceHandler<ES, CM, K, TP>
where
	CM::Target: AChannelManager,
	TP::Target: TimeProvider,
{
	type ProtocolMessage = LSPS1Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(1);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS1Message::Request(request_id, request) => match request {
				LSPS1Request::GetInfo(_) => {
					self.handle_get_info_request(request_id, counterparty_node_id)
				},
				LSPS1Request::CreateOrder(params) => {
					self.handle_create_order_request(request_id, counterparty_node_id, params)
				},
				LSPS1Request::GetOrder(params) => {
					self.handle_get_order_request(request_id, counterparty_node_id, params)
				},
			},
			_ => {
				debug_assert!(
					false,
					"Service handler received LSPS1 response message. This should never happen."
				);
				Err(LightningError { err: format!("Service handler received LSPS1 response message from node {:?}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
			},
		}
	}
}

fn check_range(min: u64, max: u64, value: u64) -> bool {
	(value >= min) && (value <= max)
}

fn is_valid(order: &LSPS1OrderParams, options: &LSPS1Options) -> bool {
	let bool = check_range(
		options.min_initial_client_balance_sat,
		options.max_initial_client_balance_sat,
		order.client_balance_sat,
	) && check_range(
		options.min_initial_lsp_balance_sat,
		options.max_initial_lsp_balance_sat,
		order.lsp_balance_sat,
	) && check_range(
		1,
		options.max_channel_expiry_blocks.into(),
		order.channel_expiry_blocks.into(),
	);

	bool
}
