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
use crate::message_queue::MessageQueue;

use crate::events::EventQueue;
use crate::lsps0::ser::{
	LSPSDateTime, LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError,
};
use crate::prelude::{new_hash_map, HashMap};
use crate::sync::{Arc, Mutex, RwLock};
use crate::utils;

use lightning::chain::Filter;
use lightning::ln::channelmanager::AChannelManager;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::errors::APIError;
use lightning::util::logger::Level;

use bitcoin::secp256k1::PublicKey;

use chrono::Utc;

/// Server-side configuration options for bLIP-51 / LSPS1 channel requests.
#[derive(Clone, Debug)]
pub struct LSPS1ServiceConfig {
	/// A token to be send with each channel request.
	pub token: Option<String>,
	/// The options supported by the LSP.
	pub supported_options: Option<LSPS1Options>,
}

struct ChannelStateError(String);

impl From<ChannelStateError> for LightningError {
	fn from(value: ChannelStateError) -> Self {
		LightningError { err: value.0, action: ErrorAction::IgnoreAndLog(Level::Info) }
	}
}

#[derive(PartialEq, Debug)]
enum OutboundRequestState {
	OrderCreated { order_id: LSPS1OrderId },
	WaitingPayment { order_id: LSPS1OrderId },
	Ready,
}

impl OutboundRequestState {
	fn awaiting_payment(&self) -> Result<Self, ChannelStateError> {
		match self {
			OutboundRequestState::OrderCreated { order_id } => {
				Ok(OutboundRequestState::WaitingPayment { order_id: order_id.clone() })
			},
			state => Err(ChannelStateError(format!("TODO. JIT Channel was in state: {:?}", state))),
		}
	}
}

struct OutboundLSPS1Config {
	order: LSPS1OrderParams,
	created_at: LSPSDateTime,
	payment: LSPS1PaymentInfo,
}

struct OutboundCRChannel {
	state: OutboundRequestState,
	config: OutboundLSPS1Config,
}

impl OutboundCRChannel {
	fn new(
		order: LSPS1OrderParams, created_at: LSPSDateTime, order_id: LSPS1OrderId,
		payment: LSPS1PaymentInfo,
	) -> Self {
		Self {
			state: OutboundRequestState::OrderCreated { order_id },
			config: OutboundLSPS1Config { order, created_at, payment },
		}
	}
	fn awaiting_payment(&mut self) -> Result<(), LightningError> {
		self.state = self.state.awaiting_payment()?;
		Ok(())
	}

	fn check_order_validity(&self, supported_options: &LSPS1Options) -> bool {
		let order = &self.config.order;

		is_valid(order, supported_options)
	}
}

#[derive(Default)]
struct PeerState {
	outbound_channels_by_order_id: HashMap<LSPS1OrderId, OutboundCRChannel>,
	request_to_cid: HashMap<LSPSRequestId, u128>,
	pending_requests: HashMap<LSPSRequestId, LSPS1Request>,
}

impl PeerState {
	fn insert_outbound_channel(&mut self, order_id: LSPS1OrderId, channel: OutboundCRChannel) {
		self.outbound_channels_by_order_id.insert(order_id, channel);
	}

	fn insert_request(&mut self, request_id: LSPSRequestId, channel_id: u128) {
		self.request_to_cid.insert(request_id, channel_id);
	}

	fn remove_outbound_channel(&mut self, order_id: LSPS1OrderId) {
		self.outbound_channels_by_order_id.remove(&order_id);
	}
}

/// The main object allowing to send and receive bLIP-51 / LSPS1 messages.
pub struct LSPS1ServiceHandler<ES: Deref, CM: Deref + Clone, C: Deref>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
{
	entropy_source: ES,
	channel_manager: CM,
	chain_source: Option<C>,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	config: LSPS1ServiceConfig,
}

impl<ES: Deref, CM: Deref + Clone, C: Deref> LSPS1ServiceHandler<ES, CM, C>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
	ES::Target: EntropySource,
{
	/// Constructs a `LSPS1ServiceHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		channel_manager: CM, chain_source: Option<C>, config: LSPS1ServiceConfig,
	) -> Self {
		Self {
			entropy_source,
			channel_manager,
			chain_source,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
			config,
		}
	}

	/// Returns a reference to the used config.
	pub fn config(&self) -> &LSPS1ServiceConfig {
		&self.config
	}

	fn handle_get_info_request(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let response = LSPS1Response::GetInfo(LSPS1GetInfoResponse {
			options: self
				.config
				.supported_options
				.clone()
				.ok_or(LightningError {
					err: format!("Configuration for LSP server not set."),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})
				.unwrap(),
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

		if !is_valid(&params.order, &self.config.supported_options.as_ref().unwrap()) {
			let response = LSPS1Response::CreateOrderError(LSPSResponseError {
				code: LSPS1_CREATE_ORDER_REQUEST_ORDER_MISMATCH_ERROR_CODE,
				message: format!("Order does not match options supported by LSP server"),
				data: Some(format!(
					"Supported options are {:?}",
					&self.config.supported_options.as_ref().unwrap()
				)),
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

			peer_state_lock
				.pending_requests
				.insert(request_id.clone(), LSPS1Request::CreateOrder(params.clone()));
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
		payment: LSPS1PaymentInfo, created_at: LSPSDateTime,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				match peer_state_lock.pending_requests.remove(&request_id) {
					Some(LSPS1Request::CreateOrder(params)) => {
						let order_id = self.generate_order_id();
						let channel = OutboundCRChannel::new(
							params.order.clone(),
							created_at.clone(),
							order_id.clone(),
							payment.clone(),
						);

						peer_state_lock.insert_outbound_channel(order_id.clone(), channel);

						let response = LSPS1Response::CreateOrder(LSPS1CreateOrderResponse {
							order: params.order,
							order_id,
							order_state: LSPS1OrderState::Created,
							created_at,
							payment,
							channel: None,
						});
						let msg = LSPS1Message::Response(request_id, response).into();
						message_queue_notifier.enqueue(counterparty_node_id, msg);
						Ok(())
					},

					_ => Err(APIError::APIMisuseError {
						err: format!("No pending buy request for request_id: {:?}", request_id),
					}),
				}
			},
			None => Err(APIError::APIMisuseError {
				err: format!("No state for the counterparty exists: {:?}", counterparty_node_id),
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

				let outbound_channel = peer_state_lock
					.outbound_channels_by_order_id
					.get_mut(&params.order_id)
					.ok_or(LightningError {
						err: format!(
							"Received get order request for unknown order id {:?}",
							params.order_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					})?;

				if let Err(e) = outbound_channel.awaiting_payment() {
					peer_state_lock.outbound_channels_by_order_id.remove(&params.order_id);
					event_queue_notifier.enqueue(LSPS1ServiceEvent::Refund {
						request_id,
						counterparty_node_id: *counterparty_node_id,
						order_id: params.order_id,
					});
					return Err(e);
				}

				peer_state_lock
					.pending_requests
					.insert(request_id.clone(), LSPS1Request::GetOrder(params.clone()));

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
		order_state: LSPS1OrderState, channel: Option<LSPS1ChannelInfo>,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();

		match outer_state_lock.get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				if let Some(outbound_channel) =
					peer_state_lock.outbound_channels_by_order_id.get_mut(&order_id)
				{
					let config = &outbound_channel.config;

					let response = LSPS1Response::GetOrder(LSPS1CreateOrderResponse {
						order_id,
						order: config.order.clone(),
						order_state,
						created_at: config.created_at.clone(),
						payment: config.payment.clone(),
						channel,
					});
					let msg = LSPS1Message::Response(request_id, response).into();
					message_queue_notifier.enqueue(&counterparty_node_id, msg);
					Ok(())
				} else {
					Err(APIError::APIMisuseError {
						err: format!("Channel with order_id {} not found", order_id.0),
					})
				}
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

impl<ES: Deref, CM: Deref + Clone, C: Deref> LSPSProtocolMessageHandler
	for LSPS1ServiceHandler<ES, CM, C>
where
	ES::Target: EntropySource,
	CM::Target: AChannelManager,
	C::Target: Filter,
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
