// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main LSPS2 client object, [`LSPS2ClientHandler`].

use crate::events::{Event, EventQueue};
use crate::lsps0::ser::{ProtocolMessageHandler, RequestId, ResponseError};
use crate::lsps2::event::LSPS2ClientEvent;
use crate::message_queue::MessageQueue;
use crate::prelude::{HashMap, HashSet, String};
use crate::sync::{Arc, Mutex, RwLock};

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::errors::APIError;
use lightning::util::logger::Level;

use bitcoin::secp256k1::PublicKey;

use core::default::Default;
use core::ops::Deref;

use crate::lsps2::msgs::{
	BuyRequest, BuyResponse, GetInfoRequest, GetInfoResponse, LSPS2Message, LSPS2Request,
	LSPS2Response, OpeningFeeParams,
};

/// Client-side configuration options for JIT channels.
#[derive(Clone, Debug, Copy)]
pub struct LSPS2ClientConfig {}

impl Default for LSPS2ClientConfig {
	fn default() -> Self {
		Self {}
	}
}

struct InboundJITChannel {
	payment_size_msat: Option<u64>,
}

impl InboundJITChannel {
	fn new(payment_size_msat: Option<u64>) -> Self {
		Self { payment_size_msat }
	}
}

struct PeerState {
	pending_get_info_requests: HashSet<RequestId>,
	pending_buy_requests: HashMap<RequestId, InboundJITChannel>,
}

impl PeerState {
	fn new() -> Self {
		let pending_get_info_requests = HashSet::new();
		let pending_buy_requests = HashMap::new();
		Self { pending_get_info_requests, pending_buy_requests }
	}
}

/// The main object allowing to send and receive LSPS2 messages.
///
/// Note that currently only the 'client-trusts-LSP' trust model is supported, i.e., we don't
/// provide any additional API guidance to allow withholding the preimage until the channel is
/// opened. Please refer to the [`LSPS2 specification`] for more information.
///
/// [`LSPS2 specification`]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/tree/main/LSPS2#trust-models
pub struct LSPS2ClientHandler<ES: Deref>
where
	ES::Target: EntropySource,
{
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	_config: LSPS2ClientConfig,
}

impl<ES: Deref> LSPS2ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	/// Constructs an `LSPS2ClientHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		_config: LSPS2ClientConfig,
	) -> Self {
		Self {
			entropy_source,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(HashMap::new()),
			_config,
		}
	}

	/// Request the channel opening parameters from the LSP.
	///
	/// This initiates the JIT-channel flow that, at the end of it, will have the LSP
	/// open a channel with sufficient inbound liquidity to be able to receive the payment.
	///
	/// The user will receive the LSP's response via an [`OpeningParametersReady`] event.
	///
	/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
	///
	/// `token` is an optional `String` that will be provided to the LSP.
	/// It can be used by the LSP as an API key, coupon code, or some other way to identify a user.
	///
	/// Returns the used [`RequestId`], which will be returned via [`OpeningParametersReady`].
	///
	/// [`OpeningParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::OpeningParametersReady
	pub fn request_opening_params(
		&self, counterparty_node_id: PublicKey, token: Option<String>,
	) -> RequestId {
		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_get_info_requests.insert(request_id.clone());
		}

		let request = LSPS2Request::GetInfo(GetInfoRequest { token });
		let msg = LSPS2Message::Request(request_id.clone(), request).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		request_id
	}

	/// Confirms a set of chosen channel opening parameters to use for the JIT channel and
	/// requests the necessary invoice generation parameters from the LSP.
	///
	/// Should be called in response to receiving a [`OpeningParametersReady`] event.
	///
	/// The user will receive the LSP's response via an [`InvoiceParametersReady`] event.
	///
	/// If `payment_size_msat` is [`Option::Some`] then the invoice will be for a fixed amount
	/// and MPP can be used to pay it.
	///
	/// If `payment_size_msat` is [`Option::None`] then the invoice can be for an arbitrary amount
	/// but MPP can no longer be used to pay it.
	///
	/// The client agrees to paying an opening fee equal to
	/// `max(min_fee_msat, proportional*(payment_size_msat/1_000_000))`.
	///
	/// [`OpeningParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::OpeningParametersReady
	/// [`InvoiceParametersReady`]: crate::lsps2::event::LSPS2ClientEvent::InvoiceParametersReady
	pub fn select_opening_params(
		&self, counterparty_node_id: PublicKey, payment_size_msat: Option<u64>,
		opening_fee_params: OpeningFeeParams,
	) -> Result<RequestId, APIError> {
		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();

			let jit_channel = InboundJITChannel::new(payment_size_msat);
			if peer_state_lock
				.pending_buy_requests
				.insert(request_id.clone(), jit_channel)
				.is_some()
			{
				return Err(APIError::APIMisuseError {
					err: format!("Failed due to duplicate request_id. This should never happen!"),
				});
			}
		}

		let request = LSPS2Request::Buy(BuyRequest { opening_fee_params, payment_size_msat });
		let msg = LSPS2Message::Request(request_id.clone(), request).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		Ok(request_id)
	}

	fn handle_get_info_response(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, result: GetInfoResponse,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_get_info_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_info response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}

				self.pending_events.enqueue(Event::LSPS2Client(
					LSPS2ClientEvent::OpeningParametersReady {
						request_id,
						counterparty_node_id: *counterparty_node_id,
						opening_fee_params_menu: result.opening_fee_params_menu,
					},
				));
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received get_info response from unknown peer: {:?}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})
			},
		}

		Ok(())
	}

	fn handle_get_info_error(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, _error: ResponseError,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_get_info_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received get_info error for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}

				Ok(())
			},
			None => {
				return Err(LightningError { err: format!("Received error response for a get_info request from an unknown counterparty ({:?})",counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
			},
		}
	}

	fn handle_buy_response(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, result: BuyResponse,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				let jit_channel =
					peer_state.pending_buy_requests.remove(&request_id).ok_or(LightningError {
						err: format!(
							"Received buy response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					})?;

				if let Ok(intercept_scid) = result.jit_channel_scid.to_scid() {
					self.pending_events.enqueue(Event::LSPS2Client(
						LSPS2ClientEvent::InvoiceParametersReady {
							request_id,
							counterparty_node_id: *counterparty_node_id,
							intercept_scid,
							cltv_expiry_delta: result.lsp_cltv_expiry_delta,
							payment_size_msat: jit_channel.payment_size_msat,
						},
					));
				} else {
					return Err(LightningError {
						err: format!(
							"Received buy response with an invalid intercept scid {:?}",
							result.jit_channel_scid
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received buy response from unknown peer: {:?}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			},
		}
		Ok(())
	}

	fn handle_buy_error(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, _error: ResponseError,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				peer_state.pending_buy_requests.remove(&request_id).ok_or(LightningError {
					err: format!("Received buy error for an unknown request: {:?}", request_id),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})?;

				Ok(())
			},
			None => {
				return Err(LightningError { err: format!("Received error response for a buy request from an unknown counterparty ({:?})", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
			},
		}
	}
}

impl<ES: Deref> ProtocolMessageHandler for LSPS2ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	type ProtocolMessage = LSPS2Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(2);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS2Message::Response(request_id, response) => match response {
				LSPS2Response::GetInfo(result) => {
					self.handle_get_info_response(request_id, counterparty_node_id, result)
				},
				LSPS2Response::GetInfoError(error) => {
					self.handle_get_info_error(request_id, counterparty_node_id, error)
				},
				LSPS2Response::Buy(result) => {
					self.handle_buy_response(request_id, counterparty_node_id, result)
				},
				LSPS2Response::BuyError(error) => {
					self.handle_buy_error(request_id, counterparty_node_id, error)
				},
			},
			_ => {
				debug_assert!(
					false,
					"Client handler received LSPS2 request message. This should never happen."
				);
				Err(LightningError { err: format!("Client handler received LSPS2 request message from node {:?}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
			},
		}
	}
}

#[cfg(test)]
mod tests {}
