// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main LSPS2 server-side object, [`LSPS2ServiceHandler`].

use crate::events::{Event, EventQueue};
use crate::lsps0::ser::{ProtocolMessageHandler, RequestId, ResponseError};
use crate::lsps2::event::LSPS2ServiceEvent;
use crate::lsps2::payment_queue::{InterceptedHTLC, PaymentQueue};
use crate::lsps2::utils::{compute_opening_fee, is_valid_opening_fee_params};
use crate::message_queue::MessageQueue;
use crate::prelude::{HashMap, String, ToString, Vec};
use crate::sync::{Arc, Mutex, RwLock};

use lightning::events::HTLCDestination;
use lightning::ln::channelmanager::{AChannelManager, InterceptId};
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::ln::types::ChannelId;
use lightning::util::errors::APIError;
use lightning::util::logger::Level;

use lightning_types::payment::PaymentHash;

use bitcoin::secp256k1::PublicKey;

use core::ops::Deref;

use crate::lsps2::msgs::{
	BuyRequest, BuyResponse, GetInfoRequest, GetInfoResponse, LSPS2Message, LSPS2Request,
	LSPS2Response, OpeningFeeParams, RawOpeningFeeParams,
	LSPS2_BUY_REQUEST_INVALID_OPENING_FEE_PARAMS_ERROR_CODE,
	LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_LARGE_ERROR_CODE,
	LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_SMALL_ERROR_CODE,
	LSPS2_GET_INFO_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE,
};

/// Server-side configuration options for JIT channels.
#[derive(Clone, Debug)]
pub struct LSPS2ServiceConfig {
	/// Used to calculate the promise for channel parameters supplied to clients.
	///
	/// Note: If this changes then old promises given out will be considered invalid.
	pub promise_secret: [u8; 32],
}

/// Information about the initial payment size and JIT channel opening fee.
/// This will be provided in the `OpenChannel` event.
#[derive(Clone, Debug, PartialEq)]
struct OpenChannelParams {
	opening_fee_msat: u64,
	amt_to_forward_msat: u64,
}

/// A payment that will be forwarded while skimming the given JIT channel opening fee.
#[derive(Clone, Debug, PartialEq)]
struct FeePayment {
	htlcs: Vec<InterceptedHTLC>,
	opening_fee_msat: u64,
}

#[derive(Debug)]
struct ChannelStateError(String);

impl From<ChannelStateError> for LightningError {
	fn from(value: ChannelStateError) -> Self {
		LightningError { err: value.0, action: ErrorAction::IgnoreAndLog(Level::Info) }
	}
}

/// Possible actions that need to be taken when an HTLC is intercepted.
#[derive(Debug, PartialEq)]
enum HTLCInterceptedAction {
	/// The opening of the JIT channel.
	OpenChannel(OpenChannelParams),
	/// The forwarding of the intercepted HTLC.
	ForwardHTLC(ChannelId),
	ForwardPayment(ChannelId, FeePayment),
}

/// The forwarding of a payment while skimming the JIT channel opening fee.
#[derive(Debug, PartialEq)]
struct ForwardPaymentAction(ChannelId, FeePayment);

/// The forwarding of previously intercepted HTLCs without skimming any further fees.
#[derive(Debug, PartialEq)]
struct ForwardHTLCsAction(ChannelId, Vec<InterceptedHTLC>);

/// The different states a requested JIT channel can be in.
#[derive(Debug)]
enum OutboundJITChannelState {
	/// The JIT channel SCID was created after a buy request, and we are awaiting an initial payment
	/// of sufficient size to open the channel.
	PendingInitialPayment { payment_queue: Arc<Mutex<PaymentQueue>> },
	/// An initial payment of sufficient size was intercepted to the JIT channel SCID, triggering the
	/// opening of the channel. We are awaiting the completion of the channel establishment.
	PendingChannelOpen { payment_queue: Arc<Mutex<PaymentQueue>>, opening_fee_msat: u64 },
	/// The channel is open and a payment was forwarded while skimming the JIT channel fee.
	/// No further payments can be forwarded until the pending payment succeeds or fails, as we need
	/// to know whether the JIT channel fee needs to be skimmed from a next payment or not.
	PendingPaymentForward {
		payment_queue: Arc<Mutex<PaymentQueue>>,
		opening_fee_msat: u64,
		channel_id: ChannelId,
	},
	/// The channel is open, no payment is currently being forwarded, and the JIT channel fee still
	/// needs to be paid. This state can occur when the initial payment fails, e.g. due to a
	/// prepayment probe. We are awaiting a next payment of sufficient size to forward and skim the
	/// JIT channel fee.
	PendingPayment {
		payment_queue: Arc<Mutex<PaymentQueue>>,
		opening_fee_msat: u64,
		channel_id: ChannelId,
	},
	/// The channel is open and a payment was successfully forwarded while skimming the JIT channel
	/// fee. Any subsequent HTLCs can be forwarded without additional logic.
	PaymentForwarded { channel_id: ChannelId },
}

impl OutboundJITChannelState {
	fn new() -> Self {
		OutboundJITChannelState::PendingInitialPayment {
			payment_queue: Arc::new(Mutex::new(PaymentQueue::new())),
		}
	}

	fn htlc_intercepted(
		&mut self, opening_fee_params: &OpeningFeeParams, payment_size_msat: &Option<u64>,
		htlc: InterceptedHTLC,
	) -> Result<(Self, Option<HTLCInterceptedAction>), ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingInitialPayment { payment_queue } => {
				let (total_expected_outbound_amount_msat, num_htlcs) =
					payment_queue.lock().unwrap().add_htlc(htlc);

				let (expected_payment_size_msat, mpp_mode) =
					if let Some(payment_size_msat) = payment_size_msat {
						(*payment_size_msat, true)
					} else {
						debug_assert_eq!(num_htlcs, 1);
						if num_htlcs != 1 {
							return Err(ChannelStateError(
								format!("Paying via multiple HTLCs is disallowed in \"no-MPP+var-invoice\" mode.")
							));
						}
						(total_expected_outbound_amount_msat, false)
					};

				if expected_payment_size_msat < opening_fee_params.min_payment_size_msat
					|| expected_payment_size_msat > opening_fee_params.max_payment_size_msat
				{
					return Err(ChannelStateError(
							format!("Payment size violates our limits: expected_payment_size_msat = {}, min_payment_size_msat = {}, max_payment_size_msat = {}",
									expected_payment_size_msat,
									opening_fee_params.min_payment_size_msat,
									opening_fee_params.max_payment_size_msat
							)));
				}

				let opening_fee_msat = compute_opening_fee(
					expected_payment_size_msat,
					opening_fee_params.min_fee_msat,
					opening_fee_params.proportional.into(),
				).ok_or(ChannelStateError(
					format!("Could not compute valid opening fee with min_fee_msat = {}, proportional = {}, and expected_payment_size_msat = {}",
						opening_fee_params.min_fee_msat,
						opening_fee_params.proportional,
						expected_payment_size_msat
					)
				))?;

				let amt_to_forward_msat =
					expected_payment_size_msat.saturating_sub(opening_fee_msat);

				// Go ahead and open the channel if we intercepted sufficient HTLCs.
				if total_expected_outbound_amount_msat >= expected_payment_size_msat
					&& amt_to_forward_msat > 0
				{
					let pending_channel_open = OutboundJITChannelState::PendingChannelOpen {
						payment_queue: Arc::clone(&payment_queue),
						opening_fee_msat,
					};
					let open_channel = HTLCInterceptedAction::OpenChannel(OpenChannelParams {
						opening_fee_msat,
						amt_to_forward_msat,
					});
					Ok((pending_channel_open, Some(open_channel)))
				} else {
					if mpp_mode {
						let pending_initial_payment =
							OutboundJITChannelState::PendingInitialPayment {
								payment_queue: Arc::clone(&payment_queue),
							};
						Ok((pending_initial_payment, None))
					} else {
						Err(ChannelStateError(
							"Intercepted HTLC is too small to pay opening fee".to_string(),
						))
					}
				}
			},
			OutboundJITChannelState::PendingChannelOpen { payment_queue, opening_fee_msat } => {
				let mut payment_queue_lock = payment_queue.lock().unwrap();
				payment_queue_lock.add_htlc(htlc);
				let pending_channel_open = OutboundJITChannelState::PendingChannelOpen {
					payment_queue: payment_queue.clone(),
					opening_fee_msat: *opening_fee_msat,
				};
				Ok((pending_channel_open, None))
			},
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				let mut payment_queue_lock = payment_queue.lock().unwrap();
				payment_queue_lock.add_htlc(htlc);
				let pending_payment_forward = OutboundJITChannelState::PendingPaymentForward {
					payment_queue: payment_queue.clone(),
					opening_fee_msat: *opening_fee_msat,
					channel_id: *channel_id,
				};
				Ok((pending_payment_forward, None))
			},
			OutboundJITChannelState::PendingPayment {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				let mut payment_queue_lock = payment_queue.lock().unwrap();
				payment_queue_lock.add_htlc(htlc);
				if let Some((_payment_hash, htlcs)) =
					payment_queue_lock.pop_greater_than_msat(*opening_fee_msat)
				{
					let pending_payment_forward = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: payment_queue.clone(),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					let forward_payment = HTLCInterceptedAction::ForwardPayment(
						*channel_id,
						FeePayment { htlcs, opening_fee_msat: *opening_fee_msat },
					);
					Ok((pending_payment_forward, Some(forward_payment)))
				} else {
					let pending_payment = OutboundJITChannelState::PendingPayment {
						payment_queue: payment_queue.clone(),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok((pending_payment, None))
				}
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				let payment_forwarded =
					OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				let forward = HTLCInterceptedAction::ForwardHTLC(*channel_id);
				Ok((payment_forwarded, Some(forward)))
			},
		}
	}

	fn channel_ready(
		&self, channel_id: ChannelId,
	) -> Result<(Self, ForwardPaymentAction), ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingChannelOpen { payment_queue, opening_fee_msat } => {
				let mut payment_queue_lock = payment_queue.lock().unwrap();
				if let Some((_payment_hash, htlcs)) =
					payment_queue_lock.pop_greater_than_msat(*opening_fee_msat)
				{
					let pending_payment_forward = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: Arc::clone(&payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id,
					};
					let forward_payment = ForwardPaymentAction(
						channel_id,
						FeePayment { opening_fee_msat: *opening_fee_msat, htlcs },
					);
					Ok((pending_payment_forward, forward_payment))
				} else {
					Err(ChannelStateError(
						"No forwardable payment available when moving to channel ready."
							.to_string(),
					))
				}
			},
			state => Err(ChannelStateError(format!(
				"Channel ready received when JIT Channel was in state: {:?}",
				state
			))),
		}
	}

	fn htlc_handling_failed(
		&mut self,
	) -> Result<(Self, Option<ForwardPaymentAction>), ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				let mut payment_queue_lock = payment_queue.lock().unwrap();
				if let Some((_payment_hash, htlcs)) =
					payment_queue_lock.pop_greater_than_msat(*opening_fee_msat)
				{
					let pending_payment_forward = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: payment_queue.clone(),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					let forward_payment = ForwardPaymentAction(
						*channel_id,
						FeePayment { htlcs, opening_fee_msat: *opening_fee_msat },
					);
					Ok((pending_payment_forward, Some(forward_payment)))
				} else {
					let pending_payment = OutboundJITChannelState::PendingPayment {
						payment_queue: payment_queue.clone(),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok((pending_payment, None))
				}
			},
			OutboundJITChannelState::PendingPayment {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				let pending_payment = OutboundJITChannelState::PendingPayment {
					payment_queue: payment_queue.clone(),
					opening_fee_msat: *opening_fee_msat,
					channel_id: *channel_id,
				};
				Ok((pending_payment, None))
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				let payment_forwarded =
					OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				Ok((payment_forwarded, None))
			},
			state => Err(ChannelStateError(format!(
				"HTLC handling failed when JIT Channel was in state: {:?}",
				state
			))),
		}
	}

	fn payment_forwarded(
		&mut self,
	) -> Result<(Self, Option<ForwardHTLCsAction>), ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue, channel_id, ..
			} => {
				let mut payment_queue_lock = payment_queue.lock().unwrap();
				let payment_forwarded =
					OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				let forward_htlcs = ForwardHTLCsAction(*channel_id, payment_queue_lock.clear());
				Ok((payment_forwarded, Some(forward_htlcs)))
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				let payment_forwarded =
					OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				Ok((payment_forwarded, None))
			},
			state => Err(ChannelStateError(format!(
				"Payment forwarded when JIT Channel was in state: {:?}",
				state
			))),
		}
	}
}

struct OutboundJITChannel {
	state: OutboundJITChannelState,
	user_channel_id: u128,
	opening_fee_params: OpeningFeeParams,
	payment_size_msat: Option<u64>,
}

impl OutboundJITChannel {
	fn new(
		payment_size_msat: Option<u64>, opening_fee_params: OpeningFeeParams, user_channel_id: u128,
	) -> Self {
		Self {
			user_channel_id,
			state: OutboundJITChannelState::new(),
			opening_fee_params,
			payment_size_msat,
		}
	}

	fn htlc_intercepted(
		&mut self, htlc: InterceptedHTLC,
	) -> Result<Option<HTLCInterceptedAction>, LightningError> {
		let (new_state, action) =
			self.state.htlc_intercepted(&self.opening_fee_params, &self.payment_size_msat, htlc)?;
		self.state = new_state;
		Ok(action)
	}

	fn htlc_handling_failed(&mut self) -> Result<Option<ForwardPaymentAction>, LightningError> {
		let (new_state, action) = self.state.htlc_handling_failed()?;
		self.state = new_state;
		Ok(action)
	}

	fn channel_ready(
		&mut self, channel_id: ChannelId,
	) -> Result<ForwardPaymentAction, LightningError> {
		let (new_state, action) = self.state.channel_ready(channel_id)?;
		self.state = new_state;
		Ok(action)
	}

	fn payment_forwarded(&mut self) -> Result<Option<ForwardHTLCsAction>, LightningError> {
		let (new_state, action) = self.state.payment_forwarded()?;
		self.state = new_state;
		Ok(action)
	}
}

struct PeerState {
	outbound_channels_by_intercept_scid: HashMap<u64, OutboundJITChannel>,
	intercept_scid_by_user_channel_id: HashMap<u128, u64>,
	intercept_scid_by_channel_id: HashMap<ChannelId, u64>,
	pending_requests: HashMap<RequestId, LSPS2Request>,
}

impl PeerState {
	fn new() -> Self {
		let outbound_channels_by_intercept_scid = HashMap::new();
		let pending_requests = HashMap::new();
		let intercept_scid_by_user_channel_id = HashMap::new();
		let intercept_scid_by_channel_id = HashMap::new();
		Self {
			outbound_channels_by_intercept_scid,
			pending_requests,
			intercept_scid_by_user_channel_id,
			intercept_scid_by_channel_id,
		}
	}

	fn insert_outbound_channel(&mut self, intercept_scid: u64, channel: OutboundJITChannel) {
		self.outbound_channels_by_intercept_scid.insert(intercept_scid, channel);
	}
}

/// The main object allowing to send and receive LSPS2 messages.
pub struct LSPS2ServiceHandler<CM: Deref + Clone>
where
	CM::Target: AChannelManager,
{
	channel_manager: CM,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	peer_by_intercept_scid: RwLock<HashMap<u64, PublicKey>>,
	peer_by_channel_id: RwLock<HashMap<ChannelId, PublicKey>>,
	config: LSPS2ServiceConfig,
}

impl<CM: Deref + Clone> LSPS2ServiceHandler<CM>
where
	CM::Target: AChannelManager,
{
	/// Constructs a `LSPS2ServiceHandler`.
	pub(crate) fn new(
		pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>, channel_manager: CM,
		config: LSPS2ServiceConfig,
	) -> Self {
		Self {
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(HashMap::new()),
			peer_by_intercept_scid: RwLock::new(HashMap::new()),
			peer_by_channel_id: RwLock::new(HashMap::new()),
			channel_manager,
			config,
		}
	}

	/// Used by LSP to inform a client requesting a JIT Channel the token they used is invalid.
	///
	/// Should be called in response to receiving a [`LSPS2ServiceEvent::GetInfo`] event.
	///
	/// [`LSPS2ServiceEvent::GetInfo`]: crate::lsps2::event::LSPS2ServiceEvent::GetInfo
	pub fn invalid_token_provided(
		&self, counterparty_node_id: &PublicKey, request_id: RequestId,
	) -> Result<(), APIError> {
		let (result, response) = {
			let outer_state_lock = self.per_peer_state.read().unwrap();

			match outer_state_lock.get(counterparty_node_id) {
				Some(inner_state_lock) => {
					let mut peer_state = inner_state_lock.lock().unwrap();

					match peer_state.pending_requests.remove(&request_id) {
						Some(LSPS2Request::GetInfo(_)) => {
							let response = LSPS2Response::GetInfoError(ResponseError {
								code: LSPS2_GET_INFO_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE,
								message: "an unrecognized or stale token was provided".to_string(),
								data: None,
							});
							(Ok(()), Some(response))
						},
						_ => (
							Err(APIError::APIMisuseError {
								err: format!(
									"No pending get_info request for request_id: {:?}",
									request_id
								),
							}),
							None,
						),
					}
				},
				None => (
					Err(APIError::APIMisuseError {
						err: format!(
							"No state for the counterparty exists: {:?}",
							counterparty_node_id
						),
					}),
					None,
				),
			}
		};

		if let Some(response) = response {
			let msg = LSPS2Message::Response(request_id, response).into();
			self.pending_messages.enqueue(counterparty_node_id, msg);
		}

		result
	}

	/// Used by LSP to provide fee parameters to a client requesting a JIT Channel.
	///
	/// Should be called in response to receiving a [`LSPS2ServiceEvent::GetInfo`] event.
	///
	/// [`LSPS2ServiceEvent::GetInfo`]: crate::lsps2::event::LSPS2ServiceEvent::GetInfo
	pub fn opening_fee_params_generated(
		&self, counterparty_node_id: &PublicKey, request_id: RequestId,
		opening_fee_params_menu: Vec<RawOpeningFeeParams>,
	) -> Result<(), APIError> {
		let (result, response) = {
			let outer_state_lock = self.per_peer_state.read().unwrap();

			match outer_state_lock.get(counterparty_node_id) {
				Some(inner_state_lock) => {
					let mut peer_state = inner_state_lock.lock().unwrap();

					match peer_state.pending_requests.remove(&request_id) {
						Some(LSPS2Request::GetInfo(_)) => {
							let response = LSPS2Response::GetInfo(GetInfoResponse {
								opening_fee_params_menu: opening_fee_params_menu
									.into_iter()
									.map(|param| {
										param.into_opening_fee_params(&self.config.promise_secret)
									})
									.collect(),
							});
							(Ok(()), Some(response))
						},
						_ => (
							Err(APIError::APIMisuseError {
								err: format!(
									"No pending get_info request for request_id: {:?}",
									request_id
								),
							}),
							None,
						),
					}
				},
				None => (
					Err(APIError::APIMisuseError {
						err: format!(
							"No state for the counterparty exists: {:?}",
							counterparty_node_id
						),
					}),
					None,
				),
			}
		};

		if let Some(response) = response {
			let msg = LSPS2Message::Response(request_id, response).into();
			self.pending_messages.enqueue(counterparty_node_id, msg);
		}

		result
	}

	/// Used by LSP to provide client with the intercept scid and cltv_expiry_delta to use in their invoice.
	///
	/// Should be called in response to receiving a [`LSPS2ServiceEvent::BuyRequest`] event.
	///
	/// [`LSPS2ServiceEvent::BuyRequest`]: crate::lsps2::event::LSPS2ServiceEvent::BuyRequest
	pub fn invoice_parameters_generated(
		&self, counterparty_node_id: &PublicKey, request_id: RequestId, intercept_scid: u64,
		cltv_expiry_delta: u32, client_trusts_lsp: bool, user_channel_id: u128,
	) -> Result<(), APIError> {
		let (result, response) = {
			let outer_state_lock = self.per_peer_state.read().unwrap();

			match outer_state_lock.get(counterparty_node_id) {
				Some(inner_state_lock) => {
					let mut peer_state = inner_state_lock.lock().unwrap();

					match peer_state.pending_requests.remove(&request_id) {
						Some(LSPS2Request::Buy(buy_request)) => {
							{
								let mut peer_by_intercept_scid =
									self.peer_by_intercept_scid.write().unwrap();
								peer_by_intercept_scid
									.insert(intercept_scid, *counterparty_node_id);
							}

							let outbound_jit_channel = OutboundJITChannel::new(
								buy_request.payment_size_msat,
								buy_request.opening_fee_params,
								user_channel_id,
							);

							peer_state
								.intercept_scid_by_user_channel_id
								.insert(user_channel_id, intercept_scid);
							peer_state
								.insert_outbound_channel(intercept_scid, outbound_jit_channel);

							let response = LSPS2Response::Buy(BuyResponse {
								jit_channel_scid: intercept_scid.into(),
								lsp_cltv_expiry_delta: cltv_expiry_delta,
								client_trusts_lsp,
							});
							(Ok(()), Some(response))
						},
						_ => (
							Err(APIError::APIMisuseError {
								err: format!(
									"No pending buy request for request_id: {:?}",
									request_id
								),
							}),
							None,
						),
					}
				},
				None => (
					Err(APIError::APIMisuseError {
						err: format!(
							"No state for the counterparty exists: {:?}",
							counterparty_node_id
						),
					}),
					None,
				),
			}
		};

		if let Some(response) = response {
			let msg = LSPS2Message::Response(request_id, response).into();
			self.pending_messages.enqueue(counterparty_node_id, msg);
		}

		result
	}

	/// Forward [`Event::HTLCIntercepted`] event parameters into this function.
	///
	/// Will fail the intercepted HTLC if the intercept scid matches a payment we are expecting
	/// but the payment amount is incorrect or the expiry has passed.
	///
	/// Will generate a [`LSPS2ServiceEvent::OpenChannel`] event if the intercept scid matches a payment we are expected
	/// and the payment amount is correct and the offer has not expired.
	///
	/// Will do nothing if the intercept scid does not match any of the ones we gave out.
	///
	/// [`Event::HTLCIntercepted`]: lightning::events::Event::HTLCIntercepted
	/// [`LSPS2ServiceEvent::OpenChannel`]: crate::lsps2::event::LSPS2ServiceEvent::OpenChannel
	pub fn htlc_intercepted(
		&self, intercept_scid: u64, intercept_id: InterceptId, expected_outbound_amount_msat: u64,
		payment_hash: PaymentHash,
	) -> Result<(), APIError> {
		let peer_by_intercept_scid = self.peer_by_intercept_scid.read().unwrap();
		if let Some(counterparty_node_id) = peer_by_intercept_scid.get(&intercept_scid) {
			let outer_state_lock = self.per_peer_state.read().unwrap();
			match outer_state_lock.get(counterparty_node_id) {
				Some(inner_state_lock) => {
					let mut peer_state = inner_state_lock.lock().unwrap();
					if let Some(jit_channel) =
						peer_state.outbound_channels_by_intercept_scid.get_mut(&intercept_scid)
					{
						let htlc = InterceptedHTLC {
							intercept_id,
							expected_outbound_amount_msat,
							payment_hash,
						};
						match jit_channel.htlc_intercepted(htlc) {
							Ok(Some(HTLCInterceptedAction::OpenChannel(open_channel_params))) => {
								let event = Event::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
									their_network_key: counterparty_node_id.clone(),
									amt_to_forward_msat: open_channel_params.amt_to_forward_msat,
									opening_fee_msat: open_channel_params.opening_fee_msat,
									user_channel_id: jit_channel.user_channel_id,
									intercept_scid,
								});
								self.pending_events.enqueue(event);
							},
							Ok(Some(HTLCInterceptedAction::ForwardHTLC(channel_id))) => {
								self.channel_manager.get_cm().forward_intercepted_htlc(
									intercept_id,
									&channel_id,
									*counterparty_node_id,
									expected_outbound_amount_msat,
								)?;
							},
							Ok(Some(HTLCInterceptedAction::ForwardPayment(
								channel_id,
								FeePayment { opening_fee_msat, htlcs },
							))) => {
								let amounts_to_forward_msat =
									calculate_amount_to_forward_per_htlc(&htlcs, opening_fee_msat);

								for (intercept_id, amount_to_forward_msat) in
									amounts_to_forward_msat
								{
									self.channel_manager.get_cm().forward_intercepted_htlc(
										intercept_id,
										&channel_id,
										*counterparty_node_id,
										amount_to_forward_msat,
									)?;
								}
							},
							Ok(None) => {},
							Err(e) => {
								self.channel_manager
									.get_cm()
									.fail_intercepted_htlc(intercept_id)?;
								peer_state
									.outbound_channels_by_intercept_scid
									.remove(&intercept_scid);
								// TODO: cleanup peer_by_intercept_scid
								return Err(APIError::APIMisuseError { err: e.err });
							},
						}
					}
				},
				None => {
					return Err(APIError::APIMisuseError {
						err: format!("No counterparty found for scid: {}", intercept_scid),
					});
				},
			}
		}

		Ok(())
	}

	/// Forward [`Event::HTLCHandlingFailed`] event parameter into this function.
	///
	/// Will attempt to forward the next payment in the queue if one is present.
	/// Will do nothing if the intercept scid does not match any of the ones we gave out
	/// or if the payment queue is empty
	///
	/// [`Event::HTLCHandlingFailed`]: lightning::events::Event::HTLCHandlingFailed
	pub fn htlc_handling_failed(
		&self, failed_next_destination: HTLCDestination,
	) -> Result<(), APIError> {
		if let HTLCDestination::NextHopChannel { channel_id, .. } = failed_next_destination {
			let peer_by_channel_id = self.peer_by_channel_id.read().unwrap();
			if let Some(counterparty_node_id) = peer_by_channel_id.get(&channel_id) {
				let outer_state_lock = self.per_peer_state.read().unwrap();
				match outer_state_lock.get(counterparty_node_id) {
					Some(inner_state_lock) => {
						let mut peer_state = inner_state_lock.lock().unwrap();
						if let Some(intercept_scid) =
							peer_state.intercept_scid_by_channel_id.get(&channel_id).copied()
						{
							if let Some(jit_channel) = peer_state
								.outbound_channels_by_intercept_scid
								.get_mut(&intercept_scid)
							{
								match jit_channel.htlc_handling_failed() {
									Ok(Some(ForwardPaymentAction(
										channel_id,
										FeePayment { opening_fee_msat, htlcs },
									))) => {
										let amounts_to_forward_msat =
											calculate_amount_to_forward_per_htlc(
												&htlcs,
												opening_fee_msat,
											);

										for (intercept_id, amount_to_forward_msat) in
											amounts_to_forward_msat
										{
											self.channel_manager
												.get_cm()
												.forward_intercepted_htlc(
													intercept_id,
													&channel_id,
													*counterparty_node_id,
													amount_to_forward_msat,
												)?;
										}
									},
									Ok(None) => {},
									Err(e) => {
										return Err(APIError::APIMisuseError {
											err: format!("Unable to fail HTLC: {}.", e.err),
										});
									},
								}
							}
						}
					},
					None => {},
				}
			}
		}

		Ok(())
	}

	/// Forward [`Event::PaymentForwarded`] event parameter into this function.
	///
	/// Will register the forwarded payment as having paid the JIT channel fee, and forward any held
	/// and future HTLCs for the SCID of the initial invoice. In the future, this will verify the
	/// `skimmed_fee_msat` in [`Event::PaymentForwarded`].
	///
	/// Note that `next_channel_id` is required to be provided. Therefore, the corresponding
	/// [`Event::PaymentForwarded`] events need to be generated and serialized by LDK versions
	/// greater or equal to 0.0.107.
	///
	/// [`Event::PaymentForwarded`]: lightning::events::Event::PaymentForwarded
	pub fn payment_forwarded(&self, next_channel_id: ChannelId) -> Result<(), APIError> {
		if let Some(counterparty_node_id) =
			self.peer_by_channel_id.read().unwrap().get(&next_channel_id)
		{
			let outer_state_lock = self.per_peer_state.read().unwrap();
			match outer_state_lock.get(&counterparty_node_id) {
				Some(inner_state_lock) => {
					let mut peer_state = inner_state_lock.lock().unwrap();
					if let Some(intercept_scid) =
						peer_state.intercept_scid_by_channel_id.get(&next_channel_id).copied()
					{
						if let Some(jit_channel) =
							peer_state.outbound_channels_by_intercept_scid.get_mut(&intercept_scid)
						{
							match jit_channel.payment_forwarded() {
								Ok(Some(ForwardHTLCsAction(channel_id, htlcs))) => {
									for htlc in htlcs {
										self.channel_manager.get_cm().forward_intercepted_htlc(
											htlc.intercept_id,
											&channel_id,
											*counterparty_node_id,
											htlc.expected_outbound_amount_msat,
										)?;
									}
								},
								Ok(None) => {},
								Err(e) => {
									return Err(APIError::APIMisuseError {
										err: format!(
											"Forwarded payment was not applicable for JIT channel: {}",
											e.err
										),
									})
								},
							}
						}
					} else {
						return Err(APIError::APIMisuseError {
							err: format!("No state for for channel id: {}", next_channel_id),
						});
					}
				},
				None => {
					return Err(APIError::APIMisuseError {
						err: format!("No counterparty state for: {}", counterparty_node_id),
					});
				},
			}
		}

		Ok(())
	}

	/// Forward [`Event::ChannelReady`] event parameters into this function.
	///
	/// Will forward the intercepted HTLC if it matches a channel
	/// we need to forward a payment over otherwise it will be ignored.
	///
	/// [`Event::ChannelReady`]: lightning::events::Event::ChannelReady
	pub fn channel_ready(
		&self, user_channel_id: u128, channel_id: &ChannelId, counterparty_node_id: &PublicKey,
	) -> Result<(), APIError> {
		{
			let mut peer_by_channel_id = self.peer_by_channel_id.write().unwrap();
			peer_by_channel_id.insert(*channel_id, *counterparty_node_id);
		}
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();
				if let Some(intercept_scid) =
					peer_state.intercept_scid_by_user_channel_id.get(&user_channel_id).copied()
				{
					peer_state.intercept_scid_by_channel_id.insert(*channel_id, intercept_scid);
					if let Some(jit_channel) =
						peer_state.outbound_channels_by_intercept_scid.get_mut(&intercept_scid)
					{
						match jit_channel.channel_ready(*channel_id) {
							Ok(ForwardPaymentAction(
								channel_id,
								FeePayment { opening_fee_msat, htlcs },
							)) => {
								let amounts_to_forward_msat =
									calculate_amount_to_forward_per_htlc(&htlcs, opening_fee_msat);

								for (intercept_id, amount_to_forward_msat) in
									amounts_to_forward_msat
								{
									self.channel_manager.get_cm().forward_intercepted_htlc(
										intercept_id,
										&channel_id,
										*counterparty_node_id,
										amount_to_forward_msat,
									)?;
								}
							},
							Err(e) => {
								return Err(APIError::APIMisuseError {
									err: format!(
										"Failed to transition to channel ready: {}",
										e.err
									),
								})
							},
						}
					} else {
						return Err(APIError::APIMisuseError {
							err: format!(
								"Could not find a channel with user_channel_id {}",
								user_channel_id
							),
						});
					}
				} else {
					return Err(APIError::APIMisuseError {
						err: format!(
							"Could not find a channel with that user_channel_id {}",
							user_channel_id
						),
					});
				}
			},
			None => {
				return Err(APIError::APIMisuseError {
					err: format!("No counterparty state for: {}", counterparty_node_id),
				});
			},
		}

		Ok(())
	}

	fn handle_get_info_request(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, params: GetInfoRequest,
	) -> Result<(), LightningError> {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock: &mut Mutex<PeerState> =
			outer_state_lock.entry(*counterparty_node_id).or_insert(Mutex::new(PeerState::new()));
		let mut peer_state_lock = inner_state_lock.lock().unwrap();
		peer_state_lock
			.pending_requests
			.insert(request_id.clone(), LSPS2Request::GetInfo(params.clone()));

		let event = Event::LSPS2Service(LSPS2ServiceEvent::GetInfo {
			request_id,
			counterparty_node_id: *counterparty_node_id,
			token: params.token,
		});
		self.pending_events.enqueue(event);
		Ok(())
	}

	fn handle_buy_request(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, params: BuyRequest,
	) -> Result<(), LightningError> {
		if let Some(payment_size_msat) = params.payment_size_msat {
			if payment_size_msat < params.opening_fee_params.min_payment_size_msat {
				let response = LSPS2Response::BuyError(ResponseError {
					code: LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_SMALL_ERROR_CODE,
					message: "payment size is below our minimum supported payment size".to_string(),
					data: None,
				});
				let msg = LSPS2Message::Response(request_id, response).into();
				self.pending_messages.enqueue(counterparty_node_id, msg);

				return Err(LightningError {
					err: "payment size is below our minimum supported payment size".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			}

			if payment_size_msat > params.opening_fee_params.max_payment_size_msat {
				let response = LSPS2Response::BuyError(ResponseError {
					code: LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_LARGE_ERROR_CODE,
					message: "payment size is above our maximum supported payment size".to_string(),
					data: None,
				});
				let msg = LSPS2Message::Response(request_id, response).into();
				self.pending_messages.enqueue(counterparty_node_id, msg);
				return Err(LightningError {
					err: "payment size is above our maximum supported payment size".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			}

			match compute_opening_fee(
				payment_size_msat,
				params.opening_fee_params.min_fee_msat,
				params.opening_fee_params.proportional.into(),
			) {
				Some(opening_fee) => {
					if opening_fee >= payment_size_msat {
						let response = LSPS2Response::BuyError(ResponseError {
							code: LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_SMALL_ERROR_CODE,
							message: "payment size is too small to cover the opening fee"
								.to_string(),
							data: None,
						});
						let msg = LSPS2Message::Response(request_id, response).into();
						self.pending_messages.enqueue(counterparty_node_id, msg);
						return Err(LightningError {
							err: "payment size is too small to cover the opening fee".to_string(),
							action: ErrorAction::IgnoreAndLog(Level::Info),
						});
					}
				},
				None => {
					let response = LSPS2Response::BuyError(ResponseError {
						code: LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_LARGE_ERROR_CODE,
						message: "overflow error when calculating opening_fee".to_string(),
						data: None,
					});
					let msg = LSPS2Message::Response(request_id, response).into();
					self.pending_messages.enqueue(counterparty_node_id, msg);
					return Err(LightningError {
						err: "overflow error when calculating opening_fee".to_string(),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				},
			}
		}

		// TODO: if payment_size_msat is specified, make sure our node has sufficient incoming liquidity from public network to receive it.

		if !is_valid_opening_fee_params(&params.opening_fee_params, &self.config.promise_secret) {
			let response = LSPS2Response::BuyError(ResponseError {
				code: LSPS2_BUY_REQUEST_INVALID_OPENING_FEE_PARAMS_ERROR_CODE,
				message: "valid_until is already past OR the promise did not match the provided parameters".to_string(),
				data: None,
			});
			let msg = LSPS2Message::Response(request_id, response).into();
			self.pending_messages.enqueue(counterparty_node_id, msg);
			return Err(LightningError {
				err: "invalid opening fee parameters were supplied by client".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(*counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock
				.pending_requests
				.insert(request_id.clone(), LSPS2Request::Buy(params.clone()));
		}

		let event = Event::LSPS2Service(LSPS2ServiceEvent::BuyRequest {
			request_id,
			counterparty_node_id: *counterparty_node_id,
			opening_fee_params: params.opening_fee_params,
			payment_size_msat: params.payment_size_msat,
		});
		self.pending_events.enqueue(event);

		Ok(())
	}
}

impl<CM: Deref + Clone> ProtocolMessageHandler for LSPS2ServiceHandler<CM>
where
	CM::Target: AChannelManager,
{
	type ProtocolMessage = LSPS2Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(2);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS2Message::Request(request_id, request) => match request {
				LSPS2Request::GetInfo(params) => {
					self.handle_get_info_request(request_id, counterparty_node_id, params)
				},
				LSPS2Request::Buy(params) => {
					self.handle_buy_request(request_id, counterparty_node_id, params)
				},
			},
			_ => {
				debug_assert!(
					false,
					"Service handler received LSPS2 response message. This should never happen."
				);
				Err(LightningError { err: format!("Service handler received LSPS2 response message from node {:?}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
			},
		}
	}
}

fn calculate_amount_to_forward_per_htlc(
	htlcs: &[InterceptedHTLC], total_fee_msat: u64,
) -> Vec<(InterceptId, u64)> {
	// TODO: we should eventually make sure the HTLCs are all above ChannelDetails::next_outbound_minimum_msat
	let total_expected_outbound_msat: u64 =
		htlcs.iter().map(|htlc| htlc.expected_outbound_amount_msat).sum();
	if total_fee_msat > total_expected_outbound_msat {
		debug_assert!(false, "Fee is larger than the total expected outbound amount.");
		return Vec::new();
	}

	let mut fee_remaining_msat = total_fee_msat;
	let mut per_htlc_forwards = vec![];
	for (index, htlc) in htlcs.iter().enumerate() {
		let proportional_fee_amt_msat = (total_fee_msat as u128
			* htlc.expected_outbound_amount_msat as u128
			/ total_expected_outbound_msat as u128) as u64;

		let mut actual_fee_amt_msat = core::cmp::min(fee_remaining_msat, proportional_fee_amt_msat);
		actual_fee_amt_msat =
			core::cmp::min(actual_fee_amt_msat, htlc.expected_outbound_amount_msat);
		fee_remaining_msat -= actual_fee_amt_msat;

		if index == htlcs.len() - 1 {
			actual_fee_amt_msat += fee_remaining_msat;
		}

		let amount_to_forward_msat =
			htlc.expected_outbound_amount_msat.saturating_sub(actual_fee_amt_msat);

		per_htlc_forwards.push((htlc.intercept_id, amount_to_forward_msat))
	}
	per_htlc_forwards
}

#[cfg(test)]
mod tests {

	use super::*;
	use chrono::TimeZone;
	use chrono::Utc;
	use proptest::prelude::*;

	const MAX_VALUE_MSAT: u64 = 21_000_000_0000_0000_000;

	fn arb_forward_amounts() -> impl Strategy<Value = (u64, u64, u64, u64)> {
		(1u64..MAX_VALUE_MSAT, 1u64..MAX_VALUE_MSAT, 1u64..MAX_VALUE_MSAT, 1u64..MAX_VALUE_MSAT)
			.prop_map(|(a, b, c, d)| {
				(a, b, c, core::cmp::min(d, a.saturating_add(b).saturating_add(c)))
			})
	}

	proptest! {
		#[test]
		fn proptest_calculate_amount_to_forward((o_0, o_1, o_2, total_fee_msat) in arb_forward_amounts()) {
			let htlcs = vec![
				InterceptedHTLC {
					intercept_id: InterceptId([0; 32]),
					expected_outbound_amount_msat: o_0,
					payment_hash: PaymentHash([0; 32]),
				},
				InterceptedHTLC {
					intercept_id: InterceptId([1; 32]),
					expected_outbound_amount_msat: o_1,
					payment_hash: PaymentHash([0; 32]),
				},
				InterceptedHTLC {
					intercept_id: InterceptId([2; 32]),
					expected_outbound_amount_msat: o_2,
					payment_hash: PaymentHash([0; 32]),
				},
			];

			let result = calculate_amount_to_forward_per_htlc(&htlcs, total_fee_msat);
			let total_received_msat = o_0 + o_1 + o_2;

			if total_received_msat < total_fee_msat {
				assert_eq!(result.len(), 0);
			} else {
				assert_ne!(result.len(), 0);
				assert_eq!(result[0].0, htlcs[0].intercept_id);
				assert_eq!(result[1].0, htlcs[1].intercept_id);
				assert_eq!(result[2].0, htlcs[2].intercept_id);
				assert!(result[0].1 <= o_0);
				assert!(result[1].1 <= o_1);
				assert!(result[2].1 <= o_2);

				let result_sum = result.iter().map(|(_, f)| f).sum::<u64>();
				assert_eq!(total_received_msat - result_sum, total_fee_msat);
				let five_pct = result_sum as f32 * 0.05;
				let fair_share_0 = (o_0 as f32 / total_received_msat as f32) * result_sum as f32;
				assert!(result[0].1 as f32 <= fair_share_0 + five_pct);
				let fair_share_1 = (o_1 as f32 / total_received_msat as f32) * result_sum as f32;
				assert!(result[1].1 as f32 <= fair_share_1 + five_pct);
				let fair_share_2 = (o_2 as f32 / total_received_msat as f32) * result_sum as f32;
				assert!(result[2].1 as f32 <= fair_share_2 + five_pct);
			}
		}
	}

	#[test]
	fn test_calculate_amount_to_forward() {
		let htlcs = vec![
			InterceptedHTLC {
				intercept_id: InterceptId([0; 32]),
				expected_outbound_amount_msat: 2,
				payment_hash: PaymentHash([0; 32]),
			},
			InterceptedHTLC {
				intercept_id: InterceptId([1; 32]),
				expected_outbound_amount_msat: 6,
				payment_hash: PaymentHash([0; 32]),
			},
			InterceptedHTLC {
				intercept_id: InterceptId([2; 32]),
				expected_outbound_amount_msat: 2,
				payment_hash: PaymentHash([0; 32]),
			},
		];
		let result = calculate_amount_to_forward_per_htlc(&htlcs, 5);
		assert_eq!(
			result,
			vec![
				(htlcs[0].intercept_id, 1),
				(htlcs[1].intercept_id, 3),
				(htlcs[2].intercept_id, 1),
			]
		);
	}

	#[test]
	fn test_jit_channel_state_mpp() {
		let payment_size_msat = Some(500_000_000);
		let opening_fee_params = OpeningFeeParams {
			min_fee_msat: 10_000_000,
			proportional: 10_000,
			valid_until: Utc.timestamp_opt(3000, 0).unwrap(),
			min_lifetime: 4032,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10_000_000,
			max_payment_size_msat: 1_000_000_000,
			promise: "ignore".to_string(),
		};
		let mut state = OutboundJITChannelState::new();
		// Intercepts the first HTLC of a multipart payment A.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([0; 32]),
						expected_outbound_amount_msat: 200_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingInitialPayment { .. }));
			assert!(action.is_none());
			state = new_state;
		}
		// Intercepts the first HTLC of a different multipart payment B.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([1; 32]),
						expected_outbound_amount_msat: 1_000_000,
						payment_hash: PaymentHash([101; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingInitialPayment { .. }));
			assert!(action.is_none());
			state = new_state;
		}
		// Intercepts the second HTLC of multipart payment A, completing the expected payment and
		// opening the channel.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([2; 32]),
						expected_outbound_amount_msat: 300_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(matches!(action, Some(HTLCInterceptedAction::OpenChannel(_))));
			state = new_state;
		}
		// Channel opens, becomes ready, and multipart payment A gets forwarded.
		{
			let (new_state, ForwardPaymentAction(channel_id, payment)) =
				state.channel_ready(ChannelId([200; 32])).unwrap();
			assert_eq!(channel_id, ChannelId([200; 32]));
			assert_eq!(payment.opening_fee_msat, 10_000_000);
			assert_eq!(
				payment.htlcs,
				vec![
					InterceptedHTLC {
						intercept_id: InterceptId([0; 32]),
						expected_outbound_amount_msat: 200_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
					InterceptedHTLC {
						intercept_id: InterceptId([2; 32]),
						expected_outbound_amount_msat: 300_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
				]
			);
			state = new_state;
		}
		// Intercepts the first HTLC of a different payment C.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([3; 32]),
						expected_outbound_amount_msat: 2_000_000,
						payment_hash: PaymentHash([102; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingPaymentForward { .. }));
			assert!(action.is_none());
			state = new_state;
		}
		// Payment A fails.
		{
			let (new_state, action) = state.htlc_handling_failed().unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingPayment { .. }));
			// No payments have received sufficient HTLCs yet.
			assert!(action.is_none());
			state = new_state;
		}
		// Additional HTLC of payment B arrives, completing the expectd payment.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([4; 32]),
						expected_outbound_amount_msat: 500_000_000,
						payment_hash: PaymentHash([101; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingPaymentForward { .. }));
			match action {
				Some(HTLCInterceptedAction::ForwardPayment(channel_id, payment)) => {
					assert_eq!(channel_id, ChannelId([200; 32]));
					assert_eq!(payment.opening_fee_msat, 10_000_000);
					assert_eq!(
						payment.htlcs,
						vec![
							InterceptedHTLC {
								intercept_id: InterceptId([1; 32]),
								expected_outbound_amount_msat: 1_000_000,
								payment_hash: PaymentHash([101; 32]),
							},
							InterceptedHTLC {
								intercept_id: InterceptId([4; 32]),
								expected_outbound_amount_msat: 500_000_000,
								payment_hash: PaymentHash([101; 32]),
							},
						]
					);
				},
				_ => panic!("Unexpected action when intercepted HTLC."),
			}
			state = new_state;
		}
		// Payment completes, queued payments get forwarded.
		{
			let (new_state, action) = state.payment_forwarded().unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PaymentForwarded { .. }));
			match action {
				Some(ForwardHTLCsAction(channel_id, htlcs)) => {
					assert_eq!(channel_id, ChannelId([200; 32]));
					assert_eq!(
						htlcs,
						vec![InterceptedHTLC {
							intercept_id: InterceptId([3; 32]),
							expected_outbound_amount_msat: 2_000_000,
							payment_hash: PaymentHash([102; 32]),
						}]
					);
				},
				_ => panic!("Unexpected action when forwarded payment."),
			}
			state = new_state;
		}
		// Any new HTLC gets automatically forwarded.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([5; 32]),
						expected_outbound_amount_msat: 200_000_000,
						payment_hash: PaymentHash([103; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PaymentForwarded { .. }));
			assert!(
				matches!(action, Some(HTLCInterceptedAction::ForwardHTLC(channel_id)) if channel_id == ChannelId([200; 32]))
			);
		}
	}

	#[test]
	fn test_jit_channel_state_no_mpp() {
		let payment_size_msat = None;
		let opening_fee_params = OpeningFeeParams {
			min_fee_msat: 10_000_000,
			proportional: 10_000,
			valid_until: Utc.timestamp_opt(3000, 0).unwrap(),
			min_lifetime: 4032,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10_000_000,
			max_payment_size_msat: 1_000_000_000,
			promise: "ignore".to_string(),
		};
		let mut state = OutboundJITChannelState::new();
		// Intercepts payment A, opening the channel.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([0; 32]),
						expected_outbound_amount_msat: 500_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(matches!(action, Some(HTLCInterceptedAction::OpenChannel(_))));
			state = new_state;
		}
		// Intercepts payment B.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([1; 32]),
						expected_outbound_amount_msat: 600_000_000,
						payment_hash: PaymentHash([101; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(action.is_none());
			state = new_state;
		}
		// Channel opens, becomes ready, and payment A gets forwarded.
		{
			let (new_state, ForwardPaymentAction(channel_id, payment)) =
				state.channel_ready(ChannelId([200; 32])).unwrap();
			assert_eq!(channel_id, ChannelId([200; 32]));
			assert_eq!(payment.opening_fee_msat, 10_000_000);
			assert_eq!(
				payment.htlcs,
				vec![InterceptedHTLC {
					intercept_id: InterceptId([0; 32]),
					expected_outbound_amount_msat: 500_000_000,
					payment_hash: PaymentHash([100; 32]),
				},]
			);
			state = new_state;
		}
		// Intercepts payment C.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([2; 32]),
						expected_outbound_amount_msat: 500_000_000,
						payment_hash: PaymentHash([102; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingPaymentForward { .. }));
			assert!(action.is_none());
			state = new_state;
		}
		// Payment A fails, and payment B is forwarded.
		{
			let (new_state, action) = state.htlc_handling_failed().unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PendingPaymentForward { .. }));
			match action {
				Some(ForwardPaymentAction(channel_id, payment)) => {
					assert_eq!(channel_id, ChannelId([200; 32]));
					assert_eq!(
						payment.htlcs,
						vec![InterceptedHTLC {
							intercept_id: InterceptId([1; 32]),
							expected_outbound_amount_msat: 600_000_000,
							payment_hash: PaymentHash([101; 32]),
						},]
					);
				},
				_ => panic!("Unexpected action when HTLC handling failed."),
			}
			state = new_state;
		}
		// Payment completes, queued payments get forwarded.
		{
			let (new_state, action) = state.payment_forwarded().unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PaymentForwarded { .. }));
			match action {
				Some(ForwardHTLCsAction(channel_id, htlcs)) => {
					assert_eq!(channel_id, ChannelId([200; 32]));
					assert_eq!(
						htlcs,
						vec![InterceptedHTLC {
							intercept_id: InterceptId([2; 32]),
							expected_outbound_amount_msat: 500_000_000,
							payment_hash: PaymentHash([102; 32]),
						}]
					);
				},
				_ => panic!("Unexpected action when forwarded payment."),
			}
			state = new_state;
		}
		// Any new HTLC gets automatically forwarded.
		{
			let (new_state, action) = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([3; 32]),
						expected_outbound_amount_msat: 200_000_000,
						payment_hash: PaymentHash([103; 32]),
					},
				)
				.unwrap();
			assert!(matches!(new_state, OutboundJITChannelState::PaymentForwarded { .. }));
			assert!(
				matches!(action, Some(HTLCInterceptedAction::ForwardHTLC(channel_id)) if channel_id == ChannelId([200; 32]))
			);
		}
	}
}
