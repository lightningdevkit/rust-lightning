// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main bLIP-52 / LSPS2 server-side object, [`LSPS2ServiceHandler`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::cmp::Ordering as CmpOrdering;
use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::events::EventQueue;
use crate::lsps0::ser::{
	LSPSMessage, LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError,
	JSONRPC_INTERNAL_ERROR_ERROR_CODE, JSONRPC_INTERNAL_ERROR_ERROR_MESSAGE,
	LSPS0_CLIENT_REJECTED_ERROR_CODE,
};
use crate::lsps2::event::LSPS2ServiceEvent;
use crate::lsps2::payment_queue::{InterceptedHTLC, PaymentQueue};
use crate::lsps2::utils::{
	compute_opening_fee, is_expired_opening_fee_params, is_valid_opening_fee_params,
};
use crate::message_queue::{MessageQueue, MessageQueueNotifierGuard};
use crate::prelude::hash_map::Entry;
use crate::prelude::{new_hash_map, HashMap};
use crate::sync::{Arc, Mutex, MutexGuard, RwLock};

use lightning::chain::chaininterface::BroadcasterInterface;
use lightning::events::HTLCHandlingFailureType;
use lightning::ln::channelmanager::{AChannelManager, FailureCode, InterceptId};
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::ln::types::ChannelId;
use lightning::util::errors::APIError;
use lightning::util::logger::Level;

use lightning_types::payment::PaymentHash;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Transaction;

use crate::lsps2::msgs::{
	LSPS2BuyRequest, LSPS2BuyResponse, LSPS2GetInfoRequest, LSPS2GetInfoResponse, LSPS2Message,
	LSPS2OpeningFeeParams, LSPS2RawOpeningFeeParams, LSPS2Request, LSPS2Response,
	LSPS2_BUY_REQUEST_INVALID_OPENING_FEE_PARAMS_ERROR_CODE,
	LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_LARGE_ERROR_CODE,
	LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_SMALL_ERROR_CODE,
	LSPS2_GET_INFO_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE,
};

const MAX_PENDING_REQUESTS_PER_PEER: usize = 10;
const MAX_TOTAL_PENDING_REQUESTS: usize = 1000;
const MAX_TOTAL_PEERS: usize = 100000;

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

#[derive(Debug, Clone)]
enum TrustModel {
	ClientTrustsLsp { funding_tx_broadcast_safe: bool, funding_tx: Option<Transaction> },
	LspTrustsClient,
}

impl TrustModel {
	fn should_manually_broadcast(&self, state_is_payment_forward: bool) -> bool {
		match self {
			TrustModel::ClientTrustsLsp { funding_tx_broadcast_safe, funding_tx } => {
				*funding_tx_broadcast_safe && state_is_payment_forward && funding_tx.is_some()
			},
			// in lsp-trusts-client, the broadcast is automatic, so we never need to manually broadcast.
			TrustModel::LspTrustsClient => false,
		}
	}

	fn new(client_trusts_lsp: bool) -> Self {
		if client_trusts_lsp {
			TrustModel::ClientTrustsLsp { funding_tx_broadcast_safe: false, funding_tx: None }
		} else {
			TrustModel::LspTrustsClient
		}
	}

	fn set_funding_tx(&mut self, funding_tx: Transaction) {
		match self {
			TrustModel::ClientTrustsLsp { funding_tx: tx, .. } => {
				*tx = Some(funding_tx);
			},
			TrustModel::LspTrustsClient => {
				// No-op
			},
		}
	}

	fn set_funding_tx_broadcast_safe(&mut self, funding_tx_broadcast_safe: bool) {
		match self {
			TrustModel::ClientTrustsLsp { funding_tx_broadcast_safe: safe, .. } => {
				*safe = funding_tx_broadcast_safe;
			},
			TrustModel::LspTrustsClient => {
				// No-op
			},
		}
	}

	fn get_funding_tx(&self) -> Option<Transaction> {
		match self {
			TrustModel::ClientTrustsLsp { funding_tx, .. } => funding_tx.clone(),
			_ => None,
		}
	}

	fn is_client_trusts_lsp(&self) -> bool {
		match self {
			TrustModel::ClientTrustsLsp { .. } => true,
			TrustModel::LspTrustsClient => false,
		}
	}
}

/// The different states a requested JIT channel can be in.
#[derive(Debug)]
enum OutboundJITChannelState {
	/// The JIT channel SCID was created after a buy request, and we are awaiting an initial payment
	/// of sufficient size to open the channel.
	PendingInitialPayment { payment_queue: PaymentQueue },
	/// An initial payment of sufficient size was intercepted to the JIT channel SCID, triggering the
	/// opening of the channel. We are awaiting the completion of the channel establishment.
	PendingChannelOpen { payment_queue: PaymentQueue, opening_fee_msat: u64 },
	/// The channel is open and a payment was forwarded while skimming the JIT channel fee.
	/// No further payments can be forwarded until the pending payment succeeds or fails, as we need
	/// to know whether the JIT channel fee needs to be skimmed from a next payment or not.
	PendingPaymentForward {
		payment_queue: PaymentQueue,
		opening_fee_msat: u64,
		channel_id: ChannelId,
	},
	/// The channel is open, no payment is currently being forwarded, and the JIT channel fee still
	/// needs to be paid. This state can occur when the initial payment fails, e.g. due to a
	/// prepayment probe. We are awaiting a next payment of sufficient size to forward and skim the
	/// JIT channel fee.
	PendingPayment { payment_queue: PaymentQueue, opening_fee_msat: u64, channel_id: ChannelId },
	/// The channel is open and a payment was successfully forwarded while skimming the JIT channel
	/// fee. Any subsequent HTLCs can be forwarded without additional logic.
	PaymentForwarded { channel_id: ChannelId },
}

impl OutboundJITChannelState {
	fn new() -> Self {
		OutboundJITChannelState::PendingInitialPayment { payment_queue: PaymentQueue::new() }
	}

	fn htlc_intercepted(
		&mut self, opening_fee_params: &LSPS2OpeningFeeParams, payment_size_msat: &Option<u64>,
		htlc: InterceptedHTLC,
	) -> Result<Option<HTLCInterceptedAction>, ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingInitialPayment { payment_queue } => {
				let (total_expected_outbound_amount_msat, num_htlcs) = payment_queue.add_htlc(htlc);

				let (expected_payment_size_msat, mpp_mode) =
					if let Some(payment_size_msat) = payment_size_msat {
						(*payment_size_msat, true)
					} else {
						debug_assert_eq!(num_htlcs, 1);
						if num_htlcs != 1 {
							return Err(ChannelStateError(
								"Paying via multiple HTLCs is disallowed in \"no-MPP+var-invoice\" mode.".to_string()
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
					))
				)?;

				let amt_to_forward_msat =
					expected_payment_size_msat.saturating_sub(opening_fee_msat);

				// Go ahead and open the channel if we intercepted sufficient HTLCs.
				if total_expected_outbound_amount_msat >= expected_payment_size_msat
					&& amt_to_forward_msat > 0
				{
					*self = OutboundJITChannelState::PendingChannelOpen {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat,
					};
					let open_channel = HTLCInterceptedAction::OpenChannel(OpenChannelParams {
						opening_fee_msat,
						amt_to_forward_msat,
					});
					Ok(Some(open_channel))
				} else {
					if mpp_mode {
						*self = OutboundJITChannelState::PendingInitialPayment {
							payment_queue: core::mem::take(payment_queue),
						};
						Ok(None)
					} else {
						Err(ChannelStateError(
							"Intercepted HTLC is too small to pay opening fee".to_string(),
						))
					}
				}
			},
			OutboundJITChannelState::PendingChannelOpen { payment_queue, opening_fee_msat } => {
				let mut payment_queue = core::mem::take(payment_queue);
				payment_queue.add_htlc(htlc);
				*self = OutboundJITChannelState::PendingChannelOpen {
					payment_queue,
					opening_fee_msat: *opening_fee_msat,
				};
				Ok(None)
			},
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				let mut payment_queue = core::mem::take(payment_queue);
				payment_queue.add_htlc(htlc);
				*self = OutboundJITChannelState::PendingPaymentForward {
					payment_queue,
					opening_fee_msat: *opening_fee_msat,
					channel_id: *channel_id,
				};
				Ok(None)
			},
			OutboundJITChannelState::PendingPayment {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				let mut payment_queue = core::mem::take(payment_queue);
				payment_queue.add_htlc(htlc);
				if let Some(entry) = payment_queue.pop_greater_than_msat(*opening_fee_msat) {
					let forward_payment = HTLCInterceptedAction::ForwardPayment(
						*channel_id,
						FeePayment { htlcs: entry.htlcs, opening_fee_msat: *opening_fee_msat },
					);
					*self = OutboundJITChannelState::PendingPaymentForward {
						payment_queue,
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(Some(forward_payment))
				} else {
					*self = OutboundJITChannelState::PendingPayment {
						payment_queue,
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(None)
				}
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				let forward = HTLCInterceptedAction::ForwardHTLC(*channel_id);
				*self = OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				Ok(Some(forward))
			},
		}
	}

	fn channel_ready(
		&mut self, channel_id: ChannelId,
	) -> Result<ForwardPaymentAction, ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingChannelOpen { payment_queue, opening_fee_msat } => {
				if let Some(entry) = payment_queue.pop_greater_than_msat(*opening_fee_msat) {
					let forward_payment = ForwardPaymentAction(
						channel_id,
						FeePayment { htlcs: entry.htlcs, opening_fee_msat: *opening_fee_msat },
					);
					*self = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id,
					};
					Ok(forward_payment)
				} else {
					return Err(ChannelStateError(
						"No forwardable payment available when moving to channel ready."
							.to_string(),
					));
				}
			},
			state => Err(ChannelStateError(format!(
				"Channel ready received when JIT Channel was in state: {:?}",
				state
			))),
		}
	}

	fn htlc_handling_failed(&mut self) -> Result<Option<ForwardPaymentAction>, ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				if let Some(entry) = payment_queue.pop_greater_than_msat(*opening_fee_msat) {
					let forward_payment = ForwardPaymentAction(
						*channel_id,
						FeePayment { htlcs: entry.htlcs, opening_fee_msat: *opening_fee_msat },
					);
					*self = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(Some(forward_payment))
				} else {
					*self = OutboundJITChannelState::PendingPayment {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(None)
				}
			},
			OutboundJITChannelState::PendingPayment {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				*self = OutboundJITChannelState::PendingPayment {
					payment_queue: core::mem::take(payment_queue),
					opening_fee_msat: *opening_fee_msat,
					channel_id: *channel_id,
				};
				Ok(None)
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				*self = OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				Ok(None)
			},
			state => Err(ChannelStateError(format!(
				"HTLC handling failed when JIT Channel was in state: {:?}",
				state
			))),
		}
	}

	fn payment_forwarded(
		&mut self, skimmed_fee_msat: Option<u64>,
	) -> Result<Option<ForwardHTLCsAction>, ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue,
				channel_id,
				opening_fee_msat,
			} => match skimmed_fee_msat {
				Some(skimmed) if skimmed >= *opening_fee_msat => {
					let mut pq = core::mem::take(payment_queue);
					let forward_htlcs = ForwardHTLCsAction(*channel_id, pq.clear());
					*self = OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
					Ok(Some(forward_htlcs))
				},
				Some(_) | None => {
					*self = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(None)
				},
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				*self = OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				Ok(None)
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
	opening_fee_params: LSPS2OpeningFeeParams,
	payment_size_msat: Option<u64>,
	trust_model: TrustModel,
}

impl OutboundJITChannel {
	fn new(
		payment_size_msat: Option<u64>, opening_fee_params: LSPS2OpeningFeeParams,
		user_channel_id: u128, client_trusts_lsp: bool,
	) -> Self {
		Self {
			user_channel_id,
			state: OutboundJITChannelState::new(),
			opening_fee_params,
			payment_size_msat,
			trust_model: TrustModel::new(client_trusts_lsp),
		}
	}

	fn htlc_intercepted(
		&mut self, htlc: InterceptedHTLC,
	) -> Result<Option<HTLCInterceptedAction>, LightningError> {
		let action =
			self.state.htlc_intercepted(&self.opening_fee_params, &self.payment_size_msat, htlc)?;
		Ok(action)
	}

	fn htlc_handling_failed(&mut self) -> Result<Option<ForwardPaymentAction>, LightningError> {
		let action = self.state.htlc_handling_failed()?;
		Ok(action)
	}

	fn channel_ready(
		&mut self, channel_id: ChannelId,
	) -> Result<ForwardPaymentAction, LightningError> {
		let action = self.state.channel_ready(channel_id)?;
		Ok(action)
	}

	fn payment_forwarded(
		&mut self, skimmed_fee_msat: Option<u64>,
	) -> Result<Option<ForwardHTLCsAction>, LightningError> {
		let action = self.state.payment_forwarded(skimmed_fee_msat)?;
		Ok(action)
	}

	fn is_pending_initial_payment(&self) -> bool {
		matches!(self.state, OutboundJITChannelState::PendingInitialPayment { .. })
	}

	fn is_prunable(&self) -> bool {
		// We deem an OutboundJITChannel prunable if our offer expired and we haven't intercepted
		// any HTLCs initiating the flow yet.
		let is_expired = is_expired_opening_fee_params(&self.opening_fee_params);
		self.is_pending_initial_payment() && is_expired
	}

	fn set_funding_tx(&mut self, funding_tx: Transaction) {
		self.trust_model.set_funding_tx(funding_tx);
	}

	fn set_funding_tx_broadcast_safe(&mut self, funding_tx_broadcast_safe: bool) {
		self.trust_model.set_funding_tx_broadcast_safe(funding_tx_broadcast_safe);
	}

	fn should_broadcast_funding_transaction(&self) -> bool {
		self.trust_model.should_manually_broadcast(matches!(
			self.state,
			OutboundJITChannelState::PaymentForwarded { .. }
		))
	}

	fn get_funding_tx(&self) -> Option<Transaction> {
		self.trust_model.get_funding_tx()
	}

	fn is_client_trusts_lsp(&self) -> bool {
		self.trust_model.is_client_trusts_lsp()
	}
}

struct PeerState {
	outbound_channels_by_intercept_scid: HashMap<u64, OutboundJITChannel>,
	intercept_scid_by_user_channel_id: HashMap<u128, u64>,
	intercept_scid_by_channel_id: HashMap<ChannelId, u64>,
	pending_requests: HashMap<LSPSRequestId, LSPS2Request>,
}

impl PeerState {
	fn new() -> Self {
		let outbound_channels_by_intercept_scid = new_hash_map();
		let pending_requests = new_hash_map();
		let intercept_scid_by_user_channel_id = new_hash_map();
		let intercept_scid_by_channel_id = new_hash_map();
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

	fn prune_expired_request_state(&mut self) {
		self.pending_requests.retain(|_, entry| {
			match entry {
				LSPS2Request::GetInfo(_) => false,
				LSPS2Request::Buy(request) => {
					// Prune any expired buy requests.
					!is_expired_opening_fee_params(&request.opening_fee_params)
				},
			}
		});

		self.outbound_channels_by_intercept_scid.retain(|intercept_scid, entry| {
			if entry.is_prunable() {
				// We abort the flow, and prune any data kept.
				self.intercept_scid_by_channel_id.retain(|_, iscid| intercept_scid != iscid);
				self.intercept_scid_by_user_channel_id.retain(|_, iscid| intercept_scid != iscid);
				return false;
			}
			true
		});
	}

	fn pending_requests_and_channels(&self) -> usize {
		let pending_requests = self.pending_requests.len();
		let pending_outbound_channels = self
			.outbound_channels_by_intercept_scid
			.iter()
			.filter(|(_, v)| v.is_pending_initial_payment())
			.count();
		pending_requests + pending_outbound_channels
	}

	fn is_prunable(&self) -> bool {
		// Return whether the entire state is empty.
		self.pending_requests.is_empty() && self.outbound_channels_by_intercept_scid.is_empty()
	}
}

macro_rules! get_or_insert_peer_state_entry {
	($self: ident, $outer_state_lock: expr, $message_queue_notifier: expr, $counterparty_node_id: expr) => {{
		// Return an internal error and abort if we hit the maximum allowed number of total peers.
		let is_limited_by_max_total_peers = $outer_state_lock.len() >= MAX_TOTAL_PEERS;
		match $outer_state_lock.entry(*$counterparty_node_id) {
			Entry::Vacant(e) => {
				if is_limited_by_max_total_peers {
					let error_response = LSPSResponseError {
						code: JSONRPC_INTERNAL_ERROR_ERROR_CODE,
						message: JSONRPC_INTERNAL_ERROR_ERROR_MESSAGE.to_string(), data: None,
					};

					let msg = LSPSMessage::Invalid(error_response);
					$message_queue_notifier.enqueue($counterparty_node_id, msg);

					let err = format!(
						"Dropping request from peer {} due to reaching maximally allowed number of total peers: {}",
						$counterparty_node_id, MAX_TOTAL_PEERS
					);

					return Err(LightningError { err, action: ErrorAction::IgnoreAndLog(Level::Error) });
				} else {
					e.insert(Mutex::new(PeerState::new()))
				}
			}
			Entry::Occupied(e) => {
				e.into_mut()
			}
		}

	}}
}

/// The main object allowing to send and receive bLIP-52 / LSPS2 messages.
pub struct LSPS2ServiceHandler<CM: Deref, T: Deref>
where
	CM::Target: AChannelManager,
	T::Target: BroadcasterInterface,
{
	channel_manager: CM,
	tx_broadcaster: T,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	peer_by_intercept_scid: RwLock<HashMap<u64, PublicKey>>,
	peer_by_channel_id: RwLock<HashMap<ChannelId, PublicKey>>,
	total_pending_requests: AtomicUsize,
	config: LSPS2ServiceConfig,
}

impl<CM: Deref, T: Deref> LSPS2ServiceHandler<CM, T>
where
	CM::Target: AChannelManager,
	T::Target: BroadcasterInterface,
{
	/// Constructs a `LSPS2ServiceHandler`.
	pub(crate) fn new(
		pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>, channel_manager: CM,
		tx_broadcaster: T, config: LSPS2ServiceConfig,
	) -> Self {
		Self {
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
			peer_by_intercept_scid: RwLock::new(new_hash_map()),
			peer_by_channel_id: RwLock::new(new_hash_map()),
			total_pending_requests: AtomicUsize::new(0),
			channel_manager,
			tx_broadcaster,
			config,
		}
	}

	/// Returns a reference to the used config.
	pub fn config(&self) -> &LSPS2ServiceConfig {
		&self.config
	}

	/// Used by LSP to inform a client requesting a JIT Channel the token they used is invalid.
	///
	/// Should be called in response to receiving a [`LSPS2ServiceEvent::GetInfo`] event.
	///
	/// [`LSPS2ServiceEvent::GetInfo`]: crate::lsps2::event::LSPS2ServiceEvent::GetInfo
	pub fn invalid_token_provided(
		&self, counterparty_node_id: &PublicKey, request_id: LSPSRequestId,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();

		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				match self.remove_pending_request(&mut peer_state_lock, &request_id) {
					Some(LSPS2Request::GetInfo(_)) => {
						let response = LSPS2Response::GetInfoError(LSPSResponseError {
							code: LSPS2_GET_INFO_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE,
							message: "an unrecognized or stale token was provided".to_string(),
							data: None,
						});
						let msg = LSPS2Message::Response(request_id, response).into();
						message_queue_notifier.enqueue(counterparty_node_id, msg);
						Ok(())
					},
					_ => Err(APIError::APIMisuseError {
						err: format!(
							"No pending get_info request for request_id: {:?}",
							request_id
						),
					}),
				}
			},
			None => Err(APIError::APIMisuseError {
				err: format!("No state for the counterparty exists: {:?}", counterparty_node_id),
			}),
		}
	}

	/// Used by LSP to provide fee parameters to a client requesting a JIT Channel.
	///
	/// Should be called in response to receiving a [`LSPS2ServiceEvent::GetInfo`] event.
	///
	/// [`LSPS2ServiceEvent::GetInfo`]: crate::lsps2::event::LSPS2ServiceEvent::GetInfo
	pub fn opening_fee_params_generated(
		&self, counterparty_node_id: &PublicKey, request_id: LSPSRequestId,
		opening_fee_params_menu: Vec<LSPS2RawOpeningFeeParams>,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();

		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				match self.remove_pending_request(&mut peer_state_lock, &request_id) {
					Some(LSPS2Request::GetInfo(_)) => {
						let mut opening_fee_params_menu: Vec<LSPS2OpeningFeeParams> =
							opening_fee_params_menu
								.into_iter()
								.map(|param| {
									param.into_opening_fee_params(&self.config.promise_secret)
								})
								.collect();
						opening_fee_params_menu.sort_by(|a, b| {
							match a.min_fee_msat.cmp(&b.min_fee_msat) {
								CmpOrdering::Equal => a.proportional.cmp(&b.proportional),
								other => other,
							}
						});
						let response = LSPS2Response::GetInfo(LSPS2GetInfoResponse {
							opening_fee_params_menu,
						});
						let msg = LSPS2Message::Response(request_id, response).into();
						message_queue_notifier.enqueue(counterparty_node_id, msg);
						Ok(())
					},
					_ => Err(APIError::APIMisuseError {
						err: format!(
							"No pending get_info request for request_id: {:?}",
							request_id
						),
					}),
				}
			},
			None => Err(APIError::APIMisuseError {
				err: format!("No state for the counterparty exists: {:?}", counterparty_node_id),
			}),
		}
	}

	/// Used by LSP to provide the client with the intercept scid and
	/// `cltv_expiry_delta` to include in their invoice. The intercept scid
	/// must be retrieved from [`ChannelManager::get_intercept_scid`].
	///
	/// Should be called in response to receiving a [`LSPS2ServiceEvent::BuyRequest`] event.
	///
	/// `client_trusts_lsp`:
	/// * false (default) => "LSP trusts client": LSP broadcasts the funding
	///   transaction as soon as it is safe and forwards the payment normally.
	/// * true => "Client trusts LSP": LSP may defer broadcasting the funding
	///   transaction until after the client claims the forwarded HTLC(s).
	///
	/// [`ChannelManager::get_intercept_scid`]: lightning::ln::channelmanager::ChannelManager::get_intercept_scid
	/// [`LSPS2ServiceEvent::BuyRequest`]: crate::lsps2::event::LSPS2ServiceEvent::BuyRequest
	pub fn invoice_parameters_generated(
		&self, counterparty_node_id: &PublicKey, request_id: LSPSRequestId, intercept_scid: u64,
		cltv_expiry_delta: u32, client_trusts_lsp: bool, user_channel_id: u128,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();

		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();

				match self.remove_pending_request(&mut peer_state_lock, &request_id) {
					Some(LSPS2Request::Buy(buy_request)) => {
						{
							let mut peer_by_intercept_scid =
								self.peer_by_intercept_scid.write().unwrap();
							peer_by_intercept_scid.insert(intercept_scid, *counterparty_node_id);
						}

						let outbound_jit_channel = OutboundJITChannel::new(
							buy_request.payment_size_msat,
							buy_request.opening_fee_params,
							user_channel_id,
							client_trusts_lsp,
						);

						peer_state_lock
							.intercept_scid_by_user_channel_id
							.insert(user_channel_id, intercept_scid);
						peer_state_lock
							.insert_outbound_channel(intercept_scid, outbound_jit_channel);

						let response = LSPS2Response::Buy(LSPS2BuyResponse {
							jit_channel_scid: intercept_scid.into(),
							lsp_cltv_expiry_delta: cltv_expiry_delta,
							client_trusts_lsp,
						});
						let msg = LSPS2Message::Response(request_id, response).into();
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
		let event_queue_notifier = self.pending_events.notifier();

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
								let event = LSPS2ServiceEvent::OpenChannel {
									their_network_key: counterparty_node_id.clone(),
									amt_to_forward_msat: open_channel_params.amt_to_forward_msat,
									opening_fee_msat: open_channel_params.opening_fee_msat,
									user_channel_id: jit_channel.user_channel_id,
									intercept_scid,
								};
								event_queue_notifier.enqueue(event);
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
		&self, failure_type: HTLCHandlingFailureType,
	) -> Result<(), APIError> {
		if let HTLCHandlingFailureType::Forward { channel_id, .. } = failure_type {
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
	/// and future HTLCs for the SCID of the initial invoice.
	///
	/// When the reported skimmed fee equals or exceeds the promised opening fee, any HTLCs that
	/// were being held for that JIT channel are forwarded. In a `client_trusts_lsp` flow, once
	/// the fee has been fully paid a [`LSPS2ServiceEvent::BroadcastFundingTransaction`] will be emitted so the
	/// caller can broadcast it.
	///
	/// Note that `next_channel_id` is required to be provided. Therefore, the corresponding
	/// [`Event::PaymentForwarded`] events need to be generated and serialized by LDK versions
	/// greater or equal to 0.0.107.
	///
	/// [`Event::PaymentForwarded`]: lightning::events::Event::PaymentForwarded
	/// [`Event::BroadcastFundingTransaction`]: crate::lsps2::event::LSPS2ServiceEvent::BroadcastFundingTransaction
	pub fn payment_forwarded(
		&self, next_channel_id: ChannelId, skimmed_fee_msat: Option<u64>,
	) -> Result<(), APIError> {
		if let Some(counterparty_node_id) =
			self.peer_by_channel_id.read().unwrap().get(&next_channel_id)
		{
			let outer_state_lock = self.per_peer_state.read().unwrap();
			match outer_state_lock.get(counterparty_node_id) {
				Some(inner_state_lock) => {
					let mut peer_state = inner_state_lock.lock().unwrap();
					if let Some(intercept_scid) =
						peer_state.intercept_scid_by_channel_id.get(&next_channel_id).copied()
					{
						if let Some(jit_channel) =
							peer_state.outbound_channels_by_intercept_scid.get_mut(&intercept_scid)
						{
							match jit_channel.payment_forwarded(skimmed_fee_msat) {
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

							self.emit_broadcast_funding_transaction_event_if_applies(
								jit_channel,
								counterparty_node_id,
							);
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

	/// Abandons a pending JIT‐open flow for `user_channel_id`, removing all local state.
	///
	/// This removes the intercept SCID, any outbound channel state, and associated
	/// channel‐ID mappings for the specified `user_channel_id`, but only while no payment
	/// has been forwarded yet and no channel has been opened on-chain.
	///
	/// Returns an error if:
	///  - there is no channel matching `user_channel_id`, or
	///  - a payment has already been forwarded or a channel has already been opened
	///
	/// Note: this does *not* close or roll back any on‐chain channel which may already
	/// have been opened. The caller must call this before or instead of initiating the channel
	/// open, as it only affects the local LSPS2 state and doesn't affect any channels that
	/// might already exist on-chain. Any pending channel open attempts must be managed
	/// separately.
	pub fn channel_open_abandoned(
		&self, counterparty_node_id: &PublicKey, user_channel_id: u128,
	) -> Result<(), APIError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		let inner_state_lock =
			outer_state_lock.get(counterparty_node_id).ok_or_else(|| APIError::APIMisuseError {
				err: format!("No counterparty state for: {}", counterparty_node_id),
			})?;
		let mut peer_state = inner_state_lock.lock().unwrap();

		let intercept_scid = peer_state
			.intercept_scid_by_user_channel_id
			.get(&user_channel_id)
			.copied()
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Could not find a channel with user_channel_id {}", user_channel_id),
			})?;

		let jit_channel = peer_state
			.outbound_channels_by_intercept_scid
			.get(&intercept_scid)
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!(
					"Failed to map intercept_scid {} for user_channel_id {} to a channel.",
					intercept_scid, user_channel_id,
				),
			})?;

		let is_pending = matches!(
			jit_channel.state,
			OutboundJITChannelState::PendingInitialPayment { .. }
				| OutboundJITChannelState::PendingChannelOpen { .. }
		);

		if !is_pending {
			return Err(APIError::APIMisuseError {
				err: "Cannot abandon channel open after channel creation or payment forwarding"
					.to_string(),
			});
		}

		peer_state.intercept_scid_by_user_channel_id.remove(&user_channel_id);
		peer_state.outbound_channels_by_intercept_scid.remove(&intercept_scid);
		peer_state.intercept_scid_by_channel_id.retain(|_, &mut scid| scid != intercept_scid);

		Ok(())
	}

	/// Used to fail intercepted HTLCs backwards when a channel open attempt ultimately fails.
	///
	/// This function should be called after receiving an [`LSPS2ServiceEvent::OpenChannel`] event
	/// but only if the channel could not be successfully established. It resets the JIT channel
	/// state so that the payer may try the payment again.
	///
	/// [`LSPS2ServiceEvent::OpenChannel`]: crate::lsps2::event::LSPS2ServiceEvent::OpenChannel
	pub fn channel_open_failed(
		&self, counterparty_node_id: &PublicKey, user_channel_id: u128,
	) -> Result<(), APIError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();

		let inner_state_lock =
			outer_state_lock.get(counterparty_node_id).ok_or_else(|| APIError::APIMisuseError {
				err: format!("No counterparty state for: {}", counterparty_node_id),
			})?;

		let mut peer_state = inner_state_lock.lock().unwrap();

		let intercept_scid = peer_state
			.intercept_scid_by_user_channel_id
			.get(&user_channel_id)
			.copied()
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Could not find a channel with user_channel_id {}", user_channel_id),
			})?;

		let jit_channel = peer_state
			.outbound_channels_by_intercept_scid
			.get_mut(&intercept_scid)
			.ok_or_else(|| APIError::APIMisuseError {
			err: format!(
				"Failed to map intercept_scid {} for user_channel_id {} to a channel.",
				intercept_scid, user_channel_id,
			),
		})?;

		if let OutboundJITChannelState::PendingChannelOpen { payment_queue, .. } =
			&mut jit_channel.state
		{
			let intercepted_htlcs = payment_queue.clear();
			for htlc in intercepted_htlcs {
				self.channel_manager.get_cm().fail_htlc_backwards_with_reason(
					&htlc.payment_hash,
					FailureCode::TemporaryNodeFailure,
				);
			}

			jit_channel.state = OutboundJITChannelState::PendingInitialPayment {
				payment_queue: PaymentQueue::new(),
			};
			Ok(())
		} else {
			Err(APIError::APIMisuseError {
				err: "Channel is not in the PendingChannelOpen state.".to_string(),
			})
		}
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
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		params: LSPS2GetInfoRequest,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();
		let event_queue_notifier = self.pending_events.notifier();

		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock = get_or_insert_peer_state_entry!(
			self,
			outer_state_lock,
			message_queue_notifier,
			counterparty_node_id
		);
		let mut peer_state_lock = inner_state_lock.lock().unwrap();
		let request = LSPS2Request::GetInfo(params.clone());
		self.insert_pending_request(
			&mut peer_state_lock,
			&mut message_queue_notifier,
			request_id.clone(),
			*counterparty_node_id,
			request,
		)?;

		let event = LSPS2ServiceEvent::GetInfo {
			request_id,
			counterparty_node_id: *counterparty_node_id,
			token: params.token,
		};
		event_queue_notifier.enqueue(event);

		Ok(())
	}

	fn handle_buy_request(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey, params: LSPS2BuyRequest,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();
		let event_queue_notifier = self.pending_events.notifier();
		if let Some(payment_size_msat) = params.payment_size_msat {
			if payment_size_msat < params.opening_fee_params.min_payment_size_msat {
				let response = LSPS2Response::BuyError(LSPSResponseError {
					code: LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_SMALL_ERROR_CODE,
					message: "payment size is below our minimum supported payment size".to_string(),
					data: None,
				});
				let msg = LSPS2Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(counterparty_node_id, msg);

				return Err(LightningError {
					err: "payment size is below our minimum supported payment size".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			}

			if payment_size_msat > params.opening_fee_params.max_payment_size_msat {
				let response = LSPS2Response::BuyError(LSPSResponseError {
					code: LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_LARGE_ERROR_CODE,
					message: "payment size is above our maximum supported payment size".to_string(),
					data: None,
				});
				let msg = LSPS2Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(counterparty_node_id, msg);
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
						let response = LSPS2Response::BuyError(LSPSResponseError {
							code: LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_SMALL_ERROR_CODE,
							message: "payment size is too small to cover the opening fee"
								.to_string(),
							data: None,
						});
						let msg = LSPS2Message::Response(request_id, response).into();
						message_queue_notifier.enqueue(counterparty_node_id, msg);
						return Err(LightningError {
							err: "payment size is too small to cover the opening fee".to_string(),
							action: ErrorAction::IgnoreAndLog(Level::Info),
						});
					}
				},
				None => {
					let response = LSPS2Response::BuyError(LSPSResponseError {
						code: LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_LARGE_ERROR_CODE,
						message: "overflow error when calculating opening_fee".to_string(),
						data: None,
					});
					let msg = LSPS2Message::Response(request_id, response).into();
					message_queue_notifier.enqueue(counterparty_node_id, msg);
					return Err(LightningError {
						err: "overflow error when calculating opening_fee".to_string(),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				},
			}
		}

		// TODO: if payment_size_msat is specified, make sure our node has sufficient incoming liquidity from public network to receive it.
		if !is_valid_opening_fee_params(&params.opening_fee_params, &self.config.promise_secret) {
			let response = LSPS2Response::BuyError(LSPSResponseError {
				code: LSPS2_BUY_REQUEST_INVALID_OPENING_FEE_PARAMS_ERROR_CODE,
				message: "valid_until is already past OR the promise did not match the provided parameters".to_string(),
				data: None,
			});
			let msg = LSPS2Message::Response(request_id, response).into();
			message_queue_notifier.enqueue(counterparty_node_id, msg);
			return Err(LightningError {
				err: "invalid opening fee parameters were supplied by client".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock = get_or_insert_peer_state_entry!(
			self,
			outer_state_lock,
			message_queue_notifier,
			counterparty_node_id
		);
		let mut peer_state_lock = inner_state_lock.lock().unwrap();

		let request = LSPS2Request::Buy(params.clone());

		self.insert_pending_request(
			&mut peer_state_lock,
			&mut message_queue_notifier,
			request_id.clone(),
			*counterparty_node_id,
			request,
		)?;

		let event = LSPS2ServiceEvent::BuyRequest {
			request_id,
			counterparty_node_id: *counterparty_node_id,
			opening_fee_params: params.opening_fee_params,
			payment_size_msat: params.payment_size_msat,
		};
		event_queue_notifier.enqueue(event);

		Ok(())
	}

	fn insert_pending_request<'a>(
		&self, peer_state_lock: &mut MutexGuard<'a, PeerState>,
		message_queue_notifier: &mut MessageQueueNotifierGuard, request_id: LSPSRequestId,
		counterparty_node_id: PublicKey, request: LSPS2Request,
	) -> Result<(), LightningError> {
		let create_pending_request_limit_exceeded_response =
			|message_queue_notifier: &mut MessageQueueNotifierGuard, error_message: String| {
				let error_details = LSPSResponseError {
					code: LSPS0_CLIENT_REJECTED_ERROR_CODE,
					message: "Reached maximum number of pending requests. Please try again later."
						.to_string(),
					data: None,
				};
				let response = match &request {
					LSPS2Request::GetInfo(_) => LSPS2Response::GetInfoError(error_details),
					LSPS2Request::Buy(_) => LSPS2Response::BuyError(error_details),
				};
				let msg = LSPS2Message::Response(request_id.clone(), response).into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);

				Err(LightningError {
					err: error_message,
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				})
			};

		if self.total_pending_requests.load(Ordering::Relaxed) >= MAX_TOTAL_PENDING_REQUESTS {
			let error_message = format!(
				"Reached maximum number of total pending requests: {}",
				MAX_TOTAL_PENDING_REQUESTS
			);
			return create_pending_request_limit_exceeded_response(
				message_queue_notifier,
				error_message,
			);
		}

		if peer_state_lock.pending_requests_and_channels() < MAX_PENDING_REQUESTS_PER_PEER {
			peer_state_lock.pending_requests.insert(request_id, request);
			self.total_pending_requests.fetch_add(1, Ordering::Relaxed);
			Ok(())
		} else {
			let error_message = format!(
				"Peer {} reached maximum number of pending requests: {}",
				counterparty_node_id, MAX_PENDING_REQUESTS_PER_PEER
			);
			create_pending_request_limit_exceeded_response(message_queue_notifier, error_message)
		}
	}

	fn remove_pending_request<'a>(
		&self, peer_state_lock: &mut MutexGuard<'a, PeerState>, request_id: &LSPSRequestId,
	) -> Option<LSPS2Request> {
		match peer_state_lock.pending_requests.remove(request_id) {
			Some(req) => {
				let res = self.total_pending_requests.fetch_update(
					Ordering::Relaxed,
					Ordering::Relaxed,
					|x| Some(x.saturating_sub(1)),
				);
				match res {
					Ok(previous_value) if previous_value == 0 => debug_assert!(
						false,
						"total_pending_requests counter out-of-sync! This should never happen!"
					),
					Err(previous_value) if previous_value == 0 => debug_assert!(
						false,
						"total_pending_requests counter out-of-sync! This should never happen!"
					),
					_ => {},
				}
				Some(req)
			},
			res => res,
		}
	}

	#[cfg(debug_assertions)]
	fn verify_pending_request_counter(&self) {
		let mut num_requests = 0;
		let outer_state_lock = self.per_peer_state.read().unwrap();
		for (_, inner) in outer_state_lock.iter() {
			let inner_state_lock = inner.lock().unwrap();
			num_requests += inner_state_lock.pending_requests.len();
		}
		debug_assert_eq!(
			num_requests,
			self.total_pending_requests.load(Ordering::Relaxed),
			"total_pending_requests counter out-of-sync! This should never happen!"
		);
	}

	pub(crate) fn peer_disconnected(&self, counterparty_node_id: PublicKey) {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let is_prunable =
			if let Some(inner_state_lock) = outer_state_lock.get(&counterparty_node_id) {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				peer_state_lock.prune_expired_request_state();
				peer_state_lock.is_prunable()
			} else {
				return;
			};
		if is_prunable {
			outer_state_lock.remove(&counterparty_node_id);
		}
	}

	#[allow(clippy::bool_comparison)]
	pub(crate) fn prune_peer_state(&self) {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		outer_state_lock.retain(|_, inner_state_lock| {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.prune_expired_request_state();
			peer_state_lock.is_prunable() == false
		});
	}

	/// Checks if the JIT channel with the given `user_channel_id` needs manual broadcast.
	/// Will be true if client_trusts_lsp is set to true
	pub fn channel_needs_manual_broadcast(
		&self, user_channel_id: u128, counterparty_node_id: &PublicKey,
	) -> Result<bool, APIError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		let inner_state_lock =
			outer_state_lock.get(counterparty_node_id).ok_or_else(|| APIError::APIMisuseError {
				err: format!("No counterparty state for: {}", counterparty_node_id),
			})?;
		let peer_state = inner_state_lock.lock().unwrap();

		let intercept_scid = peer_state
			.intercept_scid_by_user_channel_id
			.get(&user_channel_id)
			.copied()
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Could not find a channel with user_channel_id {}", user_channel_id),
			})?;

		let jit_channel = peer_state
			.outbound_channels_by_intercept_scid
			.get(&intercept_scid)
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!(
					"Failed to map intercept_scid {} for user_channel_id {} to a channel.",
					intercept_scid, user_channel_id,
				),
			})?;

		Ok(jit_channel.is_client_trusts_lsp())
	}

	/// Called to store the funding transaction for a JIT channel.
	/// This should be called when the funding transaction is created but before it's broadcast.
	pub fn store_funding_transaction(
		&self, user_channel_id: u128, counterparty_node_id: &PublicKey, funding_tx: Transaction,
	) -> Result<(), APIError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		let inner_state_lock =
			outer_state_lock.get(counterparty_node_id).ok_or_else(|| APIError::APIMisuseError {
				err: format!("No counterparty state for: {}", counterparty_node_id),
			})?;
		let mut peer_state = inner_state_lock.lock().unwrap();

		let intercept_scid = peer_state
			.intercept_scid_by_user_channel_id
			.get(&user_channel_id)
			.copied()
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Could not find a channel with user_channel_id {}", user_channel_id),
			})?;

		let jit_channel = peer_state
			.outbound_channels_by_intercept_scid
			.get_mut(&intercept_scid)
			.ok_or_else(|| APIError::APIMisuseError {
			err: format!(
				"Failed to map intercept_scid {} for user_channel_id {} to a channel.",
				intercept_scid, user_channel_id,
			),
		})?;

		jit_channel.set_funding_tx(funding_tx);

		self.emit_broadcast_funding_transaction_event_if_applies(jit_channel, counterparty_node_id);
		Ok(())
	}

	/// Marks that the funding transaction for the JIT channel identified by `user_channel_id`
	/// is now safe to broadcast.
	///
	/// In LDK call this when you receive [`Event::FundingTxBroadcastSafe`]. In other Lightning
	/// backends call it once the funding transaction is fully negotiated and signed (all
	/// signatures verified), your channel state machine will now proceed assuming the funding
	/// transaction will confirm, and you are intentionally deferring the actual broadcast so
	/// the LSPS2 flow (when `client_trusts_lsp = true`) can first collect the opening fee from
	/// the intercepted payment.
	///
	/// After this is set, in a `client_trusts_lsp` flow the handler will emit
	/// [`LSPS2ServiceEvent::BroadcastFundingTransaction`] once the opening fee has been fully
	/// skimmed.
	///
	/// [`Event::FundingTxBroadcastSafe`]: lightning::events::Event::FundingTxBroadcastSafe
	/// [`LSPS2ServiceEvent::BroadcastFundingTransaction`]: crate::lsps2::event::LSPS2ServiceEvent::BroadcastFundingTransaction
	pub fn set_funding_tx_broadcast_safe(
		&self, user_channel_id: u128, counterparty_node_id: &PublicKey,
	) -> Result<(), APIError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		let inner_state_lock =
			outer_state_lock.get(counterparty_node_id).ok_or_else(|| APIError::APIMisuseError {
				err: format!("No counterparty state for: {}", counterparty_node_id),
			})?;
		let mut peer_state = inner_state_lock.lock().unwrap();

		let intercept_scid = peer_state
			.intercept_scid_by_user_channel_id
			.get(&user_channel_id)
			.copied()
			.ok_or_else(|| APIError::APIMisuseError {
				err: format!("Could not find a channel with user_channel_id {}", user_channel_id),
			})?;

		let jit_channel = peer_state
			.outbound_channels_by_intercept_scid
			.get_mut(&intercept_scid)
			.ok_or_else(|| APIError::APIMisuseError {
			err: format!(
				"Failed to map intercept_scid {} for user_channel_id {} to a channel.",
				intercept_scid, user_channel_id,
			),
		})?;

		jit_channel.set_funding_tx_broadcast_safe(true);

		self.emit_broadcast_funding_transaction_event_if_applies(jit_channel, counterparty_node_id);
		Ok(())
	}

	fn emit_broadcast_funding_transaction_event_if_applies(
		&self, jit_channel: &OutboundJITChannel, counterparty_node_id: &PublicKey,
	) {
		if jit_channel.should_broadcast_funding_transaction() {
			let funding_tx = jit_channel.get_funding_tx();

			if let Some(funding_tx) = funding_tx {
				let event_queue_notifier = self.pending_events.notifier();
				let event = LSPS2ServiceEvent::BroadcastFundingTransaction {
					counterparty_node_id: *counterparty_node_id,
					user_channel_id: jit_channel.user_channel_id,
					funding_tx,
				};
				event_queue_notifier.enqueue(event);
			}
		}
	}

	/// Manually broadcast a transaction.
	///
	/// This method should only be used when manual control over transaction
	/// broadcast timing is required (e.g. client_trusts_lsp=true)
	pub fn broadcast_transaction(&self, tx: &Transaction) {
		self.tx_broadcaster.broadcast_transactions(&[tx]);
	}
}

impl<CM: Deref, T: Deref> LSPSProtocolMessageHandler for LSPS2ServiceHandler<CM, T>
where
	CM::Target: AChannelManager,
	T::Target: BroadcasterInterface,
{
	type ProtocolMessage = LSPS2Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(2);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS2Message::Request(request_id, request) => {
				let res = match request {
					LSPS2Request::GetInfo(params) => {
						self.handle_get_info_request(request_id, counterparty_node_id, params)
					},
					LSPS2Request::Buy(params) => {
						self.handle_buy_request(request_id, counterparty_node_id, params)
					},
				};
				#[cfg(debug_assertions)]
				self.verify_pending_request_counter();
				res
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

	use crate::lsps0::ser::LSPSDateTime;

	use proptest::prelude::*;

	use bitcoin::{absolute::LockTime, transaction::Version};
	use core::str::FromStr;

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
		let opening_fee_params = LSPS2OpeningFeeParams {
			min_fee_msat: 10_000_000,
			proportional: 10_000,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 4032,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10_000_000,
			max_payment_size_msat: 1_000_000_000,
			promise: "ignore".to_string(),
		};
		let mut state = OutboundJITChannelState::new();
		// Intercepts the first HTLC of a multipart payment A.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PendingInitialPayment { .. }));
			assert!(action.is_none());
		}
		// Intercepts the first HTLC of a different multipart payment B.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PendingInitialPayment { .. }));
			assert!(action.is_none());
		}
		// Intercepts the second HTLC of multipart payment A, completing the expected payment and
		// opening the channel.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(matches!(action, Some(HTLCInterceptedAction::OpenChannel(_))));
		}
		// Channel opens, becomes ready, and multipart payment A gets forwarded.
		{
			let ForwardPaymentAction(channel_id, payment) =
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
		}
		// Intercepts the first HTLC of a different payment C.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PendingPaymentForward { .. }));
			assert!(action.is_none());
		}
		// Payment A fails.
		{
			let action = state.htlc_handling_failed().unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingPayment { .. }));
			// No payments have received sufficient HTLCs yet.
			assert!(action.is_none());
		}
		// Additional HTLC of payment B arrives, completing the expectd payment.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PendingPaymentForward { .. }));
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
		}
		// Payment completes, queued payments get forwarded.
		{
			let action = state.payment_forwarded(Some(100000000000)).unwrap();
			assert!(matches!(state, OutboundJITChannelState::PaymentForwarded { .. }));
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
		}
		// Any new HTLC gets automatically forwarded.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PaymentForwarded { .. }));
			assert!(
				matches!(action, Some(HTLCInterceptedAction::ForwardHTLC(channel_id)) if channel_id == ChannelId([200; 32]))
			);
		}
	}

	#[test]
	fn test_jit_channel_state_no_mpp() {
		let payment_size_msat = None;
		let opening_fee_params = LSPS2OpeningFeeParams {
			min_fee_msat: 10_000_000,
			proportional: 10_000,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 4032,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10_000_000,
			max_payment_size_msat: 1_000_000_000,
			promise: "ignore".to_string(),
		};
		let mut state = OutboundJITChannelState::new();
		// Intercepts payment A, opening the channel.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(matches!(action, Some(HTLCInterceptedAction::OpenChannel(_))));
		}
		// Intercepts payment B.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(action.is_none());
		}
		// Channel opens, becomes ready, and payment A gets forwarded.
		{
			let ForwardPaymentAction(channel_id, payment) =
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
		}
		// Intercepts payment C.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PendingPaymentForward { .. }));
			assert!(action.is_none());
		}
		// Payment A fails, and payment B is forwarded.
		{
			let action = state.htlc_handling_failed().unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingPaymentForward { .. }));
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
		}
		// Payment completes, queued payments get forwarded.
		{
			let action = state.payment_forwarded(Some(10000000000)).unwrap();
			assert!(matches!(state, OutboundJITChannelState::PaymentForwarded { .. }));
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
		}
		// Any new HTLC gets automatically forwarded.
		{
			let action = state
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
			assert!(matches!(state, OutboundJITChannelState::PaymentForwarded { .. }));
			assert!(
				matches!(action, Some(HTLCInterceptedAction::ForwardHTLC(channel_id)) if channel_id == ChannelId([200; 32]))
			);
		}
	}

	#[test]
	fn broadcast_not_allowed_after_non_paying_fee_payment_claimed() {
		let min_fee_msat: u64 = 12345;
		let opening_fee_params = LSPS2OpeningFeeParams {
			min_fee_msat,
			proportional: 0,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 144,
			max_client_to_self_delay: 128,
			min_payment_size_msat: 1,
			max_payment_size_msat: 10_000_000_000,
			promise: "ignore".to_string(),
		};

		let payment_size_msat = Some(1_000_000);
		let user_channel_id = 4242u128;
		let mut jit_channel = OutboundJITChannel::new(
			payment_size_msat,
			opening_fee_params.clone(),
			user_channel_id,
			true,
		);

		let opening_payment_hash = PaymentHash([42; 32]);
		let htlcs_for_opening = [
			InterceptedHTLC {
				intercept_id: InterceptId([0; 32]),
				expected_outbound_amount_msat: 400_000,
				payment_hash: opening_payment_hash,
			},
			InterceptedHTLC {
				intercept_id: InterceptId([1; 32]),
				expected_outbound_amount_msat: 600_000,
				payment_hash: opening_payment_hash,
			},
		];

		assert!(jit_channel.htlc_intercepted(htlcs_for_opening[0].clone()).unwrap().is_none());
		let action = jit_channel.htlc_intercepted(htlcs_for_opening[1].clone()).unwrap();
		match action {
			Some(HTLCInterceptedAction::OpenChannel(_)) => {},
			other => panic!("Expected OpenChannel action, got {:?}", other),
		}

		let channel_id = ChannelId([7; 32]);
		let ForwardPaymentAction(_, fee_payment) = jit_channel.channel_ready(channel_id).unwrap();
		assert_eq!(fee_payment.opening_fee_msat, min_fee_msat);

		let followup = jit_channel.htlc_handling_failed().unwrap();
		assert!(followup.is_none());

		let dummy_tx = Transaction {
			version: Version(2),
			lock_time: LockTime::ZERO,
			input: vec![],
			output: vec![],
		};
		jit_channel.set_funding_tx(dummy_tx);
		jit_channel.set_funding_tx_broadcast_safe(true);
		assert!(
			!jit_channel.should_broadcast_funding_transaction(),
			"Should not broadcast before any successful payment is claimed"
		);

		let second_payment_hash = PaymentHash([99; 32]);
		let second_htlc = InterceptedHTLC {
			intercept_id: InterceptId([2; 32]),
			expected_outbound_amount_msat: min_fee_msat,
			payment_hash: second_payment_hash,
		};
		let action2 = jit_channel.htlc_intercepted(second_htlc).unwrap();
		let (forwarded_channel_id, fee_payment2) = match action2 {
			Some(HTLCInterceptedAction::ForwardPayment(cid, fp)) => (cid, fp),
			other => panic!("Expected ForwardPayment for second HTLC, got {:?}", other),
		};
		assert_eq!(forwarded_channel_id, channel_id);
		assert_eq!(fee_payment2.opening_fee_msat, min_fee_msat);

		assert!(
			!jit_channel.should_broadcast_funding_transaction(),
			"Should not broadcast before any successful payment is claimed"
		);

		// Forward a payment that is not enough to cover the fees
		let _ = jit_channel.payment_forwarded(Some(min_fee_msat - 1)).unwrap();

		assert!(
			!jit_channel.should_broadcast_funding_transaction(),
			"Should not broadcast before all the fees are collected"
		);

		let _ = jit_channel.payment_forwarded(Some(min_fee_msat)).unwrap();

		let broadcast_allowed = jit_channel.should_broadcast_funding_transaction();

		assert!(
			broadcast_allowed,
			"Broadcast was not allowed even though all the skimmed fees were collected"
		);
	}
}
