// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main bLIP-51 / LSPS1 server object, [`LSPS1ServiceHandler`].

use alloc::string::ToString;
use alloc::vec::Vec;

use core::future::Future as StdFuture;
use core::ops::Deref;
use core::pin::pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task;

use super::event::LSPS1ServiceEvent;
use super::msgs::{
	LSPS1ChannelInfo, LSPS1CreateOrderRequest, LSPS1CreateOrderResponse, LSPS1GetInfoResponse,
	LSPS1GetOrderRequest, LSPS1Message, LSPS1Options, LSPS1OrderId, LSPS1OrderParams,
	LSPS1PaymentInfo, LSPS1Request, LSPS1Response,
	LSPS1_CREATE_ORDER_REQUEST_OPTION_MISMATCH_ERROR_CODE,
	LSPS1_CREATE_ORDER_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE,
	LSPS1_GET_ORDER_REQUEST_ORDER_NOT_FOUND_ERROR_CODE,
};
pub use super::peer_state::PaymentMethod;
use super::peer_state::PeerState;
use crate::message_queue::MessageQueue;

use crate::events::EventQueue;
use crate::lsps0::ser::{
	LSPSDateTime, LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError,
	LSPS0_CLIENT_REJECTED_ERROR_CODE,
};
use crate::persist::{
	LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, LSPS1_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::prelude::hash_map::Entry;
use crate::prelude::HashMap;
use crate::sync::{Arc, Mutex, RwLock};
use crate::utils;
use crate::utils::async_poll::dummy_waker;
use crate::utils::time::TimeProvider;

use lightning::ln::channelmanager::AChannelManager;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::errors::APIError;
use lightning::util::logger::Level;
use lightning::util::persist::KVStore;
use lightning::util::ser::Writeable;

use bitcoin::secp256k1::PublicKey;

/// Server-side configuration options for bLIP-51 / LSPS1 channel requests.
#[derive(Clone, Debug)]
pub struct LSPS1ServiceConfig {
	/// The options supported by the LSP.
	pub supported_options: LSPS1Options,
}

const MAX_PENDING_REQUESTS_PER_PEER: usize = 10;
const MAX_TOTAL_PENDING_REQUESTS: usize = 1000;
const MAX_TOTAL_PEERS: usize = 100000;

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
	kv_store: K,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	total_pending_requests: AtomicUsize,
	persistence_in_flight: AtomicUsize,
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
		per_peer_state: HashMap<PublicKey, Mutex<PeerState>>, entropy_source: ES,
		pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue<K>>,
		channel_manager: CM, kv_store: K, time_provider: TP, config: LSPS1ServiceConfig,
	) -> Self {
		Self {
			entropy_source,
			_channel_manager: channel_manager,
			kv_store,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(per_peer_state),
			total_pending_requests: AtomicUsize::new(0),
			persistence_in_flight: AtomicUsize::new(0),
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
		outer_state_lock.get(counterparty_node_id).is_some_and(|inner| {
			let peer_state = inner.lock().unwrap();
			peer_state.has_active_requests()
		})
	}

	pub(crate) fn peer_disconnected(&self, counterparty_node_id: PublicKey) {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		if let Some(inner_state_lock) = outer_state_lock.get(&counterparty_node_id) {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			// We clean up the peer state, but leave removing the peer entry to the prune logic in
			// `persist` which removes it from the store.
			let num_pruned = peer_state_lock.prune_pending_requests();
			self.total_pending_requests.fetch_sub(num_pruned, Ordering::Relaxed);
			peer_state_lock.prune_expired_request_state();
		}
	}

	pub(crate) async fn persist(&self) -> Result<bool, lightning::io::Error> {
		// TODO: We should eventually persist in parallel, however, when we do, we probably want to
		// introduce some batching to upper-bound the number of requests inflight at any given
		// time.
		let mut did_persist = false;

		if self.persistence_in_flight.fetch_add(1, Ordering::AcqRel) > 0 {
			// If we're not the first event processor to get here, just return early, the increment
			// we just did will be treated as "go around again" at the end.
			return Ok(did_persist);
		}

		loop {
			let mut need_remove = Vec::new();
			let mut need_persist = Vec::new();

			{
				// First build a list of peers to persist and prune with the read lock. This allows
				// us to avoid the write lock unless we actually need to remove a node.
				let outer_state_lock = self.per_peer_state.read().unwrap();
				for (counterparty_node_id, inner_state_lock) in outer_state_lock.iter() {
					let mut peer_state_lock = inner_state_lock.lock().unwrap();
					peer_state_lock.prune_expired_request_state();
					let is_prunable = peer_state_lock.is_prunable();
					if is_prunable {
						need_remove.push(*counterparty_node_id);
					} else if peer_state_lock.needs_persist() {
						need_persist.push(*counterparty_node_id);
					}
				}
			}

			for counterparty_node_id in need_persist.into_iter() {
				debug_assert!(!need_remove.contains(&counterparty_node_id));
				self.persist_peer_state(counterparty_node_id).await?;
				did_persist = true;
			}

			for counterparty_node_id in need_remove {
				let mut future_opt = None;
				{
					// We need to take the `per_peer_state` write lock to remove an entry, but also
					// have to hold it until after the `remove` call returns (but not through
					// future completion) to ensure that writes for the peer's state are
					// well-ordered with other `persist_peer_state` calls even across the removal
					// itself.
					let mut per_peer_state = self.per_peer_state.write().unwrap();
					if let Entry::Occupied(mut entry) = per_peer_state.entry(counterparty_node_id) {
						let state = entry.get_mut().get_mut().unwrap();
						if state.is_prunable() {
							entry.remove();
							let key = counterparty_node_id.to_string();
							future_opt = Some(self.kv_store.remove(
								LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
								LSPS1_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
								&key,
								true,
							));
						} else {
							// If the peer got new state, force a re-persist of the current state.
							state.set_needs_persist(true);
						}
					} else {
						// This should never happen, we can only have one `persist` call
						// in-progress at once and map entries are only removed by it.
						debug_assert!(false);
					}
				}
				if let Some(future) = future_opt {
					future.await?;
					did_persist = true;
				} else {
					self.persist_peer_state(counterparty_node_id).await?;
				}
			}

			if self.persistence_in_flight.fetch_sub(1, Ordering::AcqRel) != 1 {
				// If another thread incremented the state while we were running we should go
				// around again, but only once.
				self.persistence_in_flight.store(1, Ordering::Release);
				continue;
			}
			break;
		}

		Ok(did_persist)
	}

	async fn persist_peer_state(
		&self, counterparty_node_id: PublicKey,
	) -> Result<(), lightning::io::Error> {
		let fut = {
			let outer_state_lock = self.per_peer_state.read().unwrap();
			match outer_state_lock.get(&counterparty_node_id) {
				None => {
					// We dropped the peer state by now.
					return Ok(());
				},
				Some(entry) => {
					let mut peer_state_lock = entry.lock().unwrap();
					if !peer_state_lock.needs_persist() {
						// We already have persisted otherwise by now.
						return Ok(());
					} else {
						peer_state_lock.set_needs_persist(false);
						let key = counterparty_node_id.to_string();
						let encoded = peer_state_lock.encode();
						// Begin the write with the entry lock held. This avoids racing with
						// potentially-in-flight `persist` calls writing state for the same peer.
						self.kv_store.write(
							LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
							LSPS1_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
							&key,
							encoded,
						)
					}
				},
			}
		};

		fut.await.map_err(|e| {
			self.per_peer_state
				.read()
				.unwrap()
				.get(&counterparty_node_id)
				.map(|p| p.lock().unwrap().set_needs_persist(true));
			e
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
				code: LSPS1_CREATE_ORDER_REQUEST_OPTION_MISMATCH_ERROR_CODE,
				message: "Order does not match options supported by LSP server".to_string(),
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
			let num_peers = outer_state_lock.len();

			let inner_state_entry = outer_state_lock.entry(*counterparty_node_id);

			if matches!(inner_state_entry, Entry::Vacant(_)) && num_peers >= MAX_TOTAL_PEERS {
				let response = LSPS1Response::CreateOrderError(LSPSResponseError {
					code: LSPS0_CLIENT_REJECTED_ERROR_CODE,
					message: "Reached maximum number of pending requests. Please try again later."
						.to_string(),
					data: None,
				});
				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(counterparty_node_id, msg);
				return Err(LightningError {
					err: format!(
						"Dropping request from peer {} due to reaching maximally allowed number of total peers: {}",
						counterparty_node_id, MAX_TOTAL_PEERS
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			}

			if self.total_pending_requests.load(Ordering::Relaxed) >= MAX_TOTAL_PENDING_REQUESTS {
				let response = LSPS1Response::CreateOrderError(LSPSResponseError {
					code: LSPS0_CLIENT_REJECTED_ERROR_CODE,
					message: "Reached maximum number of pending requests. Please try again later."
						.to_string(),
					data: None,
				});
				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(counterparty_node_id, msg);
				return Err(LightningError {
					err: format!(
						"Reached maximum number of total pending requests: {}",
						MAX_TOTAL_PENDING_REQUESTS
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			}

			let mut peer_state_lock =
				inner_state_entry.or_insert(Mutex::new(PeerState::default())).lock().unwrap();

			if peer_state_lock.pending_requests_and_unpaid_orders() >= MAX_PENDING_REQUESTS_PER_PEER
			{
				let response = LSPS1Response::CreateOrderError(LSPSResponseError {
					code: LSPS0_CLIENT_REJECTED_ERROR_CODE,
					message: "Reached maximum number of pending requests. Please try again later."
						.to_string(),
					data: None,
				});
				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(counterparty_node_id, msg);
				return Err(LightningError {
					err: format!(
						"Peer {} reached maximum number of pending requests: {}",
						counterparty_node_id, MAX_PENDING_REQUESTS_PER_PEER
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			}

			let request = LSPS1Request::CreateOrder(params.clone());
			peer_state_lock.register_request(request_id.clone(), request).map_err(|e| {
				let err = format!("Failed to handle request due to: {}", e);
				let action = ErrorAction::IgnoreAndLog(Level::Error);
				LightningError { err, action }
			})?;

			self.total_pending_requests.fetch_add(1, Ordering::Relaxed);
		}

		event_queue_notifier.enqueue(LSPS1ServiceEvent::RequestForPaymentDetails {
			request_id,
			counterparty_node_id: *counterparty_node_id,
			order: params.order,
			refund_onchain_address: params.refund_onchain_address,
		});

		Ok(())
	}

	/// Used by LSP to send response containing details regarding the channel fees and payment information.
	///
	/// Should be called in response to receiving a [`LSPS1ServiceEvent::RequestForPaymentDetails`] event.
	///
	/// Note that the provided `payment_details` can't include the onchain payment variant if the
	/// user didn't provide a `refund_onchain_address`. If you *require* onchain payments, you need
	/// to call [`Self::onchain_payments_required`] to reject the request.
	///
	/// [`LSPS1ServiceEvent::RequestForPaymentDetails`]: crate::lsps1::event::LSPS1ServiceEvent::RequestForPaymentDetails
	pub async fn send_payment_details(
		&self, request_id: LSPSRequestId, counterparty_node_id: PublicKey,
		payment_details: LSPS1PaymentInfo,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();
		let mut should_persist = false;

		match self.per_peer_state.read().unwrap().get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				let request = peer_state_lock.remove_request(&request_id).map_err(|e| {
					debug_assert!(false, "Failed to send response due to: {}", e);
					let err = format!("Failed to send response due to: {}", e);
					APIError::APIMisuseError { err }
				})?;
				self.total_pending_requests.fetch_sub(1, Ordering::Relaxed);

				match request {
					LSPS1Request::CreateOrder(params) => {
						let order_id = self.generate_order_id();
						let created_at = LSPSDateTime::new_from_duration_since_epoch(
							self.time_provider.duration_since_epoch(),
						);

						if payment_details.bolt11.is_none()
							&& payment_details.bolt12.is_none()
							&& payment_details.onchain.is_none()
						{
							let err = "At least one payment option must be provided".to_string();
							return Err(APIError::APIMisuseError { err });
						}

						if params.refund_onchain_address.is_none()
							&& payment_details.onchain.is_some()
						{
							// bLIP-51: 'LSP MUST disable on-chain payments if the client omits this field.'
							let err = "Onchain payments must be disabled if no refund_onchain_address is set.".to_string();
							return Err(APIError::APIMisuseError { err });
						}

						let order = peer_state_lock.new_order(
							order_id.clone(),
							params.order,
							created_at,
							payment_details,
						);
						should_persist |= peer_state_lock.needs_persist();

						let response = LSPS1Response::CreateOrder(LSPS1CreateOrderResponse {
							order_id,
							order_state: order.order_state(),
							created_at: order.created_at.clone(),
							payment: order.payment_details().clone(),
							channel: order.channel_details().cloned(),
							order: order.order_params,
						});
						let msg = LSPS1Message::Response(request_id, response).into();
						message_queue_notifier.enqueue(&counterparty_node_id, msg);
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
			None => {
				return Err(APIError::APIMisuseError {
					err: format!("No state for the counterparty exists: {}", counterparty_node_id),
				});
			},
		}

		if should_persist {
			self.persist_peer_state(counterparty_node_id).await.map_err(|e| {
				APIError::APIMisuseError {
					err: format!(
						"Failed to persist peer state for {}: {}",
						counterparty_node_id, e
					),
				}
			})?;
		}

		Ok(())
	}

	/// Used by LSP to inform a client that an order was rejected because the used token was invalid.
	///
	/// Should be called in response to receiving a [`LSPS1ServiceEvent::RequestForPaymentDetails`]
	/// event if the provided token is invalid.
	///
	/// [`LSPS1ServiceEvent::RequestForPaymentDetails`]: crate::lsps1::event::LSPS1ServiceEvent::RequestForPaymentDetails
	pub fn invalid_token_provided(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		match self.per_peer_state.read().unwrap().get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				peer_state_lock.remove_request(&request_id).map_err(|e| {
					debug_assert!(false, "Failed to send response due to: {}", e);
					let err = format!("Failed to send response due to: {}", e);
					APIError::APIMisuseError { err }
				})?;
				self.total_pending_requests.fetch_sub(1, Ordering::Relaxed);

				let response = LSPS1Response::CreateOrderError(LSPSResponseError {
					code: LSPS1_CREATE_ORDER_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE,
					message: "An unrecognized or stale token was provided".to_string(),
					data: None,
				});

				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);
				Ok(())
			},
			None => Err(APIError::APIMisuseError {
				err: format!("No state for the counterparty exists: {}", counterparty_node_id),
			}),
		}
	}

	/// Used by LSP to inform a client that an order was rejected because they require onchain
	/// payments and the client didn't provided a `refund_onchain_address`.
	///
	/// Should be called in response to receiving a [`LSPS1ServiceEvent::RequestForPaymentDetails`]
	/// event if the LSP requires onchain payments and `refund_onchain_address` is `None`.
	///
	/// [`LSPS1ServiceEvent::RequestForPaymentDetails`]: crate::lsps1::event::LSPS1ServiceEvent::RequestForPaymentDetails
	pub fn onchain_payments_required(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
	) -> Result<(), APIError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		match self.per_peer_state.read().unwrap().get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				peer_state_lock.remove_request(&request_id).map_err(|e| {
					debug_assert!(false, "Failed to send response due to: {}", e);
					let err = format!("Failed to send response due to: {}", e);
					APIError::APIMisuseError { err }
				})?;
				self.total_pending_requests.fetch_sub(1, Ordering::Relaxed);

				let response = LSPS1Response::CreateOrderError(LSPSResponseError {
					code: LSPS1_CREATE_ORDER_REQUEST_OPTION_MISMATCH_ERROR_CODE,
					message:
						"We require onchain payment but no `refund_onchain_address` was provided"
							.to_string(),
					data: None,
				});

				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);
				Ok(())
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
		let mut message_queue_notifier = self.pending_messages.notifier();
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let peer_state_lock = inner_state_lock.lock().unwrap();

				let order = peer_state_lock.get_order(&params.order_id).map_err(|e| {
					let response = LSPS1Response::GetOrderError(LSPSResponseError {
						code: LSPS1_GET_ORDER_REQUEST_ORDER_NOT_FOUND_ERROR_CODE,
						message: "Order with the requested order_id has not been found."
							.to_string(),
						data: None,
					});
					let msg = LSPS1Message::Response(request_id.clone(), response).into();
					message_queue_notifier.enqueue(counterparty_node_id, msg);
					let err = format!("Failed to handle request due to: {}", e);
					let action = ErrorAction::IgnoreAndLog(Level::Error);
					LightningError { err, action }
				})?;

				let response = LSPS1Response::GetOrder(LSPS1CreateOrderResponse {
					order_id: params.order_id,
					order: order.order_params.clone(),
					order_state: order.order_state(),
					created_at: order.created_at.clone(),
					payment: order.payment_details().clone(),
					channel: order.channel_details().cloned(),
				});
				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);
				Ok(())
			},
			None => {
				let response = LSPS1Response::GetOrderError(LSPSResponseError {
					code: LSPS1_GET_ORDER_REQUEST_ORDER_NOT_FOUND_ERROR_CODE,
					message: "Order with the requested order_id has not been found.".to_string(),
					data: None,
				});
				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(counterparty_node_id, msg);
				Err(LightningError {
					err: format!(
						"Received get_order request from an unknown counterparty ({:?})",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})
			},
		}
	}

	/// Marks an order as paid after payment has been received.
	///
	/// This should be called when the LSP detects that a Lightning payment has arrived or an
	/// on-chain payment has been confirmed.
	///
	/// This should be called before opening the channel and the channel should not be opened if
	/// this returns an error.
	///
	/// Note that in the case of a lightning payment, we expect the payment to have been received
	/// (i.e. LDK's [`Event::PaymentClaimable`]) but not claimed (i.e. calling LDK's
	/// [`ChannelManager::claim_funds`]), allowing the payment to be returned to the sender if
	/// channel opening fails.
	///
	/// [`Event::PaymentClaimable`]: lightning::events::Event::PaymentClaimable
	/// [`ChannelManager::claim_funds`]: lightning::ln::channelmanager::ChannelManager::claim_funds
	pub async fn order_payment_received(
		&self, counterparty_node_id: PublicKey, order_id: LSPS1OrderId, method: PaymentMethod,
	) -> Result<(), APIError> {
		let mut should_persist = false;
		match self.per_peer_state.read().unwrap().get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				peer_state_lock.order_payment_received(&order_id, method).map_err(|e| {
					APIError::APIMisuseError { err: format!("Failed to update order: {}", e) }
				})?;
				should_persist |= peer_state_lock.needs_persist();
			},
			None => {
				return Err(APIError::APIMisuseError {
					err: format!("No existing state with counterparty {}", counterparty_node_id),
				});
			},
		}

		if should_persist {
			self.persist_peer_state(counterparty_node_id).await.map_err(|e| {
				APIError::APIMisuseError {
					err: format!(
						"Failed to persist peer state for {}: {}",
						counterparty_node_id, e
					),
				}
			})?;
		}

		Ok(())
	}

	/// Marks an order as completed after the channel has been opened.
	///
	/// This should be called when the LSP has successfully published the funding
	/// transaction for the channel.
	pub async fn order_channel_opened(
		&self, counterparty_node_id: PublicKey, order_id: LSPS1OrderId,
		channel_info: LSPS1ChannelInfo,
	) -> Result<(), APIError> {
		let mut should_persist = false;
		match self.per_peer_state.read().unwrap().get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				peer_state_lock.order_channel_opened(&order_id, channel_info).map_err(|e| {
					APIError::APIMisuseError { err: format!("Failed to update order: {}", e) }
				})?;
				should_persist |= peer_state_lock.needs_persist();
			},
			None => {
				return Err(APIError::APIMisuseError {
					err: format!("No existing state with counterparty {}", counterparty_node_id),
				});
			},
		}

		if should_persist {
			self.persist_peer_state(counterparty_node_id).await.map_err(|e| {
				APIError::APIMisuseError {
					err: format!(
						"Failed to persist peer state for {}: {}",
						counterparty_node_id, e
					),
				}
			})?;
		}

		Ok(())
	}

	/// Marks an order as failed and refunded.
	///
	/// This should be called when:
	/// - We require onchain payment and the client didn't provide a `refund_onchain_address`.
	/// - The order expires without payment
	/// - The channel open fails after payment and the LSP must refund
	pub async fn order_failed_and_refunded(
		&self, counterparty_node_id: PublicKey, order_id: LSPS1OrderId,
	) -> Result<(), APIError> {
		let mut should_persist = false;
		match self.per_peer_state.read().unwrap().get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				peer_state_lock.order_failed_and_refunded(&order_id).map_err(|e| {
					APIError::APIMisuseError { err: format!("Failed to update order: {}", e) }
				})?;
				should_persist |= peer_state_lock.needs_persist();
			},
			None => {
				return Err(APIError::APIMisuseError {
					err: format!("No existing state with counterparty {}", counterparty_node_id),
				});
			},
		}

		if should_persist {
			self.persist_peer_state(counterparty_node_id).await.map_err(|e| {
				APIError::APIMisuseError {
					err: format!(
						"Failed to persist peer state for {}: {}",
						counterparty_node_id, e
					),
				}
			})?;
		}

		Ok(())
	}

	fn generate_order_id(&self) -> LSPS1OrderId {
		let bytes = self.entropy_source.get_secure_random_bytes();
		LSPS1OrderId(utils::hex_str(&bytes[0..16]))
	}

	#[cfg(debug_assertions)]
	fn verify_pending_request_counter(&self) {
		let mut num_requests = 0;
		let outer_state_lock = self.per_peer_state.read().unwrap();
		for (_, inner) in outer_state_lock.iter() {
			let inner_state_lock = inner.lock().unwrap();
			num_requests += inner_state_lock.pending_request_count();
		}
		debug_assert_eq!(
			num_requests,
			self.total_pending_requests.load(Ordering::Relaxed),
			"total_pending_requests counter out-of-sync! This should never happen!"
		);
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
			LSPS1Message::Request(request_id, request) => {
				let res = match request {
					LSPS1Request::GetInfo(_) => {
						self.handle_get_info_request(request_id, counterparty_node_id)
					},
					LSPS1Request::CreateOrder(params) => {
						self.handle_create_order_request(request_id, counterparty_node_id, params)
					},
					LSPS1Request::GetOrder(params) => {
						self.handle_get_order_request(request_id, counterparty_node_id, params)
					},
				};
				#[cfg(debug_assertions)]
				self.verify_pending_request_counter();
				res
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

/// A synchroneous wrapper around [`LSPS1ServiceHandler`] to be used in contexts where async is not
/// available.
pub struct LSPS1ServiceHandlerSync<
	'a,
	ES: EntropySource,
	CM: Deref + Clone,
	K: KVStore + Clone,
	TP: Deref + Clone,
> where
	CM::Target: AChannelManager,
	TP::Target: TimeProvider,
{
	inner: &'a LSPS1ServiceHandler<ES, CM, K, TP>,
}

impl<'a, ES: EntropySource, CM: Deref + Clone, K: KVStore + Clone, TP: Deref + Clone>
	LSPS1ServiceHandlerSync<'a, ES, CM, K, TP>
where
	CM::Target: AChannelManager,
	TP::Target: TimeProvider,
{
	pub(crate) fn from_inner(inner: &'a LSPS1ServiceHandler<ES, CM, K, TP>) -> Self {
		Self { inner }
	}

	/// Returns a reference to the used config.
	///
	/// Wraps [`LSPS1ServiceHandler::config`].
	pub fn config(&self) -> &LSPS1ServiceConfig {
		&self.inner.config
	}

	/// Used by LSP to send response containing details regarding the channel fees and payment information.
	///
	/// Wraps [`LSPS1ServiceHandler::send_payment_details`].
	pub fn send_payment_details(
		&self, request_id: LSPSRequestId, counterparty_node_id: PublicKey,
		payment_details: LSPS1PaymentInfo,
	) -> Result<(), APIError> {
		let mut fut = pin!(self.inner.send_payment_details(
			request_id,
			counterparty_node_id,
			payment_details
		));

		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				// In a sync context, we can't wait for the future to complete.
				unreachable!("Should not be pending in a sync context");
			},
		}
	}

	/// Used by LSP to inform a client that an order was rejected because the used token was invalid.
	///
	/// Wraps [`LSPS1ServiceHandler::invalid_token_provided`].
	pub fn invalid_token_provided(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
	) -> Result<(), APIError> {
		self.inner.invalid_token_provided(counterparty_node_id, request_id)
	}

	/// Used by LSP to inform a client that an order was rejected because they require onchain
	/// payments and the client didn't provided a `refund_onchain_address`.
	///
	/// Wraps [`LSPS1ServiceHandler::onchain_payments_required`].
	pub fn onchain_payments_required(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
	) -> Result<(), APIError> {
		self.inner.onchain_payments_required(counterparty_node_id, request_id)
	}

	/// Marks an order as paid after payment has been received.
	///
	/// Wraps [`LSPS1ServiceHandler::order_payment_received`].
	pub fn order_payment_received(
		&self, counterparty_node_id: PublicKey, order_id: LSPS1OrderId, method: PaymentMethod,
	) -> Result<(), APIError> {
		let mut fut =
			pin!(self.inner.order_payment_received(counterparty_node_id, order_id, method));

		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				// In a sync context, we can't wait for the future to complete.
				unreachable!("Should not be pending in a sync context");
			},
		}
	}

	/// Marks an order as completed after the channel has been opened.
	///
	/// Wraps [`LSPS1ServiceHandler::order_channel_opened`].
	pub fn order_channel_opened(
		&self, counterparty_node_id: PublicKey, order_id: LSPS1OrderId,
		channel_info: LSPS1ChannelInfo,
	) -> Result<(), APIError> {
		let mut fut =
			pin!(self.inner.order_channel_opened(counterparty_node_id, order_id, channel_info));

		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				// In a sync context, we can't wait for the future to complete.
				unreachable!("Should not be pending in a sync context");
			},
		}
	}

	/// Marks an order as failed and refunded.
	///
	/// Wraps [`LSPS1ServiceHandler::order_failed_and_refunded`].
	pub fn order_failed_and_refunded(
		&self, counterparty_node_id: PublicKey, order_id: LSPS1OrderId,
	) -> Result<(), APIError> {
		let mut fut = pin!(self.inner.order_failed_and_refunded(counterparty_node_id, order_id));

		let mut waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&mut waker);
		match fut.as_mut().poll(&mut ctx) {
			task::Poll::Ready(result) => result,
			task::Poll::Pending => {
				// In a sync context, we can't wait for the future to complete.
				unreachable!("Should not be pending in a sync context");
			},
		}
	}
}

fn check_range(min: u64, max: u64, value: u64) -> bool {
	(value >= min) && (value <= max)
}

fn is_valid(order: &LSPS1OrderParams, options: &LSPS1Options) -> bool {
	check_range(
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
	)
}
