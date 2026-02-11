// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main bLIP-51 / LSPS1 server object, [`LSPS1ServiceHandler`].

use alloc::string::{String, ToString};
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
	LSPS1OrderState, LSPS1PaymentInfo, LSPS1Request, LSPS1Response,
	LSPS1_CREATE_ORDER_REQUEST_ORDER_MISMATCH_ERROR_CODE,
	LSPS1_GET_ORDER_REQUEST_ORDER_NOT_FOUND_ERROR_CODE,
};
use super::peer_state::PeerState;
use crate::message_queue::MessageQueue;

use crate::events::EventQueue;
use crate::lsps0::ser::{
	LSPSDateTime, LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError,
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
	kv_store: K,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
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
		let outer_state_lock = self.per_peer_state.write().unwrap();
		if let Some(inner_state_lock) = outer_state_lock.get(&counterparty_node_id) {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			// We clean up the peer state, but leave removing the peer entry to the prune logic in
			// `persist` which removes it from the store.
			peer_state_lock.prune_pending_requests();
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
			refund_onchain_address: params.refund_onchain_address,
		});

		Ok(())
	}

	/// Used by LSP to send response containing details regarding the channel fees and payment information.
	///
	/// Should be called in response to receiving a [`LSPS1ServiceEvent::RequestForPaymentDetails`] event.
	///
	/// Note that the provided `payment_details` can't include the onchain payment variant if the
	/// user didn't provide a `refund_onchain_address`.
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
							order: order.order_params,
							order_id,

							order_state: order.order_state,
							created_at: order.created_at,
							payment: order.payment_details,
							channel: order.channel_details,
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
						message: format!("Order with the requested order_id has not been found."),
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
					order_state: order.order_state.clone(),
					created_at: order.created_at.clone(),
					payment: order.payment_details.clone(),
					channel: order.channel_details.clone(),
				});
				let msg = LSPS1Message::Response(request_id, response).into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);
				Ok(())
			},
			None => {
				let response = LSPS1Response::GetOrderError(LSPSResponseError {
					code: LSPS1_GET_ORDER_REQUEST_ORDER_NOT_FOUND_ERROR_CODE,
					message: format!("Order with the requested order_id has not been found."),
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

	/// Used by LSP to give details to client regarding the status of channel opening.
	///
	/// The LSP continously polls for checking payment confirmation on-chain or Lightning
	/// and then responds to client request.
	pub async fn update_order_status(
		&self, counterparty_node_id: PublicKey, order_id: LSPS1OrderId,
		order_state: LSPS1OrderState, channel_details: Option<LSPS1ChannelInfo>,
	) -> Result<(), APIError> {
		let mut should_persist = false;
		match self.per_peer_state.read().unwrap().get(&counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				peer_state_lock.update_order(&order_id, order_state, channel_details).map_err(
					|e| APIError::APIMisuseError {
						err: format!("Failed to update order: {:?}", e),
					},
				)?;
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

	/// Used by LSP to give details to client regarding the status of channel opening.
	///
	/// Wraps [`LSPS1ServiceHandler::update_order_status`].
	pub fn update_order_status(
		&self, counterparty_node_id: PublicKey, order_id: LSPS1OrderId,
		order_state: LSPS1OrderState, channel_details: Option<LSPS1ChannelInfo>,
	) -> Result<(), APIError> {
		let mut fut = pin!(self.inner.update_order_status(
			counterparty_node_id,
			order_id,
			order_state,
			channel_details
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
