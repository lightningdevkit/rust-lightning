// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Service implementation for LSPS5 webhook registration.

use crate::alloc::string::ToString;
use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSDateTime, LSPSProtocolMessageHandler, LSPSRequestId};
use crate::lsps5::msgs::{
	ListWebhooksRequest, ListWebhooksResponse, RemoveWebhookRequest, RemoveWebhookResponse,
	SetWebhookRequest, SetWebhookResponse, WebhookNotification, WebhookNotificationMethod,
};
use crate::message_queue::MessageQueue;
use crate::persist::{
	LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, LSPS5_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::prelude::hash_map::Entry;
use crate::prelude::*;
use crate::sync::{Arc, Mutex, RwLock, RwLockWriteGuard};
use crate::utils::time::TimeProvider;

use bitcoin::secp256k1::PublicKey;

use lightning::impl_writeable_tlv_based;
use lightning::ln::channelmanager::AChannelManager;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::NodeSigner;
use lightning::util::logger::Level;
use lightning::util::persist::KVStore;
use lightning::util::ser::Writeable;

use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use alloc::string::String;
use alloc::vec::Vec;

use super::event::LSPS5ServiceEvent;
use super::msgs::{
	LSPS5AppName, LSPS5Message, LSPS5ProtocolError, LSPS5Request, LSPS5Response, LSPS5WebhookUrl,
};

/// Minimum number of days to retain webhooks after a client's last channel is closed.
pub const MIN_WEBHOOK_RETENTION_DAYS: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Interval for pruning stale webhooks.
pub const PRUNE_STALE_WEBHOOKS_INTERVAL_DAYS: Duration = Duration::from_secs(24 * 60 * 60);

/// A stored webhook.
#[derive(Debug, Clone)]
struct Webhook {
	_app_name: LSPS5AppName,
	url: LSPS5WebhookUrl,
	_counterparty_node_id: PublicKey,
	// Timestamp used for tracking when the webhook was created / updated, or when the last notification was sent.
	// This is used to determine if the webhook is stale and should be pruned.
	last_used: LSPSDateTime,
	// Timestamp when we last sent a notification to the client. This is used to enforce
	// notification cooldowns.
	last_notification_sent: Option<LSPSDateTime>,
}

impl_writeable_tlv_based!(Webhook, {
	(0, _app_name, required),
	(2, url, required),
	(4, _counterparty_node_id, required),
	(6, last_used, required),
	(8, last_notification_sent, option),
});

/// Server-side configuration options for LSPS5 Webhook Registration.
#[derive(Clone, Debug)]
pub struct LSPS5ServiceConfig {
	/// Maximum number of webhooks allowed per client.
	pub max_webhooks_per_client: u32,
}

/// Default maximum number of webhooks allowed per client.
pub const DEFAULT_MAX_WEBHOOKS_PER_CLIENT: u32 = 10;
/// Default notification cooldown time in minutes.
pub const NOTIFICATION_COOLDOWN_TIME: Duration = Duration::from_secs(60); // 1 minute

// Default configuration for LSPS5 service.
impl Default for LSPS5ServiceConfig {
	fn default() -> Self {
		Self { max_webhooks_per_client: DEFAULT_MAX_WEBHOOKS_PER_CLIENT }
	}
}

/// Service-side handler for the [`bLIP-55 / LSPS5`] webhook registration protocol.
///
/// Runs on the LSP (server) side. Stores and manages client-registered webhooks,
/// enforces per-client limits and retention policies, and emits signed JSON-RPC
/// notifications to each webhook endpoint when events occur.
///
/// # Core Responsibilities
/// - Handle incoming JSON-RPC requests:
///   - `lsps5.set_webhook` -> insert or replace a webhook, enforce [`max_webhooks_per_client`],
/// and send an initial [`lsps5.webhook_registered`] notification if new or changed.
///   - `lsps5.list_webhooks` -> return all registered [`app_name`]s via response.
///   - `lsps5.remove_webhook` -> delete a named webhook or return [`app_name_not_found`] error.
/// - Prune stale webhooks after a client has no open channels and no activity for at least
/// [`MIN_WEBHOOK_RETENTION_DAYS`].
/// - Sign and enqueue outgoing webhook notifications:
///   - Construct JSON-RPC 2.0 Notification objects [`WebhookNotification`],
///   - Timestamp and LN-style zbase32-sign each payload,
///   - Emit [`LSPS5ServiceEvent::SendWebhookNotification`] with HTTP headers.
///
/// # Security & Spec Compliance
/// - All notifications are signed with the LSP's node key according to bLIP-50/LSPS0.
/// - Clients must validate signature, timestamp (±10 min), and replay protection via
///   `LSPS5ClientHandler::parse_webhook_notification`.
/// - Webhook endpoints use only HTTPS and must guard against unauthorized calls.
///
/// [`bLIP-55 / LSPS5`]: https://github.com/lightning/blips/pull/55/files
/// [`max_webhooks_per_client`]: super::service::LSPS5ServiceConfig::max_webhooks_per_client
/// [`app_name_not_found`]: super::msgs::LSPS5ProtocolError::AppNameNotFound
/// [`WebhookNotification`]: super::msgs::WebhookNotification
/// [`LSPS5ServiceEvent::SendWebhookNotification`]: super::event::LSPS5ServiceEvent::SendWebhookNotification
/// [`app_name`]: super::msgs::LSPS5AppName
/// [`lsps5.webhook_registered`]: super::msgs::WebhookNotificationMethod::LSPS5WebhookRegistered
pub struct LSPS5ServiceHandler<CM: Deref, NS: Deref, K: Deref + Clone, TP: Deref>
where
	CM::Target: AChannelManager,
	NS::Target: NodeSigner,
	K::Target: KVStore,
	TP::Target: TimeProvider,
{
	config: LSPS5ServiceConfig,
	per_peer_state: RwLock<HashMap<PublicKey, PeerState>>,
	event_queue: Arc<EventQueue<K>>,
	pending_messages: Arc<MessageQueue>,
	time_provider: TP,
	channel_manager: CM,
	node_signer: NS,
	kv_store: K,
	last_pruning: Mutex<Option<LSPSDateTime>>,
	persistence_in_flight: AtomicUsize,
}

impl<CM: Deref, NS: Deref, K: Deref + Clone, TP: Deref> LSPS5ServiceHandler<CM, NS, K, TP>
where
	CM::Target: AChannelManager,
	NS::Target: NodeSigner,
	K::Target: KVStore,
	TP::Target: TimeProvider,
{
	/// Constructs a `LSPS5ServiceHandler` using the given time provider.
	pub(crate) fn new_with_time_provider(
		peer_states: HashMap<PublicKey, PeerState>, event_queue: Arc<EventQueue<K>>,
		pending_messages: Arc<MessageQueue>, channel_manager: CM, kv_store: K, node_signer: NS,
		config: LSPS5ServiceConfig, time_provider: TP,
	) -> Self {
		assert!(config.max_webhooks_per_client > 0, "`max_webhooks_per_client` must be > 0");
		let per_peer_state = RwLock::new(peer_states);
		Self {
			config,
			per_peer_state,
			event_queue,
			pending_messages,
			time_provider,
			channel_manager,
			node_signer,
			kv_store,
			last_pruning: Mutex::new(None),
			persistence_in_flight: AtomicUsize::new(0),
		}
	}

	/// Enforces the prior-activity requirement for state-allocating LSPS5 requests (e.g.
	/// `lsps5.set_webhook`), rejecting and replying with `NoPriorActivityError` if not met.
	pub(crate) fn enforce_prior_activity_or_reject(
		&self, client_id: &PublicKey, lsps2_has_active_requests: bool, lsps1_has_activity: bool,
		request_id: LSPSRequestId,
	) -> Result<(), LightningError> {
		let can_accept = self.client_has_open_channel(client_id)
			|| lsps2_has_active_requests
			|| lsps1_has_activity;

		let mut message_queue_notifier = self.pending_messages.notifier();
		if !can_accept {
			let error = LSPS5ProtocolError::NoPriorActivityError;
			let msg = LSPS5Message::Response(
				request_id,
				LSPS5Response::SetWebhookError(error.clone().into()),
			)
			.into();
			message_queue_notifier.enqueue(&client_id, msg);
			return Err(LightningError {
				err: error.message().into(),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		} else {
			Ok(())
		}
	}

	async fn persist_peer_state(
		&self, counterparty_node_id: PublicKey,
	) -> Result<(), lightning::io::Error> {
		let fut = {
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let encoded = match outer_state_lock.get_mut(&counterparty_node_id) {
				None => {
					// We dropped the peer state by now.
					return Ok(());
				},
				Some(entry) => {
					if !entry.needs_persist {
						// We already have persisted otherwise by now.
						return Ok(());
					} else {
						entry.needs_persist = false;
						entry.encode()
					}
				},
			};

			let key = counterparty_node_id.to_string();

			// Begin the write with the `per_peer_state` write lock held to avoid racing with
			// potentially-in-flight `persist` calls writing state for the same peer.
			self.kv_store.write(
				LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
				LSPS5_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
				&key,
				encoded,
			)
		};

		fut.await.map_err(|e| {
			self.per_peer_state
				.write()
				.unwrap()
				.get_mut(&counterparty_node_id)
				.map(|p| p.needs_persist = true);
			e
		})
	}

	pub(crate) async fn persist(&self) -> Result<(), lightning::io::Error> {
		// TODO: We should eventually persist in parallel, however, when we do, we probably want to
		// introduce some batching to upper-bound the number of requests inflight at any given
		// time.

		if self.persistence_in_flight.fetch_add(1, Ordering::AcqRel) > 0 {
			// If we're not the first event processor to get here, just return early, the increment
			// we just did will be treated as "go around again" at the end.
			return Ok(());
		}

		loop {
			let mut need_remove = Vec::new();
			let mut need_persist = Vec::new();

			self.check_prune_stale_webhooks(&mut self.per_peer_state.write().unwrap());
			{
				let outer_state_lock = self.per_peer_state.read().unwrap();

				for (client_id, peer_state) in outer_state_lock.iter() {
					let is_prunable = peer_state.is_prunable();
					let has_open_channel = self.client_has_open_channel(client_id);
					if is_prunable && !has_open_channel {
						need_remove.push(*client_id);
					} else if peer_state.needs_persist {
						need_persist.push(*client_id);
					}
				}
			}

			for client_id in need_persist.into_iter() {
				debug_assert!(!need_remove.contains(&client_id));
				self.persist_peer_state(client_id).await?;
			}

			for client_id in need_remove {
				let mut future_opt = None;
				{
					// We need to take the `per_peer_state` write lock to remove an entry, but also
					// have to hold it until after the `remove` call returns (but not through
					// future completion) to ensure that writes for the peer's state are
					// well-ordered with other `persist_peer_state` calls even across the removal
					// itself.
					let mut per_peer_state = self.per_peer_state.write().unwrap();
					if let Entry::Occupied(mut entry) = per_peer_state.entry(client_id) {
						let state = entry.get_mut();
						if state.is_prunable() && !self.client_has_open_channel(&client_id) {
							entry.remove();
							let key = client_id.to_string();
							future_opt = Some(self.kv_store.remove(
								LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
								LSPS5_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
								&key,
							));
						} else {
							// If the peer was re-added, force a re-persist of the current state.
							state.needs_persist = true;
						}
					} else {
						// This should never happen, we can only have one `persist` call
						// in-progress at once and map entries are only removed by it.
						debug_assert!(false);
					}
				}
				if let Some(future) = future_opt {
					future.await?;
				} else {
					self.persist_peer_state(client_id).await?;
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

		Ok(())
	}

	fn check_prune_stale_webhooks<'a>(
		&self, outer_state_lock: &mut RwLockWriteGuard<'a, HashMap<PublicKey, PeerState>>,
	) {
		let mut last_pruning = self.last_pruning.lock().unwrap();
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		let should_prune = last_pruning.as_ref().map_or(true, |last_time| {
			now.duration_since(&last_time) > PRUNE_STALE_WEBHOOKS_INTERVAL_DAYS
		});

		if should_prune {
			for (_, peer_state) in outer_state_lock.iter_mut() {
				// Prune stale webhooks, but leave removal of the peers states to the prune logic
				// in `persist` which will remove it from the store.
				peer_state.prune_stale_webhooks(now)
			}
			*last_pruning = Some(now);
		}
	}

	fn handle_set_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: SetWebhookRequest,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let mut outer_state_lock = self.per_peer_state.write().unwrap();

		let peer_state =
			outer_state_lock.entry(counterparty_node_id).or_insert_with(PeerState::default);

		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		let num_webhooks = peer_state.webhooks_len();
		let mut no_change = false;

		if let Some(webhook) = peer_state.webhook_mut(&params.app_name) {
			no_change = webhook.url == params.webhook;
			if !no_change {
				// The URL was updated.
				webhook.url = params.webhook.clone();
				webhook.last_used = now;
				webhook.last_notification_sent = None;
				peer_state.needs_persist |= true;
			}
		} else {
			if num_webhooks >= self.config.max_webhooks_per_client as usize {
				let error = LSPS5ProtocolError::TooManyWebhooks;
				let msg = LSPS5Message::Response(
					request_id,
					LSPS5Response::SetWebhookError(error.clone().into()),
				)
				.into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);
				return Err(LightningError {
					err: error.message().into(),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			}

			let webhook = Webhook {
				_app_name: params.app_name.clone(),
				url: params.webhook.clone(),
				_counterparty_node_id: counterparty_node_id,
				last_used: now,
				last_notification_sent: None,
			};

			peer_state.insert_webhook(params.app_name.clone(), webhook);
		}

		if !no_change {
			self.send_webhook_registered_notification(
				counterparty_node_id,
				params.app_name.clone(),
				params.webhook,
			)
			.map_err(|e| {
				let msg = LSPS5Message::Response(
					request_id.clone(),
					LSPS5Response::SetWebhookError(e.clone().into()),
				)
				.into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);
				LightningError {
					err: e.message().into(),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				}
			})?;
		}

		let msg = LSPS5Message::Response(
			request_id,
			LSPS5Response::SetWebhook(SetWebhookResponse {
				num_webhooks: peer_state.webhooks_len() as u32,
				max_webhooks: self.config.max_webhooks_per_client,
				no_change,
			}),
		)
		.into();
		message_queue_notifier.enqueue(&counterparty_node_id, msg);
		Ok(())
	}

	fn handle_list_webhooks(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		_params: ListWebhooksRequest,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		let app_names =
			outer_state_lock.get(&counterparty_node_id).map(|p| p.app_names()).unwrap_or_default();

		let max_webhooks = self.config.max_webhooks_per_client;

		let response = ListWebhooksResponse { app_names, max_webhooks };
		let msg = LSPS5Message::Response(request_id, LSPS5Response::ListWebhooks(response)).into();
		message_queue_notifier.enqueue(&counterparty_node_id, msg);

		Ok(())
	}

	fn handle_remove_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: RemoveWebhookRequest,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let mut outer_state_lock = self.per_peer_state.write().unwrap();

		if let Some(peer_state) = outer_state_lock.get_mut(&counterparty_node_id) {
			if peer_state.remove_webhook(&params.app_name) {
				let response = RemoveWebhookResponse {};
				let msg =
					LSPS5Message::Response(request_id, LSPS5Response::RemoveWebhook(response))
						.into();
				message_queue_notifier.enqueue(&counterparty_node_id, msg);

				return Ok(());
			}
		}

		let error = LSPS5ProtocolError::AppNameNotFound;
		let msg = LSPS5Message::Response(
			request_id,
			LSPS5Response::RemoveWebhookError(error.clone().into()),
		)
		.into();

		message_queue_notifier.enqueue(&counterparty_node_id, msg);
		return Err(LightningError {
			err: error.message().into(),
			action: ErrorAction::IgnoreAndLog(Level::Info),
		});
	}

	fn send_webhook_registered_notification(
		&self, client_node_id: PublicKey, app_name: LSPS5AppName, url: LSPS5WebhookUrl,
	) -> Result<(), LSPS5ProtocolError> {
		let notification = WebhookNotification::webhook_registered();
		self.send_notification(client_node_id, app_name, url, notification)
	}

	/// Notify the LSP service that the client has one or more incoming payments pending.
	///
	/// SHOULD be called by your LSP application logic as soon as you detect an incoming
	/// payment (HTLC or future mechanism) for `client_id`.
	/// This builds a [`WebhookNotificationMethod::LSPS5PaymentIncoming`] webhook notification, signs it with your
	/// node key, and enqueues HTTP POSTs to all registered webhook URLs for that client.
	///
	/// This may fail if a similar notification was sent too recently,
	/// violating the notification cooldown period defined in [`NOTIFICATION_COOLDOWN_TIME`].
	///
	/// # Parameters
	/// - `client_id`: the client's node-ID whose webhooks should be invoked.
	///
	/// [`WebhookNotificationMethod::LSPS5PaymentIncoming`]: super::msgs::WebhookNotificationMethod::LSPS5PaymentIncoming
	/// [`NOTIFICATION_COOLDOWN_TIME`]: super::service::NOTIFICATION_COOLDOWN_TIME
	pub fn notify_payment_incoming(&self, client_id: PublicKey) -> Result<(), LSPS5ProtocolError> {
		let notification = WebhookNotification::payment_incoming();
		self.send_notifications_to_client_webhooks(client_id, notification)
	}

	/// Notify that an HTLC or other time-bound contract is expiring soon.
	///
	/// SHOULD be called by your LSP application logic when a channel contract for `client_id`
	/// is within 24 blocks of timeout, and the timeout would cause a channel closure.
	/// Builds a [`WebhookNotificationMethod::LSPS5ExpirySoon`] notification including
	/// the `timeout` block height, signs it, and enqueues HTTP POSTs to the client's
	/// registered webhooks.
	///
	/// This may fail if a similar notification was sent too recently,
	/// violating the notification cooldown period defined in [`NOTIFICATION_COOLDOWN_TIME`].
	///
	/// # Parameters
	/// - `client_id`: the client's node-ID whose webhooks should be invoked.
	/// - `timeout`: the block height at which the channel contract will expire.
	///
	/// [`WebhookNotificationMethod::LSPS5ExpirySoon`]: super::msgs::WebhookNotificationMethod::LSPS5ExpirySoon
	/// [`NOTIFICATION_COOLDOWN_TIME`]: super::service::NOTIFICATION_COOLDOWN_TIME
	pub fn notify_expiry_soon(
		&self, client_id: PublicKey, timeout: u32,
	) -> Result<(), LSPS5ProtocolError> {
		let notification = WebhookNotification::expiry_soon(timeout);
		self.send_notifications_to_client_webhooks(client_id, notification)
	}

	/// Notify that the LSP intends to manage liquidity (e.g. close or splice) on client channels.
	///
	/// SHOULD be called by your LSP application logic when you decide to reclaim or adjust
	/// liquidity for `client_id`. Builds a [`WebhookNotificationMethod::LSPS5LiquidityManagementRequest`] notification,
	/// signs it, and sends it to all of the client's registered webhook URLs.
	///
	/// This may fail if a similar notification was sent too recently,
	/// violating the notification cooldown period defined in [`NOTIFICATION_COOLDOWN_TIME`].
	///
	/// # Parameters
	/// - `client_id`: the client's node-ID whose webhooks should be invoked.
	///
	/// [`WebhookNotificationMethod::LSPS5LiquidityManagementRequest`]: super::msgs::WebhookNotificationMethod::LSPS5LiquidityManagementRequest
	/// [`NOTIFICATION_COOLDOWN_TIME`]: super::service::NOTIFICATION_COOLDOWN_TIME
	pub fn notify_liquidity_management_request(
		&self, client_id: PublicKey,
	) -> Result<(), LSPS5ProtocolError> {
		let notification = WebhookNotification::liquidity_management_request();
		self.send_notifications_to_client_webhooks(client_id, notification)
	}

	/// Notify that the client has one or more pending BOLT Onion Messages.
	///
	/// SHOULD be called by your LSP application logic when you receive Onion Messages
	/// for `client_id` while the client is offline. Builds a [`WebhookNotificationMethod::LSPS5OnionMessageIncoming`]
	/// notification, signs it, and enqueues HTTP POSTs to each registered webhook.
	///
	/// This may fail if a similar notification was sent too recently,
	/// violating the notification cooldown period defined in [`NOTIFICATION_COOLDOWN_TIME`].
	///
	/// # Parameters
	/// - `client_id`: the client's node-ID whose webhooks should be invoked.
	///
	/// [`WebhookNotificationMethod::LSPS5OnionMessageIncoming`]: super::msgs::WebhookNotificationMethod::LSPS5OnionMessageIncoming
	/// [`NOTIFICATION_COOLDOWN_TIME`]: super::service::NOTIFICATION_COOLDOWN_TIME
	pub fn notify_onion_message_incoming(
		&self, client_id: PublicKey,
	) -> Result<(), LSPS5ProtocolError> {
		let notification = WebhookNotification::onion_message_incoming();
		self.send_notifications_to_client_webhooks(client_id, notification)
	}

	fn send_notifications_to_client_webhooks(
		&self, client_id: PublicKey, notification: WebhookNotification,
	) -> Result<(), LSPS5ProtocolError> {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let peer_state = if let Some(peer_state) = outer_state_lock.get_mut(&client_id) {
			peer_state
		} else {
			return Ok(());
		};

		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		// We must avoid sending multiple notifications of the same method
		// (other than lsps5.webhook_registered) close in time.
		if notification.method != WebhookNotificationMethod::LSPS5WebhookRegistered {
			let rate_limit_applies = peer_state.webhooks().iter().any(|(_, webhook)| {
				webhook.last_notification_sent.as_ref().is_some_and(|last_sent| {
					now.duration_since(&last_sent) < NOTIFICATION_COOLDOWN_TIME
				})
			});

			if rate_limit_applies {
				return Err(LSPS5ProtocolError::SlowDownError);
			}
		}

		for (app_name, webhook) in peer_state.webhooks_mut().iter_mut() {
			self.send_notification(
				client_id,
				app_name.clone(),
				webhook.url.clone(),
				notification.clone(),
			)?;
			webhook.last_used = now;
			webhook.last_notification_sent = Some(now);
		}
		Ok(())
	}

	fn send_notification(
		&self, counterparty_node_id: PublicKey, app_name: LSPS5AppName, url: LSPS5WebhookUrl,
		notification: WebhookNotification,
	) -> Result<(), LSPS5ProtocolError> {
		let event_queue_notifier = self.event_queue.notifier();
		let timestamp =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		let signature_hex = self.sign_notification(&notification, &timestamp)?;

		let mut headers: HashMap<String, String> = [("Content-Type", "application/json")]
			.into_iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect();
		headers.insert("x-lsps5-timestamp".into(), timestamp.to_rfc3339());
		headers.insert("x-lsps5-signature".into(), signature_hex);

		event_queue_notifier.enqueue(LSPS5ServiceEvent::SendWebhookNotification {
			counterparty_node_id,
			app_name,
			url,
			notification,
			headers,
		});

		Ok(())
	}

	fn sign_notification(
		&self, body: &WebhookNotification, timestamp: &LSPSDateTime,
	) -> Result<String, LSPS5ProtocolError> {
		let notification_json =
			serde_json::to_string(body).map_err(|_| LSPS5ProtocolError::SerializationError)?;

		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
			timestamp.to_rfc3339(),
			notification_json
		);

		self.node_signer
			.sign_message(message.as_bytes())
			.map_err(|_| LSPS5ProtocolError::UnknownError)
	}

	fn client_has_open_channel(&self, client_id: &PublicKey) -> bool {
		self.channel_manager
			.get_cm()
			.list_channels()
			.iter()
			.any(|c| c.is_usable && c.counterparty.node_id == *client_id)
	}

	pub(crate) fn peer_connected(&self, counterparty_node_id: &PublicKey) {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		if let Some(peer_state) = outer_state_lock.get_mut(counterparty_node_id) {
			peer_state.reset_notification_cooldown();
		}
		self.check_prune_stale_webhooks(&mut outer_state_lock);
	}

	pub(crate) fn peer_disconnected(&self, counterparty_node_id: &PublicKey) {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		if let Some(peer_state) = outer_state_lock.get_mut(counterparty_node_id) {
			peer_state.reset_notification_cooldown();
		}
		self.check_prune_stale_webhooks(&mut outer_state_lock);
	}
}

impl<CM: Deref, NS: Deref, K: Deref + Clone, TP: Deref> LSPSProtocolMessageHandler
	for LSPS5ServiceHandler<CM, NS, K, TP>
where
	CM::Target: AChannelManager,
	NS::Target: NodeSigner,
	K::Target: KVStore,
	TP::Target: TimeProvider,
{
	type ProtocolMessage = LSPS5Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(5);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS5Message::Request(request_id, request) => {
				let res = match request {
					LSPS5Request::SetWebhook(params) => {
						self.handle_set_webhook(*counterparty_node_id, request_id, params)
					},
					LSPS5Request::ListWebhooks(params) => {
						self.handle_list_webhooks(*counterparty_node_id, request_id, params)
					},
					LSPS5Request::RemoveWebhook(params) => {
						self.handle_remove_webhook(*counterparty_node_id, request_id, params)
					},
				};
				res
			},
			_ => {
				debug_assert!(
					false,
					"Service handler received LSPS5 response message. This should never happen."
				);
				let err = format!(
					"Service handler received LSPS5 response message from node {}. This should never happen.",
					counterparty_node_id
				);
				Err(LightningError { err, action: ErrorAction::IgnoreAndLog(Level::Info) })
			},
		}
	}
}

#[derive(Debug)]
pub(crate) struct PeerState {
	webhooks: Vec<(LSPS5AppName, Webhook)>,
	needs_persist: bool,
}

impl PeerState {
	fn webhook_mut(&mut self, name: &LSPS5AppName) -> Option<&mut Webhook> {
		let res =
			self.webhooks.iter_mut().find_map(|(n, h)| if n == name { Some(h) } else { None });
		self.needs_persist |= true;
		res
	}

	fn webhooks(&self) -> &Vec<(LSPS5AppName, Webhook)> {
		&self.webhooks
	}

	fn webhooks_mut(&mut self) -> &mut Vec<(LSPS5AppName, Webhook)> {
		let res = &mut self.webhooks;
		self.needs_persist |= true;
		res
	}

	fn webhooks_len(&self) -> usize {
		self.webhooks.len()
	}

	fn app_names(&self) -> Vec<LSPS5AppName> {
		self.webhooks.iter().map(|(n, _)| n).cloned().collect()
	}

	fn insert_webhook(&mut self, name: LSPS5AppName, hook: Webhook) {
		for (n, h) in self.webhooks.iter_mut() {
			if *n == name {
				*h = hook;
				return;
			}
		}

		self.webhooks.push((name, hook));
		self.needs_persist |= true;
	}

	fn remove_webhook(&mut self, name: &LSPS5AppName) -> bool {
		let mut removed = false;
		self.webhooks.retain(|(n, _)| {
			if n != name {
				true
			} else {
				removed = true;
				false
			}
		});
		self.needs_persist |= true;
		removed
	}

	fn reset_notification_cooldown(&mut self) {
		for (_, h) in self.webhooks.iter_mut() {
			h.last_notification_sent = None;
		}
		self.needs_persist |= true;
	}

	// Returns whether the entire state is empty and can be pruned.
	fn prune_stale_webhooks(&mut self, now: LSPSDateTime) {
		self.webhooks.retain(|(_, webhook)| {
			let should_prune = now.duration_since(&webhook.last_used) >= MIN_WEBHOOK_RETENTION_DAYS;
			if should_prune {
				self.needs_persist |= true;
			}
			!should_prune
		});
	}

	fn is_prunable(&self) -> bool {
		self.webhooks.is_empty()
	}
}

impl Default for PeerState {
	fn default() -> Self {
		let webhooks = Vec::new();
		let needs_persist = true;
		Self { webhooks, needs_persist }
	}
}

impl_writeable_tlv_based!(PeerState, {
	(0, webhooks, required_vec),
	(_unused, needs_persist, (static_value, false)),
});
