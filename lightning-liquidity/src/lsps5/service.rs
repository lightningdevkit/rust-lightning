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
use crate::prelude::hash_map::Entry;
use crate::prelude::*;
use crate::sync::{Arc, Mutex};
use crate::utils::time::TimeProvider;

use bitcoin::secp256k1::PublicKey;

use lightning::ln::channelmanager::AChannelManager;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::NodeSigner;
use lightning::util::logger::Level;

use core::ops::Deref;
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
struct StoredWebhook {
	_app_name: LSPS5AppName,
	url: LSPS5WebhookUrl,
	_counterparty_node_id: PublicKey,
	last_used: LSPSDateTime,
	last_notification_sent: HashMap<WebhookNotificationMethod, LSPSDateTime>,
}

/// Server-side configuration options for LSPS5 Webhook Registration.
#[derive(Clone, Debug)]
pub struct LSPS5ServiceConfig {
	/// Maximum number of webhooks allowed per client.
	pub max_webhooks_per_client: u32,
	/// Minimum time between sending the same notification type in hours (default: 24)
	pub notification_cooldown_hours: Duration,
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
/// - Rate-limit repeat notifications of the same method to a client by
///   [`notification_cooldown_hours`].
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
/// [`notification_cooldown_hours`]: super::service::LSPS5ServiceConfig::notification_cooldown_hours
/// [`WebhookNotification`]: super::msgs::WebhookNotification
/// [`LSPS5ServiceEvent::SendWebhookNotification`]: super::event::LSPS5ServiceEvent::SendWebhookNotification
/// [`app_name`]: super::msgs::LSPS5AppName
/// [`lsps5.webhook_registered`]: super::msgs::WebhookNotificationMethod::LSPS5WebhookRegistered
pub struct LSPS5ServiceHandler<CM: Deref, NS: Deref, TP: Deref>
where
	CM::Target: AChannelManager,
	NS::Target: NodeSigner,
	TP::Target: TimeProvider,
{
	config: LSPS5ServiceConfig,
	webhooks: Mutex<HashMap<PublicKey, HashMap<LSPS5AppName, StoredWebhook>>>,
	event_queue: Arc<EventQueue>,
	pending_messages: Arc<MessageQueue>,
	time_provider: TP,
	channel_manager: CM,
	node_signer: NS,
	last_pruning: Mutex<Option<LSPSDateTime>>,
}

impl<CM: Deref, NS: Deref, TP: Deref> LSPS5ServiceHandler<CM, NS, TP>
where
	CM::Target: AChannelManager,
	NS::Target: NodeSigner,
	TP::Target: TimeProvider,
{
	/// Constructs a `LSPS5ServiceHandler` using the given time provider.
	pub(crate) fn new_with_time_provider(
		event_queue: Arc<EventQueue>, pending_messages: Arc<MessageQueue>, channel_manager: CM,
		node_signer: NS, config: LSPS5ServiceConfig, time_provider: TP,
	) -> Self {
		assert!(config.max_webhooks_per_client > 0, "`max_webhooks_per_client` must be > 0");
		Self {
			config,
			webhooks: Mutex::new(new_hash_map()),
			event_queue,
			pending_messages,
			time_provider,
			channel_manager,
			node_signer,
			last_pruning: Mutex::new(None),
		}
	}

	fn check_prune_stale_webhooks(&self) {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let should_prune = {
			let last_pruning = self.last_pruning.lock().unwrap();
			last_pruning.as_ref().map_or(true, |last_time| {
				now.abs_diff(&last_time) > PRUNE_STALE_WEBHOOKS_INTERVAL_DAYS.as_secs()
			})
		};

		if should_prune {
			self.prune_stale_webhooks();
		}
	}

	fn handle_set_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: SetWebhookRequest,
	) -> Result<(), LightningError> {
		self.check_prune_stale_webhooks();

		let mut webhooks = self.webhooks.lock().unwrap();

		let client_webhooks = webhooks.entry(counterparty_node_id).or_insert_with(new_hash_map);
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		let num_webhooks = client_webhooks.len();
		let mut no_change = false;
		match client_webhooks.entry(params.app_name.clone()) {
			Entry::Occupied(mut entry) => {
				no_change = entry.get().url == params.webhook;
				let (last_used, last_notification_sent) = if no_change {
					(entry.get().last_used.clone(), entry.get().last_notification_sent.clone())
				} else {
					(now, new_hash_map())
				};
				entry.insert(StoredWebhook {
					_app_name: params.app_name.clone(),
					url: params.webhook.clone(),
					_counterparty_node_id: counterparty_node_id,
					last_used,
					last_notification_sent,
				});
			},
			Entry::Vacant(entry) => {
				if num_webhooks >= self.config.max_webhooks_per_client as usize {
					let error = LSPS5ProtocolError::TooManyWebhooks;
					let msg = LSPS5Message::Response(
						request_id,
						LSPS5Response::SetWebhookError(error.clone().into()),
					)
					.into();
					self.pending_messages.enqueue(&counterparty_node_id, msg);
					return Err(LightningError {
						err: error.message().into(),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}

				entry.insert(StoredWebhook {
					_app_name: params.app_name.clone(),
					url: params.webhook.clone(),
					_counterparty_node_id: counterparty_node_id,
					last_used: now,
					last_notification_sent: new_hash_map(),
				});
			},
		}

		if !no_change {
			self.send_webhook_registered_notification(
				counterparty_node_id,
				params.app_name,
				params.webhook,
			)
			.map_err(|e| {
				let msg = LSPS5Message::Response(
					request_id.clone(),
					LSPS5Response::SetWebhookError(e.clone().into()),
				)
				.into();
				self.pending_messages.enqueue(&counterparty_node_id, msg);
				LightningError {
					err: e.message().into(),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				}
			})?;
		}

		let msg = LSPS5Message::Response(
			request_id,
			LSPS5Response::SetWebhook(SetWebhookResponse {
				num_webhooks: client_webhooks.len() as u32,
				max_webhooks: self.config.max_webhooks_per_client,
				no_change,
			}),
		)
		.into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);
		Ok(())
	}

	fn handle_list_webhooks(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		_params: ListWebhooksRequest,
	) -> Result<(), LightningError> {
		self.check_prune_stale_webhooks();

		let webhooks = self.webhooks.lock().unwrap();

		let app_names = webhooks
			.get(&counterparty_node_id)
			.map(|client_webhooks| client_webhooks.keys().cloned().collect::<Vec<_>>())
			.unwrap_or_else(Vec::new);

		let max_webhooks = self.config.max_webhooks_per_client;

		let response = ListWebhooksResponse { app_names, max_webhooks };
		let msg = LSPS5Message::Response(request_id, LSPS5Response::ListWebhooks(response)).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		Ok(())
	}

	fn handle_remove_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: RemoveWebhookRequest,
	) -> Result<(), LightningError> {
		self.check_prune_stale_webhooks();

		let mut webhooks = self.webhooks.lock().unwrap();

		if let Some(client_webhooks) = webhooks.get_mut(&counterparty_node_id) {
			if client_webhooks.remove(&params.app_name).is_some() {
				let response = RemoveWebhookResponse {};
				let msg =
					LSPS5Message::Response(request_id, LSPS5Response::RemoveWebhook(response))
						.into();
				self.pending_messages.enqueue(&counterparty_node_id, msg);

				return Ok(());
			}
		}

		let error = LSPS5ProtocolError::AppNameNotFound;
		let msg = LSPS5Message::Response(
			request_id,
			LSPS5Response::RemoveWebhookError(error.clone().into()),
		)
		.into();

		self.pending_messages.enqueue(&counterparty_node_id, msg);
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
	/// # Parameters
	/// - `client_id`: the client's node-ID whose webhooks should be invoked.
	///
	/// [`WebhookNotificationMethod::LSPS5PaymentIncoming`]: super::msgs::WebhookNotificationMethod::LSPS5PaymentIncoming
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
	/// # Parameters
	/// - `client_id`: the client's node-ID whose webhooks should be invoked.
	/// - `timeout`: the block height at which the channel contract will expire.
	///
	/// [`WebhookNotificationMethod::LSPS5ExpirySoon`]: super::msgs::WebhookNotificationMethod::LSPS5ExpirySoon
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
	/// # Parameters
	/// - `client_id`: the client's node-ID whose webhooks should be invoked.
	///
	/// [`WebhookNotificationMethod::LSPS5LiquidityManagementRequest`]: super::msgs::WebhookNotificationMethod::LSPS5LiquidityManagementRequest
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
	/// # Parameters
	/// - `client_id`: the client's node-ID whose webhooks should be invoked.
	///
	/// [`WebhookNotificationMethod::LSPS5OnionMessageIncoming`]: super::msgs::WebhookNotificationMethod::LSPS5OnionMessageIncoming
	pub fn notify_onion_message_incoming(
		&self, client_id: PublicKey,
	) -> Result<(), LSPS5ProtocolError> {
		let notification = WebhookNotification::onion_message_incoming();
		self.send_notifications_to_client_webhooks(client_id, notification)
	}

	fn send_notifications_to_client_webhooks(
		&self, client_id: PublicKey, notification: WebhookNotification,
	) -> Result<(), LSPS5ProtocolError> {
		let mut webhooks = self.webhooks.lock().unwrap();

		let client_webhooks = match webhooks.get_mut(&client_id) {
			Some(webhooks) if !webhooks.is_empty() => webhooks,
			_ => return Ok(()),
		};

		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		for (app_name, webhook) in client_webhooks.iter_mut() {
			if webhook
				.last_notification_sent
				.get(&notification.method)
				.map(|last_sent| now.clone().abs_diff(&last_sent))
				.map_or(true, |duration| {
					duration >= self.config.notification_cooldown_hours.as_secs()
				}) {
				webhook.last_notification_sent.insert(notification.method.clone(), now.clone());
				webhook.last_used = now.clone();
				self.send_notification(
					client_id,
					app_name.clone(),
					webhook.url.clone(),
					notification.clone(),
				)?;
			}
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

	fn prune_stale_webhooks(&self) {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let mut webhooks = self.webhooks.lock().unwrap();

		webhooks.retain(|client_id, client_webhooks| {
			if !self.client_has_open_channel(client_id) {
				client_webhooks.retain(|_, webhook| {
					now.abs_diff(&webhook.last_used) < MIN_WEBHOOK_RETENTION_DAYS.as_secs()
				});
				!client_webhooks.is_empty()
			} else {
				true
			}
		});

		let mut last_pruning = self.last_pruning.lock().unwrap();
		*last_pruning = Some(now);
	}

	fn client_has_open_channel(&self, client_id: &PublicKey) -> bool {
		self.channel_manager
			.get_cm()
			.list_channels()
			.iter()
			.any(|c| c.is_usable && c.counterparty.node_id == *client_id)
	}
}

impl<CM: Deref, NS: Deref, TP: Deref> LSPSProtocolMessageHandler for LSPS5ServiceHandler<CM, NS, TP>
where
	CM::Target: AChannelManager,
	NS::Target: NodeSigner,
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
					"Service handler received LSPS5 response message from node {:?}. This should never happen.",
					counterparty_node_id
				);
				Err(LightningError { err, action: ErrorAction::IgnoreAndLog(Level::Info) })
			},
		}
	}
}
