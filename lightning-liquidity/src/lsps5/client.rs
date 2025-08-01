// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Client implementation for LSPS5 webhook registration.

use crate::alloc::string::ToString;
use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSDateTime, LSPSMessage, LSPSProtocolMessageHandler, LSPSRequestId};
use crate::lsps5::event::LSPS5ClientEvent;
use crate::lsps5::msgs::{
	LSPS5Message, LSPS5Request, LSPS5Response, ListWebhooksRequest, RemoveWebhookRequest,
	SetWebhookRequest,
};

use crate::message_queue::MessageQueue;
use crate::prelude::{new_hash_map, HashMap};
use crate::sync::{Arc, Mutex, RwLock};
use crate::utils::generate_request_id;
use crate::utils::time::TimeProvider;

use super::msgs::{LSPS5AppName, LSPS5Error, LSPS5WebhookUrl};

use bitcoin::secp256k1::PublicKey;

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;

use alloc::string::String;

use core::ops::Deref;
use core::time::Duration;

/// Default maximum age in seconds for cached responses (1 hour).
pub const DEFAULT_RESPONSE_MAX_AGE_SECS: u64 = 3600;

#[derive(Debug, Clone)]
/// Configuration for the LSPS5 client
pub struct LSPS5ClientConfig {
	/// Maximum age in seconds for cached responses (default: [`DEFAULT_RESPONSE_MAX_AGE_SECS`]).
	pub response_max_age_secs: Duration,
}

impl Default for LSPS5ClientConfig {
	fn default() -> Self {
		Self { response_max_age_secs: Duration::from_secs(DEFAULT_RESPONSE_MAX_AGE_SECS) }
	}
}

struct PeerState<TP: Deref + Clone>
where
	TP::Target: TimeProvider,
{
	pending_set_webhook_requests:
		HashMap<LSPSRequestId, (LSPS5AppName, LSPS5WebhookUrl, LSPSDateTime)>,
	pending_list_webhooks_requests: HashMap<LSPSRequestId, LSPSDateTime>,
	pending_remove_webhook_requests: HashMap<LSPSRequestId, (LSPS5AppName, LSPSDateTime)>,
	last_cleanup: Option<LSPSDateTime>,
	max_age_secs: Duration,
	time_provider: TP,
}

impl<TP: Deref + Clone> PeerState<TP>
where
	TP::Target: TimeProvider,
{
	fn new(max_age_secs: Duration, time_provider: TP) -> Self {
		Self {
			pending_set_webhook_requests: new_hash_map(),
			pending_list_webhooks_requests: new_hash_map(),
			pending_remove_webhook_requests: new_hash_map(),
			last_cleanup: None,
			max_age_secs,
			time_provider,
		}
	}

	fn cleanup_expired_responses(&mut self) {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		// Only run cleanup once per minute to avoid excessive processing
		const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
		if let Some(last_cleanup) = &self.last_cleanup {
			let time_since_last_cleanup = Duration::from_secs(now.abs_diff(&last_cleanup));
			if time_since_last_cleanup < CLEANUP_INTERVAL {
				return;
			}
		}

		self.last_cleanup = Some(now.clone());

		self.pending_set_webhook_requests.retain(|_, (_, _, timestamp)| {
			Duration::from_secs(timestamp.abs_diff(&now)) < self.max_age_secs
		});
		self.pending_list_webhooks_requests.retain(|_, timestamp| {
			Duration::from_secs(timestamp.abs_diff(&now)) < self.max_age_secs
		});
		self.pending_remove_webhook_requests.retain(|_, (_, timestamp)| {
			Duration::from_secs(timestamp.abs_diff(&now)) < self.max_age_secs
		});
	}
}

/// Client-side handler for the LSPS5 (bLIP-55) webhook registration protocol.
///
/// `LSPS5ClientHandler` is the primary interface for LSP clients
/// to register, list, and remove webhook endpoints with an LSP.
///
/// This handler is intended for use on the client-side (e.g., a mobile app)
/// which has access to the node's keys and can send/receive peer messages.
///
/// For validating incoming webhook notifications on a server, see [`LSPS5Validator`].
///
/// # Core Capabilities
///
///  - `set_webhook(peer, app_name, url)` -> register or update a webhook [`lsps5.set_webhook`]
///  - `list_webhooks(peer)` -> retrieve all registered webhooks [`lsps5.list_webhooks`]
///  - `remove_webhook(peer, name)` -> delete a webhook [`lsps5.remove_webhook`]
///
/// [`bLIP-55 / LSPS5 specification`]: https://github.com/lightning/blips/pull/55/files
/// [`lsps5.set_webhook`]: super::msgs::LSPS5Request::SetWebhook
/// [`lsps5.list_webhooks`]: super::msgs::LSPS5Request::ListWebhooks
/// [`lsps5.remove_webhook`]: super::msgs::LSPS5Request::RemoveWebhook
/// [`LSPS5Validator`]: super::validator::LSPS5Validator
pub struct LSPS5ClientHandler<ES: Deref, TP: Deref + Clone>
where
	ES::Target: EntropySource,
	TP::Target: TimeProvider,
{
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	entropy_source: ES,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState<TP>>>>,
	config: LSPS5ClientConfig,
	time_provider: TP,
}

impl<ES: Deref, TP: Deref + Clone> LSPS5ClientHandler<ES, TP>
where
	ES::Target: EntropySource,
	TP::Target: TimeProvider,
{
	/// Constructs an `LSPS5ClientHandler`.
	pub(crate) fn new_with_time_provider(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		config: LSPS5ClientConfig, time_provider: TP,
	) -> Self {
		Self {
			pending_messages,
			pending_events,
			entropy_source,
			per_peer_state: RwLock::new(new_hash_map()),
			config,
			time_provider,
		}
	}

	fn with_peer_state<F, R>(&self, counterparty_node_id: PublicKey, f: F) -> R
	where
		F: FnOnce(&mut PeerState<TP>) -> R,
	{
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock = outer_state_lock.entry(counterparty_node_id).or_insert(Mutex::new(
			PeerState::new(self.config.response_max_age_secs, self.time_provider.clone()),
		));
		let mut peer_state_lock = inner_state_lock.lock().unwrap();

		peer_state_lock.cleanup_expired_responses();

		f(&mut *peer_state_lock)
	}

	/// Register or update a webhook endpoint under a human-readable name.
	///
	/// Sends a `lsps5.set_webhook` JSON-RPC request to the given LSP peer.
	///
	/// # Parameters
	/// - `counterparty_node_id`: The LSP node ID to contact.
	/// - `app_name`: A UTF-8 name for this webhook.
	/// - `webhook_url`: HTTPS URL for push notifications.
	///
	/// # Returns
	/// A unique `LSPSRequestId` for correlating the asynchronous response.
	///
	/// Response from the LSP peer will be provided asynchronously through a
	/// [`LSPS5Response::SetWebhook`] or [`LSPS5Response::SetWebhookError`] message, and this client
	/// will then enqueue either a [`WebhookRegistered`] or [`WebhookRegistrationFailed`] event.
	///
	/// **Note**: Ensure the app name is valid and its length does not exceed [`MAX_APP_NAME_LENGTH`].
	/// Also ensure the URL is valid, has HTTPS protocol, its length does not exceed [`MAX_WEBHOOK_URL_LENGTH`]
	/// and that the URL points to a public host.
	///
	/// [`MAX_WEBHOOK_URL_LENGTH`]: super::msgs::MAX_WEBHOOK_URL_LENGTH
	/// [`MAX_APP_NAME_LENGTH`]: super::msgs::MAX_APP_NAME_LENGTH
	/// [`WebhookRegistered`]: super::event::LSPS5ClientEvent::WebhookRegistered
	/// [`WebhookRegistrationFailed`]: super::event::LSPS5ClientEvent::WebhookRegistrationFailed
	/// [`LSPS5Response::SetWebhook`]: super::msgs::LSPS5Response::SetWebhook
	/// [`LSPS5Response::SetWebhookError`]: super::msgs::LSPS5Response::SetWebhookError
	pub fn set_webhook(
		&self, counterparty_node_id: PublicKey, app_name: String, webhook_url: String,
	) -> Result<LSPSRequestId, LSPS5Error> {
		let app_name = LSPS5AppName::from_string(app_name)?;

		let lsps_webhook_url = LSPS5WebhookUrl::from_string(webhook_url)?;

		let request_id = generate_request_id(&self.entropy_source);

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.pending_set_webhook_requests.insert(
				request_id.clone(),
				(
					app_name.clone(),
					lsps_webhook_url.clone(),
					LSPSDateTime::new_from_duration_since_epoch(
						self.time_provider.duration_since_epoch(),
					),
				),
			);
		});

		let request =
			LSPS5Request::SetWebhook(SetWebhookRequest { app_name, webhook: lsps_webhook_url });

		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		Ok(request_id)
	}

	/// List all webhook names currently registered with the LSP.
	///
	/// Sends a `lsps5.list_webhooks` JSON-RPC request to the peer.
	///
	/// # Parameters
	/// - `counterparty_node_id`: The LSP node ID to query.
	///
	/// # Returns
	/// A unique `LSPSRequestId` for correlating the asynchronous response.
	///
	/// Response from the LSP peer will be provided asynchronously through a
	/// [`LSPS5Response::ListWebhooks`] message, and this client
	/// will then enqueue a [`WebhooksListed`] event.
	///
	/// [`WebhooksListed`]: super::event::LSPS5ClientEvent::WebhooksListed
	/// [`LSPS5Response::ListWebhooks`]: super::msgs::LSPS5Response::ListWebhooks
	pub fn list_webhooks(&self, counterparty_node_id: PublicKey) -> LSPSRequestId {
		let request_id = generate_request_id(&self.entropy_source);
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.pending_list_webhooks_requests.insert(request_id.clone(), now);
		});

		let request = LSPS5Request::ListWebhooks(ListWebhooksRequest {});
		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		request_id
	}

	/// Remove a previously registered webhook by its name.
	///
	/// Sends a `lsps5.remove_webhook` JSON-RPC request to the peer.
	///
	/// # Parameters
	/// - `counterparty_node_id`: The LSP node ID to contact.
	/// - `app_name`: The name of the webhook to remove.
	///
	/// # Returns
	/// A unique `LSPSRequestId` for correlating the asynchronous response.
	///
	/// Response from the LSP peer will be provided asynchronously through a
	/// [`LSPS5Response::RemoveWebhook`] or [`LSPS5Response::RemoveWebhookError`] message, and this client
	/// will then enqueue either a [`WebhookRemoved`] or [`WebhookRemovalFailed`] event.
	///
	/// [`WebhookRemoved`]: super::event::LSPS5ClientEvent::WebhookRemoved
	/// [`WebhookRemovalFailed`]: super::event::LSPS5ClientEvent::WebhookRemovalFailed
	/// [`LSPS5Response::RemoveWebhook`]: super::msgs::LSPS5Response::RemoveWebhook
	/// [`LSPS5Response::RemoveWebhookError`]: super::msgs::LSPS5Response::RemoveWebhookError
	pub fn remove_webhook(
		&self, counterparty_node_id: PublicKey, app_name: String,
	) -> Result<LSPSRequestId, LSPS5Error> {
		let app_name = LSPS5AppName::from_string(app_name)?;

		let request_id = generate_request_id(&self.entropy_source);
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state
				.pending_remove_webhook_requests
				.insert(request_id.clone(), (app_name.clone(), now));
		});

		let request = LSPS5Request::RemoveWebhook(RemoveWebhookRequest { app_name });
		let message = LSPS5Message::Request(request_id.clone(), request);
		self.pending_messages.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

		Ok(request_id)
	}

	fn handle_message(
		&self, message: LSPS5Message, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let (request_id, response) = match message {
			LSPS5Message::Request(_, _) => {
				return Err(LightningError {
					err: format!(
						"Received unexpected request message from {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
			LSPS5Message::Response(rid, resp) => (rid, resp),
		};
		let mut result: Result<(), LightningError> = Err(LightningError {
			err: format!("Received LSPS5 response from unknown peer: {}", counterparty_node_id),
			action: ErrorAction::IgnoreAndLog(Level::Debug),
		});
		let event_queue_notifier = self.pending_events.notifier();
		let handle_response = |peer_state: &mut PeerState<TP>| {
			if let Some((app_name, webhook_url, _)) =
				peer_state.pending_set_webhook_requests.remove(&request_id)
			{
				match &response {
					LSPS5Response::SetWebhook(r) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookRegistered {
							counterparty_node_id: *counterparty_node_id,
							num_webhooks: r.num_webhooks,
							max_webhooks: r.max_webhooks,
							no_change: r.no_change,
							app_name,
							url: webhook_url,
							request_id,
						});
						result = Ok(());
					},
					LSPS5Response::SetWebhookError(e) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookRegistrationFailed {
							counterparty_node_id: *counterparty_node_id,
							error: e.clone().into(),
							app_name,
							url: webhook_url,
							request_id,
						});
						result = Ok(());
					},
					_ => {
						result = Err(LightningError {
							err: "Unexpected response type for SetWebhook".to_string(),
							action: ErrorAction::IgnoreAndLog(Level::Error),
						});
					},
				}
			} else if peer_state.pending_list_webhooks_requests.remove(&request_id).is_some() {
				match &response {
					LSPS5Response::ListWebhooks(r) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhooksListed {
							counterparty_node_id: *counterparty_node_id,
							app_names: r.app_names.clone(),
							max_webhooks: r.max_webhooks,
							request_id,
						});
						result = Ok(());
					},
					_ => {
						result = Err(LightningError {
							err: "Unexpected response type for ListWebhooks".to_string(),
							action: ErrorAction::IgnoreAndLog(Level::Error),
						});
					},
				}
			} else if let Some((app_name, _)) =
				peer_state.pending_remove_webhook_requests.remove(&request_id)
			{
				match &response {
					LSPS5Response::RemoveWebhook(_) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookRemoved {
							counterparty_node_id: *counterparty_node_id,
							app_name,
							request_id,
						});
						result = Ok(());
					},
					LSPS5Response::RemoveWebhookError(e) => {
						event_queue_notifier.enqueue(LSPS5ClientEvent::WebhookRemovalFailed {
							counterparty_node_id: *counterparty_node_id,
							error: e.clone().into(),
							app_name,
							request_id,
						});
						result = Ok(());
					},
					_ => {
						result = Err(LightningError {
							err: "Unexpected response type for RemoveWebhook".to_string(),
							action: ErrorAction::IgnoreAndLog(Level::Error),
						});
					},
				}
			} else {
				result = Err(LightningError {
					err: format!("Received response for unknown request ID: {}", request_id.0),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			}
		};
		self.with_peer_state(*counterparty_node_id, handle_response);
		result
	}
}

impl<ES: Deref, TP: Deref + Clone> LSPSProtocolMessageHandler for LSPS5ClientHandler<ES, TP>
where
	ES::Target: EntropySource,
	TP::Target: TimeProvider,
{
	type ProtocolMessage = LSPS5Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(5);

	fn handle_message(
		&self, message: Self::ProtocolMessage, lsp_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		self.handle_message(message, lsp_node_id)
	}
}

#[cfg(all(test, feature = "time"))]
mod tests {
	use core::time::Duration;

	use super::*;
	use crate::{
		lsps0::ser::LSPSRequestId, lsps5::msgs::SetWebhookResponse, tests::utils::TestEntropy,
		utils::time::DefaultTimeProvider,
	};
	use bitcoin::{key::Secp256k1, secp256k1::SecretKey};

	fn setup_test_client() -> (
		LSPS5ClientHandler<Arc<TestEntropy>, Arc<DefaultTimeProvider>>,
		Arc<MessageQueue>,
		Arc<EventQueue>,
		PublicKey,
		PublicKey,
	) {
		let test_entropy_source = Arc::new(TestEntropy {});
		let message_queue = Arc::new(MessageQueue::new());
		let event_queue = Arc::new(EventQueue::new());
		let client = LSPS5ClientHandler::new_with_time_provider(
			test_entropy_source,
			Arc::clone(&message_queue),
			Arc::clone(&event_queue),
			LSPS5ClientConfig::default(),
			Arc::new(DefaultTimeProvider),
		);

		let secp = Secp256k1::new();
		let secret_key_1 = SecretKey::from_slice(&[42u8; 32]).unwrap();
		let secret_key_2 = SecretKey::from_slice(&[43u8; 32]).unwrap();
		let peer_1 = PublicKey::from_secret_key(&secp, &secret_key_1);
		let peer_2 = PublicKey::from_secret_key(&secp, &secret_key_2);

		(client, message_queue, event_queue, peer_1, peer_2)
	}

	#[test]
	fn test_per_peer_state_isolation() {
		let (client, _, _, peer_1, peer_2) = setup_test_client();

		let req_id_1 = client
			.set_webhook(peer_1, "test-app-1".to_string(), "https://example.com/hook1".to_string())
			.unwrap();
		let req_id_2 = client
			.set_webhook(peer_2, "test-app-2".to_string(), "https://example.com/hook2".to_string())
			.unwrap();

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();

			let peer_1_state = outer_state_lock.get(&peer_1).unwrap().lock().unwrap();
			assert!(peer_1_state.pending_set_webhook_requests.contains_key(&req_id_1));

			let peer_2_state = outer_state_lock.get(&peer_2).unwrap().lock().unwrap();
			assert!(peer_2_state.pending_set_webhook_requests.contains_key(&req_id_2));
		}
	}

	#[test]
	fn test_pending_request_tracking() {
		let (client, _, _, peer, _) = setup_test_client();
		const APP_NAME: &str = "test-app";
		const WEBHOOK_URL: &str = "https://example.com/hook";
		let lsps5_app_name = LSPS5AppName::from_string(APP_NAME.to_string()).unwrap();
		let lsps5_webhook_url = LSPS5WebhookUrl::from_string(WEBHOOK_URL.to_string()).unwrap();
		let set_req_id =
			client.set_webhook(peer, APP_NAME.to_string(), WEBHOOK_URL.to_string()).unwrap();
		let list_req_id = client.list_webhooks(peer);
		let remove_req_id = client.remove_webhook(peer, "test-app".to_string()).unwrap();

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert_eq!(
				peer_state.pending_set_webhook_requests.get(&set_req_id).unwrap(),
				&(
					lsps5_app_name.clone(),
					lsps5_webhook_url,
					peer_state.pending_set_webhook_requests.get(&set_req_id).unwrap().2.clone()
				)
			);

			assert!(peer_state.pending_list_webhooks_requests.contains_key(&list_req_id));

			assert_eq!(
				peer_state.pending_remove_webhook_requests.get(&remove_req_id).unwrap().0,
				lsps5_app_name
			);
		}
	}

	#[test]
	fn test_handle_response_clears_pending_state() {
		let (client, _, _, peer, _) = setup_test_client();

		let req_id = client
			.set_webhook(peer, "test-app".to_string(), "https://example.com/hook".to_string())
			.unwrap();

		let response = LSPS5Response::SetWebhook(SetWebhookResponse {
			num_webhooks: 1,
			max_webhooks: 5,
			no_change: false,
		});
		let response_msg = LSPS5Message::Response(req_id.clone(), response);

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert!(peer_state.pending_set_webhook_requests.contains_key(&req_id));
		}

		client.handle_message(response_msg, &peer).unwrap();

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert!(!peer_state.pending_set_webhook_requests.contains_key(&req_id));
		}
	}

	#[test]
	fn test_cleanup_expired_responses() {
		let (client, _, _, _, _) = setup_test_client();
		let time_provider = &client.time_provider;
		const OLD_APP_NAME: &str = "test-app-old";
		const NEW_APP_NAME: &str = "test-app-new";
		const WEBHOOK_URL: &str = "https://example.com/hook";
		let lsps5_old_app_name = LSPS5AppName::from_string(OLD_APP_NAME.to_string()).unwrap();
		let lsps5_new_app_name = LSPS5AppName::from_string(NEW_APP_NAME.to_string()).unwrap();
		let lsps5_webhook_url = LSPS5WebhookUrl::from_string(WEBHOOK_URL.to_string()).unwrap();
		let now = time_provider.duration_since_epoch();
		let mut peer_state = PeerState::<Arc<DefaultTimeProvider>>::new(
			Duration::from_secs(1800),
			Arc::clone(time_provider),
		);
		peer_state.last_cleanup = Some(LSPSDateTime::new_from_duration_since_epoch(
			now.checked_sub(Duration::from_secs(120)).unwrap(),
		));

		let old_request_id = LSPSRequestId("test:request:old".to_string());
		let new_request_id = LSPSRequestId("test:request:new".to_string());

		// Add an old request (should be removed during cleanup)
		peer_state.pending_set_webhook_requests.insert(
			old_request_id.clone(),
			(
				lsps5_old_app_name,
				lsps5_webhook_url.clone(),
				LSPSDateTime::new_from_duration_since_epoch(
					now.checked_sub(Duration::from_secs(7200)).unwrap(),
				),
			), // 2 hours old
		);

		// Add a recent request (should be kept)
		peer_state.pending_set_webhook_requests.insert(
			new_request_id.clone(),
			(
				lsps5_new_app_name,
				lsps5_webhook_url,
				LSPSDateTime::new_from_duration_since_epoch(
					now.checked_sub(Duration::from_secs(600)).unwrap(),
				),
			), // 10 minutes old
		);

		peer_state.cleanup_expired_responses();

		assert!(!peer_state.pending_set_webhook_requests.contains_key(&old_request_id));
		assert!(peer_state.pending_set_webhook_requests.contains_key(&new_request_id));

		let cleanup_age = if let Some(last_cleanup) = peer_state.last_cleanup {
			LSPSDateTime::new_from_duration_since_epoch(time_provider.duration_since_epoch())
				.abs_diff(&last_cleanup)
		} else {
			0
		};
		assert!(cleanup_age < 10);
	}

	#[test]
	fn test_unknown_request_id_handling() {
		let (client, _message_queue, _, peer, _) = setup_test_client();

		let _valid_req = client
			.set_webhook(peer, "test-app".to_string(), "https://example.com/hook".to_string())
			.unwrap();

		let unknown_req_id = LSPSRequestId("unknown:request:id".to_string());
		let response = LSPS5Response::SetWebhook(SetWebhookResponse {
			num_webhooks: 1,
			max_webhooks: 5,
			no_change: false,
		});
		let response_msg = LSPS5Message::Response(unknown_req_id, response);

		let result = client.handle_message(response_msg, &peer);
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert!(error.err.to_lowercase().contains("unknown request id"));
	}
}
