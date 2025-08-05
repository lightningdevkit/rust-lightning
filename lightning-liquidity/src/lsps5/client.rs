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
use crate::lsps0::ser::{LSPSMessage, LSPSProtocolMessageHandler, LSPSRequestId};
use crate::lsps5::event::LSPS5ClientEvent;
use crate::lsps5::msgs::{
	LSPS5Message, LSPS5Request, LSPS5Response, ListWebhooksRequest, RemoveWebhookRequest,
	SetWebhookRequest,
};

use crate::message_queue::MessageQueue;
use crate::prelude::{new_hash_map, HashMap};
use crate::sync::{Arc, Mutex, RwLock};
use crate::utils::generate_request_id;

use super::msgs::{LSPS5AppName, LSPS5Error, LSPS5WebhookUrl};

use bitcoin::secp256k1::PublicKey;

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;

use alloc::collections::VecDeque;
use alloc::string::String;

use core::ops::Deref;

impl PartialEq<LSPSRequestId> for (LSPSRequestId, (LSPS5AppName, LSPS5WebhookUrl)) {
	fn eq(&self, other: &LSPSRequestId) -> bool {
		&self.0 == other
	}
}

impl PartialEq<LSPSRequestId> for (LSPSRequestId, LSPS5AppName) {
	fn eq(&self, other: &LSPSRequestId) -> bool {
		&self.0 == other
	}
}

#[derive(Debug, Clone, Copy, Default)]
/// Configuration for the LSPS5 client
pub struct LSPS5ClientConfig {}

struct PeerState {
	pending_set_webhook_requests: VecDeque<(LSPSRequestId, (LSPS5AppName, LSPS5WebhookUrl))>,
	pending_list_webhooks_requests: VecDeque<LSPSRequestId>,
	pending_remove_webhook_requests: VecDeque<(LSPSRequestId, LSPS5AppName)>,
}

const MAX_PENDING_REQUESTS: usize = 5;

impl PeerState {
	fn new() -> Self {
		Self {
			pending_set_webhook_requests: VecDeque::with_capacity(MAX_PENDING_REQUESTS),
			pending_list_webhooks_requests: VecDeque::with_capacity(MAX_PENDING_REQUESTS),
			pending_remove_webhook_requests: VecDeque::with_capacity(MAX_PENDING_REQUESTS),
		}
	}

	fn add_request<T, F>(&mut self, item: T, queue_selector: F)
	where
		F: FnOnce(&mut Self) -> &mut VecDeque<T>,
	{
		let queue = queue_selector(self);
		if queue.len() == MAX_PENDING_REQUESTS {
			queue.pop_front();
		}
		queue.push_back(item);
	}

	fn find_and_remove_request<T, F>(
		&mut self, queue_selector: F, request_id: &LSPSRequestId,
	) -> Option<T>
	where
		F: FnOnce(&mut Self) -> &mut VecDeque<T>,
		T: Clone,
		for<'a> &'a T: PartialEq<&'a LSPSRequestId>,
	{
		let queue = queue_selector(self);
		if let Some(pos) = queue.iter().position(|item| item == request_id) {
			queue.remove(pos)
		} else {
			None
		}
	}

	fn is_empty(&self) -> bool {
		self.pending_set_webhook_requests.is_empty()
			&& self.pending_list_webhooks_requests.is_empty()
			&& self.pending_remove_webhook_requests.is_empty()
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
pub struct LSPS5ClientHandler<ES: Deref>
where
	ES::Target: EntropySource,
{
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
	entropy_source: ES,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	_config: LSPS5ClientConfig,
}

impl<ES: Deref> LSPS5ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	/// Constructs an `LSPS5ClientHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue>,
		_config: LSPS5ClientConfig,
	) -> Self {
		Self {
			pending_messages,
			pending_events,
			entropy_source,
			per_peer_state: RwLock::new(new_hash_map()),
			_config,
		}
	}

	fn with_peer_state<F, R>(&self, counterparty_node_id: PublicKey, f: F) -> R
	where
		F: FnOnce(&mut PeerState) -> R,
	{
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let inner_state_lock =
			outer_state_lock.entry(counterparty_node_id).or_insert(Mutex::new(PeerState::new()));
		let mut peer_state_lock = inner_state_lock.lock().unwrap();

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
		let mut message_queue_notifier = self.pending_messages.notifier();
		let app_name = LSPS5AppName::from_string(app_name)?;

		let lsps_webhook_url = LSPS5WebhookUrl::from_string(webhook_url)?;

		let request_id = generate_request_id(&self.entropy_source);

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.add_request(
				(request_id.clone(), (app_name.clone(), lsps_webhook_url.clone())),
				|s| &mut s.pending_set_webhook_requests,
			);
		});

		let request =
			LSPS5Request::SetWebhook(SetWebhookRequest { app_name, webhook: lsps_webhook_url });

		let message = LSPS5Message::Request(request_id.clone(), request);
		message_queue_notifier.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

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
		let mut message_queue_notifier = self.pending_messages.notifier();
		let request_id = generate_request_id(&self.entropy_source);

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.add_request(request_id.clone(), |s| &mut s.pending_list_webhooks_requests);
		});

		let request = LSPS5Request::ListWebhooks(ListWebhooksRequest {});
		let message = LSPS5Message::Request(request_id.clone(), request);
		message_queue_notifier.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

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
		let mut message_queue_notifier = self.pending_messages.notifier();
		let app_name = LSPS5AppName::from_string(app_name)?;

		let request_id = generate_request_id(&self.entropy_source);

		self.with_peer_state(counterparty_node_id, |peer_state| {
			peer_state.add_request((request_id.clone(), app_name.clone()), |s| {
				&mut s.pending_remove_webhook_requests
			});
		});

		let request = LSPS5Request::RemoveWebhook(RemoveWebhookRequest { app_name });
		let message = LSPS5Message::Request(request_id.clone(), request);
		message_queue_notifier.enqueue(&counterparty_node_id, LSPSMessage::LSPS5(message));

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
		let handle_response = |peer_state: &mut PeerState| {
			if let Some((_, (app_name, webhook_url))) = peer_state
				.find_and_remove_request(|s| &mut s.pending_set_webhook_requests, &request_id)
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
			} else if let Some(_) = peer_state
				.find_and_remove_request(|s| &mut s.pending_list_webhooks_requests, &request_id)
			{
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
			} else if let Some((_, app_name)) = peer_state
				.find_and_remove_request(|s| &mut s.pending_remove_webhook_requests, &request_id)
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

		self.check_and_remove_empty_peer_state(counterparty_node_id);

		result
	}

	fn check_and_remove_empty_peer_state(&self, counterparty_node_id: &PublicKey) {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		let should_remove =
			if let Some(peer_state_mutex) = outer_state_lock.get(counterparty_node_id) {
				let peer_state = peer_state_mutex.lock().unwrap();
				peer_state.is_empty()
			} else {
				false
			};

		if should_remove {
			outer_state_lock.remove(counterparty_node_id);
		}
	}
}

impl<ES: Deref> LSPSProtocolMessageHandler for LSPS5ClientHandler<ES>
where
	ES::Target: EntropySource,
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

	use super::*;
	use crate::{lsps0::ser::LSPSRequestId, lsps5::msgs::SetWebhookResponse};
	use bitcoin::{key::Secp256k1, secp256k1::SecretKey};
	use core::sync::atomic::{AtomicU64, Ordering};

	struct UniqueTestEntropy {
		counter: AtomicU64,
	}

	impl EntropySource for UniqueTestEntropy {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			let counter = self.counter.fetch_add(1, Ordering::SeqCst);
			let mut bytes = [0u8; 32];
			bytes[0..8].copy_from_slice(&counter.to_be_bytes());
			bytes
		}
	}

	fn setup_test_client() -> (
		LSPS5ClientHandler<Arc<UniqueTestEntropy>>,
		Arc<MessageQueue>,
		Arc<EventQueue>,
		PublicKey,
		PublicKey,
	) {
		let test_entropy_source = Arc::new(UniqueTestEntropy { counter: AtomicU64::new(2) });
		let message_queue = Arc::new(MessageQueue::new());
		let event_queue = Arc::new(EventQueue::new());
		let client = LSPS5ClientHandler::new(
			test_entropy_source,
			Arc::clone(&message_queue),
			Arc::clone(&event_queue),
			LSPS5ClientConfig::default(),
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
			assert!(peer_1_state
				.pending_set_webhook_requests
				.iter()
				.any(|(id, _)| id == &req_id_1));

			let peer_2_state = outer_state_lock.get(&peer_2).unwrap().lock().unwrap();
			assert!(peer_2_state
				.pending_set_webhook_requests
				.iter()
				.any(|(id, _)| id == &req_id_2));
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
			let set_request = peer_state
				.pending_set_webhook_requests
				.iter()
				.find(|(id, _)| id == &set_req_id)
				.unwrap();
			assert_eq!(&set_request.1, &(lsps5_app_name.clone(), lsps5_webhook_url));

			assert!(peer_state.pending_list_webhooks_requests.contains(&list_req_id));

			let remove_request = peer_state
				.pending_remove_webhook_requests
				.iter()
				.find(|(id, _)| id == &remove_req_id)
				.unwrap();
			assert_eq!(&remove_request.1, &lsps5_app_name);
		}
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

	#[test]
	fn test_pending_request_eviction() {
		let (client, _, _, peer, _) = setup_test_client();

		let mut request_ids = Vec::new();
		for i in 0..MAX_PENDING_REQUESTS {
			let req_id = client
				.set_webhook(peer, format!("app-{}", i), format!("https://example.com/hook{}", i))
				.unwrap();
			request_ids.push(req_id);
		}

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			for req_id in &request_ids {
				assert!(peer_state.pending_set_webhook_requests.iter().any(|(id, _)| id == req_id));
			}
			assert_eq!(peer_state.pending_set_webhook_requests.len(), MAX_PENDING_REQUESTS);
		}

		let new_req_id = client
			.set_webhook(peer, "app-new".to_string(), "https://example.com/hook-new".to_string())
			.unwrap();

		{
			let outer_state_lock = client.per_peer_state.read().unwrap();
			let peer_state = outer_state_lock.get(&peer).unwrap().lock().unwrap();
			assert_eq!(peer_state.pending_set_webhook_requests.len(), MAX_PENDING_REQUESTS);

			assert!(!peer_state
				.pending_set_webhook_requests
				.iter()
				.any(|(id, _)| id == &request_ids[0]));

			for req_id in &request_ids[1..] {
				assert!(peer_state.pending_set_webhook_requests.iter().any(|(id, _)| id == req_id));
			}

			assert!(peer_state
				.pending_set_webhook_requests
				.iter()
				.any(|(id, _)| id == &new_req_id));
		}
	}

	#[test]
	fn test_peer_state_cleanup_and_recreation() {
		let (client, _, _, peer, _) = setup_test_client();

		let set_webhook_req_id = client
			.set_webhook(peer, "test-app".to_string(), "https://example.com/hook".to_string())
			.unwrap();

		let list_webhooks_req_id = client.list_webhooks(peer);

		{
			let state = client.per_peer_state.read().unwrap();
			assert!(state.contains_key(&peer));
			let peer_state = state.get(&peer).unwrap().lock().unwrap();
			assert!(peer_state
				.pending_set_webhook_requests
				.iter()
				.any(|(id, _)| id == &set_webhook_req_id));
			assert!(peer_state.pending_list_webhooks_requests.contains(&list_webhooks_req_id));
		}

		let set_webhook_response = LSPS5Response::SetWebhook(SetWebhookResponse {
			num_webhooks: 1,
			max_webhooks: 5,
			no_change: false,
		});
		let response_msg = LSPS5Message::Response(set_webhook_req_id.clone(), set_webhook_response);
		// trigger cleanup but there is still a pending request
		// so the peer state should not be removed
		client.handle_message(response_msg, &peer).unwrap();

		{
			let state = client.per_peer_state.read().unwrap();
			assert!(state.contains_key(&peer));
			let peer_state = state.get(&peer).unwrap().lock().unwrap();
			assert!(!peer_state
				.pending_set_webhook_requests
				.iter()
				.any(|(id, _)| id == &set_webhook_req_id));
			assert!(peer_state.pending_list_webhooks_requests.contains(&list_webhooks_req_id));
		}

		let list_webhooks_response =
			LSPS5Response::ListWebhooks(crate::lsps5::msgs::ListWebhooksResponse {
				app_names: vec![],
				max_webhooks: 5,
			});
		let response_msg = LSPS5Message::Response(list_webhooks_req_id, list_webhooks_response);

		// now the pending request is handled, so the peer state should be removed
		client.handle_message(response_msg, &peer).unwrap();

		{
			let state = client.per_peer_state.read().unwrap();
			assert!(!state.contains_key(&peer));
		}

		// check that it's possible to recreate the peer state by sending a new request
		let new_req_id = client
			.set_webhook(peer, "test-app-2".to_string(), "https://example.com/hook2".to_string())
			.unwrap();

		{
			let state = client.per_peer_state.read().unwrap();
			assert!(state.contains_key(&peer));
			let peer_state = state.get(&peer).unwrap().lock().unwrap();
			assert!(peer_state
				.pending_set_webhook_requests
				.iter()
				.any(|(id, _)| id == &new_req_id));
		}
	}
}
