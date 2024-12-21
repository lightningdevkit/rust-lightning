// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main LSPS5 client object, [`LSPS5ClientHandler`].

use crate::events::{Event, EventQueue};
use crate::lsps0::ser::{ProtocolMessageHandler, RequestId, ResponseError};
use crate::message_queue::MessageQueue;
use crate::prelude::{new_hash_map, new_hash_set, HashMap, HashSet, String};
use crate::sync::{Arc, Mutex, RwLock};

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;

use bitcoin::secp256k1::PublicKey;

use core::default::Default;
use core::ops::Deref;

use crate::lsps5::msgs::{
	LSPS5Message, LSPS5Request, LSPS5Response, ListWebhooksRequest, ListWebhooksResponse,
	RemoveWebhookRequest, RemoveWebhookResponse, SetWebhookRequest, SetWebhookResponse,
};

use super::event::LSPS5ClientEvent;

/// Client-side configuration options for webhook notifications.
#[derive(Clone, Debug, Copy)]
pub struct LSPS5ClientConfig {}

impl Default for LSPS5ClientConfig {
	fn default() -> Self {
		Self {}
	}
}

struct PeerState {
	pending_set_webhook_requests: HashSet<RequestId>,
	pending_list_webhooks_requests: HashSet<RequestId>,
	pending_remove_webhook_requests: HashSet<RequestId>,
}

impl PeerState {
	fn new() -> Self {
		let pending_set_webhook_requests = new_hash_set();
		let pending_list_webhooks_requests = new_hash_set();
		let pending_remove_webhook_requests = new_hash_set();
		Self {
			pending_set_webhook_requests,
			pending_list_webhooks_requests,
			pending_remove_webhook_requests,
		}
	}
}

/// The main object allowing to send and receive LSPS5 messages.
pub struct LSPS5ClientHandler<ES: Deref>
where
	ES::Target: EntropySource,
{
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue>,
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
			entropy_source,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
			_config,
		}
	}

	/// Register a webhook for an app with the LSP.
	///
	/// The user will receive the LSP's response via an [`WebhookSet`] event.
	///
	/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
	///
	/// `app_name` is a `String` that identifies the app this webhook is for.
	///
	/// Returns the used [`RequestId`], which will be returned via [`WebhookSet`].
	///
	/// [`WebhookSet`]: crate::lsps5::event::LSPS5ClientEvent::WebhookSet
	pub fn set_webhook(
		&self, counterparty_node_id: PublicKey, app_name: String, webhook: String,
	) -> RequestId {
		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_set_webhook_requests.insert(request_id.clone());
		}

		let request = LSPS5Request::SetWebhook(SetWebhookRequest { app_name, webhook });
		let msg = LSPS5Message::Request(request_id.clone(), request).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		request_id
	}

	fn handle_set_webhook_response(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, result: SetWebhookResponse,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_set_webhook_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received set_webhook response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}

				self.pending_events.enqueue(Event::LSPS5Client(LSPS5ClientEvent::WebhookSet {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					num_webhooks: result.num_webhooks,
					max_webhooks: result.max_webhooks,
					no_change: result.no_change,
				}));
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received set_webhook response from unknown peer: {:?}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})
			},
		}

		Ok(())
	}

	fn handle_set_webhook_error(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, _error: ResponseError,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_set_webhook_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received set_webhook error for an unknown request: {:?}",
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

	/// List all webhooks registered with the LSP.
	///
	/// The user will receive the LSP's response via an [`ListWebhooks`] event.
	///
	/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
	///	///
	/// Returns the used [`RequestId`], which will be returned via [`ListWebhooks`].
	///
	/// [`ListWebhooks`]: crate::lsps5::event::LSPS5ClientEvent::ListWebhooks
	pub fn list_webhooks(&self, counterparty_node_id: PublicKey) -> RequestId {
		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_list_webhooks_requests.insert(request_id.clone());
		}

		let request = LSPS5Request::ListWebhooks(ListWebhooksRequest {});
		let msg = LSPS5Message::Request(request_id.clone(), request).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		request_id
	}

	fn handle_list_webhooks_response(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey,
		result: ListWebhooksResponse,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_list_webhooks_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received list_webhooks response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}

				self.pending_events.enqueue(Event::LSPS5Client(LSPS5ClientEvent::ListWebhooks {
					request_id,
					counterparty_node_id: *counterparty_node_id,
					app_names: result.app_names.clone(),
					max_webhooks: result.max_webhooks,
				}));
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received list_webhooks response from unknown peer: {:?}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				});
			},
		}
		Ok(())
	}

	/// Remove a webhook from the LSP.
	///
	/// The user will receive the LSP's response via an [`WebhookRemoved`] event.
	///
	/// `counterparty_node_id` is the `node_id` of the LSP you would like to use.
	///
	/// `app_name` is a `String` that identifies the app this webhook is for.
	///
	/// Returns the used [`RequestId`], which will be returned via [`WebhookRemoved`].
	///
	/// [`WebhookRemoved`]: crate::lsps5::event::LSPS5ClientEvent::WebhookRemoved
	pub fn remove_webhook(&self, counterparty_node_id: PublicKey, app_name: String) -> RequestId {
		let request_id = crate::utils::generate_request_id(&self.entropy_source);

		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::new()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_remove_webhook_requests.insert(request_id.clone());
		}

		let request = LSPS5Request::RemoveWebhook(RemoveWebhookRequest { app_name });
		let msg = LSPS5Message::Request(request_id.clone(), request).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		request_id
	}

	fn handle_remove_webhook_response(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey,
		_result: RemoveWebhookResponse,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_remove_webhook_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received remove_webhook response for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}

				self.pending_events.enqueue(Event::LSPS5Client(LSPS5ClientEvent::WebhookRemoved {
					request_id,
					counterparty_node_id: *counterparty_node_id,
				}));
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received remove_webhook response from unknown peer: {:?}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})
			},
		}

		Ok(())
	}

	fn handle_remove_webhook_error(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, _error: ResponseError,
	) -> Result<(), LightningError> {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state = inner_state_lock.lock().unwrap();

				if !peer_state.pending_remove_webhook_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received remove_webhook error for an unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}

				Ok(())
			},
			None => {
				return Err(LightningError { err: format!("Received error response for a remove_webhook request from an unknown counterparty ({:?})",counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)});
			},
		}
	}
}

impl<ES: Deref> ProtocolMessageHandler for LSPS5ClientHandler<ES>
where
	ES::Target: EntropySource,
{
	type ProtocolMessage = LSPS5Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(2);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS5Message::Response(request_id, response) => match response {
				LSPS5Response::SetWebhook(result) => {
					self.handle_set_webhook_response(request_id, counterparty_node_id, result)
				},
				LSPS5Response::SetWebhookError(error) => {
					self.handle_set_webhook_error(request_id, counterparty_node_id, error)
				},
				LSPS5Response::ListWebhooks(result) => {
					self.handle_list_webhooks_response(request_id, counterparty_node_id, result)
				},
				LSPS5Response::RemoveWebhook(result) => {
					self.handle_remove_webhook_response(request_id, counterparty_node_id, result)
				},
				LSPS5Response::RemoveWebhookError(error) => {
					self.handle_remove_webhook_error(request_id, counterparty_node_id, error)
				},
			},
			_ => {
				debug_assert!(
					false,
					"Client handler received LSPS5 request message. This should never happen."
				);
				Err(LightningError { err: format!("Client handler received LSPS5 request message from node {:?}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
			},
		}
	}
}

#[cfg(test)]
mod tests {}
