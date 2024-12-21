// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the main LSPS5 server-side object, [`LSPS5ServiceHandler`].

use crate::lsps0::ser::{LSPSMessage, ProtocolMessageHandler, RequestId, ResponseError};
use crate::message_queue::MessageQueue;
use crate::prelude::{String, ToString, Vec};
use crate::sync::Arc;

use lightning::io::ErrorKind;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;

use bitcoin::secp256k1::PublicKey;
use lightning::util::persist::KVStore;

use core::ops::Deref;
use url::Url;

use crate::lsps5::msgs::{
	LSPS5Message, LSPS5Request, LSPS5Response, ListWebhooksRequest, ListWebhooksResponse,
	RemoveWebhookRequest, RemoveWebhookResponse, SetWebhookRequest, SetWebhookResponse,
	LSPS5_REMOVE_WEBHOOK_REQUEST_APP_NAME_NOT_FOUND_ERROR_CODE,
	LSPS5_SET_WEBHOOK_REQUEST_TOO_LONG_ERROR_CODE,
	LSPS5_SET_WEBHOOK_REQUEST_TOO_MANY_WEBHOOKS_ERROR_CODE,
	LSPS5_SET_WEBHOOK_REQUEST_UNSUPPORTED_PROTOCOL_ERROR_CODE,
};

use super::notifications::{
	ExpirySoonParams, FeesChangeIncomingDirection, FeesChangeIncomingParams, LSPS5Notification,
	LiquidityManagementRequestParams, OnionMessageIncomingParams, PaymentIncomingParams,
	WebhookRegisteredParams,
};

const WEBHOOK_PRIMARY_NAMESPACE: &str = "webhooks";

/// Server-side configuration options for webhook notifications.
#[derive(Clone)]
pub struct LSPS5ServiceConfig {
	/// The maximum number of webhooks that can be registered.
	pub max_webhooks: u32,
	/// The list of protocols in addition to 'https' that are supported.
	pub supported_protocols: Vec<String>,
}

impl LSPS5ServiceConfig {
	/// Create a new LSPS5ServiceConfig with the given maximum number of webhooks per client
	/// and an optional list of protocols in addition to 'https' that are supported.
	pub fn new(max_webhooks: u32, extra_protocols: Option<Vec<String>>) -> Self {
		let mut supported_protocols = vec!["https".to_string()];

		if let Some(extra_protocols) = extra_protocols {
			for extra_protocol in extra_protocols.into_iter() {
				if !supported_protocols.contains(&extra_protocol) {
					supported_protocols.push(extra_protocol);
				}
			}
		}

		Self { max_webhooks, supported_protocols }
	}
}

/// The main object allowing to send and receive LSPS5 messages.
pub struct LSPS5ServiceHandler<KV: Deref>
where
	KV::Target: KVStore,
{
	pending_messages: Arc<MessageQueue>,
	kv_store: KV,
	config: LSPS5ServiceConfig,
}

impl<KV: Deref> LSPS5ServiceHandler<KV>
where
	KV::Target: KVStore,
{
	/// Constructs a `LSPS5ServiceHandler`.
	pub(crate) fn new(
		kv_store: KV, pending_messages: Arc<MessageQueue>, config: LSPS5ServiceConfig,
	) -> Self {
		Self { kv_store, pending_messages, config }
	}

	fn send_webhook(&self, webhook_url: String, msg: LSPSMessage) -> Result<(), LightningError> {
		let _response =
			minreq::post(webhook_url).with_json(&msg).expect("json serialization").send().map_err(
				|e| LightningError {
					err: format!("failed to send webhook: {}", e.to_string()),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				},
			)?;
		Ok(())
	}

	fn send_webhook_registered_notification(
		&self, webhook_url: String,
	) -> Result<(), LightningError> {
		let msg = LSPSMessage::LSPS5(LSPS5Message::Notification(
			LSPS5Notification::WebhookRegistered(WebhookRegisteredParams {}),
		));
		self.send_webhook(webhook_url, msg)
	}

	fn send_webhook_to_counterparty(
		&self, counterparty_node_id: &PublicKey, msg: LSPSMessage,
	) -> Result<(), LightningError> {
		let registered_app_names = self
			.kv_store
			.list(WEBHOOK_PRIMARY_NAMESPACE, &counterparty_node_id.to_string())
			.map_err(|e| LightningError {
				err: format!("failed to list webhooks: {}", e.to_string()),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})?;

		for app_name in registered_app_names.into_iter() {
			let webhook_bytes = self
				.kv_store
				.read(WEBHOOK_PRIMARY_NAMESPACE, &counterparty_node_id.to_string(), &app_name)
				.map_err(|e| LightningError {
					err: format!("failed to read webhook: {}", e.to_string()),
					action: ErrorAction::IgnoreAndLog(Level::Error),
				})?;

			let webhook = String::from_utf8(webhook_bytes).map_err(|e| LightningError {
				err: format!("webhook is not a valid utf8 string: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			})?;

			let _ = self.send_webhook(webhook, msg.clone())?;
		}

		Ok(())
	}

	/// Send payment incoming notifications to all registered webhooks
	/// for this counterparty.
	pub fn send_payment_incoming_notification(
		&self, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let msg = LSPSMessage::LSPS5(LSPS5Message::Notification(
			LSPS5Notification::PaymentIncoming(PaymentIncomingParams {}),
		));
		self.send_webhook_to_counterparty(counterparty_node_id, msg)
	}

	/// Send the expiry soon notification to this counterparty to avoid channel closure.
	/// Timeout is the blockheight at which the LSP would be forced to close the channel
	/// in order to enforce the HTLC or other time-bound contract.
	pub fn send_expiry_soon_notification(
		&self, counterparty_node_id: &PublicKey, timeout: u32,
	) -> Result<(), LightningError> {
		let msg = LSPSMessage::LSPS5(LSPS5Message::Notification(LSPS5Notification::ExpirySoon(
			ExpirySoonParams { timeout },
		)));
		self.send_webhook_to_counterparty(counterparty_node_id, msg)
	}

	/// Send liquidity management request notifications to all registered webhooks
	/// for this counterparty.
	pub fn send_liquidity_management_request_notification(
		&self, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let msg = LSPSMessage::LSPS5(LSPS5Message::Notification(
			LSPS5Notification::LiquidityManagementRequest(LiquidityManagementRequestParams {}),
		));
		self.send_webhook_to_counterparty(counterparty_node_id, msg)
	}

	/// Send fees change incoming notifications to all registered webhooks
	/// for this counterparty.
	pub fn send_fees_change_incoming_notification(
		&self, counterparty_node_id: &PublicKey, direction: FeesChangeIncomingDirection,
	) -> Result<(), LightningError> {
		let msg = LSPSMessage::LSPS5(LSPS5Message::Notification(
			LSPS5Notification::FeesChangeIncoming(FeesChangeIncomingParams { direction }),
		));
		self.send_webhook_to_counterparty(counterparty_node_id, msg)
	}

	/// Send onion message incoming notifications to all registered webhooks
	/// for this counterparty.
	pub fn send_onion_message_incoming_notification(
		&self, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let msg = LSPSMessage::LSPS5(LSPS5Message::Notification(
			LSPS5Notification::OnionMessageIncoming(OnionMessageIncomingParams {}),
		));
		self.send_webhook_to_counterparty(counterparty_node_id, msg)
	}

	fn respond_with_error(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, code: i32, message: &str,
	) {
		let response = LSPS5Response::SetWebhookError(ResponseError {
			code,
			message: message.to_string(),
			data: None,
		});

		let msg = LSPS5Message::Response(request_id, response).into();
		self.pending_messages.enqueue(counterparty_node_id, msg);
	}

	fn handle_set_webhook_request(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey, params: SetWebhookRequest,
	) -> Result<(), LightningError> {
		if params.app_name.as_bytes().len() > 64 {
			self.respond_with_error(
				request_id.clone(),
				counterparty_node_id,
				LSPS5_SET_WEBHOOK_REQUEST_TOO_LONG_ERROR_CODE,
				"app_name must be less than 64 bytes",
			);
			return Err(LightningError {
				err: "app_name must be les than 64 bytes".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		if params.webhook.to_ascii_lowercase().len() > 1024 {
			self.respond_with_error(
				request_id,
				counterparty_node_id,
				LSPS5_SET_WEBHOOK_REQUEST_TOO_LONG_ERROR_CODE,
				"webhook must be less than 1024 ascii characters",
			);
			return Err(LightningError {
				err: "webhook must be less than 1024 ascii characters".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		let webhook_url = Url::parse(&params.webhook).map_err(|e| {
			self.respond_with_error(
				request_id.clone(),
				counterparty_node_id,
				LSPS5_SET_WEBHOOK_REQUEST_UNSUPPORTED_PROTOCOL_ERROR_CODE,
				&format!("webhook is not a valid url: {}", e),
			);
			LightningError {
				err: format!("webhook is not a valid url: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			}
		})?;

		if !self.config.supported_protocols.contains(&webhook_url.scheme().to_string()) {
			self.respond_with_error(
				request_id,
				counterparty_node_id,
				LSPS5_SET_WEBHOOK_REQUEST_UNSUPPORTED_PROTOCOL_ERROR_CODE,
				"webhook protocol is not supported",
			);
			return Err(LightningError {
				err: "webhook protocol is not supported".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		let existing_webhook = match self.kv_store.read(
			WEBHOOK_PRIMARY_NAMESPACE,
			&counterparty_node_id.to_string(),
			&params.app_name,
		) {
			Ok(webhook_bytes) => {
				Some(String::from_utf8(webhook_bytes).map_err(|e| LightningError {
					err: format!("webhook is not a valid utf8 string: {}", e),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})?)
			},
			Err(e) => {
				if e.kind() == ErrorKind::NotFound {
					None
				} else {
					return Err(LightningError {
						err: format!("failed to read existing webhook: {}", e),
						action: ErrorAction::IgnoreAndLog(Level::Info),
					});
				}
			},
		};

		let existing_webhooks = self
			.kv_store
			.list(WEBHOOK_PRIMARY_NAMESPACE, &counterparty_node_id.to_string())
			.map_err(|e| LightningError {
				err: format!("failed to list existing webhooks: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			})?;

		let (no_change, num_webhooks) = match existing_webhook {
			Some(existing_webhook) => {
				(existing_webhook == params.webhook, existing_webhooks.len() as u32)
			},
			None => (false, (existing_webhooks.len() + 1) as u32),
		};

		if num_webhooks > self.config.max_webhooks {
			self.respond_with_error(
				request_id,
				counterparty_node_id,
				LSPS5_SET_WEBHOOK_REQUEST_TOO_MANY_WEBHOOKS_ERROR_CODE,
				"too many webhooks",
			);
			return Err(LightningError {
				err: "too many webhooks".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		if !no_change {
			let _ = self
				.kv_store
				.write(
					WEBHOOK_PRIMARY_NAMESPACE,
					&counterparty_node_id.to_string(),
					&params.app_name,
					params.webhook.as_bytes(),
				)
				.map_err(|e| LightningError {
					err: format!("failed to write webhook: {}", e),
					action: ErrorAction::IgnoreAndLog(Level::Info),
				})?;

			self.send_webhook_registered_notification(params.webhook)?;
		}

		let response = LSPS5Response::SetWebhook(SetWebhookResponse {
			num_webhooks,
			max_webhooks: self.config.max_webhooks,
			no_change,
		});
		let msg = LSPS5Message::Response(request_id, response).into();
		self.pending_messages.enqueue(counterparty_node_id, msg);
		Ok(())
	}

	fn handle_list_webhooks_request(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey,
		_params: ListWebhooksRequest,
	) -> Result<(), LightningError> {
		let app_names = self
			.kv_store
			.list(WEBHOOK_PRIMARY_NAMESPACE, &counterparty_node_id.to_string())
			.map_err(|e| LightningError {
				err: format!("failed to list webhooks: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			})?;
		let response = LSPS5Response::ListWebhooks(ListWebhooksResponse {
			app_names,
			max_webhooks: self.config.max_webhooks,
		});
		let msg = LSPS5Message::Response(request_id, response).into();
		self.pending_messages.enqueue(counterparty_node_id, msg);
		Ok(())
	}

	fn handle_remove_webhook_request(
		&self, request_id: RequestId, counterparty_node_id: &PublicKey,
		params: RemoveWebhookRequest,
	) -> Result<(), LightningError> {
		let app_names = self
			.kv_store
			.list(WEBHOOK_PRIMARY_NAMESPACE, &counterparty_node_id.to_string())
			.map_err(|e| LightningError {
				err: format!("failed to list webhooks: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			})?;

		if !app_names.contains(&params.app_name) {
			self.respond_with_error(
				request_id,
				counterparty_node_id,
				LSPS5_REMOVE_WEBHOOK_REQUEST_APP_NAME_NOT_FOUND_ERROR_CODE,
				"app_name not found",
			);
			return Err(LightningError {
				err: format!("webhook app name not found: {}", params.app_name),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		let _ = self
			.kv_store
			.remove(
				WEBHOOK_PRIMARY_NAMESPACE,
				&counterparty_node_id.to_string(),
				&params.app_name,
				false,
			)
			.map_err(|e| LightningError {
				err: format!("failed to remove webhook: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Info),
			})?;

		let response = LSPS5Response::RemoveWebhook(RemoveWebhookResponse {});
		let msg = LSPS5Message::Response(request_id, response).into();
		self.pending_messages.enqueue(counterparty_node_id, msg);
		Ok(())
	}
}

impl<KV: Deref> ProtocolMessageHandler for LSPS5ServiceHandler<KV>
where
	KV::Target: KVStore,
{
	type ProtocolMessage = LSPS5Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(5);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS5Message::Request(request_id, request) => match request {
				LSPS5Request::SetWebhook(params) => {
					self.handle_set_webhook_request(request_id, counterparty_node_id, params)
				},
				LSPS5Request::ListWebhooks(params) => {
					self.handle_list_webhooks_request(request_id, counterparty_node_id, params)
				},
				LSPS5Request::RemoveWebhook(params) => {
					self.handle_remove_webhook_request(request_id, counterparty_node_id, params)
				},
			},
			_ => {
				debug_assert!(
					false,
					"Service handler received LSPS5 response message. This should never happen."
				);
				Err(LightningError { err: format!("Service handler received LSPS5 response message from node {:?}. This should never happen.", counterparty_node_id), action: ErrorAction::IgnoreAndLog(Level::Info)})
			},
		}
	}
}

#[cfg(test)]
mod tests {}
