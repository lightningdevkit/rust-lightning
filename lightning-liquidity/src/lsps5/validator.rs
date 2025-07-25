// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LSPS5 Validator

use super::msgs::LSPS5ClientError;

use crate::alloc::string::ToString;
use crate::lsps0::ser::LSPSDateTime;
use crate::lsps5::msgs::WebhookNotification;
use crate::sync::Mutex;

use lightning::util::message_signing;

use bitcoin::secp256k1::PublicKey;

use alloc::collections::VecDeque;
use alloc::string::String;

/// Maximum number of recent signatures to track for replay attack prevention.
pub const MAX_RECENT_SIGNATURES: usize = 5;

/// A utility for validating webhook notifications from an LSP.
///
/// In a typical setup, a proxy server receives webhook notifications from the LSP
/// and then forwards them to the client (e.g., via mobile push notifications).
/// This validator should be used by the proxy to verify the authenticity and
/// integrity of the notification before processing or forwarding it.
///
/// # Core Capabilities
///
///  - `validate(...)` -> Verifies signature, and protects against replay attacks.
///
/// The validator stores a [`small number`] of the most recently seen signatures
/// to protect against replays of the same notification.
///
/// [`small number`]: MAX_RECENT_SIGNATURES
/// [`bLIP-55 / LSPS5 specification`]: https://github.com/lightning/blips/pull/55/files
pub struct LSPS5Validator {
	recent_signatures: Mutex<VecDeque<String>>,
}

impl LSPS5Validator {
	/// Create a new LSPS5Validator instance.
	pub fn new() -> Self {
		Self { recent_signatures: Mutex::new(VecDeque::with_capacity(MAX_RECENT_SIGNATURES)) }
	}

	/// Parse and validate a webhook notification received from an LSP.
	///
	/// Verifies the webhook delivery by verifying the zbase32 LN-style signature against the LSP's node ID and ensuring that the signature is not a replay of a previously seen notification (within the last [`MAX_RECENT_SIGNATURES`] notifications).
	///
	/// Call this method on your proxy/server before processing any webhook notification
	/// to ensure its authenticity.
	///
	/// # Parameters
	/// - `counterparty_node_id`: The LSP's public key, used to verify the signature.
	/// - `timestamp`: ISO8601 time when the LSP created the notification.
	/// - `signature`: The zbase32-encoded LN signature over timestamp+body.
	/// - `notification`: The [`WebhookNotification`] received from the LSP.
	///
	/// Returns the validated [`WebhookNotification`] or an error for signature verification failure or replay attack.
	///
	/// [`WebhookNotification`]: super::msgs::WebhookNotification
	/// [`MAX_RECENT_SIGNATURES`]: MAX_RECENT_SIGNATURES
	pub fn validate(
		&self, counterparty_node_id: PublicKey, timestamp: &LSPSDateTime, signature: &str,
		notification: &WebhookNotification,
	) -> Result<WebhookNotification, LSPS5ClientError> {
		let notification_json = serde_json::to_string(notification)
			.map_err(|_| LSPS5ClientError::SerializationError)?;
		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
			timestamp.to_rfc3339(),
			notification_json
		);

		if !message_signing::verify(message.as_bytes(), signature, &counterparty_node_id) {
			return Err(LSPS5ClientError::InvalidSignature);
		}

		self.check_for_replay_attack(signature)?;

		Ok(notification.clone())
	}

	fn check_for_replay_attack(&self, signature: &str) -> Result<(), LSPS5ClientError> {
		let mut signatures = self.recent_signatures.lock().unwrap();
		if signatures.contains(&signature.to_string()) {
			return Err(LSPS5ClientError::ReplayAttack);
		}
		if signatures.len() == MAX_RECENT_SIGNATURES {
			signatures.pop_back();
		}
		signatures.push_front(signature.to_string());
		Ok(())
	}
}
