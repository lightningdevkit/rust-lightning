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
use super::service::TimeProvider;

use crate::alloc::string::ToString;
use crate::lsps0::ser::LSPSDateTime;
use crate::lsps5::msgs::WebhookNotification;
use crate::sync::Mutex;

use lightning::util::message_signing;

use bitcoin::secp256k1::PublicKey;

use alloc::collections::VecDeque;
use alloc::string::String;

use core::ops::Deref;
use core::time::Duration;

/// Configuration for signature storage.
#[derive(Clone, Copy, Debug)]
pub struct SignatureStorageConfig {
	/// Maximum number of signatures to store.
	pub max_signatures: usize,
	/// Retention time for signatures in minutes.
	pub retention_minutes: Duration,
}

/// Default retention time for signatures in minutes (LSPS5 spec requires min 20 minutes).
pub const DEFAULT_SIGNATURE_RETENTION_MINUTES: u64 = 20;

/// Default maximum number of stored signatures.
pub const DEFAULT_MAX_SIGNATURES: usize = 1000;

impl Default for SignatureStorageConfig {
	fn default() -> Self {
		Self {
			max_signatures: DEFAULT_MAX_SIGNATURES,
			retention_minutes: Duration::from_secs(DEFAULT_SIGNATURE_RETENTION_MINUTES * 60),
		}
	}
}

/// A utility for validating webhook notifications from an LSP.
///
/// In a typical setup, a proxy server receives webhook notifications from the LSP
/// and then forwards them to the client (e.g., via mobile push notifications).
/// This validator should be used by the proxy to verify the authenticity and
/// integrity of the notification before processing or forwarding it.
///
/// # Core Capabilities
///
///  - `validate(...)` -> Verifies signature, timestamp, and protects against replay attacks.
///
/// # Usage
///
/// The validator requires a `SignatureStore` to track recently seen signatures
/// to prevent replay attacks. You should create a single `LSPS5Validator` instance
/// and share it across all requests.
///
/// [`bLIP-55 / LSPS5 specification`]: https://github.com/lightning/blips/pull/55/files
pub struct LSPS5Validator<TP: Deref, SS: Deref>
where
	TP::Target: TimeProvider,
	SS::Target: SignatureStore,
{
	time_provider: TP,
	signature_store: SS,
}

impl<TP: Deref, SS: Deref> LSPS5Validator<TP, SS>
where
	TP::Target: TimeProvider,
	SS::Target: SignatureStore,
{
	/// Creates a new `LSPS5Validator`.
	pub fn new(time_provider: TP, signature_store: SS) -> Self {
		Self { time_provider, signature_store }
	}

	fn verify_notification_signature(
		&self, counterparty_node_id: PublicKey, signature_timestamp: &LSPSDateTime,
		signature: &str, notification: &WebhookNotification,
	) -> Result<(), LSPS5ClientError> {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let diff = signature_timestamp.abs_diff(&now);
		const MAX_TIMESTAMP_DRIFT_SECS: u64 = 600;
		if diff > MAX_TIMESTAMP_DRIFT_SECS {
			return Err(LSPS5ClientError::InvalidTimestamp);
		}

		let notification_json = serde_json::to_string(notification)
			.map_err(|_| LSPS5ClientError::SerializationError)?;
		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
			signature_timestamp.to_rfc3339(),
			notification_json
		);

		if message_signing::verify(message.as_bytes(), signature, &counterparty_node_id) {
			Ok(())
		} else {
			Err(LSPS5ClientError::InvalidSignature)
		}
	}

	/// Parse and validate a webhook notification received from an LSP.
	///
	/// Verifies the webhook delivery by checking the timestamp is within ±10 minutes,
	/// ensuring no signature replay within the retention window, and verifying the
	/// zbase32 LN-style signature against the LSP's node ID.
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
	/// Returns the validated [`WebhookNotification`] or an error for invalid timestamp,
	/// replay attack, or signature verification failure.
	///
	/// [`WebhookNotification`]: super::msgs::WebhookNotification
	pub fn validate(
		&self, counterparty_node_id: PublicKey, timestamp: &LSPSDateTime, signature: &str,
		notification: &WebhookNotification,
	) -> Result<WebhookNotification, LSPS5ClientError> {
		self.verify_notification_signature(
			counterparty_node_id,
			timestamp,
			signature,
			notification,
		)?;

		if self.signature_store.exists(signature)? {
			return Err(LSPS5ClientError::ReplayAttack);
		}

		self.signature_store.store(signature)?;

		Ok(notification.clone())
	}
}

/// Trait for storing and checking webhook notification signatures to prevent replay attacks.
pub trait SignatureStore {
	/// Checks if a signature already exists in the store.
	fn exists(&self, signature: &str) -> Result<bool, LSPS5ClientError>;
	/// Stores a new signature.
	fn store(&self, signature: &str) -> Result<(), LSPS5ClientError>;
}

/// An in-memory store for webhook notification signatures.
pub struct InMemorySignatureStore<TP: Deref>
where
	TP::Target: TimeProvider,
{
	recent_signatures: Mutex<VecDeque<(String, LSPSDateTime)>>,
	config: SignatureStorageConfig,
	time_provider: TP,
}

impl<TP: Deref> InMemorySignatureStore<TP>
where
	TP::Target: TimeProvider,
{
	/// Creates a new `InMemorySignatureStore`.
	pub fn new(config: SignatureStorageConfig, time_provider: TP) -> Self {
		Self {
			recent_signatures: Mutex::new(VecDeque::with_capacity(config.max_signatures)),
			config,
			time_provider,
		}
	}
}

impl<TP: Deref> SignatureStore for InMemorySignatureStore<TP>
where
	TP::Target: TimeProvider,
{
	fn exists(&self, signature: &str) -> Result<bool, LSPS5ClientError> {
		let recent_signatures = self.recent_signatures.lock().unwrap();
		for (stored_sig, _) in recent_signatures.iter() {
			if stored_sig == signature {
				return Ok(true);
			}
		}
		Ok(false)
	}

	fn store(&self, signature: &str) -> Result<(), LSPS5ClientError> {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let mut recent_signatures = self.recent_signatures.lock().unwrap();

		recent_signatures.push_back((signature.to_string(), now.clone()));

		let retention_secs = self.config.retention_minutes.as_secs();
		recent_signatures.retain(|(_, ts)| now.abs_diff(ts) <= retention_secs);

		if recent_signatures.len() > self.config.max_signatures {
			let excess = recent_signatures.len() - self.config.max_signatures;
			recent_signatures.drain(0..excess);
		}
		Ok(())
	}
}
