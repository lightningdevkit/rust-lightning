// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for LSPS5 webhook notifications

use crate::prelude::String;
use crate::prelude::Vec;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;

/// Sign a webhook notification with an LSP's signing key
///
/// This function takes a notification body and timestamp and returns a signature
/// in the format required by the LSPS5 specification.
///
/// # Arguments
///
/// * `body` - The serialized notification JSON
/// * `timestamp` - The ISO8601 timestamp string
/// * `signing_key` - The LSP private key used for signing
///
/// # Returns
///
/// * The signature in "lspsig:{hex}" format, or an error if signing fails
pub fn sign_notification(
	body: &str, timestamp: &str, signing_key: &SecretKey,
) -> Result<String, LightningError> {
	// Create the message to sign
	// According to spec:
	// The message to be signed is: "LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At ${timestamp} I notify ${body}"
	let message = format!(
		"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
		timestamp, body
	);

	// Hash the message
	let message_hash = sha256::Hash::hash(message.as_bytes());

	// Sign the message
	let secp = Secp256k1::new();
	let message_to_sign = bitcoin::secp256k1::Message::from_digest_slice(message_hash.as_ref())
		.map_err(|e| LightningError {
			err: format!("Failed to create message from digest: {}", e),
			action: ErrorAction::IgnoreAndLog(Level::Error),
		})?;

	let signature = secp.sign_ecdsa_recoverable(&message_to_sign, signing_key);

	// Convert signature to lspsig format
	let (recovery_id, signature_bytes) = signature.serialize_compact();
	let mut signature_with_recovery_id = Vec::with_capacity(65);
	signature_with_recovery_id.push(recovery_id.to_i32() as u8);
	signature_with_recovery_id.extend_from_slice(&signature_bytes);

	Ok(format!("lspsig:{}", signature_with_recovery_id.to_lower_hex_string()))
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::{hex::FromHex, secp256k1::Secp256k1};

	#[test]
	fn test_sign_notification() {
		let signing_key = SecretKey::from_slice(&[1; 32]).unwrap();
		let body = r#"{"jsonrpc":"2.0","method":"lsps5.webhook_registered","params":{}}"#;
		let timestamp = "2023-01-01T12:00:00.000Z";

		let signature = sign_notification(body, timestamp, &signing_key).unwrap();

		// Verify signature has the correct format
		assert!(signature.starts_with("lspsig:"));
		assert_eq!(signature.len(), 7 + 130); // "lspsig:" + 65 bytes as hex (130 chars)

		// Verify the signature is correct
		let secp = Secp256k1::new();
		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
			timestamp, body
		);
		let message_hash = sha256::Hash::hash(message.as_bytes());
		let message_to_verify =
			bitcoin::secp256k1::Message::from_digest_slice(message_hash.as_ref()).unwrap();

		let signature_data = &signature[7..]; // Remove "lspsig:" prefix
		let signature_bytes = Vec::from_hex(signature_data).unwrap();

		let recovery_id =
			bitcoin::secp256k1::ecdsa::RecoveryId::from_i32(signature_bytes[0] as i32).unwrap();
		let mut sig_data = [0u8; 64];
		sig_data.copy_from_slice(&signature_bytes[1..65]);

		let recoverable_sig =
			bitcoin::secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_data, recovery_id)
				.unwrap();

		let pubkey = secp.recover_ecdsa(&message_to_verify, &recoverable_sig).unwrap();
		let expected_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &signing_key);

		assert_eq!(pubkey, expected_pubkey);
	}
}
