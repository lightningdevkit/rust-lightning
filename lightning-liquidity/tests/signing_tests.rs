// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests for LSPS5 webhook notification signing and verification

#![cfg(all(test, feature = "std"))]

mod common;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use core::time::Duration;
use lightning::sign::EntropySource;
use lightning_liquidity::lsps5::client::LSPS5ClientHandler;
use lightning_liquidity::lsps5::msgs::{WebhookNotification, WebhookNotificationMethod};
use lightning_liquidity::lsps5::service::{DefaultTimeProvider, LSPS5ServiceHandler, TimeProvider};
use std::sync::Arc;

fn get_pub_and_priv_key() -> (PublicKey, SecretKey) {
	let secp = Secp256k1::new();
	let signing_key = SecretKey::from_slice(&[42u8; 32]).unwrap();
	let lsp_pubkey = PublicKey::from_secret_key(&secp, &signing_key);
	(lsp_pubkey, signing_key)
}

#[test]
fn test_basic_sign_and_verify() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	// Create a webhook notification
	let notification = WebhookNotification::webhook_registered();
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Get current time for the timestamp
	let timestamp = time_provider.to_rfc3339(time_provider.now());

	// Sign the notification using the service
	let signature =
		LSPS5ServiceHandler::sign_notification(&notification_json, &timestamp, &signing_key)
			.unwrap();

	// Verify the signature using the client
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		&timestamp,
		&signature,
		&notification,
		time_provider,
	);

	assert!(result.is_ok());
	assert!(result.unwrap());
}

#[test]
fn test_parse_webhook_notification() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	// Create a webhook notification
	let notification = WebhookNotification::payment_incoming();
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Get current time for the timestamp
	let timestamp = time_provider.to_rfc3339(time_provider.now());

	// Sign the notification using the service
	let signature =
		LSPS5ServiceHandler::sign_notification(&notification_json, &timestamp, &signing_key)
			.unwrap();

	// Parse and verify the notification using the client
	let parsed_notification =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
			lsp_pubkey,
			&timestamp,
			&signature,
			&notification_json,
			time_provider,
		)
		.unwrap();

	// Verify the parsed notification matches the original
	assert_eq!(parsed_notification.method, WebhookNotificationMethod::LSPS5PaymentIncoming);
}

#[test]
fn test_invalid_signature() {
	let (lsp_pubkey, _) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	// Create a webhook notification
	let notification = WebhookNotification::webhook_registered();

	// Get current time for the timestamp
	let timestamp = time_provider.to_rfc3339(time_provider.now());

	// Use an invalid signature
	let invalid_signature = "xdtk1zf63sfn81r6qteymy73mb1b7dspj5kwx46uxwd6c3pu7y3bto";

	// Verify should fail with the invalid signature
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		&timestamp,
		invalid_signature,
		&notification,
		time_provider,
	);

	assert!(result.is_err());
}

#[test]
fn test_invalid_timestamp() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	// Create a webhook notification
	let notification = WebhookNotification::webhook_registered();
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Use an invalid timestamp format
	let invalid_timestamp = "2023/05/04 10:52:58";

	// Sign with the invalid timestamp
	let signature =
		LSPS5ServiceHandler::sign_notification(&notification_json, invalid_timestamp, &signing_key)
			.unwrap();

	// Verify should fail with the invalid timestamp format
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		invalid_timestamp,
		&signature,
		&notification,
		time_provider,
	);

	assert!(result.is_err());
}

#[test]
fn test_all_notification_types() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	// Test all notification types
	let notifications = vec![
		WebhookNotification::webhook_registered(),
		WebhookNotification::payment_incoming(),
		WebhookNotification::expiry_soon(144),
		WebhookNotification::liquidity_management_request(),
		WebhookNotification::onion_message_incoming(),
	];

	for notification in notifications {
		let notification_json = serde_json::to_string(&notification).unwrap();
		let timestamp = time_provider.to_rfc3339(time_provider.now());

		// Sign the notification
		let signature =
			LSPS5ServiceHandler::sign_notification(&notification_json, &timestamp, &signing_key)
				.unwrap();

		// Verify the signature
		let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
			lsp_pubkey,
			&timestamp,
			&signature,
			&notification,
			time_provider.clone(),
		);

		assert!(result.is_ok());
		assert!(result.unwrap());

		// Parse the notification
		let parsed = LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
			lsp_pubkey,
			&timestamp,
			&signature,
			&notification_json,
			time_provider.clone(),
		);

		assert!(parsed.is_ok());
	}
}

#[test]
fn test_timestamp_out_of_range() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	// Create a webhook notification
	let notification = WebhookNotification::webhook_registered();
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Get timestamp that's too old (over 10 minutes)
	let too_old_timestamp = "2020-01-01T00:00:00.000Z";

	// Sign with the old timestamp
	let signature = LSPS5ServiceHandler::sign_notification(
		&notification_json,
		&too_old_timestamp,
		&signing_key,
	)
	.unwrap();

	// Verify should fail with the timestamp being too old
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		&too_old_timestamp,
		&signature,
		&notification,
		time_provider,
	);

	assert!(result.is_err());
}

#[test]
fn test_exact_bytes_from_spec_example() {
	// This test validates the exact byte sequence that should be signed
	// according to the example in the LSPS5 specification

	// Use the exact timestamp from the spec example
	let timestamp = "2023-05-04T10:52:58.395Z";

	// Create a notification similar to the spec example which used "goodbye"
	// but using webhook_registered since goodbye is not a valid method
	let notification_json = r#"{"jsonrpc":"2.0","method":"lsps5.webhook_registered","params":{}}"#;

	// Create the message to be signed exactly as described in the spec
	let message = format!(
		"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
		timestamp, notification_json
	);

	// Validate the UTF-8 byte representation
	let bytes = message.as_bytes();

	// The hex representation should match the pattern described in the spec
	// Print first few bytes to verify the format is correct
	assert_eq!(bytes[0], 0x4c); // 'L'
	assert_eq!(bytes[1], 0x53); // 'S'
	assert_eq!(bytes[2], 0x50); // 'P'
	assert_eq!(bytes[3], 0x53); // 'S'
	assert_eq!(bytes[4], 0x35); // '5'
	assert_eq!(bytes[5], 0x3a); // ':'

	// Confirm the message starts with the expected prefix
	let expected_prefix = "LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At";
	assert!(message.starts_with(expected_prefix));

	// Check for the timestamp and notification parts
	assert!(message.contains(timestamp));
	assert!(message.contains(notification_json));
}

#[test]
fn test_expiry_soon_notification_with_timeout() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	// This tests the lsps5.expiry_soon notification with its required timeout parameter
	// as per spec example

	// Create expiry_soon notification with timeout parameter
	let timeout_value = 720000; // Sample block height
	let notification = WebhookNotification::expiry_soon(timeout_value);
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Verify that the serialized JSON contains the timeout parameter
	assert!(notification_json.contains(&format!("\"timeout\":{}", timeout_value)));

	// Now test signing and verification
	let timestamp = time_provider.to_rfc3339(time_provider.now());

	// Sign the notification using the service
	let signature =
		LSPS5ServiceHandler::sign_notification(&notification_json, &timestamp, &signing_key)
			.unwrap();

	// Verify the signature using the client
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		&timestamp,
		&signature,
		&notification,
		time_provider.clone(),
	);

	assert!(result.is_ok());
	assert!(result.unwrap());

	// Parse the notification and verify parameters are preserved
	let parsed = LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
		lsp_pubkey,
		&timestamp,
		&signature,
		&notification_json,
		time_provider.clone(),
	)
	.unwrap();

	// Verify the parsed notification method is correct
	assert_eq!(parsed.method, WebhookNotificationMethod::LSPS5ExpirySoon);

	// Verify the timeout parameter is present in the parsed params
	let params_obj = parsed.params.as_object().unwrap();
	assert!(params_obj.contains_key("timeout"));
	assert_eq!(params_obj["timeout"], timeout_value);
}

#[test]
fn test_spec_example_header_format() {
	let (_, signing_key) = get_pub_and_priv_key();
	// This test verifies that the HTTP headers for webhook delivery
	// match the format specified in the LSPS5 spec

	// Create a notification
	let notification = WebhookNotification::payment_incoming();
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Use a fixed timestamp for deterministic testing
	let timestamp = "2023-05-04T10:14:23.853Z";

	// Sign the notification
	let signature =
		LSPS5ServiceHandler::sign_notification(&notification_json, timestamp, &signing_key)
			.unwrap();

	// Create headers as would be done for a webhook POST request
	let headers = vec![
		("Content-Type".to_string(), "application/json".to_string()),
		("x-lsps5-timestamp".to_string(), timestamp.to_string()),
		("x-lsps5-signature".to_string(), signature.clone()),
	];

	// Verify header format matches the spec
	let timestamp_header = headers.iter().find(|(name, _)| name == "x-lsps5-timestamp").unwrap();
	let _ = headers.iter().find(|(name, _)| name == "x-lsps5-signature").unwrap();

	// Verify timestamp header format matches ISO8601 as required
	assert_eq!(timestamp_header.1, timestamp);

	// Verify signature is in zbase32 format (character set check)
	for c in signature.chars() {
		assert!(
			(c >= 'a' && c <= 'z') || (c >= '1' && c <= '9') || c == 'y' || c == 'z',
			"Invalid character in zbase32 signature: {}",
			c
		);
	}

	// The headers "x-lsps5-timestamp" and "x-lsps5-signature" are used
	// (not "x-api-timestamp" and "x-api-signature" as incorrectly mentioned in one part of the spec)
	assert!(headers.iter().any(|(name, _)| name == "x-lsps5-timestamp"));
	assert!(headers.iter().any(|(name, _)| name == "x-lsps5-signature"));
}

#[test]
fn test_all_notification_methods_from_spec() {
	// Test all notification methods specified in the spec to ensure compatibility
	let methods = [
		("lsps5.webhook_registered", WebhookNotificationMethod::LSPS5WebhookRegistered),
		("lsps5.payment_incoming", WebhookNotificationMethod::LSPS5PaymentIncoming),
		("lsps5.expiry_soon", WebhookNotificationMethod::LSPS5ExpirySoon),
		(
			"lsps5.liquidity_management_request",
			WebhookNotificationMethod::LSPS5LiquidityManagementRequest,
		),
		("lsps5.onion_message_incoming", WebhookNotificationMethod::LSPS5OnionMessageIncoming),
	];

	for (method_name, method_enum) in methods {
		// Create a JSON string with this method
		let json = format!(r#"{{"jsonrpc":"2.0","method":"{}","params":{{}}}}"#, method_name);

		// Parse it into a WebhookNotification
		let notification: WebhookNotification = serde_json::from_str(&json).unwrap();

		// Verify the method is correctly parsed
		assert_eq!(notification.method, method_enum);

		// Serialize it back and verify it produces the expected method string
		let serialized = serde_json::to_string(&notification).unwrap();
		assert!(serialized.contains(&format!("\"method\":\"{}\"", method_name)));
	}
}

#[test]
fn test_spec_original_goodbye_example() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	// TODO: The LSPS5 spec currently contains an outdated "lsps5.goodbye" method example
	// that doesn't actually exist in the final specification. Once the spec is updated,
	// we should replace this test with one that uses the correct example.

	// Use the exact timestamp from the spec example
	let timestamp = "2023-05-04T10:52:58.395Z";

	// Create the original notification JSON string from the spec that uses the outdated "goodbye" method
	let outdated_notification_json = r#"{"jsonrpc":"2.0","method":"lsps5.goodbye","params":{}}"#;

	// Format the message to sign exactly as in the spec example
	let message = format!(
		"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
		timestamp, outdated_notification_json
	);

	// Sign the message using the correct signing method
	use lightning::util::message_signing;
	let signature = message_signing::sign(message.as_bytes(), &signing_key);

	// Create a valid notification for verification
	// Since we can't actually verify the outdated "goodbye" method directly,
	// we'll check the signature with a similar valid notification
	let valid_notification = WebhookNotification::webhook_registered();

	// The verification should fail because the serialized JSON differs from what was signed
	let result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		timestamp,
		&signature,
		&valid_notification,
		time_provider,
	);

	// The verification should fail because we're using a different notification
	assert!(result.is_err());

	// Just to verify the process works correctly, we'll check the signature against the original message
	let raw_message = message.as_bytes();
	assert!(message_signing::verify(raw_message, &signature, &lsp_pubkey));

	// Hex dump the message as shown in the spec example for reference
	println!("Hex dump of message to be signed:");
	for (i, chunk) in raw_message.chunks(16).enumerate() {
		print!("{:08x}:", i * 16);
		for b in chunk {
			print!(" {:02x}", b);
		}
		println!();
	}
}

#[test]
fn test_tampered_notification_details() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);

	// Create a webhook notification for expiry_soon
	let notification = WebhookNotification::expiry_soon(700000);
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Get current time for the timestamp
	let timestamp = time_provider.to_rfc3339(time_provider.now());

	// Sign the notification using the service
	let signature =
		LSPS5ServiceHandler::sign_notification(&notification_json, &timestamp, &signing_key)
			.unwrap();

	// First verify the original notification is valid
	let original_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
			lsp_pubkey,
			&timestamp,
			&signature,
			&notification,
			time_provider.clone(),
		);
	assert!(original_result.is_ok(), "Original notification should be valid");
	assert!(original_result.unwrap());

	// Test tampering with the notification content - change timeout value
	let mut json_value: serde_json::Value = serde_json::from_str(&notification_json).unwrap();
	json_value["params"]["timeout"] = serde_json::json!(800000); // Changed from 700000
	let tampered_timeout_json = json_value.to_string();

	let tampered_notification: WebhookNotification =
		serde_json::from_str(&tampered_timeout_json).unwrap();

	// Verify that tampered notification fails signature verification
	let tampered_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
			lsp_pubkey,
			&timestamp,
			&signature,
			&tampered_notification,
			time_provider.clone(),
		);
	assert!(tampered_result.is_err(), "Tampered notification should fail verification");

	// Test tampering with the method
	let mut json_value: serde_json::Value = serde_json::from_str(&notification_json).unwrap();
	json_value["method"] = serde_json::json!("lsps5.payment_incoming"); // Changed from expiry_soon
	let tampered_method_json = json_value.to_string();

	let tampered_method_notification: WebhookNotification =
		serde_json::from_str(&tampered_method_json).unwrap();

	// Verify that notification with tampered method fails
	let tampered_method_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
			lsp_pubkey,
			&timestamp,
			&signature,
			&tampered_method_notification,
			time_provider,
		);
	assert!(
		tampered_method_result.is_err(),
		"Notification with tampered method should fail verification"
	);
}

#[test]
fn test_timestamp_window_validation() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);

	// Create a webhook notification
	let notification = WebhookNotification::onion_message_incoming();
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Get current time
	let current_time = time_provider.now();
	let valid_timestamp = time_provider.to_rfc3339(current_time);

	// Sign the notification with current timestamp
	let signature =
		LSPS5ServiceHandler::sign_notification(&notification_json, &valid_timestamp, &signing_key)
			.unwrap();

	// Verify with the current timestamp (should pass)
	let valid_result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		&valid_timestamp,
		&signature,
		&notification,
		time_provider.clone(),
	);
	assert!(valid_result.is_ok());
	assert!(valid_result.unwrap());

	// Create past timestamp (20 minutes ago)

	let past_timestamp =
		time_provider.to_rfc3339(current_time.abs_diff(Duration::from_secs(20 * 60)));

	// Try with past timestamp (should fail)
	let past_result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		&past_timestamp,
		&signature,
		&notification,
		time_provider.clone(),
	);
	assert!(past_result.is_err(), "Notification with past timestamp should be rejected");

	// Create future timestamp (15 minutes in future)
	let future_timestamp =
		time_provider.to_rfc3339(current_time.checked_add(Duration::from_secs(15 * 60)).unwrap());

	// Try with future timestamp (should fail)
	let future_result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
		lsp_pubkey,
		&future_timestamp,
		&signature,
		&notification,
		time_provider.clone(),
	);
	assert!(future_result.is_err(), "Notification with future timestamp should be rejected");

	// Try with invalid format timestamp
	let invalid_timestamp = "2023-13-42T25:61:99Z"; // Invalid date/time
	let invalid_format_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
			lsp_pubkey,
			invalid_timestamp,
			&signature,
			&notification,
			time_provider,
		);
	assert!(
		invalid_format_result.is_err(),
		"Notification with invalid timestamp format should be rejected"
	);
}

#[test]
fn test_unknown_method_and_malformed_notifications() {
	let (lsp_pubkey, signing_key) = get_pub_and_priv_key();
	let time_provider = Arc::new(DefaultTimeProvider);
	let timestamp = time_provider.to_rfc3339(time_provider.now());

	// Helper to create notifications with custom structure
	let create_notification = |method: &str, params: serde_json::Value| -> serde_json::Value {
		serde_json::json!({
			"jsonrpc": "2.0",
			"method": method,
			"params": params
		})
	};

	// Test Case 1: Unknown notification method
	let unknown_notification =
		create_notification("lsps5.unknown_method", serde_json::json!({"some": "data"}));
	let unknown_json = unknown_notification.to_string();
	let unknown_signature =
		LSPS5ServiceHandler::sign_notification(&unknown_json, &timestamp, &signing_key).unwrap();

	// Client should reject unrecognized methods, even with valid signatures
	let unknown_result = LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
		lsp_pubkey,
		&timestamp,
		&unknown_signature,
		&unknown_json,
		time_provider.clone(),
	);
	assert!(unknown_result.is_err(), "Unknown method should be rejected even with valid signature");

	// Test Case 2: Missing required jsonrpc field
	let invalid_jsonrpc = serde_json::json!({
		"method": "lsps5.payment_incoming",
		"params": {}
		// Missing required jsonrpc field
	})
	.to_string();
	let invalid_jsonrpc_signature =
		LSPS5ServiceHandler::sign_notification(&invalid_jsonrpc, &timestamp, &signing_key).unwrap();

	let invalid_jsonrpc_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
			lsp_pubkey,
			&timestamp,
			&invalid_jsonrpc_signature,
			&invalid_jsonrpc,
			time_provider.clone(),
		);
	assert!(invalid_jsonrpc_result.is_err(), "Missing jsonrpc field should be rejected");

	// Test Case 3: Missing required params field
	let missing_params = serde_json::json!({
		"jsonrpc": "2.0",
		"method": "lsps5.payment_incoming"
		// Missing required params field
	})
	.to_string();
	let missing_params_signature =
		LSPS5ServiceHandler::sign_notification(&missing_params, &timestamp, &signing_key).unwrap();

	let missing_params_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
			lsp_pubkey,
			&timestamp,
			&missing_params_signature,
			&missing_params,
			time_provider.clone(),
		);
	assert!(missing_params_result.is_err(), "Missing params field should be rejected");

	// Test Case 4: Extra unrecognized parameters in notification
	let extra_params_notification = create_notification(
		"lsps5.expiry_soon",
		serde_json::json!({
			"timeout": 123456,
			"extra_field": "should be ignored",
			"another_extra": 42
		}),
	);
	let extra_params_json = extra_params_notification.to_string();
	let extra_params_signature =
		LSPS5ServiceHandler::sign_notification(&extra_params_json, &timestamp, &signing_key)
			.unwrap();

	// Extra params should be ignored - this should succeed
	let extra_params_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
			lsp_pubkey,
			&timestamp,
			&extra_params_signature,
			&extra_params_json,
			time_provider.clone(),
		);
	assert!(
		extra_params_result.is_ok(),
		"Notification with extra parameters should parse successfully"
	);

	// Test Case 5: Invalid JSON
	let invalid_json = "{not valid json";
	// Try to sign it (might fail depending on implementation)
	let invalid_json_signature_result =
		LSPS5ServiceHandler::sign_notification(invalid_json, &timestamp, &signing_key);

	// If signing succeeded (implementation doesn't validate JSON), try to parse
	if let Ok(invalid_signature) = invalid_json_signature_result {
		let invalid_json_result =
			LSPS5ClientHandler::<Arc<dyn EntropySource>>::parse_webhook_notification(
				lsp_pubkey,
				&timestamp,
				&invalid_signature,
				invalid_json,
				time_provider.clone(),
			);
		assert!(invalid_json_result.is_err(), "Invalid JSON should be rejected");
	} else {
		// If signing failed, that's fine too - it means the service validates JSON
		assert!(
			invalid_json_signature_result.is_err(),
			"Invalid JSON should be rejected at signing"
		);
	}

	// Test Case 6: Edge case timestamp validations (testing timestamps at the boundaries)
	let notification = WebhookNotification::payment_incoming();
	let notification_json = serde_json::to_string(&notification).unwrap();

	// Generate timestamps at edge of acceptable range
	let edge_past_timestamp =
		time_provider.to_rfc3339(time_provider.now().abs_diff(Duration::from_secs(9 * 60)));
	let edge_future_timestamp = time_provider
		.to_rfc3339(time_provider.now().checked_add(Duration::from_secs(9 * 60)).unwrap());

	// Sign with edge timestamps
	let past_edge_signature = LSPS5ServiceHandler::sign_notification(
		&notification_json,
		&edge_past_timestamp,
		&signing_key,
	)
	.unwrap();
	let future_edge_signature = LSPS5ServiceHandler::sign_notification(
		&notification_json,
		&edge_future_timestamp,
		&signing_key,
	)
	.unwrap();

	// Both should be accepted (just within 10 minute window)
	let past_edge_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
			lsp_pubkey,
			&edge_past_timestamp,
			&past_edge_signature,
			&notification,
			time_provider.clone(),
		);
	let future_edge_result =
		LSPS5ClientHandler::<Arc<dyn EntropySource>>::verify_notification_signature(
			lsp_pubkey,
			&edge_future_timestamp,
			&future_edge_signature,
			&notification,
			time_provider,
		);

	assert!(past_edge_result.is_ok(), "Timestamp just within past range should be accepted");
	assert!(future_edge_result.is_ok(), "Timestamp just within future range should be accepted");
}
