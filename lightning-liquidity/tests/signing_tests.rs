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
use common::get_client_and_service;
use core::time::Duration;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps5::msgs::{WebhookNotification, WebhookNotificationMethod};
use lightning_liquidity::lsps5::service::{DefaultTimeProvider, TimeProvider};
use std::sync::Arc;

#[test]
fn test_basic_sign_and_verify() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();
	let time_provider: Arc<(dyn TimeProvider + 'static)> = Arc::new(DefaultTimeProvider);
	let notification = WebhookNotification::webhook_registered();
	let notification_json = serde_json::to_string(&notification).unwrap();

	let timestamp = LSPSDateTime::from(time_provider.duration_since_epoch()).to_rfc3339();

	let signature = service_handler.sign_notification(&notification_json, &timestamp).unwrap();

	let result = client_handler.verify_notification_signature(
		service_node_id,
		&timestamp,
		&signature,
		&notification,
	);

	assert!(result.is_ok());
	assert!(result.unwrap());
}

#[test]
fn test_parse_webhook_notification() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();
	let time_provider: Arc<(dyn TimeProvider + 'static)> = Arc::new(DefaultTimeProvider);
	let notification = WebhookNotification::payment_incoming();
	let notification_json = serde_json::to_string(&notification).unwrap();

	let timestamp = LSPSDateTime::from(time_provider.duration_since_epoch()).to_rfc3339();

	let signature = service_handler.sign_notification(&notification_json, &timestamp).unwrap();

	let parsed_notification = client_handler
		.parse_webhook_notification(service_node_id, &timestamp, &signature, &notification_json)
		.unwrap();

	assert_eq!(parsed_notification.method, WebhookNotificationMethod::LSPS5PaymentIncoming);
}

#[test]
fn test_invalid_signature() {
	let (client_handler, _, service_node_id, _, _, _) = get_client_and_service();
	let time_provider: Arc<(dyn TimeProvider + 'static)> = Arc::new(DefaultTimeProvider);
	let notification = WebhookNotification::webhook_registered();

	let timestamp = LSPSDateTime::from(time_provider.duration_since_epoch()).to_rfc3339();

	let invalid_signature = "xdtk1zf63sfn81r6qteymy73mb1b7dspj5kwx46uxwd6c3pu7y3bto";

	let result = client_handler.verify_notification_signature(
		service_node_id,
		&timestamp,
		invalid_signature,
		&notification,
	);

	assert!(result.is_err());
}

#[test]
fn test_invalid_timestamp() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();
	let notification = WebhookNotification::webhook_registered();
	let notification_json = serde_json::to_string(&notification).unwrap();

	let invalid_timestamp = "2023/05/04 10:52:58";

	let signature =
		service_handler.sign_notification(&notification_json, invalid_timestamp).unwrap();

	let result = client_handler.verify_notification_signature(
		service_node_id,
		invalid_timestamp,
		&signature,
		&notification,
	);

	assert!(result.is_err());
}

#[test]
fn test_all_notification_types() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();
	let time_provider: Arc<(dyn TimeProvider + 'static)> = Arc::new(DefaultTimeProvider);
	let notifications = vec![
		WebhookNotification::webhook_registered(),
		WebhookNotification::payment_incoming(),
		WebhookNotification::expiry_soon(144),
		WebhookNotification::liquidity_management_request(),
		WebhookNotification::onion_message_incoming(),
	];

	for notification in notifications {
		let notification_json = serde_json::to_string(&notification).unwrap();
		let timestamp = LSPSDateTime::from(time_provider.duration_since_epoch()).to_rfc3339();

		let signature = service_handler.sign_notification(&notification_json, &timestamp).unwrap();

		let result = client_handler.verify_notification_signature(
			service_node_id,
			&timestamp,
			&signature,
			&notification,
		);

		assert!(result.is_ok());
		assert!(result.unwrap());

		let parsed = client_handler.parse_webhook_notification(
			service_node_id,
			&timestamp,
			&signature,
			&notification_json,
		);

		assert!(parsed.is_ok());
	}
}

#[test]
fn test_timestamp_out_of_range() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();

	let notification = WebhookNotification::webhook_registered();
	let notification_json = serde_json::to_string(&notification).unwrap();

	let too_old_timestamp = "2020-01-01T00:00:00.000Z";

	let signature =
		service_handler.sign_notification(&notification_json, &too_old_timestamp).unwrap();

	let result = client_handler.verify_notification_signature(
		service_node_id,
		&too_old_timestamp,
		&signature,
		&notification,
	);

	assert!(result.is_err());
}

#[test]
fn test_exact_bytes_from_spec_example() {
	let timestamp = "2023-05-04T10:52:58.395Z";

	let notification_json = r#"{"jsonrpc":"2.0","method":"lsps5.webhook_registered","params":{}}"#;

	let message = format!(
		"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
		timestamp, notification_json
	);

	let bytes = message.as_bytes();

	assert_eq!(bytes[0], 0x4c); // 'L'
	assert_eq!(bytes[1], 0x53); // 'S'
	assert_eq!(bytes[2], 0x50); // 'P'
	assert_eq!(bytes[3], 0x53); // 'S'
	assert_eq!(bytes[4], 0x35); // '5'
	assert_eq!(bytes[5], 0x3a); // ':'

	let expected_prefix = "LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At";
	assert!(message.starts_with(expected_prefix));

	assert!(message.contains(timestamp));
	assert!(message.contains(notification_json));
}

#[test]
fn test_expiry_soon_notification_with_timeout() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();
	let time_provider: Arc<(dyn TimeProvider + 'static)> = Arc::new(DefaultTimeProvider);
	let timeout_value = 720000;
	let notification = WebhookNotification::expiry_soon(timeout_value);
	let notification_json = serde_json::to_string(&notification).unwrap();

	assert!(notification_json.contains(&format!("\"timeout\":{}", timeout_value)));

	let timestamp = LSPSDateTime::from(time_provider.duration_since_epoch()).to_rfc3339();

	let signature = service_handler.sign_notification(&notification_json, &timestamp).unwrap();

	let result = client_handler.verify_notification_signature(
		service_node_id,
		&timestamp,
		&signature,
		&notification,
	);

	assert!(result.is_ok());
	assert!(result.unwrap());

	let parsed = client_handler
		.parse_webhook_notification(service_node_id, &timestamp, &signature, &notification_json)
		.unwrap();

	assert_eq!(
		parsed.method,
		WebhookNotificationMethod::LSPS5ExpirySoon { timeout: timeout_value }
	);

	let binding = parsed.method.parameters_json_value();
	let params_obj = binding.as_object().unwrap();
	assert!(params_obj.contains_key("timeout"));
	assert_eq!(params_obj["timeout"], timeout_value);
}

#[test]
fn test_spec_example_header_format() {
	let (_, service_handler, _, _, _, _) = get_client_and_service();

	let notification = WebhookNotification::payment_incoming();
	let notification_json = serde_json::to_string(&notification).unwrap();

	let timestamp = "2023-05-04T10:14:23.853Z";

	let signature = service_handler.sign_notification(&notification_json, timestamp).unwrap();

	let headers = vec![
		("Content-Type".to_string(), "application/json".to_string()),
		("x-lsps5-timestamp".to_string(), timestamp.to_string()),
		("x-lsps5-signature".to_string(), signature.clone()),
	];

	let timestamp_header = headers.iter().find(|(name, _)| name == "x-lsps5-timestamp").unwrap();
	let _ = headers.iter().find(|(name, _)| name == "x-lsps5-signature").unwrap();

	assert_eq!(timestamp_header.1, timestamp);

	for c in signature.chars() {
		assert!(
			(c >= 'a' && c <= 'z') || (c >= '1' && c <= '9') || c == 'y' || c == 'z',
			"Invalid character in zbase32 signature: {}",
			c
		);
	}

	assert!(headers.iter().any(|(name, _)| name == "x-lsps5-timestamp"));
	assert!(headers.iter().any(|(name, _)| name == "x-lsps5-signature"));
}

#[test]
fn test_all_notification_methods_from_spec() {
	let methods = [
		("lsps5.webhook_registered", WebhookNotificationMethod::LSPS5WebhookRegistered, "{}"),
		("lsps5.payment_incoming", WebhookNotificationMethod::LSPS5PaymentIncoming, "{}"),
		(
			"lsps5.expiry_soon",
			WebhookNotificationMethod::LSPS5ExpirySoon { timeout: 144 },
			"{\"timeout\":144}",
		),
		(
			"lsps5.liquidity_management_request",
			WebhookNotificationMethod::LSPS5LiquidityManagementRequest,
			"{}",
		),
		(
			"lsps5.onion_message_incoming",
			WebhookNotificationMethod::LSPS5OnionMessageIncoming,
			"{}",
		),
	];

	for (method_name, method_enum, params_json) in methods {
		let json =
			format!(r#"{{"jsonrpc":"2.0","method":"{}","params":{}}}"#, method_name, params_json);

		let notification: WebhookNotification = serde_json::from_str(&json).unwrap();

		assert_eq!(notification.method, method_enum);

		let serialized = serde_json::to_string(&notification).unwrap();
		assert!(serialized.contains(&format!("\"method\":\"{}\"", method_name)));

		if method_name == "lsps5.expiry_soon" {
			assert!(serialized.contains("\"timeout\":144"));
		}
	}
}

#[test]
fn test_tampered_notification_details() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();
	let time_provider: Arc<(dyn TimeProvider + 'static)> = Arc::new(DefaultTimeProvider);

	let notification = WebhookNotification::expiry_soon(700000);
	let notification_json = serde_json::to_string(&notification).unwrap();

	let timestamp = LSPSDateTime::from(time_provider.duration_since_epoch()).to_rfc3339();

	let signature = service_handler.sign_notification(&notification_json, &timestamp).unwrap();

	let original_result = client_handler.verify_notification_signature(
		service_node_id,
		&timestamp,
		&signature,
		&notification,
	);
	assert!(original_result.is_ok(), "Original notification should be valid");
	assert!(original_result.unwrap());

	let mut json_value: serde_json::Value = serde_json::from_str(&notification_json).unwrap();
	json_value["params"]["timeout"] = serde_json::json!(800000);
	let tampered_timeout_json = json_value.to_string();

	let tampered_notification: WebhookNotification =
		serde_json::from_str(&tampered_timeout_json).unwrap();

	let tampered_result = client_handler.verify_notification_signature(
		service_node_id,
		&timestamp,
		&signature,
		&tampered_notification,
	);
	assert!(tampered_result.is_err(), "Tampered notification should fail verification");

	let mut json_value: serde_json::Value = serde_json::from_str(&notification_json).unwrap();
	json_value["method"] = serde_json::json!("lsps5.payment_incoming");
	let tampered_method_json = json_value.to_string();

	let tampered_method_notification: WebhookNotification =
		serde_json::from_str(&tampered_method_json).unwrap();

	let tampered_method_result = client_handler.verify_notification_signature(
		service_node_id,
		&timestamp,
		&signature,
		&tampered_method_notification,
	);
	assert!(
		tampered_method_result.is_err(),
		"Notification with tampered method should fail verification"
	);
}

#[test]
fn test_timestamp_window_validation() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();
	let time_provider: Arc<(dyn TimeProvider + 'static)> = Arc::new(DefaultTimeProvider);

	let notification = WebhookNotification::onion_message_incoming();
	let notification_json = serde_json::to_string(&notification).unwrap();

	let current_time = time_provider.duration_since_epoch();
	let valid_timestamp = LSPSDateTime::from(current_time).to_rfc3339();

	let signature: String =
		service_handler.sign_notification(&notification_json, &valid_timestamp).unwrap();

	let valid_result = client_handler.verify_notification_signature(
		service_node_id,
		&valid_timestamp,
		&signature,
		&notification,
	);
	assert!(valid_result.is_ok());
	assert!(valid_result.unwrap());

	let past_timestamp =
		LSPSDateTime::from(current_time.checked_sub(Duration::from_secs(20 * 60)).unwrap())
			.to_rfc3339();

	let past_result = client_handler.verify_notification_signature(
		service_node_id,
		&past_timestamp,
		&signature,
		&notification,
	);
	assert!(past_result.is_err(), "Notification with past timestamp should be rejected");

	let future_timestamp =
		LSPSDateTime::from(current_time.checked_add(Duration::from_secs(15 * 60)).unwrap())
			.to_rfc3339();

	let future_result = client_handler.verify_notification_signature(
		service_node_id,
		&future_timestamp,
		&signature,
		&notification,
	);
	assert!(future_result.is_err(), "Notification with future timestamp should be rejected");

	let invalid_timestamp = "2023-13-42T25:61:99Z";
	let invalid_format_result = client_handler.verify_notification_signature(
		service_node_id,
		invalid_timestamp,
		&signature,
		&notification,
	);
	assert!(
		invalid_format_result.is_err(),
		"Notification with invalid timestamp format should be rejected"
	);
}

#[test]
fn test_unknown_method_and_malformed_notifications() {
	let (client_handler, service_handler, service_node_id, _, _, _) = get_client_and_service();
	let time_provider: Arc<(dyn TimeProvider + 'static)> = Arc::new(DefaultTimeProvider);
	let timestamp = LSPSDateTime::from(time_provider.duration_since_epoch()).to_rfc3339();

	let create_notification = |method: &str, params: serde_json::Value| -> serde_json::Value {
		serde_json::json!({
			"jsonrpc": "2.0",
			"method": method,
			"params": params
		})
	};

	let unknown_notification =
		create_notification("lsps5.unknown_method", serde_json::json!({"some": "data"}));
	let unknown_json = unknown_notification.to_string();
	let unknown_signature = service_handler.sign_notification(&unknown_json, &timestamp).unwrap();

	let unknown_result = client_handler.parse_webhook_notification(
		service_node_id,
		&timestamp,
		&unknown_signature,
		&unknown_json,
	);
	assert!(unknown_result.is_err(), "Unknown method should be rejected even with valid signature");

	let invalid_jsonrpc = serde_json::json!({
		"method": "lsps5.payment_incoming",
		"params": {}
	})
	.to_string();
	let invalid_jsonrpc_signature =
		service_handler.sign_notification(&invalid_jsonrpc, &timestamp).unwrap();

	let invalid_jsonrpc_result = client_handler.parse_webhook_notification(
		service_node_id,
		&timestamp,
		&invalid_jsonrpc_signature,
		&invalid_jsonrpc,
	);
	assert!(invalid_jsonrpc_result.is_err(), "Missing jsonrpc field should be rejected");

	let missing_params = serde_json::json!({
		"jsonrpc": "2.0",
		"method": "lsps5.payment_incoming"
	})
	.to_string();
	let missing_params_signature =
		service_handler.sign_notification(&missing_params, &timestamp).unwrap();

	let missing_params_result = client_handler.parse_webhook_notification(
		service_node_id,
		&timestamp,
		&missing_params_signature,
		&missing_params,
	);
	assert!(missing_params_result.is_err(), "Missing params field should be rejected");

	let invalid_json = "{not valid json";
	let invalid_json_signature_result = service_handler.sign_notification(invalid_json, &timestamp);

	if let Ok(invalid_signature) = invalid_json_signature_result {
		let invalid_json_result = client_handler.parse_webhook_notification(
			service_node_id,
			&timestamp,
			&invalid_signature,
			invalid_json,
		);
		assert!(invalid_json_result.is_err(), "Invalid JSON should be rejected");
	} else {
		assert!(
			invalid_json_signature_result.is_err(),
			"Invalid JSON should be rejected at signing"
		);
	}

	let notification = WebhookNotification::payment_incoming();
	let notification_json = serde_json::to_string(&notification).unwrap();

	let edge_past_timestamp = LSPSDateTime::from(
		time_provider.duration_since_epoch().checked_sub(Duration::from_secs(9 * 60)).unwrap(),
	)
	.to_rfc3339();
	let edge_future_timestamp = LSPSDateTime::from(
		time_provider.duration_since_epoch().checked_add(Duration::from_secs(9 * 60)).unwrap(),
	)
	.to_rfc3339();

	let past_edge_signature =
		service_handler.sign_notification(&notification_json, &edge_past_timestamp).unwrap();
	let future_edge_signature =
		service_handler.sign_notification(&notification_json, &edge_future_timestamp).unwrap();

	let past_edge_result = client_handler.verify_notification_signature(
		service_node_id,
		&edge_past_timestamp,
		&past_edge_signature,
		&notification,
	);
	let future_edge_result = client_handler.verify_notification_signature(
		service_node_id,
		&edge_future_timestamp,
		&future_edge_signature,
		&notification,
	);

	assert!(past_edge_result.is_ok(), "Timestamp just within past range should be accepted");
	assert!(future_edge_result.is_ok(), "Timestamp just within future range should be accepted");
}
