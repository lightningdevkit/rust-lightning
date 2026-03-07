// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Message, request, and other primitive types used to implement bLIP-57 / LSPS7.

use alloc::string::String;
use alloc::vec::Vec;

use core::convert::TryFrom;

use crate::lsps0::ser::{
	unchecked_address_option, LSPSDateTime, LSPSMessage, LSPSRequestId, LSPSResponseError,
};
use crate::lsps1::msgs::LSPS1PaymentInfo;

use bitcoin::Address;

use serde::{Deserialize, Serialize};

pub(crate) const LSPS7_GET_EXTENDABLE_CHANNELS_METHOD_NAME: &str = "lsps7.get_extendable_channels";
pub(crate) const LSPS7_CREATE_ORDER_METHOD_NAME: &str = "lsps7.create_order";
pub(crate) const LSPS7_GET_ORDER_METHOD_NAME: &str = "lsps7.get_order";

/// The identifier of an LSPS7 channel extension order.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub struct LSPS7OrderId(pub String);

/// An object representing the status of a channel extension order.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LSPS7OrderState {
	/// The order has been created.
	Created,
	/// The channel extension has been completed.
	Completed,
	/// The order failed.
	Failed,
}

/// A reference to the original LSPS1 order that opened the channel.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS7OriginalOrder {
	/// The id of the original order.
	pub id: String,
	/// The service that created the original order.
	pub service: String,
}

/// An object representing a channel eligible for lease extension.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS7ExtendableChannel {
	/// A reference to the original order, if applicable.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub original_order: Option<LSPS7OriginalOrder>,
	/// The ids of any previous extension orders on this channel.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub extension_order_ids: Option<Vec<String>>,
	/// The short channel id in "NNNxNNNxNNN" format.
	pub short_channel_id: String,
	/// The maximum number of blocks the channel lease can be extended by.
	pub max_channel_extension_expiry_blocks: u32,
	/// The current expiration block of the channel lease.
	pub expiration_block: u32,
}

/// A request made to an LSP to retrieve the list of channels eligible for extension.
///
/// Please refer to the bLIP-57 / LSPS7 specification for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct LSPS7GetExtendableChannelsRequest {}

/// A response to a [`LSPS7GetExtendableChannelsRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS7GetExtendableChannelsResponse {
	/// The list of channels eligible for extension.
	pub extendable_channels: Vec<LSPS7ExtendableChannel>,
}

/// A request made to an LSP to create a channel extension order.
///
/// Please refer to the bLIP-57 / LSPS7 specification for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS7CreateOrderRequest {
	/// The short channel id of the channel to extend, in "NNNxNNNxNNN" format.
	pub short_channel_id: String,
	/// The number of blocks to extend the channel lease by.
	pub channel_extension_expiry_blocks: u32,
	/// May contain arbitrary associated data like a coupon code or an authentication token.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub token: Option<String>,
	/// The address where the LSP will send the funds if the order fails.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "unchecked_address_option")]
	pub refund_onchain_address: Option<Address>,
}

/// A response to a [`LSPS7CreateOrderRequest`] or [`LSPS7GetOrderRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS7CreateOrderResponse {
	/// The id of the extension order.
	pub order_id: LSPS7OrderId,
	/// The number of blocks the channel lease will be extended by.
	pub channel_extension_expiry_blocks: u32,
	/// The new expiration block of the channel lease after extension.
	pub new_channel_expiry_block: u32,
	/// The token associated with the order.
	pub token: String,
	/// The datetime when the order was created.
	pub created_at: LSPSDateTime,
	/// The current state of the order.
	pub order_state: LSPS7OrderState,
	/// Contains details about how to pay for the order. Mirrors LSPS1 payment format.
	pub payment: LSPS1PaymentInfo,
	/// The channel being extended.
	pub channel: LSPS7ExtendableChannel,
}

/// A request made to an LSP to retrieve information about a previously made extension order.
///
/// Please refer to the bLIP-57 / LSPS7 specification for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS7GetOrderRequest {
	/// The id of the order.
	pub order_id: LSPS7OrderId,
}

/// An enum that captures all the valid JSON-RPC requests in the bLIP-57 / LSPS7 protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS7Request {
	/// A request to retrieve the list of extendable channels.
	GetExtendableChannels(LSPS7GetExtendableChannelsRequest),
	/// A request to create a channel extension order.
	CreateOrder(LSPS7CreateOrderRequest),
	/// A request to query a previously created extension order.
	GetOrder(LSPS7GetOrderRequest),
}

/// An enum that captures all the valid JSON-RPC responses in the bLIP-57 / LSPS7 protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS7Response {
	/// A successful response to a [`LSPS7GetExtendableChannelsRequest`].
	GetExtendableChannels(LSPS7GetExtendableChannelsResponse),
	/// An error response to a [`LSPS7GetExtendableChannelsRequest`].
	GetExtendableChannelsError(LSPSResponseError),
	/// A successful response to a [`LSPS7CreateOrderRequest`].
	CreateOrder(LSPS7CreateOrderResponse),
	/// An error response to a [`LSPS7CreateOrderRequest`].
	CreateOrderError(LSPSResponseError),
	/// A successful response to a [`LSPS7GetOrderRequest`].
	GetOrder(LSPS7CreateOrderResponse),
	/// An error response to a [`LSPS7GetOrderRequest`].
	GetOrderError(LSPSResponseError),
}

/// An enum that captures all valid JSON-RPC messages in the bLIP-57 / LSPS7 protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS7Message {
	/// An LSPS7 JSON-RPC request.
	Request(LSPSRequestId, LSPS7Request),
	/// An LSPS7 JSON-RPC response.
	Response(LSPSRequestId, LSPS7Response),
}

impl TryFrom<LSPSMessage> for LSPS7Message {
	type Error = ();

	fn try_from(message: LSPSMessage) -> Result<Self, Self::Error> {
		if let LSPSMessage::LSPS7(message) = message {
			return Ok(message);
		}

		Err(())
	}
}

impl From<LSPS7Message> for LSPSMessage {
	fn from(message: LSPS7Message) -> Self {
		LSPSMessage::LSPS7(message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn get_extendable_channels_request_serialization() {
		let json_str = r#"{}"#;
		let _request: LSPS7GetExtendableChannelsRequest = serde_json::from_str(json_str).unwrap();
	}

	#[test]
	fn extendable_channel_serialization() {
		let json_str = r#"{
			"original_order": {
				"id": "bb4b5d0a-8334-49d8-9463-90a6d413af7c",
				"service": "lsps1"
			},
			"extension_order_ids": ["cc5c6e1b-9445-50e9-0574-01b7e524af8d"],
			"short_channel_id": "761432x100x0",
			"max_channel_extension_expiry_blocks": 52560,
			"expiration_block": 850000
		}"#;
		let channel: LSPS7ExtendableChannel = serde_json::from_str(json_str).unwrap();
		assert_eq!(channel.short_channel_id, "761432x100x0");
		assert_eq!(channel.max_channel_extension_expiry_blocks, 52560);
		assert_eq!(channel.expiration_block, 850000);
		assert!(channel.original_order.is_some());
		assert!(channel.extension_order_ids.is_some());
	}

	#[test]
	fn get_extendable_channels_response_serialization() {
		let json_str = r#"{
			"extendable_channels": [
				{
					"short_channel_id": "761432x100x0",
					"max_channel_extension_expiry_blocks": 52560,
					"expiration_block": 850000
				}
			]
		}"#;
		let response: LSPS7GetExtendableChannelsResponse = serde_json::from_str(json_str).unwrap();
		assert_eq!(response.extendable_channels.len(), 1);
	}

	#[test]
	fn create_order_request_serialization() {
		let json_str = r#"{
			"short_channel_id": "761432x100x0",
			"channel_extension_expiry_blocks": 20160,
			"token": "my-token"
		}"#;
		let request: LSPS7CreateOrderRequest = serde_json::from_str(json_str).unwrap();
		assert_eq!(request.short_channel_id, "761432x100x0");
		assert_eq!(request.channel_extension_expiry_blocks, 20160);
		assert_eq!(request.token, Some("my-token".into()));
		assert!(request.refund_onchain_address.is_none());
	}

	#[test]
	fn order_state_serialization() {
		let json_str = r#""CREATED""#;
		let state: LSPS7OrderState = serde_json::from_str(json_str).unwrap();
		assert_eq!(state, LSPS7OrderState::Created);

		let json_str = r#""COMPLETED""#;
		let state: LSPS7OrderState = serde_json::from_str(json_str).unwrap();
		assert_eq!(state, LSPS7OrderState::Completed);

		let json_str = r#""FAILED""#;
		let state: LSPS7OrderState = serde_json::from_str(json_str).unwrap();
		assert_eq!(state, LSPS7OrderState::Failed);
	}
}
