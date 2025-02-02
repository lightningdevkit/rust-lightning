//! Message, request, and other primitive types used to implement bLIP-51 / LSPS1.

use crate::lsps0::ser::{
	string_amount, u32_fee_rate, unchecked_address, unchecked_address_option, LSPSMessage,
	LSPSRequestId, LSPSResponseError,
};

use crate::prelude::String;

use bitcoin::{Address, FeeRate, OutPoint};

use lightning_invoice::Bolt11Invoice;

use serde::{Deserialize, Serialize};

use chrono::Utc;

use core::convert::TryFrom;

pub(crate) const LSPS1_GET_INFO_METHOD_NAME: &str = "lsps1.get_info";
pub(crate) const LSPS1_CREATE_ORDER_METHOD_NAME: &str = "lsps1.create_order";
pub(crate) const LSPS1_GET_ORDER_METHOD_NAME: &str = "lsps1.get_order";

pub(crate) const _LSPS1_CREATE_ORDER_REQUEST_INVALID_PARAMS_ERROR_CODE: i32 = -32602;
#[cfg(lsps1_service)]
pub(crate) const LSPS1_CREATE_ORDER_REQUEST_ORDER_MISMATCH_ERROR_CODE: i32 = 100;

/// The identifier of an order.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub struct LSPS1OrderId(pub String);

/// A request made to an LSP to retrieve the supported options.
///
/// Please refer to the [bLIP-51 / LSPS1
/// specification](https://github.com/lightning/blips/blob/master/blip-0051.md#1-lsps1get_info) for
/// more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct LSPS1GetInfoRequest {}

/// An object representing the supported protocol options.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1Options {
	/// The smallest number of confirmations needed for the LSP to accept a channel as confirmed.
	pub min_required_channel_confirmations: u16,
	/// The smallest number of blocks in which the LSP can confirm the funding transaction.
	pub min_funding_confirms_within_blocks: u16,
	/// Indicates if the LSP supports zero reserve.
	pub supports_zero_channel_reserve: bool,
	/// The maximum number of blocks a channel can be leased for.
	pub max_channel_expiry_blocks: u32,
	/// The minimum number of satoshi that the client MUST request.
	#[serde(with = "string_amount")]
	pub min_initial_client_balance_sat: u64,
	/// The maximum number of satoshi that the client MUST request.
	#[serde(with = "string_amount")]
	pub max_initial_client_balance_sat: u64,
	/// The minimum number of satoshi that the LSP will provide to the channel.
	#[serde(with = "string_amount")]
	pub min_initial_lsp_balance_sat: u64,
	/// The maximum number of satoshi that the LSP will provide to the channel.
	#[serde(with = "string_amount")]
	pub max_initial_lsp_balance_sat: u64,
	/// The minimal channel size.
	#[serde(with = "string_amount")]
	pub min_channel_balance_sat: u64,
	/// The maximal channel size.
	#[serde(with = "string_amount")]
	pub max_channel_balance_sat: u64,
}

/// A response to a [`LSPS1GetInfoRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1GetInfoResponse {
	/// All options supported by the LSP.
	#[serde(flatten)]
	pub options: LSPS1Options,
}

/// A request made to an LSP to create an order.
///
/// Please refer to the [bLIP-51 / LSPS1
/// specification](https://github.com/lightning/blips/blob/master/blip-0051.md#2-lsps1create_order)
/// for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1CreateOrderRequest {
	/// The order made.
	#[serde(flatten)]
	pub order: LSPS1OrderParams,
	/// The address where the LSP will send the funds if the order fails.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "unchecked_address_option")]
	pub refund_onchain_address: Option<Address>,
}

/// An object representing an bLIP-51 / LSPS1 channel order.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1OrderParams {
	/// Indicates how many satoshi the LSP will provide on their side.
	#[serde(with = "string_amount")]
	pub lsp_balance_sat: u64,
	/// Indicates how many satoshi the client will provide on their side.
	///
	/// The client sends these funds to the LSP, who will push them back to the client upon opening
	/// the channel.
	#[serde(with = "string_amount")]
	pub client_balance_sat: u64,
	/// The number of confirmations the funding tx must have before the LSP sends `channel_ready`.
	pub required_channel_confirmations: u16,
	/// The maximum number of blocks the client wants to wait until the funding transaction is confirmed.
	pub funding_confirms_within_blocks: u16,
	/// Indicates how long the channel is leased for in block time.
	pub channel_expiry_blocks: u32,
	/// May contain arbitrary associated data like a coupon code or a authentication token.
	pub token: Option<String>,
	/// Indicates if the channel should be announced to the network.
	pub announce_channel: bool,
}

/// A response to a [`LSPS1CreateOrderRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1CreateOrderResponse {
	/// The id of the channel order.
	pub order_id: LSPS1OrderId,
	/// The parameters of channel order.
	#[serde(flatten)]
	pub order: LSPS1OrderParams,
	/// The datetime when the order was created
	pub created_at: chrono::DateTime<Utc>,
	/// The current state of the order.
	pub order_state: LSPS1OrderState,
	/// Contains details about how to pay for the order.
	pub payment: LSPS1PaymentInfo,
	/// Contains information about the channel state.
	pub channel: Option<LSPS1ChannelInfo>,
}

/// An object representing the status of an order.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LSPS1OrderState {
	/// The order has been created.
	Created,
	/// The LSP has opened the channel and published the funding transaction.
	Completed,
	/// The order failed.
	Failed,
}

/// Details regarding how to pay for an order.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1PaymentInfo {
	/// A Lightning payment using BOLT 11.
	pub bolt11: Option<LSPS1Bolt11PaymentInfo>,
	/// An onchain payment.
	pub onchain: Option<LSPS1OnchainPaymentInfo>,
}

/// A Lightning payment using BOLT 11.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1Bolt11PaymentInfo {
	/// Indicates the current state of the payment.
	pub state: LSPS1PaymentState,
	/// The datetime when the payment option expires.
	pub expires_at: chrono::DateTime<Utc>,
	/// The total fee the LSP will charge to open this channel in satoshi.
	#[serde(with = "string_amount")]
	pub fee_total_sat: u64,
	/// The amount the client needs to pay to have the requested channel openend.
	#[serde(with = "string_amount")]
	pub order_total_sat: u64,
	/// A BOLT11 invoice the client can pay to have to channel opened.
	pub invoice: Bolt11Invoice,
}

/// An onchain payment.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1OnchainPaymentInfo {
	/// Indicates the current state of the payment.
	pub state: LSPS1PaymentState,
	/// The datetime when the payment option expires.
	pub expires_at: chrono::DateTime<Utc>,
	/// The total fee the LSP will charge to open this channel in satoshi.
	#[serde(with = "string_amount")]
	pub fee_total_sat: u64,
	/// The amount the client needs to pay to have the requested channel openend.
	#[serde(with = "string_amount")]
	pub order_total_sat: u64,
	/// An on-chain address the client can send [`Self::order_total_sat`] to to have the channel
	/// opened.
	#[serde(with = "unchecked_address")]
	pub address: Address,
	/// The minimum number of block confirmations that are required for the on-chain payment to be
	/// considered confirmed.
	pub min_onchain_payment_confirmations: Option<u16>,
	/// The minimum fee rate for the on-chain payment in case the client wants the payment to be
	/// confirmed without a confirmation.
	#[serde(with = "u32_fee_rate")]
	pub min_fee_for_0conf: FeeRate,
	/// The address where the LSP will send the funds if the order fails.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "unchecked_address_option")]
	pub refund_onchain_address: Option<Address>,
}

/// The state of a payment.
///
/// *Note*: Previously, the spec also knew a `CANCELLED` state for BOLT11 payments, which has since
/// been deprecated and `REFUNDED` should be used instead.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LSPS1PaymentState {
	/// A payment is expected.
	ExpectPayment,
	/// A sufficient payment has been received.
	Paid,
	/// The payment has been refunded.
	#[serde(alias = "CANCELLED")]
	Refunded,
}

/// Details regarding a detected on-chain payment.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1OnchainPayment {
	/// The outpoint of the payment.
	pub outpoint: String,
	/// The amount of satoshi paid.
	#[serde(with = "string_amount")]
	pub sat: u64,
	/// Indicates if the LSP regards the transaction as sufficiently confirmed.
	pub confirmed: bool,
}

/// Details regarding the state of an ordered channel.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1ChannelInfo {
	/// The datetime when the funding transaction has been published.
	pub funded_at: chrono::DateTime<Utc>,
	/// The outpoint of the funding transaction.
	pub funding_outpoint: OutPoint,
	/// The earliest datetime when the channel may be closed by the LSP.
	pub expires_at: chrono::DateTime<Utc>,
}

/// A request made to an LSP to retrieve information about an previously made order.
///
/// Please refer to the [bLIP-51 / LSPS1
/// specification](https://github.com/lightning/blips/blob/master/blip-0051.md#21-lsps1get_order)
/// for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS1GetOrderRequest {
	/// The id of the order.
	pub order_id: LSPS1OrderId,
}

/// An enum that captures all the valid JSON-RPC requests in the bLIP-51 / LSPS1 protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS1Request {
	/// A request to learn about the options supported by the LSP.
	GetInfo(LSPS1GetInfoRequest),
	/// A request to create a channel order.
	CreateOrder(LSPS1CreateOrderRequest),
	/// A request to query a previously created channel order.
	GetOrder(LSPS1GetOrderRequest),
}

/// An enum that captures all the valid JSON-RPC responses in the bLIP-51 / LSPS1 protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS1Response {
	/// A successful response to a [`LSPS1GetInfoRequest`].
	GetInfo(LSPS1GetInfoResponse),
	/// An error response to a [`LSPS1GetInfoRequest`].
	GetInfoError(LSPSResponseError),
	/// A successful response to a [`LSPS1CreateOrderRequest`].
	CreateOrder(LSPS1CreateOrderResponse),
	/// An error response to a [`LSPS1CreateOrderRequest`].
	CreateOrderError(LSPSResponseError),
	/// A successful response to a [`LSPS1GetOrderRequest`].
	GetOrder(LSPS1CreateOrderResponse),
	/// An error response to a [`LSPS1GetOrderRequest`].
	GetOrderError(LSPSResponseError),
}

/// An enum that captures all valid JSON-RPC messages in the bLIP-51 / LSPS1 protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS1Message {
	/// An LSPS1 JSON-RPC request.
	Request(LSPSRequestId, LSPS1Request),
	/// An LSPS1 JSON-RPC response.
	Response(LSPSRequestId, LSPS1Response),
}

impl TryFrom<LSPSMessage> for LSPS1Message {
	type Error = ();

	fn try_from(message: LSPSMessage) -> Result<Self, Self::Error> {
		if let LSPSMessage::LSPS1(message) = message {
			return Ok(message);
		}

		Err(())
	}
}

impl From<LSPS1Message> for LSPSMessage {
	fn from(message: LSPS1Message) -> Self {
		LSPSMessage::LSPS1(message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::alloc::string::ToString;

	#[test]
	fn options_supported_serialization() {
		let min_required_channel_confirmations = 0;
		let min_funding_confirms_within_blocks = 6;
		let supports_zero_channel_reserve = true;
		let max_channel_expiry_blocks = 144;
		let min_initial_client_balance_sat = 10_000_000;
		let max_initial_client_balance_sat = 100_000_000;
		let min_initial_lsp_balance_sat = 100_000;
		let max_initial_lsp_balance_sat = 100_000_000;
		let min_channel_balance_sat = 100_000;
		let max_channel_balance_sat = 100_000_000;

		let options_supported = LSPS1Options {
			min_required_channel_confirmations,
			min_funding_confirms_within_blocks,
			supports_zero_channel_reserve,
			max_channel_expiry_blocks,
			min_initial_client_balance_sat,
			max_initial_client_balance_sat,
			min_initial_lsp_balance_sat,
			max_initial_lsp_balance_sat,
			min_channel_balance_sat,
			max_channel_balance_sat,
		};

		let json_str = r#"{"max_channel_balance_sat":"100000000","max_channel_expiry_blocks":144,"max_initial_client_balance_sat":"100000000","max_initial_lsp_balance_sat":"100000000","min_channel_balance_sat":"100000","min_funding_confirms_within_blocks":6,"min_initial_client_balance_sat":"10000000","min_initial_lsp_balance_sat":"100000","min_required_channel_confirmations":0,"supports_zero_channel_reserve":true}"#;

		assert_eq!(json_str, serde_json::json!(options_supported).to_string());
		assert_eq!(options_supported, serde_json::from_str(json_str).unwrap());
	}

	#[test]
	fn parse_spec_test_vectors() {
		// Here, we simply assert that we're able to parse all examples given in LSPS1.
		let json_str = r#"{}"#;
		let _get_info_request: LSPS1GetInfoRequest = serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"min_required_channel_confirmations": 0,
			"min_funding_confirms_within_blocks" : 6,
			"supports_zero_channel_reserve": true,
			"max_channel_expiry_blocks": 20160,
			"min_initial_client_balance_sat": "20000",
			"max_initial_client_balance_sat": "100000000",
			"min_initial_lsp_balance_sat": "0",
			"max_initial_lsp_balance_sat": "100000000",
			"min_channel_balance_sat": "50000",
			"max_channel_balance_sat": "100000000"
		}"#;
		let _get_info_response: LSPS1GetInfoResponse = serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"lsp_balance_sat": "5000000",
			"client_balance_sat": "2000000",
			"required_channel_confirmations" : 0,
			"funding_confirms_within_blocks": 6,
			"channel_expiry_blocks": 144,
			"token": "",
			"refund_onchain_address": "bc1qvmsy0f3yyes6z9jvddk8xqwznndmdwapvrc0xrmhd3vqj5rhdrrq6hz49h",
			"announce_channel": true
		}"#;
		let _create_order_request: LSPS1CreateOrderRequest =
			serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"state" : "EXPECT_PAYMENT",
			"expires_at": "2025-01-01T00:00:00Z",
			"fee_total_sat": "8888",
			"order_total_sat": "200888",
			"invoice": "lnbc252u1p3aht9ysp580g4633gd2x9lc5al0wd8wx0mpn9748jeyz46kqjrpxn52uhfpjqpp5qgf67tcqmuqehzgjm8mzya90h73deafvr4m5705l5u5l4r05l8cqdpud3h8ymm4w3jhytnpwpczqmt0de6xsmre2pkxzm3qydmkzdjrdev9s7zhgfaqxqyjw5qcqpjrzjqt6xptnd85lpqnu2lefq4cx070v5cdwzh2xlvmdgnu7gqp4zvkus5zapryqqx9qqqyqqqqqqqqqqqcsq9q9qyysgqen77vu8xqjelum24hgjpgfdgfgx4q0nehhalcmuggt32japhjuksq9jv6eksjfnppm4hrzsgyxt8y8xacxut9qv3fpyetz8t7tsymygq8yzn05"
		}"#;
		let _bolt11_payment: LSPS1Bolt11PaymentInfo = serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"state": "EXPECT_PAYMENT",
			"expires_at": "2025-01-01T00:00:00Z",
			"fee_total_sat": "9999",
			"order_total_sat": "200999",
			"address": "bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr",
			"min_onchain_payment_confirmations": 1,
			"min_fee_for_0conf": 253
		}"#;
		let _onchain_payment: LSPS1OnchainPaymentInfo = serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"bolt11": {
				"state" : "EXPECT_PAYMENT",
				"expires_at": "2025-01-01T00:00:00Z",
				"fee_total_sat": "8888",
				"order_total_sat": "200888",
				"invoice": "lnbc252u1p3aht9ysp580g4633gd2x9lc5al0wd8wx0mpn9748jeyz46kqjrpxn52uhfpjqpp5qgf67tcqmuqehzgjm8mzya90h73deafvr4m5705l5u5l4r05l8cqdpud3h8ymm4w3jhytnpwpczqmt0de6xsmre2pkxzm3qydmkzdjrdev9s7zhgfaqxqyjw5qcqpjrzjqt6xptnd85lpqnu2lefq4cx070v5cdwzh2xlvmdgnu7gqp4zvkus5zapryqqx9qqqyqqqqqqqqqqqcsq9q9qyysgqen77vu8xqjelum24hgjpgfdgfgx4q0nehhalcmuggt32japhjuksq9jv6eksjfnppm4hrzsgyxt8y8xacxut9qv3fpyetz8t7tsymygq8yzn05"
			},
			"onchain": {
				"state": "EXPECT_PAYMENT",
				"expires_at": "2025-01-01T00:00:00Z",
				"fee_total_sat": "9999",
				"order_total_sat": "200999",
				"address": "bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr",
				"min_onchain_payment_confirmations": 1,
				"min_fee_for_0conf": 253
			}
		}"#;
		let _payment: LSPS1PaymentInfo = serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"order_id": "bb4b5d0a-8334-49d8-9463-90a6d413af7c",
			"lsp_balance_sat": "5000000",
			"client_balance_sat": "2000000",
			"required_channel_confirmations" : 0,
			"funding_confirms_within_blocks": 1,
			"channel_expiry_blocks": 12,
			"token": "",
			"created_at": "2012-04-23T18:25:43.511Z",
			"announce_channel": true,
			"order_state": "CREATED",
			"payment": {
				"bolt11": {
					"state": "EXPECT_PAYMENT",
					"expires_at": "2015-01-25T19:29:44.612Z",
					"fee_total_sat": "8888",
					"order_total_sat": "2008888",
					"invoice" : "lnbc252u1p3aht9ysp580g4633gd2x9lc5al0wd8wx0mpn9748jeyz46kqjrpxn52uhfpjqpp5qgf67tcqmuqehzgjm8mzya90h73deafvr4m5705l5u5l4r05l8cqdpud3h8ymm4w3jhytnpwpczqmt0de6xsmre2pkxzm3qydmkzdjrdev9s7zhgfaqxqyjw5qcqpjrzjqt6xptnd85lpqnu2lefq4cx070v5cdwzh2xlvmdgnu7gqp4zvkus5zapryqqx9qqqyqqqqqqqqqqqcsq9q9qyysgqen77vu8xqjelum24hgjpgfdgfgx4q0nehhalcmuggt32japhjuksq9jv6eksjfnppm4hrzsgyxt8y8xacxut9qv3fpyetz8t7tsymygq8yzn05"
				},
				"onchain": {
					"state": "EXPECT_PAYMENT",
					"expires_at": "2015-01-25T19:29:44.612Z",
					"fee_total_sat": "9999",
					"order_total_sat": "2009999",
					"address" : "bc1p5uvtaxzkjwvey2tfy49k5vtqfpjmrgm09cvs88ezyy8h2zv7jhas9tu4yr",
					"min_fee_for_0conf": 253,
					"min_onchain_payment_confirmations": 0,
					"refund_onchain_address": "bc1qvmsy0f3yyes6z9jvddk8xqwznndmdwapvrc0xrmhd3vqj5rhdrrq6hz49h"
				}
			},
			"channel": null
		}"#;
		let _create_order_response: LSPS1CreateOrderResponse =
			serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"order_id": "bb4b5d0a-8334-49d8-9463-90a6d413af7c"
		}"#;
		let _get_order_request: LSPS1GetOrderRequest = serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"funded_at": "2012-04-23T18:25:43.511Z",
			"funding_outpoint": "0301e0480b374b32851a9462db29dc19fe830a7f7d7a88b81612b9d42099c0ae:0",
			"expires_at": "2012-04-23T18:25:43.511Z"
		}"#;
		let _channel: LSPS1ChannelInfo = serde_json::from_str(json_str).unwrap();

		let json_str = r#""CANCELLED""#;
		let payment_state: LSPS1PaymentState = serde_json::from_str(json_str).unwrap();
		assert_eq!(payment_state, LSPS1PaymentState::Refunded);

		let json_str = r#""REFUNDED""#;
		let payment_state: LSPS1PaymentState = serde_json::from_str(json_str).unwrap();
		assert_eq!(payment_state, LSPS1PaymentState::Refunded);
	}
}
