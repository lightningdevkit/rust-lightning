//! Message, request, and other primitive types used to implement LSPS2.

use core::convert::TryFrom;

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::lsps0::ser::{
	string_amount, string_amount_option, LSPSMessage, RequestId, ResponseError,
};
use crate::prelude::{String, Vec};
use crate::utils;

pub(crate) const LSPS2_GET_INFO_METHOD_NAME: &str = "lsps2.get_info";
pub(crate) const LSPS2_BUY_METHOD_NAME: &str = "lsps2.buy";

pub(crate) const LSPS2_GET_INFO_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE: i32 = 200;

pub(crate) const LSPS2_BUY_REQUEST_INVALID_OPENING_FEE_PARAMS_ERROR_CODE: i32 = 201;
pub(crate) const LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_SMALL_ERROR_CODE: i32 = 202;
pub(crate) const LSPS2_BUY_REQUEST_PAYMENT_SIZE_TOO_LARGE_ERROR_CODE: i32 = 203;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
/// A request made to an LSP to learn their current channel fees and parameters.
pub struct GetInfoRequest {
	/// An optional token to provide to the LSP.
	pub token: Option<String>,
}

/// Fees and parameters for a JIT Channel without the promise.
///
/// The promise will be calculated automatically for the LSP and this type converted
/// into an [`OpeningFeeParams`] for transit over the wire.
pub struct RawOpeningFeeParams {
	/// The minimum fee required for the channel open.
	pub min_fee_msat: u64,
	/// A fee proportional to the size of the initial payment.
	pub proportional: u32,
	/// An [`ISO8601`](https://www.iso.org/iso-8601-date-and-time-format.html) formatted date for which these params are valid.
	pub valid_until: chrono::DateTime<Utc>,
	/// The number of blocks after confirmation that the LSP promises it will keep the channel alive without closing.
	pub min_lifetime: u32,
	/// The maximum number of blocks that the client is allowed to set its `to_self_delay` parameter.
	pub max_client_to_self_delay: u32,
	/// The minimum payment size that the LSP will accept when opening a channel.
	pub min_payment_size_msat: u64,
	/// The maximum payment size that the LSP will accept when opening a channel.
	pub max_payment_size_msat: u64,
}

impl RawOpeningFeeParams {
	pub(crate) fn into_opening_fee_params(self, promise_secret: &[u8; 32]) -> OpeningFeeParams {
		let mut hmac = HmacEngine::<Sha256>::new(promise_secret);
		hmac.input(&self.min_fee_msat.to_be_bytes());
		hmac.input(&self.proportional.to_be_bytes());
		hmac.input(self.valid_until.to_rfc3339().as_bytes());
		hmac.input(&self.min_lifetime.to_be_bytes());
		hmac.input(&self.max_client_to_self_delay.to_be_bytes());
		hmac.input(&self.min_payment_size_msat.to_be_bytes());
		hmac.input(&self.max_payment_size_msat.to_be_bytes());
		let promise_bytes = Hmac::from_engine(hmac).to_byte_array();
		let promise = utils::hex_str(&promise_bytes[..]);
		OpeningFeeParams {
			min_fee_msat: self.min_fee_msat,
			proportional: self.proportional,
			valid_until: self.valid_until.clone(),
			min_lifetime: self.min_lifetime,
			max_client_to_self_delay: self.max_client_to_self_delay,
			min_payment_size_msat: self.min_payment_size_msat,
			max_payment_size_msat: self.max_payment_size_msat,
			promise,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
/// Fees and parameters for a JIT Channel including the promise.
///
/// The promise is an HMAC calculated using a secret known to the LSP and the rest of the fields as input.
/// It exists so the LSP can verify the authenticity of a client provided OpeningFeeParams by recalculating
/// the promise using the secret. Once verified they can be confident it was not modified by the client.
pub struct OpeningFeeParams {
	/// The minimum fee required for the channel open.
	#[serde(with = "string_amount")]
	pub min_fee_msat: u64,
	/// A fee proportional to the size of the initial payment.
	pub proportional: u32,
	/// An [`ISO8601`](https://www.iso.org/iso-8601-date-and-time-format.html) formatted date for which these params are valid.
	pub valid_until: chrono::DateTime<Utc>,
	/// The number of blocks after confirmation that the LSP promises it will keep the channel alive without closing.
	pub min_lifetime: u32,
	/// The maximum number of blocks that the client is allowed to set its `to_self_delay` parameter.
	pub max_client_to_self_delay: u32,
	/// The minimum payment size that the LSP will accept when opening a channel.
	#[serde(with = "string_amount")]
	pub min_payment_size_msat: u64,
	/// The maximum payment size that the LSP will accept when opening a channel.
	#[serde(with = "string_amount")]
	pub max_payment_size_msat: u64,
	/// The HMAC used to verify the authenticity of these parameters.
	pub promise: String,
}

/// A response to a [`GetInfoRequest`]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct GetInfoResponse {
	/// A set of opening fee parameters.
	pub opening_fee_params_menu: Vec<OpeningFeeParams>,
}

/// A request to buy a JIT channel.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BuyRequest {
	/// The fee parameters you would like to use.
	pub opening_fee_params: OpeningFeeParams,
	/// The size of the initial payment you expect to receive.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "string_amount_option")]
	pub payment_size_msat: Option<u64>,
}

/// A newtype that holds a `short_channel_id` in human readable format of BBBxTTTx000.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct InterceptScid(String);

impl From<u64> for InterceptScid {
	fn from(scid: u64) -> Self {
		let block = utils::block_from_scid(&scid);
		let tx_index = utils::tx_index_from_scid(&scid);
		let vout = utils::vout_from_scid(&scid);

		Self(format!("{}x{}x{}", block, tx_index, vout))
	}
}

impl InterceptScid {
	/// Try to convert a [`InterceptScid`] into a u64 used by LDK.
	pub fn to_scid(&self) -> Result<u64, ()> {
		utils::scid_from_human_readable_string(&self.0)
	}
}

/// A response to a [`BuyRequest`].
///
/// Includes information needed to construct an invoice.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BuyResponse {
	/// The intercept short channel id used by LSP to identify need to open channel.
	pub jit_channel_scid: InterceptScid,
	/// The locktime expiry delta the lsp requires.
	pub lsp_cltv_expiry_delta: u32,
	/// A flag that indicates who is trusting who.
	#[serde(default)]
	pub client_trusts_lsp: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An enum that captures all the valid JSON-RPC requests in the LSPS2 protocol.
pub enum LSPS2Request {
	/// A request to learn an LSP's channel fees and parameters.
	GetInfo(GetInfoRequest),
	/// A request to buy a JIT channel from an LSP.
	Buy(BuyRequest),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An enum that captures all the valid JSON-RPC responses in the LSPS2 protocol.
pub enum LSPS2Response {
	/// A successful response to a [`LSPS2Request::GetInfo`] request.
	GetInfo(GetInfoResponse),
	/// An error response to a [`LSPS2Request::GetInfo`] request.
	GetInfoError(ResponseError),
	/// A successful response to a [`LSPS2Request::Buy`] request.
	Buy(BuyResponse),
	/// An error response to a [`LSPS2Request::Buy`] request.
	BuyError(ResponseError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// An enum that captures all valid JSON-RPC messages in the LSPS2 protocol.
pub enum LSPS2Message {
	/// An LSPS2 JSON-RPC request.
	Request(RequestId, LSPS2Request),
	/// An LSPS2 JSON-RPC response.
	Response(RequestId, LSPS2Response),
}

impl TryFrom<LSPSMessage> for LSPS2Message {
	type Error = ();

	fn try_from(message: LSPSMessage) -> Result<Self, Self::Error> {
		if let LSPSMessage::LSPS2(message) = message {
			return Ok(message);
		}

		Err(())
	}
}

impl From<LSPS2Message> for LSPSMessage {
	fn from(message: LSPS2Message) -> Self {
		LSPSMessage::LSPS2(message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::alloc::string::ToString;
	use crate::lsps2::utils::is_valid_opening_fee_params;

	#[test]
	fn into_opening_fee_params_produces_valid_promise() {
		let min_fee_msat = 100;
		let proportional = 21;
		let valid_until: chrono::DateTime<Utc> =
			chrono::DateTime::parse_from_rfc3339("2035-05-20T08:30:45Z").unwrap().into();
		let min_lifetime = 144;
		let max_client_to_self_delay = 128;
		let min_payment_size_msat = 1;
		let max_payment_size_msat = 100_000_000;

		let raw = RawOpeningFeeParams {
			min_fee_msat,
			proportional,
			valid_until: valid_until.clone().into(),
			min_lifetime,
			max_client_to_self_delay,
			min_payment_size_msat,
			max_payment_size_msat,
		};

		let promise_secret = [1u8; 32];

		let opening_fee_params = raw.into_opening_fee_params(&promise_secret);

		assert_eq!(opening_fee_params.min_fee_msat, min_fee_msat);
		assert_eq!(opening_fee_params.proportional, proportional);
		assert_eq!(opening_fee_params.valid_until, valid_until);
		assert_eq!(opening_fee_params.min_lifetime, min_lifetime);
		assert_eq!(opening_fee_params.max_client_to_self_delay, max_client_to_self_delay);
		assert_eq!(opening_fee_params.min_payment_size_msat, min_payment_size_msat);
		assert_eq!(opening_fee_params.max_payment_size_msat, max_payment_size_msat);

		assert!(is_valid_opening_fee_params(&opening_fee_params, &promise_secret));
	}

	#[test]
	fn changing_single_field_produced_invalid_params() {
		let min_fee_msat = 100;
		let proportional = 21;
		let valid_until = chrono::DateTime::parse_from_rfc3339("2035-05-20T08:30:45Z").unwrap();
		let min_lifetime = 144;
		let max_client_to_self_delay = 128;
		let min_payment_size_msat = 1;
		let max_payment_size_msat = 100_000_000;

		let raw = RawOpeningFeeParams {
			min_fee_msat,
			proportional,
			valid_until: valid_until.into(),
			min_lifetime,
			max_client_to_self_delay,
			min_payment_size_msat,
			max_payment_size_msat,
		};

		let promise_secret = [1u8; 32];

		let mut opening_fee_params = raw.into_opening_fee_params(&promise_secret);
		opening_fee_params.min_fee_msat = min_fee_msat + 1;
		assert!(!is_valid_opening_fee_params(&opening_fee_params, &promise_secret));
	}

	#[test]
	fn wrong_secret_produced_invalid_params() {
		let min_fee_msat = 100;
		let proportional = 21;
		let valid_until = chrono::DateTime::parse_from_rfc3339("2035-05-20T08:30:45Z").unwrap();
		let min_lifetime = 144;
		let max_client_to_self_delay = 128;
		let min_payment_size_msat = 1;
		let max_payment_size_msat = 100_000_000;

		let raw = RawOpeningFeeParams {
			min_fee_msat,
			proportional,
			valid_until: valid_until.into(),
			min_lifetime,
			max_client_to_self_delay,
			min_payment_size_msat,
			max_payment_size_msat,
		};

		let promise_secret = [1u8; 32];
		let other_secret = [2u8; 32];

		let opening_fee_params = raw.into_opening_fee_params(&promise_secret);
		assert!(!is_valid_opening_fee_params(&opening_fee_params, &other_secret));
	}

	#[test]
	#[cfg(feature = "std")]
	// TODO: We need to find a way to check expiry times in no-std builds.
	fn expired_params_produces_invalid_params() {
		let min_fee_msat = 100;
		let proportional = 21;
		let valid_until = chrono::DateTime::parse_from_rfc3339("2023-05-20T08:30:45Z").unwrap();
		let min_lifetime = 144;
		let max_client_to_self_delay = 128;
		let min_payment_size_msat = 1;
		let max_payment_size_msat = 100_000_000;

		let raw = RawOpeningFeeParams {
			min_fee_msat,
			proportional,
			valid_until: valid_until.into(),
			min_lifetime,
			max_client_to_self_delay,
			min_payment_size_msat,
			max_payment_size_msat,
		};

		let promise_secret = [1u8; 32];

		let opening_fee_params = raw.into_opening_fee_params(&promise_secret);
		assert!(!is_valid_opening_fee_params(&opening_fee_params, &promise_secret));
	}

	#[test]
	fn buy_request_serialization() {
		let min_fee_msat = 100;
		let proportional = 21;
		let valid_until = chrono::DateTime::parse_from_rfc3339("2023-05-20T08:30:45Z").unwrap();
		let min_lifetime = 144;
		let max_client_to_self_delay = 128;
		let min_payment_size_msat = 1;
		let max_payment_size_msat = 100_000_000;

		let raw = RawOpeningFeeParams {
			min_fee_msat,
			proportional,
			valid_until: valid_until.into(),
			min_lifetime,
			max_client_to_self_delay,
			min_payment_size_msat,
			max_payment_size_msat,
		};

		let promise_secret = [1u8; 32];

		let opening_fee_params = raw.into_opening_fee_params(&promise_secret);
		let json_str = r#"{"max_client_to_self_delay":128,"max_payment_size_msat":"100000000","min_fee_msat":"100","min_lifetime":144,"min_payment_size_msat":"1","promise":"1134a5c51e3ba2e8f4259610d5e12c1bf4c50ddcd3f8af563e0a00d1fff41dea","proportional":21,"valid_until":"2023-05-20T08:30:45Z"}"#;
		assert_eq!(json_str, serde_json::json!(opening_fee_params).to_string());
		assert_eq!(opening_fee_params, serde_json::from_str(json_str).unwrap());

		let payment_size_msat = Some(1234);
		let buy_request_fixed =
			BuyRequest { opening_fee_params: opening_fee_params.clone(), payment_size_msat };
		let json_str = r#"{"opening_fee_params":{"max_client_to_self_delay":128,"max_payment_size_msat":"100000000","min_fee_msat":"100","min_lifetime":144,"min_payment_size_msat":"1","promise":"1134a5c51e3ba2e8f4259610d5e12c1bf4c50ddcd3f8af563e0a00d1fff41dea","proportional":21,"valid_until":"2023-05-20T08:30:45Z"},"payment_size_msat":"1234"}"#;
		assert_eq!(json_str, serde_json::json!(buy_request_fixed).to_string());
		assert_eq!(buy_request_fixed, serde_json::from_str(json_str).unwrap());

		let payment_size_msat = None;
		let buy_request_variable = BuyRequest { opening_fee_params, payment_size_msat };

		// Check we skip serialization if payment_size_msat is None.
		let json_str = r#"{"opening_fee_params":{"max_client_to_self_delay":128,"max_payment_size_msat":"100000000","min_fee_msat":"100","min_lifetime":144,"min_payment_size_msat":"1","promise":"1134a5c51e3ba2e8f4259610d5e12c1bf4c50ddcd3f8af563e0a00d1fff41dea","proportional":21,"valid_until":"2023-05-20T08:30:45Z"}}"#;
		assert_eq!(json_str, serde_json::json!(buy_request_variable).to_string());
		assert_eq!(buy_request_variable, serde_json::from_str(json_str).unwrap());

		// Check we still deserialize correctly if payment_size_msat is 'null'.
		let json_str = r#"{"opening_fee_params":{"max_client_to_self_delay":128,"max_payment_size_msat":"100000000","min_fee_msat":"100","min_lifetime":144,"min_payment_size_msat":"1","promise":"1134a5c51e3ba2e8f4259610d5e12c1bf4c50ddcd3f8af563e0a00d1fff41dea","proportional":21,"valid_until":"2023-05-20T08:30:45Z"},"payment_size_msat":null}"#;
		assert_eq!(buy_request_variable, serde_json::from_str(json_str).unwrap());
	}

	#[test]
	fn parse_spec_test_vectors() {
		// Here, we simply assert that we're able to parse all examples given in LSPS2.
		let json_str = r#"{
			"opening_fee_params_menu": [
			{
				"min_fee_msat": "546000",
				"proportional": 1200,
				"valid_until": "2023-02-23T08:47:30.511Z",
				"min_lifetime": 1008,
				"max_client_to_self_delay": 2016,
				"min_payment_size_msat": "1000",
				"max_payment_size_msat": "1000000",
				"promise": "abcdefghijklmnopqrstuvwxyz"
			},
			{
				"min_fee_msat": "1092000",
				"proportional": 2400,
				"valid_until": "2023-02-27T21:23:57.984Z",
				"min_lifetime": 1008,
				"max_client_to_self_delay": 2016,
				"min_payment_size_msat": "1000",
				"max_payment_size_msat": "1000000",
				"promise": "abcdefghijklmnopqrstuvwxyz"
			}
			]
		}"#;
		let _get_info_response: GetInfoResponse = serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"opening_fee_params": {
				"min_fee_msat": "546000",
				"proportional": 1200,
				"valid_until": "2023-02-23T08:47:30.511Z",
				"min_lifetime": 1008,
				"max_client_to_self_delay": 2016,
				"min_payment_size_msat": "1000",
				"max_payment_size_msat": "1000000",
				"promise": "abcdefghijklmnopqrstuvwxyz"
			},
			"payment_size_msat": "42000"
		}"#;
		let _buy_request: BuyRequest = serde_json::from_str(json_str).unwrap();

		let json_str = r#"{
			"jit_channel_scid": "29451x4815x1",
			"lsp_cltv_expiry_delta" : 144,
			"client_trusts_lsp": false
		}"#;
		let _buy_response: BuyResponse = serde_json::from_str(json_str).unwrap();
	}
}
