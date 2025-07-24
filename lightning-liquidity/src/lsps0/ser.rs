//! Contains basic data types that allow for the (de-)seralization of LSPS messages in the JSON-RPC 2.0 format.
//!
//! Please refer to the [bLIP-50 / LSPS0
//! specification](https://github.com/lightning/blips/blob/master/blip-0050.md) for more
//! information.

use alloc::string::String;

use core::fmt::{self, Display};
use core::str::FromStr;

use crate::lsps0::msgs::{
	LSPS0ListProtocolsRequest, LSPS0Message, LSPS0Request, LSPS0Response,
	LSPS0_LISTPROTOCOLS_METHOD_NAME,
};

use crate::lsps1::msgs::{
	LSPS1Message, LSPS1Request, LSPS1Response, LSPS1_CREATE_ORDER_METHOD_NAME,
	LSPS1_GET_INFO_METHOD_NAME, LSPS1_GET_ORDER_METHOD_NAME,
};
use crate::lsps2::msgs::{
	LSPS2Message, LSPS2Request, LSPS2Response, LSPS2_BUY_METHOD_NAME, LSPS2_GET_INFO_METHOD_NAME,
};
use crate::lsps5::msgs::{
	LSPS5Message, LSPS5Request, LSPS5Response, LSPS5_LIST_WEBHOOKS_METHOD_NAME,
	LSPS5_REMOVE_WEBHOOK_METHOD_NAME, LSPS5_SET_WEBHOOK_METHOD_NAME,
};

use crate::prelude::HashMap;

use lightning::ln::msgs::{DecodeError, LightningError};
use lightning::ln::wire;
use lightning::util::ser::{LengthLimitedRead, LengthReadable, WithoutLength};

use bitcoin::secp256k1::PublicKey;

use core::time::Duration;
#[cfg(feature = "time")]
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;

pub(crate) const LSPS_MESSAGE_SERIALIZED_STRUCT_NAME: &str = "LSPSMessage";
pub(crate) const JSONRPC_FIELD_KEY: &str = "jsonrpc";
pub(crate) const JSONRPC_FIELD_VALUE: &str = "2.0";
pub(crate) const JSONRPC_METHOD_FIELD_KEY: &str = "method";
pub(crate) const JSONRPC_ID_FIELD_KEY: &str = "id";
pub(crate) const JSONRPC_PARAMS_FIELD_KEY: &str = "params";
pub(crate) const JSONRPC_RESULT_FIELD_KEY: &str = "result";
pub(crate) const JSONRPC_ERROR_FIELD_KEY: &str = "error";
pub(crate) const JSONRPC_INVALID_MESSAGE_ERROR_CODE: i32 = -32700;
pub(crate) const JSONRPC_INVALID_MESSAGE_ERROR_MESSAGE: &str = "parse error";
pub(crate) const JSONRPC_INTERNAL_ERROR_ERROR_CODE: i32 = -32603;
pub(crate) const JSONRPC_INTERNAL_ERROR_ERROR_MESSAGE: &str = "Internal error";

pub(crate) const LSPS0_CLIENT_REJECTED_ERROR_CODE: i32 = 1;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum LSPSMethod {
	LSPS0ListProtocols,
	LSPS1GetInfo,
	LSPS1GetOrder,
	LSPS1CreateOrder,
	LSPS2GetInfo,
	LSPS2Buy,
	LSPS5SetWebhook,
	LSPS5ListWebhooks,
	LSPS5RemoveWebhook,
}

impl LSPSMethod {
	fn as_static_str(&self) -> &'static str {
		match self {
			Self::LSPS0ListProtocols => LSPS0_LISTPROTOCOLS_METHOD_NAME,
			Self::LSPS1GetInfo => LSPS1_GET_INFO_METHOD_NAME,
			Self::LSPS1CreateOrder => LSPS1_CREATE_ORDER_METHOD_NAME,
			Self::LSPS1GetOrder => LSPS1_GET_ORDER_METHOD_NAME,
			Self::LSPS2GetInfo => LSPS2_GET_INFO_METHOD_NAME,
			Self::LSPS2Buy => LSPS2_BUY_METHOD_NAME,
			Self::LSPS5SetWebhook => LSPS5_SET_WEBHOOK_METHOD_NAME,
			Self::LSPS5ListWebhooks => LSPS5_LIST_WEBHOOKS_METHOD_NAME,
			Self::LSPS5RemoveWebhook => LSPS5_REMOVE_WEBHOOK_METHOD_NAME,
		}
	}
}

impl FromStr for LSPSMethod {
	type Err = &'static str;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			LSPS0_LISTPROTOCOLS_METHOD_NAME => Ok(Self::LSPS0ListProtocols),
			LSPS1_GET_INFO_METHOD_NAME => Ok(Self::LSPS1GetInfo),
			LSPS1_CREATE_ORDER_METHOD_NAME => Ok(Self::LSPS1CreateOrder),
			LSPS1_GET_ORDER_METHOD_NAME => Ok(Self::LSPS1GetOrder),
			LSPS2_GET_INFO_METHOD_NAME => Ok(Self::LSPS2GetInfo),
			LSPS2_BUY_METHOD_NAME => Ok(Self::LSPS2Buy),
			LSPS5_SET_WEBHOOK_METHOD_NAME => Ok(Self::LSPS5SetWebhook),
			LSPS5_LIST_WEBHOOKS_METHOD_NAME => Ok(Self::LSPS5ListWebhooks),
			LSPS5_REMOVE_WEBHOOK_METHOD_NAME => Ok(Self::LSPS5RemoveWebhook),
			_ => Err(&"Unknown method name"),
		}
	}
}

impl From<&LSPS0Request> for LSPSMethod {
	fn from(value: &LSPS0Request) -> Self {
		match value {
			LSPS0Request::ListProtocols(_) => Self::LSPS0ListProtocols,
		}
	}
}

impl From<&LSPS1Request> for LSPSMethod {
	fn from(value: &LSPS1Request) -> Self {
		match value {
			LSPS1Request::GetInfo(_) => Self::LSPS1GetInfo,
			LSPS1Request::CreateOrder(_) => Self::LSPS1CreateOrder,
			LSPS1Request::GetOrder(_) => Self::LSPS1GetOrder,
		}
	}
}

impl From<&LSPS2Request> for LSPSMethod {
	fn from(value: &LSPS2Request) -> Self {
		match value {
			LSPS2Request::GetInfo(_) => Self::LSPS2GetInfo,
			LSPS2Request::Buy(_) => Self::LSPS2Buy,
		}
	}
}

impl From<&LSPS5Request> for LSPSMethod {
	fn from(value: &LSPS5Request) -> Self {
		match value {
			LSPS5Request::SetWebhook(_) => Self::LSPS5SetWebhook,
			LSPS5Request::ListWebhooks(_) => Self::LSPS5ListWebhooks,
			LSPS5Request::RemoveWebhook(_) => Self::LSPS5RemoveWebhook,
		}
	}
}

impl<'de> Deserialize<'de> for LSPSMethod {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = <&str>::deserialize(deserializer)?;
		FromStr::from_str(&s).map_err(de::Error::custom)
	}
}

impl Serialize for LSPSMethod {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&self.as_static_str())
	}
}

/// The Lightning message type id for LSPS messages.
pub const LSPS_MESSAGE_TYPE_ID: u16 = 37913;

/// A trait used to implement a specific LSPS protocol.
///
/// The messages the protocol uses need to be able to be mapped
/// from and into [`LSPSMessage`].
pub(crate) trait LSPSProtocolMessageHandler {
	type ProtocolMessage: TryFrom<LSPSMessage> + Into<LSPSMessage>;
	const PROTOCOL_NUMBER: Option<u16>;

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError>;
}

/// Lightning message type used by LSPS protocols.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawLSPSMessage {
	/// The raw string payload that holds the actual message.
	pub payload: String,
}

// We encode `RawLSPSMessage`'s payload without a length prefix as LSPS0 expects it to be the
// remainder of the object.
impl lightning::util::ser::Writeable for RawLSPSMessage {
	fn write<W: lightning::util::ser::Writer>(
		&self, w: &mut W,
	) -> Result<(), lightning::io::Error> {
		WithoutLength(&self.payload).write(w)?;
		Ok(())
	}
}

impl LengthReadable for RawLSPSMessage {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let payload_without_length: WithoutLength<String> =
			LengthReadable::read_from_fixed_length_buffer(r)?;
		Ok(Self { payload: payload_without_length.0 })
	}
}

impl wire::Type for RawLSPSMessage {
	fn type_id(&self) -> u16 {
		LSPS_MESSAGE_TYPE_ID
	}
}

/// A JSON-RPC request's `id`.
///
/// Please refer to the [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification#request_object) for
/// more information.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct LSPSRequestId(pub String);

/// An object representing datetimes as described in bLIP-50 / LSPS0.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct LSPSDateTime(pub chrono::DateTime<chrono::Utc>);

impl LSPSDateTime {
	/// Returns the LSPSDateTime as RFC3339 formatted string.
	pub fn to_rfc3339(&self) -> String {
		self.0.to_rfc3339()
	}

	/// Returns if the given time is in the past.
	#[cfg(feature = "time")]
	pub fn is_past(&self) -> bool {
		let now_seconds_since_epoch = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("system clock to be ahead of the unix epoch")
			.as_secs();
		let datetime_seconds_since_epoch =
			self.0.timestamp().try_into().expect("expiration to be ahead of unix epoch");
		now_seconds_since_epoch > datetime_seconds_since_epoch
	}

	/// Returns the time in seconds since the unix epoch.
	pub fn abs_diff(&self, other: &Self) -> u64 {
		self.0.timestamp().abs_diff(other.0.timestamp())
	}

	/// Returns the time in seconds since the unix epoch.
	pub fn new_from_duration_since_epoch(duration: Duration) -> Self {
		Self(chrono::DateTime::UNIX_EPOCH + duration)
	}
}

impl FromStr for LSPSDateTime {
	type Err = ();
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let datetime = chrono::DateTime::parse_from_rfc3339(s).map_err(|_| ())?;
		Ok(Self(datetime.into()))
	}
}

impl Display for LSPSDateTime {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.to_rfc3339())
	}
}

/// An error returned in response to an JSON-RPC request.
///
/// Please refer to the [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification#error_object) for
/// more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPSResponseError {
	/// A number that indicates the error type that occurred.
	pub code: i32,
	/// A string providing a short description of the error.
	pub message: String,
	/// A primitive or structured value that contains additional information about the error.
	pub data: Option<String>,
}

/// A (de-)serializable LSPS message allowing to be sent over the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPSMessage {
	/// An invalid variant.
	Invalid(LSPSResponseError),
	/// An LSPS0 message.
	LSPS0(LSPS0Message),
	/// An LSPS1 message.
	LSPS1(LSPS1Message),
	/// An LSPS2 message.
	LSPS2(LSPS2Message),
	/// An LSPS5 message.
	LSPS5(LSPS5Message),
}

impl LSPSMessage {
	/// A constructor returning an `LSPSMessage` from a raw JSON string.
	///
	/// The given `request_id_to_method` associates request ids with method names, as response objects
	/// don't carry the latter.
	pub(crate) fn from_str_with_id_map(
		json_str: &str, request_id_to_method_map: &mut HashMap<LSPSRequestId, LSPSMethod>,
	) -> Result<Self, serde_json::Error> {
		let deserializer = &mut serde_json::Deserializer::from_str(json_str);
		let visitor = LSPSMessageVisitor { request_id_to_method_map };
		deserializer.deserialize_any(visitor)
	}

	/// Returns the request id and the method.
	pub(crate) fn get_request_id_and_method(&self) -> Option<(LSPSRequestId, LSPSMethod)> {
		match self {
			LSPSMessage::LSPS0(LSPS0Message::Request(request_id, request)) => {
				Some((LSPSRequestId(request_id.0.clone()), request.into()))
			},
			LSPSMessage::LSPS1(LSPS1Message::Request(request_id, request)) => {
				Some((LSPSRequestId(request_id.0.clone()), request.into()))
			},
			LSPSMessage::LSPS2(LSPS2Message::Request(request_id, request)) => {
				Some((LSPSRequestId(request_id.0.clone()), request.into()))
			},
			LSPSMessage::LSPS5(LSPS5Message::Request(request_id, request)) => {
				Some((LSPSRequestId(request_id.0.clone()), request.into()))
			},
			_ => None,
		}
	}
}

impl Serialize for LSPSMessage {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		let mut jsonrpc_object =
			serializer.serialize_struct(LSPS_MESSAGE_SERIALIZED_STRUCT_NAME, 3)?;

		jsonrpc_object.serialize_field(JSONRPC_FIELD_KEY, JSONRPC_FIELD_VALUE)?;

		match self {
			LSPSMessage::LSPS0(LSPS0Message::Request(request_id, request)) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &request_id.0)?;
				jsonrpc_object
					.serialize_field(JSONRPC_METHOD_FIELD_KEY, &LSPSMethod::from(request))?;

				match request {
					LSPS0Request::ListProtocols(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
				};
			},
			LSPSMessage::LSPS0(LSPS0Message::Response(request_id, response)) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &request_id.0)?;

				match response {
					LSPS0Response::ListProtocols(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?;
					},
					LSPS0Response::ListProtocolsError(error) => {
						jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, error)?;
					},
				}
			},
			LSPSMessage::LSPS1(LSPS1Message::Request(request_id, request)) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &request_id.0)?;
				jsonrpc_object
					.serialize_field(JSONRPC_METHOD_FIELD_KEY, &LSPSMethod::from(request))?;

				match request {
					LSPS1Request::GetInfo(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
					LSPS1Request::CreateOrder(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
					LSPS1Request::GetOrder(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
				}
			},
			LSPSMessage::LSPS1(LSPS1Message::Response(request_id, response)) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &request_id.0)?;

				match response {
					LSPS1Response::GetInfo(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?
					},
					LSPS1Response::GetInfoError(error) => {
						jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, error)?
					},
					LSPS1Response::CreateOrder(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?
					},
					LSPS1Response::CreateOrderError(error) => {
						jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, error)?
					},
					LSPS1Response::GetOrder(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?
					},
					LSPS1Response::GetOrderError(error) => {
						jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, error)?
					},
				}
			},
			LSPSMessage::LSPS2(LSPS2Message::Request(request_id, request)) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &request_id.0)?;
				jsonrpc_object
					.serialize_field(JSONRPC_METHOD_FIELD_KEY, &LSPSMethod::from(request))?;

				match request {
					LSPS2Request::GetInfo(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
					LSPS2Request::Buy(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
				}
			},
			LSPSMessage::LSPS2(LSPS2Message::Response(request_id, response)) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &request_id.0)?;

				match response {
					LSPS2Response::GetInfo(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?
					},
					LSPS2Response::GetInfoError(error) => {
						jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, error)?
					},
					LSPS2Response::Buy(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?
					},
					LSPS2Response::BuyError(error) => {
						jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, error)?
					},
				}
			},
			LSPSMessage::Invalid(error) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &serde_json::Value::Null)?;
				jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, &error)?;
			},
			LSPSMessage::LSPS5(LSPS5Message::Request(request_id, request)) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &request_id.0)?;
				jsonrpc_object
					.serialize_field(JSONRPC_METHOD_FIELD_KEY, &LSPSMethod::from(request))?;

				match request {
					LSPS5Request::SetWebhook(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
					LSPS5Request::ListWebhooks(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
					LSPS5Request::RemoveWebhook(params) => {
						jsonrpc_object.serialize_field(JSONRPC_PARAMS_FIELD_KEY, params)?
					},
				}
			},
			LSPSMessage::LSPS5(LSPS5Message::Response(request_id, response)) => {
				jsonrpc_object.serialize_field(JSONRPC_ID_FIELD_KEY, &request_id.0)?;

				match response {
					LSPS5Response::SetWebhook(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?
					},
					LSPS5Response::SetWebhookError(error) => {
						jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, error)?
					},
					LSPS5Response::ListWebhooks(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?
					},
					LSPS5Response::RemoveWebhook(result) => {
						jsonrpc_object.serialize_field(JSONRPC_RESULT_FIELD_KEY, result)?
					},
					LSPS5Response::RemoveWebhookError(error) => {
						jsonrpc_object.serialize_field(JSONRPC_ERROR_FIELD_KEY, error)?
					},
				}
			},
		}

		jsonrpc_object.end()
	}
}

struct LSPSMessageVisitor<'a> {
	request_id_to_method_map: &'a mut HashMap<LSPSRequestId, LSPSMethod>,
}

impl<'de, 'a> Visitor<'de> for LSPSMessageVisitor<'a> {
	type Value = LSPSMessage;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("JSON-RPC object")
	}

	fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
	where
		A: MapAccess<'de>,
	{
		let mut id: Option<LSPSRequestId> = None;
		let mut method: Option<LSPSMethod> = None;
		let mut params = None;
		let mut result = None;
		let mut error: Option<LSPSResponseError> = None;

		while let Some(key) = map.next_key()? {
			match key {
				"id" => {
					id = map.next_value()?;
				},
				"method" => {
					method = Some(map.next_value()?);
				},
				"params" => {
					params = Some(map.next_value()?);
				},
				"result" => {
					result = Some(map.next_value()?);
				},
				"error" => {
					error = Some(map.next_value()?);
				},
				_ => {
					let _: serde_json::Value = map.next_value()?;
				},
			}
		}

		let id = match id {
			Some(id) => id,
			None => {
				if let Some(method) = method {
					return Err(de::Error::custom(format!(
						"Received unknown notification: {}",
						method.as_static_str()
					)));
				} else {
					if let Some(error) = error {
						if error.code == JSONRPC_INVALID_MESSAGE_ERROR_CODE {
							return Ok(LSPSMessage::Invalid(error));
						}
					}

					return Err(de::Error::custom("Received unknown error message"));
				}
			},
		};

		match method {
			Some(method) => match method {
				LSPSMethod::LSPS0ListProtocols => Ok(LSPSMessage::LSPS0(LSPS0Message::Request(
					id,
					LSPS0Request::ListProtocols(LSPS0ListProtocolsRequest {}),
				))),
				LSPSMethod::LSPS1GetInfo => {
					let request = serde_json::from_value(params.unwrap_or(json!({})))
						.map_err(de::Error::custom)?;
					Ok(LSPSMessage::LSPS1(LSPS1Message::Request(
						id,
						LSPS1Request::GetInfo(request),
					)))
				},
				LSPSMethod::LSPS1CreateOrder => {
					let request = serde_json::from_value(params.unwrap_or(json!({})))
						.map_err(de::Error::custom)?;
					Ok(LSPSMessage::LSPS1(LSPS1Message::Request(
						id,
						LSPS1Request::CreateOrder(request),
					)))
				},
				LSPSMethod::LSPS1GetOrder => {
					let request = serde_json::from_value(params.unwrap_or(json!({})))
						.map_err(de::Error::custom)?;
					Ok(LSPSMessage::LSPS1(LSPS1Message::Request(
						id,
						LSPS1Request::GetOrder(request),
					)))
				},
				LSPSMethod::LSPS2GetInfo => {
					let request = serde_json::from_value(params.unwrap_or(json!({})))
						.map_err(de::Error::custom)?;
					Ok(LSPSMessage::LSPS2(LSPS2Message::Request(
						id,
						LSPS2Request::GetInfo(request),
					)))
				},
				LSPSMethod::LSPS2Buy => {
					let request = serde_json::from_value(params.unwrap_or(json!({})))
						.map_err(de::Error::custom)?;
					Ok(LSPSMessage::LSPS2(LSPS2Message::Request(id, LSPS2Request::Buy(request))))
				},
				LSPSMethod::LSPS5SetWebhook => {
					let request = serde_json::from_value(params.unwrap_or(json!({})))
						.map_err(de::Error::custom)?;
					Ok(LSPSMessage::LSPS5(LSPS5Message::Request(
						id,
						LSPS5Request::SetWebhook(request),
					)))
				},
				LSPSMethod::LSPS5ListWebhooks => {
					let request = serde_json::from_value(params.unwrap_or(json!({})))
						.map_err(de::Error::custom)?;
					Ok(LSPSMessage::LSPS5(LSPS5Message::Request(
						id,
						LSPS5Request::ListWebhooks(request),
					)))
				},
				LSPSMethod::LSPS5RemoveWebhook => {
					let request = serde_json::from_value(params.unwrap_or(json!({})))
						.map_err(de::Error::custom)?;
					Ok(LSPSMessage::LSPS5(LSPS5Message::Request(
						id,
						LSPS5Request::RemoveWebhook(request),
					)))
				},
			},
			None => match self.request_id_to_method_map.remove(&id) {
				Some(method) => match method {
					LSPSMethod::LSPS0ListProtocols => {
						if let Some(error) = error {
							Ok(LSPSMessage::LSPS0(LSPS0Message::Response(
								id,
								LSPS0Response::ListProtocolsError(error),
							)))
						} else if let Some(result) = result {
							let list_protocols_response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS0(LSPS0Message::Response(
								id,
								LSPS0Response::ListProtocols(list_protocols_response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
					LSPSMethod::LSPS1GetInfo => {
						if let Some(error) = error {
							Ok(LSPSMessage::LSPS1(LSPS1Message::Response(
								id,
								LSPS1Response::GetInfoError(error),
							)))
						} else if let Some(result) = result {
							let response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS1(LSPS1Message::Response(
								id,
								LSPS1Response::GetInfo(response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
					LSPSMethod::LSPS1CreateOrder => {
						if let Some(error) = error {
							Ok(LSPSMessage::LSPS1(LSPS1Message::Response(
								id,
								LSPS1Response::CreateOrderError(error),
							)))
						} else if let Some(result) = result {
							let response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS1(LSPS1Message::Response(
								id,
								LSPS1Response::CreateOrder(response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
					LSPSMethod::LSPS1GetOrder => {
						if let Some(error) = error {
							Ok(LSPSMessage::LSPS1(LSPS1Message::Response(
								id,
								LSPS1Response::GetOrderError(error),
							)))
						} else if let Some(result) = result {
							let response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS1(LSPS1Message::Response(
								id,
								LSPS1Response::GetOrder(response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
					LSPSMethod::LSPS2GetInfo => {
						if let Some(error) = error {
							Ok(LSPSMessage::LSPS2(LSPS2Message::Response(
								id,
								LSPS2Response::GetInfoError(error),
							)))
						} else if let Some(result) = result {
							let response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS2(LSPS2Message::Response(
								id,
								LSPS2Response::GetInfo(response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
					LSPSMethod::LSPS2Buy => {
						if let Some(error) = error {
							Ok(LSPSMessage::LSPS2(LSPS2Message::Response(
								id,
								LSPS2Response::BuyError(error),
							)))
						} else if let Some(result) = result {
							let response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS2(LSPS2Message::Response(
								id,
								LSPS2Response::Buy(response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
					LSPSMethod::LSPS5SetWebhook => {
						if let Some(error) = error {
							Ok(LSPSMessage::LSPS5(LSPS5Message::Response(
								id,
								LSPS5Response::SetWebhookError(error.into()),
							)))
						} else if let Some(result) = result {
							let response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS5(LSPS5Message::Response(
								id,
								LSPS5Response::SetWebhook(response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
					LSPSMethod::LSPS5ListWebhooks => {
						if let Some(result) = result {
							let response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS5(LSPS5Message::Response(
								id,
								LSPS5Response::ListWebhooks(response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
					LSPSMethod::LSPS5RemoveWebhook => {
						if let Some(error) = error {
							Ok(LSPSMessage::LSPS5(LSPS5Message::Response(
								id,
								LSPS5Response::RemoveWebhookError(error.into()),
							)))
						} else if let Some(result) = result {
							let response =
								serde_json::from_value(result).map_err(de::Error::custom)?;
							Ok(LSPSMessage::LSPS5(LSPS5Message::Response(
								id,
								LSPS5Response::RemoveWebhook(response),
							)))
						} else {
							Err(de::Error::custom("Received invalid JSON-RPC object: one of method, result, or error required"))
						}
					},
				},
				None => Err(de::Error::custom(format!(
					"Received response for unknown request id: {}",
					id.0
				))),
			},
		}
	}
}

pub(crate) mod string_amount {
	use alloc::string::{String, ToString};
	use core::str::FromStr;
	use serde::de::Unexpected;
	use serde::{Deserialize, Deserializer, Serializer};

	pub(crate) fn serialize<S>(x: &u64, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		s.serialize_str(&x.to_string())
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
	where
		D: Deserializer<'de>,
	{
		let buf = String::deserialize(deserializer)?;

		u64::from_str(&buf).map_err(|_| {
			serde::de::Error::invalid_value(Unexpected::Str(&buf), &"invalid u64 amount string")
		})
	}
}

pub(crate) mod string_amount_option {
	use alloc::string::{String, ToString};
	use core::str::FromStr;
	use serde::de::Unexpected;
	use serde::{Deserialize, Deserializer, Serialize, Serializer};

	pub(crate) fn serialize<S>(x: &Option<u64>, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let v = x.as_ref().map(|v| v.to_string());
		Option::<String>::serialize(&v, s)
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
	where
		D: Deserializer<'de>,
	{
		if let Some(buf) = Option::<String>::deserialize(deserializer)? {
			let val = u64::from_str(&buf).map_err(|_| {
				serde::de::Error::invalid_value(Unexpected::Str(&buf), &"invalid u64 amount string")
			})?;
			Ok(Some(val))
		} else {
			Ok(None)
		}
	}
}

pub(crate) mod string_offer {
	use alloc::string::{String, ToString};
	use core::str::FromStr;
	use lightning::offers::offer::Offer;
	use serde::de::Unexpected;
	use serde::{Deserialize, Deserializer, Serializer};

	pub(crate) fn serialize<S>(x: &Offer, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		s.serialize_str(&x.to_string())
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Offer, D::Error>
	where
		D: Deserializer<'de>,
	{
		let buf = String::deserialize(deserializer)?;

		Offer::from_str(&buf).map_err(|_| {
			serde::de::Error::invalid_value(Unexpected::Str(&buf), &"invalid offer string")
		})
	}
}

pub(crate) mod unchecked_address {
	use alloc::string::{String, ToString};
	use bitcoin::Address;
	use core::str::FromStr;
	use serde::de::Unexpected;
	use serde::{Deserialize, Deserializer, Serializer};

	pub(crate) fn serialize<S>(x: &Address, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		s.serialize_str(&x.to_string())
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
	where
		D: Deserializer<'de>,
	{
		let buf = String::deserialize(deserializer)?;

		let parsed_addr = Address::from_str(&buf).map_err(|_| {
			serde::de::Error::invalid_value(Unexpected::Str(&buf), &"invalid address string")
		})?;
		Ok(parsed_addr.assume_checked())
	}
}

pub(crate) mod unchecked_address_option {
	use alloc::string::{String, ToString};
	use bitcoin::Address;
	use core::str::FromStr;
	use serde::de::Unexpected;
	use serde::{Deserialize, Deserializer, Serialize, Serializer};

	pub(crate) fn serialize<S>(x: &Option<Address>, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let v = x.as_ref().map(|v| v.to_string());
		Option::<String>::serialize(&v, s)
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<bitcoin::Address>, D::Error>
	where
		D: Deserializer<'de>,
	{
		if let Some(buf) = Option::<String>::deserialize(deserializer)? {
			let val = Address::from_str(&buf).map_err(|_| {
				serde::de::Error::invalid_value(Unexpected::Str(&buf), &"invalid address string")
			})?;
			Ok(Some(val.assume_checked()))
		} else {
			Ok(None)
		}
	}
}

pub(crate) mod u32_fee_rate {
	use bitcoin::FeeRate;
	use serde::{Deserialize, Deserializer, Serializer};

	pub(crate) fn serialize<S>(x: &FeeRate, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let fee_rate_sat_kwu = x.to_sat_per_kwu();
		s.serialize_u32(fee_rate_sat_kwu as u32)
	}

	pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<FeeRate, D::Error>
	where
		D: Deserializer<'de>,
	{
		let fee_rate_sat_kwu = u32::deserialize(deserializer)?;

		Ok(FeeRate::from_sat_per_kwu(fee_rate_sat_kwu as u64))
	}
}
