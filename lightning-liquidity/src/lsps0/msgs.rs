//! Message, request, and other primitive types used to implement LSPS0.

use crate::lsps0::ser::{LSPSMessage, LSPSRequestId, LSPSResponseError};
use crate::prelude::Vec;

use serde::{Deserialize, Serialize};

use core::convert::TryFrom;

pub(crate) const LSPS0_LISTPROTOCOLS_METHOD_NAME: &str = "lsps0.list_protocols";

/// A `list_protocols` request.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct LSPS0ListProtocolsRequest {}

/// A response to a `list_protocols` request.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LSPS0ListProtocolsResponse {
	/// A list of supported protocols.
	pub protocols: Vec<u16>,
}

/// An bLIP-50 / LSPS0 protocol request.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS0Request {
	/// A request calling `list_protocols`.
	ListProtocols(LSPS0ListProtocolsRequest),
}

impl LSPS0Request {
	/// Returns the method name associated with the given request variant.
	pub fn method(&self) -> &'static str {
		match self {
			LSPS0Request::ListProtocols(_) => LSPS0_LISTPROTOCOLS_METHOD_NAME,
		}
	}
}

/// An bLIP-50 / LSPS0 protocol request.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS0Response {
	/// A response to a `list_protocols` request.
	ListProtocols(LSPS0ListProtocolsResponse),
	/// An error response to a `list_protocols` request.
	ListProtocolsError(LSPSResponseError),
}

/// An bLIP-50 / LSPS0 protocol message.
///
/// Please refer to the [bLIP-50 / LSPS0
/// specification](https://github.com/lightning/blips/blob/master/blip-0050.md#lsps-specification-support-query)
/// for more information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS0Message {
	/// A request variant.
	Request(LSPSRequestId, LSPS0Request),
	/// A response variant.
	Response(LSPSRequestId, LSPS0Response),
}

impl TryFrom<LSPSMessage> for LSPS0Message {
	type Error = ();

	fn try_from(message: LSPSMessage) -> Result<Self, Self::Error> {
		match message {
			LSPSMessage::Invalid(_) => Err(()),
			LSPSMessage::LSPS0(message) => Ok(message),
			LSPSMessage::LSPS1(_) => Err(()),
			LSPSMessage::LSPS2(_) => Err(()),
			LSPSMessage::LSPS5(_) => Err(()),
		}
	}
}

impl From<LSPS0Message> for LSPSMessage {
	fn from(message: LSPS0Message) -> Self {
		LSPSMessage::LSPS0(message)
	}
}

#[cfg(test)]
mod tests {
	use lightning::util::hash_tables::new_hash_map;

	use super::*;
	use crate::lsps0::ser::LSPSMethod;
	use crate::prelude::ToString;

	#[test]
	fn deserializes_request() {
		let json = r#"{
			"jsonrpc": "2.0",
			"id": "request:id:xyz123",
			"method": "lsps0.list_protocols"
		}"#;

		let mut request_id_method_map = new_hash_map();

		let msg = LSPSMessage::from_str_with_id_map(json, &mut request_id_method_map);
		assert!(msg.is_ok());
		let msg = msg.unwrap();
		assert_eq!(
			msg,
			LSPSMessage::LSPS0(LSPS0Message::Request(
				LSPSRequestId("request:id:xyz123".to_string()),
				LSPS0Request::ListProtocols(LSPS0ListProtocolsRequest {})
			))
		);
	}

	#[test]
	fn serializes_request() {
		let request = LSPSMessage::LSPS0(LSPS0Message::Request(
			LSPSRequestId("request:id:xyz123".to_string()),
			LSPS0Request::ListProtocols(LSPS0ListProtocolsRequest {}),
		));
		let json = serde_json::to_string(&request).unwrap();
		assert_eq!(
			json,
			r#"{"jsonrpc":"2.0","id":"request:id:xyz123","method":"lsps0.list_protocols","params":{}}"#
		);
	}

	#[test]
	fn deserializes_success_response() {
		let json = r#"{
	        "jsonrpc": "2.0",
	        "id": "request:id:xyz123",
	        "result": {
	            "protocols": [1,2,3]
	        }
	    }"#;
		let mut request_id_to_method_map = new_hash_map();
		request_id_to_method_map
			.insert(LSPSRequestId("request:id:xyz123".to_string()), LSPSMethod::LSPS0ListProtocols);

		let response =
			LSPSMessage::from_str_with_id_map(json, &mut request_id_to_method_map).unwrap();

		assert_eq!(
			response,
			LSPSMessage::LSPS0(LSPS0Message::Response(
				LSPSRequestId("request:id:xyz123".to_string()),
				LSPS0Response::ListProtocols(LSPS0ListProtocolsResponse {
					protocols: vec![1, 2, 3]
				})
			))
		);
	}

	#[test]
	fn deserializes_error_response() {
		let json = r#"{
	        "jsonrpc": "2.0",
	        "id": "request:id:xyz123",
	        "error": {
	            "code": -32617,
				"message": "Unknown Error"
	        }
	    }"#;
		let mut request_id_to_method_map = new_hash_map();
		request_id_to_method_map
			.insert(LSPSRequestId("request:id:xyz123".to_string()), LSPSMethod::LSPS0ListProtocols);

		let response =
			LSPSMessage::from_str_with_id_map(json, &mut request_id_to_method_map).unwrap();

		assert_eq!(
			response,
			LSPSMessage::LSPS0(LSPS0Message::Response(
				LSPSRequestId("request:id:xyz123".to_string()),
				LSPS0Response::ListProtocolsError(LSPSResponseError {
					code: -32617,
					message: "Unknown Error".to_string(),
					data: None
				})
			))
		);
	}

	#[test]
	fn deserialize_fails_with_unknown_request_id() {
		let json = r#"{
	        "jsonrpc": "2.0",
	        "id": "request:id:xyz124",
	        "result": {
	            "protocols": [1,2,3]
	        }
	    }"#;
		let mut request_id_to_method_map = new_hash_map();
		request_id_to_method_map
			.insert(LSPSRequestId("request:id:xyz123".to_string()), LSPSMethod::LSPS0ListProtocols);

		let response = LSPSMessage::from_str_with_id_map(json, &mut request_id_to_method_map);
		assert!(response.is_err());
	}

	#[test]
	fn serializes_response() {
		let response = LSPSMessage::LSPS0(LSPS0Message::Response(
			LSPSRequestId("request:id:xyz123".to_string()),
			LSPS0Response::ListProtocols(LSPS0ListProtocolsResponse { protocols: vec![1, 2, 3] }),
		));
		let json = serde_json::to_string(&response).unwrap();
		assert_eq!(
			json,
			r#"{"jsonrpc":"2.0","id":"request:id:xyz123","result":{"protocols":[1,2,3]}}"#
		);
	}
}
