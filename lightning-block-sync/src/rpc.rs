//! Simple RPC client implementation which implements [`BlockSource`] against a Bitcoin Core RPC
//! endpoint.

use crate::gossip::UtxoSource;
use crate::http::{HttpClient, HttpClientError, JsonResponse, ToParseErrorMessage};
use crate::{BlockData, BlockHeaderData, BlockSource, BlockSourceResult};

use bitcoin::hash_types::BlockHash;
use bitcoin::OutPoint;

use serde_json;

use std::convert::TryFrom;
use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

/// An error returned by the RPC server.
#[derive(Debug)]
pub struct RpcError {
	/// The error code.
	pub code: i64,
	/// The error message.
	pub message: String,
}

impl fmt::Display for RpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "RPC error {}: {}", self.code, self.message)
	}
}

impl Error for RpcError {}

/// Error type for RPC client operations.
#[derive(Debug)]
pub enum RpcClientError {
	/// An HTTP client error (transport or HTTP error).
	Http(HttpClientError),
	/// An RPC error returned by the server.
	Rpc(RpcError),
	/// Invalid data in the response.
	InvalidData(String),
}

impl std::error::Error for RpcClientError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			RpcClientError::Http(e) => Some(e),
			RpcClientError::Rpc(e) => Some(e),
			RpcClientError::InvalidData(_) => None,
		}
	}
}

impl fmt::Display for RpcClientError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			RpcClientError::Http(e) => write!(f, "HTTP error: {}", e),
			RpcClientError::Rpc(e) => write!(f, "{}", e),
			RpcClientError::InvalidData(msg) => write!(f, "invalid data: {}", msg),
		}
	}
}

impl From<HttpClientError> for RpcClientError {
	fn from(e: HttpClientError) -> Self {
		RpcClientError::Http(e)
	}
}

impl From<RpcError> for RpcClientError {
	fn from(e: RpcError) -> Self {
		RpcClientError::Rpc(e)
	}
}

/// A simple RPC client for calling methods using HTTP `POST`.
///
/// Implements [`BlockSource`] and may return an `Err` containing [`RpcError`]. See
/// [`RpcClient::call_method`] for details.
pub struct RpcClient {
	basic_auth: String,
	client: HttpClient,
	id: AtomicUsize,
}

impl RpcClient {
	/// Creates a new RPC client connected to the given endpoint with the provided credentials. The
	/// credentials should be a base64 encoding of a user name and password joined by a colon, as is
	/// required for HTTP basic access authentication.
	///
	/// The base URL should include the scheme, host, and port (e.g., "http://127.0.0.1:8332").
	pub fn new(credentials: &str, base_url: String) -> Self {
		Self {
			basic_auth: "Basic ".to_string() + credentials,
			client: HttpClient::new(base_url),
			id: AtomicUsize::new(0),
		}
	}

	/// Calls a method with the response encoded in JSON format and interpreted as type `T`.
	pub async fn call_method<T>(
		&self, method: &str, params: &[serde_json::Value],
	) -> Result<T, RpcClientError>
	where
		JsonResponse: TryInto<T>,
		<JsonResponse as TryInto<T>>::Error: ToParseErrorMessage,
	{
		let content = serde_json::json!({
			"method": method,
			"params": params,
			"id": &self.id.fetch_add(1, Ordering::AcqRel).to_string()
		});

		let http_response = self.client.post::<JsonResponse>("/", &self.basic_auth, content).await;

		let mut response = match http_response {
			Ok(JsonResponse(response)) => response,
			Err(HttpClientError::Http(http_error)) => {
				// Try to parse the error body as JSON-RPC response
				match JsonResponse::try_from(http_error.contents.clone()) {
					Ok(JsonResponse(response)) => response,
					Err(_) => return Err(HttpClientError::Http(http_error).into()),
				}
			},
			Err(e) => return Err(e.into()),
		};

		if !response.is_object() {
			return Err(RpcClientError::InvalidData("expected JSON object".to_string()));
		}

		let error = &response["error"];
		if !error.is_null() {
			let rpc_error = RpcError {
				code: error["code"].as_i64().unwrap_or(-1),
				message: error["message"].as_str().unwrap_or("unknown error").to_string(),
			};
			return Err(rpc_error.into());
		}

		let result = match response.get_mut("result") {
			Some(result) => result.take(),
			None => return Err(RpcClientError::InvalidData("expected JSON result".to_string())),
		};

		JsonResponse(result)
			.try_into()
			.map_err(|e| RpcClientError::InvalidData(e.to_parse_error_message()))
	}
}

impl BlockSource for RpcClient {
	fn get_header<'a>(
		&'a self, header_hash: &'a BlockHash, _height: Option<u32>,
	) -> impl Future<Output = BlockSourceResult<BlockHeaderData>> + Send + 'a {
		async move {
			let header_hash = serde_json::json!(header_hash.to_string());
			Ok(self.call_method("getblockheader", &[header_hash]).await?)
		}
	}

	fn get_block<'a>(
		&'a self, header_hash: &'a BlockHash,
	) -> impl Future<Output = BlockSourceResult<BlockData>> + Send + 'a {
		async move {
			let header_hash = serde_json::json!(header_hash.to_string());
			let verbosity = serde_json::json!(0);
			Ok(BlockData::FullBlock(self.call_method("getblock", &[header_hash, verbosity]).await?))
		}
	}

	fn get_best_block<'a>(
		&'a self,
	) -> impl Future<Output = BlockSourceResult<(BlockHash, Option<u32>)>> + Send + 'a {
		async move { Ok(self.call_method("getblockchaininfo", &[]).await?) }
	}
}

impl UtxoSource for RpcClient {
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> impl Future<Output = BlockSourceResult<BlockHash>> + Send + 'a {
		async move {
			let height_param = serde_json::json!(block_height);
			Ok(self.call_method("getblockhash", &[height_param]).await?)
		}
	}

	fn is_output_unspent<'a>(
		&'a self, outpoint: OutPoint,
	) -> impl Future<Output = BlockSourceResult<bool>> + Send + 'a {
		async move {
			let txid_param = serde_json::json!(outpoint.txid.to_string());
			let vout_param = serde_json::json!(outpoint.vout);
			let include_mempool = serde_json::json!(false);
			let utxo_opt: serde_json::Value =
				self.call_method("gettxout", &[txid_param, vout_param, include_mempool]).await?;
			Ok(!utxo_opt.is_null())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::http::client_tests::{HttpServer, MessageBody};

	use bitcoin::hashes::Hash;

	/// Credentials encoded in base64.
	const CREDENTIALS: &'static str = "dXNlcjpwYXNzd29yZA==";

	/// Converts a JSON value into `u64`.
	impl TryInto<u64> for JsonResponse {
		type Error = &'static str;

		fn try_into(self) -> Result<u64, &'static str> {
			match self.0.as_u64() {
				None => Err("not a number"),
				Some(n) => Ok(n),
			}
		}
	}

	#[tokio::test]
	async fn call_method_returning_unknown_response() {
		let server = HttpServer::responding_with_not_found();
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(RpcClientError::Http(HttpClientError::Http(e))) => {
				assert_eq!(e.status_code, 404);
			},
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_malfomred_response() {
		let response = serde_json::json!("foo");
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(RpcClientError::InvalidData(msg)) => {
				assert_eq!(msg, "expected JSON object");
			},
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_error() {
		let response = serde_json::json!({
			"error": { "code": -8, "message": "invalid parameter" },
		});
		let server = HttpServer::responding_with_server_error(response);
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		let invalid_block_hash = serde_json::json!("foo");
		match client.call_method::<u64>("getblock", &[invalid_block_hash]).await {
			Err(RpcClientError::Rpc(rpc_error)) => {
				assert_eq!(rpc_error.code, -8);
				assert_eq!(rpc_error.message, "invalid parameter");
			},
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_missing_result() {
		let response = serde_json::json!({});
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(RpcClientError::InvalidData(msg)) => {
				assert_eq!(msg, "expected JSON result");
			},
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_malformed_result() {
		let response = serde_json::json!({ "result": "foo" });
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(RpcClientError::InvalidData(msg)) => {
				assert!(msg.contains("not a number"));
			},
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_valid_result() {
		let response = serde_json::json!({ "result": 654470 });
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(count) => assert_eq!(count, 654470),
		}
	}

	#[tokio::test]
	async fn fails_to_fetch_spent_utxo() {
		let response = serde_json::json!({ "result": null });
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());
		let outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([0; 32]), 0);
		let unspent_output = client.is_output_unspent(outpoint).await.unwrap();
		assert_eq!(unspent_output, false);
	}

	#[tokio::test]
	async fn fetches_utxo() {
		let response = serde_json::json!({ "result": {"bestblock": 1, "confirmations": 42}});
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());
		let outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([0; 32]), 0);
		let unspent_output = client.is_output_unspent(outpoint).await.unwrap();
		assert_eq!(unspent_output, true);
	}
}
