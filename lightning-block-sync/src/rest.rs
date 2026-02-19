//! Simple REST client implementation which implements [`BlockSource`] against a Bitcoin Core REST
//! endpoint.

use crate::convert::GetUtxosResponse;
use crate::gossip::UtxoSource;
use crate::http::{BinaryResponse, HttpClient, HttpClientError, JsonResponse, ToParseErrorMessage};
use crate::{BlockData, BlockHeaderData, BlockSource, BlockSourceResult};

use bitcoin::hash_types::BlockHash;
use bitcoin::OutPoint;

use std::convert::TryFrom;
use std::convert::TryInto;
use std::future::Future;

/// A simple REST client for requesting resources using HTTP `GET`.
pub struct RestClient {
	client: HttpClient,
}

impl RestClient {
	/// Creates a new REST client connected to the given endpoint.
	///
	/// The base URL should include the REST path component (e.g., "http://127.0.0.1:8332/rest").
	pub fn new(base_url: String) -> Self {
		Self { client: HttpClient::new(base_url) }
	}

	/// Requests a resource encoded in `F` format and interpreted as type `T`.
	pub async fn request_resource<F, T>(&self, resource_path: &str) -> Result<T, HttpClientError>
	where
		F: TryFrom<Vec<u8>> + TryInto<T>,
		<F as TryFrom<Vec<u8>>>::Error: ToParseErrorMessage,
		<F as TryInto<T>>::Error: ToParseErrorMessage,
	{
		let uri = format!("/{}", resource_path);
		let response = self.client.get::<F>(&uri).await?;
		response.try_into().map_err(|e| HttpClientError::Parse(e.to_parse_error_message()))
	}
}

impl BlockSource for RestClient {
	fn get_header<'a>(
		&'a self, header_hash: &'a BlockHash, _height: Option<u32>,
	) -> impl Future<Output = BlockSourceResult<BlockHeaderData>> + Send + 'a {
		async move {
			let resource_path = format!("headers/1/{}.json", header_hash.to_string());
			Ok(self.request_resource::<JsonResponse, _>(&resource_path).await?)
		}
	}

	fn get_block<'a>(
		&'a self, header_hash: &'a BlockHash,
	) -> impl Future<Output = BlockSourceResult<BlockData>> + Send + 'a {
		async move {
			let resource_path = format!("block/{}.bin", header_hash.to_string());
			Ok(BlockData::FullBlock(
				self.request_resource::<BinaryResponse, _>(&resource_path).await?,
			))
		}
	}

	fn get_best_block<'a>(
		&'a self,
	) -> impl Future<Output = BlockSourceResult<(BlockHash, Option<u32>)>> + Send + 'a {
		async move { Ok(self.request_resource::<JsonResponse, _>("chaininfo.json").await?) }
	}
}

impl UtxoSource for RestClient {
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> impl Future<Output = BlockSourceResult<BlockHash>> + Send + 'a {
		async move {
			let resource_path = format!("blockhashbyheight/{}.bin", block_height);
			Ok(self.request_resource::<BinaryResponse, _>(&resource_path).await?)
		}
	}

	fn is_output_unspent<'a>(
		&'a self, outpoint: OutPoint,
	) -> impl Future<Output = BlockSourceResult<bool>> + Send + 'a {
		async move {
			let resource_path =
				format!("getutxos/{}-{}.json", outpoint.txid.to_string(), outpoint.vout);
			let utxo_result =
				self.request_resource::<JsonResponse, GetUtxosResponse>(&resource_path).await?;
			Ok(utxo_result.hit_bitmap_nonempty)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::http::client_tests::{HttpServer, MessageBody};
	use bitcoin::hashes::Hash;

	/// Parses binary data as a string-encoded `u32`.
	impl TryInto<u32> for BinaryResponse {
		type Error = String;

		fn try_into(self) -> Result<u32, String> {
			let s = std::str::from_utf8(&self.0).map_err(|e| e.to_string())?;
			u32::from_str_radix(s, 10).map_err(|e| e.to_string())
		}
	}

	#[tokio::test]
	async fn request_unknown_resource() {
		let server = HttpServer::responding_with_not_found();
		let client = RestClient::new(server.endpoint());

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(HttpClientError::Http(e)) => assert_eq!(e.status_code, 404),
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn request_malformed_resource() {
		let server = HttpServer::responding_with_ok(MessageBody::Content("foo"));
		let client = RestClient::new(server.endpoint());

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(HttpClientError::Parse(_)) => {},
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn request_valid_resource() {
		let server = HttpServer::responding_with_ok(MessageBody::Content(42));
		let client = RestClient::new(server.endpoint());

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(n) => assert_eq!(n, 42),
		}
	}

	#[tokio::test]
	async fn parses_negative_getutxos() {
		let server = HttpServer::responding_with_ok(MessageBody::Content(
			// A real response contains a few more fields, but we actually only look at the
			// "bitmap" field, so this should suffice for testing
			"{\"chainHeight\": 1, \"bitmap\":\"0\",\"utxos\":[]}",
		));
		let client = RestClient::new(server.endpoint());

		let outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([0; 32]), 0);
		let unspent_output = client.is_output_unspent(outpoint).await.unwrap();
		assert_eq!(unspent_output, false);
	}

	#[tokio::test]
	async fn parses_positive_getutxos() {
		let server = HttpServer::responding_with_ok(MessageBody::Content(
			// A real response contains lots more data, but we actually only look at the "bitmap"
			// field, so this should suffice for testing
			"{\"chainHeight\": 1, \"bitmap\":\"1\",\"utxos\":[]}",
		));
		let client = RestClient::new(server.endpoint());

		let outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([0; 32]), 0);
		let unspent_output = client.is_output_unspent(outpoint).await.unwrap();
		assert_eq!(unspent_output, true);
	}
}
