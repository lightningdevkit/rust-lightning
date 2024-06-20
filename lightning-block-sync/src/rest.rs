//! Simple REST client implementation which implements [`BlockSource`] against a Bitcoin Core REST
//! endpoint.

use crate::convert::GetUtxosResponse;
use crate::gossip::UtxoSource;
use crate::http::{BinaryResponse, HttpClient, HttpEndpoint, JsonResponse};
use crate::{AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource};

use bitcoin::hash_types::BlockHash;
use bitcoin::OutPoint;

use std::convert::TryFrom;
use std::convert::TryInto;
use std::sync::Mutex;

/// A simple REST client for requesting resources using HTTP `GET`.
pub struct RestClient {
	endpoint: HttpEndpoint,
	client: Mutex<Option<HttpClient>>,
}

impl RestClient {
	/// Creates a new REST client connected to the given endpoint.
	///
	/// The endpoint should contain the REST path component (e.g., http://127.0.0.1:8332/rest).
	pub fn new(endpoint: HttpEndpoint) -> std::io::Result<Self> {
		Ok(Self { endpoint, client: Mutex::new(None) })
	}

	/// Requests a resource encoded in `F` format and interpreted as type `T`.
	pub async fn request_resource<F, T>(&self, resource_path: &str) -> std::io::Result<T>
	where
		F: TryFrom<Vec<u8>, Error = std::io::Error> + TryInto<T, Error = std::io::Error>,
	{
		let host = format!("{}:{}", self.endpoint.host(), self.endpoint.port());
		let uri = format!("{}/{}", self.endpoint.path().trim_end_matches("/"), resource_path);
		let mut client = if let Some(client) = self.client.lock().unwrap().take() {
			client
		} else {
			HttpClient::connect(&self.endpoint)?
		};
		let res = client.get::<F>(&uri, &host).await?.try_into();
		*self.client.lock().unwrap() = Some(client);
		res
	}
}

impl BlockSource for RestClient {
	fn get_header<'a>(
		&'a self, header_hash: &'a BlockHash, _height: Option<u32>,
	) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			let resource_path = format!("headers/1/{}.json", header_hash.to_string());
			Ok(self.request_resource::<JsonResponse, _>(&resource_path).await?)
		})
	}

	fn get_block<'a>(
		&'a self, header_hash: &'a BlockHash,
	) -> AsyncBlockSourceResult<'a, BlockData> {
		Box::pin(async move {
			let resource_path = format!("block/{}.bin", header_hash.to_string());
			Ok(BlockData::FullBlock(
				self.request_resource::<BinaryResponse, _>(&resource_path).await?,
			))
		})
	}

	fn get_best_block<'a>(&'a self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(
			async move { Ok(self.request_resource::<JsonResponse, _>("chaininfo.json").await?) },
		)
	}
}

impl UtxoSource for RestClient {
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> AsyncBlockSourceResult<'a, BlockHash> {
		Box::pin(async move {
			let resource_path = format!("blockhashbyheight/{}.bin", block_height);
			Ok(self.request_resource::<BinaryResponse, _>(&resource_path).await?)
		})
	}

	fn is_output_unspent<'a>(&'a self, outpoint: OutPoint) -> AsyncBlockSourceResult<'a, bool> {
		Box::pin(async move {
			let resource_path =
				format!("getutxos/{}-{}.json", outpoint.txid.to_string(), outpoint.vout);
			let utxo_result =
				self.request_resource::<JsonResponse, GetUtxosResponse>(&resource_path).await?;
			Ok(utxo_result.hit_bitmap_nonempty)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::http::client_tests::{HttpServer, MessageBody};
	use crate::http::BinaryResponse;
	use bitcoin::hashes::Hash;

	/// Parses binary data as a string-encoded `u32`.
	impl TryInto<u32> for BinaryResponse {
		type Error = std::io::Error;

		fn try_into(self) -> std::io::Result<u32> {
			match std::str::from_utf8(&self.0) {
				Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
				Ok(s) => match u32::from_str_radix(s, 10) {
					Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
					Ok(n) => Ok(n),
				},
			}
		}
	}

	#[tokio::test]
	async fn request_unknown_resource() {
		let server = HttpServer::responding_with_not_found();
		let client = RestClient::new(server.endpoint()).unwrap();

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Other),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn request_malformed_resource() {
		let server = HttpServer::responding_with_ok(MessageBody::Content("foo"));
		let client = RestClient::new(server.endpoint()).unwrap();

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn request_valid_resource() {
		let server = HttpServer::responding_with_ok(MessageBody::Content(42));
		let client = RestClient::new(server.endpoint()).unwrap();

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
		let client = RestClient::new(server.endpoint()).unwrap();

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
		let client = RestClient::new(server.endpoint()).unwrap();

		let outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([0; 32]), 0);
		let unspent_output = client.is_output_unspent(outpoint).await.unwrap();
		assert_eq!(unspent_output, true);
	}
}
