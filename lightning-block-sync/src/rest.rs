//! Simple REST client implementation which implements [`BlockSource`] against a Bitcoin Core REST
//! endpoint.

use crate::{BlockData, BlockHeaderData, BlockSource, AsyncBlockSourceResult};
use crate::http::{BinaryResponse, HttpEndpoint, HttpClient, JsonResponse};

use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::hex::ToHex;

use futures_util::lock::Mutex;

use std::convert::TryFrom;
use std::convert::TryInto;

/// A simple REST client for requesting resources using HTTP `GET`.
pub struct RestClient {
	endpoint: HttpEndpoint,
	client: Mutex<HttpClient>,
}

impl RestClient {
	/// Creates a new REST client connected to the given endpoint.
	///
	/// The endpoint should contain the REST path component (e.g., http://127.0.0.1:8332/rest).
	pub fn new(endpoint: HttpEndpoint) -> std::io::Result<Self> {
		let client = Mutex::new(HttpClient::connect(&endpoint)?);
		Ok(Self { endpoint, client })
	}

	/// Requests a resource encoded in `F` format and interpreted as type `T`.
	pub async fn request_resource<F, T>(&self, resource_path: &str) -> std::io::Result<T>
	where F: TryFrom<Vec<u8>, Error = std::io::Error> + TryInto<T, Error = std::io::Error> {
		let host = format!("{}:{}", self.endpoint.host(), self.endpoint.port());
		let uri = format!("{}/{}", self.endpoint.path().trim_end_matches("/"), resource_path);
		self.client.lock().await.get::<F>(&uri, &host).await?.try_into()
	}
}

impl BlockSource for RestClient {
	fn get_header<'a>(&'a self, header_hash: &'a BlockHash, _height: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			let resource_path = format!("headers/1/{}.json", header_hash.to_hex());
			Ok(self.request_resource::<JsonResponse, _>(&resource_path).await?)
		})
	}

	fn get_block<'a>(&'a self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, BlockData> {
		Box::pin(async move {
			let resource_path = format!("block/{}.bin", header_hash.to_hex());
			Ok(BlockData::FullBlock(self.request_resource::<BinaryResponse, _>(&resource_path).await?))
		})
	}

	fn get_best_block<'a>(&'a self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			Ok(self.request_resource::<JsonResponse, _>("chaininfo.json").await?)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::http::BinaryResponse;
	use crate::http::client_tests::{HttpServer, MessageBody};

	/// Parses binary data as a string-encoded `u32`.
	impl TryInto<u32> for BinaryResponse {
		type Error = std::io::Error;

		fn try_into(self) -> std::io::Result<u32> {
			match std::str::from_utf8(&self.0) {
				Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
				Ok(s) => match u32::from_str_radix(s, 10) {
					Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
					Ok(n) => Ok(n),
				}
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
}
