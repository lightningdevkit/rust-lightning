use crate::http_endpoint::HttpEndpoint;
use crate::utils::hex_to_uint256;
use crate::{BlockHeaderData, BlockSource, BlockSourceError, AsyncBlockSourceResult};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::encode;
use bitcoin::hash_types::{BlockHash, TxMerkleNode};
use bitcoin::hashes::hex::{ToHex, FromHex};

use serde_derive::Deserialize;

use serde_json;

use std::cmp;
use std::convert::TryFrom;
use std::convert::TryInto;
#[cfg(not(feature = "tokio"))]
use std::io::Write;
use std::net::ToSocketAddrs;
use std::time::Duration;

#[cfg(feature = "rpc-client")]
use base64;
#[cfg(feature = "rpc-client")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "tokio")]
use tokio::io::AsyncReadExt;
#[cfg(feature = "tokio")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

#[cfg(not(feature = "tokio"))]
use std::io::Read;
#[cfg(not(feature = "tokio"))]
use std::net::TcpStream;

/// Maximum HTTP response size in bytes.
const MAX_HTTP_RESPONSE_LEN: usize = 4_000_000;

/// Client for making HTTP requests.
struct HttpClient {
	stream: TcpStream,
}

impl HttpClient {
	/// Opens a connection to an HTTP endpoint.
	fn connect<E: ToSocketAddrs>(endpoint: E) -> std::io::Result<Self> {
		let address = match endpoint.to_socket_addrs()?.next() {
			None => {
				return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "could not resolve to any addresses"));
			},
			Some(address) => address,
		};
		let stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
		stream.set_read_timeout(Some(Duration::from_secs(2)))?;
		stream.set_write_timeout(Some(Duration::from_secs(1)))?;

		#[cfg(feature = "tokio")]
		let stream = TcpStream::from_std(stream)?;

		Ok(Self { stream })
	}

	/// Sends a `GET` request for a resource identified by `uri` at the `host`.
	async fn get<F>(&mut self, uri: &str, host: &str) -> std::io::Result<F>
	where F: TryFrom<Vec<u8>, Error = std::io::Error> {
		let request = format!(
			"GET {} HTTP/1.1\r\n\
			 Host: {}\r\n\
			 Connection: keep-alive\r\n\
			 \r\n", uri, host);
		#[cfg(feature = "tokio")]
		self.stream.write_all(request.as_bytes()).await?;
		#[cfg(not(feature = "tokio"))]
		self.stream.write_all(request.as_bytes())?;

		let bytes = read_http_resp(&mut self.stream, MAX_HTTP_RESPONSE_LEN).await?;
		F::try_from(bytes)
	}

	/// Sends a `POST` request for a resource identified by `uri` at the `host` using the given HTTP
	/// authentication credentials.
	///
	/// The request body consists of the provided JSON `content`. Returns the response body in `F`
	/// format.
	async fn post<F>(&mut self, uri: &str, host: &str, auth: &str, content: serde_json::Value) -> std::io::Result<F>
	where F: TryFrom<Vec<u8>, Error = std::io::Error> {
		let content = content.to_string();
		let request = format!(
			"POST {} HTTP/1.1\r\n\
			 Host: {}\r\n\
			 Authorization: {}\r\n\
			 Connection: keep-alive\r\n\
			 Content-Type: application/json\r\n\
			 Content-Length: {}\r\n\
			 \r\n\
			 {}", uri, host, auth, content.len(), content);
		#[cfg(feature = "tokio")]
		self.stream.write_all(request.as_bytes()).await?;
		#[cfg(not(feature = "tokio"))]
		self.stream.write_all(request.as_bytes())?;

		let bytes = read_http_resp(&mut self.stream, MAX_HTTP_RESPONSE_LEN).await?;
		F::try_from(bytes)
	}
}

async fn read_http_resp(socket: &mut TcpStream, max_resp: usize) -> std::io::Result<Vec<u8>> {
	let mut resp = Vec::new();
	let mut bytes_read = 0;
	macro_rules! read_socket { () => { {
		#[cfg(feature = "tokio")]
		let bytes_read = socket.read(&mut resp[bytes_read..]).await?;
		#[cfg(not(feature = "tokio"))]
		let bytes_read = socket.read(&mut resp[bytes_read..])?;
		if bytes_read == 0 {
			return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "zero bytes read"));
		} else {
			bytes_read
		}
	} } }

	let mut actual_len = 0;
	let mut ok_found = false;
	let mut chunked = false;
	// We expect the HTTP headers to fit in 8KB, and use resp as a temporary buffer for headers
	// until we know our real length.
	resp.extend_from_slice(&[0; 8192]);
	'read_headers: loop {
		if bytes_read >= 8192 {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "headers too large"));
		}
		bytes_read += read_socket!();
		for line in resp[..bytes_read].split(|c| *c == '\n' as u8 || *c == '\r' as u8) {
			let content_header = b"Content-Length: ";
			if line.len() > content_header.len() && line[..content_header.len()].eq_ignore_ascii_case(content_header) {
				actual_len = match match std::str::from_utf8(&line[content_header.len()..]){
					Ok(s) => s, Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
				}.parse() {
					Ok(len) => len, Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
				};
			}
			let http_resp_1 = b"HTTP/1.1 200 ";
			let http_resp_0 = b"HTTP/1.0 200 ";
			if line.len() > http_resp_1.len() && (line[..http_resp_1.len()].eq_ignore_ascii_case(http_resp_1) ||
				                                  line[..http_resp_0.len()].eq_ignore_ascii_case(http_resp_0)) {
				ok_found = true;
			}
			let transfer_encoding = b"Transfer-Encoding: ";
			if line.len() > transfer_encoding.len() && line[..transfer_encoding.len()].eq_ignore_ascii_case(transfer_encoding) {
				match &*String::from_utf8_lossy(&line[transfer_encoding.len()..]).to_ascii_lowercase() {
					"chunked" => chunked = true,
					_ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsupported transfer encoding")),
				}
			}
		}
		for (idx, window) in resp[..bytes_read].windows(4).enumerate() {
			if window[0..2] == *b"\n\n" || window[0..2] == *b"\r\r" {
				resp = resp.split_off(idx + 2);
				resp.resize(bytes_read - idx - 2, 0);
				break 'read_headers;
			} else if window[0..4] == *b"\r\n\r\n" {
				resp = resp.split_off(idx + 4);
				resp.resize(bytes_read - idx - 4, 0);
				break 'read_headers;
			}
		}
	}
	if !ok_found {
		return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"));
	}
	bytes_read = resp.len();
	if !chunked {
		if actual_len == 0 || actual_len > max_resp {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "out of range"));
		}
		resp.resize(actual_len, 0);
		while bytes_read < actual_len {
			bytes_read += read_socket!();
		}
		Ok(resp)
	} else {
		actual_len = 0;
		let mut chunk_remaining = 0;
		'read_bytes: loop {
			if chunk_remaining == 0 {
				let mut bytes_skipped = 0;
				let mut finished_read = false;
				let mut lineiter = resp[actual_len..bytes_read].split(|c| *c == '\n' as u8 || *c == '\r' as u8).peekable();
				loop {
					let line = match lineiter.next() { Some(line) => line, None => break };
					if lineiter.peek().is_none() { // We haven't yet read to the end of this line
						if line.len() > 8 {
							// No reason to ever have a chunk length line longer than 4 chars
							return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "out of range"));
						}
						break;
					}
					bytes_skipped += line.len() + 1;
					if line.len() == 0 { continue; } // Probably between the \r and \n
					match usize::from_str_radix(&match std::str::from_utf8(line) {
						Ok(s) => s, Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
					}, 16) {
						Ok(chunklen) => {
							if chunklen == 0 { finished_read = true; }
							chunk_remaining = chunklen;
							match lineiter.next() {
								Some(l) if l.is_empty() => {
									// Drop \r after \n
									bytes_skipped += 1;
									if actual_len + bytes_skipped > bytes_read {
										// Go back and get more bytes so we can skip trailing \n
										chunk_remaining = 0;
									}
								},
								Some(_) => {},
								None => {
									// Go back and get more bytes so we can skip trailing \n
									chunk_remaining = 0;
								},
							}
							break;
						},
						Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
					}
				}
				if chunk_remaining != 0 {
					bytes_read -= bytes_skipped;
					resp.drain(actual_len..actual_len + bytes_skipped);
					if actual_len + chunk_remaining > max_resp {
						return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "out of range"));
					}
					let already_in_chunk = cmp::min(bytes_read - actual_len, chunk_remaining);
					actual_len += already_in_chunk;
					chunk_remaining -= already_in_chunk;
					continue 'read_bytes;
				} else {
					if finished_read {
						// Note that we may leave some extra \r\ns to be read, but that's OK,
						// we'll ignore then when parsing headers for the next request.
						resp.resize(actual_len, 0);
						return Ok(resp);
					} else {
						// Need to read more bytes to figure out chunk length
					}
				}
			}
			resp.resize(bytes_read + cmp::max(10, chunk_remaining), 0);
			let avail = read_socket!();
			bytes_read += avail;
			if chunk_remaining != 0 {
				let chunk_read = cmp::min(chunk_remaining, avail);
				chunk_remaining -= chunk_read;
				actual_len += chunk_read;
			}
		}
	}
}

#[cfg(feature = "rest-client")]
pub struct RESTClient {
	endpoint: HttpEndpoint,
}

#[cfg(feature = "rest-client")]
impl RESTClient {
	pub fn new(endpoint: HttpEndpoint) -> Self {
		Self { endpoint }
	}

	async fn request_resource<F, T>(&self, resource_path: &str) -> std::io::Result<T>
	where F: TryFrom<Vec<u8>, Error = std::io::Error> + TryInto<T, Error = std::io::Error> {
		let host = format!("{}:{}", self.endpoint.host(), self.endpoint.port());
		let uri = format!("{}/{}", self.endpoint.path().trim_end_matches("/"), resource_path);

		let mut client = HttpClient::connect(&self.endpoint)?;
		client.get::<F>(&uri, &host).await?.try_into()
	}
}

#[cfg(feature = "rpc-client")]
pub struct RPCClient {
	basic_auth: String,
	endpoint: HttpEndpoint,
	id: AtomicUsize,
}

#[cfg(feature = "rpc-client")]
impl RPCClient {
	pub fn new(user_auth: &str, endpoint: HttpEndpoint) -> Self {
		Self {
			basic_auth: "Basic ".to_string() + &base64::encode(user_auth),
			endpoint,
			id: AtomicUsize::new(0),
		}
	}

	async fn call_method<T>(&self, method: &str, params: &[serde_json::Value]) -> std::io::Result<T>
	where JsonResponse: TryFrom<Vec<u8>, Error = std::io::Error> + TryInto<T, Error = std::io::Error> {
		let host = format!("{}:{}", self.endpoint.host(), self.endpoint.port());
		let uri = self.endpoint.path();
		let content = serde_json::json!({
			"method": method,
			"params": params,
			"id": &self.id.fetch_add(1, Ordering::AcqRel).to_string()
		});

		let mut client = HttpClient::connect(&self.endpoint)?;
		let mut response = client.post::<JsonResponse>(&uri, &host, &self.basic_auth, content).await?.0;
		if !response.is_object() {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON object"));
		}

		let error = &response["error"];
		if !error.is_null() {
			// TODO: Examine error code for a more precise std::io::ErrorKind.
			let message = error["message"].as_str().unwrap_or("unknown error");
			return Err(std::io::Error::new(std::io::ErrorKind::Other, message));
		}

		let result = &mut response["result"];
		if result.is_null() {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON result"));
		}

		JsonResponse(result.take()).try_into()
	}
}

#[derive(Deserialize)]
struct GetHeaderResponse {
	pub chainwork: String,
	pub height: u32,

	pub version: i32,
	pub merkleroot: String,
	pub time: u32,
	pub nonce: u32,
	pub bits: String,
	pub previousblockhash: String,
}

/// Converts from `GetHeaderResponse` to `BlockHeaderData`.
impl TryFrom<GetHeaderResponse> for BlockHeaderData {
	type Error = bitcoin::hashes::hex::Error;

	fn try_from(response: GetHeaderResponse) -> Result<Self, bitcoin::hashes::hex::Error> {
		Ok(BlockHeaderData {
			chainwork: hex_to_uint256(&response.chainwork)?,
			height: response.height,
			header: BlockHeader {
				version: response.version,
				prev_blockhash: BlockHash::from_hex(&response.previousblockhash)?,
				merkle_root: TxMerkleNode::from_hex(&response.merkleroot)?,
				time: response.time,
				bits: u32::from_be_bytes(<[u8; 4]>::from_hex(&response.bits)?),
				nonce: response.nonce,
			},
		})
	}
}

#[cfg(feature = "rpc-client")]
impl BlockSource for RPCClient {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, _height: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			let header_hash = serde_json::json!(header_hash.to_hex());
			Ok(self.call_method("getblockheader", &[header_hash]).await.map_err(|_| BlockSourceError::NoResponse)?)
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			let header_hash = serde_json::json!(header_hash.to_hex());
			let verbosity = serde_json::json!(0);
			Ok(self.call_method("getblock", &[header_hash, verbosity]).await.map_err(|_| BlockSourceError::NoResponse)?)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			Ok(self.call_method("getblockchaininfo", &[]).await.map_err(|_| BlockSourceError::NoResponse)?)
		})
	}
}

#[cfg(feature = "rest-client")]
impl BlockSource for RESTClient {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, _height: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			let resource_path = format!("headers/1/{}.json", header_hash.to_hex());
			Ok(self.request_resource::<JsonResponse, _>(&resource_path).await.map_err(|_| BlockSourceError::NoResponse)?)
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			let resource_path = format!("block/{}.bin", header_hash.to_hex());
			Ok(self.request_resource::<BinaryResponse, _>(&resource_path).await.map_err(|_| BlockSourceError::NoResponse)?)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			Ok(self.request_resource::<JsonResponse, _>("chaininfo.json").await.map_err(|_| BlockSourceError::NoResponse)?)
		})
	}
}

/// An HTTP response body in binary format.
struct BinaryResponse(Vec<u8>);

/// An HTTP response body in JSON format.
struct JsonResponse(serde_json::Value);

/// Interprets bytes from an HTTP response body as binary data.
impl TryFrom<Vec<u8>> for BinaryResponse {
	type Error = std::io::Error;

	fn try_from(bytes: Vec<u8>) -> std::io::Result<Self> {
		Ok(BinaryResponse(bytes))
	}
}

/// Parses binary data as a block.
impl TryInto<Block> for BinaryResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<Block> {
		match encode::deserialize(&self.0) {
			Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid block data")),
			Ok(block) => Ok(block),
		}
	}
}

/// Interprets bytes from an HTTP response body as a JSON value.
impl TryFrom<Vec<u8>> for JsonResponse {
	type Error = std::io::Error;

	fn try_from(bytes: Vec<u8>) -> std::io::Result<Self> {
		Ok(JsonResponse(serde_json::from_slice(&bytes)?))
	}
}

/// Converts a JSON value into block header data. The JSON value may be an object representing a
/// block header or an array of such objects. In the latter case, the first object is converted.
impl TryInto<BlockHeaderData> for JsonResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<BlockHeaderData> {
		let mut header = match self.0 {
			serde_json::Value::Array(mut array) if !array.is_empty() => array.drain(..).next().unwrap(),
			serde_json::Value::Object(_) => self.0,
			_ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unexpected JSON type")),
		};

		if !header.is_object() {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON object"));
		}

		// Add an empty previousblockhash for the genesis block.
		if let None = header.get("previousblockhash") {
			let hash: BlockHash = Default::default();
			header.as_object_mut().unwrap().insert("previousblockhash".to_string(), serde_json::json!(hash.to_hex()));
		}

		match serde_json::from_value::<GetHeaderResponse>(header) {
			Err(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid header response")),
			Ok(response) => match response.try_into() {
				Err(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid header data")),
				Ok(header) => Ok(header),
			},
		}
	}
}

/// Converts a JSON value into a block. Assumes the block is hex-encoded in a JSON string.
impl TryInto<Block> for JsonResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<Block> {
		match self.0.as_str() {
			None => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON string")),
			Some(hex_data) => match Vec::<u8>::from_hex(hex_data) {
				Err(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex data")),
				Ok(block_data) => match encode::deserialize(&block_data) {
					Err(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid block data")),
					Ok(block) => Ok(block),
				},
			},
		}
	}
}

/// Converts a JSON value into the best block hash and optional height.
impl TryInto<(BlockHash, Option<u32>)> for JsonResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<(BlockHash, Option<u32>)> {
		if !self.0.is_object() {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON object"));
		}

		let hash = match &self.0["bestblockhash"] {
			serde_json::Value::String(hex_data) => match BlockHash::from_hex(&hex_data) {
				Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex data")),
				Ok(block_hash) => block_hash,
			},
			_ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON string")),
		};

		let height = match &self.0["blocks"] {
			serde_json::Value::Null => None,
			serde_json::Value::Number(height) => match height.as_u64() {
				None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid height")),
				Some(height) => match height.try_into() {
					Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid height")),
					Ok(height) => Some(height),
				}
			},
			_ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON number")),
		};

		Ok((hash, height))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Write;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::consensus::encode;
	use bitcoin::network::constants::Network;

	/// Server for handling HTTP client requests with a stock response.
	struct HttpServer {
		address: std::net::SocketAddr,
		_handler: std::thread::JoinHandle<()>,
	}

	impl HttpServer {
		fn responding_with_ok<T: ToString>(body: Option<T>) -> Self {
			let body = body.map(|s| s.to_string()).unwrap_or_default();
			let response = format!(
				"HTTP/1.1 200 OK\r\n\
				 Content-Length: {}\r\n\
				 \r\n\
				 {}", body.len(), body);
			HttpServer::responding_with(response)
		}

		fn responding_with_not_found() -> Self {
			let response = "HTTP/1.1 404 Not Found\r\n\r\n".to_string();
			HttpServer::responding_with(response)
		}

		fn responding_with(response: String) -> Self {
			let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
			let address = listener.local_addr().unwrap();
			let _handler = std::thread::spawn(move || {
				for stream in listener.incoming() {
					match stream {
						Err(_) => panic!(),
						Ok(mut stream) => stream.write(response.as_bytes()).unwrap(),
					};
				}
			});

			Self { address, _handler }
		}

		fn endpoint(&self) -> HttpEndpoint {
			let uri = format!("http://{}:{}", self.address.ip(), self.address.port());
			HttpEndpoint::new(&uri).unwrap()
		}
	}

	/// Parses binary data as string-encoded u32.
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

	/// Converts a JSON value into u64.
	impl TryInto<u64> for JsonResponse {
		type Error = std::io::Error;

		fn try_into(self) -> std::io::Result<u64> {
			match self.0.as_u64() {
				None => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a number")),
				Some(n) => Ok(n),
			}
		}
	}

	/// Converts from `BlockHeaderData` into a `GetHeaderResponse` JSON value.
	impl From<BlockHeaderData> for serde_json::Value {
		fn from(data: BlockHeaderData) -> Self {
			let BlockHeaderData { chainwork, height, header } = data;
			serde_json::json!({
				"chainwork": chainwork.to_string()["0x".len()..],
				"height": height,
				"version": header.version,
				"merkleroot": header.merkle_root.to_hex(),
				"time": header.time,
				"nonce": header.nonce,
				"bits": header.bits.to_hex(),
				"previousblockhash": header.prev_blockhash.to_hex(),
			})
		}
	}

	#[test]
	fn connect_to_unresolvable_host() {
		match HttpClient::connect(("example.invalid", 80)) {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Other),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn connect_with_no_socket_address() {
		match HttpClient::connect(&vec![][..]) {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn connect_with_unknown_server() {
		match HttpClient::connect(("::", 80)) {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn connect_with_valid_endpoint() {
		let server = HttpServer::responding_with_ok::<String>(None);

		match HttpClient::connect(&server.endpoint()) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(_) => {},
		}
	}

	#[tokio::test]
	async fn request_unknown_resource() {
		let server = HttpServer::responding_with_not_found();
		let client = RESTClient::new(server.endpoint());

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn request_malformed_resource() {
		let server = HttpServer::responding_with_ok(Some("foo"));
		let client = RESTClient::new(server.endpoint());

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn request_valid_resource() {
		let server = HttpServer::responding_with_ok(Some(42));
		let client = RESTClient::new(server.endpoint());

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(n) => assert_eq!(n, 42),
		}
	}

	#[tokio::test]
	async fn call_method_returning_unknown_response() {
		let server = HttpServer::responding_with_not_found();
		let client = RPCClient::new("credentials", server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_malfomred_response() {
		let response = serde_json::json!("foo");
		let server = HttpServer::responding_with_ok(Some(response));
		let client = RPCClient::new("credentials", server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON object");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_error() {
		let response = serde_json::json!({
			"error": { "code": -8, "message": "invalid parameter" },
		});
		let server = HttpServer::responding_with_ok(Some(response));
		let client = RPCClient::new("credentials", server.endpoint());

		let invalid_block_hash = serde_json::json!("foo");
		match client.call_method::<u64>("getblock", &[invalid_block_hash]).await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid parameter");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_missing_result() {
		let response = serde_json::json!({ "result": null });
		let server = HttpServer::responding_with_ok(Some(response));
		let client = RPCClient::new("credentials", server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON result");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_valid_result() {
		let response = serde_json::json!({ "result": 654470 });
		let server = HttpServer::responding_with_ok(Some(response));
		let client = RPCClient::new("credentials", server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(count) => assert_eq!(count, 654470),
		}
	}

	#[test]
	fn from_bytes_into_binary_response() {
		let bytes = b"foo";
		match BinaryResponse::try_from(bytes.to_vec()) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(response) => assert_eq!(&response.0, bytes),
		}
	}

	#[test]
	fn from_invalid_bytes_into_json_response() {
		let json = serde_json::json!({ "result": 42 });
		match JsonResponse::try_from(json.to_string().as_bytes()[..5].to_vec()) {
			Err(_) => {},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn from_valid_bytes_into_json_response() {
		let json = serde_json::json!({ "result": 42 });
		match JsonResponse::try_from(json.to_string().as_bytes().to_vec()) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(response) => assert_eq!(response.0, json),
		}
	}

	#[test]
	fn into_block_header_from_json_response_with_unexpected_type() {
		let response = JsonResponse(serde_json::json!(42));
		match TryInto::<BlockHeaderData>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "unexpected JSON type");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_header_from_json_response_with_unexpected_header_type() {
		let response = JsonResponse(serde_json::json!([42]));
		match TryInto::<BlockHeaderData>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON object");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_header_from_json_response_with_invalid_header_response() {
		let block = genesis_block(Network::Bitcoin);
		let mut response = JsonResponse(BlockHeaderData {
			chainwork: block.header.work(),
			height: 0,
			header: block.header
		}.into());
		response.0["chainwork"].take();

		match TryInto::<BlockHeaderData>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid header response");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_header_from_json_response_with_invalid_header_data() {
		let block = genesis_block(Network::Bitcoin);
		let mut response = JsonResponse(BlockHeaderData {
			chainwork: block.header.work(),
			height: 0,
			header: block.header
		}.into());
		response.0["chainwork"] = serde_json::json!("foobar");

		match TryInto::<BlockHeaderData>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid header data");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_header_from_json_response_with_valid_header() {
		let block = genesis_block(Network::Bitcoin);
		let response = JsonResponse(BlockHeaderData {
			chainwork: block.header.work(),
			height: 0,
			header: block.header
		}.into());

		match TryInto::<BlockHeaderData>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(data) => {
				assert_eq!(data.chainwork, block.header.work());
				assert_eq!(data.height, 0);
				assert_eq!(data.header, block.header);
			},
		}
	}

	#[test]
	fn into_block_header_from_json_response_with_valid_header_array() {
		let genesis_block = genesis_block(Network::Bitcoin);
		let best_block_header = BlockHeader {
			prev_blockhash: genesis_block.block_hash(),
			..genesis_block.header
		};
		let chainwork = genesis_block.header.work() + best_block_header.work();
		let response = JsonResponse(serde_json::json!([
				serde_json::Value::from(BlockHeaderData {
					chainwork, height: 1, header: best_block_header,
				}),
				serde_json::Value::from(BlockHeaderData {
					chainwork: genesis_block.header.work(), height: 0, header: genesis_block.header,
				}),
		]));

		match TryInto::<BlockHeaderData>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(data) => {
				assert_eq!(data.chainwork, chainwork);
				assert_eq!(data.height, 1);
				assert_eq!(data.header, best_block_header);
			},
		}
	}

	#[test]
	fn into_block_header_from_json_response_without_previous_block_hash() {
		let block = genesis_block(Network::Bitcoin);
		let mut response = JsonResponse(BlockHeaderData {
			chainwork: block.header.work(),
			height: 0,
			header: block.header
		}.into());
		response.0.as_object_mut().unwrap().remove("previousblockhash");

		match TryInto::<BlockHeaderData>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(BlockHeaderData { chainwork: _, height: _, header }) => {
				assert_eq!(header, block.header);
			},
		}
	}

	#[test]
	fn into_block_from_invalid_binary_response() {
		let response = BinaryResponse(b"foo".to_vec());
		match TryInto::<Block>::try_into(response) {
			Err(_) => {},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_from_valid_binary_response() {
		let genesis_block = genesis_block(Network::Bitcoin);
		let response = BinaryResponse(encode::serialize(&genesis_block));
		match TryInto::<Block>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(block) => assert_eq!(block, genesis_block),
		}
	}

	#[test]
	fn into_block_from_json_response_with_unexpected_type() {
		let response = JsonResponse(serde_json::json!({ "result": "foo" }));
		match TryInto::<Block>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON string");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_from_json_response_with_invalid_hex_data() {
		let response = JsonResponse(serde_json::json!("foobar"));
		match TryInto::<Block>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid hex data");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_from_json_response_with_invalid_block_data() {
		let response = JsonResponse(serde_json::json!("abcd"));
		match TryInto::<Block>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid block data");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_from_json_response_with_valid_block_data() {
		let genesis_block = genesis_block(Network::Bitcoin);
		let response = JsonResponse(serde_json::json!(encode::serialize_hex(&genesis_block)));
		match TryInto::<Block>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(block) => assert_eq!(block, genesis_block),
		}
	}

	#[test]
	fn into_block_hash_from_json_response_with_unexpected_type() {
		let response = JsonResponse(serde_json::json!("foo"));
		match TryInto::<(BlockHash, Option<u32>)>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON object");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_hash_from_json_response_with_unexpected_bestblockhash_type() {
		let response = JsonResponse(serde_json::json!({ "bestblockhash": 42 }));
		match TryInto::<(BlockHash, Option<u32>)>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON string");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_hash_from_json_response_with_invalid_hex_data() {
		let response = JsonResponse(serde_json::json!({ "bestblockhash": "foobar"} ));
		match TryInto::<(BlockHash, Option<u32>)>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid hex data");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_hash_from_json_response_without_height() {
		let block = genesis_block(Network::Bitcoin);
		let response = JsonResponse(serde_json::json!({
			"bestblockhash": block.block_hash().to_hex(),
		}));
		match TryInto::<(BlockHash, Option<u32>)>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok((hash, height)) => {
				assert_eq!(hash, block.block_hash());
				assert!(height.is_none());
			},
		}
	}

	#[test]
	fn into_block_hash_from_json_response_with_unexpected_blocks_type() {
		let block = genesis_block(Network::Bitcoin);
		let response = JsonResponse(serde_json::json!({
			"bestblockhash": block.block_hash().to_hex(),
			"blocks": "foo",
		}));
		match TryInto::<(BlockHash, Option<u32>)>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON number");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_hash_from_json_response_with_invalid_height() {
		let block = genesis_block(Network::Bitcoin);
		let response = JsonResponse(serde_json::json!({
			"bestblockhash": block.block_hash().to_hex(),
			"blocks": u64::MAX,
		}));
		match TryInto::<(BlockHash, Option<u32>)>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid height");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_hash_from_json_response_with_height() {
		let block = genesis_block(Network::Bitcoin);
		let response = JsonResponse(serde_json::json!({
			"bestblockhash": block.block_hash().to_hex(),
			"blocks": 1,
		}));
		match TryInto::<(BlockHash, Option<u32>)>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok((hash, height)) => {
				assert_eq!(hash, block.block_hash());
				assert_eq!(height.unwrap(), 1);
			},
		}
	}
}
