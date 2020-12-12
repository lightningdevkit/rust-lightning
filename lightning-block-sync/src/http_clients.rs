use crate::http_endpoint::HttpEndpoint;
use crate::utils::hex_to_uint256;
use crate::{BlockHeaderData, BlockSource, BlockSourceError, AsyncBlockSourceResult};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::encode;
use bitcoin::hash_types::{BlockHash, TxMerkleNode};
use bitcoin::hashes::hex::{ToHex, FromHex};

use chunked_transfer;

use serde_derive::Deserialize;

use serde_json;

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
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;

#[cfg(not(feature = "tokio"))]
use std::io::BufRead;
use std::io::Read;
#[cfg(not(feature = "tokio"))]
use std::net::TcpStream;

/// Maximum HTTP message header size in bytes.
const MAX_HTTP_MESSAGE_HEADER_SIZE: usize = 8192;

/// Maximum HTTP message body size in bytes.
const MAX_HTTP_MESSAGE_BODY_SIZE: usize = 4_000_000;

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
		let stream = {
			stream.set_nonblocking(true)?;
			TcpStream::from_std(stream)?
		};

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
		self.write_request(request).await?;
		let bytes = self.read_response().await?;
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
		self.write_request(request).await?;
		let bytes = self.read_response().await?;
		F::try_from(bytes)
	}

	/// Writes an HTTP request message.
	async fn write_request(&mut self, request: String) -> std::io::Result<()> {
		#[cfg(feature = "tokio")]
		{
			self.stream.write_all(request.as_bytes()).await?;
			self.stream.flush().await
		}
		#[cfg(not(feature = "tokio"))]
		{
			self.stream.write_all(request.as_bytes())?;
			self.stream.flush()
		}
	}

	/// Reads an HTTP response message.
	async fn read_response(&mut self) -> std::io::Result<Vec<u8>> {
		#[cfg(feature = "tokio")]
		let stream = self.stream.split().0;
		#[cfg(not(feature = "tokio"))]
		let stream = std::io::Read::by_ref(&mut self.stream);

		let limited_stream = stream.take(MAX_HTTP_MESSAGE_HEADER_SIZE as u64);

		#[cfg(feature = "tokio")]
		let mut reader = tokio::io::BufReader::new(limited_stream);
		#[cfg(not(feature = "tokio"))]
		let mut reader = std::io::BufReader::new(limited_stream);

		macro_rules! read_line { () => { {
			let mut line = String::new();
			#[cfg(feature = "tokio")]
			let bytes_read = reader.read_line(&mut line).await?;
			#[cfg(not(feature = "tokio"))]
			let bytes_read = reader.read_line(&mut line)?;

			match bytes_read {
				0 => None,
				_ => {
					// Remove trailing CRLF
					if line.ends_with('\n') { line.pop(); if line.ends_with('\r') { line.pop(); } }
					Some(line)
				},
			}
		} } }

		// Read and parse status line
		let status_line = read_line!()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line"))?;
		let status = HttpStatus::parse(&status_line)?;

		// Read and parse relevant headers
		let mut message_length = HttpMessageLength::Empty;
		loop {
			let line = read_line!()
				.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "unexpected eof"))?;
			if line.is_empty() { break; }

			let header = HttpHeader::parse(&line)?;
			if header.has_name("Content-Length") {
				let length = header.value.parse()
					.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
				if let HttpMessageLength::Empty = message_length {
					message_length = HttpMessageLength::ContentLength(length);
				}
				continue;
			}

			if header.has_name("Transfer-Encoding") {
				message_length = HttpMessageLength::TransferEncoding(header.value.into());
				continue;
			}
		}

		if !status.is_ok() {
			return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"));
		}

		// Read message body
		let read_limit = MAX_HTTP_MESSAGE_BODY_SIZE - reader.buffer().len();
		reader.get_mut().set_limit(read_limit as u64);
		match message_length {
			HttpMessageLength::Empty => { Ok(Vec::new()) },
			HttpMessageLength::ContentLength(length) => {
				if length == 0 || length > MAX_HTTP_MESSAGE_BODY_SIZE {
					Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "out of range"))
				} else {
					let mut content = vec![0; length];
					#[cfg(feature = "tokio")]
					reader.read_exact(&mut content[..]).await?;
					#[cfg(not(feature = "tokio"))]
					reader.read_exact(&mut content[..])?;
					Ok(content)
				}
			},
			HttpMessageLength::TransferEncoding(coding) => {
				if !coding.eq_ignore_ascii_case("chunked") {
					Err(std::io::Error::new(
							std::io::ErrorKind::InvalidInput, "unsupported transfer coding"))
				} else {
					#[cfg(feature = "tokio")]
					let reader = ReadAdapter(&mut reader);
					let mut decoder = chunked_transfer::Decoder::new(reader);
					let mut content = Vec::new();
					decoder.read_to_end(&mut content)?;
					Ok(content)
				}
			},
		}
	}
}

/// HTTP response status code as defined by [RFC 7231].
///
/// [RFC 7231]: https://tools.ietf.org/html/rfc7231#section-6
struct HttpStatus<'a> {
	code: &'a str,
}

impl<'a> HttpStatus<'a> {
	/// Parses an HTTP status line as defined by [RFC 7230].
	///
	/// [RFC 7230]: https://tools.ietf.org/html/rfc7230#section-3.1.2
	fn parse(line: &'a String) -> std::io::Result<HttpStatus<'a>> {
		let mut tokens = line.splitn(3, ' ');

		let http_version = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no HTTP-Version"))?;
		if !http_version.eq_ignore_ascii_case("HTTP/1.1") &&
			!http_version.eq_ignore_ascii_case("HTTP/1.0") {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP-Version"));
		}

		let code = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no Status-Code"))?;
		if code.len() != 3 || !code.chars().all(|c| c.is_ascii_digit()) {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Status-Code"));
		}

		let _reason = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no Reason-Phrase"))?;

		Ok(Self { code })
	}

	/// Returns whether the status is successful (i.e., 2xx status class).
	fn is_ok(&self) -> bool {
		self.code.starts_with('2')
	}
}

/// HTTP response header as defined by [RFC 7231].
///
/// [RFC 7231]: https://tools.ietf.org/html/rfc7231#section-7
struct HttpHeader<'a> {
	name: &'a str,
	value: &'a str,
}

impl<'a> HttpHeader<'a> {
	/// Parses an HTTP header field as defined by [RFC 7230].
	///
	/// [RFC 7230]: https://tools.ietf.org/html/rfc7230#section-3.2
	fn parse(line: &'a String) -> std::io::Result<HttpHeader<'a>> {
		let mut tokens = line.splitn(2, ':');
		let name = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no header name"))?;
		let value = tokens.next()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "no header value"))?
			.trim_start();
		Ok(Self { name, value })
	}

	/// Returns whether or the header field has the given name.
	fn has_name(&self, name: &str) -> bool {
		self.name.eq_ignore_ascii_case(name)
	}
}

/// HTTP message body length as defined by [RFC 7230].
///
/// [RFC 7230]: https://tools.ietf.org/html/rfc7230#section-3.3.3
enum HttpMessageLength {
	Empty,
	ContentLength(usize),
	TransferEncoding(String),
}

/// An adaptor work making `tokio::io::AsyncRead` compatible with interfaces expecting
/// `std::io::Read`. This effectively makes the adapted object synchronous.
#[cfg(feature = "tokio")]
struct ReadAdapter<'a, R: tokio::io::AsyncRead + std::marker::Unpin>(&'a mut R);

#[cfg(feature = "tokio")]
impl<'a, R: tokio::io::AsyncRead + std::marker::Unpin> std::io::Read for ReadAdapter<'a, R> {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		futures::executor::block_on(self.0.read(buf))
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
			Ok(self.call_method("getblockheader", &[header_hash]).await?)
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			let header_hash = serde_json::json!(header_hash.to_hex());
			let verbosity = serde_json::json!(0);
			Ok(self.call_method("getblock", &[header_hash, verbosity]).await?)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			Ok(self.call_method("getblockchaininfo", &[]).await?)
		})
	}
}

#[cfg(feature = "rest-client")]
impl BlockSource for RESTClient {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, _height: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			let resource_path = format!("headers/1/{}.json", header_hash.to_hex());
			Ok(self.request_resource::<JsonResponse, _>(&resource_path).await?)
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			let resource_path = format!("block/{}.bin", header_hash.to_hex());
			Ok(self.request_resource::<BinaryResponse, _>(&resource_path).await?)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			Ok(self.request_resource::<JsonResponse, _>("chaininfo.json").await?)
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

/// Conversion from `std::io::Error` into `BlockSourceError`.
impl From<std::io::Error> for BlockSourceError {
	fn from(e: std::io::Error) -> BlockSourceError {
		match e.kind() {
			std::io::ErrorKind::InvalidData => BlockSourceError::Persistent,
			std::io::ErrorKind::InvalidInput => BlockSourceError::Persistent,
			_ => BlockSourceError::Transient,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::BufRead;
	use std::io::Write;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::consensus::encode;
	use bitcoin::network::constants::Network;

	/// Server for handling HTTP client requests with a stock response.
	struct HttpServer {
		address: std::net::SocketAddr,
		handler: std::thread::JoinHandle<()>,
		shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
	}

	/// Body of HTTP response messages.
	enum MessageBody<T: ToString> {
		Empty,
		Content(T),
		ChunkedContent(T),
	}

	impl HttpServer {
		fn responding_with_ok<T: ToString>(body: MessageBody<T>) -> Self {
			let response = match body {
				MessageBody::Empty => "HTTP/1.1 200 OK\r\n\r\n".to_string(),
				MessageBody::Content(body) => {
					let body = body.to_string();
					format!(
						"HTTP/1.1 200 OK\r\n\
						 Content-Length: {}\r\n\
						 \r\n\
						 {}", body.len(), body)
				},
				MessageBody::ChunkedContent(body) => {
					let mut chuncked_body = Vec::new();
					{
						use chunked_transfer::Encoder;
						let mut encoder = Encoder::with_chunks_size(&mut chuncked_body, 8);
						encoder.write_all(body.to_string().as_bytes()).unwrap();
					}
					format!(
						"HTTP/1.1 200 OK\r\n\
						 Transfer-Encoding: chunked\r\n\
						 \r\n\
						 {}", String::from_utf8(chuncked_body).unwrap())
				},
			};
			HttpServer::responding_with(response)
		}

		fn responding_with_not_found() -> Self {
			let response = "HTTP/1.1 404 Not Found\r\n\r\n".to_string();
			HttpServer::responding_with(response)
		}

		fn responding_with(response: String) -> Self {
			let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
			let address = listener.local_addr().unwrap();

			let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
			let shutdown_signaled = std::sync::Arc::clone(&shutdown);
			let handler = std::thread::spawn(move || {
				let (mut stream, _) = listener.accept().unwrap();
				stream.set_write_timeout(Some(Duration::from_secs(1))).unwrap();

				let lines_read = std::io::BufReader::new(&stream)
					.lines()
					.take_while(|line| !line.as_ref().unwrap().is_empty())
					.count();
				if lines_read == 0 { return; }

				for chunk in response.as_bytes().chunks(16) {
					if shutdown_signaled.load(std::sync::atomic::Ordering::SeqCst) {
						break;
					} else {
						stream.write(chunk).unwrap();
						stream.flush().unwrap();
					}
				}
			});

			Self { address, handler, shutdown }
		}

		fn shutdown(self) {
			self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
			self.handler.join().unwrap();
		}

		fn endpoint(&self) -> HttpEndpoint {
			HttpEndpoint::insecure_host(self.address.ip().to_string())
				.with_port(self.address.port())
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
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Empty);

		match HttpClient::connect(&server.endpoint()) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(_) => {},
		}
	}

	#[tokio::test]
	async fn read_empty_message() {
		let server = HttpServer::responding_with("".to_string());

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		drop(server);
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "no status line");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_incomplete_message() {
		let server = HttpServer::responding_with("HTTP/1.1 200 OK".to_string());

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		drop(server);
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "unexpected eof");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_too_large_message_headers() {
		let response = format!(
			"HTTP/1.1 302 Found\r\n\
			 Location: {}\r\n\
			 \r\n", "Z".repeat(MAX_HTTP_MESSAGE_HEADER_SIZE));
		let server = HttpServer::responding_with(response);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "unexpected eof");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_too_large_message_body() {
		let body = "Z".repeat(MAX_HTTP_MESSAGE_BODY_SIZE + 1);
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Content(body));

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "out of range");
			},
			Ok(_) => panic!("Expected error"),
		}
		server.shutdown();
	}

	#[tokio::test]
	async fn read_message_with_unsupported_transfer_coding() {
		let response = String::from(
			"HTTP/1.1 200 OK\r\n\
			 Transfer-Encoding: gzip\r\n\
			 \r\n\
			 foobar");
		let server = HttpServer::responding_with(response);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
				assert_eq!(e.get_ref().unwrap().to_string(), "unsupported transfer coding");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_empty_message_body() {
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Empty);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, Vec::<u8>::new()),
		}
	}

	#[tokio::test]
	async fn read_message_body_with_length() {
		let body = "foo bar baz qux".repeat(32);
		let content = MessageBody::Content(body.clone());
		let server = HttpServer::responding_with_ok::<String>(content);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, body.as_bytes()),
		}
	}

	#[tokio::test]
	async fn read_chunked_message_body() {
		let body = "foo bar baz qux".repeat(32);
		let chunked_content = MessageBody::ChunkedContent(body.clone());
		let server = HttpServer::responding_with_ok::<String>(chunked_content);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, body.as_bytes()),
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
		let server = HttpServer::responding_with_ok(MessageBody::Content("foo"));
		let client = RESTClient::new(server.endpoint());

		match client.request_resource::<BinaryResponse, u32>("/").await {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn request_valid_resource() {
		let server = HttpServer::responding_with_ok(MessageBody::Content(42));
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
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
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
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
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
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
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
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
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
