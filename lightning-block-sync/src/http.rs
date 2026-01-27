//! Simple HTTP implementation which supports both async and traditional execution environments
//! with minimal dependencies. This is used as the basis for REST and RPC clients.

use serde_json;

#[cfg(feature = "tokio")]
use bitreq::RequestExt;

use std::convert::TryFrom;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

/// Timeout for operations on TCP streams.
const TCP_STREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for reading the first byte of a response. This is separate from the general read
/// timeout as it is not uncommon for Bitcoin Core to be blocked waiting on UTXO cache flushes for
/// upwards of 10 minutes on slow devices (e.g. RPis with SSDs over USB). Note that we always retry
/// once when we time out, so the maximum time we allow Bitcoin Core to block for is twice this
/// value.
const TCP_STREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum HTTP message header size in bytes.
const MAX_HTTP_MESSAGE_HEADER_SIZE: usize = 8192;

/// Maximum HTTP message body size in bytes. Enough for a hex-encoded block in JSON format and any
/// overhead for HTTP chunked transfer encoding.
const MAX_HTTP_MESSAGE_BODY_SIZE: usize = 2 * 4_000_000 + 32_000;

/// Endpoint for interacting with an HTTP-based API.
#[derive(Debug)]
pub struct HttpEndpoint {
	host: String,
	port: Option<u16>,
	path: String,
}

impl HttpEndpoint {
	/// Creates an endpoint for the given host and default HTTP port.
	pub fn for_host(host: String) -> Self {
		Self { host, port: None, path: String::from("/") }
	}

	/// Specifies a port to use with the endpoint.
	pub fn with_port(mut self, port: u16) -> Self {
		self.port = Some(port);
		self
	}

	/// Specifies a path to use with the endpoint.
	pub fn with_path(mut self, path: String) -> Self {
		self.path = path;
		self
	}

	/// Returns the endpoint host.
	pub fn host(&self) -> &str {
		&self.host
	}

	/// Returns the endpoint port.
	pub fn port(&self) -> u16 {
		match self.port {
			None => 80,
			Some(port) => port,
		}
	}

	/// Returns the endpoint path.
	pub fn path(&self) -> &str {
		&self.path
	}
}

impl<'a> std::net::ToSocketAddrs for &'a HttpEndpoint {
	type Iter = <(&'a str, u16) as std::net::ToSocketAddrs>::Iter;

	fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
		(self.host(), self.port()).to_socket_addrs()
	}
}

/// Maximum number of cached connections in the connection pool.
const MAX_CONNECTIONS: usize = 10;

/// Client for making HTTP requests.
pub(crate) struct HttpClient {
	address: SocketAddr,
	#[cfg(feature = "tokio")]
	client: bitreq::Client,
}

impl HttpClient {
	/// Opens a connection to an HTTP endpoint.
	pub fn connect<E: ToSocketAddrs>(endpoint: E) -> std::io::Result<Self> {
		let address = match endpoint.to_socket_addrs()?.next() {
			None => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidInput,
					"could not resolve to any addresses",
				));
			},
			Some(address) => address,
		};

		// Verify reachability by attempting a connection.
		let stream = std::net::TcpStream::connect_timeout(&address, TCP_STREAM_TIMEOUT)?;
		stream.set_read_timeout(Some(TCP_STREAM_TIMEOUT))?;
		stream.set_write_timeout(Some(TCP_STREAM_TIMEOUT))?;
		drop(stream);

		Ok(Self {
			address,
			#[cfg(feature = "tokio")]
			client: bitreq::Client::new(MAX_CONNECTIONS),
		})
	}

	/// Sends a `GET` request for a resource identified by `uri` at the `host`.
	///
	/// Returns the response body in `F` format.
	#[allow(dead_code)]
	pub async fn get<F>(&mut self, uri: &str, host: &str) -> std::io::Result<F>
	where
		F: TryFrom<Vec<u8>, Error = std::io::Error>,
	{
		let address = self.address;
		let response_body = self
			.send_request_with_retry(|| {
				let url = format!("http://{}{}", address, uri);
				bitreq::get(url)
					.with_header("Host", host)
					.with_header("Connection", "keep-alive")
					.with_timeout(TCP_STREAM_RESPONSE_TIMEOUT.as_secs())
					.with_max_headers_size(Some(MAX_HTTP_MESSAGE_HEADER_SIZE))
					.with_max_status_line_length(Some(MAX_HTTP_MESSAGE_HEADER_SIZE))
					.with_max_body_size(Some(MAX_HTTP_MESSAGE_BODY_SIZE))
			})
			.await?;
		F::try_from(response_body)
	}

	/// Sends a `POST` request for a resource identified by `uri` at the `host` using the given HTTP
	/// authentication credentials.
	///
	/// The request body consists of the provided JSON `content`. Returns the response body in `F`
	/// format.
	#[allow(dead_code)]
	pub async fn post<F>(
		&mut self, uri: &str, host: &str, auth: &str, content: serde_json::Value,
	) -> std::io::Result<F>
	where
		F: TryFrom<Vec<u8>, Error = std::io::Error>,
	{
		let address = self.address;
		let content = content.to_string();
		let response_body = self
			.send_request_with_retry(|| {
				let url = format!("http://{}{}", address, uri);
				bitreq::post(url)
					.with_header("Host", host)
					.with_header("Authorization", auth)
					.with_header("Connection", "keep-alive")
					.with_header("Content-Type", "application/json")
					.with_timeout(TCP_STREAM_RESPONSE_TIMEOUT.as_secs())
					.with_max_headers_size(Some(MAX_HTTP_MESSAGE_HEADER_SIZE))
					.with_max_status_line_length(Some(MAX_HTTP_MESSAGE_HEADER_SIZE))
					.with_max_body_size(Some(MAX_HTTP_MESSAGE_BODY_SIZE))
					.with_body(content.clone())
			})
			.await?;
		F::try_from(response_body)
	}

	/// Sends an HTTP request message and reads the response, returning its body. Attempts to
	/// reconnect and retry if the connection has been closed.
	async fn send_request_with_retry(
		&mut self, build_request: impl Fn() -> bitreq::Request,
	) -> std::io::Result<Vec<u8>> {
		match self.send_request(build_request()).await {
			Ok(bytes) => Ok(bytes),
			Err(_) => {
				// Reconnect and retry on fail. This can happen if the connection was closed after
				// the keep-alive limits are reached, or generally if the request timed out due to
				// Bitcoin Core being stuck on a long-running operation or its RPC queue being
				// full.
				// Block 100ms before retrying the request as in many cases the source of the error
				// may be persistent for some time.
				#[cfg(feature = "tokio")]
				tokio::time::sleep(Duration::from_millis(100)).await;
				#[cfg(not(feature = "tokio"))]
				std::thread::sleep(Duration::from_millis(100));
				*self = Self::connect(self.address)?;
				self.send_request(build_request()).await
			},
		}
	}

	/// Sends an HTTP request message and reads the response, returning its body.
	async fn send_request(&self, request: bitreq::Request) -> std::io::Result<Vec<u8>> {
		#[cfg(feature = "tokio")]
		let response = request.send_async_with_client(&self.client).await.map_err(bitreq_to_io_error)?;
		#[cfg(not(feature = "tokio"))]
		let response = request.send().map_err(bitreq_to_io_error)?;

		let status_code = response.status_code;
		let body = response.into_bytes();

		if !(200..300).contains(&status_code) {
			let error = HttpError { status_code: status_code.to_string(), contents: body };
			return Err(std::io::Error::new(std::io::ErrorKind::Other, error));
		}

		Ok(body)
	}
}

/// Converts a bitreq error to an std::io::Error.
fn bitreq_to_io_error(err: bitreq::Error) -> std::io::Error {
	use std::io::ErrorKind;

	let kind = match &err {
		bitreq::Error::IoError(e) => e.kind(),
		bitreq::Error::HeadersOverflow
		| bitreq::Error::StatusLineOverflow
		| bitreq::Error::BodyOverflow
		| bitreq::Error::MalformedChunkLength
		| bitreq::Error::MalformedChunkEnd
		| bitreq::Error::MalformedContentLength
		| bitreq::Error::InvalidUtf8InResponse
		| bitreq::Error::InvalidUtf8InBody(_) => ErrorKind::InvalidData,
		bitreq::Error::AddressNotFound | bitreq::Error::HttpsFeatureNotEnabled => {
			ErrorKind::InvalidInput
		},
		_ => ErrorKind::Other,
	};

	std::io::Error::new(kind, err)
}

/// HTTP error consisting of a status code and body contents.
#[derive(Debug)]
pub(crate) struct HttpError {
	pub(crate) status_code: String,
	pub(crate) contents: Vec<u8>,
}

impl std::error::Error for HttpError {}

impl fmt::Display for HttpError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let contents = String::from_utf8_lossy(&self.contents);
		write!(f, "status_code: {}, contents: {}", self.status_code, contents)
	}
}

/// An HTTP response body in binary format.
pub struct BinaryResponse(pub Vec<u8>);

/// An HTTP response body in JSON format.
pub struct JsonResponse(pub serde_json::Value);

/// Interprets bytes from an HTTP response body as binary data.
impl TryFrom<Vec<u8>> for BinaryResponse {
	type Error = std::io::Error;

	fn try_from(bytes: Vec<u8>) -> std::io::Result<Self> {
		Ok(BinaryResponse(bytes))
	}
}

/// Interprets bytes from an HTTP response body as a JSON value.
impl TryFrom<Vec<u8>> for JsonResponse {
	type Error = std::io::Error;

	fn try_from(bytes: Vec<u8>) -> std::io::Result<Self> {
		Ok(JsonResponse(serde_json::from_slice(&bytes)?))
	}
}

#[cfg(test)]
mod endpoint_tests {
	use super::HttpEndpoint;

	#[test]
	fn with_default_port() {
		let endpoint = HttpEndpoint::for_host("foo.com".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.port(), 80);
	}

	#[test]
	fn with_custom_port() {
		let endpoint = HttpEndpoint::for_host("foo.com".into()).with_port(8080);
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.port(), 8080);
	}

	#[test]
	fn with_uri_path() {
		let endpoint = HttpEndpoint::for_host("foo.com".into()).with_path("/path".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.path(), "/path");
	}

	#[test]
	fn without_uri_path() {
		let endpoint = HttpEndpoint::for_host("foo.com".into());
		assert_eq!(endpoint.host(), "foo.com");
		assert_eq!(endpoint.path(), "/");
	}

	#[test]
	fn convert_to_socket_addrs() {
		let endpoint = HttpEndpoint::for_host("localhost".into());
		let host = endpoint.host();
		let port = endpoint.port();

		use std::net::ToSocketAddrs;
		match (&endpoint).to_socket_addrs() {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(socket_addrs) => {
				let mut std_addrs = (host, port).to_socket_addrs().unwrap();
				for addr in socket_addrs {
					assert_eq!(addr, std_addrs.next().unwrap());
				}
				assert!(std_addrs.next().is_none());
			},
		}
	}
}

#[cfg(test)]
pub(crate) mod client_tests {
	use super::*;
	use std::io::{BufRead, Read, Write};

	/// Server for handling HTTP client requests with a stock response.
	pub struct HttpServer {
		address: std::net::SocketAddr,
		handler: Option<std::thread::JoinHandle<()>>,
		shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
	}

	impl Drop for HttpServer {
		fn drop(&mut self) {
			self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
			// Make a connection to unblock the listener's accept() call
			let _ = std::net::TcpStream::connect(self.address);
			if let Some(handler) = self.handler.take() {
				let _ = handler.join();
			}
		}
	}

	/// Body of HTTP response messages.
	pub enum MessageBody<T: ToString> {
		Empty,
		Content(T),
		ChunkedContent(T),
	}

	/// Encodes a body using chunked transfer encoding.
	fn encode_chunked(body: &str, chunk_size: usize) -> String {
		let mut out = String::new();
		for chunk in body.as_bytes().chunks(chunk_size) {
			out.push_str(&format!("{:X}\r\n", chunk.len()));
			out.push_str(std::str::from_utf8(chunk).unwrap());
			out.push_str("\r\n");
		}
		out.push_str("0\r\n\r\n");
		out
	}

	impl HttpServer {
		fn responding_with_body<T: ToString>(status: &str, body: MessageBody<T>) -> Self {
			let response = match body {
				MessageBody::Empty => format!(
					"{}\r\n\
					 Content-Length: 0\r\n\
					 \r\n",
					status
				),
				MessageBody::Content(body) => {
					let body = body.to_string();
					format!(
						"{}\r\n\
						 Content-Length: {}\r\n\
						 \r\n\
						 {}",
						status,
						body.len(),
						body
					)
				},
				MessageBody::ChunkedContent(body) => {
					let body = body.to_string();
					let chunked_body = encode_chunked(&body, 8);
					format!(
						"{}\r\n\
						 Transfer-Encoding: chunked\r\n\
						 \r\n\
						 {}",
						status, chunked_body
					)
				},
			};
			HttpServer::responding_with(response)
		}

		pub fn responding_with_ok<T: ToString>(body: MessageBody<T>) -> Self {
			HttpServer::responding_with_body("HTTP/1.1 200 OK", body)
		}

		pub fn responding_with_not_found() -> Self {
			HttpServer::responding_with_body::<String>("HTTP/1.1 404 Not Found", MessageBody::Empty)
		}

		pub fn responding_with_server_error<T: ToString>(content: T) -> Self {
			let body = MessageBody::Content(content);
			HttpServer::responding_with_body("HTTP/1.1 500 Internal Server Error", body)
		}

		fn responding_with(response: String) -> Self {
			let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
			let address = listener.local_addr().unwrap();

			let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
			let shutdown_signaled = std::sync::Arc::clone(&shutdown);
			let handler = std::thread::spawn(move || {
				for stream in listener.incoming() {
					if shutdown_signaled.load(std::sync::atomic::Ordering::SeqCst) {
						return;
					}

					let stream = stream.unwrap();
					stream.set_write_timeout(Some(TCP_STREAM_TIMEOUT)).unwrap();
					stream.set_read_timeout(Some(TCP_STREAM_TIMEOUT)).unwrap();

					let mut reader = std::io::BufReader::new(stream);

					// Handle multiple requests on the same connection (keep-alive)
					loop {
						if shutdown_signaled.load(std::sync::atomic::Ordering::SeqCst) {
							return;
						}

						// Read request headers
						let mut lines_read = 0;
						let mut content_length: usize = 0;
						loop {
							let mut line = String::new();
							match reader.read_line(&mut line) {
								Ok(0) => break, // eof
								Ok(_) => {
									if line == "\r\n" || line == "\n" {
										break; // end of headers
									}
									// Parse content_length for POST body handling
									if let Some(value) = line.strip_prefix("Content-Length:") {
										content_length = value.trim().parse().unwrap_or(0);
									}
									lines_read += 1;
								},
								Err(_) => break, // Read error or timeout
							}
						}

						if lines_read == 0 {
							break; // No request received, connection closed
						}

						// Consume request body if present (needed for POST keep-alive)
						if content_length > 0 {
							let mut body = vec![0u8; content_length];
							if reader.read_exact(&mut body).is_err() {
								break;
							}
						}

						// Send response
						let stream = reader.get_mut();
						let mut write_error = false;
						for chunk in response.as_bytes().chunks(16) {
							if shutdown_signaled.load(std::sync::atomic::Ordering::SeqCst) {
								return;
							}
							if stream.write(chunk).is_err() || stream.flush().is_err() {
								write_error = true;
								break;
							}
						}
						if write_error {
							break;
						}
					}
				}
			});

			Self { address, handler: Some(handler), shutdown }
		}

		pub fn endpoint(&self) -> HttpEndpoint {
			HttpEndpoint::for_host(self.address.ip().to_string()).with_port(self.address.port())
		}
	}

	#[test]
	fn connect_to_unresolvable_host() {
		match HttpClient::connect(("example.invalid", 80)) {
			Err(e) => {
				assert!(
					e.to_string().contains("failed to lookup address information")
						|| e.to_string().contains("No such host"),
					"{:?}",
					e
				);
			},
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
		// get an unused port by binding to port 0
		let port = {
			let t = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
			t.local_addr().unwrap().port()
		};

		match HttpClient::connect(("::", port)) {
			#[cfg(target_os = "windows")]
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::AddrNotAvailable),
			#[cfg(not(target_os = "windows"))]
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
	async fn read_error() {
		let server = HttpServer::responding_with_server_error("foo");

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		match client.get::<JsonResponse>("/foo", "foo.com").await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				let http_error = e.into_inner().unwrap().downcast::<HttpError>().unwrap();
				assert_eq!(http_error.status_code, "500");
				assert_eq!(http_error.contents, "foo".as_bytes());
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
	async fn reconnect_closed_connection() {
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Empty);

		let mut client = HttpClient::connect(&server.endpoint()).unwrap();
		assert!(client.get::<BinaryResponse>("/foo", "foo.com").await.is_ok());
		match client.get::<BinaryResponse>("/foo", "foo.com").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, Vec::<u8>::new()),
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
}
