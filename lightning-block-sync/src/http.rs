//! Simple HTTP implementation which supports both async and traditional execution environments
//! with minimal dependencies. This is used as the basis for REST and RPC clients.

use serde_json;

#[cfg(feature = "tokio")]
use bitreq::RequestExt;

use std::convert::Infallible;
use std::convert::TryFrom;
use std::fmt;

/// Trait for converting parse errors into a String message.
pub trait ToParseErrorMessage {
	/// Converts a parse error into a human-readable message.
	fn to_parse_error_message(self) -> String;
}

impl ToParseErrorMessage for Infallible {
	fn to_parse_error_message(self) -> String {
		match self {}
	}
}

impl ToParseErrorMessage for () {
	fn to_parse_error_message(self) -> String {
		"invalid data".to_string()
	}
}

impl ToParseErrorMessage for &'static str {
	fn to_parse_error_message(self) -> String {
		self.to_string()
	}
}

impl ToParseErrorMessage for String {
	fn to_parse_error_message(self) -> String {
		self
	}
}

/// Timeout for requests in seconds. This is set to a high value as it is not uncommon for Bitcoin
/// Core to be blocked waiting on UTXO cache flushes for upwards of 10 minutes on slow devices
/// (e.g. RPis with SSDs over USB).
const TCP_STREAM_RESPONSE_TIMEOUT: u64 = 300;

/// Maximum HTTP message body size in bytes. Enough for a hex-encoded block in JSON format and any
/// overhead for HTTP chunked transfer encoding.
const MAX_HTTP_MESSAGE_BODY_SIZE: usize = 2 * 4_000_000 + 32_000;

/// Error type for HTTP client operations.
#[derive(Debug)]
pub enum HttpClientError {
	/// transport-level error (connection, timeout, protocol parsing, etc.)
	Transport(bitreq::Error),
	/// HTTP error response (non-2xx status code)
	Http(HttpError),
	/// Response parsing/conversion error
	Parse(String),
}

impl std::error::Error for HttpClientError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			HttpClientError::Transport(e) => Some(e),
			HttpClientError::Http(e) => Some(e),
			HttpClientError::Parse(_) => None,
		}
	}
}

impl fmt::Display for HttpClientError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			HttpClientError::Transport(e) => write!(f, "transport error: {}", e),
			HttpClientError::Http(e) => write!(f, "HTTP error: {}", e),
			HttpClientError::Parse(e) => write!(f, "response parsing error: {}", e),
		}
	}
}

impl From<bitreq::Error> for HttpClientError {
	fn from(e: bitreq::Error) -> Self {
		HttpClientError::Transport(e)
	}
}

impl From<HttpError> for HttpClientError {
	fn from(e: HttpError) -> Self {
		HttpClientError::Http(e)
	}
}

/// Maximum number of cached connections in the connection pool.
#[cfg(feature = "tokio")]
const MAX_CONNECTIONS: usize = 10;

/// Client for making HTTP requests.
pub(crate) struct HttpClient {
	base_url: String,
	#[cfg(feature = "tokio")]
	client: bitreq::Client,
}

impl HttpClient {
	/// Creates a new HTTP client for the given base URL.
	///
	/// The base URL should include the scheme, host, and port (e.g., "http://127.0.0.1:8332").
	/// DNS resolution is deferred until the first request is made.
	pub fn new(base_url: String) -> Self {
		Self {
			base_url,
			#[cfg(feature = "tokio")]
			client: bitreq::Client::new(MAX_CONNECTIONS),
		}
	}

	/// Sends a `GET` request for a resource identified by `uri`.
	///
	/// Returns the response body in `F` format.
	#[allow(dead_code)]
	pub async fn get<F>(&self, uri: &str) -> Result<F, HttpClientError>
	where
		F: TryFrom<Vec<u8>>,
		<F as TryFrom<Vec<u8>>>::Error: ToParseErrorMessage,
	{
		let url = format!("{}{}", self.base_url, uri);
		let request = bitreq::get(url)
			.with_timeout(TCP_STREAM_RESPONSE_TIMEOUT)
			.with_max_body_size(Some(MAX_HTTP_MESSAGE_BODY_SIZE));
		#[cfg(feature = "tokio")]
		let request = request.with_pipelining();
		let response_body = self.send_request(request).await?;
		F::try_from(response_body).map_err(|e| HttpClientError::Parse(e.to_parse_error_message()))
	}

	/// Sends a `POST` request for a resource identified by `uri` using the given HTTP
	/// authentication credentials.
	///
	/// The request body consists of the provided JSON `content`. Returns the response body in `F`
	/// format.
	#[allow(dead_code)]
	pub async fn post<F>(
		&self, uri: &str, auth: &str, content: serde_json::Value,
	) -> Result<F, HttpClientError>
	where
		F: TryFrom<Vec<u8>>,
		<F as TryFrom<Vec<u8>>>::Error: ToParseErrorMessage,
	{
		let url = format!("{}{}", self.base_url, uri);
		let request = bitreq::post(url)
			.with_header("Authorization", auth)
			.with_header("Content-Type", "application/json")
			.with_timeout(TCP_STREAM_RESPONSE_TIMEOUT)
			.with_max_body_size(Some(MAX_HTTP_MESSAGE_BODY_SIZE))
			.with_body(content.to_string());
		#[cfg(feature = "tokio")]
		let request = request.with_pipelining();
		let response_body = self.send_request(request).await?;
		F::try_from(response_body).map_err(|e| HttpClientError::Parse(e.to_parse_error_message()))
	}

	/// Sends an HTTP request message and reads the response, returning its body.
	async fn send_request(&self, request: bitreq::Request) -> Result<Vec<u8>, HttpClientError> {
		#[cfg(feature = "tokio")]
		let response = request.send_async_with_client(&self.client).await?;
		#[cfg(not(feature = "tokio"))]
		let response = request.send()?;

		let status_code = response.status_code;
		let body = response.into_bytes();

		if !(200..300).contains(&status_code) {
			return Err(HttpError { status_code, contents: body }.into());
		}

		Ok(body)
	}
}

/// HTTP error consisting of a status code and body contents.
#[derive(Debug)]
pub struct HttpError {
	/// The HTTP status code.
	pub status_code: i32,
	/// The response body contents.
	pub contents: Vec<u8>,
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
	type Error = Infallible;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Infallible> {
		Ok(BinaryResponse(bytes))
	}
}

/// Interprets bytes from an HTTP response body as a JSON value.
impl TryFrom<Vec<u8>> for JsonResponse {
	type Error = String;

	fn try_from(bytes: Vec<u8>) -> Result<Self, String> {
		serde_json::from_slice(&bytes).map(JsonResponse).map_err(|e| e.to_string())
	}
}

#[cfg(test)]
pub(crate) mod client_tests {
	use super::*;
	use std::io::{BufRead, Read, Write};
	use std::time::Duration;

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
				let timeout = Duration::from_secs(5);
				for stream in listener.incoming() {
					if shutdown_signaled.load(std::sync::atomic::Ordering::SeqCst) {
						return;
					}

					let stream = stream.unwrap();
					stream.set_write_timeout(Some(timeout)).unwrap();
					stream.set_read_timeout(Some(timeout)).unwrap();

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

		pub fn endpoint(&self) -> String {
			format!("http://{}:{}", self.address.ip(), self.address.port())
		}
	}

	#[tokio::test]
	async fn connect_with_invalid_host() {
		let client = HttpClient::new("http://invalid.host.example:80".to_string());
		match client.get::<JsonResponse>("/foo").await {
			Err(HttpClientError::Transport(_)) => {},
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_error() {
		let server = HttpServer::responding_with_server_error("foo");

		let client = HttpClient::new(server.endpoint());
		match client.get::<JsonResponse>("/foo").await {
			Err(HttpClientError::Http(http_error)) => {
				assert_eq!(http_error.status_code, 500);
				assert_eq!(http_error.contents, "foo".as_bytes());
			},
			Err(e) => panic!("Unexpected error type: {:?}", e),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn read_message_body() {
		let body = "foo bar baz qux".repeat(32);
		let content = MessageBody::Content(body.clone());
		let server = HttpServer::responding_with_ok::<String>(content);

		let client = HttpClient::new(server.endpoint());
		match client.get::<BinaryResponse>("/foo").await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(bytes) => assert_eq!(bytes.0, body.as_bytes()),
		}
	}

	#[tokio::test]
	async fn reconnect_closed_connection() {
		let server = HttpServer::responding_with_ok::<String>(MessageBody::Empty);

		let client = HttpClient::new(server.endpoint());
		assert!(client.get::<BinaryResponse>("/foo").await.is_ok());
		match client.get::<BinaryResponse>("/foo").await {
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
