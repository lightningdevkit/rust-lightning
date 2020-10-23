use crate::http_endpoint::HttpEndpoint;
use crate::utils::hex_to_uint256;
use crate::{BlockHeaderData, BlockSource, BlockSourceRespErr};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::encode;
use bitcoin::hash_types::{BlockHash, TxMerkleNode};
use bitcoin::hashes::hex::{ToHex, FromHex};

use serde_derive::Deserialize;

use serde_json;

use std::cmp;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::future::Future;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::time::Duration;

#[cfg(feature = "rpc-client")]
use base64;
#[cfg(feature = "rpc-client")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "tokio")]
use tokio::io::AsyncReadExt;
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
	fn connect(endpoint: &HttpEndpoint) -> std::io::Result<Self> {
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
		write!(self.stream,
			"GET {} HTTP/1.1\r\n\
			 Host: {}\r\n\
			 Connection: keep-alive\r\n\
			 \r\n", uri, host)?;

		match read_http_resp(&self.stream, MAX_HTTP_RESPONSE_LEN).await {
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "read error")),
			Some(bytes) => F::try_from(bytes),
		}
	}

	/// Sends a `POST` request for a resource identified by `uri` at the `host` using the given HTTP
	/// authentication credentials.
	///
	/// The request body consists of the provided JSON `content`. Returns the response body in `F`
	/// format.
	async fn post<F>(&mut self, uri: &str, host: &str, auth: &str, content: serde_json::Value) -> std::io::Result<F>
	where F: TryFrom<Vec<u8>, Error = std::io::Error> {
		let content = content.to_string();
		write!(self.stream,
			"POST {} HTTP/1.1\r\n\
			 Host: {}\r\n\
			 Authorization: {}\r\n\
			 Connection: keep-alive\r\n\
			 Content-Type: application/json\r\n\
			 Content-Length: {}\r\n\
			 \r\n\
			 {}", uri, host, auth, content.len(), content)?;

		match read_http_resp(&self.stream, MAX_HTTP_RESPONSE_LEN).await {
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "read error")),
			Some(bytes) => F::try_from(bytes),
		}
	}
}

async fn read_http_resp(mut socket: &TcpStream, max_resp: usize) -> Option<Vec<u8>> {
	let mut resp = Vec::new();
	let mut bytes_read = 0;
	macro_rules! read_socket { () => { {
		#[cfg(feature = "tokio")]
		let res = socket.read(&mut resp[bytes_read..]).await;
		#[cfg(not(feature = "tokio"))]
		let res = socket.read(&mut resp[bytes_read..]);
		match res {
			Ok(0) => return None,
			Ok(b) => b,
			Err(_) => return None,
		}
	} } }

	let mut actual_len = 0;
	let mut ok_found = false;
	let mut chunked = false;
	// We expect the HTTP headers to fit in 8KB, and use resp as a temporary buffer for headers
	// until we know our real length.
	resp.extend_from_slice(&[0; 8192]);
	'read_headers: loop {
		if bytes_read >= 8192 { return None; }
		bytes_read += read_socket!();
		for line in resp[..bytes_read].split(|c| *c == '\n' as u8 || *c == '\r' as u8) {
			let content_header = b"Content-Length: ";
			if line.len() > content_header.len() && line[..content_header.len()].eq_ignore_ascii_case(content_header) {
				actual_len = match match std::str::from_utf8(&line[content_header.len()..]){
					Ok(s) => s, Err(_) => return None,
				}.parse() {
					Ok(len) => len, Err(_) => return None,
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
					_ => return None, // Unsupported
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
	if !ok_found || (!chunked && (actual_len == 0 || actual_len > max_resp)) { return None; } // Sorry, not implemented
	bytes_read = resp.len();
	if !chunked {
		resp.resize(actual_len, 0);
		while bytes_read < actual_len {
			bytes_read += read_socket!();
		}
		Some(resp)
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
							return None;
						}
						break;
					}
					bytes_skipped += line.len() + 1;
					if line.len() == 0 { continue; } // Probably between the \r and \n
					match usize::from_str_radix(&match std::str::from_utf8(line) {
						Ok(s) => s, Err(_) => return None,
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
						Err(_) => return None,
					}
				}
				if chunk_remaining != 0 {
					bytes_read -= bytes_skipped;
					resp.drain(actual_len..actual_len + bytes_skipped);
					if actual_len + chunk_remaining > max_resp { return None; }
					let already_in_chunk = cmp::min(bytes_read - actual_len, chunk_remaining);
					actual_len += already_in_chunk;
					chunk_remaining -= already_in_chunk;
					continue 'read_bytes;
				} else {
					if finished_read {
						// Note that we may leave some extra \r\ns to be read, but that's OK,
						// we'll ignore then when parsing headers for the next request.
						resp.resize(actual_len, 0);
						return Some(resp);
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
	pub fn new(uri: &str) -> Option<Self> {
		match HttpEndpoint::new(uri) {
			Err(_) => None,
			Ok(endpoint) => Some(Self { endpoint }),
		}
	}

	async fn make_raw_rest_call(&self, req_path: &str) -> std::io::Result<Vec<u8>> {
		let host = format!("{}:{}", self.endpoint.host(), self.endpoint.port());
		let uri = format!("{}/{}", self.endpoint.path().trim_end_matches("/"), req_path);

		let mut client = HttpClient::connect(&self.endpoint)?;
		Ok(client.get::<BinaryResponse>(&uri, &host).await?.0)
	}

	async fn request_resource(&self, resource_path: &str) -> std::io::Result<serde_json::Value> {
		let resp = self.make_raw_rest_call(resource_path).await?;
		let v = JsonResponse::try_from(resp)?.0;
		if !v.is_object() {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON object"));
		}
		Ok(v)
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
	pub fn new(user_auth: &str, uri: &str) -> Option<Self> {
		match HttpEndpoint::new(uri) {
			Err(_) => None,
			Ok(endpoint) => {
				Some(Self {
					basic_auth: "Basic ".to_string() + &base64::encode(user_auth),
					endpoint,
					id: AtomicUsize::new(0),
				})
			},
		}
	}

	async fn call_method(&self, method: &str, params: &[serde_json::Value]) -> std::io::Result<serde_json::Value>
	where JsonResponse: TryFrom<Vec<u8>, Error = std::io::Error> {
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

		Ok(result.take())
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

impl GetHeaderResponse {
	/// Always returns BogusData if we return an Err
	pub fn to_block_header(self) -> Result<BlockHeaderData, BlockSourceRespErr> {
		let header = BlockHeader {
			version: self.version,
			prev_blockhash: BlockHash::from_hex(&self.previousblockhash).map_err(|_| BlockSourceRespErr::BogusData)?,
			merkle_root: TxMerkleNode::from_hex(&self.merkleroot).map_err(|_| BlockSourceRespErr::BogusData)?,
			time: self.time,
			bits: u32::from_str_radix(&self.bits, 16).map_err(|_| BlockSourceRespErr::BogusData)?,
			nonce: self.nonce,
		};

		Ok(BlockHeaderData {
			chainwork: hex_to_uint256(&self.chainwork).or(Err(BlockSourceRespErr::BogusData))?,
			height: self.height,
			header,
		})
	}
}

#[cfg(feature = "rpc-client")]
impl BlockSource for RPCClient {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, _height: Option<u32>) -> Pin<Box<dyn Future<Output = Result<BlockHeaderData, BlockSourceRespErr>> + 'a + Send>> {
		let header_hash = serde_json::json!(header_hash.to_hex());
		Box::pin(async move {
			let res = self.call_method("getblockheader", &[header_hash]).await;
			if let Ok(mut v) = res {
				if v.is_object() {
					if let None = v.get("previousblockhash") {
						// Got a request for genesis block, add a dummy previousblockhash
						v.as_object_mut().unwrap().insert("previousblockhash".to_string(), serde_json::Value::String("".to_string()));
					}
				}
				let deser_res: Result<GetHeaderResponse, _> = serde_json::from_value(v);
				match deser_res {
					Ok(resp) => resp.to_block_header(),
					Err(_) => Err(BlockSourceRespErr::NoResponse),
				}
			} else { Err(BlockSourceRespErr::NoResponse) }
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> Pin<Box<dyn Future<Output = Result<Block, BlockSourceRespErr>> + 'a + Send>> {
		let header_hash = serde_json::json!(header_hash.to_hex());
		let verbosity = serde_json::json!(0);
		Box::pin(async move {
			let blockhex = self.call_method("getblock", &[header_hash, verbosity]).await.map_err(|_| BlockSourceRespErr::NoResponse)?;
			let blockdata = Vec::<u8>::from_hex(blockhex.as_str().ok_or(BlockSourceRespErr::NoResponse)?).or(Err(BlockSourceRespErr::NoResponse))?;
			let block: Block = encode::deserialize(&blockdata).map_err(|_| BlockSourceRespErr::NoResponse)?;
			Ok(block)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(BlockHash, Option<u32>), BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			if let Ok(v) = self.call_method("getblockchaininfo", &[]).await {
				let height = v["blocks"].as_u64().ok_or(BlockSourceRespErr::NoResponse)?
					.try_into().map_err(|_| BlockSourceRespErr::NoResponse)?;
				let blockstr = v["bestblockhash"].as_str().ok_or(BlockSourceRespErr::NoResponse)?;
				Ok((BlockHash::from_hex(blockstr).map_err(|_| BlockSourceRespErr::NoResponse)?, Some(height)))
			} else { Err(BlockSourceRespErr::NoResponse) }
		})
	}
}

#[cfg(feature = "rest-client")]
impl BlockSource for RESTClient {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, _height: Option<u32>) -> Pin<Box<dyn Future<Output = Result<BlockHeaderData, BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			let reqpath = format!("headers/1/{}.json", header_hash.to_hex());
			match self.request_resource(&reqpath).await {
				Ok(serde_json::Value::Array(mut v)) if !v.is_empty() => {
					let mut header = v.drain(..).next().unwrap();
					if !header.is_object() { return Err(BlockSourceRespErr::NoResponse); }
					if let None = header.get("previousblockhash") {
						// Got a request for genesis block, add a dummy previousblockhash
						header.as_object_mut().unwrap().insert("previousblockhash".to_string(), serde_json::Value::String("".to_string()));
					}
					let deser_res: Result<GetHeaderResponse, _> = serde_json::from_value(header);
					match deser_res {
						Ok(resp) => resp.to_block_header(),
						Err(_) => Err(BlockSourceRespErr::NoResponse),
					}
				},
				_ => Err(BlockSourceRespErr::NoResponse)
			}
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> Pin<Box<dyn Future<Output = Result<Block, BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			let reqpath = format!("block/{}.bin", header_hash.to_hex());
			let blockdata = self.make_raw_rest_call(&reqpath).await.map_err(|_| BlockSourceRespErr::NoResponse)?;
			let block: Block = encode::deserialize(&blockdata).map_err(|_| BlockSourceRespErr::NoResponse)?;
			Ok(block)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(BlockHash, Option<u32>), BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			let v = self.request_resource("chaininfo.json").await.map_err(|_| BlockSourceRespErr::NoResponse)?;
			let height = v["blocks"].as_u64().ok_or(BlockSourceRespErr::NoResponse)?
				.try_into().map_err(|_| BlockSourceRespErr::NoResponse)?;
			let blockstr = v["bestblockhash"].as_str().ok_or(BlockSourceRespErr::NoResponse)?;
			Ok((BlockHash::from_hex(blockstr).map_err(|_| BlockSourceRespErr::NoResponse)?, Some(height)))
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

/// Interprets bytes from an HTTP response body as a JSON value.
impl TryFrom<Vec<u8>> for JsonResponse {
	type Error = std::io::Error;

	fn try_from(bytes: Vec<u8>) -> std::io::Result<Self> {
		Ok(JsonResponse(serde_json::from_slice(&bytes)?))
	}
}
