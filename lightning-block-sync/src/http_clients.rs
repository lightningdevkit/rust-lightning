use serde_json;

use serde_derive::Deserialize;

use crate::utils::hex_to_uint256;
use crate::{BlockHeaderData, BlockSource, BlockSourceRespErr};

use bitcoin::hashes::hex::{ToHex, FromHex};
use bitcoin::hash_types::{BlockHash, TxMerkleNode};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::encode;

use std::convert::TryInto;
use std::cmp;
use std::future::Future;
use std::pin::Pin;
use std::net::ToSocketAddrs;
use std::io::Write;
use std::time::Duration;

#[cfg(feature = "rpc-client")]
use crate::utils::hex_to_vec;
#[cfg(feature = "rpc-client")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "rpc-client")]
use base64;

#[cfg(feature = "tokio")]
use tokio::net::TcpStream;
#[cfg(feature = "tokio")]
use tokio::io::AsyncReadExt;

#[cfg(not(feature = "tokio"))]
use std::net::TcpStream;
#[cfg(not(feature = "tokio"))]
use std::io::Read;

/// Splits an HTTP URI into its component parts - (is_ssl, hostname, port number, and HTTP path)
fn split_uri<'a>(uri: &'a str) -> Option<(bool, &'a str, u16, &'a str)> {
	let mut uri_iter = uri.splitn(2, ":");
	let ssl = match uri_iter.next() {
		Some("http") => false,
		Some("https") => true,
		_ => return None,
	};
	let mut host_path = match uri_iter.next() {
		Some(r) => r,
		None => return None,
	};
	host_path = host_path.trim_start_matches("/");
	let mut host_path_iter = host_path.splitn(2, "/");
	let (host_port_len, host, port) = match host_path_iter.next() {
		Some(r) if !r.is_empty() => {
			let is_v6_explicit = r.starts_with("[");
			let mut iter = if is_v6_explicit {
				r[1..].splitn(2, "]")
			} else {
				r.splitn(2, ":")
			};
			(r.len(), match iter.next() {
				Some(host) => host,
				None => return None,
			}, match iter.next() {
				Some(port) if !is_v6_explicit || !port.is_empty() => match if is_v6_explicit {
					if port.as_bytes()[0] != ':' as u8 { return None; }
					&port[1..]
				} else { port }
				.parse::<u16>() {
					Ok(p) => p,
					Err(_) => return None,
				},
				_ => if ssl { 443 } else { 80 },
			})
		},
		_ => return None,
	};
	let path = &host_path[host_port_len..];

	Some((ssl, host, port, path))
}

async fn read_http_resp(mut socket: TcpStream, max_resp: usize) -> Option<Vec<u8>> {
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
	uri: String,
}

#[cfg(feature = "rest-client")]
impl RESTClient {
	pub fn new(uri: String) -> Option<Self> {
		match split_uri(&uri) {
			Some((ssl, _host, _port, _path)) if !ssl => Some(Self { uri }),
			_ => None,
		}
	}

	async fn make_raw_rest_call(&self, req_path: &str) -> Result<Vec<u8>, ()> {
		let (ssl, host, port, path) = split_uri(&self.uri).unwrap();
		if ssl { unreachable!(); }

		let mut stream = match std::net::TcpStream::connect_timeout(&match (host, port).to_socket_addrs() {
			Ok(mut sockaddrs) => match sockaddrs.next() { Some(sockaddr) => sockaddr, None => return Err(()) },
			Err(_) => return Err(()),
		}, Duration::from_secs(1)) {
			Ok(stream) => stream,
			Err(_) => return Err(()),
		};
		stream.set_write_timeout(Some(Duration::from_secs(1))).expect("Host kernel is uselessly old?");
		stream.set_read_timeout(Some(Duration::from_secs(2))).expect("Host kernel is uselessly old?");

		let req = format!("GET {}/{} HTTP/1.1\nHost: {}\nConnection: keep-alive\n\n", path, req_path, host);
		match stream.write(req.as_bytes()) {
			Ok(len) if len == req.len() => {},
			_ => return Err(()),
		}
		#[cfg(feature = "tokio")]
		let stream = TcpStream::from_std(stream).unwrap();
		match read_http_resp(stream, 4_000_000).await {
			Some(r) => Ok(r),
			None => return Err(()),
		}
	}

	async fn make_rest_call(&self, req_path: &str) -> Result<serde_json::Value, ()> {
		let resp = self.make_raw_rest_call(req_path).await?;
		let v: serde_json::Value = match serde_json::from_slice(&resp[..]) {
			Ok(v) => v,
			Err(_) => return Err(()),
		};
		if !v.is_object() {
			return Err(());
		}
		Ok(v)
	}
}

#[cfg(feature = "rpc-client")]
pub struct RPCClient {
	basic_auth: String,
	uri: String,
	id: AtomicUsize,
}

#[cfg(feature = "rpc-client")]
impl RPCClient {
	pub fn new(user_auth: &str, uri: String) -> Option<Self> {
		match split_uri(&uri) {
			Some((ssl, _host, _port, _path)) if !ssl => {
				Some(Self {
					basic_auth: "Basic ".to_string() + &base64::encode(user_auth),
					uri,
					id: AtomicUsize::new(0),
				})
			},
			_ => None,
		}
	}

	/// params entries must be pre-quoted if appropriate
	async fn make_rpc_call(&self, method: &str, params: &[&str]) -> Result<serde_json::Value, ()> {
		let (ssl, host, port, path) = split_uri(&self.uri).unwrap();
		if ssl { unreachable!(); }

		let mut stream = match std::net::TcpStream::connect_timeout(&match (host, port).to_socket_addrs() {
			Ok(mut sockaddrs) => match sockaddrs.next() { Some(sockaddr) => sockaddr, None => return Err(()) },
			Err(_) => return Err(()),
		}, Duration::from_secs(1)) {
			Ok(stream) => stream,
			Err(_) => return Err(()),
		};
		stream.set_write_timeout(Some(Duration::from_secs(1))).expect("Host kernel is uselessly old?");
		stream.set_read_timeout(Some(Duration::from_secs(2))).expect("Host kernel is uselessly old?");

		let mut param_str = String::new();
		for (idx, param) in params.iter().enumerate() {
			param_str += param;
			if idx != params.len() - 1 {
				param_str += ",";
			}
		}
		let req = "{\"method\":\"".to_string() + method + "\",\"params\":[" + &param_str + "],\"id\":" + &self.id.fetch_add(1, Ordering::AcqRel).to_string() + "}";

		let req = format!("POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", path, host, &self.basic_auth, req.len(), req);
		match stream.write(req.as_bytes()) {
			Ok(len) if len == req.len() => {},
			_ => return Err(()),
		}
		#[cfg(feature = "tokio")]
		let stream = TcpStream::from_std(stream).unwrap();
		let resp = match read_http_resp(stream, 4_000_000).await {
			Some(r) => r,
			None => return Err(()),
		};

		let v: serde_json::Value = match serde_json::from_slice(&resp[..]) {
			Ok(v) => v,
			Err(_) => return Err(()),
		};
		if !v.is_object() {
			return Err(());
		}
		let v_obj = v.as_object().unwrap();
		if v_obj.get("error") != Some(&serde_json::Value::Null) {
			return Err(());
		}
		if let Some(res) = v_obj.get("result") {
			Ok((*res).clone())
		} else {
			Err(())
		}
	}
}

#[derive(Deserialize)]
struct GetHeaderResponse {
	pub chainwork: String,
	pub height: u32,

	pub version: u32,
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
			chainwork: hex_to_uint256(&self.chainwork).ok_or(BlockSourceRespErr::BogusData)?,
			height: self.height,
			header,
		})
	}
}

#[cfg(feature = "rpc-client")]
impl BlockSource for RPCClient {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, _height: Option<u32>) -> Pin<Box<dyn Future<Output = Result<BlockHeaderData, BlockSourceRespErr>> + 'a + Send>> {
		let param = "\"".to_string() + &header_hash.to_hex() + "\"";
		Box::pin(async move {
			let res = self.make_rpc_call("getblockheader", &[&param]).await;
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
		let param = "\"".to_string() + &header_hash.to_hex() + "\"";
		Box::pin(async move {
			let blockhex = self.make_rpc_call("getblock", &[&param, "0"]).await.map_err(|_| BlockSourceRespErr::NoResponse)?;
			let blockdata = hex_to_vec(blockhex.as_str().ok_or(BlockSourceRespErr::NoResponse)?).ok_or(BlockSourceRespErr::NoResponse)?;
			let block: Block = encode::deserialize(&blockdata).map_err(|_| BlockSourceRespErr::NoResponse)?;
			Ok(block)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(BlockHash, Option<u32>), BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			if let Ok(v) = self.make_rpc_call("getblockchaininfo", &[]).await {
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
			match self.make_rest_call(&reqpath).await {
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
			let v = self.make_rest_call("chaininfo.json").await.map_err(|_| BlockSourceRespErr::NoResponse)?;
			let height = v["blocks"].as_u64().ok_or(BlockSourceRespErr::NoResponse)?
				.try_into().map_err(|_| BlockSourceRespErr::NoResponse)?;
			let blockstr = v["bestblockhash"].as_str().ok_or(BlockSourceRespErr::NoResponse)?;
			Ok((BlockHash::from_hex(blockstr).map_err(|_| BlockSourceRespErr::NoResponse)?, Some(height)))
		})
	}
}

#[cfg(test)]
#[test]
fn test_split_uri() {
	assert_eq!(split_uri("http://example.com:8080/path"), Some((false, "example.com", 8080, "/path")));
	assert_eq!(split_uri("http:example.com:8080/path/b"), Some((false, "example.com", 8080, "/path/b")));
	assert_eq!(split_uri("https://0.0.0.0/"), Some((true, "0.0.0.0", 443, "/")));
	assert_eq!(split_uri("http:[0:bad::43]:80/"), Some((false, "0:bad::43", 80, "/")));
	assert_eq!(split_uri("http:[::]"), Some((false, "::", 80, "")));
	assert_eq!(split_uri("http://"), None);
	assert_eq!(split_uri("http://example.com:70000/"), None);
	assert_eq!(split_uri("ftp://example.com:80/"), None);
	assert_eq!(split_uri("http://example.com"), Some((false, "example.com", 80, "")));
}
