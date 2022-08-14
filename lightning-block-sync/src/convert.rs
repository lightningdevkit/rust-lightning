use crate::http::{BinaryResponse, JsonResponse};
use crate::utils::hex_to_uint256;
use crate::{BlockHeaderData, BlockSourceError};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::encode;
use bitcoin::hash_types::{BlockHash, TxMerkleNode, Txid};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::Transaction;

use serde::Deserialize;

use serde_json;

use std::convert::From;
use std::convert::TryFrom;
use std::convert::TryInto;
use bitcoin::hashes::Hash;

/// Conversion from `std::io::Error` into `BlockSourceError`.
impl From<std::io::Error> for BlockSourceError {
	fn from(e: std::io::Error) -> BlockSourceError {
		match e.kind() {
			std::io::ErrorKind::InvalidData => BlockSourceError::persistent(e),
			std::io::ErrorKind::InvalidInput => BlockSourceError::persistent(e),
			_ => BlockSourceError::transient(e),
		}
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
			let hash: BlockHash = BlockHash::all_zeros();
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

/// Response data from `getblockheader` RPC and `headers` REST requests.
#[derive(Deserialize)]
struct GetHeaderResponse {
	pub version: i32,
	pub merkleroot: String,
	pub time: u32,
	pub nonce: u32,
	pub bits: String,
	pub previousblockhash: String,

	pub chainwork: String,
	pub height: u32,
}

/// Converts from `GetHeaderResponse` to `BlockHeaderData`.
impl TryFrom<GetHeaderResponse> for BlockHeaderData {
	type Error = bitcoin::hashes::hex::Error;

	fn try_from(response: GetHeaderResponse) -> Result<Self, bitcoin::hashes::hex::Error> {
		Ok(BlockHeaderData {
			header: BlockHeader {
				version: response.version,
				prev_blockhash: BlockHash::from_hex(&response.previousblockhash)?,
				merkle_root: TxMerkleNode::from_hex(&response.merkleroot)?,
				time: response.time,
				bits: u32::from_be_bytes(<[u8; 4]>::from_hex(&response.bits)?),
				nonce: response.nonce,
			},
			chainwork: hex_to_uint256(&response.chainwork)?,
			height: response.height,
		})
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

impl TryInto<Txid> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<Txid> {
		match self.0.as_str() {
			None => Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"expected JSON string",
			)),
			Some(hex_data) => match Vec::<u8>::from_hex(hex_data) {
				Err(_) => Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"invalid hex data",
				)),
				Ok(txid_data) => match encode::deserialize(&txid_data) {
					Err(_) => Err(std::io::Error::new(
						std::io::ErrorKind::InvalidData,
						"invalid txid",
					)),
					Ok(txid) => Ok(txid),
				},
			},
		}
	}
}

/// Converts a JSON value into a transaction. WATCH OUT! this cannot be used for zero-input transactions
/// (e.g. createrawtransaction). See <https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/197>
impl TryInto<Transaction> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<Transaction> {
		let hex_tx = if self.0.is_object() {
			// result is json encoded
			match &self.0["hex"] {
				// result has hex field
				serde_json::Value::String(hex_data) => match self.0["complete"] {
					// result may or may not be signed (e.g. signrawtransactionwithwallet)
					serde_json::Value::Bool(x) => {
						if x == false {
							let reason = match &self.0["errors"][0]["error"] {
								serde_json::Value::String(x) => x.as_str(),
								_ => "Unknown error",
							};

							return Err(std::io::Error::new(
								std::io::ErrorKind::InvalidData,
								format!("transaction couldn't be signed. {}", reason),
							));
						} else {
							hex_data
						}
					}
					// result is a complete transaction (e.g. getrawtranaction verbose)
					_ => hex_data,
				},
				_ => return Err(std::io::Error::new(
							std::io::ErrorKind::InvalidData,
							"expected JSON string",
					)),
			}
		} else {
			// result is plain text (e.g. getrawtransaction no verbose)
			match self.0.as_str() {
				Some(hex_tx) => hex_tx,
				None => {
					return Err(std::io::Error::new(
						std::io::ErrorKind::InvalidData,
						"expected JSON string",
					))
				}
			}
		};

		match Vec::<u8>::from_hex(hex_tx) {
			Err(_) => Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"invalid hex data",
			)),
			Ok(tx_data) => match encode::deserialize(&tx_data) {
				Err(_) => Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"invalid transaction",
				)),
				Ok(tx) => Ok(tx),
			},
		}
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use serde_json::value::Number;
	use serde_json::Value;

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
			"blocks": std::u64::MAX,
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

	#[test]
	fn into_txid_from_json_response_with_unexpected_type() {
		let response = JsonResponse(serde_json::json!({ "result": "foo" }));
		match TryInto::<Txid>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON string");
			}
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_txid_from_json_response_with_invalid_hex_data() {
		let response = JsonResponse(serde_json::json!("foobar"));
		match TryInto::<Txid>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid hex data");
			}
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_txid_from_json_response_with_invalid_txid_data() {
		let response = JsonResponse(serde_json::json!("abcd"));
		match TryInto::<Txid>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid txid");
			}
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_txid_from_json_response_with_valid_txid_data() {
		let target_txid = Txid::from_slice(&[1; 32]).unwrap();
		let response = JsonResponse(serde_json::json!(encode::serialize_hex(&target_txid)));
		match TryInto::<Txid>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(txid) => assert_eq!(txid, target_txid),
		}
	}

	// TryInto<Transaction> can be used in two ways, first with plain hex response where data is
	// the hex encoded transaction (e.g. as a result of getrawtransaction) or as a JSON object
	// where the hex encoded transaction can be found in the hex field of the object (if present)
	// (e.g. as a result of signrawtransactionwithwallet).

	// plain hex transaction

	#[test]
	fn into_tx_from_json_response_with_invalid_hex_data() {
		let response = JsonResponse(serde_json::json!("foobar"));
		match TryInto::<Transaction>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid hex data");
			}
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_tx_from_json_response_with_invalid_data_type() {
		let response = JsonResponse(Value::Number(Number::from_f64(1.0).unwrap()));
		match TryInto::<Transaction>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON string");
			}
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_tx_from_json_response_with_invalid_tx_data() {
		let response = JsonResponse(serde_json::json!("abcd"));
		match TryInto::<Transaction>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid transaction");
			}
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_tx_from_json_response_with_valid_tx_data_plain() {
		let genesis_block = genesis_block(Network::Bitcoin);
		let target_tx = genesis_block.txdata.get(0).unwrap();
		let response = JsonResponse(serde_json::json!(encode::serialize_hex(&target_tx)));
		match TryInto::<Transaction>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tx) => assert_eq!(&tx, target_tx),
		}
	}

	#[test]
	fn into_tx_from_json_response_with_valid_tx_data_hex_field() {
		let genesis_block = genesis_block(Network::Bitcoin);
		let target_tx = genesis_block.txdata.get(0).unwrap();
		let response = JsonResponse(serde_json::json!({"hex": encode::serialize_hex(&target_tx)}));
		match TryInto::<Transaction>::try_into(response) {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tx) => assert_eq!(&tx, target_tx),
		}
	}

	// transaction in hex field of JSON object

	#[test]
	fn into_tx_from_json_response_with_no_hex_field() {
		let response = JsonResponse(serde_json::json!({ "error": "foo" }));
		match TryInto::<Transaction>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(
					e.get_ref().unwrap().to_string(),
					"expected JSON string"
				);
			}
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_tx_from_json_response_not_signed() {
		let response = JsonResponse(serde_json::json!({ "hex": "foo", "complete": false }));
		match TryInto::<Transaction>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert!(
					e.get_ref().unwrap().to_string().contains(
					"transaction couldn't be signed")
				);
			}
			Ok(_) => panic!("Expected error"),
		}
	}
}
