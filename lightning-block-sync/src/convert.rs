use crate::http::{BinaryResponse, JsonResponse};
use crate::utils::hex_to_work;
use crate::{BlockHeaderData, BlockSourceError};

use bitcoin::blockdata::block::{Block, Header};
use bitcoin::consensus::encode;
use bitcoin::hash_types::{BlockHash, TxMerkleNode, Txid};
use bitcoin::hashes::hex::FromHex;
use bitcoin::Transaction;

use serde_json;

use bitcoin::hashes::Hash;
use std::convert::From;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::str::FromStr;

impl TryInto<serde_json::Value> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> Result<serde_json::Value, std::io::Error> {
		Ok(self.0)
	}
}

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
			Err(_) => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"invalid block data",
				))
			},
			Ok(block) => Ok(block),
		}
	}
}

/// Parses binary data as a block hash.
impl TryInto<BlockHash> for BinaryResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<BlockHash> {
		BlockHash::from_slice(&self.0).map_err(|_| {
			std::io::Error::new(std::io::ErrorKind::InvalidData, "bad block hash length")
		})
	}
}

/// Converts a JSON value into block header data. The JSON value may be an object representing a
/// block header or an array of such objects. In the latter case, the first object is converted.
impl TryInto<BlockHeaderData> for JsonResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<BlockHeaderData> {
		let header = match self.0 {
			serde_json::Value::Array(mut array) if !array.is_empty() => {
				array.drain(..).next().unwrap()
			},
			serde_json::Value::Object(_) => self.0,
			_ => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"unexpected JSON type",
				))
			},
		};

		if !header.is_object() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"expected JSON object",
			));
		}

		// Add an empty previousblockhash for the genesis block.
		match header.try_into() {
			Err(_) => {
				Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid header data"))
			},
			Ok(header) => Ok(header),
		}
	}
}

impl TryFrom<serde_json::Value> for BlockHeaderData {
	type Error = ();

	fn try_from(response: serde_json::Value) -> Result<Self, ()> {
		macro_rules! get_field {
			($name: expr, $ty_access: tt) => {
				response.get($name).ok_or(())?.$ty_access().ok_or(())?
			};
		}

		Ok(BlockHeaderData {
			header: Header {
				version: bitcoin::blockdata::block::Version::from_consensus(
					get_field!("version", as_i64).try_into().map_err(|_| ())?,
				),
				prev_blockhash: if let Some(hash_str) = response.get("previousblockhash") {
					BlockHash::from_str(hash_str.as_str().ok_or(())?).map_err(|_| ())?
				} else {
					BlockHash::all_zeros()
				},
				merkle_root: TxMerkleNode::from_str(get_field!("merkleroot", as_str))
					.map_err(|_| ())?,
				time: get_field!("time", as_u64).try_into().map_err(|_| ())?,
				bits: bitcoin::CompactTarget::from_consensus(u32::from_be_bytes(
					<[u8; 4]>::from_hex(get_field!("bits", as_str)).map_err(|_| ())?,
				)),
				nonce: get_field!("nonce", as_u64).try_into().map_err(|_| ())?,
			},
			chainwork: hex_to_work(get_field!("chainwork", as_str)).map_err(|_| ())?,
			height: get_field!("height", as_u64).try_into().map_err(|_| ())?,
		})
	}
}

/// Converts a JSON value into a block. Assumes the block is hex-encoded in a JSON string.
impl TryInto<Block> for JsonResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<Block> {
		match self.0.as_str() {
			None => {
				Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON string"))
			},
			Some(hex_data) => match Vec::<u8>::from_hex(hex_data) {
				Err(_) => {
					Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex data"))
				},
				Ok(block_data) => match encode::deserialize(&block_data) {
					Err(_) => Err(std::io::Error::new(
						std::io::ErrorKind::InvalidData,
						"invalid block data",
					)),
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
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"expected JSON object",
			));
		}

		let hash = match &self.0["bestblockhash"] {
			serde_json::Value::String(hex_data) => match BlockHash::from_str(&hex_data) {
				Err(_) => {
					return Err(std::io::Error::new(
						std::io::ErrorKind::InvalidData,
						"invalid hex data",
					))
				},
				Ok(block_hash) => block_hash,
			},
			_ => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"expected JSON string",
				))
			},
		};

		let height = match &self.0["blocks"] {
			serde_json::Value::Null => None,
			serde_json::Value::Number(height) => match height.as_u64() {
				None => {
					return Err(std::io::Error::new(
						std::io::ErrorKind::InvalidData,
						"invalid height",
					))
				},
				Some(height) => match height.try_into() {
					Err(_) => {
						return Err(std::io::Error::new(
							std::io::ErrorKind::InvalidData,
							"invalid height",
						))
					},
					Ok(height) => Some(height),
				},
			},
			_ => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"expected JSON number",
				))
			},
		};

		Ok((hash, height))
	}
}

impl TryInto<Txid> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<Txid> {
		let hex_data = self
			.0
			.as_str()
			.ok_or(Self::Error::new(std::io::ErrorKind::InvalidData, "expected JSON string"))?;
		Txid::from_str(hex_data)
			.map_err(|err| Self::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
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
					},
					// result is a complete transaction (e.g. getrawtranaction verbose)
					_ => hex_data,
				},
				_ => {
					return Err(std::io::Error::new(
						std::io::ErrorKind::InvalidData,
						"expected JSON string",
					))
				},
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
				},
			}
		};

		match Vec::<u8>::from_hex(hex_tx) {
			Err(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex data")),
			Ok(tx_data) => match encode::deserialize(&tx_data) {
				Err(_) => {
					Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid transaction"))
				},
				Ok(tx) => Ok(tx),
			},
		}
	}
}

impl TryInto<BlockHash> for JsonResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<BlockHash> {
		match self.0.as_str() {
			None => {
				Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON string"))
			},
			Some(hex_data) if hex_data.len() != 64 => {
				Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hash length"))
			},
			Some(hex_data) => BlockHash::from_str(hex_data).map_err(|_| {
				std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex data")
			}),
		}
	}
}

/// The REST `getutxos` endpoint retuns a whole pile of data we don't care about and one bit we do
/// - whether the `hit bitmap` field had any entries. Thus we condense the result down into only
/// that.
#[cfg(feature = "rest-client")]
pub(crate) struct GetUtxosResponse {
	pub(crate) hit_bitmap_nonempty: bool,
}

#[cfg(feature = "rest-client")]
impl TryInto<GetUtxosResponse> for JsonResponse {
	type Error = std::io::Error;

	fn try_into(self) -> std::io::Result<GetUtxosResponse> {
		let bitmap_str = self
			.0
			.as_object()
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected an object"))?
			.get("bitmap")
			.ok_or(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing bitmap field"))?
			.as_str()
			.ok_or(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"bitmap should be an str",
			))?;
		let mut hit_bitmap_nonempty = false;
		for c in bitmap_str.chars() {
			if c < '0' || c > '9' {
				return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid byte"));
			}
			if c > '0' {
				hit_bitmap_nonempty = true;
			}
		}
		Ok(GetUtxosResponse { hit_bitmap_nonempty })
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use hex::DisplayHex;
	use serde_json::value::Number;
	use serde_json::Value;

	/// Converts from `BlockHeaderData` into a `GetHeaderResponse` JSON value.
	impl From<BlockHeaderData> for serde_json::Value {
		fn from(data: BlockHeaderData) -> Self {
			let BlockHeaderData { chainwork, height, header } = data;
			serde_json::json!({
				"chainwork": chainwork.to_be_bytes().as_hex().to_string(),
				"height": height,
				"version": header.version.to_consensus(),
				"merkleroot": header.merkle_root.to_string(),
				"time": header.time,
				"nonce": header.nonce,
				"bits": header.bits.to_consensus().to_be_bytes().as_hex().to_string(),
				"previousblockhash": header.prev_blockhash.to_string(),
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
		let mut response = JsonResponse(
			BlockHeaderData { chainwork: block.header.work(), height: 0, header: block.header }
				.into(),
		);
		response.0["chainwork"].take();

		match TryInto::<BlockHeaderData>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "invalid header data");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_block_header_from_json_response_with_invalid_header_data() {
		let block = genesis_block(Network::Bitcoin);
		let mut response = JsonResponse(
			BlockHeaderData { chainwork: block.header.work(), height: 0, header: block.header }
				.into(),
		);
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
		let response = JsonResponse(
			BlockHeaderData { chainwork: block.header.work(), height: 0, header: block.header }
				.into(),
		);

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
		let best_block_header =
			Header { prev_blockhash: genesis_block.block_hash(), ..genesis_block.header };
		let chainwork = genesis_block.header.work() + best_block_header.work();
		let response = JsonResponse(serde_json::json!([
			serde_json::Value::from(BlockHeaderData {
				chainwork,
				height: 1,
				header: best_block_header,
			}),
			serde_json::Value::from(BlockHeaderData {
				chainwork: genesis_block.header.work(),
				height: 0,
				header: genesis_block.header,
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
		let mut response = JsonResponse(
			BlockHeaderData { chainwork: block.header.work(), height: 0, header: block.header }
				.into(),
		);
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
			"bestblockhash": block.block_hash().to_string(),
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
			"bestblockhash": block.block_hash().to_string(),
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
			"bestblockhash": block.block_hash().to_string(),
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
			"bestblockhash": block.block_hash().to_string(),
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
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_txid_from_json_response_with_invalid_hex_data() {
		let response = JsonResponse(serde_json::json!("foobar"));
		match TryInto::<Txid>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(
					e.get_ref().unwrap().to_string(),
					"bad hex string length 6 (expected 64)"
				);
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_txid_from_json_response_with_invalid_txid_data() {
		let response = JsonResponse(serde_json::json!("abcd"));
		match TryInto::<Txid>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(
					e.get_ref().unwrap().to_string(),
					"bad hex string length 4 (expected 64)"
				);
			},
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

	#[test]
	fn into_txid_from_bitcoind_rpc_json_response() {
		let mut rpc_response = serde_json::json!(
			{"error": "", "id": "770", "result": "7934f775149929a8b742487129a7c3a535dfb612f0b726cc67bc10bc2628f906"}

		);
		let r: std::io::Result<Txid> =
			JsonResponse(rpc_response.get_mut("result").unwrap().take()).try_into();
		assert_eq!(
			r.unwrap().to_string(),
			"7934f775149929a8b742487129a7c3a535dfb612f0b726cc67bc10bc2628f906"
		);
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
			},
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
			},
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
			},
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
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON string");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn into_tx_from_json_response_not_signed() {
		let response = JsonResponse(serde_json::json!({ "hex": "foo", "complete": false }));
		match TryInto::<Transaction>::try_into(response) {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert!(e
					.get_ref()
					.unwrap()
					.to_string()
					.contains("transaction couldn't be signed"));
			},
			Ok(_) => panic!("Expected error"),
		}
	}
}
