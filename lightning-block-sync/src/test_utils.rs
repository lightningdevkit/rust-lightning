use crate::{AsyncBlockSourceResult, BlockHeaderData, BlockSource, BlockSourceError};
use crate::poll::{Validate, ValidatedBlockHeader};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;
use bitcoin::util::uint::Uint256;

#[derive(Default)]
pub struct Blockchain {
	pub blocks: Vec<Block>,
	without_headers: bool,
	malformed_headers: bool,
}

impl Blockchain {
	pub fn default() -> Self {
		Blockchain::with_network(Network::Bitcoin)
	}

	pub fn with_network(network: Network) -> Self {
		let blocks = vec![genesis_block(network)];
		Self { blocks, ..Default::default() }
	}

	pub fn with_height(mut self, height: usize) -> Self {
		self.blocks.reserve_exact(height);
		let bits = BlockHeader::compact_target_from_u256(&Uint256::from_be_bytes([0xff; 32]));
		for i in 1..=height {
			let prev_block = &self.blocks[i - 1];
			let prev_blockhash = prev_block.block_hash();
			let time = prev_block.header.time + height as u32;
			self.blocks.push(Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash,
					merkle_root: Default::default(),
					time,
					bits,
					nonce: 0,
				},
				txdata: vec![],
			});
		}
		self
	}

	pub fn without_headers(self) -> Self {
		Self { without_headers: true, ..self }
	}

	pub fn malformed_headers(self) -> Self {
		Self { malformed_headers: true, ..self }
	}

	pub fn at_height(&self, height: usize) -> ValidatedBlockHeader {
		let block_header = self.at_height_unvalidated(height);
		let block_hash = self.blocks[height].block_hash();
		block_header.validate(block_hash).unwrap()
	}

	fn at_height_unvalidated(&self, height: usize) -> BlockHeaderData {
		assert!(!self.blocks.is_empty());
		assert!(height < self.blocks.len());
		BlockHeaderData {
			chainwork: self.blocks[0].header.work() + Uint256::from_u64(height as u64).unwrap(),
			height: height as u32,
			header: self.blocks[height].header.clone(),
		}
	}

	pub fn tip(&self) -> ValidatedBlockHeader {
		assert!(!self.blocks.is_empty());
		self.at_height(self.blocks.len() - 1)
	}

	pub fn disconnect_tip(&mut self) -> Option<Block> {
		self.blocks.pop()
	}
}

impl BlockSource for Blockchain {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, _height_hint: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			if self.without_headers {
				return Err(BlockSourceError::persistent("header not found"));
			}

			for (height, block) in self.blocks.iter().enumerate() {
				if block.header.block_hash() == *header_hash {
					let mut header_data = self.at_height_unvalidated(height);
					if self.malformed_headers {
						header_data.header.time += 1;
					}

					return Ok(header_data);
				}
			}
			Err(BlockSourceError::transient("header not found"))
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			for block in self.blocks.iter() {
				if block.header.block_hash() == *header_hash {
					return Ok(block.clone());
				}
			}
			Err(BlockSourceError::transient("block not found"))
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			match self.blocks.last() {
				None => Err(BlockSourceError::transient("empty chain")),
				Some(block) => {
					let height = (self.blocks.len() - 1) as u32;
					Ok((block.block_hash(), Some(height)))
				},
			}
		})
	}
}
