use crate::{AsyncBlockSourceResult, BlockHeaderData, BlockSource, BlockSourceError, ChainListener};
use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;
use bitcoin::util::uint::Uint256;
use std::collections::VecDeque;

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

	pub fn fork_at_height(&self, height: usize) -> Self {
		assert!(height + 1 < self.blocks.len());
		let mut blocks = self.blocks.clone();
		let mut prev_blockhash = blocks[height].block_hash();
		for block in blocks.iter_mut().skip(height + 1) {
			block.header.prev_blockhash = prev_blockhash;
			block.header.nonce += 1;
			prev_blockhash = block.block_hash();
		}
		Self { blocks, ..*self }
	}

	pub fn at_height(&self, height: usize) -> BlockHeaderData {
		assert!(!self.blocks.is_empty());
		assert!(height < self.blocks.len());
		BlockHeaderData {
			chainwork: self.blocks[0].header.work() + Uint256::from_u64(height as u64).unwrap(),
			height: height as u32,
			header: self.blocks[height].header.clone(),
		}
	}

	pub fn tip(&self) -> BlockHeaderData {
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
				return Err(BlockSourceError::Persistent);
			}

			for (height, block) in self.blocks.iter().enumerate() {
				if block.header.block_hash() == *header_hash {
					let mut header_data = self.at_height(height);
					if self.malformed_headers {
						header_data.header.time += 1;
					}

					return Ok(header_data);
				}
			}
			Err(BlockSourceError::Transient)
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			for block in self.blocks.iter() {
				if block.header.block_hash() == *header_hash {
					return Ok(block.clone());
				}
			}
			Err(BlockSourceError::Transient)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			match self.blocks.last() {
				None => Err(BlockSourceError::Transient),
				Some(block) => {
					let height = (self.blocks.len() - 1) as u32;
					Ok((block.block_hash(), Some(height)))
				},
			}
		})
	}
}

pub struct NullChainListener;

impl ChainListener for NullChainListener {
	fn block_connected(&mut self, _block: &Block, _height: u32) {}
	fn block_disconnected(&mut self, _header: &BlockHeader, _height: u32) {}
}

pub struct MockChainListener {
	expected_blocks_connected: VecDeque<BlockHeaderData>,
	expected_blocks_disconnected: VecDeque<BlockHeaderData>,
}

impl MockChainListener {
	pub fn new() -> Self {
		Self {
			expected_blocks_connected: VecDeque::new(),
			expected_blocks_disconnected: VecDeque::new(),
		}
	}

	pub fn expect_block_connected(mut self, block: BlockHeaderData) -> Self {
		self.expected_blocks_connected.push_back(block);
		self
	}

	pub fn expect_block_disconnected(mut self, block: BlockHeaderData) -> Self {
		self.expected_blocks_disconnected.push_back(block);
		self
	}
}

impl ChainListener for MockChainListener {
	fn block_connected(&mut self, block: &Block, height: u32) {
		match self.expected_blocks_connected.pop_front() {
			None => {
				panic!("Unexpected block connected: {:?}", block.block_hash());
			},
			Some(expected_block) => {
				assert_eq!(block.block_hash(), expected_block.header.block_hash());
				assert_eq!(height, expected_block.height);
			},
		}
	}

	fn block_disconnected(&mut self, header: &BlockHeader, height: u32) {
		match self.expected_blocks_disconnected.pop_front() {
			None => {
				panic!("Unexpected block disconnected: {:?}", header.block_hash());
			},
			Some(expected_block) => {
				assert_eq!(header.block_hash(), expected_block.header.block_hash());
				assert_eq!(height, expected_block.height);
			},
		}
	}
}

impl Drop for MockChainListener {
	fn drop(&mut self) {
		if std::thread::panicking() {
			return;
		}
		if !self.expected_blocks_connected.is_empty() {
			panic!("Expected blocks connected: {:?}", self.expected_blocks_connected);
		}
		if !self.expected_blocks_disconnected.is_empty() {
			panic!("Expected blocks disconnected: {:?}", self.expected_blocks_disconnected);
		}
	}
}
