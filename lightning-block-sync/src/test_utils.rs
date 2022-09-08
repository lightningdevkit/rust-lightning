use crate::{AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, BlockSourceError, UnboundedCache};
use crate::poll::{Validate, ValidatedBlockHeader};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::network::constants::Network;
use bitcoin::util::uint::Uint256;
use bitcoin::util::hash::bitcoin_merkle_root;
use bitcoin::{PackedLockTime, Transaction};

use lightning::chain;

use std::cell::RefCell;
use std::collections::VecDeque;

#[derive(Default)]
pub struct Blockchain {
	pub blocks: Vec<Block>,
	without_blocks: Option<std::ops::RangeFrom<usize>>,
	without_headers: bool,
	malformed_headers: bool,
	filtered_blocks: bool,
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
			// Must have at least one transaction, because the merkle root is not defined for an empty block
			// and we would fail when we later checked, as of bitcoin crate 0.28.0.
			// Note that elsewhere in tests we assume that the merkle root of an empty block is all zeros,
			// but that's OK because those tests don't trigger the check.
			let coinbase = Transaction {
				version: 0,
				lock_time: PackedLockTime::ZERO,
				input: vec![],
				output: vec![]
			};
			let merkle_root = bitcoin_merkle_root(vec![coinbase.txid().as_hash()].into_iter()).unwrap();
			self.blocks.push(Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash,
					merkle_root: merkle_root.into(),
					time,
					bits,
					nonce: 0,
				},
				txdata: vec![coinbase],
			});
		}
		self
	}

	pub fn without_blocks(self, range: std::ops::RangeFrom<usize>) -> Self {
		Self { without_blocks: Some(range), ..self }
	}

	pub fn without_headers(self) -> Self {
		Self { without_headers: true, ..self }
	}

	pub fn malformed_headers(self) -> Self {
		Self { malformed_headers: true, ..self }
	}

	pub fn filtered_blocks(self) -> Self {
		Self { filtered_blocks: true, ..self }
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
		Self { blocks, without_blocks: None, ..*self }
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

	pub fn header_cache(&self, heights: std::ops::RangeInclusive<usize>) -> UnboundedCache {
		let mut cache = UnboundedCache::new();
		for i in heights {
			let value = self.at_height(i);
			let key = value.header.block_hash();
			assert!(cache.insert(key, value).is_none());
		}
		cache
	}
}

impl BlockSource for Blockchain {
	fn get_header<'a>(&'a self, header_hash: &'a BlockHash, _height_hint: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
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

	fn get_block<'a>(&'a self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, BlockData> {
		Box::pin(async move {
			for (height, block) in self.blocks.iter().enumerate() {
				if block.header.block_hash() == *header_hash {
					if let Some(without_blocks) = &self.without_blocks {
						if without_blocks.contains(&height) {
							return Err(BlockSourceError::persistent("block not found"));
						}
					}

					if self.filtered_blocks {
						return Ok(BlockData::HeaderOnly(block.header.clone()));
					} else {
						return Ok(BlockData::FullBlock(block.clone()));
					}
				}
			}
			Err(BlockSourceError::transient("block not found"))
		})
	}

	fn get_best_block<'a>(&'a self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
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

pub struct NullChainListener;

impl chain::Listen for NullChainListener {
	fn filtered_block_connected(&self, _header: &BlockHeader, _txdata: &chain::transaction::TransactionData, _height: u32) {}
	fn block_disconnected(&self, _header: &BlockHeader, _height: u32) {}
}

pub struct MockChainListener {
	expected_blocks_connected: RefCell<VecDeque<BlockHeaderData>>,
	expected_filtered_blocks_connected: RefCell<VecDeque<BlockHeaderData>>,
	expected_blocks_disconnected: RefCell<VecDeque<BlockHeaderData>>,
}

impl MockChainListener {
	pub fn new() -> Self {
		Self {
			expected_blocks_connected: RefCell::new(VecDeque::new()),
			expected_filtered_blocks_connected: RefCell::new(VecDeque::new()),
			expected_blocks_disconnected: RefCell::new(VecDeque::new()),
		}
	}

	pub fn expect_block_connected(self, block: BlockHeaderData) -> Self {
		self.expected_blocks_connected.borrow_mut().push_back(block);
		self
	}

	pub fn expect_filtered_block_connected(self, block: BlockHeaderData) -> Self {
		self.expected_filtered_blocks_connected.borrow_mut().push_back(block);
		self
	}

	pub fn expect_block_disconnected(self, block: BlockHeaderData) -> Self {
		self.expected_blocks_disconnected.borrow_mut().push_back(block);
		self
	}
}

impl chain::Listen for MockChainListener {
	fn block_connected(&self, block: &Block, height: u32) {
		match self.expected_blocks_connected.borrow_mut().pop_front() {
			None => {
				panic!("Unexpected block connected: {:?}", block.block_hash());
			},
			Some(expected_block) => {
				assert_eq!(block.block_hash(), expected_block.header.block_hash());
				assert_eq!(height, expected_block.height);
			},
		}
	}

	fn filtered_block_connected(&self, header: &BlockHeader, _txdata: &chain::transaction::TransactionData, height: u32) {
		match self.expected_filtered_blocks_connected.borrow_mut().pop_front() {
			None => {
				panic!("Unexpected filtered block connected: {:?}", header.block_hash());
			},
			Some(expected_block) => {
				assert_eq!(header.block_hash(), expected_block.header.block_hash());
				assert_eq!(height, expected_block.height);
			},
		}
	}

	fn block_disconnected(&self, header: &BlockHeader, height: u32) {
		match self.expected_blocks_disconnected.borrow_mut().pop_front() {
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

		let expected_blocks_connected = self.expected_blocks_connected.borrow();
		if !expected_blocks_connected.is_empty() {
			panic!("Expected blocks connected: {:?}", expected_blocks_connected);
		}

		let expected_filtered_blocks_connected = self.expected_filtered_blocks_connected.borrow();
		if !expected_filtered_blocks_connected.is_empty() {
			panic!("Expected filtered_blocks connected: {:?}", expected_filtered_blocks_connected);
		}

		let expected_blocks_disconnected = self.expected_blocks_disconnected.borrow();
		if !expected_blocks_disconnected.is_empty() {
			panic!("Expected blocks disconnected: {:?}", expected_blocks_disconnected);
		}
	}
}
