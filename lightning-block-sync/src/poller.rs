use crate::{AsyncBlockSourceResult, BlockHeaderData, BlockSource, BlockSourceError, ChainTip, Poll};

use std::ops::DerefMut;

pub struct ChainPoller<'a, B: DerefMut<Target=dyn BlockSource + 'a> + Sized + Sync + Send> {
	block_source: B,
}

impl<'a, B: DerefMut<Target=dyn BlockSource + 'a> + Sized + Sync + Send> ChainPoller<'a, B> {
	pub fn new(block_source: B) -> Self {
		Self { block_source }
	}
}

impl<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> Poll<'b, B> for ChainPoller<'b, B> {

	fn poll_chain_tip<'a>(&'a mut self, best_chain_tip: BlockHeaderData) ->
		AsyncBlockSourceResult<'a, (ChainTip, &'a mut B::Target)>
	where 'b: 'a {
		Box::pin(async move {
			match self.block_source.get_best_block().await {
				Err(e) => Err(e),
				Ok((block_hash, height)) => {
					if block_hash == best_chain_tip.header.block_hash() {
						return Ok((ChainTip::Common(true), &mut *self.block_source));
					}

					match self.block_source.get_header(&block_hash, height).await {
						Err(e) => Err(e),
						Ok(chain_tip) => {
							crate::stateless_check_header(&chain_tip.header)?;
							if chain_tip.header.block_hash() != block_hash {
								Err(BlockSourceError::Persistent)
							} else if chain_tip.chainwork <= best_chain_tip.chainwork {
								Ok((ChainTip::Worse(block_hash, chain_tip), &mut *self.block_source))
							} else {
								Ok((ChainTip::Better(block_hash, chain_tip), &mut *self.block_source))
							}
						},
					}

				},
			}
		})
	}
}

pub struct MultipleChainPoller<'a, B: DerefMut<Target=dyn BlockSource + 'a> + Sized + Sync + Send> {
	pollers: Vec<(ChainPoller<'a, B>, BlockSourceError)>,
}

impl<'a, B: DerefMut<Target=dyn BlockSource + 'a> + Sized + Sync + Send> MultipleChainPoller<'a, B> {
	pub fn new(mut block_sources: Vec<B>) -> Self {
		let pollers = block_sources.drain(..).map(|block_source| {
			(ChainPoller::new(block_source), BlockSourceError::Transient)
		}).collect();
		Self { pollers }
	}
}

impl<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> Poll<'b, B> for MultipleChainPoller<'b, B> {

	fn poll_chain_tip<'a>(&'a mut self, best_chain_tip: BlockHeaderData) ->
		AsyncBlockSourceResult<'a, (ChainTip, &'a mut B::Target)>
	where 'b: 'a {
		Box::pin(async move {
			let mut heaviest_chain_tip = best_chain_tip;
			let mut best_result = Err(BlockSourceError::Persistent);
			let mut common = 0;
			let num_pollers = self.pollers.len();
			for (poller, error) in self.pollers.iter_mut() {
				if let BlockSourceError::Persistent = error {
					continue;
				}

				let result = poller.poll_chain_tip(heaviest_chain_tip).await;
				match result {
					Err(BlockSourceError::Persistent) => {
						*error = BlockSourceError::Persistent;
					},
					Err(BlockSourceError::Transient) => {
						if best_result.is_err() {
							best_result = result;
						}
					},
					Ok((ChainTip::Common(_), source)) => {
						common += 1;
						if let Ok((ChainTip::Better(_, _), _)) = best_result {} else {
							let all_common = common == num_pollers;
							best_result = Ok((ChainTip::Common(all_common), source));
						}
					},
					Ok((ChainTip::Better(_, header), _)) => {
						best_result = result;
						heaviest_chain_tip = header;
					},
					Ok((ChainTip::Worse(_, _), _)) => {
						if best_result.is_err() {
							best_result = result;
						}
					},
				}
			}
			best_result
		})
	}
}

#[cfg(test)]
mod tests {
	use crate::*;
	use super::*;
	use bitcoin::blockdata::block::Block;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::network::constants::Network;
	use bitcoin::util::uint::Uint256;

	#[derive(Default)]
	struct Blockchain {
		blocks: Vec<Block>,
		without_headers: bool,
		malformed_headers: bool,
	}

	impl Blockchain {
		fn default() -> Self {
			Blockchain::with_network(Network::Bitcoin)
		}

		fn with_network(network: Network) -> Self {
			let blocks = vec![genesis_block(network)];
			Self { blocks, ..Default::default() }
		}

		fn with_height(mut self, height: usize) -> Self {
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

		fn without_headers(self) -> Self {
			Self { without_headers: true, ..self }
		}

		fn malformed_headers(self) -> Self {
			Self { malformed_headers: true, ..self }
		}

		fn at_height(&self, height: usize) -> BlockHeaderData {
			assert!(!self.blocks.is_empty());
			assert!(height < self.blocks.len());
			BlockHeaderData {
				chainwork: self.blocks[0].header.work() * Uint256::from_u64(height as u64).unwrap(),
				height: height as u32,
				header: self.blocks[height].header.clone(),
			}
		}

		fn tip(&self) -> BlockHeaderData {
			assert!(!self.blocks.is_empty());
			self.at_height(self.blocks.len() - 1)
		}

		fn disconnect_tip(&mut self) -> Option<Block> {
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

	#[tokio::test]
	async fn poll_empty_chain() {
		let mut chain = Blockchain::default().with_height(0);
		let best_chain_tip = chain.tip();
		chain.disconnect_tip();

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => assert_eq!(e, BlockSourceError::Transient),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_without_headers() {
		let mut chain = Blockchain::default().with_height(1).without_headers();
		let best_chain_tip = chain.at_height(0);

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => assert_eq!(e, BlockSourceError::Persistent),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_invalid_pow() {
		let mut chain = Blockchain::default().with_height(1);
		let best_chain_tip = chain.at_height(0);

		// Invalidate the tip by changing its target.
		chain.blocks.last_mut().unwrap().header.bits =
			BlockHeader::compact_target_from_u256(&Uint256::from_be_bytes([0; 32]));

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => assert_eq!(e, BlockSourceError::Persistent),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_malformed_headers() {
		let mut chain = Blockchain::default().with_height(1).malformed_headers();
		let best_chain_tip = chain.at_height(0);

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => assert_eq!(e, BlockSourceError::Persistent),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_common_tip() {
		let mut chain = Blockchain::default().with_height(0);
		let best_chain_tip = chain.tip();

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok((tip, _)) => assert_eq!(tip, ChainTip::Common(true)),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_uncommon_tip_but_equal_chainwork() {
		let mut chain = Blockchain::default().with_height(1);
		let best_chain_tip = chain.tip();

		// Change the nonce to get a different block hash with the same chainwork.
		chain.blocks.last_mut().unwrap().header.nonce += 1;

		let worse_chain_tip = chain.tip();
		let worse_chain_tip_hash = worse_chain_tip.header.block_hash();
		assert_eq!(best_chain_tip.chainwork, worse_chain_tip.chainwork);

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok((tip, _)) => assert_eq!(tip, ChainTip::Worse(worse_chain_tip_hash, worse_chain_tip)),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_worse_tip() {
		let mut chain = Blockchain::default().with_height(1);
		let best_chain_tip = chain.tip();
		chain.disconnect_tip();

		let worse_chain_tip = chain.tip();
		let worse_chain_tip_hash = worse_chain_tip.header.block_hash();

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok((tip, _)) => assert_eq!(tip, ChainTip::Worse(worse_chain_tip_hash, worse_chain_tip)),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_better_tip() {
		let mut chain = Blockchain::default().with_height(1);
		let worse_chain_tip = chain.at_height(0);

		let best_chain_tip = chain.tip();
		let best_chain_tip_hash = best_chain_tip.header.block_hash();

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource);
		match poller.poll_chain_tip(worse_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok((tip, _)) => assert_eq!(tip, ChainTip::Better(best_chain_tip_hash, best_chain_tip)),
		}
	}
}
