use crate::{AsyncBlockSourceResult, BlockHeaderData, BlockSource, BlockSourceError, ChainTip, Poll};

use bitcoin::blockdata::block::Block;
use bitcoin::hash_types::BlockHash;

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
						return Ok((ChainTip::Common, &mut *self.block_source));
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
					Ok((ChainTip::Common, source)) => {
						if let Ok((ChainTip::Better(_, _), _)) = best_result {} else {
							best_result = Ok((ChainTip::Common, source));
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

pub struct ChainMultiplexer<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> {
	block_sources: Vec<(B, BlockSourceError)>,
	backup_block_sources: Vec<(B, BlockSourceError)>,
	best_block_source: usize,
}

impl<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> ChainMultiplexer<'b, B> {
	pub fn new(mut block_sources: Vec<B>, mut backup_block_sources: Vec<B>) -> Self {
		assert!(!block_sources.is_empty());
		let block_sources = block_sources.drain(..).map(|block_source| {
			(block_source, BlockSourceError::Transient)
		}).collect();

		let backup_block_sources = backup_block_sources.drain(..).map(|block_source| {
			(block_source, BlockSourceError::Transient)
		}).collect();

		Self { block_sources, backup_block_sources, best_block_source: 0 }
	}

	fn best_and_backup_block_sources(&mut self) -> Vec<&mut (B, BlockSourceError)> {
		let best_block_source = self.block_sources.get_mut(self.best_block_source).unwrap();
		let backup_block_sources = self.backup_block_sources.iter_mut();
		std::iter::once(best_block_source)
			.chain(backup_block_sources)
			.filter(|(_, e)| e == &BlockSourceError::Transient)
			.collect()
	}
}

impl<'b, B: 'b + DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> Poll<'b, B> for ChainMultiplexer<'b, B> {
	fn poll_chain_tip<'a>(&'a mut self, best_chain_tip: BlockHeaderData) ->
		AsyncBlockSourceResult<'a, (ChainTip, &'a mut B::Target)>
	where 'b: 'a {
		Box::pin(async move {
			let mut heaviest_chain_tip = best_chain_tip;
			let mut best_result = Err(BlockSourceError::Persistent);
			for (i, (block_source, error)) in self.block_sources.iter_mut().enumerate() {
				if let BlockSourceError::Persistent = error {
					continue;
				}

				let mut poller = ChainPoller::new(&mut **block_source as &mut dyn BlockSource);
				let result = poller.poll_chain_tip(heaviest_chain_tip).await
					.map(|(chain_tip, _)| chain_tip);
				match result {
					Err(BlockSourceError::Persistent) => {
						*error = BlockSourceError::Persistent;
					},
					Err(BlockSourceError::Transient) => {
						if best_result.is_err() {
							best_result = result;
						}
					},
					Ok(ChainTip::Common) => {
						if let Ok(ChainTip::Better(_, _)) = best_result {} else {
							best_result = result;
						}
					},
					Ok(ChainTip::Better(_, header)) => {
						self.best_block_source = i;
						best_result = result;
						heaviest_chain_tip = header;
					},
					Ok(ChainTip::Worse(_, _)) => {
						if best_result.is_err() {
							best_result = result;
						}
					},
				}
			}

			best_result.map(move |chain_tip| (chain_tip, self as &mut dyn BlockSource))
		})
	}
}

impl<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> BlockSource for ChainMultiplexer<'b, B> {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, height: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			for (block_source, error) in self.best_and_backup_block_sources() {
				let result = block_source.get_header(header_hash, height).await;
				match result {
					Err(e) => *error = e,
					Ok(_) => return result,
				}
			}
			Err(BlockSourceError::Persistent)
		})
	}

	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block> {
		Box::pin(async move {
			for (block_source, error) in self.best_and_backup_block_sources() {
				let result = block_source.get_block(header_hash).await;
				match result {
					Err(e) => *error = e,
					Ok(_) => return result,
				}
			}
			Err(BlockSourceError::Persistent)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move {
			for (block_source, error) in self.best_and_backup_block_sources() {
				let result = block_source.get_best_block().await;
				match result {
					Err(e) => *error = e,
					Ok(_) => return result,
				}
			}
			Err(BlockSourceError::Persistent)
		})
	}
}

#[cfg(test)]
mod tests {
	use crate::*;
	use crate::test_utils::Blockchain;
	use super::*;
	use bitcoin::util::uint::Uint256;

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
			Ok((tip, _)) => assert_eq!(tip, ChainTip::Common),
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
