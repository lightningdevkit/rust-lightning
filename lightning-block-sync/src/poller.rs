use crate::{AsyncBlockSourceResult, BlockSource, BlockSourceError, ChainTip, Poll, Validate, ValidatedBlock, ValidatedBlockHeader};

use bitcoin::network::constants::Network;

use std::ops::DerefMut;

pub struct ChainPoller<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> {
	block_source: B,
	network: Network,
}

impl<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> ChainPoller<'b, B> {
	pub fn new(block_source: B, network: Network) -> Self {
		Self { block_source, network }
	}
}

impl<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> Poll for ChainPoller<'b, B> {
	fn poll_chain_tip<'a>(&'a mut self, best_chain_tip: ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ChainTip>
	{
		Box::pin(async move {
			let (block_hash, height) = self.block_source.get_best_block().await?;
			if block_hash == best_chain_tip.header.block_hash() {
				return Ok(ChainTip::Common);
			}

			let chain_tip = self.block_source
				.get_header(&block_hash, height).await?
				.validate(block_hash)?;
			if chain_tip.chainwork > best_chain_tip.chainwork {
				Ok(ChainTip::Better(chain_tip))
			} else {
				Ok(ChainTip::Worse(chain_tip))
			}
		})
	}

	fn look_up_previous_header<'a>(&'a mut self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlockHeader>
	{
		Box::pin(async move {
			if header.height == 0 {
				return Err(BlockSourceError::Persistent);
			}

			let previous_hash = &header.header.prev_blockhash;
			let height = header.height - 1;
			let previous_header = self.block_source
				.get_header(previous_hash, Some(height)).await?
				.validate(*previous_hash)?;
			header.check_builds_on(&previous_header, self.network)?;

			Ok(previous_header)
		})
	}

	fn fetch_block<'a>(&'a mut self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlock>
	{
		Box::pin(async move {
			self.block_source
				.get_block(&header.block_hash).await?
				.validate(header.block_hash)
		})
	}
}

pub struct ChainMultiplexer<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> {
	block_sources: Vec<(ChainPoller<'b, B>, BlockSourceError)>,
	backup_block_sources: Vec<(ChainPoller<'b, B>, BlockSourceError)>,
	best_block_source: usize,
}

impl<'b, B: DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> ChainMultiplexer<'b, B> {
	pub fn new(mut block_sources: Vec<B>, mut backup_block_sources: Vec<B>, network: Network) -> Self {
		assert!(!block_sources.is_empty());
		let block_sources = block_sources.drain(..).map(|block_source| {
			(ChainPoller::new(block_source, network), BlockSourceError::Transient)
		}).collect();

		let backup_block_sources = backup_block_sources.drain(..).map(|block_source| {
			(ChainPoller::new(block_source, network), BlockSourceError::Transient)
		}).collect();

		Self { block_sources, backup_block_sources, best_block_source: 0 }
	}

	fn best_and_backup_block_sources(&mut self) -> Vec<&mut (ChainPoller<'b, B>, BlockSourceError)> {
		let best_block_source = self.block_sources.get_mut(self.best_block_source).unwrap();
		let backup_block_sources = self.backup_block_sources.iter_mut();
		std::iter::once(best_block_source)
			.chain(backup_block_sources)
			.filter(|(_, e)| e == &BlockSourceError::Transient)
			.collect()
	}
}

impl<'b, B: 'b + DerefMut<Target=dyn BlockSource + 'b> + Sized + Sync + Send> Poll for ChainMultiplexer<'b, B> {
	fn poll_chain_tip<'a>(&'a mut self, best_chain_tip: ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ChainTip>
	{
		Box::pin(async move {
			let mut heaviest_chain_tip = best_chain_tip;
			let mut best_result = Err(BlockSourceError::Persistent);
			for (i, (poller, error)) in self.block_sources.iter_mut().enumerate() {
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
					Ok(ChainTip::Common) => {
						if let Ok(ChainTip::Better(_)) = best_result {} else {
							best_result = result;
						}
					},
					Ok(ChainTip::Better(ref chain_tip)) => {
						self.best_block_source = i;
						heaviest_chain_tip = *chain_tip;
						best_result = result;
					},
					Ok(ChainTip::Worse(_)) => {
						if best_result.is_err() {
							best_result = result;
						}
					},
				}
			}

			best_result
		})
	}

	fn look_up_previous_header<'a>(&'a mut self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlockHeader>
	{
		Box::pin(async move {
			for (poller, error) in self.best_and_backup_block_sources() {
				let result = poller.look_up_previous_header(header).await;
				match result {
					Err(e) => *error = e,
					Ok(_) => return result,
				}
			}
			Err(BlockSourceError::Persistent)
		})
	}

	fn fetch_block<'a>(&'a mut self, header: &'a ValidatedBlockHeader) ->
		AsyncBlockSourceResult<'a, ValidatedBlock>
	{
		Box::pin(async move {
			for (poller, error) in self.best_and_backup_block_sources() {
				let result = poller.fetch_block(header).await;
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

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Bitcoin);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => assert_eq!(e, BlockSourceError::Transient),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_without_headers() {
		let mut chain = Blockchain::default().with_height(1).without_headers();
		let best_chain_tip = chain.at_height(0);

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Bitcoin);
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

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Bitcoin);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => assert_eq!(e, BlockSourceError::Persistent),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_malformed_headers() {
		let mut chain = Blockchain::default().with_height(1).malformed_headers();
		let best_chain_tip = chain.at_height(0);

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Bitcoin);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => assert_eq!(e, BlockSourceError::Persistent),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_common_tip() {
		let mut chain = Blockchain::default().with_height(0);
		let best_chain_tip = chain.tip();

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Bitcoin);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tip) => assert_eq!(tip, ChainTip::Common),
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
		let worse_chain_tip = worse_chain_tip.validate(worse_chain_tip_hash).unwrap();
		assert_eq!(best_chain_tip.chainwork, worse_chain_tip.chainwork);

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Bitcoin);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tip) => assert_eq!(tip, ChainTip::Worse(worse_chain_tip)),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_worse_tip() {
		let mut chain = Blockchain::default().with_height(1);
		let best_chain_tip = chain.tip();
		chain.disconnect_tip();

		let worse_chain_tip = chain.tip();
		let worse_chain_tip_hash = worse_chain_tip.header.block_hash();
		let worse_chain_tip = worse_chain_tip.validate(worse_chain_tip_hash).unwrap();

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Bitcoin);
		match poller.poll_chain_tip(best_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tip) => assert_eq!(tip, ChainTip::Worse(worse_chain_tip)),
		}
	}

	#[tokio::test]
	async fn poll_chain_with_better_tip() {
		let mut chain = Blockchain::default().with_height(1);
		let worse_chain_tip = chain.at_height(0);

		let best_chain_tip = chain.tip();
		let best_chain_tip_hash = best_chain_tip.header.block_hash();
		let best_chain_tip = best_chain_tip.validate(best_chain_tip_hash).unwrap();

		let mut poller = ChainPoller::new(&mut chain as &mut dyn BlockSource, Network::Bitcoin);
		match poller.poll_chain_tip(worse_chain_tip).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(tip) => assert_eq!(tip, ChainTip::Better(best_chain_tip)),
		}
	}
}
