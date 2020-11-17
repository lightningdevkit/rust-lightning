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
