//! An implementation of a simple SPV client which can interrogate abstract block sources to keep
//! lightning objects on the best chain.
//!
//! With feature `rpc-client` we provide a client which can fetch blocks from Bitcoin Core's RPC
//! interface.
//!
//! With feature `rest-client` we provide a client which can fetch blocks from Bitcoin Core's REST
//! interface.
//!
//! Both provided clients support either blocking TCP reads from std::net::TcpStream or, with
//! feature `tokio`, tokio::net::TcpStream inside a Tokio runtime.

#[cfg(any(feature = "rest-client", feature = "rpc-client"))]
mod utils;

#[cfg(any(feature = "rest-client", feature = "rpc-client"))]
pub mod http_clients;

use lightning::chain::{chaininterface, keysinterface};
use lightning::chain::chaininterface::{BlockNotifierArc, ChainListener};
use lightning::ln::channelmonitor::{ChannelMonitor, ManyChannelMonitor};
use lightning::ln::channelmanager::SimpleArcChannelManager;

use bitcoin::hashes::hex::ToHex;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::util::hash::BitcoinHash;
use bitcoin::util::uint::Uint256;
use bitcoin::hash_types::BlockHash;

use std::future::Future;
use std::vec::Vec;
use std::pin::Pin;
use std::ops::DerefMut;

#[derive(Clone, Debug, PartialEq)]
/// A block header and some associated data. This information should be available from most block
/// sources (and, notably, is available in Bitcoin Core's RPC and REST interfaces).
pub struct BlockHeaderData {
	/// The total chain work, in expected number of double-SHA256 hashes required to build a chain
	/// of equivalent weight
	pub chainwork: Uint256,
	/// The block height, with the genesis block heigh set to 0
	pub height: u32,
	/// The block header itself
	pub header: BlockHeader
}

#[derive(Debug, Clone)]
/// Failure type for requests to block sources.
pub enum BlockSourceRespErr {
	/// Indicates a BlockSource provided bogus data. After this is returned once we will never
	/// bother polling the returning BlockSource for block data again, so use it sparingly.
	BogusData,
	/// Indicates the BlockSource isn't responsive or may be misconfigured but we want to continue
	/// polling it.
	NoResponse,
}
/// Abstract type for a source of block header and block data.
pub trait BlockSource : Sync + Send {
	/// Gets the header for a given hash. The height the header should be at is provided, though
	/// note that you must return either the header with the requested hash, or an Err, not a
	/// different header with the same eight.
	///
	/// For sources which cannot find headers based on the hash, returning NoResponse when
	/// height_hint is None is fine, though get_best_block() should never return a None for height
	/// on the same source. Such a source should never be used in init_sync_chain_monitor as it
	/// doesn't have any initial height information.
	///
	/// Sadly rust's trait system hasn't grown the ability to take impl/differentially-sized return
	/// values yet, so we have to Box + dyn the future.
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>) -> Pin<Box<dyn Future<Output = Result<BlockHeaderData, BlockSourceRespErr>> + 'a + Send>>;

	/// Gets the block for a given hash. BlockSources may be headers-only, in which case they
	/// should always return Err(BlockSourceRespErr::NoResponse) here.
	/// Sadly rust's trait system hasn't grown the ability to take impl/differentially-sized return
	/// values yet, so we have to Box + dyn the future.
	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> Pin<Box<dyn Future<Output = Result<Block, BlockSourceRespErr>> + 'a + Send>>;

	/// Gets the best block hash and, optionally, its height.
	/// Including the height doesn't impact the chain-scannling algorithm, but it is passed to
	/// get_header() which may allow some BlockSources to more effeciently find the target header.
	///
	/// Sadly rust's trait system hasn't grown the ability to take impl/differentially-sized return
	/// values yet, so we have to Box + dyn the future.
	fn get_best_block<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(BlockHash, Option<u32>), BlockSourceRespErr>> + 'a + Send>>;
}

/// Stateless header checks on a given header.
#[inline]
fn stateless_check_header(header: &BlockHeader) -> Result<(), BlockSourceRespErr> {
	if header.validate_pow(&header.target()).is_err() {
		Err(BlockSourceRespErr::BogusData)
	} else { Ok(()) }
}

/// Check that child_header correctly builds on previous_header - the claimed work differential
/// matches the actual PoW in child_header and the difficulty transition is possible, ie within 4x.
/// Includes stateless header checks on previous_header.
fn check_builds_on(child_header: &BlockHeaderData, previous_header: &BlockHeaderData, mainnet: bool) -> Result<(), BlockSourceRespErr> {
	if child_header.header.prev_blockhash != previous_header.header.bitcoin_hash() {
		return Err(BlockSourceRespErr::BogusData);
	}

	stateless_check_header(&previous_header.header)?;
	let new_work = child_header.header.work();
	if previous_header.height != child_header.height - 1 ||
			previous_header.chainwork + new_work != child_header.chainwork {
		return Err(BlockSourceRespErr::BogusData);
	}
	if mainnet {
		if child_header.height % 2016 == 0 {
			let prev_work = previous_header.header.work();
			if new_work > prev_work << 2 || new_work < prev_work >> 2 {
				return Err(BlockSourceRespErr::BogusData)
			}
		} else if child_header.header.bits != previous_header.header.bits {
			return Err(BlockSourceRespErr::BogusData)
		}
	}
	Ok(())
}

enum ForkStep {
	ForkPoint(BlockHeaderData),
	DisconnectBlock(BlockHeaderData),
	ConnectBlock(BlockHeaderData),
}
fn find_fork_step<'a>(steps_tx: &'a mut Vec<ForkStep>, current_header: BlockHeaderData, prev_header: &'a BlockHeaderData, block_source: &'a mut dyn BlockSource, head_blocks: &'a [BlockHeaderData], mainnet: bool) -> Pin<Box<dyn Future<Output=Result<(), BlockSourceRespErr>> + Send + 'a>> {
	Box::pin(async move {
		if prev_header.header.prev_blockhash == current_header.header.prev_blockhash {
			// Found the fork, get the fork point header and we're done!
			steps_tx.push(ForkStep::DisconnectBlock(prev_header.clone()));
			steps_tx.push(ForkStep::ConnectBlock(current_header));
			if !head_blocks.is_empty() {
				let new_prev_header = head_blocks.last().unwrap();
				steps_tx.push(ForkStep::ForkPoint(new_prev_header.clone()));
			} else {
				let new_prev_header = block_source.get_header(&prev_header.header.prev_blockhash, Some(prev_header.height - 1)).await?;
				check_builds_on(&prev_header, &new_prev_header, mainnet)?;
				steps_tx.push(ForkStep::ForkPoint(new_prev_header.clone()));
			}
		} else if current_header.height == 0 {
			// We're connect through genesis, we must be on a different chain!
			return Err(BlockSourceRespErr::BogusData);
		} else if prev_header.height < current_header.height {
			if prev_header.height + 1 == current_header.height &&
					prev_header.header.bitcoin_hash() == current_header.header.prev_blockhash {
				// Current header is the one above prev_header, we're done!
				steps_tx.push(ForkStep::ConnectBlock(current_header));
			} else {
				// Current is higher than the prev, walk current down by listing blocks we need to
				// connect
				let new_cur_header = block_source.get_header(&current_header.header.prev_blockhash, Some(current_header.height - 1)).await?;
				check_builds_on(&current_header, &new_cur_header, mainnet)?;
				steps_tx.push(ForkStep::ConnectBlock(current_header));
				find_fork_step(steps_tx, new_cur_header, prev_header, block_source, head_blocks, mainnet).await?;
			}
		} else if prev_header.height > current_header.height {
			// Previous is higher, walk it back and recurse
			steps_tx.push(ForkStep::DisconnectBlock(prev_header.clone()));
			if !head_blocks.is_empty() {
				let new_prev_header = head_blocks.last().unwrap();
				let new_head_blocks = &head_blocks[..head_blocks.len() - 1];
				find_fork_step(steps_tx, current_header, new_prev_header, block_source, new_head_blocks, mainnet).await?;
			} else {
				let new_prev_header = block_source.get_header(&prev_header.header.prev_blockhash, Some(prev_header.height - 1)).await?;
				check_builds_on(&prev_header, &new_prev_header, mainnet)?;
				find_fork_step(steps_tx, current_header, &new_prev_header, block_source, head_blocks, mainnet).await?;
			}
		} else {
			// Target and current are at the same height, but we're not at fork yet, walk
			// both back and recurse
			let new_cur_header = block_source.get_header(&current_header.header.prev_blockhash, Some(current_header.height - 1)).await?;
			check_builds_on(&current_header, &new_cur_header, mainnet)?;
			steps_tx.push(ForkStep::ConnectBlock(current_header));
			steps_tx.push(ForkStep::DisconnectBlock(prev_header.clone()));
			if !head_blocks.is_empty() {
				let new_prev_header = head_blocks.last().unwrap();
				let new_head_blocks = &head_blocks[..head_blocks.len() - 1];
				find_fork_step(steps_tx, new_cur_header, new_prev_header, block_source, new_head_blocks, mainnet).await?;
			} else {
				let new_prev_header = block_source.get_header(&prev_header.header.prev_blockhash, Some(prev_header.height - 1)).await?;
				check_builds_on(&prev_header, &new_prev_header, mainnet)?;
				find_fork_step(steps_tx, new_cur_header, &new_prev_header, block_source, head_blocks, mainnet).await?;
			}
		}
		Ok(())
	})
}
/// Walks backwards from current_header and prev_header finding the fork and sending ForkStep events
/// into the steps_tx Sender. There is no ordering guarantee between different ForkStep types, but
/// DisconnectBlock and ConnectBlock events are each in reverse, height-descending order.
async fn find_fork<'a>(current_header: BlockHeaderData, prev_header: &'a BlockHeaderData, block_source: &'a mut dyn BlockSource, mut head_blocks: &'a [BlockHeaderData], mainnet: bool) -> Result<Vec<ForkStep>, BlockSourceRespErr> {
	let mut steps_tx = Vec::new();
	if current_header.header == prev_header.header { return Ok(steps_tx); }

	// If we have cached headers, they have to end with where we used to be
	head_blocks = if !head_blocks.is_empty() {
		assert_eq!(head_blocks.last().unwrap(), prev_header);
		&head_blocks[..head_blocks.len() - 1]
	} else { head_blocks };

	find_fork_step(&mut steps_tx, current_header, &prev_header, block_source, head_blocks, mainnet).await?;
	Ok(steps_tx)
}

/// A dummy trait for capturing an object which wants the chain to be replayed.
/// Implemented for lightning BlockNotifiers for general use, as well as
/// ChannelManagers and ChannelMonitors to allow for easy replaying of chain
/// data upon deserialization.
pub trait AChainListener {
	fn a_block_connected(&mut self, block: &Block, height: u32);
	fn a_block_disconnected(&mut self, header: &BlockHeader, height: u32);
}

impl AChainListener for &BlockNotifierArc {
	fn a_block_connected(&mut self, block: &Block, height: u32) {
		self.block_connected(block, height);
	}
	fn a_block_disconnected(&mut self, header: &BlockHeader, height: u32) {
		self.block_disconnected(header, height);
	}
}

impl<M, B, F> AChainListener for &SimpleArcChannelManager<M, B, F>
		where M: ManyChannelMonitor<keysinterface::InMemoryChannelKeys>,
		      B: chaininterface::BroadcasterInterface, F: chaininterface::FeeEstimator {
	fn a_block_connected(&mut self, block: &Block, height: u32) {
		let mut txn = Vec::with_capacity(block.txdata.len());
		let mut idxn = Vec::with_capacity(block.txdata.len());
		for (i, tx) in block.txdata.iter().enumerate() {
			txn.push(tx);
			idxn.push(i as u32);
		}
		self.block_connected(&block.header, height, &txn, &idxn);
	}
	fn a_block_disconnected(&mut self, header: &BlockHeader, height: u32) {
		self.block_disconnected(header, height);
	}
}

impl<CS, B, F> AChainListener for (&mut ChannelMonitor<CS>, &B, &F)
		where CS: keysinterface::ChannelKeys,
		      B: chaininterface::BroadcasterInterface, F: chaininterface::FeeEstimator {
	fn a_block_connected(&mut self, block: &Block, height: u32) {
		let mut txn = Vec::with_capacity(block.txdata.len());
		for tx in block.txdata.iter() {
			txn.push(tx);
		}
		self.0.block_connected(&txn, height, &block.bitcoin_hash(), self.1, self.2);
	}
	fn a_block_disconnected(&mut self, header: &BlockHeader, height: u32) {
		self.0.block_disconnected(height, &header.bitcoin_hash(), self.1, self.2);
	}
}

/// Finds the fork point between new_header and old_header, disconnecting blocks from old_header to
/// get to that point and then connecting blocks until we get to new_header.
///
/// We validate the headers along the transition path, but don't fetch blocks until we've
/// disconnected to the fork point. Thus, we may return an Err() that includes where our tip ended
/// up which may not be new_header. Note that iff the returned Err has a BlockHeaderData, the
/// header transition from old_header to new_header is valid.
async fn sync_chain_monitor<CL : AChainListener + Sized>(new_header: BlockHeaderData, old_header: &BlockHeaderData, block_source: &mut dyn BlockSource, chain_notifier: &mut CL, head_blocks: &mut Vec<BlockHeaderData>, mainnet: bool)
		-> Result<(), (BlockSourceRespErr, Option<BlockHeaderData>)> {
	let mut events = find_fork(new_header, old_header, block_source, &*head_blocks, mainnet).await.map_err(|e| (e, None))?;

	let mut last_disconnect_tip = None;
	let mut new_tip = None;
	for event in events.iter() {
		match &event {
			&ForkStep::DisconnectBlock(ref header) => {
				println!("Disconnecting block {}", header.header.bitcoin_hash());
				if let Some(cached_head) = head_blocks.pop() {
					assert_eq!(cached_head, *header);
				}
				chain_notifier.a_block_disconnected(&header.header, header.height);
				last_disconnect_tip = Some(header.header.prev_blockhash);
			},
			&ForkStep::ForkPoint(ref header) => {
				new_tip = Some(header.clone());
			},
			_ => {},
		}
	}

	// If we disconnected any blocks, we should have new tip data available, which should match our
	// cached header data if it is available. If we didn't disconnect any blocks we shouldn't have
	// set a ForkPoint as there is no fork.
	assert_eq!(last_disconnect_tip.is_some(), new_tip.is_some());
	if let &Some(ref tip_header) = &new_tip {
		if let Some(cached_head) = head_blocks.last() {
			assert_eq!(cached_head, tip_header);
		}
		debug_assert_eq!(tip_header.header.bitcoin_hash(), *last_disconnect_tip.as_ref().unwrap());
	} else {
		// Set new_tip to indicate that we got a valid header chain we wanted to connect to, but
		// failed
		new_tip = Some(old_header.clone());
	}

	for event in events.drain(..).rev() {
		if let ForkStep::ConnectBlock(header_data) = event {
			let block = match block_source.get_block(&header_data.header.bitcoin_hash()).await {
				Err(e) => return Err((e, new_tip)),
				Ok(b) => b,
			};
			if block.header != header_data.header || !block.check_merkle_root() || !block.check_witness_commitment() {
				return Err((BlockSourceRespErr::BogusData, new_tip));
			}
			println!("Connecting block {}", header_data.header.bitcoin_hash().to_hex());
			chain_notifier.a_block_connected(&block, header_data.height);
			head_blocks.push(header_data.clone());
			new_tip = Some(header_data);
		}
	}
	Ok(())
}

/// Do a one-time sync of a chain listener from a single *trusted* block source bringing its view
/// of the latest chain tip from old_block to new_block. This is useful on startup when you need
/// to bring each ChannelMonitor, as well as the overall ChannelManager, into sync with each other.
///
/// Once you have them all at the same block, you should switch to using MicroSPVClient.
pub async fn init_sync_chain_monitor<CL : AChainListener + Sized, B: BlockSource>(new_block: BlockHash, old_block: BlockHash, block_source: &mut B, mut chain_notifier: CL) {
	if &old_block[..] == &[0; 32] { return; }

	let new_header = block_source.get_header(&new_block, None).await.unwrap();
	assert_eq!(new_header.header.bitcoin_hash(), new_block);
	stateless_check_header(&new_header.header).unwrap();
	let old_header = block_source.get_header(&old_block, None).await.unwrap();
	assert_eq!(old_header.header.bitcoin_hash(), old_block);
	stateless_check_header(&old_header.header).unwrap();
	sync_chain_monitor(new_header, &old_header, block_source, &mut chain_notifier, &mut Vec::new(), false).await.unwrap();
}

/// Keep the chain that a chain listener knows about up-to-date with the best chain from any of the
/// given block_sources.
///
/// This implements a pretty bare-bones SPV client, checking all relevant commitments and finding
/// the heaviest chain, but not storing the full header chain, leading to some important
/// limitations.
///
/// While we never check full difficulty transition logic, the mainnet option enables checking that
/// difficulty transitions only happen every two weeks and never shift difficulty more than 4x in
/// either direction, which is sufficient to prevent most minority hashrate attacks.
///
/// We cache any headers which we connect until every block source is in agreement on the best tip.
/// This prevents one block source from being able to orphan us on a fork of its own creation by
/// not responding to requests for old headers on that fork. However, if one block source is
/// unreachable this may result in our memory usage growing in accordance with the chain.
pub struct MicroSPVClient<'a, B: DerefMut<Target=dyn BlockSource + 'a> + Sized + Sync + Send, CL : AChainListener + Sized> {
	chain_tip: (BlockHash, BlockHeaderData),
	block_sources: Vec<B>,
	backup_block_sources: Vec<B>,
	cur_blocks: Vec<Result<BlockHash, BlockSourceRespErr>>,
	blocks_past_common_tip: Vec<BlockHeaderData>,
	chain_notifier: CL,
	mainnet: bool
}
impl<'a, B: DerefMut<Target=dyn BlockSource + 'a> + Sized + Sync + Send, CL : AChainListener + Sized> MicroSPVClient<'a, B, CL> {
	/// Create a new MicroSPVClient with a set of block sources and a chain listener which will
	/// receive updates of the new tip.
	///
	/// We assume that at least one of the provided BlockSources can provide all neccessary headers
	/// to disconnect from the given chain_tip back to its common ancestor with the best chain.
	/// We assume that the height, hash, and chain work given in chain_tip are correct.
	///
	/// `backup_block_sources` are never queried unless we learned, via some `block_sources` source
	/// that there exists a better, valid header chain but we failed to fetch the blocks. This is
	/// useful when you have a block source which is more censorship-resistant than others but
	/// which only provides headers. In this case, we can use such source(s) to learn of a censorship
	/// attack without giving up privacy by querying a privacy-losing block sources.
	pub fn init(chain_tip: BlockHeaderData, block_sources: Vec<B>, backup_block_sources: Vec<B>, chain_notifier: CL, mainnet: bool) -> Self {
		let cur_blocks = vec![Err(BlockSourceRespErr::NoResponse); block_sources.len() + backup_block_sources.len()];
		let blocks_past_common_tip = Vec::new();
		Self {
			chain_tip: (chain_tip.header.bitcoin_hash(), chain_tip),
			block_sources, backup_block_sources, cur_blocks, blocks_past_common_tip, chain_notifier, mainnet
		}
	}
	/// Check each source for a new best tip and update the chain listener accordingly.
	/// Returns true if some blocks were [dis]connected, false otherwise.
	pub async fn poll_best_tip(&mut self) -> bool {
		let mut highest_valid_tip = self.chain_tip.1.chainwork;
		let mut blocks_connected = false;

		macro_rules! process_source {
			($cur_hash: expr, $source: expr) => { {
				if let Err(BlockSourceRespErr::BogusData) = $cur_hash {
					// We gave up on this provider, move on.
					continue;
				}
				macro_rules! handle_err {
					($err: expr) => {
						match $err {
							Ok(r) => r,
							Err(BlockSourceRespErr::BogusData) => {
								$cur_hash = Err(BlockSourceRespErr::BogusData);
								continue;
							},
							Err(BlockSourceRespErr::NoResponse) => {
								continue;
							},
						}
					}
				}
				let (new_hash, height_opt) = handle_err!($source.get_best_block().await);
				if new_hash == self.chain_tip.0 {
					$cur_hash = Ok(new_hash);
					continue;
				}
				let new_header = handle_err!($source.get_header(&new_hash, height_opt).await);
				if new_header.header.bitcoin_hash() != new_hash {
					$cur_hash = Err(BlockSourceRespErr::BogusData);
					continue;
				}
				handle_err!(stateless_check_header(&new_header.header));
				if new_header.chainwork <= self.chain_tip.1.chainwork {
					$cur_hash = Ok(new_hash);
					continue;
				}

				let syncres = sync_chain_monitor(new_header.clone(), &self.chain_tip.1, &mut *$source, &mut self.chain_notifier, &mut self.blocks_past_common_tip, self.mainnet).await;
				if let Err((e, new_tip)) = syncres {
					if let Some(tip) = new_tip {
						let tiphash = tip.header.bitcoin_hash();
						if tiphash != self.chain_tip.0 {
							self.chain_tip = (tiphash, tip);
							blocks_connected = true;
						}
						// We set cur_hash to where we got to since we don't mind dropping our
						// block header cache if its on a fork that no block sources care about,
						// but we (may) want to continue trying to get the blocks from this source
						// the next time we poll.
						$cur_hash = Ok(tiphash);
						highest_valid_tip = std::cmp::max(highest_valid_tip, new_header.chainwork);
					}
					handle_err!(Err(e));
				} else {
					highest_valid_tip = std::cmp::max(highest_valid_tip, new_header.chainwork);
					self.chain_tip = (new_hash, new_header);
					$cur_hash = Ok(new_hash);
					blocks_connected = true;
				}
			} }
		}

		for (cur_hash, source) in self.cur_blocks.iter_mut().take(self.block_sources.len())
				.zip(self.block_sources.iter_mut()) {
			process_source!(*cur_hash, *source);
		}

		if highest_valid_tip != self.chain_tip.1.chainwork {
			for (cur_hash, source) in self.cur_blocks.iter_mut().skip(self.block_sources.len())
					.zip(self.backup_block_sources.iter_mut()) {
				process_source!(*cur_hash, *source);
				if highest_valid_tip == self.chain_tip.1.chainwork { break; }
			}
		}

		let mut common_tip = true;
		for cur_hash in self.cur_blocks.iter() {
			if let Ok(hash) = cur_hash {
				if *hash != self.chain_tip.0 {
					common_tip = false;
					break;
				}
			}
		}
		if common_tip {
			// All block sources have the same tip. Assume we will be able to trivially get old
			// headers and drop our reorg cache.
			self.blocks_past_common_tip.clear();
		}
		blocks_connected
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::blockdata::block::{Block, BlockHeader};
	use bitcoin::util::uint::Uint256;
	use std::collections::HashMap;
	use std::sync::{Arc, Mutex};

	struct ChainListener {
		blocks_connected: Mutex<Vec<(BlockHash, u32)>>,
		blocks_disconnected: Mutex<Vec<(BlockHash, u32)>>,
	}
	impl AChainListener for Arc<ChainListener> {
		fn a_block_connected(&mut self, block: &Block, height: u32) {
			self.blocks_connected.lock().unwrap().push((block.header.bitcoin_hash(), height));
		}
		fn a_block_disconnected(&mut self, header: &BlockHeader, height: u32) {
			self.blocks_disconnected.lock().unwrap().push((header.bitcoin_hash(), height));
		}
	}

	#[derive(Clone)]
	struct BlockData {
		block: Block,
		chainwork: Uint256,
		height: u32,
	}
	struct Blockchain {
		blocks: Mutex<HashMap<BlockHash, BlockData>>,
		best_block: Mutex<(BlockHash, Option<u32>)>,
		headers_only: bool,
		disallowed: Mutex<bool>,
	}
	impl BlockSource for &Blockchain {
		fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>) -> Pin<Box<dyn Future<Output = Result<BlockHeaderData, BlockSourceRespErr>> + 'a + Send>> {
			if *self.disallowed.lock().unwrap() { unreachable!(); }
			Box::pin(async move {
				match self.blocks.lock().unwrap().get(header_hash) {
					Some(block) => {
						assert_eq!(Some(block.height), height_hint);
						Ok(BlockHeaderData {
							chainwork: block.chainwork,
							height: block.height,
							header: block.block.header.clone(),
						})
					},
					None => Err(BlockSourceRespErr::NoResponse),
				}
			})
		}
		fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> Pin<Box<dyn Future<Output = Result<Block, BlockSourceRespErr>> + 'a + Send>> {
			if *self.disallowed.lock().unwrap() { unreachable!(); }
			Box::pin(async move {
				if self.headers_only {
					Err(BlockSourceRespErr::NoResponse)
				} else {
					match self.blocks.lock().unwrap().get(header_hash) {
						Some(block) => Ok(block.block.clone()),
						None => Err(BlockSourceRespErr::NoResponse),
					}
				}
			})
		}
		fn get_best_block<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(BlockHash, Option<u32>), BlockSourceRespErr>> + 'a + Send>> {
			if *self.disallowed.lock().unwrap() { unreachable!(); }
			Box::pin(async move { Ok(self.best_block.lock().unwrap().clone()) })
		}
	}

	#[tokio::test]
	async fn simple_block_connect() {
		let genesis = BlockData {
			block: bitcoin::blockdata::constants::genesis_block(bitcoin::network::constants::Network::Bitcoin),
			chainwork: Uint256::from_u64(0).unwrap(),
			height: 0,
		};

		// Build a chain based on genesis 1a, 2a, 3a, and 4a
		let block_1a = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: genesis.block.bitcoin_hash(),
					merkle_root: Default::default(), time: 0,
					bits: genesis.block.header.bits,
					nonce: 647569994,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833).unwrap(),
			height: 1
		};
		let block_1a_hash = block_1a.block.header.bitcoin_hash();
		let block_2a = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_1a.block.bitcoin_hash(),
					merkle_root: Default::default(), time: 4,
					bits: genesis.block.header.bits,
					nonce: 1185103332,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 2).unwrap(),
			height: 2
		};
		let block_2a_hash = block_2a.block.header.bitcoin_hash();
		let block_3a = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_2a.block.bitcoin_hash(),
					merkle_root: Default::default(), time: 6,
					bits: genesis.block.header.bits,
					nonce: 198739431,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 3).unwrap(),
			height: 3
		};
		let block_3a_hash = block_3a.block.header.bitcoin_hash();
		let block_4a = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_3a.block.bitcoin_hash(),
					merkle_root: Default::default(), time: 0,
					bits: genesis.block.header.bits,
					nonce: 590371681,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 4).unwrap(),
			height: 4
		};
		let block_4a_hash = block_4a.block.header.bitcoin_hash();

		// Build a second chain based on genesis 1b, 2b, and 3b
		let block_1b = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: genesis.block.bitcoin_hash(),
					merkle_root: Default::default(), time: 6,
					bits: genesis.block.header.bits,
					nonce: 1347696353,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833).unwrap(),
			height: 1
		};
		let block_1b_hash = block_1b.block.header.bitcoin_hash();
		let block_2b = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_1b.block.bitcoin_hash(),
					merkle_root: Default::default(), time: 5,
					bits: genesis.block.header.bits,
					nonce: 144775545,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 2).unwrap(),
			height: 2
		};
		let block_2b_hash = block_2b.block.header.bitcoin_hash();

		// Build a second chain based on 3a: 4c and 5c.
		let block_4c = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_3a.block.bitcoin_hash(),
					merkle_root: Default::default(), time: 17,
					bits: genesis.block.header.bits,
					nonce: 316634915,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 4).unwrap(),
			height: 4
		};
		let block_4c_hash = block_4c.block.header.bitcoin_hash();
		let block_5c = BlockData {
			block: Block {
				header: BlockHeader {
					version: 0,
					prev_blockhash: block_4c.block.bitcoin_hash(),
					merkle_root: Default::default(), time: 3,
					bits: genesis.block.header.bits,
					nonce: 218413871,
				},
				txdata: Vec::new(),
			},
			chainwork: Uint256::from_u64(4295032833 * 5).unwrap(),
			height: 5
		};
		let block_5c_hash = block_5c.block.header.bitcoin_hash();

		// Create four block sources:
		// * chain_one and chain_two are general purpose block sources which we use to test reorgs,
		// * headers_chain only provides headers,
		// * and backup_chain is a backup which should not receive any queries (ie disallowed is
		//   false) until the headers_chain gets ahead of chain_one and chain_two.
		let mut blocks_one = HashMap::new();
		blocks_one.insert(genesis.block.header.bitcoin_hash(), genesis.clone());
		blocks_one.insert(block_1a_hash, block_1a.clone());
		blocks_one.insert(block_1b_hash, block_1b);
		blocks_one.insert(block_2b_hash, block_2b);
		let chain_one = Blockchain {
			blocks: Mutex::new(blocks_one), best_block: Mutex::new((block_2b_hash, Some(2))),
			headers_only: false, disallowed: Mutex::new(false)
		};

		let mut blocks_two = HashMap::new();
		blocks_two.insert(genesis.block.header.bitcoin_hash(), genesis.clone());
		blocks_two.insert(block_1a_hash, block_1a.clone());
		let chain_two = Blockchain {
			blocks: Mutex::new(blocks_two), best_block: Mutex::new((block_1a_hash, Some(1))),
			headers_only: false, disallowed: Mutex::new(false)
		};

		let mut blocks_three = HashMap::new();
		blocks_three.insert(genesis.block.header.bitcoin_hash(), genesis.clone());
		blocks_three.insert(block_1a_hash, block_1a.clone());
		let header_chain = Blockchain {
			blocks: Mutex::new(blocks_three), best_block: Mutex::new((block_1a_hash, Some(1))),
			headers_only: true, disallowed: Mutex::new(false)
		};

		let mut blocks_four = HashMap::new();
		blocks_four.insert(genesis.block.header.bitcoin_hash(), genesis);
		blocks_four.insert(block_1a_hash, block_1a);
		blocks_four.insert(block_2a_hash, block_2a.clone());
		blocks_four.insert(block_3a_hash, block_3a.clone());
		let backup_chain = Blockchain {
			blocks: Mutex::new(blocks_four), best_block: Mutex::new((block_3a_hash, Some(3))),
			headers_only: false, disallowed: Mutex::new(true)
		};

		// Stand up a client at block_1a with all four sources:
		let chain_notifier = Arc::new(ChainListener {
			blocks_connected: Mutex::new(Vec::new()), blocks_disconnected: Mutex::new(Vec::new())
		});
		let mut source_one = &chain_one;
		let mut source_two = &chain_two;
		let mut source_three = &header_chain;
		let mut source_four = &backup_chain;
		let mut client = MicroSPVClient::init((&chain_one).get_header(&block_1a_hash, Some(1)).await.unwrap(),
			vec![&mut source_one as &mut dyn BlockSource, &mut source_two as &mut dyn BlockSource, &mut source_three as &mut dyn BlockSource],
			vec![&mut source_four as &mut dyn BlockSource],
			Arc::clone(&chain_notifier), true);

		// Test that we will reorg onto 2b because chain_one knows about 1b + 2b
		assert!(client.poll_best_tip().await);
		assert_eq!(&chain_notifier.blocks_disconnected.lock().unwrap()[..], &[(block_1a_hash, 1)][..]);
		assert_eq!(&chain_notifier.blocks_connected.lock().unwrap()[..], &[(block_1b_hash, 1), (block_2b_hash, 2)][..]);
		assert_eq!(client.blocks_past_common_tip.len(), 2);
		assert_eq!(client.blocks_past_common_tip[0].header.bitcoin_hash(), block_1b_hash);
		assert_eq!(client.blocks_past_common_tip[1].header.bitcoin_hash(), block_2b_hash);

		// Test that even if chain_one (which we just got blocks from) stops responding to block or
		// header requests we can still reorg back because we never wiped our block cache as
		// chain_two always considered the "a" chain to contain the tip. We do this by simply
		// wiping the blocks chain_one knows about:
		chain_one.blocks.lock().unwrap().clear();
		chain_notifier.blocks_connected.lock().unwrap().clear();
		chain_notifier.blocks_disconnected.lock().unwrap().clear();

		// First test that nothing happens if nothing changes:
		assert!(!client.poll_best_tip().await);
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert!(chain_notifier.blocks_connected.lock().unwrap().is_empty());

		// Now add block 2a and 3a to chain_two and test that we reorg appropriately:
		chain_two.blocks.lock().unwrap().insert(block_2a_hash, block_2a.clone());
		chain_two.blocks.lock().unwrap().insert(block_3a_hash, block_3a.clone());
		*chain_two.best_block.lock().unwrap() = (block_3a_hash, Some(3));

		assert!(client.poll_best_tip().await);
		assert_eq!(&chain_notifier.blocks_disconnected.lock().unwrap()[..], &[(block_2b_hash, 2), (block_1b_hash, 1)][..]);
		assert_eq!(&chain_notifier.blocks_connected.lock().unwrap()[..], &[(block_1a_hash, 1), (block_2a_hash, 2), (block_3a_hash, 3)][..]);

		// Note that blocks_past_common_tip is not wiped as chain_one still returns 2a as its tip
		// (though a smarter MicroSPVClient may wipe 1a and 2a from the set eventually.
		assert_eq!(client.blocks_past_common_tip.len(), 3);
		assert_eq!(client.blocks_past_common_tip[0].header.bitcoin_hash(), block_1a_hash);
		assert_eq!(client.blocks_past_common_tip[1].header.bitcoin_hash(), block_2a_hash);
		assert_eq!(client.blocks_past_common_tip[2].header.bitcoin_hash(), block_3a_hash);

		chain_notifier.blocks_connected.lock().unwrap().clear();
		chain_notifier.blocks_disconnected.lock().unwrap().clear();

		// Test that after chain_one and header_chain consider 3a as their tip that we'll wipe our
		// block header cache:
		*chain_one.best_block.lock().unwrap() = (block_3a_hash, Some(3));
		*header_chain.best_block.lock().unwrap() = (block_3a_hash, Some(3));
		assert!(!client.poll_best_tip().await);
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert!(chain_notifier.blocks_connected.lock().unwrap().is_empty());

		assert!(client.blocks_past_common_tip.is_empty());

		// Test that setting the header chain to 4a does...almost nothing (though backup_chain
		// should now be queried) since we can't get the blocks from anywhere.
		header_chain.blocks.lock().unwrap().insert(block_2a_hash, block_2a);
		header_chain.blocks.lock().unwrap().insert(block_3a_hash, block_3a);
		header_chain.blocks.lock().unwrap().insert(block_4a_hash, block_4a.clone());
		*header_chain.best_block.lock().unwrap() = (block_4a_hash, Some(4));
		*backup_chain.disallowed.lock().unwrap() = false;

		assert!(!client.poll_best_tip().await);
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert!(chain_notifier.blocks_connected.lock().unwrap().is_empty());
		assert!(client.blocks_past_common_tip.is_empty());

		// But if backup_chain *also* has 4a, we'll fetch it from there:
		backup_chain.blocks.lock().unwrap().insert(block_4a_hash, block_4a);
		*backup_chain.best_block.lock().unwrap() = (block_4a_hash, Some(4));

		assert!(client.poll_best_tip().await);
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert_eq!(&chain_notifier.blocks_connected.lock().unwrap()[..], &[(block_4a_hash, 4)][..]);
		assert_eq!(client.blocks_past_common_tip.len(), 1);
		assert_eq!(client.blocks_past_common_tip[0].header.bitcoin_hash(), block_4a_hash);

		chain_notifier.blocks_connected.lock().unwrap().clear();
		chain_notifier.blocks_disconnected.lock().unwrap().clear();

		// Note that if only headers_chain has a reorg, we'll end up in a somewhat pessimal case
		// where we will disconnect and reconnect at each poll. We should fix this at some point by
		// making sure we can at least fetch one block before we disconnect, but short of using a
		// ton more memory there isn't much we can do in the case of two disconnects. We check that
		// the disconnect happens here on a one-block-disconnected reorg, even though its
		// non-normative behavior, as a good test of failing to reorg and returning back to the
		// best chain.
		header_chain.blocks.lock().unwrap().insert(block_4c_hash, block_4c);
		header_chain.blocks.lock().unwrap().insert(block_5c_hash, block_5c);
		*header_chain.best_block.lock().unwrap() = (block_5c_hash, Some(5));
		// We'll check the backup chain last, so don't give it 4a, as otherwise we'll connect it:
		*backup_chain.best_block.lock().unwrap() = (block_3a_hash, Some(3));

		assert!(client.poll_best_tip().await);
		assert_eq!(&chain_notifier.blocks_disconnected.lock().unwrap()[..], &[(block_4a_hash, 4)][..]);
		assert!(chain_notifier.blocks_connected.lock().unwrap().is_empty());

		chain_notifier.blocks_disconnected.lock().unwrap().clear();

		// Now reset the headers chain to 4a and test that we end up back there.
		*backup_chain.best_block.lock().unwrap() = (block_4a_hash, Some(4));
		*header_chain.best_block.lock().unwrap() = (block_4a_hash, Some(4));
		assert!(client.poll_best_tip().await);
		assert!(chain_notifier.blocks_disconnected.lock().unwrap().is_empty());
		assert_eq!(&chain_notifier.blocks_connected.lock().unwrap()[..], &[(block_4a_hash, 4)][..]);
	}
}
