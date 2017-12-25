use bitcoin::blockdata::blockchain::Blockchain;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::script::Script;
use bitcoin::network::constants::Network;
use bitcoin::util::hash::Sha256dHash;

use chain::chaininterface::{ChainWatchInterface,ChainWatchInterfaceUtil,ChainListener};

use std::sync::{Mutex,Weak};

/// Implements a ChainWatchInterface using rust-bitcoin's Blockchain class
pub struct ChainWatchImpl {
	chain: Mutex<Blockchain>,
	util: ChainWatchInterfaceUtil
}

unsafe impl Send for ChainWatchImpl {} //TODO: GAH WTF
unsafe impl Sync for ChainWatchImpl {} //TODO: GAH WTF

impl ChainWatchInterface for ChainWatchImpl {
	fn install_watch_script(&self, spk: Script) {
		self.util.install_watch_script(spk)
	}

	fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32)) {
		self.util.install_watch_outpoint(outpoint)
	}

	fn watch_all_txn(&self) {
		self.util.watch_all_txn()
	}

	fn broadcast_transaction(&self, _tx: &Transaction) {
		unimplemented!()
	}

	fn register_listener(&self, listener: Weak<ChainListener>) {
		self.util.register_listener(listener)
	}
}

impl ChainWatchImpl {
	pub fn new(network: Network) -> ChainWatchImpl {
		ChainWatchImpl {
			chain: Mutex::new(Blockchain::new(network)),
			util: ChainWatchInterfaceUtil::new(),
		}
	}

	pub fn add_block(&mut self, block: Block) {
		{
			let mut txn_matched: Vec<&Transaction> = Vec::new();
			let mut indexes_of_txn_matched = Vec::new();
			for (idx, tx) in block.txdata.iter().enumerate() {
				if self.util.does_match_tx(&tx) {
					txn_matched.push(tx);
					indexes_of_txn_matched.push(idx as u32);
				}
			}
			//TODO: Height
			self.util.do_call_block_connected(&block.header, 0, &txn_matched[..], &indexes_of_txn_matched[..]);
		}
		self.chain.lock().unwrap().add_block(block);
	}
}
