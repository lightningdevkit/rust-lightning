use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::util::hash::Sha256dHash;

use chain::chaininterface::{ChainWatchInterface,ChainWatchInterfaceUtil,ChainListener};

use std::sync::Weak;

pub struct BitcoinCoreRPCClientChain {
	util: ChainWatchInterfaceUtil
}

impl ChainWatchInterface for BitcoinCoreRPCClientChain {
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

impl BitcoinCoreRPCClientChain {
	pub fn new() -> BitcoinCoreRPCClientChain {
		BitcoinCoreRPCClientChain {
			util: ChainWatchInterfaceUtil::new(),
		}
	}
}
