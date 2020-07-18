// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Traits and utility impls which allow other parts of rust-lightning to interact with the
//! blockchain.
//!
//! Includes traits for monitoring and receiving notifications of new blocks and block
//! disconnections, transaction broadcasting, and feerate information requests.

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::Txid;

use std::sync::{Mutex, Arc};
use std::collections::HashSet;
use std::ops::Deref;
use std::marker::PhantomData;
use std::ptr;

/// An interface to send a transaction to the Bitcoin network.
pub trait BroadcasterInterface: Sync + Send {
	/// Sends a transaction out to (hopefully) be mined.
	fn broadcast_transaction(&self, tx: &Transaction);
}

/// A trait indicating a desire to listen for events from the chain
pub trait ChainListener: Sync + Send {
	/// Notifies a listener that a block was connected. Transactions may be filtered and are given
	/// paired with their position within the block.
	fn block_connected(&self, header: &BlockHeader, txdata: &[(usize, &Transaction)], height: u32);

	/// Notifies a listener that a block was disconnected.
	/// Unlike block_connected, this *must* never be called twice for the same disconnect event.
	/// Height must be the one of the block which was disconnected (not new height of the best chain)
	fn block_disconnected(&self, header: &BlockHeader, disconnected_height: u32);
}

/// An enum that represents the speed at which we want a transaction to confirm used for feerate
/// estimation.
pub enum ConfirmationTarget {
	/// We are happy with this transaction confirming slowly when feerate drops some.
	Background,
	/// We'd like this transaction to confirm without major delay, but 12-18 blocks is fine.
	Normal,
	/// We'd like this transaction to confirm in the next few blocks.
	HighPriority,
}

/// A trait which should be implemented to provide feerate information on a number of time
/// horizons.
///
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to ChainListener events, P2P events, or timer
/// events).
pub trait FeeEstimator: Sync + Send {
	/// Gets estimated satoshis of fee required per 1000 Weight-Units.
	///
	/// Must be no smaller than 253 (ie 1 satoshi-per-byte rounded up to ensure later round-downs
	/// don't put us below 1 satoshi-per-byte).
	///
	/// This translates to:
	///  * satoshis-per-byte * 250
	///  * ceil(satoshis-per-kbyte / 4)
	fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32;
}

/// Minimum relay fee as required by bitcoin network mempool policy.
pub const MIN_RELAY_FEE_SAT_PER_1000_WEIGHT: u64 = 4000;

/// Utility for tracking registered txn/outpoints and checking for matches
#[cfg_attr(test, derive(PartialEq))]
pub struct ChainWatchedUtil {
	watch_all: bool,

	// We are more conservative in matching during testing to ensure everything matches *exactly*,
	// even though during normal runtime we take more optimized match approaches...
	#[cfg(test)]
	watched_txn: HashSet<(Txid, Script)>,
	#[cfg(not(test))]
	watched_txn: HashSet<Script>,

	watched_outpoints: HashSet<(Txid, u32)>,
}

impl ChainWatchedUtil {
	/// Constructs an empty (watches nothing) ChainWatchedUtil
	pub fn new() -> Self {
		Self {
			watch_all: false,
			watched_txn: HashSet::new(),
			watched_outpoints: HashSet::new(),
		}
	}

	/// Registers a tx for monitoring, returning true if it was a new tx and false if we'd already
	/// been watching for it.
	pub fn register_tx(&mut self, txid: &Txid, script_pub_key: &Script) -> bool {
		if self.watch_all { return false; }
		#[cfg(test)]
		{
			self.watched_txn.insert((txid.clone(), script_pub_key.clone()))
		}
		#[cfg(not(test))]
		{
			let _tx_unused = txid; // It's used in cfg(test), though
			self.watched_txn.insert(script_pub_key.clone())
		}
	}

	/// Registers an outpoint for monitoring, returning true if it was a new outpoint and false if
	/// we'd already been watching for it
	pub fn register_outpoint(&mut self, outpoint: (Txid, u32), _script_pub_key: &Script) -> bool {
		if self.watch_all { return false; }
		self.watched_outpoints.insert(outpoint)
	}

	/// Sets us to match all transactions, returning true if this is a new setting and false if
	/// we'd already been set to match everything.
	pub fn watch_all(&mut self) -> bool {
		if self.watch_all { return false; }
		self.watch_all = true;
		true
	}

	/// Checks if a given transaction matches the current filter.
	pub fn does_match_tx(&self, tx: &Transaction) -> bool {
		if self.watch_all {
			return true;
		}
		for out in tx.output.iter() {
			#[cfg(test)]
			for &(ref txid, ref script) in self.watched_txn.iter() {
				if *script == out.script_pubkey {
					if tx.txid() == *txid {
						return true;
					}
				}
			}
			#[cfg(not(test))]
			for script in self.watched_txn.iter() {
				if *script == out.script_pubkey {
					return true;
				}
			}
		}
		for input in tx.input.iter() {
			for outpoint in self.watched_outpoints.iter() {
				let &(outpoint_hash, outpoint_index) = outpoint;
				if outpoint_hash == input.previous_output.txid && outpoint_index == input.previous_output.vout {
					return true;
				}
			}
		}
		false
	}
}

/// BlockNotifierArc is useful when you need a BlockNotifier that points to ChainListeners with
/// static lifetimes, e.g. when you're using lightning-net-tokio (since tokio::spawn requires
/// parameters with static lifetimes). Other times you can afford a reference, which is more
/// efficient, in which case BlockNotifierRef is a more appropriate type. Defining these type
/// aliases prevents issues such as overly long function definitions.
///
/// (C-not exported) as we let clients handle any reference counting they need to do
pub type BlockNotifierArc = Arc<BlockNotifier<'static, Arc<ChainListener>>>;

/// BlockNotifierRef is useful when you want a BlockNotifier that points to ChainListeners
/// with nonstatic lifetimes. This is useful for when static lifetimes are not needed. Nonstatic
/// lifetimes are more efficient but less flexible, and should be used by default unless static
/// lifetimes are required, e.g. when you're using lightning-net-tokio (since tokio::spawn
/// requires parameters with static lifetimes), in which case BlockNotifierArc is a more
/// appropriate type. Defining these type aliases for common usages prevents issues such as
/// overly long function definitions.
pub type BlockNotifierRef<'a> = BlockNotifier<'a, &'a ChainListener>;

/// Utility for notifying listeners when blocks are connected or disconnected.
///
/// Rather than using a plain BlockNotifier, it is preferable to use either a BlockNotifierArc
/// or a BlockNotifierRef for conciseness. See their documentation for more details, but essentially
/// you should default to using a BlockNotifierRef, and use a BlockNotifierArc instead when you
/// require ChainListeners with static lifetimes, such as when you're using lightning-net-tokio.
pub struct BlockNotifier<'a, CL: Deref + 'a>
		where CL::Target: ChainListener + 'a {
	listeners: Mutex<Vec<CL>>,
	phantom: PhantomData<&'a ()>,
}

impl<'a, CL: Deref + 'a> BlockNotifier<'a, CL>
		where CL::Target: ChainListener + 'a {
	/// Constructs a new BlockNotifier without any listeners.
	pub fn new() -> BlockNotifier<'a, CL> {
		BlockNotifier {
			listeners: Mutex::new(Vec::new()),
			phantom: PhantomData,
		}
	}

	/// Register the given listener to receive events.
	pub fn register_listener(&self, listener: CL) {
		let mut vec = self.listeners.lock().unwrap();
		vec.push(listener);
	}
	/// Unregister the given listener to no longer
	/// receive events.
	///
	/// If the same listener is registered multiple times, unregistering
	/// will remove ALL occurrences of that listener. Comparison is done using
	/// the pointer returned by the Deref trait implementation.
	///
	/// (C-not exported) because the equality check would always fail
	pub fn unregister_listener(&self, listener: CL) {
		let mut vec = self.listeners.lock().unwrap();
		// item is a ref to an abstract thing that dereferences to a ChainListener,
		// so dereference it twice to get the ChainListener itself
		vec.retain(|item | !ptr::eq(&(**item), &(*listener)));
	}

	/// Notify listeners that a block was connected.
	pub fn block_connected(&self, block: &Block, height: u32) {
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		let listeners = self.listeners.lock().unwrap();
		for listener in listeners.iter() {
			listener.block_connected(&block.header, &txdata, height);
		}
	}

	/// Notify listeners that a block was disconnected.
	pub fn block_disconnected(&self, header: &BlockHeader, disconnected_height: u32) {
		let listeners = self.listeners.lock().unwrap();
		for listener in listeners.iter() {
			listener.block_disconnected(&header, disconnected_height);
		}
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::blockdata::block::BlockHeader;
	use bitcoin::blockdata::transaction::Transaction;
	use super::{BlockNotifier, ChainListener};
	use std::ptr;

	struct TestChainListener(u8);

	impl ChainListener for TestChainListener {
		fn block_connected(&self, _header: &BlockHeader, _txdata: &[(usize, &Transaction)], _height: u32) {}
		fn block_disconnected(&self, _header: &BlockHeader, _disconnected_height: u32) {}
	}

	#[test]
	fn register_listener_test() {
		let block_notifier = BlockNotifier::new();
		assert_eq!(block_notifier.listeners.lock().unwrap().len(), 0);
		let listener = &TestChainListener(0);
		block_notifier.register_listener(listener as &ChainListener);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 1);
		let item = vec.first().unwrap();
		assert!(ptr::eq(&(**item), listener));
	}

	#[test]
	fn unregister_single_listener_test() {
		let block_notifier = BlockNotifier::new();
		let listener1 = &TestChainListener(1);
		let listener2 = &TestChainListener(2);
		block_notifier.register_listener(listener1 as &ChainListener);
		block_notifier.register_listener(listener2 as &ChainListener);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 2);
		drop(vec);
		block_notifier.unregister_listener(listener1);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 1);
		let item = vec.first().unwrap();
		assert!(ptr::eq(&(**item), listener2));
	}

	#[test]
	fn unregister_multiple_of_the_same_listeners_test() {
		let block_notifier = BlockNotifier::new();
		let listener1 = &TestChainListener(1);
		let listener2 = &TestChainListener(2);
		block_notifier.register_listener(listener1 as &ChainListener);
		block_notifier.register_listener(listener1 as &ChainListener);
		block_notifier.register_listener(listener2 as &ChainListener);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 3);
		drop(vec);
		block_notifier.unregister_listener(listener1);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 1);
		let item = vec.first().unwrap();
		assert!(ptr::eq(&(**item), listener2));
	}
}
