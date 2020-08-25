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
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::hash_types::{Txid, BlockHash};

use std::sync::{Mutex, MutexGuard, Arc};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashSet;
use std::ops::Deref;
use std::marker::PhantomData;
use std::ptr;

/// Used to give chain error details upstream
#[derive(Clone)]
pub enum ChainError {
	/// Client doesn't support UTXO lookup (but the chain hash matches our genesis block hash)
	NotSupported,
	/// Chain isn't the one watched
	NotWatched,
	/// Tx doesn't exist or is unconfirmed
	UnknownTx,
}

/// An interface to request notification of certain scripts as they appear the
/// chain.
///
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to ChainListener events, P2P events, or timer
/// events).
pub trait ChainWatchInterface: Sync + Send {
	/// Provides a txid/random-scriptPubKey-in-the-tx which much be watched for.
	fn install_watch_tx(&self, txid: &Txid, script_pub_key: &Script);

	/// Provides an outpoint which must be watched for, providing any transactions which spend the
	/// given outpoint.
	fn install_watch_outpoint(&self, outpoint: (Txid, u32), out_script: &Script);

	/// Indicates that a listener needs to see all transactions.
	fn watch_all_txn(&self);

	/// Gets the script and value in satoshis for a given unspent transaction output given a
	/// short_channel_id (aka unspent_tx_output_identier). For BTC/tBTC channels the top three
	/// bytes are the block height, the next 3 the transaction index within the block, and the
	/// final two the output within the transaction.
	fn get_chain_utxo(&self, genesis_hash: BlockHash, unspent_tx_output_identifier: u64) -> Result<(Script, u64), ChainError>;

	/// Gets the list of transaction indices within a given block that the ChainWatchInterface is
	/// watching for.
	fn filter_block(&self, block: &Block) -> Vec<usize>;

	/// Returns a usize that changes when the ChainWatchInterface's watched data is modified.
	/// Users of `filter_block` should pre-save a copy of `reentered`'s return value and use it to
	/// determine whether they need to re-filter a given block.
	fn reentered(&self) -> usize;
}

/// An interface to send a transaction to the Bitcoin network.
pub trait BroadcasterInterface: Sync + Send {
	/// Sends a transaction out to (hopefully) be mined.
	fn broadcast_transaction(&self, tx: &Transaction);
}

/// A trait indicating a desire to listen for events from the chain
pub trait ChainListener: Sync + Send {
	/// Notifies a listener that a block was connected.
	///
	/// The txn_matched array should be set to references to transactions which matched the
	/// relevant installed watch outpoints/txn, or the full set of transactions in the block.
	///
	/// Note that if txn_matched includes only matched transactions, and a new
	/// transaction/outpoint is watched during a block_connected call, the block *must* be
	/// re-scanned with the new transaction/outpoints and block_connected should be called
	/// again with the same header and (at least) the new transactions.
	///
	/// Note that if non-new transaction/outpoints are be registered during a call, a second call
	/// *must not* happen.
	///
	/// This also means those counting confirmations using block_connected callbacks should watch
	/// for duplicate headers and not count them towards confirmations!
	fn block_connected(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[usize]);
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
pub type BlockNotifierArc<C> = Arc<BlockNotifier<'static, Arc<ChainListener>, C>>;

/// BlockNotifierRef is useful when you want a BlockNotifier that points to ChainListeners
/// with nonstatic lifetimes. This is useful for when static lifetimes are not needed. Nonstatic
/// lifetimes are more efficient but less flexible, and should be used by default unless static
/// lifetimes are required, e.g. when you're using lightning-net-tokio (since tokio::spawn
/// requires parameters with static lifetimes), in which case BlockNotifierArc is a more
/// appropriate type. Defining these type aliases for common usages prevents issues such as
/// overly long function definitions.
pub type BlockNotifierRef<'a, C> = BlockNotifier<'a, &'a ChainListener, C>;

/// Utility for notifying listeners about new blocks, and handling block rescans if new watch
/// data is registered.
///
/// Rather than using a plain BlockNotifier, it is preferable to use either a BlockNotifierArc
/// or a BlockNotifierRef for conciseness. See their documentation for more details, but essentially
/// you should default to using a BlockNotifierRef, and use a BlockNotifierArc instead when you
/// require ChainListeners with static lifetimes, such as when you're using lightning-net-tokio.
pub struct BlockNotifier<'a, CL: Deref + 'a, C: Deref>
		where CL::Target: ChainListener + 'a, C::Target: ChainWatchInterface {
	listeners: Mutex<Vec<CL>>,
	chain_monitor: C,
	phantom: PhantomData<&'a ()>,
}

impl<'a, CL: Deref + 'a, C: Deref> BlockNotifier<'a, CL, C>
		where CL::Target: ChainListener + 'a, C::Target: ChainWatchInterface {
	/// Constructs a new BlockNotifier without any listeners.
	pub fn new(chain_monitor: C) -> BlockNotifier<'a, CL, C> {
		BlockNotifier {
			listeners: Mutex::new(Vec::new()),
			chain_monitor,
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
	pub fn unregister_listener(&self, listener: CL) {
		let mut vec = self.listeners.lock().unwrap();
		// item is a ref to an abstract thing that dereferences to a ChainListener,
		// so dereference it twice to get the ChainListener itself
		vec.retain(|item | !ptr::eq(&(**item), &(*listener)));
	}

	/// Notify listeners that a block was connected given a full, unfiltered block.
	///
	/// Handles re-scanning the block and calling block_connected again if listeners register new
	/// watch data during the callbacks for you (see ChainListener::block_connected for more info).
	pub fn block_connected(&self, block: &Block, height: u32) {
		let mut reentered = true;
		while reentered {
			let matched_indexes = self.chain_monitor.filter_block(block);
			let mut matched_txn = Vec::new();
			for index in matched_indexes.iter() {
				matched_txn.push(&block.txdata[*index]);
			}
			reentered = self.block_connected_checked(&block.header, height, matched_txn.as_slice(), matched_indexes.as_slice());
		}
	}

	/// Notify listeners that a block was connected, given pre-filtered list of transactions in the
	/// block which matched the filter (probably using does_match_tx).
	///
	/// Returns true if notified listeners registered additional watch data (implying that the
	/// block must be re-scanned and this function called again prior to further block_connected
	/// calls, see ChainListener::block_connected for more info).
	pub fn block_connected_checked(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[usize]) -> bool {
		let last_seen = self.chain_monitor.reentered();

		let listeners = self.listeners.lock().unwrap();
		for listener in listeners.iter() {
			listener.block_connected(header, height, txn_matched, indexes_of_txn_matched);
		}
		return last_seen != self.chain_monitor.reentered();
	}

	/// Notify listeners that a block was disconnected.
	pub fn block_disconnected(&self, header: &BlockHeader, disconnected_height: u32) {
		let listeners = self.listeners.lock().unwrap();
		for listener in listeners.iter() {
			listener.block_disconnected(&header, disconnected_height);
		}
	}
}

/// Utility to capture some common parts of ChainWatchInterface implementors.
///
/// Keeping a local copy of this in a ChainWatchInterface implementor is likely useful.
pub struct ChainWatchInterfaceUtil {
	network: Network,
	watched: Mutex<ChainWatchedUtil>,
	reentered: AtomicUsize,
}

// We only expose PartialEq in test since its somewhat unclear exactly what it should do and we're
// only comparing a subset of fields (essentially just checking that the set of things we're
// watching is the same).
#[cfg(test)]
impl PartialEq for ChainWatchInterfaceUtil {
	fn eq(&self, o: &Self) -> bool {
		self.network == o.network &&
		*self.watched.lock().unwrap() == *o.watched.lock().unwrap()
	}
}

/// Register listener
impl ChainWatchInterface for ChainWatchInterfaceUtil {
	fn install_watch_tx(&self, txid: &Txid, script_pub_key: &Script) {
		let mut watched = self.watched.lock().unwrap();
		if watched.register_tx(txid, script_pub_key) {
			self.reentered.fetch_add(1, Ordering::Relaxed);
		}
	}

	fn install_watch_outpoint(&self, outpoint: (Txid, u32), out_script: &Script) {
		let mut watched = self.watched.lock().unwrap();
		if watched.register_outpoint(outpoint, out_script) {
			self.reentered.fetch_add(1, Ordering::Relaxed);
		}
	}

	fn watch_all_txn(&self) {
		let mut watched = self.watched.lock().unwrap();
		if watched.watch_all() {
			self.reentered.fetch_add(1, Ordering::Relaxed);
		}
	}

	fn get_chain_utxo(&self, genesis_hash: BlockHash, _unspent_tx_output_identifier: u64) -> Result<(Script, u64), ChainError> {
		if genesis_hash != genesis_block(self.network).header.block_hash() {
			return Err(ChainError::NotWatched);
		}
		Err(ChainError::NotSupported)
	}

	fn filter_block(&self, block: &Block) -> Vec<usize> {
		let mut matched_index = Vec::new();
		{
			let watched = self.watched.lock().unwrap();
			for (index, transaction) in block.txdata.iter().enumerate() {
				if self.does_match_tx_unguarded(transaction, &watched) {
					matched_index.push(index);
				}
			}
		}
		matched_index
	}

	fn reentered(&self) -> usize {
		self.reentered.load(Ordering::Relaxed)
	}
}

impl ChainWatchInterfaceUtil {
	/// Creates a new ChainWatchInterfaceUtil for the given network
	pub fn new(network: Network) -> ChainWatchInterfaceUtil {
		ChainWatchInterfaceUtil {
			network,
			watched: Mutex::new(ChainWatchedUtil::new()),
			reentered: AtomicUsize::new(1),
		}
	}

	/// Checks if a given transaction matches the current filter.
	pub fn does_match_tx(&self, tx: &Transaction) -> bool {
		let watched = self.watched.lock().unwrap();
		self.does_match_tx_unguarded (tx, &watched)
	}

	fn does_match_tx_unguarded(&self, tx: &Transaction, watched: &MutexGuard<ChainWatchedUtil>) -> bool {
		watched.does_match_tx(tx)
	}
}

#[cfg(test)]
mod tests {
	use ln::functional_test_utils::{create_chanmon_cfgs, create_node_cfgs};
	use super::{BlockNotifier, ChainListener};
	use std::ptr;

	#[test]
	fn register_listener_test() {
		let chanmon_cfgs = create_chanmon_cfgs(1);
		let node_cfgs = create_node_cfgs(1, &chanmon_cfgs);
		let block_notifier = BlockNotifier::new(node_cfgs[0].chain_monitor);
		assert_eq!(block_notifier.listeners.lock().unwrap().len(), 0);
		let listener = &node_cfgs[0].chan_monitor.simple_monitor as &ChainListener;
		block_notifier.register_listener(listener);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 1);
		let item = vec.first().clone().unwrap();
		assert!(ptr::eq(&(**item), &(*listener)));
	}

	#[test]
	fn unregister_single_listener_test() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let block_notifier = BlockNotifier::new(node_cfgs[0].chain_monitor);
		let listener1 = &node_cfgs[0].chan_monitor.simple_monitor as &ChainListener;
		let listener2 = &node_cfgs[1].chan_monitor.simple_monitor as &ChainListener;
		block_notifier.register_listener(listener1);
		block_notifier.register_listener(listener2);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 2);
		drop(vec);
		block_notifier.unregister_listener(listener1);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 1);
		let item = vec.first().clone().unwrap();
		assert!(ptr::eq(&(**item), &(*listener2)));
	}

	#[test]
	fn unregister_single_listener_ref_test() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let block_notifier = BlockNotifier::new(node_cfgs[0].chain_monitor);
		block_notifier.register_listener(&node_cfgs[0].chan_monitor.simple_monitor as &ChainListener);
		block_notifier.register_listener(&node_cfgs[1].chan_monitor.simple_monitor as &ChainListener);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 2);
		drop(vec);
		block_notifier.unregister_listener(&node_cfgs[0].chan_monitor.simple_monitor);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 1);
		let item = vec.first().clone().unwrap();
		assert!(ptr::eq(&(**item), &(*&node_cfgs[1].chan_monitor.simple_monitor)));
	}

	#[test]
	fn unregister_multiple_of_the_same_listeners_test() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let block_notifier = BlockNotifier::new(node_cfgs[0].chain_monitor);
		let listener1 = &node_cfgs[0].chan_monitor.simple_monitor as &ChainListener;
		let listener2 = &node_cfgs[1].chan_monitor.simple_monitor as &ChainListener;
		block_notifier.register_listener(listener1);
		block_notifier.register_listener(listener1);
		block_notifier.register_listener(listener2);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 3);
		drop(vec);
		block_notifier.unregister_listener(listener1);
		let vec = block_notifier.listeners.lock().unwrap();
		assert_eq!(vec.len(), 1);
		let item = vec.first().clone().unwrap();
		assert!(ptr::eq(&(**item), &(*listener2)));
	}
}
