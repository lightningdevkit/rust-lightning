use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::util::hash::Sha256dHash;

use std::sync::{Weak,Mutex};

/// An interface to request notification of certain scripts as they appear the
/// chain.
pub trait ChainWatchInterface: Sync + Send {
	/// Provides a scriptPubKey which much be watched for.
	fn install_watch_script(&self, script_pub_key: Script);

	/// Provides an outpoint which must be watched for, providing any transactions which spend the
	/// given outpoint.
	fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32));

	/// Indicates that a listener needs to see all transactions.
	fn watch_all_txn(&self);

	/// Sends a transaction out to (hopefully) be mined
	fn broadcast_transaction(&self, tx: &Transaction);

	fn register_listener(&self, listener: Weak<ChainListener>);
	//TODO: unregister
}

/// A trait indicating a desire to listen for events from the chain
pub trait ChainListener: Sync + Send {
	/// Notifies a listener that a block was connected.
	/// Note that if a new script/transaction is watched during a block_connected call, the block
	/// *must* be re-scanned with the new script/transaction and block_connected should be called
	/// again with the same header and (at least) the new transactions.
	/// This also means those counting confirmations using block_connected callbacks should watch
	/// for duplicate headers and not count them towards confirmations!
	fn block_connected(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]);
	/// Notifies a listener that a block was disconnected.
	/// Unlike block_connected, this *must* never be called twice for the same disconnect event.
	fn block_disconnected(&self, header: &BlockHeader);
}

pub enum ConfirmationTarget {
	Background,
	Normal,
	HighPriority,
}

pub trait FeeEstimator: Sync + Send {
	fn get_est_sat_per_vbyte(&self, ConfirmationTarget) -> u64;
}

/// Utility to capture some common parts of ChainWatchInterface implementors.
/// Keeping a local copy of this in a ChainWatchInterface implementor is likely useful.
pub struct ChainWatchInterfaceUtil {
	watched: Mutex<(Vec<Script>, Vec<(Sha256dHash, u32)>, bool)>, //TODO: Something clever to optimize this
	listeners: Mutex<Vec<Weak<ChainListener>>>,
}

impl ChainWatchInterfaceUtil {
	pub fn new() -> ChainWatchInterfaceUtil {
		ChainWatchInterfaceUtil {
			watched: Mutex::new((Vec::new(), Vec::new(), false)),
			listeners: Mutex::new(Vec::new()),
		}
	}

	pub fn install_watch_script(&self, spk: Script) {
		let mut watched = self.watched.lock().unwrap();
		watched.0.push(Script::from(spk));
	}

	pub fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32)) {
		let mut watched = self.watched.lock().unwrap();
		watched.1.push(outpoint);
	}

	pub fn watch_all_txn(&self) { //TODO: refcnt this?
		let mut watched = self.watched.lock().unwrap();
		watched.2 = true;
	}

	pub fn register_listener(&self, listener: Weak<ChainListener>) {
		let mut vec = self.listeners.lock().unwrap();
		vec.push(listener);
	}

	pub fn do_call_block_connected(&self, header: &BlockHeader, height: u32, txn_matched: &[&Transaction], indexes_of_txn_matched: &[u32]) {
		let listeners = self.listeners.lock().unwrap().clone();
		for listener in listeners.iter() {
			match listener.upgrade() {
				Some(arc) => arc.block_connected(header, height, txn_matched, indexes_of_txn_matched),
				None => ()
			}
		}
	}

	pub fn do_call_block_disconnected(&self, header: &BlockHeader) {
		let listeners = self.listeners.lock().unwrap().clone();
		for listener in listeners.iter() {
			match listener.upgrade() {
				Some(arc) => arc.block_disconnected(header),
				None => ()
			}
		}
	}

	/// Checks if a given transaction matches the current filter
	pub fn does_match_tx(&self, tx: &Transaction) -> bool {
		let watched = self.watched.lock().unwrap();
		if watched.2 {
			return true;
		}
		for out in tx.output.iter() {
			for script in watched.0.iter() {
				if script[..] == out.script_pubkey[..] {
					return true;
				}
			}
		}
		for input in tx.input.iter() {
			for outpoint in watched.1.iter() {
				let &(outpoint_hash, outpoint_index) = outpoint;
				if outpoint_hash == input.prev_hash && outpoint_index == input.prev_index {
					return true;
				}
			}
		}
		false
	}
}
