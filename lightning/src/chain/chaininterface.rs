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

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::Txid;

use std::collections::HashSet;

/// An interface to send a transaction to the Bitcoin network.
pub trait BroadcasterInterface: Sync + Send {
	/// Sends a transaction out to (hopefully) be mined.
	fn broadcast_transaction(&self, tx: &Transaction);
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
/// called from inside the library in response to chain events, P2P events, or timer events).
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
