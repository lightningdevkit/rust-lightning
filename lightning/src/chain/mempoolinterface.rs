// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Traits and utility impls which allow other parts of rust-lightning to
//! interact with the mempool.
//!
//! Includes traits for monitoring and receiving notification for in-mempool
//! descendants of a channel output.

use crate::chain::transaction::OutPoint;

use bitcoin::blockdata::transaction::Transaction;

pub enum MempoolWatchStatus {
	/// The in-mempool descendant of the watched outpoint.
	DescendantTx(Transaction)
	/// The watch outpoint has been reorged out of the chain.
	Reorg,
}

/// An interface to monitor a local cacche of Bitcoin transacations waiting
/// confirmations.
pub trait MempoolInterface {
	fn watch_outpoint(&self, funding_txo: OutPoint) -> MempoolWatchStatus;
}
