// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Structs and traits which allow other parts of rust-lightning to interact with the blockchain.

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::TxOut;
use bitcoin::hash_types::{BlockHash, Txid};

use chain::transaction::OutPoint;

pub mod chaininterface;
pub mod transaction;
pub mod keysinterface;

/// The `Access` trait defines behavior for accessing chain data and state, such as blocks and
/// UTXOs.
pub trait Access: Send + Sync {
	/// Returns the transaction output of a funding transaction encoded by [`short_channel_id`].
	/// Returns an error if `genesis_hash` is for a different chain or if such a transaction output
	/// is unknown.
	///
	/// [`short_channel_id`]: https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	fn get_utxo(&self, genesis_hash: &BlockHash, short_channel_id: u64) -> Result<TxOut, AccessError>;
}

/// An error when accessing the chain via [`Access`].
///
/// [`Access`]: trait.Access.html
#[derive(Clone)]
pub enum AccessError {
	/// The requested chain is unknown.
	UnknownChain,

	/// The requested transaction doesn't exist or hasn't confirmed.
	UnknownTx,
}

/// An interface for providing [`WatchEvent`]s.
///
/// [`WatchEvent`]: enum.WatchEvent.html
pub trait WatchEventProvider {
	/// Releases events produced since the last call. Subsequent calls must only return new events.
	fn release_pending_watch_events(&self) -> Vec<WatchEvent>;
}

/// An event indicating on-chain activity to watch for pertaining to a channel.
pub enum WatchEvent {
	/// Watch for a transaction with `txid` and having an output with `script_pubkey` as a spending
	/// condition.
	WatchTransaction {
		/// Identifier of the transaction.
		txid: Txid,

		/// Spending condition for an output of the transaction.
		script_pubkey: Script,
	},
	/// Watch for spends of a transaction output identified by `outpoint` having `script_pubkey` as
	/// the spending condition.
	WatchOutput {
		/// Identifier for the output.
		outpoint: OutPoint,

		/// Spending condition for the output.
		script_pubkey: Script,
	}
}
