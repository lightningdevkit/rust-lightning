// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains traits for LDK to access UTXOs to check gossip data is correct.
//!
//! When lightning nodes gossip channel information, they resist DoS attacks by checking that each
//! channel matches a UTXO on-chain, requiring at least some marginal on-chain transacting in
//! order to announce a channel. This module handles that checking.

use bitcoin::{BlockHash, TxOut};
use bitcoin::hashes::hex::ToHex;

use crate::ln::chan_utils::make_funding_redeemscript_from_slices;
use crate::ln::msgs::{self, LightningError, ErrorAction};
use crate::util::ser::Writeable;

use crate::prelude::*;

use core::ops::Deref;

/// An error when accessing the chain via [`UtxoLookup`].
#[derive(Clone, Debug)]
pub enum UtxoLookupError {
	/// The requested chain is unknown.
	UnknownChain,

	/// The requested transaction doesn't exist or hasn't confirmed.
	UnknownTx,
}

/// The `UtxoLookup` trait defines behavior for accessing on-chain UTXOs.
pub trait UtxoLookup {
	/// Returns the transaction output of a funding transaction encoded by [`short_channel_id`].
	/// Returns an error if `genesis_hash` is for a different chain or if such a transaction output
	/// is unknown.
	///
	/// [`short_channel_id`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	fn get_utxo(&self, genesis_hash: &BlockHash, short_channel_id: u64) -> Result<TxOut, UtxoLookupError>;
}

pub(crate) fn check_channel_announcement<U: Deref>(
	utxo_lookup: &Option<U>, msg: &msgs::UnsignedChannelAnnouncement
) -> Result<Option<u64>, msgs::LightningError> where U::Target: UtxoLookup {
	match utxo_lookup {
		&None => {
			// Tentatively accept, potentially exposing us to DoS attacks
			Ok(None)
		},
		&Some(ref utxo_lookup) => {
			match utxo_lookup.get_utxo(&msg.chain_hash, msg.short_channel_id) {
				Ok(TxOut { value, script_pubkey }) => {
					let expected_script =
						make_funding_redeemscript_from_slices(msg.bitcoin_key_1.as_slice(), msg.bitcoin_key_2.as_slice()).to_v0_p2wsh();
					if script_pubkey != expected_script {
						return Err(LightningError{
							err: format!("Channel announcement key ({}) didn't match on-chain script ({})",
								expected_script.to_hex(), script_pubkey.to_hex()),
							action: ErrorAction::IgnoreError
						});
					}
					Ok(Some(value))
				},
				Err(UtxoLookupError::UnknownChain) => {
					Err(LightningError {
						err: format!("Channel announced on an unknown chain ({})",
							msg.chain_hash.encode().to_hex()),
						action: ErrorAction::IgnoreError
					})
				},
				Err(UtxoLookupError::UnknownTx) => {
					Err(LightningError {
						err: "Channel announced without corresponding UTXO entry".to_owned(),
						action: ErrorAction::IgnoreError
					})
				},
			}
		}
	}
}
