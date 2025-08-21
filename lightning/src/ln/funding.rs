// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Types pertaining to funding channels.

use bitcoin::{Script, Sequence, Transaction, Weight};

use crate::events::bump_transaction::{Utxo, EMPTY_SCRIPT_SIG_WEIGHT};
use crate::sign::{P2TR_KEY_PATH_WITNESS_WEIGHT, P2WPKH_WITNESS_WEIGHT};

/// An input to contribute to a channel's funding transaction either when using the v2 channel
/// establishment protocol or when splicing.
#[derive(Clone)]
pub struct FundingTxInput {
	/// The unspent [`TxOut`] that the input spends.
	///
	/// [`TxOut`]: bitcoin::TxOut
	pub(super) utxo: Utxo,

	/// The sequence number to use in the [`TxIn`].
	///
	/// [`TxIn`]: bitcoin::TxIn
	pub(super) sequence: Sequence,

	/// The transaction containing the unspent [`TxOut`] referenced by [`utxo`].
	///
	/// [`TxOut`]: bitcoin::TxOut
	/// [`utxo`]: Self::utxo
	pub(super) prevtx: Transaction,
}

impl FundingTxInput {
	fn new<F: FnOnce(&bitcoin::Script) -> bool>(
		prevtx: Transaction, vout: u32, witness_weight: Weight, script_filter: F,
	) -> Result<Self, ()> {
		Ok(FundingTxInput {
			utxo: Utxo {
				outpoint: bitcoin::OutPoint { txid: prevtx.compute_txid(), vout },
				output: prevtx
					.output
					.get(vout as usize)
					.filter(|output| script_filter(&output.script_pubkey))
					.ok_or(())?
					.clone(),
				satisfaction_weight: EMPTY_SCRIPT_SIG_WEIGHT + witness_weight.to_wu(),
			},
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			prevtx,
		})
	}

	/// Creates an input spending a P2WPKH output from the given `prevtx` at index `vout`.
	///
	/// Uses [`Sequence::ENABLE_RBF_NO_LOCKTIME`] as the [`TxIn::sequence`], which can be overridden
	/// by [`set_sequence`].
	///
	/// Returns `Err` if no such output exists in `prevtx` at index `vout`.
	///
	/// [`TxIn::sequence`]: bitcoin::TxIn::sequence
	/// [`set_sequence`]: Self::set_sequence
	pub fn new_p2wpkh(prevtx: Transaction, vout: u32) -> Result<Self, ()> {
		let witness_weight = Weight::from_wu(P2WPKH_WITNESS_WEIGHT);
		FundingTxInput::new(prevtx, vout, witness_weight, Script::is_p2wpkh)
	}

	/// Creates an input spending a P2WSH output from the given `prevtx` at index `vout`.
	///
	/// Requires passing the weight of witness needed to satisfy the output's script.
	///
	/// Uses [`Sequence::ENABLE_RBF_NO_LOCKTIME`] as the [`TxIn::sequence`], which can be overridden
	/// by [`set_sequence`].
	///
	/// Returns `Err` if no such output exists in `prevtx` at index `vout`.
	///
	/// [`TxIn::sequence`]: bitcoin::TxIn::sequence
	/// [`set_sequence`]: Self::set_sequence
	pub fn new_p2wsh(prevtx: Transaction, vout: u32, witness_weight: Weight) -> Result<Self, ()> {
		FundingTxInput::new(prevtx, vout, witness_weight, Script::is_p2wsh)
	}

	/// Creates an input spending a P2TR output from the given `prevtx` at index `vout`.
	///
	/// This is meant for inputs spending a taproot output using the key path. See
	/// [`new_p2tr_script_spend`] for when spending using a script path.
	///
	/// Uses [`Sequence::ENABLE_RBF_NO_LOCKTIME`] as the [`TxIn::sequence`], which can be overridden
	/// by [`set_sequence`].
	///
	/// Returns `Err` if no such output exists in `prevtx` at index `vout`.
	///
	/// [`new_p2tr_script_spend`]: Self::new_p2tr_script_spend
	///
	/// [`TxIn::sequence`]: bitcoin::TxIn::sequence
	/// [`set_sequence`]: Self::set_sequence
	pub fn new_p2tr_key_spend(prevtx: Transaction, vout: u32) -> Result<Self, ()> {
		let witness_weight = Weight::from_wu(P2TR_KEY_PATH_WITNESS_WEIGHT);
		FundingTxInput::new(prevtx, vout, witness_weight, Script::is_p2tr)
	}

	/// Creates an input spending a P2TR output from the given `prevtx` at index `vout`.
	///
	/// Requires passing the weight of witness needed to satisfy a script path of the taproot
	/// output. See [`new_p2tr_key_spend`] for when spending using the key path.
	///
	/// Uses [`Sequence::ENABLE_RBF_NO_LOCKTIME`] as the [`TxIn::sequence`], which can be overridden
	/// by [`set_sequence`].
	///
	/// Returns `Err` if no such output exists in `prevtx` at index `vout`.
	///
	/// [`new_p2tr_key_spend`]: Self::new_p2tr_key_spend
	///
	/// [`TxIn::sequence`]: bitcoin::TxIn::sequence
	/// [`set_sequence`]: Self::set_sequence
	pub fn new_p2tr_script_spend(
		prevtx: Transaction, vout: u32, witness_weight: Weight,
	) -> Result<Self, ()> {
		FundingTxInput::new(prevtx, vout, witness_weight, Script::is_p2tr)
	}

	/// The sequence number to use in the [`TxIn`].
	///
	/// [`TxIn`]: bitcoin::TxIn
	pub fn sequence(&self) -> Sequence {
		self.sequence
	}

	/// Sets the sequence number to use in the [`TxIn`].
	///
	/// [`TxIn`]: bitcoin::TxIn
	pub fn set_sequence(&mut self, sequence: Sequence) {
		self.sequence = sequence;
	}
}
