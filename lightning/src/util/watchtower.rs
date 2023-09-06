// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module contains a simple utility object [`JusticeTxTracker`] that can be used to track
//! the state required to build and sign a justice transaction claiming a
//! to-broadcaster output if a counterparty broadcasts a revoked commitment transaction.
//! This is intended to be used in an implementation of the [`Persist`] trait (see for
//! more info).
//!
//! [`Persist`]: crate::chain::chainmonitor::Persist

use crate::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use crate::chain::transaction::OutPoint;
use crate::ln::chan_utils::CommitmentTransaction;
use crate::sign;
use crate::prelude::*;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;

pub(crate) struct UnsignedJusticeData {
	justice_tx: Transaction,
	value: u64,
	commitment_number: u64,
}

impl_writeable_tlv_based!(UnsignedJusticeData, {
	(0, justice_tx, required),
	(2, value, required),
	(4, commitment_number, required),
});

impl UnsignedJusticeData {
	/// Returns `None` if the justice transaction cannot be built with the given feerate,
	/// or the commitment transaction lacks a to-broadcaster output.
	fn new_from_commitment_tx(
		counterparty_commitment_tx: &CommitmentTransaction, destination_script: Script,
		feerate_per_kw: u32
	) -> Option<Self> {
		let commitment_number = counterparty_commitment_tx.commitment_number();
		let trusted_tx = counterparty_commitment_tx.trust();
		let value = trusted_tx.to_broadcaster_value_sat();
		let justice_tx = trusted_tx.build_to_local_justice_tx(
			feerate_per_kw as u64, destination_script).ok()?;
		Some(Self { justice_tx, value, commitment_number })
	}
}

/// A simple utility object that can be used to track the state required to build and sign a
/// justice transaction claiming a to-broadcaster output if a counterparty broadcasts a revoked
/// commitment transaction.
/// This is intended to be used in an implementation of the [`Persist`] trait (see for
/// more info).
///
/// Note: this should be persisted and read on startup, otherwise you may end up missing justice
/// transactions for certain commitments.
///
/// [`Persist`]: crate::chain::chainmonitor::Persist
pub struct JusticeTxTracker {
	unsigned_justice_data: HashMap<OutPoint, VecDeque<UnsignedJusticeData>>,
	/// Sorted in ascending order.
	feerates_per_kw: Vec<u32>,
	destination_script: Script,
}

impl_writeable_tlv_based!(JusticeTxTracker, {
	(0, unsigned_justice_data, required),
	(2, feerates_per_kw, required),
	(4, destination_script, required),
});

impl JusticeTxTracker {
	/// Creates a new tracker that will build justice transactions for each provided feerate
	/// claiming outputs to the given destination script.
	pub fn new(mut feerates_per_kw: Vec<u32>, destination_script: Script) -> Self {
		feerates_per_kw.sort_unstable();
		Self {
			unsigned_justice_data: HashMap::new(),
			feerates_per_kw,
			destination_script,
		}
	}

	/// Processes the commitment transaction and stores the justice data, returning whether the
	/// commitment transaction had a to-broadcaster output.
	fn process_commitment_transaction(
		&mut self, funding_txo: OutPoint, commitment_tx: &CommitmentTransaction,
	) -> bool {
		for feerate_per_kw in self.feerates_per_kw.iter() {
			let justice_data = match UnsignedJusticeData::new_from_commitment_tx(
				commitment_tx, self.destination_script.clone(), *feerate_per_kw
			) {
				Some(justice_data) => justice_data,
				None => return false,
			};
			self.unsigned_justice_data
				.entry(funding_txo).or_insert(VecDeque::new())
				.push_back(justice_data);
		}
		true
	}

	/// Processes the initial commitment transaction for when the channel monitor is first
	/// persisted, expected to be used upon [`Persist::persist_new_channel`].
	///
	/// Returns `None` if the monitor doesn't track the initial commitment tx, otherwise returns
	/// `Some`, with a boolean representing whether the commitment tx had a to-broadcaster output.
	///
	/// [`Persist::persist_new_channel`]: crate::chain::chainmonitor::Persist::persist_new_channel
	pub fn add_new_channel<Signer: sign::WriteableEcdsaChannelSigner>(
		&mut self, funding_txo: OutPoint, monitor: &ChannelMonitor<Signer>
	) -> Option<bool> {
		self.unsigned_justice_data.insert(funding_txo, VecDeque::new());
		let initial_counterparty_commitment_tx = monitor.initial_counterparty_commitment_tx()?;
		Some(self.process_commitment_transaction(funding_txo, &initial_counterparty_commitment_tx))
	}

	/// Processes any new counterparty commitment transactions present in the provided `update`,
	/// and returns a list of newly signed justice transactions ready to be broadcast.
	///
	/// This is expected to be used within and implementation of
	/// [`Persist::update_persisted_channel`].
	///
	/// [`Persist::update_persisted_channel`]: crate::chain::chainmonitor::Persist::update_persisted_channel
	pub fn process_update<Signer: sign::WriteableEcdsaChannelSigner>(
		&mut self, funding_txo: OutPoint, monitor: &ChannelMonitor<Signer>,
		update: &ChannelMonitorUpdate
	) -> Vec<Transaction> {
		let commitment_txs = monitor.counterparty_commitment_txs_from_update(update);
		for commitment_tx in commitment_txs {
			self.process_commitment_transaction(funding_txo, &commitment_tx);
		}

		let mut signed_justice_txs = Vec::new();
		let channel_queue = self.unsigned_justice_data
			.entry(funding_txo).or_insert(VecDeque::new());

		while let Some(UnsignedJusticeData {
			justice_tx, value, commitment_number
		}) = channel_queue.front() {
			match monitor.sign_to_local_justice_tx(
				justice_tx.clone(), 0, *value, *commitment_number
			) {
				Ok(signed_justice_tx) => {
					signed_justice_txs.push(signed_justice_tx);
					channel_queue.pop_front();
				},
				Err(_) => break,
			}
		}
		signed_justice_txs
	}
}
