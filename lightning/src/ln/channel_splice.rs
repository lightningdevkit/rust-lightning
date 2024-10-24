// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

// Splicing related utilities

use crate::chain::transaction::OutPoint;
use crate::ln::channel::ChannelError;
use crate::prelude::*;
use crate::util::ser::TransactionU16LenLimited;
use bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, Witness};


/// Info about a pending splice, used in the pre-splice channel
#[derive(Clone)]
pub(crate) struct PendingSpliceInfoPre {
	our_funding_contribution: i64,
	pub funding_feerate_perkw: u32,
	pub locktime: u32,
	/// The funding inputs we will be contributing to the splice.
	pub our_funding_inputs: Vec<(TxIn, TransactionU16LenLimited)>,
}

impl PendingSpliceInfoPre {
	pub(crate) fn new(
		our_funding_contribution: i64, funding_feerate_perkw: u32, locktime: u32,
		our_funding_inputs: Vec<(TxIn, TransactionU16LenLimited)>,
	) -> Self {
		Self {
			our_funding_contribution, funding_feerate_perkw, locktime, our_funding_inputs,
		}
	}

	/// Accessor
	pub(crate) fn our_funding_contribution(&self) -> i64 { self.our_funding_contribution }
}

/// Info about a pending splice, used in the post-splice channel
#[derive(Clone)]
pub(crate) struct PendingSpliceInfoPost {
	pre_channel_value: u64,
	post_channel_value: u64,

	/// Save here the previous funding transaction
	pre_funding_transaction: Option<Transaction>,
	/// Save here the previous funding TXO
	pre_funding_txo: Option<OutPoint>,
}

impl PendingSpliceInfoPost {
	pub(crate) fn new(
		pre_channel_value: u64, our_funding_contribution: i64, their_funding_contribution: i64,
		pre_funding_transaction: Option<Transaction>, pre_funding_txo: Option<OutPoint>,
	) -> Self {
		let post_channel_value = Self::compute_post_value(pre_channel_value, our_funding_contribution, their_funding_contribution);
		Self {
			pre_channel_value, post_channel_value,
			pre_funding_transaction, pre_funding_txo,
		}
	}

	fn add_checked(base: u64, delta: i64) -> u64 {
		if delta >= 0 {
			base.saturating_add(delta as u64)
		} else {
			base.saturating_sub(delta.abs() as u64)
		}
	}

	/// Compute the post-splice channel value from the pre-splice values and the peer contributions
	pub fn compute_post_value(pre_channel_value: u64, our_funding_contribution: i64, their_funding_contribution: i64) -> u64 {
		Self::add_checked(pre_channel_value, our_funding_contribution.saturating_add(their_funding_contribution))
	}

	/// Accessor
	pub(crate) fn pre_channel_value(&self) -> u64 { self.pre_channel_value }

	pub(crate) fn post_channel_value(&self) -> u64 { self.post_channel_value }

	/// Get a transaction input that is the previous funding transaction
	pub(super) fn get_input_of_previous_funding(&self) -> Result<(TxIn, TransactionU16LenLimited), ChannelError> {
		if let Some(pre_funding_transaction) = &self.pre_funding_transaction {
			if let Some(pre_funding_txo) = &self.pre_funding_txo {
				Ok((
					TxIn {
						previous_output: pre_funding_txo.into_bitcoin_outpoint(),
						script_sig: ScriptBuf::new(),
						sequence: Sequence::ZERO,
						witness: Witness::new(),
					},
					TransactionU16LenLimited(pre_funding_transaction.clone()),
				))
			} else {
				Err(ChannelError::Warn("Internal error: Missing previous funding transaction outpoint".to_string()))
			}
		} else {
			Err(ChannelError::Warn("Internal error: Missing previous funding transaction".to_string()))
		}
	}

	/// Within the given transaction, find the input that corresponds to the previous funding transaction
	pub(super) fn find_input_of_previous_funding(&self, tx: &Transaction) -> Result<u16, ChannelError> {
		if let Some(pre_funding_txo) = &self.pre_funding_txo {
			for idx in 0..tx.input.len() {
				if tx.input[idx].previous_output == pre_funding_txo.into_bitcoin_outpoint() {
					return Ok(idx as u16);
				}
			}
			// Not found
			Err(ChannelError::Warn("Internal error: Previous funding transaction not found in the inputs of the new funding transaction".to_string()))
		} else {
			Err(ChannelError::Warn("Internal error: Missing previous funding transaction outpoint".to_string()))
		}
	}
}


#[cfg(test)]
mod tests {
	use crate::ln::channel_splice::PendingSpliceInfoPost;

	fn get_pre_and_post(pre_channel_value: u64, our_funding_contribution: i64, their_funding_contribution: i64) -> (u64, u64) {
		let post_channel_value = PendingSpliceInfoPost::compute_post_value(pre_channel_value, our_funding_contribution, their_funding_contribution);
		(pre_channel_value, post_channel_value)
	}

	#[test]
	fn test_pending_splice_info_new() {
		{
			// increase, small amounts
			let (pre_channel_value, post_channel_value) = get_pre_and_post(9_000, 6_000, 0);
			assert_eq!(pre_channel_value, 9_000);
			assert_eq!(post_channel_value, 15_000);
		}
		{
			// increase, small amounts
			let (pre_channel_value, post_channel_value) = get_pre_and_post(9_000, 4_000, 2_000);
			assert_eq!(pre_channel_value, 9_000);
			assert_eq!(post_channel_value, 15_000);
		}
		{
			// increase, small amounts
			let (pre_channel_value, post_channel_value) = get_pre_and_post(9_000, 0, 6_000);
			assert_eq!(pre_channel_value, 9_000);
			assert_eq!(post_channel_value, 15_000);
		}
		{
			// decrease, small amounts
			let (pre_channel_value, post_channel_value) = get_pre_and_post(15_000, -6_000, 0);
			assert_eq!(pre_channel_value, 15_000);
			assert_eq!(post_channel_value, 9_000);
		}
		{
			// decrease, small amounts
			let (pre_channel_value, post_channel_value) = get_pre_and_post(15_000, -4_000, -2_000);
			assert_eq!(pre_channel_value, 15_000);
			assert_eq!(post_channel_value, 9_000);
		}
		{
			// increase and decrease
			let (pre_channel_value, post_channel_value) = get_pre_and_post(15_000, 4_000, -2_000);
			assert_eq!(pre_channel_value, 15_000);
			assert_eq!(post_channel_value, 17_000);
		}
		let base2: u64 = 2;
		let huge63i3 = (base2.pow(63) - 3) as i64;
		assert_eq!(huge63i3, 9223372036854775805);
		assert_eq!(-huge63i3, -9223372036854775805);
		{
			// increase, large amount
			let (pre_channel_value, post_channel_value) = get_pre_and_post(9_000, huge63i3, 3);
			assert_eq!(pre_channel_value, 9_000);
			assert_eq!(post_channel_value, 9223372036854784807);
		}
		{
			// increase, large amounts
			let (pre_channel_value, post_channel_value) = get_pre_and_post(9_000, huge63i3, huge63i3);
			assert_eq!(pre_channel_value, 9_000);
			assert_eq!(post_channel_value, 9223372036854784807);
		}
	}
}
