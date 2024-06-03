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
use crate::ln::ChannelId;
use crate::ln::channel::ChannelError;
use crate::prelude::*;
use crate::util::ser::TransactionU16LenLimited;
use bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, Witness};
use core::convert::TryFrom;

/// Info about a pending splice, used in the pre-splice channel
#[derive(Clone)]
pub(crate) struct PendingSpliceInfoPre {
	/// The post splice value (current + relative)
	pub post_channel_value: u64,
	/// Reference to the post-splice channel (may be missing if channel_id is not yet known or the same)
	pub post_channel_id: Option<ChannelId>,
	pub funding_feerate_perkw: u32,
	pub locktime: u32,
	/// The funding inputs we will be contributing to the splice.
	pub our_funding_inputs: Vec<(TxIn, TransactionU16LenLimited)>,
}

/// Info about a pending splice, used in the post-splice channel
#[derive(Clone)]
pub(crate) struct PendingSpliceInfoPost {
	/// The post splice value (current + relative)
	pub post_channel_value: u64, // TODO may be removed, it's in the channel capacity
	/// The pre splice value (a bit redundant)
	pub pre_channel_value: u64,
	/// Reference to the pre-splice channel (may be missing if channel_id was the same)
	#[allow(unused)]
	pub pre_channel_id: Option<ChannelId>,

	/// Save here the previous funding transaction
	pub pre_funding_transaction: Option<Transaction>,
	/// Save here the previous funding TXO
	pub pre_funding_txo: Option<OutPoint>,
}

impl PendingSpliceInfoPre {
	pub(crate) fn new(relative_satoshis: i64, pre_channel_value: u64,
		post_channel_id: Option<ChannelId>, funding_feerate_perkw: u32, locktime: u32,
		our_funding_inputs: Vec<(TxIn, TransactionU16LenLimited)>,
	) -> Self {
		let post_channel_value = Self::add_checked(pre_channel_value, relative_satoshis);
		Self {
			post_channel_value,
			post_channel_id,
			funding_feerate_perkw,
			locktime,
			our_funding_inputs,
		}
	}

	/// Add a u64 and an i64, handling i64 overflow cases (doing without cast to i64)
	pub(crate) fn add_checked(pre_channel_value: u64, relative_satoshis: i64) -> u64 {
		if relative_satoshis >= 0 {
			pre_channel_value.saturating_add(relative_satoshis as u64)
		} else {
			pre_channel_value.saturating_sub((-relative_satoshis) as u64)
		}
	}

	/// The relative splice value (change in capacity value relative to current value)
	pub(crate) fn relative_satoshis(&self, pre_channel_value: u64) -> i64 {
		if self.post_channel_value > pre_channel_value {
			i64::try_from(self.post_channel_value.saturating_sub(pre_channel_value)).unwrap_or_default()
		} else {
			-i64::try_from(pre_channel_value.saturating_sub(self.post_channel_value)).unwrap_or_default()
		}
	}
}

impl PendingSpliceInfoPost {
	pub(crate) fn new(relative_satoshis: i64, pre_channel_value: u64, pre_channel_id: Option<ChannelId>,
		pre_funding_transaction: Option<Transaction>, pre_funding_txo: Option<OutPoint>
	) -> Self {
		let post_channel_value = PendingSpliceInfoPre::add_checked(pre_channel_value, relative_satoshis);
		Self {
			post_channel_value,
			pre_channel_value,
			pre_channel_id,
			pre_funding_transaction,
			pre_funding_txo,
		}
	}

	/// The relative splice value (change in capacity value relative to current value)
	pub(crate) fn relative_satoshis(&self) -> i64 {
		if self.post_channel_value > self.pre_channel_value {
			i64::try_from(self.post_channel_value.saturating_sub(self.pre_channel_value)).unwrap_or_default()
		} else {
			-i64::try_from(self.pre_channel_value.saturating_sub(self.post_channel_value)).unwrap_or_default()
		}
	}

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

	fn create_pending_splice_info(pre_channel_value: u64, post_channel_value: u64) -> PendingSpliceInfoPost {
		PendingSpliceInfoPost {
			post_channel_value,
			pre_channel_value,
			pre_channel_id: None,
			pre_funding_transaction: None,
			pre_funding_txo: None,
		}
	}

	#[test]
	fn test_pending_splice_info_new() {
		{
			// increase, small amounts
			let ps = create_pending_splice_info(9_000, 15_000);
			assert_eq!(ps.pre_channel_value, 9_000);
			assert_eq!(ps.post_channel_value, 15_000);
			assert_eq!(ps.relative_satoshis(), 6_000);
		}
		{
			// decrease, small amounts
			let ps = create_pending_splice_info(15_000, 9_000);
			assert_eq!(ps.pre_channel_value, 15_000);
			assert_eq!(ps.post_channel_value, 9_000);
			assert_eq!(ps.relative_satoshis(), -6_000);
		}
		let base2: u64 = 2;
		let huge63 = base2.pow(63);
		assert_eq!(huge63, 9223372036854775808);
		{
			// increase, one huge amount
			let ps = create_pending_splice_info(9_000, huge63 + 9_000 - 1);
			assert_eq!(ps.pre_channel_value, 9_000);
			assert_eq!(ps.post_channel_value, 9223372036854784807); // 2^63 + 9000 - 1
			assert_eq!(ps.relative_satoshis(), 9223372036854775807); // 2^63 - 1
		}
		{
			// decrease, one huge amount
			let ps = create_pending_splice_info(huge63 + 9_000 - 1, 9_000);
			assert_eq!(ps.pre_channel_value, 9223372036854784807); // 2^63 + 9000 - 1
			assert_eq!(ps.post_channel_value, 9_000);
			assert_eq!(ps.relative_satoshis(), -9223372036854775807); // 2^63 - 1
		}
		{
			// increase, two huge amounts
			let ps = create_pending_splice_info(huge63 + 9_000, huge63 + 15_000);
			assert_eq!(ps.pre_channel_value, 9223372036854784808); // 2^63 + 9000
			assert_eq!(ps.post_channel_value, 9223372036854790808); // 2^63 + 15000
			assert_eq!(ps.relative_satoshis(), 6_000);
		}
		{
			// decrease, two huge amounts
			let ps = create_pending_splice_info(huge63 + 15_000, huge63 + 9_000);
			assert_eq!(ps.pre_channel_value, 9223372036854790808); // 2^63 + 15000
			assert_eq!(ps.post_channel_value, 9223372036854784808); // 2^63 + 9000
			assert_eq!(ps.relative_satoshis(), -6_000);
		}
		{
			// underflow
			let ps = create_pending_splice_info(9_000, huge63 + 9_000 + 20);
			assert_eq!(ps.pre_channel_value, 9_000);
			assert_eq!(ps.post_channel_value, 9223372036854784828); // 2^63 + 9000 + 20
			assert_eq!(ps.relative_satoshis(), -0);
		}
		{
			// underflow
			let ps = create_pending_splice_info(huge63 + 9_000 + 20, 9_000);
			assert_eq!(ps.pre_channel_value, 9223372036854784828); // 2^63 + 9000 + 20
			assert_eq!(ps.post_channel_value, 9_000);
			assert_eq!(ps.relative_satoshis(), -0);
		}
	}
}
