//! Defines the `TxBuilder` trait, and the `SpecTxBuilder` type

use crate::ln::chan_utils::commit_tx_fee_sat;
use crate::ln::channel::ANCHOR_OUTPUT_VALUE_SATOSHI;
use crate::prelude::*;
use crate::types::features::ChannelTypeFeatures;

pub(crate) trait TxBuilder {
	fn commit_tx_fee_sat(
		&self, feerate_per_kw: u32, nondust_htlc_count: usize, channel_type: &ChannelTypeFeatures,
	) -> u64;
	fn balances_excluding_tx_fee(
		&self, is_outbound_from_holder: bool, channel_type: &ChannelTypeFeatures,
		value_to_self_after_htlcs: u64, value_to_remote_after_htlcs: u64,
	) -> (u64, u64);
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SpecTxBuilder {}

impl TxBuilder for SpecTxBuilder {
	fn commit_tx_fee_sat(
		&self, feerate_per_kw: u32, nondust_htlc_count: usize, channel_type: &ChannelTypeFeatures,
	) -> u64 {
		commit_tx_fee_sat(feerate_per_kw, nondust_htlc_count, channel_type)
	}
	fn balances_excluding_tx_fee(
		&self, is_outbound_from_holder: bool, channel_type: &ChannelTypeFeatures,
		value_to_self_after_htlcs: u64, value_to_remote_after_htlcs: u64,
	) -> (u64, u64) {
		let total_anchors_sat = if channel_type.supports_anchors_zero_fee_htlc_tx() {
			ANCHOR_OUTPUT_VALUE_SATOSHI * 2
		} else {
			0
		};

		let mut local_balance_before_fee_msat = value_to_self_after_htlcs;
		let mut remote_balance_before_fee_msat = value_to_remote_after_htlcs;

		if is_outbound_from_holder {
			local_balance_before_fee_msat =
				local_balance_before_fee_msat.saturating_sub(total_anchors_sat * 1000);
		} else {
			remote_balance_before_fee_msat =
				remote_balance_before_fee_msat.saturating_sub(total_anchors_sat * 1000);
		}

		(local_balance_before_fee_msat, remote_balance_before_fee_msat)
	}
}
