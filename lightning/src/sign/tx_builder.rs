//! Defines the `TxBuilder` trait, and the `SpecTxBuilder` type

use types::features::ChannelTypeFeatures;

use crate::ln::chan_utils::commit_tx_fee_sat;

pub(crate) trait TxBuilder {
	fn commit_tx_fee_sat(
		&self, feerate_per_kw: u32, nondust_htlc_count: usize, channel_type: &ChannelTypeFeatures,
	) -> u64;
}

pub(crate) struct SpecTxBuilder {}

impl TxBuilder for SpecTxBuilder {
	fn commit_tx_fee_sat(
		&self, feerate_per_kw: u32, nondust_htlc_count: usize, channel_type: &ChannelTypeFeatures,
	) -> u64 {
		commit_tx_fee_sat(feerate_per_kw, nondust_htlc_count, channel_type)
	}
}
