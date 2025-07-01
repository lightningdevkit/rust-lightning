//! Defines the `TxBuilder` trait, and the `SpecTxBuilder` type

use core::ops::Deref;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::ln::chan_utils::{
	commit_tx_fee_sat, htlc_success_tx_weight, htlc_timeout_tx_weight,
	ChannelTransactionParameters, CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{CommitmentStats, ANCHOR_OUTPUT_VALUE_SATOSHI};
use crate::prelude::*;
use crate::types::features::ChannelTypeFeatures;
use crate::util::logger::Logger;

pub(crate) trait TxBuilder {
	fn commit_tx_fee_sat(
		&self, feerate_per_kw: u32, nondust_htlc_count: usize, channel_type: &ChannelTypeFeatures,
	) -> u64;
	fn subtract_non_htlc_outputs(
		&self, is_outbound_from_holder: bool, value_to_self_after_htlcs: u64,
		value_to_remote_after_htlcs: u64, channel_type: &ChannelTypeFeatures,
	) -> (u64, u64);
	fn build_commitment_transaction<L: Deref>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_parameters: &ChannelTransactionParameters, secp_ctx: &Secp256k1<secp256k1::All>,
		value_to_self_msat: u64, htlcs_in_tx: Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_sat: u64, logger: &L,
	) -> (CommitmentTransaction, CommitmentStats)
	where
		L::Target: Logger;
}

pub(crate) struct SpecTxBuilder {}

impl TxBuilder for SpecTxBuilder {
	fn commit_tx_fee_sat(
		&self, feerate_per_kw: u32, nondust_htlc_count: usize, channel_type: &ChannelTypeFeatures,
	) -> u64 {
		commit_tx_fee_sat(feerate_per_kw, nondust_htlc_count, channel_type)
	}
	fn subtract_non_htlc_outputs(
		&self, is_outbound_from_holder: bool, value_to_self_after_htlcs: u64,
		value_to_remote_after_htlcs: u64, channel_type: &ChannelTypeFeatures,
	) -> (u64, u64) {
		let total_anchors_sat = if channel_type.supports_anchors_zero_fee_htlc_tx() {
			ANCHOR_OUTPUT_VALUE_SATOSHI * 2
		} else {
			0
		};

		let mut local_balance_before_fee_msat = value_to_self_after_htlcs;
		let mut remote_balance_before_fee_msat = value_to_remote_after_htlcs;

		// We MUST use saturating subs here, as the funder's balance is not guaranteed to be greater
		// than or equal to `total_anchors_sat`.
		//
		// This is because when the remote party sends an `update_fee` message, we build the new
		// commitment transaction *before* checking whether the remote party's balance is enough to
		// cover the total anchor sum.

		if is_outbound_from_holder {
			local_balance_before_fee_msat =
				local_balance_before_fee_msat.saturating_sub(total_anchors_sat * 1000);
		} else {
			remote_balance_before_fee_msat =
				remote_balance_before_fee_msat.saturating_sub(total_anchors_sat * 1000);
		}

		(local_balance_before_fee_msat, remote_balance_before_fee_msat)
	}
	#[rustfmt::skip]
	fn build_commitment_transaction<L: Deref>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_parameters: &ChannelTransactionParameters, secp_ctx: &Secp256k1<secp256k1::All>,
		value_to_self_msat: u64, mut htlcs_in_tx: Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_sat: u64, logger: &L,
	) -> (CommitmentTransaction, CommitmentStats)
	where
		L::Target: Logger,
	{
		let mut local_htlc_total_msat = 0;
		let mut remote_htlc_total_msat = 0;
		let channel_type = &channel_parameters.channel_type_features;

		let is_dust = |offered: bool, amount_msat: u64| -> bool {
			let htlc_tx_fee_sat = if channel_type.supports_anchors_zero_fee_htlc_tx() {
				0
			} else {
				let htlc_tx_weight = if offered {
					htlc_timeout_tx_weight(channel_type)
				} else {
					htlc_success_tx_weight(channel_type)
				};
				// As required by the spec, round down
				feerate_per_kw as u64 * htlc_tx_weight / 1000
			};
			amount_msat / 1000 < broadcaster_dust_limit_sat + htlc_tx_fee_sat
		};

		// Trim dust htlcs
		htlcs_in_tx.retain(|htlc| {
			if htlc.offered == local {
				// This is an outbound htlc
				local_htlc_total_msat += htlc.amount_msat;
			} else {
				remote_htlc_total_msat += htlc.amount_msat;
			}
			if is_dust(htlc.offered, htlc.amount_msat) {
				log_trace!(logger, "   ...trimming {} HTLC with value {}sat, hash {}, due to dust limit {}", if htlc.offered == local { "outbound" } else { "inbound" }, htlc.amount_msat / 1000, htlc.payment_hash, broadcaster_dust_limit_sat);
				false
			} else {
				true
			}
		});

		// # Panics
		//
		// The value going to each party MUST be 0 or positive, even if all HTLCs pending in the
		// commitment clear by failure.

		let commit_tx_fee_sat = self.commit_tx_fee_sat(feerate_per_kw, htlcs_in_tx.len(), &channel_parameters.channel_type_features);
		let value_to_self_after_htlcs_msat = value_to_self_msat.checked_sub(local_htlc_total_msat).unwrap();
		let value_to_remote_after_htlcs_msat =
			(channel_parameters.channel_value_satoshis * 1000).checked_sub(value_to_self_msat).unwrap().checked_sub(remote_htlc_total_msat).unwrap();
		let (local_balance_before_fee_msat, remote_balance_before_fee_msat) =
			self.subtract_non_htlc_outputs(channel_parameters.is_outbound_from_holder, value_to_self_after_htlcs_msat, value_to_remote_after_htlcs_msat, &channel_parameters.channel_type_features);

		// We MUST use saturating subs here, as the funder's balance is not guaranteed to be greater
		// than or equal to `commit_tx_fee_sat`.
		//
		// This is because when the remote party sends an `update_fee` message, we build the new
		// commitment transaction *before* checking whether the remote party's balance is enough to
		// cover the total fee.

		let (value_to_self, value_to_remote) = if channel_parameters.is_outbound_from_holder {
			((local_balance_before_fee_msat / 1000).saturating_sub(commit_tx_fee_sat), remote_balance_before_fee_msat / 1000)
		} else {
			(local_balance_before_fee_msat / 1000, (remote_balance_before_fee_msat / 1000).saturating_sub(commit_tx_fee_sat))
		};

		let mut to_broadcaster_value_sat = if local { value_to_self } else { value_to_remote };
		let mut to_countersignatory_value_sat = if local { value_to_remote } else { value_to_self };

		if to_broadcaster_value_sat >= broadcaster_dust_limit_sat {
			log_trace!(logger, "   ...including {} output with value {}", if local { "to_local" } else { "to_remote" }, to_broadcaster_value_sat);
		} else {
			to_broadcaster_value_sat = 0;
		}

		if to_countersignatory_value_sat >= broadcaster_dust_limit_sat {
			log_trace!(logger, "   ...including {} output with value {}", if local { "to_remote" } else { "to_local" }, to_countersignatory_value_sat);
		} else {
			to_countersignatory_value_sat = 0;
		}

		let directed_parameters =
			if local { channel_parameters.as_holder_broadcastable() }
			else { channel_parameters.as_counterparty_broadcastable() };
		let tx = CommitmentTransaction::new(
			commitment_number,
			per_commitment_point,
			to_broadcaster_value_sat,
			to_countersignatory_value_sat,
			feerate_per_kw,
			htlcs_in_tx,
			&directed_parameters,
			secp_ctx,
		);

		(
			tx,
			CommitmentStats {
				commit_tx_fee_sat,
				local_balance_before_fee_msat,
				remote_balance_before_fee_msat,
			},
		)
	}
}
