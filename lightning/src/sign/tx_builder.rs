//! Defines the `TxBuilder` trait, and the `SpecTxBuilder` type

use core::ops::Deref;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::ln::chan_utils::{
	self, ChannelTransactionParameters, CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{self, CommitmentStats};
use crate::prelude::*;
use crate::util::logger::Logger;

pub(crate) trait TxBuilder {
	fn build_commitment_stats(
		&self, local: bool, channel_parameters: &ChannelTransactionParameters,
		value_to_self_msat: u64, htlcs_in_tx: &Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_sat: u64,
	) -> CommitmentStats;

	fn build_commitment_transaction<L: Deref>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_parameters: &ChannelTransactionParameters, secp_ctx: &Secp256k1<secp256k1::All>,
		value_to_self_msat: u64, htlcs_in_tx: Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_satoshis: u64, logger: &L,
	) -> (CommitmentTransaction, CommitmentStats)
	where
		L::Target: Logger;
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SpecTxBuilder {}

impl TxBuilder for SpecTxBuilder {
	fn build_commitment_stats(
		&self, local: bool, channel_parameters: &ChannelTransactionParameters,
		value_to_self_msat: u64, htlcs_in_tx: &Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_sat: u64,
	) -> CommitmentStats {
		let channel_type = &channel_parameters.channel_type_features;
		let mut local_htlc_total_msat = 0;
		let mut remote_htlc_total_msat = 0;
		let mut nondust_htlc_count = 0;

		for htlc in htlcs_in_tx {
			if htlc.offered == local {
				local_htlc_total_msat += htlc.amount_msat;
			} else {
				remote_htlc_total_msat += htlc.amount_msat;
			}
			if !htlc.is_dust(feerate_per_kw, broadcaster_dust_limit_sat, channel_type) {
				nondust_htlc_count += 1;
			}
		}

		// # Panics
		//
		// The value going to each party MUST be 0 or positive, even if all HTLCs pending in the
		// commitment clear by failure.

		let mut value_to_remote_msat =
			channel_parameters.channel_value_satoshis * 1000 - value_to_self_msat;
		let value_to_self_msat = value_to_self_msat.checked_sub(local_htlc_total_msat).unwrap();
		value_to_remote_msat = value_to_remote_msat.checked_sub(remote_htlc_total_msat).unwrap();

		let total_fee_sat =
			chan_utils::commit_tx_fee_sat(feerate_per_kw, nondust_htlc_count, channel_type);
		let total_anchors_sat = if channel_type.supports_anchors_zero_fee_htlc_tx() {
			channel::ANCHOR_OUTPUT_VALUE_SATOSHI * 2
		} else {
			0
		};

		CommitmentStats {
			total_fee_sat,
			total_anchors_sat,
			nondust_htlc_count,
			local_balance_before_fee_anchors_msat: value_to_self_msat,
			remote_balance_before_fee_anchors_msat: value_to_remote_msat,
		}
	}

	fn build_commitment_transaction<L: Deref>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_parameters: &ChannelTransactionParameters, secp_ctx: &Secp256k1<secp256k1::All>,
		value_to_self_msat: u64, mut htlcs_in_tx: Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_satoshis: u64, logger: &L,
	) -> (CommitmentTransaction, CommitmentStats)
	where
		L::Target: Logger,
	{
		let stats = self.build_commitment_stats(
			local,
			&channel_parameters,
			value_to_self_msat,
			&htlcs_in_tx,
			feerate_per_kw,
			broadcaster_dust_limit_satoshis,
		);
		let CommitmentStats {
			total_fee_sat,
			total_anchors_sat,
			nondust_htlc_count,
			local_balance_before_fee_anchors_msat,
			remote_balance_before_fee_anchors_msat,
		} = stats;

		// Trim dust htlcs
		htlcs_in_tx.retain(|htlc| {
			if htlc.is_dust(
				feerate_per_kw,
				broadcaster_dust_limit_satoshis,
				&channel_parameters.channel_type_features,
			) {
				log_trace!(
					logger,
					"   ...trimming {} HTLC with value {}sat, hash {}, due to dust limit {}",
					if htlc.offered == local { "outbound" } else { "inbound" },
					htlc.amount_msat / 1000,
					htlc.payment_hash,
					broadcaster_dust_limit_satoshis
				);
				false
			} else {
				true
			}
		});
		debug_assert_eq!(htlcs_in_tx.len(), nondust_htlc_count);

		// We MUST use saturating subs here, as the funder's balance is not guaranteed to be greater
		// than or equal to the sum of `total_fee_sat` and `total_anchors_sat`.
		//
		// This is because when the remote party sends an `update_fee` message, we build the new
		// commitment transaction *before* checking whether the remote party's balance is enough to
		// cover the total fee and the anchors.

		let (value_to_self, value_to_remote) = if channel_parameters.is_outbound_from_holder {
			(
				(local_balance_before_fee_anchors_msat / 1000)
					.saturating_sub(total_anchors_sat)
					.saturating_sub(total_fee_sat),
				remote_balance_before_fee_anchors_msat / 1000,
			)
		} else {
			(
				local_balance_before_fee_anchors_msat / 1000,
				(remote_balance_before_fee_anchors_msat / 1000)
					.saturating_sub(total_anchors_sat)
					.saturating_sub(total_fee_sat),
			)
		};

		let mut to_broadcaster_value_sat = if local { value_to_self } else { value_to_remote };
		let mut to_countersignatory_value_sat = if local { value_to_remote } else { value_to_self };

		if to_broadcaster_value_sat >= broadcaster_dust_limit_satoshis {
			log_trace!(
				logger,
				"   ...including {} output with value {}",
				if local { "to_local" } else { "to_remote" },
				to_broadcaster_value_sat
			);
		} else {
			to_broadcaster_value_sat = 0;
		}

		if to_countersignatory_value_sat >= broadcaster_dust_limit_satoshis {
			log_trace!(
				logger,
				"   ...including {} output with value {}",
				if local { "to_remote" } else { "to_local" },
				to_countersignatory_value_sat
			);
		} else {
			to_countersignatory_value_sat = 0;
		}

		let directed_parameters = if local {
			channel_parameters.as_holder_broadcastable()
		} else {
			channel_parameters.as_counterparty_broadcastable()
		};

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

		(tx, stats)
	}
}
