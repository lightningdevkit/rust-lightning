//! Defines the `TxBuilder` trait, and the `SpecTxBuilder` type
#![allow(dead_code)]

use core::cmp;
use core::ops::Deref;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::ln::chan_utils::{
	commit_tx_fee_sat, htlc_success_tx_weight, htlc_timeout_tx_weight, htlc_tx_fees_sat,
	second_stage_tx_fees_sat, ChannelTransactionParameters, CommitmentTransaction,
	HTLCOutputInCommitment,
};
use crate::ln::channel::{CommitmentStats, ANCHOR_OUTPUT_VALUE_SATOSHI};
use crate::prelude::*;
use crate::types::features::ChannelTypeFeatures;
use crate::util::logger::Logger;

pub(crate) struct HTLCAmountDirection {
	pub outbound: bool,
	pub amount_msat: u64,
}

impl HTLCAmountDirection {
	fn is_dust(
		&self, local: bool, feerate_per_kw: u32, broadcaster_dust_limit_satoshis: u64,
		channel_type: &ChannelTypeFeatures,
	) -> bool {
		let (success_tx_fee_sat, timeout_tx_fee_sat) =
			second_stage_tx_fees_sat(channel_type, feerate_per_kw);
		let htlc_tx_fee_sat =
			if self.outbound == local { timeout_tx_fee_sat } else { success_tx_fee_sat };
		self.amount_msat / 1000 < broadcaster_dust_limit_satoshis + htlc_tx_fee_sat
	}
}

pub(crate) struct NextCommitmentStats {
	pub is_outbound_from_holder: bool,
	pub inbound_htlcs_count: usize,
	pub inbound_htlcs_value_msat: u64,
	pub holder_balance_before_fee_msat: Option<u64>,
	pub counterparty_balance_before_fee_msat: Option<u64>,
	pub nondust_htlc_count: usize,
	pub commit_tx_fee_sat: u64,
	pub dust_exposure_msat: u64,
	// If the counterparty sets a feerate on the channel in excess of our dust_exposure_limiting_feerate,
	// this should be set to the dust exposure that would result from us adding an additional nondust outbound
	// htlc on the counterparty's commitment transaction.
	pub extra_nondust_htlc_on_counterparty_tx_dust_exposure_msat: Option<u64>,
}

impl NextCommitmentStats {
	pub(crate) fn get_holder_counterparty_balances_incl_fee_msat(
		&self,
	) -> (Option<u64>, Option<u64>) {
		if self.is_outbound_from_holder {
			(
				self.holder_balance_before_fee_msat.and_then(|balance_msat| {
					balance_msat.checked_sub(self.commit_tx_fee_sat * 1000)
				}),
				self.counterparty_balance_before_fee_msat,
			)
		} else {
			(
				self.holder_balance_before_fee_msat,
				self.counterparty_balance_before_fee_msat.and_then(|balance_msat| {
					balance_msat.checked_sub(self.commit_tx_fee_sat * 1000)
				}),
			)
		}
	}
}

fn excess_fees_on_counterparty_tx_dust_exposure_msat(
	next_commitment_htlcs: &[HTLCAmountDirection], dust_buffer_feerate: u32, excess_feerate: u32,
	counterparty_dust_limit_satoshis: u64, dust_htlc_exposure_msat: u64,
	channel_type: &ChannelTypeFeatures,
) -> (u64, u64) {
	let on_counterparty_tx_accepted_nondust_htlcs = next_commitment_htlcs
		.iter()
		.filter(|htlc| {
			htlc.outbound
				&& !htlc.is_dust(
					false,
					dust_buffer_feerate,
					counterparty_dust_limit_satoshis,
					channel_type,
				)
		})
		.count();
	let on_counterparty_tx_offered_nondust_htlcs = next_commitment_htlcs
		.iter()
		.filter(|htlc| {
			!htlc.outbound
				&& !htlc.is_dust(
					false,
					dust_buffer_feerate,
					counterparty_dust_limit_satoshis,
					channel_type,
				)
		})
		.count();

	let commitment_fee_sat = commit_tx_fee_sat(
		excess_feerate,
		on_counterparty_tx_accepted_nondust_htlcs + on_counterparty_tx_offered_nondust_htlcs,
		channel_type,
	);
	let second_stage_fees_sat = htlc_tx_fees_sat(
		excess_feerate,
		on_counterparty_tx_accepted_nondust_htlcs,
		on_counterparty_tx_offered_nondust_htlcs,
		channel_type,
	);
	let on_counterparty_tx_dust_exposure_msat =
		dust_htlc_exposure_msat + (commitment_fee_sat + second_stage_fees_sat) * 1000;

	let extra_htlc_commitment_fee_sat = commit_tx_fee_sat(
		excess_feerate,
		on_counterparty_tx_accepted_nondust_htlcs + 1 + on_counterparty_tx_offered_nondust_htlcs,
		channel_type,
	);
	let extra_htlc_second_stage_fees_sat = htlc_tx_fees_sat(
		excess_feerate,
		on_counterparty_tx_accepted_nondust_htlcs + 1,
		on_counterparty_tx_offered_nondust_htlcs,
		channel_type,
	);
	let extra_htlc_dust_exposure_msat = dust_htlc_exposure_msat
		+ (extra_htlc_commitment_fee_sat + extra_htlc_second_stage_fees_sat) * 1000;

	(on_counterparty_tx_dust_exposure_msat, extra_htlc_dust_exposure_msat)
}

fn subtract_addl_outputs(
	is_outbound_from_holder: bool, value_to_self_after_htlcs_msat: Option<u64>,
	value_to_remote_after_htlcs_msat: Option<u64>, channel_type: &ChannelTypeFeatures,
) -> (Option<u64>, Option<u64>) {
	let total_anchors_sat = if channel_type.supports_anchors_zero_fee_htlc_tx() {
		ANCHOR_OUTPUT_VALUE_SATOSHI * 2
	} else {
		0
	};

	// We MUST use checked subs here, as the funder's balance is not guaranteed to be greater
	// than or equal to `total_anchors_sat`.
	//
	// This is because when the remote party sends an `update_fee` message, we build the new
	// commitment transaction *before* checking whether the remote party's balance is enough to
	// cover the total anchor sum.

	if is_outbound_from_holder {
		(
			value_to_self_after_htlcs_msat
				.and_then(|balance_msat| balance_msat.checked_sub(total_anchors_sat * 1000)),
			value_to_remote_after_htlcs_msat,
		)
	} else {
		(
			value_to_self_after_htlcs_msat,
			value_to_remote_after_htlcs_msat
				.and_then(|balance_msat| balance_msat.checked_sub(total_anchors_sat * 1000)),
		)
	}
}

fn get_dust_buffer_feerate(feerate_per_kw: u32) -> u32 {
	// When calculating our exposure to dust HTLCs, we assume that the channel feerate
	// may, at any point, increase by at least 10 sat/vB (i.e 2530 sat/kWU) or 25%,
	// whichever is higher. This ensures that we aren't suddenly exposed to significantly
	// more dust balance if the feerate increases when we have several HTLCs pending
	// which are near the dust limit.
	let feerate_plus_quarter = feerate_per_kw.checked_mul(1250).map(|v| v / 1000);
	cmp::max(feerate_per_kw.saturating_add(2530), feerate_plus_quarter.unwrap_or(u32::MAX))
}

pub(crate) trait TxBuilder {
	fn get_next_commitment_stats(
		&self, local: bool, is_outbound_from_holder: bool, channel_value_satoshis: u64,
		value_to_holder_msat: u64, next_commitment_htlcs: &[HTLCAmountDirection],
		addl_nondust_htlc_count: usize, feerate_per_kw: u32,
		dust_exposure_limiting_feerate: Option<u32>, broadcaster_dust_limit_satoshis: u64,
		channel_type: &ChannelTypeFeatures,
	) -> NextCommitmentStats;
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
		broadcaster_dust_limit_satoshis: u64, logger: &L,
	) -> (CommitmentTransaction, CommitmentStats)
	where
		L::Target: Logger;
}

pub(crate) struct SpecTxBuilder {}

impl TxBuilder for SpecTxBuilder {
	fn get_next_commitment_stats(
		&self, local: bool, is_outbound_from_holder: bool, channel_value_satoshis: u64,
		value_to_holder_msat: u64, next_commitment_htlcs: &[HTLCAmountDirection],
		addl_nondust_htlc_count: usize, feerate_per_kw: u32,
		dust_exposure_limiting_feerate: Option<u32>, broadcaster_dust_limit_satoshis: u64,
		channel_type: &ChannelTypeFeatures,
	) -> NextCommitmentStats {
		let excess_feerate_opt =
			feerate_per_kw.checked_sub(dust_exposure_limiting_feerate.unwrap_or(0));
		// Dust exposure is only decoupled from feerate for zero fee commitment channels.
		let is_zero_fee_comm = channel_type.supports_anchor_zero_fee_commitments();
		debug_assert_eq!(is_zero_fee_comm, dust_exposure_limiting_feerate.is_none());
		if is_zero_fee_comm {
			debug_assert_eq!(feerate_per_kw, 0);
			debug_assert_eq!(excess_feerate_opt, Some(0));
			debug_assert_eq!(addl_nondust_htlc_count, 0);
		}

		// Calculate inbound htlc count
		let inbound_htlcs_count =
			next_commitment_htlcs.iter().filter(|htlc| !htlc.outbound).count();

		// Calculate balances after htlcs
		let value_to_counterparty_msat = (channel_value_satoshis * 1000)
			.checked_sub(value_to_holder_msat)
			.expect("value_to_holder_msat outgrew the value of the channel!");
		let outbound_htlcs_value_msat: u64 = next_commitment_htlcs
			.iter()
			.filter_map(|htlc| htlc.outbound.then_some(htlc.amount_msat))
			.sum();
		let inbound_htlcs_value_msat: u64 = next_commitment_htlcs
			.iter()
			.filter_map(|htlc| (!htlc.outbound).then_some(htlc.amount_msat))
			.sum();
		// Note there is no guarantee that the subtractions of the HTLC amounts don't
		// overflow, so we do not panic. Instead, we return `None` to signal an overflow
		// to channel, and let channel take the appropriate action.
		let value_to_holder_after_htlcs_msat =
			value_to_holder_msat.checked_sub(outbound_htlcs_value_msat);
		let value_to_counterparty_after_htlcs_msat =
			value_to_counterparty_msat.checked_sub(inbound_htlcs_value_msat);

		// Subtract the anchors from the channel funder
		let (holder_balance_before_fee_msat, counterparty_balance_before_fee_msat) =
			subtract_addl_outputs(
				is_outbound_from_holder,
				value_to_holder_after_htlcs_msat,
				value_to_counterparty_after_htlcs_msat,
				channel_type,
			);

		// Increment the feerate by a buffer to calculate dust exposure
		let dust_buffer_feerate = get_dust_buffer_feerate(feerate_per_kw);

		// Calculate fees on commitment transaction
		let nondust_htlc_count = next_commitment_htlcs
			.iter()
			.filter(|htlc| {
				!htlc.is_dust(local, feerate_per_kw, broadcaster_dust_limit_satoshis, channel_type)
			})
			.count();
		let commit_tx_fee_sat = commit_tx_fee_sat(
			feerate_per_kw,
			nondust_htlc_count + addl_nondust_htlc_count,
			channel_type,
		);

		// Calculate dust exposure on commitment transaction
		let dust_exposure_msat = next_commitment_htlcs
			.iter()
			.filter_map(|htlc| {
				htlc.is_dust(
					local,
					dust_buffer_feerate,
					broadcaster_dust_limit_satoshis,
					channel_type,
				)
				.then_some(htlc.amount_msat)
			})
			.sum();

		// Count the excess fees on the counterparty's transaction as dust
		let (dust_exposure_msat, extra_nondust_htlc_on_counterparty_tx_dust_exposure_msat) =
			if let (Some(excess_feerate), false) = (excess_feerate_opt, local) {
				let (dust_exposure_msat, extra_nondust_htlc_exposure_msat) =
					excess_fees_on_counterparty_tx_dust_exposure_msat(
						&next_commitment_htlcs,
						dust_buffer_feerate,
						excess_feerate,
						broadcaster_dust_limit_satoshis,
						dust_exposure_msat,
						channel_type,
					);
				(dust_exposure_msat, Some(extra_nondust_htlc_exposure_msat))
			} else {
				(dust_exposure_msat, None)
			};

		NextCommitmentStats {
			is_outbound_from_holder,
			inbound_htlcs_count,
			inbound_htlcs_value_msat,
			holder_balance_before_fee_msat,
			counterparty_balance_before_fee_msat,
			nondust_htlc_count: nondust_htlc_count + addl_nondust_htlc_count,
			commit_tx_fee_sat,
			dust_exposure_msat,
			extra_nondust_htlc_on_counterparty_tx_dust_exposure_msat,
		}
	}
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
	fn build_commitment_transaction<L: Deref>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_parameters: &ChannelTransactionParameters, secp_ctx: &Secp256k1<secp256k1::All>,
		value_to_self_msat: u64, mut htlcs_in_tx: Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_satoshis: u64, logger: &L,
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
			amount_msat / 1000 < broadcaster_dust_limit_satoshis + htlc_tx_fee_sat
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

		// # Panics
		//
		// The value going to each party MUST be 0 or positive, even if all HTLCs pending in the
		// commitment clear by failure.

		let commit_tx_fee_sat = self.commit_tx_fee_sat(
			feerate_per_kw,
			htlcs_in_tx.len(),
			&channel_parameters.channel_type_features,
		);
		let value_to_self_after_htlcs_msat =
			value_to_self_msat.checked_sub(local_htlc_total_msat).unwrap();
		let value_to_remote_after_htlcs_msat = (channel_parameters.channel_value_satoshis * 1000)
			.checked_sub(value_to_self_msat)
			.unwrap()
			.checked_sub(remote_htlc_total_msat)
			.unwrap();
		let (local_balance_before_fee_msat, remote_balance_before_fee_msat) = self
			.subtract_non_htlc_outputs(
				channel_parameters.is_outbound_from_holder,
				value_to_self_after_htlcs_msat,
				value_to_remote_after_htlcs_msat,
				&channel_parameters.channel_type_features,
			);

		// We MUST use saturating subs here, as the funder's balance is not guaranteed to be greater
		// than or equal to `commit_tx_fee_sat`.
		//
		// This is because when the remote party sends an `update_fee` message, we build the new
		// commitment transaction *before* checking whether the remote party's balance is enough to
		// cover the total fee.

		let (value_to_self, value_to_remote) = if channel_parameters.is_outbound_from_holder {
			(
				(local_balance_before_fee_msat / 1000).saturating_sub(commit_tx_fee_sat),
				remote_balance_before_fee_msat / 1000,
			)
		} else {
			(
				local_balance_before_fee_msat / 1000,
				(remote_balance_before_fee_msat / 1000).saturating_sub(commit_tx_fee_sat),
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
