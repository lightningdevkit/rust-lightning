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
	pub holder_balance_before_fee_msat: u64,
	pub counterparty_balance_before_fee_msat: u64,
	pub nondust_htlc_count: usize,
	pub commit_tx_fee_sat: u64,
	pub dust_exposure_msat: u64,
	pub extra_accepted_htlc_dust_exposure_msat: u64,
}

impl NextCommitmentStats {
	pub(crate) fn get_holder_counterparty_balances_incl_fee_msat(&self) -> Result<(u64, u64), ()> {
		if self.is_outbound_from_holder {
			Ok((
				self.holder_balance_before_fee_msat
					.checked_sub(self.commit_tx_fee_sat * 1000)
					.ok_or(())?,
				self.counterparty_balance_before_fee_msat,
			))
		} else {
			Ok((
				self.holder_balance_before_fee_msat,
				self.counterparty_balance_before_fee_msat
					.checked_sub(self.commit_tx_fee_sat * 1000)
					.ok_or(())?,
			))
		}
	}
}

fn commit_plus_htlc_tx_fees_msat(
	local: bool, next_commitment_htlcs: &[HTLCAmountDirection], dust_buffer_feerate: u32,
	feerate: u32, broadcaster_dust_limit_satoshis: u64, channel_type: &ChannelTypeFeatures,
) -> (u64, u64) {
	let accepted_nondust_htlcs = next_commitment_htlcs
		.iter()
		.filter(|htlc| {
			htlc.outbound != local
				&& !htlc.is_dust(
					local,
					dust_buffer_feerate,
					broadcaster_dust_limit_satoshis,
					channel_type,
				)
		})
		.count();
	let offered_nondust_htlcs = next_commitment_htlcs
		.iter()
		.filter(|htlc| {
			htlc.outbound == local
				&& !htlc.is_dust(
					local,
					dust_buffer_feerate,
					broadcaster_dust_limit_satoshis,
					channel_type,
				)
		})
		.count();

	let commitment_fee_sat =
		commit_tx_fee_sat(feerate, accepted_nondust_htlcs + offered_nondust_htlcs, channel_type);
	let second_stage_fees_sat =
		htlc_tx_fees_sat(feerate, accepted_nondust_htlcs, offered_nondust_htlcs, channel_type);
	let total_fees_msat = (commitment_fee_sat + second_stage_fees_sat) * 1000;

	let extra_accepted_htlc_commitment_fee_sat = commit_tx_fee_sat(
		feerate,
		accepted_nondust_htlcs + 1 + offered_nondust_htlcs,
		channel_type,
	);
	let extra_accepted_htlc_second_stage_fees_sat =
		htlc_tx_fees_sat(feerate, accepted_nondust_htlcs + 1, offered_nondust_htlcs, channel_type);
	let extra_accepted_htlc_total_fees_msat =
		(extra_accepted_htlc_commitment_fee_sat + extra_accepted_htlc_second_stage_fees_sat) * 1000;

	(total_fees_msat, extra_accepted_htlc_total_fees_msat)
}

fn subtract_addl_outputs(
	is_outbound_from_holder: bool, value_to_self_after_htlcs_msat: u64,
	value_to_remote_after_htlcs_msat: u64, channel_type: &ChannelTypeFeatures,
) -> Result<(u64, u64), ()> {
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
		Ok((
			value_to_self_after_htlcs_msat.checked_sub(total_anchors_sat * 1000).ok_or(())?,
			value_to_remote_after_htlcs_msat,
		))
	} else {
		Ok((
			value_to_self_after_htlcs_msat,
			value_to_remote_after_htlcs_msat.checked_sub(total_anchors_sat * 1000).ok_or(())?,
		))
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

pub(crate) struct ChannelConstraints {
	pub dust_limit_satoshis: u64,
	pub channel_reserve_satoshis: u64,
	pub htlc_minimum_msat: u64,
	pub max_htlc_value_in_flight_msat: u64,
	pub max_accepted_htlcs: u64,
}

pub(crate) trait TxBuilder {
	fn get_available_balances(
		&self, is_outbound_from_holder: bool, channel_value_satoshis: u64,
		value_to_holder_msat: u64, pending_htlcs: &[HTLCAmountDirection], feerate_per_kw: u32,
		dust_exposure_limiting_feerate: Option<u32>, max_dust_htlc_exposure_msat: u64,
		holder_channel_constraints: ChannelConstraints,
		counterparty_channel_constraints: ChannelConstraints, channel_type: &ChannelTypeFeatures,
	) -> crate::ln::channel::AvailableBalances;
	fn get_next_commitment_stats(
		&self, local: bool, is_outbound_from_holder: bool, channel_value_satoshis: u64,
		value_to_holder_msat: u64, next_commitment_htlcs: &[HTLCAmountDirection],
		addl_nondust_htlc_count: usize, feerate_per_kw: u32,
		dust_exposure_limiting_feerate: Option<u32>, broadcaster_dust_limit_satoshis: u64,
		channel_type: &ChannelTypeFeatures,
	) -> Result<NextCommitmentStats, ()>;
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
	fn get_available_balances(
		&self, is_outbound_from_holder: bool, channel_value_satoshis: u64,
		value_to_holder_msat: u64, pending_htlcs: &[HTLCAmountDirection], feerate_per_kw: u32,
		dust_exposure_limiting_feerate: Option<u32>, max_dust_htlc_exposure_msat: u64,
		holder_channel_constraints: ChannelConstraints,
		counterparty_channel_constraints: ChannelConstraints, channel_type: &ChannelTypeFeatures,
	) -> crate::ln::channel::AvailableBalances {
		let fee_spike_buffer_htlc =
			if channel_type.supports_anchor_zero_fee_commitments() { 0 } else { 1 };

		let local_stats_max_fee = SpecTxBuilder {}
			.get_next_commitment_stats(
				true,
				is_outbound_from_holder,
				channel_value_satoshis,
				value_to_holder_msat,
				pending_htlcs,
				fee_spike_buffer_htlc + 1,
				feerate_per_kw,
				dust_exposure_limiting_feerate,
				holder_channel_constraints.dust_limit_satoshis,
				channel_type,
			)
			// TODO: should `get_available_balances` be fallible ?
			.unwrap();
		let local_stats_min_fee = SpecTxBuilder {}
			.get_next_commitment_stats(
				true,
				is_outbound_from_holder,
				channel_value_satoshis,
				value_to_holder_msat,
				pending_htlcs,
				fee_spike_buffer_htlc,
				feerate_per_kw,
				dust_exposure_limiting_feerate,
				holder_channel_constraints.dust_limit_satoshis,
				channel_type,
			)
			.unwrap();
		let remote_stats = SpecTxBuilder {}
			.get_next_commitment_stats(
				false,
				is_outbound_from_holder,
				channel_value_satoshis,
				value_to_holder_msat,
				pending_htlcs,
				1,
				feerate_per_kw,
				dust_exposure_limiting_feerate,
				counterparty_channel_constraints.dust_limit_satoshis,
				channel_type,
			)
			.unwrap();

		let outbound_capacity_msat = local_stats_max_fee
			.holder_balance_before_fee_msat
			.saturating_sub(holder_channel_constraints.channel_reserve_satoshis * 1000);

		let mut available_capacity_msat = outbound_capacity_msat;
		let (real_htlc_success_tx_fee_sat, real_htlc_timeout_tx_fee_sat) =
			second_stage_tx_fees_sat(channel_type, feerate_per_kw);

		if is_outbound_from_holder {
			// We should mind channel commit tx fee when computing how much of the available capacity
			// can be used in the next htlc. Mirrors the logic in send_htlc.
			//
			// The fee depends on whether the amount we will be sending is above dust or not,
			// and the answer will in turn change the amount itself — making it a circular
			// dependency.
			// This complicates the computation around dust-values, up to the one-htlc-value.

			let real_dust_limit_timeout_sat =
				real_htlc_timeout_tx_fee_sat + holder_channel_constraints.dust_limit_satoshis;
			let mut max_reserved_commit_tx_fee_msat = local_stats_max_fee.commit_tx_fee_sat * 1000;
			let mut min_reserved_commit_tx_fee_msat = local_stats_min_fee.commit_tx_fee_sat * 1000;

			if !channel_type.supports_anchors_zero_fee_htlc_tx() {
				max_reserved_commit_tx_fee_msat *=
					crate::ln::channel::FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE;
				min_reserved_commit_tx_fee_msat *=
					crate::ln::channel::FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE;
			}

			// We will first subtract the fee as if we were above-dust. Then, if the resulting
			// value ends up being below dust, we have this fee available again. In that case,
			// match the value to right-below-dust.
			let capacity_minus_max_commitment_fee_msat =
				available_capacity_msat.saturating_sub(max_reserved_commit_tx_fee_msat);
			if capacity_minus_max_commitment_fee_msat < real_dust_limit_timeout_sat * 1000 {
				let capacity_minus_min_commitment_fee_msat =
					available_capacity_msat.saturating_sub(min_reserved_commit_tx_fee_msat);
				available_capacity_msat = cmp::min(
					real_dust_limit_timeout_sat * 1000 - 1,
					capacity_minus_min_commitment_fee_msat,
				);
			} else {
				available_capacity_msat = capacity_minus_max_commitment_fee_msat;
			}
		} else {
			// If the channel is inbound (i.e. counterparty pays the fee), we need to make sure
			// sending a new HTLC won't reduce their balance below our reserve threshold.
			let real_dust_limit_success_sat =
				real_htlc_success_tx_fee_sat + counterparty_channel_constraints.dust_limit_satoshis;
			let max_reserved_commit_tx_fee_msat = remote_stats.commit_tx_fee_sat * 1000;

			let holder_selected_chan_reserve_msat =
				counterparty_channel_constraints.channel_reserve_satoshis * 1000;
			if remote_stats.counterparty_balance_before_fee_msat
				< max_reserved_commit_tx_fee_msat + holder_selected_chan_reserve_msat
			{
				// If another HTLC's fee would reduce the remote's balance below the reserve limit
				// we've selected for them, we can only send dust HTLCs.
				available_capacity_msat =
					cmp::min(available_capacity_msat, real_dust_limit_success_sat * 1000 - 1);
			}
		}

		let mut next_outbound_htlc_minimum_msat =
			counterparty_channel_constraints.htlc_minimum_msat;

		// If we get close to our maximum dust exposure, we end up in a situation where we can send
		// between zero and the remaining dust exposure limit remaining OR above the dust limit.
		// Because we cannot express this as a simple min/max, we prefer to tell the user they can
		// send above the dust limit (as the router can always overpay to meet the dust limit).
		let mut remaining_msat_below_dust_exposure_limit = None;
		let mut dust_exposure_dust_limit_msat = 0;

		let dust_buffer_feerate = get_dust_buffer_feerate(feerate_per_kw);
		let (buffer_htlc_success_tx_fee_sat, buffer_htlc_timeout_tx_fee_sat) =
			second_stage_tx_fees_sat(channel_type, dust_buffer_feerate);
		let buffer_dust_limit_success_sat =
			buffer_htlc_success_tx_fee_sat + counterparty_channel_constraints.dust_limit_satoshis;
		let buffer_dust_limit_timeout_sat =
			buffer_htlc_timeout_tx_fee_sat + holder_channel_constraints.dust_limit_satoshis;

		if remote_stats.extra_accepted_htlc_dust_exposure_msat > max_dust_htlc_exposure_msat {
			// If adding an extra HTLC would put us over the dust limit in total fees, we cannot
			// send any non-dust HTLCs.
			available_capacity_msat =
				cmp::min(available_capacity_msat, buffer_dust_limit_success_sat * 1000);
		}

		if remote_stats.dust_exposure_msat.saturating_add(buffer_dust_limit_success_sat * 1000)
			> max_dust_htlc_exposure_msat.saturating_add(1)
		{
			// Note that we don't use the `counterparty_tx_dust_exposure` (with
			// `htlc_dust_exposure_msat`) here as it only applies to non-dust HTLCs.
			remaining_msat_below_dust_exposure_limit =
				Some(max_dust_htlc_exposure_msat.saturating_sub(remote_stats.dust_exposure_msat));
			dust_exposure_dust_limit_msat =
				cmp::max(dust_exposure_dust_limit_msat, buffer_dust_limit_success_sat * 1000);
		}

		if local_stats_max_fee.dust_exposure_msat as i64
			+ buffer_dust_limit_timeout_sat as i64 * 1000
			- 1 > max_dust_htlc_exposure_msat.try_into().unwrap_or(i64::max_value())
		{
			remaining_msat_below_dust_exposure_limit = Some(cmp::min(
				remaining_msat_below_dust_exposure_limit.unwrap_or(u64::max_value()),
				max_dust_htlc_exposure_msat.saturating_sub(local_stats_max_fee.dust_exposure_msat),
			));
			dust_exposure_dust_limit_msat =
				cmp::max(dust_exposure_dust_limit_msat, buffer_dust_limit_timeout_sat * 1000);
		}

		if let Some(remaining_limit_msat) = remaining_msat_below_dust_exposure_limit {
			if available_capacity_msat < dust_exposure_dust_limit_msat {
				available_capacity_msat = cmp::min(available_capacity_msat, remaining_limit_msat);
			} else {
				next_outbound_htlc_minimum_msat =
					cmp::max(next_outbound_htlc_minimum_msat, dust_exposure_dust_limit_msat);
			}
		}

		available_capacity_msat = cmp::min(
			available_capacity_msat,
			counterparty_channel_constraints.max_htlc_value_in_flight_msat
				- pending_htlcs
					.iter()
					.filter(|htlc| htlc.outbound)
					.map(|htlc| htlc.amount_msat)
					.sum::<u64>(),
		);

		if pending_htlcs.iter().filter(|htlc| htlc.outbound).count() + 1
			> counterparty_channel_constraints.max_accepted_htlcs as usize
		{
			available_capacity_msat = 0;
		}

		crate::ln::channel::AvailableBalances {
			inbound_capacity_msat: remote_stats
				.counterparty_balance_before_fee_msat
				.saturating_sub(counterparty_channel_constraints.channel_reserve_satoshis * 1000),
			outbound_capacity_msat,
			next_outbound_htlc_limit_msat: available_capacity_msat,
			next_outbound_htlc_minimum_msat,
		}
	}
	fn get_next_commitment_stats(
		&self, local: bool, is_outbound_from_holder: bool, channel_value_satoshis: u64,
		value_to_holder_msat: u64, next_commitment_htlcs: &[HTLCAmountDirection],
		addl_nondust_htlc_count: usize, feerate_per_kw: u32,
		dust_exposure_limiting_feerate: Option<u32>, broadcaster_dust_limit_satoshis: u64,
		channel_type: &ChannelTypeFeatures,
	) -> Result<NextCommitmentStats, ()> {
		let excess_feerate =
			feerate_per_kw.saturating_sub(dust_exposure_limiting_feerate.unwrap_or(feerate_per_kw));
		if channel_type.supports_anchor_zero_fee_commitments() {
			debug_assert_eq!(feerate_per_kw, 0);
			debug_assert_eq!(excess_feerate, 0);
		}

		// Calculate inbound htlc count
		let inbound_htlcs_count =
			next_commitment_htlcs.iter().filter(|htlc| !htlc.outbound).count();

		// Calculate balances after htlcs
		let value_to_counterparty_msat =
			(channel_value_satoshis * 1000).checked_sub(value_to_holder_msat).ok_or(())?;
		let outbound_htlcs_value_msat: u64 = next_commitment_htlcs
			.iter()
			.filter_map(|htlc| htlc.outbound.then_some(htlc.amount_msat))
			.sum();
		let inbound_htlcs_value_msat: u64 = next_commitment_htlcs
			.iter()
			.filter_map(|htlc| (!htlc.outbound).then_some(htlc.amount_msat))
			.sum();
		let value_to_holder_after_htlcs_msat =
			value_to_holder_msat.checked_sub(outbound_htlcs_value_msat).ok_or(())?;
		let value_to_counterparty_after_htlcs_msat =
			value_to_counterparty_msat.checked_sub(inbound_htlcs_value_msat).ok_or(())?;

		// Subtract the anchors from the channel funder
		let (holder_balance_before_fee_msat, counterparty_balance_before_fee_msat) =
			subtract_addl_outputs(
				is_outbound_from_holder,
				value_to_holder_after_htlcs_msat,
				value_to_counterparty_after_htlcs_msat,
				channel_type,
			)?;

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

		// Add any excess fees to dust exposure on counterparty transactions
		let (dust_exposure_msat, extra_accepted_htlc_dust_exposure_msat) = if local {
			(dust_exposure_msat, dust_exposure_msat)
		} else {
			let (excess_fees_msat, extra_accepted_htlc_excess_fees_msat) =
				commit_plus_htlc_tx_fees_msat(
					local,
					&next_commitment_htlcs,
					dust_buffer_feerate,
					excess_feerate,
					broadcaster_dust_limit_satoshis,
					channel_type,
				);
			(
				dust_exposure_msat + excess_fees_msat,
				dust_exposure_msat + extra_accepted_htlc_excess_fees_msat,
			)
		};

		Ok(NextCommitmentStats {
			is_outbound_from_holder,
			inbound_htlcs_count,
			inbound_htlcs_value_msat,
			holder_balance_before_fee_msat,
			counterparty_balance_before_fee_msat,
			nondust_htlc_count: nondust_htlc_count + addl_nondust_htlc_count,
			commit_tx_fee_sat,
			dust_exposure_msat,
			extra_accepted_htlc_dust_exposure_msat,
		})
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

		let commit_tx_fee_sat = commit_tx_fee_sat(
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
		let (local_balance_before_fee_msat, remote_balance_before_fee_msat) =
			subtract_addl_outputs(
				channel_parameters.is_outbound_from_holder,
				value_to_self_after_htlcs_msat,
				value_to_remote_after_htlcs_msat,
				&channel_parameters.channel_type_features,
			)
			.unwrap();

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
