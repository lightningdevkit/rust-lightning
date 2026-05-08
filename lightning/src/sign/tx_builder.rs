//! Defines the `TxBuilder` trait, and the `SpecTxBuilder` type

use core::cmp;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::ln::chan_utils::{
	commit_tx_fee_sat, htlc_success_tx_weight, htlc_timeout_tx_weight, htlc_tx_fees_sat,
	second_stage_tx_fees_sat, ChannelTransactionParameters, CommitmentTransaction,
	HTLCOutputInCommitment,
};
use crate::ln::channel::{
	get_v2_channel_reserve_satoshis, CommitmentStats, ANCHOR_OUTPUT_VALUE_SATOSHI,
	MIN_CHANNEL_VALUE_SATOSHIS,
};
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
	pub holder_balance_msat: u64,
	pub counterparty_balance_msat: u64,
	pub dust_exposure_msat: u64,
	#[cfg(any(test, fuzzing))]
	pub nondust_htlc_count: usize,
	#[cfg(any(test, fuzzing))]
	pub commit_tx_fee_sat: u64,
}

pub(crate) struct ChannelStats {
	pub commitment_stats: NextCommitmentStats,
	pub available_balances: crate::ln::channel::AvailableBalances,
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

fn total_anchors_sat(channel_type: &ChannelTypeFeatures) -> u64 {
	if channel_type.supports_anchors_zero_fee_htlc_tx() {
		ANCHOR_OUTPUT_VALUE_SATOSHI * 2
	} else {
		0
	}
}

fn checked_sub_from_funder(
	is_outbound_from_holder: bool, value_to_holder: u64, value_to_counterparty: u64,
	value_to_subtract: u64,
) -> Result<(u64, u64), ()> {
	if is_outbound_from_holder {
		Ok((value_to_holder.checked_sub(value_to_subtract).ok_or(())?, value_to_counterparty))
	} else {
		Ok((value_to_holder, value_to_counterparty.checked_sub(value_to_subtract).ok_or(())?))
	}
}

fn saturating_sub_from_funder(
	is_outbound_from_holder: bool, value_to_holder: u64, value_to_counterparty: u64,
	value_to_subtract: u64,
) -> (u64, u64) {
	if is_outbound_from_holder {
		(value_to_holder.saturating_sub(value_to_subtract), value_to_counterparty)
	} else {
		(value_to_holder, value_to_counterparty.saturating_sub(value_to_subtract))
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct ChannelConstraints {
	pub holder_dust_limit_satoshis: u64,
	pub counterparty_selected_channel_reserve_satoshis: u64,
	pub counterparty_dust_limit_satoshis: u64,
	pub holder_selected_channel_reserve_satoshis: u64,
	pub counterparty_htlc_minimum_msat: u64,
	pub counterparty_max_htlc_value_in_flight_msat: u64,
	pub counterparty_max_accepted_htlcs: u64,
}

fn get_dust_exposure_stats(
	local: bool, commitment_htlcs: &[HTLCAmountDirection], feerate_per_kw: u32,
	dust_exposure_limiting_feerate: Option<u32>, broadcaster_dust_limit_satoshis: u64,
	channel_type: &ChannelTypeFeatures,
) -> (u64, Option<u64>) {
	let excess_feerate =
		feerate_per_kw.saturating_sub(dust_exposure_limiting_feerate.unwrap_or(feerate_per_kw));
	if channel_type.supports_anchor_zero_fee_commitments() {
		debug_assert_eq!(feerate_per_kw, 0);
		debug_assert_eq!(excess_feerate, 0);
	}

	// Increment the feerate by a buffer to calculate dust exposure
	let dust_buffer_feerate = get_dust_buffer_feerate(feerate_per_kw);

	// Calculate dust exposure on commitment transaction
	let dust_exposure_msat = commitment_htlcs
		.iter()
		.filter_map(|htlc| {
			htlc.is_dust(local, dust_buffer_feerate, broadcaster_dust_limit_satoshis, channel_type)
				.then_some(htlc.amount_msat)
		})
		.sum();

	if local || excess_feerate == 0 {
		(dust_exposure_msat, None)
	} else {
		// Add any excess fees to dust exposure on counterparty transactions
		let (excess_fees_msat, extra_accepted_htlc_excess_fees_msat) =
			commit_plus_htlc_tx_fees_msat(
				local,
				&commitment_htlcs,
				dust_buffer_feerate,
				excess_feerate,
				broadcaster_dust_limit_satoshis,
				channel_type,
			);
		(
			dust_exposure_msat + excess_fees_msat,
			Some(dust_exposure_msat + extra_accepted_htlc_excess_fees_msat),
		)
	}
}

fn has_output(
	is_outbound_from_holder: bool, holder_balance_before_fee_msat: u64,
	counterparty_balance_before_fee_msat: u64, feerate_per_kw: u32, nondust_htlc_count: usize,
	broadcaster_dust_limit_satoshis: u64, channel_type: &ChannelTypeFeatures,
) -> bool {
	let commit_tx_fee_sat = commit_tx_fee_sat(feerate_per_kw, nondust_htlc_count, channel_type);
	let (holder_balance_msat, counterparty_balance_msat) = saturating_sub_from_funder(
		is_outbound_from_holder,
		holder_balance_before_fee_msat,
		counterparty_balance_before_fee_msat,
		commit_tx_fee_sat.saturating_mul(1000),
	);

	// Make sure the commitment transaction has at least one output
	let dust_limit_msat = broadcaster_dust_limit_satoshis * 1000;
	let has_no_output = holder_balance_msat < dust_limit_msat
		&& counterparty_balance_msat < dust_limit_msat
		&& nondust_htlc_count == 0
		// 0FC channels always have a P2A output on the commitment transaction
		&& !channel_type.supports_anchor_zero_fee_commitments();
	!has_no_output
}

fn get_next_commitment_stats(
	local: bool, is_outbound_from_holder: bool, channel_value_satoshis: u64,
	value_to_holder_msat: u64, next_commitment_htlcs: &[HTLCAmountDirection],
	addl_nondust_htlc_count: usize, feerate_per_kw: u32,
	dust_exposure_limiting_feerate: Option<u32>, broadcaster_dust_limit_satoshis: u64,
	channel_type: &ChannelTypeFeatures,
) -> Result<NextCommitmentStats, ()> {
	if channel_type.supports_anchor_zero_fee_commitments() {
		debug_assert_eq!(feerate_per_kw, 0);
	}

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

	// We MUST use checked subs here, as the funder's balance is not guaranteed to be greater
	// than or equal to `total_anchors_sat`.
	//
	// This is because when the remote party sends an `update_fee` message, we build the new
	// commitment transaction *before* checking whether the remote party's balance is enough to
	// cover the total anchor sum.

	let total_anchors_sat = total_anchors_sat(channel_type);
	let (holder_balance_before_fee_msat, counterparty_balance_before_fee_msat) =
		checked_sub_from_funder(
			is_outbound_from_holder,
			value_to_holder_after_htlcs_msat,
			value_to_counterparty_after_htlcs_msat,
			total_anchors_sat.saturating_mul(1000),
		)?;

	let (dust_exposure_msat, _extra_accepted_htlc_dust_exposure_msat) = get_dust_exposure_stats(
		local,
		next_commitment_htlcs,
		feerate_per_kw,
		dust_exposure_limiting_feerate,
		broadcaster_dust_limit_satoshis,
		channel_type,
	);

	// Calculate fees on commitment transaction
	let nondust_htlc_count = next_commitment_htlcs
		.iter()
		.filter(|htlc| {
			!htlc.is_dust(local, feerate_per_kw, broadcaster_dust_limit_satoshis, channel_type)
		})
		.count();

	// For zero-reserve channels, we check two things independently:
	// 1) Given the current set of HTLCs and feerate, does the commitment have at least one output ?
	if !has_output(
		is_outbound_from_holder,
		holder_balance_before_fee_msat,
		counterparty_balance_before_fee_msat,
		feerate_per_kw,
		nondust_htlc_count,
		broadcaster_dust_limit_satoshis,
		channel_type,
	) {
		return Err(());
	}

	// 2) Now including any additional non-dust HTLCs (usually the fee spike buffer HTLC), does the funder cover
	// this bigger transaction fee ? The funder can dip below their dust limit to cover this case, as the
	// commitment will have at least one output: the non-dust fee spike buffer HTLC offered by the counterparty.
	let commit_tx_fee_sat = commit_tx_fee_sat(
		feerate_per_kw,
		nondust_htlc_count + addl_nondust_htlc_count,
		channel_type,
	);
	let (holder_balance_msat, counterparty_balance_msat) = checked_sub_from_funder(
		is_outbound_from_holder,
		holder_balance_before_fee_msat,
		counterparty_balance_before_fee_msat,
		commit_tx_fee_sat.saturating_mul(1000),
	)?;

	Ok(NextCommitmentStats {
		holder_balance_msat,
		counterparty_balance_msat,
		dust_exposure_msat,
		#[cfg(any(test, fuzzing))]
		nondust_htlc_count: nondust_htlc_count + addl_nondust_htlc_count,
		#[cfg(any(test, fuzzing))]
		commit_tx_fee_sat,
	})
}

/// Determines the maximum value that the holder can splice out of the channel, accounting
/// for the updated reserves after said splice. This maximum also makes sure the local commitment
/// retains at least one output after the splice, which is particularly relevant for
/// zero-reserve channels.
//
// The equation to determine `max_splice_percentage_constraint_sat` is:
// 1) floor((c - s) / 100) == h - s - d
// We want the maximum value of s that will satisfy equation 1, therefore, we solve:
// 2) (c - s) / 100 < h - s - d + 1
// where c: `channel_value_satoshis`
//       s: `max_splice_percentage_constraint_sat`
//       h: `local_balance_before_fee_sat`
//       d: `post_splice_delta_above_reserve_sat`
// This results in:
// 3) s < (100h + 100 - 100d - c) / 99
fn get_next_splice_out_maximum_sat(
	is_outbound_from_holder: bool, channel_value_satoshis: u64, local_balance_before_fee_msat: u64,
	remote_balance_before_fee_msat: u64, spiked_feerate: u32,
	spiked_feerate_nondust_htlc_count: usize, post_splice_delta_above_reserve_sat: u64,
	channel_constraints: &ChannelConstraints, channel_type: &ChannelTypeFeatures,
) -> u64 {
	let local_balance_before_fee_sat = local_balance_before_fee_msat / 1000;
	let mut next_splice_out_maximum_sat = if channel_constraints
		.counterparty_selected_channel_reserve_satoshis
		!= 0
	{
		let dividend_sat = local_balance_before_fee_sat
			.saturating_mul(100)
			.saturating_add(100)
			.saturating_sub(post_splice_delta_above_reserve_sat.saturating_mul(100))
			.saturating_sub(channel_value_satoshis);
		// Calculate the greatest integer that is strictly less than the RHS of inequality 3 above
		let max_splice_percentage_constraint_sat = dividend_sat.saturating_sub(1) / 99;
		let max_splice_dust_limit_constraint_sat = local_balance_before_fee_sat
			.saturating_sub(channel_constraints.holder_dust_limit_satoshis)
			.saturating_sub(post_splice_delta_above_reserve_sat);
		// Both constraints must be satisfied, so take the minimum of the two maximums
		let max_splice_out_sat =
			cmp::min(max_splice_percentage_constraint_sat, max_splice_dust_limit_constraint_sat);
		#[cfg(debug_assertions)]
		if max_splice_out_sat == 0 {
			let current_balance_sat =
				local_balance_before_fee_sat.saturating_sub(post_splice_delta_above_reserve_sat);
			let v2_reserve_sat = get_v2_channel_reserve_satoshis(
				channel_value_satoshis,
				channel_constraints.holder_dust_limit_satoshis,
				false,
			);
			// If the holder cannot splice out anything, they must be at or
			// below the v2 reserve
			debug_assert!(current_balance_sat <= v2_reserve_sat);
		} else {
			let post_splice_reserve_sat = get_v2_channel_reserve_satoshis(
				channel_value_satoshis.saturating_sub(max_splice_out_sat),
				channel_constraints.holder_dust_limit_satoshis,
				false,
			);
			// If the holder can splice out some maximum, splicing out that
			// maximum lands them at exactly the new v2 reserve + the
			// `post_splice_delta_above_reserve_sat`
			debug_assert_eq!(
				local_balance_before_fee_sat.saturating_sub(max_splice_out_sat),
				post_splice_reserve_sat.saturating_add(post_splice_delta_above_reserve_sat)
			);
		}
		max_splice_out_sat
	} else {
		// In a zero-reserve channel, the holder is free to withdraw up to its `post_splice_delta_above_reserve_sat`
		local_balance_before_fee_sat.saturating_sub(post_splice_delta_above_reserve_sat)
	};

	// We only bother to check the local commitment here, the counterparty will check its own commitment.
	//
	// If the current `next_splice_out_maximum_sat` would produce a local commitment with no
	// outputs, bump this maximum such that, after the splice, the holder's balance covers at
	// least `dust_limit_satoshis` and, if they are the funder, `current_spiked_tx_fee_sat`.
	// We don't include an additional non-dust inbound HTLC in the `current_spiked_tx_fee_sat`,
	// because we don't mind if the holder dips below their dust limit to cover the fee for that
	// inbound non-dust HTLC.
	if !has_output(
		is_outbound_from_holder,
		local_balance_before_fee_msat.saturating_sub(next_splice_out_maximum_sat * 1000),
		remote_balance_before_fee_msat,
		spiked_feerate,
		spiked_feerate_nondust_htlc_count,
		channel_constraints.holder_dust_limit_satoshis,
		channel_type,
	) {
		let dust_limit_satoshis = channel_constraints.holder_dust_limit_satoshis;
		let current_spiked_tx_fee_sat = commit_tx_fee_sat(spiked_feerate, 0, channel_type);
		let min_balance_sat = if is_outbound_from_holder {
			dust_limit_satoshis.saturating_add(current_spiked_tx_fee_sat)
		} else {
			dust_limit_satoshis
		};
		next_splice_out_maximum_sat =
			(local_balance_before_fee_msat / 1000).saturating_sub(min_balance_sat);
	}

	if channel_value_satoshis < next_splice_out_maximum_sat + MIN_CHANNEL_VALUE_SATOSHIS {
		next_splice_out_maximum_sat =
			channel_value_satoshis.saturating_sub(MIN_CHANNEL_VALUE_SATOSHIS);
	}

	next_splice_out_maximum_sat
}

fn get_available_balances(
	is_outbound_from_holder: bool, channel_value_satoshis: u64, value_to_holder_msat: u64,
	pending_htlcs: &[HTLCAmountDirection], feerate_per_kw: u32,
	dust_exposure_limiting_feerate: Option<u32>, max_dust_htlc_exposure_msat: u64,
	channel_constraints: ChannelConstraints, channel_type: &ChannelTypeFeatures,
) -> crate::ln::channel::AvailableBalances {
	// When sizing the next HTLC add, we take the remote's view of the set of pending HTLCs in
	// `ChannelContext::get_next_commitment_htlcs`, set this view to `pending_htlcs` here, and use this set of
	// pending HTLCs to calculate stats on our own commitment below.
	//
	// This means we do *not* include `LocalRemoved` HTLCs. `LocalRemoved` and `LocalAnnounced` HTLCs are applied
	// atomically to our own commitment upon the counterparty's next ack.
	//
	// `RemoteRemoved` HTLCs *are* included. While we don't expect these HTLCs to be present in our next
	// commitment, we have not ack'ed these removals yet, so we expect the counterparty to count them when
	// validating our own HTLC add. These HTLCs would also revert to `Committed` upon a disconnection.

	let fee_spike_buffer_htlc =
		if channel_type.supports_anchor_zero_fee_commitments() { 0 } else { 1 };

	// Note that the feerate is 0 in zero-fee commitment channels, so this statement is a noop
	let spiked_feerate = feerate_per_kw.saturating_mul(
		if is_outbound_from_holder && !channel_type.supports_anchors_zero_fee_htlc_tx() {
			crate::ln::channel::FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE as u32
		} else {
			1
		},
	);

	let local_nondust_htlc_count = pending_htlcs
		.iter()
		.filter(|htlc| {
			!htlc.is_dust(
				true,
				spiked_feerate,
				channel_constraints.holder_dust_limit_satoshis,
				channel_type,
			)
		})
		.count();
	let local_max_commit_tx_fee_sat = commit_tx_fee_sat(
		spiked_feerate,
		local_nondust_htlc_count + fee_spike_buffer_htlc + 1,
		channel_type,
	);
	let local_min_commit_tx_fee_sat = commit_tx_fee_sat(
		spiked_feerate,
		local_nondust_htlc_count + fee_spike_buffer_htlc,
		channel_type,
	);
	let (local_dust_exposure_msat, _) = get_dust_exposure_stats(
		true,
		pending_htlcs,
		feerate_per_kw,
		dust_exposure_limiting_feerate,
		channel_constraints.holder_dust_limit_satoshis,
		channel_type,
	);
	let remote_nondust_htlc_count = pending_htlcs
		.iter()
		.filter(|htlc| {
			!htlc.is_dust(
				false,
				feerate_per_kw,
				channel_constraints.counterparty_dust_limit_satoshis,
				channel_type,
			)
		})
		.count();
	let remote_commit_tx_fee_sat =
		commit_tx_fee_sat(feerate_per_kw, remote_nondust_htlc_count + 1, channel_type);
	let (remote_dust_exposure_msat, extra_htlc_remote_dust_exposure_msat) = get_dust_exposure_stats(
		false,
		pending_htlcs,
		feerate_per_kw,
		dust_exposure_limiting_feerate,
		channel_constraints.counterparty_dust_limit_satoshis,
		channel_type,
	);

	let outbound_htlcs_value_msat: u64 =
		pending_htlcs.iter().filter_map(|htlc| htlc.outbound.then_some(htlc.amount_msat)).sum();
	let inbound_htlcs_value_msat: u64 =
		pending_htlcs.iter().filter_map(|htlc| (!htlc.outbound).then_some(htlc.amount_msat)).sum();
	let total_anchors_sat = total_anchors_sat(channel_type);
	let (local_balance_before_fee_msat, remote_balance_before_fee_msat) =
		saturating_sub_from_funder(
			is_outbound_from_holder,
			value_to_holder_msat.saturating_sub(outbound_htlcs_value_msat),
			(channel_value_satoshis * 1000)
				.checked_sub(value_to_holder_msat)
				.unwrap()
				.saturating_sub(inbound_htlcs_value_msat),
			total_anchors_sat.saturating_mul(1000),
		);

	let next_splice_out_maximum_sat = get_next_splice_out_maximum_sat(
		is_outbound_from_holder,
		channel_value_satoshis,
		local_balance_before_fee_msat,
		remote_balance_before_fee_msat,
		spiked_feerate,
		// The number of non-dust HTLCs on the local commitment at the spiked feerate
		local_nondust_htlc_count,
		// The post-splice minimum balance of the holder
		if is_outbound_from_holder { local_min_commit_tx_fee_sat } else { 0 },
		&channel_constraints,
		channel_type,
	);

	let outbound_capacity_msat = local_balance_before_fee_msat
		.saturating_sub(channel_constraints.counterparty_selected_channel_reserve_satoshis * 1000);

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
			real_htlc_timeout_tx_fee_sat + channel_constraints.holder_dust_limit_satoshis;
		let max_reserved_commit_tx_fee_msat = local_max_commit_tx_fee_sat * 1000;
		let min_reserved_commit_tx_fee_msat = local_min_commit_tx_fee_sat * 1000;

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
			real_htlc_success_tx_fee_sat + channel_constraints.counterparty_dust_limit_satoshis;
		let max_reserved_commit_tx_fee_msat = remote_commit_tx_fee_sat * 1000;

		let holder_selected_chan_reserve_msat =
			channel_constraints.holder_selected_channel_reserve_satoshis * 1000;
		if remote_balance_before_fee_msat
			< max_reserved_commit_tx_fee_msat + holder_selected_chan_reserve_msat
		{
			// If another HTLC's fee would reduce the remote's balance below the reserve limit
			// we've selected for them, we can only send dust HTLCs.
			available_capacity_msat =
				cmp::min(available_capacity_msat, real_dust_limit_success_sat * 1000 - 1);
		}
	}

	let mut next_outbound_htlc_minimum_msat = channel_constraints.counterparty_htlc_minimum_msat;

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
		buffer_htlc_success_tx_fee_sat + channel_constraints.counterparty_dust_limit_satoshis;
	let buffer_dust_limit_timeout_sat =
		buffer_htlc_timeout_tx_fee_sat + channel_constraints.holder_dust_limit_satoshis;

	if let Some(extra_htlc_remote_dust_exposure) = extra_htlc_remote_dust_exposure_msat {
		if extra_htlc_remote_dust_exposure > max_dust_htlc_exposure_msat {
			// If adding an extra HTLC would put us over the dust limit in total fees, we cannot
			// send any non-dust HTLCs.
			available_capacity_msat =
				cmp::min(available_capacity_msat, buffer_dust_limit_success_sat * 1000);
		}
	}

	if remote_dust_exposure_msat.saturating_add(buffer_dust_limit_success_sat * 1000)
		> max_dust_htlc_exposure_msat.saturating_add(1)
	{
		// Note that we don't use the `counterparty_tx_dust_exposure` (with
		// `htlc_dust_exposure_msat`) here as it only applies to non-dust HTLCs.
		remaining_msat_below_dust_exposure_limit =
			Some(max_dust_htlc_exposure_msat.saturating_sub(remote_dust_exposure_msat));
		dust_exposure_dust_limit_msat =
			cmp::max(dust_exposure_dust_limit_msat, buffer_dust_limit_success_sat * 1000);
	}

	if local_dust_exposure_msat as i64 + buffer_dust_limit_timeout_sat as i64 * 1000 - 1
		> max_dust_htlc_exposure_msat.try_into().unwrap_or(i64::max_value())
	{
		remaining_msat_below_dust_exposure_limit = Some(cmp::min(
			remaining_msat_below_dust_exposure_limit.unwrap_or(u64::max_value()),
			max_dust_htlc_exposure_msat.saturating_sub(local_dust_exposure_msat),
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
		channel_constraints.counterparty_max_htlc_value_in_flight_msat - outbound_htlcs_value_msat,
	);

	if pending_htlcs.iter().filter(|htlc| htlc.outbound).count() + 1
		> channel_constraints.counterparty_max_accepted_htlcs as usize
	{
		available_capacity_msat = 0;
	}

	// Now adjust our min and max size HTLC to make sure both the local and the remote commitments still have
	// at least one output at the spiked feerate.

	let remote_nondust_htlc_count = pending_htlcs
		.iter()
		.filter(|htlc| {
			!htlc.is_dust(
				false,
				spiked_feerate,
				channel_constraints.counterparty_dust_limit_satoshis,
				channel_type,
			)
		})
		.count();

	let (next_outbound_htlc_minimum_msat, available_capacity_msat) =
		adjust_boundaries_if_max_dust_htlc_produces_no_output(
			true,
			is_outbound_from_holder,
			local_balance_before_fee_msat,
			remote_balance_before_fee_msat,
			local_nondust_htlc_count,
			spiked_feerate,
			channel_constraints.holder_dust_limit_satoshis,
			channel_type,
			next_outbound_htlc_minimum_msat,
			available_capacity_msat,
		);

	let (next_outbound_htlc_minimum_msat, available_capacity_msat) =
		adjust_boundaries_if_max_dust_htlc_produces_no_output(
			false,
			is_outbound_from_holder,
			local_balance_before_fee_msat,
			remote_balance_before_fee_msat,
			remote_nondust_htlc_count,
			spiked_feerate,
			channel_constraints.counterparty_dust_limit_satoshis,
			channel_type,
			next_outbound_htlc_minimum_msat,
			available_capacity_msat,
		);
	let dust_exposure_msat = cmp::max(local_dust_exposure_msat, remote_dust_exposure_msat);

	crate::ln::channel::AvailableBalances {
		inbound_capacity_msat: remote_balance_before_fee_msat
			.saturating_sub(channel_constraints.holder_selected_channel_reserve_satoshis * 1000),
		outbound_capacity_msat,
		next_outbound_htlc_limit_msat: available_capacity_msat,
		next_outbound_htlc_minimum_msat,
		dust_exposure_msat,
		next_splice_out_maximum_sat,
	}
}

fn adjust_boundaries_if_max_dust_htlc_produces_no_output(
	local: bool, is_outbound_from_holder: bool, holder_balance_before_fee_msat: u64,
	counterparty_balance_before_fee_msat: u64, nondust_htlc_count: usize, spiked_feerate: u32,
	dust_limit_satoshis: u64, channel_type: &ChannelTypeFeatures,
	next_outbound_htlc_minimum_msat: u64, available_capacity_msat: u64,
) -> (u64, u64) {
	// First, determine the biggest dust HTLC we could send
	let (htlc_success_tx_fee_sat, htlc_timeout_tx_fee_sat) =
		second_stage_tx_fees_sat(channel_type, spiked_feerate);
	let min_nondust_htlc_sat =
		dust_limit_satoshis + if local { htlc_timeout_tx_fee_sat } else { htlc_success_tx_fee_sat };
	let max_dust_htlc_msat = (min_nondust_htlc_sat.saturating_mul(1000)).saturating_sub(1);

	// If this dust HTLC produces no outputs, then we have to say something! It is now possible to produce a
	// commitment with no outputs.
	if !has_output(
		is_outbound_from_holder,
		holder_balance_before_fee_msat.saturating_sub(max_dust_htlc_msat),
		counterparty_balance_before_fee_msat,
		spiked_feerate,
		nondust_htlc_count,
		dust_limit_satoshis,
		channel_type,
	) {
		// If we are allowed to send non-dust HTLCs, set the min HTLC to the smallest non-dust HTLC...
		if available_capacity_msat >= min_nondust_htlc_sat.saturating_mul(1000) {
			(
				cmp::max(
					min_nondust_htlc_sat.saturating_mul(1000),
					next_outbound_htlc_minimum_msat,
				),
				available_capacity_msat,
			)
		// Otherwise, set the max HTLC to the biggest that still leaves our main balance output untrimmed.
		// Note that this will be a dust HTLC.
		} else {
			// Remember we've got no non-dust HTLCs on the commitment here
			let current_spiked_tx_fee_sat = commit_tx_fee_sat(spiked_feerate, 0, channel_type);
			let spike_buffer_tx_fee_sat = commit_tx_fee_sat(spiked_feerate, 1, channel_type);
			// In case we are the funder, we must cover the greater of
			// 1) The dust_limit_satoshis plus the fee of the existing commitment at the spiked feerate.
			// 2) The fee of the commitment with an additional non-dust HTLC, aka the fee spike buffer HTLC.
			//    In this case we don't mind the holder balance output dropping below the dust limit, as
			//    this additional non-dust HTLC will create the single remaining output on the commitment.
			let min_balance_msat = if is_outbound_from_holder {
				cmp::max(dust_limit_satoshis + current_spiked_tx_fee_sat, spike_buffer_tx_fee_sat)
					* 1000
			// In case we are the fundee, we can send dust HTLCs as long as our own balance output
			// remains above the dust limit.
			} else {
				dust_limit_satoshis * 1000
			};
			(
				next_outbound_htlc_minimum_msat,
				// We make no assumptions about the size of `available_capacity_msat` passed to this
				// function, we only care that the new `available_capacity_msat` is under
				// `holder_balance_before_fee_msat - min_balance_msat`
				cmp::min(
					holder_balance_before_fee_msat.saturating_sub(min_balance_msat),
					available_capacity_msat,
				),
			)
		}
	// Otherwise, it is impossible to produce no outputs with this upcoming HTLC add, so we stay quiet
	} else {
		(next_outbound_htlc_minimum_msat, available_capacity_msat)
	}
}

pub(crate) trait TxBuilder {
	fn get_channel_stats(
		&self, local: bool, is_outbound_from_holder: bool, channel_value_satoshis: u64,
		value_to_holder_msat: u64, pending_htlcs: &[HTLCAmountDirection],
		addl_nondust_htlc_count: usize, feerate_per_kw: u32,
		dust_exposure_limiting_feerate: Option<u32>, max_dust_htlc_exposure_msat: u64,
		channel_constraints: ChannelConstraints, channel_type: &ChannelTypeFeatures,
	) -> Result<ChannelStats, ()>;
	fn build_commitment_transaction<L: Logger>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_parameters: &ChannelTransactionParameters, secp_ctx: &Secp256k1<secp256k1::All>,
		value_to_self_msat: u64, htlcs_in_tx: Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_satoshis: u64, logger: &L,
	) -> (CommitmentTransaction, CommitmentStats);
}

pub(crate) struct SpecTxBuilder {}

impl TxBuilder for SpecTxBuilder {
	fn get_channel_stats(
		&self, local: bool, is_outbound_from_holder: bool, channel_value_satoshis: u64,
		value_to_holder_msat: u64, pending_htlcs: &[HTLCAmountDirection],
		addl_nondust_htlc_count: usize, feerate_per_kw: u32,
		dust_exposure_limiting_feerate: Option<u32>, max_dust_htlc_exposure_msat: u64,
		channel_constraints: ChannelConstraints, channel_type: &ChannelTypeFeatures,
	) -> Result<ChannelStats, ()> {
		let commitment_stats = if local {
			get_next_commitment_stats(
				true,
				is_outbound_from_holder,
				channel_value_satoshis,
				value_to_holder_msat,
				pending_htlcs,
				addl_nondust_htlc_count,
				feerate_per_kw,
				dust_exposure_limiting_feerate,
				channel_constraints.holder_dust_limit_satoshis,
				channel_type,
			)?
		} else {
			get_next_commitment_stats(
				false,
				is_outbound_from_holder,
				channel_value_satoshis,
				value_to_holder_msat,
				pending_htlcs,
				addl_nondust_htlc_count,
				feerate_per_kw,
				dust_exposure_limiting_feerate,
				channel_constraints.counterparty_dust_limit_satoshis,
				channel_type,
			)?
		};

		let available_balances = get_available_balances(
			is_outbound_from_holder,
			channel_value_satoshis,
			value_to_holder_msat,
			pending_htlcs,
			feerate_per_kw,
			dust_exposure_limiting_feerate,
			max_dust_htlc_exposure_msat,
			channel_constraints,
			channel_type,
		);

		Ok(ChannelStats { commitment_stats, available_balances })
	}
	fn build_commitment_transaction<L: Logger>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_parameters: &ChannelTransactionParameters, secp_ctx: &Secp256k1<secp256k1::All>,
		value_to_self_msat: u64, mut htlcs_in_tx: Vec<HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_satoshis: u64, logger: &L,
	) -> (CommitmentTransaction, CommitmentStats) {
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

		// We MUST use saturating subs here, as the funder's balance is not guaranteed to be greater
		// than or equal to `total_anchors_sat`.
		//
		// This is because when the remote party sends an `update_fee` message, we build the new
		// commitment transaction *before* checking whether the remote party's balance is enough to
		// cover the total anchor sum.

		let total_anchors_sat = total_anchors_sat(&channel_parameters.channel_type_features);
		let (local_balance_before_fee_msat, remote_balance_before_fee_msat) =
			saturating_sub_from_funder(
				channel_parameters.is_outbound_from_holder,
				value_to_self_after_htlcs_msat,
				value_to_remote_after_htlcs_msat,
				total_anchors_sat.saturating_mul(1000),
			);

		// We MUST use saturating subs here, as the funder's balance is not guaranteed to be greater
		// than or equal to `commit_tx_fee_sat`.
		//
		// This is because when the remote party sends an `update_fee` message, we build the new
		// commitment transaction *before* checking whether the remote party's balance is enough to
		// cover the total fee.

		let (value_to_self, value_to_remote) = saturating_sub_from_funder(
			channel_parameters.is_outbound_from_holder,
			local_balance_before_fee_msat / 1000,
			remote_balance_before_fee_msat / 1000,
			commit_tx_fee_sat,
		);

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
