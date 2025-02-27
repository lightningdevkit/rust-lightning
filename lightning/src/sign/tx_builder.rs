//! Defines the `TxBuilder` trait, and the `SpecTxBuilder` type
#![allow(dead_code)]
#![allow(unused_variables)]

use core::ops::Deref;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::ln::chan_utils::{
	self, ChannelTransactionParameters, CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{self, CommitmentStats};
use crate::prelude::*;
use crate::util::logger::Logger;

/// A trait for types that can build commitment transactions, both for the holder, and the counterparty.
pub(crate) trait TxBuilder {
	/// Build a commitment transaction, and populate the elements of `htlcs` with their output indices.
	fn build_commitment_transaction<'a, L: Deref>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_transaction_parameters: &ChannelTransactionParameters,
		secp_ctx: &Secp256k1<secp256k1::All>, channel_value_satoshis: u64,
		value_to_self_with_offset_msat: u64,
		htlcs_in_tx: impl Iterator<Item = &'a mut HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_satoshis: u64, logger: &L,
	) -> CommitmentStats
	where
		L::Target: Logger;
}

/// A type that builds commitment transactions according to the Lightning Specification.
#[derive(Clone, Debug, Default)]
pub(crate) struct SpecTxBuilder {}

impl TxBuilder for SpecTxBuilder {
	fn build_commitment_transaction<'a, L: Deref>(
		&self, local: bool, commitment_number: u64, per_commitment_point: &PublicKey,
		channel_transaction_parameters: &ChannelTransactionParameters,
		secp_ctx: &Secp256k1<secp256k1::All>, channel_value_satoshis: u64,
		value_to_self_with_offset_msat: u64,
		htlcs_in_tx: impl Iterator<Item = &'a mut HTLCOutputInCommitment>, feerate_per_kw: u32,
		broadcaster_dust_limit_satoshis: u64, logger: &L,
	) -> CommitmentStats
	where
		L::Target: Logger,
	{
		// We allocate this vector because we need to count the number of non-dust htlcs and calculate the total fee of the transaction
		// before calling `CommitmentTransaction::new`.
		// We could drop this vector and create two iterators: one to count the number of non-dust htlcs, and another to pass to `CommitmentTransaction::new`
		let mut included_non_dust_htlcs: Vec<&mut HTLCOutputInCommitment> =
			Vec::with_capacity(htlcs_in_tx.size_hint().0);

		let mut remote_htlc_total_msat = 0;
		let mut local_htlc_total_msat = 0;

		let channel_parameters = if local {
			channel_transaction_parameters.as_holder_broadcastable()
		} else {
			channel_transaction_parameters.as_counterparty_broadcastable()
		};
		let channel_type = channel_parameters.channel_type_features();

		// Trim dust htlcs
		for htlc in htlcs_in_tx {
			if htlc.offered {
				let outbound = local;
				if outbound {
					local_htlc_total_msat += htlc.amount_msat;
				} else {
					remote_htlc_total_msat += htlc.amount_msat;
				}
				let htlc_tx_fee = if channel_type.supports_anchors_zero_fee_htlc_tx() {
					0
				} else {
					feerate_per_kw as u64 * chan_utils::htlc_timeout_tx_weight(&channel_type) / 1000
				};
				if htlc.amount_msat / 1000 >= broadcaster_dust_limit_satoshis + htlc_tx_fee {
					log_trace!(
						logger,
						"   ...creating output for {} non-dust HTLC (hash {}) with value {}",
						if outbound { "outbound" } else { "inbound" },
						htlc.payment_hash,
						htlc.amount_msat
					);
					included_non_dust_htlcs.push(htlc);
				} else {
					log_trace!(
						logger,
						"   ...trimming {} HTLC (hash {}) with value {} due to dust limit",
						if outbound { "outbound" } else { "inbound" },
						htlc.payment_hash,
						htlc.amount_msat
					);
				}
			} else {
				let outbound = !local;
				if outbound {
					local_htlc_total_msat += htlc.amount_msat;
				} else {
					remote_htlc_total_msat += htlc.amount_msat;
				}
				let htlc_tx_fee = if channel_type.supports_anchors_zero_fee_htlc_tx() {
					0
				} else {
					feerate_per_kw as u64 * chan_utils::htlc_success_tx_weight(&channel_type) / 1000
				};
				if htlc.amount_msat / 1000 >= broadcaster_dust_limit_satoshis + htlc_tx_fee {
					log_trace!(
						logger,
						"   ...creating output for {} non-dust HTLC (hash {}) with value {}",
						if outbound { "outbound" } else { "inbound" },
						htlc.payment_hash,
						htlc.amount_msat
					);
					included_non_dust_htlcs.push(htlc);
				} else {
					log_trace!(
						logger,
						"   ...trimming {} HTLC (hash {}) with value {} due to dust limit",
						if outbound { "outbound" } else { "inbound" },
						htlc.payment_hash,
						htlc.amount_msat
					);
				}
			}
		}

		// Note that in case they have several just-awaiting-last-RAA fulfills in-progress (ie
		// AwaitingRemoteRevokeToRemove or AwaitingRemovedRemoteRevoke) we may have allowed them to
		// "violate" their reserve value by couting those against it. Thus, we have to do checked subtraction
		// as otherwise we can overflow.
		let mut value_to_remote_msat =
			u64::checked_sub(channel_value_satoshis * 1000, value_to_self_with_offset_msat)
				.unwrap();
		let value_to_self_msat =
			u64::checked_sub(value_to_self_with_offset_msat, local_htlc_total_msat).unwrap();
		value_to_remote_msat =
			u64::checked_sub(value_to_remote_msat, remote_htlc_total_msat).unwrap();

		let total_fee_sat = chan_utils::commit_tx_fee_sat(
			feerate_per_kw,
			included_non_dust_htlcs.len(),
			&channel_type,
		);
		let anchors_val = if channel_type.supports_anchors_zero_fee_htlc_tx() {
			channel::ANCHOR_OUTPUT_VALUE_SATOSHI * 2
		} else {
			0
		};
		let (value_to_self, value_to_remote) =
			if channel_transaction_parameters.is_outbound_from_holder {
				(
					(value_to_self_msat / 1000)
						.saturating_sub(anchors_val)
						.saturating_sub(total_fee_sat),
					value_to_remote_msat / 1000,
				)
			} else {
				(
					value_to_self_msat / 1000,
					(value_to_remote_msat / 1000)
						.saturating_sub(anchors_val)
						.saturating_sub(total_fee_sat),
				)
			};

		let mut value_to_a = if local { value_to_self } else { value_to_remote };
		let mut value_to_b = if local { value_to_remote } else { value_to_self };

		if value_to_a >= broadcaster_dust_limit_satoshis {
			log_trace!(
				logger,
				"   ...creating {} output with value {}",
				if local { "to_local" } else { "to_remote" },
				value_to_a
			);
		} else {
			log_trace!(
				logger,
				"   ...trimming {} output with value {} due to dust limit",
				if local { "to_local" } else { "to_remote" },
				value_to_a
			);
			value_to_a = 0;
		}

		if value_to_b >= broadcaster_dust_limit_satoshis {
			log_trace!(
				logger,
				"   ...creating {} output with value {}",
				if local { "to_remote" } else { "to_local" },
				value_to_b
			);
		} else {
			log_trace!(
				logger,
				"   ...trimming {} output with value {} due to dust limit",
				if local { "to_remote" } else { "to_local" },
				value_to_b
			);
			value_to_b = 0;
		}

		let tx = CommitmentTransaction::new(
			commitment_number,
			&per_commitment_point,
			value_to_a,
			value_to_b,
			feerate_per_kw,
			included_non_dust_htlcs.into_iter(),
			&channel_parameters,
			&secp_ctx,
		);

		CommitmentStats {
			tx,
			total_fee_sat,
			local_balance_msat: value_to_self_msat,
			remote_balance_msat: value_to_remote_msat,
		}
	}
}
