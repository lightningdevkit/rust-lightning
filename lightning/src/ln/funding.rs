// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Types pertaining to funding channels.

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, SignedAmount, TxOut, WScriptHash, Weight};

use crate::ln::chan_utils::{
	make_funding_redeemscript, BASE_INPUT_WEIGHT, EMPTY_SCRIPT_SIG_WEIGHT,
	FUNDING_TRANSACTION_WITNESS_WEIGHT,
};
use crate::ln::interactivetxs::{get_output_weight, TX_COMMON_FIELDS_WEIGHT};
use crate::ln::msgs;
use crate::ln::types::ChannelId;
use crate::ln::LN_MAX_MSG_LEN;
use crate::prelude::*;
use crate::util::native_async::MaybeSend;
use crate::util::wallet_utils::{
	CoinSelection, CoinSelectionSource, CoinSelectionSourceSync, Input,
};

/// Error returned when the acceptor's contribution cannot accommodate the initiator's proposed
/// feerate.
///
/// When building a [`FundingContribution`], fees are estimated at `min_feerate` assuming initiator
/// responsibility. If the counterparty also initiates a splice and wins the tie-break, they become
/// the initiator and choose the feerate. The fee is then re-estimated at the counterparty's
/// feerate for only our contributed inputs and outputs. When this re-estimation fails, the
/// contribution is dropped and the counterparty's splice proceeds without it.
///
/// See [`ChannelManager::splice_channel`] for further details.
///
/// [`ChannelManager::splice_channel`]: crate::ln::channelmanager::ChannelManager::splice_channel
#[derive(Debug)]
pub(super) enum FeeRateAdjustmentError {
	/// The counterparty's proposed feerate is below `min_feerate`, which was used as the feerate
	/// during coin selection. We'll retry via RBF at our preferred feerate.
	FeeRateTooLow { target_feerate: FeeRate, min_feerate: FeeRate },
	/// The counterparty's proposed feerate is above `max_feerate` and the re-estimated fee for
	/// our contributed inputs and outputs exceeds the original fee estimate (computed at
	/// `min_feerate` assuming initiator responsibility). If the re-estimated fee were within the
	/// original estimate, a feerate above `max_feerate` would be tolerable since the acceptor
	/// doesn't pay for common fields or the shared input/output.
	FeeRateTooHigh {
		target_feerate: FeeRate,
		max_feerate: FeeRate,
		target_fee: Amount,
		original_fee: Amount,
	},
	/// Arithmetic overflow when computing the fee buffer.
	FeeBufferOverflow,
	/// The re-estimated fee exceeds the available fee buffer regardless of `max_feerate`. The fee
	/// buffer is the maximum fee that can be accommodated:
	/// - **splice-in**: the selected inputs' value minus the contributed amount
	/// - **splice-out**: the channel balance minus the withdrawal outputs
	FeeBufferInsufficient { source: &'static str, available: Amount, required: Amount },
}

impl core::fmt::Display for FeeRateAdjustmentError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			FeeRateAdjustmentError::FeeRateTooLow { target_feerate, min_feerate } => {
				write!(
					f,
					"Target feerate {} is below our minimum {}; \
					 proceeding without contribution, will RBF later",
					target_feerate, min_feerate,
				)
			},
			FeeRateAdjustmentError::FeeRateTooHigh {
				target_feerate,
				max_feerate,
				target_fee,
				original_fee,
			} => {
				write!(
					f,
					"Target feerate {} exceeds our maximum {} and target fee {} exceeds original fee estimate {}",
					target_feerate, max_feerate, target_fee, original_fee,
				)
			},
			FeeRateAdjustmentError::FeeBufferOverflow => {
				write!(
					f,
					"Arithmetic overflow when computing available fee buffer; \
					 proceeding without contribution",
				)
			},
			FeeRateAdjustmentError::FeeBufferInsufficient { source, available, required } => {
				write!(
					f,
					"Fee buffer {} ({}) is insufficient for required fee {}; \
					 proceeding without contribution",
					available, source, required,
				)
			},
		}
	}
}

/// Error returned when building a [`FundingContribution`] from a [`FundingTemplate`].
#[derive(Debug)]
pub enum FundingContributionError {
	/// The feerate exceeds the maximum allowed feerate.
	FeeRateExceedsMaximum {
		/// The requested feerate.
		feerate: FeeRate,
		/// The maximum allowed feerate.
		max_feerate: FeeRate,
	},
	/// The feerate is below the minimum RBF feerate.
	///
	/// Note: [`FundingTemplate::min_rbf_feerate`] may be derived from an in-progress
	/// negotiation that later aborts, leaving a stale (higher than necessary) minimum. If
	/// this error occurs after receiving [`Event::SpliceFailed`], call
	/// [`ChannelManager::splice_channel`] again to get a fresh template.
	///
	/// [`Event::SpliceFailed`]: crate::events::Event::SpliceFailed
	/// [`ChannelManager::splice_channel`]: crate::ln::channelmanager::ChannelManager::splice_channel
	FeeRateBelowRbfMinimum {
		/// The requested feerate.
		feerate: FeeRate,
		/// The minimum RBF feerate.
		min_rbf_feerate: FeeRate,
	},
	/// The splice value is invalid (zero, empty outputs, or exceeds the maximum money supply).
	InvalidSpliceValue,
	/// Coin selection failed to find suitable inputs.
	CoinSelectionFailed,
	/// This is not an RBF scenario (no minimum RBF feerate available).
	NotRbfScenario,
}

impl core::fmt::Display for FundingContributionError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			FundingContributionError::FeeRateExceedsMaximum { feerate, max_feerate } => {
				write!(f, "Feerate {} exceeds maximum {}", feerate, max_feerate)
			},
			FundingContributionError::FeeRateBelowRbfMinimum { feerate, min_rbf_feerate } => {
				write!(f, "Feerate {} is below minimum RBF feerate {}", feerate, min_rbf_feerate)
			},
			FundingContributionError::InvalidSpliceValue => {
				write!(f, "Invalid splice value (zero, empty, or exceeds limit)")
			},
			FundingContributionError::CoinSelectionFailed => {
				write!(f, "Coin selection failed to find suitable inputs")
			},
			FundingContributionError::NotRbfScenario => {
				write!(f, "Not an RBF scenario (no minimum RBF feerate)")
			},
		}
	}
}

/// The user's prior contribution from a previous splice negotiation on this channel.
///
/// When a pending splice exists with negotiated candidates, the prior contribution is
/// available for reuse (e.g., to bump the feerate via RBF). Contains the raw contribution and
/// the holder's balance for deferred feerate adjustment in [`FundingTemplate::rbf_sync`] or
/// [`FundingTemplate::rbf`].
///
/// Use [`FundingTemplate::prior_contribution`] to inspect the prior contribution before
/// deciding whether to call [`FundingTemplate::rbf_sync`] or one of the splice methods
/// with different parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PriorContribution {
	contribution: FundingContribution,
	/// The holder's balance, used for feerate adjustment.
	///
	/// This value is captured at [`ChannelManager::splice_channel`] time and may become stale
	/// if balances change before the contribution is used. Staleness is acceptable here because
	/// this is only used as an optimization to determine if the prior contribution can be
	/// reused with adjusted fees — the contribution is re-validated at
	/// [`ChannelManager::funding_contributed`] time and again at quiescence time against the
	/// current balances.
	///
	/// [`ChannelManager::splice_channel`]: crate::ln::channelmanager::ChannelManager::splice_channel
	/// [`ChannelManager::funding_contributed`]: crate::ln::channelmanager::ChannelManager::funding_contributed
	holder_balance: Amount,
}

impl PriorContribution {
	pub(super) fn new(contribution: FundingContribution, holder_balance: Amount) -> Self {
		Self { contribution, holder_balance }
	}
}

/// A template for contributing to a channel's splice funding transaction.
///
/// This is returned from [`ChannelManager::splice_channel`] when a channel is ready to be
/// spliced. A [`FundingContribution`] must be obtained from it and passed to
/// [`ChannelManager::funding_contributed`] in order to resume the splicing process.
///
/// # Building a Contribution
///
/// For a fresh splice (no pending splice to replace), build a new contribution using one of
/// the splice methods:
/// - [`FundingTemplate::splice_in_sync`] to add funds to the channel
/// - [`FundingTemplate::splice_out`] to remove funds from the channel
/// - [`FundingTemplate::splice_in_and_out_sync`] to do both
///
/// These require `min_feerate` and `max_feerate` parameters. The splice-in variants perform
/// coin selection when wallet inputs are needed, while splice-out spends only from the channel
/// balance.
///
/// # Replace By Fee (RBF)
///
/// When a pending splice exists that hasn't been locked yet, use [`FundingTemplate::rbf_sync`]
/// (or [`FundingTemplate::rbf`] for async) to build an RBF contribution. This handles the
/// prior contribution logic internally — reusing an adjusted prior when possible, re-running
/// coin selection when needed, or creating a fee-bump-only contribution.
///
/// Check [`FundingTemplate::min_rbf_feerate`] for the minimum feerate required (the greater of
/// the previous feerate + 25 sat/kwu and the spec's 25/24 rule). Use
/// [`FundingTemplate::prior_contribution`] to inspect the prior
/// contribution's parameters (e.g., [`FundingContribution::value_added`],
/// [`FundingContribution::outputs`]) before deciding whether to reuse it via the RBF methods
/// or build a fresh contribution with different parameters using the splice methods above.
///
/// [`ChannelManager::splice_channel`]: crate::ln::channelmanager::ChannelManager::splice_channel
/// [`ChannelManager::funding_contributed`]: crate::ln::channelmanager::ChannelManager::funding_contributed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingTemplate {
	/// The shared input, which, if present indicates the funding template is for a splice funding
	/// transaction.
	shared_input: Option<Input>,

	/// The minimum RBF feerate (the greater of previous feerate + 25 sat/kwu and the spec's
	/// 25/24 rule), if this template is for an RBF attempt. `None` for fresh splices with no
	/// pending splice candidates.
	min_rbf_feerate: Option<FeeRate>,

	/// The user's prior contribution from a previous splice negotiation, if available.
	prior_contribution: Option<PriorContribution>,
}

impl FundingTemplate {
	/// Constructs a [`FundingTemplate`] for a splice using the provided shared input.
	pub(super) fn new(
		shared_input: Option<Input>, min_rbf_feerate: Option<FeeRate>,
		prior_contribution: Option<PriorContribution>,
	) -> Self {
		Self { shared_input, min_rbf_feerate, prior_contribution }
	}

	/// Returns the minimum RBF feerate, if this template is for an RBF attempt.
	///
	/// When set, the `min_feerate` passed to the splice methods (e.g.,
	/// [`FundingTemplate::splice_in_sync`]) must be at least this value.
	pub fn min_rbf_feerate(&self) -> Option<FeeRate> {
		self.min_rbf_feerate
	}

	/// Returns a reference to the prior contribution from a previous splice negotiation, if
	/// available.
	///
	/// Use this to inspect the prior contribution's parameters (e.g.,
	/// [`FundingContribution::value_added`], [`FundingContribution::outputs`]) before deciding
	/// whether to reuse it via [`FundingTemplate::rbf_sync`] or build a fresh contribution
	/// with different parameters using the splice methods.
	///
	/// Note: the returned contribution may reflect a different feerate than originally provided,
	/// as it may have been adjusted for RBF or for the counterparty's feerate when acting as
	/// the acceptor. This can change other parameters too (e.g.,
	/// [`FundingContribution::value_added`] may be higher if the change output was removed to
	/// cover a higher fee).
	pub fn prior_contribution(&self) -> Option<&FundingContribution> {
		self.prior_contribution.as_ref().map(|p| &p.contribution)
	}
}

macro_rules! build_funding_contribution {
    ($value_added:expr, $outputs:expr, $shared_input:expr, $min_rbf_feerate:expr, $feerate:expr, $max_feerate:expr, $force_coin_selection:expr, $wallet:ident, $($await:tt)*) => {{
		let value_added: Amount = $value_added;
		let outputs: Vec<TxOut> = $outputs;
		let shared_input: Option<Input> = $shared_input;
		let min_rbf_feerate: Option<FeeRate> = $min_rbf_feerate;
		let feerate: FeeRate = $feerate;
		let max_feerate: FeeRate = $max_feerate;
		let force_coin_selection: bool = $force_coin_selection;

		let value_removed = validate_funding_contribution_params(
			value_added,
			&outputs,
			min_rbf_feerate,
			feerate,
			max_feerate,
		)?;

		let is_splice = shared_input.is_some();

		let coin_selection = if value_added == Amount::ZERO && !force_coin_selection {
			CoinSelection { confirmed_utxos: vec![], change_output: None }
		} else {
			// Used for creating a redeem script for the new funding txo, since the funding pubkeys
			// are unknown at this point. Only needed when selecting which UTXOs to include in the
			// funding tx that would be sufficient to pay for fees. Hence, the value doesn't matter.
			let dummy_pubkey = PublicKey::from_slice(&[2; 33]).unwrap();

			let shared_output = bitcoin::TxOut {
				value: shared_input
					.as_ref()
					.map(|shared_input| shared_input.previous_utxo.value)
					.unwrap_or(Amount::ZERO)
					.checked_add(value_added)
					.ok_or(FundingContributionError::InvalidSpliceValue)?
					.checked_sub(value_removed)
					.ok_or(FundingContributionError::InvalidSpliceValue)?,
				script_pubkey: make_funding_redeemscript(&dummy_pubkey, &dummy_pubkey).to_p2wsh(),
			};

			let claim_id = None;
			let must_spend = shared_input.map(|input| vec![input]).unwrap_or_default();
			if outputs.is_empty() {
				let must_pay_to = &[shared_output];
				$wallet.select_confirmed_utxos(claim_id, must_spend, must_pay_to, feerate.to_sat_per_kwu() as u32, u64::MAX)$(.$await)*.map_err(|_| FundingContributionError::CoinSelectionFailed)?
			} else {
				let must_pay_to: Vec<_> = outputs.iter().cloned().chain(core::iter::once(shared_output)).collect();
				$wallet.select_confirmed_utxos(claim_id, must_spend, &must_pay_to, feerate.to_sat_per_kwu() as u32, u64::MAX)$(.$await)*.map_err(|_| FundingContributionError::CoinSelectionFailed)?
			}
		};

		// NOTE: Must NOT fail after UTXO selection

		let CoinSelection { confirmed_utxos: inputs, change_output } = coin_selection;

		Ok(FundingContribution::new(
			value_added,
			outputs,
			inputs,
			change_output,
			feerate,
			max_feerate,
			is_splice,
		))
	}};
}

fn validate_funding_contribution_params(
	value_added: Amount, outputs: &[TxOut], min_rbf_feerate: Option<FeeRate>, feerate: FeeRate,
	max_feerate: FeeRate,
) -> Result<Amount, FundingContributionError> {
	if feerate > max_feerate {
		return Err(FundingContributionError::FeeRateExceedsMaximum { feerate, max_feerate });
	}

	if let Some(min_rbf_feerate) = min_rbf_feerate {
		if feerate < min_rbf_feerate {
			return Err(FundingContributionError::FeeRateBelowRbfMinimum {
				feerate,
				min_rbf_feerate,
			});
		}
	}

	// Validate user-provided amounts are within MAX_MONEY before coin selection to
	// ensure FundingContribution::net_value() arithmetic cannot overflow. With all
	// amounts bounded by MAX_MONEY (~2.1e15 sat), the worst-case net_value()
	// computation is -2 * MAX_MONEY (~-4.2e15), well within i64::MIN (~-9.2e18).
	if value_added > Amount::MAX_MONEY {
		return Err(FundingContributionError::InvalidSpliceValue);
	}

	let mut value_removed = Amount::ZERO;
	for txout in outputs.iter() {
		value_removed = match value_removed.checked_add(txout.value) {
			Some(sum) if sum <= Amount::MAX_MONEY => sum,
			_ => return Err(FundingContributionError::InvalidSpliceValue),
		};
	}

	Ok(value_removed)
}

impl FundingTemplate {
	/// Creates a [`FundingContribution`] for adding funds to a channel using `wallet` to perform
	/// coin selection.
	///
	/// `value_added` is the total amount to add to the channel for this contribution. When
	/// replacing a prior contribution via RBF, use [`FundingTemplate::prior_contribution`] to
	/// inspect the prior parameters. To add funds on top of the prior contribution's amount,
	/// combine them: `prior.value_added() + additional_amount`.
	pub async fn splice_in<W: CoinSelectionSource + MaybeSend>(
		self, value_added: Amount, min_feerate: FeeRate, max_feerate: FeeRate, wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		if value_added == Amount::ZERO {
			return Err(FundingContributionError::InvalidSpliceValue);
		}
		let FundingTemplate { shared_input, min_rbf_feerate, .. } = self;
		build_funding_contribution!(
			value_added,
			vec![],
			shared_input,
			min_rbf_feerate,
			min_feerate,
			max_feerate,
			false,
			wallet,
			await
		)
	}

	/// Creates a [`FundingContribution`] for adding funds to a channel using `wallet` to perform
	/// coin selection.
	///
	/// See [`FundingTemplate::splice_in`] for details.
	pub fn splice_in_sync<W: CoinSelectionSourceSync>(
		self, value_added: Amount, min_feerate: FeeRate, max_feerate: FeeRate, wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		if value_added == Amount::ZERO {
			return Err(FundingContributionError::InvalidSpliceValue);
		}
		let FundingTemplate { shared_input, min_rbf_feerate, .. } = self;
		build_funding_contribution!(
			value_added,
			vec![],
			shared_input,
			min_rbf_feerate,
			min_feerate,
			max_feerate,
			false,
			wallet,
		)
	}

	/// Creates a [`FundingContribution`] for removing funds from a channel.
	///
	/// Fees are paid from the channel balance, so this does not perform coin selection or spend
	/// wallet inputs.
	///
	/// `outputs` are the complete set of withdrawal outputs for this contribution. When
	/// replacing a prior contribution via RBF, use [`FundingTemplate::prior_contribution`] to
	/// inspect the prior parameters. To keep existing withdrawals and add new ones, include the
	/// prior's outputs: combine [`FundingContribution::outputs`] with the new outputs.
	pub fn splice_out(
		self, outputs: Vec<TxOut>, min_feerate: FeeRate, max_feerate: FeeRate,
	) -> Result<FundingContribution, FundingContributionError> {
		if outputs.is_empty() {
			return Err(FundingContributionError::InvalidSpliceValue);
		}
		validate_funding_contribution_params(
			Amount::ZERO,
			&outputs,
			self.min_rbf_feerate,
			min_feerate,
			max_feerate,
		)?;
		Ok(FundingContribution::new(
			Amount::ZERO,
			outputs,
			vec![],
			None,
			min_feerate,
			max_feerate,
			self.shared_input.is_some(),
		))
	}

	/// Creates a [`FundingContribution`] for both adding and removing funds from a channel using
	/// `wallet` to perform coin selection.
	///
	/// `value_added` and `outputs` are the complete parameters for this contribution, not
	/// increments on top of a prior contribution. When replacing a prior contribution via RBF,
	/// use [`FundingTemplate::prior_contribution`] to inspect the prior parameters and combine
	/// them as needed.
	pub async fn splice_in_and_out<W: CoinSelectionSource + MaybeSend>(
		self, value_added: Amount, outputs: Vec<TxOut>, min_feerate: FeeRate, max_feerate: FeeRate,
		wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		if value_added == Amount::ZERO && outputs.is_empty() {
			return Err(FundingContributionError::InvalidSpliceValue);
		}
		let FundingTemplate { shared_input, min_rbf_feerate, .. } = self;
		build_funding_contribution!(
			value_added,
			outputs,
			shared_input,
			min_rbf_feerate,
			min_feerate,
			max_feerate,
			false,
			wallet,
			await
		)
	}

	/// Creates a [`FundingContribution`] for both adding and removing funds from a channel using
	/// `wallet` to perform coin selection.
	///
	/// See [`FundingTemplate::splice_in_and_out`] for details.
	pub fn splice_in_and_out_sync<W: CoinSelectionSourceSync>(
		self, value_added: Amount, outputs: Vec<TxOut>, min_feerate: FeeRate, max_feerate: FeeRate,
		wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		if value_added == Amount::ZERO && outputs.is_empty() {
			return Err(FundingContributionError::InvalidSpliceValue);
		}
		let FundingTemplate { shared_input, min_rbf_feerate, .. } = self;
		build_funding_contribution!(
			value_added,
			outputs,
			shared_input,
			min_rbf_feerate,
			min_feerate,
			max_feerate,
			false,
			wallet,
		)
	}

	/// Creates a [`FundingContribution`] for an RBF (Replace-By-Fee) attempt on a pending splice.
	///
	/// `max_feerate` is the maximum feerate the caller is willing to accept as acceptor. It is
	/// used as the returned contribution's `max_feerate` and also constrains coin selection when
	/// re-running it for prior contributions that cannot be adjusted or fee-bump-only
	/// contributions.
	///
	/// This handles the prior contribution logic internally:
	/// - If the prior contribution's feerate can be adjusted to the minimum RBF feerate, the
	///   adjusted contribution is returned directly. For splice-in, the change output absorbs
	///   the fee difference. For splice-out (no wallet inputs), the holder's channel balance
	///   covers the higher fees.
	/// - If adjustment fails, coin selection is re-run using the prior contribution's
	///   parameters and the caller's `max_feerate`. For splice-out contributions, this changes
	///   the fee source: wallet inputs are selected to cover fees instead of deducting them
	///   from the channel balance.
	/// - If no prior contribution exists, coin selection is run for a fee-bump-only contribution
	///   (`value_added = 0`), covering fees for the common fields and shared input/output via
	///   a newly selected input. Check [`FundingTemplate::prior_contribution`] to see if this
	///   is intended.
	///
	/// # Errors
	///
	/// Returns a [`FundingContributionError`] if this is not an RBF scenario, if `max_feerate`
	/// is below the minimum RBF feerate, or if coin selection fails.
	pub async fn rbf<W: CoinSelectionSource + MaybeSend>(
		self, max_feerate: FeeRate, wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		let FundingTemplate { shared_input, min_rbf_feerate, prior_contribution } = self;
		let rbf_feerate = min_rbf_feerate.ok_or(FundingContributionError::NotRbfScenario)?;
		if rbf_feerate > max_feerate {
			return Err(FundingContributionError::FeeRateExceedsMaximum {
				feerate: rbf_feerate,
				max_feerate,
			});
		}

		match prior_contribution {
			Some(PriorContribution { contribution, holder_balance }) => {
				// Try to adjust the prior contribution to the RBF feerate. This fails if
				// the holder balance can't cover the adjustment (splice-out) or the fee
				// buffer is insufficient (splice-in), or if the prior's feerate is already
				// above rbf_feerate (e.g., from a counterparty-initiated RBF that locked
				// at a higher feerate). In all cases, fall through to re-run coin selection.
				if contribution
					.net_value_for_initiator_at_feerate(rbf_feerate, holder_balance)
					.is_ok()
				{
					let mut adjusted = contribution
						.for_initiator_at_feerate(rbf_feerate, holder_balance)
						.expect("feerate compatibility already checked");
					adjusted.max_feerate = max_feerate;
					return Ok(adjusted);
				}
				build_funding_contribution!(
					contribution.value_added,
					contribution.outputs,
					shared_input,
					min_rbf_feerate,
					rbf_feerate,
					max_feerate,
					true,
					wallet,
					await
				)
			},
			None => {
				build_funding_contribution!(
					Amount::ZERO,
					vec![],
					shared_input,
					min_rbf_feerate,
					rbf_feerate,
					max_feerate,
					true,
					wallet,
					await
				)
			},
		}
	}

	/// Creates a [`FundingContribution`] for an RBF (Replace-By-Fee) attempt on a pending splice.
	///
	/// See [`FundingTemplate::rbf`] for details.
	pub fn rbf_sync<W: CoinSelectionSourceSync>(
		self, max_feerate: FeeRate, wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		let FundingTemplate { shared_input, min_rbf_feerate, prior_contribution } = self;
		let rbf_feerate = min_rbf_feerate.ok_or(FundingContributionError::NotRbfScenario)?;
		if rbf_feerate > max_feerate {
			return Err(FundingContributionError::FeeRateExceedsMaximum {
				feerate: rbf_feerate,
				max_feerate,
			});
		}

		match prior_contribution {
			Some(PriorContribution { contribution, holder_balance }) => {
				// See comment in `rbf` for details on when this adjustment fails.
				if contribution
					.net_value_for_initiator_at_feerate(rbf_feerate, holder_balance)
					.is_ok()
				{
					let mut adjusted = contribution
						.for_initiator_at_feerate(rbf_feerate, holder_balance)
						.expect("feerate compatibility already checked");
					adjusted.max_feerate = max_feerate;
					return Ok(adjusted);
				}
				build_funding_contribution!(
					contribution.value_added,
					contribution.outputs,
					shared_input,
					min_rbf_feerate,
					rbf_feerate,
					max_feerate,
					true,
					wallet,
				)
			},
			None => {
				build_funding_contribution!(
					Amount::ZERO,
					vec![],
					shared_input,
					min_rbf_feerate,
					rbf_feerate,
					max_feerate,
					true,
					wallet,
				)
			},
		}
	}
}

fn estimate_transaction_fee(
	inputs: &[FundingTxInput], outputs: &[TxOut], change_output: Option<&TxOut>,
	is_initiator: bool, is_splice: bool, feerate: FeeRate,
) -> Amount {
	let input_weight: u64 = inputs
		.iter()
		.map(|input| BASE_INPUT_WEIGHT.saturating_add(input.utxo.satisfaction_weight))
		.fold(0, |total_weight, input_weight| total_weight.saturating_add(input_weight));

	let output_weight: u64 = outputs
		.iter()
		.chain(change_output.into_iter())
		.map(|txout| txout.weight().to_wu())
		.fold(0, |total_weight, output_weight| total_weight.saturating_add(output_weight));

	let mut weight = input_weight.saturating_add(output_weight);

	// The initiator pays for all common fields and the shared output in the funding transaction.
	if is_initiator {
		weight = weight
			.saturating_add(TX_COMMON_FIELDS_WEIGHT)
			// The weight of the funding output, a P2WSH output
			// NOTE: The witness script hash given here is irrelevant as it's a fixed size and we just want
			// to calculate the contributed weight, so we use an all-zero hash.
			//
			// TODO(taproot): Needs to consider different weights based on channel type
			.saturating_add(
				get_output_weight(&ScriptBuf::new_p2wsh(&WScriptHash::from_raw_hash(
					Hash::all_zeros(),
				)))
				.to_wu(),
			);

		// The splice initiator pays for the input spending the previous funding output.
		if is_splice {
			weight = weight
				.saturating_add(BASE_INPUT_WEIGHT)
				.saturating_add(EMPTY_SCRIPT_SIG_WEIGHT)
				.saturating_add(FUNDING_TRANSACTION_WITNESS_WEIGHT);
			#[cfg(feature = "grind_signatures")]
			{
				// Guarantees a low R signature
				weight -= 1;
			}
		}
	}

	Weight::from_wu(weight) * feerate
}

/// The components of a funding transaction contributed by one party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingContribution {
	/// The amount to contribute to the channel.
	///
	/// If `value_added` is [`Amount::ZERO`], then any fees will be deducted from the channel
	/// balance instead of paid by `inputs`.
	value_added: Amount,

	/// The estimate fees responsible to be paid for the contribution.
	estimated_fee: Amount,

	/// The inputs included in the funding transaction to meet the contributed amount plus fees. Any
	/// excess amount will be sent to a change output.
	inputs: Vec<FundingTxInput>,

	/// The outputs to include in the funding transaction. The total value of all outputs plus fees
	/// will be the amount that is removed.
	outputs: Vec<TxOut>,

	/// The output where any change will be sent.
	change_output: Option<TxOut>,

	/// The fee rate used to select `inputs` (the minimum feerate).
	feerate: FeeRate,

	/// The maximum fee rate to accept as acceptor before rejecting the splice.
	max_feerate: FeeRate,

	/// Whether the contribution is for funding a splice.
	is_splice: bool,
}

impl_writeable_tlv_based!(FundingContribution, {
	(1, value_added, required),
	(3, estimated_fee, required),
	(5, inputs, optional_vec),
	(7, outputs, optional_vec),
	(9, change_output, option),
	(11, feerate, required),
	(13, max_feerate, required),
	(15, is_splice, required),
});

impl FundingContribution {
	fn new(
		value_added: Amount, outputs: Vec<TxOut>, inputs: Vec<FundingTxInput>,
		change_output: Option<TxOut>, feerate: FeeRate, max_feerate: FeeRate, is_splice: bool,
	) -> Self {
		// The caller creating a FundingContribution is always the initiator for fee estimation
		// purposes — this is conservative, overestimating rather than underestimating fees if the
		// node ends up as the acceptor.
		let estimated_fee = estimate_transaction_fee(
			&inputs,
			&outputs,
			change_output.as_ref(),
			true,
			is_splice,
			feerate,
		);
		debug_assert!(estimated_fee <= Amount::MAX_MONEY);

		Self {
			value_added,
			estimated_fee,
			inputs,
			outputs,
			change_output,
			feerate,
			max_feerate,
			is_splice,
		}
	}

	pub(super) fn feerate(&self) -> FeeRate {
		self.feerate
	}

	pub(super) fn is_splice(&self) -> bool {
		self.is_splice
	}

	pub(super) fn contributed_inputs(&self) -> impl Iterator<Item = OutPoint> + '_ {
		self.inputs.iter().map(|input| input.utxo.outpoint)
	}

	pub(super) fn contributed_outputs(&self) -> impl Iterator<Item = &TxOut> + '_ {
		self.outputs.iter().chain(self.change_output.iter())
	}

	/// Returns the amount added to the channel by this contribution.
	pub fn value_added(&self) -> Amount {
		self.value_added
	}

	/// Returns the outputs (e.g., withdrawal destinations) included in this contribution.
	///
	/// This does not include the change output; see [`FundingContribution::change_output`].
	pub fn outputs(&self) -> &[TxOut] {
		&self.outputs
	}

	/// Returns the change output included in this contribution, if any.
	///
	/// When coin selection provides more value than needed for the funding contribution and fees,
	/// the surplus is returned to the wallet via this change output.
	pub fn change_output(&self) -> Option<&TxOut> {
		self.change_output.as_ref()
	}

	pub(super) fn into_tx_parts(self) -> (Vec<FundingTxInput>, Vec<TxOut>) {
		let FundingContribution { inputs, mut outputs, change_output, .. } = self;

		if let Some(change_output) = change_output {
			outputs.push(change_output);
		}

		(inputs, outputs)
	}

	pub(super) fn into_contributed_inputs_and_outputs(self) -> (Vec<OutPoint>, Vec<TxOut>) {
		let (inputs, outputs) = self.into_tx_parts();

		(inputs.into_iter().map(|input| input.utxo.outpoint).collect(), outputs)
	}

	pub(super) fn into_unique_contributions<'a>(
		self, existing_inputs: impl Iterator<Item = OutPoint>,
		existing_outputs: impl Iterator<Item = &'a TxOut>,
	) -> Option<(Vec<OutPoint>, Vec<TxOut>)> {
		let (mut inputs, mut outputs) = self.into_contributed_inputs_and_outputs();
		for existing in existing_inputs {
			inputs.retain(|input| *input != existing);
		}
		for existing in existing_outputs {
			outputs.retain(|output| *output != *existing);
		}
		if inputs.is_empty() && outputs.is_empty() {
			None
		} else {
			Some((inputs, outputs))
		}
	}

	/// Validates that the funding inputs are suitable for use in the interactive transaction
	/// protocol, checking prevtx sizes and input sufficiency.
	pub fn validate(&self) -> Result<(), String> {
		for FundingTxInput { utxo, prevtx, .. } in self.inputs.iter() {
			use crate::util::ser::Writeable;
			const MESSAGE_TEMPLATE: msgs::TxAddInput = msgs::TxAddInput {
				channel_id: ChannelId([0; 32]),
				serial_id: 0,
				prevtx: None,
				prevtx_out: 0,
				sequence: 0,
				// Mutually exclusive with prevtx, which is accounted for below.
				shared_input_txid: None,
			};
			let message_len = MESSAGE_TEMPLATE.serialized_length() + prevtx.serialized_length();
			if message_len > LN_MAX_MSG_LEN {
				return Err(format!(
					"Funding input references a prevtx that is too large for tx_add_input: {}",
					utxo.outpoint
				));
			}
		}

		// Fees for splice-out are paid from the channel balance whereas fees for splice-in
		// are paid by the funding inputs. Therefore, in the case of splice-out, we add the
		// fees on top of the user-specified contribution. We leave the user-specified
		// contribution as-is for splice-ins.
		if !self.inputs.is_empty() {
			let mut total_input_value = Amount::ZERO;
			for FundingTxInput { utxo, .. } in self.inputs.iter() {
				total_input_value = total_input_value
					.checked_add(utxo.output.value)
					.ok_or("Sum of input values is greater than the total bitcoin supply")?;
			}

			// If the inputs are enough to cover intended contribution amount plus fees (which
			// include the change output weight when present), we are fine.
			// If the inputs are less, but enough to cover intended contribution amount with
			// (lower) fees without change, we are also fine (change will not be generated).
			// Since estimated_fee includes change weight, this check is conservative.
			//
			// Note: dust limit is not relevant in this check.

			let contributed_input_value = self.value_added;
			let estimated_fee = self.estimated_fee;
			let minimal_input_amount_needed = contributed_input_value
				.checked_add(estimated_fee)
				.ok_or(format!("{contributed_input_value} contribution plus {estimated_fee} fee estimate exceeds the total bitcoin supply"))?;
			if total_input_value < minimal_input_amount_needed {
				return Err(format!(
						"Total input amount {total_input_value} is lower than needed for splice-in contribution {contributed_input_value}, considering fees of {estimated_fee}. Need more inputs.",
				));
			}
		}

		Ok(())
	}

	/// Computes the adjusted fee and change output value at the given target feerate, which may
	/// differ from the feerate used during coin selection.
	///
	/// The `is_initiator` parameter determines fee responsibility: the initiator pays for common
	/// transaction fields, the shared input, and the shared output, while the acceptor only pays
	/// for their own contributed inputs and outputs.
	///
	/// On success, returns the new estimated fee and, if applicable, the new change output value:
	/// - `Some(change)` — the adjusted change output value
	/// - `None` — no change output (no inputs or change fell below dust)
	///
	/// Returns `Err` if the contribution cannot accommodate the target feerate.
	fn compute_feerate_adjustment(
		&self, target_feerate: FeeRate, holder_balance: Amount, is_initiator: bool,
	) -> Result<(Amount, Option<Amount>), FeeRateAdjustmentError> {
		if target_feerate < self.feerate {
			return Err(FeeRateAdjustmentError::FeeRateTooLow {
				target_feerate,
				min_feerate: self.feerate,
			});
		}

		// If the target fee rate exceeds our max fee rate, we may still add our contribution
		// if we pay less in fees at the target feerate than at the original feerate. This can
		// happen when adjusting as acceptor, since the acceptor doesn't pay for common fields
		// and the shared input / output.
		if target_feerate > self.max_feerate {
			let target_fee = estimate_transaction_fee(
				&self.inputs,
				&self.outputs,
				self.change_output.as_ref(),
				is_initiator,
				self.is_splice,
				target_feerate,
			);
			if target_fee > self.estimated_fee {
				return Err(FeeRateAdjustmentError::FeeRateTooHigh {
					target_feerate,
					max_feerate: self.max_feerate,
					target_fee,
					original_fee: self.estimated_fee,
				});
			}
		}

		if !self.inputs.is_empty() {
			if let Some(ref change_output) = self.change_output {
				let old_change_value = change_output.value;
				let dust_limit = change_output.script_pubkey.minimal_non_dust();

				// Target fee including the change output's weight.
				let target_fee = estimate_transaction_fee(
					&self.inputs,
					&self.outputs,
					self.change_output.as_ref(),
					is_initiator,
					self.is_splice,
					target_feerate,
				);

				let fee_buffer = self
					.estimated_fee
					.checked_add(old_change_value)
					.ok_or(FeeRateAdjustmentError::FeeBufferOverflow)?;

				match fee_buffer.checked_sub(target_fee) {
					Some(new_change_value) if new_change_value >= dust_limit => {
						Ok((target_fee, Some(new_change_value)))
					},
					_ => {
						// Change would be below dust or negative. Try without change.
						let target_fee_no_change = estimate_transaction_fee(
							&self.inputs,
							&self.outputs,
							None,
							is_initiator,
							self.is_splice,
							target_feerate,
						);
						if target_fee_no_change > fee_buffer {
							Err(FeeRateAdjustmentError::FeeBufferInsufficient {
								source: "estimated fee + change value",
								available: fee_buffer,
								required: target_fee_no_change,
							})
						} else {
							Ok((target_fee_no_change, None))
						}
					},
				}
			} else {
				// No change output.
				let target_fee = estimate_transaction_fee(
					&self.inputs,
					&self.outputs,
					None,
					is_initiator,
					self.is_splice,
					target_feerate,
				);
				// The fee buffer is total input value minus value_added and output values.
				// This is estimated_fee plus the coin selection surplus (dust burned to
				// fees), ensuring we never silently reduce value_added beyond the small
				// surplus from coin selection.
				let total_input_value: Amount =
					self.inputs.iter().map(|i| i.utxo.output.value).sum();
				let output_values: Amount = self.outputs.iter().map(|o| o.value).sum();
				let fee_buffer = total_input_value
					.checked_sub(self.value_added)
					.and_then(|v| v.checked_sub(output_values))
					.ok_or(FeeRateAdjustmentError::FeeBufferOverflow)?;
				if target_fee > fee_buffer {
					return Err(FeeRateAdjustmentError::FeeBufferInsufficient {
						source: "estimated fee + coin selection surplus",
						available: fee_buffer,
						required: target_fee,
					});
				}
				Ok((target_fee, None))
			}
		} else {
			// No inputs (splice-out): fees paid from channel balance.
			let target_fee = estimate_transaction_fee(
				&[],
				&self.outputs,
				None,
				is_initiator,
				self.is_splice,
				target_feerate,
			);

			// Check that the channel balance can cover the withdrawal outputs plus fees.
			let value_removed: Amount = self.outputs.iter().map(|o| o.value).sum();
			let total_cost = target_fee
				.checked_add(value_removed)
				.ok_or(FeeRateAdjustmentError::FeeBufferOverflow)?;
			if total_cost > holder_balance {
				return Err(FeeRateAdjustmentError::FeeBufferInsufficient {
					source: "channel balance - withdrawal outputs",
					available: holder_balance.checked_sub(value_removed).unwrap_or(Amount::ZERO),
					required: target_fee,
				});
			}
			// Surplus goes back to the channel balance.
			Ok((target_fee, None))
		}
	}

	/// Adjusts the contribution for a different feerate, updating the change output, fee
	/// estimate, and feerate. Returns the adjusted contribution, or an error if the feerate
	/// can't be accommodated.
	fn at_feerate(
		mut self, feerate: FeeRate, holder_balance: Amount, is_initiator: bool,
	) -> Result<Self, FeeRateAdjustmentError> {
		let (new_estimated_fee, new_change) =
			self.compute_feerate_adjustment(feerate, holder_balance, is_initiator)?;
		let surplus = self.fee_buffer_surplus(new_estimated_fee, &new_change);
		match new_change {
			Some(value) => self.change_output.as_mut().unwrap().value = value,
			None => self.change_output = None,
		}
		self.value_added += surplus;
		self.estimated_fee = new_estimated_fee;
		self.feerate = feerate;
		Ok(self)
	}

	/// Adjusts the contribution's change output for the initiator's feerate.
	///
	/// When the acceptor has a pending contribution (from the quiescence tie-breaker scenario),
	/// the initiator's proposed feerate may differ from the feerate used during coin selection.
	/// This adjusts the change output so the acceptor pays their target fee at the target
	/// feerate.
	pub(super) fn for_acceptor_at_feerate(
		self, feerate: FeeRate, holder_balance: Amount,
	) -> Result<Self, FeeRateAdjustmentError> {
		self.at_feerate(feerate, holder_balance, false)
	}

	/// Adjusts the contribution's change output for the minimum RBF feerate.
	///
	/// When a pending splice exists with negotiated candidates and the contribution's feerate
	/// is below the minimum RBF feerate (25/24 of the previous feerate), this adjusts the
	/// change output so the initiator pays fees at the minimum RBF feerate.
	pub(super) fn for_initiator_at_feerate(
		self, feerate: FeeRate, holder_balance: Amount,
	) -> Result<Self, FeeRateAdjustmentError> {
		self.at_feerate(feerate, holder_balance, true)
	}

	/// Returns the net value at the given target feerate without mutating `self`.
	///
	/// This serves double duty: it checks feerate compatibility (returning `Err` if the feerate
	/// can't be accommodated) and computes the adjusted net value (returning `Ok` with the value
	/// accounting for the target feerate).
	fn net_value_at_feerate(
		&self, target_feerate: FeeRate, holder_balance: Amount, is_initiator: bool,
	) -> Result<SignedAmount, FeeRateAdjustmentError> {
		let (new_estimated_fee, new_change) =
			self.compute_feerate_adjustment(target_feerate, holder_balance, is_initiator)?;
		let surplus = self
			.fee_buffer_surplus(new_estimated_fee, &new_change)
			.to_signed()
			.expect("surplus does not exceed Amount::MAX_MONEY");
		let net_value = self
			.net_value_with_fee(new_estimated_fee)
			.checked_add(surplus)
			.expect("net_value + surplus does not overflow");
		Ok(net_value)
	}

	/// Returns the net value at the given target feerate without mutating `self`,
	/// assuming acceptor fee responsibility.
	pub(super) fn net_value_for_acceptor_at_feerate(
		&self, target_feerate: FeeRate, holder_balance: Amount,
	) -> Result<SignedAmount, FeeRateAdjustmentError> {
		self.net_value_at_feerate(target_feerate, holder_balance, false)
	}

	/// Returns the net value at the given target feerate without mutating `self`,
	/// assuming initiator fee responsibility.
	pub(super) fn net_value_for_initiator_at_feerate(
		&self, target_feerate: FeeRate, holder_balance: Amount,
	) -> Result<SignedAmount, FeeRateAdjustmentError> {
		self.net_value_at_feerate(target_feerate, holder_balance, true)
	}

	/// Returns the fee buffer surplus when a change output is removed.
	///
	/// The fee buffer is the actual amount available for fees from inputs: total input value
	/// minus value_added and output values. This includes both the weight-based estimated_fee
	/// and any coin selection surplus (dust burned to fees). When the change output is removed,
	/// the fee buffer may exceed the new fee; the surplus is returned so it can be redirected
	/// to value_added rather than being burned as excess fees.
	///
	/// Returns [`Amount::ZERO`] when there are no inputs or the change output is kept.
	fn fee_buffer_surplus(&self, new_estimated_fee: Amount, new_change: &Option<Amount>) -> Amount {
		if !self.inputs.is_empty() && new_change.is_none() {
			let total_input_value: Amount = self.inputs.iter().map(|i| i.utxo.output.value).sum();
			let output_values: Amount = self.outputs.iter().map(|o| o.value).sum();
			let fee_buffer = total_input_value - self.value_added - output_values;
			debug_assert!(fee_buffer >= new_estimated_fee);
			fee_buffer - new_estimated_fee
		} else {
			Amount::ZERO
		}
	}

	/// The net value contributed to a channel by the splice. If negative, more value will be
	/// spliced out than spliced in. Fees will be deducted from the expected splice-out amount
	/// if no inputs were included.
	pub fn net_value(&self) -> SignedAmount {
		self.net_value_with_fee(self.estimated_fee)
	}

	/// Computes the net value using the given `estimated_fee` for the splice-out (no inputs)
	/// case. For splice-in, fees are paid by inputs so `estimated_fee` is not deducted.
	fn net_value_with_fee(&self, estimated_fee: Amount) -> SignedAmount {
		let unpaid_fees = if self.inputs.is_empty() { estimated_fee } else { Amount::ZERO }
			.to_signed()
			.expect("estimated_fee is validated to not exceed Amount::MAX_MONEY");
		let value_added = self
			.value_added
			.to_signed()
			.expect("value_added is validated to not exceed Amount::MAX_MONEY");
		let value_removed = self
			.outputs
			.iter()
			.map(|txout| txout.value)
			.sum::<Amount>()
			.to_signed()
			.expect("value_removed is validated to not exceed Amount::MAX_MONEY");

		let contribution_amount = value_added - value_removed;
		contribution_amount
			.checked_sub(unpaid_fees)
			.expect("all amounts are validated to not exceed Amount::MAX_MONEY")
	}
}

/// An input to contribute to a channel's funding transaction either when using the v2 channel
/// establishment protocol or when splicing.
pub type FundingTxInput = crate::util::wallet_utils::ConfirmedUtxo;

#[cfg(test)]
mod tests {
	use super::{
		estimate_transaction_fee, FeeRateAdjustmentError, FundingContribution,
		FundingContributionError, FundingTemplate, FundingTxInput, PriorContribution,
	};
	use crate::chain::ClaimId;
	use crate::util::wallet_utils::{CoinSelection, CoinSelectionSourceSync, Input};
	use bitcoin::hashes::Hash;
	use bitcoin::transaction::{Transaction, TxOut, Version};
	use bitcoin::{Amount, FeeRate, Psbt, ScriptBuf, SignedAmount, WPubkeyHash};

	#[test]
	#[rustfmt::skip]
	fn test_estimate_transaction_fee() {
		let one_input = [funding_input_sats(1_000)];
		let two_inputs = [funding_input_sats(1_000), funding_input_sats(1_000)];

		// 2 inputs, initiator, 2000 sat/kw feerate
		assert_eq!(
			estimate_transaction_fee(&two_inputs, &[], None, true, false, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 1512 } else { 1516 }),
		);

		// higher feerate
		assert_eq!(
			estimate_transaction_fee(&two_inputs, &[], None, true, false, FeeRate::from_sat_per_kwu(3000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 2268 } else { 2274 }),
		);

		// only 1 input
		assert_eq!(
			estimate_transaction_fee(&one_input, &[], None, true, false, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 970 } else { 972 }),
		);

		// 0 inputs
		assert_eq!(
			estimate_transaction_fee(&[], &[], None, true, false, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(428),
		);

		// not initiator
		assert_eq!(
			estimate_transaction_fee(&[], &[], None, false, false, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(0),
		);

		// splice initiator
		assert_eq!(
			estimate_transaction_fee(&one_input, &[], None, true, true, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 1736 } else { 1740 }),
		);

		// splice acceptor
		assert_eq!(
			estimate_transaction_fee(&one_input, &[], None, false, true, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 542 } else { 544 }),
		);

		// splice initiator, 1 input, 1 output
		let outputs = [funding_output_sats(500)];
		assert_eq!(
			estimate_transaction_fee(&one_input, &outputs, None, true, true, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 1984 } else { 1988 }),
		);

		// splice acceptor, 1 input, 1 output
		assert_eq!(
			estimate_transaction_fee(&one_input, &outputs, None, false, true, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 790 } else { 792 }),
		);

		// splice initiator, 1 input, 1 output, 1 change via change_output parameter
		let change = funding_output_sats(1_000);
		assert_eq!(
			estimate_transaction_fee(&one_input, &outputs, Some(&change), true, true, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 2232 } else { 2236 }),
		);

		// splice acceptor, 1 input, 1 output, 1 change via change_output parameter
		assert_eq!(
			estimate_transaction_fee(&one_input, &outputs, Some(&change), false, true, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 1038 } else { 1040 }),
		);
	}

	#[rustfmt::skip]
	fn funding_input_sats(input_value_sats: u64) -> FundingTxInput {
		let prevout = TxOut {
			value: Amount::from_sat(input_value_sats),
			script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
		};
		let prevtx = Transaction {
			input: vec![], output: vec![prevout],
			version: Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
		};

		FundingTxInput::new_p2wpkh(prevtx, 0).unwrap()
	}

	fn funding_output_sats(output_value_sats: u64) -> TxOut {
		TxOut {
			value: Amount::from_sat(output_value_sats),
			script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
		}
	}

	#[test]
	#[rustfmt::skip]
	fn test_check_v2_funding_inputs_sufficient() {
		// positive case, inputs well over intended contribution
		{
			let expected_fee = if cfg!(feature = "grind_signatures") { 2278 } else { 2284 };
			let contribution = FundingContribution {
				value_added: Amount::from_sat(220_000),
				estimated_fee: Amount::from_sat(expected_fee),
				inputs: vec![
					funding_input_sats(200_000),
					funding_input_sats(100_000),
				],
				outputs: vec![],
				change_output: None,
				is_splice: true,
				feerate: FeeRate::from_sat_per_kwu(2000),
				max_feerate: FeeRate::MAX,
			};
			assert!(contribution.validate().is_ok());
			assert_eq!(contribution.net_value(), contribution.value_added.to_signed().unwrap());
		}

		// Net splice-in
		{
			let expected_fee = if cfg!(feature = "grind_signatures") { 2526 } else { 2532 };
			let contribution = FundingContribution {
				value_added: Amount::from_sat(220_000),
				estimated_fee: Amount::from_sat(expected_fee),
				inputs: vec![
					funding_input_sats(200_000),
					funding_input_sats(100_000),
				],
				outputs: vec![
					funding_output_sats(200_000),
				],
				change_output: None,
				is_splice: true,
				feerate: FeeRate::from_sat_per_kwu(2000),
				max_feerate: FeeRate::MAX,
			};
			assert!(contribution.validate().is_ok());
			assert_eq!(contribution.net_value(), SignedAmount::from_sat(220_000 - 200_000));
		}

		// Net splice-out
		{
			let expected_fee = if cfg!(feature = "grind_signatures") { 2526 } else { 2532 };
			let contribution = FundingContribution {
				value_added: Amount::from_sat(220_000),
				estimated_fee: Amount::from_sat(expected_fee),
				inputs: vec![
					funding_input_sats(200_000),
					funding_input_sats(100_000),
				],
				outputs: vec![
					funding_output_sats(400_000),
				],
				change_output: None,
				is_splice: true,
				feerate: FeeRate::from_sat_per_kwu(2000),
				max_feerate: FeeRate::MAX,
			};
			assert!(contribution.validate().is_ok());
			assert_eq!(contribution.net_value(), SignedAmount::from_sat(220_000 - 400_000));
		}

		// Net splice-out, inputs insufficient to cover fees
		{
			let expected_fee = if cfg!(feature = "grind_signatures") { 113670 } else { 113940 };
			let contribution = FundingContribution {
				value_added: Amount::from_sat(220_000),
				estimated_fee: Amount::from_sat(expected_fee),
				inputs: vec![
					funding_input_sats(200_000),
					funding_input_sats(100_000),
				],
				outputs: vec![
					funding_output_sats(400_000),
				],
				change_output: None,
				is_splice: true,
				feerate: FeeRate::from_sat_per_kwu(90000),
				max_feerate: FeeRate::MAX,
			};
			assert_eq!(
				contribution.validate(),
				Err(format!(
					"Total input amount 0.00300000 BTC is lower than needed for splice-in contribution 0.00220000 BTC, considering fees of {}. Need more inputs.",
					Amount::from_sat(expected_fee),
				)),
			);
		}

		// negative case, inputs clearly insufficient
		{
			let expected_fee = if cfg!(feature = "grind_signatures") { 1736 } else { 1740 };
			let contribution = FundingContribution {
				value_added: Amount::from_sat(220_000),
				estimated_fee: Amount::from_sat(expected_fee),
				inputs: vec![
					funding_input_sats(100_000),
				],
				outputs: vec![],
				change_output: None,
				is_splice: true,
				feerate: FeeRate::from_sat_per_kwu(2000),
				max_feerate: FeeRate::MAX,
			};
			assert_eq!(
				contribution.validate(),
				Err(format!(
					"Total input amount 0.00100000 BTC is lower than needed for splice-in contribution 0.00220000 BTC, considering fees of {}. Need more inputs.",
					Amount::from_sat(expected_fee),
				)),
			);
		}

		// barely covers
		{
			let expected_fee = if cfg!(feature = "grind_signatures") { 2278 } else { 2284 };
			let contribution = FundingContribution {
				value_added: Amount::from_sat(300_000 - expected_fee - 20),
				estimated_fee: Amount::from_sat(expected_fee),
				inputs: vec![
					funding_input_sats(200_000),
					funding_input_sats(100_000),
				],
				outputs: vec![],
				change_output: None,
				is_splice: true,
				feerate: FeeRate::from_sat_per_kwu(2000),
				max_feerate: FeeRate::MAX,
			};
			assert!(contribution.validate().is_ok());
			assert_eq!(contribution.net_value(), contribution.value_added.to_signed().unwrap());
		}

		// higher fee rate, does not cover
		{
			let expected_fee = if cfg!(feature = "grind_signatures") { 2506 } else { 2513 };
			let contribution = FundingContribution {
				value_added: Amount::from_sat(298032),
				estimated_fee: Amount::from_sat(expected_fee),
				inputs: vec![
					funding_input_sats(200_000),
					funding_input_sats(100_000),
				],
				outputs: vec![],
				change_output: None,
				is_splice: true,
				feerate: FeeRate::from_sat_per_kwu(2200),
				max_feerate: FeeRate::MAX,
			};
			assert_eq!(
				contribution.validate(),
				Err(format!(
					"Total input amount 0.00300000 BTC is lower than needed for splice-in contribution 0.00298032 BTC, considering fees of {}. Need more inputs.",
					Amount::from_sat(expected_fee),
				)),
			);
		}

		// barely covers, less fees (not a splice)
		{
			let expected_fee = if cfg!(feature = "grind_signatures") { 1512 } else { 1516 };
			let contribution = FundingContribution {
				value_added: Amount::from_sat(300_000 - expected_fee - 20),
				estimated_fee: Amount::from_sat(expected_fee),
				inputs: vec![
					funding_input_sats(200_000),
					funding_input_sats(100_000),
				],
				outputs: vec![],
				change_output: None,
				is_splice: false,
				feerate: FeeRate::from_sat_per_kwu(2000),
				max_feerate: FeeRate::MAX,
			};
			assert!(contribution.validate().is_ok());
			assert_eq!(contribution.net_value(), contribution.value_added.to_signed().unwrap());
		}
	}

	struct UnreachableWallet;

	impl CoinSelectionSourceSync for UnreachableWallet {
		fn select_confirmed_utxos(
			&self, _claim_id: Option<ClaimId>, _must_spend: Vec<Input>, _must_pay_to: &[TxOut],
			_target_feerate_sat_per_1000_weight: u32, _max_tx_weight: u64,
		) -> Result<CoinSelection, ()> {
			unreachable!("should not reach coin selection")
		}
		fn sign_psbt(&self, _psbt: Psbt) -> Result<Transaction, ()> {
			unreachable!("should not reach signing")
		}
	}

	#[test]
	fn test_build_funding_contribution_validates_max_money() {
		let over_max = Amount::MAX_MONEY + Amount::from_sat(1);
		let feerate = FeeRate::from_sat_per_kwu(2000);

		// splice_in_sync with value_added > MAX_MONEY
		{
			let template = FundingTemplate::new(None, None, None);
			assert!(matches!(
				template.splice_in_sync(over_max, feerate, feerate, UnreachableWallet),
				Err(FundingContributionError::InvalidSpliceValue),
			));
		}

		// splice_out with single output value > MAX_MONEY
		{
			let template = FundingTemplate::new(None, None, None);
			let outputs = vec![funding_output_sats(over_max.to_sat())];
			assert!(matches!(
				template.splice_out(outputs, feerate, feerate),
				Err(FundingContributionError::InvalidSpliceValue),
			));
		}

		// splice_out with multiple outputs summing > MAX_MONEY
		{
			let template = FundingTemplate::new(None, None, None);
			let half_over = Amount::MAX_MONEY / 2 + Amount::from_sat(1);
			let outputs = vec![
				funding_output_sats(half_over.to_sat()),
				funding_output_sats(half_over.to_sat()),
			];
			assert!(matches!(
				template.splice_out(outputs, feerate, feerate),
				Err(FundingContributionError::InvalidSpliceValue),
			));
		}

		// splice_in_and_out_sync with value_added > MAX_MONEY
		{
			let template = FundingTemplate::new(None, None, None);
			let outputs = vec![funding_output_sats(1_000)];
			assert!(matches!(
				template.splice_in_and_out_sync(
					over_max,
					outputs,
					feerate,
					feerate,
					UnreachableWallet
				),
				Err(FundingContributionError::InvalidSpliceValue),
			));
		}

		// splice_in_and_out_sync with output sum > MAX_MONEY
		{
			let template = FundingTemplate::new(None, None, None);
			let outputs = vec![funding_output_sats(over_max.to_sat())];
			assert!(matches!(
				template.splice_in_and_out_sync(
					Amount::from_sat(1_000),
					outputs,
					feerate,
					feerate,
					UnreachableWallet,
				),
				Err(FundingContributionError::InvalidSpliceValue),
			));
		}
	}

	#[test]
	fn test_build_funding_contribution_validates_feerate_range() {
		let low = FeeRate::from_sat_per_kwu(1000);
		let high = FeeRate::from_sat_per_kwu(2000);

		// min_feerate > max_feerate is rejected
		{
			let template = FundingTemplate::new(None, None, None);
			assert!(matches!(
				template.splice_in_sync(Amount::from_sat(10_000), high, low, UnreachableWallet),
				Err(FundingContributionError::FeeRateExceedsMaximum { .. }),
			));
		}

		// min_feerate < min_rbf_feerate is rejected
		{
			let template = FundingTemplate::new(None, Some(high), None);
			assert!(matches!(
				template.splice_in_sync(
					Amount::from_sat(10_000),
					low,
					FeeRate::MAX,
					UnreachableWallet
				),
				Err(FundingContributionError::FeeRateBelowRbfMinimum { .. }),
			));
		}
	}

	#[test]
	fn test_for_acceptor_at_feerate_higher_change_adjusted() {
		// Splice-in: higher target feerate reduces the change output.
		// The fee overestimates (with is_initiator=true) by including common TX fields, shared
		// output, and shared input weight. So we need a sufficiently high target feerate for the
		// acceptor's target fee to exceed the original fee estimate, causing the change to decrease.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(6000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		// Fee estimate computed as initiator (overestimate), including change output weight.
		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs: inputs.clone(),
			outputs: vec![],
			change_output: Some(change.clone()),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let net_value_before = contribution.net_value();
		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX).unwrap();

		// Target fee at target feerate for acceptor (is_initiator=false), including change weight.
		let expected_target_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), false, true, target_feerate);
		let expected_change = estimated_fee + Amount::from_sat(10_000) - expected_target_fee;

		assert_eq!(contribution.estimated_fee, expected_target_fee);
		assert!(contribution.change_output.is_some());
		assert_eq!(contribution.change_output.as_ref().unwrap().value, expected_change);
		assert!(expected_change < Amount::from_sat(10_000)); // Change reduced
		assert_eq!(contribution.net_value(), net_value_before);
	}

	#[test]
	fn test_for_acceptor_at_feerate_lower_rejected_too_low() {
		// Splice-in: target feerate below our minimum is rejected as FeeRateTooLow.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(1000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeRateTooLow { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_change_removed() {
		// Splice-in: feerate high enough that change drops below dust and is removed,
		// but the fee buffer (estimated_fee + change) still covers the fee without the change output.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(7000);
		let value_added = Amount::from_sat(50_000);
		let change_value = Amount::from_sat(500);

		// Compute estimated_fee first (weight-based, independent of input value).
		let dummy_inputs = vec![funding_input_sats(1)];
		let change = funding_output_sats(change_value.to_sat());
		let estimated_fee = estimate_transaction_fee(
			&dummy_inputs,
			&[],
			Some(&change),
			true,
			true,
			original_feerate,
		);

		// Realistic input: value_added + estimated_fee + change (what coin selection produces).
		let input_value = value_added + estimated_fee + change_value;
		let inputs = vec![funding_input_sats(input_value.to_sat())];
		let change = funding_output_sats(change_value.to_sat());

		let contribution = FundingContribution {
			value_added,
			estimated_fee,
			inputs: inputs.clone(),
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let net_value_before = contribution.net_value();
		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX).unwrap();

		// Change should be removed; estimated_fee updated to no-change target fee.
		assert!(contribution.change_output.is_none());
		let expected_fee_no_change =
			estimate_transaction_fee(&inputs, &[], None, false, true, target_feerate);
		assert_eq!(contribution.estimated_fee, expected_fee_no_change);
		// The surplus (old fee buffer - new fee) goes to value_added, increasing net_value.
		let surplus = estimated_fee + change_value - expected_fee_no_change;
		assert_eq!(contribution.net_value(), net_value_before + surplus.to_signed().unwrap());
	}

	#[test]
	fn test_for_acceptor_at_feerate_too_high_rejected() {
		// Splice-in: feerate so high that even without change, the fee can't be covered.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(100_000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(500);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeBufferInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_splice_out_sufficient() {
		// Splice-out (no inputs): the fee estimate from the is_initiator=true overestimate covers
		// the acceptor's target fee at a moderately higher target feerate.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let outputs = vec![funding_output_sats(50_000)];

		let estimated_fee =
			estimate_transaction_fee(&[], &outputs, None, true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::ZERO,
			estimated_fee,
			inputs: vec![],
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX).unwrap();
		// estimated_fee is updated to the target fee; surplus goes back to channel balance.
		let expected_target_fee =
			estimate_transaction_fee(&[], &outputs, None, false, true, target_feerate);
		assert_eq!(contribution.estimated_fee, expected_target_fee);
		assert!(expected_target_fee <= estimated_fee);
	}

	#[test]
	fn test_for_acceptor_at_feerate_splice_out_insufficient() {
		// Splice-out: channel balance too small for outputs + target fee at high target feerate.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(50_000);
		let outputs = vec![funding_output_sats(50_000)];

		let estimated_fee =
			estimate_transaction_fee(&[], &outputs, None, true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::ZERO,
			estimated_fee,
			inputs: vec![],
			outputs,
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		// Balance of 55,000 sats can't cover outputs (50,000) + target_fee at 50k sat/kwu.
		let holder_balance = Amount::from_sat(55_000);
		let result = contribution.for_acceptor_at_feerate(target_feerate, holder_balance);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeBufferInsufficient { .. })));
	}

	#[test]
	fn test_net_value_for_acceptor_at_feerate_splice_in() {
		// Splice-in: net_value_for_acceptor_at_feerate returns the same value as net_value() since
		// splice-in fees are paid by inputs, not from channel balance.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		// For splice-in with change that stays above dust, the surplus is absorbed by the change
		// output so net_value_for_acceptor_at_feerate equals net_value.
		let net_at_feerate =
			contribution.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX).unwrap();
		assert_eq!(net_at_feerate, contribution.net_value());
		assert_eq!(net_at_feerate, Amount::from_sat(50_000).to_signed().unwrap());
	}

	#[test]
	fn test_net_value_for_acceptor_at_feerate_splice_out() {
		// Splice-out: net_value_for_acceptor_at_feerate returns the adjusted value using the target fee
		// at the target feerate.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let outputs = vec![funding_output_sats(50_000)];

		let estimated_fee =
			estimate_transaction_fee(&[], &outputs, None, true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::ZERO,
			estimated_fee,
			inputs: vec![],
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let net_at_feerate =
			contribution.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX).unwrap();

		// The target fee at target feerate should be less than the initiator's fee estimate.
		let target_fee = estimate_transaction_fee(&[], &outputs, None, false, true, target_feerate);
		let expected_net = SignedAmount::ZERO
			- Amount::from_sat(50_000).to_signed().unwrap()
			- target_fee.to_signed().unwrap();
		assert_eq!(net_at_feerate, expected_net);

		// Should be less negative than net_value() which uses the higher fee estimate.
		assert!(net_at_feerate > contribution.net_value());
	}

	#[test]
	fn test_net_value_for_acceptor_at_feerate_does_not_mutate() {
		// Verify net_value_for_acceptor_at_feerate does not modify the contribution.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(5000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let net_before = contribution.net_value();
		let fee_before = contribution.estimated_fee;
		let change_before = contribution.change_output.as_ref().unwrap().value;

		let _ = contribution.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX);

		// Nothing should have changed.
		assert_eq!(contribution.net_value(), net_before);
		assert_eq!(contribution.estimated_fee, fee_before);
		assert_eq!(contribution.change_output.as_ref().unwrap().value, change_before);
	}

	#[test]
	fn test_net_value_for_acceptor_at_feerate_too_high() {
		// net_value_for_acceptor_at_feerate returns Err when feerate can't be accommodated.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(100_000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(500);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let result = contribution.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeBufferInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_exceeds_max_rejected() {
		// Splice-in: target feerate exceeds max_feerate and target fee exceeds the fee buffer,
		// so the adjustment is rejected as FeeRateTooHigh.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let max_feerate = FeeRate::from_sat_per_kwu(3000);
		let target_feerate = FeeRate::from_sat_per_kwu(100_000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeRateTooHigh { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_exceeds_max_allowed() {
		// Splice-in: target feerate exceeds max_feerate but the acceptor's target fee
		// (is_initiator=false at target) is less than the fee buffer (is_initiator=true at
		// original feerate). This works because the initiator fee estimate includes ~598 WU of
		// extra weight (common TX fields, funding output, shared input) that the acceptor
		// doesn't pay for, so the fee buffer is ~2.5x larger than the acceptor's target fee at
		// the same feerate.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let max_feerate = FeeRate::from_sat_per_kwu(3000);
		let target_feerate = FeeRate::from_sat_per_kwu(4000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change.clone()),
			feerate: original_feerate,
			max_feerate,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(result.is_ok());
		let adjusted = result.unwrap();

		// The acceptor's target fee at target (4000, is_initiator=false) is less than the
		// fee estimate at original (2000, is_initiator=true) due to the ~2.5x weight ratio,
		// so change increases despite the higher feerate.
		assert!(adjusted.change_output.is_some());
		assert!(adjusted.change_output.as_ref().unwrap().value > Amount::from_sat(10_000));
	}

	#[test]
	fn test_for_acceptor_at_feerate_within_range() {
		// Splice-in: target feerate is between min and max, so the min/max checks
		// don't interfere and the normal adjustment logic applies.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let max_feerate = FeeRate::from_sat_per_kwu(5000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(result.is_ok());
		let adjusted = result.unwrap();

		// At a higher target feerate, the target fee increases so change should decrease
		// (or stay the same if the fee estimate absorbs the difference).
		// The key assertion is that the adjustment succeeds with a valid change output.
		assert!(adjusted.change_output.is_some());
	}

	#[test]
	fn test_for_acceptor_at_feerate_no_change_shortfall_from_value_added() {
		// Inputs present, no change output. Higher target feerate makes target_fee > estimated_fee.
		// With realistic inputs (no coin selection surplus), the fee buffer is just estimated_fee,
		// so the shortfall cannot be absorbed and the contribution is dropped.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(20_000);
		let value_added = Amount::from_sat(50_000);

		// Compute estimated_fee first (weight-based, independent of input value).
		let dummy_inputs = vec![funding_input_sats(1)];
		let estimated_fee =
			estimate_transaction_fee(&dummy_inputs, &[], None, true, true, original_feerate);

		// Realistic input: value_added + estimated_fee (what coin selection produces, no surplus).
		let inputs = vec![funding_input_sats((value_added + estimated_fee).to_sat())];
		let target_fee = estimate_transaction_fee(&inputs, &[], None, false, true, target_feerate);

		// Verify our setup: target_fee > estimated_fee (shortfall exists) and the fee buffer
		// (estimated_fee, with no coin selection surplus) cannot cover it.
		assert!(target_fee > estimated_fee);

		let contribution = FundingContribution {
			value_added,
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeBufferInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_no_change_insufficient() {
		// Inputs present, no change output. The target feerate is so high that the fee buffer
		// (total input value minus value_added) cannot cover the target fee.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(20_000);
		let value_added = Amount::from_sat(1);

		// Compute estimated_fee first (weight-based, independent of input value).
		let dummy_inputs = vec![funding_input_sats(1)];
		let estimated_fee =
			estimate_transaction_fee(&dummy_inputs, &[], None, true, true, original_feerate);

		// Realistic input: value_added + estimated_fee (no surplus).
		let inputs = vec![funding_input_sats((value_added + estimated_fee).to_sat())];
		let target_fee = estimate_transaction_fee(&inputs, &[], None, false, true, target_feerate);
		assert!(target_fee > estimated_fee);

		let contribution = FundingContribution {
			value_added,
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeBufferInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_no_change_surplus_below_dust() {
		// Inputs present, no change output. The acceptor built their contribution at a low
		// feerate as if they were the initiator (including common TX fields in estimated_fee).
		// The initiator proposes a ~3x higher feerate. At that rate, the acceptor's target fee
		// (only their personal input weight) nearly matches the original fee estimate, leaving a
		// small surplus below the dust limit.
		let original_feerate = FeeRate::from_sat_per_kwu(1000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let inputs = vec![funding_input_sats(100_000)];

		// estimated_fee includes common TX fields (is_initiator=true) at the original feerate.
		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], None, true, true, original_feerate);

		// target_fee only includes the acceptor's contributed weight (is_initiator=false) at the
		// higher target feerate.
		let target_fee = estimate_transaction_fee(&inputs, &[], None, false, true, target_feerate);

		// Verify our setup: surplus is positive and below the P2WPKH dust limit (294 sats).
		assert!(estimated_fee > target_fee);
		let dust_limit = ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()).minimal_non_dust();
		assert!(estimated_fee - target_fee < dust_limit);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX);
		assert!(result.is_ok());
		let adjusted = result.unwrap();
		assert!(adjusted.change_output.is_none());
		assert_eq!(adjusted.estimated_fee, target_fee);
	}

	#[test]
	fn test_for_acceptor_at_feerate_no_change_surplus_absorbed() {
		// Inputs, no change. The estimated_fee (is_initiator=true) far exceeds the acceptor's
		// target fee (is_initiator=false). The surplus stays in the channel balance rather than
		// being burned as excess fees.
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let value_added = Amount::from_sat(50_000);

		// Compute estimated_fee first (weight-based, independent of input value).
		let dummy_inputs = vec![funding_input_sats(1)];
		let estimated_fee = estimate_transaction_fee(&dummy_inputs, &[], None, true, true, feerate);

		// Realistic input: value_added + estimated_fee (no surplus).
		let inputs = vec![funding_input_sats((value_added + estimated_fee).to_sat())];

		// Initiator fee estimate includes common TX fields + shared output + shared input weight,
		// making it ~3x the acceptor's target fee at the same feerate.
		let target_fee = estimate_transaction_fee(&inputs, &[], None, false, true, feerate);

		let contribution = FundingContribution {
			value_added,
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		// target == min feerate, so FeeRateTooLow check passes.
		// The surplus (estimated_fee - target_fee) goes to value_added (shared output).
		let net_value_before = contribution.net_value();
		let result = contribution.for_acceptor_at_feerate(feerate, Amount::MAX);
		assert!(result.is_ok());
		let adjusted = result.unwrap();
		assert!(adjusted.change_output.is_none());
		assert_eq!(adjusted.estimated_fee, target_fee);
		let surplus = estimated_fee - target_fee;
		assert_eq!(adjusted.value_added, value_added + surplus);
		assert_eq!(adjusted.net_value(), net_value_before + surplus.to_signed().unwrap());
	}

	#[test]
	fn test_for_acceptor_at_feerate_fee_buffer_overflow() {
		// Construct a contribution with estimated_fee and change values that overflow Amount.
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let inputs = vec![funding_input_sats(100_000)];

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee: Amount::MAX,
			inputs,
			outputs: vec![],
			change_output: Some(funding_output_sats(1)),
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let result = contribution.for_acceptor_at_feerate(feerate, Amount::MAX);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeBufferOverflow)));
	}

	#[test]
	fn test_for_acceptor_at_feerate_splice_out_balance_insufficient() {
		// Splice-out: channel balance too small to cover outputs + target fee.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let outputs = vec![funding_output_sats(50_000)];

		let estimated_fee =
			estimate_transaction_fee(&[], &outputs, None, true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::ZERO,
			estimated_fee,
			inputs: vec![],
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		// Balance of 40,000 sats is less than outputs (50,000) + target_fee.
		let holder_balance = Amount::from_sat(40_000);
		let result = contribution.for_acceptor_at_feerate(target_feerate, holder_balance);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeBufferInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_splice_out_balance_sufficient() {
		// Splice-out: channel balance large enough to cover outputs + target fee.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let outputs = vec![funding_output_sats(50_000)];

		let estimated_fee =
			estimate_transaction_fee(&[], &outputs, None, true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::ZERO,
			estimated_fee,
			inputs: vec![],
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		// Balance of 100,000 sats is more than outputs (50,000) + target_fee.
		let holder_balance = Amount::from_sat(100_000);
		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, holder_balance).unwrap();
		let expected_target_fee =
			estimate_transaction_fee(&[], &outputs, None, false, true, target_feerate);
		assert_eq!(contribution.estimated_fee, expected_target_fee);
	}

	#[test]
	fn test_net_value_for_acceptor_at_feerate_splice_out_balance_insufficient() {
		// Splice-out: net_value_for_acceptor_at_feerate returns Err when channel balance
		// is too small to cover outputs + target fee.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let outputs = vec![funding_output_sats(50_000)];

		let estimated_fee =
			estimate_transaction_fee(&[], &outputs, None, true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::ZERO,
			estimated_fee,
			inputs: vec![],
			outputs,
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		// Balance of 40,000 sats is less than outputs (50,000) + target_fee.
		let holder_balance = Amount::from_sat(40_000);
		let result = contribution.net_value_for_acceptor_at_feerate(target_feerate, holder_balance);
		assert!(matches!(result, Err(FeeRateAdjustmentError::FeeBufferInsufficient { .. })));
	}

	#[test]
	fn test_for_initiator_at_feerate_higher_fee_than_acceptor() {
		// Verify that the initiator fee estimate is higher than the acceptor estimate at the
		// same feerate, since the initiator pays for common fields + shared input/output.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let acceptor =
			contribution.clone().for_acceptor_at_feerate(target_feerate, Amount::MAX).unwrap();
		let initiator = contribution.for_initiator_at_feerate(target_feerate, Amount::MAX).unwrap();

		// Initiator pays more in fees (common fields + shared input/output weight).
		assert!(initiator.estimated_fee > acceptor.estimated_fee);
		// Initiator has less change remaining.
		assert!(
			initiator.change_output.as_ref().unwrap().value
				< acceptor.change_output.as_ref().unwrap().value
		);
		// Both have the adjusted feerate.
		assert_eq!(initiator.feerate, target_feerate);
		assert_eq!(acceptor.feerate, target_feerate);
	}

	#[test]
	fn test_rbf_sync_rejects_max_feerate_below_min_rbf_feerate() {
		// When the caller's max_feerate is below the minimum RBF feerate, rbf_sync should
		// return Err(()).
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let max_feerate = FeeRate::from_sat_per_kwu(2020);

		let prior = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee: Amount::from_sat(1_000),
			inputs: vec![funding_input_sats(100_000)],
			outputs: vec![],
			change_output: None,
			feerate: prior_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		// max_feerate (2020) < min_rbf_feerate (2025).
		let template = FundingTemplate::new(
			None,
			Some(min_rbf_feerate),
			Some(PriorContribution::new(prior, Amount::MAX)),
		);
		assert!(matches!(
			template.rbf_sync(max_feerate, UnreachableWallet),
			Err(FundingContributionError::FeeRateExceedsMaximum { .. }),
		));
	}

	#[test]
	fn test_rbf_sync_adjusts_prior_to_rbf_feerate() {
		// When the prior contribution's feerate is below the minimum RBF feerate and holder
		// balance is available, rbf_sync should adjust the prior to the RBF feerate.
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let max_feerate = FeeRate::from_sat_per_kwu(5000);

		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);
		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, prior_feerate);

		let prior = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: prior_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		let template = FundingTemplate::new(
			None,
			Some(min_rbf_feerate),
			Some(PriorContribution::new(prior, Amount::MAX)),
		);
		let contribution = template.rbf_sync(max_feerate, UnreachableWallet).unwrap();
		assert_eq!(contribution.feerate, min_rbf_feerate);
		assert_eq!(contribution.max_feerate, max_feerate);
	}

	/// A mock wallet that returns a single UTXO for coin selection.
	struct SingleUtxoWallet {
		utxo: FundingTxInput,
		change_output: Option<TxOut>,
	}

	impl CoinSelectionSourceSync for SingleUtxoWallet {
		fn select_confirmed_utxos(
			&self, _claim_id: Option<ClaimId>, _must_spend: Vec<Input>, _must_pay_to: &[TxOut],
			_target_feerate_sat_per_1000_weight: u32, _max_tx_weight: u64,
		) -> Result<CoinSelection, ()> {
			Ok(CoinSelection {
				confirmed_utxos: vec![self.utxo.clone()],
				change_output: self.change_output.clone(),
			})
		}
		fn sign_psbt(&self, _psbt: Psbt) -> Result<Transaction, ()> {
			unreachable!("should not reach signing")
		}
	}

	fn shared_input(value_sats: u64) -> Input {
		Input {
			outpoint: bitcoin::OutPoint::null(),
			previous_utxo: TxOut {
				value: Amount::from_sat(value_sats),
				script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
			},
			satisfaction_weight: 107,
		}
	}

	#[test]
	fn test_rbf_sync_unadjusted_splice_out_runs_coin_selection() {
		// When the prior contribution's feerate is below the minimum RBF feerate and no
		// holder balance is available, rbf_sync should run coin selection to add inputs that
		// cover the higher RBF fee.
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let withdrawal = funding_output_sats(20_000);

		let prior = FundingContribution {
			value_added: Amount::ZERO,
			estimated_fee: Amount::from_sat(500),
			inputs: vec![],
			outputs: vec![withdrawal.clone()],
			change_output: None,
			feerate: prior_feerate,
			max_feerate: prior_feerate,
			is_splice: true,
		};

		let template = FundingTemplate::new(
			Some(shared_input(100_000)),
			Some(min_rbf_feerate),
			Some(PriorContribution::new(prior, Amount::ZERO)),
		);

		let wallet = SingleUtxoWallet {
			utxo: funding_input_sats(50_000),
			change_output: Some(funding_output_sats(40_000)),
		};

		// rbf_sync should succeed and the contribution should have inputs from coin selection.
		let contribution = template.rbf_sync(FeeRate::MAX, &wallet).unwrap();
		assert_eq!(contribution.value_added, Amount::ZERO);
		assert!(!contribution.inputs.is_empty(), "coin selection should have added inputs");
		assert_eq!(contribution.outputs, vec![withdrawal]);
		assert_eq!(contribution.feerate, min_rbf_feerate);
	}

	#[test]
	fn test_rbf_sync_no_prior_fee_bump_only_runs_coin_selection() {
		// When there is no prior contribution (e.g., acceptor), rbf_sync should run coin
		// selection to add inputs for a fee-bump-only contribution.
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);

		let template =
			FundingTemplate::new(Some(shared_input(100_000)), Some(min_rbf_feerate), None);

		let wallet = SingleUtxoWallet {
			utxo: funding_input_sats(50_000),
			change_output: Some(funding_output_sats(45_000)),
		};

		let contribution = template.rbf_sync(FeeRate::MAX, &wallet).unwrap();
		assert_eq!(contribution.value_added, Amount::ZERO);
		assert!(!contribution.inputs.is_empty(), "coin selection should have added inputs");
		assert!(contribution.outputs.is_empty());
		assert_eq!(contribution.feerate, min_rbf_feerate);
	}

	#[test]
	fn test_rbf_sync_unadjusted_uses_callers_max_feerate() {
		// When the prior contribution's feerate is below the minimum RBF feerate and no
		// holder balance is available, rbf_sync should use the caller's max_feerate (not the
		// prior's) for the resulting contribution.
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let prior_max_feerate = FeeRate::from_sat_per_kwu(50_000);
		let callers_max_feerate = FeeRate::from_sat_per_kwu(10_000);
		let withdrawal = funding_output_sats(20_000);

		let prior = FundingContribution {
			value_added: Amount::ZERO,
			estimated_fee: Amount::from_sat(500),
			inputs: vec![],
			outputs: vec![withdrawal.clone()],
			change_output: None,
			feerate: FeeRate::from_sat_per_kwu(2000),
			max_feerate: prior_max_feerate,
			is_splice: true,
		};

		let template = FundingTemplate::new(
			Some(shared_input(100_000)),
			Some(min_rbf_feerate),
			Some(PriorContribution::new(prior, Amount::MAX)),
		);

		let wallet = SingleUtxoWallet {
			utxo: funding_input_sats(50_000),
			change_output: Some(funding_output_sats(40_000)),
		};

		let contribution = template.rbf_sync(callers_max_feerate, &wallet).unwrap();
		assert_eq!(
			contribution.max_feerate, callers_max_feerate,
			"should use caller's max_feerate, not prior's"
		);
	}

	#[test]
	fn test_splice_out_skips_coin_selection_during_rbf() {
		// When splice_out_sync is called on a template with min_rbf_feerate set (user
		// choosing a fresh splice-out instead of rbf_sync), coin selection should NOT run.
		// Fees come from the channel balance.
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let feerate = FeeRate::from_sat_per_kwu(2025);
		let withdrawal = funding_output_sats(20_000);

		let template =
			FundingTemplate::new(Some(shared_input(100_000)), Some(min_rbf_feerate), None);

		let contribution =
			template.splice_out(vec![withdrawal.clone()], feerate, FeeRate::MAX).unwrap();
		assert_eq!(contribution.value_added, Amount::ZERO);
		assert!(contribution.inputs.is_empty());
		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.outputs, vec![withdrawal]);
	}
}
