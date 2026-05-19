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

/// Error returned when a [`FundingContribution`] cannot be adjusted to a target feerate.
///
/// This is used when re-estimating an already-built contribution at a different feerate than the
/// one used during coin selection. That includes, for example, acceptor-side adjustment to the
/// initiator's chosen feerate during splice tie-break resolution, as well as initiator-side
/// adjustment to a minimum RBF feerate for later attempts.
///
/// Callers decide how to handle the failure. Depending on the context, they may drop the
/// contribution, wait and retry later, or abort the splice negotiation.
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
	/// - **input-backed contributions**: the original fee plus any change output value
	/// - **input-less contributions**: the channel balance minus the withdrawal outputs
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
	/// this error occurs after receiving [`Event::SpliceNegotiationFailed`], call
	/// [`ChannelManager::splice_channel`] again to get a fresh template.
	///
	/// [`Event::SpliceNegotiationFailed`]: crate::events::Event::SpliceNegotiationFailed
	/// [`ChannelManager::splice_channel`]: crate::ln::channelmanager::ChannelManager::splice_channel
	FeeRateBelowRbfMinimum {
		/// The requested feerate.
		feerate: FeeRate,
		/// The minimum RBF feerate.
		min_rbf_feerate: FeeRate,
	},
	/// The splice value is invalid (zero, empty outputs, duplicate inputs or outputs, exceeds the
	/// maximum money supply, or splices out more than the available channel balance).
	InvalidSpliceValue,
	/// An input's `prevtx` is too large to fit in a `tx_add_input` message.
	PrevTxTooLarge,
	/// Coin selection failed to find suitable inputs.
	CoinSelectionFailed,
	/// Coin selection is required but no coin selection source was provided.
	///
	/// This can also be returned when reusing a prior contribution would otherwise satisfy the
	/// request, but that prior contribution cannot be adjusted in-place to the requested feerate.
	/// For example, an input-backed prior contribution may no longer have enough fee buffer in its
	/// change output to absorb the higher fee. In that case, providing a coin selection source lets
	/// the builder fall back to fresh coin selection, which may replace the prior input set instead
	/// of preserving it.
	MissingCoinSelectionSource,
	/// The request cannot be satisfied using the manually selected inputs.
	ManuallySelectedInputsInsufficient,
	/// This template cannot build an RBF contribution.
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
				write!(
					f,
					"Invalid splice value (zero, empty, duplicate, exceeds limit, or overdraws balance)"
				)
			},
			FundingContributionError::PrevTxTooLarge => {
				write!(f, "Input prevtx is too large to fit in a tx_add_input message")
			},
			FundingContributionError::CoinSelectionFailed => {
				write!(f, "Coin selection failed to find suitable inputs")
			},
			FundingContributionError::MissingCoinSelectionSource => {
				write!(f, "Coin selection source required to build this contribution")
			},
			FundingContributionError::ManuallySelectedInputsInsufficient => {
				write!(f, "The request cannot be satisfied using the manually selected inputs")
			},
			FundingContributionError::NotRbfScenario => {
				write!(f, "This template cannot build an RBF contribution")
			},
		}
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
/// For a fresh splice (no pending splice to replace), either use the convenience methods
/// [`FundingTemplate::splice_in_sync`] and [`FundingTemplate::splice_out`] or start with
/// [`FundingTemplate::without_prior_contribution`] to compose a request manually.
///
/// The builder API supports adding value, adding withdrawal outputs, or both. Attach a wallet
/// when the request may need new wallet inputs; pure splice-out requests can be built without one
/// and pay fees from the channel balance.
///
/// # Replace By Fee (RBF)
///
/// When a pending splice exists that hasn't been locked yet, use
/// [`FundingTemplate::rbf_prior_contribution_sync`] (or
/// [`FundingTemplate::rbf_prior_contribution`] for async) to retry the stored prior contribution
/// at an RBF-compatible feerate. To amend that prior request before building, start from
/// [`FundingTemplate::with_prior_contribution`] instead.
///
/// Check [`FundingTemplate::min_rbf_feerate`] for the minimum feerate required (the greater of
/// the previous feerate + 25 sat/kwu and the spec's 25/24 rule). Use
/// [`FundingTemplate::prior_contribution`] to inspect the stored contribution before deciding
/// whether to reuse it or replace it with a fresh request via
/// [`FundingTemplate::without_prior_contribution`].
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

	/// The user's prior contribution from a previous splice negotiation on this channel.
	prior_contribution: Option<FundingContribution>,

	/// The portion of the user's balance that can be spliced out.
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
	spliceable_balance: Amount,
}

impl FundingTemplate {
	/// Constructs a [`FundingTemplate`] for a splice using the provided shared input.
	pub(super) fn new(
		shared_input: Option<Input>, min_rbf_feerate: Option<FeeRate>,
		prior_contribution: Option<FundingContribution>, spliceable_balance: Amount,
	) -> Self {
		Self { shared_input, min_rbf_feerate, prior_contribution, spliceable_balance }
	}

	/// Returns the minimum RBF feerate, if this template is for an RBF attempt.
	///
	/// When set, the `min_feerate` passed to the splice/builder methods must be at least this
	/// value.
	pub fn min_rbf_feerate(&self) -> Option<FeeRate> {
		self.min_rbf_feerate
	}

	/// Returns a reference to the prior contribution from a previous splice negotiation, if
	/// available.
	///
	/// Use this to inspect the prior contribution's current parameters (for example,
	/// [`FundingContribution::outputs`], [`FundingContribution::change_output`], and
	/// [`FundingContribution::net_value`]) before deciding
	/// whether to reuse it via [`FundingTemplate::rbf_prior_contribution`] or build a fresh
	/// contribution with different parameters using
	/// [`FundingTemplate::without_prior_contribution`].
	///
	/// Note: the returned contribution may reflect a different feerate than originally provided,
	/// as it may have been adjusted for RBF or for the counterparty's feerate when acting as
	/// the acceptor. This can change other parameters too; for example, the amount added to the
	/// channel may increase if the change output was removed to cover a higher fee.
	pub fn prior_contribution(&self) -> Option<&FundingContribution> {
		self.prior_contribution.as_ref()
	}

	/// Creates a [`FundingBuilder`] for constructing a contribution.
	///
	/// If a prior contribution is available, the builder starts from it automatically and builder
	/// mutations amend that prior request. Use [`FundingTemplate::without_prior_contribution`] to
	/// start empty instead.
	///
	/// `feerate` is the feerate used for fee estimation and, if wallet inputs are needed, coin
	/// selection. When [`FundingTemplate::min_rbf_feerate`] is set, it must be at least that value.
	/// `max_feerate` is the highest feerate we are willing to tolerate if we end up as the
	/// acceptor, and must be at least `feerate`.
	pub fn with_prior_contribution(self, feerate: FeeRate, max_feerate: FeeRate) -> FundingBuilder {
		FundingBuilder::new(self, feerate, max_feerate)
	}

	/// Creates a [`FundingBuilder`] for constructing a contribution without using any prior
	/// contribution.
	///
	/// `feerate` and `max_feerate` have the same meaning as in
	/// [`FundingTemplate::with_prior_contribution`]. This is useful when an RBF template carries a
	/// prior contribution but the caller wants to replace, rather than amend, that request.
	pub fn without_prior_contribution(
		mut self, feerate: FeeRate, max_feerate: FeeRate,
	) -> FundingBuilder {
		self.prior_contribution.take();
		FundingBuilder::new(self, feerate, max_feerate)
	}

	/// Creates a [`FundingContribution`] for adding funds to a channel.
	///
	/// This is a convenience wrapper around [`FundingTemplate::with_prior_contribution`]. As a
	/// result, if this template carries a prior contribution, `value_added` is added on top of the
	/// amount that prior request was already adding to the channel instead of replacing it. Use
	/// [`FundingTemplate::without_prior_contribution`] if you want to replace the prior request
	/// instead.
	///
	/// `value_added` is the amount of additional value to add to the channel. `min_feerate` is the
	/// feerate used for fee estimation and, if needed, coin selection; when
	/// [`FundingTemplate::min_rbf_feerate`] is set, it must be at least that value. `max_feerate` is
	/// the highest feerate we are willing to tolerate if we end up as the acceptor, and must be at
	/// least `min_feerate`. `wallet` is only consulted if the request cannot be satisfied by
	/// reusing/amending the prior contribution. When this template carries a prior contribution,
	/// increasing its value may therefore re-run coin selection and yield a different input set than
	/// the prior contribution used. This is not supported when the prior contribution used manually
	/// selected inputs; use [`FundingTemplate::splice_in_inputs`] or
	/// [`FundingTemplate::without_prior_contribution`] in that case.
	pub async fn splice_in<W: CoinSelectionSource + MaybeSend>(
		self, value_added: Amount, min_feerate: FeeRate, max_feerate: FeeRate, wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		self.with_prior_contribution(min_feerate, max_feerate)
			.with_coin_selection_source(wallet)
			.add_value(value_added)?
			.build()
			.await
	}

	/// Creates a [`FundingContribution`] for adding funds to a channel.
	///
	/// This is the synchronous variant of [`FundingTemplate::splice_in`]; `value_added`,
	/// `min_feerate`, `max_feerate`, and `wallet` have the same meaning, including the restriction
	/// on prior contributions with manually selected inputs.
	pub fn splice_in_sync<W: CoinSelectionSourceSync>(
		self, value_added: Amount, min_feerate: FeeRate, max_feerate: FeeRate, wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		self.with_prior_contribution(min_feerate, max_feerate)
			.with_coin_selection_source_sync(wallet)
			.add_value(value_added)?
			.build()
	}

	/// Creates a [`FundingContribution`] for adding funds to a channel using manually selected
	/// inputs.
	///
	/// This is a convenience wrapper around [`FundingTemplate::with_prior_contribution`] with no
	/// wallet attached. Each input is fully consumed with no change output, so the amount added to
	/// the channel is derived from the total input value minus the estimated fee.
	///
	/// When a prior contribution with manually selected inputs is present, `inputs` are appended to
	/// the prior [`FundingContribution::inputs`] instead of replacing them. Use
	/// [`FundingTemplate::without_prior_contribution`] if you want to replace the prior request
	/// instead. If the template carries a coin-selected prior contribution, manual inputs are
	/// incompatible and this method returns [`FundingContributionError::InvalidSpliceValue`].
	///
	/// `inputs` are the additional manually selected inputs to fully consume. `min_feerate` is the
	/// feerate used for fee estimation and must be at least [`FundingTemplate::min_rbf_feerate`]
	/// when that is set. `max_feerate` is the highest feerate we are willing to tolerate if we end
	/// up as the acceptor, and must be at least `min_feerate`.
	pub fn splice_in_inputs(
		self, inputs: Vec<FundingTxInput>, min_feerate: FeeRate, max_feerate: FeeRate,
	) -> Result<FundingContribution, FundingContributionError> {
		self.with_prior_contribution(min_feerate, max_feerate).add_inputs(inputs)?.build()
	}

	/// Creates a [`FundingContribution`] for removing funds from a channel.
	///
	/// This is a convenience wrapper around [`FundingTemplate::with_prior_contribution`] with no
	/// wallet attached. For a fresh splice, fees are paid from the channel balance, so this does
	/// not perform coin selection or spend wallet inputs. When a prior contribution is present,
	/// `outputs` are appended to the prior [`FundingContribution::outputs`] instead of replacing
	/// them. Use [`FundingTemplate::without_prior_contribution`] if you want to replace the prior
	/// outputs instead.
	///
	/// `outputs` are the additional withdrawal outputs to include. `min_feerate` is the feerate
	/// used for fee estimation and must be at least [`FundingTemplate::min_rbf_feerate`] when that
	/// is set. `max_feerate` is the highest feerate we are willing to tolerate if we end up as the
	/// acceptor, and must be at least `min_feerate`.
	///
	/// If amending a prior contribution would require selecting new wallet inputs, this method
	/// returns [`FundingContributionError::MissingCoinSelectionSource`]. This can happen, for
	/// example, when the prior contribution was input-backed and its existing change output cannot
	/// absorb the additional withdrawal outputs or the higher fee implied by `min_feerate`. In
	/// that case, use the builder APIs with a coin selection source instead.
	pub fn splice_out(
		self, outputs: Vec<TxOut>, min_feerate: FeeRate, max_feerate: FeeRate,
	) -> Result<FundingContribution, FundingContributionError> {
		self.with_prior_contribution(min_feerate, max_feerate).add_outputs(outputs).build()
	}

	/// Creates a [`FundingContribution`] for an RBF (Replace-By-Fee) attempt on a pending splice.
	///
	/// This requires [`FundingTemplate::prior_contribution`] to be available. `feerate` overrides
	/// the template's minimum RBF feerate; passing `None` uses
	/// [`FundingTemplate::min_rbf_feerate`]. `max_feerate` is the highest feerate we are willing to
	/// tolerate if we end up as the acceptor, and must be at least the effective feerate. `wallet`
	/// is only consulted if the prior contribution cannot be reused or adjusted directly. The
	/// chosen `max_feerate` is stored on the returned contribution so that any later acceptor-side
	/// fee adjustment for that contribution remains capped at the caller's chosen maximum, even if
	/// this RBF attempt had to fall back to a fresh coin selection.
	///
	/// This handles the prior contribution logic internally:
	/// - If the prior contribution's feerate can be adjusted to the effective target feerate, the
	///   adjusted contribution is returned directly. For splice-in, the change output absorbs
	///   the fee difference. For splice-out (no wallet inputs), the holder's channel balance
	///   covers the higher fees.
	/// - If adjustment fails, coin selection is re-run using the prior contribution's
	///   parameters and the caller's `max_feerate`. For prior contributions without inputs,
	///   this changes the funding source: wallet inputs are selected to cover the outputs and
	///   fees instead of deducting them from the channel balance.
	/// - If no prior contribution exists, coin selection is run for a fee-bump-only contribution
	///   (`value_added = 0`), covering fees for the common fields and shared input/output via
	///   a newly selected input. Check [`FundingTemplate::prior_contribution`] to see if this
	///   is intended.
	///
	/// # Errors
	///
	/// Returns a [`FundingContributionError`] if there is no reusable prior contribution, if no
	/// effective RBF feerate is available, if the effective feerate violates the template's fee
	/// constraints, or if coin selection fails.
	pub async fn rbf_prior_contribution<W: CoinSelectionSource + MaybeSend>(
		self, feerate: Option<FeeRate>, max_feerate: FeeRate, wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		if self.prior_contribution().is_none() {
			return Err(FundingContributionError::NotRbfScenario);
		}
		let feerate = feerate
			.or_else(|| self.min_rbf_feerate())
			.ok_or(FundingContributionError::NotRbfScenario)?;
		self.with_prior_contribution(feerate, max_feerate)
			.with_coin_selection_source(wallet)
			.build()
			.await
	}

	/// Creates a [`FundingContribution`] for an RBF (Replace-By-Fee) attempt on a pending splice.
	///
	/// This is the synchronous variant of [`FundingTemplate::rbf_prior_contribution`]; `feerate`,
	/// `max_feerate`, and `wallet` have the same meaning.
	pub fn rbf_prior_contribution_sync<W: CoinSelectionSourceSync>(
		self, feerate: Option<FeeRate>, max_feerate: FeeRate, wallet: W,
	) -> Result<FundingContribution, FundingContributionError> {
		if self.prior_contribution().is_none() {
			return Err(FundingContributionError::NotRbfScenario);
		}
		let feerate = feerate
			.or_else(|| self.min_rbf_feerate())
			.ok_or(FundingContributionError::NotRbfScenario)?;

		self.with_prior_contribution(feerate, max_feerate)
			.with_coin_selection_source_sync(wallet)
			.build()
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

fn validate_inputs(inputs: &[FundingTxInput]) -> Result<(), FundingContributionError> {
	let mut total_value = Amount::ZERO;
	for (idx, input) in inputs.iter().enumerate() {
		if inputs[..idx]
			.iter()
			.any(|existing_input| existing_input.utxo.outpoint == input.utxo.outpoint)
		{
			return Err(FundingContributionError::InvalidSpliceValue);
		}

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
		let message_len = MESSAGE_TEMPLATE.serialized_length() + input.prevtx.serialized_length();
		(message_len <= LN_MAX_MSG_LEN)
			.then(|| ())
			.ok_or(FundingContributionError::PrevTxTooLarge)?;

		total_value = match total_value.checked_add(input.utxo.output.value) {
			Some(sum) if sum <= Amount::MAX_MONEY => sum,
			_ => return Err(FundingContributionError::InvalidSpliceValue),
		};
	}

	Ok(())
}

/// Describes how a contribution request should source its wallet-backed inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FundingInputs {
	/// Reuses the contribution's existing inputs while targeting at least `value_added` added to
	/// the channel after fees. If dropping the change output leaves surplus value, it remains in
	/// the channel contribution.
	CoinSelected { value_added: Amount },
	/// Replaces the contribution's inputs with the provided set and fully consumes them without a
	/// change output. The amount added to the channel is recomputed from the input total minus fees,
	/// while explicit withdrawal outputs still reduce the splice's net value.
	ManuallySelected { inputs: Vec<FundingTxInput> },
}

impl FundingInputs {
	fn mode(&self) -> FundingInputMode {
		match self {
			FundingInputs::CoinSelected { .. } => FundingInputMode::CoinSelected,
			FundingInputs::ManuallySelected { .. } => FundingInputMode::ManuallySelected,
		}
	}

	fn is_empty(&self) -> bool {
		match self {
			FundingInputs::CoinSelected { value_added } => *value_added == Amount::ZERO,
			FundingInputs::ManuallySelected { inputs } => inputs.is_empty(),
		}
	}

	fn value_added(&self) -> Amount {
		match self {
			FundingInputs::CoinSelected { value_added } => *value_added,
			FundingInputs::ManuallySelected { .. } => Amount::ZERO,
		}
	}

	fn manually_selected_inputs(&self) -> &[FundingTxInput] {
		match self {
			FundingInputs::ManuallySelected { inputs } => inputs,
			FundingInputs::CoinSelected { .. } => &[],
		}
	}
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
enum FundingInputMode {
	CoinSelected,
	ManuallySelected,
}

impl_writeable_tlv_based_enum!(FundingInputMode,
	(1, CoinSelected) => {},
	(3, ManuallySelected) => {}
);

/// The components of a funding transaction contributed by one party.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FundingContribution {
	/// The estimate fees responsible to be paid for the contribution.
	estimated_fee: Amount,

	/// The inputs included in the funding transaction.
	///
	/// For coin-selected contributions, excess value is returned via [`Self::change_output`]. For
	/// manually selected inputs, the full input value is consumed and no change output is created.
	inputs: Vec<FundingTxInput>,

	/// The outputs to include in the funding transaction.
	///
	/// When no wallet inputs are contributed, these outputs are paid from the channel balance.
	/// Otherwise, they are paid by the contributed inputs.
	outputs: Vec<TxOut>,

	/// The output where any change will be sent.
	change_output: Option<TxOut>,

	/// The fee rate used to select `inputs` (the minimum feerate).
	feerate: FeeRate,

	/// The maximum fee rate to accept as acceptor before rejecting the splice.
	max_feerate: FeeRate,

	/// Whether the contribution is for funding a splice.
	is_splice: bool,

	/// Whether this contribution currently uses coin-selected or manual-input semantics.
	///
	/// This is `None` when the contribution has no inputs and is set accordingly based on the first
	/// `add_value` or `add_input` call on the builder.
	input_mode: Option<FundingInputMode>,
}

impl_writeable_tlv_based!(FundingContribution, {
	(1, estimated_fee, required),
	(3, inputs, optional_vec),
	(5, outputs, optional_vec),
	(7, change_output, option),
	(9, feerate, required),
	(11, max_feerate, required),
	(13, is_splice, required),
	(15, input_mode, option),
});

impl FundingContribution {
	pub(super) fn is_splice(&self) -> bool {
		self.is_splice
	}

	pub(crate) fn contributed_inputs(&self) -> impl Iterator<Item = OutPoint> + '_ {
		self.inputs.iter().map(|input| input.utxo.outpoint)
	}

	pub(crate) fn contributed_outputs(&self) -> impl Iterator<Item = &bitcoin::Script> + '_ {
		self.outputs
			.iter()
			.chain(self.change_output.iter())
			.map(|output| output.script_pubkey.as_script())
	}

	/// The positive value added to the channel after explicit outputs and fees.
	///
	/// This saturates at zero for net-negative contributions. See [`Self::net_value`] for the full
	/// signed contribution to the channel.
	pub fn value_added(&self) -> Amount {
		let total_input_value = self.inputs.iter().map(|i| i.utxo.output.value).sum::<Amount>();
		let total_output_value = self.outputs.iter().map(|output| output.value).sum();
		total_input_value
			.checked_sub(total_output_value)
			.and_then(|v| v.checked_sub(self.estimated_fee))
			.and_then(|v| {
				v.checked_sub(
					self.change_output.as_ref().map_or(Amount::ZERO, |output| output.value),
				)
			})
			.unwrap_or(Amount::ZERO)
	}

	/// Returns the estimated on-chain fee this contribution is responsible for paying.
	pub fn estimated_fee(&self) -> Amount {
		self.estimated_fee
	}

	/// Returns the inputs included in this contribution.
	pub fn inputs(&self) -> &[FundingTxInput] {
		&self.inputs
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

	/// Returns the fee rate used to select `inputs` (the minimum feerate).
	pub fn feerate(&self) -> FeeRate {
		self.feerate
	}

	/// Returns the maximum fee rate this contribution will accept as acceptor before rejecting
	/// the splice.
	pub fn max_feerate(&self) -> FeeRate {
		self.max_feerate
	}

	/// Tries to satisfy a new request using only this contribution's existing inputs.
	///
	/// For input-backed contributions, this reuses the current inputs, adjusts the explicit
	/// outputs, and shrinks or drops the change output as needed before applying
	/// `target_feerate`. If dropping change leaves surplus value, that surplus remains in the
	/// channel contribution.
	///
	/// For input-less contributions, `spliceable_balance` must be provided to cover the outputs and
	/// fees from the channel balance.
	///
	/// Returns `None` if the request would require new wallet inputs or cannot accommodate the
	/// requested feerate.
	fn amend_without_coin_selection(
		self, funding_inputs: Option<FundingInputs>, outputs: &[TxOut], target_feerate: FeeRate,
		max_feerate: FeeRate, spliceable_balance: Amount,
	) -> Option<Self> {
		// NOTE: The contribution returned is not guaranteed to be valid. We defer doing so until
		// `compute_feerate_adjustment`.
		let adjust_for_inputs_and_outputs = |contribution: Self,
		                                     inputs: Option<FundingInputs>,
		                                     outputs: &[TxOut]|
		 -> Option<Self> {
			let input_mode = inputs.as_ref().map(FundingInputs::mode);
			let (target_value_added, inputs) = match inputs {
				None => (None, Vec::new()),
				Some(FundingInputs::CoinSelected { value_added }) => {
					// We track the prior contribution's inputs here to see if they can cover the
					// new `value_added` without running coin selection.
					(Some(value_added), contribution.inputs)
				},
				Some(FundingInputs::ManuallySelected { inputs }) => (None, inputs),
			};

			if inputs.is_empty() && target_value_added.unwrap_or(Amount::ZERO) != Amount::ZERO {
				// Prior contribution didn't have any inputs, but now we need some.
				return None;
			}

			// When inputs are coin-selected, adjust the existing change output, if any, to account
			// for the requested value added and any explicit outputs that must also be funded by
			// the inputs.
			if let Some(value_added) = target_value_added {
				let estimated_fee = estimate_transaction_fee(
					&inputs,
					&outputs,
					contribution.change_output.as_ref(),
					true,
					contribution.is_splice,
					contribution.feerate,
				);
				let total_output_value: Amount = outputs.iter().map(|output| output.value).sum();
				let required_value =
					value_added.checked_add(total_output_value)?.checked_add(estimated_fee)?;

				if let Some(change_output) = contribution.change_output.as_ref() {
					let dust_limit = change_output.script_pubkey.minimal_non_dust();
					let total_input_value: Amount =
						inputs.iter().map(|input| input.utxo.output.value).sum();
					match total_input_value.checked_sub(required_value) {
						Some(new_change_value) if new_change_value >= dust_limit => {
							let new_change_output = TxOut {
								value: new_change_value,
								script_pubkey: change_output.script_pubkey.clone(),
							};
							return Some(FundingContribution {
								estimated_fee,
								inputs,
								outputs: outputs.to_vec(),
								change_output: Some(new_change_output),
								input_mode,
								..contribution
							});
						},
						_ => {},
					}
				}
			}

			let estimated_fee_no_change = estimate_transaction_fee(
				&inputs,
				&outputs,
				None,
				true,
				contribution.is_splice,
				contribution.feerate,
			);
			Some(FundingContribution {
				estimated_fee: estimated_fee_no_change,
				outputs: outputs.to_vec(),
				inputs,
				change_output: None,
				input_mode,
				..contribution
			})
		};

		let new_contribution_at_current_feerate =
			adjust_for_inputs_and_outputs(self, funding_inputs, outputs)?;
		let mut new_contribution_at_target_feerate = new_contribution_at_current_feerate
			.at_feerate(target_feerate, spliceable_balance, true)
			.ok()?;
		new_contribution_at_target_feerate.max_feerate = max_feerate;

		Some(new_contribution_at_target_feerate)
	}

	pub(super) fn into_tx_parts(self) -> (Vec<FundingTxInput>, Vec<TxOut>) {
		let FundingContribution { inputs, mut outputs, change_output, .. } = self;

		if let Some(change_output) = change_output {
			outputs.push(change_output);
		}

		(inputs, outputs)
	}

	pub(super) fn into_contributed_inputs_and_outputs(self) -> (Vec<OutPoint>, Vec<ScriptBuf>) {
		let FundingContribution { inputs, outputs, change_output, .. } = self;
		let contributed_inputs = inputs.into_iter().map(|input| input.utxo.outpoint).collect();
		let contributed_outputs = outputs.into_iter().chain(change_output.into_iter());
		(contributed_inputs, contributed_outputs.map(|output| output.script_pubkey).collect())
	}

	/// Returns this contribution's inputs and outputs after removing any that overlap
	/// with the provided `existing_inputs`/`existing_outputs`.
	///
	/// Multiple contribution outputs sharing a `script_pubkey` are all dropped when any
	/// existing output uses the same script.
	///
	/// Returns `None` if every input and output was filtered as overlapping.
	pub(crate) fn into_unique_contributions<'a>(
		self, existing_inputs: impl Iterator<Item = OutPoint>,
		existing_outputs: impl Iterator<Item = &'a bitcoin::Script>,
	) -> Option<(Vec<OutPoint>, Vec<ScriptBuf>)> {
		let FundingContribution { mut inputs, mut outputs, mut change_output, .. } = self;
		for existing in existing_inputs {
			inputs.retain(|input| input.outpoint() != existing);
		}
		for existing in existing_outputs {
			outputs.retain(|output| output.script_pubkey.as_script() != existing);
			// TODO: Replace with `take_if` once our MSRV is >= 1.80.
			if change_output
				.as_ref()
				.filter(|output| output.script_pubkey.as_script() == existing)
				.is_some()
			{
				change_output.take();
			}
		}
		if inputs.is_empty() && outputs.is_empty() && change_output.as_ref().is_none() {
			None
		} else {
			let inputs = inputs.into_iter().map(|input| input.outpoint()).collect();
			let outputs = outputs
				.into_iter()
				.chain(change_output.into_iter())
				.map(|output| output.script_pubkey)
				.collect();
			Some((inputs, outputs))
		}
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
		&self, target_feerate: FeeRate, spliceable_balance: Amount, is_initiator: bool,
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

		let target_fee = estimate_transaction_fee(
			&self.inputs,
			&self.outputs,
			self.change_output.as_ref(),
			is_initiator,
			self.is_splice,
			target_feerate,
		);

		if !self.inputs.is_empty() && self.input_mode == Some(FundingInputMode::CoinSelected) {
			// Any withdrawal outputs and fees always come from the coin-selected inputs, as we want
			// to guarantee the net contribution adds the desired value.
			let fee_buffer = self
				.estimated_fee
				.checked_add(
					self.change_output.as_ref().map_or(Amount::ZERO, |output| output.value),
				)
				.ok_or(FeeRateAdjustmentError::FeeBufferOverflow)?;

			if let Some(change_output) = self.change_output.as_ref() {
				let dust_limit = change_output.script_pubkey.minimal_non_dust();
				if let Some(new_change_value) = fee_buffer.checked_sub(target_fee) {
					if new_change_value >= dust_limit {
						return Ok((target_fee, Some(new_change_value)));
					}

					// Our remaining change was not enough to be a valid output, fallthrough to the
					// no remaining change case.
				}

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
			} else if let Some(_surplus) = fee_buffer.checked_sub(target_fee) {
				Ok((target_fee, None))
			} else {
				Err(FeeRateAdjustmentError::FeeBufferInsufficient {
					source: "estimated fee",
					available: fee_buffer,
					required: target_fee,
				})
			}
		} else {
			// Manually selected inputs may either add value to the channel or offset some of the
			// withdrawal outputs. Any remaining fee cost must come from the channel balance.
			let net_value_without_fee = self.net_value_without_fee();
			let fee_buffer = if net_value_without_fee.is_negative() {
				spliceable_balance
					.checked_sub(net_value_without_fee.unsigned_abs())
					.unwrap_or(Amount::ZERO)
			} else {
				spliceable_balance
					.checked_add(net_value_without_fee.unsigned_abs())
					.ok_or(FeeRateAdjustmentError::FeeBufferOverflow)?
			};
			if fee_buffer < target_fee {
				return Err(FeeRateAdjustmentError::FeeBufferInsufficient {
					source: "channel balance",
					available: fee_buffer,
					required: target_fee,
				});
			}
			Ok((target_fee, None))
		}
	}

	/// Adjusts the contribution for a different feerate, updating the change output, fee
	/// estimate, and feerate. Returns the adjusted contribution, or an error if the feerate
	/// can't be accommodated.
	fn at_feerate(
		mut self, feerate: FeeRate, spliceable_balance: Amount, is_initiator: bool,
	) -> Result<Self, FeeRateAdjustmentError> {
		let (new_estimated_fee, new_change) =
			self.compute_feerate_adjustment(feerate, spliceable_balance, is_initiator)?;
		match new_change {
			Some(value) => self.change_output.as_mut().unwrap().value = value,
			None => self.change_output = None,
		}
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
		self, feerate: FeeRate, spliceable_balance: Amount,
	) -> Result<Self, FeeRateAdjustmentError> {
		self.at_feerate(feerate, spliceable_balance, false)
	}

	/// Adjusts the contribution's change output for the minimum RBF feerate.
	///
	/// When a pending splice exists with negotiated candidates and the contribution's feerate is
	/// below the minimum RBF feerate, this adjusts the change output so the initiator pays fees
	/// at the minimum RBF feerate.
	pub(super) fn for_initiator_at_feerate(
		self, feerate: FeeRate, spliceable_balance: Amount,
	) -> Result<Self, FeeRateAdjustmentError> {
		self.at_feerate(feerate, spliceable_balance, true)
	}

	/// Returns the net value at the given target feerate without mutating `self`.
	///
	/// This serves double duty: it checks feerate compatibility (returning `Err` if the feerate
	/// can't be accommodated) and computes the adjusted net value (returning `Ok` with the value
	/// accounting for the target feerate).
	fn net_value_at_feerate(
		&self, target_feerate: FeeRate, spliceable_balance: Amount, is_initiator: bool,
	) -> Result<SignedAmount, FeeRateAdjustmentError> {
		let (new_estimated_fee, new_change) =
			self.compute_feerate_adjustment(target_feerate, spliceable_balance, is_initiator)?;

		let prev_fee = self
			.estimated_fee
			.to_signed()
			.expect("total input amount cannot exceed Amount::MAX_MONEY");
		let prev_change = self
			.change_output
			.as_ref()
			.map_or(Amount::ZERO, |output| output.value)
			.to_signed()
			.expect("total input amount cannot exceed Amount::MAX_MONEY");

		let new_fee = new_estimated_fee
			.to_signed()
			.expect("total input amount cannot exceed Amount::MAX_MONEY");
		let new_change = new_change
			.unwrap_or(Amount::ZERO)
			.to_signed()
			.expect("total input amount cannot exceed Amount::MAX_MONEY");

		let prev_net_value = self.net_value();
		Ok(prev_net_value + prev_fee + prev_change - new_fee - new_change)
	}

	/// Returns the net value at the given target feerate without mutating `self`,
	/// assuming acceptor fee responsibility.
	pub(super) fn net_value_for_acceptor_at_feerate(
		&self, target_feerate: FeeRate, spliceable_balance: Amount,
	) -> Result<SignedAmount, FeeRateAdjustmentError> {
		self.net_value_at_feerate(target_feerate, spliceable_balance, false)
	}

	/// Returns the net value at the given target feerate without mutating `self`,
	/// assuming initiator fee responsibility.
	pub(super) fn net_value_for_initiator_at_feerate(
		&self, target_feerate: FeeRate, spliceable_balance: Amount,
	) -> Result<SignedAmount, FeeRateAdjustmentError> {
		self.net_value_at_feerate(target_feerate, spliceable_balance, true)
	}

	/// The net value contributed to a channel by the splice.
	pub fn net_value(&self) -> SignedAmount {
		let estimated_fee = self
			.estimated_fee
			.to_signed()
			.expect("total_input_value is validated to not exceed Amount::MAX_MONEY");
		self.net_value_without_fee()
			.checked_sub(estimated_fee)
			.expect("all amounts are validated to not exceed Amount::MAX_MONEY")
	}

	fn net_value_without_fee(&self) -> SignedAmount {
		let total_input_value = self
			.inputs
			.iter()
			.map(|input| input.utxo.output.value)
			.sum::<Amount>()
			.to_signed()
			.expect("total_input_value is validated to not exceed Amount::MAX_MONEY");
		let total_output_value = self
			.outputs
			.iter()
			.chain(self.change_output.iter())
			.map(|txout| txout.value)
			.sum::<Amount>()
			.to_signed()
			.expect("total_output_value is validated to not exceed Amount::MAX_MONEY");
		total_input_value
			.checked_sub(total_output_value)
			.expect("all amounts are validated to not exceed Amount::MAX_MONEY")
	}
}

/// An input to contribute to a channel's funding transaction either when using the v2 channel
/// establishment protocol or when splicing.
pub type FundingTxInput = crate::util::wallet_utils::ConfirmedUtxo;

#[derive(Debug, Clone, PartialEq, Eq)]
struct NoCoinSelectionSource;
#[derive(Debug, Clone, PartialEq, Eq)]
struct AsyncCoinSelectionSource<W>(W);
#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncCoinSelectionSource<W>(W);

#[derive(Debug, Clone, PartialEq, Eq)]
struct FundingBuilderInner<State> {
	shared_input: Option<Input>,
	min_rbf_feerate: Option<FeeRate>,
	prior_contribution: Option<FundingContribution>,
	spliceable_balance: Amount,
	funding_inputs: Option<FundingInputs>,
	outputs: Vec<TxOut>,
	feerate: FeeRate,
	max_feerate: FeeRate,
	state: State,
}

/// A builder for composing or amending a [`FundingContribution`].
///
/// The builder tracks either a requested amount to add to the channel or a fixed set of manually
/// selected inputs, together with any explicit withdrawal outputs. Building without an attached
/// wallet only succeeds when the request can be satisfied by reusing or amending a prior
/// contribution, by using only manually selected inputs, or by constructing a splice-out that
/// pays fees from the channel balance.
///
/// Attach a wallet via [`FundingBuilder::with_coin_selection_source`] or
/// [`FundingBuilder::with_coin_selection_source_sync`] when the request may need new wallet
/// inputs. Manually selected inputs are not supplemented with coin selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingBuilder(FundingBuilderInner<NoCoinSelectionSource>);

/// A [`FundingBuilder`] with an attached asynchronous [`CoinSelectionSource`].
///
/// Created by [`FundingBuilder::with_coin_selection_source`]. The attached wallet is only used
/// if the request cannot be satisfied by reusing a prior contribution, by using only manually
/// selected inputs, or by building a pure splice-out directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncFundingBuilder<W>(FundingBuilderInner<AsyncCoinSelectionSource<W>>);

/// A [`FundingBuilder`] with an attached synchronous [`CoinSelectionSourceSync`].
///
/// Created by [`FundingBuilder::with_coin_selection_source_sync`]. The attached wallet is only
/// used if the request cannot be satisfied by reusing a prior contribution, by using only
/// manually selected inputs, or by building a pure splice-out directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncFundingBuilder<W>(FundingBuilderInner<SyncCoinSelectionSource<W>>);

impl<State> FundingBuilderInner<State> {
	fn request_matches_prior(&self, prior_contribution: &FundingContribution) -> bool {
		let request_matches_prior_inputs =
			match (self.funding_inputs.as_ref(), prior_contribution.input_mode) {
				(
					Some(FundingInputs::ManuallySelected { inputs }),
					Some(FundingInputMode::ManuallySelected),
				) => {
					let request_inputs = inputs.iter().map(|input| input.utxo.outpoint);
					let prior_inputs =
						prior_contribution.inputs.iter().map(|input| input.utxo.outpoint);
					request_inputs.eq(prior_inputs)
				},
				(
					Some(FundingInputs::CoinSelected { value_added }),
					Some(FundingInputMode::CoinSelected),
				) => *value_added == prior_contribution.value_added(),
				(None, None) => true,
				_ => false,
			};
		request_matches_prior_inputs && self.outputs == prior_contribution.outputs
	}

	fn build_from_prior_contribution(
		&self, contribution: FundingContribution,
	) -> Result<FundingContribution, FundingContributionError> {
		let input_mode = self.funding_inputs.as_ref().map(FundingInputs::mode);

		if self.request_matches_prior(&contribution) {
			// Same request, but the feerate may have changed. Adjust the prior contribution
			// to the new feerate if possible.
			return contribution
				.for_initiator_at_feerate(self.feerate, self.spliceable_balance)
				.map(|mut adjusted| {
					adjusted.max_feerate = self.max_feerate;
					adjusted
				})
				.map_err(|_| {
					if input_mode == Some(FundingInputMode::ManuallySelected) {
						FundingContributionError::ManuallySelectedInputsInsufficient
					} else {
						FundingContributionError::MissingCoinSelectionSource
					}
				});
		}

		return contribution
			.amend_without_coin_selection(
				self.funding_inputs.clone(),
				&self.outputs,
				self.feerate,
				self.max_feerate,
				self.spliceable_balance,
			)
			.ok_or_else(|| {
				if input_mode == Some(FundingInputMode::ManuallySelected) {
					FundingContributionError::ManuallySelectedInputsInsufficient
				} else {
					FundingContributionError::MissingCoinSelectionSource
				}
			});
	}

	/// Tries to build the current request without selecting any new wallet inputs.
	///
	/// This first attempts to reuse or amend any prior contribution. If there is no prior
	/// contribution, it also supports manually selected inputs and pure splice-out requests by
	/// building a contribution without coin selection.
	///
	/// Returns [`FundingContributionError::MissingCoinSelectionSource`] if the request is
	/// otherwise valid but needs wallet inputs, or
	/// [`FundingContributionError::ManuallySelectedInputsInsufficient`] if the manually selected
	/// inputs cannot satisfy the request.
	fn try_build_without_coin_selection(
		&self,
	) -> Result<FundingContribution, FundingContributionError> {
		if let Some(contribution) = self.prior_contribution.as_ref() {
			return self.build_from_prior_contribution(contribution.clone());
		}

		let value_added =
			self.funding_inputs.as_ref().map_or(Amount::ZERO, FundingInputs::value_added);
		if value_added == Amount::ZERO {
			let inputs = self
				.funding_inputs
				.as_ref()
				.map_or(&[][..], FundingInputs::manually_selected_inputs);
			let input_mode =
				if inputs.is_empty() { None } else { Some(FundingInputMode::ManuallySelected) };

			let estimated_fee = estimate_transaction_fee(
				inputs,
				&self.outputs,
				None,
				true,
				self.shared_input.is_some(),
				self.feerate,
			);

			let contribution = FundingContribution {
				estimated_fee,
				inputs: match self.funding_inputs {
					Some(FundingInputs::ManuallySelected { ref inputs }) => inputs.clone(),
					None | Some(FundingInputs::CoinSelected { .. }) => Vec::new(),
				},
				outputs: self.outputs.clone(),
				change_output: None,
				feerate: self.feerate,
				max_feerate: self.max_feerate,
				is_splice: self.shared_input.is_some(),
				input_mode,
			};
			let net_value = contribution.net_value();
			if net_value.is_negative() {
				self.spliceable_balance.checked_sub(net_value.unsigned_abs()).ok_or_else(|| {
					if contribution.inputs.is_empty() {
						FundingContributionError::InvalidSpliceValue
					} else {
						FundingContributionError::ManuallySelectedInputsInsufficient
					}
				})?;
			}

			return Ok(contribution);
		}

		Err(FundingContributionError::MissingCoinSelectionSource)
	}

	fn prepare_coin_selection_request(
		&self,
	) -> Result<(Vec<Input>, Vec<TxOut>), FundingContributionError> {
		let value_added =
			self.funding_inputs.as_ref().map_or(Amount::ZERO, FundingInputs::value_added);
		let dummy_pubkey = PublicKey::from_slice(&[2; 33]).unwrap();
		let shared_output = bitcoin::TxOut {
			value: self
				.shared_input
				.as_ref()
				.map(|shared_input| shared_input.previous_utxo.value)
				.unwrap_or(Amount::ZERO)
				.checked_add(value_added)
				.ok_or(FundingContributionError::InvalidSpliceValue)?,
			script_pubkey: make_funding_redeemscript(&dummy_pubkey, &dummy_pubkey).to_p2wsh(),
		};

		let must_spend = self.shared_input.clone().map(|input| vec![input]).unwrap_or_default();
		let must_pay_to = if self.outputs.is_empty() {
			vec![shared_output]
		} else {
			self.outputs.iter().cloned().chain(core::iter::once(shared_output)).collect()
		};

		Ok((must_spend, must_pay_to))
	}

	fn validate_contribution_parameters(&self) -> Result<(), FundingContributionError> {
		if self.feerate > self.max_feerate {
			return Err(FundingContributionError::FeeRateExceedsMaximum {
				feerate: self.feerate,
				max_feerate: self.max_feerate,
			});
		}

		if let Some(min_rbf_feerate) = self.min_rbf_feerate.as_ref() {
			if self.feerate < *min_rbf_feerate {
				return Err(FundingContributionError::FeeRateBelowRbfMinimum {
					feerate: self.feerate,
					min_rbf_feerate: *min_rbf_feerate,
				});
			}
		}

		if self.funding_inputs.as_ref().map_or(true, FundingInputs::is_empty)
			&& self.outputs.is_empty()
		{
			return Err(FundingContributionError::InvalidSpliceValue);
		}

		// Validate user-provided amounts are within MAX_MONEY before coin selection to
		// ensure FundingContribution::net_value() arithmetic cannot overflow. With all
		// amounts bounded by MAX_MONEY (~2.1e15 sat), the worst-case net_value()
		// computation is -2 * MAX_MONEY (~-4.2e15), well within i64::MIN (~-9.2e18).
		if self.funding_inputs.as_ref().map_or(Amount::ZERO, FundingInputs::value_added)
			> Amount::MAX_MONEY
		{
			return Err(FundingContributionError::InvalidSpliceValue);
		}

		validate_inputs(
			self.funding_inputs.as_ref().map_or(&[][..], FundingInputs::manually_selected_inputs),
		)?;

		let mut value_removed = Amount::ZERO;
		for (idx, output) in self.outputs.iter().enumerate() {
			if self.outputs[..idx]
				.iter()
				.any(|existing_output| existing_output.script_pubkey == output.script_pubkey)
			{
				return Err(FundingContributionError::InvalidSpliceValue);
			}

			value_removed = match value_removed.checked_add(output.value) {
				Some(sum) if sum <= Amount::MAX_MONEY => sum,
				_ => return Err(FundingContributionError::InvalidSpliceValue),
			};
		}

		Ok(())
	}
}

impl FundingBuilder {
	fn new(template: FundingTemplate, feerate: FeeRate, max_feerate: FeeRate) -> FundingBuilder {
		let FundingTemplate {
			shared_input,
			min_rbf_feerate,
			prior_contribution,
			spliceable_balance,
		} = template;
		let (funding_inputs, outputs) = match prior_contribution.as_ref() {
			Some(prior_contribution) => {
				let funding_inputs = match prior_contribution.input_mode {
					Some(FundingInputMode::ManuallySelected) => {
						Some(FundingInputs::ManuallySelected {
							inputs: prior_contribution.inputs.clone(),
						})
					},
					Some(FundingInputMode::CoinSelected) => Some(FundingInputs::CoinSelected {
						value_added: prior_contribution.value_added(),
					}),
					None => None,
				};
				(funding_inputs, prior_contribution.outputs.clone())
			},
			None => (None, Vec::new()),
		};

		FundingBuilder(FundingBuilderInner {
			shared_input,
			min_rbf_feerate,
			prior_contribution,
			spliceable_balance,
			funding_inputs,
			outputs,
			feerate,
			max_feerate,
			state: NoCoinSelectionSource,
		})
	}

	/// Attaches an asynchronous [`CoinSelectionSource`] for later use.
	///
	/// The wallet is only consulted if [`AsyncFundingBuilder::build`] cannot satisfy the request by
	/// reusing a prior contribution, by using only manually selected inputs, or by constructing a
	/// pure splice-out directly.
	pub fn with_coin_selection_source<W: CoinSelectionSource + MaybeSend>(
		self, wallet: W,
	) -> AsyncFundingBuilder<W> {
		AsyncFundingBuilder(self.0.with_state(AsyncCoinSelectionSource(wallet)))
	}

	/// Attaches a synchronous [`CoinSelectionSourceSync`] for later use.
	///
	/// The wallet is only consulted if [`SyncFundingBuilder::build`] cannot satisfy the request by
	/// reusing a prior contribution, by using only manually selected inputs, or by constructing a
	/// pure splice-out directly.
	pub fn with_coin_selection_source_sync<W: CoinSelectionSourceSync>(
		self, wallet: W,
	) -> SyncFundingBuilder<W> {
		SyncFundingBuilder(self.0.with_state(SyncCoinSelectionSource(wallet)))
	}

	/// Adds a manually selected input to the request.
	///
	/// Each input is fully consumed with no change output. When built without additional coin
	/// selection, the inputs and explicit outputs are modeled by their net effect on the channel:
	/// the contribution may be net-positive or net-negative before fees.
	///
	/// Manually selected inputs are a separate request mode and cannot be combined with requesting
	/// additional coin-selected value. If the manually selected inputs cannot satisfy the request,
	/// [`FundingBuilder::build`] returns
	/// [`FundingContributionError::ManuallySelectedInputsInsufficient`] instead of falling back to
	/// coin selection.
	///
	/// Returns [`FundingContributionError::InvalidSpliceValue`] if the builder already has a
	/// coin-selected value request.
	pub fn add_input(self, input: FundingTxInput) -> Result<Self, FundingContributionError> {
		self.0.add_input_inner(input).map(FundingBuilder)
	}

	/// Adds manually selected inputs to the request.
	///
	/// Each input is fully consumed with no change output. When built without additional coin
	/// selection, the inputs and explicit outputs are modeled by their net effect on the channel:
	/// the contribution may be net-positive or net-negative before fees.
	///
	/// Manually selected inputs are a separate request mode and cannot be combined with requesting
	/// additional coin-selected value. If the manually selected inputs cannot satisfy the request,
	/// [`FundingBuilder::build`] returns
	/// [`FundingContributionError::ManuallySelectedInputsInsufficient`] instead of falling back to
	/// coin selection.
	///
	/// Returns [`FundingContributionError::InvalidSpliceValue`] if the builder already has a
	/// coin-selected value request.
	pub fn add_inputs(self, inputs: Vec<FundingTxInput>) -> Result<Self, FundingContributionError> {
		self.0.add_inputs_inner(inputs).map(FundingBuilder)
	}

	/// Removes all manually selected inputs whose outpoint matches `outpoint`.
	///
	/// Returns [`FundingContributionError::InvalidSpliceValue`] if the builder already has a
	/// coin-selected value request.
	pub fn remove_input(self, outpoint: &OutPoint) -> Result<Self, FundingContributionError> {
		self.0.remove_input_inner(outpoint).map(FundingBuilder)
	}

	/// Adds a withdrawal output to the request.
	///
	/// `output` is appended to the current set of explicit outputs. If the builder was seeded from
	/// a prior contribution, this adds an additional withdrawal on top of the prior outputs. This
	/// does not affect any change output derived when the contribution is built.
	pub fn add_output(self, output: TxOut) -> Self {
		FundingBuilder(self.0.add_output_inner(output))
	}

	/// Adds withdrawal outputs to the request.
	///
	/// `outputs` are appended to the current set of explicit outputs. If the builder was seeded
	/// from a prior contribution, this adds additional withdrawals on top of the prior outputs.
	/// This does not affect any change output derived when the contribution is built.
	pub fn add_outputs(self, outputs: Vec<TxOut>) -> Self {
		FundingBuilder(self.0.add_outputs_inner(outputs))
	}

	/// Removes all explicit withdrawal outputs whose script pubkey matches `script_pubkey`.
	///
	/// This only affects outputs returned by [`FundingContribution::outputs`]; it never removes the
	/// change output returned by [`FundingContribution::change_output`].
	pub fn remove_outputs(self, script_pubkey: &ScriptBuf) -> Self {
		FundingBuilder(self.0.remove_outputs_inner(script_pubkey))
	}

	/// Builds a [`FundingContribution`] without coin selection.
	///
	/// This succeeds when the request can be satisfied by reusing or amending a prior
	/// contribution, by using only manually selected inputs, or by building a splice-out
	/// contribution that pays fees from the channel balance.
	///
	/// Returns [`FundingContributionError::MissingCoinSelectionSource`] if additional wallet
	/// inputs are needed, or [`FundingContributionError::ManuallySelectedInputsInsufficient`] if
	/// the manually selected inputs cannot satisfy the request.
	pub fn build(self) -> Result<FundingContribution, FundingContributionError> {
		self.0.build_without_coin_selection()
	}
}

impl<State> FundingBuilderInner<State> {
	fn with_state<NewState>(self, state: NewState) -> FundingBuilderInner<NewState> {
		FundingBuilderInner {
			shared_input: self.shared_input,
			min_rbf_feerate: self.min_rbf_feerate,
			prior_contribution: self.prior_contribution,
			spliceable_balance: self.spliceable_balance,
			funding_inputs: self.funding_inputs,
			outputs: self.outputs,
			feerate: self.feerate,
			max_feerate: self.max_feerate,
			state,
		}
	}

	fn add_value_inner(mut self, value: Amount) -> Result<Self, FundingContributionError> {
		match &mut self.funding_inputs {
			None => self.funding_inputs = Some(FundingInputs::CoinSelected { value_added: value }),
			Some(FundingInputs::CoinSelected { value_added }) => {
				*value_added =
					Amount::from_sat(value_added.to_sat().saturating_add(value.to_sat()));
			},
			Some(FundingInputs::ManuallySelected { .. }) => {
				return Err(FundingContributionError::InvalidSpliceValue);
			},
		}
		Ok(self)
	}

	fn remove_value_inner(mut self, value: Amount) -> Result<Self, FundingContributionError> {
		match &mut self.funding_inputs {
			None => {},
			Some(FundingInputs::CoinSelected { value_added }) => {
				*value_added =
					Amount::from_sat(value_added.to_sat().saturating_sub(value.to_sat()));
			},
			Some(FundingInputs::ManuallySelected { .. }) => {
				return Err(FundingContributionError::InvalidSpliceValue);
			},
		}
		Ok(self)
	}

	fn add_input_inner(mut self, input: FundingTxInput) -> Result<Self, FundingContributionError> {
		match &mut self.funding_inputs {
			None => {
				self.funding_inputs = Some(FundingInputs::ManuallySelected { inputs: vec![input] })
			},
			Some(FundingInputs::ManuallySelected { inputs }) => inputs.push(input),
			Some(FundingInputs::CoinSelected { .. }) => {
				return Err(FundingContributionError::InvalidSpliceValue);
			},
		}
		Ok(self)
	}

	fn add_inputs_inner(
		mut self, inputs: Vec<FundingTxInput>,
	) -> Result<Self, FundingContributionError> {
		match &mut self.funding_inputs {
			None => self.funding_inputs = Some(FundingInputs::ManuallySelected { inputs }),
			Some(FundingInputs::ManuallySelected { inputs: existing_inputs }) => {
				existing_inputs.extend(inputs)
			},
			Some(FundingInputs::CoinSelected { .. }) => {
				return Err(FundingContributionError::InvalidSpliceValue);
			},
		}
		Ok(self)
	}

	fn remove_input_inner(mut self, outpoint: &OutPoint) -> Result<Self, FundingContributionError> {
		match &mut self.funding_inputs {
			None => {},
			Some(FundingInputs::ManuallySelected { inputs }) => {
				inputs.retain(|input| input.utxo.outpoint != *outpoint);
			},
			Some(FundingInputs::CoinSelected { .. }) => {
				return Err(FundingContributionError::InvalidSpliceValue);
			},
		}
		Ok(self)
	}

	fn add_output_inner(mut self, output: TxOut) -> Self {
		self.outputs.push(output);
		self
	}

	fn add_outputs_inner(mut self, outputs: Vec<TxOut>) -> Self {
		self.outputs.extend(outputs);
		self
	}

	fn remove_outputs_inner(mut self, script_pubkey: &ScriptBuf) -> Self {
		self.outputs.retain(|output| output.script_pubkey != *script_pubkey);
		self
	}

	/// Validates the current request and then tries to build it without selecting new wallet
	/// inputs.
	///
	/// Returns [`FundingContributionError::MissingCoinSelectionSource`] if the request is valid but
	/// cannot be satisfied without wallet inputs, or
	/// [`FundingContributionError::ManuallySelectedInputsInsufficient`] if the manually selected
	/// inputs cannot satisfy the request.
	fn build_without_coin_selection(
		&self,
	) -> Result<FundingContribution, FundingContributionError> {
		self.validate_contribution_parameters()?;
		self.try_build_without_coin_selection()
	}
}

impl<W> AsyncFundingBuilder<W> {
	/// Adds a withdrawal output to the request.
	///
	/// `output` is appended to the current set of explicit outputs. If the builder was seeded from
	/// a prior contribution, this adds an additional withdrawal on top of the prior outputs. This
	/// does not affect any change output derived when the contribution is built.
	pub fn add_output(self, output: TxOut) -> Self {
		AsyncFundingBuilder(self.0.add_output_inner(output))
	}

	/// Adds withdrawal outputs to the request.
	///
	/// `outputs` are appended to the current set of explicit outputs. If the builder was seeded
	/// from a prior contribution, this adds additional withdrawals on top of the prior outputs.
	/// This does not affect any change output derived when the contribution is built.
	pub fn add_outputs(self, outputs: Vec<TxOut>) -> Self {
		AsyncFundingBuilder(self.0.add_outputs_inner(outputs))
	}

	/// Removes all explicit withdrawal outputs whose script pubkey matches `script_pubkey`.
	///
	/// This only affects outputs returned by [`FundingContribution::outputs`]; it never removes the
	/// change output returned by [`FundingContribution::change_output`].
	pub fn remove_outputs(self, script_pubkey: &ScriptBuf) -> Self {
		AsyncFundingBuilder(self.0.remove_outputs_inner(script_pubkey))
	}

	/// Increases the requested amount to add to the channel.
	///
	/// `value` is added on top of the builder's current request. If the builder was seeded from a
	/// prior contribution, this increases that prior contribution's current amount added to the
	/// channel. If the updated request cannot be satisfied in-place, [`AsyncFundingBuilder::build`]
	/// may re-run coin selection and return a contribution with a different input set.
	///
	/// Returns [`FundingContributionError::InvalidSpliceValue`] if the builder already has manually
	/// selected inputs.
	pub fn add_value(self, value: Amount) -> Result<Self, FundingContributionError> {
		self.0.add_value_inner(value).map(AsyncFundingBuilder)
	}

	/// Decreases the requested amount to add to the channel.
	///
	/// `value` is subtracted from the builder's current request, saturating at zero. If the builder
	/// was seeded from a prior contribution, this decreases that prior contribution's current
	/// amount added to the channel. If the updated request cannot be satisfied in-place,
	/// [`AsyncFundingBuilder::build`] may re-run coin selection and return a contribution with a
	/// different input set.
	///
	/// Returns [`FundingContributionError::InvalidSpliceValue`] if the builder already has manually
	/// selected inputs.
	pub fn remove_value(self, value: Amount) -> Result<Self, FundingContributionError> {
		self.0.remove_value_inner(value).map(AsyncFundingBuilder)
	}
}

impl<W: CoinSelectionSource + MaybeSend> AsyncFundingBuilder<W> {
	/// Builds a [`FundingContribution`], using the attached asynchronous wallet only when needed.
	///
	/// If the request can be satisfied by reusing or amending a prior contribution, or by building
	/// a pure splice-out directly, or by using only manually selected inputs, the attached wallet is
	/// ignored.
	pub async fn build(self) -> Result<FundingContribution, FundingContributionError> {
		let inner = self.0;
		match inner.build_without_coin_selection() {
			Err(FundingContributionError::MissingCoinSelectionSource) => {},
			other => return other,
		}

		let (must_spend, must_pay_to) = inner.prepare_coin_selection_request()?;
		let AsyncCoinSelectionSource(wallet) = inner.state;
		let coin_selection = wallet
			.select_confirmed_utxos(
				None,
				must_spend,
				&must_pay_to,
				inner.feerate.to_sat_per_kwu() as u32,
				u64::MAX,
			)
			.await
			.map_err(|_| FundingContributionError::CoinSelectionFailed)?;

		let CoinSelection { confirmed_utxos: inputs, change_output } = coin_selection;
		validate_inputs(&inputs)?;

		let outputs = inner.outputs;
		let is_splice = inner.shared_input.is_some();
		let estimated_fee = estimate_transaction_fee(
			&inputs,
			&outputs,
			change_output.as_ref(),
			true,
			is_splice,
			inner.feerate,
		);

		return Ok(FundingContribution {
			estimated_fee,
			inputs,
			outputs,
			change_output,
			feerate: inner.feerate,
			max_feerate: inner.max_feerate,
			is_splice,
			input_mode: Some(FundingInputMode::CoinSelected),
		});
	}
}

impl<W> SyncFundingBuilder<W> {
	/// Adds a withdrawal output to the request.
	///
	/// `output` is appended to the current set of explicit outputs. If the builder was seeded from
	/// a prior contribution, this adds an additional withdrawal on top of the prior outputs. This
	/// does not affect any change output derived when the contribution is built.
	pub fn add_output(self, output: TxOut) -> Self {
		SyncFundingBuilder(self.0.add_output_inner(output))
	}

	/// Adds withdrawal outputs to the request.
	///
	/// `outputs` are appended to the current set of explicit outputs. If the builder was seeded
	/// from a prior contribution, this adds additional withdrawals on top of the prior outputs.
	/// This does not affect any change output derived when the contribution is built.
	pub fn add_outputs(self, outputs: Vec<TxOut>) -> Self {
		SyncFundingBuilder(self.0.add_outputs_inner(outputs))
	}

	/// Removes all explicit withdrawal outputs whose script pubkey matches `script_pubkey`.
	///
	/// This only affects outputs returned by [`FundingContribution::outputs`]; it never removes the
	/// change output returned by [`FundingContribution::change_output`].
	pub fn remove_outputs(self, script_pubkey: &ScriptBuf) -> Self {
		SyncFundingBuilder(self.0.remove_outputs_inner(script_pubkey))
	}

	/// Increases the requested amount to add to the channel.
	///
	/// `value` is added on top of the builder's current request. If the builder was seeded from a
	/// prior contribution, this increases that prior contribution's current amount added to the
	/// channel. If the updated request cannot be satisfied in-place, [`SyncFundingBuilder::build`]
	/// may re-run coin selection and return a contribution with a different input set.
	///
	/// Returns [`FundingContributionError::InvalidSpliceValue`] if the builder already has manually
	/// selected inputs.
	pub fn add_value(self, value: Amount) -> Result<Self, FundingContributionError> {
		self.0.add_value_inner(value).map(SyncFundingBuilder)
	}

	/// Decreases the requested amount to add to the channel.
	///
	/// `value` is subtracted from the builder's current request, saturating at zero. If the builder
	/// was seeded from a prior contribution, this decreases that prior contribution's current
	/// amount added to the channel. If the updated request cannot be satisfied in-place,
	/// [`SyncFundingBuilder::build`] may re-run coin selection and return a contribution with a
	/// different input set.
	///
	/// Returns [`FundingContributionError::InvalidSpliceValue`] if the builder already has manually
	/// selected inputs.
	pub fn remove_value(self, value: Amount) -> Result<Self, FundingContributionError> {
		self.0.remove_value_inner(value).map(SyncFundingBuilder)
	}
}

impl<W: CoinSelectionSourceSync> SyncFundingBuilder<W> {
	/// Builds a [`FundingContribution`], using the attached synchronous wallet only when needed.
	///
	/// If the request can be satisfied by reusing or amending a prior contribution, or by building
	/// a pure splice-out directly, or by using only manually selected inputs, the attached wallet is
	/// ignored.
	pub fn build(self) -> Result<FundingContribution, FundingContributionError> {
		let inner = self.0;
		match inner.build_without_coin_selection() {
			Err(FundingContributionError::MissingCoinSelectionSource) => {},
			other => return other,
		}

		let (must_spend, must_pay_to) = inner.prepare_coin_selection_request()?;
		let SyncCoinSelectionSource(wallet) = inner.state;
		let coin_selection = wallet
			.select_confirmed_utxos(
				None,
				must_spend,
				&must_pay_to,
				inner.feerate.to_sat_per_kwu() as u32,
				u64::MAX,
			)
			.map_err(|_| FundingContributionError::CoinSelectionFailed)?;

		let CoinSelection { confirmed_utxos: inputs, change_output } = coin_selection;
		validate_inputs(&inputs)?;

		let outputs = inner.outputs;
		let is_splice = inner.shared_input.is_some();
		let estimated_fee = estimate_transaction_fee(
			&inputs,
			&outputs,
			change_output.as_ref(),
			true,
			is_splice,
			inner.feerate,
		);

		return Ok(FundingContribution {
			estimated_fee,
			inputs,
			outputs,
			change_output,
			feerate: inner.feerate,
			max_feerate: inner.max_feerate,
			is_splice,
			input_mode: Some(FundingInputMode::CoinSelected),
		});
	}
}

#[cfg(test)]
mod tests {
	use super::{
		estimate_transaction_fee, FeeRateAdjustmentError, FundingBuilder, FundingContribution,
		FundingContributionError, FundingInputMode, FundingTemplate, FundingTxInput,
		SyncCoinSelectionSource, SyncFundingBuilder,
	};
	use crate::chain::ClaimId;
	use crate::util::wallet_utils::{CoinSelection, CoinSelectionSourceSync, Input};
	use bitcoin::hashes::Hash;
	use bitcoin::transaction::{Transaction, TxOut, Version};
	use bitcoin::{Amount, FeeRate, Psbt, ScriptBuf, SignedAmount, WPubkeyHash, WScriptHash};

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

	struct MustPayToWallet {
		utxo: FundingTxInput,
		change_output: Option<TxOut>,
		expected_must_pay_to_values: Vec<Amount>,
	}

	impl CoinSelectionSourceSync for MustPayToWallet {
		fn select_confirmed_utxos(
			&self, _claim_id: Option<ClaimId>, _must_spend: Vec<Input>, must_pay_to: &[TxOut],
			_target_feerate_sat_per_1000_weight: u32, _max_tx_weight: u64,
		) -> Result<CoinSelection, ()> {
			assert_eq!(
				must_pay_to.iter().map(|output| output.value).collect::<Vec<_>>(),
				self.expected_must_pay_to_values,
			);
			Ok(CoinSelection {
				confirmed_utxos: vec![self.utxo.clone()],
				change_output: self.change_output.clone(),
			})
		}

		fn sign_psbt(&self, _psbt: Psbt) -> Result<Transaction, ()> {
			unreachable!("should not reach signing")
		}
	}

	#[test]
	fn test_funding_builder_builds_splice_out_without_wallet() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let output = funding_output_sats(25_000);

		let contribution = FundingBuilder::new(
			FundingTemplate::new(None, None, None, Amount::MAX_MONEY),
			feerate,
			FeeRate::MAX,
		)
		.add_output(output.clone())
		.build()
		.unwrap();

		let expected_fee = estimate_transaction_fee(
			&[],
			std::slice::from_ref(&output),
			None,
			true,
			false,
			feerate,
		);
		assert!(contribution.inputs.is_empty());
		assert_eq!(contribution.outputs, vec![output.clone()]);
		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.estimated_fee, expected_fee);
		assert_eq!(
			contribution.net_value(),
			-output.value.to_signed().unwrap() - expected_fee.to_signed().unwrap(),
		);
	}

	#[test]
	fn test_funding_builder_rejects_splice_out_over_balance() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let output = funding_output_sats(25_000);
		let expected_fee = estimate_transaction_fee(
			&[],
			std::slice::from_ref(&output),
			None,
			true,
			false,
			feerate,
		);
		let exact_balance = output.value + expected_fee;

		let contribution = FundingTemplate::new(None, None, None, exact_balance)
			.splice_out(vec![output.clone()], feerate, FeeRate::MAX)
			.unwrap();
		assert_eq!(contribution.net_value(), -exact_balance.to_signed().unwrap());

		let result = FundingTemplate::new(None, None, None, exact_balance - Amount::from_sat(1))
			.splice_out(vec![output], feerate, FeeRate::MAX);
		assert!(matches!(result, Err(FundingContributionError::InvalidSpliceValue)));
	}

	#[test]
	fn test_funding_builder_requires_wallet_for_splice_in() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let builder = FundingBuilder::new(
			FundingTemplate::new(None, None, None, Amount::ZERO),
			feerate,
			FeeRate::MAX,
		);
		let builder = FundingBuilder(builder.0.add_value_inner(Amount::from_sat(25_000)).unwrap());

		assert!(matches!(
			builder.build(),
			Err(FundingContributionError::MissingCoinSelectionSource),
		));
	}

	#[test]
	fn test_funding_builder_amends_prior_by_dropping_subdust_change() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(500);
		let dust_limit = change.script_pubkey.minimal_non_dust();
		assert!(change.value >= dust_limit);

		let estimated_fee_with_change =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, feerate);
		let estimated_fee_no_change =
			estimate_transaction_fee(&inputs, &[], None, true, true, feerate);
		let prior = FundingContribution {
			estimated_fee: estimated_fee_with_change,
			inputs: inputs.clone(),
			outputs: vec![],
			change_output: Some(change.clone()),
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let delta = Amount::from_sat(change.value.to_sat() - dust_limit.to_sat() + 1);
		let target_value_added = prior.value_added().checked_add(delta).unwrap();
		let total_input_value: Amount = inputs.iter().map(|input| input.utxo.output.value).sum();
		let remaining_change = total_input_value
			.checked_sub(target_value_added.checked_add(estimated_fee_with_change).unwrap())
			.unwrap();
		assert_eq!(remaining_change.to_sat(), dust_limit.to_sat() - 1);
		assert!(
			total_input_value >= target_value_added.checked_add(estimated_fee_no_change).unwrap()
		);

		let builder = FundingTemplate::new(None, None, Some(prior), Amount::MAX_MONEY)
			.with_prior_contribution(feerate, FeeRate::MAX);
		let contribution =
			FundingBuilder(builder.0.add_value_inner(delta).unwrap()).build().unwrap();

		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.inputs, inputs);
		assert!(contribution.outputs.is_empty());
		assert_eq!(contribution.estimated_fee, estimated_fee_no_change);
		assert_eq!(
			contribution.value_added(),
			total_input_value.checked_sub(estimated_fee_no_change).unwrap()
		);
		assert!(contribution.value_added() > target_value_added);
	}

	#[test]
	fn test_funding_builder_remove_outputs_removes_all_matching_scripts() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let removed_script = ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros());
		let kept_script = ScriptBuf::new_p2wsh(&WScriptHash::all_zeros());
		let removed_output_1 =
			TxOut { value: Amount::from_sat(10_000), script_pubkey: removed_script.clone() };
		let removed_output_2 =
			TxOut { value: Amount::from_sat(12_000), script_pubkey: removed_script.clone() };
		let kept_output = TxOut { value: Amount::from_sat(15_000), script_pubkey: kept_script };

		let contribution = FundingBuilder::new(
			FundingTemplate::new(None, None, None, Amount::MAX_MONEY),
			feerate,
			FeeRate::MAX,
		)
		.add_output(removed_output_1)
		.add_output(kept_output.clone())
		.add_output(removed_output_2)
		.remove_outputs(&removed_script)
		.build()
		.unwrap();

		assert_eq!(contribution.outputs, vec![kept_output]);
	}

	#[test]
	fn test_funding_builder_add_and_remove_value_update_request() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let value_added = Amount::from_sat(15_000);
		let input_template = funding_input_sats(1);
		let estimated_fee = estimate_transaction_fee(
			std::slice::from_ref(&input_template),
			&[],
			None,
			true,
			false,
			feerate,
		);
		let selected_amount = value_added + estimated_fee;
		let input = funding_input_sats(selected_amount.to_sat());
		let wallet = MustPayToWallet {
			utxo: input.clone(),
			change_output: None,
			expected_must_pay_to_values: vec![value_added],
		};

		let contribution = FundingBuilder::new(
			FundingTemplate::new(None, None, None, Amount::ZERO),
			feerate,
			FeeRate::MAX,
		)
		.with_coin_selection_source_sync(wallet)
		.add_value(Amount::from_sat(20_000))
		.unwrap()
		.add_value(Amount::from_sat(5_000))
		.unwrap()
		.remove_value(Amount::from_sat(10_000))
		.unwrap()
		.build()
		.unwrap();

		assert_eq!(contribution.inputs, vec![input]);
		assert!(contribution.outputs.is_empty());
		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.value_added(), value_added);
	}

	#[test]
	fn test_coin_selection_request_funds_outputs_from_inputs() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let value_added = Amount::from_sat(15_000);
		let output = funding_output_sats(8_000);
		let input = funding_input_sats(50_000);
		let change_template = funding_output_sats(1_000);
		let estimated_fee = estimate_transaction_fee(
			std::slice::from_ref(&input),
			std::slice::from_ref(&output),
			Some(&change_template),
			true,
			false,
			feerate,
		);
		let change_value = input.utxo.output.value - value_added - output.value - estimated_fee;
		let wallet = MustPayToWallet {
			utxo: input,
			change_output: Some(TxOut {
				value: change_value,
				script_pubkey: change_template.script_pubkey,
			}),
			expected_must_pay_to_values: vec![output.value, value_added],
		};

		let contribution = FundingBuilder::new(
			FundingTemplate::new(None, None, None, Amount::MAX_MONEY),
			feerate,
			FeeRate::MAX,
		)
		.with_coin_selection_source_sync(wallet)
		.add_value(value_added)
		.unwrap()
		.add_output(output.clone())
		.build()
		.unwrap();

		assert_eq!(contribution.value_added(), value_added);
		assert_eq!(contribution.outputs, vec![output]);
		assert_eq!(contribution.change_output.as_ref().unwrap().value, change_value);
	}

	#[test]
	fn test_funding_builder_remove_value_saturates_at_zero() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let output = funding_output_sats(8_000);
		let contribution = FundingBuilder::new(
			FundingTemplate::new(None, None, None, Amount::MAX_MONEY),
			feerate,
			FeeRate::MAX,
		)
		.with_coin_selection_source_sync(UnreachableWallet)
		.add_value(Amount::from_sat(10_000))
		.unwrap()
		.remove_value(Amount::from_sat(15_000))
		.unwrap()
		.add_output(output.clone())
		.build()
		.unwrap();

		assert!(contribution.inputs.is_empty());
		assert_eq!(contribution.outputs, vec![output]);
		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.value_added(), Amount::ZERO);
	}

	#[test]
	fn test_funding_builder_builds_manual_input_contribution_without_change() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let input = funding_input_sats(100_000);
		let output = funding_output_sats(25_000);

		let contribution = FundingTemplate::new(None, None, None, Amount::ZERO)
			.without_prior_contribution(feerate, FeeRate::MAX)
			.add_input(input.clone())
			.unwrap()
			.add_output(output.clone())
			.build()
			.unwrap();

		let expected_fee = estimate_transaction_fee(
			std::slice::from_ref(&input),
			std::slice::from_ref(&output),
			None,
			true,
			false,
			feerate,
		);
		assert_eq!(contribution.inputs, vec![input]);
		assert_eq!(contribution.outputs, vec![output.clone()]);
		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.input_mode, Some(FundingInputMode::ManuallySelected));
		assert_eq!(contribution.estimated_fee, expected_fee);
		assert_eq!(
			contribution.value_added(),
			Amount::from_sat(100_000) - output.value - expected_fee,
		);
		assert_eq!(
			contribution.net_value(),
			Amount::from_sat(100_000).to_signed().unwrap()
				- output.value.to_signed().unwrap()
				- expected_fee.to_signed().unwrap(),
		);
	}

	#[test]
	fn test_funding_builder_add_inputs_builds_manual_input_contribution() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let first_input = funding_input_sats(40_000);
		let second_input = funding_input_sats(60_000);
		let output = funding_output_sats(25_000);

		let contribution = FundingTemplate::new(None, None, None, Amount::ZERO)
			.without_prior_contribution(feerate, FeeRate::MAX)
			.add_inputs(vec![first_input.clone(), second_input.clone()])
			.unwrap()
			.add_output(output.clone())
			.build()
			.unwrap();

		let expected_fee = estimate_transaction_fee(
			&[first_input.clone(), second_input.clone()],
			std::slice::from_ref(&output),
			None,
			true,
			false,
			feerate,
		);
		assert_eq!(contribution.inputs, vec![first_input, second_input]);
		assert_eq!(contribution.outputs, vec![output.clone()]);
		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.input_mode, Some(FundingInputMode::ManuallySelected));
		assert_eq!(contribution.estimated_fee, expected_fee);
		assert_eq!(
			contribution.value_added(),
			Amount::from_sat(100_000) - output.value - expected_fee,
		);
	}

	#[test]
	fn test_funding_builder_rejects_duplicate_inputs() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let input = funding_input_sats(100_000);

		let result = FundingTemplate::new(None, None, None, Amount::ZERO)
			.without_prior_contribution(feerate, FeeRate::MAX)
			.add_inputs(vec![input.clone(), input])
			.unwrap()
			.build();

		assert!(matches!(result, Err(FundingContributionError::InvalidSpliceValue),));
	}

	#[test]
	fn test_funding_builder_rejects_duplicate_outputs() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let first_output = funding_output_sats(25_000);
		let second_output = funding_output_sats(30_000);
		assert_ne!(first_output, second_output);
		assert_eq!(first_output.script_pubkey, second_output.script_pubkey);

		let result = FundingTemplate::new(None, None, None, Amount::MAX_MONEY)
			.without_prior_contribution(feerate, FeeRate::MAX)
			.add_outputs(vec![first_output, second_output])
			.build();

		assert!(matches!(result, Err(FundingContributionError::InvalidSpliceValue),));
	}

	#[test]
	fn test_funding_builder_remove_input_updates_manual_input_request() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let first_input = funding_input_sats(40_000);
		let second_input = funding_input_sats(60_000);
		let output = funding_output_sats(25_000);

		let contribution = FundingTemplate::new(None, None, None, Amount::ZERO)
			.without_prior_contribution(feerate, FeeRate::MAX)
			.add_inputs(vec![first_input.clone(), second_input.clone()])
			.unwrap()
			.remove_input(&first_input.utxo.outpoint)
			.unwrap()
			.add_output(output.clone())
			.build()
			.unwrap();

		let expected_fee = estimate_transaction_fee(
			std::slice::from_ref(&second_input),
			std::slice::from_ref(&output),
			None,
			true,
			false,
			feerate,
		);
		assert_eq!(contribution.inputs, vec![second_input]);
		assert_eq!(contribution.outputs, vec![output.clone()]);
		assert_eq!(contribution.input_mode, Some(FundingInputMode::ManuallySelected));
		assert_eq!(
			contribution.value_added(),
			Amount::from_sat(60_000) - output.value - expected_fee,
		);
	}

	#[test]
	fn test_splice_in_inputs_builds_manual_input_contribution() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let first_input = funding_input_sats(40_000);
		let second_input = funding_input_sats(60_000);

		let contribution = FundingTemplate::new(None, None, None, Amount::ZERO)
			.splice_in_inputs(
				vec![first_input.clone(), second_input.clone()],
				feerate,
				FeeRate::MAX,
			)
			.unwrap();

		let expected_fee = estimate_transaction_fee(
			&[first_input.clone(), second_input.clone()],
			&[],
			None,
			true,
			false,
			feerate,
		);
		assert_eq!(contribution.inputs, vec![first_input, second_input]);
		assert!(contribution.outputs.is_empty());
		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.input_mode, Some(FundingInputMode::ManuallySelected));
		assert_eq!(contribution.value_added(), Amount::from_sat(100_000) - expected_fee);
	}

	#[test]
	fn test_splice_in_inputs_appends_to_prior_manual_inputs() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let prior_input = funding_input_sats(40_000);
		let additional_input = funding_input_sats(60_000);
		let prior_fee = estimate_transaction_fee(
			std::slice::from_ref(&prior_input),
			&[],
			None,
			true,
			false,
			feerate,
		);
		let prior = FundingContribution {
			estimated_fee: prior_fee,
			inputs: vec![prior_input.clone()],
			outputs: vec![],
			change_output: None,
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: false,
			input_mode: Some(FundingInputMode::ManuallySelected),
		};

		let contribution = FundingTemplate::new(None, None, Some(prior), Amount::MAX_MONEY)
			.splice_in_inputs(vec![additional_input.clone()], feerate, FeeRate::MAX)
			.unwrap();

		assert_eq!(contribution.inputs, vec![prior_input, additional_input]);
		assert!(contribution.outputs.is_empty());
		assert_eq!(contribution.input_mode, Some(FundingInputMode::ManuallySelected));
	}

	#[test]
	fn test_sync_funding_builder_manual_inputs_insufficient_do_not_fallback_to_coin_selection() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let builder = FundingTemplate::new(None, None, None, Amount::ZERO)
			.without_prior_contribution(feerate, FeeRate::MAX)
			.add_input(funding_input_sats(1))
			.unwrap();
		let builder =
			SyncFundingBuilder(builder.0.with_state(SyncCoinSelectionSource(UnreachableWallet)));

		assert!(matches!(
			builder.build(),
			Err(FundingContributionError::ManuallySelectedInputsInsufficient),
		));
	}

	#[test]
	fn test_funding_builder_rejects_manual_inputs_with_value_request() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let builder = FundingTemplate::new(None, None, None, Amount::ZERO)
			.without_prior_contribution(feerate, FeeRate::MAX)
			.add_input(funding_input_sats(100_000))
			.unwrap();
		let result = builder.clone().0.add_value_inner(Amount::from_sat(1_000));
		assert!(matches!(result, Err(FundingContributionError::InvalidSpliceValue),));

		let builder =
			SyncFundingBuilder(builder.0.with_state(SyncCoinSelectionSource(UnreachableWallet)));
		let result = builder.remove_value(Amount::from_sat(1_000));
		assert!(matches!(result, Err(FundingContributionError::InvalidSpliceValue),));
	}

	#[test]
	fn test_funding_builder_rejects_manual_inputs_on_coin_selected_prior() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let prior_input = funding_input_sats(100_000);
		let prior_outpoint = prior_input.utxo.outpoint;
		let prior = FundingContribution {
			estimated_fee: Amount::from_sat(1_000),
			inputs: vec![prior_input],
			outputs: vec![],
			change_output: Some(funding_output_sats(10_000)),
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: false,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let builder = FundingTemplate::new(None, None, Some(prior), Amount::MAX_MONEY)
			.with_prior_contribution(feerate, FeeRate::MAX);

		assert!(matches!(
			builder.clone().add_input(funding_input_sats(50_000)),
			Err(FundingContributionError::InvalidSpliceValue),
		));
		assert!(matches!(
			builder.remove_input(&prior_outpoint),
			Err(FundingContributionError::InvalidSpliceValue),
		));
	}

	#[test]
	fn test_funding_builder_validates_manual_input_max_money() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let inputs = vec![funding_input_sats(Amount::MAX_MONEY.to_sat()), funding_input_sats(1)];

		let builder = FundingTemplate::new(None, None, None, Amount::ZERO)
			.without_prior_contribution(feerate, FeeRate::MAX)
			.add_inputs(inputs)
			.unwrap();

		assert!(matches!(builder.build(), Err(FundingContributionError::InvalidSpliceValue),));
	}

	#[test]
	fn test_build_from_prior_manual_inputs_exact_match_reuses_and_adjusts() {
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(3000);
		let input = funding_input_sats(100_000);
		let output = funding_output_sats(20_000);
		let estimated_fee = estimate_transaction_fee(
			std::slice::from_ref(&input),
			std::slice::from_ref(&output),
			None,
			true,
			false,
			original_feerate,
		);
		let prior = FundingContribution {
			estimated_fee,
			inputs: vec![input.clone()],
			outputs: vec![output.clone()],
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: false,
			input_mode: Some(FundingInputMode::ManuallySelected),
		};

		let contribution = FundingTemplate::new(None, None, Some(prior), Amount::MAX_MONEY)
			.with_prior_contribution(target_feerate, FeeRate::MAX)
			.build()
			.unwrap();

		assert_eq!(contribution.inputs, vec![input]);
		assert_eq!(contribution.outputs, vec![output]);
		assert_eq!(contribution.feerate, target_feerate);
		assert_eq!(contribution.input_mode, Some(FundingInputMode::ManuallySelected));
	}

	#[test]
	fn test_build_from_prior_manual_inputs_changed_request_insufficient_maps_error() {
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let input = funding_input_sats(50_000);
		let estimated_fee =
			estimate_transaction_fee(std::slice::from_ref(&input), &[], None, true, false, feerate);
		let prior = FundingContribution {
			estimated_fee,
			inputs: vec![input],
			outputs: vec![],
			change_output: None,
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: false,
			input_mode: Some(FundingInputMode::ManuallySelected),
		};

		let result = FundingTemplate::new(None, None, Some(prior), Amount::ZERO)
			.with_prior_contribution(feerate, FeeRate::MAX)
			.add_output(funding_output_sats(60_000))
			.build();

		assert!(matches!(
			result,
			Err(FundingContributionError::ManuallySelectedInputsInsufficient),
		));
	}

	#[test]
	fn test_for_acceptor_at_feerate_manual_inputs_balance_insufficient() {
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(100_000);
		let inputs = vec![funding_input_sats(100_000)];
		let outputs = vec![funding_output_sats(80_000)];
		let net_value_without_fee = Amount::from_sat(20_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &outputs, None, true, true, original_feerate);
		let target_fee =
			estimate_transaction_fee(&inputs, &outputs, None, false, true, target_feerate);
		assert!(target_fee > net_value_without_fee);

		let contribution = FundingContribution {
			estimated_fee,
			inputs,
			outputs,
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::ManuallySelected),
		};

		let holder_balance = target_fee
			.checked_sub(net_value_without_fee)
			.and_then(|shortfall| shortfall.checked_sub(Amount::from_sat(1)))
			.unwrap();
		match contribution.for_acceptor_at_feerate(target_feerate, holder_balance) {
			Err(FeeRateAdjustmentError::FeeBufferInsufficient { source, available, required }) => {
				assert_eq!(source, "channel balance");
				assert_eq!(available, target_fee - Amount::from_sat(1));
				assert_eq!(required, target_fee);
			},
			other => panic!("Expected channel-balance shortfall, got {other:?}"),
		}
	}

	#[test]
	fn test_for_acceptor_at_feerate_manual_inputs_balance_sufficient() {
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(100_000);
		let inputs = vec![funding_input_sats(100_000)];
		let outputs = vec![funding_output_sats(80_000)];
		let net_value_without_fee = Amount::from_sat(20_000);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &outputs, None, true, true, original_feerate);
		let target_fee =
			estimate_transaction_fee(&inputs, &outputs, None, false, true, target_feerate);

		let contribution = FundingContribution {
			estimated_fee,
			inputs: inputs.clone(),
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::ManuallySelected),
		};

		let holder_balance = target_fee.checked_sub(net_value_without_fee).unwrap();
		let adjusted =
			contribution.for_acceptor_at_feerate(target_feerate, holder_balance).unwrap();

		assert_eq!(adjusted.inputs, inputs);
		assert_eq!(adjusted.outputs, outputs);
		assert_eq!(adjusted.estimated_fee, target_fee);
		assert_eq!(
			adjusted.net_value(),
			net_value_without_fee.to_signed().unwrap() - target_fee.to_signed().unwrap(),
		);
	}

	#[test]
	fn test_build_funding_contribution_validates_max_money() {
		let over_max = Amount::MAX_MONEY + Amount::from_sat(1);
		let feerate = FeeRate::from_sat_per_kwu(2000);

		// splice_in_sync with value_added > MAX_MONEY
		{
			let template = FundingTemplate::new(None, None, None, Amount::ZERO);
			assert!(matches!(
				template.splice_in_sync(over_max, feerate, feerate, UnreachableWallet),
				Err(FundingContributionError::InvalidSpliceValue),
			));
		}

		// splice_out with single output value > MAX_MONEY
		{
			let template = FundingTemplate::new(None, None, None, Amount::ZERO);
			let outputs = vec![funding_output_sats(over_max.to_sat())];
			assert!(matches!(
				template.splice_out(outputs, feerate, feerate),
				Err(FundingContributionError::InvalidSpliceValue),
			));
		}

		// splice_out with multiple outputs summing > MAX_MONEY
		{
			let template = FundingTemplate::new(None, None, None, Amount::ZERO);
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
	}

	#[test]
	fn test_funding_builder_validates_mixed_request_max_money() {
		let over_max = Amount::MAX_MONEY + Amount::from_sat(1);
		let feerate = FeeRate::from_sat_per_kwu(2000);

		// Mixed add/remove request with value_added > MAX_MONEY.
		assert!(matches!(
			FundingTemplate::new(None, None, None, Amount::ZERO)
				.without_prior_contribution(feerate, feerate)
				.with_coin_selection_source_sync(UnreachableWallet)
				.add_value(over_max)
				.unwrap()
				.add_outputs(vec![funding_output_sats(1_000)])
				.build(),
			Err(FundingContributionError::InvalidSpliceValue),
		));

		// Mixed add/remove request with outputs summing > MAX_MONEY.
		let half_over = Amount::MAX_MONEY / 2 + Amount::from_sat(1);
		assert!(matches!(
			FundingTemplate::new(None, None, None, Amount::ZERO)
				.without_prior_contribution(feerate, feerate)
				.with_coin_selection_source_sync(UnreachableWallet)
				.add_value(Amount::from_sat(1_000))
				.unwrap()
				.add_outputs(vec![
					funding_output_sats(half_over.to_sat()),
					funding_output_sats(half_over.to_sat()),
				])
				.build(),
			Err(FundingContributionError::InvalidSpliceValue),
		));
	}

	#[test]
	fn test_build_funding_contribution_validates_feerate_range() {
		let low = FeeRate::from_sat_per_kwu(1000);
		let high = FeeRate::from_sat_per_kwu(2000);

		// min_feerate > max_feerate is rejected
		{
			let template = FundingTemplate::new(None, None, None, Amount::ZERO);
			assert!(matches!(
				template.splice_in_sync(Amount::from_sat(10_000), high, low, UnreachableWallet),
				Err(FundingContributionError::FeeRateExceedsMaximum { .. }),
			));
		}

		// min_feerate < min_rbf_feerate is rejected
		{
			let template = FundingTemplate::new(None, Some(high), None, Amount::ZERO);
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
	fn test_build_funding_contribution_rejects_oversized_prevtx() {
		use crate::util::ser::Writeable;

		let feerate = FeeRate::from_sat_per_kwu(2000);
		let prevtx = Transaction {
			input: vec![],
			output: vec![funding_output_sats(50_000); 2_200],
			version: Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
		};
		assert!(prevtx.serialized_length() > crate::ln::LN_MAX_MSG_LEN);

		let wallet = SingleUtxoWallet {
			utxo: FundingTxInput::new_p2wpkh(prevtx, 0).unwrap(),
			change_output: None,
		};
		assert!(matches!(
			FundingTemplate::new(None, None, None, Amount::ZERO)
				.with_prior_contribution(feerate, feerate)
				.with_coin_selection_source_sync(wallet)
				.add_value(Amount::from_sat(10_000))
				.unwrap()
				.build(),
			Err(FundingContributionError::PrevTxTooLarge),
		));
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
			estimated_fee,
			inputs: inputs.clone(),
			outputs: vec![],
			change_output: Some(change.clone()),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let net_value_before = contribution.net_value();
		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY).unwrap();

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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs: inputs.clone(),
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let net_value_before = contribution.net_value();
		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY).unwrap();

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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs: vec![],
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY).unwrap();
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
			estimated_fee,
			inputs: vec![],
			outputs,
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		// Balance of 55,000 sats can't cover outputs (50,000) + target_fee at 50k sat/kwu.
		let spliceable_balance = Amount::from_sat(55_000);
		let result = contribution.for_acceptor_at_feerate(target_feerate, spliceable_balance);
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
		let change_value = change.value;

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		// For splice-in with change that stays above dust, the surplus is absorbed by the change
		// output so net_value_for_acceptor_at_feerate equals net_value.
		let net_at_feerate = contribution
			.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY)
			.unwrap();
		assert_eq!(net_at_feerate, contribution.net_value());
		assert_eq!(
			net_at_feerate,
			(Amount::from_sat(100_000) - estimated_fee - change_value).to_signed().unwrap(),
		);
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
			estimated_fee,
			inputs: vec![],
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let net_at_feerate = contribution
			.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY)
			.unwrap();

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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let net_before = contribution.net_value();
		let fee_before = contribution.estimated_fee;
		let change_before = contribution.change_output.as_ref().unwrap().value;

		let _ = contribution.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);

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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result =
			contribution.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change.clone()),
			feerate: original_feerate,
			max_feerate,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY);
		assert!(result.is_ok());
		let adjusted = result.unwrap();
		assert!(adjusted.change_output.is_none());
		assert_eq!(adjusted.estimated_fee, target_fee);
	}

	#[test]
	fn test_for_acceptor_at_feerate_no_change_surplus_absorbed() {
		// Inputs, no change. The estimated_fee (is_initiator=true) far exceeds the acceptor's
		// target fee (is_initiator=false). The surplus stays in the channel contribution rather
		// than being burned as excess fees.
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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		// target == min feerate, so FeeRateTooLow check passes.
		// The surplus (estimated_fee - target_fee) goes to value_added (shared output).
		let net_value_before = contribution.net_value();
		let result = contribution.for_acceptor_at_feerate(feerate, Amount::MAX_MONEY);
		assert!(result.is_ok());
		let adjusted = result.unwrap();
		assert!(adjusted.change_output.is_none());
		assert_eq!(adjusted.estimated_fee, target_fee);
		let surplus = estimated_fee - target_fee;
		assert_eq!(adjusted.value_added(), value_added + surplus);
		assert_eq!(adjusted.net_value(), net_value_before + surplus.to_signed().unwrap());
	}

	#[test]
	fn test_for_acceptor_at_feerate_fee_buffer_overflow_with_change() {
		// Overflow in estimated_fee + change value should surface as FeeBufferOverflow.
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let contribution = FundingContribution {
			estimated_fee: Amount::MAX,
			inputs: vec![funding_input_sats(100_000)],
			outputs: vec![],
			change_output: Some(funding_output_sats(1)),
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let result = contribution.for_acceptor_at_feerate(feerate, Amount::MAX_MONEY);
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
			estimated_fee,
			inputs: vec![],
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		// Balance of 40,000 sats is less than outputs (50,000) + target_fee.
		let spliceable_balance = Amount::from_sat(40_000);
		let result = contribution.for_acceptor_at_feerate(target_feerate, spliceable_balance);
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
			estimated_fee,
			inputs: vec![],
			outputs: outputs.clone(),
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		// Balance of 100,000 sats is more than outputs (50,000) + target_fee.
		let spliceable_balance = Amount::from_sat(100_000);
		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, spliceable_balance).unwrap();
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
			estimated_fee,
			inputs: vec![],
			outputs,
			change_output: None,
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		// Balance of 40,000 sats is less than outputs (50,000) + target_fee.
		let spliceable_balance = Amount::from_sat(40_000);
		let result =
			contribution.net_value_for_acceptor_at_feerate(target_feerate, spliceable_balance);
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
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: original_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let acceptor = contribution
			.clone()
			.for_acceptor_at_feerate(target_feerate, Amount::MAX_MONEY)
			.unwrap();
		let initiator =
			contribution.for_initiator_at_feerate(target_feerate, Amount::MAX_MONEY).unwrap();

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
	fn test_rbf_rejects_max_feerate_below_min_rbf_feerate() {
		// When the caller's max_feerate is below the minimum RBF feerate,
		// rbf_prior_contribution_sync should return an error.
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let max_feerate = FeeRate::from_sat_per_kwu(2020);

		let prior = FundingContribution {
			estimated_fee: Amount::from_sat(1_000),
			inputs: vec![funding_input_sats(100_000)],
			outputs: vec![],
			change_output: None,
			feerate: prior_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		// max_feerate (2020) < min_rbf_feerate (2025).
		let template =
			FundingTemplate::new(None, Some(min_rbf_feerate), Some(prior), Amount::MAX_MONEY);
		assert!(matches!(
			template.rbf_prior_contribution_sync(None, max_feerate, UnreachableWallet),
			Err(FundingContributionError::FeeRateExceedsMaximum { .. }),
		));
	}

	#[test]
	fn test_rbf_adjusts_prior_to_rbf_feerate() {
		// When the prior contribution's feerate is below the minimum RBF feerate and holder
		// balance is available, rbf_prior_contribution_sync should adjust the prior to the
		// RBF feerate.
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let max_feerate = FeeRate::from_sat_per_kwu(5000);

		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);
		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, prior_feerate);

		let prior = FundingContribution {
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: prior_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let template =
			FundingTemplate::new(None, Some(min_rbf_feerate), Some(prior), Amount::MAX_MONEY);
		let contribution =
			template.rbf_prior_contribution_sync(None, max_feerate, UnreachableWallet).unwrap();
		assert_eq!(contribution.feerate, min_rbf_feerate);
		assert_eq!(contribution.max_feerate, max_feerate);
	}

	#[test]
	fn test_rbf_uses_explicit_override_feerate() {
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let override_feerate = FeeRate::from_sat_per_kwu(2100);
		let max_feerate = FeeRate::from_sat_per_kwu(5000);

		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);
		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, prior_feerate);

		let prior = FundingContribution {
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: Some(change),
			feerate: prior_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let template =
			FundingTemplate::new(None, Some(min_rbf_feerate), Some(prior), Amount::MAX_MONEY);
		let contribution = template
			.rbf_prior_contribution_sync(Some(override_feerate), max_feerate, UnreachableWallet)
			.unwrap();
		assert_eq!(contribution.feerate, override_feerate);
		assert_eq!(contribution.max_feerate, max_feerate);
	}

	#[test]
	fn test_rbf_rejects_explicit_override_below_min_rbf_feerate() {
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let override_feerate = FeeRate::from_sat_per_kwu(2024);

		let prior = FundingContribution {
			estimated_fee: Amount::from_sat(1_000),
			inputs: vec![funding_input_sats(100_000)],
			outputs: vec![],
			change_output: None,
			feerate: prior_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let template =
			FundingTemplate::new(None, Some(min_rbf_feerate), Some(prior), Amount::MAX_MONEY);
		assert!(matches!(
			template.rbf_prior_contribution_sync(
				Some(override_feerate),
				FeeRate::MAX,
				UnreachableWallet,
			),
			Err(FundingContributionError::FeeRateBelowRbfMinimum { .. }),
		));
	}

	#[test]
	fn test_rbf_rejects_explicit_override_above_max_feerate() {
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let override_feerate = FeeRate::from_sat_per_kwu(2100);
		let max_feerate = FeeRate::from_sat_per_kwu(2099);

		let prior = FundingContribution {
			estimated_fee: Amount::from_sat(1_000),
			inputs: vec![funding_input_sats(100_000)],
			outputs: vec![],
			change_output: None,
			feerate: prior_feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let template =
			FundingTemplate::new(None, Some(min_rbf_feerate), Some(prior), Amount::MAX_MONEY);
		assert!(matches!(
			template.rbf_prior_contribution_sync(
				Some(override_feerate),
				max_feerate,
				UnreachableWallet,
			),
			Err(FundingContributionError::FeeRateExceedsMaximum { .. }),
		));
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
	fn test_rbf_unadjusted_splice_out_runs_coin_selection() {
		// When the prior contribution's feerate is below the minimum RBF feerate and no
		// holder balance is available, rbf_prior_contribution_sync should run coin selection to
		// add inputs that cover the higher RBF fee.
		let prior_feerate = FeeRate::from_sat_per_kwu(2000);
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let withdrawal = funding_output_sats(20_000);

		let prior = FundingContribution {
			estimated_fee: Amount::from_sat(500),
			inputs: vec![],
			outputs: vec![withdrawal.clone()],
			change_output: None,
			feerate: prior_feerate,
			max_feerate: prior_feerate,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let template = FundingTemplate::new(
			Some(shared_input(100_000)),
			Some(min_rbf_feerate),
			Some(prior),
			Amount::ZERO,
		);

		let wallet = SingleUtxoWallet {
			utxo: funding_input_sats(50_000),
			change_output: Some(funding_output_sats(25_000)),
		};

		// rbf_prior_contribution_sync should succeed and the contribution should have inputs from
		// coin selection.
		let contribution =
			template.rbf_prior_contribution_sync(None, FeeRate::MAX, &wallet).unwrap();
		assert!(!contribution.inputs.is_empty(), "coin selection should have added inputs");
		assert!(contribution.value_added() > Amount::ZERO);
		assert_eq!(contribution.outputs, vec![withdrawal]);
		assert_eq!(contribution.feerate, min_rbf_feerate);
	}

	#[test]
	fn test_rbf_unadjusted_uses_callers_max_feerate() {
		// When the prior contribution's feerate is below the minimum RBF feerate and no
		// holder balance is available, rbf_prior_contribution_sync should use the caller's
		// max_feerate (not the prior's) for the resulting contribution.
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let prior_max_feerate = FeeRate::from_sat_per_kwu(50_000);
		let callers_max_feerate = FeeRate::from_sat_per_kwu(10_000);
		let withdrawal = funding_output_sats(20_000);

		let prior = FundingContribution {
			estimated_fee: Amount::from_sat(500),
			inputs: vec![],
			outputs: vec![withdrawal.clone()],
			change_output: None,
			feerate: FeeRate::from_sat_per_kwu(2000),
			max_feerate: prior_max_feerate,
			is_splice: true,
			input_mode: Some(FundingInputMode::CoinSelected),
		};

		let template = FundingTemplate::new(
			Some(shared_input(100_000)),
			Some(min_rbf_feerate),
			Some(prior),
			Amount::MAX_MONEY,
		);

		let wallet = SingleUtxoWallet {
			utxo: funding_input_sats(50_000),
			change_output: Some(funding_output_sats(25_000)),
		};

		let contribution =
			template.rbf_prior_contribution_sync(None, callers_max_feerate, &wallet).unwrap();
		assert_eq!(
			contribution.max_feerate, callers_max_feerate,
			"should use caller's max_feerate, not prior's"
		);
	}

	#[test]
	fn test_splice_out_skips_coin_selection_during_rbf() {
		// When splice_out is called on a template with min_rbf_feerate set (user choosing a
		// fresh splice-out instead of rbf_prior_contribution_sync), coin selection should NOT
		// run.
		// Fees come from the channel balance.
		let min_rbf_feerate = FeeRate::from_sat_per_kwu(2025);
		let feerate = FeeRate::from_sat_per_kwu(2025);
		let withdrawal = funding_output_sats(20_000);

		let template = FundingTemplate::new(
			Some(shared_input(100_000)),
			Some(min_rbf_feerate),
			None,
			Amount::MAX_MONEY,
		);

		let contribution =
			template.splice_out(vec![withdrawal.clone()], feerate, FeeRate::MAX).unwrap();
		assert_eq!(contribution.value_added(), Amount::ZERO);
		assert!(contribution.inputs.is_empty());
		assert!(contribution.change_output.is_none());
		assert_eq!(contribution.outputs, vec![withdrawal]);
	}
}
