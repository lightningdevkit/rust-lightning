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
use bitcoin::{
	Amount, FeeRate, OutPoint, ScriptBuf, SignedAmount, TxOut, WPubkeyHash, WScriptHash, Weight,
};

use crate::ln::chan_utils::{
	make_funding_redeemscript, BASE_INPUT_WEIGHT, EMPTY_SCRIPT_SIG_WEIGHT,
	FUNDING_TRANSACTION_WITNESS_WEIGHT,
};
use crate::ln::interactivetxs::{get_output_weight, TX_COMMON_FIELDS_WEIGHT};
use crate::ln::msgs;
use crate::ln::types::ChannelId;
use crate::ln::LN_MAX_MSG_LEN;
use crate::prelude::*;
use crate::util::async_poll::MaybeSend;
use crate::util::wallet_utils::{
	CoinSelection, CoinSelectionSource, CoinSelectionSourceSync, Input,
};

/// Error returned when the acceptor's contribution cannot accommodate the initiator's proposed
/// feerate.
#[derive(Debug)]
pub(super) enum FeeRateAdjustmentError {
	/// Target feerate is below our minimum. The counterparty's splice can proceed without our
	/// contribution; we'll retry via RBF at our preferred feerate.
	TooLow { target_feerate: FeeRate, min_feerate: FeeRate },
	/// Target feerate is above our maximum and our fair fee exceeds the available budget (UTXO
	/// inputs for splice-in, or channel balance for splice-out). The splice should be rejected.
	TooHigh { target_feerate: FeeRate, max_feerate: FeeRate, fair_fee: Amount, budget: Amount },
	/// Arithmetic overflow when computing the available budget.
	BudgetOverflow,
	/// The available budget is insufficient to cover the required fees. For splice-in, the budget
	/// comes from UTXO inputs; for splice-out, it comes from the channel balance. The
	/// counterparty's splice can proceed without our contribution.
	BudgetInsufficient { available: Amount, required: Amount },
	/// Fee surplus exceeds dust limit and cannot be absorbed without a change output.
	SurplusExceedsDust { surplus: Amount, dust_limit: Amount },
}

impl core::fmt::Display for FeeRateAdjustmentError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			FeeRateAdjustmentError::TooLow { target_feerate, min_feerate } => {
				write!(f, "Target feerate {} is below our minimum {}", target_feerate, min_feerate)
			},
			FeeRateAdjustmentError::TooHigh { target_feerate, max_feerate, fair_fee, budget } => {
				write!(
					f,
					"Target feerate {} exceeds our maximum {} and fair fee {} exceeds budget {}",
					target_feerate, max_feerate, fair_fee, budget,
				)
			},
			FeeRateAdjustmentError::BudgetOverflow => {
				write!(f, "Arithmetic overflow when computing available budget")
			},
			FeeRateAdjustmentError::BudgetInsufficient { available, required } => {
				write!(f, "Fee budget {} insufficient for required fee {}", available, required)
			},
			FeeRateAdjustmentError::SurplusExceedsDust { surplus, dust_limit } => {
				write!(
					f,
					"Fee surplus {} exceeds dust limit {}; cannot burn without change output",
					surplus, dust_limit,
				)
			},
		}
	}
}

/// A template for contributing to a channel's splice funding transaction.
///
/// This is returned from [`ChannelManager::splice_channel`] when a channel is ready to be
/// spliced. It must be converted to a [`FundingContribution`] using one of the splice methods
/// and passed to [`ChannelManager::funding_contributed`] in order to resume the splicing
/// process.
///
/// [`ChannelManager::splice_channel`]: crate::ln::channelmanager::ChannelManager::splice_channel
/// [`ChannelManager::funding_contributed`]: crate::ln::channelmanager::ChannelManager::funding_contributed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingTemplate {
	/// The shared input, which, if present indicates the funding template is for a splice funding
	/// transaction.
	shared_input: Option<Input>,

	/// The minimum fee rate to use for coin selection and to propose as initiator.
	min_feerate: FeeRate,

	/// The maximum fee rate to accept as acceptor before rejecting the splice.
	max_feerate: FeeRate,
}

impl FundingTemplate {
	/// Constructs a [`FundingTemplate`] for a splice using the provided shared input.
	pub(super) fn new(
		shared_input: Option<Input>, min_feerate: FeeRate, max_feerate: FeeRate,
	) -> Self {
		Self { shared_input, min_feerate, max_feerate }
	}
}

macro_rules! build_funding_contribution {
    ($value_added:expr, $outputs:expr, $shared_input:expr, $feerate:expr, $max_feerate:expr, $wallet:ident, $($await:tt)*) => {{
		let value_added: Amount = $value_added;
		let outputs: Vec<TxOut> = $outputs;
		let shared_input: Option<Input> = $shared_input;
		let feerate: FeeRate = $feerate;
		let max_feerate: FeeRate = $max_feerate;

		// Validate user-provided amounts are within MAX_MONEY before coin selection to
		// ensure FundingContribution::net_value() arithmetic cannot overflow. With all
		// amounts bounded by MAX_MONEY (~2.1e15 sat), the worst-case net_value()
		// computation is -2 * MAX_MONEY (~-4.2e15), well within i64::MIN (~-9.2e18).
		if value_added > Amount::MAX_MONEY {
			return Err(());
		}

		let mut value_removed = Amount::ZERO;
		for txout in outputs.iter() {
			value_removed = match value_removed.checked_add(txout.value) {
				Some(sum) if sum <= Amount::MAX_MONEY => sum,
				_ => return Err(()),
			};
		}

		let is_splice = shared_input.is_some();

		let coin_selection = if value_added == Amount::ZERO {
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
					.ok_or(())?
					.checked_sub(value_removed)
					.ok_or(())?,
				script_pubkey: make_funding_redeemscript(&dummy_pubkey, &dummy_pubkey).to_p2wsh(),
			};

			let claim_id = None;
			let must_spend = shared_input.map(|input| vec![input]).unwrap_or_default();
			if outputs.is_empty() {
				let must_pay_to = &[shared_output];
				$wallet.select_confirmed_utxos(claim_id, must_spend, must_pay_to, feerate.to_sat_per_kwu() as u32, u64::MAX)$(.$await)*?
			} else {
				let must_pay_to: Vec<_> = outputs.iter().cloned().chain(core::iter::once(shared_output)).collect();
				$wallet.select_confirmed_utxos(claim_id, must_spend, &must_pay_to, feerate.to_sat_per_kwu() as u32, u64::MAX)$(.$await)*?
			}
		};

		// NOTE: Must NOT fail after UTXO selection

		let CoinSelection { confirmed_utxos: inputs, change_output } = coin_selection;

		// The caller creating a FundingContribution is always the initiator for fee estimation
		// purposes — this is conservative, overestimating rather than underestimating fees if
		// the node ends up as the acceptor.
		let estimated_fee = estimate_transaction_fee(&inputs, &outputs, change_output.as_ref(), true, is_splice, feerate);
		debug_assert!(estimated_fee <= Amount::MAX_MONEY);

		let contribution = FundingContribution {
			value_added,
			estimated_fee,
			inputs,
			outputs,
			change_output,
			feerate,
			max_feerate,
			is_splice,
		};

		Ok(contribution)
	}};
}

impl FundingTemplate {
	/// Creates a [`FundingContribution`] for adding funds to a channel using `wallet` to perform
	/// coin selection.
	pub async fn splice_in<W: CoinSelectionSource + MaybeSend>(
		self, value_added: Amount, wallet: W,
	) -> Result<FundingContribution, ()> {
		if value_added == Amount::ZERO {
			return Err(());
		}
		let FundingTemplate { shared_input, min_feerate, max_feerate } = self;
		build_funding_contribution!(value_added, vec![], shared_input, min_feerate, max_feerate, wallet, await)
	}

	/// Creates a [`FundingContribution`] for adding funds to a channel using `wallet` to perform
	/// coin selection.
	pub fn splice_in_sync<W: CoinSelectionSourceSync>(
		self, value_added: Amount, wallet: W,
	) -> Result<FundingContribution, ()> {
		if value_added == Amount::ZERO {
			return Err(());
		}
		let FundingTemplate { shared_input, min_feerate, max_feerate } = self;
		build_funding_contribution!(
			value_added,
			vec![],
			shared_input,
			min_feerate,
			max_feerate,
			wallet,
		)
	}

	/// Creates a [`FundingContribution`] for removing funds from a channel using `wallet` to
	/// perform coin selection.
	pub async fn splice_out<W: CoinSelectionSource + MaybeSend>(
		self, outputs: Vec<TxOut>, wallet: W,
	) -> Result<FundingContribution, ()> {
		if outputs.is_empty() {
			return Err(());
		}
		let FundingTemplate { shared_input, min_feerate, max_feerate } = self;
		build_funding_contribution!(Amount::ZERO, outputs, shared_input, min_feerate, max_feerate, wallet, await)
	}

	/// Creates a [`FundingContribution`] for removing funds from a channel using `wallet` to
	/// perform coin selection.
	pub fn splice_out_sync<W: CoinSelectionSourceSync>(
		self, outputs: Vec<TxOut>, wallet: W,
	) -> Result<FundingContribution, ()> {
		if outputs.is_empty() {
			return Err(());
		}
		let FundingTemplate { shared_input, min_feerate, max_feerate } = self;
		build_funding_contribution!(
			Amount::ZERO,
			outputs,
			shared_input,
			min_feerate,
			max_feerate,
			wallet,
		)
	}

	/// Creates a [`FundingContribution`] for both adding and removing funds from a channel using
	/// `wallet` to perform coin selection.
	pub async fn splice_in_and_out<W: CoinSelectionSource + MaybeSend>(
		self, value_added: Amount, outputs: Vec<TxOut>, wallet: W,
	) -> Result<FundingContribution, ()> {
		if value_added == Amount::ZERO && outputs.is_empty() {
			return Err(());
		}
		let FundingTemplate { shared_input, min_feerate, max_feerate } = self;
		build_funding_contribution!(value_added, outputs, shared_input, min_feerate, max_feerate, wallet, await)
	}

	/// Creates a [`FundingContribution`] for both adding and removing funds from a channel using
	/// `wallet` to perform coin selection.
	pub fn splice_in_and_out_sync<W: CoinSelectionSourceSync>(
		self, value_added: Amount, outputs: Vec<TxOut>, wallet: W,
	) -> Result<FundingContribution, ()> {
		if value_added == Amount::ZERO && outputs.is_empty() {
			return Err(());
		}
		let FundingTemplate { shared_input, min_feerate, max_feerate } = self;
		build_funding_contribution!(
			value_added,
			outputs,
			shared_input,
			min_feerate,
			max_feerate,
			wallet,
		)
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
#[derive(Debug, Clone)]
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

impl FundingContribution {
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

	/// Computes the adjusted fee and change output value for the acceptor at the initiator's
	/// proposed feerate, which may differ from the feerate used during coin selection.
	///
	/// On success, returns the new estimated fee and, if applicable, the new change output value:
	/// - `Some(change)` — the adjusted change output value
	/// - `None` — no change output (no inputs or change fell below dust)
	///
	/// Returns `Err` if the contribution cannot accommodate the target feerate.
	fn compute_feerate_adjustment(
		&self, target_feerate: FeeRate, holder_balance: Amount,
	) -> Result<(Amount, Option<Amount>), FeeRateAdjustmentError> {
		if target_feerate < self.feerate {
			return Err(FeeRateAdjustmentError::TooLow {
				target_feerate,
				min_feerate: self.feerate,
			});
		}

		if target_feerate > self.max_feerate {
			// Check if the acceptor's fair fee exceeds their estimated fee (budget).
			// If fair_fee <= estimated_fee, the change output isn't consumed (it may even
			// grow), so we allow it despite exceeding max_feerate.
			let fair_fee = estimate_transaction_fee(
				&self.inputs,
				&self.outputs,
				self.change_output.as_ref(),
				false,
				self.is_splice,
				target_feerate,
			);
			if fair_fee > self.estimated_fee {
				return Err(FeeRateAdjustmentError::TooHigh {
					target_feerate,
					max_feerate: self.max_feerate,
					fair_fee,
					budget: self.estimated_fee,
				});
			}
			// Fall through: fair_fee <= estimated_fee, change not consumed
		}

		let is_splice = self.is_splice;

		if !self.inputs.is_empty() {
			if let Some(ref change_output) = self.change_output {
				let old_change_value = change_output.value;
				let dust_limit = change_output.script_pubkey.minimal_non_dust();

				// Fair fee including the change output's weight.
				let fair_fee = estimate_transaction_fee(
					&self.inputs,
					&self.outputs,
					self.change_output.as_ref(),
					false,
					is_splice,
					target_feerate,
				);

				let budget = self
					.estimated_fee
					.checked_add(old_change_value)
					.ok_or(FeeRateAdjustmentError::BudgetOverflow)?;

				match budget.checked_sub(fair_fee) {
					Some(new_change_value) if new_change_value >= dust_limit => {
						Ok((fair_fee, Some(new_change_value)))
					},
					_ => {
						// Change would be below dust or negative. Try without change.
						let fair_fee_no_change = estimate_transaction_fee(
							&self.inputs,
							&self.outputs,
							None,
							false,
							is_splice,
							target_feerate,
						);
						if budget >= fair_fee_no_change {
							Ok((fair_fee_no_change, None))
						} else {
							Err(FeeRateAdjustmentError::BudgetInsufficient {
								available: budget,
								required: fair_fee_no_change,
							})
						}
					},
				}
			} else {
				// No change output.
				let fair_fee = estimate_transaction_fee(
					&self.inputs,
					&self.outputs,
					None,
					false,
					is_splice,
					target_feerate,
				);
				if self.estimated_fee < fair_fee {
					return Err(FeeRateAdjustmentError::BudgetInsufficient {
						available: self.estimated_fee,
						required: fair_fee,
					});
				}
				let surplus = self.estimated_fee - fair_fee;
				let dust_limit =
					ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()).minimal_non_dust();
				if surplus >= dust_limit {
					return Err(FeeRateAdjustmentError::SurplusExceedsDust { surplus, dust_limit });
				}
				Ok((fair_fee, None))
			}
		} else {
			// No inputs (splice-out): fees paid from channel balance.
			let fair_fee = estimate_transaction_fee(
				&[],
				&self.outputs,
				None,
				false,
				is_splice,
				target_feerate,
			);
			// Check that the channel balance can cover the withdrawal outputs plus fees.
			let value_removed: Amount = self.outputs.iter().map(|o| o.value).sum();
			let total_cost = fair_fee
				.checked_add(value_removed)
				.ok_or(FeeRateAdjustmentError::BudgetOverflow)?;
			if total_cost > holder_balance {
				return Err(FeeRateAdjustmentError::BudgetInsufficient {
					available: holder_balance.checked_sub(value_removed).unwrap_or(Amount::ZERO),
					required: fair_fee,
				});
			}
			// Surplus goes back to the channel balance.
			Ok((fair_fee, None))
		}
	}

	/// Adjusts the contribution's change output for the initiator's feerate.
	///
	/// When the acceptor has a pending contribution (from the quiescence tie-breaker scenario),
	/// the initiator's proposed feerate may differ from the feerate used during coin selection.
	/// This adjusts the change output so the acceptor pays their fair share at the target
	/// feerate.
	pub(super) fn for_acceptor_at_feerate(
		mut self, feerate: FeeRate, holder_balance: Amount,
	) -> Result<Self, FeeRateAdjustmentError> {
		let (new_estimated_fee, new_change) =
			self.compute_feerate_adjustment(feerate, holder_balance)?;
		match new_change {
			Some(value) => self.change_output.as_mut().unwrap().value = value,
			None => self.change_output = None,
		}
		self.estimated_fee = new_estimated_fee;
		self.feerate = feerate;
		Ok(self)
	}

	/// Returns the net value at the given target feerate without mutating `self`.
	///
	/// This serves double duty: it checks feerate compatibility (returning `Err` if the feerate
	/// can't be accommodated) and computes the adjusted net value (returning `Ok` with the value
	/// accounting for the target feerate).
	pub(super) fn net_value_for_acceptor_at_feerate(
		&self, target_feerate: FeeRate, holder_balance: Amount,
	) -> Result<SignedAmount, FeeRateAdjustmentError> {
		let (new_estimated_fee, _) =
			self.compute_feerate_adjustment(target_feerate, holder_balance)?;
		Ok(self.net_value_with_fee(new_estimated_fee))
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
		estimate_transaction_fee, FeeRateAdjustmentError, FundingContribution, FundingTemplate,
		FundingTxInput,
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
			let template = FundingTemplate::new(None, feerate, feerate);
			assert!(template.splice_in_sync(over_max, UnreachableWallet).is_err());
		}

		// splice_out_sync with single output value > MAX_MONEY
		{
			let template = FundingTemplate::new(None, feerate, feerate);
			let outputs = vec![funding_output_sats(over_max.to_sat())];
			assert!(template.splice_out_sync(outputs, UnreachableWallet).is_err());
		}

		// splice_out_sync with multiple outputs summing > MAX_MONEY
		{
			let template = FundingTemplate::new(None, feerate, feerate);
			let half_over = Amount::MAX_MONEY / 2 + Amount::from_sat(1);
			let outputs = vec![
				funding_output_sats(half_over.to_sat()),
				funding_output_sats(half_over.to_sat()),
			];
			assert!(template.splice_out_sync(outputs, UnreachableWallet).is_err());
		}

		// splice_in_and_out_sync with value_added > MAX_MONEY
		{
			let template = FundingTemplate::new(None, feerate, feerate);
			let outputs = vec![funding_output_sats(1_000)];
			assert!(template.splice_in_and_out_sync(over_max, outputs, UnreachableWallet).is_err());
		}

		// splice_in_and_out_sync with output sum > MAX_MONEY
		{
			let template = FundingTemplate::new(None, feerate, feerate);
			let outputs = vec![funding_output_sats(over_max.to_sat())];
			assert!(template
				.splice_in_and_out_sync(Amount::from_sat(1_000), outputs, UnreachableWallet)
				.is_err());
		}
	}

	#[test]
	fn test_for_acceptor_at_feerate_higher_change_adjusted() {
		// Splice-in: higher target feerate reduces the change output.
		// The budget (is_initiator=true) overestimates by including common TX fields,
		// shared output, and shared input weight. So we need a sufficiently high target
		// feerate for the acceptor's fair fee to exceed the budget, causing the change
		// to decrease.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(6000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(10_000);

		// Budget computed as initiator (overestimate), including change output weight.
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

		// Fair fee at target feerate for acceptor (is_initiator=false), including change weight.
		let expected_fair_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), false, true, target_feerate);
		let expected_change = estimated_fee + Amount::from_sat(10_000) - expected_fair_fee;

		assert_eq!(contribution.estimated_fee, expected_fair_fee);
		assert!(contribution.change_output.is_some());
		assert_eq!(contribution.change_output.as_ref().unwrap().value, expected_change);
		assert!(expected_change < Amount::from_sat(10_000)); // Change reduced
		assert_eq!(contribution.net_value(), net_value_before);
	}

	#[test]
	fn test_for_acceptor_at_feerate_lower_rejected_too_low() {
		// Splice-in: target feerate below our minimum is rejected as TooLow.
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
		assert!(matches!(result, Err(FeeRateAdjustmentError::TooLow { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_change_removed() {
		// Splice-in: feerate high enough that change drops below dust and is removed,
		// but budget + change still covers the fee without the change output.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(7000);
		let inputs = vec![funding_input_sats(100_000)];
		let change = funding_output_sats(500);

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], Some(&change), true, true, original_feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
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

		// Change should be removed; estimated_fee updated to no-change fair fee.
		assert!(contribution.change_output.is_none());
		let expected_fee_no_change =
			estimate_transaction_fee(&inputs, &[], None, false, true, target_feerate);
		assert_eq!(contribution.estimated_fee, expected_fee_no_change);
		assert_eq!(contribution.net_value(), net_value_before);
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
		assert!(matches!(result, Err(FeeRateAdjustmentError::BudgetInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_splice_out_sufficient() {
		// Splice-out (no inputs): budget from is_initiator=true overestimate covers the
		// acceptor's fair fee at a moderately higher target feerate.
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
		// estimated_fee is updated to the fair fee; surplus goes back to channel balance.
		let expected_fair_fee =
			estimate_transaction_fee(&[], &outputs, None, false, true, target_feerate);
		assert_eq!(contribution.estimated_fee, expected_fair_fee);
		assert!(expected_fair_fee <= estimated_fee);
	}

	#[test]
	fn test_for_acceptor_at_feerate_splice_out_insufficient() {
		// Splice-out: channel balance too small for outputs + fair fee at high target feerate.
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

		// Balance of 55,000 sats can't cover outputs (50,000) + fair_fee at 50k sat/kwu.
		let holder_balance = Amount::from_sat(55_000);
		let result = contribution.for_acceptor_at_feerate(target_feerate, holder_balance);
		assert!(matches!(result, Err(FeeRateAdjustmentError::BudgetInsufficient { .. })));
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

		// For splice-in, unpaid_fees is zero so net_value_for_acceptor_at_feerate equals net_value.
		let net_at_feerate =
			contribution.net_value_for_acceptor_at_feerate(target_feerate, Amount::MAX).unwrap();
		assert_eq!(net_at_feerate, contribution.net_value());
		assert_eq!(net_at_feerate, Amount::from_sat(50_000).to_signed().unwrap());
	}

	#[test]
	fn test_net_value_for_acceptor_at_feerate_splice_out() {
		// Splice-out: net_value_for_acceptor_at_feerate returns the adjusted value using the fair fee
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

		// The fair fee at target feerate should be less than the initiator's budget.
		let fair_fee = estimate_transaction_fee(&[], &outputs, None, false, true, target_feerate);
		let expected_net = SignedAmount::ZERO
			- Amount::from_sat(50_000).to_signed().unwrap()
			- fair_fee.to_signed().unwrap();
		assert_eq!(net_at_feerate, expected_net);

		// Should be less negative than net_value() which uses the higher budget.
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
		assert!(matches!(result, Err(FeeRateAdjustmentError::BudgetInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_exceeds_max_rejected() {
		// Splice-in: target feerate exceeds max_feerate and fair fee exceeds budget,
		// so the adjustment is rejected as TooHigh.
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
		assert!(matches!(result, Err(FeeRateAdjustmentError::TooHigh { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_exceeds_max_allowed() {
		// Splice-in: target feerate exceeds max_feerate but the acceptor's fair fee
		// (is_initiator=false at target) is less than the budget (is_initiator=true at
		// original feerate). This works because the initiator budget includes ~598 WU of
		// extra weight (common TX fields, funding output, shared input) that the acceptor
		// doesn't pay for, so the budget is ~2.5x larger than the acceptor's fair fee at
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

		// The acceptor's fair fee at target (4000, is_initiator=false) is less than the
		// budget at original (2000, is_initiator=true) due to the ~2.5x weight ratio,
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

		// At a higher target feerate, the fair fee increases so change should decrease
		// (or stay the same if the budget overestimate absorbs the difference).
		// The key assertion is that the adjustment succeeds with a valid change output.
		assert!(adjusted.change_output.is_some());
	}

	#[test]
	fn test_for_acceptor_at_feerate_no_change_insufficient() {
		// Inputs present, no change output. Higher target feerate makes fair_fee > estimated_fee.
		let original_feerate = FeeRate::from_sat_per_kwu(2000);
		let target_feerate = FeeRate::from_sat_per_kwu(20_000);
		let inputs = vec![funding_input_sats(100_000)];

		let estimated_fee =
			estimate_transaction_fee(&inputs, &[], None, true, true, original_feerate);

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
		assert!(matches!(result, Err(FeeRateAdjustmentError::BudgetInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_surplus_exceeds_dust() {
		// Inputs, no change. The estimated_fee (is_initiator=true budget) far exceeds
		// the acceptor's fair fee (is_initiator=false), so surplus >= dust_limit.
		let feerate = FeeRate::from_sat_per_kwu(2000);
		let inputs = vec![funding_input_sats(100_000)];

		// Initiator budget includes common TX fields + shared output + shared input weight,
		// making it ~3x the acceptor's fair fee at the same feerate.
		let estimated_fee = estimate_transaction_fee(&inputs, &[], None, true, true, feerate);

		let contribution = FundingContribution {
			value_added: Amount::from_sat(50_000),
			estimated_fee,
			inputs,
			outputs: vec![],
			change_output: None,
			feerate,
			max_feerate: FeeRate::MAX,
			is_splice: true,
		};

		// target == min feerate, so TooLow check passes.
		// surplus = estimated_fee(initiator) - fair_fee(acceptor) >= dust_limit
		let result = contribution.for_acceptor_at_feerate(feerate, Amount::MAX);
		assert!(matches!(result, Err(FeeRateAdjustmentError::SurplusExceedsDust { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_budget_overflow() {
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
		assert!(matches!(result, Err(FeeRateAdjustmentError::BudgetOverflow)));
	}

	#[test]
	fn test_for_acceptor_at_feerate_splice_out_balance_insufficient() {
		// Splice-out: channel balance too small to cover outputs + fair fee.
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

		// Balance of 40,000 sats is less than outputs (50,000) + fair_fee.
		let holder_balance = Amount::from_sat(40_000);
		let result = contribution.for_acceptor_at_feerate(target_feerate, holder_balance);
		assert!(matches!(result, Err(FeeRateAdjustmentError::BudgetInsufficient { .. })));
	}

	#[test]
	fn test_for_acceptor_at_feerate_splice_out_balance_sufficient() {
		// Splice-out: channel balance large enough to cover outputs + fair fee.
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

		// Balance of 100,000 sats is more than outputs (50,000) + fair_fee.
		let holder_balance = Amount::from_sat(100_000);
		let contribution =
			contribution.for_acceptor_at_feerate(target_feerate, holder_balance).unwrap();
		let expected_fair_fee =
			estimate_transaction_fee(&[], &outputs, None, false, true, target_feerate);
		assert_eq!(contribution.estimated_fee, expected_fair_fee);
	}

	#[test]
	fn test_net_value_for_acceptor_at_feerate_splice_out_balance_insufficient() {
		// Splice-out: net_value_for_acceptor_at_feerate returns Err when channel balance
		// is too small to cover outputs + fair fee.
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

		// Balance of 40,000 sats is less than outputs (50,000) + fair_fee.
		let holder_balance = Amount::from_sat(40_000);
		let result = contribution.net_value_for_acceptor_at_feerate(target_feerate, holder_balance);
		assert!(matches!(result, Err(FeeRateAdjustmentError::BudgetInsufficient { .. })));
	}
}
