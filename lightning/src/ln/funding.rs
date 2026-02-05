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
use crate::util::async_poll::MaybeSend;
use crate::util::wallet_utils::{
	CoinSelection, CoinSelectionSource, CoinSelectionSourceSync, Input,
};

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

	/// The fee rate to use for coin selection.
	feerate: FeeRate,
}

impl FundingTemplate {
	/// Constructs a [`FundingTemplate`] for a splice using the provided shared input.
	pub(super) fn new(shared_input: Option<Input>, feerate: FeeRate) -> Self {
		Self { shared_input, feerate }
	}
}

macro_rules! build_funding_contribution {
    ($value_added:expr, $outputs:expr, $shared_input:expr, $feerate:expr, $wallet:ident, $($await:tt)*) => {{
		let value_added: Amount = $value_added;
		let outputs: Vec<TxOut> = $outputs;
		let shared_input: Option<Input> = $shared_input;
		let feerate: FeeRate = $feerate;

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
		let estimated_fee = estimate_transaction_fee(&inputs, &outputs, true, is_splice, feerate);
		debug_assert!(estimated_fee <= Amount::MAX_MONEY);

		let contribution = FundingContribution {
			value_added,
			estimated_fee,
			inputs,
			outputs,
			change_output,
			feerate,
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
		let FundingTemplate { shared_input, feerate } = self;
		build_funding_contribution!(value_added, vec![], shared_input, feerate, wallet, await)
	}

	/// Creates a [`FundingContribution`] for adding funds to a channel using `wallet` to perform
	/// coin selection.
	pub fn splice_in_sync<W: CoinSelectionSourceSync>(
		self, value_added: Amount, wallet: W,
	) -> Result<FundingContribution, ()> {
		if value_added == Amount::ZERO {
			return Err(());
		}
		let FundingTemplate { shared_input, feerate } = self;
		build_funding_contribution!(value_added, vec![], shared_input, feerate, wallet,)
	}

	/// Creates a [`FundingContribution`] for removing funds from a channel using `wallet` to
	/// perform coin selection.
	pub async fn splice_out<W: CoinSelectionSource + MaybeSend>(
		self, outputs: Vec<TxOut>, wallet: W,
	) -> Result<FundingContribution, ()> {
		if outputs.is_empty() {
			return Err(());
		}
		let FundingTemplate { shared_input, feerate } = self;
		build_funding_contribution!(Amount::ZERO, outputs, shared_input, feerate, wallet, await)
	}

	/// Creates a [`FundingContribution`] for removing funds from a channel using `wallet` to
	/// perform coin selection.
	pub fn splice_out_sync<W: CoinSelectionSourceSync>(
		self, outputs: Vec<TxOut>, wallet: W,
	) -> Result<FundingContribution, ()> {
		if outputs.is_empty() {
			return Err(());
		}
		let FundingTemplate { shared_input, feerate } = self;
		build_funding_contribution!(Amount::ZERO, outputs, shared_input, feerate, wallet,)
	}

	/// Creates a [`FundingContribution`] for both adding and removing funds from a channel using
	/// `wallet` to perform coin selection.
	pub async fn splice_in_and_out<W: CoinSelectionSource + MaybeSend>(
		self, value_added: Amount, outputs: Vec<TxOut>, wallet: W,
	) -> Result<FundingContribution, ()> {
		if value_added == Amount::ZERO && outputs.is_empty() {
			return Err(());
		}
		let FundingTemplate { shared_input, feerate } = self;
		build_funding_contribution!(value_added, outputs, shared_input, feerate, wallet, await)
	}

	/// Creates a [`FundingContribution`] for both adding and removing funds from a channel using
	/// `wallet` to perform coin selection.
	pub fn splice_in_and_out_sync<W: CoinSelectionSourceSync>(
		self, value_added: Amount, outputs: Vec<TxOut>, wallet: W,
	) -> Result<FundingContribution, ()> {
		if value_added == Amount::ZERO && outputs.is_empty() {
			return Err(());
		}
		let FundingTemplate { shared_input, feerate } = self;
		build_funding_contribution!(value_added, outputs, shared_input, feerate, wallet,)
	}
}

fn estimate_transaction_fee(
	inputs: &[FundingTxInput], outputs: &[TxOut], is_initiator: bool, is_splice: bool,
	feerate: FeeRate,
) -> Amount {
	let input_weight: u64 = inputs
		.iter()
		.map(|input| BASE_INPUT_WEIGHT.saturating_add(input.utxo.satisfaction_weight))
		.fold(0, |total_weight, input_weight| total_weight.saturating_add(input_weight));

	let output_weight: u64 = outputs
		.iter()
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

	/// The fee rate used to select `inputs`.
	feerate: FeeRate,

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
	(13, is_splice, required),
});

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

			// If the inputs are enough to cover intended contribution amount, with fees even when
			// there is a change output, we are fine.
			// If the inputs are less, but enough to cover intended contribution amount, with
			// (lower) fees with no change, we are also fine (change will not be generated).
			// So it's enough to check considering the lower, no-change fees.
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

	/// The net value contributed to a channel by the splice. If negative, more value will be
	/// spliced out than spliced in. Fees will be deducted from the expected splice-out amount
	/// if no inputs were included.
	pub fn net_value(&self) -> SignedAmount {
		let unpaid_fees = if self.inputs.is_empty() { self.estimated_fee } else { Amount::ZERO }
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
	use super::{estimate_transaction_fee, FundingContribution, FundingTemplate, FundingTxInput};
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
			estimate_transaction_fee(&two_inputs, &[], true, false, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 1512 } else { 1516 }),
		);

		// higher feerate
		assert_eq!(
			estimate_transaction_fee(&two_inputs, &[], true, false, FeeRate::from_sat_per_kwu(3000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 2268 } else { 2274 }),
		);

		// only 1 input
		assert_eq!(
			estimate_transaction_fee(&one_input, &[], true, false, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 970 } else { 972 }),
		);

		// 0 inputs
		assert_eq!(
			estimate_transaction_fee(&[], &[], true, false, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(428),
		);

		// not initiator
		assert_eq!(
			estimate_transaction_fee(&[], &[], false, false, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(0),
		);

		// splice initiator
		assert_eq!(
			estimate_transaction_fee(&one_input, &[], true, true, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 1736 } else { 1740 }),
		);

		// splice acceptor
		assert_eq!(
			estimate_transaction_fee(&one_input, &[], false, true, FeeRate::from_sat_per_kwu(2000)),
			Amount::from_sat(if cfg!(feature = "grind_signatures") { 542 } else { 544 }),
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
			let template = FundingTemplate::new(None, feerate);
			assert!(template.splice_in_sync(over_max, UnreachableWallet).is_err());
		}

		// splice_out_sync with single output value > MAX_MONEY
		{
			let template = FundingTemplate::new(None, feerate);
			let outputs = vec![funding_output_sats(over_max.to_sat())];
			assert!(template.splice_out_sync(outputs, UnreachableWallet).is_err());
		}

		// splice_out_sync with multiple outputs summing > MAX_MONEY
		{
			let template = FundingTemplate::new(None, feerate);
			let half_over = Amount::MAX_MONEY / 2 + Amount::from_sat(1);
			let outputs = vec![
				funding_output_sats(half_over.to_sat()),
				funding_output_sats(half_over.to_sat()),
			];
			assert!(template.splice_out_sync(outputs, UnreachableWallet).is_err());
		}

		// splice_in_and_out_sync with value_added > MAX_MONEY
		{
			let template = FundingTemplate::new(None, feerate);
			let outputs = vec![funding_output_sats(1_000)];
			assert!(template.splice_in_and_out_sync(over_max, outputs, UnreachableWallet).is_err());
		}

		// splice_in_and_out_sync with output sum > MAX_MONEY
		{
			let template = FundingTemplate::new(None, feerate);
			let outputs = vec![funding_output_sats(over_max.to_sat())];
			assert!(template
				.splice_in_and_out_sync(Amount::from_sat(1_000), outputs, UnreachableWallet)
				.is_err());
		}
	}
}
