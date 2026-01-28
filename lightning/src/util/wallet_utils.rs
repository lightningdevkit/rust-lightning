// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for wallet integration with LDK.

use core::future::Future;
use core::ops::Deref;

use crate::chain::chaininterface::fee_for_weight;
use crate::chain::ClaimId;
use crate::io_extras::sink;
use crate::ln::chan_utils::{
	BASE_INPUT_WEIGHT, BASE_TX_SIZE, EMPTY_SCRIPT_SIG_WEIGHT, P2WSH_TXOUT_WEIGHT,
	SEGWIT_MARKER_FLAG_WEIGHT,
};
use crate::ln::funding::FundingTxInput;
use crate::prelude::*;
use crate::sign::{P2TR_KEY_PATH_WITNESS_WEIGHT, P2WPKH_WITNESS_WEIGHT};
use crate::sync::Mutex;
use crate::util::async_poll::{MaybeSend, MaybeSync};
use crate::util::hash_tables::{new_hash_map, HashMap};
use crate::util::logger::Logger;

use bitcoin::amount::Amount;
use bitcoin::consensus::Encodable;
use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::key::TweakedPublicKey;
use bitcoin::{OutPoint, Psbt, PubkeyHash, ScriptBuf, Sequence, Transaction, TxOut, WPubkeyHash};

/// An input that must be included in a transaction when performing coin selection through
/// [`CoinSelectionSource::select_confirmed_utxos`]. It is guaranteed to be a SegWit input, so it
/// must have an empty [`TxIn::script_sig`] when spent.
///
/// [`TxIn::script_sig`]: bitcoin::TxIn::script_sig
#[derive(Clone, Debug, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub struct Input {
	/// The unique identifier of the input.
	pub outpoint: OutPoint,
	/// The UTXO being spent by the input.
	pub previous_utxo: TxOut,
	/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and
	/// [`TxIn::witness`], each with their lengths included, required to satisfy the output's
	/// script.
	///
	/// [`TxIn::script_sig`]: bitcoin::TxIn::script_sig
	/// [`TxIn::witness`]: bitcoin::TxIn::witness
	pub satisfaction_weight: u64,
}

/// An unspent transaction output that is available to spend resulting from a successful
/// [`CoinSelection`] attempt.
#[derive(Clone, Debug, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub struct Utxo {
	/// The unique identifier of the output.
	pub outpoint: OutPoint,
	/// The output to spend.
	pub output: TxOut,
	/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and [`TxIn::witness`], each
	/// with their lengths included, required to satisfy the output's script. The weight consumed by
	/// the input's `script_sig` must account for [`WITNESS_SCALE_FACTOR`].
	///
	/// [`TxIn::script_sig`]: bitcoin::TxIn::script_sig
	/// [`TxIn::witness`]: bitcoin::TxIn::witness
	pub satisfaction_weight: u64,
	/// The sequence number to use in the [`TxIn`] when spending the UTXO.
	///
	/// [`TxIn`]: bitcoin::TxIn
	pub sequence: Sequence,
}

impl_writeable_tlv_based!(Utxo, {
	(1, outpoint, required),
	(3, output, required),
	(5, satisfaction_weight, required),
	(7, sequence, (default_value, Sequence::ENABLE_RBF_NO_LOCKTIME)),
});

impl Utxo {
	/// Returns a `Utxo` with the `satisfaction_weight` estimate for a legacy P2PKH output.
	pub fn new_p2pkh(outpoint: OutPoint, value: Amount, pubkey_hash: &PubkeyHash) -> Self {
		let script_sig_size = 1 /* script_sig length */ +
			1 /* OP_PUSH73 */ +
			73 /* sig including sighash flag */ +
			1 /* OP_PUSH33 */ +
			33 /* pubkey */;
		Self {
			outpoint,
			output: TxOut { value, script_pubkey: ScriptBuf::new_p2pkh(pubkey_hash) },
			satisfaction_weight: script_sig_size * WITNESS_SCALE_FACTOR as u64 + 1, /* empty witness */
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
		}
	}

	/// Returns a `Utxo` with the `satisfaction_weight` estimate for a P2WPKH nested in P2SH output.
	pub fn new_nested_p2wpkh(outpoint: OutPoint, value: Amount, pubkey_hash: &WPubkeyHash) -> Self {
		let script_sig_size = 1 /* script_sig length */ +
			1 /* OP_0 */ +
			1 /* OP_PUSH20 */ +
			20 /* pubkey_hash */;
		Self {
			outpoint,
			output: TxOut {
				value,
				script_pubkey: ScriptBuf::new_p2sh(
					&ScriptBuf::new_p2wpkh(pubkey_hash).script_hash(),
				),
			},
			satisfaction_weight: script_sig_size * WITNESS_SCALE_FACTOR as u64
				+ P2WPKH_WITNESS_WEIGHT,
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
		}
	}

	/// Returns a `Utxo` with the `satisfaction_weight` estimate for a SegWit v0 P2WPKH output.
	pub fn new_v0_p2wpkh(outpoint: OutPoint, value: Amount, pubkey_hash: &WPubkeyHash) -> Self {
		Self {
			outpoint,
			output: TxOut { value, script_pubkey: ScriptBuf::new_p2wpkh(pubkey_hash) },
			satisfaction_weight: EMPTY_SCRIPT_SIG_WEIGHT + P2WPKH_WITNESS_WEIGHT,
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
		}
	}

	/// Returns a `Utxo` with the `satisfaction_weight` estimate for a keypath spend of a SegWit v1 P2TR output.
	pub fn new_v1_p2tr(
		outpoint: OutPoint, value: Amount, tweaked_public_key: TweakedPublicKey,
	) -> Self {
		Self {
			outpoint,
			output: TxOut { value, script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked_public_key) },
			satisfaction_weight: EMPTY_SCRIPT_SIG_WEIGHT + P2TR_KEY_PATH_WITNESS_WEIGHT,
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
		}
	}
}

/// An unspent transaction output with at least one confirmation.
pub type ConfirmedUtxo = FundingTxInput;

/// The result of a successful coin selection attempt for a transaction requiring additional UTXOs
/// to cover its fees.
#[derive(Clone, Debug)]
pub struct CoinSelection {
	/// The set of UTXOs (with at least 1 confirmation) to spend and use within a transaction
	/// requiring additional fees.
	pub confirmed_utxos: Vec<ConfirmedUtxo>,
	/// An additional output tracking whether any change remained after coin selection. This output
	/// should always have a value above dust for its given `script_pubkey`. It should not be
	/// spent until the transaction it belongs to confirms to ensure mempool descendant limits are
	/// not met. This implies no other party should be able to spend it except us.
	pub change_output: Option<TxOut>,
}

impl CoinSelection {
	pub(crate) fn satisfaction_weight(&self) -> u64 {
		self.confirmed_utxos.iter().map(|ConfirmedUtxo { utxo, .. }| utxo.satisfaction_weight).sum()
	}

	pub(crate) fn input_amount(&self) -> Amount {
		self.confirmed_utxos.iter().map(|ConfirmedUtxo { utxo, .. }| utxo.output.value).sum()
	}
}

/// An abstraction over a bitcoin wallet that can perform coin selection over a set of UTXOs and can
/// sign for them. The coin selection method aims to mimic Bitcoin Core's `fundrawtransaction` RPC,
/// which most wallets should be able to satisfy. Otherwise, consider implementing [`WalletSource`],
/// which can provide a default implementation of this trait when used with [`Wallet`].
///
/// For a synchronous version of this trait, see [`sync::CoinSelectionSourceSync`].
///
/// This is not exported to bindings users as async is only supported in Rust.
///
/// [`sync::CoinSelectionSourceSync`]: crate::events::bump_transaction::sync::CoinSelectionSourceSync
// Note that updates to documentation on this trait should be copied to the synchronous version.
pub trait CoinSelectionSource {
	/// Performs coin selection of a set of UTXOs, with at least 1 confirmation each, that are
	/// available to spend. Implementations are free to pick their coin selection algorithm of
	/// choice, as long as the following requirements are met:
	///
	/// 1. `must_spend` contains a set of [`Input`]s that must be included in the transaction
	///    throughout coin selection, but must not be returned as part of the result.
	/// 2. `must_pay_to` contains a set of [`TxOut`]s that must be included in the transaction
	///    throughout coin selection. In some cases, like when funding an anchor transaction, this
	///    set is empty. Implementations should ensure they handle this correctly on their end,
	///    e.g., Bitcoin Core's `fundrawtransaction` RPC requires at least one output to be
	///    provided, in which case a zero-value empty OP_RETURN output can be used instead.
	/// 3. Enough inputs must be selected/contributed for the resulting transaction (including the
	///    inputs and outputs noted above) to meet `target_feerate_sat_per_1000_weight`.
	/// 4. The final transaction must have a weight smaller than `max_tx_weight`; if this
	///    constraint can't be met, return an `Err`. In the case of counterparty-signed HTLC
	///    transactions, we will remove a chunk of HTLCs and try your algorithm again. As for
	///    anchor transactions, we will try your coin selection again with the same input-output
	///    set when you call [`ChannelMonitor::rebroadcast_pending_claims`], as anchor transactions
	///    cannot be downsized.
	///
	/// Implementations must take note that [`Input::satisfaction_weight`] only tracks the weight of
	/// the input's `script_sig` and `witness`. Some wallets, like Bitcoin Core's, may require
	/// providing the full input weight. Failing to do so may lead to underestimating fee bumps and
	/// delaying block inclusion.
	///
	/// The `claim_id` must map to the set of external UTXOs assigned to the claim, such that they
	/// can be re-used within new fee-bumped iterations of the original claiming transaction,
	/// ensuring that claims don't double spend each other. If a specific `claim_id` has never had a
	/// transaction associated with it, and all of the available UTXOs have already been assigned to
	/// other claims, implementations must be willing to double spend their UTXOs. The choice of
	/// which UTXOs to double spend is left to the implementation, but it must strive to keep the
	/// set of other claims being double spent to a minimum.
	///
	/// If `claim_id` is not set, then the selection should be treated as if it were for a unique
	/// claim and must NOT be double-spent rather than being kept to a minimum.
	///
	/// [`ChannelMonitor::rebroadcast_pending_claims`]: crate::chain::channelmonitor::ChannelMonitor::rebroadcast_pending_claims
	fn select_confirmed_utxos<'a>(
		&'a self, claim_id: Option<ClaimId>, must_spend: Vec<Input>, must_pay_to: &'a [TxOut],
		target_feerate_sat_per_1000_weight: u32, max_tx_weight: u64,
	) -> impl Future<Output = Result<CoinSelection, ()>> + MaybeSend + 'a;
	/// Signs and provides the full witness for all inputs within the transaction known to the
	/// trait (i.e., any provided via [`CoinSelectionSource::select_confirmed_utxos`]).
	///
	/// If your wallet does not support signing PSBTs you can call `psbt.extract_tx()` to get the
	/// unsigned transaction and then sign it with your wallet.
	fn sign_psbt<'a>(
		&'a self, psbt: Psbt,
	) -> impl Future<Output = Result<Transaction, ()>> + MaybeSend + 'a;
}

/// An alternative to [`CoinSelectionSource`] that can be implemented and used along [`Wallet`] to
/// provide a default implementation to [`CoinSelectionSource`].
///
/// For a synchronous version of this trait, see [`sync::WalletSourceSync`].
///
/// This is not exported to bindings users as async is only supported in Rust.
///
/// [`sync::WalletSourceSync`]: crate::events::bump_transaction::sync::WalletSourceSync
// Note that updates to documentation on this trait should be copied to the synchronous version.
pub trait WalletSource {
	/// Returns all UTXOs, with at least 1 confirmation each, that are available to spend.
	fn list_confirmed_utxos<'a>(
		&'a self,
	) -> impl Future<Output = Result<Vec<Utxo>, ()>> + MaybeSend + 'a;

	/// Returns the previous transaction containing the UTXO referenced by the outpoint.
	fn get_prevtx<'a>(
		&'a self, outpoint: OutPoint,
	) -> impl Future<Output = Result<Transaction, ()>> + MaybeSend + 'a;

	/// Returns a script to use for change above dust resulting from a successful coin selection
	/// attempt.
	fn get_change_script<'a>(
		&'a self,
	) -> impl Future<Output = Result<ScriptBuf, ()>> + MaybeSend + 'a;

	/// Signs and provides the full [`TxIn::script_sig`] and [`TxIn::witness`] for all inputs within
	/// the transaction known to the wallet (i.e., any provided via
	/// [`WalletSource::list_confirmed_utxos`]).
	///
	/// If your wallet does not support signing PSBTs you can call `psbt.extract_tx()` to get the
	/// unsigned transaction and then sign it with your wallet.
	///
	/// [`TxIn::script_sig`]: bitcoin::TxIn::script_sig
	/// [`TxIn::witness`]: bitcoin::TxIn::witness
	fn sign_psbt<'a>(
		&'a self, psbt: Psbt,
	) -> impl Future<Output = Result<Transaction, ()>> + MaybeSend + 'a;
}

/// A wrapper over [`WalletSource`] that implements [`CoinSelectionSource`] by preferring UTXOs
/// that would avoid conflicting double spends. If not enough UTXOs are available to do so,
/// conflicting double spends may happen.
///
/// For a synchronous version of this wrapper, see [`sync::WalletSync`].
///
/// This is not exported to bindings users as async is only supported in Rust.
///
/// [`sync::WalletSync`]: crate::events::bump_transaction::sync::WalletSync
// Note that updates to documentation on this struct should be copied to the synchronous version.
pub struct Wallet<W: Deref + MaybeSync + MaybeSend, L: Logger + MaybeSync + MaybeSend>
where
	W::Target: WalletSource + MaybeSend,
{
	source: W,
	logger: L,
	// TODO: Do we care about cleaning this up once the UTXOs have a confirmed spend? We can do so
	// by checking whether any UTXOs that exist in the map are no longer returned in
	// `list_confirmed_utxos`.
	locked_utxos: Mutex<HashMap<OutPoint, Option<ClaimId>>>,
}

impl<W: Deref + MaybeSync + MaybeSend, L: Logger + MaybeSync + MaybeSend> Wallet<W, L>
where
	W::Target: WalletSource + MaybeSend,
{
	/// Returns a new instance backed by the given [`WalletSource`] that serves as an implementation
	/// of [`CoinSelectionSource`].
	pub fn new(source: W, logger: L) -> Self {
		Self { source, logger, locked_utxos: Mutex::new(new_hash_map()) }
	}

	/// Performs coin selection on the set of UTXOs obtained from
	/// [`WalletSource::list_confirmed_utxos`]. Its algorithm can be described as "smallest
	/// above-dust-after-spend first", with a slight twist: we may skip UTXOs that are above dust at
	/// the target feerate after having spent them in a separate claim transaction if
	/// `force_conflicting_utxo_spend` is unset to avoid producing conflicting transactions. If
	/// `tolerate_high_network_feerates` is set, we'll attempt to spend UTXOs that contribute at
	/// least 1 satoshi at the current feerate, otherwise, we'll only attempt to spend those which
	/// contribute at least twice their fee.
	async fn select_confirmed_utxos_internal(
		&self, utxos: &[Utxo], claim_id: Option<ClaimId>, force_conflicting_utxo_spend: bool,
		tolerate_high_network_feerates: bool, target_feerate_sat_per_1000_weight: u32,
		preexisting_tx_weight: u64, input_amount_sat: Amount, target_amount_sat: Amount,
		max_tx_weight: u64,
	) -> Result<CoinSelection, ()> {
		debug_assert!(!(claim_id.is_none() && force_conflicting_utxo_spend));

		// P2WSH and P2TR outputs are both the heaviest-weight standard outputs at 34 bytes
		let max_coin_selection_weight = max_tx_weight
			.checked_sub(preexisting_tx_weight + P2WSH_TXOUT_WEIGHT)
			.ok_or_else(|| {
				log_debug!(
					self.logger,
					"max_tx_weight is too small to accommodate the preexisting tx weight plus a P2WSH/P2TR output"
				);
			})?;

		let mut selected_amount;
		let mut total_fees;
		let mut selected_utxos;
		{
			let mut locked_utxos = self.locked_utxos.lock().unwrap();
			let mut eligible_utxos = utxos
				.iter()
				.filter_map(|utxo| {
					if let Some(utxo_claim_id) = locked_utxos.get(&utxo.outpoint) {
						// TODO(splicing): For splicing (i.e., claim_id.is_none()), ideally we'd
						// allow force_conflicting_utxo_spend for an RBF attempt. However, we'd need
						// something similar to a ClaimId to identify a splice.
						if (utxo_claim_id.is_none() || claim_id.is_none())
							|| (*utxo_claim_id != claim_id && !force_conflicting_utxo_spend)
						{
							log_trace!(
								self.logger,
								"Skipping UTXO {} to prevent conflicting spend",
								utxo.outpoint
							);
							return None;
						}
					}
					let fee_to_spend_utxo = Amount::from_sat(fee_for_weight(
						target_feerate_sat_per_1000_weight,
						BASE_INPUT_WEIGHT + utxo.satisfaction_weight,
					));
					let should_spend = if tolerate_high_network_feerates {
						utxo.output.value > fee_to_spend_utxo
					} else {
						utxo.output.value >= fee_to_spend_utxo * 2
					};
					if should_spend {
						Some((utxo, fee_to_spend_utxo))
					} else {
						log_trace!(
							self.logger,
							"Skipping UTXO {} due to dust proximity after spend",
							utxo.outpoint
						);
						None
					}
				})
				.collect::<Vec<_>>();
			eligible_utxos.sort_unstable_by_key(|(utxo, fee_to_spend_utxo)| {
				utxo.output.value - *fee_to_spend_utxo
			});

			selected_amount = input_amount_sat;
			total_fees = Amount::from_sat(fee_for_weight(
				target_feerate_sat_per_1000_weight,
				preexisting_tx_weight,
			));
			selected_utxos = VecDeque::new();
			// Invariant: `selected_utxos_weight` is never greater than `max_coin_selection_weight`
			let mut selected_utxos_weight = 0;
			for (utxo, fee_to_spend_utxo) in eligible_utxos {
				if selected_amount >= target_amount_sat + total_fees {
					break;
				}
				// First skip any UTXOs with prohibitive satisfaction weights
				if BASE_INPUT_WEIGHT + utxo.satisfaction_weight > max_coin_selection_weight {
					continue;
				}
				// If adding this UTXO to `selected_utxos` would push us over the
				// `max_coin_selection_weight`, remove UTXOs from the front to make room
				// for this new UTXO.
				while selected_utxos_weight + BASE_INPUT_WEIGHT + utxo.satisfaction_weight
					> max_coin_selection_weight
					&& !selected_utxos.is_empty()
				{
					let (smallest_value_after_spend_utxo, fee_to_spend_utxo): (Utxo, Amount) =
						selected_utxos.pop_front().unwrap();
					selected_amount -= smallest_value_after_spend_utxo.output.value;
					total_fees -= fee_to_spend_utxo;
					selected_utxos_weight -=
						BASE_INPUT_WEIGHT + smallest_value_after_spend_utxo.satisfaction_weight;
				}
				selected_amount += utxo.output.value;
				total_fees += fee_to_spend_utxo;
				selected_utxos_weight += BASE_INPUT_WEIGHT + utxo.satisfaction_weight;
				selected_utxos.push_back((utxo.clone(), fee_to_spend_utxo));
			}
			if selected_amount < target_amount_sat + total_fees {
				log_debug!(
					self.logger,
					"Insufficient funds to meet target feerate {} sat/kW while remaining under {} WU",
					target_feerate_sat_per_1000_weight,
					max_coin_selection_weight,
				);
				return Err(());
			}
			// Once we've selected enough UTXOs to cover `target_amount_sat + total_fees`,
			// we may be able to remove some small-value ones while still covering
			// `target_amount_sat + total_fees`.
			while !selected_utxos.is_empty()
				&& selected_amount - selected_utxos.front().unwrap().0.output.value
					>= target_amount_sat + total_fees - selected_utxos.front().unwrap().1
			{
				let (smallest_value_after_spend_utxo, fee_to_spend_utxo) =
					selected_utxos.pop_front().unwrap();
				selected_amount -= smallest_value_after_spend_utxo.output.value;
				total_fees -= fee_to_spend_utxo;
			}
			for (utxo, _) in &selected_utxos {
				locked_utxos.insert(utxo.outpoint, claim_id);
			}
		}

		let remaining_amount = selected_amount - target_amount_sat - total_fees;
		let change_script = self.source.get_change_script().await?;
		let change_output_fee = fee_for_weight(
			target_feerate_sat_per_1000_weight,
			(8 /* value */ + change_script.consensus_encode(&mut sink()).unwrap() as u64)
				* WITNESS_SCALE_FACTOR as u64,
		);
		let change_output_amount =
			Amount::from_sat(remaining_amount.to_sat().saturating_sub(change_output_fee));
		let change_output = if change_output_amount < change_script.minimal_non_dust() {
			log_debug!(self.logger, "Coin selection attempt did not yield change output");
			None
		} else {
			Some(TxOut { script_pubkey: change_script, value: change_output_amount })
		};

		let mut confirmed_utxos = Vec::with_capacity(selected_utxos.len());
		for (utxo, _) in selected_utxos {
			let prevtx = self.source.get_prevtx(utxo.outpoint).await?;
			let prevtx_id = prevtx.compute_txid();
			if prevtx_id != utxo.outpoint.txid
				|| prevtx.output.get(utxo.outpoint.vout as usize).is_none()
			{
				log_error!(
					self.logger,
					"Tx {} from wallet source doesn't contain output referenced by outpoint: {}",
					prevtx_id,
					utxo.outpoint,
				);
				return Err(());
			}

			confirmed_utxos.push(ConfirmedUtxo { utxo, prevtx });
		}

		Ok(CoinSelection { confirmed_utxos, change_output })
	}
}

impl<W: Deref + MaybeSync + MaybeSend, L: Logger + MaybeSync + MaybeSend> CoinSelectionSource
	for Wallet<W, L>
where
	W::Target: WalletSource + MaybeSend + MaybeSync,
{
	fn select_confirmed_utxos<'a>(
		&'a self, claim_id: Option<ClaimId>, must_spend: Vec<Input>, must_pay_to: &'a [TxOut],
		target_feerate_sat_per_1000_weight: u32, max_tx_weight: u64,
	) -> impl Future<Output = Result<CoinSelection, ()>> + MaybeSend + 'a {
		async move {
			let utxos = self.source.list_confirmed_utxos().await?;
			// TODO: Use fee estimation utils when we upgrade to bitcoin v0.30.0.
			let total_output_size: u64 = must_pay_to
				.iter()
				.map(
					|output| 8 /* value */ + 1 /* script len */ + output.script_pubkey.len() as u64,
				)
				.sum();
			let total_satisfaction_weight: u64 =
				must_spend.iter().map(|input| input.satisfaction_weight).sum();
			let total_input_weight =
				(BASE_INPUT_WEIGHT * must_spend.len() as u64) + total_satisfaction_weight;

			let preexisting_tx_weight = SEGWIT_MARKER_FLAG_WEIGHT
				+ total_input_weight
				+ ((BASE_TX_SIZE + total_output_size) * WITNESS_SCALE_FACTOR as u64);
			let input_amount_sat = must_spend.iter().map(|input| input.previous_utxo.value).sum();
			let target_amount_sat = must_pay_to.iter().map(|output| output.value).sum();

			let configs = [(false, false), (false, true), (true, false), (true, true)];
			for (force_conflicting_utxo_spend, tolerate_high_network_feerates) in configs {
				if claim_id.is_none() && force_conflicting_utxo_spend {
					continue;
				}
				log_debug!(
					self.logger,
					"Attempting coin selection targeting {} sat/kW (force_conflicting_utxo_spend = {}, tolerate_high_network_feerates = {})",
					target_feerate_sat_per_1000_weight,
					force_conflicting_utxo_spend,
					tolerate_high_network_feerates
				);
				let attempt = self
					.select_confirmed_utxos_internal(
						&utxos,
						claim_id,
						force_conflicting_utxo_spend,
						tolerate_high_network_feerates,
						target_feerate_sat_per_1000_weight,
						preexisting_tx_weight,
						input_amount_sat,
						target_amount_sat,
						max_tx_weight,
					)
					.await;
				if attempt.is_ok() {
					return attempt;
				}
			}
			Err(())
		}
	}

	fn sign_psbt<'a>(
		&'a self, psbt: Psbt,
	) -> impl Future<Output = Result<Transaction, ()>> + MaybeSend + 'a {
		self.source.sign_psbt(psbt)
	}
}
