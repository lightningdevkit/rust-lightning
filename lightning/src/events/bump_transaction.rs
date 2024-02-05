// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for bumping transactions originating from [`Event`]s.
//!
//! [`Event`]: crate::events::Event

use alloc::collections::BTreeMap;
use core::ops::Deref;

use crate::chain::chaininterface::{BroadcasterInterface, fee_for_weight};
use crate::chain::ClaimId;
use crate::io_extras::sink;
use crate::ln::channel::ANCHOR_OUTPUT_VALUE_SATOSHI;
use crate::ln::ChannelId;
use crate::ln::chan_utils;
use crate::ln::chan_utils::{
	ANCHOR_INPUT_WITNESS_WEIGHT, HTLC_SUCCESS_INPUT_ANCHOR_WITNESS_WEIGHT,
	HTLC_TIMEOUT_INPUT_ANCHOR_WITNESS_WEIGHT, HTLCOutputInCommitment
};
use crate::prelude::*;
use crate::sign::{
	ChannelDerivationParameters, HTLCDescriptor, SignerProvider, P2WPKH_WITNESS_WEIGHT
};
use crate::sign::ecdsa::{EcdsaChannelSigner, WriteableEcdsaChannelSigner};
use crate::sync::Mutex;
use crate::util::logger::Logger;

use bitcoin::{OutPoint, PubkeyHash, Sequence, ScriptBuf, Transaction, TxIn, TxOut, Witness, WPubkeyHash};
use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::secp256k1::ecdsa::Signature;

const EMPTY_SCRIPT_SIG_WEIGHT: u64 = 1 /* empty script_sig */ * WITNESS_SCALE_FACTOR as u64;

const BASE_INPUT_SIZE: u64 = 32 /* txid */ + 4 /* vout */ + 4 /* sequence */;

const BASE_INPUT_WEIGHT: u64 = BASE_INPUT_SIZE * WITNESS_SCALE_FACTOR as u64;

/// A descriptor used to sign for a commitment transaction's anchor output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorDescriptor {
	/// The parameters required to derive the signer for the anchor input.
	pub channel_derivation_parameters: ChannelDerivationParameters,
	/// The transaction input's outpoint corresponding to the commitment transaction's anchor
	/// output.
	pub outpoint: OutPoint,
}

impl AnchorDescriptor {
	/// Returns the UTXO to be spent by the anchor input, which can be obtained via
	/// [`Self::unsigned_tx_input`].
	pub fn previous_utxo(&self) -> TxOut {
		TxOut {
			script_pubkey: self.witness_script().to_v0_p2wsh(),
			value: ANCHOR_OUTPUT_VALUE_SATOSHI,
		}
	}

	/// Returns the unsigned transaction input spending the anchor output in the commitment
	/// transaction.
	pub fn unsigned_tx_input(&self) -> TxIn {
		TxIn {
			previous_output: self.outpoint.clone(),
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			witness: Witness::new(),
		}
	}

	/// Returns the witness script of the anchor output in the commitment transaction.
	pub fn witness_script(&self) -> ScriptBuf {
		let channel_params = self.channel_derivation_parameters.transaction_parameters.as_holder_broadcastable();
		chan_utils::get_anchor_redeemscript(&channel_params.broadcaster_pubkeys().funding_pubkey)
	}

	/// Returns the fully signed witness required to spend the anchor output in the commitment
	/// transaction.
	pub fn tx_input_witness(&self, signature: &Signature) -> Witness {
		let channel_params = self.channel_derivation_parameters.transaction_parameters.as_holder_broadcastable();
		chan_utils::build_anchor_input_witness(&channel_params.broadcaster_pubkeys().funding_pubkey, signature)
	}

	/// Derives the channel signer required to sign the anchor input.
	pub fn derive_channel_signer<S: WriteableEcdsaChannelSigner, SP: Deref>(&self, signer_provider: &SP) -> S
	where
		SP::Target: SignerProvider<EcdsaSigner= S>
	{
		let mut signer = signer_provider.derive_channel_signer(
			self.channel_derivation_parameters.value_satoshis,
			self.channel_derivation_parameters.keys_id,
		);
		signer.provide_channel_parameters(&self.channel_derivation_parameters.transaction_parameters);
		signer
	}
}

/// Represents the different types of transactions, originating from LDK, to be bumped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BumpTransactionEvent {
	/// Indicates that a channel featuring anchor outputs is to be closed by broadcasting the local
	/// commitment transaction. Since commitment transactions have a static feerate pre-agreed upon,
	/// they may need additional fees to be attached through a child transaction using the popular
	/// [Child-Pays-For-Parent](https://bitcoinops.org/en/topics/cpfp) fee bumping technique. This
	/// child transaction must include the anchor input described within `anchor_descriptor` along
	/// with additional inputs to meet the target feerate. Failure to meet the target feerate
	/// decreases the confirmation odds of the transaction package (which includes the commitment
	/// and child anchor transactions), possibly resulting in a loss of funds. Once the transaction
	/// is constructed, it must be fully signed for and broadcast by the consumer of the event
	/// along with the `commitment_tx` enclosed. Note that the `commitment_tx` must always be
	/// broadcast first, as the child anchor transaction depends on it.
	///
	/// The consumer should be able to sign for any of the additional inputs included within the
	/// child anchor transaction. To sign its anchor input, an [`EcdsaChannelSigner`] should be
	/// re-derived through [`AnchorDescriptor::derive_channel_signer`]. The anchor input signature
	/// can be computed with [`EcdsaChannelSigner::sign_holder_anchor_input`], which can then be
	/// provided to [`build_anchor_input_witness`] along with the `funding_pubkey` to obtain the
	/// full witness required to spend.
	///
	/// It is possible to receive more than one instance of this event if a valid child anchor
	/// transaction is never broadcast or is but not with a sufficient fee to be mined. Care should
	/// be taken by the consumer of the event to ensure any future iterations of the child anchor
	/// transaction adhere to the [Replace-By-Fee
	/// rules](https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md)
	/// for fee bumps to be accepted into the mempool, and eventually the chain. As the frequency of
	/// these events is not user-controlled, users may ignore/drop the event if they are no longer
	/// able to commit external confirmed funds to the child anchor transaction.
	///
	/// The set of `pending_htlcs` on the commitment transaction to be broadcast can be inspected to
	/// determine whether a significant portion of the channel's funds are allocated to HTLCs,
	/// enabling users to make their own decisions regarding the importance of the commitment
	/// transaction's confirmation. Note that this is not required, but simply exists as an option
	/// for users to override LDK's behavior. On commitments with no HTLCs (indicated by those with
	/// an empty `pending_htlcs`), confirmation of the commitment transaction can be considered to
	/// be not urgent.
	///
	/// [`EcdsaChannelSigner`]: crate::sign::ecdsa::EcdsaChannelSigner
	/// [`EcdsaChannelSigner::sign_holder_anchor_input`]: crate::sign::ecdsa::EcdsaChannelSigner::sign_holder_anchor_input
	/// [`build_anchor_input_witness`]: crate::ln::chan_utils::build_anchor_input_witness
	ChannelClose {
		/// The `channel_id` of the channel which has been closed.
		channel_id: ChannelId,
		/// Counterparty in the closed channel.
		counterparty_node_id: PublicKey,
		/// The unique identifier for the claim of the anchor output in the commitment transaction.
		///
		/// The identifier must map to the set of external UTXOs assigned to the claim, such that
		/// they can be reused when a new claim with the same identifier needs to be made, resulting
		/// in a fee-bumping attempt.
		claim_id: ClaimId,
		/// The target feerate that the transaction package, which consists of the commitment
		/// transaction and the to-be-crafted child anchor transaction, must meet.
		package_target_feerate_sat_per_1000_weight: u32,
		/// The channel's commitment transaction to bump the fee of. This transaction should be
		/// broadcast along with the anchor transaction constructed as a result of consuming this
		/// event.
		commitment_tx: Transaction,
		/// The absolute fee in satoshis of the commitment transaction. This can be used along the
		/// with weight of the commitment transaction to determine its feerate.
		commitment_tx_fee_satoshis: u64,
		/// The descriptor to sign the anchor input of the anchor transaction constructed as a
		/// result of consuming this event.
		anchor_descriptor: AnchorDescriptor,
		/// The set of pending HTLCs on the commitment transaction that need to be resolved once the
		/// commitment transaction confirms.
		pending_htlcs: Vec<HTLCOutputInCommitment>,
	},
	/// Indicates that a channel featuring anchor outputs has unilaterally closed on-chain by a
	/// holder commitment transaction and its HTLC(s) need to be resolved on-chain. With the
	/// zero-HTLC-transaction-fee variant of anchor outputs, the pre-signed HTLC
	/// transactions have a zero fee, thus requiring additional inputs and/or outputs to be attached
	/// for a timely confirmation within the chain. These additional inputs and/or outputs must be
	/// appended to the resulting HTLC transaction to meet the target feerate. Failure to meet the
	/// target feerate decreases the confirmation odds of the transaction, possibly resulting in a
	/// loss of funds. Once the transaction meets the target feerate, it must be signed for and
	/// broadcast by the consumer of the event.
	///
	/// The consumer should be able to sign for any of the non-HTLC inputs added to the resulting
	/// HTLC transaction. To sign HTLC inputs, an [`EcdsaChannelSigner`] should be re-derived
	/// through [`HTLCDescriptor::derive_channel_signer`]. Each HTLC input's signature can be
	/// computed with [`EcdsaChannelSigner::sign_holder_htlc_transaction`], which can then be
	/// provided to [`HTLCDescriptor::tx_input_witness`] to obtain the fully signed witness required
	/// to spend.
	///
	/// It is possible to receive more than one instance of this event if a valid HTLC transaction
	/// is never broadcast or is but not with a sufficient fee to be mined. Care should be taken by
	/// the consumer of the event to ensure any future iterations of the HTLC transaction adhere to
	/// the [Replace-By-Fee
	/// rules](https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md)
	/// for fee bumps to be accepted into the mempool, and eventually the chain. As the frequency of
	/// these events is not user-controlled, users may ignore/drop the event if either they are no
	/// longer able to commit external confirmed funds to the HTLC transaction or the fee committed
	/// to the HTLC transaction is greater in value than the HTLCs being claimed.
	///
	/// [`EcdsaChannelSigner`]: crate::sign::ecdsa::EcdsaChannelSigner
	/// [`EcdsaChannelSigner::sign_holder_htlc_transaction`]: crate::sign::ecdsa::EcdsaChannelSigner::sign_holder_htlc_transaction
	HTLCResolution {
		/// The `channel_id` of the channel which has been closed.
		channel_id: ChannelId,
		/// Counterparty in the closed channel.
		counterparty_node_id: PublicKey,
		/// The unique identifier for the claim of the HTLCs in the confirmed commitment
		/// transaction.
		///
		/// The identifier must map to the set of external UTXOs assigned to the claim, such that
		/// they can be reused when a new claim with the same identifier needs to be made, resulting
		/// in a fee-bumping attempt.
		claim_id: ClaimId,
		/// The target feerate that the resulting HTLC transaction must meet.
		target_feerate_sat_per_1000_weight: u32,
		/// The set of pending HTLCs on the confirmed commitment that need to be claimed, preferably
		/// by the same transaction.
		htlc_descriptors: Vec<HTLCDescriptor>,
		/// The locktime required for the resulting HTLC transaction.
		tx_lock_time: LockTime,
	},
}

/// An input that must be included in a transaction when performing coin selection through
/// [`CoinSelectionSource::select_confirmed_utxos`]. It is guaranteed to be a SegWit input, so it
/// must have an empty [`TxIn::script_sig`] when spent.
#[derive(Clone, Debug, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub struct Input {
	/// The unique identifier of the input.
	pub outpoint: OutPoint,
	/// The UTXO being spent by the input.
	pub previous_utxo: TxOut,
	/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and
	/// [`TxIn::witness`], each with their lengths included, required to satisfy the output's
	/// script.
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
	pub satisfaction_weight: u64,
}

impl Utxo {
	/// Returns a `Utxo` with the `satisfaction_weight` estimate for a legacy P2PKH output.
	pub fn new_p2pkh(outpoint: OutPoint, value: u64, pubkey_hash: &PubkeyHash) -> Self {
		let script_sig_size = 1 /* script_sig length */ +
			1 /* OP_PUSH73 */ +
			73 /* sig including sighash flag */ +
			1 /* OP_PUSH33 */ +
			33 /* pubkey */;
		Self {
			outpoint,
			output: TxOut {
				value,
				script_pubkey: ScriptBuf::new_p2pkh(pubkey_hash),
			},
			satisfaction_weight: script_sig_size * WITNESS_SCALE_FACTOR as u64 + 1 /* empty witness */,
		}
	}

	/// Returns a `Utxo` with the `satisfaction_weight` estimate for a P2WPKH nested in P2SH output.
	pub fn new_nested_p2wpkh(outpoint: OutPoint, value: u64, pubkey_hash: &WPubkeyHash) -> Self {
		let script_sig_size = 1 /* script_sig length */ +
			1 /* OP_0 */ +
			1 /* OP_PUSH20 */ +
			20 /* pubkey_hash */;
		Self {
			outpoint,
			output: TxOut {
				value,
				script_pubkey: ScriptBuf::new_p2sh(&ScriptBuf::new_v0_p2wpkh(pubkey_hash).script_hash()),
			},
			satisfaction_weight: script_sig_size * WITNESS_SCALE_FACTOR as u64 + P2WPKH_WITNESS_WEIGHT,
		}
	}

	/// Returns a `Utxo` with the `satisfaction_weight` estimate for a SegWit v0 P2WPKH output.
	pub fn new_v0_p2wpkh(outpoint: OutPoint, value: u64, pubkey_hash: &WPubkeyHash) -> Self {
		Self {
			outpoint,
			output: TxOut {
				value,
				script_pubkey: ScriptBuf::new_v0_p2wpkh(pubkey_hash),
			},
			satisfaction_weight: EMPTY_SCRIPT_SIG_WEIGHT + P2WPKH_WITNESS_WEIGHT,
		}
	}
}

/// The result of a successful coin selection attempt for a transaction requiring additional UTXOs
/// to cover its fees.
#[derive(Clone, Debug)]
pub struct CoinSelection {
	/// The set of UTXOs (with at least 1 confirmation) to spend and use within a transaction
	/// requiring additional fees.
	pub confirmed_utxos: Vec<Utxo>,
	/// An additional output tracking whether any change remained after coin selection. This output
	/// should always have a value above dust for its given `script_pubkey`. It should not be
	/// spent until the transaction it belongs to confirms to ensure mempool descendant limits are
	/// not met. This implies no other party should be able to spend it except us.
	pub change_output: Option<TxOut>,
}

/// An abstraction over a bitcoin wallet that can perform coin selection over a set of UTXOs and can
/// sign for them. The coin selection method aims to mimic Bitcoin Core's `fundrawtransaction` RPC,
/// which most wallets should be able to satisfy. Otherwise, consider implementing [`WalletSource`],
/// which can provide a default implementation of this trait when used with [`Wallet`].
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
	fn select_confirmed_utxos(
		&self, claim_id: ClaimId, must_spend: Vec<Input>, must_pay_to: &[TxOut],
		target_feerate_sat_per_1000_weight: u32,
	) -> Result<CoinSelection, ()>;
	/// Signs and provides the full witness for all inputs within the transaction known to the
	/// trait (i.e., any provided via [`CoinSelectionSource::select_confirmed_utxos`]).
	///
	/// If your wallet does not support signing PSBTs you can call `psbt.extract_tx()` to get the
	/// unsigned transaction and then sign it with your wallet.
	fn sign_psbt(&self, psbt: PartiallySignedTransaction) -> Result<Transaction, ()>;
}

/// An alternative to [`CoinSelectionSource`] that can be implemented and used along [`Wallet`] to
/// provide a default implementation to [`CoinSelectionSource`].
pub trait WalletSource {
	/// Returns all UTXOs, with at least 1 confirmation each, that are available to spend.
	fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()>;
	/// Returns a script to use for change above dust resulting from a successful coin selection
	/// attempt.
	fn get_change_script(&self) -> Result<ScriptBuf, ()>;
	/// Signs and provides the full [`TxIn::script_sig`] and [`TxIn::witness`] for all inputs within
	/// the transaction known to the wallet (i.e., any provided via
	/// [`WalletSource::list_confirmed_utxos`]).
	///
	/// If your wallet does not support signing PSBTs you can call `psbt.extract_tx()` to get the
	/// unsigned transaction and then sign it with your wallet.
	fn sign_psbt(&self, psbt: PartiallySignedTransaction) -> Result<Transaction, ()>;
}

/// A wrapper over [`WalletSource`] that implements [`CoinSelection`] by preferring UTXOs that would
/// avoid conflicting double spends. If not enough UTXOs are available to do so, conflicting double
/// spends may happen.
pub struct Wallet<W: Deref, L: Deref>
where
	W::Target: WalletSource,
	L::Target: Logger
{
	source: W,
	logger: L,
	// TODO: Do we care about cleaning this up once the UTXOs have a confirmed spend? We can do so
	// by checking whether any UTXOs that exist in the map are no longer returned in
	// `list_confirmed_utxos`.
	locked_utxos: Mutex<HashMap<OutPoint, ClaimId>>,
}

impl<W: Deref, L: Deref> Wallet<W, L>
where
	W::Target: WalletSource,
	L::Target: Logger
{
	/// Returns a new instance backed by the given [`WalletSource`] that serves as an implementation
	/// of [`CoinSelectionSource`].
	pub fn new(source: W, logger: L) -> Self {
		Self { source, logger, locked_utxos: Mutex::new(HashMap::new()) }
	}

	/// Performs coin selection on the set of UTXOs obtained from
	/// [`WalletSource::list_confirmed_utxos`]. Its algorithm can be described as "smallest
	/// above-dust-after-spend first", with a slight twist: we may skip UTXOs that are above dust at
	/// the target feerate after having spent them in a separate claim transaction if
	/// `force_conflicting_utxo_spend` is unset to avoid producing conflicting transactions. If
	/// `tolerate_high_network_feerates` is set, we'll attempt to spend UTXOs that contribute at
	/// least 1 satoshi at the current feerate, otherwise, we'll only attempt to spend those which
	/// contribute at least twice their fee.
	fn select_confirmed_utxos_internal(
		&self, utxos: &[Utxo], claim_id: ClaimId, force_conflicting_utxo_spend: bool,
		tolerate_high_network_feerates: bool, target_feerate_sat_per_1000_weight: u32,
		preexisting_tx_weight: u64, input_amount_sat: u64, target_amount_sat: u64,
	) -> Result<CoinSelection, ()> {
		let mut locked_utxos = self.locked_utxos.lock().unwrap();
		let mut eligible_utxos = utxos.iter().filter_map(|utxo| {
			if let Some(utxo_claim_id) = locked_utxos.get(&utxo.outpoint) {
				if *utxo_claim_id != claim_id && !force_conflicting_utxo_spend {
					log_trace!(self.logger, "Skipping UTXO {} to prevent conflicting spend", utxo.outpoint);
					return None;
				}
			}
			let fee_to_spend_utxo = fee_for_weight(
				target_feerate_sat_per_1000_weight, BASE_INPUT_WEIGHT + utxo.satisfaction_weight,
			);
			let should_spend = if tolerate_high_network_feerates {
				utxo.output.value > fee_to_spend_utxo
			} else {
				utxo.output.value >= fee_to_spend_utxo * 2
			};
			if should_spend {
				Some((utxo, fee_to_spend_utxo))
			} else {
				log_trace!(self.logger, "Skipping UTXO {} due to dust proximity after spend", utxo.outpoint);
				None
			}
		}).collect::<Vec<_>>();
		eligible_utxos.sort_unstable_by_key(|(utxo, _)| utxo.output.value);

		let mut selected_amount = input_amount_sat;
		let mut total_fees = fee_for_weight(target_feerate_sat_per_1000_weight, preexisting_tx_weight);
		let mut selected_utxos = Vec::new();
		for (utxo, fee_to_spend_utxo) in eligible_utxos {
			if selected_amount >= target_amount_sat + total_fees {
				break;
			}
			selected_amount += utxo.output.value;
			total_fees += fee_to_spend_utxo;
			selected_utxos.push(utxo.clone());
		}
		if selected_amount < target_amount_sat + total_fees {
			log_debug!(self.logger, "Insufficient funds to meet target feerate {} sat/kW",
				target_feerate_sat_per_1000_weight);
			return Err(());
		}
		for utxo in &selected_utxos {
			locked_utxos.insert(utxo.outpoint, claim_id);
		}
		core::mem::drop(locked_utxos);

		let remaining_amount = selected_amount - target_amount_sat - total_fees;
		let change_script = self.source.get_change_script()?;
		let change_output_fee = fee_for_weight(
			target_feerate_sat_per_1000_weight,
			(8 /* value */ + change_script.consensus_encode(&mut sink()).unwrap() as u64) *
				WITNESS_SCALE_FACTOR as u64,
		);
		let change_output_amount = remaining_amount.saturating_sub(change_output_fee);
		let change_output = if change_output_amount < change_script.dust_value().to_sat() {
			log_debug!(self.logger, "Coin selection attempt did not yield change output");
			None
		} else {
			Some(TxOut { script_pubkey: change_script, value: change_output_amount })
		};

		Ok(CoinSelection {
			confirmed_utxos: selected_utxos,
			change_output,
		})
	}
}

impl<W: Deref, L: Deref> CoinSelectionSource for Wallet<W, L>
where
	W::Target: WalletSource,
	L::Target: Logger
{
	fn select_confirmed_utxos(
		&self, claim_id: ClaimId, must_spend: Vec<Input>, must_pay_to: &[TxOut],
		target_feerate_sat_per_1000_weight: u32,
	) -> Result<CoinSelection, ()> {
		let utxos = self.source.list_confirmed_utxos()?;
		// TODO: Use fee estimation utils when we upgrade to bitcoin v0.30.0.
		const BASE_TX_SIZE: u64 = 4 /* version */ + 1 /* input count */ + 1 /* output count */ + 4 /* locktime */;
		let total_output_size: u64 = must_pay_to.iter().map(|output|
			8 /* value */ + 1 /* script len */ + output.script_pubkey.len() as u64
		).sum();
		let total_satisfaction_weight: u64 = must_spend.iter().map(|input| input.satisfaction_weight).sum();
		let total_input_weight = (BASE_INPUT_WEIGHT * must_spend.len() as u64) + total_satisfaction_weight;

		let preexisting_tx_weight = 2 /* segwit marker & flag */ + total_input_weight +
			((BASE_TX_SIZE + total_output_size) * WITNESS_SCALE_FACTOR as u64);
		let input_amount_sat: u64 = must_spend.iter().map(|input| input.previous_utxo.value).sum();
		let target_amount_sat = must_pay_to.iter().map(|output| output.value).sum();
		let do_coin_selection = |force_conflicting_utxo_spend: bool, tolerate_high_network_feerates: bool| {
			log_debug!(self.logger, "Attempting coin selection targeting {} sat/kW (force_conflicting_utxo_spend = {}, tolerate_high_network_feerates = {})",
				target_feerate_sat_per_1000_weight, force_conflicting_utxo_spend, tolerate_high_network_feerates);
			self.select_confirmed_utxos_internal(
				&utxos, claim_id, force_conflicting_utxo_spend, tolerate_high_network_feerates,
				target_feerate_sat_per_1000_weight, preexisting_tx_weight, input_amount_sat, target_amount_sat,
			)
		};
		do_coin_selection(false, false)
			.or_else(|_| do_coin_selection(false, true))
			.or_else(|_| do_coin_selection(true, false))
			.or_else(|_| do_coin_selection(true, true))
	}

	fn sign_psbt(&self, psbt: PartiallySignedTransaction) -> Result<Transaction, ()> {
		self.source.sign_psbt(psbt)
	}
}

/// A handler for [`Event::BumpTransaction`] events that sources confirmed UTXOs from a
/// [`CoinSelectionSource`] to fee bump transactions via Child-Pays-For-Parent (CPFP) or
/// Replace-By-Fee (RBF).
///
/// [`Event::BumpTransaction`]: crate::events::Event::BumpTransaction
pub struct BumpTransactionEventHandler<B: Deref, C: Deref, SP: Deref, L: Deref>
where
	B::Target: BroadcasterInterface,
	C::Target: CoinSelectionSource,
	SP::Target: SignerProvider,
	L::Target: Logger,
{
	broadcaster: B,
	utxo_source: C,
	signer_provider: SP,
	logger: L,
	secp: Secp256k1<secp256k1::All>,
}

impl<B: Deref, C: Deref, SP: Deref, L: Deref> BumpTransactionEventHandler<B, C, SP, L>
where
	B::Target: BroadcasterInterface,
	C::Target: CoinSelectionSource,
	SP::Target: SignerProvider,
	L::Target: Logger,
{
	/// Returns a new instance capable of handling [`Event::BumpTransaction`] events.
	///
	/// [`Event::BumpTransaction`]: crate::events::Event::BumpTransaction
	pub fn new(broadcaster: B, utxo_source: C, signer_provider: SP, logger: L) -> Self {
		Self {
			broadcaster,
			utxo_source,
			signer_provider,
			logger,
			secp: Secp256k1::new(),
		}
	}

	/// Updates a transaction with the result of a successful coin selection attempt.
	fn process_coin_selection(&self, tx: &mut Transaction, coin_selection: &CoinSelection) {
		for utxo in coin_selection.confirmed_utxos.iter() {
			tx.input.push(TxIn {
				previous_output: utxo.outpoint,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			});
		}
		if let Some(change_output) = coin_selection.change_output.clone() {
			tx.output.push(change_output);
		} else if tx.output.is_empty() {
			// We weren't provided a change output, likely because the input set was a perfect
			// match, but we still need to have at least one output in the transaction for it to be
			// considered standard. We choose to go with an empty OP_RETURN as it is the cheapest
			// way to include a dummy output.
			log_debug!(self.logger, "Including dummy OP_RETURN output since an output is needed and a change output was not provided");
			tx.output.push(TxOut {
				value: 0,
				script_pubkey: ScriptBuf::new_op_return(&[]),
			});
		}
	}

	/// Handles a [`BumpTransactionEvent::ChannelClose`] event variant by producing a fully-signed
	/// transaction spending an anchor output of the commitment transaction to bump its fee and
	/// broadcasts them to the network as a package.
	fn handle_channel_close(
		&self, claim_id: ClaimId, package_target_feerate_sat_per_1000_weight: u32,
		commitment_tx: &Transaction, commitment_tx_fee_sat: u64, anchor_descriptor: &AnchorDescriptor,
	) -> Result<(), ()> {
		// Our commitment transaction already has fees allocated to it, so we should take them into
		// account. We do so by pretending the commitment tranasction's fee and weight are part of
		// the anchor input.
		let mut anchor_utxo = anchor_descriptor.previous_utxo();
		anchor_utxo.value += commitment_tx_fee_sat;
		let must_spend = vec![Input {
			outpoint: anchor_descriptor.outpoint,
			previous_utxo: anchor_utxo,
			satisfaction_weight: commitment_tx.weight().to_wu() + ANCHOR_INPUT_WITNESS_WEIGHT + EMPTY_SCRIPT_SIG_WEIGHT,
		}];
		#[cfg(debug_assertions)]
		let must_spend_amount =	must_spend.iter().map(|input| input.previous_utxo.value).sum::<u64>();

		log_debug!(self.logger, "Peforming coin selection for commitment package (commitment and anchor transaction) targeting {} sat/kW",
			package_target_feerate_sat_per_1000_weight);
		let coin_selection: CoinSelection = self.utxo_source.select_confirmed_utxos(
			claim_id, must_spend, &[], package_target_feerate_sat_per_1000_weight,
		)?;

		let mut anchor_tx = Transaction {
			version: 2,
			lock_time: LockTime::ZERO, // TODO: Use next best height.
			input: vec![anchor_descriptor.unsigned_tx_input()],
			output: vec![],
		};

		#[cfg(debug_assertions)]
		let total_satisfaction_weight = ANCHOR_INPUT_WITNESS_WEIGHT + EMPTY_SCRIPT_SIG_WEIGHT +
			coin_selection.confirmed_utxos.iter().map(|utxo| utxo.satisfaction_weight).sum::<u64>();
		#[cfg(debug_assertions)]
		let total_input_amount = must_spend_amount +
			coin_selection.confirmed_utxos.iter().map(|utxo| utxo.output.value).sum::<u64>();

		self.process_coin_selection(&mut anchor_tx, &coin_selection);
		let anchor_txid = anchor_tx.txid();

		// construct psbt
		let mut anchor_psbt = PartiallySignedTransaction::from_unsigned_tx(anchor_tx).unwrap();
		// add witness_utxo to anchor input
		anchor_psbt.inputs[0].witness_utxo = Some(anchor_descriptor.previous_utxo());
		// add witness_utxo to remaining inputs
		for (idx, utxo) in coin_selection.confirmed_utxos.into_iter().enumerate() {
			// add 1 to skip the anchor input
			let index = idx + 1;
			debug_assert_eq!(anchor_psbt.unsigned_tx.input[index].previous_output, utxo.outpoint);
			if utxo.output.script_pubkey.is_witness_program() {
				anchor_psbt.inputs[index].witness_utxo = Some(utxo.output);
			}
		}

		debug_assert_eq!(anchor_psbt.unsigned_tx.output.len(), 1);
		#[cfg(debug_assertions)]
		let unsigned_tx_weight = anchor_psbt.unsigned_tx.weight().to_wu() - (anchor_psbt.unsigned_tx.input.len() as u64 * EMPTY_SCRIPT_SIG_WEIGHT);

		log_debug!(self.logger, "Signing anchor transaction {}", anchor_txid);
		anchor_tx = self.utxo_source.sign_psbt(anchor_psbt)?;

		let signer = anchor_descriptor.derive_channel_signer(&self.signer_provider);
		let anchor_sig = signer.sign_holder_anchor_input(&anchor_tx, 0, &self.secp)?;
		anchor_tx.input[0].witness = anchor_descriptor.tx_input_witness(&anchor_sig);

		#[cfg(debug_assertions)] {
			let signed_tx_weight = anchor_tx.weight().to_wu();
			let expected_signed_tx_weight = unsigned_tx_weight + total_satisfaction_weight;
			// Our estimate should be within a 1% error margin of the actual weight and we should
			// never underestimate.
			assert!(expected_signed_tx_weight >= signed_tx_weight &&
				expected_signed_tx_weight - (expected_signed_tx_weight / 100) <= signed_tx_weight);

			let expected_package_fee = fee_for_weight(package_target_feerate_sat_per_1000_weight,
				signed_tx_weight + commitment_tx.weight().to_wu());
			let package_fee = total_input_amount -
				anchor_tx.output.iter().map(|output| output.value).sum::<u64>();
			// Our fee should be within a 5% error margin of the expected fee based on the
			// feerate and transaction weight and we should never pay less than required.
			let fee_error_margin = expected_package_fee * 5 / 100;
			assert!(package_fee >= expected_package_fee &&
				package_fee - fee_error_margin <= expected_package_fee);
		}

		log_info!(self.logger, "Broadcasting anchor transaction {} to bump channel close with txid {}",
			anchor_txid, commitment_tx.txid());
		self.broadcaster.broadcast_transactions(&[&commitment_tx, &anchor_tx]);
		Ok(())
	}

	/// Handles a [`BumpTransactionEvent::HTLCResolution`] event variant by producing a
	/// fully-signed, fee-bumped HTLC transaction that is broadcast to the network.
	fn handle_htlc_resolution(
		&self, claim_id: ClaimId, target_feerate_sat_per_1000_weight: u32,
		htlc_descriptors: &[HTLCDescriptor], tx_lock_time: LockTime,
	) -> Result<(), ()> {
		let mut htlc_tx = Transaction {
			version: 2,
			lock_time: tx_lock_time,
			input: vec![],
			output: vec![],
		};
		let mut must_spend = Vec::with_capacity(htlc_descriptors.len());
		for htlc_descriptor in htlc_descriptors {
			let htlc_input = htlc_descriptor.unsigned_tx_input();
			must_spend.push(Input {
				outpoint: htlc_input.previous_output.clone(),
				previous_utxo: htlc_descriptor.previous_utxo(&self.secp),
				satisfaction_weight: EMPTY_SCRIPT_SIG_WEIGHT + if htlc_descriptor.preimage.is_some() {
					HTLC_SUCCESS_INPUT_ANCHOR_WITNESS_WEIGHT
				} else {
					HTLC_TIMEOUT_INPUT_ANCHOR_WITNESS_WEIGHT
				},
			});
			htlc_tx.input.push(htlc_input);
			let htlc_output = htlc_descriptor.tx_output(&self.secp);
			htlc_tx.output.push(htlc_output);
		}

		log_debug!(self.logger, "Peforming coin selection for HTLC transaction targeting {} sat/kW",
			target_feerate_sat_per_1000_weight);

		#[cfg(debug_assertions)]
		let must_spend_satisfaction_weight =
			must_spend.iter().map(|input| input.satisfaction_weight).sum::<u64>();
		#[cfg(debug_assertions)]
		let must_spend_amount =	must_spend.iter().map(|input| input.previous_utxo.value).sum::<u64>();

		let coin_selection: CoinSelection = self.utxo_source.select_confirmed_utxos(
			claim_id, must_spend, &htlc_tx.output, target_feerate_sat_per_1000_weight,
		)?;

		#[cfg(debug_assertions)]
		let total_satisfaction_weight = must_spend_satisfaction_weight +
			coin_selection.confirmed_utxos.iter().map(|utxo| utxo.satisfaction_weight).sum::<u64>();
		#[cfg(debug_assertions)]
		let total_input_amount = must_spend_amount +
			coin_selection.confirmed_utxos.iter().map(|utxo| utxo.output.value).sum::<u64>();

		self.process_coin_selection(&mut htlc_tx, &coin_selection);

		// construct psbt
		let mut htlc_psbt = PartiallySignedTransaction::from_unsigned_tx(htlc_tx).unwrap();
		// add witness_utxo to htlc inputs
		for (i, htlc_descriptor) in htlc_descriptors.iter().enumerate() {
			debug_assert_eq!(htlc_psbt.unsigned_tx.input[i].previous_output, htlc_descriptor.outpoint());
			htlc_psbt.inputs[i].witness_utxo = Some(htlc_descriptor.previous_utxo(&self.secp));
		}
		// add witness_utxo to remaining inputs
		for (idx, utxo) in coin_selection.confirmed_utxos.into_iter().enumerate() {
			// offset to skip the htlc inputs
			let index = idx + htlc_descriptors.len();
			debug_assert_eq!(htlc_psbt.unsigned_tx.input[index].previous_output, utxo.outpoint);
			if utxo.output.script_pubkey.is_witness_program() {
				htlc_psbt.inputs[index].witness_utxo = Some(utxo.output);
			}
		}

		#[cfg(debug_assertions)]
		let unsigned_tx_weight = htlc_psbt.unsigned_tx.weight().to_wu() - (htlc_psbt.unsigned_tx.input.len() as u64 * EMPTY_SCRIPT_SIG_WEIGHT);

		log_debug!(self.logger, "Signing HTLC transaction {}", htlc_psbt.unsigned_tx.txid());
		htlc_tx = self.utxo_source.sign_psbt(htlc_psbt)?;

		let mut signers = BTreeMap::new();
		for (idx, htlc_descriptor) in htlc_descriptors.iter().enumerate() {
			let signer = signers.entry(htlc_descriptor.channel_derivation_parameters.keys_id)
				.or_insert_with(|| htlc_descriptor.derive_channel_signer(&self.signer_provider));
			let htlc_sig = signer.sign_holder_htlc_transaction(&htlc_tx, idx, htlc_descriptor, &self.secp)?;
			let witness_script = htlc_descriptor.witness_script(&self.secp);
			htlc_tx.input[idx].witness = htlc_descriptor.tx_input_witness(&htlc_sig, &witness_script);
		}

		#[cfg(debug_assertions)] {
			let signed_tx_weight = htlc_tx.weight().to_wu();
			let expected_signed_tx_weight = unsigned_tx_weight + total_satisfaction_weight;
			// Our estimate should be within a 1% error margin of the actual weight and we should
			// never underestimate.
			assert!(expected_signed_tx_weight >= signed_tx_weight &&
				expected_signed_tx_weight - (expected_signed_tx_weight / 100) <= signed_tx_weight);

			let expected_signed_tx_fee = fee_for_weight(target_feerate_sat_per_1000_weight, signed_tx_weight);
			let signed_tx_fee = total_input_amount -
				htlc_tx.output.iter().map(|output| output.value).sum::<u64>();
			// Our fee should be within a 5% error margin of the expected fee based on the
			// feerate and transaction weight and we should never pay less than required.
			let fee_error_margin = expected_signed_tx_fee * 5 / 100;
			assert!(signed_tx_fee >= expected_signed_tx_fee &&
				signed_tx_fee - fee_error_margin <= expected_signed_tx_fee);
		}

		log_info!(self.logger, "Broadcasting {}", log_tx!(htlc_tx));
		self.broadcaster.broadcast_transactions(&[&htlc_tx]);
		Ok(())
	}

	/// Handles all variants of [`BumpTransactionEvent`].
	pub fn handle_event(&self, event: &BumpTransactionEvent) {
		match event {
			BumpTransactionEvent::ChannelClose {
				claim_id, package_target_feerate_sat_per_1000_weight, commitment_tx,
				commitment_tx_fee_satoshis, anchor_descriptor, ..
			} => {
				log_info!(self.logger, "Handling channel close bump (claim_id = {}, commitment_txid = {})",
					log_bytes!(claim_id.0), commitment_tx.txid());
				if let Err(_) = self.handle_channel_close(
					*claim_id, *package_target_feerate_sat_per_1000_weight, commitment_tx,
					*commitment_tx_fee_satoshis, anchor_descriptor,
				) {
					log_error!(self.logger, "Failed bumping commitment transaction fee for {}",
						commitment_tx.txid());
				}
			}
			BumpTransactionEvent::HTLCResolution {
				claim_id, target_feerate_sat_per_1000_weight, htlc_descriptors, tx_lock_time, ..
			} => {
				log_info!(self.logger, "Handling HTLC bump (claim_id = {}, htlcs_to_claim = {})",
					log_bytes!(claim_id.0), log_iter!(htlc_descriptors.iter().map(|d| d.outpoint())));
				if let Err(_) = self.handle_htlc_resolution(
					*claim_id, *target_feerate_sat_per_1000_weight, htlc_descriptors, *tx_lock_time,
				) {
					log_error!(self.logger, "Failed bumping HTLC transaction fee for commitment {}",
						htlc_descriptors[0].commitment_txid);
				}
			}
		}
	}
}
