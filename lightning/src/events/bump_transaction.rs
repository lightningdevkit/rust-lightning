// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utitilies for bumping transactions originating from [`super::Event`]s.

use core::convert::TryInto;
use core::ops::Deref;

use crate::chain::chaininterface::BroadcasterInterface;
use crate::chain::ClaimId;
use crate::sign::{ChannelSigner, EcdsaChannelSigner, SignerProvider};
use crate::io_extras::sink;
use crate::ln::PaymentPreimage;
use crate::ln::chan_utils;
use crate::ln::chan_utils::{
	ANCHOR_INPUT_WITNESS_WEIGHT, HTLC_SUCCESS_INPUT_ANCHOR_WITNESS_WEIGHT,
	HTLC_TIMEOUT_INPUT_ANCHOR_WITNESS_WEIGHT, ChannelTransactionParameters, HTLCOutputInCommitment
};
use crate::events::Event;
use crate::prelude::HashMap;
use crate::util::logger::Logger;

use bitcoin::{OutPoint, PackedLockTime, PubkeyHash, Sequence, Script, Transaction, Txid, TxIn, TxOut, Witness, WPubkeyHash};
use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
use bitcoin::consensus::Encodable;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::secp256k1::ecdsa::Signature;

const EMPTY_SCRIPT_SIG_WEIGHT: u64 = 1 /* empty script_sig */ * WITNESS_SCALE_FACTOR as u64;

const BASE_INPUT_SIZE: u64 = 32 /* txid */ + 4 /* vout */ + 4 /* sequence */;

const BASE_INPUT_WEIGHT: u64 = BASE_INPUT_SIZE * WITNESS_SCALE_FACTOR as u64;

// TODO: Define typed abstraction over feerates to handle their conversions.
fn compute_feerate_sat_per_1000_weight(fee_sat: u64, weight: u64) -> u32 {
	(fee_sat * 1000 / weight).try_into().unwrap_or(u32::max_value())
}
const fn fee_for_weight(feerate_sat_per_1000_weight: u32, weight: u64) -> u64 {
	((feerate_sat_per_1000_weight as u64 * weight) + 1000 - 1) / 1000
}

/// A descriptor used to sign for a commitment transaction's anchor output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorDescriptor {
	/// A unique identifier used along with `channel_value_satoshis` to re-derive the
	/// [`InMemorySigner`] required to sign `input`.
	///
	/// [`InMemorySigner`]: crate::sign::InMemorySigner
	pub channel_keys_id: [u8; 32],
	/// The value in satoshis of the channel we're attempting to spend the anchor output of. This is
	/// used along with `channel_keys_id` to re-derive the [`InMemorySigner`] required to sign
	/// `input`.
	///
	/// [`InMemorySigner`]: crate::sign::InMemorySigner
	pub channel_value_satoshis: u64,
	/// The transaction input's outpoint corresponding to the commitment transaction's anchor
	/// output.
	pub outpoint: OutPoint,
}

/// A descriptor used to sign for a commitment transaction's HTLC output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HTLCDescriptor {
	/// A unique identifier used along with `channel_value_satoshis` to re-derive the
	/// [`InMemorySigner`] required to sign `input`.
	///
	/// [`InMemorySigner`]: crate::sign::InMemorySigner
	pub channel_keys_id: [u8; 32],
	/// The value in satoshis of the channel we're attempting to spend the anchor output of. This is
	/// used along with `channel_keys_id` to re-derive the [`InMemorySigner`] required to sign
	/// `input`.
	///
	/// [`InMemorySigner`]: crate::sign::InMemorySigner
	pub channel_value_satoshis: u64,
	/// The necessary channel parameters that need to be provided to the re-derived
	/// [`InMemorySigner`] through [`ChannelSigner::provide_channel_parameters`].
	///
	/// [`InMemorySigner`]: crate::sign::InMemorySigner
	/// [`ChannelSigner::provide_channel_parameters`]: crate::sign::ChannelSigner::provide_channel_parameters
	pub channel_parameters: ChannelTransactionParameters,
	/// The txid of the commitment transaction in which the HTLC output lives.
	pub commitment_txid: Txid,
	/// The number of the commitment transaction in which the HTLC output lives.
	pub per_commitment_number: u64,
	/// The details of the HTLC as it appears in the commitment transaction.
	pub htlc: HTLCOutputInCommitment,
	/// The preimage, if `Some`, to claim the HTLC output with. If `None`, the timeout path must be
	/// taken.
	pub preimage: Option<PaymentPreimage>,
	/// The counterparty's signature required to spend the HTLC output.
	pub counterparty_sig: Signature
}

impl HTLCDescriptor {
	/// Returns the unsigned transaction input spending the HTLC output in the commitment
	/// transaction.
	pub fn unsigned_tx_input(&self) -> TxIn {
		chan_utils::build_htlc_input(&self.commitment_txid, &self.htlc, true /* opt_anchors */)
	}

	/// Returns the delayed output created as a result of spending the HTLC output in the commitment
	/// transaction.
	pub fn tx_output<C: secp256k1::Signing + secp256k1::Verification>(
		&self, per_commitment_point: &PublicKey, secp: &Secp256k1<C>
	) -> TxOut {
		let channel_params = self.channel_parameters.as_holder_broadcastable();
		let broadcaster_keys = channel_params.broadcaster_pubkeys();
		let counterparty_keys = channel_params.countersignatory_pubkeys();
		let broadcaster_delayed_key = chan_utils::derive_public_key(
			secp, per_commitment_point, &broadcaster_keys.delayed_payment_basepoint
		);
		let counterparty_revocation_key = chan_utils::derive_public_revocation_key(
			secp, per_commitment_point, &counterparty_keys.revocation_basepoint
		);
		chan_utils::build_htlc_output(
			0 /* feerate_per_kw */, channel_params.contest_delay(), &self.htlc, true /* opt_anchors */,
			false /* use_non_zero_fee_anchors */, &broadcaster_delayed_key, &counterparty_revocation_key
		)
	}

	/// Returns the witness script of the HTLC output in the commitment transaction.
	pub fn witness_script<C: secp256k1::Signing + secp256k1::Verification>(
		&self, per_commitment_point: &PublicKey, secp: &Secp256k1<C>
	) -> Script {
		let channel_params = self.channel_parameters.as_holder_broadcastable();
		let broadcaster_keys = channel_params.broadcaster_pubkeys();
		let counterparty_keys = channel_params.countersignatory_pubkeys();
		let broadcaster_htlc_key = chan_utils::derive_public_key(
			secp, per_commitment_point, &broadcaster_keys.htlc_basepoint
		);
		let counterparty_htlc_key = chan_utils::derive_public_key(
			secp, per_commitment_point, &counterparty_keys.htlc_basepoint
		);
		let counterparty_revocation_key = chan_utils::derive_public_revocation_key(
			secp, per_commitment_point, &counterparty_keys.revocation_basepoint
		);
		chan_utils::get_htlc_redeemscript_with_explicit_keys(
			&self.htlc, true /* opt_anchors */, &broadcaster_htlc_key, &counterparty_htlc_key,
			&counterparty_revocation_key,
		)
	}

	/// Returns the fully signed witness required to spend the HTLC output in the commitment
	/// transaction.
	pub fn tx_input_witness(&self, signature: &Signature, witness_script: &Script) -> Witness {
		chan_utils::build_htlc_input_witness(
			signature, &self.counterparty_sig, &self.preimage, witness_script, true /* opt_anchors */
		)
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
	/// child anchor transaction. To sign its anchor input, an [`InMemorySigner`] should be
	/// re-derived through [`KeysManager::derive_channel_keys`] with the help of
	/// [`AnchorDescriptor::channel_keys_id`] and [`AnchorDescriptor::channel_value_satoshis`]. The
	/// anchor input signature can be computed with [`EcdsaChannelSigner::sign_holder_anchor_input`],
	/// which can then be provided to [`build_anchor_input_witness`] along with the `funding_pubkey`
	/// to obtain the full witness required to spend.
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
	/// [`InMemorySigner`]: crate::sign::InMemorySigner
	/// [`KeysManager::derive_channel_keys`]: crate::sign::KeysManager::derive_channel_keys
	/// [`EcdsaChannelSigner::sign_holder_anchor_input`]: crate::sign::EcdsaChannelSigner::sign_holder_anchor_input
	/// [`build_anchor_input_witness`]: crate::ln::chan_utils::build_anchor_input_witness
	ChannelClose {
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
	/// HTLC transaction. To sign HTLC inputs, an [`InMemorySigner`] should be re-derived through
	/// [`KeysManager::derive_channel_keys`] with the help of `channel_keys_id` and
	/// `channel_value_satoshis`. Each HTLC input's signature can be computed with
	/// [`EcdsaChannelSigner::sign_holder_htlc_transaction`], which can then be provided to
	/// [`HTLCDescriptor::tx_input_witness`] to obtain the fully signed witness required to spend.
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
	/// [`InMemorySigner`]: crate::sign::InMemorySigner
	/// [`KeysManager::derive_channel_keys`]: crate::sign::KeysManager::derive_channel_keys
	/// [`EcdsaChannelSigner::sign_holder_htlc_transaction`]: crate::sign::EcdsaChannelSigner::sign_holder_htlc_transaction
	/// [`HTLCDescriptor::tx_input_witness`]: HTLCDescriptor::tx_input_witness
	HTLCResolution {
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
		tx_lock_time: PackedLockTime,
	},
}

/// An input that must be included in a transaction when performing coin selection through
/// [`CoinSelectionSource::select_confirmed_utxos`]. It is guaranteed to be a SegWit input, so it
/// must have an empty [`TxIn::script_sig`] when spent.
pub struct Input {
	/// The unique identifier of the input.
	pub outpoint: OutPoint,
	/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and
	/// [`TxIn::witness`], each with their lengths included, required to satisfy the output's
	/// script.
	pub satisfaction_weight: u64,
}

/// An unspent transaction output that is available to spend resulting from a successful
/// [`CoinSelection`] attempt.
#[derive(Clone, Debug)]
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
	const P2WPKH_WITNESS_WEIGHT: u64 = 1 /* num stack items */ +
		1 /* sig length */ +
		73 /* sig including sighash flag */ +
		1 /* pubkey length */ +
		33 /* pubkey */;

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
				script_pubkey: Script::new_p2pkh(pubkey_hash),
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
				script_pubkey: Script::new_p2sh(&Script::new_v0_p2wpkh(pubkey_hash).script_hash()),
			},
			satisfaction_weight: script_sig_size * WITNESS_SCALE_FACTOR as u64 + Self::P2WPKH_WITNESS_WEIGHT,
		}
	}

	/// Returns a `Utxo` with the `satisfaction_weight` estimate for a SegWit v0 P2WPKH output.
	pub fn new_v0_p2wpkh(outpoint: OutPoint, value: u64, pubkey_hash: &WPubkeyHash) -> Self {
		Self {
			outpoint,
			output: TxOut {
				value,
				script_pubkey: Script::new_v0_p2wpkh(pubkey_hash),
			},
			satisfaction_weight: EMPTY_SCRIPT_SIG_WEIGHT + Self::P2WPKH_WITNESS_WEIGHT,
		}
	}
}

/// The result of a successful coin selection attempt for a transaction requiring additional UTXOs
/// to cover its fees.
pub struct CoinSelection {
	/// The set of UTXOs (with at least 1 confirmation) to spend and use within a transaction
	/// requiring additional fees.
	confirmed_utxos: Vec<Utxo>,
	/// An additional output tracking whether any change remained after coin selection. This output
	/// should always have a value above dust for its given `script_pubkey`. It should not be
	/// spent until the transaction it belongs to confirms to ensure mempool descendant limits are
	/// not met. This implies no other party should be able to spend it except us.
	change_output: Option<TxOut>,
}

/// An abstraction over a bitcoin wallet that can perform coin selection over a set of UTXOs and can
/// sign for them. The coin selection method aims to mimic Bitcoin Core's `fundrawtransaction` RPC,
/// which most wallets should be able to satisfy.
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
		&self, claim_id: ClaimId, must_spend: &[Input], must_pay_to: &[TxOut],
		target_feerate_sat_per_1000_weight: u32,
	) -> Result<CoinSelection, ()>;
	/// Signs and provides the full witness for all inputs within the transaction known to the
	/// trait (i.e., any provided via [`CoinSelectionSource::select_confirmed_utxos`]).
	fn sign_tx(&self, tx: &mut Transaction) -> Result<(), ()>;
}

/// A handler for [`Event::BumpTransaction`] events that sources confirmed UTXOs from a
/// [`CoinSelectionSource`] to fee bump transactions via Child-Pays-For-Parent (CPFP) or
/// Replace-By-Fee (RBF).
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
	fn process_coin_selection(&self, tx: &mut Transaction, mut coin_selection: CoinSelection) {
		for utxo in coin_selection.confirmed_utxos.drain(..) {
			tx.input.push(TxIn {
				previous_output: utxo.outpoint,
				script_sig: Script::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			});
		}
		if let Some(change_output) = coin_selection.change_output.take() {
			tx.output.push(change_output);
		} else if tx.output.is_empty() {
			// We weren't provided a change output, likely because the input set was a perfect
			// match, but we still need to have at least one output in the transaction for it to be
			// considered standard. We choose to go with an empty OP_RETURN as it is the cheapest
			// way to include a dummy output.
			tx.output.push(TxOut {
				value: 0,
				script_pubkey: Script::new_op_return(&[]),
			});
		}
	}

	/// Returns an unsigned transaction spending an anchor output of the commitment transaction, and
	/// any additional UTXOs sourced, to bump the commitment transaction's fee.
	fn build_anchor_tx(
		&self, claim_id: ClaimId, target_feerate_sat_per_1000_weight: u32,
		commitment_tx: &Transaction, anchor_descriptor: &AnchorDescriptor,
	) -> Result<Transaction, ()> {
		let must_spend = vec![Input {
			outpoint: anchor_descriptor.outpoint,
			satisfaction_weight: commitment_tx.weight() as u64 + ANCHOR_INPUT_WITNESS_WEIGHT + EMPTY_SCRIPT_SIG_WEIGHT,
		}];
		let coin_selection = self.utxo_source.select_confirmed_utxos(
			claim_id, &must_spend, &[], target_feerate_sat_per_1000_weight,
		)?;

		let mut tx = Transaction {
			version: 2,
			lock_time: PackedLockTime::ZERO, // TODO: Use next best height.
			input: vec![TxIn {
				previous_output: anchor_descriptor.outpoint,
				script_sig: Script::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}],
			output: vec![],
		};
		self.process_coin_selection(&mut tx, coin_selection);
		Ok(tx)
	}

	/// Handles a [`BumpTransactionEvent::ChannelClose`] event variant by producing a fully-signed
	/// transaction spending an anchor output of the commitment transaction to bump its fee and
	/// broadcasts them to the network as a package.
	fn handle_channel_close(
		&self, claim_id: ClaimId, package_target_feerate_sat_per_1000_weight: u32,
		commitment_tx: &Transaction, commitment_tx_fee_sat: u64, anchor_descriptor: &AnchorDescriptor,
	) -> Result<(), ()> {
		// Compute the feerate the anchor transaction must meet to meet the overall feerate for the
		// package (commitment + anchor transactions).
		let commitment_tx_sat_per_1000_weight: u32 = compute_feerate_sat_per_1000_weight(
			commitment_tx_fee_sat, commitment_tx.weight() as u64,
		);
		if commitment_tx_sat_per_1000_weight >= package_target_feerate_sat_per_1000_weight {
			// If the commitment transaction already has a feerate high enough on its own, broadcast
			// it as is without a child.
			self.broadcaster.broadcast_transactions(&[&commitment_tx]);
			return Ok(());
		}

		let mut anchor_tx = self.build_anchor_tx(
			claim_id, package_target_feerate_sat_per_1000_weight, commitment_tx, anchor_descriptor,
		)?;
		debug_assert_eq!(anchor_tx.output.len(), 1);

		self.utxo_source.sign_tx(&mut anchor_tx)?;
		let signer = self.signer_provider.derive_channel_signer(
			anchor_descriptor.channel_value_satoshis, anchor_descriptor.channel_keys_id,
		);
		let anchor_sig = signer.sign_holder_anchor_input(&anchor_tx, 0, &self.secp)?;
		anchor_tx.input[0].witness =
			chan_utils::build_anchor_input_witness(&signer.pubkeys().funding_pubkey, &anchor_sig);

		self.broadcaster.broadcast_transactions(&[&commitment_tx, &anchor_tx]);
		Ok(())
	}

	/// Returns an unsigned, fee-bumped HTLC transaction, along with the set of signers required to
	/// fulfill the witness for each HTLC input within it.
	fn build_htlc_tx(
		&self, claim_id: ClaimId, target_feerate_sat_per_1000_weight: u32,
		htlc_descriptors: &[HTLCDescriptor], tx_lock_time: PackedLockTime,
	) -> Result<(Transaction, HashMap<[u8; 32], <SP::Target as SignerProvider>::Signer>), ()> {
		let mut tx = Transaction {
			version: 2,
			lock_time: tx_lock_time,
			input: vec![],
			output: vec![],
		};
		// Unfortunately, we need to derive the signer for each HTLC ahead of time to obtain its
		// input.
		let mut signers = HashMap::new();
		let mut must_spend = Vec::with_capacity(htlc_descriptors.len());
		for htlc_descriptor in htlc_descriptors {
			let signer = signers.entry(htlc_descriptor.channel_keys_id)
				.or_insert_with(||
					self.signer_provider.derive_channel_signer(
						htlc_descriptor.channel_value_satoshis, htlc_descriptor.channel_keys_id,
					)
				);
			let per_commitment_point = signer.get_per_commitment_point(
				htlc_descriptor.per_commitment_number, &self.secp
			);

			let htlc_input = htlc_descriptor.unsigned_tx_input();
			must_spend.push(Input {
				outpoint: htlc_input.previous_output.clone(),
				satisfaction_weight: EMPTY_SCRIPT_SIG_WEIGHT + if htlc_descriptor.preimage.is_some() {
					HTLC_SUCCESS_INPUT_ANCHOR_WITNESS_WEIGHT
				} else {
					HTLC_TIMEOUT_INPUT_ANCHOR_WITNESS_WEIGHT
				},
			});
			tx.input.push(htlc_input);
			let htlc_output = htlc_descriptor.tx_output(&per_commitment_point, &self.secp);
			tx.output.push(htlc_output);
		}

		let coin_selection = self.utxo_source.select_confirmed_utxos(
			claim_id, &must_spend, &tx.output, target_feerate_sat_per_1000_weight,
		)?;
		self.process_coin_selection(&mut tx, coin_selection);
		Ok((tx, signers))
	}

	/// Handles a [`BumpTransactionEvent::HTLCResolution`] event variant by producing a
	/// fully-signed, fee-bumped HTLC transaction that is broadcast to the network.
	fn handle_htlc_resolution(
		&self, claim_id: ClaimId, target_feerate_sat_per_1000_weight: u32,
		htlc_descriptors: &[HTLCDescriptor], tx_lock_time: PackedLockTime,
	) -> Result<(), ()> {
		let (mut htlc_tx, signers) = self.build_htlc_tx(
			claim_id, target_feerate_sat_per_1000_weight, htlc_descriptors, tx_lock_time,
		)?;

		self.utxo_source.sign_tx(&mut htlc_tx)?;
		for (idx, htlc_descriptor) in htlc_descriptors.iter().enumerate() {
			let signer = signers.get(&htlc_descriptor.channel_keys_id).unwrap();
			let htlc_sig = signer.sign_holder_htlc_transaction(
				&htlc_tx, idx, htlc_descriptor, &self.secp
			)?;
			let per_commitment_point = signer.get_per_commitment_point(
				htlc_descriptor.per_commitment_number, &self.secp
			);
			let witness_script = htlc_descriptor.witness_script(&per_commitment_point, &self.secp);
			htlc_tx.input[idx].witness = htlc_descriptor.tx_input_witness(&htlc_sig, &witness_script);
		}

		self.broadcaster.broadcast_transactions(&[&htlc_tx]);
		Ok(())
	}

	/// Handles all variants of [`BumpTransactionEvent`], immediately returning otherwise.
	pub fn handle_event(&self, event: &Event) {
		let event = if let Event::BumpTransaction(event) = event {
			event
		} else {
			return;
		};
		match event {
			BumpTransactionEvent::ChannelClose {
				claim_id, package_target_feerate_sat_per_1000_weight, commitment_tx,
				anchor_descriptor, commitment_tx_fee_satoshis,	..
			} => {
				if let Err(_) = self.handle_channel_close(
					*claim_id, *package_target_feerate_sat_per_1000_weight, commitment_tx,
					*commitment_tx_fee_satoshis, anchor_descriptor,
				) {
					log_error!(self.logger, "Failed bumping commitment transaction fee for {}",
						commitment_tx.txid());
				}
			}
			BumpTransactionEvent::HTLCResolution {
				claim_id, target_feerate_sat_per_1000_weight, htlc_descriptors, tx_lock_time,
			} => {
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
