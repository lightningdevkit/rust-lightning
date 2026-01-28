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

pub mod sync;

use alloc::collections::BTreeMap;
use core::ops::Deref;

use crate::chain::chaininterface::{
	compute_feerate_sat_per_1000_weight, fee_for_weight, BroadcasterInterface,
};
use crate::chain::ClaimId;
use crate::ln::chan_utils;
use crate::ln::chan_utils::{
	shared_anchor_script_pubkey, HTLCOutputInCommitment, ANCHOR_INPUT_WITNESS_WEIGHT,
	EMPTY_SCRIPT_SIG_WEIGHT, EMPTY_WITNESS_WEIGHT, HTLC_SUCCESS_INPUT_KEYED_ANCHOR_WITNESS_WEIGHT,
	HTLC_SUCCESS_INPUT_P2A_ANCHOR_WITNESS_WEIGHT, HTLC_TIMEOUT_INPUT_KEYED_ANCHOR_WITNESS_WEIGHT,
	HTLC_TIMEOUT_INPUT_P2A_ANCHOR_WITNESS_WEIGHT, TRUC_CHILD_MAX_WEIGHT, TRUC_MAX_WEIGHT,
};
use crate::ln::types::ChannelId;
use crate::prelude::*;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::{ChannelDerivationParameters, HTLCDescriptor, SignerProvider};
use crate::util::logger::Logger;
use crate::util::wallet_utils::{CoinSelection, CoinSelectionSource, ConfirmedUtxo, Input};

use bitcoin::amount::Amount;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::policy::MAX_STANDARD_TX_WEIGHT;
use bitcoin::secp256k1;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// A descriptor used to sign for a commitment transaction's anchor output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorDescriptor {
	/// The parameters required to derive the signer for the anchor input.
	pub channel_derivation_parameters: ChannelDerivationParameters,
	/// The transaction input's outpoint corresponding to the commitment transaction's anchor
	/// output.
	pub outpoint: OutPoint,
	/// Zero-fee-commitment anchors have variable value, which is tracked here.
	pub value: Amount,
}

impl AnchorDescriptor {
	/// Returns the UTXO to be spent by the anchor input, which can be obtained via
	/// [`Self::unsigned_tx_input`].
	pub fn previous_utxo(&self) -> TxOut {
		let tx_params = &self.channel_derivation_parameters.transaction_parameters;
		let script_pubkey = if tx_params.channel_type_features.supports_anchors_zero_fee_htlc_tx() {
			let channel_params = tx_params.as_holder_broadcastable();
			chan_utils::get_keyed_anchor_redeemscript(
				&channel_params.broadcaster_pubkeys().funding_pubkey,
			)
		} else {
			assert!(tx_params.channel_type_features.supports_anchor_zero_fee_commitments());
			shared_anchor_script_pubkey()
		};
		TxOut { script_pubkey, value: self.value }
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

	/// Returns the fully signed witness required to spend the anchor output in the commitment
	/// transaction.
	pub fn tx_input_witness(&self, signature: &Signature) -> Witness {
		let tx_params = &self.channel_derivation_parameters.transaction_parameters;
		if tx_params.channel_type_features.supports_anchors_zero_fee_htlc_tx() {
			let channel_params =
				self.channel_derivation_parameters.transaction_parameters.as_holder_broadcastable();
			chan_utils::build_keyed_anchor_input_witness(
				&channel_params.broadcaster_pubkeys().funding_pubkey,
				signature,
			)
		} else {
			debug_assert!(tx_params.channel_type_features.supports_anchor_zero_fee_commitments());
			Witness::from_slice(&[&[]])
		}
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
	/// broadcast first, as the child anchor transaction depends on it. It is also possible that the
	/// feerate of the commitment transaction is already sufficient, in which case the child anchor
	/// transaction is not needed and only the commitment transaction should be broadcast.
	///
	/// In zero-fee commitment channels, the commitment transaction and the anchor transaction
	/// form a 1-parent-1-child package that conforms to BIP 431 (known as TRUC transactions).
	/// The anchor transaction must be version 3, and its size must be no more than 1000 vB.
	/// The anchor transaction is usually needed to bump the fee of the commitment transaction
	/// as the commitment transaction is not explicitly assigned any fees. In those cases the
	/// anchor transaction must be broadcast together with the commitment transaction as a
	/// `child-with-parents` package (usually using the Bitcoin Core `submitpackage` RPC).
	///
	/// The consumer should be able to sign for any of the additional inputs included within the
	/// child anchor transaction. To sign its keyed-anchor input, an [`EcdsaChannelSigner`] should
	/// be re-derived through [`SignerProvider::derive_channel_signer`]. The anchor input signature
	/// can be computed with [`EcdsaChannelSigner::sign_holder_keyed_anchor_input`], which can then
	/// be provided to [`build_keyed_anchor_input_witness`] along with the `funding_pubkey` to
	/// obtain the full witness required to spend. Note that no signature or witness data is
	/// required to spend the keyless anchor used in zero-fee commitment channels.
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
	/// [`EcdsaChannelSigner::sign_holder_keyed_anchor_input`]: crate::sign::ecdsa::EcdsaChannelSigner::sign_holder_keyed_anchor_input
	/// [`build_keyed_anchor_input_witness`]: crate::ln::chan_utils::build_keyed_anchor_input_witness
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
	/// holder commitment transaction and its HTLC(s) need to be resolved on-chain. In all such
	/// channels, the pre-signed HTLC transactions have a zero fee, thus requiring additional
	/// inputs and/or outputs to be attached for a timely confirmation within the chain. These
	/// additional inputs and/or outputs must be appended to the resulting HTLC transaction to
	/// meet the target feerate. Failure to meet the target feerate decreases the confirmation
	/// odds of the transaction, possibly resulting in a loss of funds. Once the transaction
	/// meets the target feerate, it must be signed for and broadcast by the consumer of the
	/// event.
	///
	/// In zero-fee commitment channels, you must set the version of the HTLC claim transaction
	/// to version 3 as the counterparty's signature commits to the version of
	/// the transaction. You must also make sure that this claim transaction does not grow
	/// bigger than 10,000 vB, the maximum vsize of any TRUC transaction as specified in
	/// BIP 431. It is possible for [`htlc_descriptors`] to be long enough such
	/// that claiming all the HTLCs therein in a single transaction would exceed this limit.
	/// In this case, you must claim all the HTLCs in [`htlc_descriptors`] using multiple
	/// transactions. Finally, note that while HTLCs in zero-fee commitment channels no
	/// longer have the 1 CSV lock, LDK will still emit this event only after the commitment
	/// transaction has 1 confirmation.
	///
	/// The consumer should be able to sign for any of the non-HTLC inputs added to the resulting
	/// HTLC transaction. To sign HTLC inputs, an [`EcdsaChannelSigner`] should be re-derived
	/// through [`SignerProvider::derive_channel_signer`]. Each HTLC input's signature can be
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
	/// [`htlc_descriptors`]: `BumpTransactionEvent::HTLCResolution::htlc_descriptors`
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

/// A handler for [`Event::BumpTransaction`] events that sources confirmed UTXOs from a
/// [`CoinSelectionSource`] to fee bump transactions via Child-Pays-For-Parent (CPFP) or
/// Replace-By-Fee (RBF).
///
/// For a synchronous version of this handler, see [`sync::BumpTransactionEventHandlerSync`].
///
/// This is not exported to bindings users as async is only supported in Rust.
///
/// [`Event::BumpTransaction`]: crate::events::Event::BumpTransaction
// Note that updates to documentation on this struct should be copied to the synchronous version.
pub struct BumpTransactionEventHandler<
	B: BroadcasterInterface,
	C: Deref,
	SP: SignerProvider,
	L: Logger,
> where
	C::Target: CoinSelectionSource,
{
	broadcaster: B,
	utxo_source: C,
	signer_provider: SP,
	logger: L,
	secp: Secp256k1<secp256k1::All>,
}

impl<B: BroadcasterInterface, C: Deref, SP: SignerProvider, L: Logger>
	BumpTransactionEventHandler<B, C, SP, L>
where
	C::Target: CoinSelectionSource,
{
	/// Returns a new instance capable of handling [`Event::BumpTransaction`] events.
	///
	/// [`Event::BumpTransaction`]: crate::events::Event::BumpTransaction
	pub fn new(broadcaster: B, utxo_source: C, signer_provider: SP, logger: L) -> Self {
		Self { broadcaster, utxo_source, signer_provider, logger, secp: Secp256k1::new() }
	}

	/// Updates a transaction with the result of a successful coin selection attempt.
	fn process_coin_selection(&self, tx: &mut Transaction, coin_selection: &CoinSelection) {
		for ConfirmedUtxo { utxo, .. } in coin_selection.confirmed_utxos.iter() {
			tx.input.push(TxIn {
				previous_output: utxo.outpoint,
				script_sig: ScriptBuf::new(),
				sequence: utxo.sequence,
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
			if tx.input.len() <= 1 {
				// Transactions have to be at least 65 bytes in non-witness data, which we can run
				// under if we have too few witness inputs.
				log_debug!(self.logger, "Including large OP_RETURN output since an output is needed and a change output was not provided and the transaction is small");
				debug_assert!(!tx.input.is_empty());
				tx.output.push(TxOut {
					value: Amount::ZERO,
					// Minimum transaction size is 60 bytes, so we need a 5-byte script to get a
					// 65 byte transaction. We do that as OP_RETURN <3 0 bytes, plus 1 byte len>.
					script_pubkey: ScriptBuf::new_op_return(&[0, 0, 0]),
				});
				debug_assert_eq!(tx.base_size(), 65);
			} else {
				log_debug!(self.logger, "Including dummy OP_RETURN output since an output is needed and a change output was not provided");
				tx.output.push(TxOut {
					value: Amount::ZERO,
					script_pubkey: ScriptBuf::new_op_return(&[]),
				});
			}
		}
	}

	/// Handles a [`BumpTransactionEvent::ChannelClose`] event variant by producing a fully-signed
	/// transaction spending an anchor output of the commitment transaction to bump its fee and
	/// broadcasts them to the network as a package.
	async fn handle_channel_close(
		&self, claim_id: ClaimId, package_target_feerate_sat_per_1000_weight: u32,
		commitment_tx: &Transaction, commitment_tx_fee_sat: u64,
		anchor_descriptor: &AnchorDescriptor,
	) -> Result<(), ()> {
		let channel_type = &anchor_descriptor
			.channel_derivation_parameters
			.transaction_parameters
			.channel_type_features;
		let anchor_input_witness_weight = if channel_type.supports_anchor_zero_fee_commitments() {
			EMPTY_WITNESS_WEIGHT
		} else {
			ANCHOR_INPUT_WITNESS_WEIGHT
		};

		// First, check if the commitment transaction has sufficient fees on its own.
		let commitment_tx_feerate_sat_per_1000_weight = compute_feerate_sat_per_1000_weight(
			commitment_tx_fee_sat,
			commitment_tx.weight().to_wu(),
		);
		if commitment_tx_feerate_sat_per_1000_weight >= package_target_feerate_sat_per_1000_weight {
			log_debug!(self.logger, "Pre-signed commitment {} already has feerate {} sat/kW above required {} sat/kW, broadcasting.",
				commitment_tx.compute_txid(), commitment_tx_feerate_sat_per_1000_weight,
				package_target_feerate_sat_per_1000_weight);
			self.broadcaster.broadcast_transactions(&[&commitment_tx]);
			return Ok(());
		}

		// Our commitment transaction already has fees allocated to it, so we should take them into
		// account. We do so by pretending the commitment transaction's fee and weight are part of
		// the anchor input.
		let mut anchor_utxo = anchor_descriptor.previous_utxo();
		let commitment_tx_fee_sat = Amount::from_sat(commitment_tx_fee_sat);
		let commitment_tx_weight = commitment_tx.weight().to_wu();
		anchor_utxo.value += commitment_tx_fee_sat;
		let starting_package_and_fixed_input_satisfaction_weight =
			commitment_tx_weight + anchor_input_witness_weight + EMPTY_SCRIPT_SIG_WEIGHT;
		let mut package_and_fixed_input_satisfaction_weight =
			starting_package_and_fixed_input_satisfaction_weight;

		loop {
			let must_spend = vec![Input {
				outpoint: anchor_descriptor.outpoint,
				previous_utxo: anchor_utxo.clone(),
				satisfaction_weight: package_and_fixed_input_satisfaction_weight,
			}];
			let must_spend_amount =
				must_spend.iter().map(|input| input.previous_utxo.value).sum::<Amount>();

			log_debug!(self.logger, "Performing coin selection for commitment package (commitment and anchor transaction) targeting {} sat/kW",
				package_target_feerate_sat_per_1000_weight);
			let coin_selection: CoinSelection = self
				.utxo_source
				.select_confirmed_utxos(
					Some(claim_id),
					must_spend,
					&[],
					package_target_feerate_sat_per_1000_weight,
					if channel_type.supports_anchor_zero_fee_commitments() {
						TRUC_CHILD_MAX_WEIGHT
					} else {
						MAX_STANDARD_TX_WEIGHT as u64
					}
					// We added the commitment tx weight to the input satisfaction weight above, so
					// increase the max_tx_weight by the same delta here.
					+ commitment_tx_weight,
				)
				.await?;

			let version = if channel_type.supports_anchor_zero_fee_commitments() {
				Version::non_standard(3)
			} else {
				Version::TWO
			};

			let mut anchor_tx = Transaction {
				version,
				lock_time: LockTime::ZERO, // TODO: Use next best height.
				input: vec![anchor_descriptor.unsigned_tx_input()],
				output: vec![],
			};

			let input_satisfaction_weight = coin_selection.satisfaction_weight();
			let total_satisfaction_weight =
				anchor_input_witness_weight + EMPTY_SCRIPT_SIG_WEIGHT + input_satisfaction_weight;
			let total_input_amount = must_spend_amount + coin_selection.input_amount();

			self.process_coin_selection(&mut anchor_tx, &coin_selection);
			let anchor_txid = anchor_tx.compute_txid();

			// construct psbt
			let mut anchor_psbt = Psbt::from_unsigned_tx(anchor_tx).unwrap();
			// add witness_utxo to anchor input
			anchor_psbt.inputs[0].witness_utxo = Some(anchor_descriptor.previous_utxo());
			// add witness_utxo to remaining inputs
			for (idx, utxo) in coin_selection.confirmed_utxos.into_iter().enumerate() {
				// add 1 to skip the anchor input
				let index = idx + 1;
				debug_assert_eq!(
					anchor_psbt.unsigned_tx.input[index].previous_output,
					utxo.outpoint()
				);
				if utxo.output().script_pubkey.is_witness_program() {
					anchor_psbt.inputs[index].witness_utxo = Some(utxo.into_output());
				}
			}

			debug_assert_eq!(anchor_psbt.unsigned_tx.output.len(), 1);
			let unsigned_tx_weight = anchor_psbt.unsigned_tx.weight().to_wu()
				- (anchor_psbt.unsigned_tx.input.len() as u64 * EMPTY_SCRIPT_SIG_WEIGHT);

			let package_fee = total_input_amount
				- anchor_psbt.unsigned_tx.output.iter().map(|output| output.value).sum();
			let package_weight = unsigned_tx_weight + 2 /* wit marker */ + total_satisfaction_weight + commitment_tx.weight().to_wu();
			if package_fee.to_sat() * 1000 / package_weight
				< package_target_feerate_sat_per_1000_weight.into()
			{
				// On the first iteration of the loop, we may undershoot the target feerate because
				// we had to add an OP_RETURN output in `process_coin_selection` which we didn't
				// select sufficient coins for. Here we detect that case and go around again
				// seeking additional weight.
				if package_and_fixed_input_satisfaction_weight
					== starting_package_and_fixed_input_satisfaction_weight
				{
					debug_assert!(
						anchor_psbt.unsigned_tx.output[0].script_pubkey.is_op_return(),
						"Coin selection failed to select sufficient coins for its change output"
					);
					package_and_fixed_input_satisfaction_weight +=
						anchor_psbt.unsigned_tx.output[0].weight().to_wu();
					continue;
				} else {
					debug_assert!(false, "Coin selection failed to select sufficient coins");
				}
			}

			log_debug!(self.logger, "Signing anchor transaction {}", anchor_txid);
			anchor_tx = self.utxo_source.sign_psbt(anchor_psbt).await?;

			// No need to produce any witness to spend P2A anchors
			if channel_type.supports_anchors_zero_fee_htlc_tx() {
				let signer = self
					.signer_provider
					.derive_channel_signer(anchor_descriptor.channel_derivation_parameters.keys_id);
				let channel_parameters =
					&anchor_descriptor.channel_derivation_parameters.transaction_parameters;
				let anchor_sig = signer.sign_holder_keyed_anchor_input(
					channel_parameters,
					&anchor_tx,
					0,
					&self.secp,
				)?;
				anchor_tx.input[0].witness = anchor_descriptor.tx_input_witness(&anchor_sig);
			}

			#[cfg(debug_assertions)]
			{
				let signed_tx_weight = anchor_tx.weight().to_wu();
				let expected_signed_tx_weight =
					unsigned_tx_weight + 2 /* wit marker */ + total_satisfaction_weight;
				// Our estimate should be within a 1% error margin of the actual weight and we should
				// never underestimate.
				assert!(expected_signed_tx_weight >= signed_tx_weight);
				assert!(expected_signed_tx_weight * 99 / 100 <= signed_tx_weight);

				let expected_package_fee = Amount::from_sat(fee_for_weight(
					package_target_feerate_sat_per_1000_weight,
					signed_tx_weight + commitment_tx.weight().to_wu(),
				));
				// Our feerate should always be at least what we were seeking. It may overshoot if
				// the coin selector burned funds to an OP_RETURN without a change output.
				assert!(package_fee >= expected_package_fee);
			}

			#[cfg(debug_assertions)]
			if channel_type.supports_anchor_zero_fee_commitments() {
				assert!(commitment_tx.weight().to_wu() < TRUC_MAX_WEIGHT);
				assert!(anchor_tx.weight().to_wu() < TRUC_CHILD_MAX_WEIGHT);
			} else {
				assert!(commitment_tx.weight().to_wu() < MAX_STANDARD_TX_WEIGHT as u64);
				assert!(anchor_tx.weight().to_wu() < MAX_STANDARD_TX_WEIGHT as u64);
			}

			log_info!(
				self.logger,
				"Broadcasting anchor transaction {} to bump channel close with txid {}",
				anchor_txid,
				commitment_tx.compute_txid()
			);
			self.broadcaster.broadcast_transactions(&[&commitment_tx, &anchor_tx]);
			return Ok(());
		}
	}

	/// Handles a [`BumpTransactionEvent::HTLCResolution`] event variant by producing a
	/// fully-signed, fee-bumped HTLC transaction that is broadcast to the network.
	async fn handle_htlc_resolution(
		&self, claim_id: ClaimId, target_feerate_sat_per_1000_weight: u32,
		htlc_descriptors: &[HTLCDescriptor], tx_lock_time: LockTime,
	) -> Result<(), ()> {
		let channel_type = &htlc_descriptors[0]
			.channel_derivation_parameters
			.transaction_parameters
			.channel_type_features;
		let (htlc_success_witness_weight, htlc_timeout_witness_weight) =
			if channel_type.supports_anchor_zero_fee_commitments() {
				(
					HTLC_SUCCESS_INPUT_P2A_ANCHOR_WITNESS_WEIGHT,
					HTLC_TIMEOUT_INPUT_P2A_ANCHOR_WITNESS_WEIGHT,
				)
			} else if channel_type.supports_anchors_zero_fee_htlc_tx() {
				(
					HTLC_SUCCESS_INPUT_KEYED_ANCHOR_WITNESS_WEIGHT,
					HTLC_TIMEOUT_INPUT_KEYED_ANCHOR_WITNESS_WEIGHT,
				)
			} else {
				panic!("channel type should be either zero-fee HTLCs, or zero-fee commitments");
			};

		let max_tx_weight = if channel_type.supports_anchor_zero_fee_commitments() {
			// Cap the size of transactions claiming `HolderHTLCOutput` in 0FC channels.
			// Otherwise, we could hit the max 10_000vB size limit on V3 transactions
			// (BIP 431 rule 4).
			TRUC_MAX_WEIGHT
		} else {
			// We should never hit this because HTLC-timeout transactions have a signed
			// locktime, HTLC-success transactions do not, and we never aggregate
			// packages with a signed locktime with packages that do not have a signed
			// locktime.
			// Hence in the worst case, we aggregate 483 success HTLC transactions,
			// and 483 * 705 ~= 341_000, and 341_000 < 400_000.
			MAX_STANDARD_TX_WEIGHT as u64
		};
		// A 1-input 1-output transaction, both p2wpkh is 438 WU.
		// This is just an initial budget, we increase it further below in case the user can't satisfy it.
		const USER_COINS_WEIGHT_BUDGET: u64 = 1000;

		let mut broadcasted_htlcs = 0;
		let mut batch_size = htlc_descriptors.len() - broadcasted_htlcs;
		let mut utxo_id = claim_id;

		while broadcasted_htlcs < htlc_descriptors.len() {
			let mut htlc_tx = Transaction {
				version: if channel_type.supports_anchor_zero_fee_commitments() {
					Version::non_standard(3)
				} else {
					Version::TWO
				},
				lock_time: tx_lock_time,
				input: vec![],
				output: vec![],
			};
			let mut must_spend = Vec::with_capacity(htlc_descriptors.len() - broadcasted_htlcs);
			let mut htlc_weight_sum = 0;
			for htlc_descriptor in
				&htlc_descriptors[broadcasted_htlcs..broadcasted_htlcs + batch_size]
			{
				let input_output_weight = if htlc_descriptor.preimage.is_some() {
					chan_utils::aggregated_htlc_success_input_output_pair_weight(channel_type)
				} else {
					chan_utils::aggregated_htlc_timeout_input_output_pair_weight(channel_type)
				};
				if htlc_weight_sum + input_output_weight >= max_tx_weight - USER_COINS_WEIGHT_BUDGET
				{
					break;
				}
				htlc_weight_sum += input_output_weight;
				let htlc_input = htlc_descriptor.unsigned_tx_input();
				must_spend.push(Input {
					outpoint: htlc_input.previous_output.clone(),
					previous_utxo: htlc_descriptor.previous_utxo(&self.secp),
					satisfaction_weight: EMPTY_SCRIPT_SIG_WEIGHT
						+ if htlc_descriptor.preimage.is_some() {
							htlc_success_witness_weight
						} else {
							htlc_timeout_witness_weight
						},
				});
				htlc_tx.input.push(htlc_input);
				let htlc_output = htlc_descriptor.tx_output(&self.secp);
				htlc_tx.output.push(htlc_output);
			}
			batch_size = htlc_tx.input.len();
			let selected_htlcs =
				&htlc_descriptors[broadcasted_htlcs..broadcasted_htlcs + batch_size];

			log_info!(
				self.logger,
				"Batch transaction assigned to UTXO id {} contains {} HTLCs: {}",
				log_bytes!(utxo_id.0),
				batch_size,
				log_iter!(selected_htlcs.iter().map(|d| d.outpoint()))
			);

			log_debug!(
				self.logger,
				"Performing coin selection for HTLC transaction targeting {} sat/kW",
				target_feerate_sat_per_1000_weight
			);

			#[cfg(debug_assertions)]
			let must_spend_satisfaction_weight =
				must_spend.iter().map(|input| input.satisfaction_weight).sum::<u64>();
			#[cfg(debug_assertions)]
			let must_spend_amount =
				must_spend.iter().map(|input| input.previous_utxo.value.to_sat()).sum::<u64>();

			let coin_selection: CoinSelection = match self
				.utxo_source
				.select_confirmed_utxos(
					Some(utxo_id),
					must_spend,
					&htlc_tx.output,
					target_feerate_sat_per_1000_weight,
					max_tx_weight,
				)
				.await
			{
				Ok(selection) => selection,
				Err(()) => {
					let htlcs_to_remove = USER_COINS_WEIGHT_BUDGET.div_ceil(
						chan_utils::aggregated_htlc_timeout_input_output_pair_weight(channel_type),
					);
					batch_size = batch_size.checked_sub(htlcs_to_remove as usize).ok_or(())?;
					if batch_size == 0 {
						return Err(());
					}
					continue;
				},
			};
			broadcasted_htlcs += batch_size;
			batch_size = htlc_descriptors.len() - broadcasted_htlcs;
			utxo_id = claim_id.step_with_bytes(&broadcasted_htlcs.to_be_bytes());

			#[cfg(debug_assertions)]
			let input_satisfaction_weight = coin_selection.satisfaction_weight();
			#[cfg(debug_assertions)]
			let total_satisfaction_weight = must_spend_satisfaction_weight + input_satisfaction_weight;
			#[cfg(debug_assertions)]
			let input_value = coin_selection.input_amount().to_sat();
			#[cfg(debug_assertions)]
			let total_input_amount = must_spend_amount + input_value;

			self.process_coin_selection(&mut htlc_tx, &coin_selection);

			// construct psbt
			let mut htlc_psbt = Psbt::from_unsigned_tx(htlc_tx).unwrap();
			// add witness_utxo to htlc inputs
			for (i, htlc_descriptor) in selected_htlcs.iter().enumerate() {
				debug_assert_eq!(
					htlc_psbt.unsigned_tx.input[i].previous_output,
					htlc_descriptor.outpoint()
				);
				htlc_psbt.inputs[i].witness_utxo = Some(htlc_descriptor.previous_utxo(&self.secp));
			}

			// add witness_utxo to remaining inputs
			for (idx, utxo) in coin_selection.confirmed_utxos.into_iter().enumerate() {
				// offset to skip the htlc inputs
				let index = idx + selected_htlcs.len();
				debug_assert_eq!(
					htlc_psbt.unsigned_tx.input[index].previous_output,
					utxo.outpoint()
				);
				if utxo.output().script_pubkey.is_witness_program() {
					htlc_psbt.inputs[index].witness_utxo = Some(utxo.into_output());
				}
			}

			#[cfg(debug_assertions)]
			let unsigned_tx_weight = htlc_psbt.unsigned_tx.weight().to_wu()
				- (htlc_psbt.unsigned_tx.input.len() as u64 * EMPTY_SCRIPT_SIG_WEIGHT);

			log_debug!(
				self.logger,
				"Signing HTLC transaction {}",
				htlc_psbt.unsigned_tx.compute_txid()
			);
			htlc_tx = self.utxo_source.sign_psbt(htlc_psbt).await?;

			let mut signers = BTreeMap::new();
			for (idx, htlc_descriptor) in selected_htlcs.iter().enumerate() {
				let keys_id = htlc_descriptor.channel_derivation_parameters.keys_id;
				let signer = signers
					.entry(keys_id)
					.or_insert_with(|| self.signer_provider.derive_channel_signer(keys_id));
				let htlc_sig = signer.sign_holder_htlc_transaction(
					&htlc_tx,
					idx,
					htlc_descriptor,
					&self.secp,
				)?;
				let witness_script = htlc_descriptor.witness_script(&self.secp);
				htlc_tx.input[idx].witness =
					htlc_descriptor.tx_input_witness(&htlc_sig, &witness_script);
			}

			#[cfg(debug_assertions)]
			{
				let signed_tx_weight = htlc_tx.weight().to_wu();
				let expected_signed_tx_weight = unsigned_tx_weight + total_satisfaction_weight;
				// Our estimate should be within a 2% error margin of the actual weight and we should
				// never underestimate.
				assert!(expected_signed_tx_weight >= signed_tx_weight);
				assert!(expected_signed_tx_weight * 98 / 100 <= signed_tx_weight);

				let expected_signed_tx_fee =
					fee_for_weight(target_feerate_sat_per_1000_weight, signed_tx_weight);
				let signed_tx_fee = total_input_amount
					- htlc_tx.output.iter().map(|output| output.value.to_sat()).sum::<u64>();
				// Our feerate should always be at least what we were seeking. It may overshoot if
				// the coin selector burned funds to an OP_RETURN without a change output.
				assert!(signed_tx_fee >= expected_signed_tx_fee);
			}

			#[cfg(debug_assertions)]
			if channel_type.supports_anchor_zero_fee_commitments() {
				assert!(htlc_tx.weight().to_wu() < TRUC_MAX_WEIGHT);
			} else {
				assert!(htlc_tx.weight().to_wu() < MAX_STANDARD_TX_WEIGHT as u64);
			}

			log_info!(self.logger, "Broadcasting {}", log_tx!(htlc_tx));
			self.broadcaster.broadcast_transactions(&[&htlc_tx]);
		}

		Ok(())
	}

	/// Handles all variants of [`BumpTransactionEvent`].
	pub async fn handle_event(&self, event: &BumpTransactionEvent) {
		match event {
			BumpTransactionEvent::ChannelClose {
				claim_id,
				package_target_feerate_sat_per_1000_weight,
				commitment_tx,
				commitment_tx_fee_satoshis,
				anchor_descriptor,
				..
			} => {
				log_info!(
					self.logger,
					"Handling channel close bump (claim_id = {}, commitment_txid = {})",
					log_bytes!(claim_id.0),
					commitment_tx.compute_txid()
				);
				self.handle_channel_close(
					*claim_id,
					*package_target_feerate_sat_per_1000_weight,
					commitment_tx,
					*commitment_tx_fee_satoshis,
					anchor_descriptor,
				)
				.await
				.unwrap_or_else(|_| {
					log_error!(
						self.logger,
						"Failed bumping commitment transaction fee for {}",
						commitment_tx.compute_txid()
					);
				});
			},
			BumpTransactionEvent::HTLCResolution {
				claim_id,
				target_feerate_sat_per_1000_weight,
				htlc_descriptors,
				tx_lock_time,
				..
			} => {
				log_info!(
					self.logger,
					"Handling HTLC bump (claim_id = {}, htlcs_to_claim = {})",
					log_bytes!(claim_id.0),
					log_iter!(htlc_descriptors.iter().map(|d| d.outpoint()))
				);
				self.handle_htlc_resolution(
					*claim_id,
					*target_feerate_sat_per_1000_weight,
					htlc_descriptors,
					*tx_lock_time,
				)
				.await
				.unwrap_or_else(|_| {
					log_error!(
						self.logger,
						"Failed bumping HTLC transaction fee for commitment {}",
						htlc_descriptors[0].commitment_txid
					);
				});
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::events::bump_transaction::sync::{
		BumpTransactionEventHandlerSync, CoinSelectionSourceSync,
	};
	use crate::io::Cursor;
	use crate::ln::chan_utils::ChannelTransactionParameters;
	use crate::ln::channel::ANCHOR_OUTPUT_VALUE_SATOSHI;
	use crate::sign::KeysManager;
	use crate::sync::Mutex;
	use crate::types::features::ChannelTypeFeatures;
	use crate::util::ser::Readable;
	use crate::util::test_utils::{TestBroadcaster, TestLogger};
	use crate::util::wallet_utils::Utxo;

	use bitcoin::constants::WITNESS_SCALE_FACTOR;
	use bitcoin::hex::FromHex;
	use bitcoin::key::TweakedPublicKey;
	use bitcoin::{
		Network, ScriptBuf, Transaction, WitnessProgram, WitnessVersion, XOnlyPublicKey,
	};

	struct TestCoinSelectionSource {
		// (commitment + anchor value, commitment + input weight, target feerate, result)
		expected_selects: Mutex<Vec<(u64, u64, u32, CoinSelection)>>,
	}
	impl CoinSelectionSourceSync for TestCoinSelectionSource {
		fn select_confirmed_utxos(
			&self, _claim_id: Option<ClaimId>, must_spend: Vec<Input>, _must_pay_to: &[TxOut],
			target_feerate_sat_per_1000_weight: u32, _max_tx_weight: u64,
		) -> Result<CoinSelection, ()> {
			let mut expected_selects = self.expected_selects.lock().unwrap();
			let (weight, value, feerate, res) = expected_selects.remove(0);
			assert_eq!(must_spend.len(), 1);
			assert_eq!(must_spend[0].satisfaction_weight, weight);
			assert_eq!(must_spend[0].previous_utxo.value.to_sat(), value);
			assert_eq!(target_feerate_sat_per_1000_weight, feerate);
			Ok(res)
		}
		fn sign_psbt(&self, psbt: Psbt) -> Result<Transaction, ()> {
			let prevtx_ids: Vec<_> = self
				.expected_selects
				.lock()
				.unwrap()
				.iter()
				.flat_map(|selection| selection.3.confirmed_utxos.iter())
				.map(|utxo| utxo.prevtx.compute_txid())
				.collect();
			let mut tx = psbt.unsigned_tx;
			for input in tx.input.iter_mut() {
				if prevtx_ids.contains(&input.previous_output.txid) {
					// Channel output, add a realistic size witness to make the assertions happy
					input.witness = Witness::from_slice(&[vec![42; 162]]);
				}
			}
			Ok(tx)
		}
	}

	impl Drop for TestCoinSelectionSource {
		fn drop(&mut self) {
			assert!(self.expected_selects.lock().unwrap().is_empty());
		}
	}

	#[test]
	fn test_op_return_under_funds() {
		// Test what happens if we have to select coins but the anchor output value itself suffices
		// to pay the required fee.
		//
		// This tests a case that occurred on mainnet (with the below transaction) where the target
		// feerate (of 868 sat/kW) was met by the anchor output's 330 sats alone. This caused the
		// use of an OP_RETURN which created a transaction which, at the time, was less than 64
		// bytes long (the current code generates a 65 byte transaction instead to meet
		// standardness rule). It also tests the handling of selection failure where we selected
		// coins which were insufficient once the OP_RETURN output was added, causing us to need to
		// select coins again with additional weight.

		// Tx 18032ad172a5f28fa6e16392d6cc57ea47895781434ce15d03766cc47a955fb9
		let commitment_tx_bytes = Vec::<u8>::from_hex("02000000000101cc6b0a9dd84b52c07340fff6fab002fc37b4bdccfdce9f39c5ec8391a56b652907000000009b948b80044a01000000000000220020b4182433fdfdfbf894897c98f84d92cec815cee222755ffd000ae091c9dadc2d4a01000000000000220020f83f7dbf90e2de325b5bb6bab0ae370151278c6964739242b2e7ce0cb68a5d81cb4a02000000000022002024add256b3dccee772610caef82a601045ab6f98fd6d5df608cc756b891ccfe63ffa490000000000220020894bf32b37906a643625e87131897c3714c71b3ac9b161862c9aa6c8d468b4c70400473044022060abd347bff2cca0212b660e6addff792b3356bd4a1b5b26672dc2e694c3c5f002202b40b7e346b494a7b1d048b4ec33ba99c90a09ab48eb1df64ccdc768066c865c014730440220554d8361e04dc0ee178dcb23d2d23f53ec7a1ae4312a5be76bd9e83ab8981f3d0220501f23ffb18cb81ccea72d30252f88d5e69fd28ba4992803d03c00d06fa8899e0147522102817f6ce189ab7114f89e8d5df58cdbbaf272dc8e71b92982d47456a0b6a0ceee2102c9b4d2f24aca54f65e13f4c83e2a8d8e877e12d3c71a76e81f28a5cabc652aa352ae626c7620").unwrap();
		let commitment_tx: Transaction =
			Readable::read(&mut Cursor::new(&commitment_tx_bytes)).unwrap();
		let commitment_txid = commitment_tx.compute_txid();
		let total_commitment_weight =
			commitment_tx.weight().to_wu() + ANCHOR_INPUT_WITNESS_WEIGHT + EMPTY_SCRIPT_SIG_WEIGHT;
		let commitment_and_anchor_fee = 930 + 330;
		let op_return_weight =
			TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new_op_return(&[0; 3]) }
				.weight()
				.to_wu();

		let prevtx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![],
			output: vec![TxOut { value: Amount::from_sat(200), script_pubkey: ScriptBuf::new() }],
		};

		let broadcaster = TestBroadcaster::new(Network::Testnet);
		let source = TestCoinSelectionSource {
			expected_selects: Mutex::new(vec![
				(
					total_commitment_weight,
					commitment_and_anchor_fee,
					868,
					CoinSelection { confirmed_utxos: Vec::new(), change_output: None },
				),
				(
					total_commitment_weight + op_return_weight,
					commitment_and_anchor_fee,
					868,
					CoinSelection {
						confirmed_utxos: vec![ConfirmedUtxo {
							utxo: Utxo {
								outpoint: OutPoint { txid: prevtx.compute_txid(), vout: 0 },
								output: prevtx.output[0].clone(),
								satisfaction_weight: 5, // Just the script_sig and witness lengths
								sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
							},
							prevtx,
						}],
						change_output: None,
					},
				),
			]),
		};
		let signer = KeysManager::new(&[42; 32], 42, 42, true);
		let logger = TestLogger::new();
		let handler = BumpTransactionEventHandlerSync::new(&broadcaster, &source, &signer, &logger);

		let mut transaction_parameters = ChannelTransactionParameters::test_dummy(42_000_000);
		transaction_parameters.channel_type_features =
			ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();

		handler.handle_event(&BumpTransactionEvent::ChannelClose {
			channel_id: ChannelId([42; 32]),
			counterparty_node_id: PublicKey::from_slice(&[2; 33]).unwrap(),
			claim_id: ClaimId([42; 32]),
			package_target_feerate_sat_per_1000_weight: 868,
			commitment_tx_fee_satoshis: 930,
			commitment_tx,
			anchor_descriptor: AnchorDescriptor {
				channel_derivation_parameters: ChannelDerivationParameters {
					value_satoshis: 42_000_000,
					keys_id: [42; 32],
					transaction_parameters,
				},
				outpoint: OutPoint { txid: commitment_txid, vout: 0 },
				value: Amount::from_sat(ANCHOR_OUTPUT_VALUE_SATOSHI),
			},
			pending_htlcs: Vec::new(),
		});
	}

	#[test]
	fn test_utxo_new_v1_p2tr() {
		// Transaction 33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036
		let p2tr_tx: Transaction = bitcoin::consensus::deserialize(&<Vec<u8>>::from_hex("01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00").unwrap()).unwrap();

		let script_pubkey = &p2tr_tx.output[1].script_pubkey;
		assert_eq!(script_pubkey.witness_version(), Some(WitnessVersion::V1));
		let witness_bytes = &script_pubkey.as_bytes()[2..];
		let witness_program = WitnessProgram::new(WitnessVersion::V1, witness_bytes).unwrap();
		let tweaked_key = TweakedPublicKey::dangerous_assume_tweaked(
			XOnlyPublicKey::from_slice(&witness_program.program().as_bytes()).unwrap(),
		);

		let utxo = Utxo::new_v1_p2tr(
			OutPoint { txid: p2tr_tx.compute_txid(), vout: 1 },
			p2tr_tx.output[1].value,
			tweaked_key,
		);
		assert_eq!(utxo.output, p2tr_tx.output[1]);
		assert_eq!(
			utxo.satisfaction_weight,
			1 /* empty script_sig */ * WITNESS_SCALE_FACTOR as u64 +
			1 /* witness items */ + 1 /* schnorr sig len */ + 64 /* schnorr sig */
		);
	}
}
