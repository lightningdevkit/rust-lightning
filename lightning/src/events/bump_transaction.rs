// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utitilies for bumping transactions originating from [`super::Event`]s.

use crate::ln::PaymentPreimage;
use crate::ln::chan_utils;
use crate::ln::chan_utils::{ChannelTransactionParameters, HTLCOutputInCommitment};

use bitcoin::{OutPoint, PackedLockTime, Script, Transaction, Txid, TxIn, TxOut, Witness};
use bitcoin::secp256k1;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::secp256k1::ecdsa::Signature;

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
		/// The target feerate that the resulting HTLC transaction must meet.
		target_feerate_sat_per_1000_weight: u32,
		/// The set of pending HTLCs on the confirmed commitment that need to be claimed, preferably
		/// by the same transaction.
		htlc_descriptors: Vec<HTLCDescriptor>,
		/// The locktime required for the resulting HTLC transaction.
		tx_lock_time: PackedLockTime,
	},
}
