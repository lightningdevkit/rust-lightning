// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Provides keys to LDK and defines some useful objects describing spendable on-chain outputs.
//!
//! The provided output descriptors follow a custom LDK data format and are currently not fully
//! compatible with Bitcoin Core output descriptors.

use bitcoin::amount::Amount;
use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::network::Network;
use bitcoin::opcodes;
use bitcoin::script::{Builder, Script, ScriptBuf};
use bitcoin::sighash;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::transaction::Version;
use bitcoin::transaction::{Transaction, TxIn, TxOut};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::{Hash, HashEngine};

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::{Keypair, PublicKey, Scalar, Secp256k1, SecretKey, Signing};
use bitcoin::{secp256k1, Psbt, Sequence, Txid, WPubkeyHash, Witness};

use lightning_invoice::RawBolt11Invoice;

use crate::chain::transaction::OutPoint;
use crate::crypto::utils::{hkdf_extract_expand_twice, sign, sign_with_aux_rand};
use crate::ln::chan_utils;
use crate::ln::chan_utils::{
	get_revokeable_redeemscript, make_funding_redeemscript, ChannelPublicKeys,
	ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
	HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use crate::ln::channel::ANCHOR_OUTPUT_VALUE_SATOSHI;
use crate::ln::channel_keys::{
	add_public_key_tweak, DelayedPaymentBasepoint, DelayedPaymentKey, HtlcBasepoint, HtlcKey,
	RevocationBasepoint, RevocationKey,
};
use crate::ln::inbound_payment::ExpandedKey;
#[cfg(taproot)]
use crate::ln::msgs::PartialSignatureWithNonce;
use crate::ln::msgs::{UnsignedChannelAnnouncement, UnsignedGossipMessage};
use crate::ln::script::ShutdownScript;
use crate::offers::invoice::UnsignedBolt12Invoice;
use crate::types::payment::PaymentPreimage;
use crate::util::async_poll::AsyncResult;
use crate::util::ser::{ReadableArgs, Writeable};
use crate::util::transaction_utils;

use crate::crypto::chacha20::ChaCha20;
use crate::prelude::*;
use crate::sign::ecdsa::EcdsaChannelSigner;
#[cfg(taproot)]
use crate::sign::taproot::TaprootChannelSigner;
use crate::util::atomic_counter::AtomicCounter;
use core::convert::TryInto;
use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(taproot)]
use musig2::types::{PartialSignature, PublicNonce};

pub(crate) mod type_resolver;

pub mod ecdsa;
#[cfg(taproot)]
pub mod taproot;
pub mod tx_builder;

/// Information about a spendable output to a P2WSH script.
///
/// See [`SpendableOutputDescriptor::DelayedPaymentOutput`] for more details on how to spend this.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DelayedPaymentOutputDescriptor {
	/// The outpoint which is spendable.
	pub outpoint: OutPoint,
	/// Per commitment point to derive the delayed payment key by key holder.
	pub per_commitment_point: PublicKey,
	/// The `nSequence` value which must be set in the spending input to satisfy the `OP_CSV` in
	/// the witness_script.
	pub to_self_delay: u16,
	/// The output which is referenced by the given outpoint.
	pub output: TxOut,
	/// The revocation point specific to the commitment transaction which was broadcast. Used to
	/// derive the witnessScript for this output.
	pub revocation_pubkey: RevocationKey,
	/// Arbitrary identification information returned by a call to [`ChannelSigner::channel_keys_id`].
	/// This may be useful in re-deriving keys used in the channel to spend the output.
	pub channel_keys_id: [u8; 32],
	/// The value of the channel which this output originated from, possibly indirectly.
	pub channel_value_satoshis: u64,
	/// The channel public keys and other parameters needed to generate a spending transaction or
	/// to provide to a signer.
	///
	/// Added as optional, but always `Some` if the descriptor was produced in v0.0.123 or later.
	pub channel_transaction_parameters: Option<ChannelTransactionParameters>,
}

impl DelayedPaymentOutputDescriptor {
	/// The maximum length a well-formed witness spending one of these should have.
	/// Note: If you have the grind_signatures feature enabled, this will be at least 1 byte
	/// shorter.
	// Calculated as 1 byte length + 73 byte signature, 1 byte empty vec push, 1 byte length plus
	// redeemscript push length.
	pub const MAX_WITNESS_LENGTH: u64 =
		1 + 73 + 1 + chan_utils::REVOKEABLE_REDEEMSCRIPT_MAX_LENGTH as u64 + 1;
}

impl_writeable_tlv_based!(DelayedPaymentOutputDescriptor, {
	(0, outpoint, required),
	(2, per_commitment_point, required),
	(4, to_self_delay, required),
	(6, output, required),
	(8, revocation_pubkey, required),
	(10, channel_keys_id, required),
	(12, channel_value_satoshis, required),
	(13, channel_transaction_parameters, (option: ReadableArgs, Some(channel_value_satoshis.0.unwrap()))),
});

pub(crate) const P2WPKH_WITNESS_WEIGHT: u64 = 1 /* num stack items */ +
	1 /* sig length */ +
	73 /* sig including sighash flag */ +
	1 /* pubkey length */ +
	33 /* pubkey */;

/// Witness weight for satisying a P2TR key-path spend.
pub(crate) const P2TR_KEY_PATH_WITNESS_WEIGHT: u64 = 1 /* witness items */
	+ 1 /* schnorr sig len */ + 64 /* schnorr sig */;

/// Information about a spendable output to our "payment key".
///
/// See [`SpendableOutputDescriptor::StaticPaymentOutput`] for more details on how to spend this.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct StaticPaymentOutputDescriptor {
	/// The outpoint which is spendable.
	pub outpoint: OutPoint,
	/// The output which is referenced by the given outpoint.
	pub output: TxOut,
	/// Arbitrary identification information returned by a call to [`ChannelSigner::channel_keys_id`].
	/// This may be useful in re-deriving keys used in the channel to spend the output.
	pub channel_keys_id: [u8; 32],
	/// The value of the channel which this transactions spends.
	pub channel_value_satoshis: u64,
	/// The necessary channel parameters that need to be provided to the signer.
	///
	/// Added as optional, but always `Some` if the descriptor was produced in v0.0.117 or later.
	pub channel_transaction_parameters: Option<ChannelTransactionParameters>,
}

impl StaticPaymentOutputDescriptor {
	/// Returns the `witness_script` of the spendable output.
	///
	/// Note that this will only return `Some` for [`StaticPaymentOutputDescriptor`]s that
	/// originated from an anchor outputs channel, as they take the form of a P2WSH script.
	pub fn witness_script(&self) -> Option<ScriptBuf> {
		self.channel_transaction_parameters.as_ref().and_then(|channel_params| {
			if channel_params.channel_type_features.supports_anchors_zero_fee_htlc_tx() {
				let payment_point = channel_params.holder_pubkeys.payment_point;
				Some(chan_utils::get_to_countersigner_keyed_anchor_redeemscript(&payment_point))
			} else {
				None
			}
		})
	}

	/// The maximum length a well-formed witness spending one of these should have.
	/// Note: If you have the grind_signatures feature enabled, this will be at least 1 byte
	/// shorter.
	pub fn max_witness_length(&self) -> u64 {
		if self.needs_csv_1_for_spend() {
			let witness_script_weight = 1 /* pubkey push */ + 33 /* pubkey */ +
				1 /* OP_CHECKSIGVERIFY */ + 1 /* OP_1 */ + 1 /* OP_CHECKSEQUENCEVERIFY */;
			1 /* num witness items */ + 1 /* sig push */ + 73 /* sig including sighash flag */ +
				1 /* witness script push */ + witness_script_weight
		} else {
			P2WPKH_WITNESS_WEIGHT
		}
	}

	/// Returns true if spending this output requires a transaction with a CheckSequenceVerify
	/// value of at least 1.
	pub fn needs_csv_1_for_spend(&self) -> bool {
		let chan_params = self.channel_transaction_parameters.as_ref();
		chan_params.map_or(false, |p| p.channel_type_features.supports_anchors_zero_fee_htlc_tx())
	}
}
impl_writeable_tlv_based!(StaticPaymentOutputDescriptor, {
	(0, outpoint, required),
	(2, output, required),
	(4, channel_keys_id, required),
	(6, channel_value_satoshis, required),
	(7, channel_transaction_parameters, (option: ReadableArgs, Some(channel_value_satoshis.0.unwrap()))),
});

/// Describes the necessary information to spend a spendable output.
///
/// When on-chain outputs are created by LDK (which our counterparty is not able to claim at any
/// point in the future) a [`SpendableOutputs`] event is generated which you must track and be able
/// to spend on-chain. The information needed to do this is provided in this enum, including the
/// outpoint describing which `txid` and output `index` is available, the full output which exists
/// at that `txid`/`index`, and any keys or other information required to sign.
///
/// [`SpendableOutputs`]: crate::events::Event::SpendableOutputs
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum SpendableOutputDescriptor {
	/// An output to a script which was provided via [`SignerProvider`] directly, either from
	/// [`get_destination_script`] or [`get_shutdown_scriptpubkey`], thus you should already
	/// know how to spend it. No secret keys are provided as LDK was never given any key.
	/// These may include outputs from a transaction punishing our counterparty or claiming an HTLC
	/// on-chain using the payment preimage or after it has timed out.
	///
	/// [`get_shutdown_scriptpubkey`]: SignerProvider::get_shutdown_scriptpubkey
	/// [`get_destination_script`]: SignerProvider::get_shutdown_scriptpubkey
	StaticOutput {
		/// The outpoint which is spendable.
		outpoint: OutPoint,
		/// The output which is referenced by the given outpoint.
		output: TxOut,
		/// The `channel_keys_id` for the channel which this output came from.
		///
		/// For channels which were generated on LDK 0.0.119 or later, this is the value which was
		/// passed to the [`SignerProvider::get_destination_script`] call which provided this
		/// output script.
		///
		/// For channels which were generated prior to LDK 0.0.119, no such argument existed,
		/// however this field may still be filled in if such data is available.
		channel_keys_id: Option<[u8; 32]>,
	},
	/// An output to a P2WSH script which can be spent with a single signature after an `OP_CSV`
	/// delay.
	///
	/// The witness in the spending input should be:
	/// ```bitcoin
	/// <BIP 143 signature> <empty vector> (MINIMALIF standard rule) <provided witnessScript>
	/// ```
	///
	/// Note that the `nSequence` field in the spending input must be set to
	/// [`DelayedPaymentOutputDescriptor::to_self_delay`] (which means the transaction is not
	/// broadcastable until at least [`DelayedPaymentOutputDescriptor::to_self_delay`] blocks after
	/// the outpoint confirms, see [BIP
	/// 68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki)). Also note that LDK
	/// won't generate a [`SpendableOutputDescriptor`] until the corresponding block height
	/// is reached.
	///
	/// These are generally the result of a "revocable" output to us, spendable only by us unless
	/// it is an output from an old state which we broadcast (which should never happen).
	///
	/// To derive the delayed payment key which is used to sign this input, you must pass the
	/// holder [`InMemorySigner::delayed_payment_base_key`] (i.e., the private key which corresponds to the
	/// [`ChannelPublicKeys::delayed_payment_basepoint`] in [`ChannelSigner::pubkeys`]) and the provided
	/// [`DelayedPaymentOutputDescriptor::per_commitment_point`] to [`chan_utils::derive_private_key`]. The DelayedPaymentKey can be
	/// generated without the secret key using [`DelayedPaymentKey::from_basepoint`] and only the
	/// [`ChannelPublicKeys::delayed_payment_basepoint`] which appears in [`ChannelSigner::pubkeys`].
	///
	/// To derive the [`DelayedPaymentOutputDescriptor::revocation_pubkey`] provided here (which is
	/// used in the witness script generation), you must pass the counterparty
	/// [`ChannelPublicKeys::revocation_basepoint`] and the provided
	/// [`DelayedPaymentOutputDescriptor::per_commitment_point`] to
	/// [`RevocationKey`].
	///
	/// The witness script which is hashed and included in the output `script_pubkey` may be
	/// regenerated by passing the [`DelayedPaymentOutputDescriptor::revocation_pubkey`] (derived
	/// as explained above), our delayed payment pubkey (derived as explained above), and the
	/// [`DelayedPaymentOutputDescriptor::to_self_delay`] contained here to
	/// [`chan_utils::get_revokeable_redeemscript`].
	DelayedPaymentOutput(DelayedPaymentOutputDescriptor),
	/// An output spendable exclusively by our payment key (i.e., the private key that corresponds
	/// to the `payment_point` in [`ChannelSigner::pubkeys`]). The output type depends on the
	/// channel type negotiated.
	///
	/// On an anchor outputs channel, the witness in the spending input is:
	/// ```bitcoin
	/// <BIP 143 signature> <witness script>
	/// ```
	///
	/// Otherwise, it is:
	/// ```bitcoin
	/// <BIP 143 signature> <payment key>
	/// ```
	///
	/// These are generally the result of our counterparty having broadcast the current state,
	/// allowing us to claim the non-HTLC-encumbered outputs immediately, or after one confirmation
	/// in the case of anchor outputs channels.
	StaticPaymentOutput(StaticPaymentOutputDescriptor),
}

impl_writeable_tlv_based_enum_legacy!(SpendableOutputDescriptor,
	(0, StaticOutput) => {
		(0, outpoint, required),
		(1, channel_keys_id, option),
		(2, output, required),
	},
;
	(1, DelayedPaymentOutput),
	(2, StaticPaymentOutput),
);

impl SpendableOutputDescriptor {
	/// Turns this into a [`bitcoin::psbt::Input`] which can be used to create a
	/// [`Psbt`] which spends the given descriptor.
	///
	/// Note that this does not include any signatures, just the information required to
	/// construct the transaction and sign it.
	///
	/// This is not exported to bindings users as there is no standard serialization for an input.
	/// See [`Self::create_spendable_outputs_psbt`] instead.
	///
	/// The proprietary field is used to store add tweak for the signing key of this transaction.
	/// See the [`DelayedPaymentBasepoint::derive_add_tweak`] docs for more info on add tweak and how to use it.
	///
	/// To get the proprietary field use:
	/// ```
	/// use bitcoin::psbt::{Psbt};
	/// use bitcoin::hex::FromHex;
	///
	/// # let s = "70736274ff0100520200000001dee978529ab3e61a2987bea5183713d0e6d5ceb5ac81100fdb54a1a2\
	///	# 		 69cef505000000000090000000011f26000000000000160014abb3ab63280d4ccc5c11d6b50fd427a8\
	///	# 		 e19d6470000000000001012b10270000000000002200200afe4736760d814a2651bae63b572d935d9a\
	/// # 		 b74a1a16c01774e341a32afa763601054d63210394a27a700617f5b7aee72bd4f8076b5770a582b7fb\
	///	# 		 d1d4ee2ea3802cd3cfbe2067029000b27521034629b1c8fdebfaeb58a74cd181f485e2c462e594cb30\
	///	# 		 34dee655875f69f6c7c968ac20fc144c444b5f7370656e6461626c655f6f7574707574006164645f74\
	///	# 		 7765616b20a86534f38ad61dc580ef41c3886204adf0911b81619c1ad7a2f5b5de39a2ba600000";
	/// # let psbt = Psbt::deserialize(<Vec<u8> as FromHex>::from_hex(s).unwrap().as_slice()).unwrap();
	/// let key = bitcoin::psbt::raw::ProprietaryKey {
	/// 	prefix: "LDK_spendable_output".as_bytes().to_vec(),
	/// 	subtype: 0,
	/// 	key: "add_tweak".as_bytes().to_vec(),
	/// };
	/// let value = psbt
	/// 	.inputs
	/// 	.first()
	/// 	.expect("Unable to get add tweak as there are no inputs")
	/// 	.proprietary
	/// 	.get(&key)
	/// 	.map(|x| x.to_owned());
	/// ```
	pub fn to_psbt_input<T: secp256k1::Signing>(
		&self, secp_ctx: &Secp256k1<T>,
	) -> bitcoin::psbt::Input {
		match self {
			SpendableOutputDescriptor::StaticOutput { output, .. } => {
				// Is a standard P2WPKH, no need for witness script
				bitcoin::psbt::Input { witness_utxo: Some(output.clone()), ..Default::default() }
			},
			SpendableOutputDescriptor::DelayedPaymentOutput(DelayedPaymentOutputDescriptor {
				channel_transaction_parameters,
				per_commitment_point,
				revocation_pubkey,
				to_self_delay,
				output,
				..
			}) => {
				let delayed_payment_basepoint = channel_transaction_parameters
					.as_ref()
					.map(|params| params.holder_pubkeys.delayed_payment_basepoint);

				let (witness_script, add_tweak) =
					if let Some(basepoint) = delayed_payment_basepoint.as_ref() {
						// Required to derive signing key: privkey = basepoint_secret + SHA256(per_commitment_point || basepoint)
						let add_tweak = basepoint.derive_add_tweak(&per_commitment_point);
						let payment_key = DelayedPaymentKey(add_public_key_tweak(
							secp_ctx,
							&basepoint.to_public_key(),
							&add_tweak,
						));

						(
							Some(get_revokeable_redeemscript(
								&revocation_pubkey,
								*to_self_delay,
								&payment_key,
							)),
							Some(add_tweak),
						)
					} else {
						(None, None)
					};

				bitcoin::psbt::Input {
					witness_utxo: Some(output.clone()),
					witness_script,
					proprietary: add_tweak
						.map(|add_tweak| {
							[(
								bitcoin::psbt::raw::ProprietaryKey {
									// A non standard namespace for spendable outputs, used to store the tweak needed
									// to derive the private key
									prefix: "LDK_spendable_output".as_bytes().to_vec(),
									subtype: 0,
									key: "add_tweak".as_bytes().to_vec(),
								},
								add_tweak.as_byte_array().to_vec(),
							)]
							.into_iter()
							.collect()
						})
						.unwrap_or_default(),
					..Default::default()
				}
			},
			SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => bitcoin::psbt::Input {
				witness_utxo: Some(descriptor.output.clone()),
				witness_script: descriptor.witness_script(),
				..Default::default()
			},
		}
	}

	/// Creates an unsigned [`Psbt`] which spends the given descriptors to
	/// the given outputs, plus an output to the given change destination (if sufficient
	/// change value remains). The PSBT will have a feerate, at least, of the given value.
	///
	/// The `locktime` argument is used to set the transaction's locktime. If `None`, the
	/// transaction will have a locktime of 0. It it recommended to set this to the current block
	/// height to avoid fee sniping, unless you have some specific reason to use a different
	/// locktime.
	///
	/// Returns the PSBT and expected max transaction weight.
	///
	/// Returns `Err(())` if the output value is greater than the input value minus required fee,
	/// if a descriptor was duplicated, or if an output descriptor `script_pubkey`
	/// does not match the one we can spend.
	///
	/// We do not enforce that outputs meet the dust limit or that any output scripts are standard.
	pub fn create_spendable_outputs_psbt<T: secp256k1::Signing>(
		secp_ctx: &Secp256k1<T>, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
		locktime: Option<LockTime>,
	) -> Result<(Psbt, u64), ()> {
		let mut input = Vec::with_capacity(descriptors.len());
		let mut input_value = Amount::ZERO;
		let mut witness_weight = 0;
		let mut output_set = hash_set_with_capacity(descriptors.len());
		for outp in descriptors {
			match outp {
				SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
					if !output_set.insert(descriptor.outpoint) {
						return Err(());
					}
					let sequence = if descriptor.needs_csv_1_for_spend() {
						Sequence::from_consensus(1)
					} else {
						Sequence::ZERO
					};
					input.push(TxIn {
						previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
						script_sig: ScriptBuf::new(),
						sequence,
						witness: Witness::new(),
					});
					witness_weight += descriptor.max_witness_length();
					#[cfg(feature = "grind_signatures")]
					{
						// Guarantees a low R signature
						witness_weight -= 1;
					}
					input_value += descriptor.output.value;
				},
				SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
					if !output_set.insert(descriptor.outpoint) {
						return Err(());
					}
					input.push(TxIn {
						previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
						script_sig: ScriptBuf::new(),
						sequence: Sequence(descriptor.to_self_delay as u32),
						witness: Witness::new(),
					});
					witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
					#[cfg(feature = "grind_signatures")]
					{
						// Guarantees a low R signature
						witness_weight -= 1;
					}
					input_value += descriptor.output.value;
				},
				SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output, .. } => {
					if !output_set.insert(*outpoint) {
						return Err(());
					}
					input.push(TxIn {
						previous_output: outpoint.into_bitcoin_outpoint(),
						script_sig: ScriptBuf::new(),
						sequence: Sequence::ZERO,
						witness: Witness::new(),
					});
					witness_weight += 1 + 73 + 34;
					#[cfg(feature = "grind_signatures")]
					{
						// Guarantees a low R signature
						witness_weight -= 1;
					}
					input_value += output.value;
				},
			}
			if input_value > Amount::MAX_MONEY {
				return Err(());
			}
		}
		let mut tx = Transaction {
			version: Version::TWO,
			lock_time: locktime.unwrap_or(LockTime::ZERO),
			input,
			output: outputs,
		};
		let expected_max_weight = transaction_utils::maybe_add_change_output(
			&mut tx,
			input_value,
			witness_weight,
			feerate_sat_per_1000_weight,
			change_destination_script,
		)?;

		let psbt_inputs =
			descriptors.iter().map(|d| d.to_psbt_input(&secp_ctx)).collect::<Vec<_>>();
		let psbt = Psbt {
			inputs: psbt_inputs,
			outputs: vec![Default::default(); tx.output.len()],
			unsigned_tx: tx,
			xpub: Default::default(),
			version: 0,
			proprietary: Default::default(),
			unknown: Default::default(),
		};
		Ok((psbt, expected_max_weight))
	}

	/// Returns the outpoint of the spendable output.
	pub fn spendable_outpoint(&self) -> OutPoint {
		match self {
			Self::StaticOutput { outpoint, .. } => *outpoint,
			Self::StaticPaymentOutput(descriptor) => descriptor.outpoint,
			Self::DelayedPaymentOutput(descriptor) => descriptor.outpoint,
		}
	}
}

/// The parameters required to derive a channel signer via [`SignerProvider`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelDerivationParameters {
	/// The value in satoshis of the channel we're attempting to spend the anchor output of.
	pub value_satoshis: u64,
	/// The unique identifier to re-derive the signer for the associated channel.
	pub keys_id: [u8; 32],
	/// The necessary channel parameters that need to be provided to the signer.
	pub transaction_parameters: ChannelTransactionParameters,
}

impl_writeable_tlv_based!(ChannelDerivationParameters, {
	(0, value_satoshis, required),
	(2, keys_id, required),
	(4, transaction_parameters, (required: ReadableArgs, Some(value_satoshis.0.unwrap()))),
});

/// A descriptor used to sign for a commitment transaction's HTLC output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HTLCDescriptor {
	/// The parameters required to derive the signer for the HTLC input.
	pub channel_derivation_parameters: ChannelDerivationParameters,
	/// The txid of the commitment transaction in which the HTLC output lives.
	pub commitment_txid: Txid,
	/// The number of the commitment transaction in which the HTLC output lives.
	pub per_commitment_number: u64,
	/// The key tweak corresponding to the number of the commitment transaction in which the HTLC
	/// output lives. This tweak is applied to all the basepoints for both parties in the channel to
	/// arrive at unique keys per commitment.
	///
	/// See <https://github.com/lightning/bolts/blob/master/03-transactions.md#keys> for more info.
	pub per_commitment_point: PublicKey,
	/// The feerate to use on the HTLC claiming transaction. This is always `0` for HTLCs
	/// originating from a channel supporting anchor outputs, otherwise it is the channel's
	/// negotiated feerate at the time the commitment transaction was built.
	pub feerate_per_kw: u32,
	/// The details of the HTLC as it appears in the commitment transaction.
	pub htlc: HTLCOutputInCommitment,
	/// The preimage, if `Some`, to claim the HTLC output with. If `None`, the timeout path must be
	/// taken.
	pub preimage: Option<PaymentPreimage>,
	/// The counterparty's signature required to spend the HTLC output.
	pub counterparty_sig: Signature,
}

impl_writeable_tlv_based!(HTLCDescriptor, {
	(0, channel_derivation_parameters, required),
	(1, feerate_per_kw, (default_value, 0)),
	(2, commitment_txid, required),
	(4, per_commitment_number, required),
	(6, per_commitment_point, required),
	(8, htlc, required),
	(10, preimage, option),
	(12, counterparty_sig, required),
});

impl HTLCDescriptor {
	/// Returns the outpoint of the HTLC output in the commitment transaction. This is the outpoint
	/// being spent by the HTLC input in the HTLC transaction.
	pub fn outpoint(&self) -> bitcoin::OutPoint {
		bitcoin::OutPoint {
			txid: self.commitment_txid,
			vout: self.htlc.transaction_output_index.unwrap(),
		}
	}

	/// Returns the UTXO to be spent by the HTLC input, which can be obtained via
	/// [`Self::unsigned_tx_input`].
	pub fn previous_utxo<C: secp256k1::Signing + secp256k1::Verification>(
		&self, secp: &Secp256k1<C>,
	) -> TxOut {
		TxOut {
			script_pubkey: self.witness_script(secp).to_p2wsh(),
			value: self.htlc.to_bitcoin_amount(),
		}
	}

	/// Returns the unsigned transaction input spending the HTLC output in the commitment
	/// transaction.
	pub fn unsigned_tx_input(&self) -> TxIn {
		chan_utils::build_htlc_input(
			&self.commitment_txid,
			&self.htlc,
			&self.channel_derivation_parameters.transaction_parameters.channel_type_features,
		)
	}

	/// Returns the delayed output created as a result of spending the HTLC output in the commitment
	/// transaction.
	pub fn tx_output<C: secp256k1::Signing + secp256k1::Verification>(
		&self, secp: &Secp256k1<C>,
	) -> TxOut {
		let channel_params =
			self.channel_derivation_parameters.transaction_parameters.as_holder_broadcastable();
		let broadcaster_keys = channel_params.broadcaster_pubkeys();
		let counterparty_keys = channel_params.countersignatory_pubkeys();
		let broadcaster_delayed_key = DelayedPaymentKey::from_basepoint(
			secp,
			&broadcaster_keys.delayed_payment_basepoint,
			&self.per_commitment_point,
		);
		let counterparty_revocation_key = &RevocationKey::from_basepoint(
			&secp,
			&counterparty_keys.revocation_basepoint,
			&self.per_commitment_point,
		);
		chan_utils::build_htlc_output(
			self.feerate_per_kw,
			channel_params.contest_delay(),
			&self.htlc,
			channel_params.channel_type_features(),
			&broadcaster_delayed_key,
			&counterparty_revocation_key,
		)
	}

	/// Returns the witness script of the HTLC output in the commitment transaction.
	pub fn witness_script<C: secp256k1::Signing + secp256k1::Verification>(
		&self, secp: &Secp256k1<C>,
	) -> ScriptBuf {
		let channel_params =
			self.channel_derivation_parameters.transaction_parameters.as_holder_broadcastable();
		let broadcaster_keys = channel_params.broadcaster_pubkeys();
		let counterparty_keys = channel_params.countersignatory_pubkeys();
		let broadcaster_htlc_key = HtlcKey::from_basepoint(
			secp,
			&broadcaster_keys.htlc_basepoint,
			&self.per_commitment_point,
		);
		let counterparty_htlc_key = HtlcKey::from_basepoint(
			secp,
			&counterparty_keys.htlc_basepoint,
			&self.per_commitment_point,
		);
		let counterparty_revocation_key = &RevocationKey::from_basepoint(
			&secp,
			&counterparty_keys.revocation_basepoint,
			&self.per_commitment_point,
		);
		chan_utils::get_htlc_redeemscript_with_explicit_keys(
			&self.htlc,
			channel_params.channel_type_features(),
			&broadcaster_htlc_key,
			&counterparty_htlc_key,
			&counterparty_revocation_key,
		)
	}

	/// Returns the fully signed witness required to spend the HTLC output in the commitment
	/// transaction.
	pub fn tx_input_witness(&self, signature: &Signature, witness_script: &Script) -> Witness {
		chan_utils::build_htlc_input_witness(
			signature,
			&self.counterparty_sig,
			&self.preimage,
			witness_script,
			&self.channel_derivation_parameters.transaction_parameters.channel_type_features,
		)
	}
}

/// A trait to handle Lightning channel key material without concretizing the channel type or
/// the signature mechanism.
///
/// Several methods allow errors to be returned to support async signing. In such cases, the
/// signing operation can be replayed by calling [`ChannelManager::signer_unblocked`] once the
/// result is ready, at which point the channel operation will resume. Methods which allow for
/// async results are explicitly documented as such
///
/// [`ChannelManager::signer_unblocked`]: crate::ln::channelmanager::ChannelManager::signer_unblocked
pub trait ChannelSigner {
	/// Gets the per-commitment point for a specific commitment number
	///
	/// Note that the commitment number starts at `(1 << 48) - 1` and counts backwards.
	///
	/// This method is *not* asynchronous. This method is expected to always return `Ok`
	/// immediately after we reconnect to peers, and returning an `Err` may lead to an immediate
	/// `panic`. This method will be made asynchronous in a future release.
	fn get_per_commitment_point(
		&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<PublicKey, ()>;

	/// Gets the commitment secret for a specific commitment number as part of the revocation process
	///
	/// An external signer implementation should error here if the commitment was already signed
	/// and should refuse to sign it in the future.
	///
	/// May be called more than once for the same index.
	///
	/// Note that the commitment number starts at `(1 << 48) - 1` and counts backwards.
	///
	/// An `Err` can be returned to signal that the signer is unavailable/cannot produce a valid
	/// signature and should be retried later. Once the signer is ready to provide a signature after
	/// previously returning an `Err`, [`ChannelManager::signer_unblocked`] must be called.
	///
	/// [`ChannelManager::signer_unblocked`]: crate::ln::channelmanager::ChannelManager::signer_unblocked
	fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()>;

	/// Validate the counterparty's signatures on the holder commitment transaction and HTLCs.
	///
	/// This is required in order for the signer to make sure that releasing a commitment
	/// secret won't leave us without a broadcastable holder transaction.
	/// Policy checks should be implemented in this function, including checking the amount
	/// sent to us and checking the HTLCs.
	///
	/// The preimages of outbound HTLCs that were fulfilled since the last commitment are provided.
	/// A validating signer should ensure that an HTLC output is removed only when the matching
	/// preimage is provided, or when the value to holder is restored.
	///
	/// Note that all the relevant preimages will be provided, but there may also be additional
	/// irrelevant or duplicate preimages.
	///
	/// This method is *not* asynchronous. If an `Err` is returned, the channel will be immediately
	/// closed. If you wish to make this operation asynchronous, you should instead return `Ok(())`
	/// and pause future signing operations until this validation completes.
	fn validate_holder_commitment(
		&self, holder_tx: &HolderCommitmentTransaction,
		outbound_htlc_preimages: Vec<PaymentPreimage>,
	) -> Result<(), ()>;

	/// Validate the counterparty's revocation.
	///
	/// This is required in order for the signer to make sure that the state has moved
	/// forward and it is safe to sign the next counterparty commitment.
	///
	/// This method is *not* asynchronous. If an `Err` is returned, the channel will be immediately
	/// closed. If you wish to make this operation asynchronous, you should instead return `Ok(())`
	/// and pause future signing operations until this validation completes.
	fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()>;

	/// Returns the holder's channel public keys and basepoints.
	///
	/// `splice_parent_funding_txid` can be used to compute a tweak to rotate the funding key in the
	/// 2-of-2 multisig script during a splice. See [`compute_funding_key_tweak`] for an example
	/// tweak and more details.
	///
	/// This method is *not* asynchronous. Instead, the value must be cached locally.
	fn pubkeys(
		&self, splice_parent_funding_txid: Option<Txid>, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> ChannelPublicKeys;

	/// Returns an arbitrary identifier describing the set of keys which are provided back to you in
	/// some [`SpendableOutputDescriptor`] types. This should be sufficient to identify this
	/// [`EcdsaChannelSigner`] object uniquely and lookup or re-derive its keys.
	///
	/// This method is *not* asynchronous. Instead, the value must be cached locally.
	fn channel_keys_id(&self) -> [u8; 32];
}

/// Represents the secret key material used for encrypting Peer Storage.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerStorageKey {
	/// Represents the key used to encrypt and decrypt Peer Storage.
	pub inner: [u8; 32],
}

/// A secret key used to authenticate message contexts in received [`BlindedMessagePath`]s.
///
/// This key ensures that a node only accepts incoming messages delivered through
/// blinded paths that it constructed itself.
///
/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReceiveAuthKey(pub [u8; 32]);

/// Specifies the recipient of an invoice.
///
/// This indicates to [`NodeSigner::sign_invoice`] what node secret key should be used to sign
/// the invoice.
#[derive(Clone, Copy)]
pub enum Recipient {
	/// The invoice should be signed with the local node secret key.
	Node,
	/// The invoice should be signed with the phantom node secret key. This secret key must be the
	/// same for all nodes participating in the [phantom node payment].
	///
	/// [phantom node payment]: PhantomKeysManager
	PhantomNode,
}

/// A trait that describes a source of entropy.
pub trait EntropySource {
	/// Gets a unique, cryptographically-secure, random 32-byte value. This method must return a
	/// different value each time it is called.
	fn get_secure_random_bytes(&self) -> [u8; 32];
}

/// A trait that can handle cryptographic operations at the scope level of a node.
pub trait NodeSigner {
	/// Get the [`ExpandedKey`] for use in encrypting and decrypting inbound payment data.
	///
	/// If the implementor of this trait supports [phantom node payments], then every node that is
	/// intended to be included in the phantom invoice route hints must return the same value from
	/// this method.
	// This is because LDK avoids storing inbound payment data by encrypting payment data in the
	// payment hash and/or payment secret, therefore for a payment to be receivable by multiple
	// nodes, they must share the key that encrypts this payment data.
	///
	/// This method must return the same value each time it is called.
	///
	/// [phantom node payments]: PhantomKeysManager
	fn get_inbound_payment_key(&self) -> ExpandedKey;

	/// Defines a method to derive a 32-byte encryption key for peer storage.
	///
	/// Implementations of this method must derive a secure encryption key.
	/// The key is used to encrypt or decrypt backups of our state stored with our peers.
	///
	/// Thus, if you wish to rely on recovery using this method, you should use a key which
	/// can be re-derived from data which would be available after state loss (eg the wallet seed).
	fn get_peer_storage_key(&self) -> PeerStorageKey;

	/// Returns the [`ReceiveAuthKey`] used to authenticate incoming [`BlindedMessagePath`] contexts.
	///
	/// This key is used as additional associated data (AAD) during MAC verification of the
	/// [`MessageContext`] at the final hop of a blinded path. It ensures that only paths
	/// constructed by this node will be accepted, preventing unauthorized parties from forging
	/// valid-looking messages.
	///
	/// Implementers must ensure that this key remains secret and consistent across invocations.
	///
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`MessageContext`]: crate::blinded_path::message::MessageContext
	fn get_receive_auth_key(&self) -> ReceiveAuthKey;

	/// Get node id based on the provided [`Recipient`].
	///
	/// This method must return the same value each time it is called with a given [`Recipient`]
	/// parameter.
	///
	/// Errors if the [`Recipient`] variant is not supported by the implementation.
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()>;

	/// Gets the ECDH shared secret of our node secret and `other_key`, multiplying by `tweak` if
	/// one is provided. Note that this tweak can be applied to `other_key` instead of our node
	/// secret, though this is less efficient.
	///
	/// Note that if this fails while attempting to forward an HTLC, LDK will panic. The error
	/// should be resolved to allow LDK to resume forwarding HTLCs.
	///
	/// Errors if the [`Recipient`] variant is not supported by the implementation.
	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()>;

	/// Sign an invoice.
	///
	/// By parameterizing by the raw invoice bytes instead of the hash, we allow implementors of
	/// this trait to parse the invoice and make sure they're signing what they expect, rather than
	/// blindly signing the hash.
	///
	/// The `hrp_bytes` are ASCII bytes, while the `invoice_data` is base32.
	///
	/// The secret key used to sign the invoice is dependent on the [`Recipient`].
	///
	/// Errors if the [`Recipient`] variant is not supported by the implementation.
	fn sign_invoice(
		&self, invoice: &RawBolt11Invoice, recipient: Recipient,
	) -> Result<RecoverableSignature, ()>;

	/// Signs the [`TaggedHash`] of a BOLT 12 invoice.
	///
	/// May be called by a function passed to [`UnsignedBolt12Invoice::sign`] where `invoice` is the
	/// callee.
	///
	/// Implementors may check that the `invoice` is expected rather than blindly signing the tagged
	/// hash. An `Ok` result should sign `invoice.tagged_hash().as_digest()` with the node's signing
	/// key or an ephemeral key to preserve privacy, whichever is associated with
	/// [`UnsignedBolt12Invoice::signing_pubkey`].
	///
	/// [`TaggedHash`]: crate::offers::merkle::TaggedHash
	fn sign_bolt12_invoice(
		&self, invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()>;

	/// Sign a gossip message.
	///
	/// Note that if this fails, LDK may panic and the message will not be broadcast to the network
	/// or a possible channel counterparty. If LDK panics, the error should be resolved to allow the
	/// message to be broadcast, as otherwise it may prevent one from receiving funds over the
	/// corresponding channel.
	fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()>;

	/// Sign an arbitrary message with the node's secret key.
	///
	/// Creates a digital signature of a message given the node's secret. The message is prefixed
	/// with "Lightning Signed Message:" before signing. See [this description of the format](https://web.archive.org/web/20191010011846/https://twitter.com/rusty_twit/status/1182102005914800128)
	/// for more details.
	///
	/// A receiver knowing the node's id and the message can be sure that the signature was generated by the caller.
	/// An `Err` can be returned to signal that the signer is unavailable / cannot produce a valid
	/// signature.
	fn sign_message(&self, msg: &[u8]) -> Result<String, ()>;
}

/// A trait that describes a wallet capable of creating a spending [`Transaction`] from a set of
/// [`SpendableOutputDescriptor`]s.
pub trait OutputSpender {
	/// Creates a [`Transaction`] which spends the given descriptors to the given outputs, plus an
	/// output to the given change destination (if sufficient change value remains). The
	/// transaction will have a feerate, at least, of the given value.
	///
	/// The `locktime` argument is used to set the transaction's locktime. If `None`, the
	/// transaction will have a locktime of 0. It it recommended to set this to the current block
	/// height to avoid fee sniping, unless you have some specific reason to use a different
	/// locktime.
	///
	/// Returns `Err(())` if the output value is greater than the input value minus required fee,
	/// if a descriptor was duplicated, or if an output descriptor `script_pubkey`
	/// does not match the one we can spend.
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
		locktime: Option<LockTime>, secp_ctx: &Secp256k1<All>,
	) -> Result<Transaction, ()>;
}

// Primarily needed in doctests because of https://github.com/rust-lang/rust/issues/67295
/// A dynamic [`SignerProvider`] temporarily needed for doc tests.
///
/// This is not exported to bindings users as it is not intended for public consumption.
#[cfg(taproot)]
#[doc(hidden)]
#[deprecated(note = "Remove once taproot cfg is removed")]
pub type DynSignerProvider =
	dyn SignerProvider<EcdsaSigner = InMemorySigner, TaprootSigner = InMemorySigner>;

/// A dynamic [`SignerProvider`] temporarily needed for doc tests.
///
/// This is not exported to bindings users as it is not intended for public consumption.
#[cfg(not(taproot))]
#[doc(hidden)]
#[deprecated(note = "Remove once taproot cfg is removed")]
pub type DynSignerProvider = dyn SignerProvider<EcdsaSigner = InMemorySigner>;

/// A trait that can return signer instances for individual channels.
pub trait SignerProvider {
	/// A type which implements [`EcdsaChannelSigner`] which will be returned by [`Self::derive_channel_signer`].
	type EcdsaSigner: EcdsaChannelSigner;
	#[cfg(taproot)]
	/// A type which implements [`TaprootChannelSigner`]
	type TaprootSigner: TaprootChannelSigner;

	/// Generates a unique `channel_keys_id` that can be used to obtain a [`Self::EcdsaSigner`] through
	/// [`SignerProvider::derive_channel_signer`]. The `user_channel_id` is provided to allow
	/// implementations of [`SignerProvider`] to maintain a mapping between itself and the generated
	/// `channel_keys_id`.
	///
	/// This method must return a different value each time it is called.
	fn generate_channel_keys_id(&self, inbound: bool, user_channel_id: u128) -> [u8; 32];

	/// Derives the private key material backing a `Signer`.
	///
	/// To derive a new `Signer`, a fresh `channel_keys_id` should be obtained through
	/// [`SignerProvider::generate_channel_keys_id`]. Otherwise, an existing `Signer` can be
	/// re-derived from its `channel_keys_id`, which can be obtained through its trait method
	/// [`ChannelSigner::channel_keys_id`].
	fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner;

	/// Get a script pubkey which we send funds to when claiming on-chain contestable outputs.
	///
	/// If this function returns an error, this will result in a channel failing to open.
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds across channels as controlled to the same user. `channel_keys_id` may be
	/// used to derive a unique value for each channel.
	fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()>;

	/// Get a script pubkey which we will send funds to when closing a channel.
	///
	/// If this function returns an error, this will result in a channel failing to open or close.
	/// In the event of a failure when the counterparty is initiating a close, this can result in a
	/// channel force close.
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds across channels as controlled to the same user.
	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()>;
}

/// A helper trait that describes an on-chain wallet capable of returning a (change) destination
/// script.
pub trait ChangeDestinationSource {
	/// Returns a script pubkey which can be used as a change destination for
	/// [`OutputSpender::spend_spendable_outputs`].
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds controlled to the same user.
	fn get_change_destination_script<'a>(&self) -> AsyncResult<'a, ScriptBuf>;
}

/// A synchronous helper trait that describes an on-chain wallet capable of returning a (change) destination script.
pub trait ChangeDestinationSourceSync {
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds controlled to the same user.
	fn get_change_destination_script(&self) -> Result<ScriptBuf, ()>;
}

/// A wrapper around [`ChangeDestinationSource`] to allow for async calls.
#[cfg(any(test, feature = "_test_utils"))]
pub struct ChangeDestinationSourceSyncWrapper<T: Deref>(T)
where
	T::Target: ChangeDestinationSourceSync;
#[cfg(not(any(test, feature = "_test_utils")))]
pub(crate) struct ChangeDestinationSourceSyncWrapper<T: Deref>(T)
where
	T::Target: ChangeDestinationSourceSync;

impl<T: Deref> ChangeDestinationSourceSyncWrapper<T>
where
	T::Target: ChangeDestinationSourceSync,
{
	/// Creates a new [`ChangeDestinationSourceSyncWrapper`].
	pub fn new(source: T) -> Self {
		Self(source)
	}
}
impl<T: Deref> ChangeDestinationSource for ChangeDestinationSourceSyncWrapper<T>
where
	T::Target: ChangeDestinationSourceSync,
{
	fn get_change_destination_script<'a>(&self) -> AsyncResult<'a, ScriptBuf> {
		let script = self.0.get_change_destination_script();
		Box::pin(async move { script })
	}
}

mod sealed {
	use bitcoin::secp256k1::{Scalar, SecretKey};

	#[derive(Clone, PartialEq)]
	pub struct MaybeTweakedSecretKey(SecretKey);

	impl From<SecretKey> for MaybeTweakedSecretKey {
		fn from(value: SecretKey) -> Self {
			Self(value)
		}
	}

	impl MaybeTweakedSecretKey {
		pub fn with_tweak(&self, tweak: Option<Scalar>) -> SecretKey {
			tweak
				.map(|tweak| {
					self.0
						.add_tweak(&tweak)
						.expect("Addition only fails if the tweak is the inverse of the key")
				})
				.unwrap_or(self.0)
		}
	}
}

/// Computes the tweak to apply to the base funding key of a channel.
///
/// The tweak is computed similar to existing tweaks used in
/// [BOLT-3](https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation):
///
/// 1. We use the txid of the funding transaction the splice transaction is spending instead of the
///    `per_commitment_point` to guarantee uniqueness.
/// 2. We include the private key instead of the public key to guarantee only those with knowledge
///    of it can re-derive the new funding key.
///
///   tweak = SHA256(splice_parent_funding_txid || base_funding_secret_key)
///   tweaked_funding_key = base_funding_key + tweak
///
/// While the use of this tweak is not required (signers may choose to compute a tweak of their
/// choice), signers must ensure their tweak guarantees the two properties mentioned above:
/// uniqueness and derivable only by one or both of the channel participants.
pub fn compute_funding_key_tweak(
	base_funding_secret_key: &SecretKey, splice_parent_funding_txid: &Txid,
) -> Scalar {
	let mut sha = Sha256::engine();
	sha.input(splice_parent_funding_txid.as_byte_array());
	sha.input(&base_funding_secret_key.secret_bytes());
	Scalar::from_be_bytes(Sha256::from_engine(sha).to_byte_array()).unwrap()
}

/// A simple implementation of [`EcdsaChannelSigner`] that just keeps the private keys in memory.
///
/// This implementation performs no policy checks and is insufficient by itself as
/// a secure external signer.
pub struct InMemorySigner {
	/// Holder secret key in the 2-of-2 multisig script of a channel. This key also backs the
	/// holder's anchor output in a commitment transaction, if one is present.
	funding_key: sealed::MaybeTweakedSecretKey,
	/// Holder secret key for blinded revocation pubkey.
	pub revocation_base_key: SecretKey,
	/// Holder secret key used for our balance in counterparty-broadcasted commitment transactions.
	pub payment_key: SecretKey,
	/// Holder secret key used in an HTLC transaction.
	pub delayed_payment_base_key: SecretKey,
	/// Holder HTLC secret key used in commitment transaction HTLC outputs.
	pub htlc_base_key: SecretKey,
	/// Commitment seed.
	pub commitment_seed: [u8; 32],
	/// Holder public keys and basepoints.
	pub(crate) holder_channel_pubkeys: ChannelPublicKeys,
	/// Key derivation parameters.
	channel_keys_id: [u8; 32],
	/// A source of random bytes.
	entropy_source: RandomBytes,
}

impl PartialEq for InMemorySigner {
	fn eq(&self, other: &Self) -> bool {
		self.funding_key == other.funding_key
			&& self.revocation_base_key == other.revocation_base_key
			&& self.payment_key == other.payment_key
			&& self.delayed_payment_base_key == other.delayed_payment_base_key
			&& self.htlc_base_key == other.htlc_base_key
			&& self.commitment_seed == other.commitment_seed
			&& self.holder_channel_pubkeys == other.holder_channel_pubkeys
			&& self.channel_keys_id == other.channel_keys_id
	}
}

impl Clone for InMemorySigner {
	fn clone(&self) -> Self {
		Self {
			funding_key: self.funding_key.clone(),
			revocation_base_key: self.revocation_base_key.clone(),
			payment_key: self.payment_key.clone(),
			delayed_payment_base_key: self.delayed_payment_base_key.clone(),
			htlc_base_key: self.htlc_base_key.clone(),
			commitment_seed: self.commitment_seed.clone(),
			holder_channel_pubkeys: self.holder_channel_pubkeys.clone(),
			channel_keys_id: self.channel_keys_id,
			entropy_source: RandomBytes::new(self.get_secure_random_bytes()),
		}
	}
}

impl InMemorySigner {
	/// Creates a new [`InMemorySigner`].
	pub fn new<C: Signing>(
		secp_ctx: &Secp256k1<C>, funding_key: SecretKey, revocation_base_key: SecretKey,
		payment_key: SecretKey, delayed_payment_base_key: SecretKey, htlc_base_key: SecretKey,
		commitment_seed: [u8; 32], channel_keys_id: [u8; 32], rand_bytes_unique_start: [u8; 32],
	) -> InMemorySigner {
		let holder_channel_pubkeys = InMemorySigner::make_holder_keys(
			secp_ctx,
			&funding_key,
			&revocation_base_key,
			&payment_key,
			&delayed_payment_base_key,
			&htlc_base_key,
		);
		InMemorySigner {
			funding_key: sealed::MaybeTweakedSecretKey::from(funding_key),
			revocation_base_key,
			payment_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			holder_channel_pubkeys,
			channel_keys_id,
			entropy_source: RandomBytes::new(rand_bytes_unique_start),
		}
	}

	/// Holder secret key in the 2-of-2 multisig script of a channel. This key also backs the
	/// holder's anchor output in a commitment transaction, if one is present.
	pub fn funding_key(&self, splice_parent_funding_txid: Option<Txid>) -> SecretKey {
		let tweak = splice_parent_funding_txid
			.map(|txid| compute_funding_key_tweak(&self.funding_key.with_tweak(None), &txid));
		self.funding_key.with_tweak(tweak)
	}

	fn make_holder_keys<C: Signing>(
		secp_ctx: &Secp256k1<C>, funding_key: &SecretKey, revocation_base_key: &SecretKey,
		payment_key: &SecretKey, delayed_payment_base_key: &SecretKey, htlc_base_key: &SecretKey,
	) -> ChannelPublicKeys {
		let from_secret = |s: &SecretKey| PublicKey::from_secret_key(secp_ctx, s);
		ChannelPublicKeys {
			funding_pubkey: from_secret(&funding_key),
			revocation_basepoint: RevocationBasepoint::from(from_secret(&revocation_base_key)),
			payment_point: from_secret(&payment_key),
			delayed_payment_basepoint: DelayedPaymentBasepoint::from(from_secret(
				&delayed_payment_base_key,
			)),
			htlc_basepoint: HtlcBasepoint::from(from_secret(&htlc_base_key)),
		}
	}

	/// Sign the single input of `spend_tx` at index `input_idx`, which spends the output described
	/// by `descriptor`, returning the witness stack for the input.
	///
	/// Returns an error if the input at `input_idx` does not exist, has a non-empty `script_sig`,
	/// is not spending the outpoint described by [`descriptor.outpoint`],
	/// or if an output descriptor `script_pubkey` does not match the one we can spend.
	///
	/// [`descriptor.outpoint`]: StaticPaymentOutputDescriptor::outpoint
	pub fn sign_counterparty_payment_input<C: Signing>(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<C>,
	) -> Result<Witness, ()> {
		// TODO: We really should be taking the SigHashCache as a parameter here instead of
		// spend_tx, but ideally the SigHashCache would expose the transaction's inputs read-only
		// so that we can check them. This requires upstream rust-bitcoin changes (as well as
		// bindings updates to support SigHashCache objects).
		if spend_tx.input.len() <= input_idx {
			return Err(());
		}
		if !spend_tx.input[input_idx].script_sig.is_empty() {
			return Err(());
		}
		if spend_tx.input[input_idx].previous_output != descriptor.outpoint.into_bitcoin_outpoint()
		{
			return Err(());
		}

		let remotepubkey = bitcoin::PublicKey::new(self.holder_channel_pubkeys.payment_point);
		let supports_anchors_zero_fee_htlc_tx = descriptor
			.channel_transaction_parameters
			.as_ref()
			.map(|params| params.channel_type_features.supports_anchors_zero_fee_htlc_tx())
			.unwrap_or(false);

		let witness_script = if supports_anchors_zero_fee_htlc_tx {
			chan_utils::get_to_countersigner_keyed_anchor_redeemscript(&remotepubkey.inner)
		} else {
			ScriptBuf::new_p2pkh(&remotepubkey.pubkey_hash())
		};
		let sighash = hash_to_message!(
			&sighash::SighashCache::new(spend_tx)
				.p2wsh_signature_hash(
					input_idx,
					&witness_script,
					descriptor.output.value,
					EcdsaSighashType::All
				)
				.unwrap()[..]
		);
		let remotesig = sign_with_aux_rand(secp_ctx, &sighash, &self.payment_key, &self);
		let payment_script = if supports_anchors_zero_fee_htlc_tx {
			witness_script.to_p2wsh()
		} else {
			ScriptBuf::new_p2wpkh(&remotepubkey.wpubkey_hash().unwrap())
		};

		if payment_script != descriptor.output.script_pubkey {
			return Err(());
		}

		let mut witness = Vec::with_capacity(2);
		witness.push(remotesig.serialize_der().to_vec());
		witness[0].push(EcdsaSighashType::All as u8);
		if supports_anchors_zero_fee_htlc_tx {
			witness.push(witness_script.to_bytes());
		} else {
			witness.push(remotepubkey.to_bytes());
		}
		Ok(witness.into())
	}

	/// Sign the single input of `spend_tx` at index `input_idx` which spends the output
	/// described by `descriptor`, returning the witness stack for the input.
	///
	/// Returns an error if the input at `input_idx` does not exist, has a non-empty `script_sig`,
	/// is not spending the outpoint described by [`descriptor.outpoint`], does not have a
	/// sequence set to [`descriptor.to_self_delay`], or if an output descriptor
	/// `script_pubkey` does not match the one we can spend.
	///
	/// [`descriptor.outpoint`]: DelayedPaymentOutputDescriptor::outpoint
	/// [`descriptor.to_self_delay`]: DelayedPaymentOutputDescriptor::to_self_delay
	pub fn sign_dynamic_p2wsh_input<C: Signing>(
		&self, spend_tx: &Transaction, input_idx: usize,
		descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<C>,
	) -> Result<Witness, ()> {
		// TODO: We really should be taking the SigHashCache as a parameter here instead of
		// spend_tx, but ideally the SigHashCache would expose the transaction's inputs read-only
		// so that we can check them. This requires upstream rust-bitcoin changes (as well as
		// bindings updates to support SigHashCache objects).
		if spend_tx.input.len() <= input_idx {
			return Err(());
		}
		if !spend_tx.input[input_idx].script_sig.is_empty() {
			return Err(());
		}
		if spend_tx.input[input_idx].previous_output != descriptor.outpoint.into_bitcoin_outpoint()
		{
			return Err(());
		}
		if spend_tx.input[input_idx].sequence.0 != descriptor.to_self_delay as u32 {
			return Err(());
		}

		let delayed_payment_key = chan_utils::derive_private_key(
			&secp_ctx,
			&descriptor.per_commitment_point,
			&self.delayed_payment_base_key,
		);
		let delayed_payment_pubkey =
			DelayedPaymentKey::from_secret_key(&secp_ctx, &delayed_payment_key);
		let witness_script = chan_utils::get_revokeable_redeemscript(
			&descriptor.revocation_pubkey,
			descriptor.to_self_delay,
			&delayed_payment_pubkey,
		);
		let sighash = hash_to_message!(
			&sighash::SighashCache::new(spend_tx)
				.p2wsh_signature_hash(
					input_idx,
					&witness_script,
					descriptor.output.value,
					EcdsaSighashType::All
				)
				.unwrap()[..]
		);
		let local_delayedsig = EcdsaSignature {
			signature: sign_with_aux_rand(secp_ctx, &sighash, &delayed_payment_key, &self),
			sighash_type: EcdsaSighashType::All,
		};
		let payment_script =
			bitcoin::Address::p2wsh(&witness_script, Network::Bitcoin).script_pubkey();

		if descriptor.output.script_pubkey != payment_script {
			return Err(());
		}

		Ok(Witness::from_slice(&[
			&local_delayedsig.serialize()[..],
			&[], // MINIMALIF
			witness_script.as_bytes(),
		]))
	}
}

impl EntropySource for InMemorySigner {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		self.entropy_source.get_secure_random_bytes()
	}
}

impl ChannelSigner for InMemorySigner {
	fn get_per_commitment_point(
		&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<PublicKey, ()> {
		let commitment_secret =
			SecretKey::from_slice(&chan_utils::build_commitment_secret(&self.commitment_seed, idx))
				.unwrap();
		Ok(PublicKey::from_secret_key(secp_ctx, &commitment_secret))
	}

	fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()> {
		Ok(chan_utils::build_commitment_secret(&self.commitment_seed, idx))
	}

	fn validate_holder_commitment(
		&self, _holder_tx: &HolderCommitmentTransaction,
		_outbound_htlc_preimages: Vec<PaymentPreimage>,
	) -> Result<(), ()> {
		Ok(())
	}

	fn validate_counterparty_revocation(&self, _idx: u64, _secret: &SecretKey) -> Result<(), ()> {
		Ok(())
	}

	fn pubkeys(
		&self, splice_parent_funding_txid: Option<Txid>, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> ChannelPublicKeys {
		let mut pubkeys = self.holder_channel_pubkeys.clone();
		if splice_parent_funding_txid.is_some() {
			pubkeys.funding_pubkey =
				self.funding_key(splice_parent_funding_txid).public_key(secp_ctx);
		}
		pubkeys
	}

	fn channel_keys_id(&self) -> [u8; 32] {
		self.channel_keys_id
	}
}

const MISSING_PARAMS_ERR: &'static str =
	"ChannelTransactionParameters must be populated before signing operations";

impl EcdsaChannelSigner for InMemorySigner {
	fn sign_counterparty_commitment(
		&self, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &CommitmentTransaction, _inbound_htlc_preimages: Vec<PaymentPreimage>,
		_outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<(Signature, Vec<Signature>), ()> {
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let trusted_tx = commitment_tx.trust();
		let keys = trusted_tx.keys();

		let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
		let funding_pubkey = funding_key.public_key(secp_ctx);
		let counterparty_keys =
			channel_parameters.counterparty_pubkeys().expect(MISSING_PARAMS_ERR);
		let channel_funding_redeemscript =
			make_funding_redeemscript(&funding_pubkey, &counterparty_keys.funding_pubkey);

		let built_tx = trusted_tx.built_transaction();
		let commitment_sig = built_tx.sign_counterparty_commitment(
			&funding_key,
			&channel_funding_redeemscript,
			channel_parameters.channel_value_satoshis,
			secp_ctx,
		);
		let commitment_txid = built_tx.txid;

		let mut htlc_sigs = Vec::with_capacity(commitment_tx.nondust_htlcs().len());
		for htlc in commitment_tx.nondust_htlcs() {
			let holder_selected_contest_delay = channel_parameters.holder_selected_contest_delay;
			let chan_type = &channel_parameters.channel_type_features;
			let htlc_tx = chan_utils::build_htlc_transaction(
				&commitment_txid,
				commitment_tx.feerate_per_kw(),
				holder_selected_contest_delay,
				htlc,
				chan_type,
				&keys.broadcaster_delayed_payment_key,
				&keys.revocation_key,
			);
			let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, chan_type, &keys);
			let htlc_sighashtype = if chan_type.supports_anchors_zero_fee_htlc_tx() {
				EcdsaSighashType::SinglePlusAnyoneCanPay
			} else {
				EcdsaSighashType::All
			};
			let htlc_sighash = hash_to_message!(
				&sighash::SighashCache::new(&htlc_tx)
					.p2wsh_signature_hash(
						0,
						&htlc_redeemscript,
						htlc.to_bitcoin_amount(),
						htlc_sighashtype
					)
					.unwrap()[..]
			);
			let holder_htlc_key = chan_utils::derive_private_key(
				&secp_ctx,
				&keys.per_commitment_point,
				&self.htlc_base_key,
			);
			htlc_sigs.push(sign(secp_ctx, &htlc_sighash, &holder_htlc_key));
		}

		Ok((commitment_sig, htlc_sigs))
	}

	fn sign_holder_commitment(
		&self, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
		let funding_pubkey = funding_key.public_key(secp_ctx);
		let counterparty_keys =
			channel_parameters.counterparty_pubkeys().expect(MISSING_PARAMS_ERR);
		let funding_redeemscript =
			make_funding_redeemscript(&funding_pubkey, &counterparty_keys.funding_pubkey);
		let trusted_tx = commitment_tx.trust();
		Ok(trusted_tx.built_transaction().sign_holder_commitment(
			&funding_key,
			&funding_redeemscript,
			channel_parameters.channel_value_satoshis,
			&self,
			secp_ctx,
		))
	}

	#[cfg(any(test, feature = "_test_utils", feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment(
		&self, channel_parameters: &ChannelTransactionParameters,
		commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
		let funding_pubkey = funding_key.public_key(secp_ctx);
		let counterparty_keys =
			channel_parameters.counterparty_pubkeys().expect(MISSING_PARAMS_ERR);
		let funding_redeemscript =
			make_funding_redeemscript(&funding_pubkey, &counterparty_keys.funding_pubkey);
		let trusted_tx = commitment_tx.trust();
		Ok(trusted_tx.built_transaction().sign_holder_commitment(
			&funding_key,
			&funding_redeemscript,
			channel_parameters.channel_value_satoshis,
			&self,
			secp_ctx,
		))
	}

	fn sign_justice_revoked_output(
		&self, channel_parameters: &ChannelTransactionParameters, justice_tx: &Transaction,
		input: usize, amount: u64, per_commitment_key: &SecretKey,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let revocation_key = chan_utils::derive_private_revocation_key(
			&secp_ctx,
			&per_commitment_key,
			&self.revocation_base_key,
		);
		let per_commitment_point = PublicKey::from_secret_key(secp_ctx, &per_commitment_key);
		let revocation_pubkey = RevocationKey::from_basepoint(
			&secp_ctx,
			&channel_parameters.holder_pubkeys.revocation_basepoint,
			&per_commitment_point,
		);
		let witness_script = {
			let counterparty_keys =
				channel_parameters.counterparty_pubkeys().expect(MISSING_PARAMS_ERR);
			let holder_selected_contest_delay = channel_parameters.holder_selected_contest_delay;
			let counterparty_delayedpubkey = DelayedPaymentKey::from_basepoint(
				&secp_ctx,
				&counterparty_keys.delayed_payment_basepoint,
				&per_commitment_point,
			);
			chan_utils::get_revokeable_redeemscript(
				&revocation_pubkey,
				holder_selected_contest_delay,
				&counterparty_delayedpubkey,
			)
		};
		let mut sighash_parts = sighash::SighashCache::new(justice_tx);
		let sighash = hash_to_message!(
			&sighash_parts
				.p2wsh_signature_hash(
					input,
					&witness_script,
					Amount::from_sat(amount),
					EcdsaSighashType::All
				)
				.unwrap()[..]
		);
		return Ok(sign_with_aux_rand(secp_ctx, &sighash, &revocation_key, &self));
	}

	fn sign_justice_revoked_htlc(
		&self, channel_parameters: &ChannelTransactionParameters, justice_tx: &Transaction,
		input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let revocation_key = chan_utils::derive_private_revocation_key(
			&secp_ctx,
			&per_commitment_key,
			&self.revocation_base_key,
		);
		let per_commitment_point = PublicKey::from_secret_key(secp_ctx, &per_commitment_key);
		let revocation_pubkey = RevocationKey::from_basepoint(
			&secp_ctx,
			&channel_parameters.holder_pubkeys.revocation_basepoint,
			&per_commitment_point,
		);
		let witness_script = {
			let counterparty_keys =
				channel_parameters.counterparty_pubkeys().expect(MISSING_PARAMS_ERR);
			let counterparty_htlcpubkey = HtlcKey::from_basepoint(
				&secp_ctx,
				&counterparty_keys.htlc_basepoint,
				&per_commitment_point,
			);
			let holder_htlcpubkey = HtlcKey::from_basepoint(
				&secp_ctx,
				&channel_parameters.holder_pubkeys.htlc_basepoint,
				&per_commitment_point,
			);
			chan_utils::get_htlc_redeemscript_with_explicit_keys(
				&htlc,
				&channel_parameters.channel_type_features,
				&counterparty_htlcpubkey,
				&holder_htlcpubkey,
				&revocation_pubkey,
			)
		};
		let mut sighash_parts = sighash::SighashCache::new(justice_tx);
		let sighash = hash_to_message!(
			&sighash_parts
				.p2wsh_signature_hash(
					input,
					&witness_script,
					Amount::from_sat(amount),
					EcdsaSighashType::All
				)
				.unwrap()[..]
		);
		return Ok(sign_with_aux_rand(secp_ctx, &sighash, &revocation_key, &self));
	}

	fn sign_holder_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		let channel_parameters =
			&htlc_descriptor.channel_derivation_parameters.transaction_parameters;
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let witness_script = htlc_descriptor.witness_script(secp_ctx);
		let sighash = &sighash::SighashCache::new(&*htlc_tx)
			.p2wsh_signature_hash(
				input,
				&witness_script,
				htlc_descriptor.htlc.to_bitcoin_amount(),
				EcdsaSighashType::All,
			)
			.map_err(|_| ())?;
		let our_htlc_private_key = chan_utils::derive_private_key(
			&secp_ctx,
			&htlc_descriptor.per_commitment_point,
			&self.htlc_base_key,
		);
		let sighash = hash_to_message!(sighash.as_byte_array());
		Ok(sign_with_aux_rand(&secp_ctx, &sighash, &our_htlc_private_key, &self))
	}

	fn sign_counterparty_htlc_transaction(
		&self, channel_parameters: &ChannelTransactionParameters, htlc_tx: &Transaction,
		input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let htlc_key =
			chan_utils::derive_private_key(&secp_ctx, &per_commitment_point, &self.htlc_base_key);
		let revocation_pubkey = RevocationKey::from_basepoint(
			&secp_ctx,
			&channel_parameters.holder_pubkeys.revocation_basepoint,
			&per_commitment_point,
		);
		let counterparty_keys =
			channel_parameters.counterparty_pubkeys().expect(MISSING_PARAMS_ERR);
		let counterparty_htlcpubkey = HtlcKey::from_basepoint(
			&secp_ctx,
			&counterparty_keys.htlc_basepoint,
			&per_commitment_point,
		);
		let htlc_basepoint = channel_parameters.holder_pubkeys.htlc_basepoint;
		let htlcpubkey = HtlcKey::from_basepoint(&secp_ctx, &htlc_basepoint, &per_commitment_point);
		let chan_type = &channel_parameters.channel_type_features;
		let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(
			&htlc,
			chan_type,
			&counterparty_htlcpubkey,
			&htlcpubkey,
			&revocation_pubkey,
		);
		let mut sighash_parts = sighash::SighashCache::new(htlc_tx);
		let sighash = hash_to_message!(
			&sighash_parts
				.p2wsh_signature_hash(
					input,
					&witness_script,
					Amount::from_sat(amount),
					EcdsaSighashType::All
				)
				.unwrap()[..]
		);
		Ok(sign_with_aux_rand(secp_ctx, &sighash, &htlc_key, &self))
	}

	fn sign_closing_transaction(
		&self, channel_parameters: &ChannelTransactionParameters, closing_tx: &ClosingTransaction,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
		let funding_pubkey = funding_key.public_key(secp_ctx);
		let counterparty_funding_key =
			&channel_parameters.counterparty_pubkeys().expect(MISSING_PARAMS_ERR).funding_pubkey;
		let channel_funding_redeemscript =
			make_funding_redeemscript(&funding_pubkey, counterparty_funding_key);
		Ok(closing_tx.trust().sign(
			&funding_key,
			&channel_funding_redeemscript,
			channel_parameters.channel_value_satoshis,
			secp_ctx,
		))
	}

	fn sign_holder_keyed_anchor_input(
		&self, chan_params: &ChannelTransactionParameters, anchor_tx: &Transaction, input: usize,
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		assert!(chan_params.is_populated(), "Channel parameters must be fully populated");

		let witness_script =
			chan_utils::get_keyed_anchor_redeemscript(&chan_params.holder_pubkeys.funding_pubkey);
		let amt = Amount::from_sat(ANCHOR_OUTPUT_VALUE_SATOSHI);
		let sighash = sighash::SighashCache::new(&*anchor_tx)
			.p2wsh_signature_hash(input, &witness_script, amt, EcdsaSighashType::All)
			.unwrap();
		let funding_key = self.funding_key(chan_params.splice_parent_funding_txid);
		Ok(sign_with_aux_rand(secp_ctx, &hash_to_message!(&sighash[..]), &funding_key, &self))
	}

	fn sign_channel_announcement_with_funding_key(
		&self, channel_parameters: &ChannelTransactionParameters,
		msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		let msghash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
		let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
		Ok(secp_ctx.sign_ecdsa(&msghash, &funding_key))
	}

	fn sign_splicing_funding_input(
		&self, channel_parameters: &ChannelTransactionParameters, tx: &Transaction,
		input_index: usize, input_value: u64, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");

		let funding_key = self.funding_key(channel_parameters.splice_parent_funding_txid);
		let funding_pubkey = funding_key.public_key(secp_ctx);
		let counterparty_funding_key =
			&channel_parameters.counterparty_pubkeys().expect(MISSING_PARAMS_ERR).funding_pubkey;
		let funding_redeemscript =
			make_funding_redeemscript(&funding_pubkey, counterparty_funding_key);
		let sighash = &sighash::SighashCache::new(tx)
			.p2wsh_signature_hash(
				input_index,
				&funding_redeemscript,
				Amount::from_sat(input_value),
				EcdsaSighashType::All,
			)
			.unwrap()[..];
		let msg = hash_to_message!(sighash);
		Ok(sign(secp_ctx, &msg, &funding_key))
	}
}

#[cfg(taproot)]
#[allow(unused)]
impl TaprootChannelSigner for InMemorySigner {
	fn generate_local_nonce_pair(
		&self, commitment_number: u64, secp_ctx: &Secp256k1<All>,
	) -> PublicNonce {
		todo!()
	}

	fn partially_sign_counterparty_commitment(
		&self, counterparty_nonce: PublicNonce, commitment_tx: &CommitmentTransaction,
		inbound_htlc_preimages: Vec<PaymentPreimage>,
		outbound_htlc_preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<All>,
	) -> Result<(PartialSignatureWithNonce, Vec<schnorr::Signature>), ()> {
		todo!()
	}

	fn finalize_holder_commitment(
		&self, commitment_tx: &HolderCommitmentTransaction,
		counterparty_partial_signature: PartialSignatureWithNonce, secp_ctx: &Secp256k1<All>,
	) -> Result<PartialSignature, ()> {
		todo!()
	}

	fn sign_justice_revoked_output(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		secp_ctx: &Secp256k1<All>,
	) -> Result<schnorr::Signature, ()> {
		todo!()
	}

	fn sign_justice_revoked_htlc(
		&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>,
	) -> Result<schnorr::Signature, ()> {
		todo!()
	}

	fn sign_holder_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor,
		secp_ctx: &Secp256k1<All>,
	) -> Result<schnorr::Signature, ()> {
		todo!()
	}

	fn sign_counterparty_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey,
		htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<All>,
	) -> Result<schnorr::Signature, ()> {
		todo!()
	}

	fn partially_sign_closing_transaction(
		&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<All>,
	) -> Result<PartialSignature, ()> {
		todo!()
	}
}

/// Simple implementation of [`EntropySource`], [`NodeSigner`], and [`SignerProvider`] that takes a
/// 32-byte seed for use as a BIP 32 extended key and derives keys from that.
///
/// Your `node_id` is seed/0'.
/// Unilateral closes may use seed/1'.
/// Cooperative closes may use seed/2'.
/// The two close keys may be needed to claim on-chain funds!
///
/// This struct cannot be used for nodes that wish to support receiving phantom payments;
/// [`PhantomKeysManager`] must be used instead.
///
/// Note that switching between this struct and [`PhantomKeysManager`] will invalidate any
/// previously issued invoices and attempts to pay previous invoices will fail.
pub struct KeysManager {
	secp_ctx: Secp256k1<secp256k1::All>,
	node_secret: SecretKey,
	node_id: PublicKey,
	inbound_payment_key: ExpandedKey,
	destination_script: ScriptBuf,
	shutdown_pubkey: PublicKey,
	channel_master_key: Xpriv,
	channel_child_index: AtomicUsize,
	peer_storage_key: PeerStorageKey,
	receive_auth_key: ReceiveAuthKey,

	#[cfg(test)]
	pub(crate) entropy_source: RandomBytes,
	#[cfg(not(test))]
	entropy_source: RandomBytes,

	seed: [u8; 32],
	starting_time_secs: u64,
	starting_time_nanos: u32,
}

impl KeysManager {
	/// Constructs a [`KeysManager`] from a 32-byte seed. If the seed is in some way biased (e.g.,
	/// your CSRNG is busted) this may panic (but more importantly, you will possibly lose funds).
	/// `starting_time` isn't strictly required to actually be a time, but it must absolutely,
	/// without a doubt, be unique to this instance. ie if you start multiple times with the same
	/// `seed`, `starting_time` must be unique to each run. Thus, the easiest way to achieve this
	/// is to simply use the current time (with very high precision).
	///
	/// The `seed` MUST be backed up safely prior to use so that the keys can be re-created, however,
	/// obviously, `starting_time` should be unique every time you reload the library - it is only
	/// used to generate new ephemeral key data (which will be stored by the individual channel if
	/// necessary).
	///
	/// Note that the seed is required to recover certain on-chain funds independent of
	/// [`ChannelMonitor`] data, though a current copy of [`ChannelMonitor`] data is also required
	/// for any channel, and some on-chain during-closing funds.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	pub fn new(seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32) -> Self {
		// Constants for key derivation path indices used in this function.
		const NODE_SECRET_INDEX: ChildNumber = ChildNumber::Hardened { index: 0 };
		const DESTINATION_SCRIPT_INDEX: ChildNumber = ChildNumber::Hardened { index: 1 };
		const SHUTDOWN_PUBKEY_INDEX: ChildNumber = ChildNumber::Hardened { index: 2 };
		const CHANNEL_MASTER_KEY_INDEX: ChildNumber = ChildNumber::Hardened { index: 3 };
		const INBOUND_PAYMENT_KEY_INDEX: ChildNumber = ChildNumber::Hardened { index: 5 };
		const PEER_STORAGE_KEY_INDEX: ChildNumber = ChildNumber::Hardened { index: 6 };
		const RECEIVE_AUTH_KEY_INDEX: ChildNumber = ChildNumber::Hardened { index: 7 };

		let secp_ctx = Secp256k1::new();
		// Note that when we aren't serializing the key, network doesn't matter
		match Xpriv::new_master(Network::Testnet, seed) {
			Ok(master_key) => {
				let node_secret = master_key
					.derive_priv(&secp_ctx, &NODE_SECRET_INDEX)
					.expect("Your RNG is busted")
					.private_key;
				let node_id = PublicKey::from_secret_key(&secp_ctx, &node_secret);
				let destination_script =
					match master_key.derive_priv(&secp_ctx, &DESTINATION_SCRIPT_INDEX) {
						Ok(destination_key) => {
							let wpubkey_hash = WPubkeyHash::hash(
								&Xpub::from_priv(&secp_ctx, &destination_key).to_pub().to_bytes(),
							);
							Builder::new()
								.push_opcode(opcodes::all::OP_PUSHBYTES_0)
								.push_slice(&wpubkey_hash.to_byte_array())
								.into_script()
						},
						Err(_) => panic!("Your RNG is busted"),
					};
				let shutdown_pubkey =
					match master_key.derive_priv(&secp_ctx, &SHUTDOWN_PUBKEY_INDEX) {
						Ok(shutdown_key) => Xpub::from_priv(&secp_ctx, &shutdown_key).public_key,
						Err(_) => panic!("Your RNG is busted"),
					};
				let channel_master_key = master_key
					.derive_priv(&secp_ctx, &CHANNEL_MASTER_KEY_INDEX)
					.expect("Your RNG is busted");
				let inbound_payment_key: SecretKey = master_key
					.derive_priv(&secp_ctx, &INBOUND_PAYMENT_KEY_INDEX)
					.expect("Your RNG is busted")
					.private_key;
				let mut inbound_pmt_key_bytes = [0; 32];
				inbound_pmt_key_bytes.copy_from_slice(&inbound_payment_key[..]);
				let peer_storage_key = master_key
					.derive_priv(&secp_ctx, &PEER_STORAGE_KEY_INDEX)
					.expect("Your RNG is busted")
					.private_key;

				let receive_auth_key = master_key
					.derive_priv(&secp_ctx, &RECEIVE_AUTH_KEY_INDEX)
					.expect("Your RNG is busted")
					.private_key;

				let mut rand_bytes_engine = Sha256::engine();
				rand_bytes_engine.input(&starting_time_secs.to_be_bytes());
				rand_bytes_engine.input(&starting_time_nanos.to_be_bytes());
				rand_bytes_engine.input(seed);
				rand_bytes_engine.input(b"LDK PRNG Seed");
				let rand_bytes_unique_start =
					Sha256::from_engine(rand_bytes_engine).to_byte_array();

				let mut res = KeysManager {
					secp_ctx,
					node_secret,
					node_id,
					inbound_payment_key: ExpandedKey::new(inbound_pmt_key_bytes),

					peer_storage_key: PeerStorageKey { inner: peer_storage_key.secret_bytes() },
					receive_auth_key: ReceiveAuthKey(receive_auth_key.secret_bytes()),

					destination_script,
					shutdown_pubkey,

					channel_master_key,
					channel_child_index: AtomicUsize::new(0),

					entropy_source: RandomBytes::new(rand_bytes_unique_start),

					seed: *seed,
					starting_time_secs,
					starting_time_nanos,
				};
				let secp_seed = res.get_secure_random_bytes();
				res.secp_ctx.seeded_randomize(&secp_seed);
				res
			},
			Err(_) => panic!("Your rng is busted"),
		}
	}

	/// Gets the "node_id" secret key used to sign gossip announcements, decode onion data, etc.
	pub fn get_node_secret_key(&self) -> SecretKey {
		self.node_secret
	}

	/// Derive an old [`EcdsaChannelSigner`] containing per-channel secrets based on a key derivation parameters.
	pub fn derive_channel_keys(&self, params: &[u8; 32]) -> InMemorySigner {
		let chan_id = u64::from_be_bytes(params[0..8].try_into().unwrap());
		let mut unique_start = Sha256::engine();
		unique_start.input(params);
		unique_start.input(&self.seed);

		// We only seriously intend to rely on the channel_master_key for true secure
		// entropy, everything else just ensures uniqueness. We rely on the unique_start (ie
		// starting_time provided in the constructor) to be unique.
		let child_privkey = self
			.channel_master_key
			.derive_priv(
				&self.secp_ctx,
				&ChildNumber::from_hardened_idx((chan_id as u32) % (1 << 31))
					.expect("key space exhausted"),
			)
			.expect("Your RNG is busted");
		unique_start.input(&child_privkey.private_key[..]);

		let seed = Sha256::from_engine(unique_start).to_byte_array();

		let commitment_seed = {
			let mut sha = Sha256::engine();
			sha.input(&seed);
			sha.input(&b"commitment seed"[..]);
			Sha256::from_engine(sha).to_byte_array()
		};
		macro_rules! key_step {
			($info: expr, $prev_key: expr) => {{
				let mut sha = Sha256::engine();
				sha.input(&seed);
				sha.input(&$prev_key[..]);
				sha.input(&$info[..]);
				SecretKey::from_slice(&Sha256::from_engine(sha).to_byte_array())
					.expect("SHA-256 is busted")
			}};
		}
		let funding_key = key_step!(b"funding key", commitment_seed);
		let revocation_base_key = key_step!(b"revocation base key", funding_key);
		let payment_key = key_step!(b"payment key", revocation_base_key);
		let delayed_payment_base_key = key_step!(b"delayed payment base key", payment_key);
		let htlc_base_key = key_step!(b"HTLC base key", delayed_payment_base_key);
		let prng_seed = self.get_secure_random_bytes();

		InMemorySigner::new(
			&self.secp_ctx,
			funding_key,
			revocation_base_key,
			payment_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			params.clone(),
			prng_seed,
		)
	}

	/// Signs the given [`Psbt`] which spends the given [`SpendableOutputDescriptor`]s.
	/// The resulting inputs will be finalized and the PSBT will be ready for broadcast if there
	/// are no other inputs that need signing.
	///
	/// Returns `Err(())` if the PSBT is missing a descriptor or if we fail to sign.
	///
	/// May panic if the [`SpendableOutputDescriptor`]s were not generated by channels which used
	/// this [`KeysManager`] or one of the [`InMemorySigner`] created by this [`KeysManager`].
	pub fn sign_spendable_outputs_psbt<C: Signing>(
		&self, descriptors: &[&SpendableOutputDescriptor], mut psbt: Psbt, secp_ctx: &Secp256k1<C>,
	) -> Result<Psbt, ()> {
		let mut keys_cache: Option<(InMemorySigner, [u8; 32])> = None;
		for outp in descriptors {
			let get_input_idx = |outpoint: &OutPoint| {
				psbt.unsigned_tx
					.input
					.iter()
					.position(|i| i.previous_output == outpoint.into_bitcoin_outpoint())
					.ok_or(())
			};
			match outp {
				SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
					let input_idx = get_input_idx(&descriptor.outpoint)?;
					if keys_cache.is_none()
						|| keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id
					{
						let signer = self.derive_channel_keys(&descriptor.channel_keys_id);
						keys_cache = Some((signer, descriptor.channel_keys_id));
					}
					let witness = keys_cache.as_ref().unwrap().0.sign_counterparty_payment_input(
						&psbt.unsigned_tx,
						input_idx,
						&descriptor,
						&secp_ctx,
					)?;
					psbt.inputs[input_idx].final_script_witness = Some(witness);
				},
				SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
					let input_idx = get_input_idx(&descriptor.outpoint)?;
					if keys_cache.is_none()
						|| keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id
					{
						keys_cache = Some((
							self.derive_channel_keys(&descriptor.channel_keys_id),
							descriptor.channel_keys_id,
						));
					}
					let witness = keys_cache.as_ref().unwrap().0.sign_dynamic_p2wsh_input(
						&psbt.unsigned_tx,
						input_idx,
						&descriptor,
						&secp_ctx,
					)?;
					psbt.inputs[input_idx].final_script_witness = Some(witness);
				},
				SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output, .. } => {
					let input_idx = get_input_idx(outpoint)?;
					let derivation_idx =
						if output.script_pubkey == self.destination_script { 1 } else { 2 };
					let secret = {
						// Note that when we aren't serializing the key, network doesn't matter
						match Xpriv::new_master(Network::Testnet, &self.seed) {
							Ok(master_key) => {
								match master_key.derive_priv(
									&secp_ctx,
									&ChildNumber::from_hardened_idx(derivation_idx)
										.expect("key space exhausted"),
								) {
									Ok(key) => key,
									Err(_) => panic!("Your RNG is busted"),
								}
							},
							Err(_) => panic!("Your rng is busted"),
						}
					};
					let pubkey = Xpub::from_priv(&secp_ctx, &secret).to_pub();
					if derivation_idx == 2 {
						assert_eq!(pubkey.0, self.shutdown_pubkey);
					}
					let witness_script =
						bitcoin::Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
					let payment_script =
						bitcoin::Address::p2wpkh(&pubkey, Network::Testnet).script_pubkey();

					if payment_script != output.script_pubkey {
						return Err(());
					};

					let sighash = hash_to_message!(
						&sighash::SighashCache::new(&psbt.unsigned_tx)
							.p2wsh_signature_hash(
								input_idx,
								&witness_script,
								output.value,
								EcdsaSighashType::All
							)
							.unwrap()[..]
					);
					let sig = sign_with_aux_rand(secp_ctx, &sighash, &secret.private_key, &self);
					let mut sig_ser = sig.serialize_der().to_vec();
					sig_ser.push(EcdsaSighashType::All as u8);
					let witness = Witness::from_slice(&[&sig_ser, &pubkey.0.serialize().to_vec()]);
					psbt.inputs[input_idx].final_script_witness = Some(witness);
				},
			}
		}

		Ok(psbt)
	}
}

impl EntropySource for KeysManager {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		self.entropy_source.get_secure_random_bytes()
	}
}

impl NodeSigner for KeysManager {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		match recipient {
			Recipient::Node => Ok(self.node_id.clone()),
			Recipient::PhantomNode => Err(()),
		}
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(()),
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_inbound_payment_key(&self) -> ExpandedKey {
		self.inbound_payment_key.clone()
	}

	fn get_peer_storage_key(&self) -> PeerStorageKey {
		self.peer_storage_key.clone()
	}

	fn get_receive_auth_key(&self) -> ReceiveAuthKey {
		self.receive_auth_key.clone()
	}

	fn sign_invoice(
		&self, invoice: &RawBolt11Invoice, recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		let hash = invoice.signable_hash();
		let secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(()),
		}?;
		Ok(self.secp_ctx.sign_ecdsa_recoverable(&hash_to_message!(&hash), secret))
	}

	fn sign_bolt12_invoice(
		&self, invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		let message = invoice.tagged_hash().as_digest();
		let keys = Keypair::from_secret_key(&self.secp_ctx, &self.node_secret);
		let aux_rand = self.get_secure_random_bytes();
		Ok(self.secp_ctx.sign_schnorr_with_aux_rand(message, &keys, &aux_rand))
	}

	fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
		Ok(self.secp_ctx.sign_ecdsa(&msg_hash, &self.node_secret))
	}

	fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
		Ok(crate::util::message_signing::sign(msg, &self.node_secret))
	}
}

impl OutputSpender for KeysManager {
	/// Creates a [`Transaction`] which spends the given descriptors to the given outputs, plus an
	/// output to the given change destination (if sufficient change value remains).
	///
	/// See [`OutputSpender::spend_spendable_outputs`] documentation for more information.
	///
	/// We do not enforce that outputs meet the dust limit or that any output scripts are standard.
	///
	/// May panic if the [`SpendableOutputDescriptor`]s were not generated by channels which used
	/// this [`KeysManager`] or one of the [`InMemorySigner`] created by this [`KeysManager`].
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
		locktime: Option<LockTime>, secp_ctx: &Secp256k1<All>,
	) -> Result<Transaction, ()> {
		let (mut psbt, expected_max_weight) =
			SpendableOutputDescriptor::create_spendable_outputs_psbt(
				secp_ctx,
				descriptors,
				outputs,
				change_destination_script,
				feerate_sat_per_1000_weight,
				locktime,
			)?;
		psbt = self.sign_spendable_outputs_psbt(descriptors, psbt, secp_ctx)?;

		let spend_tx = psbt.extract_tx_unchecked_fee_rate();

		debug_assert!(expected_max_weight >= spend_tx.weight().to_wu());
		// Note that witnesses with a signature vary somewhat in size, so allow
		// `expected_max_weight` to overshoot by up to 3 bytes per input.
		debug_assert!(
			expected_max_weight <= spend_tx.weight().to_wu() + descriptors.len() as u64 * 3
		);

		Ok(spend_tx)
	}
}

impl SignerProvider for KeysManager {
	type EcdsaSigner = InMemorySigner;
	#[cfg(taproot)]
	type TaprootSigner = InMemorySigner;

	fn generate_channel_keys_id(&self, _inbound: bool, user_channel_id: u128) -> [u8; 32] {
		let child_idx = self.channel_child_index.fetch_add(1, Ordering::AcqRel);
		// `child_idx` is the only thing guaranteed to make each channel unique without a restart
		// (though `user_channel_id` should help, depending on user behavior). If it manages to
		// roll over, we may generate duplicate keys for two different channels, which could result
		// in loss of funds. Because we only support 32-bit+ systems, assert that our `AtomicUsize`
		// doesn't reach `u32::MAX`.
		assert!(child_idx < core::u32::MAX as usize, "2^32 channels opened without restart");
		let mut id = [0; 32];
		id[0..4].copy_from_slice(&(child_idx as u32).to_be_bytes());
		id[4..8].copy_from_slice(&self.starting_time_nanos.to_be_bytes());
		id[8..16].copy_from_slice(&self.starting_time_secs.to_be_bytes());
		id[16..32].copy_from_slice(&user_channel_id.to_be_bytes());
		id
	}

	fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
		self.derive_channel_keys(&channel_keys_id)
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		Ok(self.destination_script.clone())
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		Ok(ShutdownScript::new_p2wpkh_from_pubkey(self.shutdown_pubkey.clone()))
	}
}

/// Similar to [`KeysManager`], but allows the node using this struct to receive phantom node
/// payments.
///
/// A phantom node payment is a payment made to a phantom invoice, which is an invoice that can be
/// paid to one of multiple nodes. This works because we encode the invoice route hints such that
/// LDK will recognize an incoming payment as destined for a phantom node, and collect the payment
/// itself without ever needing to forward to this fake node.
///
/// Phantom node payments are useful for load balancing between multiple LDK nodes. They also
/// provide some fault tolerance, because payers will automatically retry paying other provided
/// nodes in the case that one node goes down.
///
/// Note that multi-path payments are not supported in phantom invoices for security reasons.
// In the hypothetical case that we did support MPP phantom payments, there would be no way for
// nodes to know when the full payment has been received (and the preimage can be released) without
// significantly compromising on our safety guarantees. I.e., if we expose the ability for the user
// to tell LDK when the preimage can be released, we open ourselves to attacks where the preimage
// is released too early.
//
/// Switching between this struct and [`KeysManager`] will invalidate any previously issued
/// invoices and attempts to pay previous invoices will fail.
pub struct PhantomKeysManager {
	#[cfg(test)]
	pub(crate) inner: KeysManager,
	#[cfg(not(test))]
	inner: KeysManager,
	inbound_payment_key: ExpandedKey,
	phantom_secret: SecretKey,
	phantom_node_id: PublicKey,
}

impl EntropySource for PhantomKeysManager {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		self.inner.get_secure_random_bytes()
	}
}

impl NodeSigner for PhantomKeysManager {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		match recipient {
			Recipient::Node => self.inner.get_node_id(Recipient::Node),
			Recipient::PhantomNode => Ok(self.phantom_node_id.clone()),
		}
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => self.inner.node_secret.clone(),
			Recipient::PhantomNode => self.phantom_secret.clone(),
		};
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_inbound_payment_key(&self) -> ExpandedKey {
		self.inbound_payment_key.clone()
	}

	fn get_peer_storage_key(&self) -> PeerStorageKey {
		self.inner.peer_storage_key.clone()
	}

	fn get_receive_auth_key(&self) -> ReceiveAuthKey {
		self.inner.receive_auth_key.clone()
	}

	fn sign_invoice(
		&self, invoice: &RawBolt11Invoice, recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		let hash = invoice.signable_hash();
		let secret = match recipient {
			Recipient::Node => &self.inner.node_secret,
			Recipient::PhantomNode => &self.phantom_secret,
		};
		Ok(self.inner.secp_ctx.sign_ecdsa_recoverable(&hash_to_message!(&hash), secret))
	}

	fn sign_bolt12_invoice(
		&self, invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		self.inner.sign_bolt12_invoice(invoice)
	}

	fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
		self.inner.sign_gossip_message(msg)
	}

	fn sign_message(&self, msg: &[u8]) -> Result<String, ()> {
		self.inner.sign_message(msg)
	}
}

impl OutputSpender for PhantomKeysManager {
	/// See [`OutputSpender::spend_spendable_outputs`] and [`KeysManager::spend_spendable_outputs`]
	/// for documentation on this method.
	fn spend_spendable_outputs(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
		locktime: Option<LockTime>, secp_ctx: &Secp256k1<All>,
	) -> Result<Transaction, ()> {
		self.inner.spend_spendable_outputs(
			descriptors,
			outputs,
			change_destination_script,
			feerate_sat_per_1000_weight,
			locktime,
			secp_ctx,
		)
	}
}

impl SignerProvider for PhantomKeysManager {
	type EcdsaSigner = InMemorySigner;
	#[cfg(taproot)]
	type TaprootSigner = InMemorySigner;

	fn generate_channel_keys_id(&self, inbound: bool, user_channel_id: u128) -> [u8; 32] {
		self.inner.generate_channel_keys_id(inbound, user_channel_id)
	}

	fn derive_channel_signer(&self, channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
		self.inner.derive_channel_signer(channel_keys_id)
	}

	fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		self.inner.get_destination_script(channel_keys_id)
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		self.inner.get_shutdown_scriptpubkey()
	}
}

impl PhantomKeysManager {
	/// Constructs a [`PhantomKeysManager`] given a 32-byte seed and an additional `cross_node_seed`
	/// that is shared across all nodes that intend to participate in [phantom node payments]
	/// together.
	///
	/// See [`KeysManager::new`] for more information on `seed`, `starting_time_secs`, and
	/// `starting_time_nanos`.
	///
	/// `cross_node_seed` must be the same across all phantom payment-receiving nodes and also the
	/// same across restarts, or else inbound payments may fail.
	///
	/// [phantom node payments]: PhantomKeysManager
	pub fn new(
		seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32,
		cross_node_seed: &[u8; 32],
	) -> Self {
		let inner = KeysManager::new(seed, starting_time_secs, starting_time_nanos);
		let (inbound_key, phantom_key) = hkdf_extract_expand_twice(
			b"LDK Inbound and Phantom Payment Key Expansion",
			cross_node_seed,
		);
		let phantom_secret = SecretKey::from_slice(&phantom_key).unwrap();
		let phantom_node_id = PublicKey::from_secret_key(&inner.secp_ctx, &phantom_secret);
		Self {
			inner,
			inbound_payment_key: ExpandedKey::new(inbound_key),
			phantom_secret,
			phantom_node_id,
		}
	}

	/// See [`KeysManager::derive_channel_keys`] for documentation on this method.
	pub fn derive_channel_keys(&self, params: &[u8; 32]) -> InMemorySigner {
		self.inner.derive_channel_keys(params)
	}

	/// Gets the "node_id" secret key used to sign gossip announcements, decode onion data, etc.
	pub fn get_node_secret_key(&self) -> SecretKey {
		self.inner.get_node_secret_key()
	}

	/// Gets the "node_id" secret key of the phantom node used to sign invoices, decode the
	/// last-hop onion data, etc.
	pub fn get_phantom_node_secret_key(&self) -> SecretKey {
		self.phantom_secret
	}
}

/// An implementation of [`EntropySource`] using ChaCha20.
pub struct RandomBytes {
	/// Seed from which all randomness produced is derived from.
	seed: [u8; 32],
	/// Tracks the number of times we've produced randomness to ensure we don't return the same
	/// bytes twice.
	index: AtomicCounter,
}

impl RandomBytes {
	/// Creates a new instance using the given seed.
	pub fn new(seed: [u8; 32]) -> Self {
		Self { seed, index: AtomicCounter::new() }
	}
}

impl EntropySource for RandomBytes {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let index = self.index.next();
		let mut nonce = [0u8; 16];
		nonce[..8].copy_from_slice(&index.to_be_bytes());
		ChaCha20::get_single_block(&self.seed, &nonce)
	}
}

// Ensure that EcdsaChannelSigner can have a vtable
#[test]
pub fn dyn_sign() {
	let _signer: Box<dyn EcdsaChannelSigner>;
}

#[cfg(ldk_bench)]
pub mod benches {
	use crate::sign::{EntropySource, KeysManager};
	use bitcoin::constants::genesis_block;
	use bitcoin::Network;
	use std::sync::mpsc::TryRecvError;
	use std::sync::{mpsc, Arc};
	use std::thread;
	use std::time::Duration;

	use criterion::Criterion;

	pub fn bench_get_secure_random_bytes(bench: &mut Criterion) {
		let seed = [0u8; 32];
		let now = Duration::from_secs(genesis_block(Network::Testnet).header.time as u64);
		let keys_manager = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_micros()));

		let mut handles = Vec::new();
		let mut stops = Vec::new();
		for _ in 1..5 {
			let keys_manager_clone = Arc::clone(&keys_manager);
			let (stop_sender, stop_receiver) = mpsc::channel();
			let handle = thread::spawn(move || loop {
				keys_manager_clone.get_secure_random_bytes();
				match stop_receiver.try_recv() {
					Ok(_) | Err(TryRecvError::Disconnected) => {
						println!("Terminating.");
						break;
					},
					Err(TryRecvError::Empty) => {},
				}
			});
			handles.push(handle);
			stops.push(stop_sender);
		}

		bench.bench_function("get_secure_random_bytes", |b| {
			b.iter(|| keys_manager.get_secure_random_bytes())
		});

		for stop in stops {
			let _ = stop.send(());
		}
		for handle in handles {
			handle.join().unwrap();
		}
	}
}
