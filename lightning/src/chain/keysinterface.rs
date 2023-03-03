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

use bitcoin::blockdata::transaction::{Transaction, TxOut, TxIn, EcdsaSighashType};
use bitcoin::blockdata::script::{Script, Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, ChildNumber};
use bitcoin::util::sighash;

use bitcoin::bech32::u5;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hash_types::WPubkeyHash;

use bitcoin::secp256k1::{SecretKey, PublicKey, Scalar};
use bitcoin::secp256k1::{Secp256k1, ecdsa::Signature, Signing};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::RecoverableSignature;
use bitcoin::{PackedLockTime, secp256k1, Sequence, Witness};

use crate::util::transaction_utils;
use crate::util::crypto::{hkdf_extract_expand_twice, sign};
use crate::util::ser::{Writeable, Writer, Readable};
#[cfg(anchors)]
use crate::util::events::HTLCDescriptor;
use crate::chain::transaction::OutPoint;
use crate::ln::channel::ANCHOR_OUTPUT_VALUE_SATOSHI;
use crate::ln::{chan_utils, PaymentPreimage};
use crate::ln::chan_utils::{HTLCOutputInCommitment, make_funding_redeemscript, ChannelPublicKeys, HolderCommitmentTransaction, ChannelTransactionParameters, CommitmentTransaction, ClosingTransaction};
use crate::ln::msgs::{UnsignedChannelAnnouncement, UnsignedGossipMessage};
use crate::ln::script::ShutdownScript;

use crate::prelude::*;
use core::convert::TryInto;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::io::{self, Error};
use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
use crate::util::atomic_counter::AtomicCounter;
use crate::util::chacha20::ChaCha20;
use crate::util::invoice::construct_invoice_preimage;

/// Used as initial key material, to be expanded into multiple secret keys (but not to be used
/// directly). This is used within LDK to encrypt/decrypt inbound payment data.
///
/// (C-not exported) as we just use `[u8; 32]` directly
#[derive(Hash, Copy, Clone, PartialEq, Eq, Debug)]
pub struct KeyMaterial(pub [u8; 32]);

/// Information about a spendable output to a P2WSH script.
///
/// See [`SpendableOutputDescriptor::DelayedPaymentOutput`] for more details on how to spend this.
#[derive(Clone, Debug, PartialEq, Eq)]
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
	pub revocation_pubkey: PublicKey,
	/// Arbitrary identification information returned by a call to [`ChannelSigner::channel_keys_id`].
	/// This may be useful in re-deriving keys used in the channel to spend the output.
	pub channel_keys_id: [u8; 32],
	/// The value of the channel which this output originated from, possibly indirectly.
	pub channel_value_satoshis: u64,
}
impl DelayedPaymentOutputDescriptor {
	/// The maximum length a well-formed witness spending one of these should have.
	// Calculated as 1 byte length + 73 byte signature, 1 byte empty vec push, 1 byte length plus
	// redeemscript push length.
	pub const MAX_WITNESS_LENGTH: usize = 1 + 73 + 1 + chan_utils::REVOKEABLE_REDEEMSCRIPT_MAX_LENGTH + 1;
}

impl_writeable_tlv_based!(DelayedPaymentOutputDescriptor, {
	(0, outpoint, required),
	(2, per_commitment_point, required),
	(4, to_self_delay, required),
	(6, output, required),
	(8, revocation_pubkey, required),
	(10, channel_keys_id, required),
	(12, channel_value_satoshis, required),
});

/// Information about a spendable output to our "payment key".
///
/// See [`SpendableOutputDescriptor::StaticPaymentOutput`] for more details on how to spend this.
#[derive(Clone, Debug, PartialEq, Eq)]
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
}
impl StaticPaymentOutputDescriptor {
	/// The maximum length a well-formed witness spending one of these should have.
	// Calculated as 1 byte legnth + 73 byte signature, 1 byte empty vec push, 1 byte length plus
	// redeemscript push length.
	pub const MAX_WITNESS_LENGTH: usize = 1 + 73 + 34;
}
impl_writeable_tlv_based!(StaticPaymentOutputDescriptor, {
	(0, outpoint, required),
	(2, output, required),
	(4, channel_keys_id, required),
	(6, channel_value_satoshis, required),
});

/// Describes the necessary information to spend a spendable output.
///
/// When on-chain outputs are created by LDK (which our counterparty is not able to claim at any
/// point in the future) a [`SpendableOutputs`] event is generated which you must track and be able
/// to spend on-chain. The information needed to do this is provided in this enum, including the
/// outpoint describing which `txid` and output `index` is available, the full output which exists
/// at that `txid`/`index`, and any keys or other information required to sign.
///
/// [`SpendableOutputs`]: crate::util::events::Event::SpendableOutputs
#[derive(Clone, Debug, PartialEq, Eq)]
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
	/// [`DelayedPaymentOutputDescriptor::per_commitment_point`] to [`chan_utils::derive_private_key`]. The public key can be
	/// generated without the secret key using [`chan_utils::derive_public_key`] and only the
	/// [`ChannelPublicKeys::delayed_payment_basepoint`] which appears in [`ChannelSigner::pubkeys`].
	///
	/// To derive the [`DelayedPaymentOutputDescriptor::revocation_pubkey`] provided here (which is
	/// used in the witness script generation), you must pass the counterparty
	/// [`ChannelPublicKeys::revocation_basepoint`] (which appears in the call to
	/// [`ChannelSigner::provide_channel_parameters`]) and the provided
	/// [`DelayedPaymentOutputDescriptor::per_commitment_point`] to
	/// [`chan_utils::derive_public_revocation_key`].
	///
	/// The witness script which is hashed and included in the output `script_pubkey` may be
	/// regenerated by passing the [`DelayedPaymentOutputDescriptor::revocation_pubkey`] (derived
	/// as explained above), our delayed payment pubkey (derived as explained above), and the
	/// [`DelayedPaymentOutputDescriptor::to_self_delay`] contained here to
	/// [`chan_utils::get_revokeable_redeemscript`].
	DelayedPaymentOutput(DelayedPaymentOutputDescriptor),
	/// An output to a P2WPKH, spendable exclusively by our payment key (i.e., the private key
	/// which corresponds to the `payment_point` in [`ChannelSigner::pubkeys`]). The witness
	/// in the spending input is, thus, simply:
	/// ```bitcoin
	/// <BIP 143 signature> <payment key>
	/// ```
	///
	/// These are generally the result of our counterparty having broadcast the current state,
	/// allowing us to claim the non-HTLC-encumbered outputs immediately.
	StaticPaymentOutput(StaticPaymentOutputDescriptor),
}

impl_writeable_tlv_based_enum!(SpendableOutputDescriptor,
	(0, StaticOutput) => {
		(0, outpoint, required),
		(2, output, required),
	},
;
	(1, DelayedPaymentOutput),
	(2, StaticPaymentOutput),
);

/// A trait to handle Lightning channel key material without concretizing the channel type or
/// the signature mechanism.
pub trait ChannelSigner {
	/// Gets the per-commitment point for a specific commitment number
	///
	/// Note that the commitment number starts at `(1 << 48) - 1` and counts backwards.
	fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> PublicKey;

	/// Gets the commitment secret for a specific commitment number as part of the revocation process
	///
	/// An external signer implementation should error here if the commitment was already signed
	/// and should refuse to sign it in the future.
	///
	/// May be called more than once for the same index.
	///
	/// Note that the commitment number starts at `(1 << 48) - 1` and counts backwards.
	// TODO: return a Result so we can signal a validation error
	fn release_commitment_secret(&self, idx: u64) -> [u8; 32];

	/// Validate the counterparty's signatures on the holder commitment transaction and HTLCs.
	///
	/// This is required in order for the signer to make sure that releasing a commitment
	/// secret won't leave us without a broadcastable holder transaction.
	/// Policy checks should be implemented in this function, including checking the amount
	/// sent to us and checking the HTLCs.
	///
	/// The preimages of outgoing HTLCs that were fulfilled since the last commitment are provided.
	/// A validating signer should ensure that an HTLC output is removed only when the matching
	/// preimage is provided, or when the value to holder is restored.
	///
	/// Note that all the relevant preimages will be provided, but there may also be additional
	/// irrelevant or duplicate preimages.
	fn validate_holder_commitment(&self, holder_tx: &HolderCommitmentTransaction,
		preimages: Vec<PaymentPreimage>) -> Result<(), ()>;

	/// Returns the holder's channel public keys and basepoints.
	fn pubkeys(&self) -> &ChannelPublicKeys;

	/// Returns an arbitrary identifier describing the set of keys which are provided back to you in
	/// some [`SpendableOutputDescriptor`] types. This should be sufficient to identify this
	/// [`EcdsaChannelSigner`] object uniquely and lookup or re-derive its keys.
	fn channel_keys_id(&self) -> [u8; 32];

	/// Set the counterparty static channel data, including basepoints,
	/// `counterparty_selected`/`holder_selected_contest_delay` and funding outpoint.
	///
	/// This data is static, and will never change for a channel once set. For a given [`ChannelSigner`]
	/// instance, LDK will call this method exactly once - either immediately after construction
	/// (not including if done via [`SignerProvider::read_chan_signer`]) or when the funding
	/// information has been generated.
	///
	/// channel_parameters.is_populated() MUST be true.
	fn provide_channel_parameters(&mut self, channel_parameters: &ChannelTransactionParameters);
}

/// A trait to sign Lightning channel transactions as described in
/// [BOLT 3](https://github.com/lightning/bolts/blob/master/03-transactions.md).
///
/// Signing services could be implemented on a hardware wallet and should implement signing
/// policies in order to be secure. Please refer to the [VLS Policy
/// Controls](https://gitlab.com/lightning-signer/validating-lightning-signer/-/blob/main/docs/policy-controls.md)
/// for an example of such policies.
pub trait EcdsaChannelSigner: ChannelSigner {
	/// Create a signature for a counterparty's commitment transaction and associated HTLC transactions.
	///
	/// Note that if signing fails or is rejected, the channel will be force-closed.
	///
	/// Policy checks should be implemented in this function, including checking the amount
	/// sent to us and checking the HTLCs.
	///
	/// The preimages of outgoing HTLCs that were fulfilled since the last commitment are provided.
	/// A validating signer should ensure that an HTLC output is removed only when the matching
	/// preimage is provided, or when the value to holder is restored.
	///
	/// Note that all the relevant preimages will be provided, but there may also be additional
	/// irrelevant or duplicate preimages.
	//
	// TODO: Document the things someone using this interface should enforce before signing.
	fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction,
		preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<(Signature, Vec<Signature>), ()>;
	/// Validate the counterparty's revocation.
	///
	/// This is required in order for the signer to make sure that the state has moved
	/// forward and it is safe to sign the next counterparty commitment.
	fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()>;
	/// Creates a signature for a holder's commitment transaction and its claiming HTLC transactions.
	///
	/// This will be called
	/// - with a non-revoked `commitment_tx`.
	/// - with the latest `commitment_tx` when we initiate a force-close.
	/// - with the previous `commitment_tx`, just to get claiming HTLC
	///   signatures, if we are reacting to a [`ChannelMonitor`]
	///   [replica](https://github.com/lightningdevkit/rust-lightning/blob/main/GLOSSARY.md#monitor-replicas)
	///   that decided to broadcast before it had been updated to the latest `commitment_tx`.
	///
	/// This may be called multiple times for the same transaction.
	///
	/// An external signer implementation should check that the commitment has not been revoked.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	// TODO: Document the things someone using this interface should enforce before signing.
	fn sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()>;
	/// Same as [`sign_holder_commitment_and_htlcs`], but exists only for tests to get access to
	/// holder commitment transactions which will be broadcasted later, after the channel has moved
	/// on to a newer state. Thus, needs its own method as [`sign_holder_commitment_and_htlcs`] may
	/// enforce that we only ever get called once.
	#[cfg(any(test,feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()>;
	/// Create a signature for the given input in a transaction spending an HTLC transaction output
	/// or a commitment transaction `to_local` output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// Amount is value of the output spent by this input, committed to in the BIP 143 signature.
	///
	/// `per_commitment_key` is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder `revocation_secret` to do
	/// so).
	fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64,
		per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()>;
	/// Create a signature for the given input in a transaction spending a commitment transaction
	/// HTLC output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// `amount` is the value of the output spent by this input, committed to in the BIP 143
	/// signature.
	///
	/// `per_commitment_key` is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder revocation_secret to do
	/// so).
	///
	/// `htlc` holds HTLC elements (hash, timelock), thus changing the format of the witness script
	/// (which is committed to in the BIP 143 signatures).
	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64,
		per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;
	#[cfg(anchors)]
	/// Computes the signature for a commitment transaction's HTLC output used as an input within
	/// `htlc_tx`, which spends the commitment transaction at index `input`. The signature returned
	/// must be be computed using [`EcdsaSighashType::All`]. Note that this should only be used to
	/// sign HTLC transactions from channels supporting anchor outputs after all additional
	/// inputs/outputs have been added to the transaction.
	///
	/// [`EcdsaSighashType::All`]: bitcoin::blockdata::transaction::EcdsaSighashType::All
	fn sign_holder_htlc_transaction(&self, htlc_tx: &Transaction, input: usize,
		htlc_descriptor: &HTLCDescriptor, secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()>;
	/// Create a signature for a claiming transaction for a HTLC output on a counterparty's commitment
	/// transaction, either offered or received.
	///
	/// Such a transaction may claim multiples offered outputs at same time if we know the
	/// preimage for each when we create it, but only the input at index `input` should be
	/// signed for here. It may be called multiple times for same output(s) if a fee-bump is
	/// needed with regards to an upcoming timelock expiration.
	///
	/// `witness_script` is either an offered or received script as defined in BOLT3 for HTLC
	/// outputs.
	///
	/// `amount` is value of the output spent by this input, committed to in the BIP 143 signature.
	///
	/// `per_commitment_point` is the dynamic point corresponding to the channel state
	/// detected onchain. It has been generated by our counterparty and is used to derive
	/// channel state keys, which are then included in the witness script and committed to in the
	/// BIP 143 signature.
	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64,
		per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;
	/// Create a signature for a (proposed) closing transaction.
	///
	/// Note that, due to rounding, there may be one "missing" satoshi, and either party may have
	/// chosen to forgo their output as dust.
	fn sign_closing_transaction(&self, closing_tx: &ClosingTransaction,
		secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;
	/// Computes the signature for a commitment transaction's anchor output used as an
	/// input within `anchor_tx`, which spends the commitment transaction, at index `input`.
	fn sign_holder_anchor_input(
		&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()>;
	/// Signs a channel announcement message with our funding key proving it comes from one of the
	/// channel participants.
	///
	/// Channel announcements also require a signature from each node's network key. Our node
	/// signature is computed through [`NodeSigner::sign_gossip_message`].
	///
	/// Note that if this fails or is rejected, the channel will not be publicly announced and
	/// our counterparty may (though likely will not) close the channel on us for violating the
	/// protocol.
	fn sign_channel_announcement_with_funding_key(
		&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()>;
}

/// A writeable signer.
///
/// There will always be two instances of a signer per channel, one occupied by the
/// [`ChannelManager`] and another by the channel's [`ChannelMonitor`].
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
pub trait WriteableEcdsaChannelSigner: EcdsaChannelSigner + Writeable {}

/// Specifies the recipient of an invoice.
///
/// This indicates to [`NodeSigner::sign_invoice`] what node secret key should be used to sign
/// the invoice.
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
	/// Get secret key material as bytes for use in encrypting and decrypting inbound payment data.
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
	fn get_inbound_payment_key_material(&self) -> KeyMaterial;

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
	fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()>;

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
	fn sign_invoice(&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient) -> Result<RecoverableSignature, ()>;

	/// Sign a gossip message.
	///
	/// Note that if this fails, LDK may panic and the message will not be broadcast to the network
	/// or a possible channel counterparty. If LDK panics, the error should be resolved to allow the
	/// message to be broadcast, as otherwise it may prevent one from receiving funds over the
	/// corresponding channel.
	fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()>;
}

/// A trait that can return signer instances for individual channels.
pub trait SignerProvider {
	/// A type which implements [`WriteableEcdsaChannelSigner`] which will be returned by [`Self::derive_channel_signer`].
	type Signer : WriteableEcdsaChannelSigner;

	/// Generates a unique `channel_keys_id` that can be used to obtain a [`Self::Signer`] through
	/// [`SignerProvider::derive_channel_signer`]. The `user_channel_id` is provided to allow
	/// implementations of [`SignerProvider`] to maintain a mapping between itself and the generated
	/// `channel_keys_id`.
	///
	/// This method must return a different value each time it is called.
	fn generate_channel_keys_id(&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128) -> [u8; 32];

	/// Derives the private key material backing a `Signer`.
	///
	/// To derive a new `Signer`, a fresh `channel_keys_id` should be obtained through
	/// [`SignerProvider::generate_channel_keys_id`]. Otherwise, an existing `Signer` can be
	/// re-derived from its `channel_keys_id`, which can be obtained through its trait method
	/// [`ChannelSigner::channel_keys_id`].
	fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> Self::Signer;

	/// Reads a [`Signer`] for this [`SignerProvider`] from the given input stream.
	/// This is only called during deserialization of other objects which contain
	/// [`WriteableEcdsaChannelSigner`]-implementing objects (i.e., [`ChannelMonitor`]s and [`ChannelManager`]s).
	/// The bytes are exactly those which `<Self::Signer as Writeable>::write()` writes, and
	/// contain no versioning scheme. You may wish to include your own version prefix and ensure
	/// you've read all of the provided bytes to ensure no corruption occurred.
	///
	/// This method is slowly being phased out -- it will only be called when reading objects
	/// written by LDK versions prior to 0.0.113.
	///
	/// [`Signer`]: Self::Signer
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError>;

	/// Get a script pubkey which we send funds to when claiming on-chain contestable outputs.
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds across channels as controlled to the same user.
	fn get_destination_script(&self) -> Script;

	/// Get a script pubkey which we will send funds to when closing a channel.
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds across channels as controlled to the same user.
	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript;
}

#[derive(Clone)]
/// A simple implementation of [`WriteableEcdsaChannelSigner`] that just keeps the private keys in memory.
///
/// This implementation performs no policy checks and is insufficient by itself as
/// a secure external signer.
pub struct InMemorySigner {
	/// Holder secret key in the 2-of-2 multisig script of a channel. This key also backs the
	/// holder's anchor output in a commitment transaction, if one is present.
	pub funding_key: SecretKey,
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
	/// Counterparty public keys and counterparty/holder `selected_contest_delay`, populated on channel acceptance.
	channel_parameters: Option<ChannelTransactionParameters>,
	/// The total value of this channel.
	channel_value_satoshis: u64,
	/// Key derivation parameters.
	channel_keys_id: [u8; 32],
}

impl InMemorySigner {
	/// Creates a new [`InMemorySigner`].
	pub fn new<C: Signing>(
		secp_ctx: &Secp256k1<C>,
		funding_key: SecretKey,
		revocation_base_key: SecretKey,
		payment_key: SecretKey,
		delayed_payment_base_key: SecretKey,
		htlc_base_key: SecretKey,
		commitment_seed: [u8; 32],
		channel_value_satoshis: u64,
		channel_keys_id: [u8; 32],
	) -> InMemorySigner {
		let holder_channel_pubkeys =
			InMemorySigner::make_holder_keys(secp_ctx, &funding_key, &revocation_base_key,
				&payment_key, &delayed_payment_base_key,
				&htlc_base_key);
		InMemorySigner {
			funding_key,
			revocation_base_key,
			payment_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			channel_value_satoshis,
			holder_channel_pubkeys,
			channel_parameters: None,
			channel_keys_id,
		}
	}

	fn make_holder_keys<C: Signing>(secp_ctx: &Secp256k1<C>,
			funding_key: &SecretKey,
			revocation_base_key: &SecretKey,
			payment_key: &SecretKey,
			delayed_payment_base_key: &SecretKey,
			htlc_base_key: &SecretKey) -> ChannelPublicKeys {
		let from_secret = |s: &SecretKey| PublicKey::from_secret_key(secp_ctx, s);
		ChannelPublicKeys {
			funding_pubkey: from_secret(&funding_key),
			revocation_basepoint: from_secret(&revocation_base_key),
			payment_point: from_secret(&payment_key),
			delayed_payment_basepoint: from_secret(&delayed_payment_base_key),
			htlc_basepoint: from_secret(&htlc_base_key),
		}
	}

	/// Returns the counterparty's pubkeys.
	///
	/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
	pub fn counterparty_pubkeys(&self) -> &ChannelPublicKeys { &self.get_channel_parameters().counterparty_parameters.as_ref().unwrap().pubkeys }
	/// Returns the `contest_delay` value specified by our counterparty and applied on holder-broadcastable
	/// transactions, i.e., the amount of time that we have to wait to recover our funds if we
	/// broadcast a transaction.
	///
	/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
	pub fn counterparty_selected_contest_delay(&self) -> u16 { self.get_channel_parameters().counterparty_parameters.as_ref().unwrap().selected_contest_delay }
	/// Returns the `contest_delay` value specified by us and applied on transactions broadcastable
	/// by our counterparty, i.e., the amount of time that they have to wait to recover their funds
	/// if they broadcast a transaction.
	///
	/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
	pub fn holder_selected_contest_delay(&self) -> u16 { self.get_channel_parameters().holder_selected_contest_delay }
	/// Returns whether the holder is the initiator.
	///
	/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
	pub fn is_outbound(&self) -> bool { self.get_channel_parameters().is_outbound_from_holder }
	/// Funding outpoint
	///
	/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
	pub fn funding_outpoint(&self) -> &OutPoint { self.get_channel_parameters().funding_outpoint.as_ref().unwrap() }
	/// Returns a [`ChannelTransactionParameters`] for this channel, to be used when verifying or
	/// building transactions.
	///
	/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
	pub fn get_channel_parameters(&self) -> &ChannelTransactionParameters {
		self.channel_parameters.as_ref().unwrap()
	}
	/// Returns whether anchors should be used.
	///
	/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
	pub fn opt_anchors(&self) -> bool {
		self.get_channel_parameters().opt_anchors.is_some()
	}
	/// Sign the single input of `spend_tx` at index `input_idx`, which spends the output described
	/// by `descriptor`, returning the witness stack for the input.
	///
	/// Returns an error if the input at `input_idx` does not exist, has a non-empty `script_sig`,
	/// is not spending the outpoint described by [`descriptor.outpoint`],
	/// or if an output descriptor `script_pubkey` does not match the one we can spend.
	///
	/// [`descriptor.outpoint`]: StaticPaymentOutputDescriptor::outpoint
	pub fn sign_counterparty_payment_input<C: Signing>(&self, spend_tx: &Transaction, input_idx: usize, descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<C>) -> Result<Vec<Vec<u8>>, ()> {
		// TODO: We really should be taking the SigHashCache as a parameter here instead of
		// spend_tx, but ideally the SigHashCache would expose the transaction's inputs read-only
		// so that we can check them. This requires upstream rust-bitcoin changes (as well as
		// bindings updates to support SigHashCache objects).
		if spend_tx.input.len() <= input_idx { return Err(()); }
		if !spend_tx.input[input_idx].script_sig.is_empty() { return Err(()); }
		if spend_tx.input[input_idx].previous_output != descriptor.outpoint.into_bitcoin_outpoint() { return Err(()); }

		let remotepubkey = self.pubkeys().payment_point;
		let witness_script = bitcoin::Address::p2pkh(&::bitcoin::PublicKey{compressed: true, inner: remotepubkey}, Network::Testnet).script_pubkey();
		let sighash = hash_to_message!(&sighash::SighashCache::new(spend_tx).segwit_signature_hash(input_idx, &witness_script, descriptor.output.value, EcdsaSighashType::All).unwrap()[..]);
		let remotesig = sign(secp_ctx, &sighash, &self.payment_key);
		let payment_script = bitcoin::Address::p2wpkh(&::bitcoin::PublicKey{compressed: true, inner: remotepubkey}, Network::Bitcoin).unwrap().script_pubkey();

		if payment_script != descriptor.output.script_pubkey { return Err(()); }

		let mut witness = Vec::with_capacity(2);
		witness.push(remotesig.serialize_der().to_vec());
		witness[0].push(EcdsaSighashType::All as u8);
		witness.push(remotepubkey.serialize().to_vec());
		Ok(witness)
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
	pub fn sign_dynamic_p2wsh_input<C: Signing>(&self, spend_tx: &Transaction, input_idx: usize, descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<C>) -> Result<Vec<Vec<u8>>, ()> {
		// TODO: We really should be taking the SigHashCache as a parameter here instead of
		// spend_tx, but ideally the SigHashCache would expose the transaction's inputs read-only
		// so that we can check them. This requires upstream rust-bitcoin changes (as well as
		// bindings updates to support SigHashCache objects).
		if spend_tx.input.len() <= input_idx { return Err(()); }
		if !spend_tx.input[input_idx].script_sig.is_empty() { return Err(()); }
		if spend_tx.input[input_idx].previous_output != descriptor.outpoint.into_bitcoin_outpoint() { return Err(()); }
		if spend_tx.input[input_idx].sequence.0 != descriptor.to_self_delay as u32 { return Err(()); }

		let delayed_payment_key = chan_utils::derive_private_key(&secp_ctx, &descriptor.per_commitment_point, &self.delayed_payment_base_key);
		let delayed_payment_pubkey = PublicKey::from_secret_key(&secp_ctx, &delayed_payment_key);
		let witness_script = chan_utils::get_revokeable_redeemscript(&descriptor.revocation_pubkey, descriptor.to_self_delay, &delayed_payment_pubkey);
		let sighash = hash_to_message!(&sighash::SighashCache::new(spend_tx).segwit_signature_hash(input_idx, &witness_script, descriptor.output.value, EcdsaSighashType::All).unwrap()[..]);
		let local_delayedsig = sign(secp_ctx, &sighash, &delayed_payment_key);
		let payment_script = bitcoin::Address::p2wsh(&witness_script, Network::Bitcoin).script_pubkey();

		if descriptor.output.script_pubkey != payment_script { return Err(()); }

		let mut witness = Vec::with_capacity(3);
		witness.push(local_delayedsig.serialize_der().to_vec());
		witness[0].push(EcdsaSighashType::All as u8);
		witness.push(vec!()); //MINIMALIF
		witness.push(witness_script.clone().into_bytes());
		Ok(witness)
	}
}

impl ChannelSigner for InMemorySigner {
	fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> PublicKey {
		let commitment_secret = SecretKey::from_slice(&chan_utils::build_commitment_secret(&self.commitment_seed, idx)).unwrap();
		PublicKey::from_secret_key(secp_ctx, &commitment_secret)
	}

	fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
		chan_utils::build_commitment_secret(&self.commitment_seed, idx)
	}

	fn validate_holder_commitment(&self, _holder_tx: &HolderCommitmentTransaction, _preimages: Vec<PaymentPreimage>) -> Result<(), ()> {
		Ok(())
	}

	fn pubkeys(&self) -> &ChannelPublicKeys { &self.holder_channel_pubkeys }

	fn channel_keys_id(&self) -> [u8; 32] { self.channel_keys_id }

	fn provide_channel_parameters(&mut self, channel_parameters: &ChannelTransactionParameters) {
		assert!(self.channel_parameters.is_none() || self.channel_parameters.as_ref().unwrap() == channel_parameters);
		if self.channel_parameters.is_some() {
			// The channel parameters were already set and they match, return early.
			return;
		}
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");
		self.channel_parameters = Some(channel_parameters.clone());
	}
}

impl EcdsaChannelSigner for InMemorySigner {
	fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction, _preimages: Vec<PaymentPreimage>, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		let trusted_tx = commitment_tx.trust();
		let keys = trusted_tx.keys();

		let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &self.funding_key);
		let channel_funding_redeemscript = make_funding_redeemscript(&funding_pubkey, &self.counterparty_pubkeys().funding_pubkey);

		let built_tx = trusted_tx.built_transaction();
		let commitment_sig = built_tx.sign(&self.funding_key, &channel_funding_redeemscript, self.channel_value_satoshis, secp_ctx);
		let commitment_txid = built_tx.txid;

		let mut htlc_sigs = Vec::with_capacity(commitment_tx.htlcs().len());
		for htlc in commitment_tx.htlcs() {
			let channel_parameters = self.get_channel_parameters();
			let htlc_tx = chan_utils::build_htlc_transaction(&commitment_txid, commitment_tx.feerate_per_kw(), self.holder_selected_contest_delay(), htlc, self.opt_anchors(), channel_parameters.opt_non_zero_fee_anchors.is_some(), &keys.broadcaster_delayed_payment_key, &keys.revocation_key);
			let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, self.opt_anchors(), &keys);
			let htlc_sighashtype = if self.opt_anchors() { EcdsaSighashType::SinglePlusAnyoneCanPay } else { EcdsaSighashType::All };
			let htlc_sighash = hash_to_message!(&sighash::SighashCache::new(&htlc_tx).segwit_signature_hash(0, &htlc_redeemscript, htlc.amount_msat / 1000, htlc_sighashtype).unwrap()[..]);
			let holder_htlc_key = chan_utils::derive_private_key(&secp_ctx, &keys.per_commitment_point, &self.htlc_base_key);
			htlc_sigs.push(sign(secp_ctx, &htlc_sighash, &holder_htlc_key));
		}

		Ok((commitment_sig, htlc_sigs))
	}

	fn validate_counterparty_revocation(&self, _idx: u64, _secret: &SecretKey) -> Result<(), ()> {
		Ok(())
	}

	fn sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &self.funding_key);
		let funding_redeemscript = make_funding_redeemscript(&funding_pubkey, &self.counterparty_pubkeys().funding_pubkey);
		let trusted_tx = commitment_tx.trust();
		let sig = trusted_tx.built_transaction().sign(&self.funding_key, &funding_redeemscript, self.channel_value_satoshis, secp_ctx);
		let channel_parameters = self.get_channel_parameters();
		let htlc_sigs = trusted_tx.get_htlc_sigs(&self.htlc_base_key, &channel_parameters.as_holder_broadcastable(), secp_ctx)?;
		Ok((sig, htlc_sigs))
	}

	#[cfg(any(test,feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &self.funding_key);
		let funding_redeemscript = make_funding_redeemscript(&funding_pubkey, &self.counterparty_pubkeys().funding_pubkey);
		let trusted_tx = commitment_tx.trust();
		let sig = trusted_tx.built_transaction().sign(&self.funding_key, &funding_redeemscript, self.channel_value_satoshis, secp_ctx);
		let channel_parameters = self.get_channel_parameters();
		let htlc_sigs = trusted_tx.get_htlc_sigs(&self.htlc_base_key, &channel_parameters.as_holder_broadcastable(), secp_ctx)?;
		Ok((sig, htlc_sigs))
	}

	fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		let revocation_key = chan_utils::derive_private_revocation_key(&secp_ctx, &per_commitment_key, &self.revocation_base_key);
		let per_commitment_point = PublicKey::from_secret_key(secp_ctx, &per_commitment_key);
		let revocation_pubkey = chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &self.pubkeys().revocation_basepoint);
		let witness_script = {
			let counterparty_delayedpubkey = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.counterparty_pubkeys().delayed_payment_basepoint);
			chan_utils::get_revokeable_redeemscript(&revocation_pubkey, self.holder_selected_contest_delay(), &counterparty_delayedpubkey)
		};
		let mut sighash_parts = sighash::SighashCache::new(justice_tx);
		let sighash = hash_to_message!(&sighash_parts.segwit_signature_hash(input, &witness_script, amount, EcdsaSighashType::All).unwrap()[..]);
		return Ok(sign(secp_ctx, &sighash, &revocation_key))
	}

	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		let revocation_key = chan_utils::derive_private_revocation_key(&secp_ctx, &per_commitment_key, &self.revocation_base_key);
		let per_commitment_point = PublicKey::from_secret_key(secp_ctx, &per_commitment_key);
		let revocation_pubkey = chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &self.pubkeys().revocation_basepoint);
		let witness_script = {
			let counterparty_htlcpubkey = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.counterparty_pubkeys().htlc_basepoint);
			let holder_htlcpubkey = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.pubkeys().htlc_basepoint);
			chan_utils::get_htlc_redeemscript_with_explicit_keys(&htlc, self.opt_anchors(), &counterparty_htlcpubkey, &holder_htlcpubkey, &revocation_pubkey)
		};
		let mut sighash_parts = sighash::SighashCache::new(justice_tx);
		let sighash = hash_to_message!(&sighash_parts.segwit_signature_hash(input, &witness_script, amount, EcdsaSighashType::All).unwrap()[..]);
		return Ok(sign(secp_ctx, &sighash, &revocation_key))
	}

	#[cfg(anchors)]
	fn sign_holder_htlc_transaction(
		&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor,
		secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()> {
		let per_commitment_point = self.get_per_commitment_point(
			htlc_descriptor.per_commitment_number, &secp_ctx
		);
		let witness_script = htlc_descriptor.witness_script(&per_commitment_point, secp_ctx);
		let sighash = &sighash::SighashCache::new(&*htlc_tx).segwit_signature_hash(
			input, &witness_script, htlc_descriptor.htlc.amount_msat / 1000, EcdsaSighashType::All
		).map_err(|_| ())?;
		let our_htlc_private_key = chan_utils::derive_private_key(
			&secp_ctx, &per_commitment_point, &self.htlc_base_key
		);
		Ok(sign(&secp_ctx, &hash_to_message!(sighash), &our_htlc_private_key))
	}

	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		let htlc_key = chan_utils::derive_private_key(&secp_ctx, &per_commitment_point, &self.htlc_base_key);
		let revocation_pubkey = chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &self.pubkeys().revocation_basepoint);
		let counterparty_htlcpubkey = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.counterparty_pubkeys().htlc_basepoint);
		let htlcpubkey = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.pubkeys().htlc_basepoint);
		let witness_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&htlc, self.opt_anchors(), &counterparty_htlcpubkey, &htlcpubkey, &revocation_pubkey);
		let mut sighash_parts = sighash::SighashCache::new(htlc_tx);
		let sighash = hash_to_message!(&sighash_parts.segwit_signature_hash(input, &witness_script, amount, EcdsaSighashType::All).unwrap()[..]);
		Ok(sign(secp_ctx, &sighash, &htlc_key))
	}

	fn sign_closing_transaction(&self, closing_tx: &ClosingTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &self.funding_key);
		let channel_funding_redeemscript = make_funding_redeemscript(&funding_pubkey, &self.counterparty_pubkeys().funding_pubkey);
		Ok(closing_tx.trust().sign(&self.funding_key, &channel_funding_redeemscript, self.channel_value_satoshis, secp_ctx))
	}

	fn sign_holder_anchor_input(
		&self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<Signature, ()> {
		let witness_script = chan_utils::get_anchor_redeemscript(&self.holder_channel_pubkeys.funding_pubkey);
		let sighash = sighash::SighashCache::new(&*anchor_tx).segwit_signature_hash(
			input, &witness_script, ANCHOR_OUTPUT_VALUE_SATOSHI, EcdsaSighashType::All,
		).unwrap();
		Ok(sign(secp_ctx, &hash_to_message!(&sighash[..]), &self.funding_key))
	}

	fn sign_channel_announcement_with_funding_key(
		&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>
	) -> Result<Signature, ()> {
		let msghash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
		Ok(sign(secp_ctx, &msghash, &self.funding_key))
	}
}

const SERIALIZATION_VERSION: u8 = 1;

const MIN_SERIALIZATION_VERSION: u8 = 1;

impl WriteableEcdsaChannelSigner for InMemorySigner {}

impl Writeable for InMemorySigner {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);

		self.funding_key.write(writer)?;
		self.revocation_base_key.write(writer)?;
		self.payment_key.write(writer)?;
		self.delayed_payment_base_key.write(writer)?;
		self.htlc_base_key.write(writer)?;
		self.commitment_seed.write(writer)?;
		self.channel_parameters.write(writer)?;
		self.channel_value_satoshis.write(writer)?;
		self.channel_keys_id.write(writer)?;

		write_tlv_fields!(writer, {});

		Ok(())
	}
}

impl Readable for InMemorySigner {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		let funding_key = Readable::read(reader)?;
		let revocation_base_key = Readable::read(reader)?;
		let payment_key = Readable::read(reader)?;
		let delayed_payment_base_key = Readable::read(reader)?;
		let htlc_base_key = Readable::read(reader)?;
		let commitment_seed = Readable::read(reader)?;
		let counterparty_channel_data = Readable::read(reader)?;
		let channel_value_satoshis = Readable::read(reader)?;
		let secp_ctx = Secp256k1::signing_only();
		let holder_channel_pubkeys =
			InMemorySigner::make_holder_keys(&secp_ctx, &funding_key, &revocation_base_key,
				 &payment_key, &delayed_payment_base_key, &htlc_base_key);
		let keys_id = Readable::read(reader)?;

		read_tlv_fields!(reader, {});

		Ok(InMemorySigner {
			funding_key,
			revocation_base_key,
			payment_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			channel_value_satoshis,
			holder_channel_pubkeys,
			channel_parameters: counterparty_channel_data,
			channel_keys_id: keys_id,
		})
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
	inbound_payment_key: KeyMaterial,
	destination_script: Script,
	shutdown_pubkey: PublicKey,
	channel_master_key: ExtendedPrivKey,
	channel_child_index: AtomicUsize,

	rand_bytes_unique_start: [u8; 32],
	rand_bytes_index: AtomicCounter,

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
		let secp_ctx = Secp256k1::new();
		// Note that when we aren't serializing the key, network doesn't matter
		match ExtendedPrivKey::new_master(Network::Testnet, seed) {
			Ok(master_key) => {
				let node_secret = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(0).unwrap()).expect("Your RNG is busted").private_key;
				let node_id = PublicKey::from_secret_key(&secp_ctx, &node_secret);
				let destination_script = match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(1).unwrap()) {
					Ok(destination_key) => {
						let wpubkey_hash = WPubkeyHash::hash(&ExtendedPubKey::from_priv(&secp_ctx, &destination_key).to_pub().to_bytes());
						Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
							.push_slice(&wpubkey_hash.into_inner())
							.into_script()
					},
					Err(_) => panic!("Your RNG is busted"),
				};
				let shutdown_pubkey = match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(2).unwrap()) {
					Ok(shutdown_key) => ExtendedPubKey::from_priv(&secp_ctx, &shutdown_key).public_key,
					Err(_) => panic!("Your RNG is busted"),
				};
				let channel_master_key = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(3).unwrap()).expect("Your RNG is busted");
				let inbound_payment_key: SecretKey = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(5).unwrap()).expect("Your RNG is busted").private_key;
				let mut inbound_pmt_key_bytes = [0; 32];
				inbound_pmt_key_bytes.copy_from_slice(&inbound_payment_key[..]);

				let mut rand_bytes_engine = Sha256::engine();
				rand_bytes_engine.input(&starting_time_secs.to_be_bytes());
				rand_bytes_engine.input(&starting_time_nanos.to_be_bytes());
				rand_bytes_engine.input(seed);
				rand_bytes_engine.input(b"LDK PRNG Seed");
				let rand_bytes_unique_start = Sha256::from_engine(rand_bytes_engine).into_inner();

				let mut res = KeysManager {
					secp_ctx,
					node_secret,
					node_id,
					inbound_payment_key: KeyMaterial(inbound_pmt_key_bytes),

					destination_script,
					shutdown_pubkey,

					channel_master_key,
					channel_child_index: AtomicUsize::new(0),

					rand_bytes_unique_start,
					rand_bytes_index: AtomicCounter::new(),

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

	/// Derive an old [`WriteableEcdsaChannelSigner`] containing per-channel secrets based on a key derivation parameters.
	pub fn derive_channel_keys(&self, channel_value_satoshis: u64, params: &[u8; 32]) -> InMemorySigner {
		let chan_id = u64::from_be_bytes(params[0..8].try_into().unwrap());
		let mut unique_start = Sha256::engine();
		unique_start.input(params);
		unique_start.input(&self.seed);

		// We only seriously intend to rely on the channel_master_key for true secure
		// entropy, everything else just ensures uniqueness. We rely on the unique_start (ie
		// starting_time provided in the constructor) to be unique.
		let child_privkey = self.channel_master_key.ckd_priv(&self.secp_ctx,
				ChildNumber::from_hardened_idx((chan_id as u32) % (1 << 31)).expect("key space exhausted")
			).expect("Your RNG is busted");
		unique_start.input(&child_privkey.private_key[..]);

		let seed = Sha256::from_engine(unique_start).into_inner();

		let commitment_seed = {
			let mut sha = Sha256::engine();
			sha.input(&seed);
			sha.input(&b"commitment seed"[..]);
			Sha256::from_engine(sha).into_inner()
		};
		macro_rules! key_step {
			($info: expr, $prev_key: expr) => {{
				let mut sha = Sha256::engine();
				sha.input(&seed);
				sha.input(&$prev_key[..]);
				sha.input(&$info[..]);
				SecretKey::from_slice(&Sha256::from_engine(sha).into_inner()).expect("SHA-256 is busted")
			}}
		}
		let funding_key = key_step!(b"funding key", commitment_seed);
		let revocation_base_key = key_step!(b"revocation base key", funding_key);
		let payment_key = key_step!(b"payment key", revocation_base_key);
		let delayed_payment_base_key = key_step!(b"delayed payment base key", payment_key);
		let htlc_base_key = key_step!(b"HTLC base key", delayed_payment_base_key);

		InMemorySigner::new(
			&self.secp_ctx,
			funding_key,
			revocation_base_key,
			payment_key,
			delayed_payment_base_key,
			htlc_base_key,
			commitment_seed,
			channel_value_satoshis,
			params.clone(),
		)
	}

	/// Creates a [`Transaction`] which spends the given descriptors to the given outputs, plus an
	/// output to the given change destination (if sufficient change value remains). The
	/// transaction will have a feerate, at least, of the given value.
	///
	/// Returns `Err(())` if the output value is greater than the input value minus required fee,
	/// if a descriptor was duplicated, or if an output descriptor `script_pubkey`
	/// does not match the one we can spend.
	///
	/// We do not enforce that outputs meet the dust limit or that any output scripts are standard.
	///
	/// May panic if the [`SpendableOutputDescriptor`]s were not generated by channels which used
	/// this [`KeysManager`] or one of the [`InMemorySigner`] created by this [`KeysManager`].
	pub fn spend_spendable_outputs<C: Signing>(&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>, change_destination_script: Script, feerate_sat_per_1000_weight: u32, secp_ctx: &Secp256k1<C>) -> Result<Transaction, ()> {
		let mut input = Vec::new();
		let mut input_value = 0;
		let mut witness_weight = 0;
		let mut output_set = HashSet::with_capacity(descriptors.len());
		for outp in descriptors {
			match outp {
				SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
					input.push(TxIn {
						previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
						script_sig: Script::new(),
						sequence: Sequence::ZERO,
						witness: Witness::new(),
					});
					witness_weight += StaticPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
					input_value += descriptor.output.value;
					if !output_set.insert(descriptor.outpoint) { return Err(()); }
				},
				SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
					input.push(TxIn {
						previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
						script_sig: Script::new(),
						sequence: Sequence(descriptor.to_self_delay as u32),
						witness: Witness::new(),
					});
					witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
					input_value += descriptor.output.value;
					if !output_set.insert(descriptor.outpoint) { return Err(()); }
				},
				SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output } => {
					input.push(TxIn {
						previous_output: outpoint.into_bitcoin_outpoint(),
						script_sig: Script::new(),
						sequence: Sequence::ZERO,
						witness: Witness::new(),
					});
					witness_weight += 1 + 73 + 34;
					input_value += output.value;
					if !output_set.insert(*outpoint) { return Err(()); }
				}
			}
			if input_value > MAX_VALUE_MSAT / 1000 { return Err(()); }
		}
		let mut spend_tx = Transaction {
			version: 2,
			lock_time: PackedLockTime(0),
			input,
			output: outputs,
		};
		let expected_max_weight =
			transaction_utils::maybe_add_change_output(&mut spend_tx, input_value, witness_weight, feerate_sat_per_1000_weight, change_destination_script)?;

		let mut keys_cache: Option<(InMemorySigner, [u8; 32])> = None;
		let mut input_idx = 0;
		for outp in descriptors {
			match outp {
				SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
					if keys_cache.is_none() || keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id {
						keys_cache = Some((
							self.derive_channel_keys(descriptor.channel_value_satoshis, &descriptor.channel_keys_id),
							descriptor.channel_keys_id));
					}
					spend_tx.input[input_idx].witness = Witness::from_vec(keys_cache.as_ref().unwrap().0.sign_counterparty_payment_input(&spend_tx, input_idx, &descriptor, &secp_ctx)?);
				},
				SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
					if keys_cache.is_none() || keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id {
						keys_cache = Some((
							self.derive_channel_keys(descriptor.channel_value_satoshis, &descriptor.channel_keys_id),
							descriptor.channel_keys_id));
					}
					spend_tx.input[input_idx].witness = Witness::from_vec(keys_cache.as_ref().unwrap().0.sign_dynamic_p2wsh_input(&spend_tx, input_idx, &descriptor, &secp_ctx)?);
				},
				SpendableOutputDescriptor::StaticOutput { ref output, .. } => {
					let derivation_idx = if output.script_pubkey == self.destination_script {
						1
					} else {
						2
					};
					let secret = {
						// Note that when we aren't serializing the key, network doesn't matter
						match ExtendedPrivKey::new_master(Network::Testnet, &self.seed) {
							Ok(master_key) => {
								match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(derivation_idx).expect("key space exhausted")) {
									Ok(key) => key,
									Err(_) => panic!("Your RNG is busted"),
								}
							}
							Err(_) => panic!("Your rng is busted"),
						}
					};
					let pubkey = ExtendedPubKey::from_priv(&secp_ctx, &secret).to_pub();
					if derivation_idx == 2 {
						assert_eq!(pubkey.inner, self.shutdown_pubkey);
					}
					let witness_script = bitcoin::Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
					let payment_script = bitcoin::Address::p2wpkh(&pubkey, Network::Testnet).expect("uncompressed key found").script_pubkey();

					if payment_script != output.script_pubkey { return Err(()); };

					let sighash = hash_to_message!(&sighash::SighashCache::new(&spend_tx).segwit_signature_hash(input_idx, &witness_script, output.value, EcdsaSighashType::All).unwrap()[..]);
					let sig = sign(secp_ctx, &sighash, &secret.private_key);
					let mut sig_ser = sig.serialize_der().to_vec();
					sig_ser.push(EcdsaSighashType::All as u8);
					spend_tx.input[input_idx].witness.push(sig_ser);
					spend_tx.input[input_idx].witness.push(pubkey.inner.serialize().to_vec());
				},
			}
			input_idx += 1;
		}

		debug_assert!(expected_max_weight >= spend_tx.weight());
		// Note that witnesses with a signature vary somewhat in size, so allow
		// `expected_max_weight` to overshoot by up to 3 bytes per input.
		debug_assert!(expected_max_weight <= spend_tx.weight() + descriptors.len() * 3);

		Ok(spend_tx)
	}
}

impl EntropySource for KeysManager {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let index = self.rand_bytes_index.get_increment();
		let mut nonce = [0u8; 16];
		nonce[..8].copy_from_slice(&index.to_be_bytes());
		ChaCha20::get_single_block(&self.rand_bytes_unique_start, &nonce)
	}
}

impl NodeSigner for KeysManager {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		match recipient {
			Recipient::Node => Ok(self.node_id.clone()),
			Recipient::PhantomNode => Err(())
		}
	}

	fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(())
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.inbound_payment_key.clone()
	}

	fn sign_invoice(&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient) -> Result<RecoverableSignature, ()> {
		let preimage = construct_invoice_preimage(&hrp_bytes, &invoice_data);
		let secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(())
		}?;
		Ok(self.secp_ctx.sign_ecdsa_recoverable(&hash_to_message!(&Sha256::hash(&preimage)), secret))
	}

	fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
		let msg_hash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
		Ok(sign(&self.secp_ctx, &msg_hash, &self.node_secret))
	}
}

impl SignerProvider for KeysManager {
	type Signer = InMemorySigner;

	fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, user_channel_id: u128) -> [u8; 32] {
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

	fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> Self::Signer {
		self.derive_channel_keys(channel_value_satoshis, &channel_keys_id)
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		InMemorySigner::read(&mut io::Cursor::new(reader))
	}

	fn get_destination_script(&self) -> Script {
		self.destination_script.clone()
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
		ShutdownScript::new_p2wpkh_from_pubkey(self.shutdown_pubkey.clone())
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
	inner: KeysManager,
	inbound_payment_key: KeyMaterial,
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

	fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => self.inner.node_secret.clone(),
			Recipient::PhantomNode => self.phantom_secret.clone(),
		};
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		self.inbound_payment_key.clone()
	}

	fn sign_invoice(&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient) -> Result<RecoverableSignature, ()> {
		let preimage = construct_invoice_preimage(&hrp_bytes, &invoice_data);
		let secret = match recipient {
			Recipient::Node => &self.inner.node_secret,
			Recipient::PhantomNode => &self.phantom_secret,
		};
		Ok(self.inner.secp_ctx.sign_ecdsa_recoverable(&hash_to_message!(&Sha256::hash(&preimage)), secret))
	}

	fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
		self.inner.sign_gossip_message(msg)
	}
}

impl SignerProvider for PhantomKeysManager {
	type Signer = InMemorySigner;

	fn generate_channel_keys_id(&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128) -> [u8; 32] {
		self.inner.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
	}

	fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> Self::Signer {
		self.inner.derive_channel_signer(channel_value_satoshis, channel_keys_id)
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		self.inner.read_chan_signer(reader)
	}

	fn get_destination_script(&self) -> Script {
		self.inner.get_destination_script()
	}

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
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
	pub fn new(seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32, cross_node_seed: &[u8; 32]) -> Self {
		let inner = KeysManager::new(seed, starting_time_secs, starting_time_nanos);
		let (inbound_key, phantom_key) = hkdf_extract_expand_twice(b"LDK Inbound and Phantom Payment Key Expansion", cross_node_seed);
		let phantom_secret = SecretKey::from_slice(&phantom_key).unwrap();
		let phantom_node_id = PublicKey::from_secret_key(&inner.secp_ctx, &phantom_secret);
		Self {
			inner,
			inbound_payment_key: KeyMaterial(inbound_key),
			phantom_secret,
			phantom_node_id,
		}
	}

	/// See [`KeysManager::spend_spendable_outputs`] for documentation on this method.
	pub fn spend_spendable_outputs<C: Signing>(&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>, change_destination_script: Script, feerate_sat_per_1000_weight: u32, secp_ctx: &Secp256k1<C>) -> Result<Transaction, ()> {
		self.inner.spend_spendable_outputs(descriptors, outputs, change_destination_script, feerate_sat_per_1000_weight, secp_ctx)
	}

	/// See [`KeysManager::derive_channel_keys`] for documentation on this method.
	pub fn derive_channel_keys(&self, channel_value_satoshis: u64, params: &[u8; 32]) -> InMemorySigner {
		self.inner.derive_channel_keys(channel_value_satoshis, params)
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

// Ensure that EcdsaChannelSigner can have a vtable
#[test]
pub fn dyn_sign() {
	let _signer: Box<dyn EcdsaChannelSigner>;
}

#[cfg(all(test, feature = "_bench_unstable", not(feature = "no-std")))]
mod benches {
	use std::sync::{Arc, mpsc};
	use std::sync::mpsc::TryRecvError;
	use std::thread;
	use std::time::Duration;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::Network;
	use crate::chain::keysinterface::{EntropySource, KeysManager};

	use test::Bencher;

	#[bench]
	fn bench_get_secure_random_bytes(bench: &mut Bencher) {
		let seed = [0u8; 32];
		let now = Duration::from_secs(genesis_block(Network::Testnet).header.time as u64);
		let keys_manager = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_micros()));

		let mut handles = Vec::new();
		let mut stops = Vec::new();
		for _ in 1..5 {
			let keys_manager_clone = Arc::clone(&keys_manager);
			let (stop_sender, stop_receiver) = mpsc::channel();
			let handle = thread::spawn(move || {
				loop {
					keys_manager_clone.get_secure_random_bytes();
					match stop_receiver.try_recv() {
						Ok(_) | Err(TryRecvError::Disconnected) => {
							println!("Terminating.");
							break;
						}
						Err(TryRecvError::Empty) => {}
					}
				}
			});
			handles.push(handle);
			stops.push(stop_sender);
		}

		bench.iter(|| {
			for _ in 1..100 {
				keys_manager.get_secure_random_bytes();
			}
		});

		for stop in stops {
			let _ = stop.send(());
		}
		for handle in handles {
			handle.join().unwrap();
		}
	}

}
