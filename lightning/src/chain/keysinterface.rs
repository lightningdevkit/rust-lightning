// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! keysinterface provides keys into rust-lightning and defines some useful enums which describe
//! spendable on-chain outputs which the user owns and is responsible for using just as any other
//! on-chain output which is theirs.

use bitcoin::blockdata::transaction::{Transaction, TxOut, TxIn, SigHashType};
use bitcoin::blockdata::script::{Script, Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, ChildNumber};
use bitcoin::util::bip143;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::HashEngine as Sha256State;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hash_types::WPubkeyHash;

use bitcoin::secp256k1::key::{SecretKey, PublicKey};
use bitcoin::secp256k1::{Secp256k1, Signature, Signing};
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1;

use util::{byte_utils, transaction_utils};
use util::ser::{Writeable, Writer, Readable};

use chain::transaction::OutPoint;
use ln::chan_utils;
use ln::chan_utils::{HTLCOutputInCommitment, make_funding_redeemscript, ChannelPublicKeys, HolderCommitmentTransaction, ChannelTransactionParameters, CommitmentTransaction};
use ln::msgs::UnsignedChannelAnnouncement;

use prelude::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use io::{self, Error};
use ln::msgs::{DecodeError, MAX_VALUE_MSAT};

/// Information about a spendable output to a P2WSH script. See
/// SpendableOutputDescriptor::DelayedPaymentOutput for more details on how to spend this.
#[derive(Clone, Debug, PartialEq)]
pub struct DelayedPaymentOutputDescriptor {
	/// The outpoint which is spendable
	pub outpoint: OutPoint,
	/// Per commitment point to derive delayed_payment_key by key holder
	pub per_commitment_point: PublicKey,
	/// The nSequence value which must be set in the spending input to satisfy the OP_CSV in
	/// the witness_script.
	pub to_self_delay: u16,
	/// The output which is referenced by the given outpoint
	pub output: TxOut,
	/// The revocation point specific to the commitment transaction which was broadcast. Used to
	/// derive the witnessScript for this output.
	pub revocation_pubkey: PublicKey,
	/// Arbitrary identification information returned by a call to
	/// `Sign::channel_keys_id()`. This may be useful in re-deriving keys used in
	/// the channel to spend the output.
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

/// Information about a spendable output to our "payment key". See
/// SpendableOutputDescriptor::StaticPaymentOutput for more details on how to spend this.
#[derive(Clone, Debug, PartialEq)]
pub struct StaticPaymentOutputDescriptor {
	/// The outpoint which is spendable
	pub outpoint: OutPoint,
	/// The output which is referenced by the given outpoint
	pub output: TxOut,
	/// Arbitrary identification information returned by a call to
	/// `Sign::channel_keys_id()`. This may be useful in re-deriving keys used in
	/// the channel to spend the output.
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

/// When on-chain outputs are created by rust-lightning (which our counterparty is not able to
/// claim at any point in the future) an event is generated which you must track and be able to
/// spend on-chain. The information needed to do this is provided in this enum, including the
/// outpoint describing which txid and output index is available, the full output which exists at
/// that txid/index, and any keys or other information required to sign.
#[derive(Clone, Debug, PartialEq)]
pub enum SpendableOutputDescriptor {
	/// An output to a script which was provided via KeysInterface directly, either from
	/// `get_destination_script()` or `get_shutdown_pubkey()`, thus you should already know how to
	/// spend it. No secret keys are provided as rust-lightning was never given any key.
	/// These may include outputs from a transaction punishing our counterparty or claiming an HTLC
	/// on-chain using the payment preimage or after it has timed out.
	StaticOutput {
		/// The outpoint which is spendable
		outpoint: OutPoint,
		/// The output which is referenced by the given outpoint.
		output: TxOut,
	},
	/// An output to a P2WSH script which can be spent with a single signature after a CSV delay.
	///
	/// The witness in the spending input should be:
	/// <BIP 143 signature> <empty vector> (MINIMALIF standard rule) <provided witnessScript>
	///
	/// Note that the nSequence field in the spending input must be set to to_self_delay
	/// (which means the transaction is not broadcastable until at least to_self_delay
	/// blocks after the outpoint confirms).
	///
	/// These are generally the result of a "revocable" output to us, spendable only by us unless
	/// it is an output from an old state which we broadcast (which should never happen).
	///
	/// To derive the delayed_payment key which is used to sign for this input, you must pass the
	/// holder delayed_payment_base_key (ie the private key which corresponds to the pubkey in
	/// Sign::pubkeys().delayed_payment_basepoint) and the provided per_commitment_point to
	/// chan_utils::derive_private_key. The public key can be generated without the secret key
	/// using chan_utils::derive_public_key and only the delayed_payment_basepoint which appears in
	/// Sign::pubkeys().
	///
	/// To derive the revocation_pubkey provided here (which is used in the witness
	/// script generation), you must pass the counterparty revocation_basepoint (which appears in the
	/// call to Sign::ready_channel) and the provided per_commitment point
	/// to chan_utils::derive_public_revocation_key.
	///
	/// The witness script which is hashed and included in the output script_pubkey may be
	/// regenerated by passing the revocation_pubkey (derived as above), our delayed_payment pubkey
	/// (derived as above), and the to_self_delay contained here to
	/// chan_utils::get_revokeable_redeemscript.
	DelayedPaymentOutput(DelayedPaymentOutputDescriptor),
	/// An output to a P2WPKH, spendable exclusively by our payment key (ie the private key which
	/// corresponds to the public key in Sign::pubkeys().payment_point).
	/// The witness in the spending input, is, thus, simply:
	/// <BIP 143 signature> <payment key>
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

/// A trait to sign lightning channel transactions as described in BOLT 3.
///
/// Signing services could be implemented on a hardware wallet. In this case,
/// the current Sign would be a front-end on top of a communication
/// channel connected to your secure device and lightning key material wouldn't
/// reside on a hot server. Nevertheless, a this deployment would still need
/// to trust the ChannelManager to avoid loss of funds as this latest component
/// could ask to sign commitment transaction with HTLCs paying to attacker pubkeys.
///
/// A more secure iteration would be to use hashlock (or payment points) to pair
/// invoice/incoming HTLCs with outgoing HTLCs to implement a no-trust-ChannelManager
/// at the price of more state and computation on the hardware wallet side. In the future,
/// we are looking forward to design such interface.
///
/// In any case, ChannelMonitor or fallback watchtowers are always going to be trusted
/// to act, as liveness and breach reply correctness are always going to be hard requirements
/// of LN security model, orthogonal of key management issues.
// TODO: We should remove Clone by instead requesting a new Sign copy when we create
// ChannelMonitors instead of expecting to clone the one out of the Channel into the monitors.
pub trait BaseSign {
	/// Gets the per-commitment point for a specific commitment number
	///
	/// Note that the commitment number starts at (1 << 48) - 1 and counts backwards.
	fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> PublicKey;
	/// Gets the commitment secret for a specific commitment number as part of the revocation process
	///
	/// An external signer implementation should error here if the commitment was already signed
	/// and should refuse to sign it in the future.
	///
	/// May be called more than once for the same index.
	///
	/// Note that the commitment number starts at (1 << 48) - 1 and counts backwards.
	// TODO: return a Result so we can signal a validation error
	fn release_commitment_secret(&self, idx: u64) -> [u8; 32];
	/// Gets the holder's channel public keys and basepoints
	fn pubkeys(&self) -> &ChannelPublicKeys;
	/// Gets an arbitrary identifier describing the set of keys which are provided back to you in
	/// some SpendableOutputDescriptor types. This should be sufficient to identify this
	/// Sign object uniquely and lookup or re-derive its keys.
	fn channel_keys_id(&self) -> [u8; 32];

	/// Create a signature for a counterparty's commitment transaction and associated HTLC transactions.
	///
	/// Note that if signing fails or is rejected, the channel will be force-closed.
	//
	// TODO: Document the things someone using this interface should enforce before signing.
	fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()>;

	/// Create a signatures for a holder's commitment transaction and its claiming HTLC transactions.
	/// This will only ever be called with a non-revoked commitment_tx.  This will be called with the
	/// latest commitment_tx when we initiate a force-close.
	/// This will be called with the previous latest, just to get claiming HTLC signatures, if we are
	/// reacting to a ChannelMonitor replica that decided to broadcast before it had been updated to
	/// the latest.
	/// This may be called multiple times for the same transaction.
	///
	/// An external signer implementation should check that the commitment has not been revoked.
	///
	/// May return Err if key derivation fails.  Callers, such as ChannelMonitor, will panic in such a case.
	//
	// TODO: Document the things someone using this interface should enforce before signing.
	// TODO: Key derivation failure should panic rather than Err
	fn sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()>;

	/// Same as sign_holder_commitment, but exists only for tests to get access to holder commitment
	/// transactions which will be broadcasted later, after the channel has moved on to a newer
	/// state. Thus, needs its own method as sign_holder_commitment may enforce that we only ever
	/// get called once.
	#[cfg(any(test,feature = "unsafe_revoked_tx_signing"))]
	fn unsafe_sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()>;

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
	/// per_commitment_key is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder revocation_secret to do
	/// so).
	fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;

	/// Create a signature for the given input in a transaction spending a commitment transaction
	/// HTLC output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// Amount is value of the output spent by this input, committed to in the BIP 143 signature.
	///
	/// per_commitment_key is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder revocation_secret to do
	/// so).
	///
	/// htlc holds HTLC elements (hash, timelock), thus changing the format of the witness script
	/// (which is committed to in the BIP 143 signatures).
	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;

	/// Create a signature for a claiming transaction for a HTLC output on a counterparty's commitment
	/// transaction, either offered or received.
	///
	/// Such a transaction may claim multiples offered outputs at same time if we know the
	/// preimage for each when we create it, but only the input at index `input` should be
	/// signed for here. It may be called multiple times for same output(s) if a fee-bump is
	/// needed with regards to an upcoming timelock expiration.
	///
	/// Witness_script is either a offered or received script as defined in BOLT3 for HTLC
	/// outputs.
	///
	/// Amount is value of the output spent by this input, committed to in the BIP 143 signature.
	///
	/// Per_commitment_point is the dynamic point corresponding to the channel state
	/// detected onchain. It has been generated by our counterparty and is used to derive
	/// channel state keys, which are then included in the witness script and committed to in the
	/// BIP 143 signature.
	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;

	/// Create a signature for a (proposed) closing transaction.
	///
	/// Note that, due to rounding, there may be one "missing" satoshi, and either party may have
	/// chosen to forgo their output as dust.
	fn sign_closing_transaction(&self, closing_tx: &Transaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;

	/// Signs a channel announcement message with our funding key, proving it comes from one
	/// of the channel participants.
	///
	/// Note that if this fails or is rejected, the channel will not be publicly announced and
	/// our counterparty may (though likely will not) close the channel on us for violating the
	/// protocol.
	fn sign_channel_announcement(&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()>;

	/// Set the counterparty static channel data, including basepoints,
	/// counterparty_selected/holder_selected_contest_delay and funding outpoint.
	/// This is done as soon as the funding outpoint is known.  Since these are static channel data,
	/// they MUST NOT be allowed to change to different values once set.
	///
	/// channel_parameters.is_populated() MUST be true.
	///
	/// We bind holder_selected_contest_delay late here for API convenience.
	///
	/// Will be called before any signatures are applied.
	fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters);
}

/// A cloneable signer.
///
/// Although we require signers to be cloneable, it may be useful for developers to be able to use
/// signers in an un-sized way, for example as `dyn BaseSign`. Therefore we separate the Clone trait,
/// which implies Sized, into this derived trait.
pub trait Sign: BaseSign + Writeable + Clone {
}

/// A trait to describe an object which can get user secrets and key material.
pub trait KeysInterface {
	/// A type which implements Sign which will be returned by get_channel_signer.
	type Signer : Sign;

	/// Get node secret key (aka node_id or network_key).
	///
	/// This method must return the same value each time it is called.
	fn get_node_secret(&self) -> SecretKey;
	/// Get a script pubkey which we send funds to when claiming on-chain contestable outputs.
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds across channels as controlled to the same user.
	fn get_destination_script(&self) -> Script;
	/// Get a public key which we will send funds to (in the form of a P2WPKH output) when closing
	/// a channel.
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds across channels as controlled to the same user.
	fn get_shutdown_pubkey(&self) -> PublicKey;
	/// Get a new set of Sign for per-channel secrets. These MUST be unique even if you
	/// restarted with some stale data!
	///
	/// This method must return a different value each time it is called.
	fn get_channel_signer(&self, inbound: bool, channel_value_satoshis: u64) -> Self::Signer;
	/// Gets a unique, cryptographically-secure, random 32 byte value. This is used for encrypting
	/// onion packets and for temporary channel IDs. There is no requirement that these be
	/// persisted anywhere, though they must be unique across restarts.
	///
	/// This method must return a different value each time it is called.
	fn get_secure_random_bytes(&self) -> [u8; 32];

	/// Reads a `Signer` for this `KeysInterface` from the given input stream.
	/// This is only called during deserialization of other objects which contain
	/// `Sign`-implementing objects (ie `ChannelMonitor`s and `ChannelManager`s).
	/// The bytes are exactly those which `<Self::Signer as Writeable>::write()` writes, and
	/// contain no versioning scheme. You may wish to include your own version prefix and ensure
	/// you've read all of the provided bytes to ensure no corruption occurred.
	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError>;

	/// Sign an invoice's preimage (note that this is the preimage of the invoice, not the HTLC's
	/// preimage). By parameterizing by the preimage instead of the hash, we allow implementors of
	/// this trait to parse the invoice and make sure they're signing what they expect, rather than
	/// blindly signing the hash.
	fn sign_invoice(&self, invoice_preimage: Vec<u8>) -> Result<RecoverableSignature, ()>;
}

#[derive(Clone)]
/// A simple implementation of Sign that just keeps the private keys in memory.
///
/// This implementation performs no policy checks and is insufficient by itself as
/// a secure external signer.
pub struct InMemorySigner {
	/// Private key of anchor tx
	pub funding_key: SecretKey,
	/// Holder secret key for blinded revocation pubkey
	pub revocation_base_key: SecretKey,
	/// Holder secret key used for our balance in counterparty-broadcasted commitment transactions
	pub payment_key: SecretKey,
	/// Holder secret key used in HTLC tx
	pub delayed_payment_base_key: SecretKey,
	/// Holder htlc secret key used in commitment tx htlc outputs
	pub htlc_base_key: SecretKey,
	/// Commitment seed
	pub commitment_seed: [u8; 32],
	/// Holder public keys and basepoints
	pub(crate) holder_channel_pubkeys: ChannelPublicKeys,
	/// Counterparty public keys and counterparty/holder selected_contest_delay, populated on channel acceptance
	channel_parameters: Option<ChannelTransactionParameters>,
	/// The total value of this channel
	channel_value_satoshis: u64,
	/// Key derivation parameters
	channel_keys_id: [u8; 32],
}

impl InMemorySigner {
	/// Create a new InMemorySigner
	pub fn new<C: Signing>(
		secp_ctx: &Secp256k1<C>,
		funding_key: SecretKey,
		revocation_base_key: SecretKey,
		payment_key: SecretKey,
		delayed_payment_base_key: SecretKey,
		htlc_base_key: SecretKey,
		commitment_seed: [u8; 32],
		channel_value_satoshis: u64,
		channel_keys_id: [u8; 32]) -> InMemorySigner {
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

	/// Counterparty pubkeys.
	/// Will panic if ready_channel wasn't called.
	pub fn counterparty_pubkeys(&self) -> &ChannelPublicKeys { &self.get_channel_parameters().counterparty_parameters.as_ref().unwrap().pubkeys }

	/// The contest_delay value specified by our counterparty and applied on holder-broadcastable
	/// transactions, ie the amount of time that we have to wait to recover our funds if we
	/// broadcast a transaction.
	/// Will panic if ready_channel wasn't called.
	pub fn counterparty_selected_contest_delay(&self) -> u16 { self.get_channel_parameters().counterparty_parameters.as_ref().unwrap().selected_contest_delay }

	/// The contest_delay value specified by us and applied on transactions broadcastable
	/// by our counterparty, ie the amount of time that they have to wait to recover their funds
	/// if they broadcast a transaction.
	/// Will panic if ready_channel wasn't called.
	pub fn holder_selected_contest_delay(&self) -> u16 { self.get_channel_parameters().holder_selected_contest_delay }

	/// Whether the holder is the initiator
	/// Will panic if ready_channel wasn't called.
	pub fn is_outbound(&self) -> bool { self.get_channel_parameters().is_outbound_from_holder }

	/// Funding outpoint
	/// Will panic if ready_channel wasn't called.
	pub fn funding_outpoint(&self) -> &OutPoint { self.get_channel_parameters().funding_outpoint.as_ref().unwrap() }

	/// Obtain a ChannelTransactionParameters for this channel, to be used when verifying or
	/// building transactions.
	///
	/// Will panic if ready_channel wasn't called.
	pub fn get_channel_parameters(&self) -> &ChannelTransactionParameters {
		self.channel_parameters.as_ref().unwrap()
	}

	/// Sign the single input of spend_tx at index `input_idx` which spends the output
	/// described by descriptor, returning the witness stack for the input.
	///
	/// Returns an Err if the input at input_idx does not exist, has a non-empty script_sig,
	/// or is not spending the outpoint described by `descriptor.outpoint`.
	pub fn sign_counterparty_payment_input<C: Signing>(&self, spend_tx: &Transaction, input_idx: usize, descriptor: &StaticPaymentOutputDescriptor, secp_ctx: &Secp256k1<C>) -> Result<Vec<Vec<u8>>, ()> {
		// TODO: We really should be taking the SigHashCache as a parameter here instead of
		// spend_tx, but ideally the SigHashCache would expose the transaction's inputs read-only
		// so that we can check them. This requires upstream rust-bitcoin changes (as well as
		// bindings updates to support SigHashCache objects).
		if spend_tx.input.len() <= input_idx { return Err(()); }
		if !spend_tx.input[input_idx].script_sig.is_empty() { return Err(()); }
		if spend_tx.input[input_idx].previous_output != descriptor.outpoint.into_bitcoin_outpoint() { return Err(()); }

		let remotepubkey = self.pubkeys().payment_point;
		let witness_script = bitcoin::Address::p2pkh(&::bitcoin::PublicKey{compressed: true, key: remotepubkey}, Network::Testnet).script_pubkey();
		let sighash = hash_to_message!(&bip143::SigHashCache::new(spend_tx).signature_hash(input_idx, &witness_script, descriptor.output.value, SigHashType::All)[..]);
		let remotesig = secp_ctx.sign(&sighash, &self.payment_key);

		let mut witness = Vec::with_capacity(2);
		witness.push(remotesig.serialize_der().to_vec());
		witness[0].push(SigHashType::All as u8);
		witness.push(remotepubkey.serialize().to_vec());
		Ok(witness)
	}

	/// Sign the single input of spend_tx at index `input_idx` which spends the output
	/// described by descriptor, returning the witness stack for the input.
	///
	/// Returns an Err if the input at input_idx does not exist, has a non-empty script_sig,
	/// is not spending the outpoint described by `descriptor.outpoint`, or does not have a
	/// sequence set to `descriptor.to_self_delay`.
	pub fn sign_dynamic_p2wsh_input<C: Signing>(&self, spend_tx: &Transaction, input_idx: usize, descriptor: &DelayedPaymentOutputDescriptor, secp_ctx: &Secp256k1<C>) -> Result<Vec<Vec<u8>>, ()> {
		// TODO: We really should be taking the SigHashCache as a parameter here instead of
		// spend_tx, but ideally the SigHashCache would expose the transaction's inputs read-only
		// so that we can check them. This requires upstream rust-bitcoin changes (as well as
		// bindings updates to support SigHashCache objects).
		if spend_tx.input.len() <= input_idx { return Err(()); }
		if !spend_tx.input[input_idx].script_sig.is_empty() { return Err(()); }
		if spend_tx.input[input_idx].previous_output != descriptor.outpoint.into_bitcoin_outpoint() { return Err(()); }
		if spend_tx.input[input_idx].sequence != descriptor.to_self_delay as u32 { return Err(()); }

		let delayed_payment_key = chan_utils::derive_private_key(&secp_ctx, &descriptor.per_commitment_point, &self.delayed_payment_base_key)
			.expect("We constructed the payment_base_key, so we can only fail here if the RNG is busted.");
		let delayed_payment_pubkey = PublicKey::from_secret_key(&secp_ctx, &delayed_payment_key);
		let witness_script = chan_utils::get_revokeable_redeemscript(&descriptor.revocation_pubkey, descriptor.to_self_delay, &delayed_payment_pubkey);
		let sighash = hash_to_message!(&bip143::SigHashCache::new(spend_tx).signature_hash(input_idx, &witness_script, descriptor.output.value, SigHashType::All)[..]);
		let local_delayedsig = secp_ctx.sign(&sighash, &delayed_payment_key);

		let mut witness = Vec::with_capacity(3);
		witness.push(local_delayedsig.serialize_der().to_vec());
		witness[0].push(SigHashType::All as u8);
		witness.push(vec!()); //MINIMALIF
		witness.push(witness_script.clone().into_bytes());
		Ok(witness)
	}
}

impl BaseSign for InMemorySigner {
	fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> PublicKey {
		let commitment_secret = SecretKey::from_slice(&chan_utils::build_commitment_secret(&self.commitment_seed, idx)).unwrap();
		PublicKey::from_secret_key(secp_ctx, &commitment_secret)
	}

	fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
		chan_utils::build_commitment_secret(&self.commitment_seed, idx)
	}

	fn pubkeys(&self) -> &ChannelPublicKeys { &self.holder_channel_pubkeys }
	fn channel_keys_id(&self) -> [u8; 32] { self.channel_keys_id }

	fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<(Signature, Vec<Signature>), ()> {
		let trusted_tx = commitment_tx.trust();
		let keys = trusted_tx.keys();

		let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &self.funding_key);
		let channel_funding_redeemscript = make_funding_redeemscript(&funding_pubkey, &self.counterparty_pubkeys().funding_pubkey);

		let built_tx = trusted_tx.built_transaction();
		let commitment_sig = built_tx.sign(&self.funding_key, &channel_funding_redeemscript, self.channel_value_satoshis, secp_ctx);
		let commitment_txid = built_tx.txid;

		let mut htlc_sigs = Vec::with_capacity(commitment_tx.htlcs().len());
		for htlc in commitment_tx.htlcs() {
			let htlc_tx = chan_utils::build_htlc_transaction(&commitment_txid, commitment_tx.feerate_per_kw(), self.holder_selected_contest_delay(), htlc, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);
			let htlc_redeemscript = chan_utils::get_htlc_redeemscript(&htlc, &keys);
			let htlc_sighash = hash_to_message!(&bip143::SigHashCache::new(&htlc_tx).signature_hash(0, &htlc_redeemscript, htlc.amount_msat / 1000, SigHashType::All)[..]);
			let holder_htlc_key = chan_utils::derive_private_key(&secp_ctx, &keys.per_commitment_point, &self.htlc_base_key).map_err(|_| ())?;
			htlc_sigs.push(secp_ctx.sign(&htlc_sighash, &holder_htlc_key));
		}

		Ok((commitment_sig, htlc_sigs))
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
		let revocation_key = chan_utils::derive_private_revocation_key(&secp_ctx, &per_commitment_key, &self.revocation_base_key).map_err(|_| ())?;
		let per_commitment_point = PublicKey::from_secret_key(secp_ctx, &per_commitment_key);
		let revocation_pubkey = chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &self.pubkeys().revocation_basepoint).map_err(|_| ())?;
		let witness_script = {
			let counterparty_delayedpubkey = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.counterparty_pubkeys().delayed_payment_basepoint).map_err(|_| ())?;
			chan_utils::get_revokeable_redeemscript(&revocation_pubkey, self.holder_selected_contest_delay(), &counterparty_delayedpubkey)
		};
		let mut sighash_parts = bip143::SigHashCache::new(justice_tx);
		let sighash = hash_to_message!(&sighash_parts.signature_hash(input, &witness_script, amount, SigHashType::All)[..]);
		return Ok(secp_ctx.sign(&sighash, &revocation_key))
	}

	fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		let revocation_key = chan_utils::derive_private_revocation_key(&secp_ctx, &per_commitment_key, &self.revocation_base_key).map_err(|_| ())?;
		let per_commitment_point = PublicKey::from_secret_key(secp_ctx, &per_commitment_key);
		let revocation_pubkey = chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &self.pubkeys().revocation_basepoint).map_err(|_| ())?;
		let witness_script = {
			let counterparty_htlcpubkey = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.counterparty_pubkeys().htlc_basepoint).map_err(|_| ())?;
			let holder_htlcpubkey = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.pubkeys().htlc_basepoint).map_err(|_| ())?;
			chan_utils::get_htlc_redeemscript_with_explicit_keys(&htlc, &counterparty_htlcpubkey, &holder_htlcpubkey, &revocation_pubkey)
		};
		let mut sighash_parts = bip143::SigHashCache::new(justice_tx);
		let sighash = hash_to_message!(&sighash_parts.signature_hash(input, &witness_script, amount, SigHashType::All)[..]);
		return Ok(secp_ctx.sign(&sighash, &revocation_key))
	}

	fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		if let Ok(htlc_key) = chan_utils::derive_private_key(&secp_ctx, &per_commitment_point, &self.htlc_base_key) {
			let witness_script = if let Ok(revocation_pubkey) = chan_utils::derive_public_revocation_key(&secp_ctx, &per_commitment_point, &self.pubkeys().revocation_basepoint) {
				if let Ok(counterparty_htlcpubkey) = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.counterparty_pubkeys().htlc_basepoint) {
					if let Ok(htlcpubkey) = chan_utils::derive_public_key(&secp_ctx, &per_commitment_point, &self.pubkeys().htlc_basepoint) {
						chan_utils::get_htlc_redeemscript_with_explicit_keys(&htlc, &counterparty_htlcpubkey, &htlcpubkey, &revocation_pubkey)
					} else { return Err(()) }
				} else { return Err(()) }
			} else { return Err(()) };
			let mut sighash_parts = bip143::SigHashCache::new(htlc_tx);
			let sighash = hash_to_message!(&sighash_parts.signature_hash(input, &witness_script, amount, SigHashType::All)[..]);
			return Ok(secp_ctx.sign(&sighash, &htlc_key))
		}
		Err(())
	}

	fn sign_closing_transaction(&self, closing_tx: &Transaction, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		if closing_tx.input.len() != 1 { return Err(()); }
		if closing_tx.input[0].witness.len() != 0 { return Err(()); }
		if closing_tx.output.len() > 2 { return Err(()); }

		let funding_pubkey = PublicKey::from_secret_key(secp_ctx, &self.funding_key);
		let channel_funding_redeemscript = make_funding_redeemscript(&funding_pubkey, &self.counterparty_pubkeys().funding_pubkey);

		let sighash = hash_to_message!(&bip143::SigHashCache::new(closing_tx)
			.signature_hash(0, &channel_funding_redeemscript, self.channel_value_satoshis, SigHashType::All)[..]);
		Ok(secp_ctx.sign(&sighash, &self.funding_key))
	}

	fn sign_channel_announcement(&self, msg: &UnsignedChannelAnnouncement, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<Signature, ()> {
		let msghash = hash_to_message!(&Sha256dHash::hash(&msg.encode()[..])[..]);
		Ok(secp_ctx.sign(&msghash, &self.funding_key))
	}

	fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters) {
		assert!(self.channel_parameters.is_none(), "Acceptance already noted");
		assert!(channel_parameters.is_populated(), "Channel parameters must be fully populated");
		self.channel_parameters = Some(channel_parameters.clone());
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Sign for InMemorySigner {}

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
			                                     &payment_key, &delayed_payment_base_key,
			                                     &htlc_base_key);
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

/// Simple KeysInterface implementor that takes a 32-byte seed for use as a BIP 32 extended key
/// and derives keys from that.
///
/// Your node_id is seed/0'
/// ChannelMonitor closes may use seed/1'
/// Cooperative closes may use seed/2'
/// The two close keys may be needed to claim on-chain funds!
pub struct KeysManager {
	secp_ctx: Secp256k1<secp256k1::All>,
	node_secret: SecretKey,
	destination_script: Script,
	shutdown_pubkey: PublicKey,
	channel_master_key: ExtendedPrivKey,
	channel_child_index: AtomicUsize,

	rand_bytes_master_key: ExtendedPrivKey,
	rand_bytes_child_index: AtomicUsize,
	rand_bytes_unique_start: Sha256State,

	seed: [u8; 32],
	starting_time_secs: u64,
	starting_time_nanos: u32,
}

impl KeysManager {
	/// Constructs a KeysManager from a 32-byte seed. If the seed is in some way biased (eg your
	/// CSRNG is busted) this may panic (but more importantly, you will possibly lose funds).
	/// starting_time isn't strictly required to actually be a time, but it must absolutely,
	/// without a doubt, be unique to this instance. ie if you start multiple times with the same
	/// seed, starting_time must be unique to each run. Thus, the easiest way to achieve this is to
	/// simply use the current time (with very high precision).
	///
	/// The seed MUST be backed up safely prior to use so that the keys can be re-created, however,
	/// obviously, starting_time should be unique every time you reload the library - it is only
	/// used to generate new ephemeral key data (which will be stored by the individual channel if
	/// necessary).
	///
	/// Note that the seed is required to recover certain on-chain funds independent of
	/// ChannelMonitor data, though a current copy of ChannelMonitor data is also required for any
	/// channel, and some on-chain during-closing funds.
	///
	/// Note that until the 0.1 release there is no guarantee of backward compatibility between
	/// versions. Once the library is more fully supported, the docs will be updated to include a
	/// detailed description of the guarantee.
	pub fn new(seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32) -> Self {
		let secp_ctx = Secp256k1::new();
		// Note that when we aren't serializing the key, network doesn't matter
		match ExtendedPrivKey::new_master(Network::Testnet, seed) {
			Ok(master_key) => {
				let node_secret = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(0).unwrap()).expect("Your RNG is busted").private_key.key;
				let destination_script = match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(1).unwrap()) {
					Ok(destination_key) => {
						let wpubkey_hash = WPubkeyHash::hash(&ExtendedPubKey::from_private(&secp_ctx, &destination_key).public_key.to_bytes());
						Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
						              .push_slice(&wpubkey_hash.into_inner())
						              .into_script()
					},
					Err(_) => panic!("Your RNG is busted"),
				};
				let shutdown_pubkey = match master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(2).unwrap()) {
					Ok(shutdown_key) => ExtendedPubKey::from_private(&secp_ctx, &shutdown_key).public_key.key,
					Err(_) => panic!("Your RNG is busted"),
				};
				let channel_master_key = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(3).unwrap()).expect("Your RNG is busted");
				let rand_bytes_master_key = master_key.ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(4).unwrap()).expect("Your RNG is busted");

				let mut rand_bytes_unique_start = Sha256::engine();
				rand_bytes_unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
				rand_bytes_unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
				rand_bytes_unique_start.input(seed);

				let mut res = KeysManager {
					secp_ctx,
					node_secret,

					destination_script,
					shutdown_pubkey,

					channel_master_key,
					channel_child_index: AtomicUsize::new(0),

					rand_bytes_master_key,
					rand_bytes_child_index: AtomicUsize::new(0),
					rand_bytes_unique_start,

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
	/// Derive an old Sign containing per-channel secrets based on a key derivation parameters.
	///
	/// Key derivation parameters are accessible through a per-channel secrets
	/// Sign::channel_keys_id and is provided inside DynamicOuputP2WSH in case of
	/// onchain output detection for which a corresponding delayed_payment_key must be derived.
	pub fn derive_channel_keys(&self, channel_value_satoshis: u64, params: &[u8; 32]) -> InMemorySigner {
		let chan_id = byte_utils::slice_to_be64(&params[0..8]);
		assert!(chan_id <= core::u32::MAX as u64); // Otherwise the params field wasn't created by us
		let mut unique_start = Sha256::engine();
		unique_start.input(params);
		unique_start.input(&self.seed);

		// We only seriously intend to rely on the channel_master_key for true secure
		// entropy, everything else just ensures uniqueness. We rely on the unique_start (ie
		// starting_time provided in the constructor) to be unique.
		let child_privkey = self.channel_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(chan_id as u32).expect("key space exhausted")).expect("Your RNG is busted");
		unique_start.input(&child_privkey.private_key.key[..]);

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
			params.clone()
		)
	}

	/// Creates a Transaction which spends the given descriptors to the given outputs, plus an
	/// output to the given change destination (if sufficient change value remains). The
	/// transaction will have a feerate, at least, of the given value.
	///
	/// Returns `Err(())` if the output value is greater than the input value minus required fee or
	/// if a descriptor was duplicated.
	///
	/// We do not enforce that outputs meet the dust limit or that any output scripts are standard.
	///
	/// May panic if the `SpendableOutputDescriptor`s were not generated by Channels which used
	/// this KeysManager or one of the `InMemorySigner` created by this KeysManager.
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
						sequence: 0,
						witness: Vec::new(),
					});
					witness_weight += StaticPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
					input_value += descriptor.output.value;
					if !output_set.insert(descriptor.outpoint) { return Err(()); }
				},
				SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
					input.push(TxIn {
						previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
						script_sig: Script::new(),
						sequence: descriptor.to_self_delay as u32,
						witness: Vec::new(),
					});
					witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
					input_value += descriptor.output.value;
					if !output_set.insert(descriptor.outpoint) { return Err(()); }
				},
				SpendableOutputDescriptor::StaticOutput { ref outpoint, ref output } => {
					input.push(TxIn {
						previous_output: outpoint.into_bitcoin_outpoint(),
						script_sig: Script::new(),
						sequence: 0,
						witness: Vec::new(),
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
			lock_time: 0,
			input,
			output: outputs,
		};
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
					spend_tx.input[input_idx].witness = keys_cache.as_ref().unwrap().0.sign_counterparty_payment_input(&spend_tx, input_idx, &descriptor, &secp_ctx).unwrap();
				},
				SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
					if keys_cache.is_none() || keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id {
						keys_cache = Some((
							self.derive_channel_keys(descriptor.channel_value_satoshis, &descriptor.channel_keys_id),
							descriptor.channel_keys_id));
					}
					spend_tx.input[input_idx].witness = keys_cache.as_ref().unwrap().0.sign_dynamic_p2wsh_input(&spend_tx, input_idx, &descriptor, &secp_ctx).unwrap();
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
					let pubkey = ExtendedPubKey::from_private(&secp_ctx, &secret).public_key;
					if derivation_idx == 2 {
						assert_eq!(pubkey.key, self.shutdown_pubkey);
					}
					let witness_script = bitcoin::Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
					let sighash = hash_to_message!(&bip143::SigHashCache::new(&spend_tx).signature_hash(input_idx, &witness_script, output.value, SigHashType::All)[..]);
					let sig = secp_ctx.sign(&sighash, &secret.private_key.key);
					spend_tx.input[input_idx].witness.push(sig.serialize_der().to_vec());
					spend_tx.input[input_idx].witness[0].push(SigHashType::All as u8);
					spend_tx.input[input_idx].witness.push(pubkey.key.serialize().to_vec());
				},
			}
			input_idx += 1;
		}
		Ok(spend_tx)
	}
}

impl KeysInterface for KeysManager {
	type Signer = InMemorySigner;

	fn get_node_secret(&self) -> SecretKey {
		self.node_secret.clone()
	}

	fn get_destination_script(&self) -> Script {
		self.destination_script.clone()
	}

	fn get_shutdown_pubkey(&self) -> PublicKey {
		self.shutdown_pubkey.clone()
	}

	fn get_channel_signer(&self, _inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
		let child_ix = self.channel_child_index.fetch_add(1, Ordering::AcqRel);
		assert!(child_ix <= core::u32::MAX as usize);
		let mut id = [0; 32];
		id[0..8].copy_from_slice(&byte_utils::be64_to_array(child_ix as u64));
		id[8..16].copy_from_slice(&byte_utils::be64_to_array(self.starting_time_nanos as u64));
		id[16..24].copy_from_slice(&byte_utils::be64_to_array(self.starting_time_secs));
		self.derive_channel_keys(channel_value_satoshis, &id)
	}

	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let mut sha = self.rand_bytes_unique_start.clone();

		let child_ix = self.rand_bytes_child_index.fetch_add(1, Ordering::AcqRel);
		let child_privkey = self.rand_bytes_master_key.ckd_priv(&self.secp_ctx, ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted")).expect("Your RNG is busted");
		sha.input(&child_privkey.private_key.key[..]);

		sha.input(b"Unique Secure Random Bytes Salt");
		Sha256::from_engine(sha).into_inner()
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
		InMemorySigner::read(&mut io::Cursor::new(reader))
	}

	fn sign_invoice(&self, invoice_preimage: Vec<u8>) -> Result<RecoverableSignature, ()> {
		Ok(self.secp_ctx.sign_recoverable(&hash_to_message!(&Sha256::hash(&invoice_preimage)), &self.get_node_secret()))
	}
}

// Ensure that BaseSign can have a vtable
#[test]
pub fn dyn_sign() {
	let _signer: Box<dyn BaseSign>;
}
