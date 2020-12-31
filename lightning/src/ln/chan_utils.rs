// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Various utilities for building scripts and deriving keys related to channels. These are
//! largely of interest for those implementing chain::keysinterface::ChannelKeys message signing
//! by hand.

use bitcoin::blockdata::script::{Script,Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::transaction::{TxIn,TxOut,OutPoint,Transaction, SigHashType};
use bitcoin::util::bip143;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::ripemd160::Hash as Ripemd160;
use bitcoin::hash_types::{Txid, PubkeyHash};

use ln::channelmanager::{PaymentHash, PaymentPreimage};
use ln::msgs::DecodeError;
use util::ser::{Readable, Writeable, Writer, MAX_BUF_SIZE};
use util::byte_utils;

use bitcoin::hash_types::WPubkeyHash;
use bitcoin::secp256k1::key::{SecretKey, PublicKey};
use bitcoin::secp256k1::{Secp256k1, Signature, Message};
use bitcoin::secp256k1::Error as SecpError;
use bitcoin::secp256k1;

use std::cmp;
use ln::chan_utils;
use util::transaction_utils::sort_outputs;
use ln::channel::INITIAL_COMMITMENT_NUMBER;
use std::io::Read;
use std::ops::Deref;
use chain;

const HTLC_OUTPUT_IN_COMMITMENT_SIZE: usize = 1 + 8 + 4 + 32 + 5;

pub(crate) const MAX_HTLCS: u16 = 483;

// This checks that the buffer size is greater than the maximum possible size for serialized HTLCS
const _EXCESS_BUFFER_SIZE: usize = MAX_BUF_SIZE - MAX_HTLCS as usize * HTLC_OUTPUT_IN_COMMITMENT_SIZE;

pub(super) const HTLC_SUCCESS_TX_WEIGHT: u64 = 703;
pub(super) const HTLC_TIMEOUT_TX_WEIGHT: u64 = 663;

#[derive(PartialEq)]
pub(crate) enum HTLCType {
	AcceptedHTLC,
	OfferedHTLC
}

impl HTLCType {
	/// Check if a given tx witnessScript len matchs one of a pre-signed HTLC
	pub(crate) fn scriptlen_to_htlctype(witness_script_len: usize) ->  Option<HTLCType> {
		if witness_script_len == 133 {
			Some(HTLCType::OfferedHTLC)
		} else if witness_script_len >= 136 && witness_script_len <= 139 {
			Some(HTLCType::AcceptedHTLC)
		} else {
			None
		}
	}
}

// Various functions for key derivation and transaction creation for use within channels. Primarily
// used in Channel and ChannelMonitor.

/// Build the commitment secret from the seed and the commitment number
pub fn build_commitment_secret(commitment_seed: &[u8; 32], idx: u64) -> [u8; 32] {
	let mut res: [u8; 32] = commitment_seed.clone();
	for i in 0..48 {
		let bitpos = 47 - i;
		if idx & (1 << bitpos) == (1 << bitpos) {
			res[bitpos / 8] ^= 1 << (bitpos & 7);
			res = Sha256::hash(&res).into_inner();
		}
	}
	res
}

/// Implements the per-commitment secret storage scheme from
/// [BOLT 3](https://github.com/lightningnetwork/lightning-rfc/blob/dcbf8583976df087c79c3ce0b535311212e6812d/03-transactions.md#efficient-per-commitment-secret-storage).
///
/// Allows us to keep track of all of the revocation secrets of counterarties in just 50*32 bytes
/// or so.
#[derive(Clone)]
pub(crate) struct CounterpartyCommitmentSecrets {
	old_secrets: [([u8; 32], u64); 49],
}

impl PartialEq for CounterpartyCommitmentSecrets {
	fn eq(&self, other: &Self) -> bool {
		for (&(ref secret, ref idx), &(ref o_secret, ref o_idx)) in self.old_secrets.iter().zip(other.old_secrets.iter()) {
			if secret != o_secret || idx != o_idx {
				return false
			}
		}
		true
	}
}

impl CounterpartyCommitmentSecrets {
	pub(crate) fn new() -> Self {
		Self { old_secrets: [([0; 32], 1 << 48); 49], }
	}

	#[inline]
	fn place_secret(idx: u64) -> u8 {
		for i in 0..48 {
			if idx & (1 << i) == (1 << i) {
				return i
			}
		}
		48
	}

	pub(crate) fn get_min_seen_secret(&self) -> u64 {
		//TODO This can be optimized?
		let mut min = 1 << 48;
		for &(_, idx) in self.old_secrets.iter() {
			if idx < min {
				min = idx;
			}
		}
		min
	}

	#[inline]
	fn derive_secret(secret: [u8; 32], bits: u8, idx: u64) -> [u8; 32] {
		let mut res: [u8; 32] = secret;
		for i in 0..bits {
			let bitpos = bits - 1 - i;
			if idx & (1 << bitpos) == (1 << bitpos) {
				res[(bitpos / 8) as usize] ^= 1 << (bitpos & 7);
				res = Sha256::hash(&res).into_inner();
			}
		}
		res
	}

	pub(crate) fn provide_secret(&mut self, idx: u64, secret: [u8; 32]) -> Result<(), ()> {
		let pos = Self::place_secret(idx);
		for i in 0..pos {
			let (old_secret, old_idx) = self.old_secrets[i as usize];
			if Self::derive_secret(secret, pos, old_idx) != old_secret {
				return Err(());
			}
		}
		if self.get_min_seen_secret() <= idx {
			return Ok(());
		}
		self.old_secrets[pos as usize] = (secret, idx);
		Ok(())
	}

	/// Can only fail if idx is < get_min_seen_secret
	pub(crate) fn get_secret(&self, idx: u64) -> Option<[u8; 32]> {
		for i in 0..self.old_secrets.len() {
			if (idx & (!((1 << i) - 1))) == self.old_secrets[i].1 {
				return Some(Self::derive_secret(self.old_secrets[i].0, i as u8, idx))
			}
		}
		assert!(idx < self.get_min_seen_secret());
		None
	}
}

impl Writeable for CounterpartyCommitmentSecrets {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		for &(ref secret, ref idx) in self.old_secrets.iter() {
			writer.write_all(secret)?;
			writer.write_all(&byte_utils::be64_to_array(*idx))?;
		}
		Ok(())
	}
}
impl Readable for CounterpartyCommitmentSecrets {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut old_secrets = [([0; 32], 1 << 48); 49];
		for &mut (ref mut secret, ref mut idx) in old_secrets.iter_mut() {
			*secret = Readable::read(reader)?;
			*idx = Readable::read(reader)?;
		}

		Ok(Self { old_secrets })
	}
}

/// Derives a per-commitment-transaction private key (eg an htlc key or delayed_payment key)
/// from the base secret and the per_commitment_point.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
pub fn derive_private_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_secret: &SecretKey) -> Result<SecretKey, SecpError> {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&PublicKey::from_secret_key(&secp_ctx, &base_secret).serialize());
	let res = Sha256::from_engine(sha).into_inner();

	let mut key = base_secret.clone();
	key.add_assign(&res)?;
	Ok(key)
}

/// Derives a per-commitment-transaction public key (eg an htlc key or a delayed_payment key)
/// from the base point and the per_commitment_key. This is the public equivalent of
/// derive_private_key - using only public keys to derive a public key instead of private keys.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
pub fn derive_public_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_point: &PublicKey) -> Result<PublicKey, SecpError> {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&base_point.serialize());
	let res = Sha256::from_engine(sha).into_inner();

	let hashkey = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&res)?);
	base_point.combine(&hashkey)
}

/// Derives a per-commitment-transaction revocation key from its constituent parts.
///
/// Only the cheating participant owns a valid witness to propagate a revoked 
/// commitment transaction, thus per_commitment_secret always come from cheater
/// and revocation_base_secret always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
pub fn derive_private_revocation_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_secret: &SecretKey, countersignatory_revocation_base_secret: &SecretKey) -> Result<SecretKey, SecpError> {
	let countersignatory_revocation_base_point = PublicKey::from_secret_key(&secp_ctx, &countersignatory_revocation_base_secret);
	let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);

	let rev_append_commit_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&countersignatory_revocation_base_point.serialize());
		sha.input(&per_commitment_point.serialize());

		Sha256::from_engine(sha).into_inner()
	};
	let commit_append_rev_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&per_commitment_point.serialize());
		sha.input(&countersignatory_revocation_base_point.serialize());

		Sha256::from_engine(sha).into_inner()
	};

	let mut countersignatory_contrib = countersignatory_revocation_base_secret.clone();
	countersignatory_contrib.mul_assign(&rev_append_commit_hash_key)?;
	let mut broadcaster_contrib = per_commitment_secret.clone();
	broadcaster_contrib.mul_assign(&commit_append_rev_hash_key)?;
	countersignatory_contrib.add_assign(&broadcaster_contrib[..])?;
	Ok(countersignatory_contrib)
}

/// Derives a per-commitment-transaction revocation public key from its constituent parts. This is
/// the public equivalend of derive_private_revocation_key - using only public keys to derive a
/// public key instead of private keys.
///
/// Only the cheating participant owns a valid witness to propagate a revoked 
/// commitment transaction, thus per_commitment_point always come from cheater
/// and revocation_base_point always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
pub fn derive_public_revocation_key<T: secp256k1::Verification>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, countersignatory_revocation_base_point: &PublicKey) -> Result<PublicKey, SecpError> {
	let rev_append_commit_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&countersignatory_revocation_base_point.serialize());
		sha.input(&per_commitment_point.serialize());

		Sha256::from_engine(sha).into_inner()
	};
	let commit_append_rev_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&per_commitment_point.serialize());
		sha.input(&countersignatory_revocation_base_point.serialize());

		Sha256::from_engine(sha).into_inner()
	};

	let mut countersignatory_contrib = countersignatory_revocation_base_point.clone();
	countersignatory_contrib.mul_assign(&secp_ctx, &rev_append_commit_hash_key)?;
	let mut broadcaster_contrib = per_commitment_point.clone();
	broadcaster_contrib.mul_assign(&secp_ctx, &commit_append_rev_hash_key)?;
	countersignatory_contrib.combine(&broadcaster_contrib)
}

/// The set of public keys which are used in the creation of one commitment transaction.
/// These are derived from the channel base keys and per-commitment data.
///
/// A broadcaster key is provided from potential broadcaster of the computed transaction.
/// A countersignatory key is coming from a protocol participant unable to broadcast the
/// transaction.
///
/// These keys are assumed to be good, either because the code derived them from
/// channel basepoints via the new function, or they were obtained via
/// CommitmentTransaction.trust().keys() because we trusted the source of the
/// pre-calculated keys.
#[derive(PartialEq, Clone)]
pub struct TxCreationKeys {
	/// The broadcaster's per-commitment public key which was used to derive the other keys.
	pub per_commitment_point: PublicKey,
	/// The revocation key which is used to allow the broadcaster of the commitment
	/// transaction to provide their counterparty the ability to punish them if they broadcast
	/// an old state.
	pub revocation_key: PublicKey,
	/// Broadcaster's HTLC Key
	pub broadcaster_htlc_key: PublicKey,
	/// Countersignatory's HTLC Key
	pub countersignatory_htlc_key: PublicKey,
	/// Broadcaster's Payment Key (which isn't allowed to be spent from for some delay)
	pub broadcaster_delayed_payment_key: PublicKey,
}
impl_writeable!(TxCreationKeys, 33*6,
	{ per_commitment_point, revocation_key, broadcaster_htlc_key, countersignatory_htlc_key, broadcaster_delayed_payment_key });

/// One counterparty's public keys which do not change over the life of a channel.
#[derive(Clone, PartialEq)]
pub struct ChannelPublicKeys {
	/// The public key which is used to sign all commitment transactions, as it appears in the
	/// on-chain channel lock-in 2-of-2 multisig output.
	pub funding_pubkey: PublicKey,
	/// The base point which is used (with derive_public_revocation_key) to derive per-commitment
	/// revocation keys. This is combined with the per-commitment-secret generated by the
	/// counterparty to create a secret which the counterparty can reveal to revoke previous
	/// states.
	pub revocation_basepoint: PublicKey,
	/// The public key on which the non-broadcaster (ie the countersignatory) receives an immediately
	/// spendable primary channel balance on the broadcaster's commitment transaction. This key is
	/// static across every commitment transaction.
	pub payment_point: PublicKey,
	/// The base point which is used (with derive_public_key) to derive a per-commitment payment
	/// public key which receives non-HTLC-encumbered funds which are only available for spending
	/// after some delay (or can be claimed via the revocation path).
	pub delayed_payment_basepoint: PublicKey,
	/// The base point which is used (with derive_public_key) to derive a per-commitment public key
	/// which is used to encumber HTLC-in-flight outputs.
	pub htlc_basepoint: PublicKey,
}

impl_writeable!(ChannelPublicKeys, 33*5, {
	funding_pubkey,
	revocation_basepoint,
	payment_point,
	delayed_payment_basepoint,
	htlc_basepoint
});


impl TxCreationKeys {
	/// Create per-state keys from channel base points and the per-commitment point.
	/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
	pub fn derive_new<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, broadcaster_delayed_payment_base: &PublicKey, broadcaster_htlc_base: &PublicKey, countersignatory_revocation_base: &PublicKey, countersignatory_htlc_base: &PublicKey) -> Result<TxCreationKeys, SecpError> {
		Ok(TxCreationKeys {
			per_commitment_point: per_commitment_point.clone(),
			revocation_key: derive_public_revocation_key(&secp_ctx, &per_commitment_point, &countersignatory_revocation_base)?,
			broadcaster_htlc_key: derive_public_key(&secp_ctx, &per_commitment_point, &broadcaster_htlc_base)?,
			countersignatory_htlc_key: derive_public_key(&secp_ctx, &per_commitment_point, &countersignatory_htlc_base)?,
			broadcaster_delayed_payment_key: derive_public_key(&secp_ctx, &per_commitment_point, &broadcaster_delayed_payment_base)?,
		})
	}

	/// Generate per-state keys from channel static keys.
	/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
	pub fn from_channel_static_keys<T: secp256k1::Signing + secp256k1::Verification>(per_commitment_point: &PublicKey, broadcaster_keys: &ChannelPublicKeys, countersignatory_keys: &ChannelPublicKeys, secp_ctx: &Secp256k1<T>) -> Result<TxCreationKeys, SecpError> {
		TxCreationKeys::derive_new(
			&secp_ctx,
			&per_commitment_point,
			&broadcaster_keys.delayed_payment_basepoint,
			&broadcaster_keys.htlc_basepoint,
			&countersignatory_keys.revocation_basepoint,
			&countersignatory_keys.htlc_basepoint,
		)
	}
}

/// A script either spendable by the revocation
/// key or the broadcaster_delayed_payment_key and satisfying the relative-locktime OP_CSV constrain.
/// Encumbering a `to_holder` output on a commitment transaction or 2nd-stage HTLC transactions.
pub fn get_revokeable_redeemscript(revocation_key: &PublicKey, contest_delay: u16, broadcaster_delayed_payment_key: &PublicKey) -> Script {
	Builder::new().push_opcode(opcodes::all::OP_IF)
	              .push_slice(&revocation_key.serialize())
	              .push_opcode(opcodes::all::OP_ELSE)
	              .push_int(contest_delay as i64)
	              .push_opcode(opcodes::all::OP_CSV)
	              .push_opcode(opcodes::all::OP_DROP)
	              .push_slice(&broadcaster_delayed_payment_key.serialize())
	              .push_opcode(opcodes::all::OP_ENDIF)
	              .push_opcode(opcodes::all::OP_CHECKSIG)
	              .into_script()
}

#[derive(Clone, PartialEq)]
/// Information about an HTLC as it appears in a commitment transaction
pub struct HTLCOutputInCommitment {
	/// Whether the HTLC was "offered" (ie outbound in relation to this commitment transaction).
	/// Note that this is not the same as whether it is ountbound *from us*. To determine that you
	/// need to compare this value to whether the commitment transaction in question is that of
	/// the counterparty or our own.
	pub offered: bool,
	/// The value, in msat, of the HTLC. The value as it appears in the commitment transaction is
	/// this divided by 1000.
	pub amount_msat: u64,
	/// The CLTV lock-time at which this HTLC expires.
	pub cltv_expiry: u32,
	/// The hash of the preimage which unlocks this HTLC.
	pub payment_hash: PaymentHash,
	/// The position within the commitment transactions' outputs. This may be None if the value is
	/// below the dust limit (in which case no output appears in the commitment transaction and the
	/// value is spent to additional transaction fees).
	pub transaction_output_index: Option<u32>,
}

impl_writeable!(HTLCOutputInCommitment, HTLC_OUTPUT_IN_COMMITMENT_SIZE, {
	offered,
	amount_msat,
	cltv_expiry,
	payment_hash,
	transaction_output_index
});

#[inline]
pub(crate) fn get_htlc_redeemscript_with_explicit_keys(htlc: &HTLCOutputInCommitment, broadcaster_htlc_key: &PublicKey, countersignatory_htlc_key: &PublicKey, revocation_key: &PublicKey) -> Script {
	let payment_hash160 = Ripemd160::hash(&htlc.payment_hash.0[..]).into_inner();
	if htlc.offered {
		Builder::new().push_opcode(opcodes::all::OP_DUP)
		              .push_opcode(opcodes::all::OP_HASH160)
		              .push_slice(&PubkeyHash::hash(&revocation_key.serialize())[..])
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_IF)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_slice(&countersignatory_htlc_key.serialize()[..])
		              .push_opcode(opcodes::all::OP_SWAP)
		              .push_opcode(opcodes::all::OP_SIZE)
		              .push_int(32)
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_NOTIF)
		              .push_opcode(opcodes::all::OP_DROP)
		              .push_int(2)
		              .push_opcode(opcodes::all::OP_SWAP)
		              .push_slice(&broadcaster_htlc_key.serialize()[..])
		              .push_int(2)
		              .push_opcode(opcodes::all::OP_CHECKMULTISIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_opcode(opcodes::all::OP_HASH160)
		              .push_slice(&payment_hash160)
		              .push_opcode(opcodes::all::OP_EQUALVERIFY)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ENDIF)
		              .push_opcode(opcodes::all::OP_ENDIF)
		              .into_script()
	} else {
		Builder::new().push_opcode(opcodes::all::OP_DUP)
		              .push_opcode(opcodes::all::OP_HASH160)
		              .push_slice(&PubkeyHash::hash(&revocation_key.serialize())[..])
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_IF)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_slice(&countersignatory_htlc_key.serialize()[..])
		              .push_opcode(opcodes::all::OP_SWAP)
		              .push_opcode(opcodes::all::OP_SIZE)
		              .push_int(32)
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_IF)
		              .push_opcode(opcodes::all::OP_HASH160)
		              .push_slice(&payment_hash160)
		              .push_opcode(opcodes::all::OP_EQUALVERIFY)
		              .push_int(2)
		              .push_opcode(opcodes::all::OP_SWAP)
		              .push_slice(&broadcaster_htlc_key.serialize()[..])
		              .push_int(2)
		              .push_opcode(opcodes::all::OP_CHECKMULTISIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_opcode(opcodes::all::OP_DROP)
		              .push_int(htlc.cltv_expiry as i64)
		              .push_opcode(opcodes::all::OP_CLTV)
		              .push_opcode(opcodes::all::OP_DROP)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ENDIF)
		              .push_opcode(opcodes::all::OP_ENDIF)
		              .into_script()
	}
}

/// Gets the witness redeemscript for an HTLC output in a commitment transaction. Note that htlc
/// does not need to have its previous_output_index filled.
#[inline]
pub fn get_htlc_redeemscript(htlc: &HTLCOutputInCommitment, keys: &TxCreationKeys) -> Script {
	get_htlc_redeemscript_with_explicit_keys(htlc, &keys.broadcaster_htlc_key, &keys.countersignatory_htlc_key, &keys.revocation_key)
}

/// Gets the redeemscript for a funding output from the two funding public keys.
/// Note that the order of funding public keys does not matter.
pub fn make_funding_redeemscript(broadcaster: &PublicKey, countersignatory: &PublicKey) -> Script {
	let broadcaster_funding_key = broadcaster.serialize();
	let countersignatory_funding_key = countersignatory.serialize();

	let builder = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2);
	if broadcaster_funding_key[..] < countersignatory_funding_key[..] {
		builder.push_slice(&broadcaster_funding_key)
			.push_slice(&countersignatory_funding_key)
	} else {
		builder.push_slice(&countersignatory_funding_key)
			.push_slice(&broadcaster_funding_key)
	}.push_opcode(opcodes::all::OP_PUSHNUM_2).push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script()
}

/// panics if htlc.transaction_output_index.is_none()!
pub fn build_htlc_transaction(prev_hash: &Txid, feerate_per_kw: u32, contest_delay: u16, htlc: &HTLCOutputInCommitment, broadcaster_delayed_payment_key: &PublicKey, revocation_key: &PublicKey) -> Transaction {
	let mut txins: Vec<TxIn> = Vec::new();
	txins.push(TxIn {
		previous_output: OutPoint {
			txid: prev_hash.clone(),
			vout: htlc.transaction_output_index.expect("Can't build an HTLC transaction for a dust output"),
		},
		script_sig: Script::new(),
		sequence: 0,
		witness: Vec::new(),
	});

	let total_fee = if htlc.offered {
			feerate_per_kw as u64 * HTLC_TIMEOUT_TX_WEIGHT / 1000
		} else {
			feerate_per_kw as u64 * HTLC_SUCCESS_TX_WEIGHT / 1000
		};

	let mut txouts: Vec<TxOut> = Vec::new();
	txouts.push(TxOut {
		script_pubkey: get_revokeable_redeemscript(revocation_key, contest_delay, broadcaster_delayed_payment_key).to_v0_p2wsh(),
		value: htlc.amount_msat / 1000 - total_fee //TODO: BOLT 3 does not specify if we should add amount_msat before dividing or if we should divide by 1000 before subtracting (as we do here)
	});

	Transaction {
		version: 2,
		lock_time: if htlc.offered { htlc.cltv_expiry } else { 0 },
		input: txins,
		output: txouts,
	}
}

/// Per-channel data used to build transactions in conjunction with the per-commitment data (CommitmentTransaction).
/// The fields are organized by holder/counterparty.
///
/// Normally, this is converted to the broadcaster/countersignatory-organized DirectedChannelTransactionParameters
/// before use, via the as_holder_broadcastable and as_counterparty_broadcastable functions.
#[derive(Clone)]
pub struct ChannelTransactionParameters {
	/// Holder public keys
	pub holder_pubkeys: ChannelPublicKeys,
	/// The contest delay selected by the holder, which applies to counterparty-broadcast transactions
	pub holder_selected_contest_delay: u16,
	/// Whether the holder is the initiator of this channel.
	/// This is an input to the commitment number obscure factor computation.
	pub is_outbound_from_holder: bool,
	/// The late-bound counterparty channel transaction parameters.
	/// These parameters are populated at the point in the protocol where the counterparty provides them.
	pub counterparty_parameters: Option<CounterpartyChannelTransactionParameters>,
	/// The late-bound funding outpoint
	pub funding_outpoint: Option<chain::transaction::OutPoint>,
}

/// Late-bound per-channel counterparty data used to build transactions.
#[derive(Clone)]
pub struct CounterpartyChannelTransactionParameters {
	/// Counter-party public keys
	pub pubkeys: ChannelPublicKeys,
	/// The contest delay selected by the counterparty, which applies to holder-broadcast transactions
	pub selected_contest_delay: u16,
}

impl ChannelTransactionParameters {
	/// Whether the late bound parameters are populated.
	pub fn is_populated(&self) -> bool {
		self.counterparty_parameters.is_some() && self.funding_outpoint.is_some()
	}

	/// Convert the holder/counterparty parameters to broadcaster/countersignatory-organized parameters,
	/// given that the holder is the broadcaster.
	///
	/// self.is_populated() must be true before calling this function.
	pub fn as_holder_broadcastable(&self) -> DirectedChannelTransactionParameters {
		assert!(self.is_populated(), "self.late_parameters must be set before using as_holder_broadcastable");
		DirectedChannelTransactionParameters {
			inner: self,
			holder_is_broadcaster: true
		}
	}

	/// Convert the holder/counterparty parameters to broadcaster/countersignatory-organized parameters,
	/// given that the counterparty is the broadcaster.
	///
	/// self.is_populated() must be true before calling this function.
	pub fn as_counterparty_broadcastable(&self) -> DirectedChannelTransactionParameters {
		assert!(self.is_populated(), "self.late_parameters must be set before using as_counterparty_broadcastable");
		DirectedChannelTransactionParameters {
			inner: self,
			holder_is_broadcaster: false
		}
	}
}

impl_writeable!(CounterpartyChannelTransactionParameters, 0, {
	pubkeys,
	selected_contest_delay
});

impl_writeable!(ChannelTransactionParameters, 0, {
	holder_pubkeys,
	holder_selected_contest_delay,
	is_outbound_from_holder,
	counterparty_parameters,
	funding_outpoint
});

/// Static channel fields used to build transactions given per-commitment fields, organized by
/// broadcaster/countersignatory.
///
/// This is derived from the holder/counterparty-organized ChannelTransactionParameters via the
/// as_holder_broadcastable and as_counterparty_broadcastable functions.
pub struct DirectedChannelTransactionParameters<'a> {
	/// The holder's channel static parameters
	inner: &'a ChannelTransactionParameters,
	/// Whether the holder is the broadcaster
	holder_is_broadcaster: bool,
}

impl<'a> DirectedChannelTransactionParameters<'a> {
	/// Get the channel pubkeys for the broadcaster
	pub fn broadcaster_pubkeys(&self) -> &ChannelPublicKeys {
		if self.holder_is_broadcaster {
			&self.inner.holder_pubkeys
		} else {
			&self.inner.counterparty_parameters.as_ref().unwrap().pubkeys
		}
	}

	/// Get the channel pubkeys for the countersignatory
	pub fn countersignatory_pubkeys(&self) -> &ChannelPublicKeys {
		if self.holder_is_broadcaster {
			&self.inner.counterparty_parameters.as_ref().unwrap().pubkeys
		} else {
			&self.inner.holder_pubkeys
		}
	}

	/// Get the contest delay applicable to the transactions.
	/// Note that the contest delay was selected by the countersignatory.
	pub fn contest_delay(&self) -> u16 {
		let counterparty_parameters = self.inner.counterparty_parameters.as_ref().unwrap();
		if self.holder_is_broadcaster { counterparty_parameters.selected_contest_delay } else { self.inner.holder_selected_contest_delay }
	}

	/// Whether the channel is outbound from the broadcaster.
	///
	/// The boolean representing the side that initiated the channel is
	/// an input to the commitment number obscure factor computation.
	pub fn is_outbound(&self) -> bool {
		if self.holder_is_broadcaster { self.inner.is_outbound_from_holder } else { !self.inner.is_outbound_from_holder }
	}

	/// The funding outpoint
	pub fn funding_outpoint(&self) -> OutPoint {
		self.inner.funding_outpoint.unwrap().into_bitcoin_outpoint()
	}
}

/// Information needed to build and sign a holder's commitment transaction.
///
/// The transaction is only signed once we are ready to broadcast.
#[derive(Clone)]
pub struct HolderCommitmentTransaction {
	inner: CommitmentTransaction,
	/// Our counterparty's signature for the transaction
	pub counterparty_sig: Signature,
	/// All non-dust counterparty HTLC signatures, in the order they appear in the transaction
	pub counterparty_htlc_sigs: Vec<Signature>,
	// Which order the signatures should go in when constructing the final commitment tx witness.
	// The user should be able to reconstruct this themselves, so we don't bother to expose it.
	holder_sig_first: bool,
}

impl Deref for HolderCommitmentTransaction {
	type Target = CommitmentTransaction;

	fn deref(&self) -> &Self::Target { &self.inner }
}

impl PartialEq for HolderCommitmentTransaction {
	// We dont care whether we are signed in equality comparison
	fn eq(&self, o: &Self) -> bool {
		self.inner == o.inner
	}
}

impl_writeable!(HolderCommitmentTransaction, 0, {
	inner, counterparty_sig, counterparty_htlc_sigs, holder_sig_first
});

impl HolderCommitmentTransaction {
	#[cfg(test)]
	pub fn dummy() -> Self {
		let secp_ctx = Secp256k1::new();
		let dummy_key = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let dummy_sig = secp_ctx.sign(&secp256k1::Message::from_slice(&[42; 32]).unwrap(), &SecretKey::from_slice(&[42; 32]).unwrap());

		let keys = TxCreationKeys {
			per_commitment_point: dummy_key.clone(),
			revocation_key: dummy_key.clone(),
			broadcaster_htlc_key: dummy_key.clone(),
			countersignatory_htlc_key: dummy_key.clone(),
			broadcaster_delayed_payment_key: dummy_key.clone(),
		};
		let channel_pubkeys = ChannelPublicKeys {
			funding_pubkey: dummy_key.clone(),
			revocation_basepoint: dummy_key.clone(),
			payment_point: dummy_key.clone(),
			delayed_payment_basepoint: dummy_key.clone(),
			htlc_basepoint: dummy_key.clone()
		};
		let channel_parameters = ChannelTransactionParameters {
			holder_pubkeys: channel_pubkeys.clone(),
			holder_selected_contest_delay: 0,
			is_outbound_from_holder: false,
			counterparty_parameters: Some(CounterpartyChannelTransactionParameters { pubkeys: channel_pubkeys.clone(), selected_contest_delay: 0 }),
			funding_outpoint: Some(chain::transaction::OutPoint { txid: Default::default(), index: 0 })
		};
		let mut htlcs_with_aux: Vec<(_, ())> = Vec::new();
		let inner = CommitmentTransaction::new_with_auxiliary_htlc_data(0, 0, 0, keys, 0, &mut htlcs_with_aux, &channel_parameters.as_counterparty_broadcastable());
		HolderCommitmentTransaction {
			inner,
			counterparty_sig: dummy_sig,
			counterparty_htlc_sigs: Vec::new(),
			holder_sig_first: false
		}
	}

	/// Create a new holder transaction with the given counterparty signatures.
	/// The funding keys are used to figure out which signature should go first when building the transaction for broadcast.
	pub fn new(commitment_tx: CommitmentTransaction, counterparty_sig: Signature, counterparty_htlc_sigs: Vec<Signature>, holder_funding_key: &PublicKey, counterparty_funding_key: &PublicKey) -> Self {
		Self {
			inner: commitment_tx,
			counterparty_sig,
			counterparty_htlc_sigs,
			holder_sig_first: holder_funding_key.serialize()[..] < counterparty_funding_key.serialize()[..],
		}
	}

	pub(crate) fn add_holder_sig(&self, funding_redeemscript: &Script, holder_sig: Signature) -> Transaction {
		// First push the multisig dummy, note that due to BIP147 (NULLDUMMY) it must be a zero-length element.
		let mut tx = self.inner.built.transaction.clone();
		tx.input[0].witness.push(Vec::new());

		if self.holder_sig_first {
			tx.input[0].witness.push(holder_sig.serialize_der().to_vec());
			tx.input[0].witness.push(self.counterparty_sig.serialize_der().to_vec());
		} else {
			tx.input[0].witness.push(self.counterparty_sig.serialize_der().to_vec());
			tx.input[0].witness.push(holder_sig.serialize_der().to_vec());
		}
		tx.input[0].witness[1].push(SigHashType::All as u8);
		tx.input[0].witness[2].push(SigHashType::All as u8);

		tx.input[0].witness.push(funding_redeemscript.as_bytes().to_vec());
		tx
	}
}

/// A pre-built Bitcoin commitment transaction and its txid.
#[derive(Clone)]
pub struct BuiltCommitmentTransaction {
	/// The commitment transaction
	pub transaction: Transaction,
	/// The txid for the commitment transaction.
	///
	/// This is provided as a performance optimization, instead of calling transaction.txid()
	/// multiple times.
	pub txid: Txid,
}

impl_writeable!(BuiltCommitmentTransaction, 0, { transaction, txid });

impl BuiltCommitmentTransaction {
	/// Get the SIGHASH_ALL sighash value of the transaction.
	///
	/// This can be used to verify a signature.
	pub fn get_sighash_all(&self, funding_redeemscript: &Script, channel_value_satoshis: u64) -> Message {
		let sighash = &bip143::SigHashCache::new(&self.transaction).signature_hash(0, funding_redeemscript, channel_value_satoshis, SigHashType::All)[..];
		hash_to_message!(sighash)
	}

	/// Sign a transaction, either because we are counter-signing the counterparty's transaction or
	/// because we are about to broadcast a holder transaction.
	pub fn sign<T: secp256k1::Signing>(&self, funding_key: &SecretKey, funding_redeemscript: &Script, channel_value_satoshis: u64, secp_ctx: &Secp256k1<T>) -> Signature {
		let sighash = self.get_sighash_all(funding_redeemscript, channel_value_satoshis);
		secp_ctx.sign(&sighash, funding_key)
	}
}

/// This class tracks the per-transaction information needed to build a commitment transaction and to
/// actually build it and sign.  It is used for holder transactions that we sign only when needed
/// and for transactions we sign for the counterparty.
///
/// This class can be used inside a signer implementation to generate a signature given the relevant
/// secret key.
#[derive(Clone)]
pub struct CommitmentTransaction {
	commitment_number: u64,
	to_broadcaster_value_sat: u64,
	to_countersignatory_value_sat: u64,
	feerate_per_kw: u32,
	htlcs: Vec<HTLCOutputInCommitment>,
	// A cache of the parties' pubkeys required to construct the transaction, see doc for trust()
	keys: TxCreationKeys,
	// For access to the pre-built transaction, see doc for trust()
	built: BuiltCommitmentTransaction,
}

impl PartialEq for CommitmentTransaction {
	fn eq(&self, o: &Self) -> bool {
		let eq = self.commitment_number == o.commitment_number &&
			self.to_broadcaster_value_sat == o.to_broadcaster_value_sat &&
			self.to_countersignatory_value_sat == o.to_countersignatory_value_sat &&
			self.feerate_per_kw == o.feerate_per_kw &&
			self.htlcs == o.htlcs &&
			self.keys == o.keys;
		if eq {
			debug_assert_eq!(self.built.transaction, o.built.transaction);
			debug_assert_eq!(self.built.txid, o.built.txid);
		}
		eq
	}
}

/// (C-not exported) as users never need to call this directly
impl Writeable for Vec<HTLCOutputInCommitment> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		(self.len() as u16).write(w)?;
		for e in self.iter() {
			e.write(w)?;
		}
		Ok(())
	}
}

/// (C-not exported) as users never need to call this directly
impl Readable for Vec<HTLCOutputInCommitment> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let len: u16 = Readable::read(r)?;
		let byte_size = (len as usize)
			.checked_mul(HTLC_OUTPUT_IN_COMMITMENT_SIZE)
			.ok_or(DecodeError::BadLengthDescriptor)?;
		if byte_size > MAX_BUF_SIZE {
			return Err(DecodeError::BadLengthDescriptor);
		}
		let mut ret = Vec::with_capacity(len as usize);
		for _ in 0..len { ret.push(HTLCOutputInCommitment::read(r)?); }
		Ok(ret)
	}
}

impl_writeable!(CommitmentTransaction, 0, {
	commitment_number,
	to_broadcaster_value_sat,
	to_countersignatory_value_sat,
	feerate_per_kw,
	htlcs,
	keys,
	built
});

impl CommitmentTransaction {
	/// Construct an object of the class while assigning transaction output indices to HTLCs.
	///
	/// Populates HTLCOutputInCommitment.transaction_output_index in htlcs_with_aux.
	///
	/// The generic T allows the caller to match the HTLC output index with auxiliary data.
	/// This auxiliary data is not stored in this object.
	///
	/// Only include HTLCs that are above the dust limit for the channel.
	///
	/// (C-not exported) due to the generic though we likely should expose a version without
	pub fn new_with_auxiliary_htlc_data<T>(commitment_number: u64, to_broadcaster_value_sat: u64, to_countersignatory_value_sat: u64, keys: TxCreationKeys, feerate_per_kw: u32, htlcs_with_aux: &mut Vec<(HTLCOutputInCommitment, T)>, channel_parameters: &DirectedChannelTransactionParameters) -> CommitmentTransaction {
		// Sort outputs and populate output indices while keeping track of the auxiliary data
		let (outputs, htlcs) = Self::internal_build_outputs(&keys, to_broadcaster_value_sat, to_countersignatory_value_sat, htlcs_with_aux, channel_parameters).unwrap();

		let (obscured_commitment_transaction_number, txins) = Self::internal_build_inputs(commitment_number, channel_parameters);
		let transaction = Self::make_transaction(obscured_commitment_transaction_number, txins, outputs);
		let txid = transaction.txid();
		CommitmentTransaction {
			commitment_number,
			to_broadcaster_value_sat,
			to_countersignatory_value_sat,
			feerate_per_kw,
			htlcs,
			keys,
			built: BuiltCommitmentTransaction {
				transaction,
				txid
			},
		}
	}

	fn internal_rebuild_transaction(&self, keys: &TxCreationKeys, channel_parameters: &DirectedChannelTransactionParameters) -> Result<BuiltCommitmentTransaction, ()> {
		let (obscured_commitment_transaction_number, txins) = Self::internal_build_inputs(self.commitment_number, channel_parameters);

		let mut htlcs_with_aux = self.htlcs.iter().map(|h| (h.clone(), ())).collect();
		let (outputs, _) = Self::internal_build_outputs(keys, self.to_broadcaster_value_sat, self.to_countersignatory_value_sat, &mut htlcs_with_aux, channel_parameters)?;

		let transaction = Self::make_transaction(obscured_commitment_transaction_number, txins, outputs);
		let txid = transaction.txid();
		let built_transaction = BuiltCommitmentTransaction {
			transaction,
			txid
		};
		Ok(built_transaction)
	}

	fn make_transaction(obscured_commitment_transaction_number: u64, txins: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
		Transaction {
			version: 2,
			lock_time: ((0x20 as u32) << 8 * 3) | ((obscured_commitment_transaction_number & 0xffffffu64) as u32),
			input: txins,
			output: outputs,
		}
	}

	// This is used in two cases:
	// - initial sorting of outputs / HTLCs in the constructor, in which case T is auxiliary data the
	//   caller needs to have sorted together with the HTLCs so it can keep track of the output index
	// - building of a bitcoin transaction during a verify() call, in which case T is just ()
	fn internal_build_outputs<T>(keys: &TxCreationKeys, to_broadcaster_value_sat: u64, to_countersignatory_value_sat: u64, htlcs_with_aux: &mut Vec<(HTLCOutputInCommitment, T)>, channel_parameters: &DirectedChannelTransactionParameters) -> Result<(Vec<TxOut>, Vec<HTLCOutputInCommitment>), ()> {
		let countersignatory_pubkeys = channel_parameters.countersignatory_pubkeys();
		let contest_delay = channel_parameters.contest_delay();

		let mut txouts: Vec<(TxOut, Option<&mut HTLCOutputInCommitment>)> = Vec::new();

		if to_countersignatory_value_sat > 0 {
			let script = script_for_p2wpkh(&countersignatory_pubkeys.payment_point);
			txouts.push((
				TxOut {
					script_pubkey: script.clone(),
					value: to_countersignatory_value_sat,
				},
				None,
			))
		}

		if to_broadcaster_value_sat > 0 {
			let redeem_script = get_revokeable_redeemscript(
				&keys.revocation_key,
				contest_delay,
				&keys.broadcaster_delayed_payment_key,
			);
			txouts.push((
				TxOut {
					script_pubkey: redeem_script.to_v0_p2wsh(),
					value: to_broadcaster_value_sat,
				},
				None,
			));
		}

		let mut htlcs = Vec::with_capacity(htlcs_with_aux.len());
		for (htlc, _) in htlcs_with_aux {
			let script = chan_utils::get_htlc_redeemscript(&htlc, &keys);
			let txout = TxOut {
				script_pubkey: script.to_v0_p2wsh(),
				value: htlc.amount_msat / 1000,
			};
			txouts.push((txout, Some(htlc)));
		}

		// Sort output in BIP-69 order (amount, scriptPubkey).  Tie-breaks based on HTLC
		// CLTV expiration height.
		sort_outputs(&mut txouts, |a, b| {
			if let &Some(ref a_htlcout) = a {
				if let &Some(ref b_htlcout) = b {
					a_htlcout.cltv_expiry.cmp(&b_htlcout.cltv_expiry)
						// Note that due to hash collisions, we have to have a fallback comparison
						// here for fuzztarget mode (otherwise at least chanmon_fail_consistency
						// may fail)!
						.then(a_htlcout.payment_hash.0.cmp(&b_htlcout.payment_hash.0))
				// For non-HTLC outputs, if they're copying our SPK we don't really care if we
				// close the channel due to mismatches - they're doing something dumb:
				} else { cmp::Ordering::Equal }
			} else { cmp::Ordering::Equal }
		});

		let mut outputs = Vec::with_capacity(txouts.len());
		for (idx, out) in txouts.drain(..).enumerate() {
			if let Some(htlc) = out.1 {
				htlc.transaction_output_index = Some(idx as u32);
				htlcs.push(htlc.clone());
			}
			outputs.push(out.0);
		}
		Ok((outputs, htlcs))
	}

	fn internal_build_inputs(commitment_number: u64, channel_parameters: &DirectedChannelTransactionParameters) -> (u64, Vec<TxIn>) {
		let broadcaster_pubkeys = channel_parameters.broadcaster_pubkeys();
		let countersignatory_pubkeys = channel_parameters.countersignatory_pubkeys();
		let commitment_transaction_number_obscure_factor = get_commitment_transaction_number_obscure_factor(
			&broadcaster_pubkeys.payment_point,
			&countersignatory_pubkeys.payment_point,
			channel_parameters.is_outbound(),
		);

		let obscured_commitment_transaction_number =
			commitment_transaction_number_obscure_factor ^ (INITIAL_COMMITMENT_NUMBER - commitment_number);

		let txins = {
			let mut ins: Vec<TxIn> = Vec::new();
			ins.push(TxIn {
				previous_output: channel_parameters.funding_outpoint(),
				script_sig: Script::new(),
				sequence: ((0x80 as u32) << 8 * 3)
					| ((obscured_commitment_transaction_number >> 3 * 8) as u32),
				witness: Vec::new(),
			});
			ins
		};
		(obscured_commitment_transaction_number, txins)
	}

	/// The backwards-counting commitment number
	pub fn commitment_number(&self) -> u64 {
		self.commitment_number
	}

	/// The value to be sent to the broadcaster
	pub fn to_broadcaster_value_sat(&self) -> u64 {
		self.to_broadcaster_value_sat
	}

	/// The value to be sent to the counterparty
	pub fn to_countersignatory_value_sat(&self) -> u64 {
		self.to_countersignatory_value_sat
	}

	/// The feerate paid per 1000-weight-unit in this commitment transaction.
	pub fn feerate_per_kw(&self) -> u32 {
		self.feerate_per_kw
	}

	/// The non-dust HTLCs (direction, amt, height expiration, hash, transaction output index)
	/// which were included in this commitment transaction in output order.
	/// The transaction index is always populated.
	///
	/// (C-not exported) as we cannot currently convert Vec references to/from C, though we should
	/// expose a less effecient version which creates a Vec of references in the future.
	pub fn htlcs(&self) -> &Vec<HTLCOutputInCommitment> {
		&self.htlcs
	}

	/// Trust our pre-built transaction and derived transaction creation public keys.
	///
	/// Applies a wrapper which allows access to these fields.
	///
	/// This should only be used if you fully trust the builder of this object.  It should not
	///	be used by an external signer - instead use the verify function.
	pub fn trust(&self) -> TrustedCommitmentTransaction {
		TrustedCommitmentTransaction { inner: self }
	}

	/// Verify our pre-built transaction and derived transaction creation public keys.
	///
	/// Applies a wrapper which allows access to these fields.
	///
	/// An external validating signer must call this method before signing
	/// or using the built transaction.
	pub fn verify<T: secp256k1::Signing + secp256k1::Verification>(&self, channel_parameters: &DirectedChannelTransactionParameters, broadcaster_keys: &ChannelPublicKeys, countersignatory_keys: &ChannelPublicKeys, secp_ctx: &Secp256k1<T>) -> Result<TrustedCommitmentTransaction, ()> {
		// This is the only field of the key cache that we trust
		let per_commitment_point = self.keys.per_commitment_point;
		let keys = TxCreationKeys::from_channel_static_keys(&per_commitment_point, broadcaster_keys, countersignatory_keys, secp_ctx).unwrap();
		if keys != self.keys {
			return Err(());
		}
		let tx = self.internal_rebuild_transaction(&keys, channel_parameters)?;
		if self.built.transaction != tx.transaction || self.built.txid != tx.txid {
			return Err(());
		}
		Ok(TrustedCommitmentTransaction { inner: self })
	}
}

/// A wrapper on CommitmentTransaction indicating that the derived fields (the built bitcoin
/// transaction and the transaction creation keys) are trusted.
///
/// See trust() and verify() functions on CommitmentTransaction.
///
/// This structure implements Deref.
pub struct TrustedCommitmentTransaction<'a> {
	inner: &'a CommitmentTransaction,
}

impl<'a> Deref for TrustedCommitmentTransaction<'a> {
	type Target = CommitmentTransaction;

	fn deref(&self) -> &Self::Target { self.inner }
}

impl<'a> TrustedCommitmentTransaction<'a> {
	/// The transaction ID of the built Bitcoin transaction
	pub fn txid(&self) -> Txid {
		self.inner.built.txid
	}

	/// The pre-built Bitcoin commitment transaction
	pub fn built_transaction(&self) -> &BuiltCommitmentTransaction {
		&self.inner.built
	}

	/// The pre-calculated transaction creation public keys.
	pub fn keys(&self) -> &TxCreationKeys {
		&self.inner.keys
	}

	/// Get a signature for each HTLC which was included in the commitment transaction (ie for
	/// which HTLCOutputInCommitment::transaction_output_index.is_some()).
	///
	/// The returned Vec has one entry for each HTLC, and in the same order.
	pub fn get_htlc_sigs<T: secp256k1::Signing>(&self, htlc_base_key: &SecretKey, channel_parameters: &DirectedChannelTransactionParameters, secp_ctx: &Secp256k1<T>) -> Result<Vec<Signature>, ()> {
		let inner = self.inner;
		let keys = &inner.keys;
		let txid = inner.built.txid;
		let mut ret = Vec::with_capacity(inner.htlcs.len());
		let holder_htlc_key = derive_private_key(secp_ctx, &inner.keys.per_commitment_point, htlc_base_key).map_err(|_| ())?;

		for this_htlc in inner.htlcs.iter() {
			assert!(this_htlc.transaction_output_index.is_some());
			let htlc_tx = build_htlc_transaction(&txid, inner.feerate_per_kw, channel_parameters.contest_delay(), &this_htlc, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

			let htlc_redeemscript = get_htlc_redeemscript_with_explicit_keys(&this_htlc, &keys.broadcaster_htlc_key, &keys.countersignatory_htlc_key, &keys.revocation_key);

			let sighash = hash_to_message!(&bip143::SigHashCache::new(&htlc_tx).signature_hash(0, &htlc_redeemscript, this_htlc.amount_msat / 1000, SigHashType::All)[..]);
			ret.push(secp_ctx.sign(&sighash, &holder_htlc_key));
		}
		Ok(ret)
	}

	/// Gets a signed HTLC transaction given a preimage (for !htlc.offered) and the holder HTLC transaction signature.
	pub(crate) fn get_signed_htlc_tx(&self, channel_parameters: &DirectedChannelTransactionParameters, htlc_index: usize, counterparty_signature: &Signature, signature: &Signature, preimage: &Option<PaymentPreimage>) -> Transaction {
		let inner = self.inner;
		let keys = &inner.keys;
		let txid = inner.built.txid;
		let this_htlc = &inner.htlcs[htlc_index];
		assert!(this_htlc.transaction_output_index.is_some());
		// if we don't have preimage for an HTLC-Success, we can't generate an HTLC transaction.
		if !this_htlc.offered && preimage.is_none() { unreachable!(); }
		// Further, we should never be provided the preimage for an HTLC-Timeout transaction.
		if  this_htlc.offered && preimage.is_some() { unreachable!(); }

		let mut htlc_tx = build_htlc_transaction(&txid, inner.feerate_per_kw, channel_parameters.contest_delay(), &this_htlc, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

		let htlc_redeemscript = get_htlc_redeemscript_with_explicit_keys(&this_htlc, &keys.broadcaster_htlc_key, &keys.countersignatory_htlc_key, &keys.revocation_key);

		// First push the multisig dummy, note that due to BIP147 (NULLDUMMY) it must be a zero-length element.
		htlc_tx.input[0].witness.push(Vec::new());

		htlc_tx.input[0].witness.push(counterparty_signature.serialize_der().to_vec());
		htlc_tx.input[0].witness.push(signature.serialize_der().to_vec());
		htlc_tx.input[0].witness[1].push(SigHashType::All as u8);
		htlc_tx.input[0].witness[2].push(SigHashType::All as u8);

		if this_htlc.offered {
			// Due to BIP146 (MINIMALIF) this must be a zero-length element to relay.
			htlc_tx.input[0].witness.push(Vec::new());
		} else {
			htlc_tx.input[0].witness.push(preimage.unwrap().0.to_vec());
		}

		htlc_tx.input[0].witness.push(htlc_redeemscript.as_bytes().to_vec());
		htlc_tx
	}
}

/// Get the transaction number obscure factor
pub fn get_commitment_transaction_number_obscure_factor(
	broadcaster_payment_basepoint: &PublicKey,
	countersignatory_payment_basepoint: &PublicKey,
	outbound_from_broadcaster: bool,
) -> u64 {
	let mut sha = Sha256::engine();

	if outbound_from_broadcaster {
		sha.input(&broadcaster_payment_basepoint.serialize());
		sha.input(&countersignatory_payment_basepoint.serialize());
	} else {
		sha.input(&countersignatory_payment_basepoint.serialize());
		sha.input(&broadcaster_payment_basepoint.serialize());
	}
	let res = Sha256::from_engine(sha).into_inner();

	((res[26] as u64) << 5 * 8)
		| ((res[27] as u64) << 4 * 8)
		| ((res[28] as u64) << 3 * 8)
		| ((res[29] as u64) << 2 * 8)
		| ((res[30] as u64) << 1 * 8)
		| ((res[31] as u64) << 0 * 8)
}

fn script_for_p2wpkh(key: &PublicKey) -> Script {
	Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
		.push_slice(&WPubkeyHash::hash(&key.serialize())[..])
		.into_script()
}

#[cfg(test)]
mod tests {
	use super::CounterpartyCommitmentSecrets;
	use hex;

	#[test]
	fn test_per_commitment_storage() {
		// Test vectors from BOLT 3:
		let mut secrets: Vec<[u8; 32]> = Vec::new();
		let mut monitor;

		macro_rules! test_secrets {
			() => {
				let mut idx = 281474976710655;
				for secret in secrets.iter() {
					assert_eq!(monitor.get_secret(idx).unwrap(), *secret);
					idx -= 1;
				}
				assert_eq!(monitor.get_min_seen_secret(), idx + 1);
				assert!(monitor.get_secret(idx).is_none());
			};
		}

		{
			// insert_secret correct sequence
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();
		}

		{
			// insert_secret #1 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			assert!(monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).is_err());
		}

		{
			// insert_secret #2 incorrect (#1 derived from incorrect)
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			assert!(monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).is_err());
		}

		{
			// insert_secret #3 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			assert!(monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).is_err());
		}

		{
			// insert_secret #4 incorrect (1,2,3 derived from incorrect)
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("ba65d7b0ef55a3ba300d4e87af29868f394f8f138d78a7011669c79b37b936f4").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).is_err());
		}

		{
			// insert_secret #5 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			assert!(monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).is_err());
		}

		{
			// insert_secret #6 incorrect (5 derived from incorrect)
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("b7e76a83668bde38b373970155c868a653304308f9896692f904a23731224bb1").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).is_err());
		}

		{
			// insert_secret #7 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("e7971de736e01da8ed58b94c2fc216cb1dca9e326f3a96e7194fe8ea8af6c0a3").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).is_err());
		}

		{
			// insert_secret #8 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex::decode("a7efbc61aac46d34f77778bac22c8a20c6a46ca460addc49009bda875ec88fa4").unwrap());
			assert!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).is_err());
		}
	}
}
