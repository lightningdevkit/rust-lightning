// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Various utilities for building scripts and deriving keys related to channels. These are
//! largely of interest for those implementing chain::keysinterface::Sign message signing by hand.

use bitcoin::blockdata::script::{Script,Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::transaction::{TxIn,TxOut,OutPoint,Transaction, EcdsaSighashType};
use bitcoin::util::sighash;
use bitcoin::util::address::Payload;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::ripemd160::Hash as Ripemd160;
use bitcoin::hash_types::{Txid, PubkeyHash};

use crate::ln::{PaymentHash, PaymentPreimage};
use crate::ln::msgs::DecodeError;
use crate::util::ser::{Readable, Writeable, Writer};
use crate::util::transaction_utils;

use bitcoin::secp256k1::{SecretKey, PublicKey, Scalar};
use bitcoin::secp256k1::{Secp256k1, ecdsa::Signature, Message};
use bitcoin::{PackedLockTime, secp256k1, Sequence, Witness};
use bitcoin::PublicKey as BitcoinPublicKey;

use crate::io;
use crate::prelude::*;
use core::cmp;
use crate::ln::chan_utils;
use crate::util::transaction_utils::sort_outputs;
use crate::ln::channel::{INITIAL_COMMITMENT_NUMBER, ANCHOR_OUTPUT_VALUE_SATOSHI};
use core::ops::Deref;
use crate::chain;
use crate::util::crypto::sign;

/// Maximum number of one-way in-flight HTLC (protocol-level value).
pub const MAX_HTLCS: u16 = 483;
/// The weight of a BIP141 witnessScript for a BOLT3's "offered HTLC output" on a commitment transaction, non-anchor variant.
pub const OFFERED_HTLC_SCRIPT_WEIGHT: usize = 133;
/// The weight of a BIP141 witnessScript for a BOLT3's "offered HTLC output" on a commitment transaction, anchor variant.
pub const OFFERED_HTLC_SCRIPT_WEIGHT_ANCHORS: usize = 136;

/// The weight of a BIP141 witnessScript for a BOLT3's "received HTLC output" can vary in function of its CLTV argument value.
/// We define a range that encompasses both its non-anchors and anchors variants.
pub(crate) const MIN_ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = 136;
/// The weight of a BIP141 witnessScript for a BOLT3's "received HTLC output" can vary in function of its CLTV argument value.
/// We define a range that encompasses both its non-anchors and anchors variants.
/// This is the maximum post-anchor value.
pub const MAX_ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = 143;

/// Gets the weight for an HTLC-Success transaction.
#[inline]
pub fn htlc_success_tx_weight(opt_anchors: bool) -> u64 {
	const HTLC_SUCCESS_TX_WEIGHT: u64 = 703;
	const HTLC_SUCCESS_ANCHOR_TX_WEIGHT: u64 = 706;
	if opt_anchors { HTLC_SUCCESS_ANCHOR_TX_WEIGHT } else { HTLC_SUCCESS_TX_WEIGHT }
}

/// Gets the weight for an HTLC-Timeout transaction.
#[inline]
pub fn htlc_timeout_tx_weight(opt_anchors: bool) -> u64 {
	const HTLC_TIMEOUT_TX_WEIGHT: u64 = 663;
	const HTLC_TIMEOUT_ANCHOR_TX_WEIGHT: u64 = 666;
	if opt_anchors { HTLC_TIMEOUT_ANCHOR_TX_WEIGHT } else { HTLC_TIMEOUT_TX_WEIGHT }
}

/// Describes the type of HTLC claim as determined by analyzing the witness.
#[derive(PartialEq, Eq)]
pub enum HTLCClaim {
	/// Claims an offered output on a commitment transaction through the timeout path.
	OfferedTimeout,
	/// Claims an offered output on a commitment transaction through the success path.
	OfferedPreimage,
	/// Claims an accepted output on a commitment transaction through the timeout path.
	AcceptedTimeout,
	/// Claims an accepted output on a commitment transaction through the success path.
	AcceptedPreimage,
	/// Claims an offered/accepted output on a commitment transaction through the revocation path.
	Revocation,
}

impl HTLCClaim {
	/// Check if a given input witness attempts to claim a HTLC.
	pub fn from_witness(witness: &Witness) -> Option<Self> {
		debug_assert_eq!(OFFERED_HTLC_SCRIPT_WEIGHT_ANCHORS, MIN_ACCEPTED_HTLC_SCRIPT_WEIGHT);
		if witness.len() < 2 {
			return None;
		}
		let witness_script = witness.last().unwrap();
		let second_to_last = witness.second_to_last().unwrap();
		if witness_script.len() == OFFERED_HTLC_SCRIPT_WEIGHT {
			if witness.len() == 3 && second_to_last.len() == 33 {
				// <revocation sig> <revocationpubkey> <witness_script>
				Some(Self::Revocation)
			} else if witness.len() == 3 && second_to_last.len() == 32 {
				// <remotehtlcsig> <payment_preimage> <witness_script>
				Some(Self::OfferedPreimage)
			} else if witness.len() == 5 && second_to_last.len() == 0 {
				// 0 <remotehtlcsig> <localhtlcsig> <> <witness_script>
				Some(Self::OfferedTimeout)
			} else {
				None
			}
		} else if witness_script.len() == OFFERED_HTLC_SCRIPT_WEIGHT_ANCHORS {
			// It's possible for the weight of `offered_htlc_script` and `accepted_htlc_script` to
			// match so we check for both here.
			if witness.len() == 3 && second_to_last.len() == 33 {
				// <revocation sig> <revocationpubkey> <witness_script>
				Some(Self::Revocation)
			} else if witness.len() == 3 && second_to_last.len() == 32 {
				// <remotehtlcsig> <payment_preimage> <witness_script>
				Some(Self::OfferedPreimage)
			} else if witness.len() == 5 && second_to_last.len() == 0 {
				// 0 <remotehtlcsig> <localhtlcsig> <> <witness_script>
				Some(Self::OfferedTimeout)
			} else if witness.len() == 3 && second_to_last.len() == 0 {
				// <remotehtlcsig> <> <witness_script>
				Some(Self::AcceptedTimeout)
			} else if witness.len() == 5 && second_to_last.len() == 32 {
				// 0 <remotehtlcsig> <localhtlcsig> <payment_preimage> <witness_script>
				Some(Self::AcceptedPreimage)
			} else {
				None
			}
		} else if witness_script.len() > MIN_ACCEPTED_HTLC_SCRIPT_WEIGHT &&
			witness_script.len() <= MAX_ACCEPTED_HTLC_SCRIPT_WEIGHT {
			// Handle remaining range of ACCEPTED_HTLC_SCRIPT_WEIGHT.
			if witness.len() == 3 && second_to_last.len() == 33 {
				// <revocation sig> <revocationpubkey> <witness_script>
				Some(Self::Revocation)
			} else if witness.len() == 3 && second_to_last.len() == 0 {
				// <remotehtlcsig> <> <witness_script>
				Some(Self::AcceptedTimeout)
			} else if witness.len() == 5 && second_to_last.len() == 32 {
				// 0 <remotehtlcsig> <localhtlcsig> <payment_preimage> <witness_script>
				Some(Self::AcceptedPreimage)
			} else {
				None
			}
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

/// Build a closing transaction
pub fn build_closing_transaction(to_holder_value_sat: u64, to_counterparty_value_sat: u64, to_holder_script: Script, to_counterparty_script: Script, funding_outpoint: OutPoint) -> Transaction {
	let txins = {
		let mut ins: Vec<TxIn> = Vec::new();
		ins.push(TxIn {
			previous_output: funding_outpoint,
			script_sig: Script::new(),
			sequence: Sequence::MAX,
			witness: Witness::new(),
		});
		ins
	};

	let mut txouts: Vec<(TxOut, ())> = Vec::new();

	if to_counterparty_value_sat > 0 {
		txouts.push((TxOut {
			script_pubkey: to_counterparty_script,
			value: to_counterparty_value_sat
		}, ()));
	}

	if to_holder_value_sat > 0 {
		txouts.push((TxOut {
			script_pubkey: to_holder_script,
			value: to_holder_value_sat
		}, ()));
	}

	transaction_utils::sort_outputs(&mut txouts, |_, _| { cmp::Ordering::Equal }); // Ordering doesnt matter if they used our pubkey...

	let mut outputs: Vec<TxOut> = Vec::new();
	for out in txouts.drain(..) {
		outputs.push(out.0);
	}

	Transaction {
		version: 2,
		lock_time: PackedLockTime::ZERO,
		input: txins,
		output: outputs,
	}
}

/// Implements the per-commitment secret storage scheme from
/// [BOLT 3](https://github.com/lightning/bolts/blob/dcbf8583976df087c79c3ce0b535311212e6812d/03-transactions.md#efficient-per-commitment-secret-storage).
///
/// Allows us to keep track of all of the revocation secrets of our counterparty in just 50*32 bytes
/// or so.
#[derive(Clone)]
pub struct CounterpartyCommitmentSecrets {
	old_secrets: [([u8; 32], u64); 49],
}

impl Eq for CounterpartyCommitmentSecrets {}
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
	/// Creates a new empty `CounterpartyCommitmentSecrets` structure.
	pub fn new() -> Self {
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

	/// Returns the minimum index of all stored secrets. Note that indexes start
	/// at 1 << 48 and get decremented by one for each new secret.
	pub fn get_min_seen_secret(&self) -> u64 {
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

	/// Inserts the `secret` at `idx`. Returns `Ok(())` if the secret
	/// was generated in accordance with BOLT 3 and is consistent with previous secrets.
	pub fn provide_secret(&mut self, idx: u64, secret: [u8; 32]) -> Result<(), ()> {
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

	/// Returns the secret at `idx`.
	/// Returns `None` if `idx` is < [`CounterpartyCommitmentSecrets::get_min_seen_secret`].
	pub fn get_secret(&self, idx: u64) -> Option<[u8; 32]> {
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
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		for &(ref secret, ref idx) in self.old_secrets.iter() {
			writer.write_all(secret)?;
			writer.write_all(&idx.to_be_bytes())?;
		}
		write_tlv_fields!(writer, {});
		Ok(())
	}
}
impl Readable for CounterpartyCommitmentSecrets {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut old_secrets = [([0; 32], 1 << 48); 49];
		for &mut (ref mut secret, ref mut idx) in old_secrets.iter_mut() {
			*secret = Readable::read(reader)?;
			*idx = Readable::read(reader)?;
		}
		read_tlv_fields!(reader, {});
		Ok(Self { old_secrets })
	}
}

/// Derives a per-commitment-transaction private key (eg an htlc key or delayed_payment key)
/// from the base secret and the per_commitment_point.
pub fn derive_private_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_secret: &SecretKey) -> SecretKey {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&PublicKey::from_secret_key(&secp_ctx, &base_secret).serialize());
	let res = Sha256::from_engine(sha).into_inner();

	base_secret.clone().add_tweak(&Scalar::from_be_bytes(res).unwrap())
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak contains the hash of the key.")
}

/// Derives a per-commitment-transaction public key (eg an htlc key or a delayed_payment key)
/// from the base point and the per_commitment_key. This is the public equivalent of
/// derive_private_key - using only public keys to derive a public key instead of private keys.
pub fn derive_public_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_point: &PublicKey) -> PublicKey {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&base_point.serialize());
	let res = Sha256::from_engine(sha).into_inner();

	let hashkey = PublicKey::from_secret_key(&secp_ctx,
		&SecretKey::from_slice(&res).expect("Hashes should always be valid keys unless SHA-256 is broken"));
	base_point.combine(&hashkey)
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak contains the hash of the key.")
}

/// Derives a per-commitment-transaction revocation key from its constituent parts.
///
/// Only the cheating participant owns a valid witness to propagate a revoked
/// commitment transaction, thus per_commitment_secret always come from cheater
/// and revocation_base_secret always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
pub fn derive_private_revocation_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>,
	per_commitment_secret: &SecretKey, countersignatory_revocation_base_secret: &SecretKey)
-> SecretKey {
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

	let countersignatory_contrib = countersignatory_revocation_base_secret.clone().mul_tweak(&Scalar::from_be_bytes(rev_append_commit_hash_key).unwrap())
		.expect("Multiplying a secret key by a hash is expected to never fail per secp256k1 docs");
	let broadcaster_contrib = per_commitment_secret.clone().mul_tweak(&Scalar::from_be_bytes(commit_append_rev_hash_key).unwrap())
		.expect("Multiplying a secret key by a hash is expected to never fail per secp256k1 docs");
	countersignatory_contrib.add_tweak(&Scalar::from_be_bytes(broadcaster_contrib.secret_bytes()).unwrap())
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak commits to the key.")
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
pub fn derive_public_revocation_key<T: secp256k1::Verification>(secp_ctx: &Secp256k1<T>,
	per_commitment_point: &PublicKey, countersignatory_revocation_base_point: &PublicKey)
-> PublicKey {
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

	let countersignatory_contrib = countersignatory_revocation_base_point.clone().mul_tweak(&secp_ctx, &Scalar::from_be_bytes(rev_append_commit_hash_key).unwrap())
		.expect("Multiplying a valid public key by a hash is expected to never fail per secp256k1 docs");
	let broadcaster_contrib = per_commitment_point.clone().mul_tweak(&secp_ctx, &Scalar::from_be_bytes(commit_append_rev_hash_key).unwrap())
		.expect("Multiplying a valid public key by a hash is expected to never fail per secp256k1 docs");
	countersignatory_contrib.combine(&broadcaster_contrib)
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak commits to the key.")
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
#[derive(PartialEq, Eq, Clone)]
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

impl_writeable_tlv_based!(TxCreationKeys, {
	(0, per_commitment_point, required),
	(2, revocation_key, required),
	(4, broadcaster_htlc_key, required),
	(6, countersignatory_htlc_key, required),
	(8, broadcaster_delayed_payment_key, required),
});

/// One counterparty's public keys which do not change over the life of a channel.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl_writeable_tlv_based!(ChannelPublicKeys, {
	(0, funding_pubkey, required),
	(2, revocation_basepoint, required),
	(4, payment_point, required),
	(6, delayed_payment_basepoint, required),
	(8, htlc_basepoint, required),
});

impl TxCreationKeys {
	/// Create per-state keys from channel base points and the per-commitment point.
	/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
	pub fn derive_new<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, broadcaster_delayed_payment_base: &PublicKey, broadcaster_htlc_base: &PublicKey, countersignatory_revocation_base: &PublicKey, countersignatory_htlc_base: &PublicKey) -> TxCreationKeys {
		TxCreationKeys {
			per_commitment_point: per_commitment_point.clone(),
			revocation_key: derive_public_revocation_key(&secp_ctx, &per_commitment_point, &countersignatory_revocation_base),
			broadcaster_htlc_key: derive_public_key(&secp_ctx, &per_commitment_point, &broadcaster_htlc_base),
			countersignatory_htlc_key: derive_public_key(&secp_ctx, &per_commitment_point, &countersignatory_htlc_base),
			broadcaster_delayed_payment_key: derive_public_key(&secp_ctx, &per_commitment_point, &broadcaster_delayed_payment_base),
		}
	}

	/// Generate per-state keys from channel static keys.
	/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
	pub fn from_channel_static_keys<T: secp256k1::Signing + secp256k1::Verification>(per_commitment_point: &PublicKey, broadcaster_keys: &ChannelPublicKeys, countersignatory_keys: &ChannelPublicKeys, secp_ctx: &Secp256k1<T>) -> TxCreationKeys {
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

/// The maximum length of a script returned by get_revokeable_redeemscript.
// Calculated as 6 bytes of opcodes, 1 byte push plus 2 bytes for contest_delay, and two public
// keys of 33 bytes (+ 1 push).
pub const REVOKEABLE_REDEEMSCRIPT_MAX_LENGTH: usize = 6 + 3 + 34*2;

/// A script either spendable by the revocation
/// key or the broadcaster_delayed_payment_key and satisfying the relative-locktime OP_CSV constrain.
/// Encumbering a `to_holder` output on a commitment transaction or 2nd-stage HTLC transactions.
pub fn get_revokeable_redeemscript(revocation_key: &PublicKey, contest_delay: u16, broadcaster_delayed_payment_key: &PublicKey) -> Script {
	let res = Builder::new().push_opcode(opcodes::all::OP_IF)
	              .push_slice(&revocation_key.serialize())
	              .push_opcode(opcodes::all::OP_ELSE)
	              .push_int(contest_delay as i64)
	              .push_opcode(opcodes::all::OP_CSV)
	              .push_opcode(opcodes::all::OP_DROP)
	              .push_slice(&broadcaster_delayed_payment_key.serialize())
	              .push_opcode(opcodes::all::OP_ENDIF)
	              .push_opcode(opcodes::all::OP_CHECKSIG)
	              .into_script();
	debug_assert!(res.len() <= REVOKEABLE_REDEEMSCRIPT_MAX_LENGTH);
	res
}

/// Information about an HTLC as it appears in a commitment transaction
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl_writeable_tlv_based!(HTLCOutputInCommitment, {
	(0, offered, required),
	(2, amount_msat, required),
	(4, cltv_expiry, required),
	(6, payment_hash, required),
	(8, transaction_output_index, option),
});

#[inline]
pub(crate) fn get_htlc_redeemscript_with_explicit_keys(htlc: &HTLCOutputInCommitment, opt_anchors: bool, broadcaster_htlc_key: &PublicKey, countersignatory_htlc_key: &PublicKey, revocation_key: &PublicKey) -> Script {
	let payment_hash160 = Ripemd160::hash(&htlc.payment_hash.0[..]).into_inner();
	if htlc.offered {
		let mut bldr = Builder::new().push_opcode(opcodes::all::OP_DUP)
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
		              .push_opcode(opcodes::all::OP_ENDIF);
		if opt_anchors {
			bldr = bldr.push_opcode(opcodes::all::OP_PUSHNUM_1)
				.push_opcode(opcodes::all::OP_CSV)
				.push_opcode(opcodes::all::OP_DROP);
		}
		bldr.push_opcode(opcodes::all::OP_ENDIF)
			.into_script()
	} else {
			let mut bldr = Builder::new().push_opcode(opcodes::all::OP_DUP)
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
		              .push_opcode(opcodes::all::OP_ENDIF);
		if opt_anchors {
			bldr = bldr.push_opcode(opcodes::all::OP_PUSHNUM_1)
				.push_opcode(opcodes::all::OP_CSV)
				.push_opcode(opcodes::all::OP_DROP);
		}
		bldr.push_opcode(opcodes::all::OP_ENDIF)
			.into_script()
	}
}

/// Gets the witness redeemscript for an HTLC output in a commitment transaction. Note that htlc
/// does not need to have its previous_output_index filled.
#[inline]
pub fn get_htlc_redeemscript(htlc: &HTLCOutputInCommitment, opt_anchors: bool, keys: &TxCreationKeys) -> Script {
	get_htlc_redeemscript_with_explicit_keys(htlc, opt_anchors, &keys.broadcaster_htlc_key, &keys.countersignatory_htlc_key, &keys.revocation_key)
}

/// Gets the redeemscript for a funding output from the two funding public keys.
/// Note that the order of funding public keys does not matter.
pub fn make_funding_redeemscript(broadcaster: &PublicKey, countersignatory: &PublicKey) -> Script {
	let broadcaster_funding_key = broadcaster.serialize();
	let countersignatory_funding_key = countersignatory.serialize();

	make_funding_redeemscript_from_slices(&broadcaster_funding_key, &countersignatory_funding_key)
}

pub(crate) fn make_funding_redeemscript_from_slices(broadcaster_funding_key: &[u8], countersignatory_funding_key: &[u8]) -> Script {
	let builder = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2);
	if broadcaster_funding_key[..] < countersignatory_funding_key[..] {
		builder.push_slice(broadcaster_funding_key)
			.push_slice(countersignatory_funding_key)
	} else {
		builder.push_slice(countersignatory_funding_key)
			.push_slice(broadcaster_funding_key)
	}.push_opcode(opcodes::all::OP_PUSHNUM_2).push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script()
}

/// Builds an unsigned HTLC-Success or HTLC-Timeout transaction from the given channel and HTLC
/// parameters. This is used by [`TrustedCommitmentTransaction::get_htlc_sigs`] to fetch the
/// transaction which needs signing, and can be used to construct an HTLC transaction which is
/// broadcastable given a counterparty HTLC signature.
///
/// Panics if htlc.transaction_output_index.is_none() (as such HTLCs do not appear in the
/// commitment transaction).
pub fn build_htlc_transaction(commitment_txid: &Txid, feerate_per_kw: u32, contest_delay: u16, htlc: &HTLCOutputInCommitment, opt_anchors: bool, use_non_zero_fee_anchors: bool, broadcaster_delayed_payment_key: &PublicKey, revocation_key: &PublicKey) -> Transaction {
	let mut txins: Vec<TxIn> = Vec::new();
	txins.push(build_htlc_input(commitment_txid, htlc, opt_anchors));

	let mut txouts: Vec<TxOut> = Vec::new();
	txouts.push(build_htlc_output(
		feerate_per_kw, contest_delay, htlc, opt_anchors, use_non_zero_fee_anchors,
		broadcaster_delayed_payment_key, revocation_key
	));

	Transaction {
		version: 2,
		lock_time: PackedLockTime(if htlc.offered { htlc.cltv_expiry } else { 0 }),
		input: txins,
		output: txouts,
	}
}

pub(crate) fn build_htlc_input(commitment_txid: &Txid, htlc: &HTLCOutputInCommitment, opt_anchors: bool) -> TxIn {
	TxIn {
		previous_output: OutPoint {
			txid: commitment_txid.clone(),
			vout: htlc.transaction_output_index.expect("Can't build an HTLC transaction for a dust output"),
		},
		script_sig: Script::new(),
		sequence: Sequence(if opt_anchors { 1 } else { 0 }),
		witness: Witness::new(),
	}
}

pub(crate) fn build_htlc_output(
	feerate_per_kw: u32, contest_delay: u16, htlc: &HTLCOutputInCommitment, opt_anchors: bool,
	use_non_zero_fee_anchors: bool, broadcaster_delayed_payment_key: &PublicKey, revocation_key: &PublicKey
) -> TxOut {
	let weight = if htlc.offered {
		htlc_timeout_tx_weight(opt_anchors)
	} else {
		htlc_success_tx_weight(opt_anchors)
	};
	let output_value = if opt_anchors && !use_non_zero_fee_anchors {
		htlc.amount_msat / 1000
	} else {
		let total_fee = feerate_per_kw as u64 * weight / 1000;
		htlc.amount_msat / 1000 - total_fee
	};

	TxOut {
		script_pubkey: get_revokeable_redeemscript(revocation_key, contest_delay, broadcaster_delayed_payment_key).to_v0_p2wsh(),
		value: output_value,
	}
}

/// Returns the witness required to satisfy and spend a HTLC input.
pub fn build_htlc_input_witness(
	local_sig: &Signature, remote_sig: &Signature, preimage: &Option<PaymentPreimage>,
	redeem_script: &Script, opt_anchors: bool,
) -> Witness {
	let remote_sighash_type = if opt_anchors {
		EcdsaSighashType::SinglePlusAnyoneCanPay
	} else {
		EcdsaSighashType::All
	};

	let mut witness = Witness::new();
	// First push the multisig dummy, note that due to BIP147 (NULLDUMMY) it must be a zero-length element.
	witness.push(vec![]);
	witness.push_bitcoin_signature(&remote_sig.serialize_der(), remote_sighash_type);
	witness.push_bitcoin_signature(&local_sig.serialize_der(), EcdsaSighashType::All);
	if let Some(preimage) = preimage {
		witness.push(preimage.0.to_vec());
	} else {
		// Due to BIP146 (MINIMALIF) this must be a zero-length element to relay.
		witness.push(vec![]);
	}
	witness.push(redeem_script.to_bytes());
	witness
}

/// Gets the witnessScript for the to_remote output when anchors are enabled.
#[inline]
pub fn get_to_countersignatory_with_anchors_redeemscript(payment_point: &PublicKey) -> Script {
	Builder::new()
		.push_slice(&payment_point.serialize()[..])
		.push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
		.push_int(1)
		.push_opcode(opcodes::all::OP_CSV)
		.into_script()
}

/// Gets the witnessScript for an anchor output from the funding public key.
/// The witness in the spending input must be:
/// <BIP 143 funding_signature>
/// After 16 blocks of confirmation, an alternative satisfying witness could be:
/// <>
/// (empty vector required to satisfy compliance with MINIMALIF-standard rule)
#[inline]
pub fn get_anchor_redeemscript(funding_pubkey: &PublicKey) -> Script {
	Builder::new().push_slice(&funding_pubkey.serialize()[..])
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.push_opcode(opcodes::all::OP_IFDUP)
		.push_opcode(opcodes::all::OP_NOTIF)
		.push_int(16)
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_ENDIF)
		.into_script()
}

#[cfg(anchors)]
/// Locates the output with an anchor script paying to `funding_pubkey` within `commitment_tx`.
pub(crate) fn get_anchor_output<'a>(commitment_tx: &'a Transaction, funding_pubkey: &PublicKey) -> Option<(u32, &'a TxOut)> {
	let anchor_script = chan_utils::get_anchor_redeemscript(funding_pubkey).to_v0_p2wsh();
	commitment_tx.output.iter().enumerate()
		.find(|(_, txout)| txout.script_pubkey == anchor_script)
		.map(|(idx, txout)| (idx as u32, txout))
}

/// Returns the witness required to satisfy and spend an anchor input.
pub fn build_anchor_input_witness(funding_key: &PublicKey, funding_sig: &Signature) -> Witness {
	let anchor_redeem_script = chan_utils::get_anchor_redeemscript(funding_key);
	let mut ret = Witness::new();
	ret.push_bitcoin_signature(&funding_sig.serialize_der(), EcdsaSighashType::All);
	ret.push(anchor_redeem_script.as_bytes());
	ret
}

/// Per-channel data used to build transactions in conjunction with the per-commitment data (CommitmentTransaction).
/// The fields are organized by holder/counterparty.
///
/// Normally, this is converted to the broadcaster/countersignatory-organized DirectedChannelTransactionParameters
/// before use, via the as_holder_broadcastable and as_counterparty_broadcastable functions.
#[derive(Clone, Debug, PartialEq)]
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
	/// Are anchors (zero fee HTLC transaction variant) used for this channel. Boolean is
	/// serialization backwards-compatible.
	pub opt_anchors: Option<()>,
	/// Are non-zero-fee anchors are enabled (used in conjuction with opt_anchors)
	/// It is intended merely for backwards compatibility with signers that need it.
	/// There is no support for this feature in LDK channel negotiation.
	pub opt_non_zero_fee_anchors: Option<()>,
}

/// Late-bound per-channel counterparty data used to build transactions.
#[derive(Clone, Debug, PartialEq)]
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

impl_writeable_tlv_based!(CounterpartyChannelTransactionParameters, {
	(0, pubkeys, required),
	(2, selected_contest_delay, required),
});

impl_writeable_tlv_based!(ChannelTransactionParameters, {
	(0, holder_pubkeys, required),
	(2, holder_selected_contest_delay, required),
	(4, is_outbound_from_holder, required),
	(6, counterparty_parameters, option),
	(8, funding_outpoint, option),
	(10, opt_anchors, option),
	(12, opt_non_zero_fee_anchors, option),
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

	/// Whether to use anchors for this channel
	pub fn opt_anchors(&self) -> bool {
		self.inner.opt_anchors.is_some()
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

impl Eq for HolderCommitmentTransaction {}
impl PartialEq for HolderCommitmentTransaction {
	// We dont care whether we are signed in equality comparison
	fn eq(&self, o: &Self) -> bool {
		self.inner == o.inner
	}
}

impl_writeable_tlv_based!(HolderCommitmentTransaction, {
	(0, inner, required),
	(2, counterparty_sig, required),
	(4, holder_sig_first, required),
	(6, counterparty_htlc_sigs, vec_type),
});

impl HolderCommitmentTransaction {
	#[cfg(test)]
	pub fn dummy() -> Self {
		let secp_ctx = Secp256k1::new();
		let dummy_key = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let dummy_sig = sign(&secp_ctx, &secp256k1::Message::from_slice(&[42; 32]).unwrap(), &SecretKey::from_slice(&[42; 32]).unwrap());

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
			funding_outpoint: Some(chain::transaction::OutPoint { txid: Txid::all_zeros(), index: 0 }),
			opt_anchors: None,
			opt_non_zero_fee_anchors: None,
		};
		let mut htlcs_with_aux: Vec<(_, ())> = Vec::new();
		let inner = CommitmentTransaction::new_with_auxiliary_htlc_data(0, 0, 0, false, dummy_key.clone(), dummy_key.clone(), keys, 0, &mut htlcs_with_aux, &channel_parameters.as_counterparty_broadcastable());
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
			tx.input[0].witness.push_bitcoin_signature(&holder_sig.serialize_der(), EcdsaSighashType::All);
			tx.input[0].witness.push_bitcoin_signature(&self.counterparty_sig.serialize_der(), EcdsaSighashType::All);
		} else {
			tx.input[0].witness.push_bitcoin_signature(&self.counterparty_sig.serialize_der(), EcdsaSighashType::All);
			tx.input[0].witness.push_bitcoin_signature(&holder_sig.serialize_der(), EcdsaSighashType::All);
		}

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

impl_writeable_tlv_based!(BuiltCommitmentTransaction, {
	(0, transaction, required),
	(2, txid, required),
});

impl BuiltCommitmentTransaction {
	/// Get the SIGHASH_ALL sighash value of the transaction.
	///
	/// This can be used to verify a signature.
	pub fn get_sighash_all(&self, funding_redeemscript: &Script, channel_value_satoshis: u64) -> Message {
		let sighash = &sighash::SighashCache::new(&self.transaction).segwit_signature_hash(0, funding_redeemscript, channel_value_satoshis, EcdsaSighashType::All).unwrap()[..];
		hash_to_message!(sighash)
	}

	/// Sign a transaction, either because we are counter-signing the counterparty's transaction or
	/// because we are about to broadcast a holder transaction.
	pub fn sign<T: secp256k1::Signing>(&self, funding_key: &SecretKey, funding_redeemscript: &Script, channel_value_satoshis: u64, secp_ctx: &Secp256k1<T>) -> Signature {
		let sighash = self.get_sighash_all(funding_redeemscript, channel_value_satoshis);
		sign(secp_ctx, &sighash, funding_key)
	}
}

/// This class tracks the per-transaction information needed to build a closing transaction and will
/// actually build it and sign.
///
/// This class can be used inside a signer implementation to generate a signature given the relevant
/// secret key.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct ClosingTransaction {
	to_holder_value_sat: u64,
	to_counterparty_value_sat: u64,
	to_holder_script: Script,
	to_counterparty_script: Script,
	built: Transaction,
}

impl ClosingTransaction {
	/// Construct an object of the class
	pub fn new(
		to_holder_value_sat: u64,
		to_counterparty_value_sat: u64,
		to_holder_script: Script,
		to_counterparty_script: Script,
		funding_outpoint: OutPoint,
	) -> Self {
		let built = build_closing_transaction(
			to_holder_value_sat, to_counterparty_value_sat,
			to_holder_script.clone(), to_counterparty_script.clone(),
			funding_outpoint
		);
		ClosingTransaction {
			to_holder_value_sat,
			to_counterparty_value_sat,
			to_holder_script,
			to_counterparty_script,
			built
		}
	}

	/// Trust our pre-built transaction.
	///
	/// Applies a wrapper which allows access to the transaction.
	///
	/// This should only be used if you fully trust the builder of this object. It should not
	/// be used by an external signer - instead use the verify function.
	pub fn trust(&self) -> TrustedClosingTransaction {
		TrustedClosingTransaction { inner: self }
	}

	/// Verify our pre-built transaction.
	///
	/// Applies a wrapper which allows access to the transaction.
	///
	/// An external validating signer must call this method before signing
	/// or using the built transaction.
	pub fn verify(&self, funding_outpoint: OutPoint) -> Result<TrustedClosingTransaction, ()> {
		let built = build_closing_transaction(
			self.to_holder_value_sat, self.to_counterparty_value_sat,
			self.to_holder_script.clone(), self.to_counterparty_script.clone(),
			funding_outpoint
		);
		if self.built != built {
			return Err(())
		}
		Ok(TrustedClosingTransaction { inner: self })
	}

	/// The value to be sent to the holder, or zero if the output will be omitted
	pub fn to_holder_value_sat(&self) -> u64 {
		self.to_holder_value_sat
	}

	/// The value to be sent to the counterparty, or zero if the output will be omitted
	pub fn to_counterparty_value_sat(&self) -> u64 {
		self.to_counterparty_value_sat
	}

	/// The destination of the holder's output
	pub fn to_holder_script(&self) -> &Script {
		&self.to_holder_script
	}

	/// The destination of the counterparty's output
	pub fn to_counterparty_script(&self) -> &Script {
		&self.to_counterparty_script
	}
}

/// A wrapper on ClosingTransaction indicating that the built bitcoin
/// transaction is trusted.
///
/// See trust() and verify() functions on CommitmentTransaction.
///
/// This structure implements Deref.
pub struct TrustedClosingTransaction<'a> {
	inner: &'a ClosingTransaction,
}

impl<'a> Deref for TrustedClosingTransaction<'a> {
	type Target = ClosingTransaction;

	fn deref(&self) -> &Self::Target { self.inner }
}

impl<'a> TrustedClosingTransaction<'a> {
	/// The pre-built Bitcoin commitment transaction
	pub fn built_transaction(&self) -> &Transaction {
		&self.inner.built
	}

	/// Get the SIGHASH_ALL sighash value of the transaction.
	///
	/// This can be used to verify a signature.
	pub fn get_sighash_all(&self, funding_redeemscript: &Script, channel_value_satoshis: u64) -> Message {
		let sighash = &sighash::SighashCache::new(&self.inner.built).segwit_signature_hash(0, funding_redeemscript, channel_value_satoshis, EcdsaSighashType::All).unwrap()[..];
		hash_to_message!(sighash)
	}

	/// Sign a transaction, either because we are counter-signing the counterparty's transaction or
	/// because we are about to broadcast a holder transaction.
	pub fn sign<T: secp256k1::Signing>(&self, funding_key: &SecretKey, funding_redeemscript: &Script, channel_value_satoshis: u64, secp_ctx: &Secp256k1<T>) -> Signature {
		let sighash = self.get_sighash_all(funding_redeemscript, channel_value_satoshis);
		sign(secp_ctx, &sighash, funding_key)
	}
}

/// This class tracks the per-transaction information needed to build a commitment transaction and will
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
	// A boolean that is serialization backwards-compatible
	opt_anchors: Option<()>,
	// Whether non-zero-fee anchors should be used
	opt_non_zero_fee_anchors: Option<()>,
	// A cache of the parties' pubkeys required to construct the transaction, see doc for trust()
	keys: TxCreationKeys,
	// For access to the pre-built transaction, see doc for trust()
	built: BuiltCommitmentTransaction,
}

impl Eq for CommitmentTransaction {}
impl PartialEq for CommitmentTransaction {
	fn eq(&self, o: &Self) -> bool {
		let eq = self.commitment_number == o.commitment_number &&
			self.to_broadcaster_value_sat == o.to_broadcaster_value_sat &&
			self.to_countersignatory_value_sat == o.to_countersignatory_value_sat &&
			self.feerate_per_kw == o.feerate_per_kw &&
			self.htlcs == o.htlcs &&
			self.opt_anchors == o.opt_anchors &&
			self.keys == o.keys;
		if eq {
			debug_assert_eq!(self.built.transaction, o.built.transaction);
			debug_assert_eq!(self.built.txid, o.built.txid);
		}
		eq
	}
}

impl_writeable_tlv_based!(CommitmentTransaction, {
	(0, commitment_number, required),
	(2, to_broadcaster_value_sat, required),
	(4, to_countersignatory_value_sat, required),
	(6, feerate_per_kw, required),
	(8, keys, required),
	(10, built, required),
	(12, htlcs, vec_type),
	(14, opt_anchors, option),
	(16, opt_non_zero_fee_anchors, option),
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
	pub fn new_with_auxiliary_htlc_data<T>(commitment_number: u64, to_broadcaster_value_sat: u64, to_countersignatory_value_sat: u64, opt_anchors: bool, broadcaster_funding_key: PublicKey, countersignatory_funding_key: PublicKey, keys: TxCreationKeys, feerate_per_kw: u32, htlcs_with_aux: &mut Vec<(HTLCOutputInCommitment, T)>, channel_parameters: &DirectedChannelTransactionParameters) -> CommitmentTransaction {
		// Sort outputs and populate output indices while keeping track of the auxiliary data
		let (outputs, htlcs) = Self::internal_build_outputs(&keys, to_broadcaster_value_sat, to_countersignatory_value_sat, htlcs_with_aux, channel_parameters, opt_anchors, &broadcaster_funding_key, &countersignatory_funding_key).unwrap();

		let (obscured_commitment_transaction_number, txins) = Self::internal_build_inputs(commitment_number, channel_parameters);
		let transaction = Self::make_transaction(obscured_commitment_transaction_number, txins, outputs);
		let txid = transaction.txid();
		CommitmentTransaction {
			commitment_number,
			to_broadcaster_value_sat,
			to_countersignatory_value_sat,
			feerate_per_kw,
			htlcs,
			opt_anchors: if opt_anchors { Some(()) } else { None },
			keys,
			built: BuiltCommitmentTransaction {
				transaction,
				txid
			},
			opt_non_zero_fee_anchors: None,
		}
	}

	/// Use non-zero fee anchors
	///
	/// (C-not exported) due to move, and also not likely to be useful for binding users
	pub fn with_non_zero_fee_anchors(mut self) -> Self {
		self.opt_non_zero_fee_anchors = Some(());
		self
	}

	fn internal_rebuild_transaction(&self, keys: &TxCreationKeys, channel_parameters: &DirectedChannelTransactionParameters, broadcaster_funding_key: &PublicKey, countersignatory_funding_key: &PublicKey) -> Result<BuiltCommitmentTransaction, ()> {
		let (obscured_commitment_transaction_number, txins) = Self::internal_build_inputs(self.commitment_number, channel_parameters);

		let mut htlcs_with_aux = self.htlcs.iter().map(|h| (h.clone(), ())).collect();
		let (outputs, _) = Self::internal_build_outputs(keys, self.to_broadcaster_value_sat, self.to_countersignatory_value_sat, &mut htlcs_with_aux, channel_parameters, self.opt_anchors.is_some(), broadcaster_funding_key, countersignatory_funding_key)?;

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
			lock_time: PackedLockTime(((0x20 as u32) << 8 * 3) | ((obscured_commitment_transaction_number & 0xffffffu64) as u32)),
			input: txins,
			output: outputs,
		}
	}

	// This is used in two cases:
	// - initial sorting of outputs / HTLCs in the constructor, in which case T is auxiliary data the
	//   caller needs to have sorted together with the HTLCs so it can keep track of the output index
	// - building of a bitcoin transaction during a verify() call, in which case T is just ()
	fn internal_build_outputs<T>(keys: &TxCreationKeys, to_broadcaster_value_sat: u64, to_countersignatory_value_sat: u64, htlcs_with_aux: &mut Vec<(HTLCOutputInCommitment, T)>, channel_parameters: &DirectedChannelTransactionParameters, opt_anchors: bool, broadcaster_funding_key: &PublicKey, countersignatory_funding_key: &PublicKey) -> Result<(Vec<TxOut>, Vec<HTLCOutputInCommitment>), ()> {
		let countersignatory_pubkeys = channel_parameters.countersignatory_pubkeys();
		let contest_delay = channel_parameters.contest_delay();

		let mut txouts: Vec<(TxOut, Option<&mut HTLCOutputInCommitment>)> = Vec::new();

		if to_countersignatory_value_sat > 0 {
			let script = if opt_anchors {
			    get_to_countersignatory_with_anchors_redeemscript(&countersignatory_pubkeys.payment_point).to_v0_p2wsh()
			} else {
			    Payload::p2wpkh(&BitcoinPublicKey::new(countersignatory_pubkeys.payment_point)).unwrap().script_pubkey()
			};
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

		if opt_anchors {
			if to_broadcaster_value_sat > 0 || !htlcs_with_aux.is_empty() {
				let anchor_script = get_anchor_redeemscript(broadcaster_funding_key);
				txouts.push((
					TxOut {
						script_pubkey: anchor_script.to_v0_p2wsh(),
						value: ANCHOR_OUTPUT_VALUE_SATOSHI,
					},
					None,
				));
			}

			if to_countersignatory_value_sat > 0 || !htlcs_with_aux.is_empty() {
				let anchor_script = get_anchor_redeemscript(countersignatory_funding_key);
				txouts.push((
					TxOut {
						script_pubkey: anchor_script.to_v0_p2wsh(),
						value: ANCHOR_OUTPUT_VALUE_SATOSHI,
					},
					None,
				));
			}
		}

		let mut htlcs = Vec::with_capacity(htlcs_with_aux.len());
		for (htlc, _) in htlcs_with_aux {
			let script = chan_utils::get_htlc_redeemscript(&htlc, opt_anchors, &keys);
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
						// here for fuzzing mode (otherwise at least chanmon_fail_consistency
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
				sequence: Sequence(((0x80 as u32) << 8 * 3)
					| ((obscured_commitment_transaction_number >> 3 * 8) as u32)),
				witness: Witness::new(),
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
	/// be used by an external signer - instead use the verify function.
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
		let keys = TxCreationKeys::from_channel_static_keys(&per_commitment_point, broadcaster_keys, countersignatory_keys, secp_ctx);
		if keys != self.keys {
			return Err(());
		}
		let tx = self.internal_rebuild_transaction(&keys, channel_parameters, &broadcaster_keys.funding_pubkey, &countersignatory_keys.funding_pubkey)?;
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

	/// Should anchors be used.
	pub fn opt_anchors(&self) -> bool {
		self.opt_anchors.is_some()
	}

	/// Get a signature for each HTLC which was included in the commitment transaction (ie for
	/// which HTLCOutputInCommitment::transaction_output_index.is_some()).
	///
	/// The returned Vec has one entry for each HTLC, and in the same order.
	///
	/// This function is only valid in the holder commitment context, it always uses EcdsaSighashType::All.
	pub fn get_htlc_sigs<T: secp256k1::Signing>(&self, htlc_base_key: &SecretKey, channel_parameters: &DirectedChannelTransactionParameters, secp_ctx: &Secp256k1<T>) -> Result<Vec<Signature>, ()> {
		let inner = self.inner;
		let keys = &inner.keys;
		let txid = inner.built.txid;
		let mut ret = Vec::with_capacity(inner.htlcs.len());
		let holder_htlc_key = derive_private_key(secp_ctx, &inner.keys.per_commitment_point, htlc_base_key);

		for this_htlc in inner.htlcs.iter() {
			assert!(this_htlc.transaction_output_index.is_some());
			let htlc_tx = build_htlc_transaction(&txid, inner.feerate_per_kw, channel_parameters.contest_delay(), &this_htlc, self.opt_anchors(), self.opt_non_zero_fee_anchors.is_some(), &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

			let htlc_redeemscript = get_htlc_redeemscript_with_explicit_keys(&this_htlc, self.opt_anchors(), &keys.broadcaster_htlc_key, &keys.countersignatory_htlc_key, &keys.revocation_key);

			let sighash = hash_to_message!(&sighash::SighashCache::new(&htlc_tx).segwit_signature_hash(0, &htlc_redeemscript, this_htlc.amount_msat / 1000, EcdsaSighashType::All).unwrap()[..]);
			ret.push(sign(secp_ctx, &sighash, &holder_htlc_key));
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

		let mut htlc_tx = build_htlc_transaction(&txid, inner.feerate_per_kw, channel_parameters.contest_delay(), &this_htlc, self.opt_anchors(), self.opt_non_zero_fee_anchors.is_some(), &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

		let htlc_redeemscript = get_htlc_redeemscript_with_explicit_keys(&this_htlc, self.opt_anchors(), &keys.broadcaster_htlc_key, &keys.countersignatory_htlc_key, &keys.revocation_key);

		htlc_tx.input[0].witness = chan_utils::build_htlc_input_witness(
			signature, counterparty_signature, preimage, &htlc_redeemscript, self.opt_anchors(),
		);
		htlc_tx
	}
}

/// Commitment transaction numbers which appear in the transactions themselves are XOR'd with a
/// shared secret first. This prevents on-chain observers from discovering how many commitment
/// transactions occurred in a channel before it was closed.
///
/// This function gets the shared secret from relevant channel public keys and can be used to
/// "decrypt" the commitment transaction number given a commitment transaction on-chain.
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

#[cfg(test)]
mod tests {
	use super::CounterpartyCommitmentSecrets;
	use crate::{hex, chain};
	use crate::prelude::*;
	use crate::ln::chan_utils::{get_htlc_redeemscript, get_to_countersignatory_with_anchors_redeemscript, CommitmentTransaction, TxCreationKeys, ChannelTransactionParameters, CounterpartyChannelTransactionParameters, HTLCOutputInCommitment};
	use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
	use crate::util::test_utils;
	use crate::chain::keysinterface::{ChannelSigner, SignerProvider};
	use bitcoin::{Network, Txid};
	use bitcoin::hashes::Hash;
	use crate::ln::PaymentHash;
	use bitcoin::hashes::hex::ToHex;
	use bitcoin::util::address::Payload;
	use bitcoin::PublicKey as BitcoinPublicKey;

	#[test]
	fn test_anchors() {
		let secp_ctx = Secp256k1::new();

		let seed = [42; 32];
		let network = Network::Testnet;
		let keys_provider = test_utils::TestKeysInterface::new(&seed, network);
		let signer = keys_provider.derive_channel_signer(3000, keys_provider.generate_channel_keys_id(false, 1_000_000, 0));
		let counterparty_signer = keys_provider.derive_channel_signer(3000, keys_provider.generate_channel_keys_id(true, 1_000_000, 1));
		let delayed_payment_base = &signer.pubkeys().delayed_payment_basepoint;
		let per_commitment_secret = SecretKey::from_slice(&hex::decode("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();
		let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
		let htlc_basepoint = &signer.pubkeys().htlc_basepoint;
		let holder_pubkeys = signer.pubkeys();
		let counterparty_pubkeys = counterparty_signer.pubkeys();
		let keys = TxCreationKeys::derive_new(&secp_ctx, &per_commitment_point, delayed_payment_base, htlc_basepoint, &counterparty_pubkeys.revocation_basepoint, &counterparty_pubkeys.htlc_basepoint);
		let mut channel_parameters = ChannelTransactionParameters {
			holder_pubkeys: holder_pubkeys.clone(),
			holder_selected_contest_delay: 0,
			is_outbound_from_holder: false,
			counterparty_parameters: Some(CounterpartyChannelTransactionParameters { pubkeys: counterparty_pubkeys.clone(), selected_contest_delay: 0 }),
			funding_outpoint: Some(chain::transaction::OutPoint { txid: Txid::all_zeros(), index: 0 }),
			opt_anchors: None,
			opt_non_zero_fee_anchors: None,
		};

		let mut htlcs_with_aux: Vec<(_, ())> = Vec::new();

		// Generate broadcaster and counterparty outputs
		let tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			0, 1000, 2000,
			false,
			holder_pubkeys.funding_pubkey,
			counterparty_pubkeys.funding_pubkey,
			keys.clone(), 1,
			&mut htlcs_with_aux, &channel_parameters.as_holder_broadcastable()
		);
		assert_eq!(tx.built.transaction.output.len(), 2);
		assert_eq!(tx.built.transaction.output[1].script_pubkey, Payload::p2wpkh(&BitcoinPublicKey::new(counterparty_pubkeys.payment_point)).unwrap().script_pubkey());

		// Generate broadcaster and counterparty outputs as well as two anchors
		let tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			0, 1000, 2000,
			true,
			holder_pubkeys.funding_pubkey,
			counterparty_pubkeys.funding_pubkey,
			keys.clone(), 1,
			&mut htlcs_with_aux, &channel_parameters.as_holder_broadcastable()
		);
		assert_eq!(tx.built.transaction.output.len(), 4);
		assert_eq!(tx.built.transaction.output[3].script_pubkey, get_to_countersignatory_with_anchors_redeemscript(&counterparty_pubkeys.payment_point).to_v0_p2wsh());

		// Generate broadcaster output and anchor
		let tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			0, 3000, 0,
			true,
			holder_pubkeys.funding_pubkey,
			counterparty_pubkeys.funding_pubkey,
			keys.clone(), 1,
			&mut htlcs_with_aux, &channel_parameters.as_holder_broadcastable()
		);
		assert_eq!(tx.built.transaction.output.len(), 2);

		// Generate counterparty output and anchor
		let tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			0, 0, 3000,
			true,
			holder_pubkeys.funding_pubkey,
			counterparty_pubkeys.funding_pubkey,
			keys.clone(), 1,
			&mut htlcs_with_aux, &channel_parameters.as_holder_broadcastable()
		);
		assert_eq!(tx.built.transaction.output.len(), 2);

		let received_htlc = HTLCOutputInCommitment {
			offered: false,
			amount_msat: 400000,
			cltv_expiry: 100,
			payment_hash: PaymentHash([42; 32]),
			transaction_output_index: None,
		};

		let offered_htlc = HTLCOutputInCommitment {
			offered: true,
			amount_msat: 600000,
			cltv_expiry: 100,
			payment_hash: PaymentHash([43; 32]),
			transaction_output_index: None,
		};

		// Generate broadcaster output and received and offered HTLC outputs,  w/o anchors
		let tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			0, 3000, 0,
			false,
			holder_pubkeys.funding_pubkey,
			counterparty_pubkeys.funding_pubkey,
			keys.clone(), 1,
			&mut vec![(received_htlc.clone(), ()), (offered_htlc.clone(), ())],
			&channel_parameters.as_holder_broadcastable()
		);
		assert_eq!(tx.built.transaction.output.len(), 3);
		assert_eq!(tx.built.transaction.output[0].script_pubkey, get_htlc_redeemscript(&received_htlc, false, &keys).to_v0_p2wsh());
		assert_eq!(tx.built.transaction.output[1].script_pubkey, get_htlc_redeemscript(&offered_htlc, false, &keys).to_v0_p2wsh());
		assert_eq!(get_htlc_redeemscript(&received_htlc, false, &keys).to_v0_p2wsh().to_hex(),
				   "0020e43a7c068553003fe68fcae424fb7b28ec5ce48cd8b6744b3945631389bad2fb");
		assert_eq!(get_htlc_redeemscript(&offered_htlc, false, &keys).to_v0_p2wsh().to_hex(),
				   "0020215d61bba56b19e9eadb6107f5a85d7f99c40f65992443f69229c290165bc00d");

		// Generate broadcaster output and received and offered HTLC outputs,  with anchors
		channel_parameters.opt_anchors = Some(());
		let tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			0, 3000, 0,
			true,
			holder_pubkeys.funding_pubkey,
			counterparty_pubkeys.funding_pubkey,
			keys.clone(), 1,
			&mut vec![(received_htlc.clone(), ()), (offered_htlc.clone(), ())],
			&channel_parameters.as_holder_broadcastable()
		);
		assert_eq!(tx.built.transaction.output.len(), 5);
		assert_eq!(tx.built.transaction.output[2].script_pubkey, get_htlc_redeemscript(&received_htlc, true, &keys).to_v0_p2wsh());
		assert_eq!(tx.built.transaction.output[3].script_pubkey, get_htlc_redeemscript(&offered_htlc, true, &keys).to_v0_p2wsh());
		assert_eq!(get_htlc_redeemscript(&received_htlc, true, &keys).to_v0_p2wsh().to_hex(),
				   "0020b70d0649c72b38756885c7a30908d912a7898dd5d79457a7280b8e9a20f3f2bc");
		assert_eq!(get_htlc_redeemscript(&offered_htlc, true, &keys).to_v0_p2wsh().to_hex(),
				   "002087a3faeb1950a469c0e2db4a79b093a41b9526e5a6fc6ef5cb949bde3be379c7");
	}

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
