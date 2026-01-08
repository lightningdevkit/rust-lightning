// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Various utilities for building scripts related to channels. These are
//! largely of interest for those implementing the traits on [`crate::sign`] by hand.

use bitcoin::amount::Amount;
use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::opcodes;
use bitcoin::script::{Builder, Script, ScriptBuf};
use bitcoin::sighash;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::transaction::Version;
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::{PubkeyHash, WPubkeyHash};

use bitcoin::hash_types::Txid;
use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::hashes::ripemd160::Hash as Ripemd160;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

use crate::chain::chaininterface::{
	fee_for_weight, ConfirmationTarget, FeeEstimator, LowerBoundedFeeEstimator,
};
use crate::chain::package::WEIGHT_REVOKED_OUTPUT;
use crate::ln::msgs::DecodeError;
use crate::sign::EntropySource;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{Readable, ReadableArgs, RequiredWrapper, Writeable, Writer};
use crate::util::transaction_utils;

use bitcoin::ecdsa::Signature as BitcoinSignature;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1};
use bitcoin::secp256k1::{PublicKey, Scalar, SecretKey};
use bitcoin::{secp256k1, Sequence, Witness};

use super::channel_keys::{
	DelayedPaymentBasepoint, DelayedPaymentKey, HtlcBasepoint, HtlcKey, RevocationBasepoint,
	RevocationKey,
};
use crate::chain;
use crate::crypto::utils::{sign, sign_with_aux_rand};
use crate::io;
use crate::ln::channel::{ANCHOR_OUTPUT_VALUE_SATOSHI, INITIAL_COMMITMENT_NUMBER};
use crate::types::features::ChannelTypeFeatures;
use core::cmp;
use core::ops::Deref;

#[allow(unused_imports)]
use crate::prelude::*;

/// Maximum number of in-flight HTLCs in each direction allowed by the lightning protocol.
///
/// 483 for non-zero-fee-commitment channels and 114 for zero-fee-commitment channels.
///
/// Actual maximums can be set equal to or below this value by each channel participant.
pub fn max_htlcs(channel_type: &ChannelTypeFeatures) -> u16 {
	if channel_type.supports_anchor_zero_fee_commitments() {
		// TRUC restricts the size of our commitment transactions to 10K vB rather than 100K vB
		114
	} else {
		483
	}
}
/// The weight of a BIP141 witnessScript for a BOLT3's "offered HTLC output" on a commitment transaction, non-anchor and p2a anchor variant.
pub const OFFERED_HTLC_SCRIPT_WEIGHT: usize = 133;
/// The weight of a BIP141 witnessScript for a BOLT3's "offered HTLC output" on a commitment transaction, keyed anchor variant.
pub const OFFERED_HTLC_SCRIPT_WEIGHT_KEYED_ANCHORS: usize = 136;

/// The weight of a BIP141 witnessScript for a BOLT3's "received HTLC output" can vary in function of its CLTV argument value.
/// We define a range that encompasses both its non-anchors and anchors variants.
pub(crate) const MIN_ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = 136;
/// The weight of a BIP141 witnessScript for a BOLT3's "received HTLC output" can vary in function of its CLTV argument value.
/// We define a range that encompasses both its non-anchors and anchors variants.
/// This is the maximum post-anchor value.
pub const MAX_ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = 143;

/// The upper bound weight of an anchor input.
#[cfg(feature = "grind_signatures")]
pub const ANCHOR_INPUT_WITNESS_WEIGHT: u64 = 114;
/// The upper bound weight of an anchor input.
#[cfg(not(feature = "grind_signatures"))]
pub const ANCHOR_INPUT_WITNESS_WEIGHT: u64 = 115;

/// The weight of an empty witness; used to spend a P2A output.
pub const EMPTY_WITNESS_WEIGHT: u64 = 1;

/// The maximum value of a P2A anchor.
pub const P2A_MAX_VALUE: u64 = 240;

/// The maximum weight of a TRUC transaction, see BIP431.
pub const TRUC_MAX_WEIGHT: u64 = 10_000 * WITNESS_SCALE_FACTOR as u64;

/// The maximum weight of a TRUC transaction with an unconfirmed TRUC ancestor, see BIP431.
pub const TRUC_CHILD_MAX_WEIGHT: u64 = 1000 * WITNESS_SCALE_FACTOR as u64;

/// The upper bound weight of an HTLC timeout input from a commitment transaction with keyed anchor outputs.
pub const HTLC_TIMEOUT_INPUT_KEYED_ANCHOR_WITNESS_WEIGHT: u64 = 288;
/// The upper bound weight of an HTLC timeout input from a commitment transaction with a p2a anchor output.
/// Note the corresponding outputs no longer have the 1 CSV lock.
pub const HTLC_TIMEOUT_INPUT_P2A_ANCHOR_WITNESS_WEIGHT: u64 = 285;
/// The upper bound weight of an HTLC success input from a commitment transaction with keyed anchor outputs.
pub const HTLC_SUCCESS_INPUT_KEYED_ANCHOR_WITNESS_WEIGHT: u64 = 327;
/// The upper bound weight of an HTLC success input from a commitment transaction with a p2a anchor output.
/// Note the corresponding outputs no longer have the 1 CSV lock.
pub const HTLC_SUCCESS_INPUT_P2A_ANCHOR_WITNESS_WEIGHT: u64 = 324;

/// The size of the 2-of-2 multisig script
const MULTISIG_SCRIPT_SIZE: u64 = 1 + // OP_2
	1 + // data len
	crate::sign::COMPRESSED_PUBLIC_KEY_SIZE as u64 + // pubkey1
	1 + // data len
	crate::sign::COMPRESSED_PUBLIC_KEY_SIZE as u64 + // pubkey2
	1 + // OP_2
	1; // OP_CHECKMULTISIG

/// The weight of a funding transaction input (2-of-2 P2WSH).
///
/// Unlike in the [spec], 72 WU is used for the max signature size since 73 WU signatures are
/// non-standard.
///
/// Note: If you have the `grind_signatures` feature enabled, this will be at least 1 byte
/// shorter.
///
/// [spec]: https://github.com/lightning/bolts/blob/master/03-transactions.md#expected-weight-of-the-commitment-transaction
pub const FUNDING_TRANSACTION_WITNESS_WEIGHT: u64 = 1 + // number_of_witness_elements
	1 + // nil_len
	1 + // sig len
	crate::sign::MAX_STANDARD_SIGNATURE_SIZE as u64 + // sig1
	1 + // sig len
	crate::sign::MAX_STANDARD_SIGNATURE_SIZE as u64 + // sig2
	1 + // witness_script_length
	MULTISIG_SCRIPT_SIZE;

pub(crate) const BASE_TX_SIZE: u64 = 4 /* version */ + 1 /* input count */ + 1 /* output count */ + 4 /* locktime */;
pub(crate) const SEGWIT_MARKER_FLAG_WEIGHT: u64 = 2;
pub(crate) const EMPTY_SCRIPT_SIG_WEIGHT: u64 =
	1 /* empty script_sig */ * WITNESS_SCALE_FACTOR as u64;
pub(crate) const BASE_INPUT_SIZE: u64 = 32 /* txid */ + 4 /* vout */ + 4 /* sequence */;
pub(crate) const BASE_INPUT_WEIGHT: u64 = BASE_INPUT_SIZE * WITNESS_SCALE_FACTOR as u64;
pub(crate) const P2WSH_TXOUT_WEIGHT: u64 =
	(8 /* value */ + 1 /* var_int */ + 34/* p2wsh spk */) * WITNESS_SCALE_FACTOR as u64;

/// Gets the weight for an HTLC-Success transaction.
#[inline]
#[rustfmt::skip]
pub fn htlc_success_tx_weight(channel_type_features: &ChannelTypeFeatures) -> u64 {
	const HTLC_SUCCESS_TX_WEIGHT: u64 = 703;
	const HTLC_SUCCESS_ANCHOR_TX_WEIGHT: u64 = 706;
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() { HTLC_SUCCESS_ANCHOR_TX_WEIGHT } else { HTLC_SUCCESS_TX_WEIGHT }
}

/// Gets the weight of a single input-output pair in externally funded HTLC-success transactions
pub fn aggregated_htlc_success_input_output_pair_weight(
	channel_type_features: &ChannelTypeFeatures,
) -> u64 {
	let satisfaction_weight = if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
		EMPTY_SCRIPT_SIG_WEIGHT + HTLC_SUCCESS_INPUT_KEYED_ANCHOR_WITNESS_WEIGHT
	} else {
		EMPTY_SCRIPT_SIG_WEIGHT + HTLC_SUCCESS_INPUT_P2A_ANCHOR_WITNESS_WEIGHT
	};
	BASE_INPUT_WEIGHT + P2WSH_TXOUT_WEIGHT + satisfaction_weight
}

/// Gets the weight for an HTLC-Timeout transaction.
#[inline]
#[rustfmt::skip]
pub fn htlc_timeout_tx_weight(channel_type_features: &ChannelTypeFeatures) -> u64 {
	const HTLC_TIMEOUT_TX_WEIGHT: u64 = 663;
	const HTLC_TIMEOUT_ANCHOR_TX_WEIGHT: u64 = 666;
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() { HTLC_TIMEOUT_ANCHOR_TX_WEIGHT } else { HTLC_TIMEOUT_TX_WEIGHT }
}

/// Gets the weight of a single input-output pair in externally funded HTLC-timeout transactions
pub fn aggregated_htlc_timeout_input_output_pair_weight(
	channel_type_features: &ChannelTypeFeatures,
) -> u64 {
	let satisfaction_weight = if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
		EMPTY_SCRIPT_SIG_WEIGHT + HTLC_TIMEOUT_INPUT_KEYED_ANCHOR_WITNESS_WEIGHT
	} else {
		EMPTY_SCRIPT_SIG_WEIGHT + HTLC_TIMEOUT_INPUT_P2A_ANCHOR_WITNESS_WEIGHT
	};
	BASE_INPUT_WEIGHT + P2WSH_TXOUT_WEIGHT + satisfaction_weight
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
	#[rustfmt::skip]
	pub fn from_witness(witness: &Witness) -> Option<Self> {
		debug_assert_eq!(OFFERED_HTLC_SCRIPT_WEIGHT_KEYED_ANCHORS, MIN_ACCEPTED_HTLC_SCRIPT_WEIGHT);
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
		} else if witness_script.len() == OFFERED_HTLC_SCRIPT_WEIGHT_KEYED_ANCHORS {
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

#[cfg(not(any(test, feature = "_test_utils")))]
const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;
#[cfg(any(test, feature = "_test_utils"))]
pub const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;

#[rustfmt::skip]
pub(crate) fn commitment_tx_base_weight(channel_type_features: &ChannelTypeFeatures) -> u64 {
	const COMMITMENT_TX_BASE_WEIGHT: u64 = 724;
	const COMMITMENT_TX_BASE_ANCHOR_WEIGHT: u64 = 1124;
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() { COMMITMENT_TX_BASE_ANCHOR_WEIGHT } else { COMMITMENT_TX_BASE_WEIGHT }
}

/// Get the fee cost of a commitment tx with a given number of HTLC outputs.
/// Note that num_htlcs should not include dust HTLCs.
#[rustfmt::skip]
pub(crate) fn commit_tx_fee_sat(feerate_per_kw: u32, num_htlcs: usize, channel_type_features: &ChannelTypeFeatures) -> u64 {
	feerate_per_kw as u64 *
		(commitment_tx_base_weight(channel_type_features) +
			num_htlcs as u64 * COMMITMENT_TX_WEIGHT_PER_HTLC)
		/ 1000
}

/// Returns the fees for success and timeout second stage HTLC transactions.
pub(crate) fn second_stage_tx_fees_sat(
	channel_type: &ChannelTypeFeatures, feerate_sat_per_1000_weight: u32,
) -> (u64, u64) {
	if channel_type.supports_anchors_zero_fee_htlc_tx()
		|| channel_type.supports_anchor_zero_fee_commitments()
	{
		(0, 0)
	} else {
		(
			feerate_sat_per_1000_weight as u64 * htlc_success_tx_weight(channel_type) / 1000,
			feerate_sat_per_1000_weight as u64 * htlc_timeout_tx_weight(channel_type) / 1000,
		)
	}
}

#[rustfmt::skip]
pub(crate) fn htlc_tx_fees_sat(feerate_per_kw: u32, num_accepted_htlcs: usize, num_offered_htlcs: usize, channel_type_features: &ChannelTypeFeatures) -> u64 {
	let (htlc_success_tx_fee_sat, htlc_timeout_tx_fee_sat) = second_stage_tx_fees_sat(
		channel_type_features, feerate_per_kw,
	);

	num_accepted_htlcs as u64 * htlc_success_tx_fee_sat + num_offered_htlcs as u64 * htlc_timeout_tx_fee_sat
}

/// Returns a fee estimate for the commitment transaction that we would ideally like to set,
/// depending on channel type.
pub(super) fn selected_commitment_sat_per_1000_weight<F: Deref>(
	fee_estimator: &LowerBoundedFeeEstimator<F>, channel_type: &ChannelTypeFeatures,
) -> u32
where
	F::Target: FeeEstimator,
{
	if channel_type.supports_anchor_zero_fee_commitments() {
		0
	} else if channel_type.supports_anchors_zero_fee_htlc_tx() {
		fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::AnchorChannelFee)
	} else {
		fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee)
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
			res = Sha256::hash(&res).to_byte_array();
		}
	}
	res
}

/// Build a closing transaction
#[rustfmt::skip]
pub fn build_closing_transaction(to_holder_value_sat: Amount, to_counterparty_value_sat: Amount, to_holder_script: ScriptBuf, to_counterparty_script: ScriptBuf, funding_outpoint: OutPoint) -> Transaction {
	let txins = {
		let ins: Vec<TxIn> = vec![TxIn {
			previous_output: funding_outpoint,
			script_sig: ScriptBuf::new(),
			sequence: Sequence::MAX,
			witness: Witness::new(),
		}];
		ins
	};

	let mut txouts: Vec<(TxOut, ())> = Vec::new();

	if to_counterparty_value_sat > Amount::ZERO {
		txouts.push((TxOut {
			script_pubkey: to_counterparty_script,
			value: to_counterparty_value_sat
		}, ()));
	}

	if to_holder_value_sat > Amount::ZERO {
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
		version: Version::TWO,
		lock_time: LockTime::ZERO,
		input: txins,
		output: outputs,
	}
}

/// Implements the per-commitment secret storage scheme from
/// [BOLT 3](https://github.com/lightning/bolts/blob/dcbf8583976df087c79c3ce0b535311212e6812d/03-transactions.md#efficient-per-commitment-secret-storage).
///
/// Allows us to keep track of all of the revocation secrets of our counterparty in just 50*32 bytes
/// or so.
#[derive(Clone, Debug)]
pub struct CounterpartyCommitmentSecrets {
	old_secrets: [([u8; 32], u64); 49],
}

impl Eq for CounterpartyCommitmentSecrets {}
impl PartialEq for CounterpartyCommitmentSecrets {
	#[rustfmt::skip]
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
	#[rustfmt::skip]
	pub fn new() -> Self {
		Self { old_secrets: [([0; 32], 1 << 48); 49], }
	}

	#[inline]
	#[rustfmt::skip]
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
				res = Sha256::hash(&res).to_byte_array();
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
	#[rustfmt::skip]
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
pub fn derive_private_key<T: secp256k1::Signing>(
	secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_secret: &SecretKey,
) -> SecretKey {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&PublicKey::from_secret_key(&secp_ctx, &base_secret).serialize());
	let res = Sha256::from_engine(sha).to_byte_array();

	base_secret.clone().add_tweak(&Scalar::from_be_bytes(res).unwrap())
		.expect("Addition only fails if the tweak is the inverse of the key. This is not possible when the tweak contains the hash of the key.")
}

/// Derives a per-commitment-transaction revocation key from its constituent parts.
///
/// Only the cheating participant owns a valid witness to propagate a revoked
/// commitment transaction, thus per_commitment_secret always come from cheater
/// and revocation_base_secret always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
#[rustfmt::skip]
pub fn derive_private_revocation_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>,
	per_commitment_secret: &SecretKey, countersignatory_revocation_base_secret: &SecretKey)
-> SecretKey {
	let countersignatory_revocation_base_point = PublicKey::from_secret_key(&secp_ctx, &countersignatory_revocation_base_secret);
	let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);

	let rev_append_commit_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&countersignatory_revocation_base_point.serialize());
		sha.input(&per_commitment_point.serialize());

		Sha256::from_engine(sha).to_byte_array()
	};
	let commit_append_rev_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&per_commitment_point.serialize());
		sha.input(&countersignatory_revocation_base_point.serialize());

		Sha256::from_engine(sha).to_byte_array()
	};

	let countersignatory_contrib = countersignatory_revocation_base_secret.clone().mul_tweak(&Scalar::from_be_bytes(rev_append_commit_hash_key).unwrap())
		.expect("Multiplying a secret key by a hash is expected to never fail per secp256k1 docs");
	let broadcaster_contrib = per_commitment_secret.clone().mul_tweak(&Scalar::from_be_bytes(commit_append_rev_hash_key).unwrap())
		.expect("Multiplying a secret key by a hash is expected to never fail per secp256k1 docs");
	countersignatory_contrib.add_tweak(&Scalar::from_be_bytes(broadcaster_contrib.secret_bytes()).unwrap())
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
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TxCreationKeys {
	/// The broadcaster's per-commitment public key which was used to derive the other keys.
	pub per_commitment_point: PublicKey,
	/// The revocation key which is used to allow the broadcaster of the commitment
	/// transaction to provide their counterparty the ability to punish them if they broadcast
	/// an old state.
	pub revocation_key: RevocationKey,
	/// Broadcaster's HTLC Key
	pub broadcaster_htlc_key: HtlcKey,
	/// Countersignatory's HTLC Key
	pub countersignatory_htlc_key: HtlcKey,
	/// Broadcaster's Payment Key (which isn't allowed to be spent from for some delay)
	pub broadcaster_delayed_payment_key: DelayedPaymentKey,
}

impl_writeable_tlv_based!(TxCreationKeys, {
	(0, per_commitment_point, required),
	(2, revocation_key, required),
	(4, broadcaster_htlc_key, required),
	(6, countersignatory_htlc_key, required),
	(8, broadcaster_delayed_payment_key, required),
});

/// One counterparty's public keys which do not change over the life of a channel.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ChannelPublicKeys {
	/// The public key which is used to sign all commitment transactions, as it appears in the
	/// on-chain channel lock-in 2-of-2 multisig output.
	pub funding_pubkey: PublicKey,
	/// The base point which is used (with [`RevocationKey::from_basepoint`]) to derive per-commitment
	/// revocation keys. This is combined with the per-commitment-secret generated by the
	/// counterparty to create a secret which the counterparty can reveal to revoke previous
	/// states.
	pub revocation_basepoint: RevocationBasepoint,
	/// The public key on which the non-broadcaster (ie the countersignatory) receives an immediately
	/// spendable primary channel balance on the broadcaster's commitment transaction. This key is
	/// static across every commitment transaction.
	pub payment_point: PublicKey,
	/// The base point which is used (with derive_public_key) to derive a per-commitment payment
	/// public key which receives non-HTLC-encumbered funds which are only available for spending
	/// after some delay (or can be claimed via the revocation path).
	pub delayed_payment_basepoint: DelayedPaymentBasepoint,
	/// The base point which is used (with derive_public_key) to derive a per-commitment public key
	/// which is used to encumber HTLC-in-flight outputs.
	pub htlc_basepoint: HtlcBasepoint,
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
	#[rustfmt::skip]
	pub fn derive_new<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, broadcaster_delayed_payment_base: &DelayedPaymentBasepoint, broadcaster_htlc_base: &HtlcBasepoint, countersignatory_revocation_base: &RevocationBasepoint, countersignatory_htlc_base: &HtlcBasepoint) -> TxCreationKeys {
		TxCreationKeys {
			per_commitment_point: per_commitment_point.clone(),
			revocation_key: RevocationKey::from_basepoint(&secp_ctx, &countersignatory_revocation_base, &per_commitment_point),
			broadcaster_htlc_key: HtlcKey::from_basepoint(&secp_ctx, &broadcaster_htlc_base, &per_commitment_point),
			countersignatory_htlc_key: HtlcKey::from_basepoint(&secp_ctx, &countersignatory_htlc_base, &per_commitment_point),
			broadcaster_delayed_payment_key: DelayedPaymentKey::from_basepoint(&secp_ctx, &broadcaster_delayed_payment_base, &per_commitment_point),
		}
	}

	/// Generate per-state keys from channel static keys.
	/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
	pub fn from_channel_static_keys<T: secp256k1::Signing + secp256k1::Verification>(
		per_commitment_point: &PublicKey, broadcaster_keys: &ChannelPublicKeys,
		countersignatory_keys: &ChannelPublicKeys, secp_ctx: &Secp256k1<T>,
	) -> TxCreationKeys {
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
// Calculated as 6 bytes of opcodes, 1 byte push plus 3 bytes for contest_delay, and two public
// keys of 33 bytes (+ 1 push). Generally, pushes are only 2 bytes (for values below 0x7fff, i.e.
// around 7 months), however, a 7 month contest delay shouldn't result in being unable to reclaim
// on-chain funds.
pub const REVOKEABLE_REDEEMSCRIPT_MAX_LENGTH: usize = 6 + 4 + 34 * 2;

/// A script either spendable by the revocation
/// key or the broadcaster_delayed_payment_key and satisfying the relative-locktime OP_CSV constrain.
/// Encumbering a `to_holder` output on a commitment transaction or 2nd-stage HTLC transactions.
#[rustfmt::skip]
pub fn get_revokeable_redeemscript(revocation_key: &RevocationKey, contest_delay: u16, broadcaster_delayed_payment_key: &DelayedPaymentKey) -> ScriptBuf {
	let res = Builder::new().push_opcode(opcodes::all::OP_IF)
	              .push_slice(&revocation_key.to_public_key().serialize())
	              .push_opcode(opcodes::all::OP_ELSE)
	              .push_int(contest_delay as i64)
	              .push_opcode(opcodes::all::OP_CSV)
	              .push_opcode(opcodes::all::OP_DROP)
	              .push_slice(&broadcaster_delayed_payment_key.to_public_key().serialize())
	              .push_opcode(opcodes::all::OP_ENDIF)
	              .push_opcode(opcodes::all::OP_CHECKSIG)
	              .into_script();
	debug_assert!(res.len() <= REVOKEABLE_REDEEMSCRIPT_MAX_LENGTH);
	res
}

/// Returns the script for the countersigner's (i.e. non-broadcaster's) output on a commitment
/// transaction based on the channel type.
pub fn get_countersigner_payment_script(
	channel_type_features: &ChannelTypeFeatures, payment_key: &PublicKey,
) -> ScriptBuf {
	if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
		get_to_countersigner_keyed_anchor_redeemscript(payment_key).to_p2wsh()
	} else {
		ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&payment_key.serialize()))
	}
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

impl HTLCOutputInCommitment {
	/// Converts HTLC's value with millisatoshi precision into [bitcoin::Amount] with satoshi precision.
	/// Typically this conversion is needed when transitioning from LN into base-layer Bitcoin,
	/// e. g. in commitment transactions.
	pub const fn to_bitcoin_amount(&self) -> Amount {
		Amount::from_sat(self.amount_msat / 1000)
	}

	/// This method intentionally does not compare the transaction output indices, as it serves to
	/// match HTLCs that do not have their output index populated with those that do.
	pub(crate) fn is_data_equal(&self, other: &HTLCOutputInCommitment) -> bool {
		self.offered == other.offered
			&& self.amount_msat == other.amount_msat
			&& self.cltv_expiry == other.cltv_expiry
			&& self.payment_hash == other.payment_hash
	}
}

impl_writeable_tlv_based!(HTLCOutputInCommitment, {
	(0, offered, required),
	(2, amount_msat, required),
	(4, cltv_expiry, required),
	(6, payment_hash, required),
	(8, transaction_output_index, option),
});

#[inline]
#[rustfmt::skip]
pub(crate) fn get_htlc_redeemscript_with_explicit_keys(htlc: &HTLCOutputInCommitment, channel_type_features: &ChannelTypeFeatures, broadcaster_htlc_key: &HtlcKey, countersignatory_htlc_key: &HtlcKey, revocation_key: &RevocationKey) -> ScriptBuf {
	let payment_hash160 = Ripemd160::hash(&htlc.payment_hash.0[..]).to_byte_array();
	if htlc.offered {
		let mut bldr = Builder::new().push_opcode(opcodes::all::OP_DUP)
		              .push_opcode(opcodes::all::OP_HASH160)
		              .push_slice(PubkeyHash::hash(&revocation_key.to_public_key().serialize()))
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_IF)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_slice(&countersignatory_htlc_key.to_public_key().serialize())
		              .push_opcode(opcodes::all::OP_SWAP)
		              .push_opcode(opcodes::all::OP_SIZE)
		              .push_int(32)
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_NOTIF)
		              .push_opcode(opcodes::all::OP_DROP)
		              .push_int(2)
		              .push_opcode(opcodes::all::OP_SWAP)
		              .push_slice(&broadcaster_htlc_key.to_public_key().serialize())
		              .push_int(2)
		              .push_opcode(opcodes::all::OP_CHECKMULTISIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_opcode(opcodes::all::OP_HASH160)
		              .push_slice(&payment_hash160)
		              .push_opcode(opcodes::all::OP_EQUALVERIFY)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ENDIF);
		if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
			bldr = bldr.push_opcode(opcodes::all::OP_PUSHNUM_1)
				.push_opcode(opcodes::all::OP_CSV)
				.push_opcode(opcodes::all::OP_DROP);
		}
		bldr.push_opcode(opcodes::all::OP_ENDIF)
			.into_script()
	} else {
			let mut bldr = Builder::new().push_opcode(opcodes::all::OP_DUP)
		              .push_opcode(opcodes::all::OP_HASH160)
		              .push_slice(&PubkeyHash::hash(&revocation_key.to_public_key().serialize()))
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_IF)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_slice(&countersignatory_htlc_key.to_public_key().serialize())
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
		              .push_slice(&broadcaster_htlc_key.to_public_key().serialize())
		              .push_int(2)
		              .push_opcode(opcodes::all::OP_CHECKMULTISIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_opcode(opcodes::all::OP_DROP)
		              .push_int(htlc.cltv_expiry as i64)
		              .push_opcode(opcodes::all::OP_CLTV)
		              .push_opcode(opcodes::all::OP_DROP)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ENDIF);
		if channel_type_features.supports_anchors_zero_fee_htlc_tx() {
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
#[rustfmt::skip]
pub fn get_htlc_redeemscript(htlc: &HTLCOutputInCommitment, channel_type_features: &ChannelTypeFeatures, keys: &TxCreationKeys) -> ScriptBuf {
	get_htlc_redeemscript_with_explicit_keys(htlc, channel_type_features, &keys.broadcaster_htlc_key, &keys.countersignatory_htlc_key, &keys.revocation_key)
}

/// Gets the redeemscript for a funding output from the two funding public keys.
/// Note that the order of funding public keys does not matter.
pub fn make_funding_redeemscript(
	broadcaster: &PublicKey, countersignatory: &PublicKey,
) -> ScriptBuf {
	let broadcaster_funding_key = broadcaster.serialize();
	let countersignatory_funding_key = countersignatory.serialize();

	make_funding_redeemscript_from_slices(&broadcaster_funding_key, &countersignatory_funding_key)
}

#[rustfmt::skip]
pub(crate) fn make_funding_redeemscript_from_slices(broadcaster_funding_key: &[u8; 33], countersignatory_funding_key: &[u8; 33]) -> ScriptBuf {
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
pub fn build_htlc_transaction(
	commitment_txid: &Txid, feerate_per_kw: u32, contest_delay: u16, htlc: &HTLCOutputInCommitment,
	channel_type_features: &ChannelTypeFeatures,
	broadcaster_delayed_payment_key: &DelayedPaymentKey, revocation_key: &RevocationKey,
) -> Transaction {
	let txins = vec![build_htlc_input(commitment_txid, htlc, channel_type_features)];

	let txouts: Vec<TxOut> = vec![build_htlc_output(
		feerate_per_kw,
		contest_delay,
		htlc,
		channel_type_features,
		broadcaster_delayed_payment_key,
		revocation_key,
	)];

	let version = if channel_type_features.supports_anchor_zero_fee_commitments() {
		Version::non_standard(3)
	} else {
		Version::TWO
	};

	Transaction {
		version,
		lock_time: LockTime::from_consensus(if htlc.offered { htlc.cltv_expiry } else { 0 }),
		input: txins,
		output: txouts,
	}
}

#[rustfmt::skip]
pub(crate) fn build_htlc_input(commitment_txid: &Txid, htlc: &HTLCOutputInCommitment, channel_type_features: &ChannelTypeFeatures) -> TxIn {
	TxIn {
		previous_output: OutPoint {
			txid: commitment_txid.clone(),
			vout: htlc.transaction_output_index.expect("Can't build an HTLC transaction for a dust output"),
		},
		script_sig: ScriptBuf::new(),
		sequence: Sequence(if channel_type_features.supports_anchors_zero_fee_htlc_tx() { 1 } else { 0 }),
		witness: Witness::new(),
	}
}

#[rustfmt::skip]
pub(crate) fn build_htlc_output(
	feerate_per_kw: u32, contest_delay: u16, htlc: &HTLCOutputInCommitment, channel_type_features: &ChannelTypeFeatures, broadcaster_delayed_payment_key: &DelayedPaymentKey, revocation_key: &RevocationKey
) -> TxOut {
	let (htlc_success_tx_fee_sat, htlc_timeout_tx_fee_sat) = second_stage_tx_fees_sat(
		channel_type_features, feerate_per_kw,
	);

	let output_value = {
		let total_fee = if htlc.offered {
			htlc_timeout_tx_fee_sat
		} else {
			htlc_success_tx_fee_sat
		};
		htlc.to_bitcoin_amount() - Amount::from_sat(total_fee)
	};

	TxOut {
		script_pubkey: get_revokeable_redeemscript(revocation_key, contest_delay, broadcaster_delayed_payment_key).to_p2wsh(),
		value: output_value,
	}
}

/// Returns the witness required to satisfy and spend a HTLC input.
pub fn build_htlc_input_witness(
	local_sig: &Signature, remote_sig: &Signature, preimage: &Option<PaymentPreimage>,
	redeem_script: &Script, channel_type_features: &ChannelTypeFeatures,
) -> Witness {
	let remote_sighash_type = if channel_type_features.supports_anchors_zero_fee_htlc_tx()
		|| channel_type_features.supports_anchor_zero_fee_commitments()
	{
		EcdsaSighashType::SinglePlusAnyoneCanPay
	} else {
		EcdsaSighashType::All
	};

	let mut witness = Witness::new();
	// First push the multisig dummy, note that due to BIP147 (NULLDUMMY) it must be a zero-length element.
	witness.push(vec![]);
	witness.push_ecdsa_signature(&BitcoinSignature {
		signature: *remote_sig,
		sighash_type: remote_sighash_type,
	});
	witness.push_ecdsa_signature(&BitcoinSignature::sighash_all(*local_sig));
	if let Some(preimage) = preimage {
		witness.push(preimage.0.to_vec());
	} else {
		// Due to BIP146 (MINIMALIF) this must be a zero-length element to relay.
		witness.push(vec![]);
	}
	witness.push(redeem_script.to_bytes());
	witness
}

/// Pre-anchors channel type features did not use to get serialized in the following six structs:
/// — [`ChannelTransactionParameters`]
/// — [`CommitmentTransaction`]
/// — [`CounterpartyOfferedHTLCOutput`]
/// — [`CounterpartyReceivedHTLCOutput`]
/// — [`HolderHTLCOutput`]
/// — [`HolderFundingOutput`]
///
/// To ensure a forwards-compatible serialization, we use odd TLV fields. However, if new features
/// are used that could break security, where old signers should be prevented from handling the
/// serialized data, an optional even-field TLV will be used as a stand-in to break compatibility.
///
/// This method determines whether or not that option needs to be set based on the chanenl type
/// features, and returns it.
///
/// [`CounterpartyOfferedHTLCOutput`]: crate::chain::package::CounterpartyOfferedHTLCOutput
/// [`CounterpartyReceivedHTLCOutput`]: crate::chain::package::CounterpartyReceivedHTLCOutput
/// [`HolderHTLCOutput`]: crate::chain::package::HolderHTLCOutput
/// [`HolderFundingOutput`]: crate::chain::package::HolderFundingOutput
pub(crate) fn legacy_deserialization_prevention_marker_for_channel_type_features(
	features: &ChannelTypeFeatures,
) -> Option<()> {
	let mut legacy_version_bit_set = ChannelTypeFeatures::only_static_remote_key();
	legacy_version_bit_set.set_scid_privacy_required();
	legacy_version_bit_set.set_zero_conf_required();

	debug_assert!(!legacy_version_bit_set.supports_any_optional_bits());
	debug_assert!(!features.supports_any_optional_bits());
	if features.requires_unknown_bits_from(&legacy_version_bit_set) {
		Some(())
	} else {
		None
	}
}

/// Gets the witnessScript for the to_remote output when anchors are enabled.
#[inline]
pub fn get_to_countersigner_keyed_anchor_redeemscript(payment_point: &PublicKey) -> ScriptBuf {
	Builder::new()
		.push_slice(payment_point.serialize())
		.push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
		.push_int(1)
		.push_opcode(opcodes::all::OP_CSV)
		.into_script()
}

/// Gets the script_pubkey for a shared anchor
pub fn shared_anchor_script_pubkey() -> ScriptBuf {
	Builder::new().push_int(1).push_slice(&[0x4e, 0x73]).into_script()
}

/// Gets the witnessScript for a keyed anchor (non-zero-fee-commitments) output from the funding
/// public key.
///
/// The witness in the spending input must be:
/// <BIP 143 funding_signature>
/// After 16 blocks of confirmation, an alternative satisfying witness could be:
/// <>
/// (empty vector required to satisfy compliance with MINIMALIF-standard rule)
#[rustfmt::skip]
pub fn get_keyed_anchor_redeemscript(funding_pubkey: &PublicKey) -> ScriptBuf {
	Builder::new().push_slice(funding_pubkey.serialize())
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.push_opcode(opcodes::all::OP_IFDUP)
		.push_opcode(opcodes::all::OP_NOTIF)
		.push_int(16)
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_ENDIF)
		.into_script()
}

/// Returns the witness required to satisfy and spend a keyed anchor (non-zero-fee-commitments)
/// input.
pub fn build_keyed_anchor_input_witness(
	funding_key: &PublicKey, funding_sig: &Signature,
) -> Witness {
	let anchor_redeem_script = get_keyed_anchor_redeemscript(funding_key);
	let mut ret = Witness::new();
	ret.push_ecdsa_signature(&BitcoinSignature::sighash_all(*funding_sig));
	ret.push(anchor_redeem_script.as_bytes());
	ret
}

/// Per-channel data used to build transactions in conjunction with the per-commitment data (CommitmentTransaction).
/// The fields are organized by holder/counterparty.
///
/// Normally, this is converted to the broadcaster/countersignatory-organized DirectedChannelTransactionParameters
/// before use, via the as_holder_broadcastable and as_counterparty_broadcastable functions.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
	/// The parent funding txid for a channel that has been spliced.
	///
	/// If a channel was funded with transaction A, and later spliced with transaction B, this field
	/// tracks the txid of transaction A.
	///
	/// See [`compute_funding_key_tweak`] and [`ChannelSigner::new_funding_pubkey`] for more context
	/// on how this may be used.
	///
	/// [`compute_funding_key_tweak`]: crate::sign::compute_funding_key_tweak
	/// [`ChannelSigner::new_funding_pubkey`]: crate::sign::ChannelSigner::new_funding_pubkey
	pub splice_parent_funding_txid: Option<Txid>,
	/// This channel's type, as negotiated during channel open. For old objects where this field
	/// wasn't serialized, it will default to static_remote_key at deserialization.
	pub channel_type_features: ChannelTypeFeatures,
	/// The value locked in the channel, denominated in satoshis.
	pub channel_value_satoshis: u64,
}

/// Late-bound per-channel counterparty data used to build transactions.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
	#[rustfmt::skip]
	pub fn as_holder_broadcastable(&self) -> DirectedChannelTransactionParameters<'_> {
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
	#[rustfmt::skip]
	pub fn as_counterparty_broadcastable(&self) -> DirectedChannelTransactionParameters<'_> {
		assert!(self.is_populated(), "self.late_parameters must be set before using as_counterparty_broadcastable");
		DirectedChannelTransactionParameters {
			inner: self,
			holder_is_broadcaster: false
		}
	}

	pub(crate) fn make_funding_redeemscript(&self) -> ScriptBuf {
		self.make_funding_redeemscript_opt().unwrap()
	}

	pub(crate) fn make_funding_redeemscript_opt(&self) -> Option<ScriptBuf> {
		self.counterparty_parameters.as_ref().map(|p| {
			make_funding_redeemscript(
				&self.holder_pubkeys.funding_pubkey,
				&p.pubkeys.funding_pubkey,
			)
		})
	}

	/// Returns the counterparty's pubkeys.
	pub fn counterparty_pubkeys(&self) -> Option<&ChannelPublicKeys> {
		self.counterparty_parameters.as_ref().map(|params| &params.pubkeys)
	}

	#[cfg(test)]
	#[rustfmt::skip]
	pub fn test_dummy(channel_value_satoshis: u64) -> Self {
		let dummy_keys = ChannelPublicKeys {
			funding_pubkey: PublicKey::from_slice(&[2; 33]).unwrap(),
			revocation_basepoint: PublicKey::from_slice(&[2; 33]).unwrap().into(),
			payment_point: PublicKey::from_slice(&[2; 33]).unwrap(),
			delayed_payment_basepoint: PublicKey::from_slice(&[2; 33]).unwrap().into(),
			htlc_basepoint: PublicKey::from_slice(&[2; 33]).unwrap().into(),
		};
		Self {
			holder_pubkeys: dummy_keys.clone(),
			holder_selected_contest_delay: 42,
			is_outbound_from_holder: true,
			counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
				pubkeys: dummy_keys,
				selected_contest_delay: 42,
			}),
			funding_outpoint: Some(chain::transaction::OutPoint {
				txid: Txid::from_byte_array([42; 32]), index: 0
			}),
			splice_parent_funding_txid: None,
			channel_type_features: ChannelTypeFeatures::empty(),
			channel_value_satoshis,
		}
	}
}

impl_writeable_tlv_based!(CounterpartyChannelTransactionParameters, {
	(0, pubkeys, required),
	(2, selected_contest_delay, required),
});

impl Writeable for ChannelTransactionParameters {
	#[rustfmt::skip]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let legacy_deserialization_prevention_marker = legacy_deserialization_prevention_marker_for_channel_type_features(&self.channel_type_features);
		write_tlv_fields!(writer, {
			(0, self.holder_pubkeys, required),
			(2, self.holder_selected_contest_delay, required),
			(4, self.is_outbound_from_holder, required),
			(6, self.counterparty_parameters, option),
			(8, self.funding_outpoint, option),
			(10, legacy_deserialization_prevention_marker, option),
			(11, self.channel_type_features, required),
			(12, self.splice_parent_funding_txid, option),
			(13, self.channel_value_satoshis, required),
		});
		Ok(())
	}
}

impl ReadableArgs<Option<u64>> for ChannelTransactionParameters {
	#[rustfmt::skip]
	fn read<R: io::Read>(reader: &mut R, read_args: Option<u64>) -> Result<Self, DecodeError> {
		let mut holder_pubkeys = RequiredWrapper(None);
		let mut holder_selected_contest_delay = RequiredWrapper(None);
		let mut is_outbound_from_holder = RequiredWrapper(None);
		let mut counterparty_parameters = None;
		let mut funding_outpoint = None;
		let mut splice_parent_funding_txid = None;
		let mut _legacy_deserialization_prevention_marker: Option<()> = None;
		let mut channel_type_features = None;
		let mut channel_value_satoshis = None;

		read_tlv_fields!(reader, {
			(0, holder_pubkeys, required),
			(2, holder_selected_contest_delay, required),
			(4, is_outbound_from_holder, required),
			(6, counterparty_parameters, option),
			(8, funding_outpoint, option),
			(10, _legacy_deserialization_prevention_marker, option),
			(11, channel_type_features, option),
			(12, splice_parent_funding_txid, option),
			(13, channel_value_satoshis, option),
		});

		let channel_value_satoshis = match read_args {
			None => channel_value_satoshis.ok_or(DecodeError::InvalidValue)?,
			Some(expected_value) => {
				let channel_value_satoshis = channel_value_satoshis.unwrap_or(expected_value);
				if channel_value_satoshis == expected_value {
					channel_value_satoshis
				} else {
					return Err(DecodeError::InvalidValue);
				}
			},
		};

		let mut additional_features = ChannelTypeFeatures::empty();
		additional_features.set_anchors_nonzero_fee_htlc_tx_required();
		chain::package::verify_channel_type_features(&channel_type_features, Some(&additional_features))?;

		Ok(Self {
			holder_pubkeys: holder_pubkeys.0.unwrap(),
			holder_selected_contest_delay: holder_selected_contest_delay.0.unwrap(),
			is_outbound_from_holder: is_outbound_from_holder.0.unwrap(),
			counterparty_parameters,
			funding_outpoint,
			splice_parent_funding_txid,
			channel_type_features: channel_type_features.unwrap_or(ChannelTypeFeatures::only_static_remote_key()),
			channel_value_satoshis,
		})
	}
}

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
	pub fn broadcaster_pubkeys(&self) -> &'a ChannelPublicKeys {
		if self.holder_is_broadcaster {
			&self.inner.holder_pubkeys
		} else {
			&self.inner.counterparty_parameters.as_ref().unwrap().pubkeys
		}
	}

	/// Get the channel pubkeys for the countersignatory
	pub fn countersignatory_pubkeys(&self) -> &'a ChannelPublicKeys {
		if self.holder_is_broadcaster {
			&self.inner.counterparty_parameters.as_ref().unwrap().pubkeys
		} else {
			&self.inner.holder_pubkeys
		}
	}

	/// Get the contest delay applicable to the transactions.
	/// Note that the contest delay was selected by the countersignatory.
	#[rustfmt::skip]
	pub fn contest_delay(&self) -> u16 {
		let counterparty_parameters = self.inner.counterparty_parameters.as_ref().unwrap();
		if self.holder_is_broadcaster { counterparty_parameters.selected_contest_delay } else { self.inner.holder_selected_contest_delay }
	}

	/// Whether the channel is outbound from the broadcaster.
	///
	/// The boolean representing the side that initiated the channel is
	/// an input to the commitment number obscure factor computation.
	#[rustfmt::skip]
	pub fn is_outbound(&self) -> bool {
		if self.holder_is_broadcaster { self.inner.is_outbound_from_holder } else { !self.inner.is_outbound_from_holder }
	}

	/// The funding outpoint
	pub fn funding_outpoint(&self) -> OutPoint {
		self.inner.funding_outpoint.unwrap().into_bitcoin_outpoint()
	}

	/// The type of channel these parameters are for
	pub fn channel_type_features(&self) -> &'a ChannelTypeFeatures {
		&self.inner.channel_type_features
	}

	/// The value locked in the channel, denominated in satoshis.
	pub fn channel_value_satoshis(&self) -> u64 {
		self.inner.channel_value_satoshis
	}
}

/// Information needed to build and sign a holder's commitment transaction.
///
/// The transaction is only signed once we are ready to broadcast.
#[derive(Clone, Debug)]
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

	#[rustfmt::skip]
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
	(6, counterparty_htlc_sigs, required_vec),
});

impl HolderCommitmentTransaction {
	#[cfg(test)]
	#[rustfmt::skip]
	pub fn dummy(channel_value_satoshis: u64, funding_outpoint: chain::transaction::OutPoint, nondust_htlcs: Vec<HTLCOutputInCommitment>) -> Self {
		let secp_ctx = Secp256k1::new();
		let dummy_key = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let dummy_sig = sign(&secp_ctx, &secp256k1::Message::from_digest([42; 32]), &SecretKey::from_slice(&[42; 32]).unwrap());

		let channel_pubkeys = ChannelPublicKeys {
			funding_pubkey: dummy_key.clone(),
			revocation_basepoint: RevocationBasepoint::from(dummy_key),
			payment_point: dummy_key.clone(),
			delayed_payment_basepoint: DelayedPaymentBasepoint::from(dummy_key.clone()),
			htlc_basepoint: HtlcBasepoint::from(dummy_key.clone())
		};
		let channel_parameters = ChannelTransactionParameters {
			holder_pubkeys: channel_pubkeys.clone(),
			holder_selected_contest_delay: 0,
			is_outbound_from_holder: false,
			counterparty_parameters: Some(CounterpartyChannelTransactionParameters { pubkeys: channel_pubkeys.clone(), selected_contest_delay: 0 }),
			funding_outpoint: Some(funding_outpoint),
			splice_parent_funding_txid: None,
			channel_type_features: ChannelTypeFeatures::only_static_remote_key(),
			channel_value_satoshis,
		};
		let mut counterparty_htlc_sigs = Vec::new();
		for _ in 0..nondust_htlcs.len() {
			counterparty_htlc_sigs.push(dummy_sig);
		}
		let inner = CommitmentTransaction::new(0, &dummy_key, 0, 0, 0, nondust_htlcs, &channel_parameters.as_counterparty_broadcastable(), &secp_ctx);
		HolderCommitmentTransaction {
			inner,
			counterparty_sig: dummy_sig,
			counterparty_htlc_sigs,
			holder_sig_first: false
		}
	}

	/// Create a new holder transaction with the given counterparty signatures.
	/// The funding keys are used to figure out which signature should go first when building the transaction for broadcast.
	#[rustfmt::skip]
	pub fn new(commitment_tx: CommitmentTransaction, counterparty_sig: Signature, counterparty_htlc_sigs: Vec<Signature>, holder_funding_key: &PublicKey, counterparty_funding_key: &PublicKey) -> Self {
		Self {
			inner: commitment_tx,
			counterparty_sig,
			counterparty_htlc_sigs,
			holder_sig_first: holder_funding_key.serialize()[..] < counterparty_funding_key.serialize()[..],
		}
	}

	#[rustfmt::skip]
	pub(crate) fn add_holder_sig(&self, funding_redeemscript: &Script, holder_sig: Signature) -> Transaction {
		// First push the multisig dummy, note that due to BIP147 (NULLDUMMY) it must be a zero-length element.
		let mut tx = self.inner.built.transaction.clone();
		tx.input[0].witness.push(Vec::new());

		if self.holder_sig_first {
			tx.input[0].witness.push_ecdsa_signature(&BitcoinSignature::sighash_all(holder_sig));
			tx.input[0].witness.push_ecdsa_signature(&BitcoinSignature::sighash_all(self.counterparty_sig));
		} else {
			tx.input[0].witness.push_ecdsa_signature(&BitcoinSignature::sighash_all(self.counterparty_sig));
			tx.input[0].witness.push_ecdsa_signature(&BitcoinSignature::sighash_all(holder_sig));
		}

		tx.input[0].witness.push(funding_redeemscript.as_bytes().to_vec());
		tx
	}
}

/// A pre-built Bitcoin commitment transaction and its txid.
#[derive(Clone, Debug)]
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
	#[rustfmt::skip]
	pub fn get_sighash_all(&self, funding_redeemscript: &Script, channel_value_satoshis: u64) -> Message {
		let sighash = &sighash::SighashCache::new(&self.transaction).p2wsh_signature_hash(0, funding_redeemscript, Amount::from_sat(channel_value_satoshis), EcdsaSighashType::All).unwrap()[..];
		hash_to_message!(sighash)
	}

	/// Signs the counterparty's commitment transaction.
	pub fn sign_counterparty_commitment<T: secp256k1::Signing>(
		&self, funding_key: &SecretKey, funding_redeemscript: &Script, channel_value_satoshis: u64,
		secp_ctx: &Secp256k1<T>,
	) -> Signature {
		let sighash = self.get_sighash_all(funding_redeemscript, channel_value_satoshis);
		sign(secp_ctx, &sighash, funding_key)
	}

	/// Signs the holder commitment transaction because we are about to broadcast it.
	pub fn sign_holder_commitment<T: secp256k1::Signing, ES: Deref>(
		&self, funding_key: &SecretKey, funding_redeemscript: &Script, channel_value_satoshis: u64,
		entropy_source: &ES, secp_ctx: &Secp256k1<T>,
	) -> Signature
	where
		ES::Target: EntropySource,
	{
		let sighash = self.get_sighash_all(funding_redeemscript, channel_value_satoshis);
		sign_with_aux_rand(secp_ctx, &sighash, funding_key, entropy_source)
	}
}

/// This class tracks the per-transaction information needed to build a closing transaction and will
/// actually build it and sign.
///
/// This class can be used inside a signer implementation to generate a signature given the relevant
/// secret key.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct ClosingTransaction {
	to_holder_value_sat: Amount,
	to_counterparty_value_sat: Amount,
	to_holder_script: ScriptBuf,
	to_counterparty_script: ScriptBuf,
	built: Transaction,
}

impl ClosingTransaction {
	/// Construct an object of the class
	#[rustfmt::skip]
	pub fn new(
		to_holder_value_sat: u64,
		to_counterparty_value_sat: u64,
		to_holder_script: ScriptBuf,
		to_counterparty_script: ScriptBuf,
		funding_outpoint: OutPoint,
	) -> Self {
		let to_holder_value_sat = Amount::from_sat(to_holder_value_sat);
		let to_counterparty_value_sat = Amount::from_sat(to_counterparty_value_sat);
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
	pub fn trust(&self) -> TrustedClosingTransaction<'_> {
		TrustedClosingTransaction { inner: self }
	}

	/// Verify our pre-built transaction.
	///
	/// Applies a wrapper which allows access to the transaction.
	///
	/// An external validating signer must call this method before signing
	/// or using the built transaction.
	#[rustfmt::skip]
	pub fn verify(&self, funding_outpoint: OutPoint) -> Result<TrustedClosingTransaction<'_>, ()> {
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
		self.to_holder_value_sat.to_sat()
	}

	/// The value to be sent to the counterparty, or zero if the output will be omitted
	pub fn to_counterparty_value_sat(&self) -> u64 {
		self.to_counterparty_value_sat.to_sat()
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

	#[rustfmt::skip]
	fn deref(&self) -> &Self::Target { self.inner }
}

impl<'a> TrustedClosingTransaction<'a> {
	/// The pre-built Bitcoin commitment transaction
	pub fn built_transaction(&self) -> &'a Transaction {
		&self.inner.built
	}

	/// Get the SIGHASH_ALL sighash value of the transaction.
	///
	/// This can be used to verify a signature.
	#[rustfmt::skip]
	pub fn get_sighash_all(&self, funding_redeemscript: &Script, channel_value_satoshis: u64) -> Message {
		let sighash = &sighash::SighashCache::new(&self.inner.built).p2wsh_signature_hash(0, funding_redeemscript, Amount::from_sat(channel_value_satoshis), EcdsaSighashType::All).unwrap()[..];
		hash_to_message!(sighash)
	}

	/// Sign a transaction, either because we are counter-signing the counterparty's transaction or
	/// because we are about to broadcast a holder transaction.
	pub fn sign<T: secp256k1::Signing>(
		&self, funding_key: &SecretKey, funding_redeemscript: &Script, channel_value_satoshis: u64,
		secp_ctx: &Secp256k1<T>,
	) -> Signature {
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
#[derive(Clone, Debug)]
pub struct CommitmentTransaction {
	commitment_number: u64,
	to_broadcaster_value_sat: Amount,
	to_countersignatory_value_sat: Amount,
	to_broadcaster_delay: Option<u16>, // Added in 0.0.117
	feerate_per_kw: u32,
	// The set of non-dust HTLCs included in the commitment. They must be sorted in increasing
	// output index order.
	nondust_htlcs: Vec<HTLCOutputInCommitment>,
	// Note that on upgrades, some features of existing outputs may be missed.
	channel_type_features: ChannelTypeFeatures,
	// A cache of the parties' pubkeys required to construct the transaction, see doc for trust()
	keys: TxCreationKeys,
	// For access to the pre-built transaction, see doc for trust()
	built: BuiltCommitmentTransaction,
}

impl Eq for CommitmentTransaction {}
impl PartialEq for CommitmentTransaction {
	#[rustfmt::skip]
	fn eq(&self, o: &Self) -> bool {
		let eq = self.commitment_number == o.commitment_number &&
			self.to_broadcaster_value_sat == o.to_broadcaster_value_sat &&
			self.to_countersignatory_value_sat == o.to_countersignatory_value_sat &&
			self.feerate_per_kw == o.feerate_per_kw &&
			self.nondust_htlcs == o.nondust_htlcs &&
			self.channel_type_features == o.channel_type_features &&
			self.keys == o.keys;
		if eq {
			debug_assert_eq!(self.built.transaction, o.built.transaction);
			debug_assert_eq!(self.built.txid, o.built.txid);
		}
		eq
	}
}

impl Writeable for CommitmentTransaction {
	#[rustfmt::skip]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let legacy_deserialization_prevention_marker = legacy_deserialization_prevention_marker_for_channel_type_features(&self.channel_type_features);
		write_tlv_fields!(writer, {
			(0, self.commitment_number, required),
			(1, self.to_broadcaster_delay, option),
			(2, self.to_broadcaster_value_sat, required),
			(4, self.to_countersignatory_value_sat, required),
			(6, self.feerate_per_kw, required),
			(8, self.keys, required),
			(10, self.built, required),
			(12, self.nondust_htlcs, required_vec),
			(14, legacy_deserialization_prevention_marker, option),
			(15, self.channel_type_features, required),
		});
		Ok(())
	}
}

impl Readable for CommitmentTransaction {
	#[rustfmt::skip]
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, commitment_number, required),
			(1, to_broadcaster_delay, option),
			(2, to_broadcaster_value_sat, required),
			(4, to_countersignatory_value_sat, required),
			(6, feerate_per_kw, required),
			(8, keys, required),
			(10, built, required),
			(12, nondust_htlcs, required_vec),
			(14, _legacy_deserialization_prevention_marker, (option, explicit_type: ())),
			(15, channel_type_features, option),
		});

		let mut additional_features = ChannelTypeFeatures::empty();
		additional_features.set_anchors_nonzero_fee_htlc_tx_required();
		chain::package::verify_channel_type_features(&channel_type_features, Some(&additional_features))?;

		Ok(Self {
			commitment_number: commitment_number.0.unwrap(),
			to_broadcaster_value_sat: to_broadcaster_value_sat.0.unwrap(),
			to_countersignatory_value_sat: to_countersignatory_value_sat.0.unwrap(),
			to_broadcaster_delay,
			feerate_per_kw: feerate_per_kw.0.unwrap(),
			keys: keys.0.unwrap(),
			built: built.0.unwrap(),
			nondust_htlcs,
			channel_type_features: channel_type_features.unwrap_or(ChannelTypeFeatures::only_static_remote_key())
		})
	}
}

impl CommitmentTransaction {
	/// Constructs a new `CommitmentTransaction` from the list of HTLCs and the direct balances.
	///
	/// All HTLCs MUST be above the dust limit for the channel.
	/// The broadcaster and countersignatory amounts MUST be either 0 or above dust. If the amount
	/// is 0, the corresponding output will be omitted from the transaction.
	#[rustfmt::skip]
	pub fn new(commitment_number: u64, per_commitment_point: &PublicKey, to_broadcaster_value_sat: u64, to_countersignatory_value_sat: u64, feerate_per_kw: u32, mut nondust_htlcs: Vec<HTLCOutputInCommitment>, channel_parameters: &DirectedChannelTransactionParameters, secp_ctx: &Secp256k1<secp256k1::All>) -> CommitmentTransaction {
		let to_broadcaster_value_sat = Amount::from_sat(to_broadcaster_value_sat);
		let to_countersignatory_value_sat = Amount::from_sat(to_countersignatory_value_sat);
		let keys = TxCreationKeys::from_channel_static_keys(per_commitment_point, channel_parameters.broadcaster_pubkeys(), channel_parameters.countersignatory_pubkeys(), secp_ctx);

		// Build and sort the outputs of the transaction.
		// Also sort the HTLC output data in `nondust_htlcs` in the same order, and populate the
		// transaction output indices therein.
		let outputs = Self::build_outputs_and_htlcs(&keys, to_broadcaster_value_sat, to_countersignatory_value_sat, &mut nondust_htlcs, channel_parameters);

		let (obscured_commitment_transaction_number, txins) = Self::build_inputs(commitment_number, channel_parameters);
		let transaction = Self::make_transaction(obscured_commitment_transaction_number, txins, outputs, channel_parameters);
		let txid = transaction.compute_txid();
		CommitmentTransaction {
			commitment_number,
			to_broadcaster_value_sat,
			to_countersignatory_value_sat,
			to_broadcaster_delay: Some(channel_parameters.contest_delay()),
			feerate_per_kw,
			nondust_htlcs,
			channel_type_features: channel_parameters.channel_type_features().clone(),
			keys,
			built: BuiltCommitmentTransaction {
				transaction,
				txid
			},
		}
	}

	/// Use non-zero fee anchors
	///
	/// This is not exported to bindings users due to move, and also not likely to be useful for binding users
	pub fn with_non_zero_fee_anchors(mut self) -> Self {
		self.channel_type_features.set_anchors_nonzero_fee_htlc_tx_required();
		self
	}

	// A helper function that checks if the HTLC to the left of the HTLC at i is greater than itself,
	// first by value, then by script pubkey, then by cltv expiry.
	//
	// It does so by reading both a vector of `TxOut` and a vector of `HTLCOutputInCommitment`.
	//
	// We use this function to both sort HTLCs, and to check that a set of HTLCs is sorted.
	//
	// `txouts` and `nondust_htlcs` MUST be of equal length, and of length >= 2.
	// For all `i < len`, the `TxOut` at `txouts[i]` MUST correspond to the HTLC at `nondust_htlcs[i]`.
	#[rustfmt::skip]
	fn is_left_greater(i: usize, txouts: &Vec<TxOut>, nondust_htlcs: &Vec<HTLCOutputInCommitment>) -> bool {
		txouts[i - 1].value.cmp(&txouts[i].value)
			.then(txouts[i - 1].script_pubkey.cmp(&txouts[i].script_pubkey))
			.then(nondust_htlcs[i - 1].cltv_expiry.cmp(&nondust_htlcs[i].cltv_expiry))
			// Note that due to hash collisions, we have to have a fallback comparison
			// here for fuzzing mode (otherwise at least chanmon_fail_consistency
			// may fail)!
			.then(nondust_htlcs[i - 1].payment_hash.cmp(&nondust_htlcs[i].payment_hash))
			.is_gt()
	}

	#[rustfmt::skip]
	fn rebuild_transaction(&self, keys: &TxCreationKeys, channel_parameters: &DirectedChannelTransactionParameters) -> Result<BuiltCommitmentTransaction, ()> {
		let (obscured_commitment_transaction_number, txins) = Self::build_inputs(self.commitment_number, channel_parameters);

		// First rebuild the htlc outputs, note that `outputs` is now the same length as `self.nondust_htlcs`
		let mut outputs = Self::build_htlc_outputs(keys, &self.nondust_htlcs, channel_parameters.channel_type_features());

		let nondust_htlcs_value_sum_sat = self.nondust_htlcs.iter().map(|htlc| htlc.to_bitcoin_amount()).sum();

		// Check that the HTLC outputs are sorted by value, script pubkey, and cltv expiry.
		// Note that this only iterates if the length of `outputs` and `self.nondust_htlcs` is >= 2.
		if (1..outputs.len()).into_iter().any(|i| Self::is_left_greater(i, &outputs, &self.nondust_htlcs)) {
			return Err(())
		}

		// Then insert the max-4 non-htlc outputs, ordered by value, then by script pubkey
		let insert_non_htlc_output = |non_htlc_output: TxOut| {
			let idx = match outputs.binary_search_by(|output| output.value.cmp(&non_htlc_output.value).then(output.script_pubkey.cmp(&non_htlc_output.script_pubkey))) {
				// For non-HTLC outputs, if they're copying our SPK we don't really care if we
				// close the channel due to mismatches - they're doing something dumb
				Ok(i) => i,
				Err(i) => i,
			};
			outputs.insert(idx, non_htlc_output);
		};

		Self::insert_non_htlc_outputs(
			keys,
			self.to_broadcaster_value_sat,
			self.to_countersignatory_value_sat,
			channel_parameters,
			nondust_htlcs_value_sum_sat,
			insert_non_htlc_output
		);

		let transaction = Self::make_transaction(obscured_commitment_transaction_number, txins, outputs, channel_parameters);
		let txid = transaction.compute_txid();
		let built_transaction = BuiltCommitmentTransaction {
			transaction,
			txid
		};
		Ok(built_transaction)
	}

	#[rustfmt::skip]
	fn make_transaction(obscured_commitment_transaction_number: u64, txins: Vec<TxIn>, outputs: Vec<TxOut>, channel_parameters: &DirectedChannelTransactionParameters) -> Transaction {
		let version = if channel_parameters.channel_type_features().supports_anchor_zero_fee_commitments() {
			Version::non_standard(3)
		} else {
			Version::TWO
		};
		Transaction {
			version,
			lock_time: LockTime::from_consensus(((0x20 as u32) << 8 * 3) | ((obscured_commitment_transaction_number & 0xffffffu64) as u32)),
			input: txins,
			output: outputs,
		}
	}

	#[rustfmt::skip]
	fn build_outputs_and_htlcs(
		keys: &TxCreationKeys,
		to_broadcaster_value_sat: Amount,
		to_countersignatory_value_sat: Amount,
		nondust_htlcs: &mut Vec<HTLCOutputInCommitment>,
		channel_parameters: &DirectedChannelTransactionParameters
	) -> Vec<TxOut> {
		// First build and sort the HTLC outputs.
		// Also sort the HTLC output data in `nondust_htlcs` in the same order.
		let mut outputs = Self::build_sorted_htlc_outputs(keys, nondust_htlcs, channel_parameters.channel_type_features());

		let nondust_htlcs_value_sum_sat = nondust_htlcs.iter().map(|htlc| htlc.to_bitcoin_amount()).sum();

		// Initialize the transaction output indices; we will update them below when we
		// add the non-htlc transaction outputs.
		nondust_htlcs
			.iter_mut()
			.enumerate()
			.for_each(|(i, htlc)| htlc.transaction_output_index = Some(i as u32));

		// Then insert the max-4 non-htlc outputs, ordered by value, then by script pubkey
		let insert_non_htlc_output = |non_htlc_output: TxOut| {
			let idx = match outputs.binary_search_by(|output| output.value.cmp(&non_htlc_output.value).then(output.script_pubkey.cmp(&non_htlc_output.script_pubkey))) {
				// For non-HTLC outputs, if they're copying our SPK we don't really care if we
				// close the channel due to mismatches - they're doing something dumb
				Ok(i) => i,
				Err(i) => i,
			};
			outputs.insert(idx, non_htlc_output);

			// Increment the transaction output indices of all the HTLCs that come after the output we
			// just inserted.
			nondust_htlcs
				.iter_mut()
				.rev()
				.map_while(|htlc| {
					// This unwrap is safe; we've initialized all the transaction output indices above
					let i = htlc.transaction_output_index.as_mut().unwrap();
					(*i >= idx as u32).then(|| i)
				})
				.for_each(|i| *i += 1);
		};

		Self::insert_non_htlc_outputs(
			keys,
			to_broadcaster_value_sat,
			to_countersignatory_value_sat,
			channel_parameters,
			nondust_htlcs_value_sum_sat,
			insert_non_htlc_output
		);

		outputs
	}

	#[rustfmt::skip]
	fn insert_non_htlc_outputs<F>(
		keys: &TxCreationKeys,
		to_broadcaster_value_sat: Amount,
		to_countersignatory_value_sat: Amount,
		channel_parameters: &DirectedChannelTransactionParameters,
		nondust_htlcs_value_sum_sat: Amount,
		mut insert_non_htlc_output: F,
	) where
		F: FnMut(TxOut),
	{
		let countersignatory_payment_point = &channel_parameters.countersignatory_pubkeys().payment_point;
		let countersignatory_funding_key = &channel_parameters.countersignatory_pubkeys().funding_pubkey;
		let broadcaster_funding_key = &channel_parameters.broadcaster_pubkeys().funding_pubkey;
		let channel_type = channel_parameters.channel_type_features();
		let contest_delay = channel_parameters.contest_delay();
		let tx_has_htlc_outputs = nondust_htlcs_value_sum_sat != Amount::ZERO;

		if to_countersignatory_value_sat > Amount::ZERO {
			let script = if channel_type.supports_anchors_zero_fee_htlc_tx() {
				get_to_countersigner_keyed_anchor_redeemscript(countersignatory_payment_point).to_p2wsh()
			} else {
				ScriptBuf::new_p2wpkh(&Hash160::hash(&countersignatory_payment_point.serialize()).into())
			};
			insert_non_htlc_output(TxOut {
				script_pubkey: script,
				value: to_countersignatory_value_sat,
			});
		}

		if to_broadcaster_value_sat > Amount::ZERO {
			let redeem_script = get_revokeable_redeemscript(
				&keys.revocation_key,
				contest_delay,
				&keys.broadcaster_delayed_payment_key,
			);
			insert_non_htlc_output(TxOut {
				script_pubkey: redeem_script.to_p2wsh(),
				value: to_broadcaster_value_sat,
			});
		}

		if channel_type.supports_anchors_zero_fee_htlc_tx() {
			if to_broadcaster_value_sat > Amount::ZERO || tx_has_htlc_outputs {
				let anchor_script = get_keyed_anchor_redeemscript(broadcaster_funding_key);
				insert_non_htlc_output(TxOut {
					script_pubkey: anchor_script.to_p2wsh(),
					value: Amount::from_sat(ANCHOR_OUTPUT_VALUE_SATOSHI),
				});
			}

			if to_countersignatory_value_sat > Amount::ZERO || tx_has_htlc_outputs {
				let anchor_script = get_keyed_anchor_redeemscript(countersignatory_funding_key);
				insert_non_htlc_output(TxOut {
					script_pubkey: anchor_script.to_p2wsh(),
					value: Amount::from_sat(ANCHOR_OUTPUT_VALUE_SATOSHI),
				});
			}
		}

		if channel_type.supports_anchor_zero_fee_commitments() {
				let channel_value_satoshis = Amount::from_sat(channel_parameters.channel_value_satoshis());
				// These subtractions panic on underflow, but this should never happen
				let trimmed_sum_sat = channel_value_satoshis - nondust_htlcs_value_sum_sat - to_broadcaster_value_sat - to_countersignatory_value_sat;
				insert_non_htlc_output(TxOut {
					script_pubkey: shared_anchor_script_pubkey(),
					value: cmp::min(Amount::from_sat(P2A_MAX_VALUE), trimmed_sum_sat),
				});
		}
	}

	#[rustfmt::skip]
	fn build_htlc_outputs(keys: &TxCreationKeys, nondust_htlcs: &Vec<HTLCOutputInCommitment>, channel_type: &ChannelTypeFeatures) -> Vec<TxOut> {
		// Allocate memory for the 4 possible non-htlc outputs
		let mut txouts = Vec::with_capacity(nondust_htlcs.len() + 4);

		for htlc in nondust_htlcs {
			let script = get_htlc_redeemscript(htlc, channel_type, keys);
			let txout = TxOut {
				script_pubkey: script.to_p2wsh(),
				value: htlc.to_bitcoin_amount(),
			};
			txouts.push(txout);
		}

		txouts
	}

	#[rustfmt::skip]
	fn build_sorted_htlc_outputs(
		keys: &TxCreationKeys,
		nondust_htlcs: &mut Vec<HTLCOutputInCommitment>,
		channel_type: &ChannelTypeFeatures
	) -> Vec<TxOut> {
		// Note that `txouts` has the same length as `nondust_htlcs` here
		let mut txouts = Self::build_htlc_outputs(keys, nondust_htlcs, channel_type);

		// Sort the HTLC outputs by value, then by script pubkey, then by cltv expiration height.
		//
		// Also sort the HTLC output data in `nondust_htlcs` in the same order.
		//
		// This is insertion sort. In the worst case this is O(n^2) over 2 * 483 HTLCs in the
		// channel. We expect people to transition soon to zero-fee-commitment channels,
		// where n will be 2 * 114.
		//
		// These are small numbers, and channels today rarely reach this protocol-max, if ever,
		// so we accept the performance tradeoff.

		// Note that if we enter this loop, the length of `txouts` and `nondust_htlcs` is at least 2
		for i in 1..txouts.len() {
			let mut j = i;
			// While there is a value to the left of j,
			// and that value is greater than the value at j,
			// swap the two values.
			while j > 0 && Self::is_left_greater(j, &txouts, &nondust_htlcs) {
				txouts.swap(j - 1, j);
				nondust_htlcs.swap(j - 1, j);
				j -= 1;
			}
		}

		txouts
	}

	#[rustfmt::skip]
	fn build_inputs(commitment_number: u64, channel_parameters: &DirectedChannelTransactionParameters) -> (u64, Vec<TxIn>) {
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
			let ins: Vec<TxIn> = vec![TxIn {
				previous_output: channel_parameters.funding_outpoint(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence(((0x80 as u32) << 8 * 3)
					| ((obscured_commitment_transaction_number >> 3 * 8) as u32)),
				witness: Witness::new(),
			}];
			ins
		};
		(obscured_commitment_transaction_number, txins)
	}

	/// The backwards-counting commitment number
	pub fn commitment_number(&self) -> u64 {
		self.commitment_number
	}

	/// The per commitment point used by the broadcaster.
	pub fn per_commitment_point(&self) -> PublicKey {
		self.keys.per_commitment_point
	}

	/// The value to be sent to the broadcaster
	pub fn to_broadcaster_value_sat(&self) -> u64 {
		self.to_broadcaster_value_sat.to_sat()
	}

	/// The value to be sent to the counterparty
	pub fn to_countersignatory_value_sat(&self) -> u64 {
		self.to_countersignatory_value_sat.to_sat()
	}

	/// The feerate paid per 1000-weight-unit we negotiated with our
	/// peer for this commitment transaction. Note that the actual
	/// feerate of the commitment transaction may be higher than the
	/// negotiated feerate.
	pub fn negotiated_feerate_per_kw(&self) -> u32 {
		self.feerate_per_kw
	}

	/// The non-dust HTLCs (direction, amt, height expiration, hash, transaction output index)
	/// which were included in this commitment transaction in output order.
	/// The transaction index is always populated.
	///
	/// This is not exported to bindings users as we cannot currently convert Vec references to/from C, though we should
	/// expose a less effecient version which creates a Vec of references in the future.
	pub fn nondust_htlcs(&self) -> &Vec<HTLCOutputInCommitment> {
		&self.nondust_htlcs
	}

	/// Trust our pre-built transaction and derived transaction creation public keys.
	///
	/// Applies a wrapper which allows access to these fields.
	///
	/// This should only be used if you fully trust the builder of this object.  It should not
	/// be used by an external signer - instead use the verify function.
	pub fn trust(&self) -> TrustedCommitmentTransaction<'_> {
		TrustedCommitmentTransaction { inner: self }
	}

	/// Verify our pre-built transaction and derived transaction creation public keys.
	///
	/// Applies a wrapper which allows access to these fields.
	///
	/// An external validating signer must call this method before signing
	/// or using the built transaction.
	#[rustfmt::skip]
	pub fn verify<T: secp256k1::Signing + secp256k1::Verification>(&self, channel_parameters: &DirectedChannelTransactionParameters, secp_ctx: &Secp256k1<T>) -> Result<TrustedCommitmentTransaction<'_>, ()> {
		// This is the only field of the key cache that we trust
		let per_commitment_point = &self.keys.per_commitment_point;
		let keys = TxCreationKeys::from_channel_static_keys(per_commitment_point, channel_parameters.broadcaster_pubkeys(), channel_parameters.countersignatory_pubkeys(), secp_ctx);
		if keys != self.keys {
			return Err(());
		}
		let tx = self.rebuild_transaction(&keys, channel_parameters)?;
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

	#[rustfmt::skip]
	fn deref(&self) -> &Self::Target { self.inner }
}

impl<'a> TrustedCommitmentTransaction<'a> {
	/// The transaction ID of the built Bitcoin transaction
	pub fn txid(&self) -> Txid {
		self.inner.built.txid
	}

	/// The pre-built Bitcoin commitment transaction
	pub fn built_transaction(&self) -> &'a BuiltCommitmentTransaction {
		&self.inner.built
	}

	/// The pre-calculated transaction creation public keys.
	pub fn keys(&self) -> &'a TxCreationKeys {
		&self.inner.keys
	}

	/// Should anchors be used.
	pub fn channel_type_features(&self) -> &'a ChannelTypeFeatures {
		&self.inner.channel_type_features
	}

	/// Get a signature for each HTLC which was included in the commitment transaction (ie for
	/// which HTLCOutputInCommitment::transaction_output_index.is_some()).
	///
	/// The returned Vec has one entry for each HTLC, and in the same order.
	///
	/// This function is only valid in the holder commitment context, it always uses EcdsaSighashType::All.
	#[rustfmt::skip]
	pub fn get_htlc_sigs<T: secp256k1::Signing, ES: Deref>(
		&self, htlc_base_key: &SecretKey, channel_parameters: &DirectedChannelTransactionParameters,
		entropy_source: &ES, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<Signature>, ()> where ES::Target: EntropySource {
		let inner = self.inner;
		let keys = &inner.keys;
		let txid = inner.built.txid;
		let mut ret = Vec::with_capacity(inner.nondust_htlcs.len());
		let holder_htlc_key = derive_private_key(secp_ctx, &inner.keys.per_commitment_point, htlc_base_key);

		for this_htlc in inner.nondust_htlcs.iter() {
			assert!(this_htlc.transaction_output_index.is_some());
			let htlc_tx = build_htlc_transaction(&txid, inner.feerate_per_kw, channel_parameters.contest_delay(), &this_htlc, &self.channel_type_features, &keys.broadcaster_delayed_payment_key, &keys.revocation_key);

			let htlc_redeemscript = get_htlc_redeemscript_with_explicit_keys(&this_htlc, &self.channel_type_features, &keys.broadcaster_htlc_key, &keys.countersignatory_htlc_key, &keys.revocation_key);

			let sighash = hash_to_message!(&sighash::SighashCache::new(&htlc_tx).p2wsh_signature_hash(0, &htlc_redeemscript, this_htlc.to_bitcoin_amount(), EcdsaSighashType::All).unwrap()[..]);
			ret.push(sign_with_aux_rand(secp_ctx, &sighash, &holder_htlc_key, entropy_source));
		}
		Ok(ret)
	}

	/// Returns the index of the revokeable output, i.e. the `to_local` output sending funds to
	/// the broadcaster, in the built transaction, if any exists.
	///
	/// There are two cases where this may return `None`:
	/// - The balance of the revokeable output is below the dust limit (only found on commitments
	/// early in the channel's lifetime, i.e. before the channel reserve is met).
	/// - This commitment was created before LDK 0.0.117. In this case, the
	/// commitment transaction previously didn't contain enough information to locate the
	/// revokeable output.
	#[rustfmt::skip]
	pub fn revokeable_output_index(&self) -> Option<usize> {
		let revokeable_redeemscript = get_revokeable_redeemscript(
			&self.keys.revocation_key,
			self.to_broadcaster_delay?,
			&self.keys.broadcaster_delayed_payment_key,
		);
		let revokeable_p2wsh = revokeable_redeemscript.to_p2wsh();
		let outputs = &self.inner.built.transaction.output;
		outputs.iter().enumerate()
			.find(|(_, out)| out.script_pubkey == revokeable_p2wsh)
			.map(|(idx, _)| idx)
	}

	/// Helper method to build an unsigned justice transaction spending the revokeable
	/// `to_local` output to a destination script. Fee estimation accounts for the expected
	/// revocation witness data that will be added when signed.
	///
	/// This method will error if the given fee rate results in a fee greater than the value
	/// of the output being spent, or if there exists no revokeable `to_local` output on this
	/// commitment transaction. See [`Self::revokeable_output_index`] for more details.
	///
	/// The built transaction will allow fee bumping with RBF, and this method takes
	/// `feerate_per_kw` as an input such that multiple copies of a justice transaction at different
	/// fee rates may be built.
	#[rustfmt::skip]
	pub fn build_to_local_justice_tx(&self, feerate_per_kw: u64, destination_script: ScriptBuf)
	-> Result<Transaction, ()> {
		let output_idx = self.revokeable_output_index().ok_or(())?;
		let input = vec![TxIn {
			previous_output: OutPoint {
				txid: self.trust().txid(),
				vout: output_idx as u32,
			},
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
			witness: Witness::new(),
		}];
		let value = self.inner.built.transaction.output[output_idx].value;
		let output = vec![TxOut {
			script_pubkey: destination_script,
			value,
		}];
		let mut justice_tx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input,
			output,
		};
		let weight = justice_tx.weight().to_wu() + WEIGHT_REVOKED_OUTPUT;
		let fee = Amount::from_sat(fee_for_weight(feerate_per_kw as u32, weight));
		justice_tx.output[0].value = value.checked_sub(fee).ok_or(())?;
		Ok(justice_tx)
	}
}

/// Commitment transaction numbers which appear in the transactions themselves are XOR'd with a
/// shared secret first. This prevents on-chain observers from discovering how many commitment
/// transactions occurred in a channel before it was closed.
///
/// This function gets the shared secret from relevant channel public keys and can be used to
/// "decrypt" the commitment transaction number given a commitment transaction on-chain.
pub fn get_commitment_transaction_number_obscure_factor(
	broadcaster_payment_basepoint: &PublicKey, countersignatory_payment_basepoint: &PublicKey,
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
	let res = Sha256::from_engine(sha).to_byte_array();

	((res[26] as u64) << 5 * 8)
		| ((res[27] as u64) << 4 * 8)
		| ((res[28] as u64) << 3 * 8)
		| ((res[29] as u64) << 2 * 8)
		| ((res[30] as u64) << 1 * 8)
		| ((res[31] as u64) << 0 * 8)
}

#[cfg(test)]
mod tests {
	use super::{ChannelPublicKeys, CounterpartyCommitmentSecrets};
	use crate::chain;
	use crate::ln::chan_utils::{
		get_htlc_redeemscript, get_keyed_anchor_redeemscript,
		get_to_countersigner_keyed_anchor_redeemscript, shared_anchor_script_pubkey,
		BuiltCommitmentTransaction, ChannelTransactionParameters, CommitmentTransaction,
		CounterpartyChannelTransactionParameters, HTLCOutputInCommitment,
		TrustedCommitmentTransaction,
	};
	use crate::sign::{ChannelSigner, SignerProvider};
	use crate::types::features::ChannelTypeFeatures;
	use crate::types::payment::PaymentHash;
	use crate::util::test_utils;
	use bitcoin::hashes::Hash;
	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
	use bitcoin::PublicKey as BitcoinPublicKey;
	use bitcoin::{CompressedPublicKey, Network, ScriptBuf, Txid};

	#[allow(unused_imports)]
	use crate::prelude::*;

	struct TestCommitmentTxBuilder {
		commitment_number: u64,
		per_commitment_point: PublicKey,
		feerate_per_kw: u32,
		channel_parameters: ChannelTransactionParameters,
		counterparty_pubkeys: ChannelPublicKeys,
		secp_ctx: Secp256k1<secp256k1::All>,
	}

	impl TestCommitmentTxBuilder {
		#[rustfmt::skip]
		fn new() -> Self {
			let secp_ctx = Secp256k1::new();
			let seed = [42; 32];
			let network = Network::Testnet;
			let keys_provider = test_utils::TestKeysInterface::new(&seed, network);
			let signer = keys_provider.derive_channel_signer(keys_provider.generate_channel_keys_id(false, 0));
			let counterparty_signer = keys_provider.derive_channel_signer(keys_provider.generate_channel_keys_id(true, 1));
			let per_commitment_secret = SecretKey::from_slice(&<Vec<u8>>::from_hex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100").unwrap()[..]).unwrap();
			let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);
			let holder_pubkeys = signer.pubkeys(&secp_ctx);
			let counterparty_pubkeys = counterparty_signer.pubkeys(&secp_ctx).clone();
			let channel_parameters = ChannelTransactionParameters {
				holder_pubkeys: holder_pubkeys.clone(),
				holder_selected_contest_delay: 0,
				is_outbound_from_holder: false,
				counterparty_parameters: Some(CounterpartyChannelTransactionParameters { pubkeys: counterparty_pubkeys.clone(), selected_contest_delay: 0 }),
				funding_outpoint: Some(chain::transaction::OutPoint { txid: Txid::all_zeros(), index: 0 }),
				splice_parent_funding_txid: None,
				channel_type_features: ChannelTypeFeatures::only_static_remote_key(),
				channel_value_satoshis: 4000,
			};

			Self {
				commitment_number: 0,
				per_commitment_point,
				feerate_per_kw: 1,
				channel_parameters,
				counterparty_pubkeys,
				secp_ctx,
			}
		}

		#[rustfmt::skip]
		fn build(&self, to_broadcaster_sats: u64, to_countersignatory_sats: u64, nondust_htlcs: Vec<HTLCOutputInCommitment>) -> CommitmentTransaction {
			CommitmentTransaction::new(
				self.commitment_number, &self.per_commitment_point, to_broadcaster_sats, to_countersignatory_sats, self.feerate_per_kw,
				nondust_htlcs, &self.channel_parameters.as_holder_broadcastable(), &self.secp_ctx
			)
		}

		fn verify<'a>(
			&self, tx: &'a CommitmentTransaction,
		) -> Result<TrustedCommitmentTransaction<'a>, ()> {
			tx.verify(&self.channel_parameters.as_holder_broadcastable(), &self.secp_ctx)
		}
	}

	#[test]
	#[rustfmt::skip]
	fn test_anchors() {
		let mut builder = TestCommitmentTxBuilder::new();

		// Generate broadcaster and counterparty outputs
		let tx = builder.build(1000, 2000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 2);
		assert_eq!(tx.built.transaction.output[1].script_pubkey, bitcoin::address::Address::p2wpkh(&CompressedPublicKey(builder.counterparty_pubkeys.payment_point), Network::Testnet).script_pubkey());

		// Generate broadcaster and counterparty outputs as well as two anchors
		builder.channel_parameters.channel_type_features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
		let tx = builder.build(1000, 2000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 4);
		assert_eq!(tx.built.transaction.output[3].script_pubkey, get_to_countersigner_keyed_anchor_redeemscript(&builder.counterparty_pubkeys.payment_point).to_p2wsh());
		assert_eq!(tx.built.transaction.output[0].script_pubkey, get_keyed_anchor_redeemscript(&builder.channel_parameters.holder_pubkeys.funding_pubkey).to_p2wsh());
		assert_eq!(tx.built.transaction.output[0].value.to_sat(), 330);
		assert_eq!(tx.built.transaction.output[1].script_pubkey, get_keyed_anchor_redeemscript(&builder.counterparty_pubkeys.funding_pubkey).to_p2wsh());
		assert_eq!(tx.built.transaction.output[1].value.to_sat(), 330);

		// Generate broadcaster output and anchor
		let tx = builder.build(3000, 0, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 2);
		assert_eq!(tx.built.transaction.output[0].script_pubkey, get_keyed_anchor_redeemscript(&builder.channel_parameters.holder_pubkeys.funding_pubkey).to_p2wsh());
		assert_eq!(tx.built.transaction.output[0].value.to_sat(), 330);

		// Generate counterparty output and anchor
		let tx = builder.build(0, 3000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 2);
		assert_eq!(tx.built.transaction.output[0].script_pubkey, get_keyed_anchor_redeemscript(&builder.counterparty_pubkeys.funding_pubkey).to_p2wsh());
		assert_eq!(tx.built.transaction.output[0].value.to_sat(), 330);

		// Generate broadcaster and counterparty outputs as well as a single anchor
		builder.channel_parameters.channel_type_features = ChannelTypeFeatures::anchors_zero_fee_commitments();
		let tx = builder.build(1000, 2000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 3);
		assert_eq!(tx.built.transaction.output[2].script_pubkey, bitcoin::address::Address::p2wpkh(&CompressedPublicKey(builder.counterparty_pubkeys.payment_point), Network::Testnet).script_pubkey());
		assert_eq!(tx.built.transaction.output[0].script_pubkey, shared_anchor_script_pubkey());
		assert_eq!(tx.built.transaction.output[0].value.to_sat(), 240); // remember total channel value is 4000sat

		// Generate broadcaster output and anchor
		let tx = builder.build(3000, 0, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 2);
		assert_eq!(tx.built.transaction.output[0].script_pubkey, shared_anchor_script_pubkey());
		assert_eq!(tx.built.transaction.output[0].value.to_sat(), 240); // remember total channel value is 4000sat

		// Generate counterparty output and anchor
		let tx = builder.build(0, 3000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 2);
		assert_eq!(tx.built.transaction.output[0].script_pubkey, shared_anchor_script_pubkey());
		assert_eq!(tx.built.transaction.output[0].value.to_sat(), 240); // remember total channel value is 4000sat

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

		// Generate broadcaster output and received and offered HTLC outputs, w/o anchors
		builder.channel_parameters.channel_type_features = ChannelTypeFeatures::only_static_remote_key();
		let tx = builder.build(3000, 0, vec![received_htlc.clone(), offered_htlc.clone()]);
		let keys = tx.trust().keys();
		assert_eq!(tx.built.transaction.output.len(), 3);
		assert_eq!(tx.built.transaction.output[0].script_pubkey, get_htlc_redeemscript(&received_htlc, &ChannelTypeFeatures::only_static_remote_key(), &keys).to_p2wsh());
		assert_eq!(tx.built.transaction.output[1].script_pubkey, get_htlc_redeemscript(&offered_htlc, &ChannelTypeFeatures::only_static_remote_key(), &keys).to_p2wsh());
		assert_eq!(get_htlc_redeemscript(&received_htlc, &ChannelTypeFeatures::only_static_remote_key(), &keys).to_p2wsh().to_hex_string(),
				   "0020e43a7c068553003fe68fcae424fb7b28ec5ce48cd8b6744b3945631389bad2fb");
		assert_eq!(get_htlc_redeemscript(&offered_htlc, &ChannelTypeFeatures::only_static_remote_key(), &keys).to_p2wsh().to_hex_string(),
				   "0020215d61bba56b19e9eadb6107f5a85d7f99c40f65992443f69229c290165bc00d");

		// Generate broadcaster output and received and offered HTLC outputs, with keyed anchors
		builder.channel_parameters.channel_type_features = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();
		let tx = builder.build(3000, 0, vec![received_htlc.clone(), offered_htlc.clone()]);
		assert_eq!(tx.built.transaction.output.len(), 5);
		assert_eq!(tx.built.transaction.output[0].script_pubkey, get_keyed_anchor_redeemscript(&builder.channel_parameters.holder_pubkeys.funding_pubkey).to_p2wsh());
		assert_eq!(tx.built.transaction.output[0].value.to_sat(), 330);
		assert_eq!(tx.built.transaction.output[1].script_pubkey, get_keyed_anchor_redeemscript(&builder.counterparty_pubkeys.funding_pubkey).to_p2wsh());
		assert_eq!(tx.built.transaction.output[1].value.to_sat(), 330);
		assert_eq!(tx.built.transaction.output[2].script_pubkey, get_htlc_redeemscript(&received_htlc, &ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(), &keys).to_p2wsh());
		assert_eq!(tx.built.transaction.output[3].script_pubkey, get_htlc_redeemscript(&offered_htlc, &ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(), &keys).to_p2wsh());
		assert_eq!(get_htlc_redeemscript(&received_htlc, &ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(), &keys).to_p2wsh().to_hex_string(),
				   "0020b70d0649c72b38756885c7a30908d912a7898dd5d79457a7280b8e9a20f3f2bc");
		assert_eq!(get_htlc_redeemscript(&offered_htlc, &ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(), &keys).to_p2wsh().to_hex_string(),
				   "002087a3faeb1950a469c0e2db4a79b093a41b9526e5a6fc6ef5cb949bde3be379c7");

		// Generate broadcaster output and received and offered HTLC outputs, with P2A anchors
		builder.channel_parameters.channel_type_features = ChannelTypeFeatures::anchors_zero_fee_commitments();
		let tx = builder.build(3000, 0, vec![received_htlc.clone(), offered_htlc.clone()]);
		assert_eq!(tx.built.transaction.output.len(), 4);
		assert_eq!(tx.built.transaction.output[0].script_pubkey, shared_anchor_script_pubkey());
		assert_eq!(tx.built.transaction.output[0].value.to_sat(), 0);
		assert_eq!(tx.built.transaction.output[1].script_pubkey, get_htlc_redeemscript(&received_htlc, &ChannelTypeFeatures::anchors_zero_fee_commitments(), &keys).to_p2wsh());
		assert_eq!(tx.built.transaction.output[2].script_pubkey, get_htlc_redeemscript(&offered_htlc, &ChannelTypeFeatures::anchors_zero_fee_commitments(), &keys).to_p2wsh());
		assert_eq!(get_htlc_redeemscript(&received_htlc, &ChannelTypeFeatures::anchors_zero_fee_commitments(), &keys).to_p2wsh().to_hex_string(),
				   "0020e43a7c068553003fe68fcae424fb7b28ec5ce48cd8b6744b3945631389bad2fb");
		assert_eq!(get_htlc_redeemscript(&offered_htlc, &ChannelTypeFeatures::anchors_zero_fee_commitments(), &keys).to_p2wsh().to_hex_string(),
				   "0020215d61bba56b19e9eadb6107f5a85d7f99c40f65992443f69229c290165bc00d");
	}

	#[test]
	fn test_finding_revokeable_output_index() {
		let builder = TestCommitmentTxBuilder::new();

		// Revokeable output present
		let tx = builder.build(1000, 2000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 2);
		assert_eq!(tx.trust().revokeable_output_index(), Some(0));

		// Revokeable output present (but to_broadcaster_delay missing)
		let tx = CommitmentTransaction { to_broadcaster_delay: None, ..tx };
		assert_eq!(tx.built.transaction.output.len(), 2);
		assert_eq!(tx.trust().revokeable_output_index(), None);

		// Revokeable output not present (our balance is dust)
		let tx = builder.build(0, 2000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 1);
		assert_eq!(tx.trust().revokeable_output_index(), None);
	}

	#[test]
	#[rustfmt::skip]
	fn test_building_to_local_justice_tx() {
		let builder = TestCommitmentTxBuilder::new();

		// Revokeable output not present (our balance is dust)
		let tx = builder.build(0, 2000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 1);
		assert!(tx.trust().build_to_local_justice_tx(253, ScriptBuf::new()).is_err());

		// Revokeable output present
		let tx = builder.build(1000, 2000, Vec::new());
		assert_eq!(tx.built.transaction.output.len(), 2);

		// Too high feerate
		assert!(tx.trust().build_to_local_justice_tx(100_000, ScriptBuf::new()).is_err());

		// Generate a random public key for destination script
		let secret_key = SecretKey::from_slice(
			&<Vec<u8>>::from_hex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
			.unwrap()[..]).unwrap();
		let pubkey_hash = BitcoinPublicKey::new(
			PublicKey::from_secret_key(&Secp256k1::new(), &secret_key)).wpubkey_hash().unwrap();
		let destination_script = ScriptBuf::new_p2wpkh(&pubkey_hash);

		let justice_tx = tx.trust().build_to_local_justice_tx(253, destination_script.clone()).unwrap();
		assert_eq!(justice_tx.input.len(), 1);
		assert_eq!(justice_tx.input[0].previous_output.txid, tx.built.transaction.compute_txid());
		assert_eq!(justice_tx.input[0].previous_output.vout, tx.trust().revokeable_output_index().unwrap() as u32);
		assert!(justice_tx.input[0].sequence.is_rbf());

		assert_eq!(justice_tx.output.len(), 1);
		assert!(justice_tx.output[0].value.to_sat() < 1000);
		assert_eq!(justice_tx.output[0].script_pubkey, destination_script);
	}

	#[test]
	fn test_per_commitment_storage() {
		// Test vectors from BOLT 3:
		let mut secrets: Vec<[u8; 32]> = Vec::new();
		let mut monitor;

		#[rustfmt::skip]
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

			let hex = "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();
		}

		{
			// insert_secret #1 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			let hex = "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			assert!(monitor
				.provide_secret(281474976710654, secrets.last().unwrap().clone())
				.is_err());
		}

		{
			// insert_secret #2 incorrect (#1 derived from incorrect)
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			let hex = "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			assert!(monitor
				.provide_secret(281474976710652, secrets.last().unwrap().clone())
				.is_err());
		}

		{
			// insert_secret #3 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			let hex = "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			assert!(monitor
				.provide_secret(281474976710652, secrets.last().unwrap().clone())
				.is_err());
		}

		{
			// insert_secret #4 incorrect (1,2,3 derived from incorrect)
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			let hex = "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "ba65d7b0ef55a3ba300d4e87af29868f394f8f138d78a7011669c79b37b936f4";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			assert!(monitor
				.provide_secret(281474976710648, secrets.last().unwrap().clone())
				.is_err());
		}

		{
			// insert_secret #5 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			let hex = "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			assert!(monitor
				.provide_secret(281474976710650, secrets.last().unwrap().clone())
				.is_err());
		}

		{
			// insert_secret #6 incorrect (5 derived from incorrect)
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			let hex = "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "b7e76a83668bde38b373970155c868a653304308f9896692f904a23731224bb1";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			assert!(monitor
				.provide_secret(281474976710648, secrets.last().unwrap().clone())
				.is_err());
		}

		{
			// insert_secret #7 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			let hex = "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "e7971de736e01da8ed58b94c2fc216cb1dca9e326f3a96e7194fe8ea8af6c0a3";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			assert!(monitor
				.provide_secret(281474976710648, secrets.last().unwrap().clone())
				.is_err());
		}

		{
			// insert_secret #8 incorrect
			monitor = CounterpartyCommitmentSecrets::new();
			secrets.clear();

			let hex = "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
			test_secrets!();

			let hex = "a7efbc61aac46d34f77778bac22c8a20c6a46ca460addc49009bda875ec88fa4";
			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&<Vec<u8>>::from_hex(hex).unwrap());
			assert!(monitor
				.provide_secret(281474976710648, secrets.last().unwrap().clone())
				.is_err());
		}
	}

	#[test]
	fn test_verify_sorted_htlcs() {
		// Assert that `CommitmentTransaction::verify` checks that the HTLCs are sorted

		#[rustfmt::skip]
		macro_rules! swap_htlcs {
			($small_htlc: expr, $big_htlc: expr) => {
				let builder = TestCommitmentTxBuilder::new();

				let nondust_htlcs = vec![$small_htlc.clone(), $big_htlc.clone()];
				let mut commit_tx = builder.build(0, 0, nondust_htlcs.clone());
				// Everything should be OK up to this point
				builder.verify(&commit_tx).unwrap();
				// Sanity check that `small_htlc` was actually smaller than `big_htlc`
				assert_eq!(commit_tx.nondust_htlcs, nondust_htlcs);

				// Swap the HTLCs in the `nondust_htlcs` vector
				commit_tx.nondust_htlcs.swap(0, 1);

				// Also swap the HTLCs in the outputs of the cached transaction
				let mut transaction = commit_tx.built.transaction.clone();
				// The transaction should just have 2 HTLC outputs
				assert_eq!(transaction.output.len(), 2);
				transaction.output.swap(0, 1);
				let txid = transaction.compute_txid();
				let built = BuiltCommitmentTransaction {
					transaction,
					txid,
				};
				commit_tx.built = built;

				// Yes the HTLCs in `nondust_htlcs` are in the same order as in the cached transaction,
				// but they are not sorted!
				assert!(builder.verify(&commit_tx).is_err());
			}
		}

		// script_pubkey: Script(OP_0 OP_PUSHBYTES_32 1b202f6bdf42cd8ba08e263868b5bd0cf5a7f95c227c27e1935984a8f6130fa3)
		let small_htlc = HTLCOutputInCommitment {
			offered: true,
			amount_msat: 10_000,
			cltv_expiry: 123,
			payment_hash: PaymentHash([0xbb; 32]),
			transaction_output_index: Some(0),
		};

		// Check amount sorting
		let mut big_htlc = small_htlc.clone();
		big_htlc.amount_msat = 20_000;
		big_htlc.transaction_output_index = Some(1);

		swap_htlcs!(small_htlc.clone(), big_htlc);

		// Check script pubkey sorting
		let mut big_htlc = small_htlc.clone();
		// script_pubkey: Script(OP_0 OP_PUSHBYTES_32 b929ab63800ff4e350d2e2ad320b44d643829f135f60ad6a4f01e39fff228810)
		big_htlc.payment_hash = PaymentHash([0xaa; 32]);
		big_htlc.transaction_output_index = Some(1);

		swap_htlcs!(small_htlc.clone(), big_htlc);

		// Check CLTV sorting.
		// We want identical `TxOut`'s, so make sure the HTLCs are offered HTLCs with same amounts and payment hashes.
		let mut big_htlc = small_htlc.clone();
		big_htlc.cltv_expiry = 124;
		big_htlc.transaction_output_index = Some(1);

		swap_htlcs!(small_htlc, big_htlc);
	}
}
