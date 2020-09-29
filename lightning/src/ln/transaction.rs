//! Transaction utils

use std::cmp;

use bitcoin::{OutPoint, Script, Transaction, TxIn, TxOut};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hash_types::WPubkeyHash;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::key::PublicKey;

use ln::chan_utils::{get_revokeable_redeemscript, HTLCOutputInCommitment, TxCreationKeys};
use ln::chan_utils;
use util::transaction_utils::sort_outputs;

/// Commitment info
#[derive(Clone)]
pub struct CommitmentInfo {
	/// True if the counterparty is the broadcaster, false if we are
	pub is_counterparty_broadcaster: bool,
	/// Countersigner payment pubkey
	pub to_countersigner_pubkey: PublicKey,
	/// Countersigner value
	pub to_countersigner_value_sat: u64,
	/// Broadcaster revocation pubkey
	pub revocation_pubkey: PublicKey,
	/// Broadcaster delayed payment key
	pub to_broadcaster_delayed_pubkey: PublicKey,
	/// Broadcaster value
	pub to_broadcaster_value_sat: u64,
	/// delay for to-broadcaster output
	pub to_self_delay: u16,
	/// HTLC info, with unpopulated output index
	pub htlcs: Vec<HTLCOutputInCommitment>,
}

fn script_for_p2wpkh(key: &PublicKey) -> Script {
	Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
		.push_slice(&WPubkeyHash::hash(&key.serialize())[..])
		.into_script()
}

/// Build the commitment tx.
///
/// Returns the transaction, the HTLC descriptions with output index populated
/// and the redeem scripts for the transaction.
/// Note that the redeem scripts are returned for test purposes.
pub fn build_commitment_tx(
	keys: &TxCreationKeys,
	info: &CommitmentInfo,
	obscured_commitment_transaction_number: u64,
	funding_outpoint: OutPoint,
) -> (Transaction, Vec<HTLCOutputInCommitment>, Vec<Script>) {
	let txins = {
		let mut ins: Vec<TxIn> = Vec::new();
		ins.push(TxIn {
			previous_output: funding_outpoint,
			script_sig: Script::new(),
			sequence: ((0x80 as u32) << 8 * 3)
				| ((obscured_commitment_transaction_number >> 3 * 8) as u32),
			witness: Vec::new(),
		});
		ins
	};

	let mut txouts: Vec<(TxOut, (Script, Option<HTLCOutputInCommitment>))> = Vec::new();

	if info.to_countersigner_value_sat > 0 {
		let script = script_for_p2wpkh(&info.to_countersigner_pubkey);
		txouts.push((
			TxOut {
				script_pubkey: script.clone(),
				value: info.to_countersigner_value_sat as u64,
			},
			(script, None),
		))
	}

	if info.to_broadcaster_value_sat > 0 {
		let redeem_script = get_revokeable_redeemscript(
			&info.revocation_pubkey,
			info.to_self_delay,
			&info.to_broadcaster_delayed_pubkey,
		);
		txouts.push((
			TxOut {
				script_pubkey: redeem_script.to_v0_p2wsh(),
				value: info.to_broadcaster_value_sat as u64,
			},
			(redeem_script, None),
		));
	}

	for htlc in &info.htlcs {
		let script = chan_utils::get_htlc_redeemscript(htlc, &keys);
		let txout = TxOut {
			script_pubkey: script.to_v0_p2wsh(),
			value: htlc.amount_msat / 1000,
		};
		txouts.push((txout, (script, Some(htlc.clone()))));
	}
	sort_outputs(&mut txouts, |a, b| {
		// BEGIN NOT TESTED
		if let &(_, Some(ref a_htlcout)) = a {
			if let &(_, Some(ref b_htlcout)) = b {
				a_htlcout.cltv_expiry.cmp(&b_htlcout.cltv_expiry)
			} else {
				cmp::Ordering::Equal
			}
		} else {
			cmp::Ordering::Equal
		}
		// END NOT TESTED
	});
	let mut outputs = Vec::with_capacity(txouts.len());
	let mut scripts = Vec::with_capacity(txouts.len());
	let mut htlcs = Vec::new();
	for (idx, mut out) in txouts.drain(..).enumerate() {
		outputs.push(out.0);
		scripts.push((out.1).0.clone());
		if let Some(mut htlc) = (out.1).1.take() {
			htlc.transaction_output_index = Some(idx as u32);
			htlcs.push(htlc);
		}
	}

	(
		Transaction {
			version: 2,
			lock_time: ((0x20 as u32) << 8 * 3) | ((obscured_commitment_transaction_number & 0xffffffu64) as u32),
			input: txins,
			output: outputs,
		},
		htlcs,
		scripts,
	)
}

/// Get the transaction number obscure factor
pub fn get_commitment_transaction_number_obscure_factor(
	holder_payment_basepoint: &PublicKey,
	counterparty_payment_basepoint: &PublicKey,
	outbound: bool,
) -> u64 {
	let mut sha = Sha256::engine();

	let their_payment_basepoint = counterparty_payment_basepoint.serialize();
	if outbound {
		sha.input(&holder_payment_basepoint.serialize());
		sha.input(&their_payment_basepoint);
	} else {
		sha.input(&their_payment_basepoint);
		sha.input(&holder_payment_basepoint.serialize());
	}
	let res = Sha256::from_engine(sha).into_inner();

	((res[26] as u64) << 5 * 8)
		| ((res[27] as u64) << 4 * 8)
		| ((res[28] as u64) << 3 * 8)
		| ((res[29] as u64) << 2 * 8)
		| ((res[30] as u64) << 1 * 8)
		| ((res[31] as u64) << 0 * 8)
}
