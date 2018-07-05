use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
use bitcoin::util::hash::{Hash160, Sha256dHash};

use secp256k1;
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::Secp256k1;

use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;

use util::sha2::Sha256;

pub const HTLC_SUCCESS_TX_WEIGHT: u64 = 703;
pub const HTLC_TIMEOUT_TX_WEIGHT: u64 = 663;

// Various functions for key derivation and transaction creation for use within channels. Primarily
// used in Channel and ChannelMonitor.

pub fn build_commitment_secret(commitment_seed: [u8; 32], idx: u64) -> [u8; 32] {
	let mut res: [u8; 32] = commitment_seed;
	for i in 0..48 {
		let bitpos = 47 - i;
		if idx & (1 << bitpos) == (1 << bitpos) {
			res[bitpos / 8] ^= 1 << (bitpos & 7);
			let mut sha = Sha256::new();
			sha.input(&res);
			sha.result(&mut res);
		}
	}
	res
}

pub fn derive_private_key(
	secp_ctx: &Secp256k1,
	per_commitment_point: &PublicKey,
	base_secret: &SecretKey,
) -> Result<SecretKey, secp256k1::Error> {
	let mut sha = Sha256::new();
	sha.input(&per_commitment_point.serialize());
	sha.input(&PublicKey::from_secret_key(&secp_ctx, &base_secret)
		.unwrap()
		.serialize());
	let mut res = [0; 32];
	sha.result(&mut res);

	let mut key = base_secret.clone();
	key.add_assign(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &res)?)?;
	Ok(key)
}

pub fn derive_public_key(
	secp_ctx: &Secp256k1,
	per_commitment_point: &PublicKey,
	base_point: &PublicKey,
) -> Result<PublicKey, secp256k1::Error> {
	let mut sha = Sha256::new();
	sha.input(&per_commitment_point.serialize());
	sha.input(&base_point.serialize());
	let mut res = [0; 32];
	sha.result(&mut res);

	let hashkey =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secp_ctx, &res)?).unwrap();
	base_point.combine(&secp_ctx, &hashkey)
}

/// Derives a revocation key from its constituent parts
pub fn derive_private_revocation_key(
	secp_ctx: &Secp256k1,
	per_commitment_secret: &SecretKey,
	revocation_base_secret: &SecretKey,
) -> Result<SecretKey, secp256k1::Error> {
	let revocation_base_point =
		PublicKey::from_secret_key(&secp_ctx, &revocation_base_secret).unwrap();
	let per_commitment_point =
		PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret).unwrap();

	let rev_append_commit_hash_key = {
		let mut sha = Sha256::new();
		sha.input(&revocation_base_point.serialize());
		sha.input(&per_commitment_point.serialize());
		let mut res = [0; 32];
		sha.result(&mut res);

		SecretKey::from_slice(&secp_ctx, &res)?
	};
	let commit_append_rev_hash_key = {
		let mut sha = Sha256::new();
		sha.input(&per_commitment_point.serialize());
		sha.input(&revocation_base_point.serialize());
		let mut res = [0; 32];
		sha.result(&mut res);

		SecretKey::from_slice(&secp_ctx, &res)?
	};

	let mut part_a = revocation_base_secret.clone();
	part_a.mul_assign(&secp_ctx, &rev_append_commit_hash_key)?;
	let mut part_b = per_commitment_secret.clone();
	part_b.mul_assign(&secp_ctx, &commit_append_rev_hash_key)?;
	part_a.add_assign(&secp_ctx, &part_b)?;
	Ok(part_a)
}

pub fn derive_public_revocation_key(
	secp_ctx: &Secp256k1,
	per_commitment_point: &PublicKey,
	revocation_base_point: &PublicKey,
) -> Result<PublicKey, secp256k1::Error> {
	let rev_append_commit_hash_key = {
		let mut sha = Sha256::new();
		sha.input(&revocation_base_point.serialize());
		sha.input(&per_commitment_point.serialize());
		let mut res = [0; 32];
		sha.result(&mut res);

		SecretKey::from_slice(&secp_ctx, &res)?
	};
	let commit_append_rev_hash_key = {
		let mut sha = Sha256::new();
		sha.input(&per_commitment_point.serialize());
		sha.input(&revocation_base_point.serialize());
		let mut res = [0; 32];
		sha.result(&mut res);

		SecretKey::from_slice(&secp_ctx, &res)?
	};

	let mut part_a = revocation_base_point.clone();
	part_a.mul_assign(&secp_ctx, &rev_append_commit_hash_key)?;
	let mut part_b = per_commitment_point.clone();
	part_b.mul_assign(&secp_ctx, &commit_append_rev_hash_key)?;
	part_a.combine(&secp_ctx, &part_b)
}

pub struct TxCreationKeys {
	pub per_commitment_point: PublicKey,
	pub revocation_key: PublicKey,
	pub a_htlc_key: PublicKey,
	pub b_htlc_key: PublicKey,
	pub a_delayed_payment_key: PublicKey,
	pub b_payment_key: PublicKey,
}

impl TxCreationKeys {
	pub fn new(
		secp_ctx: &Secp256k1,
		per_commitment_point: &PublicKey,
		a_delayed_payment_base: &PublicKey,
		a_htlc_base: &PublicKey,
		b_revocation_base: &PublicKey,
		b_payment_base: &PublicKey,
		b_htlc_base: &PublicKey,
	) -> Result<TxCreationKeys, secp256k1::Error> {
		Ok(TxCreationKeys {
			per_commitment_point: per_commitment_point.clone(),
			revocation_key: derive_public_revocation_key(
				&secp_ctx,
				&per_commitment_point,
				&b_revocation_base,
			)?,
			a_htlc_key: derive_public_key(&secp_ctx, &per_commitment_point, &a_htlc_base)?,
			b_htlc_key: derive_public_key(&secp_ctx, &per_commitment_point, &b_htlc_base)?,
			a_delayed_payment_key: derive_public_key(
				&secp_ctx,
				&per_commitment_point,
				&a_delayed_payment_base,
			)?,
			b_payment_key: derive_public_key(&secp_ctx, &per_commitment_point, &b_payment_base)?,
		})
	}
}

/// Gets the "to_local" output redeemscript, ie the script which is time-locked or spendable by
/// the revocation key
pub fn get_revokeable_redeemscript(
	revocation_key: &PublicKey,
	to_self_delay: u16,
	delayed_payment_key: &PublicKey,
) -> Script {
	Builder::new()
		.push_opcode(opcodes::All::OP_IF)
		.push_slice(&revocation_key.serialize())
		.push_opcode(opcodes::All::OP_ELSE)
		.push_int(to_self_delay as i64)
		.push_opcode(opcodes::OP_CSV)
		.push_opcode(opcodes::All::OP_DROP)
		.push_slice(&delayed_payment_key.serialize())
		.push_opcode(opcodes::All::OP_ENDIF)
		.push_opcode(opcodes::All::OP_CHECKSIG)
		.into_script()
}

#[derive(Clone)]
pub struct HTLCOutputInCommitment {
	pub offered: bool,
	pub amount_msat: u64,
	pub cltv_expiry: u32,
	pub payment_hash: [u8; 32],
	pub transaction_output_index: u32,
}

#[inline]
pub fn get_htlc_redeemscript_with_explicit_keys(
	htlc: &HTLCOutputInCommitment,
	a_htlc_key: &PublicKey,
	b_htlc_key: &PublicKey,
	revocation_key: &PublicKey,
) -> Script {
	let payment_hash160 = {
		let mut ripemd = Ripemd160::new();
		ripemd.input(&htlc.payment_hash);
		let mut res = [0; 20];
		ripemd.result(&mut res);
		res
	};
	if htlc.offered {
		Builder::new()
			.push_opcode(opcodes::All::OP_DUP)
			.push_opcode(opcodes::All::OP_HASH160)
			.push_slice(&Hash160::from_data(&revocation_key.serialize())[..])
			.push_opcode(opcodes::All::OP_EQUAL)
			.push_opcode(opcodes::All::OP_IF)
			.push_opcode(opcodes::All::OP_CHECKSIG)
			.push_opcode(opcodes::All::OP_ELSE)
			.push_slice(&b_htlc_key.serialize()[..])
			.push_opcode(opcodes::All::OP_SWAP)
			.push_opcode(opcodes::All::OP_SIZE)
			.push_int(32)
			.push_opcode(opcodes::All::OP_EQUAL)
			.push_opcode(opcodes::All::OP_NOTIF)
			.push_opcode(opcodes::All::OP_DROP)
			.push_int(2)
			.push_opcode(opcodes::All::OP_SWAP)
			.push_slice(&a_htlc_key.serialize()[..])
			.push_int(2)
			.push_opcode(opcodes::All::OP_CHECKMULTISIG)
			.push_opcode(opcodes::All::OP_ELSE)
			.push_opcode(opcodes::All::OP_HASH160)
			.push_slice(&payment_hash160)
			.push_opcode(opcodes::All::OP_EQUALVERIFY)
			.push_opcode(opcodes::All::OP_CHECKSIG)
			.push_opcode(opcodes::All::OP_ENDIF)
			.push_opcode(opcodes::All::OP_ENDIF)
			.into_script()
	} else {
		Builder::new()
			.push_opcode(opcodes::All::OP_DUP)
			.push_opcode(opcodes::All::OP_HASH160)
			.push_slice(&Hash160::from_data(&revocation_key.serialize())[..])
			.push_opcode(opcodes::All::OP_EQUAL)
			.push_opcode(opcodes::All::OP_IF)
			.push_opcode(opcodes::All::OP_CHECKSIG)
			.push_opcode(opcodes::All::OP_ELSE)
			.push_slice(&b_htlc_key.serialize()[..])
			.push_opcode(opcodes::All::OP_SWAP)
			.push_opcode(opcodes::All::OP_SIZE)
			.push_int(32)
			.push_opcode(opcodes::All::OP_EQUAL)
			.push_opcode(opcodes::All::OP_IF)
			.push_opcode(opcodes::All::OP_HASH160)
			.push_slice(&payment_hash160)
			.push_opcode(opcodes::All::OP_EQUALVERIFY)
			.push_int(2)
			.push_opcode(opcodes::All::OP_SWAP)
			.push_slice(&a_htlc_key.serialize()[..])
			.push_int(2)
			.push_opcode(opcodes::All::OP_CHECKMULTISIG)
			.push_opcode(opcodes::All::OP_ELSE)
			.push_opcode(opcodes::All::OP_DROP)
			.push_int(htlc.cltv_expiry as i64)
			.push_opcode(opcodes::OP_CLTV)
			.push_opcode(opcodes::All::OP_DROP)
			.push_opcode(opcodes::All::OP_CHECKSIG)
			.push_opcode(opcodes::All::OP_ENDIF)
			.push_opcode(opcodes::All::OP_ENDIF)
			.into_script()
	}
}

/// note here that 'a_revocation_key' is generated using b_revocation_basepoint and a's
/// commitment secret. 'htlc' does *not* need to have its previous_output_index filled.
#[inline]
pub fn get_htlc_redeemscript(htlc: &HTLCOutputInCommitment, keys: &TxCreationKeys) -> Script {
	get_htlc_redeemscript_with_explicit_keys(
		htlc,
		&keys.a_htlc_key,
		&keys.b_htlc_key,
		&keys.revocation_key,
	)
}

pub fn build_htlc_transaction(
	prev_hash: &Sha256dHash,
	feerate_per_kw: u64,
	to_self_delay: u16,
	htlc: &HTLCOutputInCommitment,
	a_delayed_payment_key: &PublicKey,
	revocation_key: &PublicKey,
) -> Transaction {
	let mut txins: Vec<TxIn> = Vec::new();
	txins.push(TxIn {
		prev_hash: prev_hash.clone(),
		prev_index: htlc.transaction_output_index,
		script_sig: Script::new(),
		sequence: 0,
		witness: Vec::new(),
	});

	let total_fee = if htlc.offered {
		feerate_per_kw * HTLC_TIMEOUT_TX_WEIGHT / 1000
	} else {
		feerate_per_kw * HTLC_SUCCESS_TX_WEIGHT / 1000
	};

	let mut txouts: Vec<TxOut> = Vec::new();
	txouts.push(TxOut {
		script_pubkey: get_revokeable_redeemscript(
			revocation_key,
			to_self_delay,
			a_delayed_payment_key,
		).to_v0_p2wsh(),
		value: htlc.amount_msat / 1000 - total_fee, //TODO: BOLT 3 does not specify if we should add amount_msat before dividing or if we should divide by 1000 before subtracting (as we do here)
	});

	Transaction {
		version: 2,
		lock_time: if htlc.offered {
			htlc.cltv_expiry
		} else {
			0
		},
		input: txins,
		output: txouts,
	}
}
