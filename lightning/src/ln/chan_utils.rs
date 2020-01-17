//! Various utilities for building scripts and deriving keys related to channels. These are
//! largely of interest for those implementing chain::keysinterface::ChannelKeys message signing
//! by hand.

use bitcoin::blockdata::script::{Script,Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::transaction::{TxIn,TxOut,OutPoint,Transaction, SigHashType};
use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::util::bip143;

use bitcoin_hashes::{Hash, HashEngine};
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::ripemd160::Hash as Ripemd160;
use bitcoin_hashes::hash160::Hash as Hash160;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;

use ln::channelmanager::{PaymentHash, PaymentPreimage};
use ln::msgs::DecodeError;
use util::ser::{Readable, Writeable, Writer, WriterWriteAdaptor};

use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::{Secp256k1, Signature};
use secp256k1;

pub(super) const HTLC_SUCCESS_TX_WEIGHT: u64 = 703;
pub(super) const HTLC_TIMEOUT_TX_WEIGHT: u64 = 663;

// Various functions for key derivation and transaction creation for use within channels. Primarily
// used in Channel and ChannelMonitor.

pub(super) fn build_commitment_secret(commitment_seed: &[u8; 32], idx: u64) -> [u8; 32] {
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

/// Derives a per-commitment-transaction private key (eg an htlc key or payment key) from the base
/// private key for that type of key and the per_commitment_point (available in TxCreationKeys)
pub fn derive_private_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_secret: &SecretKey) -> Result<SecretKey, secp256k1::Error> {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&PublicKey::from_secret_key(&secp_ctx, &base_secret).serialize());
	let res = Sha256::from_engine(sha).into_inner();

	let mut key = base_secret.clone();
	key.add_assign(&res)?;
	Ok(key)
}

pub(super) fn derive_public_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, base_point: &PublicKey) -> Result<PublicKey, secp256k1::Error> {
	let mut sha = Sha256::engine();
	sha.input(&per_commitment_point.serialize());
	sha.input(&base_point.serialize());
	let res = Sha256::from_engine(sha).into_inner();

	let hashkey = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&res)?);
	base_point.combine(&hashkey)
}

/// Derives a revocation key from its constituent parts.
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
pub(super) fn derive_private_revocation_key<T: secp256k1::Signing>(secp_ctx: &Secp256k1<T>, per_commitment_secret: &SecretKey, revocation_base_secret: &SecretKey) -> Result<SecretKey, secp256k1::Error> {
	let revocation_base_point = PublicKey::from_secret_key(&secp_ctx, &revocation_base_secret);
	let per_commitment_point = PublicKey::from_secret_key(&secp_ctx, &per_commitment_secret);

	let rev_append_commit_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&revocation_base_point.serialize());
		sha.input(&per_commitment_point.serialize());

		Sha256::from_engine(sha).into_inner()
	};
	let commit_append_rev_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&per_commitment_point.serialize());
		sha.input(&revocation_base_point.serialize());

		Sha256::from_engine(sha).into_inner()
	};

	let mut part_a = revocation_base_secret.clone();
	part_a.mul_assign(&rev_append_commit_hash_key)?;
	let mut part_b = per_commitment_secret.clone();
	part_b.mul_assign(&commit_append_rev_hash_key)?;
	part_a.add_assign(&part_b[..])?;
	Ok(part_a)
}

pub(super) fn derive_public_revocation_key<T: secp256k1::Verification>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, revocation_base_point: &PublicKey) -> Result<PublicKey, secp256k1::Error> {
	let rev_append_commit_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&revocation_base_point.serialize());
		sha.input(&per_commitment_point.serialize());

		Sha256::from_engine(sha).into_inner()
	};
	let commit_append_rev_hash_key = {
		let mut sha = Sha256::engine();
		sha.input(&per_commitment_point.serialize());
		sha.input(&revocation_base_point.serialize());

		Sha256::from_engine(sha).into_inner()
	};

	let mut part_a = revocation_base_point.clone();
	part_a.mul_assign(&secp_ctx, &rev_append_commit_hash_key)?;
	let mut part_b = per_commitment_point.clone();
	part_b.mul_assign(&secp_ctx, &commit_append_rev_hash_key)?;
	part_a.combine(&part_b)
}

/// The set of public keys which are used in the creation of one commitment transaction.
/// These are derived from the channel base keys and per-commitment data.
#[derive(PartialEq)]
pub struct TxCreationKeys {
	/// The per-commitment public key which was used to derive the other keys.
	pub per_commitment_point: PublicKey,
	/// The revocation key which is used to allow the owner of the commitment transaction to
	/// provide their counterparty the ability to punish them if they broadcast an old state.
	pub(crate) revocation_key: PublicKey,
	/// A's HTLC Key
	pub(crate) a_htlc_key: PublicKey,
	/// B's HTLC Key
	pub(crate) b_htlc_key: PublicKey,
	/// A's Payment Key (which isn't allowed to be spent from for some delay)
	pub(crate) a_delayed_payment_key: PublicKey,
	/// B's Payment Key
	pub(crate) b_payment_key: PublicKey,
}

/// One counterparty's public keys which do not change over the life of a channel.
#[derive(Clone)]
pub struct ChannelPublicKeys {
	/// The public key which is used to sign all commitment transactions, as it appears in the
	/// on-chain channel lock-in 2-of-2 multisig output.
	pub funding_pubkey: PublicKey,
	/// The base point which is used (with derive_public_revocation_key) to derive per-commitment
	/// revocation keys. The per-commitment revocation private key is then revealed by the owner of
	/// a commitment transaction so that their counterparty can claim all available funds if they
	/// broadcast an old state.
	pub revocation_basepoint: PublicKey,
	/// The base point which is used (with derive_public_key) to derive a per-commitment payment
	/// public key which receives immediately-spendable non-HTLC-encumbered funds.
	pub payment_basepoint: PublicKey,
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
	payment_basepoint,
	delayed_payment_basepoint,
	htlc_basepoint
});


impl TxCreationKeys {
	pub(crate) fn new<T: secp256k1::Signing + secp256k1::Verification>(secp_ctx: &Secp256k1<T>, per_commitment_point: &PublicKey, a_delayed_payment_base: &PublicKey, a_htlc_base: &PublicKey, b_revocation_base: &PublicKey, b_payment_base: &PublicKey, b_htlc_base: &PublicKey) -> Result<TxCreationKeys, secp256k1::Error> {
		Ok(TxCreationKeys {
			per_commitment_point: per_commitment_point.clone(),
			revocation_key: derive_public_revocation_key(&secp_ctx, &per_commitment_point, &b_revocation_base)?,
			a_htlc_key: derive_public_key(&secp_ctx, &per_commitment_point, &a_htlc_base)?,
			b_htlc_key: derive_public_key(&secp_ctx, &per_commitment_point, &b_htlc_base)?,
			a_delayed_payment_key: derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)?,
			b_payment_key: derive_public_key(&secp_ctx, &per_commitment_point, &b_payment_base)?,
		})
	}
}

/// Gets the "to_local" output redeemscript, ie the script which is time-locked or spendable by
/// the revocation key
pub(super) fn get_revokeable_redeemscript(revocation_key: &PublicKey, to_self_delay: u16, delayed_payment_key: &PublicKey) -> Script {
	Builder::new().push_opcode(opcodes::all::OP_IF)
	              .push_slice(&revocation_key.serialize())
	              .push_opcode(opcodes::all::OP_ELSE)
	              .push_int(to_self_delay as i64)
	              .push_opcode(opcodes::all::OP_CSV)
	              .push_opcode(opcodes::all::OP_DROP)
	              .push_slice(&delayed_payment_key.serialize())
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
	/// the remote party or our own.
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

#[inline]
pub(super) fn get_htlc_redeemscript_with_explicit_keys(htlc: &HTLCOutputInCommitment, a_htlc_key: &PublicKey, b_htlc_key: &PublicKey, revocation_key: &PublicKey) -> Script {
	let payment_hash160 = Ripemd160::hash(&htlc.payment_hash.0[..]).into_inner();
	if htlc.offered {
		Builder::new().push_opcode(opcodes::all::OP_DUP)
		              .push_opcode(opcodes::all::OP_HASH160)
		              .push_slice(&Hash160::hash(&revocation_key.serialize())[..])
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_IF)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_slice(&b_htlc_key.serialize()[..])
		              .push_opcode(opcodes::all::OP_SWAP)
		              .push_opcode(opcodes::all::OP_SIZE)
		              .push_int(32)
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_NOTIF)
		              .push_opcode(opcodes::all::OP_DROP)
		              .push_int(2)
		              .push_opcode(opcodes::all::OP_SWAP)
		              .push_slice(&a_htlc_key.serialize()[..])
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
		              .push_slice(&Hash160::hash(&revocation_key.serialize())[..])
		              .push_opcode(opcodes::all::OP_EQUAL)
		              .push_opcode(opcodes::all::OP_IF)
		              .push_opcode(opcodes::all::OP_CHECKSIG)
		              .push_opcode(opcodes::all::OP_ELSE)
		              .push_slice(&b_htlc_key.serialize()[..])
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
		              .push_slice(&a_htlc_key.serialize()[..])
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

/// note here that 'a_revocation_key' is generated using b_revocation_basepoint and a's
/// commitment secret. 'htlc' does *not* need to have its previous_output_index filled.
#[inline]
pub fn get_htlc_redeemscript(htlc: &HTLCOutputInCommitment, keys: &TxCreationKeys) -> Script {
	get_htlc_redeemscript_with_explicit_keys(htlc, &keys.a_htlc_key, &keys.b_htlc_key, &keys.revocation_key)
}

/// Gets the redeemscript for a funding output from the two funding public keys.
/// Note that the order of funding public keys does not matter.
pub fn make_funding_redeemscript(a: &PublicKey, b: &PublicKey) -> Script {
	let our_funding_key = a.serialize();
	let their_funding_key = b.serialize();

	let builder = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2);
	if our_funding_key[..] < their_funding_key[..] {
		builder.push_slice(&our_funding_key)
			.push_slice(&their_funding_key)
	} else {
		builder.push_slice(&their_funding_key)
			.push_slice(&our_funding_key)
	}.push_opcode(opcodes::all::OP_PUSHNUM_2).push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script()
}

/// panics if htlc.transaction_output_index.is_none()!
pub fn build_htlc_transaction(prev_hash: &Sha256dHash, feerate_per_kw: u64, to_self_delay: u16, htlc: &HTLCOutputInCommitment, a_delayed_payment_key: &PublicKey, revocation_key: &PublicKey) -> Transaction {
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
			feerate_per_kw * HTLC_TIMEOUT_TX_WEIGHT / 1000
		} else {
			feerate_per_kw * HTLC_SUCCESS_TX_WEIGHT / 1000
		};

	let mut txouts: Vec<TxOut> = Vec::new();
	txouts.push(TxOut {
		script_pubkey: get_revokeable_redeemscript(revocation_key, to_self_delay, a_delayed_payment_key).to_v0_p2wsh(),
		value: htlc.amount_msat / 1000 - total_fee //TODO: BOLT 3 does not specify if we should add amount_msat before dividing or if we should divide by 1000 before subtracting (as we do here)
	});

	Transaction {
		version: 2,
		lock_time: if htlc.offered { htlc.cltv_expiry } else { 0 },
		input: txins,
		output: txouts,
	}
}

/// Signs a transaction created by build_htlc_transaction. If the transaction is an
/// HTLC-Success transaction (ie htlc.offered is false), preimage must be set!
pub(crate) fn sign_htlc_transaction<T: secp256k1::Signing>(tx: &mut Transaction, their_sig: &Signature, preimage: &Option<PaymentPreimage>, htlc: &HTLCOutputInCommitment, a_htlc_key: &PublicKey, b_htlc_key: &PublicKey, revocation_key: &PublicKey, per_commitment_point: &PublicKey, htlc_base_key: &SecretKey, secp_ctx: &Secp256k1<T>) -> Result<(Signature, Script), ()> {
	if tx.input.len() != 1 { return Err(()); }
	if tx.input[0].witness.len() != 0 { return Err(()); }

	let htlc_redeemscript = get_htlc_redeemscript_with_explicit_keys(&htlc, a_htlc_key, b_htlc_key, revocation_key);

	let our_htlc_key = derive_private_key(secp_ctx, per_commitment_point, htlc_base_key).map_err(|_| ())?;
	let sighash = hash_to_message!(&bip143::SighashComponents::new(&tx).sighash_all(&tx.input[0], &htlc_redeemscript, htlc.amount_msat / 1000)[..]);
	let local_tx = PublicKey::from_secret_key(&secp_ctx, &our_htlc_key) == *a_htlc_key;
	let our_sig = secp_ctx.sign(&sighash, &our_htlc_key);

	tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

	if local_tx { // b, then a
		tx.input[0].witness.push(their_sig.serialize_der().to_vec());
		tx.input[0].witness.push(our_sig.serialize_der().to_vec());
	} else {
		tx.input[0].witness.push(our_sig.serialize_der().to_vec());
		tx.input[0].witness.push(their_sig.serialize_der().to_vec());
	}
	tx.input[0].witness[1].push(SigHashType::All as u8);
	tx.input[0].witness[2].push(SigHashType::All as u8);

	if htlc.offered {
		tx.input[0].witness.push(Vec::new());
		assert!(preimage.is_none());
	} else {
		tx.input[0].witness.push(preimage.unwrap().0.to_vec());
	}

	tx.input[0].witness.push(htlc_redeemscript.as_bytes().to_vec());

	Ok((our_sig, htlc_redeemscript))
}

#[derive(Clone)]
/// We use this to track local commitment transactions and put off signing them until we are ready
/// to broadcast. Eventually this will require a signer which is possibly external, but for now we
/// just pass in the SecretKeys required.
pub(crate) struct LocalCommitmentTransaction {
	tx: Transaction
}
impl LocalCommitmentTransaction {
	#[cfg(test)]
	pub fn dummy() -> Self {
		Self { tx: Transaction {
			version: 2,
			input: Vec::new(),
			output: Vec::new(),
			lock_time: 0,
		} }
	}

	pub fn new_missing_local_sig(mut tx: Transaction, their_sig: &Signature, our_funding_key: &PublicKey, their_funding_key: &PublicKey) -> LocalCommitmentTransaction {
		if tx.input.len() != 1 { panic!("Tried to store a commitment transaction that had input count != 1!"); }
		if tx.input[0].witness.len() != 0 { panic!("Tried to store a signed commitment transaction?"); }

		tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

		if our_funding_key.serialize()[..] < their_funding_key.serialize()[..] {
			tx.input[0].witness.push(Vec::new());
			tx.input[0].witness.push(their_sig.serialize_der().to_vec());
			tx.input[0].witness[2].push(SigHashType::All as u8);
		} else {
			tx.input[0].witness.push(their_sig.serialize_der().to_vec());
			tx.input[0].witness[1].push(SigHashType::All as u8);
			tx.input[0].witness.push(Vec::new());
		}

		Self { tx }
	}

	pub fn txid(&self) -> Sha256dHash {
		self.tx.txid()
	}

	pub fn has_local_sig(&self) -> bool {
		if self.tx.input.len() != 1 { panic!("Commitment transactions must have input count == 1!"); }
		if self.tx.input[0].witness.len() == 4 {
			assert!(!self.tx.input[0].witness[1].is_empty());
			assert!(!self.tx.input[0].witness[2].is_empty());
			true
		} else {
			assert_eq!(self.tx.input[0].witness.len(), 3);
			assert!(self.tx.input[0].witness[0].is_empty());
			assert!(self.tx.input[0].witness[1].is_empty() || self.tx.input[0].witness[2].is_empty());
			false
		}
	}

	pub fn add_local_sig<T: secp256k1::Signing>(&mut self, funding_key: &SecretKey, funding_redeemscript: &Script, channel_value_satoshis: u64, secp_ctx: &Secp256k1<T>) {
		if self.has_local_sig() { return; }
		let sighash = hash_to_message!(&bip143::SighashComponents::new(&self.tx)
			.sighash_all(&self.tx.input[0], funding_redeemscript, channel_value_satoshis)[..]);
		let our_sig = secp_ctx.sign(&sighash, funding_key);

		if self.tx.input[0].witness[1].is_empty() {
			self.tx.input[0].witness[1] = our_sig.serialize_der().to_vec();
			self.tx.input[0].witness[1].push(SigHashType::All as u8);
		} else {
			self.tx.input[0].witness[2] = our_sig.serialize_der().to_vec();
			self.tx.input[0].witness[2].push(SigHashType::All as u8);
		}

		self.tx.input[0].witness.push(funding_redeemscript.as_bytes().to_vec());
	}

	pub fn without_valid_witness(&self) -> &Transaction { &self.tx }
	pub fn with_valid_witness(&self) -> &Transaction {
		assert!(self.has_local_sig());
		&self.tx
	}
}
impl PartialEq for LocalCommitmentTransaction {
	// We dont care whether we are signed in equality comparison
	fn eq(&self, o: &Self) -> bool {
		self.txid() == o.txid()
	}
}
impl Writeable for LocalCommitmentTransaction {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		if let Err(e) = self.tx.consensus_encode(&mut WriterWriteAdaptor(writer)) {
			match e {
				encode::Error::Io(e) => return Err(e),
				_ => panic!("local tx must have been well-formed!"),
			}
		}
		Ok(())
	}
}
impl<R: ::std::io::Read> Readable<R> for LocalCommitmentTransaction {
	fn read(reader: &mut R) -> Result<Self, DecodeError> {
		let tx = match Transaction::consensus_decode(reader.by_ref()) {
			Ok(tx) => tx,
			Err(e) => match e {
				encode::Error::Io(ioe) => return Err(DecodeError::Io(ioe)),
				_ => return Err(DecodeError::InvalidValue),
			},
		};

		if tx.input.len() != 1 {
			// Ensure tx didn't hit the 0-input ambiguity case.
			return Err(DecodeError::InvalidValue);
		}
		Ok(Self { tx })
	}
}
