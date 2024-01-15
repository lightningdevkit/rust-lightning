//#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), deny(missing_docs))]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

//! A simple mutual-authentication protocol which allows two parties to maintain a set of public
//! keys which they're willing to exchange messages with and exchange a message with an extra
//! half-round-trip.
//!
//! The protocol contains one party wishing to send a message to another. The message recipient is
//! the `initiator` in the protocol, and speaks first. Most of the CPU cost is born by the message
//! sender.
//!
//! Both parties first create a [`TrustedSet`] listing the public keys which they are willing to
//! exchange messages with.
//!
//! In order to exchange a message, the message recipient calls [`get_init_bytes`] and sends the
//! resulting message bytes to the message sender. That message sender then uses
//! [`respond_with_message`] to determine if both sides are mutually in each others' [`TrustedSet`]
//! and encrypt the message if so. Finally, the initiator uses [`decode_msg`]
//!
//! If the message sender is in the initiator's trusted set and the message sender has the public
//! key for the initiator, the message sender will learn who the initiator is upon receipt of the
//! init message (without any response). The initiator will only learn who the message sender is
//! (and the message sender will only respond) if both sides are mutually-trusting.
//!
//! In any other case, neither party learns anything about the other, apart from a rough estimate
//! of the trusted set size of the initiator.

extern crate alloc;

use bitcoin_hashes::cmp::fixed_time_eq;

#[allow(dead_code)]
mod chacha20;
#[allow(dead_code)]
mod chacha20poly1305rfc;
#[allow(dead_code)]
mod poly1305;

use alloc::vec;
use alloc::vec::Vec;

use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, SecretKey};

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::{Hash, HashEngine};

use chacha20::ChaCha20;
use chacha20poly1305rfc::ChaCha20Poly1305RFC;

/// The maximum number of trusted counterparties which is allowed to be in a single [`TrustedSet`].
pub const MAX_TRUSTED_KEYS: usize = 1024;

/// A `TrustedSet` stores the set of peers which we are willing to talk to.
pub struct TrustedSet {
	trusted_ecdhs: Vec<[u8; 32]>,
	state_key: [u8; 32],
}

impl TrustedSet {
	/// Constructs a new [`TrustedSet`] given a list of trusted counterparties. The keys are not
	/// stored, only ECDH results are.
	///
	/// `trusted_counterparties` must not exceed [`MAX_TRUSTED_KEYS`] entries or the construction
	/// will fail. In all other cases construction succeeds.
	pub fn new(our_key: &SecretKey, trusted_counterparties: &[PublicKey]) -> Result<Self, ()> {
		if trusted_counterparties.len() > MAX_TRUSTED_KEYS {
			return Err(());
		}

		let mut trusted_ecdhs = Vec::with_capacity(trusted_counterparties.len());
		for counterparty in trusted_counterparties.iter() {
			let mut ecdh_hash = Sha256::engine();
			ecdh_hash.input(b"Mutual Message Exchange ECDH Result");
			ecdh_hash.input(&SharedSecret::new(counterparty, &our_key).secret_bytes());
			trusted_ecdhs.push(Sha256::from_engine(ecdh_hash).to_byte_array());
		}
		let mut state_key_hash = Sha256::engine();
		state_key_hash.input(b"Mutual Private Auth State Key Generation");
		state_key_hash.input(&Sha256::hash(&our_key[..]).to_byte_array());
		let state_key = Sha256::from_engine(state_key_hash).to_byte_array();

		Ok(Self { trusted_ecdhs, state_key })
	}

	fn get_cover_trusted_count(&self) -> usize {
		// In order to avoid giving away exactly how many keys we trust, we include some fake
		// entries in our message. To avoid too much overhead we only round the trusted set up a
		// bit.
		debug_assert!(self.trusted_ecdhs.len() <= MAX_TRUSTED_KEYS);
		match self.trusted_ecdhs.len() {
			0..=16 => 16,
			17..=32 => 32,
			33..=128 => 128,
			129..=512 => 512,
			_ => MAX_TRUSTED_KEYS,
		}
	}
}

/// The per-trusted-peer length in the intitial bytes.
///
/// Fixed by the protocol.
const PER_PEER_LEN: usize = 32 + 16;
/// The length of the repeated data we sent in the init bytes and expect to be repeated in the
/// response. This is floating in the protocol, but we fix it for ourselves.
const OUR_REPEATED_DATA_LEN: usize = 64 + 32 + 8 + 16;

/// In order to avoid a message recipient having any guess as to the size our trusted set is, we
/// shuffle the entries in our init deterministically, using the permutation calculated here.
fn get_idx_permutation(cover_trusted_set_len: usize, rng_seed: &[u8]) -> [u16; MAX_TRUSTED_KEYS] {
	debug_assert!(cover_trusted_set_len <= MAX_TRUSTED_KEYS);
	debug_assert!(MAX_TRUSTED_KEYS <= u16::MAX.into());
	debug_assert_eq!(rng_seed.len(), 32);

	let mut perm = [0; MAX_TRUSTED_KEYS];
	for i in 0..MAX_TRUSTED_KEYS {
		perm[i] = i as u16;
	}
	let mut rng = ChaCha20::new(rng_seed, b"MPA PERM RNG");
	for i in 0..cover_trusted_set_len {
		let mut pos;
		let max_pos = (cover_trusted_set_len - i) as u64;
		loop {
			let mut rand = [0; 8];
			rng.process_in_place(&mut rand);
			pos = u64::from_le_bytes(rand);
			if pos < u64::MAX / max_pos * max_pos {
				pos %= max_pos;
				break;
			}
		}
		perm.swap(i, pos as usize);
	}
	perm
}

/// Gets the initial bytes this initiator should send to a (potential) message sender.
///
/// It requires 64 secure random bytes, a reference to a [`TrustedSet`], and a `salt` and `aad`.
///
/// The `salt` should uniquely describe this protocol the protocol being built using this mutual
/// authentication handshake. The `aad` should describe the particular message type being sent
/// (which the sender expects).
pub fn get_init_bytes(
	secure_random_nonce: [u8; 64], trusted_set: &TrustedSet, salt: [u8; 8], aad: &[u8],
) -> Vec<u8> {
	let mut local_nonce = [0; 32];
	local_nonce.copy_from_slice(&secure_random_nonce[..32]);

	let mut chacha_salt = [0; 12];
	chacha_salt[4..].copy_from_slice(&salt);

	let mut rng = ChaCha20::new(&secure_random_nonce[32..], b"MPA INIT RNG");

	// Init message format is
	// 2 byte handshake count
	// PER_PEER_LEN * handshake count:
	//   32-byte encrypted initiator nonce
	//   16-byte poly1305 tag
	// 2 byte repeated data len
	// repeated data len bytes of data to be repeated
	// any further bytes uninterpreted (for extensibility)
	//
	// Our repeated data is a 40 byte IV (XOR'd into `state_key` and "NONCE KY" to form the ChaCha
	// key and nonce to encrypt remaining bytes), followed by 64 bytes containing the
	// ChaCha-encrypted `secure_random_nonce` and the 16 byte Poly1305 MAC tag for the same.

	let vec_cnt = trusted_set.get_cover_trusted_count();
	let repeated_data_offs = 2 + vec_cnt * PER_PEER_LEN;
	let mut res = Vec::with_capacity(repeated_data_offs + 2 + OUR_REPEATED_DATA_LEN);
	res.resize(2 + vec_cnt * PER_PEER_LEN + 2 + OUR_REPEATED_DATA_LEN, 0);
	res[..2].copy_from_slice(&(vec_cnt as u16).to_be_bytes());

	// First fill in the encrypted slots for our trusted peers and fill remaining slots with noise.
	let idx_permutation = get_idx_permutation(vec_cnt, &secure_random_nonce[32..]);
	for (pos, idx) in idx_permutation.iter().take(vec_cnt).enumerate() {
		let idx_slice = &mut res[2 + pos * PER_PEER_LEN..8 + (pos + 1) * PER_PEER_LEN];
		if *idx as usize >= trusted_set.trusted_ecdhs.len() {
			rng.process_in_place(idx_slice);
		} else {
			let ecdh = &trusted_set.trusted_ecdhs[*idx as usize];
			let mut cryptoor = ChaCha20Poly1305RFC::new(ecdh, &chacha_salt, aad);
			let (crypted, tag) = idx_slice.split_at_mut(32);
			cryptoor.encrypt(&local_nonce, crypted, tag);
		}
	}

	// Pick a random nonce to XOR into the ChaCha key and nonce. Note that we reuse the `state_key`
	// here repeatedly, so need the IV here to make the ChaCha pad unique.
	let mut repeated_data_key_mask = [0; 32 + 8];
	rng.process_in_place(&mut repeated_data_key_mask);
	let mut repeated_data_key = [0; 32];
	for i in 0..32 {
		repeated_data_key[i] = trusted_set.state_key[i] ^ repeated_data_key_mask[i];
	}
	let mut repeated_data_nonce = [0; 12];
	for i in 0..8 {
		repeated_data_nonce[4 + i] = b"NONCE KY"[i] ^ repeated_data_key_mask[32 + i];
	}

	res[repeated_data_offs..repeated_data_offs + 2]
		.copy_from_slice(&(OUR_REPEATED_DATA_LEN as u16).to_be_bytes());
	res[repeated_data_offs + 2..repeated_data_offs + 2 + 32 + 8]
		.copy_from_slice(&repeated_data_key_mask);

	let (crypted_nonce, tag) = res[repeated_data_offs + 2 + 32 + 8..].split_at_mut(64);
	let mut state_store = ChaCha20Poly1305RFC::new(&repeated_data_key, &repeated_data_nonce, &[]);
	state_store.encrypt(&secure_random_nonce, crypted_nonce, tag);
	res
}

/// Decode the message our counterparty sent us. The `salt` and `aad` provided must match the one
/// set in [`get_init_bytes`] and the one used by the message sender in [`respond_with_message`].
///
/// Returns both the message sent to us by the counterparty (if any) and a shared key which can be
/// used to en/decrypt future messages with the message-sender.
pub fn decode_msg(
	trusted_set: &TrustedSet, salt: [u8; 8], aad: &[u8], wire_msg: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), ()> {
	// Message format is:
	// 2 byte selected challenge index
	// 32 + 16 byte encrypted + MAC'd nonce
	// 2 byte repeated data len
	// repeated data len bytes of repeated data
	// 2 byte message length (not counting mac)
	// message length of encrypted message data
	// 16 byte poly1305 message MAC
	//
	// Our repeated data is a 40 byte IV (XOR'd into `state_key` and "NONCE KY" to form the ChaCha
	// key and nonce to encrypt remaining bytes), followed by 64 bytes containing the
	// ChaCha-encrypted `secure_random_nonce` and the 16 byte Poly1305 MAC tag for the same.
	const REPEATED_DATA_OFFS: usize = 2 + 32 + 16;
	const CONST_OVERHEAD: usize = 2 + 32 + 16 + 2 + 2 + 16;

	let mut chacha_salt = [0; 12];
	chacha_salt[4..].copy_from_slice(&salt);
	for b in chacha_salt.iter_mut().skip(4) {
		*b ^= 0xff;
	}
	if wire_msg.len() < CONST_OVERHEAD {
		return Err(());
	}

	// Read our state storage (i.e. the "secure_random_nonce" parameter from `get_init_bytes`.
	let mut secure_random_nonce = [0; 64];
	let repeated_part_len;
	let msg_offs: usize;
	{
		let mut repeated_part_len_bytes = [0; 2];
		repeated_part_len_bytes
			.copy_from_slice(&wire_msg[REPEATED_DATA_OFFS..REPEATED_DATA_OFFS + 2]);
		repeated_part_len = u16::from_be_bytes(repeated_part_len_bytes);

		if repeated_part_len as usize != OUR_REPEATED_DATA_LEN {
			return Err(());
		}
		if wire_msg.len() < CONST_OVERHEAD + OUR_REPEATED_DATA_LEN {
			return Err(());
		}
		msg_offs = REPEATED_DATA_OFFS + 2 + OUR_REPEATED_DATA_LEN;

		let mut repeated_data_key = [0; 32];
		for i in 0..32 {
			repeated_data_key[i] = trusted_set.state_key[i] ^ wire_msg[REPEATED_DATA_OFFS + 2 + i];
		}
		let mut repeated_data_nonce = [0; 12];
		for i in 0..8 {
			repeated_data_nonce[4 + i] = b"NONCE KY"[i] ^ wire_msg[REPEATED_DATA_OFFS + 2 + 32 + i];
		}

		let mut state_store =
			ChaCha20Poly1305RFC::new(&repeated_data_key, &repeated_data_nonce, &[]);
		let ciphertext = &wire_msg
			[REPEATED_DATA_OFFS + 2 + 32 + 8..REPEATED_DATA_OFFS + 2 + OUR_REPEATED_DATA_LEN - 16];
		let mac = &wire_msg[REPEATED_DATA_OFFS + 2 + OUR_REPEATED_DATA_LEN - 16
			..REPEATED_DATA_OFFS + 2 + OUR_REPEATED_DATA_LEN];
		// The message sender (presumably) knows if they modified the repeated data, so there's no
		// need to be constant-time wrt failures here (and thus we also return early).
		state_store.variable_time_decrypt(ciphertext, &mut secure_random_nonce, mac)?;
	}

	let mut local_nonce = [0; 32];
	local_nonce.copy_from_slice(&secure_random_nonce[..32]);

	let mut remote_nonce = [0; 32];

	// Decrypt and validate the remote nonce
	{
		let mut peer_idx_bytes = [0; 2];
		peer_idx_bytes.copy_from_slice(&wire_msg[..2]);
		let peer_idx = u16::from_be_bytes(peer_idx_bytes);
		let idx_permutation =
			get_idx_permutation(trusted_set.get_cover_trusted_count(), &secure_random_nonce[32..]);

		// The message sender has already learned if they're in our trusted peer list and if we're
		// in theirs. Same goes for any third-party observers who would detect the same by the fact
		// that some response was made. Thus, there's no need to worry about timing differences
		// giving that away here - if the idx is bogus we can simply return and we can do a
		// variable time decryption (and early return if it fails).
		let ecdh_idx = idx_permutation.get(peer_idx as usize).ok_or(())?;
		let ecdh = trusted_set.trusted_ecdhs.get(*ecdh_idx as usize).ok_or(())?;

		let mut remote_nonce_key = Sha256::engine();
		remote_nonce_key.input(ecdh);
		remote_nonce_key.input(&local_nonce);

		let mut cryptoor =
			ChaCha20Poly1305RFC::new(&Sha256::from_engine(remote_nonce_key)[..], &chacha_salt, aad);
		let ciphertext = &wire_msg[2..2 + 32];
		let tag = &wire_msg[2 + 32..2 + 32 + 16];
		cryptoor.variable_time_decrypt(ciphertext, &mut remote_nonce, tag)?;
	}

	for b in chacha_salt.iter_mut().skip(4) {
		*b ^= 0x0f;
	}

	let mut msg_key = local_nonce;
	for (out, remote) in msg_key.iter_mut().zip(remote_nonce.iter()) {
		*out ^= *remote;
	}

	let separated_msg_keys = ChaCha20::get_single_block(&msg_key, b"INLINE KEY STRCH");
	let mut oob_msg_key = [0; 32];
	oob_msg_key.copy_from_slice(&separated_msg_keys[32..]);

	let mut msg_len_bytes = [0; 2];
	msg_len_bytes.copy_from_slice(&wire_msg[msg_offs..msg_offs + 2]);
	let msg_len = u16::from_be_bytes(msg_len_bytes);

	let mut res = Vec::new();
	if msg_len != 0 {
		if msg_len < 16 {
			return Err(());
		}
		if wire_msg.len() < msg_offs + msg_len as usize {
			return Err(());
		}
		res = vec![0; msg_len as usize - 16];
		let ciphertext = &wire_msg[msg_offs + 2..msg_offs + 2 + msg_len as usize - 16];
		let mac = &wire_msg[msg_offs + 2 + msg_len as usize - 16..msg_offs + 2 + msg_len as usize];

		let mut msg_cryptoor =
			ChaCha20Poly1305RFC::new(&separated_msg_keys[..32], &chacha_salt, aad);
		if msg_cryptoor.variable_time_decrypt(ciphertext, &mut res, mac).is_err() {
			return Err(());
		}
	}

	Ok((res, oob_msg_key))
}

/// Processes the initial message sent by the initiator and generates an encrypted response,
/// containing the given `msg`. Also returns a negotiated shared key which can be used to encrypt
/// further messages to the initiator.
///
/// Requires a random 64 bytes, a [`TrustedSet`] of peers, the `peer_init` message sent to us by
/// the initiator (via [`get_init_bytes`]), and a `salt` and `aad` which match those used by the
/// initiator.
///
/// The `salt` should uniquely describe this protocol the protocol being built using this mutual
/// authentication handshake. The `aad` should describe the particular message type being sent
/// (which the recipient expects).
pub fn respond_with_message(
	secure_random_nonce: [u8; 64], trusted_set: &TrustedSet, peer_init: &[u8], salt: &[u8; 8],
	aad: &[u8], msg: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), ()> {
	// Init message format is
	// 2 byte handshake count
	// PER_PEER_LEN * handshake count:
	//   32-byte encrypted initiator nonce
	//   16-byte poly1305 tag
	// 2 byte repeated data len
	// repeated data len bytes of data to be repeated
	// any further bytes uninterpreted (for extensibility)

	if peer_init.len() < 4 {
		return Err(());
	}

	let mut handshake_count_bytes = [0; 2];
	handshake_count_bytes.copy_from_slice(&peer_init[..2]);
	let handshake_count = u16::from_be_bytes(handshake_count_bytes);
	if peer_init.len() < 4 + handshake_count as usize * PER_PEER_LEN {
		return Err(());
	}

	let mut repeated_data_len_bytes = [0; 2];
	repeated_data_len_bytes.copy_from_slice(
		&peer_init[2 + handshake_count as usize * PER_PEER_LEN
			..2 + handshake_count as usize * PER_PEER_LEN + 2],
	);
	let repeated_data_len = u16::from_be_bytes(repeated_data_len_bytes);
	if peer_init.len() < 4 + handshake_count as usize * PER_PEER_LEN + repeated_data_len as usize {
		return Err(());
	}

	let mut chacha_salt = [0; 12];
	chacha_salt[4..].copy_from_slice(salt);

	let mut local_nonce = [0; 32];
	local_nonce.copy_from_slice(&secure_random_nonce[..32]);
	let mut rng = ChaCha20::new(&secure_random_nonce[32..], b"MPA Key Salt");

	let mut default_peer_bytes = [0; 8];
	rng.process_in_place(&mut default_peer_bytes);
	let mut peer_match_idx = (u64::from_le_bytes(default_peer_bytes) as usize)
		% core::cmp::max(trusted_set.trusted_ecdhs.len(), 1);
	let mut remote_nonce = [0; 32];
	rng.process_in_place(&mut remote_nonce);
	let mut peer_ecdh = &remote_nonce;

	let enc_bytes = &peer_init[2..2 + handshake_count as usize * PER_PEER_LEN];
	'match_search: for (idx, peer_enc) in enc_bytes.chunks(PER_PEER_LEN).enumerate() {
		for ecdh in trusted_set.trusted_ecdhs.iter() {
			let mut cryptoor = ChaCha20Poly1305RFC::new(ecdh, &chacha_salt, aad);

			let mut peer_nonce = [0; 32];
			// Because the sender (should have) randomized the order of their trusted-peers list,
			// the time taken to find a matching ECDH entry shouldn't give away who they were to a
			// third-party observer. Thus, variable-time decryption (and an early return) should be
			// fine.
			let decrypt_res =
				cryptoor.variable_time_decrypt(&peer_enc[..32], &mut peer_nonce, &peer_enc[32..]);
			if decrypt_res.is_ok() {
				peer_ecdh = ecdh;
				remote_nonce = peer_nonce;
				peer_match_idx = idx;
				break 'match_search;
			}
		}
	}

	for b in chacha_salt.iter_mut().skip(4) {
		*b ^= 0xff;
	}

	// Message format is:
	// 2 byte selected challenge index
	// 32 + 16 byte encrypted + MAC'd nonce
	// 2 byte repeated data len
	// repeated data len bytes of repeated data
	// 2 byte message length (not counting mac)
	// message length of encrypted message data
	// 16 byte poly1305 message MAC

	let mut res =
		Vec::with_capacity(2 + 32 + 16 + 2 + repeated_data_len as usize + 2 + msg.len() + 16);
	res.resize(2 + 32 + 16 + 2 + repeated_data_len as usize + 2 + msg.len() + 16, 0);
	res[0..2].copy_from_slice(&(peer_match_idx as u16).to_be_bytes());
	let mut res_write_pos = 2;

	let mut noise = [0; 32];
	rng.process_in_place(&mut noise);

	let mut local_nonce_key = Sha256::engine();
	local_nonce_key.input(peer_ecdh);
	local_nonce_key.input(&remote_nonce);
	{
		let mut cryptoor =
			ChaCha20Poly1305RFC::new(&Sha256::from_engine(local_nonce_key)[..], &chacha_salt, aad);
		let (crypted, tag) = res.split_at_mut(res_write_pos + 32);
		cryptoor.encrypt(&local_nonce, &mut crypted[res_write_pos..], &mut tag[..16]);
		res_write_pos += 32 + 16;
	}

	res[res_write_pos..res_write_pos + 2].copy_from_slice(&repeated_data_len_bytes);
	res_write_pos += 2;
	res[res_write_pos..res_write_pos + repeated_data_len as usize].copy_from_slice(
		&peer_init[2 + handshake_count as usize * PER_PEER_LEN + 2
			..2 + handshake_count as usize * PER_PEER_LEN + 2 + repeated_data_len as usize],
	);
	res_write_pos += repeated_data_len as usize;

	for b in chacha_salt.iter_mut().skip(4) {
		*b ^= 0x0f;
	}

	let mut msg_key = local_nonce;
	for (out, remote) in msg_key.iter_mut().zip(remote_nonce.iter()) {
		*out ^= *remote;
	}

	let separated_msg_keys = ChaCha20::get_single_block(&msg_key, b"INLINE KEY STRCH");
	let mut oob_msg_key = [0; 32];
	oob_msg_key.copy_from_slice(&separated_msg_keys[32..]);

	let proto_msg_len = if msg.is_empty() { 0 } else { msg.len() as u16 + 16 };
	res[res_write_pos..res_write_pos + 2].copy_from_slice(&proto_msg_len.to_be_bytes());
	res_write_pos += 2;

	let mut msg_cryptoor = ChaCha20Poly1305RFC::new(&separated_msg_keys[0..32], &chacha_salt, aad);
	let (crypted, tag) = res.split_at_mut(res_write_pos + msg.len());
	debug_assert_eq!(tag.len(), 16);
	msg_cryptoor.encrypt(msg, &mut crypted[res_write_pos..], tag);
	res_write_pos += msg.len() + 16;
	debug_assert_eq!(res_write_pos, res.len());

	Ok((res, oob_msg_key))
}

#[cfg(test)]
mod tests {
	use super::*;

	use secp256k1::{PublicKey, Secp256k1, SecretKey};

	use std::hash::{BuildHasher, Hasher};

	fn rand_bytes() -> [u8; 32] {
		let random_number = std::collections::hash_map::RandomState::new().build_hasher().finish();
		[random_number as u8; 32]
	}
	fn rand_64_bytes() -> [u8; 64] {
		let mut res = [0; 64];
		res[..32].copy_from_slice(&rand_bytes());
		res[32..].copy_from_slice(&rand_bytes());
		res
	}

	#[test]
	fn simple_test() {
		let secp_ctx = Secp256k1::new();

		let initiator_key = SecretKey::from_slice(&rand_bytes()).unwrap();
		let initiator_pk = PublicKey::from_secret_key(&secp_ctx, &initiator_key);
		let receiver_key = SecretKey::from_slice(&rand_bytes()).unwrap();
		let receiver_pk = PublicKey::from_secret_key(&secp_ctx, &receiver_key);

		let initiator_state = TrustedSet::new(&initiator_key, &[receiver_pk]).unwrap();
		const SALT: &[u8; 8] = b"SALTSALT";
		let init_msg = get_init_bytes(rand_64_bytes(), &initiator_state, *SALT, b"42");

		let receiver_state = TrustedSet::new(&receiver_key, &[initiator_pk]).unwrap();
		let msg = b"Hello Initiator!";
		let (receiver_wire, receiver_shared_key) =
			respond_with_message(rand_64_bytes(), &receiver_state, &init_msg, SALT, b"42", msg)
				.unwrap();

		let (initiator_msg, initiator_shared_key) =
			decode_msg(&initiator_state, *b"SALTSALT", b"42", &receiver_wire).unwrap();
		assert_eq!(&initiator_msg[..], msg);
		assert_eq!(receiver_shared_key, initiator_shared_key);
	}
}
