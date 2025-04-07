// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! `OurPeerStorage` enables versioned storage of serialized channel data.
//! It supports encryption and decryption to maintain data integrity and security during
//! transmission.
//!
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

use crate::sign::PeerStorageKey;

use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;
use crate::prelude::*;

/// [`OurPeerStorage`] is used to store channel information that allows for the creation of a
/// `peer_storage` backup.
///
/// This structure is designed to serialize channel data for backup and supports encryption
/// and decryption using `ChaCha20Poly1305RFC` to ensure data integrity and security during exchange or storage.
///
/// # Key Methods
/// - [`OurPeerStorage::create_from_data`]: Returns an encrypted [`OurPeerStorage`] instance created from the provided data.
/// - [`OurPeerStorage::decrypt_our_peer_storage`]: Decrypts the [`OurPeerStorage::encrypted_data`] using the key and returns decrypted data.
///
/// ## Example
/// ```
/// use lightning::ln::our_peer_storage::OurPeerStorage;
/// use lightning::sign::PeerStorageKey;
/// let key = PeerStorageKey{inner: [0u8; 32]};
/// let our_peer_storage = OurPeerStorage::create_from_data(key.clone(), vec![1, 2, 3], [0u8; 32]);
/// let decrypted_data = our_peer_storage.decrypt_our_peer_storage(key).unwrap();
/// assert_eq!(decrypted_data, vec![1, 2, 3]);
/// ```
#[derive(PartialEq)]
pub struct OurPeerStorage {
	encrypted_data: Vec<u8>,
}

impl OurPeerStorage {
	/// Creates a new [`OurPeerStorage`] with given encrypted_data.
	pub fn new(encrypted_data: Vec<u8>) -> Self {
		Self { encrypted_data }
	}

	/// Get encrypted data stored inside [`OurPeerStorage`].
	pub fn into_vec(self) -> Vec<u8> {
		self.encrypted_data
	}

	/// Creates a serialised representation of [`OurPeerStorage`] from the given `ser_channels` data.
	///
	/// This function takes a `key` (for encryption), `ser_channels` data
	/// (serialised channel information) and random_bytes (to derive nonce for encryption) and returns a serialised
	/// [`OurPeerStorage`] as a `Vec<u8>`.
	///
	/// The resulting serialised data is intended to be directly used for transmission to the peers.
	pub fn create_from_data(
		key: PeerStorageKey, mut ser_channels: Vec<u8>, random_bytes: [u8; 32],
	) -> OurPeerStorage {
		let key_hash = Sha256::const_hash(&key.inner);

		let plaintext_len = ser_channels.len();

		// Compute Sha256(Sha256(key) + random_bytes).
		let mut sha = Sha256::engine();
		sha.input(&key_hash.to_byte_array());
		sha.input(&random_bytes);

		let mut nonce = [0u8; 12];
		nonce[4..].copy_from_slice(&Sha256::from_engine(sha).to_byte_array()[0..8]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key.inner, &nonce, b"");
		let mut tag = [0; 16];
		chacha.encrypt_full_message_in_place(&mut ser_channels[0..plaintext_len], &mut tag);

		ser_channels.extend_from_slice(&tag);

		// Append `random_bytes` in front of the encrypted_blob.
		ser_channels.splice(0..0, random_bytes);
		Self { encrypted_data: ser_channels }
	}

	/// Decrypt `OurPeerStorage` using the `key`, result is stored inside the `res`.
	/// Returns an error if the the `cyphertext` is not correct.
	pub fn decrypt_our_peer_storage(mut self, key: PeerStorageKey) -> Result<Vec<u8>, ()> {
		let key_hash = Sha256::const_hash(&key.inner);

		// Length of tag + Length of random_bytes
		const MIN_CYPHERTEXT_LEN: usize = 16 + 32;
		let cyphertext_len = self.encrypted_data.len();

		// Ensure the cyphertext is at least as large as the MIN_CYPHERTEXT_LEN.
		if cyphertext_len < MIN_CYPHERTEXT_LEN {
			return Err(());
		}

		// Ciphertext is of the form: random_bytes(32 bytes) + encrypted_data + tag(16 bytes).
		let (data_mut, tag) = self.encrypted_data.split_at_mut(cyphertext_len - 16);
		let (random_bytes, encrypted_data) = data_mut.split_at_mut(32);

		let mut sha = Sha256::engine();
		sha.input(&key_hash.to_byte_array());
		sha.input(random_bytes);

		let mut nonce = [0u8; 12];
		nonce[4..].copy_from_slice(&Sha256::from_engine(sha).to_byte_array()[0..8]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key.inner, &nonce, b"");

		if chacha.check_decrypt_in_place(encrypted_data, tag).is_err() {
			return Err(());
		}

		self.encrypted_data.truncate(cyphertext_len - 16);
		self.encrypted_data.drain(0..32);

		Ok(self.encrypted_data)
	}
}
