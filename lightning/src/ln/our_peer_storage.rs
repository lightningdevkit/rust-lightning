// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! `OurPeerStorage` enables storage of encrypted serialized channel data.
//! It provides encryption and decryption of data to maintain data integrity and
//! security during transmission.
//!

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};

use crate::sign::PeerStorageKey;

use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;
use crate::prelude::*;

/// [`OurPeerStorage`] is used to store encrypted channel information that allows for the creation of a
/// `peer_storage` backup.
///
/// This structure is designed to serialize channel data for backup and supports encryption
/// and decryption using `ChaCha20Poly1305RFC` for transmission.
///
/// # Key Methods
/// - [`OurPeerStorage::new`]: Returns [`OurPeerStorage`] with the given encrypted_data.
/// - [`OurPeerStorage::create_from_data`]: Returns [`OurPeerStorage`] created from encrypting the provided data.
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
	/// Returns an error if the `encrypted_data` is less than the
	/// appropriate length.
	pub fn new(encrypted_data: Vec<u8>) -> Result<Self, ()> {
		// Length of tag + Length of random_bytes
		const MIN_CYPHERTEXT_LEN: usize = 16 + 32;

		if encrypted_data.len() < MIN_CYPHERTEXT_LEN {
			Err(())
		} else {
			Ok(Self { encrypted_data })
		}
	}

	/// Get encrypted data stored inside [`OurPeerStorage`].
	pub fn into_vec(self) -> Vec<u8> {
		self.encrypted_data
	}

	/// Returns [`OurPeerStorage`] with encrypted `ser_channels`.
	///
	/// This function takes a `key` (for encryption), `ser_channels` data
	/// (serialised channel information) and random_bytes (to derive nonce for encryption) and returns a
	/// [`OurPeerStorage`] with encrypted data inside.
	///
	/// The resulting serialised data is intended to be directly used for transmission to the peers.
	pub fn create_from_data(
		key: PeerStorageKey, mut ser_channels: Vec<u8>, random_bytes: [u8; 32],
	) -> OurPeerStorage {
		let plaintext_len = ser_channels.len();
		let nonce = derive_nonce(&key, &random_bytes);

		let mut chacha = ChaCha20Poly1305RFC::new(&key.inner, &nonce, b"");
		let mut tag = [0; 16];
		chacha.encrypt_full_message_in_place(&mut ser_channels[0..plaintext_len], &mut tag);

		ser_channels.extend_from_slice(&tag);

		// Prepend `random_bytes` in front of the encrypted_blob.
		ser_channels.splice(0..0, random_bytes);
		Self { encrypted_data: ser_channels }
	}

	/// Decrypt `OurPeerStorage` using the `key`, result is stored inside the `res`.
	/// Returns an error if the the `cyphertext` is not correct.
	pub fn decrypt_our_peer_storage(mut self, key: PeerStorageKey) -> Result<Vec<u8>, ()> {
		let cyphertext_len = self.encrypted_data.len();

		// Ciphertext is of the form: random_bytes(32 bytes) + encrypted_data + tag(16 bytes).
		let (data_mut, tag) = self.encrypted_data.split_at_mut(cyphertext_len - 16);
		let (random_bytes, encrypted_data) = data_mut.split_at_mut(32);

		let nonce = derive_nonce(&key, random_bytes);

		let mut chacha = ChaCha20Poly1305RFC::new(&key.inner, &nonce, b"");

		if chacha.check_decrypt_in_place(encrypted_data, tag).is_err() {
			return Err(());
		}

		self.encrypted_data.truncate(cyphertext_len - 16);
		self.encrypted_data.drain(0..32);

		Ok(self.encrypted_data)
	}
}

/// Nonce for encryption and decryption: Hmac(Sha256(key) + random_bytes).
fn derive_nonce(key: &PeerStorageKey, random_bytes: &[u8]) -> [u8; 12] {
	let key_hash = Sha256::const_hash(&key.inner);

	let mut hmac = HmacEngine::<Sha256>::new(key_hash.as_byte_array());
	hmac.input(&random_bytes);
	let mut nonce = [0u8; 12];
	// First 4 bytes of the nonce should be 0.
	nonce[4..].copy_from_slice(&Hmac::from_engine(hmac).to_byte_array()[0..8]);

	nonce
}

#[cfg(test)]
mod tests {
	use crate::ln::our_peer_storage::{derive_nonce, OurPeerStorage};
	use crate::sign::PeerStorageKey;

	#[test]
	fn test_peer_storage_encryption_decryption() {
		let key1 = PeerStorageKey { inner: [0u8; 32] };
		let key2 = PeerStorageKey { inner: [1u8; 32] };
		let random_bytes1 = [200; 32];
		let random_bytes2 = [201; 32];

		// Happy Path
		let our_peer_storage =
			OurPeerStorage::create_from_data(key1.clone(), vec![42u8; 32], random_bytes1);
		let decrypted_data = our_peer_storage.decrypt_our_peer_storage(key1.clone()).unwrap();
		assert_eq!(decrypted_data, vec![42u8; 32]);

		// Changing Key
		let our_peer_storage_wrong_key =
			OurPeerStorage::create_from_data(key1.clone(), vec![42u8; 32], random_bytes1);
		let decrypted_data_wrong_key = our_peer_storage_wrong_key.decrypt_our_peer_storage(key2);
		assert!(decrypted_data_wrong_key.is_err());

		// Nonce derivation happy path
		let nonce = derive_nonce(&key1, &random_bytes1);
		let nonce_happy_path = derive_nonce(&key1, &random_bytes1);
		assert_eq!(nonce, nonce_happy_path);

		// Nonce derivation with different `random_bytes` & `key`
		let nonce_diff_random_bytes = derive_nonce(&key1, &random_bytes2);
		let nonce_diff_key = derive_nonce(&key2, &random_bytes1);
		let nonce_diff_key_random_bytes = derive_nonce(&key2, &random_bytes2);
		assert_ne!(nonce, nonce_diff_random_bytes);
		assert_ne!(nonce, nonce_diff_key);
		assert_ne!(nonce, nonce_diff_key_random_bytes);
	}
}
