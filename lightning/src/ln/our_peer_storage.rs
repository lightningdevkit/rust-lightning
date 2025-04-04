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
use crate::sign::PeerStorageKey;

use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;
use crate::prelude::*;

/// [`OurPeerStorage`] is used to store channel information that allows for the creation of a
/// `peer_storage` backup. It includes versioning and timestamping for comparison between
/// instances of [`OurPeerStorage`].
///
/// This structure is designed to serialize channel data for backup and supports encryption
/// and decryption to ensure data integrity and security during exchange or storage.
///
/// # Key Methods
/// - `create_from_data`: Returns an encrypted [`OurPeerStorage`] instance created from the provided data.
/// - `decrypt_our_peer_storage`: Decrypts the [`OurPeerStorage::encrypted_data`] using the key and returns decrypted data.
///
/// # Usage
/// This structure can be used for securely managing and exchanging peer storage backups. It
/// includes methods for encryption and decryption using `ChaCha20Poly1305RFC`, making it
/// suitable for on-the-wire transmission.
///
/// ## Example
/// ```
/// use lightning::ln::our_peer_storage::OurPeerStorage;
/// use lightning::sign::PeerStorageKey;
/// let key = PeerStorageKey{inner: [0u8; 32]};
/// let our_peer_storage = OurPeerStorage::create_from_data(key.clone(), vec![1, 2, 3]);
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
	pub fn encrypted_data(&self) -> Vec<u8> {
		self.encrypted_data.clone()
	}

	/// Creates a serialised representation of [`OurPeerStorage`] from the given `ser_channels` data.
	///
	/// This function takes a `key` (for encryption) and `ser_channels` data
	/// (serialised channel information), and returns a serialised [`OurPeerStorage`] as a `Vec<u8>`.
	///
	/// The resulting serialised data is intended to be directly used for transmission to the peers.
	pub fn create_from_data(key: PeerStorageKey, mut ser_channels: Vec<u8>) -> OurPeerStorage {
		let n = 0u64;

		let plaintext_len = ser_channels.len();

		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key.inner, &nonce, b"");
		let mut tag = [0; 16];
		chacha.encrypt_full_message_in_place(&mut ser_channels[0..plaintext_len], &mut tag);

		ser_channels.extend_from_slice(&tag);

		Self { encrypted_data: ser_channels }
	}

	/// Decrypt `OurPeerStorage` using the `key`, result is stored inside the `res`.
	/// Returns an error if the the `cyphertext` is not correct.
	pub fn decrypt_our_peer_storage(mut self, key: PeerStorageKey) -> Result<Vec<u8>, ()> {
		const MIN_CYPHERTEXT_LEN: usize = 16;
		let cyphertext_len = self.encrypted_data.len();

		// Ensure the cyphertext is at least as large as the MIN_CYPHERTEXT_LEN.
		if cyphertext_len < MIN_CYPHERTEXT_LEN {
			return Err(());
		}

		// Split the cyphertext into the encrypted data and the authentication tag.
		let (encrypted_data, tag) = self.encrypted_data.split_at_mut(cyphertext_len - 16);

		let n = 0u64;
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key.inner, &nonce, b"");

		if chacha.check_decrypt_in_place(encrypted_data, tag).is_err() {
			return Err(());
		}

		self.encrypted_data.truncate(cyphertext_len - 16);

		Ok(self.encrypted_data)
	}
}
