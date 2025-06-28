// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! `DecryptedOurPeerStorage` enables storage of encrypted serialized channel data.
//! It provides encryption of data to maintain data integrity and
//! security during transmission.

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::PublicKey;

use crate::ln::types::ChannelId;
use crate::sign::PeerStorageKey;

use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;
use crate::prelude::*;

/// [`DecryptedOurPeerStorage`] is used to store serialised channel information that allows for the creation of a
/// `peer_storage` backup.
///
/// This structure is designed to serialize channel data for backup and supports encryption
/// using `ChaCha20Poly1305RFC` for transmission.
///
/// # Key Methods
/// - [`DecryptedOurPeerStorage::new`]: Returns [`DecryptedOurPeerStorage`] with the given data.
/// - [`DecryptedOurPeerStorage::encrypt`]: Returns [`EncryptedOurPeerStorage`] created from encrypting the provided data.
/// - [`DecryptedOurPeerStorage::into_vec`]: Returns the data in [`Vec<u8>`] format.
///
/// ## Example
/// ```
/// use lightning::ln::our_peer_storage::DecryptedOurPeerStorage;
/// use lightning::sign::{KeysManager, NodeSigner};
/// let seed = [1u8; 32];
/// let keys_mgr = KeysManager::new(&seed, 42, 42);
/// let key = keys_mgr.get_peer_storage_key();
/// let decrypted_ops = DecryptedOurPeerStorage::new(vec![1, 2, 3]);
/// let our_peer_storage = decrypted_ops.encrypt(&key, &[0u8; 32]);
/// let decrypted_data = our_peer_storage.decrypt(&key).unwrap();
/// assert_eq!(decrypted_data.into_vec(), vec![1, 2, 3]);
/// ```
pub struct DecryptedOurPeerStorage {
	data: Vec<u8>,
}

impl DecryptedOurPeerStorage {
	/// Returns [`DecryptedOurPeerStorage`] with the given data.
	pub fn new(data: Vec<u8>) -> Self {
		Self { data }
	}

	/// Returns data stored in [`Vec<u8>`] format.
	pub fn into_vec(self) -> Vec<u8> {
		self.data
	}

	/// Encrypts the data inside [`DecryptedOurPeerStorage`] using [`PeerStorageKey`] and `random_bytes`
	/// and returns [`EncryptedOurPeerStorage`].
	pub fn encrypt(self, key: &PeerStorageKey, random_bytes: &[u8; 32]) -> EncryptedOurPeerStorage {
		let mut data = self.data;
		let plaintext_len = data.len();
		let nonce = derive_nonce(key, random_bytes);

		let mut chacha = ChaCha20Poly1305RFC::new(&key.inner, &nonce, b"");
		let mut tag = [0; 16];
		chacha.encrypt_full_message_in_place(&mut data[0..plaintext_len], &mut tag);

		data.extend_from_slice(&tag);

		// Append `random_bytes` in front of the encrypted_blob.
		data.extend_from_slice(random_bytes);

		EncryptedOurPeerStorage { cipher: data }
	}
}

/// [`EncryptedOurPeerStorage`] represents encrypted state of the corresponding [`DecryptedOurPeerStorage`].
///
/// # Key Methods
/// - [`EncryptedOurPeerStorage::new`]: Returns [`EncryptedOurPeerStorage`] with the given encrypted cipher.
/// - [`EncryptedOurPeerStorage::decrypt`]: Returns [`DecryptedOurPeerStorage`] created from decrypting the cipher.
/// - [`EncryptedOurPeerStorage::into_vec`]: Returns the cipher in [`Vec<u8>`] format.
pub struct EncryptedOurPeerStorage {
	cipher: Vec<u8>,
}

impl EncryptedOurPeerStorage {
	// Ciphertext is of the form: random_bytes(32 bytes) + encrypted_data + tag(16 bytes).
	const MIN_CIPHERTEXT_LEN: usize = 32 + 16;

	/// Returns [`EncryptedOurPeerStorage`] if cipher is of appropriate length, else returns error.
	pub fn new(cipher: Vec<u8>) -> Result<Self, ()> {
		if cipher.len() < Self::MIN_CIPHERTEXT_LEN {
			return Err(());
		}
		return Ok(Self { cipher });
	}

	/// Returns cipher in the format [`Vec<u8>`].
	pub fn into_vec(self) -> Vec<u8> {
		self.cipher
	}

	/// Returns [`DecryptedOurPeerStorage`] if it successfully decrypts the ciphertext with the `key`,
	/// else returns error.
	pub fn decrypt(self, key: &PeerStorageKey) -> Result<DecryptedOurPeerStorage, ()> {
		let mut cipher = self.cipher;
		let cyphertext_len = cipher.len();

		if cipher.len() < Self::MIN_CIPHERTEXT_LEN {
			return Err(());
		}

		// Ciphertext is of the form: encrypted_data + tag(16 bytes) + random_bytes(32 bytes).
		let (data_mut, random_bytes) = cipher.split_at_mut(cyphertext_len - 32);
		let (encrypted_data, tag) = data_mut.split_at_mut(data_mut.len() - 16);

		let nonce = derive_nonce(key, random_bytes);

		let mut chacha = ChaCha20Poly1305RFC::new(&key.inner, &nonce, b"");

		if chacha.check_decrypt_in_place(encrypted_data, tag).is_err() {
			return Err(());
		}

		// Remove tag(16 bytes) + random_bytes(32 bytes).
		cipher.truncate(cyphertext_len - 16 - 32);

		Ok(DecryptedOurPeerStorage { data: cipher })
	}
}

/// Nonce for encryption and decryption: Hmac(Sha256(key) + random_bytes).
fn derive_nonce(key: &PeerStorageKey, random_bytes: &[u8]) -> [u8; 12] {
	let key_hash = Sha256::hash(&key.inner);

	let mut hmac = HmacEngine::<Sha256>::new(key_hash.as_byte_array());
	hmac.input(&random_bytes);
	let mut nonce = [0u8; 12];
	// First 4 bytes of the nonce should be 0.
	nonce[4..].copy_from_slice(&Hmac::from_engine(hmac).to_byte_array()[0..8]);

	nonce
}

/// [`PeerStorageMonitorHolder`] represents a single channel sent over the wire.
/// This would be used inside [`ChannelManager`] to determine
/// if the user has lost channel states so that we can do something about it.
///
/// The main idea here is to just enable node to figure out that it has lost some data
/// using peer storage backups.
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
///
/// TODO(aditya): Write FundRecoverer to use `monitor_bytes` to drop onchain.
pub(crate) struct PeerStorageMonitorHolder {
	/// Channel Id of the channel.
	pub(crate) channel_id: ChannelId,
	/// Node Id of the channel partner.
	pub(crate) counterparty_node_id: PublicKey,
	/// Minimum seen secret to determine if we have lost state.
	pub(crate) min_seen_secret: u64,
	/// Whole serialised ChannelMonitor to recover funds.
	pub(crate) monitor_bytes: Vec<u8>,
}

impl_writeable_tlv_based!(PeerStorageMonitorHolder, {
	(0, channel_id, required),
	(2, counterparty_node_id, required),
	(4, min_seen_secret, required),
	(6, monitor_bytes, required_vec),
});

#[cfg(test)]
mod tests {
	use crate::ln::our_peer_storage::{derive_nonce, DecryptedOurPeerStorage};
	use crate::sign::PeerStorageKey;

	#[test]
	fn test_peer_storage_encryption_decryption() {
		let key1 = PeerStorageKey { inner: [0u8; 32] };
		let key2 = PeerStorageKey { inner: [1u8; 32] };
		let random_bytes1 = [200; 32];
		let random_bytes2 = [201; 32];

		// Happy Path
		let decrypted_ops = DecryptedOurPeerStorage::new(vec![42u8; 32]);
		let decrypted_ops_res: DecryptedOurPeerStorage =
			decrypted_ops.encrypt(&key1, &random_bytes1).decrypt(&key1).unwrap();
		assert_eq!(decrypted_ops_res.into_vec(), vec![42u8; 32]);

		// Changing Key
		let decrypted_ops_wrong_key = DecryptedOurPeerStorage::new(vec![42u8; 32]);
		let decrypted_ops_wrong_key_res =
			decrypted_ops_wrong_key.encrypt(&key2, &random_bytes2).decrypt(&key1);
		assert!(decrypted_ops_wrong_key_res.is_err());

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
