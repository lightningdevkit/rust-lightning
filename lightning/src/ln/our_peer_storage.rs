// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! `OurPeerStorage` enables versioned and timestamped storage of serialized channel data.
//! It supports encryption and decryption to maintain data integrity and security during
//! transmission.

use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;

use crate::util::ser::{Readable, VecWriter, Writeable, Writer};

use crate::io::{self, Error};
use crate::prelude::*;

use crate::ln::msgs::DecodeError;

/// [`OurPeerStorage`] is used to store channel information that allows for the creation of a
/// `peer_storage` backup. It includes versioning and timestamping for comparison between
/// instances of [`OurPeerStorage`].
///
/// This structure is designed to serialize channel data for backup and supports encryption
/// and decryption to ensure data integrity and security during exchange or storage.
///
/// # Fields
/// - `version`: Defines the structure's version for backward compatibility.
/// - `timestamp`: UNIX timestamp indicating the creation or modification time of the instance.
/// - `ser_channels`: Serialized channel data.
///
/// # Key Methods
/// - `new`: Creates a new [`OurPeerStorage`] instance with the current timestamp.
/// - `stub_channels`: Updates the serialized channel data.
/// - `get_ser_channels`: Retrieves the serialized channel data.
/// - `encrypt_our_peer_storage`: Encrypts the storage using a given key and returns the ciphertext.
/// - `decrypt_our_peer_storage`: Decrypts the ciphertext using the key and updates the result buffer.
///
/// # Usage
/// This structure can be used for securely managing and exchanging peer storage backups. It
/// includes methods for encryption and decryption using `ChaCha20Poly1305RFC`, making it
/// suitable for on-the-wire transmission.
///
/// ## Example
/// ```ignore
/// let mut our_peer_storage = OurPeerStorage::new();
/// our_peer_storage.stub_channels(vec![1, 2, 3]);
/// let key = [0u8; 32];
/// let encrypted = our_peer_storage.encrypt_our_peer_storage(key);
/// let mut decrypted = vec![0u8; encrypted.len()];
/// OurPeerStorage::decrypt_our_peer_storage(&mut decrypted, &encrypted).unwrap();
/// ```
#[derive(PartialEq)]
pub struct OurPeerStorage {
	version: u8,
	// If the block height is 0, OurPeerStorage doesn't have any channels backed up.
	block_height: u32,
	ser_channels: Vec<u8>,
}

impl OurPeerStorage {
	/// Returns a [`OurPeerStorage`] with version 1 and current timestamp.
	pub fn new() -> Self {
		Self { version: 1, block_height: 0u32, ser_channels: Vec::new() }
	}

	/// Stubs a channel inside [`OurPeerStorage`]
	pub fn stub_channels(&mut self, ser_chan: Vec<u8>) {
		self.ser_channels = ser_chan;
	}

	/// Get `ser_channels` field from [`OurPeerStorage`]
	pub fn get_ser_channels(&self) -> Vec<u8> {
		self.ser_channels.clone()
	}

	pub fn get_block_height(&self) -> u32 {
		self.block_height
	}

	/// Encrypt [`OurPeerStorage`] using the `key` and return a `Vec<u8>` containing the result.
	pub fn encrypt_our_peer_storage(&self, key: [u8; 32]) -> Vec<u8> {
		let n = 0u64;
		let mut peer_storage = VecWriter(Vec::new());
		self.write(&mut peer_storage).unwrap();
		let mut res = vec![0; peer_storage.0.len() + 16];

		let plaintext = &peer_storage.0[..];
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key, &nonce, b"");
		let mut tag = [0; 16];
		chacha.encrypt(plaintext, &mut res[0..plaintext.len()], &mut tag);
		res[plaintext.len()..].copy_from_slice(&tag);
		res
	}

	/// Decrypt `OurPeerStorage` using the `key`, result is stored inside the `res`.
	/// Returns an error if the the `cyphertext` is not correct.
	pub fn decrypt_our_peer_storage(res: &mut [u8], cyphertext_with_key: &[u8]) -> Result<(), ()> {
		const KEY_SIZE: usize = 32;

		// Ensure the combined data is at least as large as the key size
		if cyphertext_with_key.len() <= KEY_SIZE {
			return Err(());
		}

		let (cyphertext, key) = cyphertext_with_key.split_at(cyphertext_with_key.len() - KEY_SIZE);
		let n = 0u64;
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key, &nonce, b"");
		if chacha
			.variable_time_decrypt(
				&cyphertext[0..cyphertext.len() - 16],
				res,
				&cyphertext[cyphertext.len() - 16..],
			)
			.is_err()
		{
			return Err(());
		}
		Ok(())
	}
}

impl Writeable for OurPeerStorage {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		write_ver_prefix!(writer, self.version, 1);
		self.block_height.write(writer)?;
		self.ser_channels.write(writer)?;
		Ok(())
	}
}

impl Readable for OurPeerStorage {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let ver = read_ver_prefix!(reader, 1u8);
		let block_height: u32 = Readable::read(reader)?;
		let ser_channels = <Vec<u8> as Readable>::read(reader)?;

		let ps = OurPeerStorage { version: ver, block_height, ser_channels };
		Ok(ps)
	}
}
