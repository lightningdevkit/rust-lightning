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
/// # Key Methods
/// - `create_from_data`: Returns an encrypted PeerStorage instance created from the provided data.
/// - `get_ser_channels`: Retrieves the serialized channel data.
/// - `decrypt_our_peer_storage`: Decrypts the ciphertext using the key and updates the result buffer.
///
/// # Usage
/// This structure can be used for securely managing and exchanging peer storage backups. It
/// includes methods for encryption and decryption using `ChaCha20Poly1305RFC`, making it
/// suitable for on-the-wire transmission.
///
/// ## Example
/// ```ignore
/// let key = [0u8; 32];
/// let mut our_peer_storage = OurPeerStorage::create_from_data(key.clone(), vec![1,2,3]);
/// let mut decrypted = vec![0u8; encrypted.len()];
/// OurPeerStorage::decrypt_our_peer_storage(&mut decrypted, &our_peer_storage, key).unwrap();
/// ```
#[derive(PartialEq)]
pub struct OurPeerStorage {
	version: u8,
	ser_channels: Vec<u8>,
}

impl OurPeerStorage {
	/// Get `ser_channels` field from [`OurPeerStorage`]
	pub fn get_ser_channels(&self) -> Vec<u8> {
		self.ser_channels.clone()
	}

	/// Create serialised [`OurPeerStorage`] from the given ser_channels data.
	pub fn create_from_data(key: [u8; 32], ser_channels: Vec<u8>) -> Vec<u8> {
		let our_peer_storage = Self { version: 1, ser_channels };

		let n = 0u64;
		let mut peer_storage = VecWriter(Vec::new());
		our_peer_storage.write(&mut peer_storage).unwrap();
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
	pub fn decrypt_our_peer_storage(
		res: &mut [u8], cyphertext: &[u8], key: [u8; 32],
	) -> Result<(), ()> {
		const MIN_CYPHERTEXT_LEN: usize = 16;

		// Ensure the cyphertext is at least as large as the MIN_CYPHERTEXT_LEN.
		if cyphertext.len() < MIN_CYPHERTEXT_LEN {
			return Err(());
		}

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
		self.ser_channels.write(writer)?;
		Ok(())
	}
}

impl Readable for OurPeerStorage {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let ver = read_ver_prefix!(reader, 1u8);
		let ser_channels = <Vec<u8> as Readable>::read(reader)?;

		let ps = OurPeerStorage { version: ver, ser_channels };
		Ok(ps)
	}
}
