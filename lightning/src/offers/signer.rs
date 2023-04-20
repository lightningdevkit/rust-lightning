// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for signing offer messages and verifying metadata.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey, self};
use core::convert::TryFrom;
use core::fmt;
use crate::ln::inbound_payment::{ExpandedKey, IV_LEN, Nonce};
use crate::offers::merkle::TlvRecord;
use crate::util::ser::Writeable;

use crate::prelude::*;

const DERIVED_METADATA_HMAC_INPUT: &[u8; 16] = &[1; 16];
const DERIVED_METADATA_AND_KEYS_HMAC_INPUT: &[u8; 16] = &[2; 16];

/// Message metadata which possibly is derived from [`MetadataMaterial`] such that it can be
/// verified.
#[derive(Clone)]
pub(super) enum Metadata {
	/// Metadata as parsed, supplied by the user, or derived from the message contents.
	Bytes(Vec<u8>),

	/// Metadata to be derived from message contents and given material.
	Derived(MetadataMaterial),

	/// Metadata and signing pubkey to be derived from message contents and given material.
	DerivedSigningPubkey(MetadataMaterial),
}

impl Metadata {
	pub fn as_bytes(&self) -> Option<&Vec<u8>> {
		match self {
			Metadata::Bytes(bytes) => Some(bytes),
			Metadata::Derived(_) => None,
			Metadata::DerivedSigningPubkey(_) => None,
		}
	}

	pub fn has_derivation_material(&self) -> bool {
		match self {
			Metadata::Bytes(_) => false,
			Metadata::Derived(_) => true,
			Metadata::DerivedSigningPubkey(_) => true,
		}
	}

	pub fn derives_keys(&self) -> bool {
		match self {
			// Infer whether Metadata::derived_from was called on Metadata::DerivedSigningPubkey to
			// produce Metadata::Bytes. This is merely to determine which fields should be included
			// when verifying a message. It doesn't necessarily indicate that keys were in fact
			// derived, as wouldn't be the case if a Metadata::Bytes with length Nonce::LENGTH had
			// been set explicitly.
			Metadata::Bytes(bytes) => bytes.len() == Nonce::LENGTH,
			Metadata::Derived(_) => false,
			Metadata::DerivedSigningPubkey(_) => true,
		}
	}

	pub fn without_keys(self) -> Self {
		match self {
			Metadata::Bytes(_) => self,
			Metadata::Derived(_) => self,
			Metadata::DerivedSigningPubkey(material) => Metadata::Derived(material),
		}
	}

	pub fn derive_from<W: Writeable, T: secp256k1::Signing>(
		self, tlv_stream: W, secp_ctx: Option<&Secp256k1<T>>
	) -> (Self, Option<KeyPair>) {
		match self {
			Metadata::Bytes(_) => (self, None),
			Metadata::Derived(mut metadata_material) => {
				tlv_stream.write(&mut metadata_material.hmac).unwrap();
				(Metadata::Bytes(metadata_material.derive_metadata()), None)
			},
			Metadata::DerivedSigningPubkey(mut metadata_material) => {
				tlv_stream.write(&mut metadata_material.hmac).unwrap();
				let secp_ctx = secp_ctx.unwrap();
				let (metadata, keys) = metadata_material.derive_metadata_and_keys(secp_ctx);
				(Metadata::Bytes(metadata), Some(keys))
			},
		}
	}
}

impl Default for Metadata {
	fn default() -> Self {
		Metadata::Bytes(vec![])
	}
}

impl fmt::Debug for Metadata {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Metadata::Bytes(bytes) => bytes.fmt(f),
			Metadata::Derived(_) => f.write_str("Derived"),
			Metadata::DerivedSigningPubkey(_) => f.write_str("DerivedSigningPubkey"),
		}
	}
}

#[cfg(test)]
impl PartialEq for Metadata {
	fn eq(&self, other: &Self) -> bool {
		match self {
			Metadata::Bytes(bytes) => if let Metadata::Bytes(other_bytes) = other {
				bytes == other_bytes
			} else {
				false
			},
			Metadata::Derived(_) => false,
			Metadata::DerivedSigningPubkey(_) => false,
		}
	}
}

/// Material used to create metadata for a message.
#[derive(Clone)]
pub(super) struct MetadataMaterial {
	nonce: Nonce,
	hmac: HmacEngine<Sha256>,
}

impl MetadataMaterial {
	pub fn new(nonce: Nonce, expanded_key: &ExpandedKey, iv_bytes: &[u8; IV_LEN]) -> Self {
		Self {
			nonce,
			hmac: expanded_key.hmac_for_offer(nonce, iv_bytes),
		}
	}

	fn derive_metadata(mut self) -> Vec<u8> {
		self.hmac.input(DERIVED_METADATA_HMAC_INPUT);

		let mut bytes = self.nonce.as_slice().to_vec();
		bytes.extend_from_slice(&Hmac::from_engine(self.hmac).into_inner());
		bytes
	}

	fn derive_metadata_and_keys<T: secp256k1::Signing>(
		mut self, secp_ctx: &Secp256k1<T>
	) -> (Vec<u8>, KeyPair) {
		self.hmac.input(DERIVED_METADATA_AND_KEYS_HMAC_INPUT);

		let hmac = Hmac::from_engine(self.hmac);
		let privkey = SecretKey::from_slice(hmac.as_inner()).unwrap();
		let keys = KeyPair::from_secret_key(secp_ctx, &privkey);
		(self.nonce.as_slice().to_vec(), keys)
	}
}

pub(super) fn derive_keys(nonce: Nonce, expanded_key: &ExpandedKey) -> KeyPair {
	const IV_BYTES: &[u8; IV_LEN] = b"LDK Invoice ~~~~";
	let secp_ctx = Secp256k1::new();
	let hmac = Hmac::from_engine(expanded_key.hmac_for_offer(nonce, IV_BYTES));
	let privkey = SecretKey::from_slice(hmac.as_inner()).unwrap();
	KeyPair::from_secret_key(&secp_ctx, &privkey)
}

/// Verifies data given in a TLV stream was used to produce the given metadata, consisting of:
/// - a 128-bit [`Nonce`] and possibly
/// - a [`Sha256`] hash of the nonce and the TLV records using the [`ExpandedKey`].
///
/// If the latter is not included in the metadata, the TLV stream is used to check if the given
/// `signing_pubkey` can be derived from it.
pub(super) fn verify_metadata<'a, T: secp256k1::Signing>(
	metadata: &[u8], expanded_key: &ExpandedKey, iv_bytes: &[u8; IV_LEN],
	signing_pubkey: PublicKey, tlv_stream: impl core::iter::Iterator<Item = TlvRecord<'a>>,
	secp_ctx: &Secp256k1<T>
) -> Result<Option<KeyPair>, ()> {
	let hmac = hmac_for_message(metadata, expanded_key, iv_bytes, tlv_stream)?;

	if metadata.len() == Nonce::LENGTH {
		let derived_keys = KeyPair::from_secret_key(
			secp_ctx, &SecretKey::from_slice(hmac.as_inner()).unwrap()
		);
		if fixed_time_eq(&signing_pubkey.serialize(), &derived_keys.public_key().serialize()) {
			Ok(Some(derived_keys))
		} else {
			Err(())
		}
	} else if metadata[Nonce::LENGTH..].len() == Sha256::LEN {
		if fixed_time_eq(&metadata[Nonce::LENGTH..], &hmac.into_inner()) {
			Ok(None)
		} else {
			Err(())
		}
	} else {
		Err(())
	}
}

fn hmac_for_message<'a>(
	metadata: &[u8], expanded_key: &ExpandedKey, iv_bytes: &[u8; IV_LEN],
	tlv_stream: impl core::iter::Iterator<Item = TlvRecord<'a>>
) -> Result<Hmac<Sha256>, ()> {
	if metadata.len() < Nonce::LENGTH {
		return Err(());
	}

	let nonce = match Nonce::try_from(&metadata[..Nonce::LENGTH]) {
		Ok(nonce) => nonce,
		Err(_) => return Err(()),
	};
	let mut hmac = expanded_key.hmac_for_offer(nonce, iv_bytes);

	for record in tlv_stream {
		hmac.input(record.record_bytes);
	}

	if metadata.len() == Nonce::LENGTH {
		hmac.input(DERIVED_METADATA_AND_KEYS_HMAC_INPUT);
	} else {
		hmac.input(DERIVED_METADATA_HMAC_INPUT);
	}

	Ok(Hmac::from_engine(hmac))
}
