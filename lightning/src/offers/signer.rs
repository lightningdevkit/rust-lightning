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
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, self};
use core::fmt;
use crate::ln::channelmanager::PaymentId;
use crate::ln::inbound_payment::{ExpandedKey, IV_LEN, Nonce};
use crate::offers::merkle::TlvRecord;
use crate::util::ser::Writeable;

use crate::prelude::*;

// Use a different HMAC input for each derivation. Otherwise, an attacker could:
// - take an Offer that has metadata consisting of a nonce and HMAC
// - strip off the HMAC and replace the signing_pubkey where the privkey is the HMAC,
// - generate and sign an invoice using the new signing_pubkey, and
// - claim they paid it since they would know the preimage of the invoice's payment_hash
const DERIVED_METADATA_HMAC_INPUT: &[u8; 16] = &[1; 16];
const DERIVED_METADATA_AND_KEYS_HMAC_INPUT: &[u8; 16] = &[2; 16];

// Additional HMAC inputs to distinguish use cases, either Offer or Refund/InvoiceRequest, where
// metadata for the latter contain an encrypted PaymentId.
const WITHOUT_ENCRYPTED_PAYMENT_ID_HMAC_INPUT: &[u8; 16] = &[3; 16];
const WITH_ENCRYPTED_PAYMENT_ID_HMAC_INPUT: &[u8; 16] = &[4; 16];

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

	pub fn derives_payer_keys(&self) -> bool {
		match self {
			// Infer whether Metadata::derived_from was called on Metadata::DerivedSigningPubkey to
			// produce Metadata::Bytes. This is merely to determine which fields should be included
			// when verifying a message. It doesn't necessarily indicate that keys were in fact
			// derived, as wouldn't be the case if a Metadata::Bytes with length PaymentId::LENGTH +
			// Nonce::LENGTH had been set explicitly.
			Metadata::Bytes(bytes) => bytes.len() == PaymentId::LENGTH + Nonce::LENGTH,
			Metadata::Derived(_) => false,
			Metadata::DerivedSigningPubkey(_) => true,
		}
	}

	pub fn derives_recipient_keys(&self) -> bool {
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
	) -> (Self, Option<Keypair>) {
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
	// Some for payer metadata and None for offer metadata
	encrypted_payment_id: Option<[u8; PaymentId::LENGTH]>,
}

impl MetadataMaterial {
	pub fn new(
		nonce: Nonce, expanded_key: &ExpandedKey, iv_bytes: &[u8; IV_LEN],
		payment_id: Option<PaymentId>
	) -> Self {
		// Encrypt payment_id
		let encrypted_payment_id = payment_id.map(|payment_id| {
			expanded_key.crypt_for_offer(payment_id.0, nonce)
		});

		Self {
			nonce,
			hmac: expanded_key.hmac_for_offer(nonce, iv_bytes),
			encrypted_payment_id,
		}
	}

	fn derive_metadata(mut self) -> Vec<u8> {
		self.hmac.input(DERIVED_METADATA_HMAC_INPUT);
		self.maybe_include_encrypted_payment_id();

		let mut bytes = self.encrypted_payment_id.map(|id| id.to_vec()).unwrap_or(vec![]);
		bytes.extend_from_slice(self.nonce.as_slice());
		bytes.extend_from_slice(Hmac::from_engine(self.hmac).as_byte_array());
		bytes
	}

	fn derive_metadata_and_keys<T: secp256k1::Signing>(
		mut self, secp_ctx: &Secp256k1<T>
	) -> (Vec<u8>, Keypair) {
		self.hmac.input(DERIVED_METADATA_AND_KEYS_HMAC_INPUT);
		self.maybe_include_encrypted_payment_id();

		let mut bytes = self.encrypted_payment_id.map(|id| id.to_vec()).unwrap_or(vec![]);
		bytes.extend_from_slice(self.nonce.as_slice());

		let hmac = Hmac::from_engine(self.hmac);
		let privkey = SecretKey::from_slice(hmac.as_byte_array()).unwrap();
		let keys = Keypair::from_secret_key(secp_ctx, &privkey);

		(bytes, keys)
	}

	fn maybe_include_encrypted_payment_id(&mut self) {
		match self.encrypted_payment_id {
			None => self.hmac.input(WITHOUT_ENCRYPTED_PAYMENT_ID_HMAC_INPUT),
			Some(encrypted_payment_id) => {
				self.hmac.input(WITH_ENCRYPTED_PAYMENT_ID_HMAC_INPUT);
				self.hmac.input(&encrypted_payment_id)
			},
		}
	}
}

pub(super) fn derive_keys(nonce: Nonce, expanded_key: &ExpandedKey) -> Keypair {
	const IV_BYTES: &[u8; IV_LEN] = b"LDK Invoice ~~~~";
	let secp_ctx = Secp256k1::new();
	let hmac = Hmac::from_engine(expanded_key.hmac_for_offer(nonce, IV_BYTES));
	let privkey = SecretKey::from_slice(hmac.as_byte_array()).unwrap();
	Keypair::from_secret_key(&secp_ctx, &privkey)
}

/// Verifies data given in a TLV stream was used to produce the given metadata, consisting of:
/// - a 256-bit [`PaymentId`],
/// - a 128-bit [`Nonce`], and possibly
/// - a [`Sha256`] hash of the nonce and the TLV records using the [`ExpandedKey`].
///
/// If the latter is not included in the metadata, the TLV stream is used to check if the given
/// `signing_pubkey` can be derived from it.
///
/// Returns the [`PaymentId`] that should be used for sending the payment.
pub(super) fn verify_payer_metadata<'a, T: secp256k1::Signing>(
	metadata: &[u8], expanded_key: &ExpandedKey, iv_bytes: &[u8; IV_LEN],
	signing_pubkey: PublicKey, tlv_stream: impl core::iter::Iterator<Item = TlvRecord<'a>>,
	secp_ctx: &Secp256k1<T>
) -> Result<PaymentId, ()> {
	if metadata.len() < PaymentId::LENGTH {
		return Err(());
	}

	let mut encrypted_payment_id = [0u8; PaymentId::LENGTH];
	encrypted_payment_id.copy_from_slice(&metadata[..PaymentId::LENGTH]);

	let mut hmac = hmac_for_message(
		&metadata[PaymentId::LENGTH..], expanded_key, iv_bytes, tlv_stream
	)?;
	hmac.input(WITH_ENCRYPTED_PAYMENT_ID_HMAC_INPUT);
	hmac.input(&encrypted_payment_id);

	verify_metadata(
		&metadata[PaymentId::LENGTH..], Hmac::from_engine(hmac), signing_pubkey, secp_ctx
	)?;

	let nonce = Nonce::try_from(&metadata[PaymentId::LENGTH..][..Nonce::LENGTH]).unwrap();
	let payment_id = expanded_key.crypt_for_offer(encrypted_payment_id, nonce);

	Ok(PaymentId(payment_id))
}

/// Verifies data given in a TLV stream was used to produce the given metadata, consisting of:
/// - a 128-bit [`Nonce`] and possibly
/// - a [`Sha256`] hash of the nonce and the TLV records using the [`ExpandedKey`].
///
/// If the latter is not included in the metadata, the TLV stream is used to check if the given
/// `signing_pubkey` can be derived from it.
///
/// Returns the [`Keypair`] for signing the invoice, if it can be derived from the metadata.
pub(super) fn verify_recipient_metadata<'a, T: secp256k1::Signing>(
	metadata: &[u8], expanded_key: &ExpandedKey, iv_bytes: &[u8; IV_LEN],
	signing_pubkey: PublicKey, tlv_stream: impl core::iter::Iterator<Item = TlvRecord<'a>>,
	secp_ctx: &Secp256k1<T>
) -> Result<Option<Keypair>, ()> {
	let mut hmac = hmac_for_message(metadata, expanded_key, iv_bytes, tlv_stream)?;
	hmac.input(WITHOUT_ENCRYPTED_PAYMENT_ID_HMAC_INPUT);

	verify_metadata(metadata, Hmac::from_engine(hmac), signing_pubkey, secp_ctx)
}

fn verify_metadata<T: secp256k1::Signing>(
	metadata: &[u8], hmac: Hmac<Sha256>, signing_pubkey: PublicKey, secp_ctx: &Secp256k1<T>
) -> Result<Option<Keypair>, ()> {
	if metadata.len() == Nonce::LENGTH {
		let derived_keys = Keypair::from_secret_key(
			secp_ctx, &SecretKey::from_slice(hmac.as_byte_array()).unwrap()
		);
		if fixed_time_eq(&signing_pubkey.serialize(), &derived_keys.public_key().serialize()) {
			Ok(Some(derived_keys))
		} else {
			Err(())
		}
	} else if metadata[Nonce::LENGTH..].len() == Sha256::LEN {
		if fixed_time_eq(&metadata[Nonce::LENGTH..], &hmac.to_byte_array()) {
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
) -> Result<HmacEngine<Sha256>, ()> {
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

	Ok(hmac)
}
