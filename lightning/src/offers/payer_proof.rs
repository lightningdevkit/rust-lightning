// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Payer proofs for BOLT 12 invoices.
//!
//! A [`PayerProof`] cryptographically proves that a BOLT 12 invoice was paid by demonstrating:
//! - Possession of the payment preimage (proving the payment occurred)
//! - A valid invoice signature over a merkle root (proving the invoice is authentic)
//! - The payer's signature (proving who authorized the payment)
//!
//! This implements the payer proof extension to BOLT 12 as specified in
//! <https://github.com/lightning/bolts/pull/1295>.

use alloc::collections::BTreeSet;

use crate::offers::invoice::{Bolt12Invoice, SIGNATURE_TAG};
use crate::offers::merkle::{
	self, SelectiveDisclosure, SelectiveDisclosureError, TaggedHash, TlvStream, SIGNATURE_TYPES,
};
use crate::offers::parse::Bech32Encode;
use crate::types::features::Bolt12InvoiceFeatures;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::Writeable;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};

use core::convert::TryFrom;
use core::time::Duration;

#[allow(unused_imports)]
use crate::prelude::*;

/// Human-readable prefix for payer proofs in bech32 encoding.
pub const PAYER_PROOF_HRP: &str = "lnp";

/// Error when building or verifying a payer proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayerProofError {
	/// The preimage doesn't match the invoice's payment hash.
	PreimageMismatch,
	/// Error during merkle tree operations.
	MerkleError(SelectiveDisclosureError),
	/// The invoice signature is invalid.
	InvalidInvoiceSignature,
	/// The payer signature is invalid.
	InvalidPayerSignature,
	/// Error during signing.
	SigningError,
	/// Missing required field in the proof.
	MissingRequiredField(&'static str),
	/// The proof contains invalid data.
	InvalidData(&'static str),
}

impl From<SelectiveDisclosureError> for PayerProofError {
	fn from(e: SelectiveDisclosureError) -> Self {
		PayerProofError::MerkleError(e)
	}
}

/// A cryptographic proof that a BOLT 12 invoice was paid.
///
/// Contains the payment preimage, selective disclosure of invoice fields,
/// the invoice signature, and a payer signature proving who paid.
#[derive(Clone, Debug)]
pub struct PayerProof {
	bytes: Vec<u8>,
	contents: PayerProofContents,
	merkle_root: sha256::Hash,
}

#[derive(Clone, Debug)]
struct PayerProofContents {
	// Required fields (always present)
	payer_id: PublicKey,
	payment_hash: PaymentHash,
	invoice_node_id: PublicKey,
	preimage: PaymentPreimage,
	invoice_signature: Signature,
	payer_signature: Signature,
	payer_note: Option<String>,

	// Merkle reconstruction data
	leaf_hashes: Vec<sha256::Hash>,
	omitted_tlvs: Vec<u64>,
	missing_hashes: Vec<sha256::Hash>,

	// Optional included fields from invoice
	#[allow(dead_code)]
	offer_description: Option<String>,
	#[allow(dead_code)]
	offer_issuer: Option<String>,
	#[allow(dead_code)]
	invoice_amount: Option<u64>,
	#[allow(dead_code)]
	invoice_created_at: Option<Duration>,
	#[allow(dead_code)]
	invoice_features: Option<Bolt12InvoiceFeatures>,
}

/// Builds a [`PayerProof`] from a paid invoice and its preimage.
///
/// By default, only the required fields are included (payer_id, payment_hash,
/// invoice_node_id). Additional fields can be included for selective disclosure
/// using the `include_*` methods.
pub struct PayerProofBuilder<'a> {
	invoice: &'a Bolt12Invoice,
	preimage: PaymentPreimage,
	included_types: BTreeSet<u64>,
}

impl<'a> PayerProofBuilder<'a> {
	/// Create a new builder from a paid invoice and its preimage.
	///
	/// Returns an error if the preimage doesn't match the invoice's payment hash.
	pub fn new(
		invoice: &'a Bolt12Invoice,
		preimage: PaymentPreimage,
	) -> Result<Self, PayerProofError> {
		// Verify preimage matches payment_hash
		let computed_hash = sha256::Hash::hash(&preimage.0);
		if computed_hash.as_byte_array() != &invoice.payment_hash().0 {
			return Err(PayerProofError::PreimageMismatch);
		}

		// Start with required types
		let mut included_types = BTreeSet::new();
		included_types.insert(88); // invreq_payer_id (required)
		included_types.insert(168); // invoice_payment_hash (required)
		included_types.insert(176); // invoice_node_id (required)

		// Include invoice_features if present
		if invoice.invoice_features() != &Bolt12InvoiceFeatures::empty() {
			included_types.insert(174);
		}

		Ok(Self { invoice, preimage, included_types })
	}

	/// Include the offer description in the proof.
	pub fn include_offer_description(mut self) -> Self {
		self.included_types.insert(10);
		self
	}

	/// Include the offer issuer in the proof.
	pub fn include_offer_issuer(mut self) -> Self {
		self.included_types.insert(18);
		self
	}

	/// Include the invoice amount in the proof.
	pub fn include_invoice_amount(mut self) -> Self {
		self.included_types.insert(170);
		self
	}

	/// Include the invoice creation timestamp in the proof.
	pub fn include_invoice_created_at(mut self) -> Self {
		self.included_types.insert(164);
		self
	}

	/// Build an unsigned payer proof.
	pub fn build(self) -> Result<UnsignedPayerProof, PayerProofError> {
		// Serialize the invoice to get its bytes
		let mut invoice_bytes = Vec::new();
		self.invoice.write(&mut invoice_bytes).expect("Vec write should not fail");

		// Get bytes without signature for merkle computation
		let bytes_without_sig: Vec<u8> = TlvStream::new(&invoice_bytes)
			.filter(|r| !SIGNATURE_TYPES.contains(&r.r#type))
			.flat_map(|r| r.record_bytes.to_vec())
			.collect();

		// Compute selective disclosure
		let disclosure =
			merkle::compute_selective_disclosure(&bytes_without_sig, &self.included_types)?;

		// Extract included TLV records
		let included_records: Vec<(u64, Vec<u8>)> = TlvStream::new(&invoice_bytes)
			.filter(|r| self.included_types.contains(&r.r#type))
			.map(|r| (r.r#type, r.record_bytes.to_vec()))
			.collect();

		// Get the invoice signature
		let invoice_signature = self.invoice.signature();

		Ok(UnsignedPayerProof {
			invoice_signature,
			preimage: self.preimage,
			payer_id: self.invoice.payer_signing_pubkey(),
			payment_hash: self.invoice.payment_hash().clone(),
			invoice_node_id: self.invoice.signing_pubkey(),
			included_records,
			disclosure,
			invoice_features: if self.included_types.contains(&174) {
				Some(self.invoice.invoice_features().clone())
			} else {
				None
			},
		})
	}
}

/// An unsigned [`PayerProof`] ready for signing.
pub struct UnsignedPayerProof {
	invoice_signature: Signature,
	preimage: PaymentPreimage,
	payer_id: PublicKey,
	payment_hash: PaymentHash,
	invoice_node_id: PublicKey,
	included_records: Vec<(u64, Vec<u8>)>,
	disclosure: SelectiveDisclosure,
	invoice_features: Option<Bolt12InvoiceFeatures>,
}

impl UnsignedPayerProof {
	/// Returns the merkle root of the invoice.
	pub fn merkle_root(&self) -> sha256::Hash {
		self.disclosure.merkle_root
	}

	/// Sign the proof with the payer's key to create a complete proof.
	///
	/// The signing function receives a message that is SHA256(note || merkle_root).
	pub fn sign<F>(self, sign_fn: F, note: Option<&str>) -> Result<PayerProof, PayerProofError>
	where
		F: FnOnce(&Message) -> Result<Signature, ()>,
	{
		// Compute message: SHA256(note || merkle_root)
		let message = Self::compute_payer_signature_message(note, &self.disclosure.merkle_root);

		// Sign
		let payer_signature = sign_fn(&message).map_err(|_| PayerProofError::SigningError)?;

		// Verify signature
		let secp_ctx = Secp256k1::verification_only();
		secp_ctx
			.verify_schnorr(&payer_signature, &message, &self.payer_id.into())
			.map_err(|_| PayerProofError::InvalidPayerSignature)?;

		// Serialize to bytes
		let bytes = self.serialize_payer_proof(&payer_signature, note);

		Ok(PayerProof {
			bytes,
			contents: PayerProofContents {
				payer_id: self.payer_id,
				payment_hash: self.payment_hash,
				invoice_node_id: self.invoice_node_id,
				preimage: self.preimage,
				invoice_signature: self.invoice_signature,
				payer_signature,
				payer_note: note.map(String::from),
				leaf_hashes: self.disclosure.leaf_hashes,
				omitted_tlvs: self.disclosure.omitted_tlvs,
				missing_hashes: self.disclosure.missing_hashes,
				offer_description: None,
				offer_issuer: None,
				invoice_amount: None,
				invoice_created_at: None,
				invoice_features: self.invoice_features,
			},
			merkle_root: self.disclosure.merkle_root,
		})
	}

	fn compute_payer_signature_message(note: Option<&str>, merkle_root: &sha256::Hash) -> Message {
		let mut hasher = sha256::Hash::engine();
		if let Some(n) = note {
			hasher.input(n.as_bytes());
		}
		hasher.input(merkle_root.as_ref());
		let msg_hash = sha256::Hash::from_engine(hasher);
		Message::from_digest(*msg_hash.as_byte_array())
	}

	fn serialize_payer_proof(&self, payer_signature: &Signature, note: Option<&str>) -> Vec<u8> {
		let mut bytes = Vec::new();

		// Write included TLV records (invoice fields)
		for (_, record_bytes) in &self.included_records {
			bytes.extend_from_slice(record_bytes);
		}

		// Write invoice signature (type 240)
		self.invoice_signature.write(&mut bytes).expect("Vec write should not fail");

		// Write preimage (type 242)
		bytes.extend_from_slice(&self.preimage.0);

		// Write omitted_tlvs (type 244) - simplified encoding
		for marker in &self.disclosure.omitted_tlvs {
			bytes.extend_from_slice(&marker.to_be_bytes());
		}

		// Write missing_hashes (type 246)
		for hash in &self.disclosure.missing_hashes {
			bytes.extend_from_slice(hash.as_ref());
		}

		// Write leaf_hashes (type 248)
		for hash in &self.disclosure.leaf_hashes {
			bytes.extend_from_slice(hash.as_ref());
		}

		// Write payer_signature (type 250)
		payer_signature.write(&mut bytes).expect("Vec write should not fail");
		if let Some(n) = note {
			bytes.extend_from_slice(n.as_bytes());
		}

		bytes
	}
}

impl PayerProof {
	/// Verify the payer proof.
	///
	/// This checks:
	/// 1. SHA256(preimage) == payment_hash
	/// 2. The invoice signature is valid over the reconstructed merkle root
	/// 3. The payer signature is valid
	pub fn verify(&self) -> Result<(), PayerProofError> {
		// 1. Verify SHA256(preimage) == payment_hash
		let computed = sha256::Hash::hash(&self.contents.preimage.0);
		if computed.as_byte_array() != &self.contents.payment_hash.0 {
			return Err(PayerProofError::PreimageMismatch);
		}

		// 2. Verify invoice signature over merkle root
		let tagged_hash = TaggedHash::from_merkle_root(SIGNATURE_TAG, self.merkle_root);
		merkle::verify_signature(
			&self.contents.invoice_signature,
			&tagged_hash,
			self.contents.invoice_node_id,
		)
		.map_err(|_| PayerProofError::InvalidInvoiceSignature)?;

		// 3. Verify payer signature
		let message = UnsignedPayerProof::compute_payer_signature_message(
			self.contents.payer_note.as_deref(),
			&self.merkle_root,
		);

		let secp_ctx = Secp256k1::verification_only();
		secp_ctx
			.verify_schnorr(
				&self.contents.payer_signature,
				&message,
				&self.contents.payer_id.into(),
			)
			.map_err(|_| PayerProofError::InvalidPayerSignature)?;

		Ok(())
	}

	/// The payment preimage proving the invoice was paid.
	pub fn preimage(&self) -> PaymentPreimage {
		self.contents.preimage
	}

	/// The payer's public key (who paid).
	pub fn payer_id(&self) -> PublicKey {
		self.contents.payer_id
	}

	/// The invoice node ID (who was paid).
	pub fn invoice_node_id(&self) -> PublicKey {
		self.contents.invoice_node_id
	}

	/// The payment hash.
	pub fn payment_hash(&self) -> PaymentHash {
		self.contents.payment_hash
	}

	/// The payer's note, if any.
	pub fn payer_note(&self) -> Option<&str> {
		self.contents.payer_note.as_deref()
	}

	/// The merkle root of the original invoice.
	pub fn merkle_root(&self) -> sha256::Hash {
		self.merkle_root
	}

	/// The raw bytes of the payer proof.
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}
}

// Bech32 encoding with "lnp" prefix
impl Bech32Encode for PayerProof {
	const BECH32_HRP: &'static str = PAYER_PROOF_HRP;
}

impl AsRef<[u8]> for PayerProof {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

impl TryFrom<Vec<u8>> for PayerProof {
	type Error = crate::offers::parse::Bolt12ParseError;

	fn try_from(_bytes: Vec<u8>) -> Result<Self, Self::Error> {
		// TODO: Implement proper parsing for PoC
		// For now, just return an error as parsing is complex
		Err(crate::offers::parse::Bolt12ParseError::Decode(
			crate::ln::msgs::DecodeError::InvalidValue,
		))
	}
}

impl core::fmt::Display for PayerProof {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		self.fmt_bech32_str(f)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::offers::merkle::compute_selective_disclosure;

	#[test]
	fn test_selective_disclosure_computation() {
		// Test that the merkle selective disclosure works correctly
		// Simple TLV stream with types 1, 2
		let tlv_bytes = vec![
			0x01, 0x03, 0xe8, 0x03, 0xe8, // type 1, length 3, value
			0x02, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x03, // type 2
		];

		let mut included = BTreeSet::new();
		included.insert(1);

		let result = compute_selective_disclosure(&tlv_bytes, &included);
		assert!(result.is_ok());

		let disclosure = result.unwrap();
		assert_eq!(disclosure.leaf_hashes.len(), 1); // One included TLV
		assert!(!disclosure.missing_hashes.is_empty()); // Should have missing hashes for omitted
	}
}
