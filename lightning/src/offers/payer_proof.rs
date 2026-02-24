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

use crate::io;
use crate::io::Read;
use crate::ln::channelmanager::PaymentId;
use crate::ln::inbound_payment::ExpandedKey;
use crate::offers::invoice::{Bolt12Invoice, SIGNATURE_TAG};
use crate::offers::invoice_request::INVOICE_REQUEST_PAYER_ID_TYPE;
use crate::offers::merkle::{
	self, SelectiveDisclosure, SelectiveDisclosureError, TaggedHash, TlvStream, SIGNATURE_TYPES,
};
use crate::offers::nonce::Nonce;
use crate::offers::parse::Bech32Encode;
use crate::types::features::Bolt12InvoiceFeatures;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{BigSize, Readable, Writeable};

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};

use core::convert::TryFrom;

#[allow(unused_imports)]
use crate::prelude::*;

const TLV_SIGNATURE: u64 = 240;
const TLV_PREIMAGE: u64 = 242;
const TLV_OMITTED_MARKERS: u64 = 244;
const TLV_MISSING_HASHES: u64 = 246;
const TLV_LEAF_HASHES: u64 = 248;
const TLV_PAYER_SIGNATURE: u64 = 250;

const TLV_INVREQ_METADATA: u64 = 0;
// Note: Payer ID type (88) is imported as INVOICE_REQUEST_PAYER_ID_TYPE from invoice_request.rs
// TODO: Invoice TLV types (168, 174, 176) could potentially be exported from invoice.rs
const TLV_INVOICE_PAYMENT_HASH: u64 = 168;
const TLV_INVOICE_FEATURES: u64 = 174;
const TLV_ISSUER_SIGNING_PUBKEY: u64 = 176;

/// Human-readable prefix for payer proofs in bech32 encoding.
pub const PAYER_PROOF_HRP: &str = "lnp";

/// Tag for payer signature computation per BOLT 12 signature calculation.
/// Format: "lightning" || messagename || fieldname
const PAYER_SIGNATURE_TAG: &str = concat!("lightning", "payer_proof", "payer_signature");

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
	/// Failed to re-derive the payer signing key from the provided nonce and payment ID.
	KeyDerivationFailed,
	/// Error during signing.
	SigningError,
	/// Missing required field in the proof.
	MissingRequiredField(&'static str),
	/// The proof contains invalid data.
	InvalidData(&'static str),
	/// The invreq_metadata field cannot be included (per spec).
	InvreqMetadataNotAllowed,
	/// The omitted_markers contains an included TLV type.
	OmittedMarkersContainIncluded,
	/// The omitted_markers has too many trailing markers.
	TooManyTrailingOmittedMarkers,
	/// Error decoding the payer proof.
	DecodeError(crate::ln::msgs::DecodeError),
}

impl From<SelectiveDisclosureError> for PayerProofError {
	fn from(e: SelectiveDisclosureError) -> Self {
		PayerProofError::MerkleError(e)
	}
}

impl From<crate::ln::msgs::DecodeError> for PayerProofError {
	fn from(e: crate::ln::msgs::DecodeError) -> Self {
		PayerProofError::DecodeError(e)
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
	payer_id: PublicKey,
	payment_hash: PaymentHash,
	issuer_signing_pubkey: PublicKey,
	preimage: PaymentPreimage,
	invoice_signature: Signature,
	payer_signature: Signature,
	payer_note: Option<String>,
}

/// Builds a [`PayerProof`] from a paid invoice and its preimage.
///
/// By default, only the required fields are included (payer_id, payment_hash,
/// issuer_signing_pubkey). Additional fields can be included for selective disclosure
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
		invoice: &'a Bolt12Invoice, preimage: PaymentPreimage,
	) -> Result<Self, PayerProofError> {
		let computed_hash = sha256::Hash::hash(&preimage.0);
		if computed_hash.as_byte_array() != &invoice.payment_hash().0 {
			return Err(PayerProofError::PreimageMismatch);
		}

		let mut included_types = BTreeSet::new();
		included_types.insert(INVOICE_REQUEST_PAYER_ID_TYPE);
		included_types.insert(TLV_INVOICE_PAYMENT_HASH);
		included_types.insert(TLV_ISSUER_SIGNING_PUBKEY);

		if invoice.invoice_features() != &Bolt12InvoiceFeatures::empty() {
			included_types.insert(TLV_INVOICE_FEATURES);
		}

		Ok(Self { invoice, preimage, included_types })
	}

	/// Check if a TLV type is allowed to be included in the payer proof.
	///
	/// Per spec: MUST NOT include invreq_metadata (type 0).
	fn is_type_allowed(tlv_type: u64) -> bool {
		tlv_type != TLV_INVREQ_METADATA
	}

	/// Include a specific TLV type in the proof.
	///
	/// Returns an error if the type is not allowed (e.g., invreq_metadata).
	pub fn include_type(mut self, tlv_type: u64) -> Result<Self, PayerProofError> {
		if !Self::is_type_allowed(tlv_type) {
			return Err(PayerProofError::InvreqMetadataNotAllowed);
		}
		self.included_types.insert(tlv_type);
		Ok(self)
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

	/// Builds a signed [`PayerProof`] using the provided signing function.
	///
	/// Use this when you have direct access to the payer's signing key.
	pub fn build_and_sign<F>(
		self, sign_fn: F, note: Option<&str>,
	) -> Result<PayerProof, PayerProofError>
	where
		F: FnOnce(&Message) -> Result<Signature, ()>,
	{
		let unsigned = self.build_unsigned()?;
		unsigned.sign(sign_fn, note)
	}

	/// Builds a signed [`PayerProof`] using a key derived from an [`ExpandedKey`] and [`Nonce`].
	///
	/// This re-derives the payer signing key using the same derivation scheme as invoice requests
	/// created with `deriving_signing_pubkey`. The `nonce` and `payment_id` must be the same ones
	/// used when creating the original invoice request (available from the
	/// [`OffersContext::OutboundPaymentForOffer`]).
	///
	/// [`OffersContext::OutboundPaymentForOffer`]: crate::blinded_path::message::OffersContext::OutboundPaymentForOffer
	pub fn build_and_sign_with_derived_key(
		self, expanded_key: &ExpandedKey, nonce: Nonce, payment_id: PaymentId, note: Option<&str>,
	) -> Result<PayerProof, PayerProofError> {
		let secp_ctx = Secp256k1::new();
		let keys = self
			.invoice
			.derive_signing_keys(payment_id, nonce, expanded_key, &secp_ctx)
			.map_err(|_| PayerProofError::KeyDerivationFailed)?;

		let unsigned = self.build_unsigned()?;
		unsigned.sign(|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message, &keys)), note)
	}

	fn build_unsigned(self) -> Result<UnsignedPayerProof, PayerProofError> {
		let mut invoice_bytes = Vec::new();
		self.invoice.write(&mut invoice_bytes).expect("Vec write should not fail");
		let mut bytes_without_sig = Vec::new();
		for r in TlvStream::new(&invoice_bytes).filter(|r| !SIGNATURE_TYPES.contains(&r.r#type)) {
			bytes_without_sig.extend_from_slice(r.record_bytes);
		}

		let disclosure =
			merkle::compute_selective_disclosure(&bytes_without_sig, &self.included_types)?;

		let included_records: Vec<(u64, Vec<u8>)> = TlvStream::new(&invoice_bytes)
			.filter(|r| self.included_types.contains(&r.r#type))
			.map(|r| (r.r#type, r.record_bytes.to_vec()))
			.collect();

		let invoice_signature = self.invoice.signature();

		Ok(UnsignedPayerProof {
			invoice_signature,
			preimage: self.preimage,
			payer_id: self.invoice.payer_signing_pubkey(),
			payment_hash: self.invoice.payment_hash().clone(),
			issuer_signing_pubkey: self.invoice.signing_pubkey(),
			included_records,
			disclosure,
		})
	}
}

/// An unsigned [`PayerProof`] ready for signing.
struct UnsignedPayerProof {
	invoice_signature: Signature,
	preimage: PaymentPreimage,
	payer_id: PublicKey,
	payment_hash: PaymentHash,
	issuer_signing_pubkey: PublicKey,
	included_records: Vec<(u64, Vec<u8>)>,
	disclosure: SelectiveDisclosure,
}

impl UnsignedPayerProof {
	fn sign<F>(self, sign_fn: F, note: Option<&str>) -> Result<PayerProof, PayerProofError>
	where
		F: FnOnce(&Message) -> Result<Signature, ()>,
	{
		let message = Self::compute_payer_signature_message(note, &self.disclosure.merkle_root);
		let payer_signature = sign_fn(&message).map_err(|_| PayerProofError::SigningError)?;

		let secp_ctx = Secp256k1::verification_only();
		secp_ctx
			.verify_schnorr(&payer_signature, &message, &self.payer_id.into())
			.map_err(|_| PayerProofError::InvalidPayerSignature)?;

		let bytes = self.serialize_payer_proof(&payer_signature, note);

		Ok(PayerProof {
			bytes,
			contents: PayerProofContents {
				payer_id: self.payer_id,
				payment_hash: self.payment_hash,
				issuer_signing_pubkey: self.issuer_signing_pubkey,
				preimage: self.preimage,
				invoice_signature: self.invoice_signature,
				payer_signature,
				payer_note: note.map(String::from),
			},
			merkle_root: self.disclosure.merkle_root,
		})
	}

	/// Compute the payer signature message per BOLT 12 signature calculation.
	fn compute_payer_signature_message(note: Option<&str>, merkle_root: &sha256::Hash) -> Message {
		let mut inner_hasher = sha256::Hash::engine();
		if let Some(n) = note {
			inner_hasher.input(n.as_bytes());
		}
		inner_hasher.input(merkle_root.as_ref());
		let inner_msg = sha256::Hash::from_engine(inner_hasher);

		let tag_hash = sha256::Hash::hash(PAYER_SIGNATURE_TAG.as_bytes());

		let mut final_hasher = sha256::Hash::engine();
		final_hasher.input(tag_hash.as_ref());
		final_hasher.input(tag_hash.as_ref());
		final_hasher.input(inner_msg.as_ref());
		let final_digest = sha256::Hash::from_engine(final_hasher);

		Message::from_digest(*final_digest.as_byte_array())
	}

	fn serialize_payer_proof(&self, payer_signature: &Signature, note: Option<&str>) -> Vec<u8> {
		let mut bytes = Vec::new();

		for (_, record_bytes) in &self.included_records {
			bytes.extend_from_slice(record_bytes);
		}

		BigSize(TLV_SIGNATURE).write(&mut bytes).expect("Vec write should not fail");
		BigSize(64).write(&mut bytes).expect("Vec write should not fail");
		self.invoice_signature.write(&mut bytes).expect("Vec write should not fail");

		BigSize(TLV_PREIMAGE).write(&mut bytes).expect("Vec write should not fail");
		BigSize(32).write(&mut bytes).expect("Vec write should not fail");
		bytes.extend_from_slice(&self.preimage.0);

		if !self.disclosure.omitted_markers.is_empty() {
			let omitted_len: u64 = self
				.disclosure
				.omitted_markers
				.iter()
				.map(|m| BigSize(*m).serialized_length() as u64)
				.sum();
			BigSize(TLV_OMITTED_MARKERS).write(&mut bytes).expect("Vec write should not fail");
			BigSize(omitted_len).write(&mut bytes).expect("Vec write should not fail");
			for marker in &self.disclosure.omitted_markers {
				BigSize(*marker).write(&mut bytes).expect("Vec write should not fail");
			}
		}

		if !self.disclosure.missing_hashes.is_empty() {
			let len = self.disclosure.missing_hashes.len() * 32;
			BigSize(TLV_MISSING_HASHES).write(&mut bytes).expect("Vec write should not fail");
			BigSize(len as u64).write(&mut bytes).expect("Vec write should not fail");
			for hash in &self.disclosure.missing_hashes {
				bytes.extend_from_slice(hash.as_ref());
			}
		}

		if !self.disclosure.leaf_hashes.is_empty() {
			let len = self.disclosure.leaf_hashes.len() * 32;
			BigSize(TLV_LEAF_HASHES).write(&mut bytes).expect("Vec write should not fail");
			BigSize(len as u64).write(&mut bytes).expect("Vec write should not fail");
			for hash in &self.disclosure.leaf_hashes {
				bytes.extend_from_slice(hash.as_ref());
			}
		}

		let note_bytes = note.map(|n| n.as_bytes()).unwrap_or(&[]);
		let payer_sig_len = 64 + note_bytes.len();
		BigSize(TLV_PAYER_SIGNATURE).write(&mut bytes).expect("Vec write should not fail");
		BigSize(payer_sig_len as u64).write(&mut bytes).expect("Vec write should not fail");
		payer_signature.write(&mut bytes).expect("Vec write should not fail");
		bytes.extend_from_slice(note_bytes);

		bytes
	}
}

impl PayerProof {
	/// Verify the payer proof.
	pub fn verify(&self) -> Result<(), PayerProofError> {
		let computed = sha256::Hash::hash(&self.contents.preimage.0);
		if computed.as_byte_array() != &self.contents.payment_hash.0 {
			return Err(PayerProofError::PreimageMismatch);
		}

		let tagged_hash = TaggedHash::from_merkle_root(SIGNATURE_TAG, self.merkle_root);
		merkle::verify_signature(
			&self.contents.invoice_signature,
			&tagged_hash,
			self.contents.issuer_signing_pubkey,
		)
		.map_err(|_| PayerProofError::InvalidInvoiceSignature)?;

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

	/// The issuer's signing public key (the key that signed the invoice).
	pub fn issuer_signing_pubkey(&self) -> PublicKey {
		self.contents.issuer_signing_pubkey
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

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		use crate::ln::msgs::DecodeError;
		use crate::offers::parse::Bolt12ParseError;

		let mut payer_id: Option<PublicKey> = None;
		let mut payment_hash: Option<PaymentHash> = None;
		let mut issuer_signing_pubkey: Option<PublicKey> = None;
		let mut invoice_signature: Option<Signature> = None;
		let mut preimage: Option<PaymentPreimage> = None;
		let mut payer_signature: Option<Signature> = None;
		let mut payer_note: Option<String> = None;

		let mut leaf_hashes: Vec<sha256::Hash> = Vec::new();
		let mut omitted_markers: Vec<u64> = Vec::new();
		let mut missing_hashes: Vec<sha256::Hash> = Vec::new();

		let mut included_types: BTreeSet<u64> = BTreeSet::new();
		let mut included_records: Vec<(u64, usize, usize)> = Vec::new();

		let mut prev_tlv_type: u64 = 0;

		for record in TlvStream::new(&bytes) {
			let tlv_type = record.r#type;

			// Strict ascending order check covers both ordering and duplicates.
			if tlv_type <= prev_tlv_type && prev_tlv_type != 0 {
				return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
			}
			prev_tlv_type = tlv_type;

			match tlv_type {
				INVOICE_REQUEST_PAYER_ID_TYPE => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let _len: BigSize = Readable::read(&mut record_cursor)?;
					payer_id = Some(Readable::read(&mut record_cursor)?);
					included_types.insert(tlv_type);
					included_records.push((
						tlv_type,
						record.end - record.record_bytes.len(),
						record.end,
					));
				},
				TLV_INVOICE_PAYMENT_HASH => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let _len: BigSize = Readable::read(&mut record_cursor)?;
					payment_hash = Some(Readable::read(&mut record_cursor)?);
					included_types.insert(tlv_type);
					included_records.push((
						tlv_type,
						record.end - record.record_bytes.len(),
						record.end,
					));
				},
				TLV_ISSUER_SIGNING_PUBKEY => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let _len: BigSize = Readable::read(&mut record_cursor)?;
					issuer_signing_pubkey = Some(Readable::read(&mut record_cursor)?);
					included_types.insert(tlv_type);
					included_records.push((
						tlv_type,
						record.end - record.record_bytes.len(),
						record.end,
					));
				},
				TLV_SIGNATURE => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let _len: BigSize = Readable::read(&mut record_cursor)?;
					invoice_signature = Some(Readable::read(&mut record_cursor)?);
				},
				TLV_PREIMAGE => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let _len: BigSize = Readable::read(&mut record_cursor)?;
					let mut preimage_bytes = [0u8; 32];
					record_cursor
						.read_exact(&mut preimage_bytes)
						.map_err(|_| DecodeError::ShortRead)?;
					preimage = Some(PaymentPreimage(preimage_bytes));
				},
				TLV_OMITTED_MARKERS => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let len: BigSize = Readable::read(&mut record_cursor)?;
					let end_pos = record_cursor.position() + len.0;
					while record_cursor.position() < end_pos {
						let marker: BigSize = Readable::read(&mut record_cursor)?;
						omitted_markers.push(marker.0);
					}
				},
				TLV_MISSING_HASHES => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let len: BigSize = Readable::read(&mut record_cursor)?;
					if len.0 % 32 != 0 {
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					let num_hashes = len.0 / 32;
					for _ in 0..num_hashes {
						let mut hash_bytes = [0u8; 32];
						record_cursor
							.read_exact(&mut hash_bytes)
							.map_err(|_| DecodeError::ShortRead)?;
						missing_hashes.push(sha256::Hash::from_byte_array(hash_bytes));
					}
				},
				TLV_LEAF_HASHES => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let len: BigSize = Readable::read(&mut record_cursor)?;
					if len.0 % 32 != 0 {
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					let num_hashes = len.0 / 32;
					for _ in 0..num_hashes {
						let mut hash_bytes = [0u8; 32];
						record_cursor
							.read_exact(&mut hash_bytes)
							.map_err(|_| DecodeError::ShortRead)?;
						leaf_hashes.push(sha256::Hash::from_byte_array(hash_bytes));
					}
				},
				TLV_PAYER_SIGNATURE => {
					let mut record_cursor = io::Cursor::new(record.record_bytes);
					let _type: BigSize = Readable::read(&mut record_cursor)?;
					let len: BigSize = Readable::read(&mut record_cursor)?;
					payer_signature = Some(Readable::read(&mut record_cursor)?);
					let note_len = len.0.saturating_sub(64);
					if note_len > 0 {
						let mut note_bytes = vec![0u8; note_len as usize];
						record_cursor
							.read_exact(&mut note_bytes)
							.map_err(|_| DecodeError::ShortRead)?;
						payer_note = Some(
							String::from_utf8(note_bytes).map_err(|_| DecodeError::InvalidValue)?,
						);
					}
				},
				_ => {
					if tlv_type == TLV_INVREQ_METADATA {
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					if !SIGNATURE_TYPES.contains(&tlv_type) {
						included_types.insert(tlv_type);
						included_records.push((
							tlv_type,
							record.end - record.record_bytes.len(),
							record.end,
						));
					}
				},
			}
		}

		let payer_id = payer_id.ok_or(Bolt12ParseError::InvalidSemantics(
			crate::offers::parse::Bolt12SemanticError::MissingPayerSigningPubkey,
		))?;
		let payment_hash = payment_hash.ok_or(Bolt12ParseError::InvalidSemantics(
			crate::offers::parse::Bolt12SemanticError::MissingPaymentHash,
		))?;
		let issuer_signing_pubkey =
			issuer_signing_pubkey.ok_or(Bolt12ParseError::InvalidSemantics(
				crate::offers::parse::Bolt12SemanticError::MissingSigningPubkey,
			))?;
		let invoice_signature = invoice_signature.ok_or(Bolt12ParseError::InvalidSemantics(
			crate::offers::parse::Bolt12SemanticError::MissingSignature,
		))?;
		let preimage = preimage.ok_or(Bolt12ParseError::Decode(DecodeError::InvalidValue))?;
		let payer_signature = payer_signature.ok_or(Bolt12ParseError::InvalidSemantics(
			crate::offers::parse::Bolt12SemanticError::MissingSignature,
		))?;

		validate_omitted_markers_for_parsing(&omitted_markers, &included_types)
			.map_err(|_| Bolt12ParseError::Decode(DecodeError::InvalidValue))?;

		if leaf_hashes.len() != included_records.len() {
			return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
		}

		let included_refs: Vec<(u64, &[u8])> =
			included_records.iter().map(|&(t, start, end)| (t, &bytes[start..end])).collect();
		let merkle_root = merkle::reconstruct_merkle_root(
			&included_refs,
			&leaf_hashes,
			&omitted_markers,
			&missing_hashes,
		)
		.map_err(|_| Bolt12ParseError::Decode(DecodeError::InvalidValue))?;

		Ok(PayerProof {
			bytes,
			contents: PayerProofContents {
				payer_id,
				payment_hash,
				issuer_signing_pubkey,
				preimage,
				invoice_signature,
				payer_signature,
				payer_note,
			},
			merkle_root,
		})
	}
}

/// Validate omitted markers during parsing.
///
/// Per spec:
/// - MUST NOT contain 0
/// - MUST NOT contain signature TLV element numbers (240-1000)
/// - MUST be in strict ascending order
/// - MUST NOT contain the number of an included TLV field
/// - MUST NOT contain more than one number larger than the largest included non-signature TLV
/// - Markers MUST be minimized: each marker must be exactly prev_value + 1 within
///   a run, and the first marker after an included type X must be X + 1
fn validate_omitted_markers_for_parsing(
	omitted_markers: &[u64], included_types: &BTreeSet<u64>,
) -> Result<(), PayerProofError> {
	let mut inc_iter = included_types.iter().copied().peekable();
	// After implicit TLV0 (marker 0), the first minimized marker would be 1
	let mut expected_next: u64 = 1;
	let mut trailing_count = 0;
	let max_included = included_types.iter().copied().max().unwrap_or(0);
	let mut prev = 0u64;

	for &marker in omitted_markers {
		// MUST NOT contain 0
		if marker == 0 {
			return Err(PayerProofError::InvalidData("omitted_markers contains 0"));
		}

		// MUST NOT contain signature TLV types
		if SIGNATURE_TYPES.contains(&marker) {
			return Err(PayerProofError::InvalidData("omitted_markers contains signature type"));
		}

		// MUST be strictly ascending
		if marker <= prev {
			return Err(PayerProofError::InvalidData("omitted_markers not strictly ascending"));
		}

		// MUST NOT contain included TLV types
		if included_types.contains(&marker) {
			return Err(PayerProofError::OmittedMarkersContainIncluded);
		}

		// Validate minimization: marker must equal expected_next (continuation
		// of current run), or there must be an included type X between the
		// previous position and this marker such that X + 1 == marker.
		if marker != expected_next {
			let mut found = false;
			for inc_type in inc_iter.by_ref() {
				if inc_type + 1 == marker {
					found = true;
					break;
				}
				if inc_type >= marker {
					return Err(PayerProofError::InvalidData("omitted_markers not minimized"));
				}
			}
			if !found {
				return Err(PayerProofError::InvalidData("omitted_markers not minimized"));
			}
		}

		expected_next = marker + 1;

		// Count markers larger than largest included
		if marker > max_included {
			trailing_count += 1;
		}

		prev = marker;
	}

	// MUST NOT contain more than one number larger than largest included
	if trailing_count > 1 {
		return Err(PayerProofError::TooManyTrailingOmittedMarkers);
	}

	Ok(())
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

	/// Test the omitted_markers marker algorithm per BOLT 12 payer proof spec.
	///
	/// From the spec example:
	/// TLVs: 0 (omitted), 10 (included), 20 (omitted), 30 (omitted),
	///       40 (included), 50 (omitted), 60 (omitted), 240 (signature)
	///
	/// Expected markers: [11, 12, 41, 42]
	///
	/// The algorithm:
	/// - TLV 0 is always omitted and implicit (not in markers)
	/// - For omitted TLV after included: marker = prev_included_type + 1
	/// - For consecutive omitted TLVs: marker = prev_marker + 1
	#[test]
	fn test_omitted_markers_spec_example() {
		// Build a synthetic TLV stream matching the spec example
		// TLV format: type (BigSize) || length (BigSize) || value
		let mut tlv_bytes = Vec::new();

		// TLV 0: type=0, len=4, value=dummy
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
		// TLV 10: type=10, len=2, value=dummy
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]);
		// TLV 20: type=20, len=2, value=dummy
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]);
		// TLV 30: type=30, len=2, value=dummy
		tlv_bytes.extend_from_slice(&[0x1e, 0x02, 0x00, 0x00]);
		// TLV 40: type=40, len=2, value=dummy
		tlv_bytes.extend_from_slice(&[0x28, 0x02, 0x00, 0x00]);
		// TLV 50: type=50, len=2, value=dummy
		tlv_bytes.extend_from_slice(&[0x32, 0x02, 0x00, 0x00]);
		// TLV 60: type=60, len=2, value=dummy
		tlv_bytes.extend_from_slice(&[0x3c, 0x02, 0x00, 0x00]);

		// Include types 10 and 40
		let mut included = BTreeSet::new();
		included.insert(10);
		included.insert(40);

		let disclosure = compute_selective_disclosure(&tlv_bytes, &included).unwrap();

		// Per spec example, omitted_markers should be [11, 12, 41, 42]
		assert_eq!(disclosure.omitted_markers, vec![11, 12, 41, 42]);

		// leaf_hashes should have 2 entries (one for each included TLV)
		assert_eq!(disclosure.leaf_hashes.len(), 2);
	}

	/// Test that the marker algorithm handles edge cases correctly.
	#[test]
	fn test_omitted_markers_edge_cases() {
		// Test with only one included TLV at the start
		let mut tlv_bytes = Vec::new();
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // TLV 0
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]); // TLV 10
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]); // TLV 20
		tlv_bytes.extend_from_slice(&[0x1e, 0x02, 0x00, 0x00]); // TLV 30

		let mut included = BTreeSet::new();
		included.insert(10);

		let disclosure = compute_selective_disclosure(&tlv_bytes, &included).unwrap();

		// After included type 10, omitted types 20 and 30 get markers 11 and 12
		assert_eq!(disclosure.omitted_markers, vec![11, 12]);
	}

	/// Test that all included TLVs produce no omitted markers (except implicit TLV0).
	#[test]
	fn test_omitted_markers_all_included() {
		let mut tlv_bytes = Vec::new();
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // TLV 0 (always omitted)
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]); // TLV 10
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]); // TLV 20

		let mut included = BTreeSet::new();
		included.insert(10);
		included.insert(20);

		let disclosure = compute_selective_disclosure(&tlv_bytes, &included).unwrap();

		// Only TLV 0 is omitted (implicit), so no markers needed
		assert!(disclosure.omitted_markers.is_empty());
	}

	/// Test validation of omitted_markers - must not contain 0.
	#[test]
	fn test_validate_omitted_markers_rejects_zero() {
		let omitted = vec![0, 11, 12];
		let included: BTreeSet<u64> = [10, 30].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(matches!(result, Err(PayerProofError::InvalidData(_))));
	}

	/// Test validation of omitted_markers - must not contain signature types.
	#[test]
	fn test_validate_omitted_markers_rejects_signature_types() {
		// included=[10], markers=[1, 2, 250] — 250 is a signature type
		let omitted = vec![1, 2, 250];
		let included: BTreeSet<u64> = [10].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(matches!(result, Err(PayerProofError::InvalidData(_))));
	}

	/// Test validation of omitted_markers - must be strictly ascending.
	#[test]
	fn test_validate_omitted_markers_rejects_non_ascending() {
		// markers=[1, 11, 9]: 1 ok, 11 ok (after included 10), but 9 <= 11 fails ascending
		let omitted = vec![1, 11, 9];
		let included: BTreeSet<u64> = [10, 30].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(matches!(result, Err(PayerProofError::InvalidData(_))));
	}

	/// Test validation of omitted_markers - must not contain included types.
	#[test]
	fn test_validate_omitted_markers_rejects_included_types() {
		// included=[10, 30], markers=[1, 10] — 10 is in included set
		let omitted = vec![1, 10];
		let included: BTreeSet<u64> = [10, 30].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(matches!(result, Err(PayerProofError::OmittedMarkersContainIncluded)));
	}

	/// Test validation of omitted_markers - must not have too many trailing markers.
	#[test]
	fn test_validate_omitted_markers_rejects_too_many_trailing() {
		// included=[10, 20], markers=[1, 21, 22] — both 21 and 22 > max included (20)
		let omitted = vec![1, 21, 22];
		let included: BTreeSet<u64> = [10, 20].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(matches!(result, Err(PayerProofError::TooManyTrailingOmittedMarkers)));
	}

	/// Test that valid minimized omitted_markers pass validation.
	#[test]
	fn test_validate_omitted_markers_accepts_valid() {
		// Realistic payer proof: included types include required fields (88, 168, 176)
		// so max_included=176 and markers are well below it.
		// Layout: 0(omit), 10(incl), 20(omit), 30(omit), 40(incl), 50(omit), 88(incl),
		//         168(incl), 176(incl)
		// markers=[11, 12, 41, 89]
		let omitted = vec![11, 12, 41, 89];
		let included: BTreeSet<u64> = [10, 40, 88, 168, 176].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(result.is_ok());
	}

	/// Test that non-minimized markers are rejected.
	#[test]
	fn test_validate_omitted_markers_rejects_non_minimized() {
		// included=[10, 40], markers=[11, 15, 41, 42]
		// marker 15 should be 12 (continuation of run after 11)
		let omitted = vec![11, 15, 41, 42];
		let included: BTreeSet<u64> = [10, 40].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(matches!(result, Err(PayerProofError::InvalidData(_))));
	}

	/// Test that non-minimized first marker in a run is rejected.
	#[test]
	fn test_validate_omitted_markers_rejects_non_minimized_run_start() {
		// included=[10, 40], markers=[11, 12, 45, 46]
		// marker 45 should be 41 (first omitted after included 40)
		let omitted = vec![11, 12, 45, 46];
		let included: BTreeSet<u64> = [10, 40].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(matches!(result, Err(PayerProofError::InvalidData(_))));
	}

	/// Test minimized markers with omitted TLVs before any included type.
	#[test]
	fn test_validate_omitted_markers_accepts_leading_run() {
		// included=[40], markers=[1, 2, 41]
		// Two omitted before any included type, one after 40
		let omitted = vec![1, 2, 41];
		let included: BTreeSet<u64> = [40].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(result.is_ok());
	}

	/// Test minimized markers with consecutive included types (no markers between them).
	#[test]
	fn test_validate_omitted_markers_accepts_consecutive_included() {
		// included=[10, 20, 40], markers=[1, 41]
		// One omitted before 10, no omitted between 10-20 or 20-40, one after 40
		let omitted = vec![1, 41];
		let included: BTreeSet<u64> = [10, 20, 40].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(result.is_ok());
	}

	/// Test that invreq_metadata (type 0) cannot be explicitly included.
	#[test]
	fn test_invreq_metadata_not_allowed() {
		assert!(!PayerProofBuilder::<'_>::is_type_allowed(TLV_INVREQ_METADATA));
		assert!(PayerProofBuilder::<'_>::is_type_allowed(INVOICE_REQUEST_PAYER_ID_TYPE));
	}

	/// Test that out-of-order TLVs are rejected during parsing.
	#[test]
	fn test_parsing_rejects_out_of_order_tlvs() {
		use core::convert::TryFrom;

		// Create a malformed TLV stream with out-of-order types (20 before 10)
		// TLV format: type (BigSize) || length (BigSize) || value
		let mut bytes = Vec::new();
		// TLV type 20, length 2, value
		bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]);
		// TLV type 10, length 2, value (OUT OF ORDER!)
		bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]);

		let result = PayerProof::try_from(bytes);
		assert!(result.is_err());
	}

	/// Test that duplicate TLVs are rejected during parsing.
	#[test]
	fn test_parsing_rejects_duplicate_tlvs() {
		use core::convert::TryFrom;

		// Create a malformed TLV stream with duplicate type 10
		let mut bytes = Vec::new();
		// TLV type 10, length 2, value
		bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]);
		// TLV type 10 again (DUPLICATE!)
		bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]);

		let result = PayerProof::try_from(bytes);
		assert!(result.is_err());
	}

	/// Test that invalid hash lengths (not multiple of 32) are rejected.
	#[test]
	fn test_parsing_rejects_invalid_hash_length() {
		use core::convert::TryFrom;

		// Create a TLV stream with missing_hashes (type 246) that has invalid length
		// BigSize encoding: values 0-252 are single byte, 253-65535 use 0xFD prefix
		let mut bytes = Vec::new();
		// TLV type 246 (missing_hashes) - 246 < 253 so single byte
		bytes.push(0xf6); // type 246
		bytes.push(0x21); // length 33 (not multiple of 32!)
		bytes.extend_from_slice(&[0x00; 33]); // 33 bytes of zeros

		let result = PayerProof::try_from(bytes);
		assert!(result.is_err());
	}

	/// Test that invalid leaf_hashes length (not multiple of 32) is rejected.
	#[test]
	fn test_parsing_rejects_invalid_leaf_hashes_length() {
		use core::convert::TryFrom;

		// Create a TLV stream with leaf_hashes (type 248) that has invalid length
		// BigSize encoding: values 0-252 are single byte, 253-65535 use 0xFD prefix
		let mut bytes = Vec::new();
		// TLV type 248 (leaf_hashes) - 248 < 253 so single byte
		bytes.push(0xf8); // type 248
		bytes.push(0x1f); // length 31 (not multiple of 32!)
		bytes.extend_from_slice(&[0x00; 31]); // 31 bytes of zeros

		let result = PayerProof::try_from(bytes);
		assert!(result.is_err());
	}
}
