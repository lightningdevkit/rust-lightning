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
use crate::ln::channelmanager::PaymentId;
use crate::ln::inbound_payment::ExpandedKey;
use crate::offers::invoice::{
	Bolt12Invoice, INVOICE_AMOUNT_TYPE, INVOICE_CREATED_AT_TYPE, INVOICE_FEATURES_TYPE,
	INVOICE_NODE_ID_TYPE, INVOICE_PAYMENT_HASH_TYPE, SIGNATURE_TAG,
};
use crate::offers::invoice_request::INVOICE_REQUEST_PAYER_ID_TYPE;
use crate::offers::merkle::{
	self, SelectiveDisclosure, SelectiveDisclosureError, TaggedHash, TlvStream, SIGNATURE_TYPES,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{OFFER_DESCRIPTION_TYPE, OFFER_ISSUER_TYPE};
use crate::offers::parse::Bech32Encode;
use crate::offers::payer::PAYER_METADATA_TYPE;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{BigSize, HighZeroBytesDroppedBigSize, Readable, Writeable};
use lightning_types::string::PrintableString;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};

use core::convert::TryFrom;
use core::time::Duration;

#[allow(unused_imports)]
use crate::prelude::*;

const TLV_SIGNATURE: u64 = 240;
const TLV_PREIMAGE: u64 = 242;
const TLV_OMITTED_TLVS: u64 = 244;
const TLV_MISSING_HASHES: u64 = 246;
const TLV_LEAF_HASHES: u64 = 248;
const TLV_PAYER_SIGNATURE: u64 = 250;

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
	/// The invreq_metadata field cannot be included (per spec).
	InvreqMetadataNotAllowed,
	/// TLV types >= 240 cannot be included — they are in the
	/// signature/payer-proof range and handled separately.
	SignatureTypeNotAllowed,

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
	disclosed_fields: DisclosedFields,
}

#[derive(Clone, Debug, Default)]
struct DisclosedFields {
	offer_description: Option<String>,
	offer_issuer: Option<String>,
	invoice_amount_msats: Option<u64>,
	invoice_created_at: Option<Duration>,
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
	invoice_bytes: Vec<u8>,
}

impl<'a> PayerProofBuilder<'a> {
	/// Create a new builder from a paid invoice and its preimage.
	///
	/// Returns an error if the preimage doesn't match the invoice's payment hash.
	pub(super) fn new(
		invoice: &'a Bolt12Invoice, preimage: PaymentPreimage,
	) -> Result<Self, PayerProofError> {
		let computed_hash = sha256::Hash::hash(&preimage.0);
		if computed_hash.as_byte_array() != &invoice.payment_hash().0 {
			return Err(PayerProofError::PreimageMismatch);
		}

		let mut invoice_bytes = Vec::new();
		invoice.write(&mut invoice_bytes).expect("Vec write should not fail");

		let mut included_types = BTreeSet::new();
		included_types.insert(INVOICE_REQUEST_PAYER_ID_TYPE);
		included_types.insert(INVOICE_PAYMENT_HASH_TYPE);
		included_types.insert(INVOICE_NODE_ID_TYPE);

		// Per spec, invoice_features MUST be included "if present" — meaning if the
		// TLV exists in the invoice byte stream, regardless of whether the parsed
		// value is empty. Check the raw bytes so we handle invoices from other
		// implementations that may serialize empty features.
		let has_features_tlv =
			TlvStream::new(&invoice_bytes).any(|r| r.r#type == INVOICE_FEATURES_TYPE);
		if has_features_tlv {
			included_types.insert(INVOICE_FEATURES_TYPE);
		}

		Ok(Self { invoice, preimage, included_types, invoice_bytes })
	}

	/// Include a specific TLV type in the proof.
	///
	/// Returns an error if the type is not allowed (e.g., invreq_metadata or
	/// types in the signature/payer-proof range (240..=1000), which are handled
	/// separately.
	pub fn include_type(mut self, tlv_type: u64) -> Result<Self, PayerProofError> {
		if tlv_type == PAYER_METADATA_TYPE {
			return Err(PayerProofError::InvreqMetadataNotAllowed);
		}
		if SIGNATURE_TYPES.contains(&tlv_type) {
			return Err(PayerProofError::SignatureTypeNotAllowed);
		}
		self.included_types.insert(tlv_type);
		Ok(self)
	}

	/// Include the offer description in the proof.
	pub fn include_offer_description(mut self) -> Self {
		self.included_types.insert(OFFER_DESCRIPTION_TYPE);
		self
	}

	/// Include the offer issuer in the proof.
	pub fn include_offer_issuer(mut self) -> Self {
		self.included_types.insert(OFFER_ISSUER_TYPE);
		self
	}

	/// Include the invoice amount in the proof.
	pub fn include_invoice_amount(mut self) -> Self {
		self.included_types.insert(INVOICE_AMOUNT_TYPE);
		self
	}

	/// Include the invoice creation timestamp in the proof.
	pub fn include_invoice_created_at(mut self) -> Self {
		self.included_types.insert(INVOICE_CREATED_AT_TYPE);
		self
	}

	/// Builds a signed [`PayerProof`] using the provided signing function.
	///
	/// Use this when you have direct access to the payer's signing key.
	pub fn build<F>(self, sign_fn: F, note: Option<&str>) -> Result<PayerProof, PayerProofError>
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
	pub fn build_with_derived_key(
		self, expanded_key: &ExpandedKey, nonce: Nonce, payment_id: PaymentId, note: Option<&str>,
	) -> Result<PayerProof, PayerProofError> {
		let secp_ctx = Secp256k1::signing_only();
		let keys = self
			.invoice
			.derive_payer_signing_keys(payment_id, nonce, expanded_key, &secp_ctx)
			.map_err(|_| PayerProofError::KeyDerivationFailed)?;

		let unsigned = self.build_unsigned()?;
		unsigned.sign(|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message, &keys)), note)
	}

	fn build_unsigned(self) -> Result<UnsignedPayerProof, PayerProofError> {
		let invoice_bytes = self.invoice_bytes;
		let mut bytes_without_sig = Vec::with_capacity(invoice_bytes.len());
		for r in TlvStream::new(&invoice_bytes).filter(|r| !SIGNATURE_TYPES.contains(&r.r#type)) {
			bytes_without_sig.extend_from_slice(r.record_bytes);
		}
		let disclosed_fields =
			extract_disclosed_fields(TlvStream::new(&invoice_bytes).filter(|r| {
				self.included_types.contains(&r.r#type) && !SIGNATURE_TYPES.contains(&r.r#type)
			}))?;

		let disclosure =
			merkle::compute_selective_disclosure(&bytes_without_sig, &self.included_types)?;

		let invoice_signature = self.invoice.signature();

		Ok(UnsignedPayerProof {
			invoice_signature,
			preimage: self.preimage,
			payer_id: self.invoice.payer_signing_pubkey(),
			payment_hash: self.invoice.payment_hash().clone(),
			issuer_signing_pubkey: self.invoice.signing_pubkey(),
			invoice_bytes,
			included_types: self.included_types,
			disclosed_fields,
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
	invoice_bytes: Vec<u8>,
	included_types: BTreeSet<u64>,
	disclosed_fields: DisclosedFields,
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
				disclosed_fields: self.disclosed_fields,
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

		// Preserve TLV ordering by emitting included invoice records below the
		// payer-proof range first, then payer-proof TLVs (240..=250), then any
		// disclosed experimental invoice records above the reserved range.
		for record in TlvStream::new(&self.invoice_bytes)
			.filter(|r| self.included_types.contains(&r.r#type) && r.r#type < TLV_SIGNATURE)
		{
			bytes.extend_from_slice(record.record_bytes);
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
			BigSize(TLV_OMITTED_TLVS).write(&mut bytes).expect("Vec write should not fail");
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

		for record in TlvStream::new(&self.invoice_bytes).filter(|r| {
			self.included_types.contains(&r.r#type)
				&& !SIGNATURE_TYPES.contains(&r.r#type)
				&& r.r#type > *SIGNATURE_TYPES.end()
		}) {
			bytes.extend_from_slice(record.record_bytes);
		}

		bytes
	}
}

impl PayerProof {
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

	/// The invoice signature over the merkle root.
	pub fn invoice_signature(&self) -> Signature {
		self.contents.invoice_signature
	}

	/// The payer's schnorr signature proving who authorized the payment.
	pub fn payer_signature(&self) -> Signature {
		self.contents.payer_signature
	}

	/// The disclosed offer description, if included in the proof.
	pub fn offer_description(&self) -> Option<PrintableString<'_>> {
		self.contents.disclosed_fields.offer_description.as_deref().map(PrintableString)
	}

	/// The disclosed offer issuer, if included in the proof.
	pub fn offer_issuer(&self) -> Option<PrintableString<'_>> {
		self.contents.disclosed_fields.offer_issuer.as_deref().map(PrintableString)
	}

	/// The disclosed invoice amount, if included in the proof.
	pub fn invoice_amount_msats(&self) -> Option<u64> {
		self.contents.disclosed_fields.invoice_amount_msats
	}

	/// The disclosed invoice creation time, if included in the proof.
	pub fn invoice_created_at(&self) -> Option<Duration> {
		self.contents.disclosed_fields.invoice_created_at
	}

	/// The payer's note, if any.
	pub fn payer_note(&self) -> Option<PrintableString<'_>> {
		self.contents.payer_note.as_deref().map(PrintableString)
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

/// Validate that the byte slice is a well-formed TLV stream.
///
/// `TlvStream::new()` assumes well-formed input and panics on malformed BigSize
/// values or out-of-bounds lengths. This function validates the framing first,
/// returning an error instead of panicking on untrusted input.
fn validate_tlv_framing(bytes: &[u8]) -> Result<(), crate::ln::msgs::DecodeError> {
	use crate::ln::msgs::DecodeError;
	let mut cursor = io::Cursor::new(bytes);
	while (cursor.position() as usize) < bytes.len() {
		let _type: BigSize = Readable::read(&mut cursor).map_err(|_| DecodeError::InvalidValue)?;
		let length: BigSize = Readable::read(&mut cursor).map_err(|_| DecodeError::InvalidValue)?;
		let end = cursor.position().checked_add(length.0).ok_or(DecodeError::InvalidValue)?;
		let end_usize = usize::try_from(end).map_err(|_| DecodeError::InvalidValue)?;
		if end_usize > bytes.len() {
			return Err(DecodeError::ShortRead);
		}
		cursor.set_position(end);
	}
	Ok(())
}

fn update_disclosed_fields(
	record: &crate::offers::merkle::TlvRecord<'_>, disclosed_fields: &mut DisclosedFields,
) -> Result<(), crate::ln::msgs::DecodeError> {
	use crate::ln::msgs::DecodeError;

	match record.r#type {
		OFFER_DESCRIPTION_TYPE => {
			disclosed_fields.offer_description = Some(
				String::from_utf8(record.value_bytes.to_vec())
					.map_err(|_| DecodeError::InvalidValue)?,
			);
		},
		OFFER_ISSUER_TYPE => {
			disclosed_fields.offer_issuer = Some(
				String::from_utf8(record.value_bytes.to_vec())
					.map_err(|_| DecodeError::InvalidValue)?,
			);
		},
		INVOICE_CREATED_AT_TYPE => {
			disclosed_fields.invoice_created_at = Some(Duration::from_secs(
				record.read_value::<HighZeroBytesDroppedBigSize<u64>>()?.0,
			));
		},
		INVOICE_AMOUNT_TYPE => {
			disclosed_fields.invoice_amount_msats =
				Some(record.read_value::<HighZeroBytesDroppedBigSize<u64>>()?.0);
		},
		_ => {},
	}

	Ok(())
}

fn extract_disclosed_fields<'a>(
	records: impl core::iter::Iterator<Item = crate::offers::merkle::TlvRecord<'a>>,
) -> Result<DisclosedFields, crate::ln::msgs::DecodeError> {
	let mut disclosed_fields = DisclosedFields::default();
	for record in records {
		update_disclosed_fields(&record, &mut disclosed_fields)?;
	}
	Ok(disclosed_fields)
}

// Payer proofs use manual TLV parsing rather than `ParsedMessage` / `tlv_stream!`
// because of their hybrid structure: a dynamic, variable set of included invoice
// TLV records (types 0-239, preserved as raw bytes for merkle reconstruction) plus
// payer-proof-specific TLVs (types 240-250) with non-standard encodings such as
// BigSize lists (`omitted_tlvs`) and concatenated 32-byte hashes
// (`missing_hashes`, `leaf_hashes`). The `tlv_stream!` macro assumes a fixed set
// of known fields with standard `Readable`/`Writeable` encodings, so it cannot
// express the passthrough-or-parse logic required here.
impl TryFrom<Vec<u8>> for PayerProof {
	type Error = crate::offers::parse::Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		use crate::ln::msgs::DecodeError;
		use crate::offers::parse::Bolt12ParseError;

		// Validate TLV framing before passing to TlvStream, which assumes
		// well-formed input and panics on malformed BigSize or out-of-bounds
		// lengths. This mirrors the validation that ParsedMessage / CursorReadable
		// provides for other BOLT 12 types.
		validate_tlv_framing(&bytes)
			.map_err(|_| Bolt12ParseError::Decode(DecodeError::InvalidValue))?;

		let mut payer_id: Option<PublicKey> = None;
		let mut payment_hash: Option<PaymentHash> = None;
		let mut issuer_signing_pubkey: Option<PublicKey> = None;
		let mut invoice_signature: Option<Signature> = None;
		let mut preimage: Option<PaymentPreimage> = None;
		let mut payer_signature: Option<Signature> = None;
		let mut payer_note: Option<String> = None;
		let mut disclosed_fields = DisclosedFields::default();

		let mut leaf_hashes: Vec<sha256::Hash> = Vec::new();
		let mut omitted_markers: Vec<u64> = Vec::new();
		let mut missing_hashes: Vec<sha256::Hash> = Vec::new();

		let mut included_types: BTreeSet<u64> = BTreeSet::new();
		let mut included_records: Vec<(u64, usize, usize)> = Vec::new();

		let mut prev_tlv_type: Option<u64> = None;

		for record in TlvStream::new(&bytes) {
			let tlv_type = record.r#type;

			// Strict ascending order check covers both ordering and duplicates.
			if let Some(prev) = prev_tlv_type {
				if tlv_type <= prev {
					return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
				}
			}
			prev_tlv_type = Some(tlv_type);
			update_disclosed_fields(&record, &mut disclosed_fields)?;

			match tlv_type {
				INVOICE_REQUEST_PAYER_ID_TYPE => {
					payer_id = Some(record.read_value()?);
					included_types.insert(tlv_type);
					included_records.push((
						tlv_type,
						record.end - record.record_bytes.len(),
						record.end,
					));
				},
				INVOICE_PAYMENT_HASH_TYPE => {
					payment_hash = Some(record.read_value()?);
					included_types.insert(tlv_type);
					included_records.push((
						tlv_type,
						record.end - record.record_bytes.len(),
						record.end,
					));
				},
				INVOICE_NODE_ID_TYPE => {
					issuer_signing_pubkey = Some(record.read_value()?);
					included_types.insert(tlv_type);
					included_records.push((
						tlv_type,
						record.end - record.record_bytes.len(),
						record.end,
					));
				},
				TLV_SIGNATURE => {
					invoice_signature = Some(record.read_value()?);
				},
				TLV_PREIMAGE => {
					preimage = Some(record.read_value()?);
				},
				TLV_OMITTED_TLVS => {
					let mut cursor = io::Cursor::new(record.value_bytes);
					while (cursor.position() as usize) < record.value_bytes.len() {
						let marker: BigSize = Readable::read(&mut cursor)?;
						omitted_markers.push(marker.0);
					}
				},
				TLV_MISSING_HASHES => {
					if record.value_bytes.len() % 32 != 0 {
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					for chunk in record.value_bytes.chunks_exact(32) {
						let hash_bytes: [u8; 32] = chunk.try_into().expect("chunks_exact(32)");
						missing_hashes.push(sha256::Hash::from_byte_array(hash_bytes));
					}
				},
				TLV_LEAF_HASHES => {
					if record.value_bytes.len() % 32 != 0 {
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					for chunk in record.value_bytes.chunks_exact(32) {
						let hash_bytes: [u8; 32] = chunk.try_into().expect("chunks_exact(32)");
						leaf_hashes.push(sha256::Hash::from_byte_array(hash_bytes));
					}
				},
				TLV_PAYER_SIGNATURE => {
					if record.value_bytes.len() < 64 {
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					let mut cursor = io::Cursor::new(record.value_bytes);
					payer_signature = Some(Readable::read(&mut cursor)?);
					if record.value_bytes.len() > 64 {
						let note_bytes = &record.value_bytes[64..];
						payer_note = Some(
							String::from_utf8(note_bytes.to_vec())
								.map_err(|_| DecodeError::InvalidValue)?,
						);
					}
				},
				_ => {
					if tlv_type == PAYER_METADATA_TYPE {
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					if !SIGNATURE_TYPES.contains(&tlv_type) {
						// Included invoice TLV record (passthrough for merkle
						// reconstruction).
						included_types.insert(tlv_type);
						included_records.push((
							tlv_type,
							record.end - record.record_bytes.len(),
							record.end,
						));
					} else if tlv_type % 2 == 0 {
						// Unknown even types are mandatory-to-understand per
						// BOLT convention — reject them.
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					// Unknown odd types can be safely ignored.
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
			.map_err(Bolt12ParseError::Decode)?;

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

		// Verify preimage matches payment hash.
		let computed = sha256::Hash::hash(&preimage.0);
		if computed.as_byte_array() != &payment_hash.0 {
			return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
		}

		// Verify the invoice signature against the issuer signing pubkey.
		let tagged_hash = TaggedHash::from_merkle_root(SIGNATURE_TAG, merkle_root);
		merkle::verify_signature(&invoice_signature, &tagged_hash, issuer_signing_pubkey)
			.map_err(|_| Bolt12ParseError::Decode(DecodeError::InvalidValue))?;

		// Verify the payer signature.
		let message = UnsignedPayerProof::compute_payer_signature_message(
			payer_note.as_deref(),
			&merkle_root,
		);
		let secp_ctx = Secp256k1::verification_only();
		secp_ctx
			.verify_schnorr(&payer_signature, &message, &payer_id.into())
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
				disclosed_fields,
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
/// - Markers MUST be minimized: each marker must be exactly prev_value + 1 within
///   a run, and the first marker after an included type X must be X + 1. This
///   naturally allows a trailing run of omitted TLVs after the final included
///   type.
fn validate_omitted_markers_for_parsing(
	omitted_markers: &[u64], included_types: &BTreeSet<u64>,
) -> Result<(), crate::ln::msgs::DecodeError> {
	let mut inc_iter = included_types.iter().copied().peekable();
	// After implicit TLV0 (marker 0), the first minimized marker would be 1
	let mut expected_next: u64 = 1;
	let mut prev = 0u64;

	for &marker in omitted_markers {
		// MUST NOT contain 0
		if marker == 0 {
			return Err(crate::ln::msgs::DecodeError::InvalidValue);
		}

		// MUST NOT contain signature TLV types
		if SIGNATURE_TYPES.contains(&marker) {
			return Err(crate::ln::msgs::DecodeError::InvalidValue);
		}

		// MUST be strictly ascending
		if marker <= prev {
			return Err(crate::ln::msgs::DecodeError::InvalidValue);
		}

		// MUST NOT contain included TLV types
		if included_types.contains(&marker) {
			return Err(crate::ln::msgs::DecodeError::InvalidValue);
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
					return Err(crate::ln::msgs::DecodeError::InvalidValue);
				}
			}
			if !found {
				return Err(crate::ln::msgs::DecodeError::InvalidValue);
			}
		}

		expected_next = marker + 1;
		prev = marker;
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
	use crate::ln::channelmanager::PaymentId;
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::offers::merkle::compute_selective_disclosure;
	use crate::offers::nonce::Nonce;
	#[cfg(not(c_bindings))]
	use crate::offers::refund::RefundBuilder;
	#[cfg(c_bindings)]
	use crate::offers::refund::RefundMaybeWithDerivedMetadataBuilder as RefundBuilder;
	use crate::offers::test_utils::*;
	use crate::util::ser::HighZeroBytesDroppedBigSize;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
	use core::time::Duration;

	const EXPERIMENTAL_TEST_TLV_TYPE: u64 = 1_000_000_001;

	fn write_tlv_record<T: Writeable>(bytes: &mut Vec<u8>, tlv_type: u64, value: &T) {
		let mut value_bytes = Vec::new();
		value.write(&mut value_bytes).expect("Vec write should not fail");

		BigSize(tlv_type).write(bytes).expect("Vec write should not fail");
		BigSize(value_bytes.len() as u64).write(bytes).expect("Vec write should not fail");
		bytes.extend_from_slice(&value_bytes);
	}

	fn write_tlv_record_bytes(bytes: &mut Vec<u8>, tlv_type: u64, value_bytes: &[u8]) {
		BigSize(tlv_type).write(bytes).expect("Vec write should not fail");
		BigSize(value_bytes.len() as u64).write(bytes).expect("Vec write should not fail");
		bytes.extend_from_slice(value_bytes);
	}

	fn build_round_trip_proof_with_included_experimental_tlv() -> PayerProof {
		let secp_ctx = Secp256k1::new();

		let payer_secret = SecretKey::from_slice(&[42; 32]).unwrap();
		let payer_keys = Keypair::from_secret_key(&secp_ctx, &payer_secret);
		let payer_id = payer_keys.public_key();

		let issuer_secret = SecretKey::from_slice(&[43; 32]).unwrap();
		let issuer_keys = Keypair::from_secret_key(&secp_ctx, &issuer_secret);
		let issuer_signing_pubkey = issuer_keys.public_key();

		let preimage = PaymentPreimage([44; 32]);
		let payment_hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());

		let mut invoice_bytes = Vec::new();
		write_tlv_record_bytes(&mut invoice_bytes, PAYER_METADATA_TYPE, &[45; 32]);
		write_tlv_record(&mut invoice_bytes, INVOICE_REQUEST_PAYER_ID_TYPE, &payer_id);
		write_tlv_record(&mut invoice_bytes, INVOICE_PAYMENT_HASH_TYPE, &payment_hash);
		write_tlv_record(&mut invoice_bytes, INVOICE_NODE_ID_TYPE, &issuer_signing_pubkey);
		write_tlv_record_bytes(
			&mut invoice_bytes,
			EXPERIMENTAL_TEST_TLV_TYPE,
			b"experimental-payer-proof-field",
		);

		let invoice_message =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &invoice_bytes);
		let invoice_signature =
			secp_ctx.sign_schnorr_no_aux_rand(invoice_message.as_digest(), &issuer_keys);

		let included_types: BTreeSet<u64> = [
			INVOICE_REQUEST_PAYER_ID_TYPE,
			INVOICE_PAYMENT_HASH_TYPE,
			INVOICE_NODE_ID_TYPE,
			EXPERIMENTAL_TEST_TLV_TYPE,
		]
		.into_iter()
		.collect();
		let disclosed_fields = extract_disclosed_fields(
			TlvStream::new(&invoice_bytes).filter(|r| included_types.contains(&r.r#type)),
		)
		.unwrap();
		let disclosure = compute_selective_disclosure(&invoice_bytes, &included_types).unwrap();

		let unsigned = UnsignedPayerProof {
			invoice_signature,
			preimage,
			payer_id,
			payment_hash,
			issuer_signing_pubkey,
			invoice_bytes,
			included_types,
			disclosed_fields,
			disclosure,
		};

		unsigned
			.sign(|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message, &payer_keys)), None)
			.unwrap()
	}

	fn build_round_trip_proof_with_multiple_trailing_omitted_tlvs() -> PayerProof {
		let secp_ctx = Secp256k1::new();

		let payer_secret = SecretKey::from_slice(&[52; 32]).unwrap();
		let payer_keys = Keypair::from_secret_key(&secp_ctx, &payer_secret);
		let payer_id = payer_keys.public_key();

		let issuer_secret = SecretKey::from_slice(&[53; 32]).unwrap();
		let issuer_keys = Keypair::from_secret_key(&secp_ctx, &issuer_secret);
		let issuer_signing_pubkey = issuer_keys.public_key();

		let preimage = PaymentPreimage([54; 32]);
		let payment_hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());

		let mut invoice_bytes = Vec::new();
		write_tlv_record_bytes(&mut invoice_bytes, PAYER_METADATA_TYPE, &[55; 32]);
		write_tlv_record(&mut invoice_bytes, INVOICE_REQUEST_PAYER_ID_TYPE, &payer_id);
		write_tlv_record(&mut invoice_bytes, INVOICE_PAYMENT_HASH_TYPE, &payment_hash);
		write_tlv_record(&mut invoice_bytes, INVOICE_NODE_ID_TYPE, &issuer_signing_pubkey);
		write_tlv_record_bytes(&mut invoice_bytes, 1_000_000_001, b"first-omitted-experimental");
		write_tlv_record_bytes(&mut invoice_bytes, 1_000_000_003, b"second-omitted-experimental");

		let invoice_message =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &invoice_bytes);
		let invoice_signature =
			secp_ctx.sign_schnorr_no_aux_rand(invoice_message.as_digest(), &issuer_keys);

		let included_types: BTreeSet<u64> =
			[INVOICE_REQUEST_PAYER_ID_TYPE, INVOICE_PAYMENT_HASH_TYPE, INVOICE_NODE_ID_TYPE]
				.into_iter()
				.collect();
		let disclosed_fields = extract_disclosed_fields(
			TlvStream::new(&invoice_bytes).filter(|r| included_types.contains(&r.r#type)),
		)
		.unwrap();
		let disclosure = compute_selective_disclosure(&invoice_bytes, &included_types).unwrap();
		assert_eq!(disclosure.omitted_markers, vec![177, 178]);

		let unsigned = UnsignedPayerProof {
			invoice_signature,
			preimage,
			payer_id,
			payment_hash,
			issuer_signing_pubkey,
			invoice_bytes,
			included_types,
			disclosed_fields,
			disclosure,
		};

		unsigned
			.sign(|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message, &payer_keys)), None)
			.unwrap()
	}

	fn build_round_trip_proof_with_disclosed_fields() -> PayerProof {
		let secp_ctx = Secp256k1::new();

		let payer_secret = SecretKey::from_slice(&[62; 32]).unwrap();
		let payer_keys = Keypair::from_secret_key(&secp_ctx, &payer_secret);
		let payer_id = payer_keys.public_key();

		let issuer_secret = SecretKey::from_slice(&[63; 32]).unwrap();
		let issuer_keys = Keypair::from_secret_key(&secp_ctx, &issuer_secret);
		let issuer_signing_pubkey = issuer_keys.public_key();

		let preimage = PaymentPreimage([64; 32]);
		let payment_hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());

		let mut invoice_bytes = Vec::new();
		write_tlv_record_bytes(&mut invoice_bytes, PAYER_METADATA_TYPE, &[65; 32]);
		write_tlv_record_bytes(&mut invoice_bytes, OFFER_DESCRIPTION_TYPE, b"coffee beans");
		write_tlv_record_bytes(&mut invoice_bytes, OFFER_ISSUER_TYPE, b"LDK Roastery");
		write_tlv_record(&mut invoice_bytes, INVOICE_REQUEST_PAYER_ID_TYPE, &payer_id);
		write_tlv_record(
			&mut invoice_bytes,
			INVOICE_CREATED_AT_TYPE,
			&HighZeroBytesDroppedBigSize(1_700_000_000u64),
		);
		write_tlv_record(&mut invoice_bytes, INVOICE_PAYMENT_HASH_TYPE, &payment_hash);
		write_tlv_record(
			&mut invoice_bytes,
			INVOICE_AMOUNT_TYPE,
			&HighZeroBytesDroppedBigSize(42_000u64),
		);
		write_tlv_record(&mut invoice_bytes, INVOICE_NODE_ID_TYPE, &issuer_signing_pubkey);

		let invoice_message =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &invoice_bytes);
		let invoice_signature =
			secp_ctx.sign_schnorr_no_aux_rand(invoice_message.as_digest(), &issuer_keys);

		let included_types: BTreeSet<u64> = [
			OFFER_DESCRIPTION_TYPE,
			OFFER_ISSUER_TYPE,
			INVOICE_REQUEST_PAYER_ID_TYPE,
			INVOICE_CREATED_AT_TYPE,
			INVOICE_PAYMENT_HASH_TYPE,
			INVOICE_AMOUNT_TYPE,
			INVOICE_NODE_ID_TYPE,
		]
		.into_iter()
		.collect();
		let disclosed_fields = extract_disclosed_fields(
			TlvStream::new(&invoice_bytes).filter(|r| included_types.contains(&r.r#type)),
		)
		.unwrap();
		let disclosure = compute_selective_disclosure(&invoice_bytes, &included_types).unwrap();

		let unsigned = UnsignedPayerProof {
			invoice_signature,
			preimage,
			payer_id,
			payment_hash,
			issuer_signing_pubkey,
			invoice_bytes,
			included_types,
			disclosed_fields,
			disclosure,
		};

		unsigned
			.sign(|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message, &payer_keys)), None)
			.unwrap()
	}

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
		assert!(result.is_err());
	}

	/// Test validation of omitted_markers - must not contain signature types.
	#[test]
	fn test_validate_omitted_markers_rejects_signature_types() {
		// included=[10], markers=[1, 2, 250] — 250 is a signature type
		let omitted = vec![1, 2, 250];
		let included: BTreeSet<u64> = [10].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(result.is_err());
	}

	/// Test validation of omitted_markers - must be strictly ascending.
	#[test]
	fn test_validate_omitted_markers_rejects_non_ascending() {
		// markers=[1, 11, 9]: 1 ok, 11 ok (after included 10), but 9 <= 11 fails ascending
		let omitted = vec![1, 11, 9];
		let included: BTreeSet<u64> = [10, 30].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(result.is_err());
	}

	/// Test validation of omitted_markers - must not contain included types.
	#[test]
	fn test_validate_omitted_markers_rejects_included_types() {
		// included=[10, 30], markers=[1, 10] — 10 is in included set
		let omitted = vec![1, 10];
		let included: BTreeSet<u64> = [10, 30].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(matches!(result, Err(crate::ln::msgs::DecodeError::InvalidValue)));
	}

	/// Test that a minimized trailing run is accepted.
	#[test]
	fn test_validate_omitted_markers_accepts_trailing_run() {
		// included=[10, 20], markers=[1, 21, 22] — both 21 and 22 > max included (20)
		let omitted = vec![1, 21, 22];
		let included: BTreeSet<u64> = [10, 20].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(result.is_ok());
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
		assert!(result.is_err());
	}

	/// Test that non-minimized first marker in a run is rejected.
	#[test]
	fn test_validate_omitted_markers_rejects_non_minimized_run_start() {
		// included=[10, 40], markers=[11, 12, 45, 46]
		// marker 45 should be 41 (first omitted after included 40)
		let omitted = vec![11, 12, 45, 46];
		let included: BTreeSet<u64> = [10, 40].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(result.is_err());
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

	/// Test that invreq_metadata (type 0) cannot be explicitly included via include_type.
	#[test]
	fn test_invreq_metadata_not_allowed() {
		assert_eq!(PAYER_METADATA_TYPE, 0);
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

	/// Test that TLV types >= 240 are rejected by include_type.
	///
	/// Per spec, all types >= 240 are in the signature/payer-proof range and
	/// handled separately. This includes types > 1000 (experimental range)
	/// which were previously allowed through.
	#[test]
	fn test_include_type_rejects_signature_types() {
		// Test the type validation logic directly.
		fn check_include_type(tlv_type: u64) -> Result<(), PayerProofError> {
			if tlv_type == PAYER_METADATA_TYPE {
				return Err(PayerProofError::InvreqMetadataNotAllowed);
			}
			if SIGNATURE_TYPES.contains(&tlv_type) {
				return Err(PayerProofError::SignatureTypeNotAllowed);
			}
			Ok(())
		}

		// Signature-range types 240..=1000 must be rejected.
		assert!(matches!(check_include_type(240), Err(PayerProofError::SignatureTypeNotAllowed)));
		assert!(matches!(check_include_type(250), Err(PayerProofError::SignatureTypeNotAllowed)));
		assert!(matches!(check_include_type(1000), Err(PayerProofError::SignatureTypeNotAllowed)));
		// Types above 1000 are experimental/non-signature TLVs and should remain includable.
		assert!(check_include_type(1001).is_ok());
		assert!(check_include_type(u64::MAX).is_ok());
		// Just below the boundary
		assert!(check_include_type(239).is_ok());
		// Payer metadata still rejected
		assert!(matches!(check_include_type(0), Err(PayerProofError::InvreqMetadataNotAllowed)));
	}

	#[test]
	fn test_round_trip_accepts_included_experimental_tlv() {
		let proof = build_round_trip_proof_with_included_experimental_tlv();
		let result = PayerProof::try_from(proof.bytes().to_vec());
		assert!(
			result.is_ok(),
			"Included experimental TLVs should survive payer proof parsing: {:?}",
			result
		);
	}

	#[test]
	fn test_round_trip_accepts_multiple_trailing_omitted_tlvs() {
		let proof = build_round_trip_proof_with_multiple_trailing_omitted_tlvs();
		let result = PayerProof::try_from(proof.bytes().to_vec());
		assert!(
			result.is_ok(),
			"Multiple trailing omitted TLVs should survive payer proof parsing: {:?}",
			result
		);
	}

	#[test]
	fn test_parsed_proof_exposes_disclosed_fields() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let parsed = PayerProof::try_from(proof.bytes().to_vec()).unwrap();

		assert_eq!(parsed.offer_description().map(|s| s.0), Some("coffee beans"));
		assert_eq!(parsed.offer_issuer().map(|s| s.0), Some("LDK Roastery"));
		assert_eq!(parsed.invoice_amount_msats(), Some(42_000));
		assert_eq!(parsed.invoice_created_at(), Some(Duration::from_secs(1_700_000_000)));
	}

	/// Test that unknown even TLV types >= 240 are rejected during parsing.
	///
	/// Per BOLT convention, even types are mandatory-to-understand. The parser
	/// must reject unknown even types in the signature range to prevent
	/// accepting malformed proofs.
	#[test]
	fn test_parsing_rejects_unknown_even_signature_range_types() {
		use core::convert::TryFrom;

		// Craft a payer proof with an unknown even type 252 (in signature range,
		// but not one of the known payer proof TLVs)
		let mut bytes = Vec::new();
		// Some included invoice TLV first (type 10)
		bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]);
		// Unknown even type 252 (in signature range 240-1000)
		bytes.push(0xfc); // type 252
		bytes.push(0x02); // length 2
		bytes.extend_from_slice(&[0x00, 0x00]);

		let result = PayerProof::try_from(bytes);
		assert!(result.is_err(), "Unknown even type 252 should be rejected");
	}

	/// Test that malformed TLV framing is rejected without panicking.
	///
	/// TlvStream::new() panics on malformed BigSize values or out-of-bounds
	/// lengths. The parser must validate framing before constructing TlvStream.
	#[test]
	fn test_parsing_rejects_malformed_tlv_framing() {
		use core::convert::TryFrom;

		// Truncated BigSize type (0xFD prefix requires 2 more bytes)
		let result = PayerProof::try_from(vec![0xFD, 0x01]);
		assert!(result.is_err(), "Truncated BigSize type should be rejected");

		// Valid type but truncated length
		let result = PayerProof::try_from(vec![0x0a]);
		assert!(result.is_err(), "Missing length should be rejected");

		// Length exceeds remaining bytes
		let result = PayerProof::try_from(vec![0x0a, 0x04, 0x00, 0x00]);
		assert!(result.is_err(), "Length exceeding data should be rejected");

		// Empty input should not panic
		let result = PayerProof::try_from(vec![]);
		assert!(result.is_err(), "Empty input should be rejected");

		// Completely invalid bytes
		let result = PayerProof::try_from(vec![0xFF, 0xFF]);
		assert!(result.is_err(), "Invalid bytes should be rejected");
	}

	/// Test that duplicate type-0 TLVs are rejected.
	///
	/// Previously the ordering check used `u64` initialized to 0, which
	/// skipped the check for the first TLV if its type was 0, allowing
	/// duplicate type-0 records.
	#[test]
	fn test_parsing_rejects_duplicate_type_zero() {
		use core::convert::TryFrom;

		// Two TLV records both with type 0
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // type 0, len 2
		bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // type 0 again (DUPLICATE!)

		let result = PayerProof::try_from(bytes);
		assert!(result.is_err(), "Duplicate type-0 TLVs should be rejected");
	}

	/// Test that payer_signature TLV with length < 64 is rejected.
	///
	/// The payer_signature value contains a 64-byte schnorr signature
	/// followed by an optional note. A length < 64 is always invalid.
	#[test]
	fn test_parsing_rejects_short_payer_signature() {
		use core::convert::TryFrom;

		// Craft a TLV with type 250 (payer_signature) but only 32 bytes of value
		let mut bytes = Vec::new();
		bytes.push(0xfa); // type 250
		bytes.push(0x20); // length 32 (too short for 64-byte signature)
		bytes.extend_from_slice(&[0x00; 32]);

		let result = PayerProof::try_from(bytes);
		assert!(result.is_err(), "payer_signature with len < 64 should be rejected");
	}

	#[test]
	fn test_round_trip_with_trailing_experimental_tlvs() {
		use core::convert::TryFrom;

		let preimage = PaymentPreimage([1; 32]);
		let payment_hash = PaymentHash(*sha256::Hash::hash(&preimage.0).as_byte_array());
		let invoice = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000)
			.unwrap()
			.experimental_foo(42)
			.experimental_bar(43)
			.build()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash, recipient_pubkey(), now())
			.unwrap()
			.experimental_baz(44)
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let secp_ctx = Secp256k1::signing_only();
		let payer_keys = payer_keys();
		let proof = invoice
			.payer_proof_builder(preimage)
			.unwrap()
			.build(|message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message, &payer_keys)), None)
			.unwrap();
		let parsed = PayerProof::try_from(proof.bytes().to_vec()).unwrap();

		assert_eq!(parsed.bytes(), proof.bytes());
		assert_eq!(parsed.preimage(), preimage);
		assert_eq!(parsed.payment_hash(), payment_hash);
	}

	#[test]
	fn test_build_with_derived_key_for_refund_invoice() {
		use core::convert::TryFrom;

		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);
		let preimage = PaymentPreimage([2; 32]);
		let payment_hash = PaymentHash(*sha256::Hash::hash(&preimage.0).as_byte_array());

		let invoice = RefundBuilder::deriving_signing_pubkey(
			payer_pubkey(),
			&expanded_key,
			nonce,
			&secp_ctx,
			1000,
			payment_id,
		)
		.unwrap()
		.path(blinded_path())
		.experimental_foo(42)
		.experimental_bar(43)
		.build()
		.unwrap()
		.respond_with_no_std(payment_paths(), payment_hash, recipient_pubkey(), now())
		.unwrap()
		.experimental_baz(44)
		.build()
		.unwrap()
		.sign(recipient_sign)
		.unwrap();

		let proof = invoice
			.payer_proof_builder(preimage)
			.unwrap()
			.build_with_derived_key(&expanded_key, nonce, payment_id, Some("refund"))
			.unwrap();
		let parsed = PayerProof::try_from(proof.bytes().to_vec()).unwrap();

		assert_eq!(parsed.preimage(), preimage);
		assert_eq!(parsed.payment_hash(), payment_hash);
		assert_eq!(parsed.payer_note().map(|note| note.to_string()), Some("refund".to_string()));
	}
}
