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
use crate::ln::msgs::DecodeError;
use crate::offers::invoice::{
	Bolt12Invoice, INVOICE_AMOUNT_TYPE, INVOICE_CREATED_AT_TYPE, INVOICE_FEATURES_TYPE,
	INVOICE_NODE_ID_TYPE, INVOICE_PAYMENT_HASH_TYPE, SIGNATURE_TAG,
};
use crate::offers::invoice_request::INVOICE_REQUEST_PAYER_ID_TYPE;
use crate::offers::merkle::{
	self, SelectiveDisclosure, SelectiveDisclosureError, SignError, TaggedHash, TlvRecord,
	TlvStream, SIGNATURE_TYPES,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{EXPERIMENTAL_OFFER_TYPES, OFFER_DESCRIPTION_TYPE, OFFER_ISSUER_TYPE};
use crate::offers::parse::{Bech32Encode, Bolt12ParseError, Bolt12SemanticError};
use crate::offers::payer::PAYER_METADATA_TYPE;
use crate::offers::static_invoice::StaticInvoice;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{
	BigSize, HighZeroBytesDroppedBigSize, IterableOwned, LengthReadable, Readable, WithoutLength,
	Writeable, Writer,
};
use lightning_types::string::PrintableString;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1;
use bitcoin::secp256k1::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1};

use core::convert::TryFrom;
use core::time::Duration;

#[allow(unused_imports)]
use crate::prelude::*;

/// The type of BOLT 12 invoice that was paid.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Bolt12InvoiceType {
	/// A standard BOLT 12 invoice, allowing proof of payment.
	Bolt12Invoice(Bolt12Invoice),
	/// A static invoice used in async payments, where proof of payment is not possible.
	StaticInvoice(StaticInvoice),
}

impl_writeable_tlv_based_enum!(Bolt12InvoiceType,
	{0, Bolt12Invoice} => (),
	{2, StaticInvoice} => (),
);

/// A paid BOLT 12 invoice with the data needed to construct payer proofs.
///
/// For standard [`Bolt12Invoice`] payments, use [`Self::prove_payer`] or
/// [`Self::prove_payer_derived`] to build a [`PayerProof`] that selectively discloses
/// invoice fields to a third-party verifier.
///
/// For async payments (i.e., [`StaticInvoice`]), payer proofs are not supported and those
/// methods will return [`PayerProofError::IncompatibleInvoice`].
///
/// Surfaced in [`Event::PaymentSent::bolt12_invoice`].
///
/// [`Event::PaymentSent::bolt12_invoice`]: crate::events::Event::PaymentSent::bolt12_invoice
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidBolt12Invoice {
	invoice: Bolt12InvoiceType,
	preimage: PaymentPreimage,
	nonce: Option<Nonce>,
}

impl PaidBolt12Invoice {
	pub(crate) fn new(
		invoice: Bolt12InvoiceType, preimage: PaymentPreimage, nonce: Option<Nonce>,
	) -> Self {
		Self { invoice, preimage, nonce }
	}

	/// The payment preimage proving the invoice was paid.
	pub fn preimage(&self) -> PaymentPreimage {
		self.preimage
	}

	pub(crate) fn invoice_type(&self) -> &Bolt12InvoiceType {
		&self.invoice
	}

	pub(crate) fn nonce(&self) -> Option<Nonce> {
		self.nonce
	}

	/// Returns the [`Bolt12Invoice`] if the payment was for a standard BOLT 12 invoice.
	pub fn bolt12_invoice(&self) -> Option<&Bolt12Invoice> {
		match &self.invoice {
			Bolt12InvoiceType::Bolt12Invoice(invoice) => Some(invoice),
			_ => None,
		}
	}

	/// Returns the [`StaticInvoice`] if the payment was for an async payment.
	pub fn static_invoice(&self) -> Option<&StaticInvoice> {
		match &self.invoice {
			Bolt12InvoiceType::StaticInvoice(invoice) => Some(invoice),
			_ => None,
		}
	}

	/// Creates a [`PayerProofBuilder`] for this paid invoice.
	pub fn prove_payer(
		&self,
	) -> Result<PayerProofBuilder<'_, ExplicitSigningKey>, PayerProofError> {
		let invoice = self.bolt12_invoice().ok_or(PayerProofError::IncompatibleInvoice)?;
		PayerProofBuilder::new(invoice, self.preimage)
	}

	/// Creates a [`PayerProofBuilder`] with a pre-derived signing keypair.
	///
	/// This re-derives the payer signing key, failing early if derivation fails.
	pub fn prove_payer_derived<T: secp256k1::Signing>(
		&self, expanded_key: &ExpandedKey, payment_id: PaymentId, secp_ctx: &Secp256k1<T>,
	) -> Result<PayerProofBuilder<'_, DerivedSigningKey>, PayerProofError> {
		let nonce = self.nonce.ok_or(PayerProofError::KeyDerivationFailed)?;
		let invoice = self.bolt12_invoice().ok_or(PayerProofError::IncompatibleInvoice)?;
		PayerProofBuilder::new_derived(
			invoice,
			self.preimage,
			expanded_key,
			nonce,
			payment_id,
			secp_ctx,
		)
	}
}

const PAYER_PROOF_SIGNATURE_TYPE: u64 = 240;
const PAYER_PROOF_PREIMAGE_TYPE: u64 = 242;
const PAYER_PROOF_OMITTED_TLVS_TYPE: u64 = 244;
const PAYER_PROOF_MISSING_HASHES_TYPE: u64 = 246;
const PAYER_PROOF_LEAF_HASHES_TYPE: u64 = 248;
const PAYER_PROOF_PAYER_SIGNATURE_TYPE: u64 = 250;

/// Human-readable prefix for payer proofs in bech32 encoding.
pub const PAYER_PROOF_HRP: &str = "lnp";

/// Tag for payer signature computation per BOLT 12 signature calculation.
/// Format: "lightning" || messagename || fieldname
const PAYER_SIGNATURE_TAG: &str = concat!("lightning", "payer_proof", "payer_signature");

/// Error when building or verifying a payer proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayerProofError {
	/// The invoice is not a [`Bolt12Invoice`] (e.g., it is a [`StaticInvoice`]).
	///
	/// [`StaticInvoice`]: crate::offers::static_invoice::StaticInvoice
	IncompatibleInvoice,
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
	DecodeError(DecodeError),
}

impl From<SelectiveDisclosureError> for PayerProofError {
	fn from(e: SelectiveDisclosureError) -> Self {
		PayerProofError::MerkleError(e)
	}
}

impl From<DecodeError> for PayerProofError {
	fn from(e: DecodeError) -> Self {
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

/// The signing key was explicitly provided.
pub struct ExplicitSigningKey {}

/// The signing key was derived from an [`ExpandedKey`] and [`Nonce`].
pub struct DerivedSigningKey(Keypair);

/// Builds a [`PayerProof`] from a paid invoice and its preimage.
///
/// By default, only the required fields are included (payer_id, payment_hash,
/// issuer_signing_pubkey). Additional fields can be included for selective disclosure
/// using the `include_*` methods.
pub struct PayerProofBuilder<'a, S: SigningStrategy> {
	invoice: &'a Bolt12Invoice,
	preimage: PaymentPreimage,
	included_types: BTreeSet<u64>,
	signing_strategy: S,
}

/// Sealed trait for signing strategy type-state.
pub trait SigningStrategy: sealed_signing::Sealed {}
impl SigningStrategy for ExplicitSigningKey {}
impl SigningStrategy for DerivedSigningKey {}

mod sealed_signing {
	pub trait Sealed {}
	impl Sealed for super::ExplicitSigningKey {}
	impl Sealed for super::DerivedSigningKey {}
}

impl<'a> PayerProofBuilder<'a, ExplicitSigningKey> {
	/// Create a new builder from an invoice and its payment preimage.
	///
	/// Returns an error if the preimage doesn't match the invoice's payment hash.
	fn new(invoice: &'a Bolt12Invoice, preimage: PaymentPreimage) -> Result<Self, PayerProofError> {
		let computed_hash = sha256::Hash::hash(&preimage.0);
		if computed_hash.as_byte_array() != &invoice.payment_hash().0 {
			return Err(PayerProofError::PreimageMismatch);
		}

		let invoice_bytes = invoice.invoice_bytes();

		let mut included_types = BTreeSet::new();
		included_types.insert(INVOICE_REQUEST_PAYER_ID_TYPE);
		included_types.insert(INVOICE_PAYMENT_HASH_TYPE);
		included_types.insert(INVOICE_NODE_ID_TYPE);

		let has_features_tlv =
			TlvStream::new(invoice_bytes).any(|r| r.r#type == INVOICE_FEATURES_TYPE);
		if has_features_tlv {
			included_types.insert(INVOICE_FEATURES_TYPE);
		}

		Ok(Self { invoice, preimage, included_types, signing_strategy: ExplicitSigningKey {} })
	}

	/// Builds an [`UnsignedPayerProof`] that can be signed with [`UnsignedPayerProof::sign`].
	pub fn build(
		self, payer_note: Option<String>,
	) -> Result<UnsignedPayerProof<'a>, PayerProofError> {
		self.build_unsigned(payer_note)
	}
}

impl<'a> PayerProofBuilder<'a, DerivedSigningKey> {
	/// Create a new builder with a pre-derived signing keypair.
	///
	/// Derives the payer signing key using the same derivation scheme as invoice requests
	/// created with `deriving_signing_pubkey`. Fails early if key derivation fails.
	fn new_derived<T: secp256k1::Signing>(
		invoice: &'a Bolt12Invoice, preimage: PaymentPreimage, expanded_key: &ExpandedKey,
		nonce: Nonce, payment_id: PaymentId, secp_ctx: &Secp256k1<T>,
	) -> Result<Self, PayerProofError> {
		let computed_hash = sha256::Hash::hash(&preimage.0);
		if computed_hash.as_byte_array() != &invoice.payment_hash().0 {
			return Err(PayerProofError::PreimageMismatch);
		}

		let keys = invoice
			.derive_payer_signing_keys(payment_id, nonce, expanded_key, secp_ctx)
			.map_err(|_| PayerProofError::KeyDerivationFailed)?;

		let invoice_bytes = invoice.invoice_bytes();

		let mut included_types = BTreeSet::new();
		included_types.insert(INVOICE_REQUEST_PAYER_ID_TYPE);
		included_types.insert(INVOICE_PAYMENT_HASH_TYPE);
		included_types.insert(INVOICE_NODE_ID_TYPE);

		let has_features_tlv =
			TlvStream::new(invoice_bytes).any(|r| r.r#type == INVOICE_FEATURES_TYPE);
		if has_features_tlv {
			included_types.insert(INVOICE_FEATURES_TYPE);
		}

		Ok(Self { invoice, preimage, included_types, signing_strategy: DerivedSigningKey(keys) })
	}

	/// Builds and signs a [`PayerProof`] using the keypair derived at construction time.
	pub fn build_and_sign(self, payer_note: Option<String>) -> Result<PayerProof, PayerProofError> {
		let secp_ctx = Secp256k1::signing_only();
		let keys = self.signing_strategy.0;
		let unsigned = self.build_unsigned(payer_note)?;
		unsigned.sign(|proof: &UnsignedPayerProof| {
			Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &keys))
		})
	}
}

impl<'a, S: SigningStrategy> PayerProofBuilder<'a, S> {
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

	fn build_unsigned(
		self, payer_note: Option<String>,
	) -> Result<UnsignedPayerProof<'a>, PayerProofError> {
		let invoice_bytes = self.invoice.invoice_bytes();
		let disclosed_fields =
			DisclosedFields::from_records(TlvStream::new(invoice_bytes).filter(|r| {
				self.included_types.contains(&r.r#type) && !SIGNATURE_TYPES.contains(&r.r#type)
			}))?;

		let disclosure = merkle::compute_selective_disclosure(
			TlvStream::new(invoice_bytes).filter(|r| !SIGNATURE_TYPES.contains(&r.r#type)),
			&self.included_types,
		)?;

		let invoice_signature = self.invoice.signature();

		let tagged_hash = payer_signature_hash(payer_note.as_deref(), &disclosure.merkle_root);

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
			payer_note,
			tagged_hash,
		})
	}
}

/// Computes the [`TaggedHash`] for a payer proof signature.
///
/// The payer signature is computed over `H(tag||tag||H(note||merkle_root))`. The inner
/// hash `H(note||merkle_root)` serves as the "merkle root" for [`TaggedHash::from_merkle_root`].
fn payer_signature_hash(note: Option<&str>, merkle_root: &sha256::Hash) -> TaggedHash {
	let mut engine = sha256::Hash::engine();
	if let Some(n) = note {
		engine.input(n.as_bytes());
	}
	engine.input(merkle_root.as_ref());
	let inner_hash = sha256::Hash::from_engine(engine);

	TaggedHash::from_merkle_root(PAYER_SIGNATURE_TAG, inner_hash)
}

/// An unsigned [`PayerProof`] ready for signing.
pub struct UnsignedPayerProof<'a> {
	invoice_signature: Signature,
	preimage: PaymentPreimage,
	payer_id: PublicKey,
	payment_hash: PaymentHash,
	issuer_signing_pubkey: PublicKey,
	invoice_bytes: &'a [u8],
	included_types: BTreeSet<u64>,
	disclosed_fields: DisclosedFields,
	disclosure: SelectiveDisclosure,
	payer_note: Option<String>,
	tagged_hash: TaggedHash,
}

impl AsRef<TaggedHash> for UnsignedPayerProof<'_> {
	fn as_ref(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

/// A function for signing an [`UnsignedPayerProof`].
pub trait SignPayerProofFn {
	/// Signs a [`TaggedHash`] computed over the payer note and the invoice's merkle root.
	fn sign_payer_proof(&self, message: &UnsignedPayerProof) -> Result<Signature, ()>;
}

impl<F> SignPayerProofFn for F
where
	F: Fn(&UnsignedPayerProof) -> Result<Signature, ()>,
{
	fn sign_payer_proof(&self, message: &UnsignedPayerProof) -> Result<Signature, ()> {
		self(message)
	}
}

impl<F> merkle::SignFn<UnsignedPayerProof<'_>> for F
where
	F: SignPayerProofFn,
{
	fn sign(&self, message: &UnsignedPayerProof) -> Result<Signature, ()> {
		self.sign_payer_proof(message)
	}
}

/// Compound value for the payer signature TLV (type 250): a schnorr signature
/// followed by optional UTF-8 note bytes.
struct PayerSignatureWithNote<'a> {
	signature: &'a Signature,
	note_bytes: &'a [u8],
}

impl Writeable for PayerSignatureWithNote<'_> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.signature.write(w)?;
		w.write_all(self.note_bytes)
	}
}

impl UnsignedPayerProof<'_> {
	/// Signs the [`UnsignedPayerProof`] using the given function.
	pub fn sign<F: SignPayerProofFn>(self, sign: F) -> Result<PayerProof, PayerProofError> {
		let pubkey = self.payer_id;
		let payer_signature = merkle::sign_message(sign, &self, pubkey).map_err(|e| match e {
			SignError::Signing => PayerProofError::SigningError,
			SignError::Verification(_) => PayerProofError::InvalidPayerSignature,
		})?;

		let bytes =
			self.serialize_payer_proof(&payer_signature).expect("Vec write should not fail");

		Ok(PayerProof {
			bytes,
			contents: PayerProofContents {
				payer_id: self.payer_id,
				payment_hash: self.payment_hash,
				issuer_signing_pubkey: self.issuer_signing_pubkey,
				preimage: self.preimage,
				invoice_signature: self.invoice_signature,
				payer_signature,
				payer_note: self.payer_note,
				disclosed_fields: self.disclosed_fields,
			},
			merkle_root: self.disclosure.merkle_root,
		})
	}

	fn serialize_payer_proof(&self, payer_signature: &Signature) -> Result<Vec<u8>, io::Error> {
		const PAYER_PROOF_ALLOCATION_SIZE: usize = 512;
		let mut bytes = Vec::with_capacity(PAYER_PROOF_ALLOCATION_SIZE);

		// Preserve TLV ordering by emitting included invoice records below the
		// payer-proof range first, then payer-proof TLVs (240..=250), then any
		// disclosed experimental invoice records above the reserved range.
		for record in TlvStream::new(&self.invoice_bytes)
			.range(0..PAYER_PROOF_SIGNATURE_TYPE)
			.filter(|r| self.included_types.contains(&r.r#type))
		{
			bytes.extend_from_slice(record.record_bytes);
		}

		let note_bytes = self.payer_note.as_deref().map(|n| n.as_bytes()).unwrap_or(&[]);
		let payer_sig = PayerSignatureWithNote { signature: payer_signature, note_bytes };
		let omitted_markers = if self.disclosure.omitted_markers.is_empty() {
			None
		} else {
			Some(IterableOwned(self.disclosure.omitted_markers.iter().map(|m| BigSize(*m))))
		};

		encode_tlv_stream!(&mut bytes, {
			(PAYER_PROOF_SIGNATURE_TYPE, &self.invoice_signature, required),
			(PAYER_PROOF_PREIMAGE_TYPE, &self.preimage, required),
			(PAYER_PROOF_OMITTED_TLVS_TYPE, omitted_markers, option),
			(PAYER_PROOF_MISSING_HASHES_TYPE, &self.disclosure.missing_hashes, optional_vec),
			(PAYER_PROOF_LEAF_HASHES_TYPE, &self.disclosure.leaf_hashes, optional_vec),
			(PAYER_PROOF_PAYER_SIGNATURE_TYPE, &payer_sig, required),
		});

		for record in TlvStream::new(&self.invoice_bytes)
			.range(EXPERIMENTAL_OFFER_TYPES.start..)
			.filter(|r| self.included_types.contains(&r.r#type))
		{
			bytes.extend_from_slice(record.record_bytes);
		}

		Ok(bytes)
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
/// returning an error instead of panicking on untrusted input. It also checks
/// strict ascending TLV type ordering (which covers duplicates).
fn validate_tlv_framing(bytes: &[u8]) -> Result<(), DecodeError> {
	let mut cursor = io::Cursor::new(bytes);
	let mut prev_type: Option<u64> = None;
	while (cursor.position() as usize) < bytes.len() {
		let tlv_type: BigSize =
			Readable::read(&mut cursor).map_err(|_| DecodeError::InvalidValue)?;
		if let Some(prev) = prev_type {
			if tlv_type.0 <= prev {
				return Err(DecodeError::InvalidValue);
			}
		}
		prev_type = Some(tlv_type.0);
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

impl DisclosedFields {
	fn update(&mut self, record: &TlvRecord<'_>) -> Result<(), DecodeError> {
		match record.r#type {
			OFFER_DESCRIPTION_TYPE => {
				self.offer_description = Some(
					String::from_utf8(record.value_bytes.to_vec())
						.map_err(|_| DecodeError::InvalidValue)?,
				);
			},
			OFFER_ISSUER_TYPE => {
				self.offer_issuer = Some(
					String::from_utf8(record.value_bytes.to_vec())
						.map_err(|_| DecodeError::InvalidValue)?,
				);
			},
			INVOICE_CREATED_AT_TYPE => {
				self.invoice_created_at = Some(Duration::from_secs(
					record.read_value::<HighZeroBytesDroppedBigSize<u64>>()?.0,
				));
			},
			INVOICE_AMOUNT_TYPE => {
				self.invoice_amount_msats =
					Some(record.read_value::<HighZeroBytesDroppedBigSize<u64>>()?.0);
			},
			_ => {},
		}

		Ok(())
	}

	fn from_records<'a>(
		records: impl core::iter::Iterator<Item = TlvRecord<'a>>,
	) -> Result<Self, DecodeError> {
		let mut disclosed_fields = DisclosedFields::default();
		for record in records {
			disclosed_fields.update(&record)?;
		}
		Ok(disclosed_fields)
	}
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
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
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
		let mut included_records: Vec<merkle::TlvRecord<'_>> = Vec::new();

		for record in TlvStream::new(&bytes) {
			let tlv_type = record.r#type;
			disclosed_fields.update(&record)?;

			match tlv_type {
				INVOICE_REQUEST_PAYER_ID_TYPE => {
					payer_id = Some(record.read_value()?);
					included_types.insert(tlv_type);
					included_records.push(record);
				},
				INVOICE_PAYMENT_HASH_TYPE => {
					payment_hash = Some(record.read_value()?);
					included_types.insert(tlv_type);
					included_records.push(record);
				},
				INVOICE_NODE_ID_TYPE => {
					issuer_signing_pubkey = Some(record.read_value()?);
					included_types.insert(tlv_type);
					included_records.push(record);
				},
				PAYER_PROOF_SIGNATURE_TYPE => {
					invoice_signature = Some(record.read_value()?);
				},
				PAYER_PROOF_PREIMAGE_TYPE => {
					preimage = Some(record.read_value()?);
				},
				PAYER_PROOF_OMITTED_TLVS_TYPE => {
					let mut cursor = io::Cursor::new(record.value_bytes);
					while (cursor.position() as usize) < record.value_bytes.len() {
						let marker: BigSize = Readable::read(&mut cursor)?;
						omitted_markers.push(marker.0);
					}
				},
				PAYER_PROOF_MISSING_HASHES_TYPE => {
					let WithoutLength(hashes) = LengthReadable::read_from_fixed_length_buffer(
						&mut &record.value_bytes[..],
					)?;
					missing_hashes = hashes;
				},
				PAYER_PROOF_LEAF_HASHES_TYPE => {
					let WithoutLength(hashes) = LengthReadable::read_from_fixed_length_buffer(
						&mut &record.value_bytes[..],
					)?;
					leaf_hashes = hashes;
				},
				PAYER_PROOF_PAYER_SIGNATURE_TYPE => {
					if record.value_bytes.len() < SCHNORR_SIGNATURE_SIZE {
						return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
					}
					let mut cursor = io::Cursor::new(record.value_bytes);
					payer_signature = Some(Readable::read(&mut cursor)?);
					if record.value_bytes.len() > SCHNORR_SIGNATURE_SIZE {
						let note_bytes = &record.value_bytes[SCHNORR_SIGNATURE_SIZE..];
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
						// reconstruction). These are raw bytes the payer selected
						// for disclosure; we don't apply the unknown-even check
						// here because all standard invoice TLV types are even
						// and the verifier will reject any record that doesn't
						// match the original invoice's merkle root.
						included_types.insert(tlv_type);
						included_records.push(record);
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
			Bolt12SemanticError::MissingPayerSigningPubkey,
		))?;
		let payment_hash = payment_hash
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaymentHash))?;
		let issuer_signing_pubkey = issuer_signing_pubkey
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSigningPubkey))?;
		let invoice_signature = invoice_signature
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature))?;
		let preimage = preimage.ok_or(Bolt12ParseError::Decode(DecodeError::InvalidValue))?;
		let payer_signature = payer_signature
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature))?;

		validate_omitted_markers_for_parsing(&omitted_markers, &included_types)
			.map_err(Bolt12ParseError::Decode)?;

		if leaf_hashes.len() != included_records.len() {
			return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
		}

		let merkle_root = merkle::reconstruct_merkle_root(
			&included_records,
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
		let payer_tagged_hash = payer_signature_hash(payer_note.as_deref(), &merkle_root);
		merkle::verify_signature(&payer_signature, &payer_tagged_hash, payer_id)
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
) -> Result<(), DecodeError> {
	let mut inc_iter = included_types.iter().copied().peekable();
	// After implicit TLV0 (marker 0), the first minimized marker would be 1
	let mut expected_next: u64 = 1;
	let mut prev = 0u64;

	for &marker in omitted_markers {
		// MUST NOT contain 0
		if marker == 0 {
			return Err(DecodeError::InvalidValue);
		}

		// MUST NOT contain signature TLV types
		if SIGNATURE_TYPES.contains(&marker) {
			return Err(DecodeError::InvalidValue);
		}

		// MUST be strictly ascending
		if marker <= prev {
			return Err(DecodeError::InvalidValue);
		}

		// MUST NOT contain included TLV types
		if included_types.contains(&marker) {
			return Err(DecodeError::InvalidValue);
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
					return Err(DecodeError::InvalidValue);
				}
			}
			if !found {
				return Err(DecodeError::InvalidValue);
			}
		}

		expected_next = marker + 1;
		prev = marker;
	}

	Ok(())
}

impl core::str::FromStr for PayerProof {
	type Err = Bolt12ParseError;

	fn from_str(s: &str) -> Result<Self, <Self as core::str::FromStr>::Err> {
		Self::from_bech32_str(s)
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
		let disclosed_fields = DisclosedFields::from_records(
			TlvStream::new(&invoice_bytes).filter(|r| included_types.contains(&r.r#type)),
		)
		.unwrap();
		let disclosure =
			compute_selective_disclosure(TlvStream::new(&invoice_bytes), &included_types).unwrap();

		let unsigned = UnsignedPayerProof {
			invoice_signature,
			preimage,
			payer_id,
			payment_hash,
			issuer_signing_pubkey,
			invoice_bytes: &invoice_bytes,
			included_types,
			disclosed_fields,
			tagged_hash: payer_signature_hash(None, &disclosure.merkle_root),
			disclosure,
			payer_note: None,
		};

		unsigned
			.sign(|proof: &UnsignedPayerProof| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
			})
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
		let disclosed_fields = DisclosedFields::from_records(
			TlvStream::new(&invoice_bytes).filter(|r| included_types.contains(&r.r#type)),
		)
		.unwrap();
		let disclosure =
			compute_selective_disclosure(TlvStream::new(&invoice_bytes), &included_types).unwrap();
		assert_eq!(disclosure.omitted_markers, vec![177, 178]);

		let unsigned = UnsignedPayerProof {
			invoice_signature,
			preimage,
			payer_id,
			payment_hash,
			issuer_signing_pubkey,
			invoice_bytes: &invoice_bytes,
			included_types,
			disclosed_fields,
			tagged_hash: payer_signature_hash(None, &disclosure.merkle_root),
			disclosure,
			payer_note: None,
		};

		unsigned
			.sign(|proof: &UnsignedPayerProof| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
			})
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
		let disclosed_fields = DisclosedFields::from_records(
			TlvStream::new(&invoice_bytes).filter(|r| included_types.contains(&r.r#type)),
		)
		.unwrap();
		let disclosure =
			compute_selective_disclosure(TlvStream::new(&invoice_bytes), &included_types).unwrap();

		let unsigned = UnsignedPayerProof {
			invoice_signature,
			preimage,
			payer_id,
			payment_hash,
			issuer_signing_pubkey,
			invoice_bytes: &invoice_bytes,
			included_types,
			disclosed_fields,
			tagged_hash: payer_signature_hash(None, &disclosure.merkle_root),
			disclosure,
			payer_note: None,
		};

		unsigned
			.sign(|proof: &UnsignedPayerProof| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
			})
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

		let result = compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included);
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

		let disclosure =
			compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included).unwrap();

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

		let disclosure =
			compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included).unwrap();

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

		let disclosure =
			compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included).unwrap();

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
		assert!(matches!(result, Err(DecodeError::InvalidValue)));
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

	/// Test that even TLV types outside the signature range are accepted as
	/// passthrough invoice records, while unknown even types inside the
	/// signature range (240..=1000) are rejected.
	///
	/// Non-signature types are invoice TLV records selected for disclosure.
	/// They bypass the unknown-even check because all standard invoice TLV
	/// types are even and the verifier rejects any record not matching the
	/// original invoice's merkle root.
	#[test]
	fn test_parsing_even_type_handling_by_range() {
		use core::convert::TryFrom;

		// Craft minimal TLV streams to test just the parsing logic.
		// These will fail later validation (missing required fields), but the
		// match arm behavior is what we're testing.

		// Case 1: Unknown even type 200 (outside signature range) — should be
		// accepted as a passthrough record. The parse will fail later due to
		// missing required fields, not due to the even type.
		let mut bytes = Vec::new();
		BigSize(200).write(&mut bytes).unwrap();
		BigSize(4).write(&mut bytes).unwrap();
		bytes.extend_from_slice(b"test");

		let result = PayerProof::try_from(bytes);
		// Fails because required fields (payer_id, etc.) are missing — but NOT
		// because of an unknown-even-type rejection.
		match result {
			Err(Bolt12ParseError::InvalidSemantics(_)) => {},
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)) => {
				panic!(
					"Even type 200 was rejected as invalid, but should be accepted as passthrough"
				);
			},
			Ok(_) => panic!("Should fail due to missing required fields"),
			Err(e) => panic!("Unexpected error: {:?}", e),
		}

		// Case 2: Unknown even type 252 (inside signature range) — should be
		// rejected immediately as unknown-even.
		let mut bytes = Vec::new();
		BigSize(252).write(&mut bytes).unwrap();
		BigSize(4).write(&mut bytes).unwrap();
		bytes.extend_from_slice(b"test");

		let result = PayerProof::try_from(bytes);
		match result {
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue)) => {},
			_ => panic!("Even type 252 in signature range should be rejected"),
		}
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
		let paid_invoice =
			PaidBolt12Invoice::new(Bolt12InvoiceType::Bolt12Invoice(invoice), preimage, None);
		let payer_proof = paid_invoice
			.prove_payer()
			.unwrap()
			.build(None)
			.unwrap()
			.sign(|proof: &UnsignedPayerProof| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
			})
			.unwrap();
		let parsed = PayerProof::try_from(payer_proof.bytes().to_vec()).unwrap();

		assert_eq!(parsed.bytes(), payer_proof.bytes());
		assert_eq!(parsed.preimage(), preimage);
		assert_eq!(parsed.payment_hash(), payment_hash);
	}

	#[test]
	fn test_build_with_derived_signing_keys_for_refund_invoice() {
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

		let paid_invoice = PaidBolt12Invoice::new(
			Bolt12InvoiceType::Bolt12Invoice(invoice),
			preimage,
			Some(nonce),
		);
		let payer_proof = paid_invoice
			.prove_payer_derived(&expanded_key, payment_id, &secp_ctx)
			.unwrap()
			.build_and_sign(Some("refund".into()))
			.unwrap();
		let parsed = PayerProof::try_from(payer_proof.bytes().to_vec()).unwrap();

		assert_eq!(parsed.preimage(), preimage);
		assert_eq!(parsed.payment_hash(), payment_hash);
		assert_eq!(parsed.payer_note().map(|note| note.to_string()), Some("refund".to_string()));
	}

	// BOLT 12 payer proof test vectors (from bolt12/payer-proof-test.json).
	// All four vectors share the same invoice and preimage.
	const PAYER_SECRET_HEX: &str =
		"4242424242424242424242424242424242424242424242424242424242424242";
	const INVOICE_HEX: &str = "0010000000000000000000000000000000001621024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382520203e858210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca076027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000a21c00000001000000020003000000000000000400000000000000050000a40467527988a82072cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793aa0203e8b021024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382f04098c093015fb630fa7aeeecebb7af826edc447244d4fab5d535fbf1ca008ff086bcb7d612f105d0aeeaf5711c30af20e8b438d736ca4d774af4cbdc7d855c8f88feb2d05e010142";
	const PREIMAGE_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

	struct PayerProofVector {
		name: &'static str,
		included_types: &'static [u64],
		note: Option<&'static str>,
		leaf_hashes_hex: &'static str,
		omitted_tlvs: &'static [u64],
		missing_hashes_hex: &'static str,
		merkle_root_hex: &'static str,
		bech32: &'static str,
	}

	const PAYER_PROOF_VECTORS: &[PayerProofVector] = &[
		PayerProofVector {
			name: "full_disclosure",
			included_types: &[22, 82, 160, 162, 164, 170, 3000000001],
			note: None,
			leaf_hashes_hex: "8c9057ed88f3c5a6b6441dcac3b5e4cefb3615904d7362b86e78427fb695f4618dc54a97453dee6f207fa5216a30f1567442712ca98852bc789b73885029283cf2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f54f80c94a87383f2a8ef7c3e461c62b67a51da5bccf6cd96a7dbab29bea51fa7849b8b856e1d2a63d9ce7dc1a78e05cbb2def1f5d7709c48e8707e0a59fe51e19e7e4eee6bf56c6c589fe50035490c1a7c91b753cb8007c4b52838a6772f997f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1adc0b8de03f1a0b0531bff146982d7d613ef6e1ef8d3bdd9590971fc18d835ffb7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cbabaab91b367e30fea7026daf9f2590bb7e9cc31db8221f4013c67289e38f22c8",
			omitted_tlvs: &[],
			missing_hashes_hex: "0b510ba4c6884d603159ced2f0ca21e772424b59e52a2191bbfbcf07377805a1",
			merkle_root_hex: "d75cc1c4a81b39f841f8db4e8b3156f73d973f32fc982cdce884f2d396504db1",
			bech32: "lnp1zcssyj7z5vfx29flqlnsuzatppeyu6u9ugtl3ntz3n4k996zg7a5jvuz2gpq86zcyypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k89qwcp87v0tc4rzc87uuxmn0m8l2tfh6aw75s7wz8r56fd299ckt74zqpcr9s9he72nyjs86pfe3vjqzaxups47g3xedv2e4fk877c7v6rgpxgszqhd4w73ddqusdcmjthj7pxprpd57qakmn2jh2dh3kwhezwg7gs3g5qpqqqqqqqqqqqqqqqqqqqqqqqqqq9zrsqqqqqpqqqqqqsqqvqqqqqqqqqqqpqqqqqqqqqqqqzsqq9yq3n4y7vg4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0ya2qgp73vppqf9u9gcjv52n7pl8pc96kzrjfe4ctcshlrxk9r8tv2t5y3amfyec9uzqnrqfxq2lkcc057hwan4m0tuzdmwygujy6natt4f4l0cu5qy07zrted7kztcst59wat6hz8ps4usw3dpc6umv5nthft6vhhras4wglz8jyqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsra3qpdgshfxx3pxkqv2eemf0pj3puaeyyj6eu54zrydml08swdmcqksl3lgpgzxfq4ld3reutf4kgswu4sa4un80kds4jpxhxc4cdeuyylakjh6xrrw9f2t5200wdus8lffpdgc0z4n5gfcje2vg22783xmn3pgzj2pu7t027heshc7wmz0u0sjdgg5pn0cx4u8y3gc5ywaapcnrfu7rmenl2nuqe99gwwpl92800slyv8rzkea9rkjmenmvm948mw4jn049r7ncfxuts4hp62nrm888msd83czuhvk7786awuyufr58qls2t8l9rcv70e8wu6l4d3k938l9qq65jrq60jgmw57tsqrufdfg8zn8wtue0uqers6sqqj8249c6zsedzv2099l8h5fnqjhz9udjvd0ldj57rq6ms9cmcplrg9s2vdl79rfsttavyl0dc0035aam9vsju0urrvrtlahay4h0w0rssm9pakd0m55ke6na2wlx5ehzzcymmngdtfhv526tjat42u3kdn7xrl2wqnd470jty9m06wvx8dcyg05qy7xw2y78rezerayq3hqtyn5aat00khnft954rp9e9xe5rcjwujcf9haa46ngfrszv8pctgspa890llf6qh0emq2gr2lv87ta6ly7vrnk583tcaj0kvv33p0avkstcqszss",
		},
		PayerProofVector {
			name: "minimal_disclosure",
			included_types: &[],
			note: None,
			leaf_hashes_hex: "f2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1a7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cb",
			omitted_tlvs: &[1, 2, 89, 90, 91, 169, 177],
			missing_hashes_hex: "bf8cb2b1d6fa9bcdcab501b59f82c65c506b7f43514737f7197f1fcfeaebad41b9406f4ce526a6a0d4e0b3a63ed89a832e31cb9939dfe1a7b5dd7232d32c02abcd9c44b53b31700c9ed0e3330ce425f7f18fac2fc1d566a34468439274f0e3169f9830f2c3070cfbad13fde30ee36cd7143591164ed12040a9cd595c96840ac9998ab7fa9c743fb9dbdb0d8d46fbe3ad333400bd07f328dcdb6008790bc9d2db3358d8be254efbc28a1f7f9caa8c21432ba93b512d07349764d61386f186471a",
			merkle_root_hex: "d75cc1c4a81b39f841f8db4e8b3156f73d973f32fc982cdce884f2d396504db1",
			bech32: "lnp1tqssxfr986kyx3ygqqkvq6alklcslcvfj834l8lyxqkmafkjx57up2cu4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0yasyypyhs4rzfj320c8uu8qh2cgwf8xhp0zzluv6c5vad3fwsj8hdyn8qhsgzvvpycpt7mrp7n6amkwhda0sfhdc3rjgn204dw4xhalrjsq3lcgd09h6cf0zpws4m402uguxzhjp6958rtndjjdwa90fj7u0kz4erug7gsqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszq05quqsyk26tw5mrakqh7xt9vwkl2dumj44qx6elqkxt3gxkl6r29rn0ace0u0ul6ht44qmjsr0fnjjdf4q6nst8f37mzdgxt33ewvnnhlp576a6u3j6vkq927dn3zt2we3wqxfa58rxvxwgf0h7x86ct7p64n2x3rggwf8fu8rz60esv8jcvrse7adz077xrhrdnt3gdv3ze8dzgzq48x4jhykss9vnxv2klafcaplh8dakrvdgma78tfnxsqt6pln9rwdkcqg0y9un5kmxdvd3039fmau9zsl07w24rppgv46jw6395rnf9my6cfcduvxgud0sc8jm6h47v978nkcnlruyn2z9qvm7p40pey2x9prh0gwyc608s77vlcpj8p4qqpyw42t359pj6yc572t700gnxp9wytcmyc6l7m9fuxp5l5jkaaeuwzrv58ke4lwjjm8204fmu6nxugtqn0wdp4dxaj3tfwtlfqydczeya802mma4u62ed9gcfwffkdq7ynhykzfdl0dw56zguqnpcwz6yq0fetll6ws9m7wczjq6hmpljlwhe8nqua4pu278vnanryvgg",
		},
		PayerProofVector {
			name: "with_note",
			included_types: &[],
			note: Some("test note"),
			leaf_hashes_hex: "f2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1a7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cb",
			omitted_tlvs: &[1, 2, 89, 90, 91, 169, 177],
			missing_hashes_hex: "bf8cb2b1d6fa9bcdcab501b59f82c65c506b7f43514737f7197f1fcfeaebad41b9406f4ce526a6a0d4e0b3a63ed89a832e31cb9939dfe1a7b5dd7232d32c02abcd9c44b53b31700c9ed0e3330ce425f7f18fac2fc1d566a34468439274f0e3169f9830f2c3070cfbad13fde30ee36cd7143591164ed12040a9cd595c96840ac9998ab7fa9c743fb9dbdb0d8d46fbe3ad333400bd07f328dcdb6008790bc9d2db3358d8be254efbc28a1f7f9caa8c21432ba93b512d07349764d61386f186471a",
			merkle_root_hex: "d75cc1c4a81b39f841f8db4e8b3156f73d973f32fc982cdce884f2d396504db1",
			bech32: "lnp1tqssxfr986kyx3ygqqkvq6alklcslcvfj834l8lyxqkmafkjx57up2cu4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0yasyypyhs4rzfj320c8uu8qh2cgwf8xhp0zzluv6c5vad3fwsj8hdyn8qhsgzvvpycpt7mrp7n6amkwhda0sfhdc3rjgn204dw4xhalrjsq3lcgd09h6cf0zpws4m402uguxzhjp6958rtndjjdwa90fj7u0kz4erug7gsqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszq05quqsyk26tw5mrakqh7xt9vwkl2dumj44qx6elqkxt3gxkl6r29rn0ace0u0ul6ht44qmjsr0fnjjdf4q6nst8f37mzdgxt33ewvnnhlp576a6u3j6vkq927dn3zt2we3wqxfa58rxvxwgf0h7x86ct7p64n2x3rggwf8fu8rz60esv8jcvrse7adz077xrhrdnt3gdv3ze8dzgzq48x4jhykss9vnxv2klafcaplh8dakrvdgma78tfnxsqt6pln9rwdkcqg0y9un5kmxdvd3039fmau9zsl07w24rppgv46jw6395rnf9my6cfcduvxgud0sc8jm6h47v978nkcnlruyn2z9qvm7p40pey2x9prh0gwyc608s77vlcpj8p4qqpyw42t359pj6yc572t700gnxp9wytcmyc6l7m9fuxp5l5jkaaeuwzrv58ke4lwjjm8204fmu6nxugtqn0wdp4dxaj3tfwtlfyuphgt5cgcrfg50lvxftvudtmrf7ns44kal2njhfqqqy23vh0v0vn4uv74dv966eq8gmsx3xkgt3nmq6f0kzztcj9xqfcs80g6aj6sde6x2um5yphx7ar9",
		},
		PayerProofVector {
			name: "left_subtree_omitted",
			included_types: &[170],
			note: None,
			leaf_hashes_hex: "f2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1adc0b8de03f1a0b0531bff146982d7d613ef6e1ef8d3bdd9590971fc18d835ffb7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cb",
			omitted_tlvs: &[1, 2, 89, 90, 91, 177],
			missing_hashes_hex: "bf8cb2b1d6fa9bcdcab501b59f82c65c506b7f43514737f7197f1fcfeaebad41b9406f4ce526a6a0d4e0b3a63ed89a832e31cb9939dfe1a7b5dd7232d32c02abcd9c44b53b31700c9ed0e3330ce425f7f18fac2fc1d566a34468439274f0e3169f9830f2c3070cfbad13fde30ee36cd7143591164ed12040a9cd595c96840ac93358d8be254efbc28a1f7f9caa8c21432ba93b512d07349764d61386f186471a",
			merkle_root_hex: "d75cc1c4a81b39f841f8db4e8b3156f73d973f32fc982cdce884f2d396504db1",
			bech32: "lnp1tqssxfr986kyx3ygqqkvq6alklcslcvfj834l8lyxqkmafkjx57up2cu4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0ya2qgp73vppqf9u9gcjv52n7pl8pc96kzrjfe4ctcshlrxk9r8tv2t5y3amfyec9uzqnrqfxq2lkcc057hwan4m0tuzdmwygujy6natt4f4l0cu5qy07zrted7kztcst59wat6hz8ps4usw3dpc6umv5nthft6vhhras4wglz8jyqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsraqxqyp9jkjmk8m2p0uvk2cad75meh9t2qd4n7pvvhzsddl5x528xlm3jlclel4wht2ph9qx7n89y6n2p48qkwnraky6svhrrjue8807rfa4m4er95evq24um8zyk5anzuqvnmgwxvcvusjl0uv04shur4tx5dzxssujwncwx95lnqc09sc8pna66ylauv8wxmxhzs6ez9jw6ysyp2wdt9wfdpq2eye43k97y480hs52ralee25vy9pjh2fm2ykswdyhvntp8ph3ser347yq7t027heshc7wmz0u0sjdgg5pn0cx4u8y3gc5ywaapcnrfu7rmenlqxgux5qqy364fwxs5xtgnznef0eaazvcy4c30rvnrtlmv48scxkupwx7q0c6pvznr0l3g6vz6ltp8mmwrmud80wetyyhrlqcmq6lldlf9dmmncuyxeg0dnt7a99kw5l2nhe4xdcskpx7u6r26dm9zkjuh7jqgms9jf6w74hhmte54j623sjujnv6puf8wfvyjm776af5y3cpxrsu95gq7njhll5aqthuas9yp40krl97a0j0xpem2rc4uwe8mxxgcss",
		},
	];

	fn hex_decode(s: &str) -> Vec<u8> {
		(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
	}

	fn hex_encode(b: &[u8]) -> String {
		b.iter().map(|x| format!("{:02x}", x)).collect()
	}

	/// Split a concatenated hex string into 32-byte hash hex strings.
	fn split_hashes_hex(hex: &str) -> Vec<String> {
		(0..hex.len()).step_by(64).map(|i| hex[i..i + 64].to_string()).collect()
	}

	#[test]
	fn check_against_spec_vectors() {
		let secp_ctx = Secp256k1::new();
		let payer_keys = Keypair::from_secret_key(
			&secp_ctx,
			&SecretKey::from_slice(&hex_decode(PAYER_SECRET_HEX)).unwrap(),
		);

		let invoice = Bolt12Invoice::try_from(hex_decode(INVOICE_HEX))
			.expect("failed to parse invoice from test vector");

		let preimage = PaymentPreimage(hex_decode(PREIMAGE_HEX).try_into().unwrap());

		for vector in PAYER_PROOF_VECTORS {
			let mut builder = PayerProofBuilder::new(&invoice, preimage)
				.unwrap_or_else(|e| panic!("{}: builder failed: {:?}", vector.name, e));
			for &typ in vector.included_types {
				if typ != INVOICE_REQUEST_PAYER_ID_TYPE
					&& typ != INVOICE_PAYMENT_HASH_TYPE
					&& typ != INVOICE_NODE_ID_TYPE
				{
					builder = builder.include_type(typ).unwrap_or_else(|e| {
						panic!("{}: include_type({}) failed: {:?}", vector.name, typ, e)
					});
				}
			}

			let unsigned = builder
				.build_unsigned(vector.note.map(str::to_owned))
				.unwrap_or_else(|e| panic!("{}: build failed: {:?}", vector.name, e));

			let got_leaves: Vec<String> =
				unsigned.disclosure.leaf_hashes.iter().map(|h| hex_encode(h.as_ref())).collect();
			assert_eq!(
				got_leaves,
				split_hashes_hex(vector.leaf_hashes_hex),
				"{}: leaf_hashes mismatch",
				vector.name
			);

			assert_eq!(
				unsigned.disclosure.omitted_markers, vector.omitted_tlvs,
				"{}: omitted_tlvs mismatch",
				vector.name
			);

			let got_missing: Vec<String> =
				unsigned.disclosure.missing_hashes.iter().map(|h| hex_encode(h.as_ref())).collect();
			assert_eq!(
				got_missing,
				split_hashes_hex(vector.missing_hashes_hex),
				"{}: missing_hashes mismatch",
				vector.name
			);

			let got_root = hex_encode(unsigned.disclosure.merkle_root.as_ref());
			assert_eq!(got_root, vector.merkle_root_hex, "{}: merkle_root mismatch", vector.name);

			let proof = unsigned
				.sign(|proof: &UnsignedPayerProof| {
					Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
				})
				.unwrap_or_else(|e| panic!("{}: sign failed: {:?}", vector.name, e));

			assert_eq!(proof.to_string(), vector.bech32, "{}: bech32 mismatch", vector.name);
		}
	}
}
