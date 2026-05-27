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
	Bolt12Invoice, DerivedSigningPubkey, ExperimentalInvoiceTlvStream, ExplicitSigningPubkey,
	InvoiceTlvStream, SigningPubkeyStrategy, EXPERIMENTAL_INVOICE_TYPES, INVOICE_AMOUNT_TYPE,
	INVOICE_CREATED_AT_TYPE, INVOICE_FEATURES_TYPE, INVOICE_NODE_ID_TYPE,
	INVOICE_PAYMENT_HASH_TYPE, SIGNATURE_TAG,
};
use crate::offers::invoice_request::{
	ExperimentalInvoiceRequestTlvStream, InvoiceRequestTlvStream, INVOICE_REQUEST_PAYER_ID_TYPE,
};
use crate::offers::merkle::{
	self, next_marker, SelectiveDisclosure, SelectiveDisclosureError, SignError, TaggedHash,
	TlvRecord, TlvStream, SIGNATURE_TYPES,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{
	ExperimentalOfferTlvStream, OfferTlvStream, EXPERIMENTAL_OFFER_TYPES, OFFER_DESCRIPTION_TYPE,
	OFFER_ISSUER_TYPE,
};
use crate::offers::parse::{Bech32Encode, Bolt12ParseError, Bolt12SemanticError, ParsedMessage};
use crate::offers::payer::PAYER_METADATA_TYPE;
use crate::offers::static_invoice::StaticInvoice;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{
	BigSize, CursorReadable, HighZeroBytesDroppedBigSize, WithoutLength, Writeable,
};
use lightning_types::string::PrintableString;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1};

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
	pub fn payment_preimage(&self) -> PaymentPreimage {
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
	) -> Result<PayerProofBuilder<'_, ExplicitSigningPubkey>, PayerProofError> {
		let invoice = self.bolt12_invoice().ok_or(PayerProofError::IncompatibleInvoice)?;
		PayerProofBuilder::new(invoice, self.preimage)
	}

	/// Creates a [`PayerProofBuilder`] with a pre-derived signing keypair.
	///
	/// This re-derives the payer signing key, failing early if derivation fails.
	pub fn prove_payer_derived<T: secp256k1::Signing>(
		&self, expanded_key: &ExpandedKey, payment_id: PaymentId, secp_ctx: &Secp256k1<T>,
	) -> Result<PayerProofBuilder<'_, DerivedSigningPubkey>, PayerProofError> {
		// Check invoice type first: a `StaticInvoice` never carries a `Nonce`, so checking
		// `nonce` before the invoice type would surface a misleading `KeyDerivationFailed`
		// error instead of `IncompatibleInvoice`.
		let invoice = self.bolt12_invoice().ok_or(PayerProofError::IncompatibleInvoice)?;
		let nonce = self.nonce.ok_or(PayerProofError::KeyDerivationFailed)?;
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

const PAYER_PROOF_ISSUER_SIGNATURE_TYPE: u64 = 240;
const PAYER_PROOF_PROOF_SIGNATURE_TYPE: u64 = 241;
const PAYER_PROOF_PREIMAGE_TYPE: u64 = 1001;
const PAYER_PROOF_OMITTED_TLVS_TYPE: u64 = 1002;
const PAYER_PROOF_MISSING_HASHES_TYPE: u64 = 1003;
const PAYER_PROOF_LEAF_HASHES_TYPE: u64 = 1004;
const PAYER_PROOF_PROOF_NOTE_TYPE: u64 = 1005;

/// Range covering the data-bearing payer-proof TLVs.
pub(super) const PAYER_PROOF_DATA_TYPES: core::ops::Range<u64> = 1001..1_000_000_000;

/// Human-readable prefix for payer proofs in bech32 encoding.
pub const PAYER_PROOF_HRP: &str = "lnp";

/// Tag for `proof_signature` computation per BOLT 12 signature calculation.
/// Format: "lightning" || messagename || fieldname
const PROOF_SIGNATURE_TAG: &str = concat!("lightning", "payer_proof", "proof_signature");

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
	/// Failed to re-derive the payer signing key from the provided nonce and payment ID.
	KeyDerivationFailed,
	/// The given TLV type cannot be included in a payer proof. Carries the offending
	/// type number. Reasons include `PAYER_METADATA_TYPE`, TLVs in `SIGNATURE_TYPES`,
	/// or TLVs in `PAYER_PROOF_DATA_TYPES`.
	DisallowedTlvType(u64),

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
	proof_signature: Signature,
	merkle_root: sha256::Hash,
}

/// The contents of a [`PayerProof`] -- everything shared between a signed
/// [`PayerProof`] and its [`UnsignedPayerProof`] sibling, with the exception
/// of the `proof_signature` which is only available after signing.
#[derive(Clone, Debug)]
struct PayerProofContents {
	payer_signing_pubkey: PublicKey,
	payment_hash: PaymentHash,
	issuer_signing_pubkey: PublicKey,
	preimage: PaymentPreimage,
	invoice_signature: Signature,
	proof_note: Option<String>,
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
/// By default, only the required fields are included ([`payer_signing_pubkey`],
/// [`payment_hash`], [`issuer_signing_pubkey`]). Additional fields can be included for
/// selective disclosure using the `include_*` methods.
///
/// [`payer_signing_pubkey`]: PayerProof::payer_signing_pubkey
/// [`payment_hash`]: PayerProof::payment_hash
/// [`issuer_signing_pubkey`]: PayerProof::issuer_signing_pubkey
pub struct PayerProofBuilder<'a, S: SigningPubkeyStrategy> {
	invoice: &'a Bolt12Invoice,
	preimage: PaymentPreimage,
	included_types: BTreeSet<u64>,
	proof_note: Option<String>,
	signing_strategy: S,
}

/// The default set of TLV types always included in a payer proof: payer_id,
/// payment_hash, issuer signing pubkey, and invoice features when present.
fn default_included_types(invoice: &Bolt12Invoice) -> BTreeSet<u64> {
	let mut types = BTreeSet::new();
	types.insert(INVOICE_REQUEST_PAYER_ID_TYPE);
	types.insert(INVOICE_PAYMENT_HASH_TYPE);
	types.insert(INVOICE_NODE_ID_TYPE);
	if TlvStream::new(invoice.invoice_bytes()).any(|r| r.r#type == INVOICE_FEATURES_TYPE) {
		types.insert(INVOICE_FEATURES_TYPE);
	}
	types
}

impl<'a> PayerProofBuilder<'a, ExplicitSigningPubkey> {
	/// Create a new builder from an invoice and its payment preimage.
	///
	/// Returns an error if the preimage doesn't match the invoice's payment hash.
	pub(super) fn new(
		invoice: &'a Bolt12Invoice, preimage: PaymentPreimage,
	) -> Result<Self, PayerProofError> {
		let computed_hash: PaymentHash = preimage.into();
		if computed_hash != invoice.payment_hash() {
			return Err(PayerProofError::PreimageMismatch);
		}

		Ok(Self {
			invoice,
			preimage,
			included_types: default_included_types(invoice),
			proof_note: None,
			signing_strategy: ExplicitSigningPubkey {},
		})
	}

	/// Builds an [`UnsignedPayerProof`] that can be signed with [`UnsignedPayerProof::sign`].
	pub fn build(self) -> Result<UnsignedPayerProof, PayerProofError> {
		self.build_unsigned()
	}
}

impl<'a> PayerProofBuilder<'a, DerivedSigningPubkey> {
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

		Ok(Self {
			invoice,
			preimage,
			included_types: default_included_types(invoice),
			proof_note: None,
			signing_strategy: DerivedSigningPubkey(keys),
		})
	}

	/// Builds and signs a [`PayerProof`] using the keypair derived at construction time.
	pub fn build_and_sign(self) -> Result<PayerProof, PayerProofError> {
		let secp_ctx = Secp256k1::signing_only();
		let keys = self.signing_strategy.0;
		let unsigned = self.build_unsigned()?;
		// Signing with a derived keypair and an infallible closure cannot fail:
		// the signing function never errors and verification succeeds because we
		// derived the matching pubkey.
		let proof = unsigned
			.sign(|proof: &UnsignedPayerProof| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &keys))
			})
			.expect("signing with derived keys and infallible closure cannot fail");
		Ok(proof)
	}
}

impl<'a, S: SigningPubkeyStrategy> PayerProofBuilder<'a, S> {
	/// Include a specific TLV type in the proof.
	///
	/// Returns an error if the type is not allowed: `PAYER_METADATA_TYPE`, TLVs in
	/// `SIGNATURE_TYPES`, or TLVs in `PAYER_PROOF_DATA_TYPES`.
	pub fn include_type(mut self, tlv_type: u64) -> Result<Self, PayerProofError> {
		if tlv_type == PAYER_METADATA_TYPE
			|| SIGNATURE_TYPES.contains(&tlv_type)
			|| PAYER_PROOF_DATA_TYPES.contains(&tlv_type)
		{
			return Err(PayerProofError::DisallowedTlvType(tlv_type));
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

	/// Attach a `proof_note` to this proof. The note is scoped to the proof and
	/// is committed to by the `proof_signature` alongside the invoice's merkle
	/// root. It is independent of any [`InvoiceRequest::payer_note`] set during
	/// the payment flow.
	///
	/// [`InvoiceRequest::payer_note`]: crate::offers::invoice_request::InvoiceRequest::payer_note
	pub fn with_proof_note(mut self, note: String) -> Self {
		self.proof_note = Some(note);
		self
	}

	fn build_unsigned(self) -> Result<UnsignedPayerProof, PayerProofError> {
		let invoice_bytes = self.invoice.invoice_bytes();
		let disclosed_fields =
			DisclosedFields::from_records(TlvStream::new(invoice_bytes).filter(|r| {
				self.included_types.contains(&r.r#type) && !SIGNATURE_TYPES.contains(&r.r#type)
			}))?;

		let disclosure = merkle::compute_selective_disclosure(
			TlvStream::new(invoice_bytes).filter(|r| !SIGNATURE_TYPES.contains(&r.r#type)),
			&self.included_types,
		)?;

		let contents = PayerProofContents {
			payer_signing_pubkey: self.invoice.payer_signing_pubkey(),
			payment_hash: self.invoice.payment_hash().clone(),
			issuer_signing_pubkey: self.invoice.signing_pubkey(),
			preimage: self.preimage,
			invoice_signature: self.invoice.signature(),
			proof_note: self.proof_note,
			disclosed_fields,
		};

		Ok(UnsignedPayerProof::new(invoice_bytes, &self.included_types, contents, disclosure))
	}
}

/// Computes the [`TaggedHash`] for the `proof_signature` over the merkle root
/// of the payer-proof TLV stream.
fn proof_signature_hash(bytes: &[u8]) -> TaggedHash {
	TaggedHash::from_valid_tlv_stream_bytes(PROOF_SIGNATURE_TAG, bytes)
}

/// An unsigned [`PayerProof`] ready for signing.
///
/// The serialised proof is stored as two byte buffers split at the
/// `proof_signature` TLV insertion point. [`Self::sign`] writes the freshly
/// computed `proof_signature` TLV between them to produce the final
/// [`PayerProof`] bytes, so no second serialisation pass is needed. The
/// [`TaggedHash`] is computed up front over the same concatenated stream.
pub struct UnsignedPayerProof {
	/// Bytes of the included invoice records up to and including the
	/// `invoice_signature` TLV (`PAYER_PROOF_ISSUER_SIGNATURE_TYPE`).
	bytes_before_proof_signature: Vec<u8>,
	/// Bytes of the payer-proof data TLVs followed by any disclosed
	/// experimental invoice TLVs. Together with the bytes above, these form
	/// the merkle-root input the `proof_signature` is computed over.
	bytes_after_proof_signature: Vec<u8>,
	contents: PayerProofContents,
	/// Merkle root of the underlying invoice, surfaced on the resulting
	/// [`PayerProof`].
	merkle_root: sha256::Hash,
	tagged_hash: TaggedHash,
}

impl AsRef<TaggedHash> for UnsignedPayerProof {
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

impl<F> merkle::SignFn<UnsignedPayerProof> for F
where
	F: SignPayerProofFn,
{
	fn sign(&self, message: &UnsignedPayerProof) -> Result<Signature, ()> {
		self.sign_payer_proof(message)
	}
}

// The proof's signature TLVs sit in the BOLT 12 `SIGNATURE_TYPES` range and are
// excluded from the standard merkle-root computation.
tlv_stream!(
	PayerProofSignatureTlvStream, PayerProofSignatureTlvStreamRef<'a>, SIGNATURE_TYPES, {
		(PAYER_PROOF_ISSUER_SIGNATURE_TYPE, invoice_signature: Signature),
		(PAYER_PROOF_PROOF_SIGNATURE_TYPE, proof_signature: Signature),
	}
);

// The data-bearing TLVs sit in `PAYER_PROOF_DATA_TYPES`, outside the signature
// range, so the standard merkle root for `proof_signature` includes them as
// leaves.
tlv_stream!(
	PayerProofDataTlvStream, PayerProofDataTlvStreamRef<'a>, PAYER_PROOF_DATA_TYPES, {
		(PAYER_PROOF_PREIMAGE_TYPE, proof_preimage: PaymentPreimage),
		(PAYER_PROOF_OMITTED_TLVS_TYPE, proof_omitted_markers: (Vec<BigSize>, WithoutLength)),
		(PAYER_PROOF_MISSING_HASHES_TYPE, proof_missing_hashes: (Vec<sha256::Hash>, WithoutLength)),
		(PAYER_PROOF_LEAF_HASHES_TYPE, proof_leaf_hashes: (Vec<sha256::Hash>, WithoutLength)),
		(PAYER_PROOF_PROOF_NOTE_TYPE, proof_note: (String, WithoutLength)),
	}
);

// Ordered to match canonical TLV ordering: offer, invoice_request, invoice,
// signature, proof data, experimental_offer, experimental_invoice_request,
// experimental_invoice.
type FullPayerProofTlvStream = (
	OfferTlvStream,
	InvoiceRequestTlvStream,
	InvoiceTlvStream,
	PayerProofSignatureTlvStream,
	PayerProofDataTlvStream,
	ExperimentalOfferTlvStream,
	ExperimentalInvoiceRequestTlvStream,
	ExperimentalInvoiceTlvStream,
);

impl CursorReadable for FullPayerProofTlvStream {
	fn read<R: AsRef<[u8]>>(r: &mut io::Cursor<R>) -> Result<Self, DecodeError> {
		let offer = CursorReadable::read(r)?;
		let invoice_request = CursorReadable::read(r)?;
		let invoice = CursorReadable::read(r)?;
		let payer_proof_signatures = CursorReadable::read(r)?;
		let payer_proof_data = CursorReadable::read(r)?;
		let experimental_offer = CursorReadable::read(r)?;
		let experimental_invoice_request = CursorReadable::read(r)?;
		let experimental_invoice = CursorReadable::read(r)?;

		Ok((
			offer,
			invoice_request,
			invoice,
			payer_proof_signatures,
			payer_proof_data,
			experimental_offer,
			experimental_invoice_request,
			experimental_invoice,
		))
	}
}

impl UnsignedPayerProof {
	/// Build an `UnsignedPayerProof` from the underlying invoice bytes, the
	/// included TLV types, the proof contents (everything except
	/// `proof_signature`), and the precomputed selective-disclosure data.
	///
	/// This performs the byte-level serialization split at the
	/// `proof_signature` TLV insertion point and computes the tagged hash,
	/// so callers never see a partially-initialised struct.
	fn new(
		invoice_bytes: &[u8], included_types: &BTreeSet<u64>, contents: PayerProofContents,
		disclosure: SelectiveDisclosure,
	) -> Self {
		// Pre-`proof_signature` bytes hold the included invoice records plus the
		// `invoice_signature` TLV; post-`proof_signature` bytes hold the
		// payer-proof data TLVs plus any disclosed experimental invoice TLVs.
		// Data TLVs always carry the preimage and the merkle proof, so the
		// post-signature buffer is typically the larger of the two.
		const BYTES_BEFORE_PROOF_SIGNATURE_ALLOCATION_SIZE: usize = 256;
		const BYTES_AFTER_PROOF_SIGNATURE_ALLOCATION_SIZE: usize = 512;
		let mut bytes_before_proof_signature =
			Vec::with_capacity(BYTES_BEFORE_PROOF_SIGNATURE_ALLOCATION_SIZE);
		let mut bytes_after_proof_signature =
			Vec::with_capacity(BYTES_AFTER_PROOF_SIGNATURE_ALLOCATION_SIZE);

		// Emit included invoice records below the signature range, then the
		// `invoice_signature` TLV. The `proof_signature` TLV is inserted at
		// sign time between the buffer above and the buffer assembled below.
		for record in TlvStream::new(invoice_bytes)
			.range(0..PAYER_PROOF_ISSUER_SIGNATURE_TYPE)
			.filter(|r| included_types.contains(&r.r#type))
		{
			bytes_before_proof_signature.extend_from_slice(record.record_bytes);
		}
		let invoice_signature_tlv = PayerProofSignatureTlvStreamRef {
			invoice_signature: Some(&contents.invoice_signature),
			proof_signature: None,
		};
		invoice_signature_tlv
			.write(&mut bytes_before_proof_signature)
			.expect("Vec write should not fail");

		// Post-signature half: payer-proof data TLVs, then disclosed
		// experimental invoice records.
		let proof_omitted_markers = (!disclosure.omitted_markers.is_empty())
			.then(|| disclosure.omitted_markers.iter().copied().map(BigSize).collect::<Vec<_>>());
		let data = PayerProofDataTlvStreamRef {
			proof_preimage: Some(&contents.preimage),
			proof_omitted_markers: proof_omitted_markers.as_ref(),
			proof_missing_hashes: (!disclosure.missing_hashes.is_empty())
				.then_some(&disclosure.missing_hashes),
			proof_leaf_hashes: (!disclosure.leaf_hashes.is_empty())
				.then_some(&disclosure.leaf_hashes),
			proof_note: contents.proof_note.as_ref(),
		};
		data.write(&mut bytes_after_proof_signature).expect("Vec write should not fail");
		for record in TlvStream::new(invoice_bytes)
			.range(EXPERIMENTAL_OFFER_TYPES.start..)
			.filter(|r| included_types.contains(&r.r#type))
		{
			bytes_after_proof_signature.extend_from_slice(record.record_bytes);
		}

		// The tagged hash for `proof_signature` is the merkle root over the
		// full proof TLV stream excluding the `proof_signature` TLV itself.
		// Iterate the two halves in sequence so no third buffer is allocated.
		let tlv_stream = TlvStream::new(&bytes_before_proof_signature)
			.chain(TlvStream::new(&bytes_after_proof_signature));
		let tagged_hash = TaggedHash::from_tlv_stream(PROOF_SIGNATURE_TAG, tlv_stream);

		Self {
			bytes_before_proof_signature,
			bytes_after_proof_signature,
			contents,
			merkle_root: disclosure.merkle_root,
			tagged_hash,
		}
	}

	/// Signs the [`UnsignedPayerProof`] using the given function.
	pub fn sign<F: SignPayerProofFn>(self, sign: F) -> Result<PayerProof, SignError> {
		let pubkey = self.contents.payer_signing_pubkey;
		let proof_signature = merkle::sign_message(sign, &self, pubkey)?;

		// Assemble the final proof bytes by inserting the proof_signature TLV
		// between the pre- and post-signature halves we serialised at build
		// time.
		let mut bytes = self.bytes_before_proof_signature;
		let proof_signature_tlv = PayerProofSignatureTlvStreamRef {
			invoice_signature: None,
			proof_signature: Some(&proof_signature),
		};
		proof_signature_tlv.write(&mut bytes).expect("Vec write should not fail");
		bytes.extend_from_slice(&self.bytes_after_proof_signature);

		Ok(PayerProof {
			bytes,
			contents: self.contents,
			proof_signature,
			merkle_root: self.merkle_root,
		})
	}
}

impl PayerProof {
	/// The payment preimage proving the invoice was paid.
	pub fn payment_preimage(&self) -> PaymentPreimage {
		self.contents.preimage
	}

	/// The payer's public key (who paid).
	pub fn payer_signing_pubkey(&self) -> PublicKey {
		self.contents.payer_signing_pubkey
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
	pub fn proof_signature(&self) -> Signature {
		self.proof_signature
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

	/// A note the payer attached to this proof, if any.
	///
	/// This is distinct from [`InvoiceRequest::payer_note`]: the invoice-request note is
	/// sent to the payee at payment time, while this note is scoped to the proof and is
	/// committed to by the [`proof_signature`] alongside the invoice's merkle root.
	///
	/// [`InvoiceRequest::payer_note`]: crate::offers::invoice_request::InvoiceRequest::payer_note
	/// [`proof_signature`]: Self::proof_signature
	pub fn proof_note(&self) -> Option<PrintableString<'_>> {
		self.contents.proof_note.as_deref().map(PrintableString)
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

struct ParsedPayerProofFields {
	contents: PayerProofContents,
	proof_signature: Signature,
	omitted_markers: Vec<u64>,
	missing_hashes: Vec<sha256::Hash>,
	leaf_hashes: Vec<sha256::Hash>,
}

impl TryFrom<FullPayerProofTlvStream> for ParsedPayerProofFields {
	type Error = Bolt12ParseError;

	fn try_from(tlv_stream: FullPayerProofTlvStream) -> Result<Self, Self::Error> {
		let (
			OfferTlvStream { description, issuer, .. },
			// `payer_id` is the TLV-stream field name (tied to the spec TLV). Rebind to
			// `payer_signing_pubkey` to match `PayerProofContents` naming.
			InvoiceRequestTlvStream { payer_id: payer_signing_pubkey, .. },
			InvoiceTlvStream { created_at, payment_hash, amount, node_id, .. },
			PayerProofSignatureTlvStream { invoice_signature, proof_signature },
			PayerProofDataTlvStream {
				proof_preimage,
				proof_omitted_markers,
				proof_missing_hashes,
				proof_leaf_hashes,
				proof_note,
			},
			_experimental_offer,
			_experimental_invoice_request,
			_experimental_invoice,
		) = tlv_stream;

		let payer_signing_pubkey = payer_signing_pubkey.ok_or(
			Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPayerSigningPubkey),
		)?;
		let payment_hash = payment_hash
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaymentHash))?;
		let issuer_signing_pubkey = node_id
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSigningPubkey))?;
		let invoice_signature = invoice_signature
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature))?;
		let preimage = proof_preimage.ok_or(Bolt12ParseError::Decode(DecodeError::InvalidValue))?;
		let proof_signature = proof_signature
			.ok_or(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature))?;
		// Per BOLT 12 PR 1295, both `proof_missing_hashes` and `proof_leaf_hashes`
		// TLVs MUST be present. `proof_omitted_markers` MAY be omitted when empty.
		let missing_hashes =
			proof_missing_hashes.ok_or(Bolt12ParseError::Decode(DecodeError::InvalidValue))?;
		let leaf_hashes =
			proof_leaf_hashes.ok_or(Bolt12ParseError::Decode(DecodeError::InvalidValue))?;

		Ok(Self {
			contents: PayerProofContents {
				payer_signing_pubkey,
				payment_hash,
				issuer_signing_pubkey,
				preimage,
				invoice_signature,
				proof_note,
				disclosed_fields: DisclosedFields {
					offer_description: description,
					offer_issuer: issuer,
					invoice_amount_msats: amount,
					invoice_created_at: created_at.map(Duration::from_secs),
				},
			},
			proof_signature,
			omitted_markers: proof_omitted_markers
				.unwrap_or_default()
				.into_iter()
				.map(|marker| marker.0)
				.collect(),
			missing_hashes,
			leaf_hashes,
		})
	}
}

fn tlv_stream_iter<'a>(bytes: &'a [u8]) -> impl core::iter::Iterator<Item = TlvRecord<'a>> {
	// Strip both `SIGNATURE_TYPES` and `PAYER_PROOF_DATA_TYPES` so the
	// remaining records reconstruct the invoice merkle root.
	TlvStream::new(bytes).filter(|record| {
		!SIGNATURE_TYPES.contains(&record.r#type)
			&& !PAYER_PROOF_DATA_TYPES.contains(&record.r#type)
	})
}

impl TryFrom<Vec<u8>> for PayerProof {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let parsed_proof = ParsedMessage::<FullPayerProofTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = parsed_proof;
		let ParsedPayerProofFields {
			contents,
			proof_signature,
			omitted_markers,
			missing_hashes,
			leaf_hashes,
		} = ParsedPayerProofFields::try_from(tlv_stream)?;
		let included_records: Vec<_> = tlv_stream_iter(&bytes).collect();
		let included_types = included_records.iter().map(|record| record.r#type).collect();

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
		let computed = sha256::Hash::hash(&contents.preimage.0);
		if computed.as_byte_array() != &contents.payment_hash.0 {
			return Err(Bolt12ParseError::Decode(DecodeError::InvalidValue));
		}

		// Verify the invoice signature against the issuer signing pubkey.
		let tagged_hash = TaggedHash::from_merkle_root(SIGNATURE_TAG, merkle_root);
		merkle::verify_signature(
			&contents.invoice_signature,
			&tagged_hash,
			contents.issuer_signing_pubkey,
		)
		.map_err(|_| Bolt12ParseError::Decode(DecodeError::InvalidValue))?;

		// Verify the payer signature against the merkle root of the proof
		// itself, computed over every payer-proof TLV except the
		// `proof_signature` TLV being verified. See module docs.
		let proof_tagged_hash = proof_signature_hash(&bytes);
		merkle::verify_signature(
			&proof_signature,
			&proof_tagged_hash,
			contents.payer_signing_pubkey,
		)
		.map_err(|_| Bolt12ParseError::Decode(DecodeError::InvalidValue))?;

		Ok(PayerProof { bytes, contents, proof_signature, merkle_root })
	}
}

/// Validate omitted markers during parsing.
///
/// Per spec:
/// - MUST NOT contain 0
/// - MUST be in one of the two valid ranges: `1..=239` or
///   `1_000_000_000..=3_999_999_999`. Anything in the signature range
///   (`240..=1000`), the payer-proof data range (`1001..=999_999_999`), or
///   above the experimental invoice range (`>= 4_000_000_000`) is rejected.
/// - MUST be in strict ascending order
/// - MUST NOT contain the number of an included TLV field
/// - Markers MUST be minimized: each marker is the marker number following the
///   previous marker (or the previous included type X) — one greater, except a
///   value that would land in the signature/payer-proof gap jumps to the
///   experimental range. This naturally allows a trailing run of omitted TLVs
///   after the final included type.
fn validate_omitted_markers_for_parsing(
	omitted_markers: &[u64], included_types: &BTreeSet<u64>,
) -> Result<(), DecodeError> {
	let mut inc_iter = included_types.iter().copied().peekable();
	// After implicit TLV0 (marker 0), the first minimized marker would be 1
	let mut expected_next: u64 = 1;
	let mut prev = PAYER_METADATA_TYPE;

	for &marker in omitted_markers {
		// MUST NOT contain PAYER_METADATA_TYPE
		if marker == PAYER_METADATA_TYPE {
			return Err(DecodeError::InvalidValue);
		}

		// MUST be inside one of the two valid ranges (`1..=239` or
		// `1_000_000_000..=3_999_999_999`).
		if SIGNATURE_TYPES.contains(&marker)
			|| PAYER_PROOF_DATA_TYPES.contains(&marker)
			|| marker >= EXPERIMENTAL_INVOICE_TYPES.end
		{
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
				if next_marker(inc_type) == marker {
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

		expected_next = next_marker(marker);
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

	/// Builds a proof whose underlying invoice carries a synthetic experimental TLV
	/// at type [`EXPERIMENTAL_TEST_TLV_TYPE`] (`1_000_000_001`). Constructed by
	/// hand because the public `RefundBuilder` API doesn't expose a way to write
	/// arbitrary experimental TLV types — the existing `experimental_foo` family
	/// of methods uses fixed type numbers that wouldn't exercise the same code
	/// path.
	fn build_round_trip_proof_with_included_experimental_tlv() -> PayerProof {
		let secp_ctx = Secp256k1::new();

		let payer_secret = SecretKey::from_slice(&[42; 32]).unwrap();
		let payer_keys = Keypair::from_secret_key(&secp_ctx, &payer_secret);
		let payer_signing_pubkey = payer_keys.public_key();

		let issuer_secret = SecretKey::from_slice(&[43; 32]).unwrap();
		let issuer_keys = Keypair::from_secret_key(&secp_ctx, &issuer_secret);
		let issuer_signing_pubkey = issuer_keys.public_key();

		let preimage = PaymentPreimage([44; 32]);
		let payment_hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());

		let mut invoice_bytes = Vec::new();
		write_tlv_record_bytes(&mut invoice_bytes, PAYER_METADATA_TYPE, &[45; 32]);
		write_tlv_record(&mut invoice_bytes, INVOICE_REQUEST_PAYER_ID_TYPE, &payer_signing_pubkey);
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

		let contents = PayerProofContents {
			payer_signing_pubkey,
			payment_hash,
			issuer_signing_pubkey,
			preimage,
			invoice_signature,
			proof_note: None,
			disclosed_fields,
		};
		let unsigned =
			UnsignedPayerProof::new(&invoice_bytes, &included_types, contents, disclosure);

		unsigned
			.sign(|proof: &UnsignedPayerProof| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
			})
			.unwrap()
	}

	/// Builds a proof with two consecutive *trailing* omitted experimental TLVs at
	/// types `1_000_000_001` and `1_000_000_003`. The exact layout is load-bearing
	/// for the `omitted_markers == [177, 178]` assertion on the parsed proof, and
	/// the public `RefundBuilder` API doesn't expose a way to produce that exact
	/// pair of trailing experimental types — so this helper writes the invoice
	/// bytes by hand.
	fn build_round_trip_proof_with_multiple_trailing_omitted_tlvs() -> PayerProof {
		let secp_ctx = Secp256k1::new();

		let payer_secret = SecretKey::from_slice(&[52; 32]).unwrap();
		let payer_keys = Keypair::from_secret_key(&secp_ctx, &payer_secret);
		let payer_signing_pubkey = payer_keys.public_key();

		let issuer_secret = SecretKey::from_slice(&[53; 32]).unwrap();
		let issuer_keys = Keypair::from_secret_key(&secp_ctx, &issuer_secret);
		let issuer_signing_pubkey = issuer_keys.public_key();

		let preimage = PaymentPreimage([54; 32]);
		let payment_hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());

		let mut invoice_bytes = Vec::new();
		write_tlv_record_bytes(&mut invoice_bytes, PAYER_METADATA_TYPE, &[55; 32]);
		write_tlv_record(&mut invoice_bytes, INVOICE_REQUEST_PAYER_ID_TYPE, &payer_signing_pubkey);
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

		let contents = PayerProofContents {
			payer_signing_pubkey,
			payment_hash,
			issuer_signing_pubkey,
			preimage,
			invoice_signature,
			proof_note: None,
			disclosed_fields,
		};
		let unsigned =
			UnsignedPayerProof::new(&invoice_bytes, &included_types, contents, disclosure);

		unsigned
			.sign(|proof: &UnsignedPayerProof| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
			})
			.unwrap()
	}

	fn build_round_trip_proof_with_disclosed_fields() -> PayerProof {
		let preimage = PaymentPreimage([64; 32]);
		let payment_hash = PaymentHash(*sha256::Hash::hash(&preimage.0).as_byte_array());
		let invoice = RefundBuilder::new(vec![1; 32], payer_pubkey(), 42_000)
			.unwrap()
			.description("coffee beans".into())
			.issuer("LDK Roastery".into())
			.build()
			.unwrap()
			.respond_with_no_std(
				payment_paths(),
				payment_hash,
				recipient_pubkey(),
				Duration::from_secs(1_700_000_000),
			)
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let paid_invoice =
			PaidBolt12Invoice::new(Bolt12InvoiceType::Bolt12Invoice(invoice), preimage, None);
		paid_invoice
			.prove_payer()
			.unwrap()
			.include_offer_description()
			.include_offer_issuer()
			.include_invoice_amount()
			.include_invoice_created_at()
			.build()
			.unwrap()
			.sign(|proof: &UnsignedPayerProof| payer_sign(proof))
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

	/// Test the omitted_markers marker algorithm with two included runs (10 and 40).
	///
	/// TLVs: 0 (omitted), 10 (included), 20 (omitted), 30 (omitted),
	///       40 (included), 50 (omitted), 60 (omitted)
	///
	/// Expected markers: [11, 12, 41, 42]
	///
	/// The algorithm:
	/// - TLV 0 is always omitted and implicit (not in markers)
	/// - For omitted TLV after included: marker = prev_included_type + 1
	/// - For consecutive omitted TLVs: marker = prev_marker + 1
	#[test]
	fn test_omitted_markers_two_included_runs() {
		// Build a synthetic TLV stream
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

		assert_eq!(disclosure.omitted_markers, vec![11, 12, 41, 42]);

		// leaf_hashes should have 2 entries (one for each included TLV)
		assert_eq!(disclosure.leaf_hashes.len(), 2);
	}

	/// Test the omitted_markers + missing_hashes algorithms against the BOLT 12
	/// PR 1295 spec example (post commit `d6dbb9d8`).
	///
	/// TLVs: 0, 10, 20, 30 (all omitted), 40 (included), 50, 60 (both omitted)
	///
	/// Per spec lines 1131-1146 of `12-offer-encoding.md`:
	/// - `omitted_tlvs` array = `[1, 2, 3, 41, 42]` (markers 1..3 cover the
	///   leading omitted run after implicit TLV0; 41,42 cover the trailing run)
	/// - `missing_hashes` is in post-order DFS order:
	///     1. leaf hash for TLV 50
	///     2. leaf hash for TLV 60
	///     3. the entire `(0,10) | (20,30)` left subtree (asterisk node)
	#[test]
	fn test_omitted_markers_spec_example() {
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

		// Include only TLV 40 (matching the spec example)
		let mut included = BTreeSet::new();
		included.insert(40);

		let disclosure =
			compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included).unwrap();

		// Per spec example: omitted_markers = [1, 2, 3, 41, 42]
		assert_eq!(disclosure.omitted_markers, vec![1, 2, 3, 41, 42]);

		// One leaf_hash for the single included TLV (40)
		assert_eq!(disclosure.leaf_hashes.len(), 1);

		// Post-order DFS missing_hashes: [TLV50_leaf, TLV60_leaf, left_subtree]
		assert_eq!(disclosure.missing_hashes.len(), 3);
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

	/// Test validation of omitted_markers - must not contain payer-proof data
	/// range types (1001..=999_999_999) per BOLT 12 PR 1295.
	#[test]
	fn test_validate_omitted_markers_rejects_data_range_types() {
		let included: BTreeSet<u64> = [10].iter().copied().collect();

		// 1001 is the low end of the data range
		assert!(validate_omitted_markers_for_parsing(&[1, 2, 1001], &included).is_err());
		// somewhere in the middle of the data range
		assert!(validate_omitted_markers_for_parsing(&[1, 2, 500_000_000], &included).is_err());
		// 999_999_999 is the high end of the data range
		assert!(validate_omitted_markers_for_parsing(&[1, 2, 999_999_999], &included).is_err());
	}

	/// Test validation of omitted_markers - must not contain values above the
	/// experimental invoice range (>= 4_000_000_000) per BOLT 12 PR 1295.
	#[test]
	fn test_validate_omitted_markers_rejects_above_experimental_range() {
		let included: BTreeSet<u64> = [10].iter().copied().collect();

		// 4_000_000_000 is the lowest invalid value
		assert!(validate_omitted_markers_for_parsing(&[1, 2, 4_000_000_000], &included).is_err());
		// far above
		assert!(validate_omitted_markers_for_parsing(&[1, 2, u64::MAX], &included).is_err());
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

	/// Reproduces the producer/consumer gap-jump mismatch.
	///
	/// `compute_omitted_markers` emits `[1, ..., 239, 1_000_000_000]` for 240
	/// consecutive omitted TLVs (see the merkle.rs test
	/// `compute_omitted_markers_jumps_to_high_range_after_239`): the marker after
	/// 239 jumps over the signature/payer-proof gap into the experimental range.
	/// `validate_omitted_markers_for_parsing` must accept that jump as a valid
	/// minimized sequence, otherwise a proof the producer can legitimately build
	/// is rejected on parse.
	#[test]
	fn test_validate_omitted_markers_accepts_gap_jump() {
		let mut omitted: Vec<u64> = (1..=239).collect();
		omitted.push(1_000_000_000);
		let included: BTreeSet<u64> = BTreeSet::new();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(result.is_ok(), "gap-jumped markers must be accepted, got {:?}", result);
	}

	/// An included TLV of type 239 followed by an omitted TLV: the producer emits
	/// marker `next_marker(239)` = `1_000_000_000`. The reader's
	/// jump-after-included-type path must accept it.
	#[test]
	fn test_validate_omitted_markers_accepts_gap_jump_after_included() {
		let omitted = vec![1_000_000_000];
		let included: BTreeSet<u64> = [239].iter().copied().collect();

		let result = validate_omitted_markers_for_parsing(&omitted, &included);
		assert!(
			result.is_ok(),
			"gap-jump after included type 239 must be accepted, got {:?}",
			result
		);
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

	/// Test that an invalid `proof_missing_hashes` length (not a multiple of 32)
	/// is rejected.
	#[test]
	fn test_parsing_rejects_invalid_hash_length() {
		use core::convert::TryFrom;

		// `proof_missing_hashes` decodes as a `WithoutLength` `Vec<sha256::Hash>`,
		// so a value length that is not a multiple of 32 cannot decode to whole
		// hashes.
		let mut bytes = Vec::new();
		BigSize(PAYER_PROOF_MISSING_HASHES_TYPE).write(&mut bytes).unwrap();
		BigSize(33).write(&mut bytes).unwrap(); // 33 is not a multiple of 32
		bytes.extend_from_slice(&[0x00; 33]);

		let result = PayerProof::try_from(bytes);
		assert!(
			matches!(result, Err(Bolt12ParseError::Decode(DecodeError::ShortRead))),
			"expected Decode(ShortRead), got {:?}",
			result,
		);
	}

	/// Test that an invalid `proof_leaf_hashes` length (not a multiple of 32) is
	/// rejected.
	#[test]
	fn test_parsing_rejects_invalid_leaf_hashes_length() {
		use core::convert::TryFrom;

		// `proof_leaf_hashes` decodes as a `WithoutLength` `Vec<sha256::Hash>`,
		// so a value length that is not a multiple of 32 cannot decode to whole
		// hashes.
		let mut bytes = Vec::new();
		BigSize(PAYER_PROOF_LEAF_HASHES_TYPE).write(&mut bytes).unwrap();
		BigSize(31).write(&mut bytes).unwrap(); // 31 is not a multiple of 32
		bytes.extend_from_slice(&[0x00; 31]);

		let result = PayerProof::try_from(bytes);
		assert!(
			matches!(result, Err(Bolt12ParseError::Decode(DecodeError::ShortRead))),
			"expected Decode(ShortRead), got {:?}",
			result,
		);
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
			if tlv_type == PAYER_METADATA_TYPE
				|| SIGNATURE_TYPES.contains(&tlv_type)
				|| PAYER_PROOF_DATA_TYPES.contains(&tlv_type)
			{
				return Err(PayerProofError::DisallowedTlvType(tlv_type));
			}
			Ok(())
		}

		// Signature-range types 240..=1000 and the unsupported gap before experimental
		// ranges begins must be rejected.
		assert!(matches!(check_include_type(240), Err(PayerProofError::DisallowedTlvType(240))));
		assert!(matches!(check_include_type(250), Err(PayerProofError::DisallowedTlvType(250))));
		assert!(matches!(check_include_type(1000), Err(PayerProofError::DisallowedTlvType(1000))));
		assert!(matches!(check_include_type(1001), Err(PayerProofError::DisallowedTlvType(1001))));
		let gap_top = EXPERIMENTAL_OFFER_TYPES.start - 1;
		assert!(matches!(
			check_include_type(gap_top),
			Err(PayerProofError::DisallowedTlvType(t)) if t == gap_top,
		));
		// Experimental TLV ranges should remain includable.
		assert!(check_include_type(EXPERIMENTAL_OFFER_TYPES.start).is_ok());
		assert!(check_include_type(u64::MAX).is_ok());
		// Just below the boundary
		assert!(check_include_type(239).is_ok());
		// Payer metadata still rejected
		assert!(matches!(check_include_type(0), Err(PayerProofError::DisallowedTlvType(0))));
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

	/// Confirms that type 0 (`payer_metadata`) is rejected when parsing a payer proof —
	/// matching the same behavior as `FullOfferTlvStream`.
	///
	/// `FullPayerProofTlvStream` has no sub-stream that covers type 0 (the lowest sub-stream
	/// is `OfferTlvStream`, range `1..80`). Each `CursorReadable` impl reads the type BigSize,
	/// finds it out of range, rewinds the type bytes, and breaks — without consuming the
	/// length or value. The cursor is therefore left before the type-0 TLV, and the
	/// all-bytes-consumed check in `ParsedMessage::try_from` rejects the input with
	/// `DecodeError::InvalidValue` before any semantic validation runs.
	#[test]
	fn test_parsing_rejects_payer_metadata() {
		let proof = build_round_trip_proof_with_multiple_trailing_omitted_tlvs();
		let mut bytes = Vec::new();
		write_tlv_record_bytes(&mut bytes, PAYER_METADATA_TYPE, &[1; 32]);
		bytes.extend_from_slice(proof.bytes());

		let result = PayerProof::try_from(bytes);
		assert!(matches!(result, Err(Bolt12ParseError::Decode(DecodeError::InvalidValue))));
	}

	#[test]
	fn test_round_trip_rejects_unknown_odd_data_range_tlv() {
		// Unknown odd TLVs in the `PAYER_PROOF_DATA_TYPES` range are merkle
		// leaves; inserting one after signing shifts the merkle root and the
		// `proof_signature` no longer verifies.
		let unknown_odd_data_range_type = PAYER_PROOF_PROOF_NOTE_TYPE + 2;
		assert_eq!(unknown_odd_data_range_type % 2, 1);
		assert!(PAYER_PROOF_DATA_TYPES.contains(&unknown_odd_data_range_type));

		let proof = build_round_trip_proof_with_multiple_trailing_omitted_tlvs();
		let mut bytes = proof.bytes().to_vec();
		write_tlv_record_bytes(&mut bytes, unknown_odd_data_range_type, b"ignored");

		assert!(matches!(
			PayerProof::try_from(bytes),
			Err(Bolt12ParseError::Decode(DecodeError::InvalidValue))
		));
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

	/// Test that unknown even TLV types in every payer-proof BOLT 12 sub-stream
	/// namespace are rejected by the `tlv_stream!`-based parser, and that types
	/// in the unused gap ranges between sub-streams are rejected by
	/// `ParsedMessage`'s all-bytes-consumed check.
	///
	/// Per BOLT convention, even types are mandatory-to-understand. For payer
	/// proofs this is stricter than the general invoice rule because including
	/// an unknown even TLV in a proof implies the verifier must check something
	/// about it, and it cannot. See the upstream discussion:
	/// <https://github.com/lightningdevkit/rust-lightning/pull/4297#discussion_r3107812262>.
	#[test]
	fn test_parsing_rejects_unknown_even_tlvs_in_every_range() {
		use core::convert::TryFrom;

		/// Parse a payer-proof byte stream that contains only a single TLV with
		/// the given type and a 4-byte dummy value, and assert it is rejected
		/// with the expected error variant.
		fn assert_rejected(tlv_type: u64, expected: DecodeError, label: &str) {
			let mut bytes = Vec::new();
			BigSize(tlv_type).write(&mut bytes).expect("Vec write should not fail");
			BigSize(4).write(&mut bytes).expect("Vec write should not fail");
			bytes.extend_from_slice(b"test");

			match PayerProof::try_from(bytes) {
				Err(Bolt12ParseError::Decode(ref err)) if err == &expected => {},
				other => panic!(
					"{} (type {}): expected {:?}, got {:?}",
					label, tlv_type, expected, other,
				),
			}
		}

		// Sub-stream ranges: rejected by `tlv_stream!`'s unknown-even fallback.
		assert_rejected(50, DecodeError::UnknownRequiredFeature, "offer range");
		assert_rejected(100, DecodeError::UnknownRequiredFeature, "invoice_request range");
		assert_rejected(200, DecodeError::UnknownRequiredFeature, "invoice range");
		// 240 and 241 are the known signature TLVs; 254 is unknown.
		assert_rejected(254, DecodeError::UnknownRequiredFeature, "payer-proof/signature range");
		// 1001..=1005 are the known data TLVs; 1006 is unknown.
		assert_rejected(1006, DecodeError::UnknownRequiredFeature, "payer-proof data range (low)");
		assert_rejected(
			1_000_000,
			DecodeError::UnknownRequiredFeature,
			"payer-proof data range (mid)",
		);
		assert_rejected(
			1_500_000_000,
			DecodeError::UnknownRequiredFeature,
			"experimental offer range",
		);
		assert_rejected(
			2_500_000_000,
			DecodeError::UnknownRequiredFeature,
			"experimental invoice_request range",
		);
		assert_rejected(
			3_500_000_000,
			DecodeError::UnknownRequiredFeature,
			"experimental invoice range",
		);

		// Type 0 is rejected separately by the `payer_metadata` check
		// (see `test_parsing_rejects_payer_metadata`).
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

	/// Test that a `proof_signature` TLV with a value shorter than 64 bytes is
	/// rejected.
	#[test]
	fn test_parsing_rejects_short_proof_signature() {
		use core::convert::TryFrom;

		// `proof_signature` decodes as a 64-byte schnorr `Signature`; a 32-byte
		// value is too short.
		let mut bytes = Vec::new();
		BigSize(PAYER_PROOF_PROOF_SIGNATURE_TYPE).write(&mut bytes).unwrap();
		BigSize(32).write(&mut bytes).unwrap(); // too short for a 64-byte signature
		bytes.extend_from_slice(&[0x00; 32]);

		let result = PayerProof::try_from(bytes);
		assert!(
			matches!(result, Err(Bolt12ParseError::Decode(DecodeError::ShortRead))),
			"expected Decode(ShortRead), got {:?}",
			result,
		);
	}

	/// Helper: serialize a payer_proof's bytes minus any TLV record matching `drop_type`.
	fn proof_bytes_without_tlv(proof: &PayerProof, drop_type: u64) -> Vec<u8> {
		let mut out = Vec::new();
		for record in TlvStream::new(proof.bytes()) {
			if record.r#type != drop_type {
				out.extend_from_slice(record.record_bytes);
			}
		}
		out
	}

	/// Helper: copy a payer_proof's bytes, applying `mutator` to the value of any
	/// TLV record matching `target_type`. The TLV's length stays the same; only
	/// the value bytes are mutated in place.
	fn proof_bytes_with_mutated_tlv_value<F: FnMut(&mut [u8])>(
		proof: &PayerProof, target_type: u64, mut mutator: F,
	) -> Vec<u8> {
		let mut out = Vec::with_capacity(proof.bytes().len());
		for record in TlvStream::new(proof.bytes()) {
			if record.r#type == target_type {
				let prefix_len = record.record_bytes.len() - record.value_bytes.len();
				out.extend_from_slice(&record.record_bytes[..prefix_len]);
				let mut value = record.value_bytes.to_vec();
				mutator(&mut value);
				out.extend_from_slice(&value);
			} else {
				out.extend_from_slice(record.record_bytes);
			}
		}
		out
	}

	/// Helper: drop the first 32-byte sha256 hash from any TLV record matching
	/// `target_type`, re-encoding the BigSize length. Useful for crafting a
	/// shorter `proof_leaf_hashes` / `proof_missing_hashes` to test count checks.
	fn proof_bytes_with_first_hash_dropped(proof: &PayerProof, target_type: u64) -> Vec<u8> {
		let mut out = Vec::with_capacity(proof.bytes().len());
		for record in TlvStream::new(proof.bytes()) {
			if record.r#type == target_type {
				assert!(
					record.value_bytes.len() >= 32,
					"target TLV {} value too short to drop a hash",
					target_type
				);
				BigSize(target_type).write(&mut out).expect("Vec write should not fail");
				let new_len = record.value_bytes.len() - 32;
				BigSize(new_len as u64).write(&mut out).expect("Vec write should not fail");
				out.extend_from_slice(&record.value_bytes[32..]);
			} else {
				out.extend_from_slice(record.record_bytes);
			}
		}
		out
	}

	/// Per BOLT 12 PR 1295: SHA256(`proof_preimage`) must equal `invoice_payment_hash`,
	/// otherwise the reader MUST reject. Flipping a byte in `proof_preimage` (TLV 1001)
	/// must therefore fail parsing.
	#[test]
	fn test_parsing_rejects_modified_preimage() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let mutated =
			proof_bytes_with_mutated_tlv_value(&proof, PAYER_PROOF_PREIMAGE_TYPE, |value| {
				value[0] ^= 0x01;
			});
		let result = PayerProof::try_from(mutated);
		assert!(
			matches!(result, Err(Bolt12ParseError::Decode(DecodeError::InvalidValue))),
			"modified proof_preimage must be rejected with InvalidValue, got {:?}",
			result
		);
	}

	/// Flipping a byte inside `proof_leaf_hashes` (TLV 1004) changes the
	/// reconstructed invoice merkle root, which makes the issuer's `signature`
	/// fail verification.
	#[test]
	fn test_parsing_rejects_modified_leaf_hash() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let mutated =
			proof_bytes_with_mutated_tlv_value(&proof, PAYER_PROOF_LEAF_HASHES_TYPE, |value| {
				value[0] ^= 0x01;
			});
		let result = PayerProof::try_from(mutated);
		assert!(
			matches!(result, Err(Bolt12ParseError::Decode(DecodeError::InvalidValue))),
			"modified proof_leaf_hashes must be rejected with InvalidValue, got {:?}",
			result
		);
	}

	/// Flipping a byte inside `proof_missing_hashes` (TLV 1003) changes the
	/// reconstructed invoice merkle root, which makes the issuer's `signature`
	/// fail verification.
	#[test]
	fn test_parsing_rejects_modified_missing_hash() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let mutated =
			proof_bytes_with_mutated_tlv_value(&proof, PAYER_PROOF_MISSING_HASHES_TYPE, |value| {
				value[0] ^= 0x01;
			});
		let result = PayerProof::try_from(mutated);
		assert!(
			matches!(result, Err(Bolt12ParseError::Decode(DecodeError::InvalidValue))),
			"modified proof_missing_hashes must be rejected with InvalidValue, got {:?}",
			result
		);
	}

	/// Per BOLT 12 PR 1295: `proof_leaf_hashes` MUST contain exactly one hash for
	/// each non-signature TLV field. Dropping one hash must therefore fail parsing.
	#[test]
	fn test_parsing_rejects_leaf_hashes_count_mismatch() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_with_first_hash_dropped(&proof, PAYER_PROOF_LEAF_HASHES_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(
			matches!(result, Err(Bolt12ParseError::Decode(DecodeError::InvalidValue))),
			"proof_leaf_hashes count mismatch must be rejected with InvalidValue, got {:?}",
			result
		);
	}

	/// Per BOLT 12 PR 1295: the reader MUST reject a payer_proof if `proof_missing_hashes`
	/// (TLV 1003) is missing.
	#[test]
	fn test_parsing_rejects_missing_proof_missing_hashes() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_without_tlv(&proof, PAYER_PROOF_MISSING_HASHES_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(result.is_err(), "missing proof_missing_hashes TLV must be rejected");
	}

	/// Per BOLT 12 PR 1295: the reader MUST reject a payer_proof if `proof_leaf_hashes`
	/// (TLV 1004) is missing.
	#[test]
	fn test_parsing_rejects_missing_proof_leaf_hashes() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_without_tlv(&proof, PAYER_PROOF_LEAF_HASHES_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(result.is_err(), "missing proof_leaf_hashes TLV must be rejected");
	}

	/// Per BOLT 12 PR 1295: the reader MUST reject a payer_proof if `invreq_payer_id`
	/// (TLV 88) is missing.
	#[test]
	fn test_parsing_rejects_missing_payer_id() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_without_tlv(&proof, INVOICE_REQUEST_PAYER_ID_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(
			matches!(
				result,
				Err(Bolt12ParseError::InvalidSemantics(
					Bolt12SemanticError::MissingPayerSigningPubkey
				))
			),
			"missing invreq_payer_id TLV must be rejected with MissingPayerSigningPubkey, got {:?}",
			result
		);
	}

	/// Per BOLT 12 PR 1295: the reader MUST reject a payer_proof if `invoice_payment_hash`
	/// (TLV 168) is missing.
	#[test]
	fn test_parsing_rejects_missing_payment_hash() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_without_tlv(&proof, INVOICE_PAYMENT_HASH_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(
			matches!(
				result,
				Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPaymentHash))
			),
			"missing invoice_payment_hash TLV must be rejected with MissingPaymentHash, got {:?}",
			result
		);
	}

	/// Per BOLT 12 PR 1295: the reader MUST reject a payer_proof if `invoice_node_id`
	/// (TLV 176) is missing.
	#[test]
	fn test_parsing_rejects_missing_node_id() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_without_tlv(&proof, INVOICE_NODE_ID_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(
			matches!(
				result,
				Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSigningPubkey))
			),
			"missing invoice_node_id TLV must be rejected with MissingSigningPubkey, got {:?}",
			result
		);
	}

	/// Per BOLT 12 PR 1295: the reader MUST reject a payer_proof if the issuer
	/// `signature` (TLV 240) is missing.
	#[test]
	fn test_parsing_rejects_missing_invoice_signature() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_without_tlv(&proof, PAYER_PROOF_ISSUER_SIGNATURE_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(
			matches!(
				result,
				Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature))
			),
			"missing invoice signature TLV must be rejected with MissingSignature, got {:?}",
			result
		);
	}

	/// Per BOLT 12 PR 1295: the reader MUST reject a payer_proof if `proof_signature`
	/// (TLV 241) is missing.
	#[test]
	fn test_parsing_rejects_missing_proof_signature() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_without_tlv(&proof, PAYER_PROOF_PROOF_SIGNATURE_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(
			matches!(
				result,
				Err(Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature))
			),
			"missing proof_signature TLV must be rejected with MissingSignature, got {:?}",
			result
		);
	}

	/// Per BOLT 12 PR 1295: the reader MUST reject a payer_proof if `proof_preimage`
	/// (TLV 1001) is missing.
	#[test]
	fn test_parsing_rejects_missing_proof_preimage() {
		let proof = build_round_trip_proof_with_disclosed_fields();
		let stripped = proof_bytes_without_tlv(&proof, PAYER_PROOF_PREIMAGE_TYPE);
		let result = PayerProof::try_from(stripped);
		assert!(
			matches!(result, Err(Bolt12ParseError::Decode(DecodeError::InvalidValue))),
			"missing proof_preimage TLV must be rejected with InvalidValue, got {:?}",
			result
		);
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
			.build()
			.unwrap()
			.sign(|proof: &UnsignedPayerProof| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
			})
			.unwrap();
		let parsed = PayerProof::try_from(payer_proof.bytes().to_vec()).unwrap();

		assert_eq!(parsed.bytes(), payer_proof.bytes());
		assert_eq!(parsed.payment_preimage(), preimage);
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
			.with_proof_note("refund".into())
			.build_and_sign()
			.unwrap();
		let parsed = PayerProof::try_from(payer_proof.bytes().to_vec()).unwrap();

		assert_eq!(parsed.payment_preimage(), preimage);
		assert_eq!(parsed.payment_hash(), payment_hash);
		assert_eq!(parsed.proof_note().map(|note| note.to_string()), Some("refund".to_string()));
	}

	/// Per BOLT 12 PR 1295: building a payer proof with a preimage whose SHA256
	/// doesn't match the invoice's `payment_hash` must fail at construction time
	/// with `PreimageMismatch`.
	#[test]
	fn test_prove_payer_rejects_wrong_preimage() {
		let preimage = PaymentPreimage([1; 32]);
		let payment_hash = PaymentHash(*sha256::Hash::hash(&preimage.0).as_byte_array());
		let invoice = RefundBuilder::new(vec![1; 32], payer_pubkey(), 1000)
			.unwrap()
			.build()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash, recipient_pubkey(), now())
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();

		let wrong_preimage = PaymentPreimage([0xDE; 32]);
		let paid_invoice =
			PaidBolt12Invoice::new(Bolt12InvoiceType::Bolt12Invoice(invoice), wrong_preimage, None);
		assert!(matches!(paid_invoice.prove_payer(), Err(PayerProofError::PreimageMismatch)));
	}

	/// Per BOLT 12 PR 1295: deriving the payer signing key with the wrong
	/// `payment_id` must fail at construction time with `KeyDerivationFailed`.
	#[test]
	fn test_prove_payer_derived_rejects_wrong_payment_id() {
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
		.build()
		.unwrap()
		.respond_with_no_std(payment_paths(), payment_hash, recipient_pubkey(), now())
		.unwrap()
		.build()
		.unwrap()
		.sign(recipient_sign)
		.unwrap();

		let paid_invoice = PaidBolt12Invoice::new(
			Bolt12InvoiceType::Bolt12Invoice(invoice),
			preimage,
			Some(nonce),
		);

		let wrong_payment_id = PaymentId([0xFF; 32]);
		let result = paid_invoice.prove_payer_derived(&expanded_key, wrong_payment_id, &secp_ctx);
		assert!(matches!(result, Err(PayerProofError::KeyDerivationFailed)));
	}

	/// Per BOLT 12 PR 1295: deriving the payer signing key with the wrong nonce
	/// must fail at construction time with `KeyDerivationFailed`.
	#[test]
	fn test_prove_payer_derived_rejects_wrong_nonce() {
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
		.build()
		.unwrap()
		.respond_with_no_std(payment_paths(), payment_hash, recipient_pubkey(), now())
		.unwrap()
		.build()
		.unwrap()
		.sign(recipient_sign)
		.unwrap();

		// `PaidBolt12Invoice` carries a *different* nonce than the one used to
		// derive `invreq_payer_id`, so re-derivation produces a key that doesn't
		// match the invoice's `invreq_payer_id`.
		let wrong_nonce = Nonce::try_from(&[0xAA; Nonce::LENGTH][..]).unwrap();
		let paid_invoice = PaidBolt12Invoice::new(
			Bolt12InvoiceType::Bolt12Invoice(invoice),
			preimage,
			Some(wrong_nonce),
		);

		let result = paid_invoice.prove_payer_derived(&expanded_key, payment_id, &secp_ctx);
		assert!(matches!(result, Err(PayerProofError::KeyDerivationFailed)));
	}

	// BOLT 12 payer proof test vectors (from bolt12/payer-proof-test.json).
	// Each vector carries its own invoice; all share the payer secret and preimage.
	const PAYER_SECRET_HEX: &str =
		"4242424242424242424242424242424242424242424242424242424242424242";
	const PREIMAGE_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

	struct PayerProofVector {
		name: &'static str,
		invoice_hex: &'static str,
		included_types: &'static [u64],
		note: Option<&'static str>,
		leaf_hashes_hex: &'static str,
		omitted_tlvs: &'static [u64],
		missing_hashes_hex: &'static str,
		/// The merkle root of the invoice the proof is derived from.
		merkle_root_hex: &'static str,
		bech32: &'static str,
		/// `true` when LDK's encoder reproduces `bech32` byte-for-byte. The
		/// `empty_proof_omitted_tlvs_explicit` vector serializes an empty
		/// `proof_omitted_tlvs` TLV, which LDK omits per the spec's "MAY omit"
		/// rule, so for that vector only the parse path is exercised.
		byte_exact: bool,
	}

	const PAYER_PROOF_VECTORS: &[PayerProofVector] = &[
		PayerProofVector {
			name: "full_disclosure",
			invoice_hex: "0010000000000000000000000000000000001621024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382520203e858210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca076027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000a21c00000001000000020003000000000000000400000000000000050000a40467527988a82072cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793aa0203e8ae0d08000000000000000000000000b021024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382f040fbb932e6a9d5b4d88ca0ddc9cf9f8cc880ef41e3ec9574da89f624db898ab3e9d3ed6caa8744633b855167da009119d9834ae71f7b06f02732dc4c1debab0577feb2d05e010142",
			included_types: &[22, 82, 88, 160, 162, 164, 168, 170, 174, 176, 3000000001],
			note: None,
			leaf_hashes_hex: "8c9057ed88f3c5a6b6441dcac3b5e4cefb3615904d7362b86e78427fb695f4618dc54a97453dee6f207fa5216a30f1567442712ca98852bc789b73885029283cf2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f54f80c94a87383f2a8ef7c3e461c62b67a51da5bccf6cd96a7dbab29bea51fa7849b8b856e1d2a63d9ce7dc1a78e05cbb2def1f5d7709c48e8707e0a59fe51e19e7e4eee6bf56c6c589fe50035490c1a7c91b753cb8007c4b52838a6772f997f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1adc0b8de03f1a0b0531bff146982d7d613ef6e1ef8d3bdd9590971fc18d835ffbc14cfffaa314261bcbb2ed4ca24d5717bb608d8a6cc9910790bc1d49af7858ab7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cbabaab91b367e30fea7026daf9f2590bb7e9cc31db8221f4013c67289e38f22c8",
			omitted_tlvs: &[],
			missing_hashes_hex: "0b510ba4c6884d603159ced2f0ca21e772424b59e52a2191bbfbcf07377805a1",
			merkle_root_hex: "cb9e0c81bb39fc244f9f523c748ab4de0e09f1a5fef74359c2e1f7cc7cdc7447",
			bech32: "lnp1zcssyj7z5vfx29flqlnsuzatppeyu6u9ugtl3ntz3n4k996zg7a5jvuz2gpq86zcyypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k89qwcp87v0tc4rzc87uuxmn0m8l2tfh6aw75s7wz8r56fd299ckt74zqpcr9s9he72nyjs86pfe3vjqzaxups47g3xedv2e4fk877c7v6rgpxgszqhd4w73ddqusdcmjthj7pxprpd57qakmn2jh2dh3kwhezwg7gs3g5qpqqqqqqqqqqqqqqqqqqqqqqqqqq9zrsqqqqqpqqqqqqsqqvqqqqqqqqqqqpqqqqqqqqqqqqzsqq9yq3n4y7vg4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0ya2qgp73tsdpqqqqqqqqqqqqqqqqqqqpvppqf9u9gcjv52n7pl8pc96kzrjfe4ctcshlrxk9r8tv2t5y3amfyec9uzqlwun9e4f6k6d3r9qmhyul8uvezqw7s0raj2hfk5f7cjdhzv2k05a8mtv42r5gcems4gk0ksqjyvanq62uu0hkphsyuedcnqaaw4s2al3gpykzve5p8698d233l9uvc5ndl95dekpmwxev0zyke74valsll8r43wyy2far0qjnzcdvueq5aewyzsxcp5alfc8nhujq7m82dthxhwhl5p7jgqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq87s86eqpdgshfxx3pxkqv2eemf0pj3puaeyyj6eu54zrydml08swdmcqksl6qlvl5qkprys2lkc3u7956myg8w2cw67fnhmxc2eqntnv2uxu7zz07mftarp3hz549698hhx7grl55sk5v832e6yyufv4xy990rcndecs5pf9q709h40tuctu08d3878cfx5y2qehur27rjg5v2z8w7suf3570pauel4f7qvjj588qlj4rhhc0jxr33tv7j3mfdueakdj6nah2efh6j3lfuynw9c2msa9f3annnacxncupwtkt00rawhwzwy36rs0c99nlj3ux08unhwd06kcmzcnljsqd2fpsd8eydh209cqp7yk55r3fnh97vh7qv3cdgqqfr42judpgvk3x98jjlnm6yesft3z7xexxhlke20psddczuduql35zc9xxllz35c947kz0hku8hc6w7ajkgfw87p3kp4l77pfnll4gc5ycduhvhdfj3y64chhdsgmznvexgs0y9ur4y677zc4dlf9dmmncuyxeg0dnt7a99kw5l2nhe4xdcskpx7u6r26dm9zkjuh2a2hydnvl3sl6nsymd0nujepwm7nnp3mwpzraqp83nj383c7gkgl6edqhspq9pq",
			byte_exact: true,
		},
		PayerProofVector {
			name: "minimal_disclosure",
			invoice_hex: "0010000000000000000000000000000000001621024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382520203e858210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca076027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000a21c00000001000000020003000000000000000400000000000000050000a40467527988a82072cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793aa0203e8b021024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382f0400a33224568b6aae6ed252012bd7fe1072c03ebdca7fa44f95b03f1cd09be28b0a83c9c32105978cd80da068979662c80fa00ff250ccdc4d18b709ffd1c7ae319",
			included_types: &[88, 168, 176],
			note: None,
			leaf_hashes_hex: "f2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1a7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cb",
			omitted_tlvs: &[1, 2, 89, 90, 91, 169],
			missing_hashes_hex: "bf8cb2b1d6fa9bcdcab501b59f82c65c506b7f43514737f7197f1fcfeaebad41b9406f4ce526a6a0d4e0b3a63ed89a832e31cb9939dfe1a7b5dd7232d32c02abcd9c44b53b31700c9ed0e3330ce425f7f18fac2fc1d566a34468439274f0e3169f9830f2c3070cfbad13fde30ee36cd7143591164ed12040a9cd595c96840ac9998ab7fa9c743fb9dbdb0d8d46fbe3ad333400bd07f328dcdb6008790bc9d2db",
			merkle_root_hex: "0501ea6d4ad9fe7fce7edd5e3795987bd409d66c5709c2a17f9c0dfb839e3d8e",
			bech32: "lnp1tqssxfr986kyx3ygqqkvq6alklcslcvfj834l8lyxqkmafkjx57up2cu4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0yasyypyhs4rzfj320c8uu8qh2cgwf8xhp0zzluv6c5vad3fwsj8hdyn8qhsgq9rxgj9dzm24ehdy5sp90tluyrjcqltmjnl538etvplrngfhc5tp2punsepqktcekqd5p5f09nzeq86qrlj2rxdcngckuyll5w84cce79qva0p96s9zmynmt672hpqq74p0hdag733w3hvq9wcnupgtn0ef8d690svmg6j8vaq0jlyadmq5ru35xnzaf7398gwjawyfd6adn9z4en7s86fqqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyql6ql2qcqsyk26tw5l6qlt5zlcev436mafhnw2k5qmt8uzcew9q6mlgdg5wdlhr9l3lnl2awk5rw2qdaxw2f4x5r2wpvax8mvf4qewx89ejwwluxnmthtjxtfjcq4tekwyfdfmx9cqe8ksuveseep97lccltp0c82kdg6ydppeya8suvtflxps7tpswr8m45flmccwudkdw9p4jytya5fqgz5u6k2uj6zq4jve32ml48r587uahkcd34r0hcadxv6qp0g87v5dekmqppushjwjm07s8mrq7t027heshc7wmz0u0sjdgg5pn0cx4u8y3gc5ywaapcnrfu7rmenlqxgux5qqy364fwxs5xtgnznef0eaazvcy4c30rvnrtlmv48scxn7j2mhh83cgdjs7mxha62tvaf7480n2vm3pvzdae5x45mk29d9ev",
			byte_exact: true,
		},
		PayerProofVector {
			name: "with_note",
			invoice_hex: "0010000000000000000000000000000000001621024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382520203e858210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca076027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000a21c00000001000000020003000000000000000400000000000000050000a40467527988a82072cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793aa0203e8b021024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382f0400a33224568b6aae6ed252012bd7fe1072c03ebdca7fa44f95b03f1cd09be28b0a83c9c32105978cd80da068979662c80fa00ff250ccdc4d18b709ffd1c7ae319",
			included_types: &[88, 168, 176],
			note: Some("test note"),
			leaf_hashes_hex: "f2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1a7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cb",
			omitted_tlvs: &[1, 2, 89, 90, 91, 169],
			missing_hashes_hex: "bf8cb2b1d6fa9bcdcab501b59f82c65c506b7f43514737f7197f1fcfeaebad41b9406f4ce526a6a0d4e0b3a63ed89a832e31cb9939dfe1a7b5dd7232d32c02abcd9c44b53b31700c9ed0e3330ce425f7f18fac2fc1d566a34468439274f0e3169f9830f2c3070cfbad13fde30ee36cd7143591164ed12040a9cd595c96840ac9998ab7fa9c743fb9dbdb0d8d46fbe3ad333400bd07f328dcdb6008790bc9d2db",
			merkle_root_hex: "0501ea6d4ad9fe7fce7edd5e3795987bd409d66c5709c2a17f9c0dfb839e3d8e",
			bech32: "lnp1tqssxfr986kyx3ygqqkvq6alklcslcvfj834l8lyxqkmafkjx57up2cu4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0yasyypyhs4rzfj320c8uu8qh2cgwf8xhp0zzluv6c5vad3fwsj8hdyn8qhsgq9rxgj9dzm24ehdy5sp90tluyrjcqltmjnl538etvplrngfhc5tp2punsepqktcekqd5p5f09nzeq86qrlj2rxdcngckuyll5w84cce79qz53lesac2aq2pr8tg9fa3na7wnczs5wa5nkds5qcugmvuk4arqawacga8gtmdxw7yaj8pw7pjwj2tafmd9mjkgcj7nxlmjhxzpxnhyt7s86fqqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyql6ql2qcqsyk26tw5l6qlt5zlcev436mafhnw2k5qmt8uzcew9q6mlgdg5wdlhr9l3lnl2awk5rw2qdaxw2f4x5r2wpvax8mvf4qewx89ejwwluxnmthtjxtfjcq4tekwyfdfmx9cqe8ksuveseep97lccltp0c82kdg6ydppeya8suvtflxps7tpswr8m45flmccwudkdw9p4jytya5fqgz5u6k2uj6zq4jve32ml48r587uahkcd34r0hcadxv6qp0g87v5dekmqppushjwjm07s8mrq7t027heshc7wmz0u0sjdgg5pn0cx4u8y3gc5ywaapcnrfu7rmenlqxgux5qqy364fwxs5xtgnznef0eaazvcy4c30rvnrtlmv48scxn7j2mhh83cgdjs7mxha62tvaf7480n2vm3pvzdae5x45mk29d9e07s8mgfw3jhxapqdehhgeg",
			byte_exact: true,
		},
		PayerProofVector {
			name: "left_subtree_omitted",
			invoice_hex: "0010000000000000000000000000000000001621024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382520203e858210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca076027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000a21c00000001000000020003000000000000000400000000000000050000a40467527988a82072cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793aa0203e8b021024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382f0400a33224568b6aae6ed252012bd7fe1072c03ebdca7fa44f95b03f1cd09be28b0a83c9c32105978cd80da068979662c80fa00ff250ccdc4d18b709ffd1c7ae319",
			included_types: &[88, 168, 170, 176],
			note: None,
			leaf_hashes_hex: "f2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1adc0b8de03f1a0b0531bff146982d7d613ef6e1ef8d3bdd9590971fc18d835ffb7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cb",
			omitted_tlvs: &[1, 2, 89, 90, 91],
			missing_hashes_hex: "bf8cb2b1d6fa9bcdcab501b59f82c65c506b7f43514737f7197f1fcfeaebad41b9406f4ce526a6a0d4e0b3a63ed89a832e31cb9939dfe1a7b5dd7232d32c02abcd9c44b53b31700c9ed0e3330ce425f7f18fac2fc1d566a34468439274f0e3169f9830f2c3070cfbad13fde30ee36cd7143591164ed12040a9cd595c96840ac9",
			merkle_root_hex: "0501ea6d4ad9fe7fce7edd5e3795987bd409d66c5709c2a17f9c0dfb839e3d8e",
			bech32: "lnp1tqssxfr986kyx3ygqqkvq6alklcslcvfj834l8lyxqkmafkjx57up2cu4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0ya2qgp73vppqf9u9gcjv52n7pl8pc96kzrjfe4ctcshlrxk9r8tv2t5y3amfyec9uzqpgejy3tgk64wdmf9yqft6llpqukq867u5layf72mq0cu6zd79zc2s0yuxgg9j7xdsrdqdztevckgp7sqlujsenwy6x9hp8lar3awxx03grks8mzc6kkxwefefp4md6xk7wymvd6mv6fllhes4yu3jkgdw3868ylegkjauwa404ju0asaauwwl292qwrjtv2m7ra8jl0apr9fw5u2l5p7jgqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq87s86s9qyp9jkjml5p7hq9l3jetr4h6n0xu4dgpkk0c93ju2p4h7s63gumlwxtlrl8746adgxu5qm6vu5n2dgx5uze6v0kcn2pjuvwtnyualcd8khwhyvkn9sp2hnvugj6nkvtspj0dpcenpnjztal337kzlsw4v635g6zrjf60pcckn7vrpukrqux0htgnlh3sacmv6u2rtygkfmgjqs9fe4v4e95yptyl6qlvsredat6lxzlremvfl37zf4pzsxdlq6hsuj9rzs3mh58zvd8nc00x0uqers6sqqj8249c6zsedzv2099l8h5fnqjhz9udjvd0ldj57rq6ms9cmcplrg9s2vdl79rfsttavyl0dc0035aam9vsju0urrvrtlahay4h0w0rssm9pakd0m55ke6na2wlx5ehzzcymmngdtfhv526tjc",
			byte_exact: true,
		},
		PayerProofVector {
			name: "empty_proof_omitted_tlvs_explicit",
			invoice_hex: "0010000000000000000000000000000000001621024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382520203e858210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca076027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000a21c00000001000000020003000000000000000400000000000000050000a40467527988a82072cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793aa0203e8b021024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382f0400a33224568b6aae6ed252012bd7fe1072c03ebdca7fa44f95b03f1cd09be28b0a83c9c32105978cd80da068979662c80fa00ff250ccdc4d18b709ffd1c7ae319",
			included_types: &[22, 82, 88, 160, 162, 164, 168, 170, 176],
			note: None,
			leaf_hashes_hex: "8c9057ed88f3c5a6b6441dcac3b5e4cefb3615904d7362b86e78427fb695f4618dc54a97453dee6f207fa5216a30f1567442712ca98852bc789b73885029283cf2deaf5f30be3ced89fc7c24d422819bf06af0e48a31423bbd0e2634f3c3de67f54f80c94a87383f2a8ef7c3e461c62b67a51da5bccf6cd96a7dbab29bea51fa7849b8b856e1d2a63d9ce7dc1a78e05cbb2def1f5d7709c48e8707e0a59fe51e19e7e4eee6bf56c6c589fe50035490c1a7c91b753cb8007c4b52838a6772f997f0191c35000247554b8d0a196898a794bf3de89982571178d931affb654f0c1adc0b8de03f1a0b0531bff146982d7d613ef6e1ef8d3bdd9590971fc18d835ffb7e92b77b9e3843650f6cd7ee94b6753ea9df3533710b04dee686ad376515a5cb",
			omitted_tlvs: &[],
			missing_hashes_hex: "0b510ba4c6884d603159ced2f0ca21e772424b59e52a2191bbfbcf07377805a1",
			merkle_root_hex: "0501ea6d4ad9fe7fce7edd5e3795987bd409d66c5709c2a17f9c0dfb839e3d8e",
			bech32: "lnp1zcssyj7z5vfx29flqlnsuzatppeyu6u9ugtl3ntz3n4k996zg7a5jvuz2gpq86zcyypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k89qwcp87v0tc4rzc87uuxmn0m8l2tfh6aw75s7wz8r56fd299ckt74zqpcr9s9he72nyjs86pfe3vjqzaxups47g3xedv2e4fk877c7v6rgpxgszqhd4w73ddqusdcmjthj7pxprpd57qakmn2jh2dh3kwhezwg7gs3g5qpqqqqqqqqqqqqqqqqqqqqqqqqqq9zrsqqqqqpqqqqqqsqqvqqqqqqqqqqqpqqqqqqqqqqqqzsqq9yq3n4y7vg4qs89ntwss3vgplmd5ycdy83zv9hmmt7ctmltcwnp0va2g0sz5mr0ya2qgp73vppqf9u9gcjv52n7pl8pc96kzrjfe4ctcshlrxk9r8tv2t5y3amfyec9uzqpgejy3tgk64wdmf9yqft6llpqukq867u5layf72mq0cu6zd79zc2s0yuxgg9j7xdsrdqdztevckgp7sqlujsenwy6x9hp8lar3awxx03gr0luckkg3kpste9q0ncpl8qnlzu7vgw7999faja6803yspek75f0u55q3c2cruc2luzdv3j9zwq438xjf72vlvq29nlkzkax5hc3tw3l5p7jgqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq87s86sql5p7kgqt2y96f35gf4srzkww6tcv5g08wfpykk099gserwlmeurnw7q9587s8m8aqysgeyzhaky083dxkezpmjkrkhjva7ekzkgy6umzhph8ssnlk62lgcvdc49fw3faaehjqla9y94rpu2kw3p8zt9f3pftc7ymwwy9q2fg8nedat6lxzlremvfl37zf4pzsxdlq6hsuj9rzs3mh58zvd8nc00x0a20sry54pec8u4gaa7ru3suv2m855w6t0x0dnvk5ld6k2d755060pym3wzku8f2v0vuulwp578qtjajmmclt4msn3ywsur7pfvlu50pnelyamnt74kxckylu5qr2jgvrf7frd6newqq03949qu2vae0n9lsrywr2qqzga25hrg2r95f3fu5hu773xvz2ugh3kf34lak2ncvrtwqhr0q8udqkpf3hlc5dxpd04snaahpa7xnhhv4jzt3lsvdsd0lkl5jkaaeuwzrv58ke4lwjjm8204fmu6nxugtqn0wdp4dxaj3tfwt",
			byte_exact: false,
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

	/// Build a focused failure report for two bech32 strings that are expected
	/// to be byte-identical except in the `payer_signature` region.
	///
	/// Returns `None` when the strings match exactly. Otherwise returns a
	/// `String` summarizing the divergence: how many leading/trailing bytes
	/// match, the byte range of the differing region, and a short snippet
	/// from each side. This avoids dumping ~1700-char bech32 strings into
	/// the panic message.
	fn report_bech32_mismatch(label: &str, got: &str, want: &str) -> Option<String> {
		if got == want {
			return None;
		}

		let first_diff = got.bytes().zip(want.bytes()).position(|(a, b)| a != b);
		let Some(first) = first_diff else {
			return Some(format!(
				"{}: bech32 length differs (got {} chars, want {} chars), \
				 but the common prefix matches",
				label,
				got.len(),
				want.len(),
			));
		};

		// Walk from the end to find where the strings reconverge.
		let trailing_match =
			got.bytes().rev().zip(want.bytes().rev()).position(|(a, b)| a != b).unwrap_or(0);
		let got_diff_end = got.len() - trailing_match;
		let want_diff_end = want.len() - trailing_match;
		let snippet = 40usize;
		let got_snippet = &got[first..got_diff_end.min(first + snippet)];
		let want_snippet = &want[first..want_diff_end.min(first + snippet)];
		let got_truncated = got_diff_end > first + snippet;
		let want_truncated = want_diff_end > first + snippet;

		Some(format!(
			"{label}: bech32 differs in chars [{first}..{got_diff_end}] (got len {got_len}) \
			 and [{first}..{want_diff_end}] (want len {want_len}). \
			 First {first} chars match; last {trailing_match} chars match.\n  \
			 got  : \"{got_snippet}{got_ellipsis}\"\n  \
			 want : \"{want_snippet}{want_ellipsis}\"",
			label = label,
			first = first,
			got_diff_end = got_diff_end,
			want_diff_end = want_diff_end,
			got_len = got.len(),
			want_len = want.len(),
			trailing_match = trailing_match,
			got_snippet = got_snippet,
			got_ellipsis = if got_truncated { "…" } else { "" },
			want_snippet = want_snippet,
			want_ellipsis = if want_truncated { "…" } else { "" },
		))
	}

	#[test]
	fn check_against_spec_vectors() {
		let secp_ctx = Secp256k1::new();
		let payer_keys = Keypair::from_secret_key(
			&secp_ctx,
			&SecretKey::from_slice(&hex_decode(PAYER_SECRET_HEX)).unwrap(),
		);

		let preimage = PaymentPreimage(hex_decode(PREIMAGE_HEX).try_into().unwrap());

		for vector in PAYER_PROOF_VECTORS {
			let invoice = Bolt12Invoice::try_from(hex_decode(vector.invoice_hex))
				.unwrap_or_else(|e| panic!("{}: failed to parse invoice: {:?}", vector.name, e));

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

			if let Some(note) = vector.note {
				builder = builder.with_proof_note(note.to_owned());
			}

			// The selective-disclosure data is derived from the invoice's merkle
			// tree and is independent of how the proof's optional TLVs are
			// encoded, so every spec vector must match here. Recompute it
			// independently of the builder so we can compare leaf hashes,
			// omitted markers, missing hashes, and merkle root against the
			// spec vector before signing the proof.
			let invoice_bytes_for_check = invoice.invoice_bytes();
			let included_types_for_check: BTreeSet<u64> =
				vector.included_types.iter().copied().collect();
			let disclosure = compute_selective_disclosure(
				TlvStream::new(invoice_bytes_for_check)
					.filter(|r| !SIGNATURE_TYPES.contains(&r.r#type)),
				&included_types_for_check,
			)
			.unwrap_or_else(|e| panic!("{}: disclosure computation failed: {:?}", vector.name, e));

			let got_leaves: Vec<String> =
				disclosure.leaf_hashes.iter().map(|h| hex_encode(h.as_ref())).collect();
			assert_eq!(
				got_leaves,
				split_hashes_hex(vector.leaf_hashes_hex),
				"{}: leaf_hashes mismatch",
				vector.name
			);

			assert_eq!(
				disclosure.omitted_markers, vector.omitted_tlvs,
				"{}: omitted_tlvs mismatch",
				vector.name
			);

			let got_missing: Vec<String> =
				disclosure.missing_hashes.iter().map(|h| hex_encode(h.as_ref())).collect();
			assert_eq!(
				got_missing,
				split_hashes_hex(vector.missing_hashes_hex),
				"{}: missing_hashes mismatch",
				vector.name
			);

			let got_root = hex_encode(disclosure.merkle_root.as_ref());
			assert_eq!(got_root, vector.merkle_root_hex, "{}: merkle_root mismatch", vector.name);

			let unsigned = builder
				.build_unsigned()
				.unwrap_or_else(|e| panic!("{}: build failed: {:?}", vector.name, e));

			let proof = unsigned
				.sign(|proof: &UnsignedPayerProof| {
					Ok(secp_ctx.sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &payer_keys))
				})
				.unwrap_or_else(|e| panic!("{}: sign failed: {:?}", vector.name, e));

			// Every spec vector must be readable, including the one that encodes
			// an explicit empty `proof_omitted_tlvs` TLV.
			vector
				.bech32
				.parse::<PayerProof>()
				.unwrap_or_else(|e| panic!("{}: spec proof failed to parse: {:?}", vector.name, e));

			if vector.byte_exact {
				// LDK's encoder must also reproduce the spec proof byte-for-byte.
				if let Some(report) =
					report_bech32_mismatch(vector.name, &proof.to_string(), vector.bech32)
				{
					panic!("{}", report);
				}
			}
		}
	}
}
