// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Verification of BOLT 12 payer proofs.
//!
//! * Verify a bech32 proof with [`verify`] (`lnp1...`) or [`verify_bytes`]
//! * Inspect the result with [`VerifiedPayerProof`]
//! * Check an offer's recipient with [`VerifiedPayerProof::pays_offers_recipient`]
//!
//! A successful verify does not mean they paid the invoice you have in mind. Anyone can issue an
//! invoice to themselves, pay it, and hand out a proof that verifies.
//!
//! ```ignore
//! use lightning_payer_proof::{verify, Offer};
//!
//! let encoded = "lnp1...";
//! let offer = "lno1...";
//!
//! let proof = verify(encoded).unwrap();
//! let offer: Offer = offer.parse().unwrap();
//! assert!(proof.pays_offers_recipient(&offer));
//! ```

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use lightning::bitcoin::hashes::Hash;
use lightning::offers::parse::Bolt12ParseError;
use lightning::offers::payer_proof::PayerProof;

pub use lightning::bitcoin::secp256k1::PublicKey;
pub use lightning::offers::offer::Offer;
pub use lightning::offers::payer_proof::PayerProof as UnderlyingPayerProof;
pub use lightning::types::payment::{PaymentHash, PaymentPreimage};
pub use lightning::types::string::UntrustedString;

/// Why a payer proof was rejected.
///
/// Every variant means the proof is unusable. They are distinguished so a verifier can tell a
/// mistyped string apart from a proof that decoded cleanly but failed a cryptographic check, which
/// are very different things to show a user.
///
/// Failed cryptographic checks currently all arrive as [`MalformedProof`].
///
/// [`MalformedProof`]: Self::MalformedProof
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
	/// The string is not a bech32-encoded payer proof, or carries a prefix other than `lnp`.
	InvalidBech32,
	/// The bytes decoded as bech32 but are not a well-formed payer proof TLV stream.
	///
	/// Failed cryptographic checks currently arrive here too.
	MalformedProof,
	/// The TLV stream is well-formed but omits a field required to verify the proof at all, such
	/// as the payment hash, the preimage, or one of the signatures.
	IncompleteProof,
}

impl core::fmt::Display for VerifyError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = match self {
			VerifyError::InvalidBech32 => "not a bech32-encoded payer proof",
			VerifyError::MalformedProof => "malformed payer proof",
			VerifyError::IncompleteProof => "payer proof is missing a required field",
		};
		f.write_str(message)
	}
}

impl From<Bolt12ParseError> for VerifyError {
	fn from(error: Bolt12ParseError) -> Self {
		match error {
			Bolt12ParseError::InvalidContinuation
			| Bolt12ParseError::InvalidLeadingWhitespace
			| Bolt12ParseError::InvalidBech32Hrp
			| Bolt12ParseError::Bech32(_)
			| Bolt12ParseError::InvalidPadding(_) => VerifyError::InvalidBech32,
			// Every failed cryptographic check arrives here too, indistinguishable from a stream
			// that was never well-formed.
			Bolt12ParseError::Decode(_) => VerifyError::MalformedProof,
			Bolt12ParseError::InvalidSemantics(_) => VerifyError::IncompleteProof,
			// Raised when a key or signature fails to deserialize, which leaves us unable to say
			// anything about whether the signature would have verified.
			Bolt12ParseError::InvalidSignature(_) => VerifyError::MalformedProof,
		}
	}
}

/// Verifies a bech32-encoded payer proof, the `lnp1...` string a payer hands over.
///
/// Uppercase input, and the `+` continuation from BOLT 12 allowing long strings to be split across
/// lines, are both accepted.
pub fn verify(proof: &str) -> Result<VerifiedPayerProof, VerifyError> {
	proof.parse::<PayerProof>().map(VerifiedPayerProof).map_err(VerifyError::from)
}

/// Verifies a payer proof in its raw TLV stream form, skipping the bech32 layer.
pub fn verify_bytes(proof: &[u8]) -> Result<VerifiedPayerProof, VerifyError> {
	PayerProof::try_from(proof.to_vec()).map(VerifiedPayerProof).map_err(VerifyError::from)
}

/// A payer proof that passed every check in [`verify`].
///
/// Fields the payer withheld return `None`.
#[derive(Clone, Debug)]
pub struct VerifiedPayerProof(PayerProof);

impl VerifiedPayerProof {
	/// The payment hash this proof settles.
	///
	/// Compare this against your own records to learn whether the proof concerns you at all.
	pub fn payment_hash(&self) -> PaymentHash {
		self.0.payment_hash()
	}

	/// The preimage that unlocked the payment, proven here to hash to [`Self::payment_hash`].
	pub fn payment_preimage(&self) -> PaymentPreimage {
		self.0.payment_preimage()
	}

	/// The key the payer signed this proof with.
	pub fn payer_signing_pubkey(&self) -> PublicKey {
		self.0.payer_signing_pubkey()
	}

	/// The key the invoice was signed with, identifying who issued it.
	pub fn issuer_signing_pubkey(&self) -> PublicKey {
		self.0.issuer_signing_pubkey()
	}

	/// The invoiced amount in millisatoshis, if disclosed.
	pub fn invoice_amount_msats(&self) -> Option<u64> {
		self.0.invoice_amount_msats()
	}

	/// When the invoice was created, in seconds since the Unix epoch, if disclosed.
	pub fn invoice_created_at_secs(&self) -> Option<u64> {
		self.0.invoice_created_at().map(|created_at| created_at.as_secs())
	}

	/// The offer description the invoice was built from, if disclosed.
	///
	/// Untrusted text; sanitize control characters before displaying.
	pub fn offer_description(&self) -> Option<UntrustedString> {
		self.0.offer_description().map(|text| UntrustedString(text.0.to_string()))
	}

	/// The offer issuer, if disclosed.
	///
	/// This is a human-readable label chosen by whoever built the offer, not an identity. It is
	/// [`Self::issuer_signing_pubkey`] that says who signed.
	pub fn offer_issuer(&self) -> Option<UntrustedString> {
		self.0.offer_issuer().map(|text| UntrustedString(text.0.to_string()))
	}

	/// A note the payer attached when building the proof, if any.
	pub fn proof_note(&self) -> Option<UntrustedString> {
		self.0.proof_note().map(|text| UntrustedString(text.0.to_string()))
	}

	/// The merkle root of the invoice the issuer signed.
	pub fn merkle_root(&self) -> [u8; 32] {
		self.0.merkle_root().to_byte_array()
	}

	/// The issuer's signature over the invoice, in BIP 340 form.
	pub fn invoice_signature(&self) -> [u8; 64] {
		*self.0.invoice_signature().as_ref()
	}

	/// The payer's signature over this proof, in BIP 340 form.
	pub fn proof_signature(&self) -> [u8; 64] {
		*self.0.proof_signature().as_ref()
	}

	/// Re-encodes the proof as the `lnp1...` string it was parsed from.
	pub fn to_bech32(&self) -> String {
		self.0.to_string()
	}

	/// The proof's raw TLV stream, as accepted by [`verify_bytes`].
	pub fn encode(&self) -> Vec<u8> {
		self.0.bytes().to_vec()
	}

	/// Whether the invoice this proof covers was issued by `offer`'s recipient.
	///
	/// Inlined here so this crate can answer the question against LDK 0.3, which has the
	/// accessors but not `PayerProof::pays_offers_recipient`.
	///
	/// This identifies the recipient, not the offer: two offers published by the same recipient
	/// are indistinguishable here, so a `true` answers "this was paid to whoever `offer` names"
	/// rather than "this paid `offer`".
	pub fn pays_offers_recipient(&self, offer: &Offer) -> bool {
		let invoice_key = self.0.issuer_signing_pubkey();
		if let Some(issuer_id) = offer.issuer_signing_pubkey() {
			return invoice_key == issuer_id;
		}
		offer
			.paths()
			.iter()
			.filter_map(|path| path.blinded_hops().last())
			.any(|last_hop| invoice_key == last_hop.blinded_node_id)
	}

	/// Whether the invoice this proof covers was issued by the recipient of the offer encoded as
	/// `offer` (`lno1...`).
	pub fn pays_offers_recipient_str(&self, offer: &str) -> bool {
		offer.parse::<Offer>().map(|offer| self.pays_offers_recipient(&offer)).unwrap_or(false)
	}

	/// The underlying [`PayerProof`], for callers who want to work with LDK's own type.
	pub fn inner(&self) -> &PayerProof {
		&self.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A valid payer proof over a 42,000 msat invoice created at Unix time 1,700,000,000,
	/// disclosing the offer description ("coffee beans"), the issuer ("LDK Roastery"), the amount
	/// and the creation timestamp, with the payer note "order-1234" attached.
	const FULL_PROOF_HEX: &str = include_str!("../test_vectors/valid_proof.hex");

	/// A valid payer proof over the same invoice disclosing none of the optional fields and
	/// carrying no note, so every `Option` accessor returns `None`.
	const MINIMAL_PROOF_HEX: &str = include_str!("../test_vectors/minimal_proof.hex");

	/// An offer, a proof over an invoice built from it, and a second offer that differs only in
	/// issuer id, so a recipient check against it must fail.
	const OFFER_HEX: &str = include_str!("../test_vectors/offer.hex");
	const OFFER_PROOF_HEX: &str = include_str!("../test_vectors/offer_proof.hex");
	const OTHER_OFFER_HEX: &str = include_str!("../test_vectors/other_offer.hex");

	/// Both vectors were produced by the `RefundBuilder` -> `prove_payer` -> `sign` path exercised
	/// by the tests in `lightning::offers::payer_proof`, using that module's fixed test keys. They
	/// are frozen here rather than regenerated so a change in encoding shows up as a test failure.
	/// They pin this implementation against itself; BOLT 12 payer proofs have no cross-
	/// implementation test vectors yet, so nothing here demonstrates interop.
	fn decode_hex(hex: &str) -> Vec<u8> {
		let hex = hex.trim();
		assert!(hex.len() % 2 == 0, "vector must have an even number of hex digits");
		(0..hex.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("vector must be valid hex"))
			.collect()
	}

	fn full_proof_bytes() -> Vec<u8> {
		decode_hex(FULL_PROOF_HEX)
	}

	/// Reads a BigSize-prefixed integer, returning it alongside the offset just past it.
	fn read_bigsize(bytes: &[u8], offset: usize) -> (u64, usize) {
		match bytes[offset] {
			0xff => {
				(u64::from_be_bytes(bytes[offset + 1..offset + 9].try_into().unwrap()), offset + 9)
			},
			0xfe => (
				u32::from_be_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as u64,
				offset + 5,
			),
			0xfd => (
				u16::from_be_bytes(bytes[offset + 1..offset + 3].try_into().unwrap()) as u64,
				offset + 3,
			),
			byte => (byte as u64, offset + 1),
		}
	}

	/// Returns the byte range covering the value of the TLV record with the given type.
	fn tlv_value_range(bytes: &[u8], tlv_type: u64) -> core::ops::Range<usize> {
		let mut offset = 0;
		while offset < bytes.len() {
			let (found_type, after_type) = read_bigsize(bytes, offset);
			let (length, after_length) = read_bigsize(bytes, after_type);
			let value = after_length..after_length + length as usize;
			if found_type == tlv_type {
				return value;
			}
			offset = value.end;
		}
		panic!("vector has no TLV of type {}", tlv_type);
	}

	// TLV types a payer proof is built from, per BOLT 12 and its payer proof extension.
	const INVOICE_NODE_ID: u64 = 176;
	const ISSUER_SIGNATURE: u64 = 240;
	const PROOF_SIGNATURE: u64 = 241;
	const PROOF_PREIMAGE: u64 = 1001;
	const PROOF_OMITTED_MARKERS: u64 = 1002;
	const PROOF_LEAF_HASHES: u64 = 1004;
	const PROOF_NOTE: u64 = 1005;

	#[test]
	fn verifies_a_valid_proof() {
		let proof = verify_bytes(&full_proof_bytes()).unwrap();

		assert_eq!(proof.invoice_amount_msats(), Some(42_000));
		assert_eq!(proof.invoice_created_at_secs(), Some(1_700_000_000));
		assert_eq!(proof.offer_description().map(|d| d.0), Some("coffee beans".to_string()));
		assert_eq!(proof.offer_issuer().map(|i| i.0), Some("LDK Roastery".to_string()));
		assert_eq!(proof.proof_note().map(|n| n.0), Some("order-1234".to_string()));
	}

	/// The two keys carry the whole weight of deciding whether a proof concerns the verifier, so
	/// pin each to its own value rather than only checking that they parse.
	#[test]
	fn exposes_the_two_signing_keys_distinctly() {
		let bytes = full_proof_bytes();
		let proof = verify_bytes(&bytes).unwrap();

		assert_eq!(
			proof.issuer_signing_pubkey().serialize().to_vec(),
			bytes[tlv_value_range(&bytes, INVOICE_NODE_ID)].to_vec()
		);
		assert_ne!(proof.payer_signing_pubkey(), proof.issuer_signing_pubkey());
	}

	#[test]
	fn exposes_the_signatures_and_merkle_root() {
		let bytes = full_proof_bytes();
		let proof = verify_bytes(&bytes).unwrap();

		assert_eq!(
			proof.invoice_signature().to_vec(),
			bytes[tlv_value_range(&bytes, ISSUER_SIGNATURE)].to_vec()
		);
		assert_eq!(
			proof.proof_signature().to_vec(),
			bytes[tlv_value_range(&bytes, PROOF_SIGNATURE)].to_vec()
		);
		assert_ne!(proof.merkle_root(), [0; 32], "merkle root must not be left unset");
		assert_eq!(proof.merkle_root(), proof.inner().merkle_root().to_byte_array());
	}

	#[test]
	fn preimage_hashes_to_the_payment_hash() {
		let proof = verify_bytes(&full_proof_bytes()).unwrap();

		let preimage = proof.payment_preimage();
		let hash = lightning::bitcoin::hashes::sha256::Hash::hash(&preimage.0);
		assert_eq!(proof.payment_hash().0, hash.to_byte_array());
	}

	/// Withholding every optional field is a valid choice by the payer, not an error.
	#[test]
	fn verifies_a_proof_disclosing_nothing_optional() {
		let proof = verify_bytes(&decode_hex(MINIMAL_PROOF_HEX)).unwrap();

		assert_eq!(proof.invoice_amount_msats(), None);
		assert_eq!(proof.invoice_created_at_secs(), None);
		assert!(proof.offer_description().is_none());
		assert!(proof.offer_issuer().is_none());
		assert!(proof.proof_note().is_none());

		// The fields verification itself needs are still there.
		assert_ne!(proof.merkle_root(), [0; 32]);
		assert_ne!(proof.payer_signing_pubkey(), proof.issuer_signing_pubkey());
	}

	#[test]
	fn round_trips_through_bech32() {
		let bytes = full_proof_bytes();
		let encoded = verify_bytes(&bytes).unwrap().to_bech32();

		assert!(encoded.starts_with("lnp1"), "unexpected prefix: {}", encoded);

		let reparsed = verify(&encoded).unwrap();
		assert_eq!(reparsed.encode(), bytes);
	}

	#[test]
	fn accepts_uppercase_and_continuations() {
		let encoded = verify_bytes(&full_proof_bytes()).unwrap().to_bech32();

		assert!(verify(&encoded.to_uppercase()).is_ok());

		let (head, tail) = encoded.split_at(encoded.len() / 2);
		assert!(verify(&alloc::format!("{}+\n {}", head, tail)).is_ok());
	}

	#[test]
	fn rejects_non_bech32_input() {
		assert_eq!(verify("").unwrap_err(), VerifyError::InvalidBech32);
		assert_eq!(verify("not a proof").unwrap_err(), VerifyError::InvalidBech32);
		// BOLT 12 strings carry no checksum, so this is rejected on its human-readable part
		// rather than on its data: `lno` is an offer, not a payer proof.
		assert_eq!(verify("lno1pqps7sjqpgt").unwrap_err(), VerifyError::InvalidBech32);
	}

	#[test]
	fn rejects_empty_and_truncated_bytes() {
		assert!(verify_bytes(&[]).is_err());

		let bytes = full_proof_bytes();
		assert!(verify_bytes(&bytes[..bytes.len() - 8]).is_err());
	}

	/// Appending a TLV the proof never committed to must not be accepted, or a proof could be
	/// extended after signing.
	#[test]
	fn rejects_appended_data() {
		let mut bytes = full_proof_bytes();
		bytes.extend_from_slice(&[0xfd, 0x27, 0x11, 0x01, 0x00]);

		assert!(verify_bytes(&bytes).is_err());
	}

	/// Corrupting any field the proof commits to must be rejected. `lightning` reports every failed
	/// cryptographic check as an undifferentiated decode failure, so all of these currently come
	/// back as [`VerifyError::MalformedProof`].
	#[test]
	fn rejects_a_corrupted_field() {
		let bytes = full_proof_bytes();
		let cases = [
			(PROOF_PREIMAGE, VerifyError::MalformedProof),
			(INVOICE_NODE_ID, VerifyError::MalformedProof),
			(ISSUER_SIGNATURE, VerifyError::MalformedProof),
			(PROOF_LEAF_HASHES, VerifyError::MalformedProof),
			(PROOF_OMITTED_MARKERS, VerifyError::MalformedProof),
			(PROOF_SIGNATURE, VerifyError::MalformedProof),
			(PROOF_NOTE, VerifyError::MalformedProof),
		];

		for (tlv_type, expected) in cases {
			let range = tlv_value_range(&bytes, tlv_type);
			let mut corrupted = bytes.clone();
			// Flip the last byte of the value: for the pubkey and signature fields an early byte
			// can instead make the field fail to deserialize, which is a different complaint.
			corrupted[range.end - 1] ^= 0x01;

			assert_eq!(
				verify_bytes(&corrupted).unwrap_err(),
				expected,
				"corrupting TLV {} was reported as the wrong error",
				tlv_type
			);
		}
	}

	fn test_offer() -> Offer {
		let hex = OFFER_HEX.trim();
		let bytes: Vec<u8> = (0..hex.len())
			.step_by(2)
			.map(|i| {
				u8::from_str_radix(&hex[i..i + 2], 16).expect("offer vector must be valid hex")
			})
			.collect();
		Offer::try_from(bytes).expect("offer vector must parse")
	}

	#[test]
	fn checks_the_recipient_of_the_offer_it_was_built_from() {
		let proof = verify_bytes(&decode_hex(OFFER_PROOF_HEX)).unwrap();
		assert!(proof.pays_offers_recipient(&test_offer()));

		let other_hex = OTHER_OFFER_HEX.trim();
		let other_bytes: Vec<u8> = (0..other_hex.len())
			.step_by(2)
			.map(|i| {
				u8::from_str_radix(&other_hex[i..i + 2], 16).expect("vector must be valid hex")
			})
			.collect();
		let someone_else = Offer::try_from(other_bytes).expect("other offer must parse");
		assert!(!proof.pays_offers_recipient(&someone_else));
	}

	#[test]
	fn checks_the_recipient_of_an_offer_in_its_bech32_form() {
		let proof = verify_bytes(&decode_hex(OFFER_PROOF_HEX)).unwrap();
		assert!(proof.pays_offers_recipient_str(&test_offer().to_string()));
		assert!(!proof.pays_offers_recipient_str("not an offer"));
		assert!(!proof.pays_offers_recipient_str(""));
	}

	/// Every byte of the stream must be covered by something the proof commits to. Walk all of
	/// them so no region is left silently unauthenticated.
	#[test]
	fn rejects_a_tampered_proof() {
		let bytes = full_proof_bytes();

		for index in 0..bytes.len() {
			let mut tampered = bytes.clone();
			tampered[index] ^= 0x01;

			assert!(
				verify_bytes(&tampered).is_err(),
				"flipping byte {} left the proof verifying",
				index
			);
		}
	}
}
