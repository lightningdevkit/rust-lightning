// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! UniFFI-compatible payer proof verification wrappers.

// Note this crate cannot `forbid(unsafe_code)` the way `lightning-payer-proof` does: the
// scaffolding uniffi generates from `interface.udl` is the FFI entry point and exports
// `#[no_mangle]` symbols. Nothing hand-written here is unsafe.
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

uniffi::include_scaffolding!("interface");

/// Why a payer proof was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
	/// The string is not a bech32-encoded payer proof, or carries a prefix other than `lnp`.
	InvalidBech32,
	/// The bytes decoded as bech32 but are not a well-formed payer proof TLV stream.
	MalformedProof,
	/// The TLV stream is well-formed but omits a field required to verify the proof at all.
	IncompleteProof,
}

impl core::fmt::Display for VerifyError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		f.write_str(match self {
			VerifyError::InvalidBech32 => "not a bech32-encoded payer proof",
			VerifyError::MalformedProof => "malformed payer proof",
			VerifyError::IncompleteProof => "payer proof is missing a required field",
		})
	}
}

impl std::error::Error for VerifyError {}

impl From<lightning_payer_proof::VerifyError> for VerifyError {
	fn from(error: lightning_payer_proof::VerifyError) -> Self {
		match error {
			lightning_payer_proof::VerifyError::InvalidBech32 => VerifyError::InvalidBech32,
			lightning_payer_proof::VerifyError::MalformedProof => VerifyError::MalformedProof,
			lightning_payer_proof::VerifyError::IncompleteProof => VerifyError::IncompleteProof,
		}
	}
}

/// A payer proof that passed every check in [`verify`].
///
/// This proves the preimage hashes to the payment hash, the issuer signed the disclosed fields,
/// and the payer signed this proof. It does not prove they paid the invoice you have in mind.
/// Anyone can issue an invoice to themselves, pay it, and hand out a proof that verifies. Check
/// the proof against the offer with [`pays_offers_recipient`].
///
/// Keys, hashes and signatures are wire-encoded (33-byte compressed pubkeys, 32-byte hashes or
/// preimages, 64-byte BIP 340 signatures). Withheld fields are `None`.
#[derive(Clone, Debug)]
pub struct VerifiedPayerProof {
	/// The payment hash this proof settles, 32 bytes.
	pub payment_hash: Vec<u8>,
	/// The preimage that unlocked the payment, 32 bytes, proven to hash to `payment_hash`.
	pub payment_preimage: Vec<u8>,
	/// The compressed public key the payer signed this proof with, 33 bytes.
	pub payer_signing_pubkey: Vec<u8>,
	/// The compressed public key the invoice was signed with, 33 bytes, identifying who issued it.
	pub issuer_signing_pubkey: Vec<u8>,
	/// The invoiced amount in millisatoshis, if disclosed.
	pub invoice_amount_msats: Option<u64>,
	/// When the invoice was created, in seconds since the Unix epoch, if disclosed.
	pub invoice_created_at_secs: Option<u64>,
	/// The offer description the invoice was built from, if disclosed.
	///
	/// Untrusted text; sanitize control characters before displaying.
	pub offer_description: Option<String>,
	/// The offer issuer, if disclosed.
	///
	/// A human-readable label chosen by whoever built the offer, not an identity.
	pub offer_issuer: Option<String>,
	/// A note the payer attached when building the proof, if any.
	pub proof_note: Option<String>,
	/// The merkle root of the invoice the issuer signed, 32 bytes.
	pub merkle_root: Vec<u8>,
	/// The issuer's signature over the invoice, 64 bytes in BIP 340 form.
	pub invoice_signature: Vec<u8>,
	/// The payer's signature over this proof, 64 bytes in BIP 340 form.
	pub proof_signature: Vec<u8>,
	/// The proof re-encoded as the `lnp1...` string it was parsed from.
	pub bech32: String,
	/// The proof's raw TLV stream, as accepted by [`verify_bytes`].
	pub encoded: Vec<u8>,
}

impl From<lightning_payer_proof::VerifiedPayerProof> for VerifiedPayerProof {
	fn from(proof: lightning_payer_proof::VerifiedPayerProof) -> Self {
		Self {
			payment_hash: proof.payment_hash().0.to_vec(),
			payment_preimage: proof.payment_preimage().0.to_vec(),
			payer_signing_pubkey: proof.payer_signing_pubkey().serialize().to_vec(),
			issuer_signing_pubkey: proof.issuer_signing_pubkey().serialize().to_vec(),
			invoice_amount_msats: proof.invoice_amount_msats(),
			invoice_created_at_secs: proof.invoice_created_at_secs(),
			offer_description: proof.offer_description().map(|text| text.0),
			offer_issuer: proof.offer_issuer().map(|text| text.0),
			proof_note: proof.proof_note().map(|text| text.0),
			merkle_root: proof.merkle_root().to_vec(),
			invoice_signature: proof.invoice_signature().to_vec(),
			proof_signature: proof.proof_signature().to_vec(),
			bech32: proof.to_bech32(),
			encoded: proof.encode(),
		}
	}
}

/// Verifies a bech32-encoded (`lnp1...`) payer proof.
///
/// Uppercase and BOLT 12 `+` line-splitting are accepted.
pub fn verify(proof: String) -> Result<VerifiedPayerProof, VerifyError> {
	lightning_payer_proof::verify(&proof).map(Into::into).map_err(Into::into)
}

/// Verifies a payer proof from its raw TLV bytes, skipping bech32.
pub fn verify_bytes(proof: Vec<u8>) -> Result<VerifiedPayerProof, VerifyError> {
	lightning_payer_proof::verify_bytes(&proof).map(Into::into).map_err(Into::into)
}

/// Whether this already-verified `proof` was issued by the recipient of `offer` (`lno1...`).
///
/// A `true` identifies the recipient, not the offer. A garbage offer is `false`.
pub fn pays_offers_recipient(proof: VerifiedPayerProof, offer: String) -> bool {
	lightning_payer_proof::verify_bytes(&proof.encoded)
		.map(|proof| proof.pays_offers_recipient_str(&offer))
		.unwrap_or(false)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The same proof `lightning-payer-proof`'s own tests use: a 42,000 msat invoice created at
	/// Unix time 1,700,000,000, disclosing the description, issuer, amount and timestamp, with the
	/// payer note "order-1234".
	const FULL_PROOF_HEX: &str = include_str!("../../test_vectors/valid_proof.hex");

	/// The same invoice with none of the optional fields disclosed and no note.
	const MINIMAL_PROOF_HEX: &str = include_str!("../../test_vectors/minimal_proof.hex");

	/// An offer, a proof over an invoice built from it, and a second offer that differs only in
	/// issuer id.
	const OFFER_HEX: &str = include_str!("../../test_vectors/offer.hex");
	const OFFER_PROOF_HEX: &str = include_str!("../../test_vectors/offer_proof.hex");
	const OTHER_OFFER_HEX: &str = include_str!("../../test_vectors/other_offer.hex");

	fn decode_hex(hex: &str) -> Vec<u8> {
		let hex = hex.trim();
		(0..hex.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("vector must be valid hex"))
			.collect()
	}

	/// Every field must survive the flattening at the width the wire encoding gives it, since a
	/// caller on the other side of the FFI has only these bytes to work with.
	#[test]
	fn flattens_a_verified_proof() {
		let proof = verify_bytes(decode_hex(FULL_PROOF_HEX)).unwrap();

		assert_eq!(proof.payment_hash.len(), 32);
		assert_eq!(proof.payment_preimage.len(), 32);
		assert_eq!(proof.merkle_root.len(), 32);
		assert_eq!(proof.payer_signing_pubkey.len(), 33);
		assert_eq!(proof.issuer_signing_pubkey.len(), 33);
		assert_eq!(proof.invoice_signature.len(), 64);
		assert_eq!(proof.proof_signature.len(), 64);
		assert_ne!(proof.payer_signing_pubkey, proof.issuer_signing_pubkey);

		assert_eq!(proof.invoice_amount_msats, Some(42_000));
		assert_eq!(proof.invoice_created_at_secs, Some(1_700_000_000));
		assert_eq!(proof.offer_description.as_deref(), Some("coffee beans"));
		assert_eq!(proof.offer_issuer.as_deref(), Some("LDK Roastery"));
		assert_eq!(proof.proof_note.as_deref(), Some("order-1234"));

		assert!(proof.bech32.starts_with("lnp1"), "unexpected prefix: {}", proof.bech32);
		assert_eq!(verify(proof.bech32.clone()).unwrap().encoded, proof.encoded);
	}

	/// Withheld fields must arrive as `None`, not as empty strings or zeroes, or a caller cannot
	/// tell "not disclosed" from "disclosed as nothing".
	#[test]
	fn withheld_fields_are_none() {
		let proof = verify_bytes(decode_hex(MINIMAL_PROOF_HEX)).unwrap();

		assert_eq!(proof.invoice_amount_msats, None);
		assert_eq!(proof.invoice_created_at_secs, None);
		assert_eq!(proof.offer_description, None);
		assert_eq!(proof.offer_issuer, None);
		assert_eq!(proof.proof_note, None);
	}

	/// The whole point of mirroring the error enum is that the specific check still comes through.
	#[test]
	fn maps_errors_to_their_own_variants() {
		assert_eq!(verify(String::new()).unwrap_err(), VerifyError::InvalidBech32);
		assert_eq!(verify("not a proof".to_string()).unwrap_err(), VerifyError::InvalidBech32);

		let mut corrupted = decode_hex(FULL_PROOF_HEX);
		let last = corrupted.len() - 1;
		corrupted[last] ^= 0x01;
		assert_eq!(verify_bytes(corrupted).unwrap_err(), VerifyError::MalformedProof);
	}

	fn offer_bech32(hex: &str) -> String {
		let bytes = decode_hex(hex);
		lightning_payer_proof::Offer::try_from(bytes).expect("offer vector must parse").to_string()
	}

	#[test]
	fn checks_the_recipient_of_a_verified_proof() {
		let proof = verify_bytes(decode_hex(OFFER_PROOF_HEX)).unwrap();
		assert!(pays_offers_recipient(proof.clone(), offer_bech32(OFFER_HEX)));
		assert!(!pays_offers_recipient(proof.clone(), offer_bech32(OTHER_OFFER_HEX)));
		assert!(!pays_offers_recipient(proof, "not an offer".to_string()));
	}
}
