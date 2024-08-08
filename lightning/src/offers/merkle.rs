// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tagged hashes for use in signature calculation and verification.

use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, self};
use bitcoin::secp256k1::schnorr::Signature;
use crate::io;
use crate::util::ser::{BigSize, Readable, Writeable, Writer};

#[allow(unused_imports)]
use crate::prelude::*;

/// Valid type range for signature TLV records.
const SIGNATURE_TYPES: core::ops::RangeInclusive<u64> = 240..=1000;

tlv_stream!(SignatureTlvStream, SignatureTlvStreamRef, SIGNATURE_TYPES, {
	(240, signature: Signature),
});

/// A hash for use in a specific context by tweaking with a context-dependent tag as per [BIP 340]
/// and computed over the merkle root of a TLV stream to sign as defined in [BOLT 12].
///
/// [BIP 340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/// [BOLT 12]: https://github.com/rustyrussell/lightning-rfc/blob/guilt/offers/12-offer-encoding.md#signature-calculation
#[derive(Clone, Debug, PartialEq)]
pub struct TaggedHash {
	tag: &'static str,
	merkle_root: sha256::Hash,
	digest: Message,
}

impl TaggedHash {
	/// Creates a tagged hash with the given parameters.
	///
	/// Panics if `bytes` is not a well-formed TLV stream containing at least one TLV record.
	pub(super) fn from_valid_tlv_stream_bytes(tag: &'static str, bytes: &[u8]) -> Self {
		let tlv_stream = TlvStream::new(bytes);
		Self::from_tlv_stream(tag, tlv_stream)
	}

	/// Creates a tagged hash with the given parameters.
	///
	/// Panics if `tlv_stream` is not a well-formed TLV stream containing at least one TLV record.
	pub(super) fn from_tlv_stream<'a, I: core::iter::Iterator<Item = TlvRecord<'a>>>(
		tag: &'static str, tlv_stream: I
	) -> Self {
		let tag_hash = sha256::Hash::hash(tag.as_bytes());
		let merkle_root = root_hash(tlv_stream);
		let digest = Message::from_digest(tagged_hash(tag_hash, merkle_root).to_byte_array());
		Self {
			tag,
			merkle_root,
			digest,
		}
	}

	/// Returns the digest to sign.
	pub fn as_digest(&self) -> &Message {
		&self.digest
	}

	/// Returns the tag used in the tagged hash.
	pub fn tag(&self) -> &str {
		&self.tag
	}

	/// Returns the merkle root used in the tagged hash.
	pub fn merkle_root(&self) -> sha256::Hash {
		self.merkle_root
	}

	pub(super) fn to_bytes(&self) -> [u8; 32] {
		*self.digest.as_ref()
	}
}

impl AsRef<TaggedHash> for TaggedHash {
	fn as_ref(&self) -> &TaggedHash {
		self
	}
}

/// Error when signing messages.
#[derive(Debug, PartialEq)]
pub enum SignError {
	/// User-defined error when signing the message.
	Signing,
	/// Error when verifying the produced signature using the given pubkey.
	Verification(secp256k1::Error),
}

/// A function for signing a [`TaggedHash`].
pub(super) trait SignFn<T: AsRef<TaggedHash>> {
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	fn sign(&self, message: &T) -> Result<Signature, ()>;
}

impl<F> SignFn<TaggedHash> for F
where
	F: Fn(&TaggedHash) -> Result<Signature, ()>,
{
	fn sign(&self, message: &TaggedHash) -> Result<Signature, ()> {
		self(message)
	}
}

/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream, checking if it
/// can be verified with the supplied `pubkey`.
///
/// Since `message` is any type that implements [`AsRef<TaggedHash>`], `sign` may be a closure that
/// takes a message such as [`Bolt12Invoice`] or [`InvoiceRequest`]. This allows further message
/// verification before signing its [`TaggedHash`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
pub(super) fn sign_message<F, T>(
	f: F, message: &T, pubkey: PublicKey,
) -> Result<Signature, SignError>
where
	F: SignFn<T>,
	T: AsRef<TaggedHash>,
{
	let signature = f.sign(message).map_err(|()| SignError::Signing)?;

	let digest = message.as_ref().as_digest();
	let pubkey = pubkey.into();
	let secp_ctx = Secp256k1::verification_only();
	secp_ctx.verify_schnorr(&signature, digest, &pubkey).map_err(|e| SignError::Verification(e))?;

	Ok(signature)
}

/// Verifies the signature with a pubkey over the given message using a tagged hash as the message
/// digest.
pub(super) fn verify_signature(
	signature: &Signature, message: &TaggedHash, pubkey: PublicKey,
) -> Result<(), secp256k1::Error> {
	let digest = message.as_digest();
	let pubkey = pubkey.into();
	let secp_ctx = Secp256k1::verification_only();
	secp_ctx.verify_schnorr(signature, digest, &pubkey)
}

/// Computes a merkle root hash for the given data, which must be a well-formed TLV stream
/// containing at least one TLV record.
fn root_hash<'a, I: core::iter::Iterator<Item = TlvRecord<'a>>>(tlv_stream: I) -> sha256::Hash {
	let mut tlv_stream = tlv_stream.peekable();
	let nonce_tag = tagged_hash_engine(sha256::Hash::from_engine({
		let first_tlv_record = tlv_stream.peek().unwrap();
		let mut engine = sha256::Hash::engine();
		engine.input("LnNonce".as_bytes());
		engine.input(first_tlv_record.record_bytes);
		engine
	}));
	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	let mut leaves = Vec::new();
	for record in TlvStream::skip_signatures(tlv_stream) {
		leaves.push(tagged_hash_from_engine(leaf_tag.clone(), &record.record_bytes));
		leaves.push(tagged_hash_from_engine(nonce_tag.clone(), &record.type_bytes));
	}

	// Calculate the merkle root hash in place.
	let num_leaves = leaves.len();
	for level in 0.. {
		let step = 2 << level;
		let offset = step / 2;
		if offset >= num_leaves {
			break;
		}

		let left_branches = (0..num_leaves).step_by(step);
		let right_branches = (offset..num_leaves).step_by(step);
		for (i, j) in left_branches.zip(right_branches) {
			leaves[i] = tagged_branch_hash_from_engine(branch_tag.clone(), leaves[i], leaves[j]);
		}
	}

	*leaves.first().unwrap()
}

fn tagged_hash<T: AsRef<[u8]>>(tag: sha256::Hash, msg: T) -> sha256::Hash {
	let engine = tagged_hash_engine(tag);
	tagged_hash_from_engine(engine, msg)
}

fn tagged_hash_engine(tag: sha256::Hash) -> sha256::HashEngine {
	let mut engine = sha256::Hash::engine();
	engine.input(tag.as_ref());
	engine.input(tag.as_ref());
	engine
}

fn tagged_hash_from_engine<T: AsRef<[u8]>>(mut engine: sha256::HashEngine, msg: T) -> sha256::Hash {
	engine.input(msg.as_ref());
	sha256::Hash::from_engine(engine)
}

fn tagged_branch_hash_from_engine(
	mut engine: sha256::HashEngine, leaf1: sha256::Hash, leaf2: sha256::Hash,
) -> sha256::Hash {
	if leaf1 < leaf2 {
		engine.input(leaf1.as_ref());
		engine.input(leaf2.as_ref());
	} else {
		engine.input(leaf2.as_ref());
		engine.input(leaf1.as_ref());
	};
	sha256::Hash::from_engine(engine)
}

/// [`Iterator`] over a sequence of bytes yielding [`TlvRecord`]s. The input is assumed to be a
/// well-formed TLV stream.
#[derive(Clone)]
pub(super) struct TlvStream<'a> {
	data: io::Cursor<&'a [u8]>,
}

impl<'a> TlvStream<'a> {
	pub fn new(data: &'a [u8]) -> Self {
		Self {
			data: io::Cursor::new(data),
		}
	}

	pub fn range<T>(self, types: T) -> impl core::iter::Iterator<Item = TlvRecord<'a>>
	where
		T: core::ops::RangeBounds<u64> + Clone,
	{
		let take_range = types.clone();
		self.skip_while(move |record| !types.contains(&record.r#type))
			.take_while(move |record| take_range.contains(&record.r#type))
	}

	fn skip_signatures(
		tlv_stream: impl core::iter::Iterator<Item = TlvRecord<'a>>
	) -> impl core::iter::Iterator<Item = TlvRecord<'a>> {
		tlv_stream.filter(|record| !SIGNATURE_TYPES.contains(&record.r#type))
	}
}

/// A slice into a [`TlvStream`] for a record.
pub(super) struct TlvRecord<'a> {
	pub(super) r#type: u64,
	type_bytes: &'a [u8],
	// The entire TLV record.
	pub(super) record_bytes: &'a [u8],
}

impl<'a> Iterator for TlvStream<'a> {
	type Item = TlvRecord<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.data.position() < self.data.get_ref().len() as u64 {
			let start = self.data.position();

			let r#type = <BigSize as Readable>::read(&mut self.data).unwrap().0;
			let offset = self.data.position();
			let type_bytes = &self.data.get_ref()[start as usize..offset as usize];

			let length = <BigSize as Readable>::read(&mut self.data).unwrap().0;
			let offset = self.data.position();
			let end = offset + length;

			let _value = &self.data.get_ref()[offset as usize..end as usize];
			let record_bytes = &self.data.get_ref()[start as usize..end as usize];

			self.data.set_position(end);

			Some(TlvRecord { r#type, type_bytes, record_bytes })
		} else {
			None
		}
	}
}

/// Encoding for a pre-serialized TLV stream that excludes any signature TLV records.
///
/// Panics if the wrapped bytes are not a well-formed TLV stream.
pub(super) struct WithoutSignatures<'a>(pub &'a [u8]);

impl<'a> Writeable for WithoutSignatures<'a> {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let tlv_stream = TlvStream::new(self.0);
		for record in TlvStream::skip_signatures(tlv_stream) {
			writer.write_all(record.record_bytes)?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::{SIGNATURE_TYPES, TlvStream, WithoutSignatures};

	use bitcoin::hashes::{Hash, sha256};
	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
	use bitcoin::secp256k1::schnorr::Signature;
	use crate::offers::offer::{Amount, OfferBuilder};
	use crate::offers::invoice_request::{InvoiceRequest, UnsignedInvoiceRequest};
	use crate::offers::parse::Bech32Encode;
	use crate::offers::test_utils::{payer_pubkey, recipient_pubkey};
	use crate::util::ser::Writeable;

	#[test]
	fn calculates_merkle_root_hash() {
		// BOLT 12 test vectors
		macro_rules! tlv1 { () => { "010203e8" } }
		macro_rules! tlv2 { () => { "02080000010000020003" } }
		macro_rules! tlv3 { () => { "03310266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351800000000000000010000000000000002" } }
		assert_eq!(
			super::root_hash(TlvStream::new(&<Vec<u8>>::from_hex(tlv1!()).unwrap())),
			sha256::Hash::from_slice(&<Vec<u8>>::from_hex("b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93").unwrap()).unwrap(),
		);
		assert_eq!(
			super::root_hash(TlvStream::new(&<Vec<u8>>::from_hex(concat!(tlv1!(), tlv2!())).unwrap())),
			sha256::Hash::from_slice(&<Vec<u8>>::from_hex("c3774abbf4815aa54ccaa026bff6581f01f3be5fe814c620a252534f434bc0d1").unwrap()).unwrap(),
		);
		assert_eq!(
			super::root_hash(TlvStream::new(&<Vec<u8>>::from_hex(concat!(tlv1!(), tlv2!(), tlv3!())).unwrap())),
			sha256::Hash::from_slice(&<Vec<u8>>::from_hex("ab2e79b1283b0b31e0b035258de23782df6b89a38cfa7237bde69aed1a658c5d").unwrap()).unwrap(),
		);
	}

	#[test]
	fn calculates_merkle_root_hash_from_invoice_request() {
		let secp_ctx = Secp256k1::new();
		let recipient_pubkey = {
			let secret_key = SecretKey::from_slice(&<Vec<u8>>::from_hex("4141414141414141414141414141414141414141414141414141414141414141").unwrap()).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key).public_key()
		};
		let payer_keys = {
			let secret_key = SecretKey::from_slice(&<Vec<u8>>::from_hex("4242424242424242424242424242424242424242424242424242424242424242").unwrap()).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key)
		};

		// BOLT 12 test vectors
		let invoice_request = OfferBuilder::new(recipient_pubkey)
			.description("A Mathematical Treatise".into())
			.amount(Amount::Currency { iso4217_code: *b"USD", amount: 100 })
			.build_unchecked()
			.request_invoice(vec![0; 8], payer_keys.public_key()).unwrap()
			.build_unchecked()
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &payer_keys))
			)
			.unwrap();
		assert_eq!(
			invoice_request.to_string(),
			"lnr1qqyqqqqqqqqqqqqqqcp4256ypqqkgzshgysy6ct5dpjk6ct5d93kzmpq23ex2ct5d9ek293pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpjkppqvjx204vgdzgsqpvcp4mldl3plscny0rt707gvpdh6ndydfacz43euzqhrurageg3n7kafgsek6gz3e9w52parv8gs2hlxzk95tzeswywffxlkeyhml0hh46kndmwf4m6xma3tkq2lu04qz3slje2rfthc89vss",
		);
		assert_eq!(
			super::root_hash(TlvStream::new(&invoice_request.bytes[..])),
			sha256::Hash::from_slice(&<Vec<u8>>::from_hex("608407c18ad9a94d9ea2bcdbe170b6c20c462a7833a197621c916f78cf18e624").unwrap()).unwrap(),
		);
		assert_eq!(
			invoice_request.signature(),
			Signature::from_slice(&<Vec<u8>>::from_hex("b8f83ea3288cfd6ea510cdb481472575141e8d8744157f98562d162cc1c472526fdb24befefbdebab4dbb726bbd1b7d8aec057f8fa805187e5950d2bbe0e5642").unwrap()).unwrap(),
		);
	}

        #[test]
        fn compute_tagged_hash() {
                let unsigned_invoice_request = OfferBuilder::new(recipient_pubkey())
                        .amount_msats(1000)
                        .build().unwrap()
                        .request_invoice(vec![1; 32], payer_pubkey()).unwrap()
                        .payer_note("bar".into())
                        .build().unwrap();

                // Simply test that we can grab the tag and merkle root exposed by the accessor
                // functions, then use them to succesfully compute a tagged hash.
                let tagged_hash = unsigned_invoice_request.as_ref();
                let expected_digest = unsigned_invoice_request.as_ref().as_digest();
                let tag = sha256::Hash::hash(tagged_hash.tag().as_bytes());
                let actual_digest = Message::from_digest(super::tagged_hash(tag, tagged_hash.merkle_root()).to_byte_array());
                assert_eq!(*expected_digest, actual_digest);
        }

	#[test]
	fn skips_encoding_signature_tlv_records() {
		let secp_ctx = Secp256k1::new();
		let recipient_pubkey = {
			let secret_key = SecretKey::from_slice(&[41; 32]).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key).public_key()
		};
		let payer_keys = {
			let secret_key = SecretKey::from_slice(&[42; 32]).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key)
		};

		let invoice_request = OfferBuilder::new(recipient_pubkey)
			.amount_msats(100)
			.build_unchecked()
			.request_invoice(vec![0; 8], payer_keys.public_key()).unwrap()
			.build_unchecked()
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &payer_keys))
			)
			.unwrap();

		let mut bytes_without_signature = Vec::new();
		WithoutSignatures(&invoice_request.bytes).write(&mut bytes_without_signature).unwrap();

		assert_ne!(bytes_without_signature, invoice_request.bytes);
		assert_eq!(
			TlvStream::new(&bytes_without_signature).count(),
			TlvStream::new(&invoice_request.bytes).count() - 1,
		);
	}

	#[test]
	fn iterates_over_tlv_stream_range() {
		let secp_ctx = Secp256k1::new();
		let recipient_pubkey = {
			let secret_key = SecretKey::from_slice(&[41; 32]).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key).public_key()
		};
		let payer_keys = {
			let secret_key = SecretKey::from_slice(&[42; 32]).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key)
		};

		let invoice_request = OfferBuilder::new(recipient_pubkey)
			.amount_msats(100)
			.build_unchecked()
			.request_invoice(vec![0; 8], payer_keys.public_key()).unwrap()
			.build_unchecked()
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &payer_keys))
			)
			.unwrap();

		let tlv_stream = TlvStream::new(&invoice_request.bytes).range(0..1)
			.chain(TlvStream::new(&invoice_request.bytes).range(1..80))
			.chain(TlvStream::new(&invoice_request.bytes).range(80..160))
			.chain(TlvStream::new(&invoice_request.bytes).range(160..240))
			.chain(TlvStream::new(&invoice_request.bytes).range(SIGNATURE_TYPES))
			.map(|r| r.record_bytes.to_vec())
			.flatten()
			.collect::<Vec<u8>>();

		assert_eq!(tlv_stream, invoice_request.bytes);
	}

	impl AsRef<[u8]> for InvoiceRequest {
		fn as_ref(&self) -> &[u8] {
			&self.bytes
		}
	}

	impl Bech32Encode for InvoiceRequest {
		const BECH32_HRP: &'static str = "lnr";
	}

	impl core::fmt::Display for InvoiceRequest {
		fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
			self.fmt_bech32_str(f)
		}
	}
}
