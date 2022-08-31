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
use crate::util::ser::{BigSize, Readable};

use crate::prelude::*;

/// Valid type range for signature TLV records.
const SIGNATURE_TYPES: core::ops::RangeInclusive<u64> = 240..=1000;

tlv_stream!(SignatureTlvStream, SignatureTlvStreamRef, SIGNATURE_TYPES, {
	(240, signature: Signature),
});

/// Error when signing messages.
#[derive(Debug)]
pub enum SignError<E> {
	/// User-defined error when signing the message.
	Signing(E),
	/// Error when verifying the produced signature using the given pubkey.
	Verification(secp256k1::Error),
}

/// Signs a message digest consisting of a tagged hash of the given bytes, checking if it can be
/// verified with the supplied pubkey.
///
/// Panics if `bytes` is not a well-formed TLV stream containing at least one TLV record.
pub(super) fn sign_message<F, E>(
	sign: F, tag: &str, bytes: &[u8], pubkey: PublicKey,
) -> Result<Signature, SignError<E>>
where
	F: FnOnce(&Message) -> Result<Signature, E>
{
	let digest = message_digest(tag, bytes);
	let signature = sign(&digest).map_err(|e| SignError::Signing(e))?;

	let pubkey = pubkey.into();
	let secp_ctx = Secp256k1::verification_only();
	secp_ctx.verify_schnorr(&signature, &digest, &pubkey).map_err(|e| SignError::Verification(e))?;

	Ok(signature)
}

/// Verifies the signature with a pubkey over the given bytes using a tagged hash as the message
/// digest.
///
/// Panics if `bytes` is not a well-formed TLV stream containing at least one TLV record.
pub(super) fn verify_signature(
	signature: &Signature, tag: &str, bytes: &[u8], pubkey: PublicKey,
) -> Result<(), secp256k1::Error> {
	let digest = message_digest(tag, bytes);
	let pubkey = pubkey.into();
	let secp_ctx = Secp256k1::verification_only();
	secp_ctx.verify_schnorr(signature, &digest, &pubkey)
}

fn message_digest(tag: &str, bytes: &[u8]) -> Message {
	let tag = sha256::Hash::hash(tag.as_bytes());
	let merkle_root = root_hash(bytes);
	Message::from_slice(&tagged_hash(tag, merkle_root)).unwrap()
}

/// Computes a merkle root hash for the given data, which must be a well-formed TLV stream
/// containing at least one TLV record.
fn root_hash(data: &[u8]) -> sha256::Hash {
	let mut tlv_stream = TlvStream::new(&data[..]).peekable();
	let nonce_tag = tagged_hash_engine(sha256::Hash::from_engine({
		let mut engine = sha256::Hash::engine();
		engine.input("LnNonce".as_bytes());
		engine.input(tlv_stream.peek().unwrap().record_bytes);
		engine
	}));
	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	let mut leaves = Vec::new();
	for record in tlv_stream {
		if !SIGNATURE_TYPES.contains(&record.r#type) {
			leaves.push(tagged_hash_from_engine(leaf_tag.clone(), &record));
			leaves.push(tagged_hash_from_engine(nonce_tag.clone(), &record.type_bytes));
		}
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
struct TlvStream<'a> {
	data: io::Cursor<&'a [u8]>,
}

impl<'a> TlvStream<'a> {
	fn new(data: &'a [u8]) -> Self {
		Self {
			data: io::Cursor::new(data),
		}
	}
}

/// A slice into a [`TlvStream`] for a record.
struct TlvRecord<'a> {
	r#type: u64,
	type_bytes: &'a [u8],
	// The entire TLV record.
	record_bytes: &'a [u8],
}

impl AsRef<[u8]> for TlvRecord<'_> {
	fn as_ref(&self) -> &[u8] { &self.record_bytes }
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

#[cfg(test)]
mod tests {
	use bitcoin::hashes::{Hash, sha256};

	#[test]
	fn calculates_merkle_root_hash() {
		// BOLT 12 test vectors
		macro_rules! tlv1 { () => { "010203e8" } }
		macro_rules! tlv2 { () => { "02080000010000020003" } }
		macro_rules! tlv3 { () => { "03310266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351800000000000000010000000000000002" } }
		assert_eq!(
			super::root_hash(&hex::decode(tlv1!()).unwrap()),
			sha256::Hash::from_slice(&hex::decode("b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93").unwrap()).unwrap(),
		);
		assert_eq!(
			super::root_hash(&hex::decode(concat!(tlv1!(), tlv2!())).unwrap()),
			sha256::Hash::from_slice(&hex::decode("c3774abbf4815aa54ccaa026bff6581f01f3be5fe814c620a252534f434bc0d1").unwrap()).unwrap(),
		);
		assert_eq!(
			super::root_hash(&hex::decode(concat!(tlv1!(), tlv2!(), tlv3!())).unwrap()),
			sha256::Hash::from_slice(&hex::decode("ab2e79b1283b0b31e0b035258de23782df6b89a38cfa7237bde69aed1a658c5d").unwrap()).unwrap(),
		);
	}
}
