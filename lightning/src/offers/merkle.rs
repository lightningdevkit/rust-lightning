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

/// Verifies the signature with a pubkey over the given bytes using a tagged hash as the message
/// digest.
pub(super) fn verify_signature(
	signature: &Signature, tag: &str, bytes: &[u8], pubkey: PublicKey,
) -> Result<(), secp256k1::Error> {
	let tag = sha256::Hash::hash(tag.as_bytes());
	let merkle_root = root_hash(bytes);
	let digest = Message::from_slice(&tagged_hash(tag, merkle_root)).unwrap();
	let pubkey = pubkey.into();
	let secp_ctx = Secp256k1::verification_only();
	secp_ctx.verify_schnorr(signature, &digest, &pubkey)
}

/// Computes a merkle root hash for the given data, which must be a well-formed TLV stream
/// containing at least one TLV record.
fn root_hash(data: &[u8]) -> sha256::Hash {
	let mut tlv_stream = TlvStream::new(&data[..]).peekable();
	let nonce_tag = tagged_hash_engine(sha256::Hash::from_engine({
		let mut engine = sha256::Hash::engine();
		engine.input("LnNonce".as_bytes());
		engine.input(tlv_stream.peek().unwrap().type_bytes);
		engine
	}));
	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	let mut leaves = Vec::new();
	for record in tlv_stream {
		if !SIGNATURE_TYPES.contains(&record.r#type.0) {
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

		for (i, j) in (0..num_leaves).step_by(step).zip((offset..num_leaves).step_by(step)) {
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
	r#type: BigSize,
	type_bytes: &'a [u8],
	data: &'a [u8],
}

impl AsRef<[u8]> for TlvRecord<'_> {
	fn as_ref(&self) -> &[u8] { &self.data }
}

impl<'a> Iterator for TlvStream<'a> {
	type Item = TlvRecord<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.data.position() < self.data.get_ref().len() as u64 {
			let start = self.data.position();

			let r#type: BigSize = Readable::read(&mut self.data).unwrap();
			let offset = self.data.position();
			let type_bytes = &self.data.get_ref()[start as usize..offset as usize];

			let length: BigSize = Readable::read(&mut self.data).unwrap();
			let offset = self.data.position();
			let end = offset + length.0;

			let _value = &self.data.get_ref()[offset as usize..end as usize];
			let data = &self.data.get_ref()[start as usize..end as usize];

			self.data.set_position(end);

			Some(TlvRecord { r#type, type_bytes, data })
		} else {
			None
		}
	}
}
