// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tagged hashes for use in signature calculation and verification.

use crate::io;
use crate::util::ser::{BigSize, Readable, Writeable, Writer};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, Message, PublicKey, Secp256k1};

#[allow(unused_imports)]
use crate::prelude::*;

/// Valid type range for signature TLV records.
pub(super) const SIGNATURE_TYPES: core::ops::RangeInclusive<u64> = 240..=1000;

tlv_stream!(SignatureTlvStream, SignatureTlvStreamRef<'a>, SIGNATURE_TYPES, {
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
		tag: &'static str, tlv_stream: I,
	) -> Self {
		let tag_hash = sha256::Hash::hash(tag.as_bytes());
		let merkle_root = root_hash(tlv_stream);
		let digest = Message::from_digest(tagged_hash(tag_hash, merkle_root).to_byte_array());
		Self { tag, merkle_root, digest }
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

	/// Creates a tagged hash from a pre-computed merkle root.
	pub(super) fn from_merkle_root(tag: &'static str, merkle_root: sha256::Hash) -> Self {
		let tag_hash = sha256::Hash::hash(tag.as_bytes());
		let digest = Message::from_digest(tagged_hash(tag_hash, merkle_root).to_byte_array());
		Self { tag, merkle_root, digest }
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
///
/// This is not exported to bindings users as signing functions should just be used per-signed-type
/// instead.
pub trait SignFn<T: AsRef<TaggedHash>> {
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
pub fn sign_message<F, T>(f: F, message: &T, pubkey: PublicKey) -> Result<Signature, SignError>
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
pub fn verify_signature(
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
	for record in tlv_stream.filter(|record| !SIGNATURE_TYPES.contains(&record.r#type)) {
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
		Self { data: io::Cursor::new(data) }
	}

	pub fn range<T>(self, types: T) -> impl core::iter::Iterator<Item = TlvRecord<'a>>
	where
		T: core::ops::RangeBounds<u64> + Clone,
	{
		let take_range = types.clone();
		self.skip_while(move |record| !types.contains(&record.r#type))
			.take_while(move |record| take_range.contains(&record.r#type))
	}
}

/// A slice into a [`TlvStream`] for a record.
pub(super) struct TlvRecord<'a> {
	pub(super) r#type: u64,
	type_bytes: &'a [u8],
	// The entire TLV record.
	pub(super) record_bytes: &'a [u8],
	pub(super) end: usize,
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

			let record_bytes = &self.data.get_ref()[start as usize..end as usize];

			self.data.set_position(end);

			Some(TlvRecord { r#type, type_bytes, record_bytes, end: end as usize })
		} else {
			None
		}
	}
}

impl<'a> Writeable for TlvRecord<'a> {
	#[inline]
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(self.record_bytes)
	}
}

// ============================================================================
// Selective Disclosure for Payer Proofs (BOLT 12 extension)
// ============================================================================

use alloc::collections::BTreeSet;

/// Error during selective disclosure operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectiveDisclosureError {
	/// The omitted markers are not in strict ascending order.
	InvalidOmittedMarkersOrder,
	/// The omitted markers contain an invalid marker (0 or signature type).
	InvalidOmittedMarkersMarker,
	/// The leaf_hashes count doesn't match included TLVs.
	LeafHashCountMismatch,
	/// Insufficient missing_hashes to reconstruct the tree.
	InsufficientMissingHashes,
	/// The TLV stream is empty.
	EmptyTlvStream,
}

/// Data needed to reconstruct a merkle root with selective disclosure.
///
/// This is used in payer proofs to allow verification of an invoice signature
/// without revealing all invoice fields.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct SelectiveDisclosure {
	/// Nonce hashes for included TLVs (in TLV type order).
	pub(super) leaf_hashes: Vec<sha256::Hash>,
	/// Marker numbers for omitted TLVs (excluding implicit TLV0).
	pub(super) omitted_markers: Vec<u64>,
	/// Minimal merkle hashes for omitted subtrees.
	pub(super) missing_hashes: Vec<sha256::Hash>,
	/// The complete merkle root.
	pub(super) merkle_root: sha256::Hash,
}

/// Internal data for each TLV during tree construction.
struct TlvMerkleData {
	tlv_type: u64,
	per_tlv_hash: sha256::Hash,
	is_included: bool,
}

/// Compute selective disclosure data from a TLV stream.
///
/// This builds the full merkle tree and extracts the data needed for a payer proof:
/// - `leaf_hashes`: nonce hashes for included TLVs
/// - `omitted_markers`: marker numbers for omitted TLVs
/// - `missing_hashes`: minimal merkle hashes for omitted subtrees
///
/// # Arguments
/// * `tlv_bytes` - Complete TLV stream (e.g., invoice bytes without signature)
/// * `included_types` - Set of TLV types to include in the disclosure
pub(super) fn compute_selective_disclosure(
	tlv_bytes: &[u8], included_types: &BTreeSet<u64>,
) -> Result<SelectiveDisclosure, SelectiveDisclosureError> {
	let mut tlv_stream = TlvStream::new(tlv_bytes).peekable();
	let first_record = tlv_stream.peek().ok_or(SelectiveDisclosureError::EmptyTlvStream)?;
	let nonce_tag_hash = sha256::Hash::from_engine({
		let mut engine = sha256::Hash::engine();
		engine.input("LnNonce".as_bytes());
		engine.input(first_record.record_bytes);
		engine
	});

	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let nonce_tag = tagged_hash_engine(nonce_tag_hash);
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	let mut tlv_data: Vec<TlvMerkleData> = Vec::new();
	let mut leaf_hashes: Vec<sha256::Hash> = Vec::new();
	for record in tlv_stream.filter(|r| !SIGNATURE_TYPES.contains(&r.r#type)) {
		let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record.record_bytes);
		let nonce_hash = tagged_hash_from_engine(nonce_tag.clone(), record.type_bytes);
		let per_tlv_hash =
			tagged_branch_hash_from_engine(branch_tag.clone(), leaf_hash, nonce_hash);

		let is_included = included_types.contains(&record.r#type);
		if is_included {
			leaf_hashes.push(nonce_hash);
		}
		tlv_data.push(TlvMerkleData { tlv_type: record.r#type, per_tlv_hash, is_included });
	}

	if tlv_data.is_empty() {
		return Err(SelectiveDisclosureError::EmptyTlvStream);
	}
	let omitted_markers = compute_omitted_markers(&tlv_data);
	let (merkle_root, missing_hashes) = build_tree_with_disclosure(&tlv_data, &branch_tag);

	Ok(SelectiveDisclosure { leaf_hashes, omitted_markers, missing_hashes, merkle_root })
}

/// Compute omitted markers per BOLT 12 payer proof spec.
fn compute_omitted_markers(tlv_data: &[TlvMerkleData]) -> Vec<u64> {
	let mut markers = Vec::new();
	let mut prev_included_type: Option<u64> = None;
	let mut prev_marker: Option<u64> = None;

	for data in tlv_data {
		if data.tlv_type == 0 {
			continue;
		}

		if !data.is_included {
			let marker = if let Some(prev_type) = prev_included_type {
				prev_type + 1
			} else if let Some(last_marker) = prev_marker {
				last_marker + 1
			} else {
				1
			};

			markers.push(marker);
			prev_marker = Some(marker);
			prev_included_type = None;
		} else {
			prev_included_type = Some(data.tlv_type);
			prev_marker = None;
		}
	}

	markers
}

/// A node in the merkle tree during selective disclosure processing.
struct TreeNode {
	hash: Option<sha256::Hash>,
	included: bool,
	min_type: u64,
}

/// Build merkle tree and collect missing_hashes for omitted subtrees.
///
/// Returns hashes sorted by ascending TLV type as required by the spec. For internal
/// nodes, the type used for ordering is the minimum TLV type in that subtree.
///
/// Uses `n` tree nodes (one per TLV) rather than `2n`, since the per-TLV hashes
/// already combine leaf and nonce. The tree traversal starts at level 0 to pair
/// adjacent per-TLV hashes, matching the structure of `root_hash()`.
fn build_tree_with_disclosure(
	tlv_data: &[TlvMerkleData], branch_tag: &sha256::HashEngine,
) -> (sha256::Hash, Vec<sha256::Hash>) {
	let num_nodes = tlv_data.len();
	debug_assert!(num_nodes > 0, "TLV stream must contain at least one record");

	let num_omitted = tlv_data.iter().filter(|d| !d.is_included).count();

	let mut nodes: Vec<TreeNode> = tlv_data
		.iter()
		.map(|data| TreeNode {
			hash: Some(data.per_tlv_hash),
			included: data.is_included,
			min_type: data.tlv_type,
		})
		.collect();

	let mut missing_with_types: Vec<(u64, sha256::Hash)> = Vec::with_capacity(num_omitted);

	for level in 0.. {
		let step = 2 << level;
		let offset = step / 2;
		if offset >= num_nodes {
			break;
		}

		for (left_pos, right_pos) in
			(0..num_nodes).step_by(step).zip((offset..num_nodes).step_by(step))
		{
			let left_hash = nodes[left_pos].hash;
			let right_hash = nodes[right_pos].hash;
			let left_incl = nodes[left_pos].included;
			let right_incl = nodes[right_pos].included;
			let right_min_type = nodes[right_pos].min_type;

			match (left_hash, right_hash, left_incl, right_incl) {
				(Some(l), Some(r), true, false) => {
					missing_with_types.push((right_min_type, r));
					nodes[left_pos].hash =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					nodes[left_pos].included = true;
					nodes[left_pos].min_type =
						core::cmp::min(nodes[left_pos].min_type, right_min_type);
				},
				(Some(l), Some(r), false, true) => {
					missing_with_types.push((nodes[left_pos].min_type, l));
					let left_min = nodes[left_pos].min_type;
					nodes[left_pos].hash =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					nodes[left_pos].included = true;
					nodes[left_pos].min_type = core::cmp::min(left_min, right_min_type);
				},
				(Some(l), Some(r), true, true) => {
					nodes[left_pos].hash =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					nodes[left_pos].included = true;
					nodes[left_pos].min_type =
						core::cmp::min(nodes[left_pos].min_type, right_min_type);
				},
				(Some(l), Some(r), false, false) => {
					nodes[left_pos].hash =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					nodes[left_pos].min_type =
						core::cmp::min(nodes[left_pos].min_type, right_min_type);
				},
				(Some(_), None, _, _) => {},
				_ => unreachable!("Invalid state in merkle tree construction"),
			}
		}
	}

	missing_with_types.sort_by_key(|(min_type, _)| *min_type);
	let missing_hashes: Vec<sha256::Hash> =
		missing_with_types.into_iter().map(|(_, h)| h).collect();

	(nodes[0].hash.expect("Tree should have a root"), missing_hashes)
}

/// Reconstruct merkle root from selective disclosure data.
///
/// The `missing_hashes` must be in ascending type order per spec.
///
/// Uses `n` tree nodes (one per TLV position) rather than `2n`, since per-TLV
/// hashes already combine leaf and nonce. Two passes over the tree determine
/// where missing hashes are needed and then combine all hashes to the root.
pub(super) fn reconstruct_merkle_root<'a>(
	included_records: &[(u64, &'a [u8])], leaf_hashes: &[sha256::Hash], omitted_markers: &[u64],
	missing_hashes: &[sha256::Hash],
) -> Result<sha256::Hash, SelectiveDisclosureError> {
	// Callers are expected to validate omitted_markers before calling this function
	// (e.g., via validate_omitted_markers_for_parsing). Debug-assert for safety.
	debug_assert!(validate_omitted_markers(omitted_markers).is_ok());

	if included_records.len() != leaf_hashes.len() {
		return Err(SelectiveDisclosureError::LeafHashCountMismatch);
	}

	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	// Build TreeNode vec directly by interleaving included/omitted positions,
	// eliminating the intermediate Vec<bool> from reconstruct_positions_from_records.
	let num_nodes = 1 + included_records.len() + omitted_markers.len();
	let mut nodes: Vec<TreeNode> = Vec::with_capacity(num_nodes);

	// TLV0 is always omitted
	nodes.push(TreeNode { hash: None, included: false, min_type: 0 });

	let mut inc_idx = 0;
	let mut mrk_idx = 0;
	let mut prev_marker: u64 = 0;
	let mut node_idx: u64 = 1;

	while inc_idx < included_records.len() || mrk_idx < omitted_markers.len() {
		if mrk_idx >= omitted_markers.len() {
			// No more markers, remaining positions are included
			let (_, record_bytes) = included_records[inc_idx];
			let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record_bytes);
			let nonce_hash = leaf_hashes[inc_idx];
			let hash = tagged_branch_hash_from_engine(branch_tag.clone(), leaf_hash, nonce_hash);
			nodes.push(TreeNode { hash: Some(hash), included: true, min_type: node_idx });
			inc_idx += 1;
		} else if inc_idx >= included_records.len() {
			// No more included types, remaining positions are omitted
			nodes.push(TreeNode { hash: None, included: false, min_type: node_idx });
			prev_marker = omitted_markers[mrk_idx];
			mrk_idx += 1;
		} else {
			let marker = omitted_markers[mrk_idx];
			let (inc_type, _) = included_records[inc_idx];

			if marker == prev_marker + 1 {
				// Continuation of current run -> omitted position
				nodes.push(TreeNode { hash: None, included: false, min_type: node_idx });
				prev_marker = marker;
				mrk_idx += 1;
			} else {
				// Jump detected -> included position comes first
				let (_, record_bytes) = included_records[inc_idx];
				let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record_bytes);
				let nonce_hash = leaf_hashes[inc_idx];
				let hash =
					tagged_branch_hash_from_engine(branch_tag.clone(), leaf_hash, nonce_hash);
				nodes.push(TreeNode { hash: Some(hash), included: true, min_type: node_idx });
				prev_marker = inc_type;
				inc_idx += 1;
			}
		}
		node_idx += 1;
	}

	// First pass: walk the tree to discover which positions need missing hashes.
	// We mutate nodes[].included and nodes[].min_type directly since the second
	// pass only reads nodes[].hash, making this safe without a separate allocation.
	let num_omitted = omitted_markers.len() + 1; // +1 for implicit TLV0
	let mut needs_hash: Vec<(u64, usize)> = Vec::with_capacity(num_omitted);

	for level in 0.. {
		let step = 2 << level;
		let offset = step / 2;
		if offset >= num_nodes {
			break;
		}

		for left_pos in (0..num_nodes).step_by(step) {
			let right_pos = left_pos + offset;
			if right_pos >= num_nodes {
				continue;
			}

			let r_min = nodes[right_pos].min_type;

			match (nodes[left_pos].included, nodes[right_pos].included) {
				(true, false) => {
					needs_hash.push((r_min, right_pos));
					nodes[left_pos].min_type = core::cmp::min(nodes[left_pos].min_type, r_min);
				},
				(false, true) => {
					needs_hash.push((nodes[left_pos].min_type, left_pos));
					nodes[left_pos].included = true;
					nodes[left_pos].min_type = core::cmp::min(nodes[left_pos].min_type, r_min);
				},
				(true, true) => {
					nodes[left_pos].min_type = core::cmp::min(nodes[left_pos].min_type, r_min);
				},
				(false, false) => {
					nodes[left_pos].min_type = core::cmp::min(nodes[left_pos].min_type, r_min);
				},
			}
		}
	}

	needs_hash.sort_by_key(|(min_pos, _)| *min_pos);

	if needs_hash.len() != missing_hashes.len() {
		return Err(SelectiveDisclosureError::InsufficientMissingHashes);
	}

	// Place missing hashes directly into the nodes array.
	for (i, &(_, tree_pos)) in needs_hash.iter().enumerate() {
		nodes[tree_pos].hash = Some(missing_hashes[i]);
	}

	// Second pass: combine hashes up the tree.
	for level in 0.. {
		let step = 2 << level;
		let offset = step / 2;
		if offset >= num_nodes {
			break;
		}

		for left_pos in (0..num_nodes).step_by(step) {
			let right_pos = left_pos + offset;
			if right_pos >= num_nodes {
				continue;
			}

			match (nodes[left_pos].hash, nodes[right_pos].hash) {
				(Some(l), Some(r)) => {
					nodes[left_pos].hash =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
				},
				(Some(_), None) => {},
				(None, _) => {
					return Err(SelectiveDisclosureError::InsufficientMissingHashes);
				},
			};
		}
	}

	nodes[0].hash.ok_or(SelectiveDisclosureError::InsufficientMissingHashes)
}

fn validate_omitted_markers(markers: &[u64]) -> Result<(), SelectiveDisclosureError> {
	let mut prev = 0u64;
	for &marker in markers {
		if marker == 0 {
			return Err(SelectiveDisclosureError::InvalidOmittedMarkersMarker);
		}
		if SIGNATURE_TYPES.contains(&marker) {
			return Err(SelectiveDisclosureError::InvalidOmittedMarkersMarker);
		}
		if marker <= prev {
			return Err(SelectiveDisclosureError::InvalidOmittedMarkersOrder);
		}
		prev = marker;
	}
	Ok(())
}

/// Reconstruct position inclusion map from included types and omitted markers.
///
/// This reverses the marker encoding algorithm from `compute_omitted_markers`:
/// - Markers form "runs" of consecutive values (e.g., [11, 12] is a run)
/// - A "jump" in markers (e.g., 12 → 41) indicates an included TLV came between
/// - After included type X, the next marker in that run equals X + 1
///
/// The algorithm tracks `prev_marker` to detect continuations vs jumps:
/// - If `marker == prev_marker + 1`: continuation → omitted position
/// - Otherwise: jump → included position comes first, then process marker as continuation
///
/// Example: included=[10, 40], markers=[11, 12, 41, 42]
/// - Position 0: TLV0 (always omitted)
/// - marker=11, prev=0: 11 != 1, jump! Insert included (10), prev=10
/// - marker=11, prev=10: 11 == 11, continuation → omitted, prev=11
/// - marker=12, prev=11: 12 == 12, continuation → omitted, prev=12
/// - marker=41, prev=12: 41 != 13, jump! Insert included (40), prev=40
/// - marker=41, prev=40: 41 == 41, continuation → omitted, prev=41
/// - marker=42, prev=41: 42 == 42, continuation → omitted, prev=42
/// Result: [O, I, O, O, I, O, O]
#[cfg(test)]
fn reconstruct_positions(included_types: &[u64], omitted_markers: &[u64]) -> Vec<bool> {
	let total = 1 + included_types.len() + omitted_markers.len();
	let mut positions = Vec::with_capacity(total);
	positions.push(false); // TLV0 is always omitted

	let mut inc_idx = 0;
	let mut mrk_idx = 0;
	// After TLV0 (implicit marker 0), next continuation would be marker 1
	let mut prev_marker: u64 = 0;

	while inc_idx < included_types.len() || mrk_idx < omitted_markers.len() {
		if mrk_idx >= omitted_markers.len() {
			// No more markers, remaining positions are included
			positions.push(true);
			inc_idx += 1;
		} else if inc_idx >= included_types.len() {
			// No more included types, remaining positions are omitted
			positions.push(false);
			prev_marker = omitted_markers[mrk_idx];
			mrk_idx += 1;
		} else {
			let marker = omitted_markers[mrk_idx];
			let inc_type = included_types[inc_idx];

			if marker == prev_marker + 1 {
				// Continuation of current run → this position is omitted
				positions.push(false);
				prev_marker = marker;
				mrk_idx += 1;
			} else {
				// Jump detected! An included TLV comes before this marker.
				// After the included type, prev_marker resets to that type,
				// so the marker will be processed as a continuation next iteration.
				positions.push(true);
				prev_marker = inc_type;
				inc_idx += 1;
				// Don't advance mrk_idx - same marker will be continuation next
			}
		}
	}

	positions
}

#[cfg(test)]
mod tests {
	use super::{TlvStream, SIGNATURE_TYPES};

	use crate::ln::channelmanager::PaymentId;
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::offers::invoice_request::{InvoiceRequest, UnsignedInvoiceRequest};
	use crate::offers::nonce::Nonce;
	use crate::offers::offer::{Amount, CurrencyCode, OfferBuilder};
	use crate::offers::parse::Bech32Encode;
	use crate::offers::signer::Metadata;
	use crate::offers::test_utils::recipient_pubkey;
	use crate::util::ser::Writeable;
	use bitcoin::hashes::{sha256, Hash};
	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::schnorr::Signature;
	use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

	#[test]
	fn calculates_merkle_root_hash() {
		// BOLT 12 test vectors
		const HEX_1: &'static str = "010203e8";
		let bytes_1 =
			<Vec<u8>>::from_hex("b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93")
				.unwrap();
		assert_eq!(
			super::root_hash(TlvStream::new(&<Vec<u8>>::from_hex(HEX_1).unwrap())),
			sha256::Hash::from_slice(&bytes_1).unwrap(),
		);

		const HEX_2: &'static str = concat!("010203e8", "02080000010000020003");
		let bytes_2 =
			<Vec<u8>>::from_hex("c3774abbf4815aa54ccaa026bff6581f01f3be5fe814c620a252534f434bc0d1")
				.unwrap();
		assert_eq!(
			super::root_hash(TlvStream::new(&<Vec<u8>>::from_hex(HEX_2).unwrap())),
			sha256::Hash::from_slice(&bytes_2).unwrap(),
		);

		const HEX_3: &'static str = concat!("010203e8","02080000010000020003", "03310266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351800000000000000010000000000000002");
		let bytes_3 =
			<Vec<u8>>::from_hex("ab2e79b1283b0b31e0b035258de23782df6b89a38cfa7237bde69aed1a658c5d")
				.unwrap();
		assert_eq!(
			super::root_hash(TlvStream::new(&<Vec<u8>>::from_hex(HEX_3).unwrap())),
			sha256::Hash::from_slice(&bytes_3).unwrap(),
		);
	}

	#[test]
	fn calculates_merkle_root_hash_from_invoice_request() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let nonce = Nonce([0u8; 16]);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let recipient_pubkey = {
			let secret_bytes = <Vec<u8>>::from_hex(
				"4141414141414141414141414141414141414141414141414141414141414141",
			)
			.unwrap();
			let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key).public_key()
		};
		let payer_keys = {
			let secret_bytes = <Vec<u8>>::from_hex(
				"4242424242424242424242424242424242424242424242424242424242424242",
			)
			.unwrap();
			let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key)
		};

		// BOLT 12 test vectors
		let invoice_request = OfferBuilder::new(recipient_pubkey)
			.description("A Mathematical Treatise".into())
			.amount(Amount::Currency {
				iso4217_code: CurrencyCode::new(*b"USD").unwrap(),
				amount: 100,
			})
			.build_unchecked()
			// Override the payer metadata and signing pubkey to match the test vectors
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.payer_metadata(Metadata::Bytes(vec![0; 8]))
			.payer_signing_pubkey(payer_keys.public_key())
			.build_unchecked()
			.sign(|message: &UnsignedInvoiceRequest| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &payer_keys))
			})
			.unwrap();
		assert_eq!(
			invoice_request.to_string(),
			"lnr1qqyqqqqqqqqqqqqqqcp4256ypqqkgzshgysy6ct5dpjk6ct5d93kzmpq23ex2ct5d9ek293pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpjkppqvjx204vgdzgsqpvcp4mldl3plscny0rt707gvpdh6ndydfacz43euzqhrurageg3n7kafgsek6gz3e9w52parv8gs2hlxzk95tzeswywffxlkeyhml0hh46kndmwf4m6xma3tkq2lu04qz3slje2rfthc89vss",
		);

		let bytes =
			<Vec<u8>>::from_hex("608407c18ad9a94d9ea2bcdbe170b6c20c462a7833a197621c916f78cf18e624")
				.unwrap();
		assert_eq!(
			super::root_hash(TlvStream::new(&invoice_request.bytes[..])),
			sha256::Hash::from_slice(&bytes).unwrap(),
		);

		let bytes = <Vec<u8>>::from_hex("b8f83ea3288cfd6ea510cdb481472575141e8d8744157f98562d162cc1c472526fdb24befefbdebab4dbb726bbd1b7d8aec057f8fa805187e5950d2bbe0e5642").unwrap();
		assert_eq!(invoice_request.signature(), Signature::from_slice(&bytes).unwrap(),);
	}

	#[test]
	fn compute_tagged_hash() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let nonce = Nonce([0u8; 16]);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let unsigned_invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.payer_note("bar".into())
			.build_unchecked();

		// Simply test that we can grab the tag and merkle root exposed by the accessor
		// functions, then use them to succesfully compute a tagged hash.
		let tagged_hash = unsigned_invoice_request.as_ref();
		let expected_digest = unsigned_invoice_request.as_ref().as_digest();
		let tag = sha256::Hash::hash(tagged_hash.tag().as_bytes());
		let actual_digest = Message::from_digest(
			super::tagged_hash(tag, tagged_hash.merkle_root()).to_byte_array(),
		);
		assert_eq!(*expected_digest, actual_digest);
	}

	#[test]
	fn skips_encoding_signature_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let nonce = Nonce([0u8; 16]);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let recipient_pubkey = {
			let secret_key = SecretKey::from_slice(&[41; 32]).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key).public_key()
		};

		let invoice_request = OfferBuilder::new(recipient_pubkey)
			.amount_msats(100)
			.build_unchecked()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut bytes_without_signature = Vec::new();
		let tlv_stream_without_signatures = TlvStream::new(&invoice_request.bytes)
			.filter(|record| !SIGNATURE_TYPES.contains(&record.r#type));
		for record in tlv_stream_without_signatures {
			record.write(&mut bytes_without_signature).unwrap();
		}

		assert_ne!(bytes_without_signature, invoice_request.bytes);
		assert_eq!(
			TlvStream::new(&bytes_without_signature).count(),
			TlvStream::new(&invoice_request.bytes).count() - 1,
		);
	}

	#[test]
	fn iterates_over_tlv_stream_range() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let nonce = Nonce([0u8; 16]);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let recipient_pubkey = {
			let secret_key = SecretKey::from_slice(&[41; 32]).unwrap();
			Keypair::from_secret_key(&secp_ctx, &secret_key).public_key()
		};

		let invoice_request = OfferBuilder::new(recipient_pubkey)
			.amount_msats(100)
			.build_unchecked()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let tlv_stream = TlvStream::new(&invoice_request.bytes)
			.range(0..1)
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

	// ============================================================================
	// Tests for selective disclosure / payer proof reconstruction
	// ============================================================================

	/// Test reconstruct_positions with the BOLT 12 payer proof spec example.
	///
	/// TLVs: 0(omit), 10(incl), 20(omit), 30(omit), 40(incl), 50(omit), 60(omit)
	/// Markers: [11, 12, 41, 42]
	/// Expected positions: [O, I, O, O, I, O, O]
	#[test]
	fn test_reconstruct_positions_spec_example() {
		let included_types = vec![10, 40];
		let markers = vec![11, 12, 41, 42];
		let positions = super::reconstruct_positions(&included_types, &markers);
		assert_eq!(positions, vec![false, true, false, false, true, false, false]);
	}

	/// Test reconstruct_positions when there are omitted TLVs before the first included.
	///
	/// TLVs: 0(omit), 5(omit), 10(incl), 20(omit)
	/// Markers: [1, 11] (1 is first omitted after TLV0, 11 is after included 10)
	/// Expected positions: [O, O, I, O]
	#[test]
	fn test_reconstruct_positions_omitted_before_included() {
		let included_types = vec![10];
		let markers = vec![1, 11];
		let positions = super::reconstruct_positions(&included_types, &markers);
		assert_eq!(positions, vec![false, false, true, false]);
	}

	/// Test reconstruct_positions with only included TLVs (no omitted except TLV0).
	///
	/// TLVs: 0(omit), 10(incl), 20(incl)
	/// Markers: [] (no omitted TLVs after TLV0)
	/// Expected positions: [O, I, I]
	#[test]
	fn test_reconstruct_positions_no_omitted() {
		let included_types = vec![10, 20];
		let markers = vec![];
		let positions = super::reconstruct_positions(&included_types, &markers);
		assert_eq!(positions, vec![false, true, true]);
	}

	/// Test reconstruct_positions with only omitted TLVs (no included).
	///
	/// TLVs: 0(omit), 5(omit), 10(omit)
	/// Markers: [1, 2] (consecutive omitted after TLV0)
	/// Expected positions: [O, O, O]
	#[test]
	fn test_reconstruct_positions_no_included() {
		let included_types = vec![];
		let markers = vec![1, 2];
		let positions = super::reconstruct_positions(&included_types, &markers);
		assert_eq!(positions, vec![false, false, false]);
	}

	/// Test round-trip: compute selective disclosure then reconstruct merkle root.
	#[test]
	fn test_selective_disclosure_round_trip() {
		use alloc::collections::BTreeSet;

		// Build TLV stream matching spec example structure
		// TLVs: 0, 10, 20, 30, 40, 50, 60
		let mut tlv_bytes = Vec::new();
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // TLV 0
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]); // TLV 10
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]); // TLV 20
		tlv_bytes.extend_from_slice(&[0x1e, 0x02, 0x00, 0x00]); // TLV 30
		tlv_bytes.extend_from_slice(&[0x28, 0x02, 0x00, 0x00]); // TLV 40
		tlv_bytes.extend_from_slice(&[0x32, 0x02, 0x00, 0x00]); // TLV 50
		tlv_bytes.extend_from_slice(&[0x3c, 0x02, 0x00, 0x00]); // TLV 60

		// Include types 10 and 40
		let mut included = BTreeSet::new();
		included.insert(10);
		included.insert(40);

		// Compute selective disclosure
		let disclosure = super::compute_selective_disclosure(&tlv_bytes, &included).unwrap();

		// Verify markers match spec example
		assert_eq!(disclosure.omitted_markers, vec![11, 12, 41, 42]);

		// Verify leaf_hashes count matches included TLVs
		assert_eq!(disclosure.leaf_hashes.len(), 2);

		// Collect included records for reconstruction
		let included_records: Vec<(u64, &[u8])> = TlvStream::new(&tlv_bytes)
			.filter(|r| included.contains(&r.r#type))
			.map(|r| (r.r#type, r.record_bytes))
			.collect();

		// Reconstruct merkle root
		let reconstructed = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.leaf_hashes,
			&disclosure.omitted_markers,
			&disclosure.missing_hashes,
		)
		.unwrap();

		// Must match original
		assert_eq!(reconstructed, disclosure.merkle_root);
	}

	/// Test that missing_hashes are in ascending type order per spec.
	///
	/// Per spec: "MUST include the minimal set of merkle hashes of missing merkle
	/// leaves or nodes in `missing_hashes`, in ascending type order."
	///
	/// For the spec example with TLVs [0(o), 10(I), 20(o), 30(o), 40(I), 50(o), 60(o)]:
	/// - hash(0) covers type 0
	/// - hash(B(20,30)) covers types 20-30 (min=20)
	/// - hash(50) covers type 50
	/// - hash(60) covers type 60
	///
	/// Expected order: [type 0, type 20, type 50, type 60]
	/// This means 4 missing_hashes in this order.
	#[test]
	fn test_missing_hashes_ascending_type_order() {
		use alloc::collections::BTreeSet;

		// Build TLV stream: 0, 10, 20, 30, 40, 50, 60
		let mut tlv_bytes = Vec::new();
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // TLV 0
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]); // TLV 10
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]); // TLV 20
		tlv_bytes.extend_from_slice(&[0x1e, 0x02, 0x00, 0x00]); // TLV 30
		tlv_bytes.extend_from_slice(&[0x28, 0x02, 0x00, 0x00]); // TLV 40
		tlv_bytes.extend_from_slice(&[0x32, 0x02, 0x00, 0x00]); // TLV 50
		tlv_bytes.extend_from_slice(&[0x3c, 0x02, 0x00, 0x00]); // TLV 60

		// Include types 10 and 40 (same as spec example)
		let mut included = BTreeSet::new();
		included.insert(10);
		included.insert(40);

		let disclosure = super::compute_selective_disclosure(&tlv_bytes, &included).unwrap();

		// We should have 4 missing hashes for omitted types:
		// - type 0 (single leaf)
		// - types 20+30 (combined branch, min_type=20)
		// - type 50 (single leaf)
		// - type 60 (single leaf)
		//
		// The spec example only shows 3, but that appears to be incomplete
		// (missing hash for type 60). Our implementation should produce 4.
		assert_eq!(
			disclosure.missing_hashes.len(),
			4,
			"Expected 4 missing hashes for omitted types [0, 20+30, 50, 60]"
		);

		// Verify the round-trip still works with the correct ordering
		let included_records: Vec<(u64, &[u8])> = TlvStream::new(&tlv_bytes)
			.filter(|r| included.contains(&r.r#type))
			.map(|r| (r.r#type, r.record_bytes))
			.collect();

		let reconstructed = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.leaf_hashes,
			&disclosure.omitted_markers,
			&disclosure.missing_hashes,
		)
		.unwrap();

		assert_eq!(reconstructed, disclosure.merkle_root);
	}

	/// Test that reconstruction fails with wrong number of missing_hashes.
	#[test]
	fn test_reconstruction_fails_with_wrong_missing_hashes() {
		use alloc::collections::BTreeSet;

		let mut tlv_bytes = Vec::new();
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // TLV 0
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]); // TLV 10
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]); // TLV 20

		let mut included = BTreeSet::new();
		included.insert(10);

		let disclosure = super::compute_selective_disclosure(&tlv_bytes, &included).unwrap();

		let included_records: Vec<(u64, &[u8])> = TlvStream::new(&tlv_bytes)
			.filter(|r| included.contains(&r.r#type))
			.map(|r| (r.r#type, r.record_bytes))
			.collect();

		// Try with empty missing_hashes (should fail)
		let result = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.leaf_hashes,
			&disclosure.omitted_markers,
			&[], // Wrong!
		);

		assert!(result.is_err());
	}
}
