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

			let _value = &self.data.get_ref()[offset as usize..end as usize];
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
	/// The omitted_tlvs markers are not in strict ascending order.
	InvalidOmittedTlvsOrder,
	/// The omitted_tlvs contains an invalid marker (0 or signature type).
	InvalidOmittedTlvsMarker,
	/// The leaf_hashes count doesn't match included TLVs.
	LeafHashCountMismatch,
	/// Insufficient missing_hashes to reconstruct the tree.
	InsufficientMissingHashes,
	/// Excess missing_hashes after reconstruction.
	ExcessMissingHashes,
	/// The TLV stream is empty.
	EmptyTlvStream,
}

/// Data needed to reconstruct a merkle root with selective disclosure.
///
/// This is used in payer proofs to allow verification of an invoice signature
/// without revealing all invoice fields.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectiveDisclosure {
	/// Nonce hashes for included TLVs (in TLV type order).
	pub leaf_hashes: Vec<sha256::Hash>,
	/// Marker numbers for omitted TLVs (excluding implicit TLV0).
	pub omitted_tlvs: Vec<u64>,
	/// Minimal merkle hashes for omitted subtrees.
	pub missing_hashes: Vec<sha256::Hash>,
	/// The complete merkle root.
	pub merkle_root: sha256::Hash,
}

/// Internal data for each TLV during tree construction.
struct TlvMerkleData {
	tlv_type: u64,
	per_tlv_hash: sha256::Hash,
	nonce_hash: sha256::Hash,
	is_included: bool,
}

/// Compute selective disclosure data from a TLV stream.
///
/// This builds the full merkle tree and extracts the data needed for a payer proof:
/// - `leaf_hashes`: nonce hashes for included TLVs
/// - `omitted_tlvs`: marker numbers for omitted TLVs
/// - `missing_hashes`: minimal merkle hashes for omitted subtrees
///
/// # Arguments
/// * `tlv_bytes` - Complete TLV stream (e.g., invoice bytes without signature)
/// * `included_types` - Set of TLV types to include in the disclosure
pub(super) fn compute_selective_disclosure(
	tlv_bytes: &[u8], included_types: &BTreeSet<u64>,
) -> Result<SelectiveDisclosure, SelectiveDisclosureError> {
	let mut tlv_stream = TlvStream::new(tlv_bytes).peekable();

	// Get TLV0 for nonce tag computation
	//
	// TODO(spec-clarification): The spec notation H("LnNonce"||TLV0,type) is ambiguous.
	// It could mean either:
	// 1. Tagged hash: H(H("LnNonce"||TLV0) || H("LnNonce"||TLV0) || type) - BIP340 style
	// 2. Simple concatenation: H("LnNonce" || TLV0 || type)
	//
	// We use interpretation (1) - tagged hash style - which is consistent with how
	// LnLeaf and LnBranch are computed in the existing BOLT 12 merkle implementation.
	// This should be confirmed with spec authors or test vectors when available.
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

	// Build per-TLV data
	let mut tlv_data: Vec<TlvMerkleData> = Vec::new();
	for record in tlv_stream.filter(|r| !SIGNATURE_TYPES.contains(&r.r#type)) {
		let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record.record_bytes);
		let nonce_hash = tagged_hash_from_engine(nonce_tag.clone(), record.type_bytes);
		let per_tlv_hash =
			tagged_branch_hash_from_engine(branch_tag.clone(), leaf_hash, nonce_hash);

		let is_included = included_types.contains(&record.r#type);
		tlv_data.push(TlvMerkleData {
			tlv_type: record.r#type,
			per_tlv_hash,
			nonce_hash,
			is_included,
		});
	}

	if tlv_data.is_empty() {
		return Err(SelectiveDisclosureError::EmptyTlvStream);
	}

	// Compute leaf_hashes (nonce hashes for included TLVs)
	let leaf_hashes: Vec<_> =
		tlv_data.iter().filter(|d| d.is_included).map(|d| d.nonce_hash).collect();

	// Compute omitted_tlvs markers
	let omitted_tlvs = compute_omitted_markers(&tlv_data);

	// Build tree and compute missing_hashes
	let (merkle_root, missing_hashes) = build_tree_with_disclosure(&tlv_data, &branch_tag);

	Ok(SelectiveDisclosure { leaf_hashes, omitted_tlvs, missing_hashes, merkle_root })
}

/// Compute omitted_tlvs marker numbers per BOLT 12 payer proof spec.
///
/// The marker algorithm (from spec):
/// - TLV0 is always omitted and implicit (not in markers)
/// - For omitted TLV after an included one: marker = prev_included_type + 1
/// - For consecutive omitted TLVs: marker > last_marker (we use last_marker + 1 as minimal value)
///
/// The spec says "marker > last_marker" which we satisfy by using the minimal strictly greater
/// value (last_marker + 1). This produces minimal markers that hide real TLV type numbers while
/// preserving ordering information needed for merkle reconstruction.
///
/// Example from spec:
/// TLVs: 0(omit), 10(incl), 20(omit), 30(omit), 40(incl), 50(omit), 60(omit)
/// Markers: [11, 12, 41, 42]
/// - After 10 (included), omitted 20 gets marker 11 (= 10 + 1)
/// - Next omitted 30 gets marker 12 (> 11)
/// - After 40 (included), omitted 50 gets marker 41 (= 40 + 1)
/// - Next omitted 60 gets marker 42 (> 41)
fn compute_omitted_markers(tlv_data: &[TlvMerkleData]) -> Vec<u64> {
	let mut markers = Vec::new();
	let mut prev_included_type: Option<u64> = None;
	let mut prev_marker: Option<u64> = None;

	for data in tlv_data {
		if data.tlv_type == 0 {
			// TLV0 is always omitted and implicit - skip
			continue;
		}

		if !data.is_included {
			// Compute marker for this omitted TLV
			let marker = if let Some(prev_type) = prev_included_type {
				// Previous was included: marker = prev_type + 1
				prev_type + 1
			} else if let Some(last_marker) = prev_marker {
				// Previous was also omitted: marker > last_marker
				last_marker + 1
			} else {
				// First omitted after implicit 0
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

/// Build merkle tree and collect missing_hashes for omitted subtrees.
///
/// The `missing_hashes` are collected during bottom-up tree construction and then
/// sorted by ascending TLV type as required by the spec:
/// "MUST include the minimal set of merkle hashes of missing merkle leaves or nodes
/// in `missing_hashes`, in ascending type order."
///
/// For internal nodes (combined branches), the "type" used for ordering is the minimum
/// TLV type covered by that subtree. This ensures the output matches the recursive
/// left-to-right traversal order described in the spec.
///
/// The algorithm: during bottom-up merkle construction, when combining a node where one side
/// is included and the other is omitted, we collect the omitted side's hash along with
/// its minimum type. When both sides are omitted, we combine them (the combined hash will
/// be collected at a higher level if needed). Finally, we sort by type and return just
/// the hashes.
fn build_tree_with_disclosure(
	tlv_data: &[TlvMerkleData], branch_tag: &sha256::HashEngine,
) -> (sha256::Hash, Vec<sha256::Hash>) {
	let n = tlv_data.len();
	debug_assert!(n > 0, "TLV stream must contain at least one record");

	// Initialize: 2 leaves per TLV, but we only use even positions for per-TLV hashes
	let num_leaves = n * 2;
	let mut hashes: Vec<Option<sha256::Hash>> = vec![None; num_leaves];
	let mut is_included: Vec<bool> = vec![false; num_leaves];
	// Track minimum TLV type covered by each position (for sorting missing_hashes)
	let mut min_types: Vec<u64> = vec![u64::MAX; num_leaves];

	// Fill in per-TLV hashes at even positions
	for (i, data) in tlv_data.iter().enumerate() {
		let pos = i * 2;
		hashes[pos] = Some(data.per_tlv_hash);
		is_included[pos] = data.is_included;
		min_types[pos] = data.tlv_type;
	}

	// Collect (min_type, hash) pairs, will sort by min_type at the end
	let mut missing_with_types: Vec<(u64, sha256::Hash)> = Vec::new();

	// Bottom-up merkle tree construction (same algorithm as root_hash)
	// Level 0 is already done (per-TLV hashes at even positions after leaf+nonce combining)
	// We start from level 1
	for level in 1.. {
		let step = 2 << level;
		let offset = step / 2;
		if offset >= num_leaves {
			break;
		}

		let left_positions: Vec<_> = (0..num_leaves).step_by(step).collect();
		let right_positions: Vec<_> = (offset..num_leaves).step_by(step).collect();

		for (&left_pos, &right_pos) in left_positions.iter().zip(right_positions.iter()) {
			let left_hash = hashes[left_pos];
			let right_hash = hashes[right_pos];
			let left_incl = is_included[left_pos];
			let right_incl = is_included[right_pos];
			let left_min_type = min_types[left_pos];
			let right_min_type = min_types[right_pos];

			match (left_hash, right_hash, left_incl, right_incl) {
				(Some(l), Some(r), true, false) => {
					// Left included, right omitted -> collect right with its min_type
					missing_with_types.push((right_min_type, r));
					hashes[left_pos] =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					is_included[left_pos] = true;
					// min_type for combined node is min of both children
					min_types[left_pos] = core::cmp::min(left_min_type, right_min_type);
				},
				(Some(l), Some(r), false, true) => {
					// Left omitted, right included -> collect left with its min_type
					missing_with_types.push((left_min_type, l));
					hashes[left_pos] =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					is_included[left_pos] = true;
					min_types[left_pos] = core::cmp::min(left_min_type, right_min_type);
				},
				(Some(l), Some(r), true, true) => {
					// Both included -> just combine
					hashes[left_pos] =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					is_included[left_pos] = true;
					min_types[left_pos] = core::cmp::min(left_min_type, right_min_type);
				},
				(Some(l), Some(r), false, false) => {
					// Both omitted -> combine but mark as omitted (will be collected later)
					hashes[left_pos] =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					is_included[left_pos] = false;
					min_types[left_pos] = core::cmp::min(left_min_type, right_min_type);
				},
				(Some(l), None, incl, _) => {
					// Odd node - propagate unchanged
					hashes[left_pos] = Some(l);
					is_included[left_pos] = incl;
					// min_type already set from left
				},
				_ => unreachable!("Invalid state in merkle tree construction"),
			}
		}
	}

	// Sort by ascending type order as required by spec
	missing_with_types.sort_by_key(|(min_type, _)| *min_type);
	let missing_hashes: Vec<sha256::Hash> =
		missing_with_types.into_iter().map(|(_, h)| h).collect();

	(hashes[0].expect("Tree should have a root"), missing_hashes)
}

/// Reconstruct merkle root from selective disclosure data.
///
/// This is used during payer proof verification to reconstruct the invoice's
/// merkle root from the included TLV records and disclosure data.
///
/// The `missing_hashes` are expected in ascending type order per spec. This function
/// first identifies which positions need missing hashes, sorts them by min_type,
/// and maps the provided hashes accordingly before running the bottom-up reconstruction.
///
/// # Arguments
/// * `included_records` - Iterator of (type, record_bytes) for included TLVs
/// * `leaf_hashes` - Nonce hashes for included TLVs (from payer_proof)
/// * `omitted_tlvs` - Marker numbers for omitted TLVs (from payer_proof)
/// * `missing_hashes` - Merkle hashes for omitted subtrees (from payer_proof), in ascending type order
pub(super) fn reconstruct_merkle_root<'a>(
	included_records: &[(u64, &'a [u8])], leaf_hashes: &[sha256::Hash], omitted_tlvs: &[u64],
	missing_hashes: &[sha256::Hash],
) -> Result<sha256::Hash, SelectiveDisclosureError> {
	// Validate omitted_tlvs
	validate_omitted_tlvs(omitted_tlvs)?;

	// Check leaf_hashes count
	if included_records.len() != leaf_hashes.len() {
		return Err(SelectiveDisclosureError::LeafHashCountMismatch);
	}

	// Extract sorted included types for position reconstruction
	let included_types: Vec<u64> = included_records.iter().map(|(t, _)| *t).collect();

	// Reconstruct position map using the new algorithm
	let positions = reconstruct_positions(&included_types, omitted_tlvs);

	let total_tlvs = positions.len();
	let num_leaves = total_tlvs * 2;

	// Compute per-TLV hashes for included TLVs
	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	let mut hashes: Vec<Option<sha256::Hash>> = vec![None; num_leaves];
	let mut is_included: Vec<bool> = vec![false; num_leaves];
	// Track minimum position (which corresponds to min type) for each tree position
	let mut min_positions: Vec<usize> = (0..num_leaves).collect();

	let mut leaf_hash_idx = 0;
	for (i, &incl) in positions.iter().enumerate() {
		let pos = i * 2;
		is_included[pos] = incl;
		min_positions[pos] = i; // Position i corresponds to type at position i

		if incl {
			// Compute per-TLV hash from included data + leaf_hashes
			let (_, record_bytes) = included_records[leaf_hash_idx];
			let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record_bytes);
			let nonce_hash = leaf_hashes[leaf_hash_idx];
			let per_tlv = tagged_branch_hash_from_engine(branch_tag.clone(), leaf_hash, nonce_hash);
			hashes[pos] = Some(per_tlv);
			leaf_hash_idx += 1;
		}
	}

	// First pass: identify all positions that need missing hashes and their min_positions
	// We simulate the bottom-up algorithm to find these positions
	let mut needs_hash: Vec<(usize, usize)> = Vec::new(); // (min_position, tree_position)
	{
		let mut temp_hashes: Vec<Option<()>> = vec![None; num_leaves];
		let mut temp_included: Vec<bool> = is_included.clone();
		let mut temp_min_pos: Vec<usize> = min_positions.clone();

		for (i, &incl) in positions.iter().enumerate() {
			let pos = i * 2;
			if incl {
				temp_hashes[pos] = Some(());
			}
		}

		for level in 1.. {
			let step = 2 << level;
			let offset = step / 2;
			if offset >= num_leaves {
				break;
			}

			for left_pos in (0..num_leaves).step_by(step) {
				let right_pos = left_pos + offset;
				if right_pos >= num_leaves {
					continue;
				}

				let left_hash = temp_hashes[left_pos];
				let right_hash = temp_hashes[right_pos];
				let left_incl = temp_included[left_pos];
				let right_incl = temp_included[right_pos];
				let left_min = temp_min_pos[left_pos];
				let right_min = temp_min_pos[right_pos];

				match (left_hash, right_hash, left_incl, right_incl) {
					(Some(_), None, true, false) => {
						// Need hash for right subtree, keyed by right's min_position
						needs_hash.push((right_min, right_pos));
						temp_hashes[left_pos] = Some(());
						temp_included[left_pos] = true;
						temp_min_pos[left_pos] = core::cmp::min(left_min, right_min);
					},
					(None, Some(_), false, true) => {
						// Need hash for left subtree, keyed by left's min_position
						needs_hash.push((left_min, left_pos));
						temp_hashes[left_pos] = Some(());
						temp_included[left_pos] = true;
						temp_min_pos[left_pos] = core::cmp::min(left_min, right_min);
					},
					(Some(_), Some(_), _, _) => {
						temp_hashes[left_pos] = Some(());
						temp_included[left_pos] = true;
						temp_min_pos[left_pos] = core::cmp::min(left_min, right_min);
					},
					(Some(_), None, false, false) => {
						// Odd node propagation
					},
					(None, None, false, false) => {
						temp_min_pos[left_pos] = core::cmp::min(left_min, right_min);
					},
					_ => {},
				}
			}
		}
	}

	// Sort by min_position (ascending type order) and create position -> hash mapping
	needs_hash.sort_by_key(|(min_pos, _)| *min_pos);

	if needs_hash.len() != missing_hashes.len() {
		return Err(SelectiveDisclosureError::InsufficientMissingHashes);
	}

	// Map tree_position -> hash
	let mut hash_map: alloc::collections::BTreeMap<usize, sha256::Hash> =
		alloc::collections::BTreeMap::new();
	for (i, (_, tree_pos)) in needs_hash.iter().enumerate() {
		hash_map.insert(*tree_pos, missing_hashes[i]);
	}

	// Second pass: actual reconstruction using the pre-mapped hashes
	for level in 1.. {
		let step = 2 << level;
		let offset = step / 2;
		if offset >= num_leaves {
			break;
		}

		for left_pos in (0..num_leaves).step_by(step) {
			let right_pos = left_pos + offset;
			if right_pos >= num_leaves {
				continue;
			}

			let left_hash = hashes[left_pos];
			let right_hash = hashes[right_pos];
			let left_incl = is_included[left_pos];
			let right_incl = is_included[right_pos];
			let left_min = min_positions[left_pos];
			let right_min = min_positions[right_pos];

			match (left_hash, right_hash, left_incl, right_incl) {
				(Some(l), None, true, false) => {
					// Left included, right omitted -> get right hash from map
					let r = hash_map
						.get(&right_pos)
						.ok_or(SelectiveDisclosureError::InsufficientMissingHashes)?;
					hashes[left_pos] =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, *r));
					is_included[left_pos] = true;
					min_positions[left_pos] = core::cmp::min(left_min, right_min);
				},
				(None, Some(r), false, true) => {
					// Left omitted, right included -> get left hash from map
					let l = hash_map
						.get(&left_pos)
						.ok_or(SelectiveDisclosureError::InsufficientMissingHashes)?;
					hashes[left_pos] =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), *l, r));
					is_included[left_pos] = true;
					min_positions[left_pos] = core::cmp::min(left_min, right_min);
				},
				(Some(l), Some(r), _, _) => {
					// Both present (either computed or from previous level)
					hashes[left_pos] =
						Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r));
					is_included[left_pos] = true;
					min_positions[left_pos] = core::cmp::min(left_min, right_min);
				},
				(Some(l), None, false, false) => {
					// Odd node propagation (left exists, right doesn't)
					hashes[left_pos] = Some(l);
					// is_included stays as-is
				},
				(None, None, false, false) => {
					// Both fully omitted - propagate None, combined hash pulled at higher level
					min_positions[left_pos] = core::cmp::min(left_min, right_min);
				},
				_ => {
					// Unexpected state
					return Err(SelectiveDisclosureError::InsufficientMissingHashes);
				},
			};
		}
	}

	hashes[0].ok_or(SelectiveDisclosureError::InsufficientMissingHashes)
}

fn validate_omitted_tlvs(markers: &[u64]) -> Result<(), SelectiveDisclosureError> {
	let mut prev = 0u64;
	for &marker in markers {
		if marker == 0 {
			return Err(SelectiveDisclosureError::InvalidOmittedTlvsMarker);
		}
		if SIGNATURE_TYPES.contains(&marker) {
			return Err(SelectiveDisclosureError::InvalidOmittedTlvsMarker);
		}
		if marker <= prev {
			return Err(SelectiveDisclosureError::InvalidOmittedTlvsOrder);
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

/// Creates a TaggedHash directly from a merkle root (for payer proof verification).
impl TaggedHash {
	/// Creates a tagged hash from a pre-computed merkle root.
	pub(super) fn from_merkle_root(tag: &'static str, merkle_root: sha256::Hash) -> Self {
		let tag_hash = sha256::Hash::hash(tag.as_bytes());
		let digest = Message::from_digest(tagged_hash(tag_hash, merkle_root).to_byte_array());
		Self { tag, merkle_root, digest }
	}
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
		assert_eq!(disclosure.omitted_tlvs, vec![11, 12, 41, 42]);

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
			&disclosure.omitted_tlvs,
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
			&disclosure.omitted_tlvs,
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
			&disclosure.omitted_tlvs,
			&[], // Wrong!
		);

		assert!(result.is_err());
	}
}
