// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Selective disclosure support for BOLT 12 payer proofs.

use alloc::collections::BTreeSet;

use bitcoin::hashes::{sha256, Hash, HashEngine};

use crate::offers::invoice::INVOICE_TYPES;
use crate::offers::merkle::{
	tagged_branch_hash_from_engine, tagged_hash_engine, tagged_hash_from_engine, TlvRecord,
	SIGNATURE_TYPES,
};
use crate::offers::offer::EXPERIMENTAL_OFFER_TYPES;
use crate::offers::payer::PAYER_METADATA_TYPE;

#[allow(unused_imports)]
use crate::prelude::*;

/// Error during selective disclosure operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectiveDisclosureError {
	/// The omitted markers are not in strict ascending order.
	InvalidOmittedMarkersOrder,
	/// The omitted markers contain an invalid marker (0 or signature type).
	InvalidOmittedMarker,
	/// The nonce_hashes count doesn't match included TLVs.
	LeafHashCountMismatch,
	/// Insufficient missing_hashes to reconstruct the tree.
	InsufficientMissingHashes,
}

/// Data needed to reconstruct a merkle root with selective disclosure.
///
/// This is used in payer proofs to allow verification of an invoice signature
/// without revealing all invoice fields.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct SelectiveDisclosure {
	/// Nonce hashes for included TLVs (in TLV type order).
	pub(super) nonce_hashes: Vec<sha256::Hash>,
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
	nonce_hash: sha256::Hash,
	per_tlv_hash: sha256::Hash,
	is_included: bool,
}

fn merkle_tlv_data<'a, I, F>(
	tlv_stream: I, mut is_included: F,
) -> (impl Iterator<Item = TlvMerkleData> + 'a, sha256::HashEngine)
where
	I: core::iter::Iterator<Item = TlvRecord<'a>> + 'a,
	F: FnMut(u64) -> bool + 'a,
{
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
	let iter_branch_tag = branch_tag.clone();

	let tlv_data =
		tlv_stream.filter(|record| !SIGNATURE_TYPES.contains(&record.r#type)).map(move |record| {
			let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record.record_bytes);
			let nonce_hash = tagged_hash_from_engine(nonce_tag.clone(), record.type_bytes);
			let per_tlv_hash =
				tagged_branch_hash_from_engine(iter_branch_tag.clone(), leaf_hash, nonce_hash);

			TlvMerkleData {
				tlv_type: record.r#type,
				nonce_hash,
				per_tlv_hash,
				is_included: is_included(record.r#type),
			}
		});

	(tlv_data, branch_tag)
}

/// Compute selective disclosure data from a TLV stream.
///
/// This builds the full merkle tree and extracts the data needed for a payer proof:
/// - `nonce_hashes`: nonce hashes for included TLVs
/// - `omitted_markers`: marker numbers for omitted TLVs
/// - `missing_hashes`: minimal merkle hashes for omitted subtrees
///
/// # Arguments
/// * `records` - Iterator of [`TlvRecord`]s from the invoice
/// * `included_types` - Set of TLV types to include in the disclosure
pub(super) fn compute_selective_disclosure<'a>(
	records: impl Iterator<Item = TlvRecord<'a>> + 'a, included_types: &'a BTreeSet<u64>,
) -> SelectiveDisclosure {
	let (tlv_data, branch_tag) =
		merkle_tlv_data(records, |tlv_type| included_types.contains(&tlv_type));
	let tlv_data: Vec<TlvMerkleData> = tlv_data.collect();
	assert!(!tlv_data.is_empty(), "TLV stream must contain at least one non-signature record");

	let num_omitted_markers = tlv_data
		.iter()
		.filter(|data| !data.is_included && data.tlv_type != PAYER_METADATA_TYPE)
		.count();
	let mut omitted_markers = Vec::with_capacity(num_omitted_markers);
	omitted_markers.extend(compute_omitted_markers(tlv_data.iter()));
	let nonce_hashes =
		tlv_data.iter().filter(|data| data.is_included).map(|data| data.nonce_hash).collect();
	let (merkle_root, missing_hashes) = build_tree_with_disclosure(&tlv_data, &branch_tag);

	SelectiveDisclosure { nonce_hashes, omitted_markers, missing_hashes, merkle_root }
}

/// Returns the marker number that follows `prev` (an included TLV type or a
/// previous marker) per BOLT 12 PR 1295.
///
/// A marker is one greater than the previous value, except that a value landing
/// in the gap between the invoice TLV range and the experimental range (the
/// signature/payer-proof range) jumps to the start of the experimental range.
/// The producer and the readers all go through this so their marker sequences
/// stay in agreement.
pub(super) fn next_marker(prev: u64) -> u64 {
	let next = prev.saturating_add(1);
	if (INVOICE_TYPES.end..EXPERIMENTAL_OFFER_TYPES.start).contains(&next) {
		EXPERIMENTAL_OFFER_TYPES.start
	} else {
		next
	}
}

/// Compute omitted markers per BOLT 12 payer proof spec.
///
/// Each omitted TLV gets the marker number following the previous included TLV
/// type or the previous marker (see [`next_marker`]). TLV type 0 is implicitly
/// omitted (never assigned a marker).
fn compute_omitted_markers<'a>(
	tlv_data: impl Iterator<Item = &'a TlvMerkleData> + 'a,
) -> impl Iterator<Item = u64> + 'a {
	tlv_data
		.filter(|data| data.tlv_type != PAYER_METADATA_TYPE)
		.scan(0u64, |prev_value, data| {
			if data.is_included {
				*prev_value = data.tlv_type;
				Some(None)
			} else {
				let marker = next_marker(*prev_value);
				*prev_value = marker;
				Some(Some(marker))
			}
		})
		.flatten()
}

/// Build merkle tree recursively (DFS, left-to-right) and collect missing_hashes.
///
/// Per the spec, missing_hashes are in depth-first left-to-right order.
///
/// Note: a level-by-level approach (as used by `root_hash()`) cannot produce
/// DFS-ordered missing_hashes because it processes all subtrees at each depth
/// simultaneously rather than completing each subtree before the next.
fn build_tree_with_disclosure(
	tlv_data: &[TlvMerkleData], branch_tag: &sha256::HashEngine,
) -> (sha256::Hash, Vec<sha256::Hash>) {
	let mut missing_hashes = Vec::new();
	let (root, _) = build_tree_dfs(tlv_data, branch_tag, &mut missing_hashes);
	(root, missing_hashes)
}

fn build_tree_dfs(
	tlv_data: &[TlvMerkleData], branch_tag: &sha256::HashEngine,
	missing_hashes: &mut Vec<sha256::Hash>,
) -> (sha256::Hash, bool) {
	if tlv_data.len() == 1 {
		return (tlv_data[0].per_tlv_hash, tlv_data[0].is_included);
	}

	let mid = tlv_data.len().next_power_of_two() / 2;
	let (left_data, right_data) = tlv_data.split_at(mid);
	let (left_hash, left_incl) = build_tree_dfs(left_data, branch_tag, missing_hashes);
	let (right_hash, right_incl) = build_tree_dfs(right_data, branch_tag, missing_hashes);

	if left_incl && !right_incl {
		missing_hashes.push(right_hash);
	} else if !left_incl && right_incl {
		missing_hashes.push(left_hash);
	}

	let combined = tagged_branch_hash_from_engine(branch_tag.clone(), left_hash, right_hash);
	(combined, left_incl || right_incl)
}

/// Decodes the per-position inclusion map (`true` = included, `false` = omitted) from included
/// TLV types and omitted markers, with the implicit omitted TLV0 at the front.
fn decode_positions(
	included_types: impl ExactSizeIterator<Item = u64>, omitted_markers: &[u64],
) -> Vec<bool> {
	let mut positions = Vec::with_capacity(1 + included_types.len() + omitted_markers.len());
	positions.push(false); // TLV0 is always omitted.

	let mut included = included_types.peekable();
	let mut markers = omitted_markers.iter().copied().peekable();
	let mut prev_marker = 0u64;

	loop {
		match (included.peek().copied(), markers.peek().copied()) {
			(None, None) => break,
			// No more markers: every remaining position is included.
			(Some(_), None) => {
				included.next();
				positions.push(true);
			},
			// No more included types: every remaining position is omitted.
			(None, Some(marker)) => {
				markers.next();
				prev_marker = marker;
				positions.push(false);
			},
			// Continuation of the current run -> omitted position.
			(Some(_), Some(marker)) if marker == next_marker(prev_marker) => {
				markers.next();
				prev_marker = marker;
				positions.push(false);
			},
			// Jump -> an included TLV sits here; the marker is reprocessed next iteration.
			(Some(inc_type), Some(_)) => {
				included.next();
				prev_marker = inc_type;
				positions.push(true);
			},
		}
	}

	positions
}

/// Reconstruct merkle root from selective disclosure data.
///
/// `missing_hashes` must be in DFS (left-to-right recursive traversal) order,
/// matching the order produced by [`build_tree_with_disclosure`].
pub(super) fn reconstruct_merkle_root(
	included_records: &[TlvRecord<'_>], nonce_hashes: &[sha256::Hash], omitted_markers: &[u64],
	missing_hashes: &[sha256::Hash],
) -> Result<sha256::Hash, SelectiveDisclosureError> {
	debug_assert!({
		let included_types: BTreeSet<u64> = included_records.iter().map(|r| r.r#type).collect();
		validate_omitted_markers(omitted_markers, &included_types).is_ok()
	});

	if included_records.len() != nonce_hashes.len() {
		return Err(SelectiveDisclosureError::LeafHashCountMismatch);
	}

	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	// Build per-position hash array: Some(hash) for included positions, None for omitted (including
	// the implicit TLV0 at position 0). `decode_positions` is the shared source of truth
	// for the run/jump structure, so this consumer cannot drift from the encoder or the test.
	let positions = decode_positions(included_records.iter().map(|r| r.r#type), omitted_markers);
	let mut hashes: Vec<Option<sha256::Hash>> = Vec::with_capacity(positions.len());

	let mut inc_idx = 0;
	for included in positions {
		if included {
			let record = &included_records[inc_idx];
			let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record.record_bytes);
			let nonce_hash = nonce_hashes[inc_idx];
			hashes.push(Some(tagged_branch_hash_from_engine(
				branch_tag.clone(),
				leaf_hash,
				nonce_hash,
			)));
			inc_idx += 1;
		} else {
			hashes.push(None);
		}
	}

	let mut missing_idx: usize = 0;
	let root = reconstruct_merkle_root_dfs(&hashes, &branch_tag, missing_hashes, &mut missing_idx)?;

	if missing_idx != missing_hashes.len() {
		return Err(SelectiveDisclosureError::InsufficientMissingHashes);
	}

	root.ok_or(SelectiveDisclosureError::InsufficientMissingHashes)
}

fn reconstruct_merkle_root_dfs(
	hashes: &[Option<sha256::Hash>], branch_tag: &sha256::HashEngine,
	missing_hashes: &[sha256::Hash], missing_idx: &mut usize,
) -> Result<Option<sha256::Hash>, SelectiveDisclosureError> {
	if hashes.len() == 1 {
		return Ok(hashes[0]);
	}

	let mid = hashes.len().next_power_of_two() / 2;
	let (left_hashes, right_hashes) = hashes.split_at(mid);
	let left = reconstruct_merkle_root_dfs(left_hashes, branch_tag, missing_hashes, missing_idx)?;
	let right = reconstruct_merkle_root_dfs(right_hashes, branch_tag, missing_hashes, missing_idx)?;

	match (left, right) {
		(None, None) => Ok(None),
		(Some(l), None) => {
			if *missing_idx >= missing_hashes.len() {
				return Err(SelectiveDisclosureError::InsufficientMissingHashes);
			}
			let r = missing_hashes[*missing_idx];
			*missing_idx += 1;
			Ok(Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r)))
		},
		(None, Some(r)) => {
			if *missing_idx >= missing_hashes.len() {
				return Err(SelectiveDisclosureError::InsufficientMissingHashes);
			}
			let l = missing_hashes[*missing_idx];
			*missing_idx += 1;
			Ok(Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r)))
		},
		(Some(l), Some(r)) => Ok(Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r))),
	}
}

/// Validates that `markers` is a minimized omitted-marker sequence per BOLT 12 PR 1295, relative
/// to `included_types`. Each marker MUST be strictly ascending, non-zero, MUST NOT be an included
/// TLV type, and MUST be minimized: it equals the marker following the previous marker (continuing
/// a run) or the previous included type (starting a new run), per [`next_marker`]. The
/// signature-gap jump is handled by [`next_marker`], so signature-range markers are rejected
/// implicitly. This is the single source of truth for marker minimality; callers layer any
/// additional range restrictions on top (e.g. the payer-proof valid ranges).
pub(super) fn validate_omitted_markers(
	markers: &[u64], included_types: &BTreeSet<u64>,
) -> Result<(), SelectiveDisclosureError> {
	let mut inc_iter = included_types.iter().copied().peekable();
	// After the implicit TLV0 (marker 0), the first minimized marker is `next_marker(0)`.
	let mut expected_next: u64 = next_marker(0);
	let mut prev = 0u64;

	for &marker in markers {
		if marker == 0 {
			return Err(SelectiveDisclosureError::InvalidOmittedMarker);
		}
		if marker <= prev {
			return Err(SelectiveDisclosureError::InvalidOmittedMarkersOrder);
		}
		if included_types.contains(&marker) {
			return Err(SelectiveDisclosureError::InvalidOmittedMarker);
		}

		// Minimization: `marker` continues the current run (`expected_next`), or an included type
		// X sits between the previous position and `marker` with `next_marker(X) == marker`.
		if marker != expected_next {
			let mut found = false;
			for inc_type in inc_iter.by_ref() {
				if next_marker(inc_type) == marker {
					found = true;
					break;
				}
				if inc_type >= marker {
					return Err(SelectiveDisclosureError::InvalidOmittedMarker);
				}
			}
			if !found {
				return Err(SelectiveDisclosureError::InvalidOmittedMarker);
			}
		}

		expected_next = next_marker(marker);
		prev = marker;
	}

	Ok(())
}

/// Reconstruct the position inclusion map (`true` = included, `false` = omitted) from included
/// types and omitted markers, using the same [`decode_positions`] logic `reconstruct_merkle_root`
/// uses to place hashes.
#[cfg(test)]
fn reconstruct_positions(included_types: &[u64], omitted_markers: &[u64]) -> Vec<bool> {
	decode_positions(included_types.iter().copied(), omitted_markers)
}

#[cfg(test)]
mod tests {
	use super::{compute_omitted_markers, TlvMerkleData};
	use crate::offers::merkle::{TlvRecord, TlvStream};
	use bitcoin::hashes::{sha256, Hash};

	/// Builds a synthetic TLV stream with one record per type in `types`, each carrying a fixed
	/// 2-byte value. Types must be < 253 so each encodes as a single BigSize byte. Only the types
	/// and their order matter for selective-disclosure marker/position logic.
	fn synthetic_tlv_stream(types: &[u64]) -> Vec<u8> {
		let mut bytes = Vec::new();
		for &tlv_type in types {
			assert!(tlv_type < 253, "helper only supports single-byte BigSize types");
			bytes.extend_from_slice(&[tlv_type as u8, 0x02, 0x00, 0x00]);
		}
		bytes
	}

	/// Computes the disclosure for `included` over `tlv_bytes`, checks the omitted markers and the
	/// reconstructed positions, then reconstructs the merkle root and asserts it matches the
	/// full-tree root. Unlike feeding hand-written markers to `reconstruct_positions`, this proves
	/// the producer (`compute_selective_disclosure`) and consumer agree on the same stream.
	fn assert_disclosure_round_trip(
		tlv_bytes: &[u8], included: &[u64], expected_markers: &[u64], expected_positions: &[bool],
	) {
		use alloc::collections::BTreeSet;
		let included_types: BTreeSet<u64> = included.iter().copied().collect();

		let disclosure =
			super::compute_selective_disclosure(TlvStream::new(tlv_bytes), &included_types);
		assert_eq!(disclosure.omitted_markers.as_slice(), expected_markers);
		assert_eq!(
			super::reconstruct_positions(included, &disclosure.omitted_markers).as_slice(),
			expected_positions,
		);

		let included_records: Vec<TlvRecord<'_>> =
			TlvStream::new(tlv_bytes).filter(|r| included_types.contains(&r.r#type)).collect();
		let reconstructed = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.nonce_hashes,
			&disclosure.omitted_markers,
			&disclosure.missing_hashes,
		)
		.unwrap();
		assert_eq!(reconstructed, disclosure.merkle_root);
	}

	/// BOLT 12 payer proof spec example.
	/// TLVs: 0(omit), 10(incl), 20(omit), 30(omit), 40(incl), 50(omit), 60(omit)
	#[test]
	fn test_reconstruct_positions_spec_example() {
		assert_disclosure_round_trip(
			&synthetic_tlv_stream(&[0, 10, 20, 30, 40, 50, 60]),
			&[10, 40],
			&[11, 12, 41, 42],
			&[false, true, false, false, true, false, false],
		);
	}

	/// Omitted TLVs before the first included one.
	/// TLVs: 0(omit), 5(omit), 10(incl), 20(omit)
	#[test]
	fn test_reconstruct_positions_omitted_before_included() {
		assert_disclosure_round_trip(
			&synthetic_tlv_stream(&[0, 5, 10, 20]),
			&[10],
			&[1, 11],
			&[false, false, true, false],
		);
	}

	/// Only included TLVs (just the implicit TLV0 is omitted).
	/// TLVs: 0(omit), 10(incl), 20(incl)
	#[test]
	fn test_reconstruct_positions_no_omitted() {
		assert_disclosure_round_trip(
			&synthetic_tlv_stream(&[0, 10, 20]),
			&[10, 20],
			&[],
			&[false, true, true],
		);
	}

	/// Only omitted TLVs (nothing included). This is not a real proof shape -- a proof must
	/// disclose the required fields -- so there is no disclosed leaf to anchor reconstruction.
	/// The producer still emits markers/positions, but reconstructing the root must fail.
	/// TLVs: 0(omit), 5(omit), 10(omit)
	#[test]
	fn test_reconstruct_positions_no_included() {
		use alloc::collections::BTreeSet;

		let tlv_bytes = synthetic_tlv_stream(&[0, 5, 10]);
		let included_types = BTreeSet::new();
		let disclosure =
			super::compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included_types);
		assert_eq!(disclosure.omitted_markers, vec![1, 2]);
		assert_eq!(
			super::reconstruct_positions(&[], &disclosure.omitted_markers),
			vec![false, false, false],
		);

		assert_eq!(
			super::reconstruct_merkle_root(
				&[],
				&disclosure.nonce_hashes,
				&disclosure.omitted_markers,
				&disclosure.missing_hashes,
			),
			Err(super::SelectiveDisclosureError::InsufficientMissingHashes),
		);
	}

	#[test]
	fn test_validate_omitted_markers_edge_cases() {
		use alloc::collections::BTreeSet;

		let included_types = |types: &[u64]| -> BTreeSet<u64> { types.iter().copied().collect() };

		assert!(super::validate_omitted_markers(&[1, 2, 3, 41, 42], &included_types(&[40])).is_ok());
		assert!(super::validate_omitted_markers(&[11, 12], &included_types(&[10])).is_ok());
		assert!(super::validate_omitted_markers(&[], &included_types(&[10, 20])).is_ok());
		assert!(super::validate_omitted_markers(&[1_000_000_000], &included_types(&[239])).is_ok());

		assert_eq!(
			super::validate_omitted_markers(&[0], &included_types(&[])),
			Err(super::SelectiveDisclosureError::InvalidOmittedMarker)
		);
		assert_eq!(
			super::validate_omitted_markers(&[11, 11], &included_types(&[10])),
			Err(super::SelectiveDisclosureError::InvalidOmittedMarkersOrder)
		);
		assert_eq!(
			super::validate_omitted_markers(&[10], &included_types(&[10])),
			Err(super::SelectiveDisclosureError::InvalidOmittedMarker)
		);
		assert_eq!(
			super::validate_omitted_markers(&[11, 15, 41], &included_types(&[10, 40])),
			Err(super::SelectiveDisclosureError::InvalidOmittedMarker)
		);
		assert_eq!(
			super::validate_omitted_markers(&[11, 12, 45], &included_types(&[10, 40])),
			Err(super::SelectiveDisclosureError::InvalidOmittedMarker)
		);
	}

	#[test]
	fn compute_selective_disclosure_skips_signature_tlv_records() {
		use alloc::collections::BTreeSet;

		let bytes_without_signature = vec![
			0x00, 0x01, 0x00, // payer_metadata
			0x0a, 0x01, 0x01, // type 10
			0x14, 0x01, 0x02, // type 20
		];
		let bytes_with_signature = vec![
			0x00, 0x01, 0x00, // payer_metadata
			0x0a, 0x01, 0x01, // type 10
			0xf0, 0x00, // signature type 240, ignored by merkle calculation
			0x14, 0x01, 0x02, // type 20
		];
		let included = [10, 20].into_iter().collect::<BTreeSet<_>>();

		assert_eq!(
			super::compute_selective_disclosure(TlvStream::new(&bytes_with_signature), &included),
			super::compute_selective_disclosure(
				TlvStream::new(&bytes_without_signature),
				&included
			)
		);
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
		let disclosure = super::compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included);

		// Verify markers match spec example
		assert_eq!(disclosure.omitted_markers, vec![11, 12, 41, 42]);

		// Verify nonce_hashes count matches included TLVs
		assert_eq!(disclosure.nonce_hashes.len(), 2);

		// Collect included records for reconstruction
		let included_records: Vec<TlvRecord<'_>> =
			TlvStream::new(&tlv_bytes).filter(|r| included.contains(&r.r#type)).collect();

		// Reconstruct merkle root
		let reconstructed = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.nonce_hashes,
			&disclosure.omitted_markers,
			&disclosure.missing_hashes,
		)
		.unwrap();

		// Must match original
		assert_eq!(reconstructed, disclosure.merkle_root);
	}

	/// Test that the synthetic 7-node example still requires four missing hashes.
	///
	/// For the synthetic tree with TLVs [0(o), 10(I), 20(o), 30(o), 40(I), 50(o), 60(o)]:
	/// - hash(0) covers type 0
	/// - hash(B(20,30)) covers types 20-30
	/// - hash(50) covers type 50
	/// - hash(60) covers type 60
	///
	/// This still needs 4 missing hashes. The DFS-ordering fix changes the order
	/// they are emitted and consumed in, but not the count for this tree shape.
	#[test]
	fn test_missing_hashes_for_synthetic_tree() {
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

		let disclosure = super::compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included);

		// We should still have 4 missing hashes for omitted types:
		// - type 0 (single leaf)
		// - types 20+30 (combined branch)
		// - type 50 (single leaf)
		// - type 60 (single leaf)
		assert_eq!(
			disclosure.missing_hashes.len(),
			4,
			"Expected 4 missing hashes for omitted types [0, 20+30, 50, 60]"
		);

		// Verify the round-trip still works with the correct ordering
		let included_records: Vec<TlvRecord<'_>> =
			TlvStream::new(&tlv_bytes).filter(|r| included.contains(&r.r#type)).collect();

		let reconstructed = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.nonce_hashes,
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

		let disclosure = super::compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included);

		let included_records: Vec<TlvRecord<'_>> =
			TlvStream::new(&tlv_bytes).filter(|r| included.contains(&r.r#type)).collect();

		// Try with empty missing_hashes (should fail)
		let result = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.nonce_hashes,
			&disclosure.omitted_markers,
			&[], // Wrong!
		);

		assert!(result.is_err());
	}

	/// Verify that [`compute_omitted_markers`] jumps from the top of the low
	/// marker range (239) to the start of the high range (1_000_000_000) per
	/// BOLT 12 PR 1295, rather than entering the signature type range. Real
	/// BOLT 12 invoices have far fewer than 239 non-signature TLVs, so this
	/// case is unreachable in practice.
	#[test]
	fn compute_omitted_markers_jumps_to_high_range_after_239() {
		// 240 consecutive omitted TLVs at types 1..=240. The first 239 markers
		// climb 1..=239; the 240th would be 240 (in the signature range), so it
		// jumps to 1_000_000_000 instead.
		let dummy_hash = sha256::Hash::all_zeros();
		let tlv_data: Vec<TlvMerkleData> = (1u64..=240)
			.map(|tlv_type| TlvMerkleData {
				tlv_type,
				nonce_hash: dummy_hash,
				per_tlv_hash: dummy_hash,
				is_included: false,
			})
			.collect();

		let markers: Vec<u64> = compute_omitted_markers(tlv_data.iter()).collect();

		let mut expected: Vec<u64> = (1..=239).collect();
		expected.push(1_000_000_000);
		assert_eq!(markers, expected);
	}

	/// An *included* TLV at the top of the low range (type 239) followed by an
	/// omitted TLV: the marker must skip the signature/payer-proof gap and jump
	/// to the start of the experimental range, not land on 240.
	#[test]
	fn compute_omitted_markers_jumps_after_included_at_top_of_low_range() {
		let dummy_hash = sha256::Hash::all_zeros();
		let tlv_data = [
			TlvMerkleData {
				tlv_type: 239,
				nonce_hash: dummy_hash,
				per_tlv_hash: dummy_hash,
				is_included: true,
			},
			TlvMerkleData {
				tlv_type: 1_500_000_000,
				nonce_hash: dummy_hash,
				per_tlv_hash: dummy_hash,
				is_included: false,
			},
		];
		let markers: Vec<u64> = compute_omitted_markers(tlv_data.iter()).collect();
		assert_eq!(markers, vec![1_000_000_000]);
	}

	/// After a jump into the experimental range, subsequent omitted markers
	/// continue sequentially within that range.
	#[test]
	fn compute_omitted_markers_continue_in_experimental_range_after_jump() {
		let dummy_hash = sha256::Hash::all_zeros();
		let tlv_data = [
			TlvMerkleData {
				tlv_type: 239,
				nonce_hash: dummy_hash,
				per_tlv_hash: dummy_hash,
				is_included: true,
			},
			TlvMerkleData {
				tlv_type: 3_000_000_000,
				nonce_hash: dummy_hash,
				per_tlv_hash: dummy_hash,
				is_included: false,
			},
			TlvMerkleData {
				tlv_type: 3_000_000_001,
				nonce_hash: dummy_hash,
				per_tlv_hash: dummy_hash,
				is_included: false,
			},
		];
		let markers: Vec<u64> = compute_omitted_markers(tlv_data.iter()).collect();
		assert_eq!(markers, vec![1_000_000_000, 1_000_000_001]);
	}

	/// [`next_marker`] increments by one within a range but jumps over the
	/// signature/payer-proof gap, so producer and readers stay in agreement.
	#[test]
	fn next_marker_jumps_the_gap() {
		assert_eq!(super::next_marker(0), 1);
		assert_eq!(super::next_marker(5), 6);
		assert_eq!(super::next_marker(238), 239);
		// 240 would land in the signature range, so it jumps to the experimental range.
		assert_eq!(super::next_marker(239), 1_000_000_000);
		assert_eq!(super::next_marker(1_000_000_000), 1_000_000_001);
	}

	#[test]
	fn validate_omitted_markers_direct() {
		use alloc::collections::BTreeSet;
		let none: BTreeSet<u64> = BTreeSet::new();

		// A minimized leading run with nothing included is accepted.
		assert!(super::validate_omitted_markers(&[1, 2, 3], &none).is_ok());
		// The empty sequence is accepted.
		assert!(super::validate_omitted_markers(&[], &none).is_ok());
		// Zero is rejected (it is the implicit TLV0 marker).
		assert!(super::validate_omitted_markers(&[0], &none).is_err());
		// A non-ascending sequence is rejected.
		assert!(super::validate_omitted_markers(&[2, 1], &none).is_err());
		// A gap with no intervening included type to justify it is non-minimized -> rejected.
		assert!(super::validate_omitted_markers(&[1, 3], &none).is_err());

		// The same `[1, 3]` is accepted when included type 2 sits between them, because
		// next_marker(2) == 3 justifies the jump.
		let inc2: BTreeSet<u64> = [2u64].into_iter().collect();
		assert!(super::validate_omitted_markers(&[1, 3], &inc2).is_ok());
		// A marker equal to an included type is rejected.
		assert!(super::validate_omitted_markers(&[2], &inc2).is_err());

		// The signature-gap jump is accepted when justified by an included type at the top of the
		// low range: included 239, omitted marker 1_000_000_000 (next_marker(239)).
		let inc239: BTreeSet<u64> = [239u64].into_iter().collect();
		assert!(super::validate_omitted_markers(&[1_000_000_000], &inc239).is_ok());
		// ...but not without that justification.
		assert!(super::validate_omitted_markers(&[1_000_000_000], &none).is_err());
	}
}
