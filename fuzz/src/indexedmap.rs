// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use lightning::util::indexed_map::{IndexedMap, self};
use std::collections::{BTreeMap, btree_map};
use hashbrown::HashSet;

use crate::utils::test_logger;

use std::ops::{RangeBounds, Bound};

struct ExclLowerInclUpper(u8, u8);
impl RangeBounds<u8> for ExclLowerInclUpper {
	fn start_bound(&self) -> Bound<&u8> { Bound::Excluded(&self.0) }
	fn end_bound(&self) -> Bound<&u8> { Bound::Included(&self.1) }
}
struct ExclLowerExclUpper(u8, u8);
impl RangeBounds<u8> for ExclLowerExclUpper {
	fn start_bound(&self) -> Bound<&u8> { Bound::Excluded(&self.0) }
	fn end_bound(&self) -> Bound<&u8> { Bound::Excluded(&self.1) }
}

fn check_eq(btree: &BTreeMap<u8, u8>, mut indexed: IndexedMap<u8, u8>) {
	assert_eq!(btree.len(), indexed.len());
	assert_eq!(btree.is_empty(), indexed.is_empty());

	let mut btree_clone = btree.clone();
	assert!(btree_clone == *btree);
	let mut indexed_clone = indexed.clone();
	assert!(indexed_clone == indexed);

	for k in 0..=255 {
		assert_eq!(btree.contains_key(&k), indexed.contains_key(&k));
		assert_eq!(btree.get(&k), indexed.get(&k));

		let btree_entry = btree_clone.entry(k);
		let indexed_entry = indexed_clone.entry(k);
		match btree_entry {
			btree_map::Entry::Occupied(mut bo) => {
				if let indexed_map::Entry::Occupied(mut io) = indexed_entry {
					assert_eq!(bo.get(), io.get());
					assert_eq!(bo.get_mut(), io.get_mut());
				} else { panic!(); }
			},
			btree_map::Entry::Vacant(_) => {
				if let indexed_map::Entry::Vacant(_) = indexed_entry {
				} else { panic!(); }
			}
		}
	}

	const STRIDE: u8 = 16;
	for range_type in 0..4 {
		for k in 0..=255/STRIDE {
			let lower_bound = k * STRIDE;
			let upper_bound = lower_bound + (STRIDE - 1);
			macro_rules! range { ($map: expr) => {
				match range_type {
					0 => $map.range(lower_bound..upper_bound),
					1 => $map.range(lower_bound..=upper_bound),
					2 => $map.range(ExclLowerInclUpper(lower_bound, upper_bound)),
					3 => $map.range(ExclLowerExclUpper(lower_bound, upper_bound)),
					_ => unreachable!(),
				}
			} }
			let mut btree_iter = range!(btree);
			let mut indexed_iter = range!(indexed);
			loop {
				let b_v = btree_iter.next();
				let i_v = indexed_iter.next();
				assert_eq!(b_v, i_v);
				if b_v.is_none() { break; }
			}
		}
	}

	let mut key_set = HashSet::with_capacity(256);
	for k in indexed.unordered_keys() {
		assert!(key_set.insert(*k));
		assert!(btree.contains_key(k));
	}
	assert_eq!(key_set.len(), btree.len());

	key_set.clear();
	for (k, v) in indexed.unordered_iter() {
		assert!(key_set.insert(*k));
		assert_eq!(btree.get(k).unwrap(), v);
	}
	assert_eq!(key_set.len(), btree.len());

	key_set.clear();
	for (k, v) in indexed_clone.unordered_iter_mut() {
		assert!(key_set.insert(*k));
		assert_eq!(btree.get(k).unwrap(), v);
	}
	assert_eq!(key_set.len(), btree.len());
}

#[inline]
pub fn do_test(data: &[u8]) {
	if data.len() % 2 != 0 { return; }
	let mut btree = BTreeMap::new();
	let mut indexed = IndexedMap::new();

	// Read in k-v pairs from the input and insert them into the maps then check that the maps are
	// equivalent in every way we can read them.
	for tuple in data.windows(2) {
		let prev_value_b = btree.insert(tuple[0], tuple[1]);
		let prev_value_i = indexed.insert(tuple[0], tuple[1]);
		assert_eq!(prev_value_b, prev_value_i);
	}
	check_eq(&btree, indexed.clone());

	// Now, modify the maps in all the ways we have to do so, checking that the maps remain
	// equivalent as we go.
	for (k, v) in indexed.unordered_iter_mut() {
		*v = *k;
		*btree.get_mut(k).unwrap() = *k;
	}
	check_eq(&btree, indexed.clone());

	for k in 0..=255 {
		match btree.entry(k) {
			btree_map::Entry::Occupied(mut bo) => {
				if let indexed_map::Entry::Occupied(mut io) = indexed.entry(k) {
					if k < 64 {
						*io.get_mut() ^= 0xff;
						*bo.get_mut() ^= 0xff;
					} else if k < 128 {
						*io.into_mut() ^= 0xff;
						*bo.get_mut() ^= 0xff;
					} else {
						assert_eq!(bo.remove_entry(), io.remove_entry());
					}
				} else { panic!(); }
			},
			btree_map::Entry::Vacant(bv) => {
				if let indexed_map::Entry::Vacant(iv) = indexed.entry(k) {
					bv.insert(k);
					iv.insert(k);
				} else { panic!(); }
			},
		}
	}
	check_eq(&btree, indexed);
}

pub fn indexedmap_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn indexedmap_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
