// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use lightning::types::features::FeatureFlags;

use crate::utils::test_logger;

use std::ops::{Deref, DerefMut};

/// Check various methods on [`FeatureFlags`] given `v` which should be equal to `feat` and an
/// `old_v` which should be equal to `old_feat`.
fn check_eq(v: &Vec<u8>, feat: &FeatureFlags, old_v: &mut Vec<u8>, old_feat: &mut FeatureFlags) {
	assert_eq!(v.len(), feat.len());
	assert_eq!(v.deref(), feat.deref());
	assert_eq!(old_v.deref_mut(), old_feat.deref_mut());

	let mut feat_clone = feat.clone();
	assert!(feat_clone == *feat);

	// Test iteration over the `FeatureFlags` with the base iterator
	let mut feat_iter = feat.iter();
	let mut vec_iter = v.iter();
	assert_eq!(feat_iter.len(), vec_iter.len());
	while let Some(feat) = feat_iter.next() {
		let v = vec_iter.next().unwrap();
		assert_eq!(*feat, *v);
	}
	assert!(vec_iter.next().is_none());

	// Do the same test of iteration over the `FeatureFlags` with the mutable iterator
	let mut feat_iter = feat_clone.iter_mut();
	let mut vec_iter = v.iter();
	assert_eq!(feat_iter.len(), vec_iter.len());
	while let Some(feat) = feat_iter.next() {
		let v = vec_iter.next().unwrap();
		assert_eq!(*feat, *v);
	}
	assert!(vec_iter.next().is_none());

	assert_eq!(v < old_v, feat < old_feat);
	assert_eq!(v.partial_cmp(old_v), feat.partial_cmp(old_feat));
}

#[inline]
pub fn do_test(data: &[u8]) {
	if data.len() % 3 != 0 {
		return;
	}
	let mut vec = Vec::new();
	let mut features = FeatureFlags::empty();

	// For each 3-tuple in the input, interpret the first byte as a "command", the second byte as
	// an index within `vec`/`features` to mutate, and the third byte as a value.
	for step in data.windows(3) {
		let mut old_vec = vec.clone();
		let mut old_features = features.clone();
		match step[0] {
			0 => {
				vec.resize(step[1] as usize, step[2]);
				features.resize(step[1] as usize, step[2]);
			},
			1 => {
				if vec.len() > step[1] as usize {
					vec[step[1] as usize] = step[2];
					features[step[1] as usize] = step[2];
				}
			},
			2 => {
				if vec.len() > step[1] as usize {
					*vec.iter_mut().skip(step[1] as usize).next().unwrap() = step[2];
					*features.iter_mut().skip(step[1] as usize).next().unwrap() = step[2];
				}
			},
			_ => {},
		}
		// After each mutation, check that `vec` and `features` remain the same, and pass the
		// previous state for testing comparisons.
		check_eq(&vec, &features, &mut old_vec, &mut old_features);
	}

	check_eq(&vec, &features, &mut vec.clone(), &mut features.clone());
}

pub fn feature_flags_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn feature_flags_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
