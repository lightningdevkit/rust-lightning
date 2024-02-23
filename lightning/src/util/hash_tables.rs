//! Generally LDK uses `std`'s `HashMap`s, however when building for no-std, LDK uses `hashbrown`'s
//! `HashMap`s with the `std` `SipHasher` and uses `getrandom` to opportunistically randomize it,
//! if randomization is available.
//!
//! This module simply re-exports the `HashMap` used in LDK for public consumption.

#[cfg(feature = "hashbrown")]
extern crate hashbrown;
#[cfg(feature = "possiblyrandom")]
extern crate possiblyrandom;

// For no-std builds, we need to use hashbrown, however, by default, it doesn't randomize the
// hashing and is vulnerable to HashDoS attacks. Thus, we use the core SipHasher when not using
// std, but use `getrandom` to randomize it if its available.

#[cfg(not(feature = "hashbrown"))]
mod std_hashtables {
	pub use std::collections::hash_map::RandomState;
	pub use std::collections::HashMap;

	pub(crate) use std::collections::{hash_map, HashSet};

	pub(crate) type OccupiedHashMapEntry<'a, K, V> =
		std::collections::hash_map::OccupiedEntry<'a, K, V>;
	pub(crate) type VacantHashMapEntry<'a, K, V> =
		std::collections::hash_map::VacantEntry<'a, K, V>;

	/// Builds a new [`HashMap`].
	pub fn new_hash_map<K, V>() -> HashMap<K, V> {
		HashMap::new()
	}
	/// Builds a new [`HashMap`] with the given capacity.
	pub fn hash_map_with_capacity<K, V>(cap: usize) -> HashMap<K, V> {
		HashMap::with_capacity(cap)
	}
	pub(crate) fn hash_map_from_iter<
		K: core::hash::Hash + Eq,
		V,
		I: IntoIterator<Item = (K, V)>,
	>(
		iter: I,
	) -> HashMap<K, V> {
		HashMap::from_iter(iter)
	}

	pub(crate) fn new_hash_set<K>() -> HashSet<K> {
		HashSet::new()
	}
	pub(crate) fn hash_set_with_capacity<K>(cap: usize) -> HashSet<K> {
		HashSet::with_capacity(cap)
	}
	pub(crate) fn hash_set_from_iter<K: core::hash::Hash + Eq, I: IntoIterator<Item = K>>(
		iter: I,
	) -> HashSet<K> {
		HashSet::from_iter(iter)
	}
}
#[cfg(not(feature = "hashbrown"))]
pub use std_hashtables::*;

#[cfg(feature = "hashbrown")]
pub(crate) use self::hashbrown::hash_map;

#[cfg(feature = "hashbrown")]
mod hashbrown_tables {
	#[cfg(feature = "std")]
	mod hasher {
		pub use std::collections::hash_map::RandomState;
	}
	#[cfg(not(feature = "std"))]
	mod hasher {
		#![allow(deprecated)] // hash::SipHasher was deprecated in favor of something only in std.
		use core::hash::{BuildHasher, SipHasher};

		#[derive(Clone, Copy)]
		/// A simple implementation of [`BuildHasher`] that uses `getrandom` to opportunistically
		/// randomize, if the platform supports it.
		pub struct RandomState {
			k0: u64,
			k1: u64,
		}

		impl RandomState {
			/// Constructs a new [`RandomState`] which may or may not be random, depending on the
			/// target platform.
			pub fn new() -> RandomState {
				let (k0, k1);
				#[cfg(all(not(fuzzing), feature = "possiblyrandom"))]
				{
					let mut keys = [0; 16];
					possiblyrandom::getpossiblyrandom(&mut keys);

					let mut k0_bytes = [0; 8];
					let mut k1_bytes = [0; 8];
					k0_bytes.copy_from_slice(&keys[..8]);
					k1_bytes.copy_from_slice(&keys[8..]);
					k0 = u64::from_le_bytes(k0_bytes);
					k1 = u64::from_le_bytes(k1_bytes);
				}
				#[cfg(any(fuzzing, not(feature = "possiblyrandom")))]
				{
					k0 = 0;
					k1 = 0;
				}
				RandomState { k0, k1 }
			}
		}

		impl Default for RandomState {
			fn default() -> RandomState {
				RandomState::new()
			}
		}

		impl BuildHasher for RandomState {
			type Hasher = SipHasher;
			fn build_hasher(&self) -> SipHasher {
				SipHasher::new_with_keys(self.k0, self.k1)
			}
		}
	}

	use super::*;
	pub use hasher::*;

	/// The HashMap type used in LDK.
	pub type HashMap<K, V> = hashbrown::HashMap<K, V, RandomState>;
	pub(crate) type HashSet<K> = hashbrown::HashSet<K, RandomState>;

	pub(crate) type OccupiedHashMapEntry<'a, K, V> =
		hashbrown::hash_map::OccupiedEntry<'a, K, V, RandomState>;
	pub(crate) type VacantHashMapEntry<'a, K, V> =
		hashbrown::hash_map::VacantEntry<'a, K, V, RandomState>;

	/// Builds a new [`HashMap`].
	pub fn new_hash_map<K, V>() -> HashMap<K, V> {
		HashMap::with_hasher(RandomState::new())
	}
	/// Builds a new [`HashMap`] with the given capacity.
	pub fn hash_map_with_capacity<K, V>(cap: usize) -> HashMap<K, V> {
		HashMap::with_capacity_and_hasher(cap, RandomState::new())
	}
	pub(crate) fn hash_map_from_iter<
		K: core::hash::Hash + Eq,
		V,
		I: IntoIterator<Item = (K, V)>,
	>(
		iter: I,
	) -> HashMap<K, V> {
		let iter = iter.into_iter();
		let min_size = iter.size_hint().0;
		let mut res = HashMap::with_capacity_and_hasher(min_size, RandomState::new());
		res.extend(iter);
		res
	}

	pub(crate) fn new_hash_set<K>() -> HashSet<K> {
		HashSet::with_hasher(RandomState::new())
	}
	pub(crate) fn hash_set_with_capacity<K>(cap: usize) -> HashSet<K> {
		HashSet::with_capacity_and_hasher(cap, RandomState::new())
	}
	pub(crate) fn hash_set_from_iter<K: core::hash::Hash + Eq, I: IntoIterator<Item = K>>(
		iter: I,
	) -> HashSet<K> {
		let iter = iter.into_iter();
		let min_size = iter.size_hint().0;
		let mut res = HashSet::with_capacity_and_hasher(min_size, RandomState::new());
		res.extend(iter);
		res
	}
}
#[cfg(feature = "hashbrown")]
pub use hashbrown_tables::*;
