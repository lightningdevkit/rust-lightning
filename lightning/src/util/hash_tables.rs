//! Generally LDK uses `hashbrown`'s `HashMap`s with the `std` `SipHasher` and uses `getrandom` to
//! opportunistically randomize it, if randomization is available.
//!
//! This module simply re-exports the `HashMap` used in LDK for public consumption.

pub use hashbrown::hash_map;

mod hashbrown_tables {
	#[cfg(all(feature = "std", not(test)))]
	mod hasher {
		pub use std::collections::hash_map::RandomState;
	}
	#[cfg(all(feature = "std", test))]
	mod hasher {
		#![allow(deprecated)] // hash::SipHasher was deprecated in favor of something only in std.
		use core::hash::{BuildHasher, Hasher};

		/// A [`BuildHasher`] for tests that supports deterministic behavior via environment variable.
		///
		/// When `LDK_TEST_DETERMINISTIC_HASHES` is set, uses fixed keys for deterministic iteration.
		/// Otherwise, delegates to std's RandomState for random hashing.
		#[derive(Clone)]
		pub enum RandomState {
			Std(std::collections::hash_map::RandomState),
			Deterministic,
		}

		impl RandomState {
			pub fn new() -> RandomState {
				if std::env::var("LDK_TEST_DETERMINISTIC_HASHES").map(|v| v == "1").unwrap_or(false)
				{
					RandomState::Deterministic
				} else {
					RandomState::Std(std::collections::hash_map::RandomState::new())
				}
			}
		}

		impl Default for RandomState {
			fn default() -> RandomState {
				RandomState::new()
			}
		}

		/// A hasher wrapper that delegates to either std's DefaultHasher or a deterministic SipHasher.
		pub enum RandomStateHasher {
			Std(std::collections::hash_map::DefaultHasher),
			Deterministic(core::hash::SipHasher),
		}

		impl Hasher for RandomStateHasher {
			fn finish(&self) -> u64 {
				match self {
					RandomStateHasher::Std(h) => h.finish(),
					RandomStateHasher::Deterministic(h) => h.finish(),
				}
			}
			fn write(&mut self, bytes: &[u8]) {
				match self {
					RandomStateHasher::Std(h) => h.write(bytes),
					RandomStateHasher::Deterministic(h) => h.write(bytes),
				}
			}
		}

		impl BuildHasher for RandomState {
			type Hasher = RandomStateHasher;
			fn build_hasher(&self) -> RandomStateHasher {
				match self {
					RandomState::Std(s) => RandomStateHasher::Std(s.build_hasher()),
					RandomState::Deterministic => {
						RandomStateHasher::Deterministic(core::hash::SipHasher::new_with_keys(0, 0))
					},
				}
			}
		}
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
				#[cfg(not(fuzzing))]
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
				#[cfg(fuzzing)]
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

	pub use hasher::*;

	/// The HashMap type used in LDK.
	pub type HashMap<K, V> = hashbrown::HashMap<K, V, RandomState>;
	/// The HashSet type used in LDK.
	pub type HashSet<K> = hashbrown::HashSet<K, RandomState>;

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

	/// Builds a new [`HashSet`].
	pub fn new_hash_set<K>() -> HashSet<K> {
		HashSet::with_hasher(RandomState::new())
	}
	/// Builds a new [`HashSet`] with the given capacity.
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

pub use hashbrown_tables::*;
