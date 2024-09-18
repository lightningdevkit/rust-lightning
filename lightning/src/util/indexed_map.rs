//! This module has a map which can be iterated in a deterministic order. See the [`IndexedMap`].

use crate::prelude::*;
use alloc::slice::Iter;
use core::hash::Hash;
use core::ops::{Bound, RangeBounds};

/// A map which can be iterated in a deterministic order.
///
/// This would traditionally be accomplished by simply using a [`BTreeMap`], however B-Trees
/// generally have very slow lookups. Because we use a nodes+channels map while finding routes
/// across the network graph, our network graph backing map must be as performant as possible.
/// However, because peers expect to sync the network graph from us (and we need to support that
/// without holding a lock on the graph for the duration of the sync or dumping the entire graph
/// into our outbound message queue), we need an iterable map with a consistent iteration order we
/// can jump to a starting point on.
///
/// Thus, we have a custom data structure here - its API mimics that of Rust's [`BTreeMap`], but is
/// actually backed by a [`HashMap`], with some additional tracking to ensure we can iterate over
/// keys in the order defined by [`Ord`].
///
/// This is not exported to bindings users as bindings provide alternate accessors rather than exposing maps directly.
///
/// [`BTreeMap`]: alloc::collections::BTreeMap
#[derive(Clone, Debug, Eq)]
pub struct IndexedMap<K: Hash + Ord, V> {
	map: HashMap<K, V>,
	keys: Vec<K>,
}

impl<K: Clone + Hash + Ord, V> IndexedMap<K, V> {
	/// Constructs a new, empty map
	pub fn new() -> Self {
		Self { map: new_hash_map(), keys: Vec::new() }
	}

	/// Constructs a new, empty map with the given capacity pre-allocated
	pub fn with_capacity(capacity: usize) -> Self {
		Self { map: hash_map_with_capacity(capacity), keys: Vec::with_capacity(capacity) }
	}

	#[inline(always)]
	/// Fetches the element with the given `key`, if one exists.
	pub fn get(&self, key: &K) -> Option<&V> {
		self.map.get(key)
	}

	/// Fetches a mutable reference to the element with the given `key`, if one exists.
	pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
		self.map.get_mut(key)
	}

	/// Fetches the key-value pair corresponding to the supplied key, if one exists.
	pub fn get_key_value(&self, key: &K) -> Option<(&K, &V)> {
		self.map.get_key_value(key)
	}

	#[inline]
	/// Returns true if an element with the given `key` exists in the map.
	pub fn contains_key(&self, key: &K) -> bool {
		self.map.contains_key(key)
	}

	/// Removes the element with the given `key`, returning it, if one exists.
	pub fn remove(&mut self, key: &K) -> Option<V> {
		let ret = self.map.remove(key);
		if let Some(_) = ret {
			let idx =
				self.keys.iter().position(|k| k == key).expect("map and keys must be consistent");
			self.keys.remove(idx);
		}
		ret
	}

	/// Inserts the given `key`/`value` pair into the map, returning the element that was
	/// previously stored at the given `key`, if one exists.
	pub fn insert(&mut self, key: K, value: V) -> Option<V> {
		let ret = self.map.insert(key.clone(), value);
		if ret.is_none() {
			self.keys.push(key);
		}
		ret
	}

	/// Returns an [`Entry`] for the given `key` in the map, allowing access to the value.
	pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
		match self.map.entry(key.clone()) {
			hash_map::Entry::Vacant(entry) => {
				Entry::Vacant(VacantEntry { underlying_entry: entry, key, keys: &mut self.keys })
			},
			hash_map::Entry::Occupied(entry) => {
				Entry::Occupied(OccupiedEntry { underlying_entry: entry, keys: &mut self.keys })
			},
		}
	}

	/// Returns an iterator which iterates over the keys in the map, in a random order.
	pub fn unordered_keys(&self) -> impl Iterator<Item = &K> {
		self.map.keys()
	}

	/// Returns an iterator which iterates over the `key`/`value` pairs in a random order.
	pub fn unordered_iter(&self) -> impl Iterator<Item = (&K, &V)> {
		self.map.iter()
	}

	/// Returns an iterator which iterates over the `key`s and mutable references to `value`s in a
	/// random order.
	pub fn unordered_iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
		self.map.iter_mut()
	}

	/// Returns an iterator which iterates over the `key`/`value` pairs in a given range.
	pub fn range<R: RangeBounds<K>>(&mut self, range: R) -> Range<K, V> {
		self.keys.sort_unstable();
		let start = match range.start_bound() {
			Bound::Unbounded => 0,
			Bound::Included(key) => self.keys.binary_search(key).unwrap_or_else(|index| index),
			Bound::Excluded(key) => {
				self.keys.binary_search(key).map(|index| index + 1).unwrap_or_else(|index| index)
			},
		};
		let end = match range.end_bound() {
			Bound::Unbounded => self.keys.len(),
			Bound::Included(key) => {
				self.keys.binary_search(key).map(|index| index + 1).unwrap_or_else(|index| index)
			},
			Bound::Excluded(key) => self.keys.binary_search(key).unwrap_or_else(|index| index),
		};

		Range { inner_range: self.keys[start..end].iter(), map: &self.map }
	}

	/// Returns the number of `key`/`value` pairs in the map
	pub fn len(&self) -> usize {
		self.map.len()
	}

	/// Returns true if there are no elements in the map
	pub fn is_empty(&self) -> bool {
		self.map.is_empty()
	}
}

impl<K: Hash + Ord + PartialEq, V: PartialEq> PartialEq for IndexedMap<K, V> {
	fn eq(&self, other: &Self) -> bool {
		self.map == other.map
	}
}

/// An iterator over a range of values in an [`IndexedMap`]
///
/// This is not exported to bindings users as bindings provide alternate accessors rather than exposing maps directly.
pub struct Range<'a, K: Hash + Ord, V> {
	inner_range: Iter<'a, K>,
	map: &'a HashMap<K, V>,
}
impl<'a, K: Hash + Ord, V: 'a> Iterator for Range<'a, K, V> {
	type Item = (&'a K, &'a V);
	fn next(&mut self) -> Option<(&'a K, &'a V)> {
		self.inner_range
			.next()
			.map(|k| (k, self.map.get(k).expect("map and keys must be consistent")))
	}
}

/// An [`Entry`] for a key which currently has no value
///
/// This is not exported to bindings users as bindings provide alternate accessors rather than exposing maps directly.
pub struct VacantEntry<'a, K: Hash + Ord, V> {
	underlying_entry: VacantHashMapEntry<'a, K, V>,
	key: K,
	keys: &'a mut Vec<K>,
}

/// An [`Entry`] for an existing key-value pair
///
/// This is not exported to bindings users as bindings provide alternate accessors rather than exposing maps directly.
pub struct OccupiedEntry<'a, K: Hash + Ord, V> {
	underlying_entry: OccupiedHashMapEntry<'a, K, V>,
	keys: &'a mut Vec<K>,
}

/// A mutable reference to a position in the map. This can be used to reference, add, or update the
/// value at a fixed key.
///
/// This is not exported to bindings users as bindings provide alternate accessors rather than exposing maps directly.
pub enum Entry<'a, K: Hash + Ord, V> {
	/// A mutable reference to a position within the map where there is no value.
	Vacant(VacantEntry<'a, K, V>),
	/// A mutable reference to a position within the map where there is currently a value.
	Occupied(OccupiedEntry<'a, K, V>),
}

impl<'a, K: Hash + Ord, V> VacantEntry<'a, K, V> {
	/// Insert a value into the position described by this entry.
	pub fn insert(self, value: V) -> &'a mut V {
		self.keys.push(self.key);
		self.underlying_entry.insert(value)
	}
}

impl<'a, K: Hash + Ord, V> OccupiedEntry<'a, K, V> {
	/// Remove the value at the position described by this entry.
	pub fn remove_entry(self) -> (K, V) {
		let res = self.underlying_entry.remove_entry();
		let idx =
			self.keys.iter().position(|k| k == &res.0).expect("map and keys must be consistent");
		self.keys.remove(idx);
		res
	}

	/// Get a reference to the value at the position described by this entry.
	pub fn get(&self) -> &V {
		self.underlying_entry.get()
	}

	/// Get a mutable reference to the value at the position described by this entry.
	pub fn get_mut(&mut self) -> &mut V {
		self.underlying_entry.get_mut()
	}

	/// Consume this entry, returning a mutable reference to the value at the position described by
	/// this entry.
	pub fn into_mut(self) -> &'a mut V {
		self.underlying_entry.into_mut()
	}
}
