//! This module has a map which can be iterated in a deterministic order. See the [`IndexedMap`].

use crate::prelude::HashMap;
use alloc::collections::{BTreeMap, btree_map};
use core::cmp::Ord;
use core::ops::RangeBounds;

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
/// [`BTreeMap`]: alloc::collections::BTreeMap
#[derive(Clone, PartialEq, Eq)]
pub struct IndexedMap<K: Ord, V> {
	map: BTreeMap<K, V>,
}

impl<K: Ord, V> IndexedMap<K, V> {
	/// Constructs a new, empty map
	pub fn new() -> Self {
		Self {
			map: BTreeMap::new(),
		}
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

	#[inline]
	/// Returns true if an element with the given `key` exists in the map.
	pub fn contains_key(&self, key: &K) -> bool {
		self.map.contains_key(key)
	}

	/// Removes the element with the given `key`, returning it, if one exists.
	pub fn remove(&mut self, key: &K) -> Option<V> {
		self.map.remove(key)
	}

	/// Inserts the given `key`/`value` pair into the map, returning the element that was
	/// previously stored at the given `key`, if one exists.
	pub fn insert(&mut self, key: K, value: V) -> Option<V> {
		self.map.insert(key, value)
	}

	/// Returns an [`Entry`] for the given `key` in the map, allowing access to the value.
	pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
		match self.map.entry(key) {
			btree_map::Entry::Vacant(entry) => {
				Entry::Vacant(VacantEntry {
					underlying_entry: entry
				})
			},
			btree_map::Entry::Occupied(entry) => {
				Entry::Occupied(OccupiedEntry {
					underlying_entry: entry
				})
			}
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
	pub fn range<R: RangeBounds<K>>(&self, range: R) -> btree_map::Range<K, V> {
		self.map.range(range)
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

/// An [`Entry`] for a key which currently has no value
pub struct VacantEntry<'a, K: Ord, V> {
	underlying_entry: btree_map::VacantEntry<'a, K, V>,
}

/// An [`Entry`] for an existing key-value pair
pub struct OccupiedEntry<'a, K: Ord, V> {
	underlying_entry: btree_map::OccupiedEntry<'a, K, V>,
}

/// A mutable reference to a position in the map. This can be used to reference, add, or update the
/// value at a fixed key.
pub enum Entry<'a, K: Ord, V> {
	/// A mutable reference to a position within the map where there is no value.
	Vacant(VacantEntry<'a, K, V>),
	/// A mutable reference to a position within the map where there is currently a value.
	Occupied(OccupiedEntry<'a, K, V>),
}

impl<'a, K: Ord, V> VacantEntry<'a, K, V> {
	/// Insert a value into the position described by this entry.
	pub fn insert(self, value: V) -> &'a mut V {
		self.underlying_entry.insert(value)
	}
}

impl<'a, K: Ord, V> OccupiedEntry<'a, K, V> {
	/// Remove the value at the position described by this entry.
	pub fn remove_entry(self) -> (K, V) {
		self.underlying_entry.remove_entry()
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
