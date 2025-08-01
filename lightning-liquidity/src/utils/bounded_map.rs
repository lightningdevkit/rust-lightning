use crate::prelude::HashMap;
use alloc::collections::VecDeque;
use core::hash::Hash;
use lightning::util::hash_tables::hash_map_with_capacity;

/// Fixed size map with FIFO eviction.
pub(crate) struct BoundedMap<K, V> {
	map: HashMap<K, V>,
	order: VecDeque<K>,
	cap: usize,
}

impl<K, V> BoundedMap<K, V>
where
	K: Eq + Hash + Clone,
{
	/// Create a new map with the desired capacity.
	pub(crate) fn new(capacity: usize) -> Self {
		Self {
			map: hash_map_with_capacity(capacity),
			order: VecDeque::with_capacity(capacity),
			cap: capacity,
		}
	}

	/// Insert or update a key.  
	/// If we exceed `cap`, the oldest key is removed.
	pub(crate) fn insert(&mut self, key: K, value: V) {
		if self.map.contains_key(&key) {
			self.order.retain(|k| k != &key);
		}

		self.map.insert(key.clone(), value);
		self.order.push_back(key);

		if self.order.len() > self.cap {
			if let Some(oldest) = self.order.pop_front() {
				self.map.remove(&oldest);
			}
		}
		self.check_invariants();
	}

	/// Remove a key (if present) and return its value.
	pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
		let val = self.map.remove(key);
		if val.is_some() {
			self.order.retain(|k| k != key);
		}
		self.check_invariants();
		val
	}

	fn check_invariants(&self) {
		debug_assert!(self.map.len() <= self.cap);
		debug_assert!(self.order.len() <= self.cap);
		debug_assert!(self.map.len() == self.order.len());
	}

	/// Get a reference to the value associated with `key`.
	#[cfg(test)]
	pub(crate) fn get(&self, key: &K) -> Option<&V> {
		self.map.get(key)
	}

	/// Current number of entries.
	#[cfg(test)]
	pub(crate) fn len(&self) -> usize {
		self.map.len()
	}

	/// Check whether the map holds `key`.
	#[cfg(test)]
	pub(crate) fn contains_key(&self, key: &K) -> bool {
		self.map.contains_key(key)
	}

	/// Check whether the map is empty.
	pub(crate) fn is_empty(&self) -> bool {
		self.map.is_empty()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;
	use std::sync::{Arc, Mutex};
	use std::thread;

	#[test]
	fn new_empty() {
		let m: BoundedMap<&str, i32> = BoundedMap::new(3);
		assert_eq!(m.len(), 0);
		assert!(m.is_empty());
		assert!(m.get(&"key").is_none());
	}

	#[test]
	fn insert_within_capacity() {
		let mut m = BoundedMap::new(2);
		assert!(m.is_empty());
		m.insert("a", 1);
		m.insert("b", 2);

		assert!(!m.is_empty());
		assert_eq!(m.len(), 2);
		assert!(m.contains_key(&"a"));
		assert_eq!(m.get(&"a"), Some(&1));
		assert_eq!(m.get(&"b"), Some(&2));
	}

	#[test]
	fn is_empty() {
		let mut m: BoundedMap<&str, i32> = BoundedMap::new(3);
		assert!(m.is_empty());

		m.insert("a", 1);
		assert!(!m.is_empty());

		m.remove(&"a");
		assert!(m.is_empty());
	}

	#[test]
	fn eviction_fifo() {
		let mut m = BoundedMap::new(2);
		m.insert("first", 1);
		m.insert("second", 2);
		m.insert("third", 3); // evicts "first"

		assert_eq!(m.len(), 2);
		assert!(!m.is_empty());
		assert!(m.get(&"first").is_none());
		assert_eq!(m.get(&"second"), Some(&2));
		assert_eq!(m.get(&"third"), Some(&3));
	}

	#[test]
	fn update_moves_to_back() {
		let mut m = BoundedMap::new(2);
		m.insert("old", 1);
		m.insert("new", 2);
		m.insert("old", 10); // update moves "old" to back
		m.insert("newer", 3); // should evict "new", not "old"

		assert!(!m.is_empty());
		assert_eq!(m.get(&"old"), Some(&10));
		assert!(m.get(&"new").is_none());
		assert_eq!(m.get(&"newer"), Some(&3));
	}

	#[test]
	fn remove_existing() {
		let mut m = BoundedMap::new(2);
		m.insert("keep", 1);
		m.insert("remove", 2);
		assert!(!m.is_empty());

		assert_eq!(m.remove(&"remove"), Some(2));
		assert_eq!(m.len(), 1);
		assert!(!m.is_empty());
		assert!(m.get(&"remove").is_none());
		assert_eq!(m.get(&"keep"), Some(&1));

		m.remove(&"keep");
		assert!(m.is_empty());
	}

	#[test]
	fn remove_nonexistent() {
		let mut m = BoundedMap::new(2);
		m.insert("exists", 1);
		assert!(!m.is_empty());

		assert_eq!(m.remove(&"missing"), None);
		assert_eq!(m.len(), 1);
		assert!(!m.is_empty());
	}

	#[test]
	fn zero_capacity() {
		let mut m = BoundedMap::new(0);
		assert!(m.is_empty());
		m.insert("any", 42);

		assert_eq!(m.len(), 0);
		assert!(m.is_empty());
		assert!(m.get(&"any").is_none());
	}

	#[test]
	fn capacity_one() {
		let mut m = BoundedMap::new(1);
		assert!(m.is_empty());
		m.insert("first", 1);
		assert!(!m.is_empty());
		assert_eq!(m.get(&"first"), Some(&1));

		m.insert("second", 2);
		assert!(!m.is_empty());
		assert!(m.get(&"first").is_none());
		assert_eq!(m.get(&"second"), Some(&2));
	}

	proptest! {
		#[test]
		fn prop_bounded_map_never_exceeds_capacity(
			cap in 0usize..5,
			ops in proptest::collection::vec((any::<bool>(), any::<u8>(), any::<u8>()), 1..100)
		) {
			let mut m = BoundedMap::new(cap);
			for (do_insert, k, v) in ops {
				if do_insert {
					m.insert(k, v);
				} else {
					m.remove(&k);
				}
				prop_assert!(m.len() <= cap);
				prop_assert!(m.order.len() <= cap);
				prop_assert!(m.map.len() <= cap);
			}
		}

		#[test]
		fn prop_duplicate_insert_len_stable(
			cap in 1usize..5,
			key in any::<u8>(),
			v1 in any::<u8>(),
			v2 in any::<u8>()
		) {
			let mut m = BoundedMap::new(cap);
			m.insert(key, v1);
			let before = m.len();

			m.insert(key, v2);

			prop_assert_eq!(m.len(), before);
			prop_assert_eq!(m.get(&key), Some(&v2));
		}

		#[test]
		fn prop_remove_twice_is_safe(
			cap in 1usize..5,
			key in any::<u8>(),
			val in any::<u8>()
		) {
			let mut m = BoundedMap::new(cap);
			m.insert(key, val);

			let first = m.remove(&key);
			let second = m.remove(&key);

			prop_assert!(first.is_some());
			prop_assert_eq!(second, None);
		}

		#[test]
		fn prop_contains_agrees_with_get(
			cap in 0usize..5,
			ops in proptest::collection::vec((any::<bool>(), any::<u8>(), any::<u8>()), 1..50)
		) {
			let mut m = BoundedMap::new(cap);

			for (insert, k, v) in ops {
				if insert {
					m.insert(k, v);
				} else {
					m.remove(&k);
				}
				prop_assert_eq!(m.contains_key(&k), m.get(&k).is_some());
			}
		}
		#[test]
		fn prop_zero_capacity_always_empty(
			ops in proptest::collection::vec((any::<bool>(), any::<u8>(), any::<u8>()), 1..50)
		) {
			let mut m = BoundedMap::new(0);
			for (insert, k, v) in ops {
				if insert {
					m.insert(k, v);
				} else {
					m.remove(&k);
				}
				prop_assert_eq!(m.len(), 0);
				prop_assert!(m.is_empty());
			}
		}

		#[test]
		fn prop_fifo_eviction_holds(
			(first, second, third) in (any::<u8>(), any::<u8>(), any::<u8>())
			.prop_filter("keys must be distinct", |(a, b, c)| a != b && a != c && b != c)
		) {
			let mut m = BoundedMap::new(2);
			m.insert(first, 1);
			m.insert(second, 1);
			m.insert(third, 1);

			prop_assert!(!m.contains_key(&first));
			prop_assert!(m.contains_key(&second));
			prop_assert!(m.contains_key(&third));
		}

		#[test]
		fn prop_threaded_access_is_safe(
			cap in 1usize..4,
			thread_count in 2usize..6,
			ops in proptest::collection::vec((any::<bool>(), any::<u8>(), any::<u8>()), 20..200)
		) {
			let shared = Arc::new(Mutex::new(BoundedMap::new(cap)));

			let chunk_size = (ops.len() + thread_count - 1) / thread_count;
			let mut handles = Vec::new();

			for chunk in ops.chunks(chunk_size) {
				let map_clone = Arc::clone(&shared);
				let chunk = chunk.to_vec();
				handles.push(thread::spawn(move || {
					for (insert, k, v) in chunk {
						let mut m = map_clone.lock().unwrap();
						if insert {
							m.insert(k, v);
						} else {
							m.remove(&k);
						}
					}
				}));
			}

			for h in handles {
				h.join().unwrap();
			}

			let m = shared.lock().unwrap();
			prop_assert!(m.len() <= cap);
			prop_assert_eq!(m.len(), m.order.len());
		}
	}
}
