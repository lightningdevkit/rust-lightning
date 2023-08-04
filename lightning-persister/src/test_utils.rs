use lightning::util::persist::{KVStore, KVSTORE_NAMESPACE_KEY_MAX_LEN};

use std::panic::RefUnwindSafe;

pub(crate) fn do_read_write_remove_list_persist<K: KVStore + RefUnwindSafe>(kv_store: &K) {
	let data = [42u8; 32];

	let namespace = "testspace";
	let sub_namespace = "testsubspace";
	let key = "testkey";

	// Test the basic KVStore operations.
	kv_store.write(namespace, sub_namespace, key, &data).unwrap();

	// Test empty namespace/sub_namespace is allowed, but not empty namespace and non-empty
	// sub-namespace, and not empty key.
	kv_store.write("", "", key, &data).unwrap();
	let res = std::panic::catch_unwind(|| kv_store.write("", sub_namespace, key, &data));
	assert!(res.is_err());
	let res = std::panic::catch_unwind(|| kv_store.write(namespace, sub_namespace, "", &data));
	assert!(res.is_err());

	let listed_keys = kv_store.list(namespace, sub_namespace).unwrap();
	assert_eq!(listed_keys.len(), 1);
	assert_eq!(listed_keys[0], key);

	let read_data = kv_store.read(namespace, sub_namespace, key).unwrap();
	assert_eq!(data, &*read_data);

	kv_store.remove(namespace, sub_namespace, key, false).unwrap();

	let listed_keys = kv_store.list(namespace, sub_namespace).unwrap();
	assert_eq!(listed_keys.len(), 0);

	// Ensure we have no issue operating with namespace/sub_namespace/key being KVSTORE_NAMESPACE_KEY_MAX_LEN
	let max_chars: String = std::iter::repeat('A').take(KVSTORE_NAMESPACE_KEY_MAX_LEN).collect();
	kv_store.write(&max_chars, &max_chars, &max_chars, &data).unwrap();

	let listed_keys = kv_store.list(&max_chars, &max_chars).unwrap();
	assert_eq!(listed_keys.len(), 1);
	assert_eq!(listed_keys[0], max_chars);

	let read_data = kv_store.read(&max_chars, &max_chars, &max_chars).unwrap();
	assert_eq!(data, &*read_data);

	kv_store.remove(&max_chars, &max_chars, &max_chars, false).unwrap();

	let listed_keys = kv_store.list(&max_chars, &max_chars).unwrap();
	assert_eq!(listed_keys.len(), 0);
}
