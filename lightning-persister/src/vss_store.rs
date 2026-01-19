// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Objects related to [`VssStore`] live here.

use std::boxed::Box;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
#[cfg(test)]
use std::panic::RefUnwindSafe;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::key::Secp256k1;
use lightning::impl_writeable_tlv_based_enum;
use lightning::io::{self, Error, ErrorKind};
use lightning::util::persist::{KVStore, KVStoreSync};
use lightning::util::ser::{Readable, Writeable};
use rand::RngCore;
use vss_client::client::VssClient;
use vss_client::error::VssError;
use vss_client::headers::{FixedHeaders, LnurlAuthToJwtProvider, VssHeaderProvider};
use vss_client::prost::Message;
use vss_client::types::{
	DeleteObjectRequest, GetObjectRequest, KeyValue, ListKeyVersionsRequest, PutObjectRequest,
	Storable,
};
use vss_client::util::key_obfuscator::KeyObfuscator;
use vss_client::util::retry::{
	ExponentialBackoffRetryPolicy, FilteredRetryPolicy, JitteredRetryPolicy,
	MaxAttemptsRetryPolicy, MaxTotalDelayRetryPolicy, RetryPolicy,
};
use vss_client::util::storable_builder::{EntropySource, StorableBuilder};

use crate::utils::check_namespace_key_validity;

type CustomRetryPolicy = FilteredRetryPolicy<
	JitteredRetryPolicy<
		MaxTotalDelayRetryPolicy<MaxAttemptsRetryPolicy<ExponentialBackoffRetryPolicy<VssError>>>,
	>,
	Box<dyn Fn(&VssError) -> bool + 'static + Send + Sync>,
>;

#[derive(Debug, PartialEq)]
enum VssSchemaVersion {
	// The initial schema version.
	// This used an empty `aad` and unobfuscated `primary_namespace`/`secondary_namespace`s in the
	// stored key.
	V0,
	// The second deployed schema version.
	// Here we started to obfuscate the primary and secondary namespaces and the obfuscated `store_key` (`obfuscate(primary_namespace#secondary_namespace)#obfuscate(key)`) is now used as `aad` for encryption, ensuring that the encrypted blobs commit to the key they're stored under.
	V1,
}

impl_writeable_tlv_based_enum!(VssSchemaVersion,
	(0, V0) => {},
	(1, V1) => {},
);

const VSS_LNURL_AUTH_HARDENED_CHILD_INDEX: u32 = 138;
const VSS_SCHEMA_VERSION_KEY: &str = "vss_schema_version";

// We set this to a small number of threads that would still allow to make some progress if one
// would hit a blocking case
const INTERNAL_RUNTIME_WORKERS: usize = 2;

/// A [`KVStore`]/[`KVStoreSync`] implementation that writes to and reads from a [VSS] backend.
///
/// [VSS]: https://github.com/lightningdevkit/vss-server/blob/main/README.md
pub struct VssStore {
	inner: Arc<VssStoreInner>,
	// Version counter to ensure that writes are applied in the correct order. It is assumed that read and list
	// operations aren't sensitive to the order of execution.
	next_version: AtomicU64,
	// A VSS-internal runtime we use to avoid any deadlocks we could hit when waiting on a spawned
	// blocking task to finish while the blocked thread had acquired the reactor. In particular,
	// this works around a previously-hit case where a concurrent call to
	// `PeerManager::process_pending_events` -> `ChannelManager::get_and_clear_pending_msg_events`
	// would deadlock when trying to acquire sync `Mutex` locks that are held by the thread
	// currently being blocked waiting on the VSS operation to finish.
	internal_runtime: Option<tokio::runtime::Runtime>,
}

impl VssStore {
	pub(crate) fn new(
		base_url: String, store_id: String, vss_seed: [u8; 32],
		header_provider: Arc<dyn VssHeaderProvider>,
	) -> io::Result<Self> {
		let next_version = AtomicU64::new(1);
		let internal_runtime = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.thread_name_fn(|| {
				static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
				let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
				format!("ldk-node-vss-runtime-{}", id)
			})
			.worker_threads(INTERNAL_RUNTIME_WORKERS)
			.max_blocking_threads(INTERNAL_RUNTIME_WORKERS)
			.build()
			.unwrap();

		let (data_encryption_key, obfuscation_master_key) =
			derive_data_encryption_and_obfuscation_keys(&vss_seed);
		let key_obfuscator = KeyObfuscator::new(obfuscation_master_key);

		let sync_retry_policy = retry_policy();
		let blocking_client = VssClient::new_with_headers(
			base_url.clone(),
			sync_retry_policy,
			header_provider.clone(),
		);

		let runtime_handle = internal_runtime.handle();
		let schema_version = tokio::task::block_in_place(|| {
			runtime_handle.block_on(async {
				determine_and_write_schema_version(
					&blocking_client,
					&store_id,
					data_encryption_key,
					&key_obfuscator,
				)
				.await
			})
		})?;

		let async_retry_policy = retry_policy();
		let async_client =
			VssClient::new_with_headers(base_url, async_retry_policy, header_provider);

		let inner = Arc::new(VssStoreInner::new(
			schema_version,
			blocking_client,
			async_client,
			store_id,
			data_encryption_key,
			key_obfuscator,
		));

		Ok(Self { inner, next_version, internal_runtime: Some(internal_runtime) })
	}
	/// Returns a [`VssStoreBuilder`] allowing to build a [`VssStore`].
	pub fn builder(vss_xprv: Xpriv, vss_url: String, store_id: String) -> VssStoreBuilder {
		VssStoreBuilder::new(vss_xprv, vss_url, store_id)
	}

	// Same logic as for the obfuscated keys below, but just for locking, using the plaintext keys
	fn build_locking_key(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> String {
		if primary_namespace.is_empty() {
			key.to_owned()
		} else {
			format!("{}#{}#{}", primary_namespace, secondary_namespace, key)
		}
	}

	fn get_new_version_and_lock_ref(
		&self, locking_key: String,
	) -> (Arc<tokio::sync::Mutex<u64>>, u64) {
		let version = self.next_version.fetch_add(1, Ordering::Relaxed);
		if version == u64::MAX {
			panic!("VssStore version counter overflowed");
		}

		// Get a reference to the inner lock. We do this early so that the arc can double as an in-flight counter for
		// cleaning up unused locks.
		let inner_lock_ref = self.inner.get_inner_lock_ref(locking_key);

		(inner_lock_ref, version)
	}
}

impl KVStoreSync for VssStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> io::Result<Vec<u8>> {
		let internal_runtime = self.internal_runtime.as_ref().ok_or_else(|| {
			debug_assert!(false, "Failed to access internal runtime");
			let msg = format!("Failed to access internal runtime");
			Error::new(ErrorKind::Other, msg)
		})?;
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key = key.to_string();
		let inner = Arc::clone(&self.inner);
		let fut = async move {
			inner
				.read_internal(&inner.blocking_client, primary_namespace, secondary_namespace, key)
				.await
		};
		tokio::task::block_in_place(move || internal_runtime.block_on(fut))
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> io::Result<()> {
		let internal_runtime = self.internal_runtime.as_ref().ok_or_else(|| {
			debug_assert!(false, "Failed to access internal runtime");
			let msg = format!("Failed to access internal runtime");
			Error::new(ErrorKind::Other, msg)
		})?;
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key = key.to_string();
		let inner = Arc::clone(&self.inner);
		let locking_key = self.build_locking_key(&primary_namespace, &secondary_namespace, &key);
		let (inner_lock_ref, version) = self.get_new_version_and_lock_ref(locking_key.clone());
		let fut = async move {
			inner
				.write_internal(
					&inner.blocking_client,
					inner_lock_ref,
					locking_key,
					version,
					primary_namespace,
					secondary_namespace,
					key,
					buf,
				)
				.await
		};
		tokio::task::block_in_place(move || internal_runtime.block_on(fut))
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> io::Result<()> {
		let internal_runtime = self.internal_runtime.as_ref().ok_or_else(|| {
			debug_assert!(false, "Failed to access internal runtime");
			let msg = format!("Failed to access internal runtime");
			Error::new(ErrorKind::Other, msg)
		})?;
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key = key.to_string();
		let inner = Arc::clone(&self.inner);
		let locking_key = self.build_locking_key(&primary_namespace, &secondary_namespace, &key);
		let (inner_lock_ref, version) = self.get_new_version_and_lock_ref(locking_key.clone());
		let fut = async move {
			inner
				.remove_internal(
					&inner.blocking_client,
					inner_lock_ref,
					locking_key,
					version,
					primary_namespace,
					secondary_namespace,
					key,
				)
				.await
		};
		if lazy {
			internal_runtime.spawn(async { fut.await });
			Ok(())
		} else {
			tokio::task::block_in_place(move || internal_runtime.block_on(fut))
		}
	}

	fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> io::Result<Vec<String>> {
		let internal_runtime = self.internal_runtime.as_ref().ok_or_else(|| {
			debug_assert!(false, "Failed to access internal runtime");
			let msg = format!("Failed to access internal runtime");
			Error::new(ErrorKind::Other, msg)
		})?;
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let inner = Arc::clone(&self.inner);
		let fut = async move {
			inner
				.list_internal(&inner.blocking_client, primary_namespace, secondary_namespace)
				.await
		};
		tokio::task::block_in_place(move || internal_runtime.block_on(fut))
	}
}

impl KVStore for VssStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> impl Future<Output = Result<Vec<u8>, io::Error>> + 'static + Send {
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key = key.to_string();
		let inner = Arc::clone(&self.inner);
		async move {
			inner
				.read_internal(&inner.async_client, primary_namespace, secondary_namespace, key)
				.await
		}
	}
	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> impl Future<Output = Result<(), io::Error>> + 'static + Send {
		let locking_key = self.build_locking_key(primary_namespace, secondary_namespace, key);
		let (inner_lock_ref, version) = self.get_new_version_and_lock_ref(locking_key.clone());
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key = key.to_string();
		let inner = Arc::clone(&self.inner);
		async move {
			inner
				.write_internal(
					&inner.async_client,
					inner_lock_ref,
					locking_key,
					version,
					primary_namespace,
					secondary_namespace,
					key,
					buf,
				)
				.await
		}
	}
	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> impl Future<Output = Result<(), io::Error>> + 'static + Send {
		let locking_key = self.build_locking_key(primary_namespace, secondary_namespace, key);
		let (inner_lock_ref, version) = self.get_new_version_and_lock_ref(locking_key.clone());
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let key = key.to_string();
		let inner = Arc::clone(&self.inner);
		let fut = async move {
			inner
				.remove_internal(
					&inner.async_client,
					inner_lock_ref,
					locking_key,
					version,
					primary_namespace,
					secondary_namespace,
					key,
				)
				.await
		};
		async move {
			if lazy {
				tokio::task::spawn(async move { fut.await });
				Ok(())
			} else {
				fut.await
			}
		}
	}
	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> impl Future<Output = Result<Vec<String>, io::Error>> + 'static + Send {
		let primary_namespace = primary_namespace.to_string();
		let secondary_namespace = secondary_namespace.to_string();
		let inner = Arc::clone(&self.inner);
		async move {
			inner.list_internal(&inner.async_client, primary_namespace, secondary_namespace).await
		}
	}
}

impl Drop for VssStore {
	fn drop(&mut self) {
		let internal_runtime = self.internal_runtime.take();
		tokio::task::block_in_place(move || drop(internal_runtime));
	}
}

struct VssStoreInner {
	schema_version: VssSchemaVersion,
	blocking_client: VssClient<CustomRetryPolicy>,
	// A secondary client that will only be used for async persistence via `KVStore`, to ensure TCP
	// connections aren't shared between our outer and the internal runtime.
	async_client: VssClient<CustomRetryPolicy>,
	store_id: String,
	data_encryption_key: [u8; 32],
	key_obfuscator: KeyObfuscator,
	// Per-key locks that ensures that we don't have concurrent writes to the same namespace/key.
	// The lock also encapsulates the latest written version per key.
	locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<u64>>>>,
}

impl VssStoreInner {
	pub(crate) fn new(
		schema_version: VssSchemaVersion, blocking_client: VssClient<CustomRetryPolicy>,
		async_client: VssClient<CustomRetryPolicy>, store_id: String,
		data_encryption_key: [u8; 32], key_obfuscator: KeyObfuscator,
	) -> Self {
		let locks = Mutex::new(HashMap::new());
		Self {
			schema_version,
			blocking_client,
			async_client,
			store_id,
			data_encryption_key,
			key_obfuscator,
			locks,
		}
	}

	fn get_inner_lock_ref(&self, locking_key: String) -> Arc<tokio::sync::Mutex<u64>> {
		let mut outer_lock = self.locks.lock().unwrap();
		Arc::clone(&outer_lock.entry(locking_key).or_default())
	}

	fn build_obfuscated_key(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> String {
		if self.schema_version == VssSchemaVersion::V1 {
			let obfuscated_prefix =
				self.build_obfuscated_prefix(primary_namespace, secondary_namespace);
			let obfuscated_key = self.key_obfuscator.obfuscate(key);
			format!("{}#{}", obfuscated_prefix, obfuscated_key)
		} else {
			// Default to V0 schema
			let obfuscated_key = self.key_obfuscator.obfuscate(key);
			if primary_namespace.is_empty() {
				obfuscated_key
			} else {
				format!("{}#{}#{}", primary_namespace, secondary_namespace, obfuscated_key)
			}
		}
	}

	fn build_obfuscated_prefix(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> String {
		if self.schema_version == VssSchemaVersion::V1 {
			let prefix = format!("{}#{}", primary_namespace, secondary_namespace);
			self.key_obfuscator.obfuscate(&prefix)
		} else {
			// Default to V0 schema
			format!("{}#{}", primary_namespace, secondary_namespace)
		}
	}

	fn extract_key(&self, unified_key: &str) -> io::Result<String> {
		let mut parts = if self.schema_version == VssSchemaVersion::V1 {
			let mut parts = unified_key.splitn(2, '#');
			let _obfuscated_namespace = parts.next();
			parts
		} else {
			// Default to V0 schema
			let mut parts = unified_key.splitn(3, '#');
			let (_primary_namespace, _secondary_namespace) = (parts.next(), parts.next());
			parts
		};
		match parts.next() {
			Some(obfuscated_key) => {
				let actual_key = self.key_obfuscator.deobfuscate(obfuscated_key)?;
				Ok(actual_key)
			},
			None => Err(Error::new(ErrorKind::InvalidData, "Invalid key format")),
		}
	}

	async fn list_all_keys(
		&self, client: &VssClient<CustomRetryPolicy>, primary_namespace: &str,
		secondary_namespace: &str,
	) -> io::Result<Vec<String>> {
		let mut page_token = None;
		let mut keys = vec![];
		let key_prefix = self.build_obfuscated_prefix(primary_namespace, secondary_namespace);
		while page_token != Some("".to_string()) {
			let request = ListKeyVersionsRequest {
				store_id: self.store_id.clone(),
				key_prefix: Some(key_prefix.clone()),
				page_token,
				page_size: None,
			};

			let response = client.list_key_versions(&request).await.map_err(|e| {
				let msg = format!(
					"Failed to list keys in {}/{}: {}",
					primary_namespace, secondary_namespace, e
				);
				Error::new(ErrorKind::Other, msg)
			})?;

			for kv in response.key_versions {
				keys.push(self.extract_key(&kv.key)?);
			}
			page_token = response.next_page_token;
		}
		Ok(keys)
	}

	async fn read_internal(
		&self, client: &VssClient<CustomRetryPolicy>, primary_namespace: String,
		secondary_namespace: String, key: String,
	) -> io::Result<Vec<u8>> {
		check_namespace_key_validity(&primary_namespace, &secondary_namespace, Some(&key), "read")?;

		let store_key = self.build_obfuscated_key(&primary_namespace, &secondary_namespace, &key);
		let request = GetObjectRequest { store_id: self.store_id.clone(), key: store_key.clone() };
		let resp = client.get_object(&request).await.map_err(|e| {
			let msg = format!(
				"Failed to read from key {}/{}/{}: {}",
				primary_namespace, secondary_namespace, key, e
			);
			match e {
				VssError::NoSuchKeyError(..) => Error::new(ErrorKind::NotFound, msg),
				_ => Error::new(ErrorKind::Other, msg),
			}
		})?;

		// unwrap safety: resp.value must be always present for a non-erroneous VSS response, otherwise
		// it is an API-violation which is converted to [`VssError::InternalServerError`] in [`VssClient`]
		let storable = Storable::decode(&resp.value.unwrap().value[..]).map_err(|e| {
			let msg = format!(
				"Failed to decode data read from key {}/{}/{}: {}",
				primary_namespace, secondary_namespace, key, e
			);
			Error::new(ErrorKind::Other, msg)
		})?;

		let storable_builder = StorableBuilder::new(RandEntropySource);
		let aad =
			if self.schema_version == VssSchemaVersion::V1 { store_key.as_bytes() } else { &[] };
		let decrypted = storable_builder.deconstruct(storable, &self.data_encryption_key, aad)?.0;
		Ok(decrypted)
	}

	async fn write_internal(
		&self, client: &VssClient<CustomRetryPolicy>, inner_lock_ref: Arc<tokio::sync::Mutex<u64>>,
		locking_key: String, version: u64, primary_namespace: String, secondary_namespace: String,
		key: String, buf: Vec<u8>,
	) -> io::Result<()> {
		check_namespace_key_validity(
			&primary_namespace,
			&secondary_namespace,
			Some(&key),
			"write",
		)?;

		let store_key = self.build_obfuscated_key(&primary_namespace, &secondary_namespace, &key);
		let vss_version = -1;
		let storable_builder = StorableBuilder::new(RandEntropySource);
		let aad =
			if self.schema_version == VssSchemaVersion::V1 { store_key.as_bytes() } else { &[] };
		let storable =
			storable_builder.build(buf.to_vec(), vss_version, &self.data_encryption_key, aad);
		let request = PutObjectRequest {
			store_id: self.store_id.clone(),
			global_version: None,
			transaction_items: vec![KeyValue {
				key: store_key,
				version: vss_version,
				value: storable.encode_to_vec(),
			}],
			delete_items: vec![],
		};

		self.execute_locked_write(inner_lock_ref, locking_key, version, async move || {
			client.put_object(&request).await.map_err(|e| {
				let msg = format!(
					"Failed to write to key {}/{}/{}: {}",
					primary_namespace, secondary_namespace, key, e
				);
				Error::new(ErrorKind::Other, msg)
			})?;

			Ok(())
		})
		.await
	}

	async fn remove_internal(
		&self, client: &VssClient<CustomRetryPolicy>, inner_lock_ref: Arc<tokio::sync::Mutex<u64>>,
		locking_key: String, version: u64, primary_namespace: String, secondary_namespace: String,
		key: String,
	) -> io::Result<()> {
		check_namespace_key_validity(
			&primary_namespace,
			&secondary_namespace,
			Some(&key),
			"remove",
		)?;

		let obfuscated_key =
			self.build_obfuscated_key(&primary_namespace, &secondary_namespace, &key);

		let key_value = KeyValue { key: obfuscated_key, version: -1, value: vec![] };
		self.execute_locked_write(inner_lock_ref, locking_key, version, async move || {
			let request =
				DeleteObjectRequest { store_id: self.store_id.clone(), key_value: Some(key_value) };

			client.delete_object(&request).await.map_err(|e| {
				let msg = format!(
					"Failed to delete key {}/{}/{}: {}",
					primary_namespace, secondary_namespace, key, e
				);
				Error::new(ErrorKind::Other, msg)
			})?;

			Ok(())
		})
		.await
	}

	async fn list_internal(
		&self, client: &VssClient<CustomRetryPolicy>, primary_namespace: String,
		secondary_namespace: String,
	) -> io::Result<Vec<String>> {
		check_namespace_key_validity(&primary_namespace, &secondary_namespace, None, "list")?;

		let keys = self
			.list_all_keys(client, &primary_namespace, &secondary_namespace)
			.await
			.map_err(|e| {
				let msg = format!(
					"Failed to retrieve keys in namespace: {}/{} : {}",
					primary_namespace, secondary_namespace, e
				);
				Error::new(ErrorKind::Other, msg)
			})?;

		Ok(keys)
	}

	async fn execute_locked_write<
		F: Future<Output = Result<(), lightning::io::Error>>,
		FN: FnOnce() -> F,
	>(
		&self, inner_lock_ref: Arc<tokio::sync::Mutex<u64>>, locking_key: String, version: u64,
		callback: FN,
	) -> Result<(), lightning::io::Error> {
		let res = {
			let mut last_written_version = inner_lock_ref.lock().await;

			// Check if we already have a newer version written/removed. This is used in async contexts to realize eventual
			// consistency.
			let is_stale_version = version <= *last_written_version;

			// If the version is not stale, we execute the callback. Otherwise we can and must skip writing.
			if is_stale_version {
				Ok(())
			} else {
				callback().await.map(|_| {
					*last_written_version = version;
				})
			}
		};

		self.clean_locks(&inner_lock_ref, locking_key);

		res
	}

	fn clean_locks(&self, inner_lock_ref: &Arc<tokio::sync::Mutex<u64>>, locking_key: String) {
		// If there no arcs in use elsewhere, this means that there are no in-flight writes. We can remove the map entry
		// to prevent leaking memory. The two arcs that are expected are the one in the map and the one held here in
		// inner_lock_ref. The outer lock is obtained first, to avoid a new arc being cloned after we've already
		// counted.
		let mut outer_lock = self.locks.lock().unwrap();

		let strong_count = Arc::strong_count(&inner_lock_ref);
		debug_assert!(strong_count >= 2, "Unexpected VssStore strong count");

		if strong_count == 2 {
			outer_lock.remove(&locking_key);
		}
	}
}

fn derive_data_encryption_and_obfuscation_keys(vss_seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
	let hkdf = |initial_key_material: &[u8], salt: &[u8]| -> [u8; 32] {
		let mut engine = HmacEngine::<sha256::Hash>::new(salt);
		engine.input(initial_key_material);
		Hmac::from_engine(engine).to_byte_array()
	};

	let prk = hkdf(vss_seed, b"pseudo_random_key");
	let k1 = hkdf(&prk, b"data_encryption_key");
	let k2 = hkdf(&prk, &[&k1[..], b"obfuscation_key"].concat());
	(k1, k2)
}

fn retry_policy() -> CustomRetryPolicy {
	ExponentialBackoffRetryPolicy::new(Duration::from_millis(10))
		.with_max_attempts(100)
		.with_max_total_delay(Duration::from_secs(180))
		.with_max_jitter(Duration::from_millis(100))
		.skip_retry_on_error(Box::new(|e: &VssError| {
			matches!(
				e,
				VssError::NoSuchKeyError(..)
					| VssError::InvalidRequestError(..)
					| VssError::ConflictError(..)
			)
		}) as _)
}

async fn determine_and_write_schema_version(
	client: &VssClient<CustomRetryPolicy>, store_id: &String, data_encryption_key: [u8; 32],
	key_obfuscator: &KeyObfuscator,
) -> io::Result<VssSchemaVersion> {
	// Build the obfuscated `vss_schema_version` key.
	let obfuscated_prefix = key_obfuscator.obfuscate(&format! {"{}#{}", "", ""});
	let obfuscated_key = key_obfuscator.obfuscate(VSS_SCHEMA_VERSION_KEY);
	let store_key = format!("{}#{}", obfuscated_prefix, obfuscated_key);

	// Try to read the stored schema version.
	let request = GetObjectRequest { store_id: store_id.clone(), key: store_key.clone() };
	let resp = match client.get_object(&request).await {
		Ok(resp) => Some(resp),
		Err(VssError::NoSuchKeyError(..)) => {
			// The value is not set.
			None
		},
		Err(e) => {
			let msg = format!("Failed to read schema version: {}", e);
			return Err(Error::new(ErrorKind::Other, msg));
		},
	};

	if let Some(resp) = resp {
		// The schema version was present, so just decrypt the stored data.

		// unwrap safety: resp.value must be always present for a non-erroneous VSS response, otherwise
		// it is an API-violation which is converted to [`VssError::InternalServerError`] in [`VssClient`]
		let storable = Storable::decode(&resp.value.unwrap().value[..]).map_err(|e| {
			let msg = format!("Failed to decode schema version: {}", e);
			Error::new(ErrorKind::Other, msg)
		})?;

		let storable_builder = StorableBuilder::new(RandEntropySource);
		// Schema version was added starting with V1, so if set at all, we use the key as `aad`
		let aad = store_key.as_bytes();
		let decrypted = storable_builder
			.deconstruct(storable, &data_encryption_key, aad)
			.map_err(|e| {
				let msg = format!("Failed to decode schema version: {}", e);
				Error::new(ErrorKind::Other, msg)
			})?
			.0;

		let schema_version: VssSchemaVersion = Readable::read(&mut &*decrypted).map_err(|e| {
			let msg = format!("Failed to decode schema version: {}", e);
			Error::new(ErrorKind::Other, msg)
		})?;
		Ok(schema_version)
	} else {
		// The schema version wasn't present, this either means we're running for the first time *or* it's V0 pre-migration (predating writing of the schema version).

		// Check if any `bdk_wallet` data was written by listing keys under the respective
		// (unobfuscated) prefix.
		const V0_BDK_WALLET_PREFIX: &str = "bdk_wallet#";
		let request = ListKeyVersionsRequest {
			store_id: store_id.clone(),
			key_prefix: Some(V0_BDK_WALLET_PREFIX.to_string()),
			page_token: None,
			page_size: None,
		};

		let response = client.list_key_versions(&request).await.map_err(|e| {
			let msg = format!("Failed to determine schema version: {}", e);
			Error::new(ErrorKind::Other, msg)
		})?;

		let wallet_data_present = !response.key_versions.is_empty();
		if wallet_data_present {
			// If the wallet data is present, it means we're not running for the first time.
			Ok(VssSchemaVersion::V0)
		} else {
			// We're running for the first time, write the schema version to save unnecessary IOps
			// on future startup.
			let schema_version = VssSchemaVersion::V1;
			let encoded_version = schema_version.encode();

			let storable_builder = StorableBuilder::new(RandEntropySource);
			let vss_version = -1;
			let aad = store_key.as_bytes();
			let storable =
				storable_builder.build(encoded_version, vss_version, &data_encryption_key, aad);

			let request = PutObjectRequest {
				store_id: store_id.clone(),
				global_version: None,
				transaction_items: vec![KeyValue {
					key: store_key,
					version: vss_version,
					value: storable.encode_to_vec(),
				}],
				delete_items: vec![],
			};

			client.put_object(&request).await.map_err(|e| {
				let msg = format!("Failed to write schema version: {}", e);
				Error::new(ErrorKind::Other, msg)
			})?;

			Ok(schema_version)
		}
	}
}

/// A source for generating entropy/randomness using [`rand`].
pub(crate) struct RandEntropySource;

impl EntropySource for RandEntropySource {
	fn fill_bytes(&self, buffer: &mut [u8]) {
		rand::rng().fill_bytes(buffer);
	}
}

#[cfg(test)]
impl RefUnwindSafe for VssStore {}

/// An error that could arise during [`VssStore`] building.
#[derive(Debug, Clone, PartialEq)]
pub enum VssStoreBuildError {
	/// Key derivation failed
	KeyDerivationFailed,
	/// Authentication provider setup failed
	AuthProviderSetupFailed,
	/// Store setup failed
	StoreSetupFailed,
}

impl fmt::Display for VssStoreBuildError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Self::KeyDerivationFailed => write!(f, "Key derivation failed"),
			Self::AuthProviderSetupFailed => write!(f, "Authentication provider setup failed"),
			Self::StoreSetupFailed => write!(f, "Store setup failed"),
		}
	}
}

impl std::error::Error for VssStoreBuildError {}

/// A builder for a [`VssStore`] instance.
pub struct VssStoreBuilder {
	vss_xprv: Xpriv,
	vss_url: String,
	store_id: String,
}

impl VssStoreBuilder {
	/// Create a new [`VssStoreBuilder`].
	pub fn new(vss_xprv: Xpriv, vss_url: String, store_id: String) -> Self {
		Self { vss_xprv, vss_url, store_id }
	}

	/// Builds a [`VssStore`] with [LNURL-auth] based authentication scheme as default method for
	/// authentication/authorization.
	///
	/// The LNURL challenge will be retrieved by making a request to the given
	/// `lnurl_auth_server_url`. The returned JWT token in response to the signed LNURL request,
	/// will be used for authentication/authorization of all the requests made to VSS.
	///
	/// `fixed_headers` are included as it is in all the requests made to VSS and LNURL auth
	/// server.
	///
	/// **Caution**: VSS support is in **alpha** and is considered experimental. Using VSS (or any
	/// remote persistence) may cause LDK to panic if persistence failures are unrecoverable, i.e.,
	/// if they remain unresolved after internal retries are exhausted.
	///
	/// [VSS]: https://github.com/lightningdevkit/vss-server/blob/main/README.md
	/// [LNURL-auth]: https://github.com/lnurl/luds/blob/luds/04.md
	pub fn build(
		&self, lnurl_auth_server_url: String, fixed_headers: HashMap<String, String>,
	) -> Result<VssStore, VssStoreBuildError> {
		let secp_ctx = Secp256k1::new();
		let lnurl_auth_xprv = self
			.vss_xprv
			.derive_priv(
				&secp_ctx,
				&[ChildNumber::Hardened { index: VSS_LNURL_AUTH_HARDENED_CHILD_INDEX }],
			)
			.map_err(|_| VssStoreBuildError::KeyDerivationFailed)?;

		let lnurl_auth_jwt_provider =
			LnurlAuthToJwtProvider::new(lnurl_auth_xprv, lnurl_auth_server_url, fixed_headers)
				.map_err(|_| VssStoreBuildError::AuthProviderSetupFailed)?;

		let header_provider = Arc::new(lnurl_auth_jwt_provider);

		self.build_with_header_provider(header_provider)
	}

	/// Builds a [`VssStore`] with [`FixedHeaders`] as default method for
	/// authentication/authorization.
	///
	/// Given `fixed_headers` are included as it is in all the requests made to VSS.
	///
	/// **Caution**: VSS support is in **alpha** and is considered experimental. Using VSS (or any
	/// remote persistence) may cause LDK to panic if persistence failures are unrecoverable, i.e.,
	/// if they remain unresolved after internal retries are exhausted.
	///
	/// [VSS]: https://github.com/lightningdevkit/vss-server/blob/main/README.md
	pub fn build_with_fixed_headers(
		&self, fixed_headers: HashMap<String, String>,
	) -> Result<VssStore, VssStoreBuildError> {
		let header_provider = Arc::new(FixedHeaders::new(fixed_headers));
		self.build_with_header_provider(header_provider)
	}

	/// Builds a [`VssStore`] with [`VssHeaderProvider`].
	///
	/// Any headers provided by `header_provider` will be attached to every request made to VSS.
	///
	/// **Caution**: VSS support is in **alpha** and is considered experimental.
	/// Using VSS (or any remote persistence) may cause LDK to panic if persistence failures are
	/// unrecoverable, i.e., if they remain unresolved after internal retries are exhausted.
	///
	/// [VSS]: https://github.com/lightningdevkit/vss-server/blob/main/README.md
	pub fn build_with_header_provider(
		&self, header_provider: Arc<dyn VssHeaderProvider>,
	) -> Result<VssStore, VssStoreBuildError> {
		let vss_seed_bytes: [u8; 32] = self.vss_xprv.private_key.secret_bytes();

		let vss_store = VssStore::new(
			self.vss_url.clone(),
			self.store_id.clone(),
			vss_seed_bytes,
			header_provider,
		)
		.map_err(|_| VssStoreBuildError::StoreSetupFailed)?;

		Ok(vss_store)
	}
}

#[cfg(test)]
#[cfg(vss_test)]
mod tests {
	use std::collections::HashMap;

	use rand::distr::Alphanumeric;
	use rand::{rng, Rng, RngCore};
	use vss_client::headers::FixedHeaders;

	use super::*;
	use crate::io::test_utils::do_read_write_remove_list_persist;

	#[test]
	fn vss_read_write_remove_list_persist() {
		let vss_base_url = std::env::var("TEST_VSS_BASE_URL").unwrap();
		let mut rng = rng();
		let rand_store_id: String = (0..7).map(|_| rng.sample(Alphanumeric) as char).collect();
		let mut vss_seed = [0u8; 32];
		rng.fill_bytes(&mut vss_seed);
		let header_provider = Arc::new(FixedHeaders::new(HashMap::new()));
		let vss_store =
			VssStore::new(vss_base_url, rand_store_id, vss_seed, header_provider).unwrap();
		do_read_write_remove_list_persist(&vss_store);
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
	async fn vss_read_write_remove_list_persist_in_runtime_context() {
		let vss_base_url = std::env::var("TEST_VSS_BASE_URL").unwrap();
		let mut rng = rng();
		let rand_store_id: String = (0..7).map(|_| rng.sample(Alphanumeric) as char).collect();
		let mut vss_seed = [0u8; 32];
		rng.fill_bytes(&mut vss_seed);
		let header_provider = Arc::new(FixedHeaders::new(HashMap::new()));
		let vss_store =
			VssStore::new(vss_base_url, rand_store_id, vss_seed, header_provider).unwrap();

		do_read_write_remove_list_persist(&vss_store);
		drop(vss_store)
	}
}
