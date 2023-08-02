//! Objects related to [`SqliteStore`] live here.
use crate::utils::check_namespace_key_validity;

use lightning::util::persist::KVStore;
use lightning::util::string::PrintableString;
use lightning::io;

use rusqlite::{named_params, Connection};

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The default database file name.
pub const DEFAULT_SQLITE_DB_FILE_NAME: &str = "ldk_data.sqlite";

/// The default table in which we store all data.
pub const DEFAULT_KV_TABLE_NAME: &str = "ldk_data";

// The current SQLite `user_version`, which we can use if we'd ever need to do a schema migration.
const SCHEMA_USER_VERSION: u16 = 2;

/// A [`KVStore`] implementation that writes to and reads from an [SQLite] database.
///
/// [SQLite]: https://sqlite.org
pub struct SqliteStore {
	connection: Arc<Mutex<Connection>>,
	data_dir: PathBuf,
	kv_table_name: String,
}

impl SqliteStore {
	/// Constructs a new [`SqliteStore`].
	///
	/// If not already existing, a new SQLite database will be created in the given `data_dir` under the
	/// given `db_file_name` (or the default to [`DEFAULT_SQLITE_DB_FILE_NAME`] if set to `None`).
	///
	/// Similarly, the given `kv_table_name` will be used or default to [`DEFAULT_KV_TABLE_NAME`].
	pub fn new(data_dir: PathBuf, db_file_name: Option<String>, kv_table_name: Option<String>) -> io::Result<Self> {
		let db_file_name = db_file_name.unwrap_or(DEFAULT_SQLITE_DB_FILE_NAME.to_string());
		let kv_table_name = kv_table_name.unwrap_or(DEFAULT_KV_TABLE_NAME.to_string());

		fs::create_dir_all(data_dir.clone()).map_err(|e| {
			let msg = format!("Failed to create database destination directory {}: {}",
				data_dir.display(), e);
			io::Error::new(io::ErrorKind::Other, msg)
		})?;
		let mut db_file_path = data_dir.clone();
		db_file_path.push(db_file_name);

		let connection = Connection::open(db_file_path.clone()).map_err(|e| {
			let msg = format!("Failed to open/create database file {}: {}",
				db_file_path.display(), e);
			io::Error::new(io::ErrorKind::Other, msg)
		})?;

		connection.pragma(Some(rusqlite::DatabaseName::Main),
			"user_version", SCHEMA_USER_VERSION, |_| {
				Ok(())
			}).map_err(|e| {
				let msg = format!("Failed to set PRAGMA user_version: {}", e);
				io::Error::new(io::ErrorKind::Other, msg)
			})?;

		let sql = format!(
			"CREATE TABLE IF NOT EXISTS {} (
			namespace TEXT NOT NULL,
			sub_namespace TEXT DEFAULT \"\" NOT NULL,
			key TEXT NOT NULL CHECK (key <> ''),
			value BLOB, PRIMARY KEY ( namespace, sub_namespace, key )
			);",
			kv_table_name
		);

		connection.execute(&sql, []).map_err(|e| {
			let msg = format!("Failed to create table {}: {}", kv_table_name, e);
			io::Error::new(io::ErrorKind::Other, msg)
		})?;

		let connection = Arc::new(Mutex::new(connection));
		Ok(Self { connection, data_dir, kv_table_name })
	}

	/// Returns the data directory.
	pub fn get_data_dir(&self) -> PathBuf {
		self.data_dir.clone()
	}
}

impl KVStore for SqliteStore {
	fn read(&self, namespace: &str, sub_namespace: &str, key: &str) -> std::io::Result<Vec<u8>> {
		check_namespace_key_validity(namespace, sub_namespace, Some(key), "read")?;

		let locked_conn = self.connection.lock().unwrap();
		let sql =
			format!("SELECT value FROM {} WHERE namespace=:namespace AND sub_namespace=:sub_namespace AND key=:key;",
			self.kv_table_name);

		let mut stmt = locked_conn.prepare_cached(&sql).map_err(|e| {
			let msg = format!("Failed to prepare statement: {}", e);
			std::io::Error::new(std::io::ErrorKind::Other, msg)
		})?;

		let res = stmt
			.query_row(
				named_params! {
					":namespace": namespace,
					":sub_namespace": sub_namespace,
					":key": key,
				},
				|row| row.get(0),
			)
			.map_err(|e| match e {
				rusqlite::Error::QueryReturnedNoRows => {
					let msg =
						format!("Failed to read as key could not be found: {}/{}/{}",
						PrintableString(namespace), PrintableString(sub_namespace), PrintableString(key));
					std::io::Error::new(std::io::ErrorKind::NotFound, msg)
				}
				e => {
					let msg = format!("Failed to read from key {}/{}/{}: {}",
						PrintableString(namespace), PrintableString(sub_namespace),
						PrintableString(key), e);
					std::io::Error::new(std::io::ErrorKind::Other, msg)
				}
			})?;
		Ok(res)
	}

	fn write(&self, namespace: &str, sub_namespace: &str, key: &str, buf: &[u8]) -> std::io::Result<()> {
		check_namespace_key_validity(namespace, sub_namespace, Some(key), "write")?;

		let locked_conn = self.connection.lock().unwrap();

		let sql = format!(
			"INSERT OR REPLACE INTO {} (namespace, sub_namespace, key, value) VALUES (:namespace, :sub_namespace, :key, :value);",
			self.kv_table_name
		);

		let mut stmt = locked_conn.prepare_cached(&sql).map_err(|e| {
			let msg = format!("Failed to prepare statement: {}", e);
			std::io::Error::new(std::io::ErrorKind::Other, msg)
		})?;

		stmt.execute(
			named_params! {
				":namespace": namespace,
				":sub_namespace": sub_namespace,
				":key": key,
				":value": buf,
			},
			)
			.map(|_| ())
			.map_err(|e| {
				let msg = format!("Failed to write to key {}/{}/{}: {}",
					PrintableString(namespace), PrintableString(sub_namespace),
					PrintableString(key), e);
				std::io::Error::new(std::io::ErrorKind::Other, msg)
			})
	}

	fn remove(&self, namespace: &str, sub_namespace: &str, key: &str, _lazy: bool) -> std::io::Result<()> {
		check_namespace_key_validity(namespace, sub_namespace, Some(key), "remove")?;

		let locked_conn = self.connection.lock().unwrap();

		let sql = format!("DELETE FROM {} WHERE namespace=:namespace AND sub_namespace=:sub_namespace AND key=:key;", self.kv_table_name);

		let mut stmt = locked_conn.prepare_cached(&sql).map_err(|e| {
			let msg = format!("Failed to prepare statement: {}", e);
			std::io::Error::new(std::io::ErrorKind::Other, msg)
		})?;

		stmt.execute(
			named_params! {
				":namespace": namespace,
				":sub_namespace": sub_namespace,
				":key": key,
			},
			)
			.map_err(|e| {
				let msg = format!("Failed to delete key {}/{}/{}: {}",
					PrintableString(namespace), PrintableString(sub_namespace),
					PrintableString(key), e);
				std::io::Error::new(std::io::ErrorKind::Other, msg)
			})?;
		Ok(())
	}

	fn list(&self, namespace: &str, sub_namespace: &str) -> std::io::Result<Vec<String>> {
		check_namespace_key_validity(namespace, sub_namespace, None, "list")?;

		let locked_conn = self.connection.lock().unwrap();

		let sql = format!("SELECT key FROM {} WHERE namespace=:namespace AND sub_namespace=:sub_namespace", self.kv_table_name);
		let mut stmt = locked_conn.prepare_cached(&sql).map_err(|e| {
			let msg = format!("Failed to prepare statement: {}", e);
			std::io::Error::new(std::io::ErrorKind::Other, msg)
		})?;

		let mut keys = Vec::new();

		let rows_iter = stmt
			.query_map(
				named_params! {
					":namespace": namespace,
					":sub_namespace": sub_namespace,
			}, |row| row.get(0))
			.map_err(|e| {
				let msg = format!("Failed to retrieve queried rows: {}", e);
				std::io::Error::new(std::io::ErrorKind::Other, msg)
			})?;

		for k in rows_iter {
			keys.push(k.map_err(|e| {
				let msg = format!("Failed to retrieve queried rows: {}", e);
				std::io::Error::new(std::io::ErrorKind::Other, msg)
			})?);
		}

		Ok(keys)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_utils::{do_read_write_remove_list_persist,do_test_store};

	impl Drop for SqliteStore {
		fn drop(&mut self) {
			match fs::remove_dir_all(&self.data_dir) {
				Err(e) => println!("Failed to remove test store directory: {}", e),
				_ => {}
			}
		}
	}

	#[test]
	fn read_write_remove_list_persist() {
		let mut temp_path = std::env::temp_dir();
		temp_path.push("read_write_remove_list_persist");
		let store = SqliteStore::new(temp_path, Some("test_db".to_string()), Some("test_table".to_string())).unwrap();
		do_read_write_remove_list_persist(&store);
	}

	#[test]
	fn test_sqlite_store() {
		let mut temp_path = std::env::temp_dir();
		temp_path.push("test_sqlite_store");
		let store_0 = SqliteStore::new(temp_path.clone(), Some("test_db_0".to_string()), Some("test_table".to_string())).unwrap();
		let store_1 = SqliteStore::new(temp_path, Some("test_db_1".to_string()), Some("test_table".to_string())).unwrap();
		do_test_store(&store_0, &store_1)
	}
}

#[cfg(ldk_bench)]
/// Benches
pub mod bench {
	use criterion::Criterion;

	/// Bench!
	pub fn bench_sends(bench: &mut Criterion) {
		let store_a = super::SqliteStore::new("bench_sqlite_store_a".into(), None, None).unwrap();
		let store_b = super::SqliteStore::new("bench_sqlite_store_b".into(), None, None).unwrap();
		lightning::ln::channelmanager::bench::bench_two_sends(
			bench, "bench_sqlite_persisted_sends", store_a, store_b);
	}
}
