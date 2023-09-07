use rusqlite::Connection;

use lightning::io;

pub(super) fn migrate_schema(connection: &Connection, kv_table_name: &str, from_version: u16, to_version: u16) -> io::Result<()> {
	assert!(from_version < to_version);
	if from_version == 1 && to_version == 2 {
		let sql = format!(
			"ALTER TABLE {}
				ADD sub_namespace TEXT DEFAULT \"\" NOT NULL;",
				kv_table_name);
		connection .execute(&sql, []).map_err(|e| {
				let msg = format!("Failed to migrate table {} from user_version {} to {}: {}",
				kv_table_name, from_version, to_version, e);
				io::Error::new(io::ErrorKind::Other, msg)
			})?;

		connection.pragma(Some(rusqlite::DatabaseName::Main),
			"user_version", to_version, |_| {
				Ok(())
		}).map_err(|e| {
			let msg = format!("Failed to upgrade user_version from {} to {}: {}",
				from_version, to_version, e);
			io::Error::new(io::ErrorKind::Other, msg)
		})?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::sqlite_store::SqliteStore;
	use crate::test_utils::do_read_write_remove_list_persist;

	use lightning::util::persist::KVStore;

	use rusqlite::{named_params, Connection};

	use std::fs;

	#[test]
	fn rwrl_post_schema_1_migration() {
		let old_schema_version = 1;

		let mut temp_path = std::env::temp_dir();
		temp_path.push("rwrl_post_schema_1_migration");

		let db_file_name = "test_db".to_string();
		let kv_table_name = "test_table".to_string();

		let test_namespace = "testspace".to_string();
		let test_key = "testkey".to_string();
		let test_data = [42u8; 32];

		{
			// We create a database with a SCHEMA_VERSION 1 table
			fs::create_dir_all(temp_path.clone()).unwrap();
			let mut db_file_path = temp_path.clone();
			db_file_path.push(db_file_name.clone());

			let connection = Connection::open(db_file_path.clone()).unwrap();

			connection
				.pragma(Some(rusqlite::DatabaseName::Main), "user_version", old_schema_version, |_| {
					Ok(())
				}).unwrap();

			let sql = format!(
				"CREATE TABLE IF NOT EXISTS {} (
					namespace TEXT NOT NULL,
					key TEXT NOT NULL CHECK (key <> ''),
					value BLOB, PRIMARY KEY ( namespace, key )
					);",
					kv_table_name
					);

			connection.execute(&sql, []).unwrap();

			// We write some data to to the table
			let sql = format!(
				"INSERT OR REPLACE INTO {} (namespace, key, value) VALUES (:namespace, :key, :value);",
				kv_table_name
				);
			let mut stmt = connection.prepare_cached(&sql).unwrap();

			stmt.execute(
				named_params! {
					":namespace": test_namespace,
					":key": test_key,
					":value": test_data,
				}).unwrap();

			// We read the just written data back to assert it happened.
			let sql = format!("SELECT value FROM {} WHERE namespace=:namespace AND key=:key;",
				kv_table_name);
			let mut stmt = connection.prepare_cached(&sql).unwrap();

			let res: Vec<u8> = stmt
				.query_row(
					named_params! {
						":namespace": test_namespace,
						":key": test_key,
					},
					|row| row.get(0),
					).unwrap();

			assert_eq!(res, test_data);
		}

		// Check we migrate the db just fine without losing our written data.
		let store = SqliteStore::new(temp_path, Some(db_file_name), Some(kv_table_name)).unwrap();
		let res = store.read(&test_namespace, "", &test_key).unwrap();
		assert_eq!(res, test_data);

		// Check we can continue to use the store just fine.
		do_read_write_remove_list_persist(&store);
	}
}
