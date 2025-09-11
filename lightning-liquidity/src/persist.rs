// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Types and utils for persistence.

use crate::lsps2::service::PeerState as LSPS2ServicePeerState;
use crate::prelude::{new_hash_map, HashMap};
use crate::sync::Mutex;

use lightning::io::Cursor;
use lightning::util::persist::KVStore;
use lightning::util::ser::Readable;

use bitcoin::secp256k1::PublicKey;

use core::ops::Deref;
use core::str::FromStr;

/// The primary namespace under which the [`LiquidityManager`] will be persisted.
///
/// [`LiquidityManager`]: crate::LiquidityManager
pub const LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE: &str = "lightning_liquidity_state";

/// The secondary namespace under which the [`LiquidityManager`] event queue will be persisted.
///
/// [`LiquidityManager`]: crate::LiquidityManager
pub const LIQUIDITY_MANAGER_EVENT_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE: &str = "";

/// The key under which the [`LiquidityManager`] event queue will be persisted.
///
/// [`LiquidityManager`]: crate::LiquidityManager
pub const LIQUIDITY_MANAGER_EVENT_QUEUE_PERSISTENCE_KEY: &str = "event_queue";

/// The secondary namespace under which the [`LSPS2ServiceHandler`] data will be persisted.
///
/// [`LSPS2ServiceHandler`]: crate::lsps2::service::LSPS2ServiceHandler
pub const LSPS2_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE: &str = "lsps2_service";

/// The secondary namespace under which the [`LSPS5ServiceHandler`] data will be persisted.
///
/// [`LSPS5ServiceHandler`]: crate::lsps5::service::LSPS5ServiceHandler
pub const LSPS5_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE: &str = "lsps5_service";

pub(crate) async fn read_lsps2_service_peer_states<K: Deref>(
	kv_store: K,
) -> Result<HashMap<PublicKey, Mutex<LSPS2ServicePeerState>>, lightning::io::Error>
where
	K::Target: KVStore,
{
	let mut res = new_hash_map();

	for stored_key in kv_store
		.list(
			LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
			LSPS2_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
		)
		.await?
	{
		let mut reader = Cursor::new(
			kv_store
				.read(
					LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
					LSPS2_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE,
					&stored_key,
				)
				.await?,
		);

		let peer_state = LSPS2ServicePeerState::read(&mut reader).map_err(|_| {
			lightning::io::Error::new(
				lightning::io::ErrorKind::InvalidData,
				"Failed to deserialize LSPS2 peer state",
			)
		})?;

		let key = PublicKey::from_str(&stored_key).map_err(|_| {
			lightning::io::Error::new(
				lightning::io::ErrorKind::InvalidData,
				"Failed to deserialize stored key entry",
			)
		})?;

		res.insert(key, Mutex::new(peer_state));
	}
	Ok(res)
}
