// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Types and utils for persistence.

/// The primary namespace under which the [`LiquidityManager`] will be persisted.
///
/// [`LiquidityManager`]: crate::LiquidityManager
pub const LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE: &str = "lightning_liquidity_state";

/// The secondary namespace under which the [`LSPS2ServiceHandler`] data will be persisted.
///
/// [`LSPS2ServiceHandler`]: crate::lsps2::service::LSPS2ServiceHandler
pub const LSPS2_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE: &str = "lsps2_service";

/// The secondary namespace under which the [`LSPS5ServiceHandler`] data will be persisted.
///
/// [`LSPS5ServiceHandler`]: crate::lsps5::service::LSPS5ServiceHandler
pub const LSPS5_SERVICE_PERSISTENCE_SECONDARY_NAMESPACE: &str = "lsps5_service";
