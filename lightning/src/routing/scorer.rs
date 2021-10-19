// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for scoring payment channels.
//!
//! [`Scorer`] may be given to [`get_route`] to score payment channels during path finding when a
//! custom [`routing::Score`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate secp256k1;
//! #
//! # use lightning::routing::network_graph::NetworkGraph;
//! # use lightning::routing::router::get_route;
//! # use lightning::routing::scorer::Scorer;
//! # use lightning::util::logger::{Logger, Record};
//! # use secp256k1::key::PublicKey;
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # fn find_scored_route(payer: PublicKey, payee: PublicKey, network_graph: NetworkGraph) {
//! # let logger = FakeLogger {};
//! #
//! // Use the default channel penalty.
//! let scorer = Scorer::default();
//!
//! // Or use a custom channel penalty.
//! let scorer = Scorer::new(1_000);
//!
//! let route = get_route(&payer, &network_graph, &payee, None, None, &vec![], 1_000, 42, &logger, &scorer);
//! # }
//! ```
//!
//! [`get_route`]: crate::routing::router::get_route

use routing;

use routing::network_graph::NodeId;

/// [`routing::Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: crate::routing::scorer
pub struct Scorer {
	base_penalty_msat: u64,
}

impl Scorer {
	/// Creates a new scorer using `base_penalty_msat` as the channel penalty.
	pub fn new(base_penalty_msat: u64) -> Self {
		Self { base_penalty_msat }
	}
}

impl Default for Scorer {
	/// Creates a new scorer using 500 msat as the channel penalty.
	fn default() -> Self {
		Scorer::new(500)
	}
}

impl routing::Score for Scorer {
	fn channel_penalty_msat(
		&self, _short_channel_id: u64, _source: &NodeId, _target: &NodeId
	) -> u64 {
		self.base_penalty_msat
	}
}
