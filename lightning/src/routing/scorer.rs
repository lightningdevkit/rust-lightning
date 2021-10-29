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
//! [`Scorer`] may be given to [`find_route`] to score payment channels during path finding when a
//! custom [`routing::Score`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate secp256k1;
//! #
//! # use lightning::routing::network_graph::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scorer::{Scorer, ScoringParameters};
//! # use lightning::util::logger::{Logger, Record};
//! # use secp256k1::key::PublicKey;
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # fn find_scored_route(payer: PublicKey, params: RouteParameters, network_graph: NetworkGraph) {
//! # let logger = FakeLogger {};
//! #
//! // Use the default channel penalties.
//! let scorer = Scorer::default();
//!
//! // Or use custom channel penalties.
//! let scorer = Scorer::new(ScoringParameters {
//!     base_penalty_msat: 1000,
//!     failure_penalty_msat: 2 * 1024 * 1000,
//!     ..ScoringParameters::default()
//! });
//!
//! let route = find_route(&payer, &params, &network_graph, None, &logger, &scorer);
//! # }
//! ```
//!
//! [`find_route`]: crate::routing::router::find_route

use routing;

use routing::network_graph::NodeId;
use routing::router::RouteHop;

use prelude::*;
use core::time::Duration;
#[cfg(not(feature = "no-std"))]
use std::time::Instant;

/// [`routing::Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. Will further penalize channels that fail to relay payments.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: crate::routing::scorer
pub struct Scorer {
	params: ScoringParameters,
	// TODO: Remove entries of closed channels.
	channel_failures: HashMap<u64, ChannelFailure>,
}

/// Parameters for configuring [`Scorer`].
pub struct ScoringParameters {
	/// A fixed penalty in msats to apply to each channel.
	pub base_penalty_msat: u64,

	/// A penalty in msats to apply to a channel upon failing to relay a payment.
	///
	/// This accumulates for each failure but may be reduced over time based on
	/// [`failure_penalty_half_life`].
	///
	/// [`failure_penalty_half_life`]: Self::failure_penalty_half_life
	pub failure_penalty_msat: u64,

	/// The time required to elapse before any accumulated [`failure_penalty_msat`] penalties are
	/// cut in half.
	///
	/// [`failure_penalty_msat`]: Self::failure_penalty_msat
	pub failure_penalty_half_life: Duration,
}

/// Accounting for penalties against a channel for failing to relay any payments.
///
/// Penalties decay over time, though accumulate as more failures occur.
struct ChannelFailure {
	/// Accumulated penalty in msats for the channel as of `last_failed`.
	undecayed_penalty_msat: u64,

	/// Last time the channel failed. Used to decay `undecayed_penalty_msat`.
	#[cfg(not(feature = "no-std"))]
	last_failed: Instant,
}

impl Scorer {
	/// Creates a new scorer using the given scoring parameters.
	pub fn new(params: ScoringParameters) -> Self {
		Self {
			params,
			channel_failures: HashMap::new(),
		}
	}

	/// Creates a new scorer using `penalty_msat` as a fixed channel penalty.
	#[cfg(any(test, feature = "fuzztarget", feature = "_test_utils"))]
	pub fn with_fixed_penalty(penalty_msat: u64) -> Self {
		Self::new(ScoringParameters {
			base_penalty_msat: penalty_msat,
			failure_penalty_msat: 0,
			failure_penalty_half_life: Duration::from_secs(0),
		})
	}
}

impl ChannelFailure {
	fn new(failure_penalty_msat: u64) -> Self {
		Self {
			undecayed_penalty_msat: failure_penalty_msat,
			#[cfg(not(feature = "no-std"))]
			last_failed: Instant::now(),
		}
	}

	fn add_penalty(&mut self, failure_penalty_msat: u64, half_life: Duration) {
		self.undecayed_penalty_msat = self.decayed_penalty_msat(half_life) + failure_penalty_msat;
		#[cfg(not(feature = "no-std"))]
		{
			self.last_failed = Instant::now();
		}
	}

	fn decayed_penalty_msat(&self, half_life: Duration) -> u64 {
		let decays = self.elapsed().as_secs().checked_div(half_life.as_secs());
		match decays {
			Some(decays) => self.undecayed_penalty_msat >> decays,
			None => 0,
		}
	}

	fn elapsed(&self) -> Duration {
		#[cfg(not(feature = "no-std"))]
		return self.last_failed.elapsed();
		#[cfg(feature = "no-std")]
		return Duration::from_secs(0);
	}
}

impl Default for Scorer {
	fn default() -> Self {
		Scorer::new(ScoringParameters::default())
	}
}

impl Default for ScoringParameters {
	fn default() -> Self {
		Self {
			base_penalty_msat: 500,
			failure_penalty_msat: 1024 * 1000,
			failure_penalty_half_life: Duration::from_secs(3600),
		}
	}
}

impl routing::Score for Scorer {
	fn channel_penalty_msat(
		&self, short_channel_id: u64, _source: &NodeId, _target: &NodeId
	) -> u64 {
		let failure_penalty_msat = self.channel_failures
			.get(&short_channel_id)
			.map_or(0, |value| value.decayed_penalty_msat(self.params.failure_penalty_half_life));

		self.params.base_penalty_msat + failure_penalty_msat
	}

	fn payment_path_failed(&mut self, _path: &Vec<RouteHop>, short_channel_id: u64) {
		let failure_penalty_msat = self.params.failure_penalty_msat;
		let half_life = self.params.failure_penalty_half_life;
		self.channel_failures
			.entry(short_channel_id)
			.and_modify(|failure| failure.add_penalty(failure_penalty_msat, half_life))
			.or_insert_with(|| ChannelFailure::new(failure_penalty_msat));
	}
}
