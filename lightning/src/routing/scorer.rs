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
#[cfg(not(feature = "no-std"))]
use core::time::Duration;
#[cfg(not(feature = "no-std"))]
use std::time::Instant;

/// [`routing::Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. May also further penalize failed channels.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: crate::routing::scorer
pub struct Scorer {
	params: ScoringParameters,
	#[cfg(not(feature = "no-std"))]
	channel_failures: HashMap<u64, (u64, Instant)>,
	#[cfg(feature = "no-std")]
	channel_failures: HashMap<u64, u64>,
}

/// Parameters for configuring [`Scorer`].
pub struct ScoringParameters {
	/// A fixed penalty in msats to apply to each channel.
	pub base_penalty_msat: u64,

	/// A penalty in msats to apply to a channel upon failure.
	///
	/// This may be reduced over time based on [`failure_penalty_half_life`].
	///
	/// [`failure_penalty_half_life`]: Self::failure_penalty_half_life
	pub failure_penalty_msat: u64,

	/// The time needed before any accumulated channel failure penalties are cut in half.
	#[cfg(not(feature = "no-std"))]
	pub failure_penalty_half_life: Duration,
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
			#[cfg(not(feature = "no-std"))]
			failure_penalty_half_life: Duration::from_secs(0),
		})
	}

	#[cfg(not(feature = "no-std"))]
	fn decay_from(&self, penalty_msat: u64, last_failure: &Instant) -> u64 {
		decay_from(penalty_msat, last_failure, self.params.failure_penalty_half_life)
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
			#[cfg(not(feature = "no-std"))]
			failure_penalty_half_life: Duration::from_secs(3600),
		}
	}
}

impl routing::Score for Scorer {
	fn channel_penalty_msat(
		&self, short_channel_id: u64, _source: &NodeId, _target: &NodeId
	) -> u64 {
		#[cfg(not(feature = "no-std"))]
		let failure_penalty_msat = match self.channel_failures.get(&short_channel_id) {
			Some((penalty_msat, last_failure)) => self.decay_from(*penalty_msat, last_failure),
			None => 0,
		};
		#[cfg(feature = "no-std")]
		let failure_penalty_msat =
			self.channel_failures.get(&short_channel_id).copied().unwrap_or(0);

		self.params.base_penalty_msat + failure_penalty_msat
	}

	fn payment_path_failed(&mut self, _path: &Vec<RouteHop>, short_channel_id: u64) {
		let failure_penalty_msat = self.params.failure_penalty_msat;
		#[cfg(not(feature = "no-std"))]
		{
			let half_life = self.params.failure_penalty_half_life;
			self.channel_failures
				.entry(short_channel_id)
				.and_modify(|(penalty_msat, last_failure)| {
					let decayed_penalty = decay_from(*penalty_msat, last_failure, half_life);
					*penalty_msat = decayed_penalty + failure_penalty_msat;
					*last_failure = Instant::now();
				})
				.or_insert_with(|| (failure_penalty_msat, Instant::now()));
		}
		#[cfg(feature = "no-std")]
		self.channel_failures
			.entry(short_channel_id)
			.and_modify(|penalty_msat| *penalty_msat += failure_penalty_msat)
			.or_insert(failure_penalty_msat);
	}
}

#[cfg(not(feature = "no-std"))]
fn decay_from(penalty_msat: u64, last_failure: &Instant, half_life: Duration) -> u64 {
	let decays = last_failure.elapsed().as_secs().checked_div(half_life.as_secs());
	match decays {
		Some(decays) => penalty_msat >> decays,
		None => 0,
	}
}
