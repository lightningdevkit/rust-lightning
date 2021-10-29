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
//! # Note
//!
//! If persisting [`Scorer`], it must be restored using the same [`Time`] parameterization. Using a
//! different type results in undefined behavior. Specifically, persisting when built with feature
//! `no-std` and restoring without it, or vice versa, uses different types and thus is undefined.
//!
//! [`find_route`]: crate::routing::router::find_route

use routing;

use ln::msgs::DecodeError;
use routing::network_graph::NodeId;
use routing::router::RouteHop;
use util::ser::{Readable, Writeable, Writer};

use prelude::*;
use core::ops::Sub;
use core::time::Duration;
use io::{self, Read};

/// [`routing::Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. Will further penalize channels that fail to relay payments.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: crate::routing::scorer
pub type Scorer = ScorerUsingTime::<DefaultTime>;

/// Time used by [`Scorer`].
#[cfg(not(feature = "no-std"))]
pub type DefaultTime = std::time::Instant;

/// Time used by [`Scorer`].
#[cfg(feature = "no-std")]
pub type DefaultTime = Eternity;

/// [`routing::Score`] implementation parameterized by [`Time`].
///
/// See [`Scorer`] for details.
///
/// # Note
///
/// Mixing [`Time`] types between serialization and deserialization results in undefined behavior.
pub struct ScorerUsingTime<T: Time> {
	params: ScoringParameters,
	// TODO: Remove entries of closed channels.
	channel_failures: HashMap<u64, ChannelFailure<T>>,
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
	/// # Note
	///
	/// When time is an [`Eternity`], as is default when enabling feature `no-std`, it will never
	/// elapse. Therefore, this penalty will never decay.
	///
	/// [`failure_penalty_msat`]: Self::failure_penalty_msat
	pub failure_penalty_half_life: Duration,
}

impl_writeable_tlv_based!(ScoringParameters, {
	(0, base_penalty_msat, required),
	(2, failure_penalty_msat, required),
	(4, failure_penalty_half_life, required),
});

/// Accounting for penalties against a channel for failing to relay any payments.
///
/// Penalties decay over time, though accumulate as more failures occur.
struct ChannelFailure<T: Time> {
	/// Accumulated penalty in msats for the channel as of `last_failed`.
	undecayed_penalty_msat: u64,

	/// Last time the channel failed. Used to decay `undecayed_penalty_msat`.
	last_failed: T,
}

/// A measurement of time.
pub trait Time: Sub<Duration, Output = Self> where Self: Sized {
	/// Returns an instance corresponding to the current moment.
	fn now() -> Self;

	/// Returns the amount of time elapsed since `self` was created.
	fn elapsed(&self) -> Duration;

	/// Returns the amount of time passed since the beginning of [`Time`].
	///
	/// Used during (de-)serialization.
	fn duration_since_epoch() -> Duration;
}

impl<T: Time> ScorerUsingTime<T> {
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

impl<T: Time> ChannelFailure<T> {
	fn new(failure_penalty_msat: u64) -> Self {
		Self {
			undecayed_penalty_msat: failure_penalty_msat,
			last_failed: T::now(),
		}
	}

	fn add_penalty(&mut self, failure_penalty_msat: u64, half_life: Duration) {
		self.undecayed_penalty_msat = self.decayed_penalty_msat(half_life) + failure_penalty_msat;
		self.last_failed = T::now();
	}

	fn decayed_penalty_msat(&self, half_life: Duration) -> u64 {
		let decays = self.last_failed.elapsed().as_secs().checked_div(half_life.as_secs());
		match decays {
			Some(decays) => self.undecayed_penalty_msat >> decays,
			None => 0,
		}
	}
}

impl<T: Time> Default for ScorerUsingTime<T> {
	fn default() -> Self {
		Self::new(ScoringParameters::default())
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

impl<T: Time> routing::Score for ScorerUsingTime<T> {
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

#[cfg(not(feature = "no-std"))]
impl Time for std::time::Instant {
	fn now() -> Self {
		std::time::Instant::now()
	}

	fn duration_since_epoch() -> Duration {
		use std::time::SystemTime;
		SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()
	}

	fn elapsed(&self) -> Duration {
		std::time::Instant::elapsed(self)
	}
}

/// A state in which time has no meaning.
pub struct Eternity;

impl Time for Eternity {
	fn now() -> Self {
		Self
	}

	fn duration_since_epoch() -> Duration {
		Duration::from_secs(0)
	}

	fn elapsed(&self) -> Duration {
		Duration::from_secs(0)
	}
}

impl Sub<Duration> for Eternity {
	type Output = Self;

	fn sub(self, _other: Duration) -> Self {
		self
	}
}

impl<T: Time> Writeable for ScorerUsingTime<T> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.params.write(w)?;
		self.channel_failures.write(w)
	}
}

impl<T: Time> Readable for ScorerUsingTime<T> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			params: Readable::read(r)?,
			channel_failures: Readable::read(r)?,
		})
	}
}

impl<T: Time> Writeable for ChannelFailure<T> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.undecayed_penalty_msat.write(w)?;
		(T::duration_since_epoch() - self.last_failed.elapsed()).write(w)
	}
}

impl<T: Time> Readable for ChannelFailure<T> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			undecayed_penalty_msat: Readable::read(r)?,
			last_failed: T::now() - (T::duration_since_epoch() - Readable::read(r)?),
		})
	}
}
