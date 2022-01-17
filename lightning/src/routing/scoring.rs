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
//! [`ProbabilisticScorer`] may be given to [`find_route`] to score payment channels during path
//! finding when a custom [`Score`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate secp256k1;
//! #
//! # use lightning::routing::network_graph::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters, Scorer, ScoringParameters};
//! # use lightning::util::logger::{Logger, Record};
//! # use secp256k1::key::PublicKey;
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # fn find_scored_route(payer: PublicKey, route_params: RouteParameters, network_graph: NetworkGraph) {
//! # let logger = FakeLogger {};
//! #
//! // Use the default channel penalties.
//! let params = ProbabilisticScoringParameters::default();
//! let scorer = ProbabilisticScorer::new(params, &network_graph);
//!
//! // Or use custom channel penalties.
//! let params = ProbabilisticScoringParameters {
//!     liquidity_penalty_multiplier_msat: 2 * 1000,
//!     ..ProbabilisticScoringParameters::default()
//! };
//! let scorer = ProbabilisticScorer::new(params, &network_graph);
//!
//! let route = find_route(&payer, &route_params, &network_graph, None, &logger, &scorer);
//! # }
//! ```
//!
//! # Note
//!
//! Persisting when built with feature `no-std` and restoring without it, or vice versa, uses
//! different types and thus is undefined.
//!
//! [`find_route`]: crate::routing::router::find_route

use ln::msgs::DecodeError;
use routing::network_graph::{NetworkGraph, NodeId};
use routing::router::RouteHop;
use util::ser::{Readable, ReadableArgs, Writeable, Writer};

use prelude::*;
use core::cell::{RefCell, RefMut};
use core::ops::{Deref, DerefMut};
use core::time::Duration;
use io::{self, Read};
use sync::{Mutex, MutexGuard};

/// We define Score ever-so-slightly differently based on whether we are being built for C bindings
/// or not. For users, `LockableScore` must somehow be writeable to disk. For Rust users, this is
/// no problem - you move a `Score` that implements `Writeable` into a `Mutex`, lock it, and now
/// you have the original, concrete, `Score` type, which presumably implements `Writeable`.
///
/// For C users, once you've moved the `Score` into a `LockableScore` all you have after locking it
/// is an opaque trait object with an opaque pointer with no type info. Users could take the unsafe
/// approach of blindly casting that opaque pointer to a concrete type and calling `Writeable` from
/// there, but other languages downstream of the C bindings (e.g. Java) can't even do that.
/// Instead, we really want `Score` and `LockableScore` to implement `Writeable` directly, which we
/// do here by defining `Score` differently for `cfg(c_bindings)`.
macro_rules! define_score { ($($supertrait: path)*) => {
/// An interface used to score payment channels for path finding.
///
///	Scoring is in terms of fees willing to be paid in order to avoid routing through a channel.
pub trait Score $(: $supertrait)* {
	/// Returns the fee in msats willing to be paid to avoid routing `send_amt_msat` through the
	/// given channel in the direction from `source` to `target`.
	///
	/// The channel's capacity (less any other MPP parts that are also being considered for use in
	/// the same payment) is given by `capacity_msat`. It may be determined from various sources
	/// such as a chain data, network gossip, or invoice hints. For invoice hints, a capacity near
	/// [`u64::max_value`] is given to indicate sufficient capacity for the invoice's full amount.
	/// Thus, implementations should be overflow-safe.
	fn channel_penalty_msat(&self, short_channel_id: u64, send_amt_msat: u64, capacity_msat: u64, source: &NodeId, target: &NodeId) -> u64;

	/// Handles updating channel penalties after failing to route through a channel.
	fn payment_path_failed(&mut self, path: &[&RouteHop], short_channel_id: u64);

	/// Handles updating channel penalties after successfully routing along a path.
	fn payment_path_successful(&mut self, path: &[&RouteHop]);
}

impl<S: Score, T: DerefMut<Target=S> $(+ $supertrait)*> Score for T {
	fn channel_penalty_msat(&self, short_channel_id: u64, send_amt_msat: u64, capacity_msat: u64, source: &NodeId, target: &NodeId) -> u64 {
		self.deref().channel_penalty_msat(short_channel_id, send_amt_msat, capacity_msat, source, target)
	}

	fn payment_path_failed(&mut self, path: &[&RouteHop], short_channel_id: u64) {
		self.deref_mut().payment_path_failed(path, short_channel_id)
	}

	fn payment_path_successful(&mut self, path: &[&RouteHop]) {
		self.deref_mut().payment_path_successful(path)
	}
}
} }

#[cfg(c_bindings)]
define_score!(Writeable);
#[cfg(not(c_bindings))]
define_score!();

/// A scorer that is accessed under a lock.
///
/// Needed so that calls to [`Score::channel_penalty_msat`] in [`find_route`] can be made while
/// having shared ownership of a scorer but without requiring internal locking in [`Score`]
/// implementations. Internal locking would be detrimental to route finding performance and could
/// result in [`Score::channel_penalty_msat`] returning a different value for the same channel.
///
/// [`find_route`]: crate::routing::router::find_route
pub trait LockableScore<'a> {
	/// The locked [`Score`] type.
	type Locked: 'a + Score;

	/// Returns the locked scorer.
	fn lock(&'a self) -> Self::Locked;
}

/// (C-not exported)
impl<'a, T: 'a + Score> LockableScore<'a> for Mutex<T> {
	type Locked = MutexGuard<'a, T>;

	fn lock(&'a self) -> MutexGuard<'a, T> {
		Mutex::lock(self).unwrap()
	}
}

impl<'a, T: 'a + Score> LockableScore<'a> for RefCell<T> {
	type Locked = RefMut<'a, T>;

	fn lock(&'a self) -> RefMut<'a, T> {
		self.borrow_mut()
	}
}

#[cfg(c_bindings)]
/// A concrete implementation of [`LockableScore`] which supports multi-threading.
pub struct MultiThreadedLockableScore<S: Score> {
	score: Mutex<S>,
}
#[cfg(c_bindings)]
/// (C-not exported)
impl<'a, T: Score + 'a> LockableScore<'a> for MultiThreadedLockableScore<T> {
	type Locked = MutexGuard<'a, T>;

	fn lock(&'a self) -> MutexGuard<'a, T> {
		Mutex::lock(&self.score).unwrap()
	}
}

#[cfg(c_bindings)]
impl<T: Score> MultiThreadedLockableScore<T> {
	/// Creates a new [`MultiThreadedLockableScore`] given an underlying [`Score`].
	pub fn new(score: T) -> Self {
		MultiThreadedLockableScore { score: Mutex::new(score) }
	}
}

#[cfg(c_bindings)]
/// (C-not exported)
impl<'a, T: Writeable> Writeable for RefMut<'a, T> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		T::write(&**self, writer)
	}
}

#[cfg(c_bindings)]
/// (C-not exported)
impl<'a, S: Writeable> Writeable for MutexGuard<'a, S> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		S::write(&**self, writer)
	}
}

/// [`Score`] implementation that uses a fixed penalty.
pub struct FixedPenaltyScorer {
	penalty_msat: u64,
}

impl_writeable_tlv_based!(FixedPenaltyScorer, {
	(0, penalty_msat, required),
});

impl FixedPenaltyScorer {
	/// Creates a new scorer using `penalty_msat`.
	pub fn with_penalty(penalty_msat: u64) -> Self {
		Self { penalty_msat }
	}
}

impl Score for FixedPenaltyScorer {
	fn channel_penalty_msat(&self, _: u64, _: u64, _: u64, _: &NodeId, _: &NodeId) -> u64 {
		self.penalty_msat
	}

	fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}

	fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
}

/// [`Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. Will further penalize channels that fail to relay payments.
///
/// See [module-level documentation] for usage and [`ScoringParameters`] for customization.
///
/// # Note
///
/// Mixing the `no-std` feature between serialization and deserialization results in undefined
/// behavior.
///
/// [module-level documentation]: crate::routing::scoring
#[deprecated(
	since = "0.0.105",
	note = "ProbabilisticScorer should be used instead of Scorer.",
)]
pub type Scorer = ScorerUsingTime::<ConfiguredTime>;

#[cfg(not(feature = "no-std"))]
type ConfiguredTime = std::time::Instant;
#[cfg(feature = "no-std")]
type ConfiguredTime = time::Eternity;

// Note that ideally we'd hide ScorerUsingTime from public view by sealing it as well, but rustdoc
// doesn't handle this well - instead exposing a `Scorer` which has no trait implementation(s) or
// methods at all.

/// [`Score`] implementation.
///
/// (C-not exported) generally all users should use the [`Scorer`] type alias.
#[doc(hidden)]
pub struct ScorerUsingTime<T: Time> {
	params: ScoringParameters,
	// TODO: Remove entries of closed channels.
	channel_failures: HashMap<u64, ChannelFailure<T>>,
}

/// Parameters for configuring [`Scorer`].
pub struct ScoringParameters {
	/// A fixed penalty in msats to apply to each channel.
	///
	/// Default value: 500 msat
	pub base_penalty_msat: u64,

	/// A penalty in msats to apply to a channel upon failing to relay a payment.
	///
	/// This accumulates for each failure but may be reduced over time based on
	/// [`failure_penalty_half_life`] or when successfully routing through a channel.
	///
	/// Default value: 1,024,000 msat
	///
	/// [`failure_penalty_half_life`]: Self::failure_penalty_half_life
	pub failure_penalty_msat: u64,

	/// When the amount being sent over a channel is this many 1024ths of the total channel
	/// capacity, we begin applying [`overuse_penalty_msat_per_1024th`].
	///
	/// Default value: 128 1024ths (i.e. begin penalizing when an HTLC uses 1/8th of a channel)
	///
	/// [`overuse_penalty_msat_per_1024th`]: Self::overuse_penalty_msat_per_1024th
	pub overuse_penalty_start_1024th: u16,

	/// A penalty applied, per whole 1024ths of the channel capacity which the amount being sent
	/// over the channel exceeds [`overuse_penalty_start_1024th`] by.
	///
	/// Default value: 20 msat (i.e. 2560 msat penalty to use 1/4th of a channel, 7680 msat penalty
	///                to use half a channel, and 12,560 msat penalty to use 3/4ths of a channel)
	///
	/// [`overuse_penalty_start_1024th`]: Self::overuse_penalty_start_1024th
	pub overuse_penalty_msat_per_1024th: u64,

	/// The time required to elapse before any accumulated [`failure_penalty_msat`] penalties are
	/// cut in half.
	///
	/// Successfully routing through a channel will immediately cut the penalty in half as well.
	///
	/// Default value: 1 hour
	///
	/// # Note
	///
	/// When built with the `no-std` feature, time will never elapse. Therefore, this penalty will
	/// never decay.
	///
	/// [`failure_penalty_msat`]: Self::failure_penalty_msat
	pub failure_penalty_half_life: Duration,
}

impl_writeable_tlv_based!(ScoringParameters, {
	(0, base_penalty_msat, required),
	(1, overuse_penalty_start_1024th, (default_value, 128)),
	(2, failure_penalty_msat, required),
	(3, overuse_penalty_msat_per_1024th, (default_value, 20)),
	(4, failure_penalty_half_life, required),
});

/// Accounting for penalties against a channel for failing to relay any payments.
///
/// Penalties decay over time, though accumulate as more failures occur.
struct ChannelFailure<T: Time> {
	/// Accumulated penalty in msats for the channel as of `last_updated`.
	undecayed_penalty_msat: u64,

	/// Last time the channel either failed to route or successfully routed a payment. Used to decay
	/// `undecayed_penalty_msat`.
	last_updated: T,
}

impl<T: Time> ScorerUsingTime<T> {
	/// Creates a new scorer using the given scoring parameters.
	pub fn new(params: ScoringParameters) -> Self {
		Self {
			params,
			channel_failures: HashMap::new(),
		}
	}
}

impl<T: Time> ChannelFailure<T> {
	fn new(failure_penalty_msat: u64) -> Self {
		Self {
			undecayed_penalty_msat: failure_penalty_msat,
			last_updated: T::now(),
		}
	}

	fn add_penalty(&mut self, failure_penalty_msat: u64, half_life: Duration) {
		self.undecayed_penalty_msat = self.decayed_penalty_msat(half_life) + failure_penalty_msat;
		self.last_updated = T::now();
	}

	fn reduce_penalty(&mut self, half_life: Duration) {
		self.undecayed_penalty_msat = self.decayed_penalty_msat(half_life) >> 1;
		self.last_updated = T::now();
	}

	fn decayed_penalty_msat(&self, half_life: Duration) -> u64 {
		self.last_updated.elapsed().as_secs()
			.checked_div(half_life.as_secs())
			.and_then(|decays| self.undecayed_penalty_msat.checked_shr(decays as u32))
			.unwrap_or(0)
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
			overuse_penalty_start_1024th: 1024 / 8,
			overuse_penalty_msat_per_1024th: 20,
		}
	}
}

impl<T: Time> Score for ScorerUsingTime<T> {
	fn channel_penalty_msat(
		&self, short_channel_id: u64, send_amt_msat: u64, capacity_msat: u64, _source: &NodeId, _target: &NodeId
	) -> u64 {
		let failure_penalty_msat = self.channel_failures
			.get(&short_channel_id)
			.map_or(0, |value| value.decayed_penalty_msat(self.params.failure_penalty_half_life));

		let mut penalty_msat = self.params.base_penalty_msat + failure_penalty_msat;
		let send_1024ths = send_amt_msat.checked_mul(1024).unwrap_or(u64::max_value()) / capacity_msat;
		if send_1024ths > self.params.overuse_penalty_start_1024th as u64 {
			penalty_msat = penalty_msat.checked_add(
					(send_1024ths - self.params.overuse_penalty_start_1024th as u64)
					.checked_mul(self.params.overuse_penalty_msat_per_1024th).unwrap_or(u64::max_value()))
				.unwrap_or(u64::max_value());
		}

		penalty_msat
	}

	fn payment_path_failed(&mut self, _path: &[&RouteHop], short_channel_id: u64) {
		let failure_penalty_msat = self.params.failure_penalty_msat;
		let half_life = self.params.failure_penalty_half_life;
		self.channel_failures
			.entry(short_channel_id)
			.and_modify(|failure| failure.add_penalty(failure_penalty_msat, half_life))
			.or_insert_with(|| ChannelFailure::new(failure_penalty_msat));
	}

	fn payment_path_successful(&mut self, path: &[&RouteHop]) {
		let half_life = self.params.failure_penalty_half_life;
		for hop in path.iter() {
			self.channel_failures
				.entry(hop.short_channel_id)
				.and_modify(|failure| failure.reduce_penalty(half_life));
		}
	}
}

impl<T: Time> Writeable for ScorerUsingTime<T> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.params.write(w)?;
		self.channel_failures.write(w)?;
		write_tlv_fields!(w, {});
		Ok(())
	}
}

impl<T: Time> Readable for ScorerUsingTime<T> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let res = Ok(Self {
			params: Readable::read(r)?,
			channel_failures: Readable::read(r)?,
		});
		read_tlv_fields!(r, {});
		res
	}
}

impl<T: Time> Writeable for ChannelFailure<T> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let duration_since_epoch = T::duration_since_epoch() - self.last_updated.elapsed();
		write_tlv_fields!(w, {
			(0, self.undecayed_penalty_msat, required),
			(2, duration_since_epoch, required),
		});
		Ok(())
	}
}

impl<T: Time> Readable for ChannelFailure<T> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut undecayed_penalty_msat = 0;
		let mut duration_since_epoch = Duration::from_secs(0);
		read_tlv_fields!(r, {
			(0, undecayed_penalty_msat, required),
			(2, duration_since_epoch, required),
		});
		Ok(Self {
			undecayed_penalty_msat,
			last_updated: T::now() - (T::duration_since_epoch() - duration_since_epoch),
		})
	}
}

/// [`Score`] implementation using channel success probability distributions.
///
/// Based on *Optimally Reliable & Cheap Payment Flows on the Lightning Network* by Rene Pickhardt
/// and Stefan Richter [[1]]. Given the uncertainty of channel liquidity balances, probability
/// distributions are defined based on knowledge learned from successful and unsuccessful attempts.
/// Then the negative `log10` of the success probability is used to determine the cost of routing a
/// specific HTLC amount through a channel.
///
/// Knowledge about channel liquidity balances takes the form of upper and lower bounds on the
/// possible liquidity. Certainty of the bounds is decreased over time using a decay function. See
/// [`ProbabilisticScoringParameters`] for details.
///
/// Since the scorer aims to learn the current channel liquidity balances, it works best for nodes
/// with high payment volume or that actively probe the [`NetworkGraph`]. Nodes with low payment
/// volume are more likely to experience failed payment paths, which would need to be retried.
///
/// # Note
///
/// Mixing the `no-std` feature between serialization and deserialization results in undefined
/// behavior.
///
/// [1]: https://arxiv.org/abs/2107.05322
pub type ProbabilisticScorer<G> = ProbabilisticScorerUsingTime::<G, ConfiguredTime>;

/// Probabilistic [`Score`] implementation.
///
/// (C-not exported) generally all users should use the [`ProbabilisticScorer`] type alias.
#[doc(hidden)]
pub struct ProbabilisticScorerUsingTime<G: Deref<Target = NetworkGraph>, T: Time> {
	params: ProbabilisticScoringParameters,
	network_graph: G,
	// TODO: Remove entries of closed channels.
	channel_liquidities: HashMap<u64, ChannelLiquidity<T>>,
}

/// Parameters for configuring [`ProbabilisticScorer`].
#[derive(Clone, Copy)]
pub struct ProbabilisticScoringParameters {
	/// A multiplier used to determine the amount in msats willing to be paid to avoid routing
	/// through a channel, as per multiplying by the negative `log10` of the channel's success
	/// probability for a payment.
	///
	/// The success probability is determined by the effective channel capacity, the payment amount,
	/// and knowledge learned from prior successful and unsuccessful payments. The lower bound of
	/// the success probability is 0.01, effectively limiting the penalty to the range
	/// `0..=2*liquidity_penalty_multiplier_msat`. The knowledge learned is decayed over time based
	/// on [`liquidity_offset_half_life`].
	///
	/// Default value: 10,000 msat
	///
	/// [`liquidity_offset_half_life`]: Self::liquidity_offset_half_life
	pub liquidity_penalty_multiplier_msat: u64,

	/// The time required to elapse before any knowledge learned about channel liquidity balances is
	/// cut in half.
	///
	/// The bounds are defined in terms of offsets and are initially zero. Increasing the offsets
	/// gives tighter bounds on the channel liquidity balance. Thus, halving the offsets decreases
	/// the certainty of the channel liquidity balance.
	///
	/// Default value: 1 hour
	///
	/// # Note
	///
	/// When built with the `no-std` feature, time will never elapse. Therefore, the channel
	/// liquidity knowledge will never decay except when the bounds cross.
	pub liquidity_offset_half_life: Duration,
}

impl_writeable_tlv_based!(ProbabilisticScoringParameters, {
	(0, liquidity_penalty_multiplier_msat, required),
	(2, liquidity_offset_half_life, required),
});

/// Accounting for channel liquidity balance uncertainty.
///
/// Direction is defined in terms of [`NodeId`] partial ordering, where the source node is the
/// first node in the ordering of the channel's counterparties. Thus, swapping the two liquidity
/// offset fields gives the opposite direction.
struct ChannelLiquidity<T: Time> {
	/// Lower channel liquidity bound in terms of an offset from zero.
	min_liquidity_offset_msat: u64,

	/// Upper channel liquidity bound in terms of an offset from the effective capacity.
	max_liquidity_offset_msat: u64,

	/// Time when the liquidity bounds were last modified.
	last_updated: T,
}

/// A snapshot of [`ChannelLiquidity`] in one direction assuming a certain channel capacity and
/// decayed with a given half life.
struct DirectedChannelLiquidity<L: Deref<Target = u64>, T: Time, U: Deref<Target = T>> {
	min_liquidity_offset_msat: L,
	max_liquidity_offset_msat: L,
	capacity_msat: u64,
	last_updated: U,
	now: T,
	half_life: Duration,
}

impl<G: Deref<Target = NetworkGraph>, T: Time> ProbabilisticScorerUsingTime<G, T> {
	/// Creates a new scorer using the given scoring parameters for sending payments from a node
	/// through a network graph.
	pub fn new(params: ProbabilisticScoringParameters, network_graph: G) -> Self {
		Self {
			params,
			network_graph,
			channel_liquidities: HashMap::new(),
		}
	}

	#[cfg(test)]
	fn with_channel(mut self, short_channel_id: u64, liquidity: ChannelLiquidity<T>) -> Self {
		assert!(self.channel_liquidities.insert(short_channel_id, liquidity).is_none());
		self
	}
}

impl Default for ProbabilisticScoringParameters {
	fn default() -> Self {
		Self {
			liquidity_penalty_multiplier_msat: 10_000,
			liquidity_offset_half_life: Duration::from_secs(3600),
		}
	}
}

impl<T: Time> ChannelLiquidity<T> {
	#[inline]
	fn new() -> Self {
		Self {
			min_liquidity_offset_msat: 0,
			max_liquidity_offset_msat: 0,
			last_updated: T::now(),
		}
	}

	/// Returns a view of the channel liquidity directed from `source` to `target` assuming
	/// `capacity_msat`.
	fn as_directed(
		&self, source: &NodeId, target: &NodeId, capacity_msat: u64, half_life: Duration
	) -> DirectedChannelLiquidity<&u64, T, &T> {
		let (min_liquidity_offset_msat, max_liquidity_offset_msat) = if source < target {
			(&self.min_liquidity_offset_msat, &self.max_liquidity_offset_msat)
		} else {
			(&self.max_liquidity_offset_msat, &self.min_liquidity_offset_msat)
		};

		DirectedChannelLiquidity {
			min_liquidity_offset_msat,
			max_liquidity_offset_msat,
			capacity_msat,
			last_updated: &self.last_updated,
			now: T::now(),
			half_life,
		}
	}

	/// Returns a mutable view of the channel liquidity directed from `source` to `target` assuming
	/// `capacity_msat`.
	fn as_directed_mut(
		&mut self, source: &NodeId, target: &NodeId, capacity_msat: u64, half_life: Duration
	) -> DirectedChannelLiquidity<&mut u64, T, &mut T> {
		let (min_liquidity_offset_msat, max_liquidity_offset_msat) = if source < target {
			(&mut self.min_liquidity_offset_msat, &mut self.max_liquidity_offset_msat)
		} else {
			(&mut self.max_liquidity_offset_msat, &mut self.min_liquidity_offset_msat)
		};

		DirectedChannelLiquidity {
			min_liquidity_offset_msat,
			max_liquidity_offset_msat,
			capacity_msat,
			last_updated: &mut self.last_updated,
			now: T::now(),
			half_life,
		}
	}
}

impl<L: Deref<Target = u64>, T: Time, U: Deref<Target = T>> DirectedChannelLiquidity<L, T, U> {
	/// Returns the success probability of routing the given HTLC `amount_msat` through the channel
	/// in this direction.
	fn success_probability(&self, amount_msat: u64) -> f64 {
		let max_liquidity_msat = self.max_liquidity_msat();
		let min_liquidity_msat = core::cmp::min(self.min_liquidity_msat(), max_liquidity_msat);
		if amount_msat > max_liquidity_msat {
			0.0
		} else if amount_msat <= min_liquidity_msat {
			1.0
		} else {
			let numerator = max_liquidity_msat + 1 - amount_msat;
			let denominator = max_liquidity_msat + 1 - min_liquidity_msat;
			numerator as f64 / denominator as f64
		}.max(0.01) // Lower bound the success probability to ensure some channel is selected.
	}

	/// Returns the lower bound of the channel liquidity balance in this direction.
	fn min_liquidity_msat(&self) -> u64 {
		self.decayed_offset_msat(*self.min_liquidity_offset_msat)
	}

	/// Returns the upper bound of the channel liquidity balance in this direction.
	fn max_liquidity_msat(&self) -> u64 {
		self.capacity_msat
			.checked_sub(self.decayed_offset_msat(*self.max_liquidity_offset_msat))
			.unwrap_or(0)
	}

	fn decayed_offset_msat(&self, offset_msat: u64) -> u64 {
		self.now.duration_since(*self.last_updated).as_secs()
			.checked_div(self.half_life.as_secs())
			.and_then(|decays| offset_msat.checked_shr(decays as u32))
			.unwrap_or(0)
	}
}

impl<L: DerefMut<Target = u64>, T: Time, U: DerefMut<Target = T>> DirectedChannelLiquidity<L, T, U> {
	/// Adjusts the channel liquidity balance bounds when failing to route `amount_msat`.
	fn failed_at_channel(&mut self, amount_msat: u64) {
		if amount_msat < self.max_liquidity_msat() {
			self.set_max_liquidity_msat(amount_msat);
		}
	}

	/// Adjusts the channel liquidity balance bounds when failing to route `amount_msat` downstream.
	fn failed_downstream(&mut self, amount_msat: u64) {
		if amount_msat > self.min_liquidity_msat() {
			self.set_min_liquidity_msat(amount_msat);
		}
	}

	/// Adjusts the channel liquidity balance bounds when successfully routing `amount_msat`.
	fn successful(&mut self, amount_msat: u64) {
		let max_liquidity_msat = self.max_liquidity_msat().checked_sub(amount_msat).unwrap_or(0);
		self.set_max_liquidity_msat(max_liquidity_msat);
	}

	/// Adjusts the lower bound of the channel liquidity balance in this direction.
	fn set_min_liquidity_msat(&mut self, amount_msat: u64) {
		*self.min_liquidity_offset_msat = amount_msat;
		*self.max_liquidity_offset_msat = if amount_msat > self.max_liquidity_msat() {
			0
		} else {
			self.decayed_offset_msat(*self.max_liquidity_offset_msat)
		};
		*self.last_updated = self.now;
	}

	/// Adjusts the upper bound of the channel liquidity balance in this direction.
	fn set_max_liquidity_msat(&mut self, amount_msat: u64) {
		*self.max_liquidity_offset_msat = self.capacity_msat.checked_sub(amount_msat).unwrap_or(0);
		*self.min_liquidity_offset_msat = if amount_msat < self.min_liquidity_msat() {
			0
		} else {
			self.decayed_offset_msat(*self.min_liquidity_offset_msat)
		};
		*self.last_updated = self.now;
	}
}

impl<G: Deref<Target = NetworkGraph>, T: Time> Score for ProbabilisticScorerUsingTime<G, T> {
	fn channel_penalty_msat(
		&self, short_channel_id: u64, amount_msat: u64, capacity_msat: u64, source: &NodeId,
		target: &NodeId
	) -> u64 {
		let liquidity_penalty_multiplier_msat = self.params.liquidity_penalty_multiplier_msat;
		let liquidity_offset_half_life = self.params.liquidity_offset_half_life;
		let success_probability = self.channel_liquidities
			.get(&short_channel_id)
			.unwrap_or(&ChannelLiquidity::new())
			.as_directed(source, target, capacity_msat, liquidity_offset_half_life)
			.success_probability(amount_msat);
		// NOTE: If success_probability is ever changed to return 0.0, log10 is undefined so return
		// u64::max_value instead.
		debug_assert!(success_probability > core::f64::EPSILON);
		(-(success_probability.log10()) * liquidity_penalty_multiplier_msat as f64) as u64
	}

	fn payment_path_failed(&mut self, path: &[&RouteHop], short_channel_id: u64) {
		let amount_msat = path.split_last().map(|(hop, _)| hop.fee_msat).unwrap_or(0);
		let liquidity_offset_half_life = self.params.liquidity_offset_half_life;
		let network_graph = self.network_graph.read_only();
		for hop in path {
			let target = NodeId::from_pubkey(&hop.pubkey);
			let channel_directed_from_source = network_graph.channels()
				.get(&hop.short_channel_id)
				.and_then(|channel| channel.as_directed_to(&target));

			// Only score announced channels.
			if let Some((channel, source)) = channel_directed_from_source {
				let capacity_msat = channel.effective_capacity().as_msat();
				if hop.short_channel_id == short_channel_id {
					self.channel_liquidities
						.entry(hop.short_channel_id)
						.or_insert_with(ChannelLiquidity::new)
						.as_directed_mut(source, &target, capacity_msat, liquidity_offset_half_life)
						.failed_at_channel(amount_msat);
					break;
				}

				self.channel_liquidities
					.entry(hop.short_channel_id)
					.or_insert_with(ChannelLiquidity::new)
					.as_directed_mut(source, &target, capacity_msat, liquidity_offset_half_life)
					.failed_downstream(amount_msat);
			}
		}
	}

	fn payment_path_successful(&mut self, path: &[&RouteHop]) {
		let amount_msat = path.split_last().map(|(hop, _)| hop.fee_msat).unwrap_or(0);
		let liquidity_offset_half_life = self.params.liquidity_offset_half_life;
		let network_graph = self.network_graph.read_only();
		for hop in path {
			let target = NodeId::from_pubkey(&hop.pubkey);
			let channel_directed_from_source = network_graph.channels()
				.get(&hop.short_channel_id)
				.and_then(|channel| channel.as_directed_to(&target));

			// Only score announced channels.
			if let Some((channel, source)) = channel_directed_from_source {
				let capacity_msat = channel.effective_capacity().as_msat();
				self.channel_liquidities
					.entry(hop.short_channel_id)
					.or_insert_with(ChannelLiquidity::new)
					.as_directed_mut(source, &target, capacity_msat, liquidity_offset_half_life)
					.successful(amount_msat);
			}
		}
	}
}

impl<G: Deref<Target = NetworkGraph>, T: Time> Writeable for ProbabilisticScorerUsingTime<G, T> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(w, {
			(0, self.channel_liquidities, required)
		});
		Ok(())
	}
}

impl<G, T> ReadableArgs<(ProbabilisticScoringParameters, G)> for ProbabilisticScorerUsingTime<G, T>
where
	G: Deref<Target = NetworkGraph>,
	T: Time,
{
	#[inline]
	fn read<R: Read>(
		r: &mut R, args: (ProbabilisticScoringParameters, G)
	) -> Result<Self, DecodeError> {
		let (params, network_graph) = args;
		let mut channel_liquidities = HashMap::new();
		read_tlv_fields!(r, {
			(0, channel_liquidities, required)
		});
		Ok(Self {
			params,
			network_graph,
			channel_liquidities,
		})
	}
}

impl<T: Time> Writeable for ChannelLiquidity<T> {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let duration_since_epoch = T::duration_since_epoch() - self.last_updated.elapsed();
		write_tlv_fields!(w, {
			(0, self.min_liquidity_offset_msat, required),
			(2, self.max_liquidity_offset_msat, required),
			(4, duration_since_epoch, required),
		});
		Ok(())
	}
}

impl<T: Time> Readable for ChannelLiquidity<T> {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut min_liquidity_offset_msat = 0;
		let mut max_liquidity_offset_msat = 0;
		let mut duration_since_epoch = Duration::from_secs(0);
		read_tlv_fields!(r, {
			(0, min_liquidity_offset_msat, required),
			(2, max_liquidity_offset_msat, required),
			(4, duration_since_epoch, required),
		});
		Ok(Self {
			min_liquidity_offset_msat,
			max_liquidity_offset_msat,
			last_updated: T::now() - (T::duration_since_epoch() - duration_since_epoch),
		})
	}
}

pub(crate) mod time {
	use core::ops::Sub;
	use core::time::Duration;
	/// A measurement of time.
	pub trait Time: Copy + Sub<Duration, Output = Self> where Self: Sized {
		/// Returns an instance corresponding to the current moment.
		fn now() -> Self;

		/// Returns the amount of time elapsed since `self` was created.
		fn elapsed(&self) -> Duration;

		/// Returns the amount of time passed between `earlier` and `self`.
		fn duration_since(&self, earlier: Self) -> Duration;

		/// Returns the amount of time passed since the beginning of [`Time`].
		///
		/// Used during (de-)serialization.
		fn duration_since_epoch() -> Duration;
	}

	/// A state in which time has no meaning.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	pub struct Eternity;

	#[cfg(not(feature = "no-std"))]
	impl Time for std::time::Instant {
		fn now() -> Self {
			std::time::Instant::now()
		}

		fn duration_since(&self, earlier: Self) -> Duration {
			self.duration_since(earlier)
		}

		fn duration_since_epoch() -> Duration {
			use std::time::SystemTime;
			SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()
		}

		fn elapsed(&self) -> Duration {
			std::time::Instant::elapsed(self)
		}
	}

	impl Time for Eternity {
		fn now() -> Self {
			Self
		}

		fn duration_since(&self, _earlier: Self) -> Duration {
			Duration::from_secs(0)
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
}

pub(crate) use self::time::Time;

#[cfg(test)]
mod tests {
	use super::{ChannelLiquidity, ProbabilisticScoringParameters, ProbabilisticScorerUsingTime, ScoringParameters, ScorerUsingTime, Time};
	use super::time::Eternity;

	use ln::features::{ChannelFeatures, NodeFeatures};
	use ln::msgs::{ChannelAnnouncement, ChannelUpdate, OptionalField, UnsignedChannelAnnouncement, UnsignedChannelUpdate};
	use routing::scoring::Score;
	use routing::network_graph::{NetworkGraph, NodeId};
	use routing::router::RouteHop;
	use util::ser::{Readable, ReadableArgs, Writeable};

	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::hashes::Hash;
	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use core::cell::Cell;
	use core::ops::Sub;
	use core::time::Duration;
	use io;

	// `Time` tests

	/// Time that can be advanced manually in tests.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	struct SinceEpoch(Duration);

	impl SinceEpoch {
		thread_local! {
			static ELAPSED: Cell<Duration> = core::cell::Cell::new(Duration::from_secs(0));
		}

		fn advance(duration: Duration) {
			Self::ELAPSED.with(|elapsed| elapsed.set(elapsed.get() + duration))
		}
	}

	impl Time for SinceEpoch {
		fn now() -> Self {
			Self(Self::duration_since_epoch())
		}

		fn duration_since(&self, earlier: Self) -> Duration {
			self.0 - earlier.0
		}

		fn duration_since_epoch() -> Duration {
			Self::ELAPSED.with(|elapsed| elapsed.get())
		}

		fn elapsed(&self) -> Duration {
			Self::duration_since_epoch() - self.0
		}
	}

	impl Sub<Duration> for SinceEpoch {
		type Output = Self;

		fn sub(self, other: Duration) -> Self {
			Self(self.0 - other)
		}
	}

	#[test]
	fn time_passes_when_advanced() {
		let now = SinceEpoch::now();
		assert_eq!(now.elapsed(), Duration::from_secs(0));

		SinceEpoch::advance(Duration::from_secs(1));
		SinceEpoch::advance(Duration::from_secs(1));

		let elapsed = now.elapsed();
		let later = SinceEpoch::now();

		assert_eq!(elapsed, Duration::from_secs(2));
		assert_eq!(later - elapsed, now);
	}

	#[test]
	fn time_never_passes_in_an_eternity() {
		let now = Eternity::now();
		let elapsed = now.elapsed();
		let later = Eternity::now();

		assert_eq!(now.elapsed(), Duration::from_secs(0));
		assert_eq!(later - elapsed, now);
	}

	// `Scorer` tests

	/// A scorer for testing with time that can be manually advanced.
	type Scorer = ScorerUsingTime::<SinceEpoch>;

	fn source_privkey() -> SecretKey {
		SecretKey::from_slice(&[42; 32]).unwrap()
	}

	fn target_privkey() -> SecretKey {
		SecretKey::from_slice(&[43; 32]).unwrap()
	}

	fn source_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &source_privkey())
	}

	fn target_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &target_privkey())
	}

	fn source_node_id() -> NodeId {
		NodeId::from_pubkey(&source_pubkey())
	}

	fn target_node_id() -> NodeId {
		NodeId::from_pubkey(&target_pubkey())
	}

	#[test]
	fn penalizes_without_channel_failures() {
		let scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 1_000,
			failure_penalty_msat: 512,
			failure_penalty_half_life: Duration::from_secs(1),
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
		});
		let source = source_node_id();
		let target = target_node_id();
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);

		SinceEpoch::advance(Duration::from_secs(1));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);
	}

	#[test]
	fn accumulates_channel_failure_penalties() {
		let mut scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 1_000,
			failure_penalty_msat: 64,
			failure_penalty_half_life: Duration::from_secs(10),
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
		});
		let source = source_node_id();
		let target = target_node_id();
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_064);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_128);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_192);
	}

	#[test]
	fn decays_channel_failure_penalties_over_time() {
		let mut scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 1_000,
			failure_penalty_msat: 512,
			failure_penalty_half_life: Duration::from_secs(10),
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
		});
		let source = source_node_id();
		let target = target_node_id();
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(9));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(1));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_256);

		SinceEpoch::advance(Duration::from_secs(10 * 8));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_001);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);
	}

	#[test]
	fn decays_channel_failure_penalties_without_shift_overflow() {
		let mut scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 1_000,
			failure_penalty_msat: 512,
			failure_penalty_half_life: Duration::from_secs(10),
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
		});
		let source = source_node_id();
		let target = target_node_id();
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_512);

		// An unchecked right shift 64 bits or more in ChannelFailure::decayed_penalty_msat would
		// cause an overflow.
		SinceEpoch::advance(Duration::from_secs(10 * 64));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);
	}

	#[test]
	fn accumulates_channel_failure_penalties_after_decay() {
		let mut scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 1_000,
			failure_penalty_msat: 512,
			failure_penalty_half_life: Duration::from_secs(10),
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
		});
		let source = source_node_id();
		let target = target_node_id();
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_256);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_768);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_384);
	}

	#[test]
	fn reduces_channel_failure_penalties_after_success() {
		let mut scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 1_000,
			failure_penalty_msat: 512,
			failure_penalty_half_life: Duration::from_secs(10),
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
		});
		let source = source_node_id();
		let target = target_node_id();
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_000);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_256);

		let hop = RouteHop {
			pubkey: PublicKey::from_slice(target.as_slice()).unwrap(),
			node_features: NodeFeatures::known(),
			short_channel_id: 42,
			channel_features: ChannelFeatures::known(),
			fee_msat: 1,
			cltv_expiry_delta: 18,
		};
		scorer.payment_path_successful(&[&hop]);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_128);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_064);
	}

	#[test]
	fn restores_persisted_channel_failure_penalties() {
		let mut scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 1_000,
			failure_penalty_msat: 512,
			failure_penalty_half_life: Duration::from_secs(10),
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
		});
		let source = source_node_id();
		let target = target_node_id();

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_256);

		scorer.payment_path_failed(&[], 43);
		assert_eq!(scorer.channel_penalty_msat(43, 1, 1, &source, &target), 1_512);

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		let deserialized_scorer = <Scorer>::read(&mut io::Cursor::new(&serialized_scorer)).unwrap();
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_256);
		assert_eq!(deserialized_scorer.channel_penalty_msat(43, 1, 1, &source, &target), 1_512);
	}

	#[test]
	fn decays_persisted_channel_failure_penalties() {
		let mut scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 1_000,
			failure_penalty_msat: 512,
			failure_penalty_half_life: Duration::from_secs(10),
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
		});
		let source = source_node_id();
		let target = target_node_id();

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_512);

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		SinceEpoch::advance(Duration::from_secs(10));

		let deserialized_scorer = <Scorer>::read(&mut io::Cursor::new(&serialized_scorer)).unwrap();
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_256);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 1, 1, &source, &target), 1_128);
	}

	#[test]
	fn charges_per_1024th_penalty() {
		let scorer = Scorer::new(ScoringParameters {
			base_penalty_msat: 0,
			failure_penalty_msat: 0,
			failure_penalty_half_life: Duration::from_secs(0),
			overuse_penalty_start_1024th: 256,
			overuse_penalty_msat_per_1024th: 100,
		});
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 1_000, 1_024_000, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 256_999, 1_024_000, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 257_000, 1_024_000, &source, &target), 100);
		assert_eq!(scorer.channel_penalty_msat(42, 258_000, 1_024_000, &source, &target), 200);
		assert_eq!(scorer.channel_penalty_msat(42, 512_000, 1_024_000, &source, &target), 256 * 100);
	}

	// `ProbabilisticScorer` tests

	/// A probabilistic scorer for testing with time that can be manually advanced.
	type ProbabilisticScorer<'a> = ProbabilisticScorerUsingTime::<&'a NetworkGraph, SinceEpoch>;

	fn sender_privkey() -> SecretKey {
		SecretKey::from_slice(&[41; 32]).unwrap()
	}

	fn recipient_privkey() -> SecretKey {
		SecretKey::from_slice(&[45; 32]).unwrap()
	}

	fn sender_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &sender_privkey())
	}

	fn recipient_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &recipient_privkey())
	}

	fn sender_node_id() -> NodeId {
		NodeId::from_pubkey(&sender_pubkey())
	}

	fn recipient_node_id() -> NodeId {
		NodeId::from_pubkey(&recipient_pubkey())
	}

	fn network_graph() -> NetworkGraph {
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let mut network_graph = NetworkGraph::new(genesis_hash);
		add_channel(&mut network_graph, 42, source_privkey(), target_privkey());
		add_channel(&mut network_graph, 43, target_privkey(), recipient_privkey());

		network_graph
	}

	fn add_channel(
		network_graph: &mut NetworkGraph, short_channel_id: u64, node_1_key: SecretKey,
		node_2_key: SecretKey
	) {
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let node_1_secret = &SecretKey::from_slice(&[39; 32]).unwrap();
		let node_2_secret = &SecretKey::from_slice(&[40; 32]).unwrap();
		let secp_ctx = Secp256k1::new();
		let unsigned_announcement = UnsignedChannelAnnouncement {
			features: ChannelFeatures::known(),
			chain_hash: genesis_hash,
			short_channel_id,
			node_id_1: PublicKey::from_secret_key(&secp_ctx, &node_1_key),
			node_id_2: PublicKey::from_secret_key(&secp_ctx, &node_2_key),
			bitcoin_key_1: PublicKey::from_secret_key(&secp_ctx, &node_1_secret),
			bitcoin_key_2: PublicKey::from_secret_key(&secp_ctx, &node_2_secret),
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let signed_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, &node_1_key),
			node_signature_2: secp_ctx.sign(&msghash, &node_2_key),
			bitcoin_signature_1: secp_ctx.sign(&msghash, &node_1_secret),
			bitcoin_signature_2: secp_ctx.sign(&msghash, &node_2_secret),
			contents: unsigned_announcement,
		};
		let chain_source: Option<&::util::test_utils::TestChainSource> = None;
		network_graph.update_channel_from_announcement(
			&signed_announcement, &chain_source, &secp_ctx).unwrap();
		update_channel(network_graph, short_channel_id, node_1_key, 0);
		update_channel(network_graph, short_channel_id, node_2_key, 1);
	}

	fn update_channel(
		network_graph: &mut NetworkGraph, short_channel_id: u64, node_key: SecretKey, flags: u8
	) {
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let secp_ctx = Secp256k1::new();
		let unsigned_update = UnsignedChannelUpdate {
			chain_hash: genesis_hash,
			short_channel_id,
			timestamp: 100,
			flags,
			cltv_expiry_delta: 18,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Present(1_000),
			fee_base_msat: 1,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_update.encode()[..])[..]);
		let signed_update = ChannelUpdate {
			signature: secp_ctx.sign(&msghash, &node_key),
			contents: unsigned_update,
		};
		network_graph.update_channel(&signed_update, &secp_ctx).unwrap();
	}

	fn payment_path_for_amount(amount_msat: u64) -> Vec<RouteHop> {
		vec![
			RouteHop {
				pubkey: source_pubkey(),
				node_features: NodeFeatures::known(),
				short_channel_id: 41,
				channel_features: ChannelFeatures::known(),
				fee_msat: 1,
				cltv_expiry_delta: 18,
			},
			RouteHop {
				pubkey: target_pubkey(),
				node_features: NodeFeatures::known(),
				short_channel_id: 42,
				channel_features: ChannelFeatures::known(),
				fee_msat: 2,
				cltv_expiry_delta: 18,
			},
			RouteHop {
				pubkey: recipient_pubkey(),
				node_features: NodeFeatures::known(),
				short_channel_id: 43,
				channel_features: ChannelFeatures::known(),
				fee_msat: amount_msat,
				cltv_expiry_delta: 18,
			},
		]
	}

	#[test]
	fn liquidity_bounds_directed_from_lowest_node_id() {
		let last_updated = SinceEpoch::now();
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters::default();
		let mut scorer = ProbabilisticScorer::new(params, &network_graph)
			.with_channel(42,
				ChannelLiquidity {
					min_liquidity_offset_msat: 700, max_liquidity_offset_msat: 100, last_updated
				})
			.with_channel(43,
				ChannelLiquidity {
					min_liquidity_offset_msat: 700, max_liquidity_offset_msat: 100, last_updated
				});
		let source = source_node_id();
		let target = target_node_id();
		let recipient = recipient_node_id();
		assert!(source > target);
		assert!(target < recipient);

		// Update minimum liquidity.

		let liquidity_offset_half_life = scorer.params.liquidity_offset_half_life;
		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 100);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 900);

		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000, liquidity_offset_half_life)
			.set_min_liquidity_msat(200);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		// Update maximum liquidity.

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&target, &recipient, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 900);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&recipient, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 100);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		scorer.channel_liquidities.get_mut(&43).unwrap()
			.as_directed_mut(&target, &recipient, 1_000, liquidity_offset_half_life)
			.set_max_liquidity_msat(200);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&target, &recipient, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 200);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&recipient, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 800);
		assert_eq!(liquidity.max_liquidity_msat(), 1000);
	}

	#[test]
	fn resets_liquidity_upper_bound_when_crossed_by_lower_bound() {
		let last_updated = SinceEpoch::now();
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters::default();
		let mut scorer = ProbabilisticScorer::new(params, &network_graph)
			.with_channel(42,
				ChannelLiquidity {
					min_liquidity_offset_msat: 200, max_liquidity_offset_msat: 400, last_updated
				});
		let source = source_node_id();
		let target = target_node_id();
		assert!(source > target);

		// Check initial bounds.
		let liquidity_offset_half_life = scorer.params.liquidity_offset_half_life;
		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		// Reset from source to target.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000, liquidity_offset_half_life)
			.set_min_liquidity_msat(900);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 900);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 100);

		// Reset from target to source.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&target, &source, 1_000, liquidity_offset_half_life)
			.set_min_liquidity_msat(400);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);
	}

	#[test]
	fn resets_liquidity_lower_bound_when_crossed_by_upper_bound() {
		let last_updated = SinceEpoch::now();
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters::default();
		let mut scorer = ProbabilisticScorer::new(params, &network_graph)
			.with_channel(42,
				ChannelLiquidity {
					min_liquidity_offset_msat: 200, max_liquidity_offset_msat: 400, last_updated
				});
		let source = source_node_id();
		let target = target_node_id();
		assert!(source > target);

		// Check initial bounds.
		let liquidity_offset_half_life = scorer.params.liquidity_offset_half_life;
		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		// Reset from source to target.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000, liquidity_offset_half_life)
			.set_max_liquidity_msat(300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		// Reset from target to source.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&target, &source, 1_000, liquidity_offset_half_life)
			.set_max_liquidity_msat(600);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, liquidity_offset_half_life);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 600);
	}

	#[test]
	fn increased_penalty_nearing_liquidity_upper_bound() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000, ..Default::default()
		};
		let scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 100, 100_000, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 1_000, 100_000, &source, &target), 4);
		assert_eq!(scorer.channel_penalty_msat(42, 10_000, 100_000, &source, &target), 45);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000, 100_000, &source, &target), 2_000);

		assert_eq!(scorer.channel_penalty_msat(42, 125, 1_000, &source, &target), 57);
		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 124);
		assert_eq!(scorer.channel_penalty_msat(42, 375, 1_000, &source, &target), 203);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(42, 625, 1_000, &source, &target), 425);
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), 600);
		assert_eq!(scorer.channel_penalty_msat(42, 875, 1_000, &source, &target), 900);
	}

	#[test]
	fn constant_penalty_outside_liquidity_bounds() {
		let last_updated = SinceEpoch::now();
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000, ..Default::default()
		};
		let scorer = ProbabilisticScorer::new(params, &network_graph)
			.with_channel(42,
				ChannelLiquidity {
					min_liquidity_offset_msat: 40, max_liquidity_offset_msat: 40, last_updated
				});
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 39, 100, &source, &target), 0);
		assert_ne!(scorer.channel_penalty_msat(42, 50, 100, &source, &target), 0);
		assert_ne!(scorer.channel_penalty_msat(42, 50, 100, &source, &target), 2_000);
		assert_eq!(scorer.channel_penalty_msat(42, 61, 100, &source, &target), 2_000);
	}

	#[test]
	fn does_not_further_penalize_own_channel() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000, ..Default::default()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let sender = sender_node_id();
		let source = source_node_id();
		let failed_path = payment_path_for_amount(500);
		let successful_path = payment_path_for_amount(200);

		assert_eq!(scorer.channel_penalty_msat(41, 500, 1_000, &sender, &source), 300);

		scorer.payment_path_failed(&failed_path.iter().collect::<Vec<_>>(), 41);
		assert_eq!(scorer.channel_penalty_msat(41, 500, 1_000, &sender, &source), 300);

		scorer.payment_path_successful(&successful_path.iter().collect::<Vec<_>>());
		assert_eq!(scorer.channel_penalty_msat(41, 500, 1_000, &sender, &source), 300);
	}

	#[test]
	fn sets_liquidity_lower_bound_on_downstream_failure() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000, ..Default::default()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();
		let path = payment_path_for_amount(500);

		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 124);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), 600);

		scorer.payment_path_failed(&path.iter().collect::<Vec<_>>(), 43);

		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), 300);
	}

	#[test]
	fn sets_liquidity_upper_bound_on_failure() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000, ..Default::default()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();
		let path = payment_path_for_amount(500);

		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 124);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), 600);

		scorer.payment_path_failed(&path.iter().collect::<Vec<_>>(), 42);

		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 2_000);
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), 2_000);
	}

	#[test]
	fn reduces_liquidity_upper_bound_along_path_on_success() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000, ..Default::default()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let sender = sender_node_id();
		let source = source_node_id();
		let target = target_node_id();
		let recipient = recipient_node_id();
		let path = payment_path_for_amount(500);

		assert_eq!(scorer.channel_penalty_msat(41, 250, 1_000, &sender, &source), 124);
		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 124);
		assert_eq!(scorer.channel_penalty_msat(43, 250, 1_000, &target, &recipient), 124);

		scorer.payment_path_successful(&path.iter().collect::<Vec<_>>());

		assert_eq!(scorer.channel_penalty_msat(41, 250, 1_000, &sender, &source), 124);
		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(43, 250, 1_000, &target, &recipient), 300);
	}

	#[test]
	fn decays_liquidity_bounds_over_time() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_offset_half_life: Duration::from_secs(10),
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 0, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 1_024, 1_024, &source, &target), 2_000);

		scorer.payment_path_failed(&payment_path_for_amount(768).iter().collect::<Vec<_>>(), 42);
		scorer.payment_path_failed(&payment_path_for_amount(128).iter().collect::<Vec<_>>(), 43);

		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 92);
		assert_eq!(scorer.channel_penalty_msat(42, 768, 1_024, &source, &target), 1_424);
		assert_eq!(scorer.channel_penalty_msat(42, 896, 1_024, &source, &target), 2_000);

		SinceEpoch::advance(Duration::from_secs(9));
		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 92);
		assert_eq!(scorer.channel_penalty_msat(42, 768, 1_024, &source, &target), 1_424);
		assert_eq!(scorer.channel_penalty_msat(42, 896, 1_024, &source, &target), 2_000);

		SinceEpoch::advance(Duration::from_secs(1));
		assert_eq!(scorer.channel_penalty_msat(42, 64, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 34);
		assert_eq!(scorer.channel_penalty_msat(42, 896, 1_024, &source, &target), 1_812);
		assert_eq!(scorer.channel_penalty_msat(42, 960, 1_024, &source, &target), 2_000);

		// Fully decay liquidity lower bound.
		SinceEpoch::advance(Duration::from_secs(10 * 7));
		assert_eq!(scorer.channel_penalty_msat(42, 0, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 1, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 1_023, 1_024, &source, &target), 2_000);
		assert_eq!(scorer.channel_penalty_msat(42, 1_024, 1_024, &source, &target), 2_000);

		// Fully decay liquidity upper bound.
		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 0, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 1_024, 1_024, &source, &target), 2_000);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 0, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 1_024, 1_024, &source, &target), 2_000);
	}

	#[test]
	fn decays_liquidity_bounds_without_shift_overflow() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_offset_half_life: Duration::from_secs(10),
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 124);

		scorer.payment_path_failed(&payment_path_for_amount(512).iter().collect::<Vec<_>>(), 42);
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 281);

		// An unchecked right shift 64 bits or more in DirectedChannelLiquidity::decayed_offset_msat
		// would cause an overflow.
		SinceEpoch::advance(Duration::from_secs(10 * 64));
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 124);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 124);
	}

	#[test]
	fn restricts_liquidity_bounds_after_decay() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_offset_half_life: Duration::from_secs(10),
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 300);

		// More knowledge gives higher confidence (256, 768), meaning a lower penalty.
		scorer.payment_path_failed(&payment_path_for_amount(768).iter().collect::<Vec<_>>(), 42);
		scorer.payment_path_failed(&payment_path_for_amount(256).iter().collect::<Vec<_>>(), 43);
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 281);

		// Decaying knowledge gives less confidence (128, 896), meaning a higher penalty.
		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 293);

		// Reducing the upper bound gives more confidence (128, 832) that the payment amount (512)
		// is closer to the upper bound, meaning a higher penalty.
		scorer.payment_path_successful(&payment_path_for_amount(64).iter().collect::<Vec<_>>());
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 333);

		// Increasing the lower bound gives more confidence (256, 832) that the payment amount (512)
		// is closer to the lower bound, meaning a lower penalty.
		scorer.payment_path_failed(&payment_path_for_amount(256).iter().collect::<Vec<_>>(), 43);
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 247);

		// Further decaying affects the lower bound more than the upper bound (128, 928).
		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 280);
	}

	#[test]
	fn restores_persisted_liquidity_bounds() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_offset_half_life: Duration::from_secs(10),
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		scorer.payment_path_failed(&payment_path_for_amount(500).iter().collect::<Vec<_>>(), 42);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 2_000);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 475);

		scorer.payment_path_failed(&payment_path_for_amount(250).iter().collect::<Vec<_>>(), 43);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		let mut serialized_scorer = io::Cursor::new(&serialized_scorer);
		let deserialized_scorer =
			<ProbabilisticScorer>::read(&mut serialized_scorer, (params, &network_graph)).unwrap();
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);
	}

	#[test]
	fn decays_persisted_liquidity_bounds() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_offset_half_life: Duration::from_secs(10),
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		scorer.payment_path_failed(&payment_path_for_amount(500).iter().collect::<Vec<_>>(), 42);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 2_000);

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		SinceEpoch::advance(Duration::from_secs(10));

		let mut serialized_scorer = io::Cursor::new(&serialized_scorer);
		let deserialized_scorer =
			<ProbabilisticScorer>::read(&mut serialized_scorer, (params, &network_graph)).unwrap();
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 475);

		scorer.payment_path_failed(&payment_path_for_amount(250).iter().collect::<Vec<_>>(), 43);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 367);
	}
}
