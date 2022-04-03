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
//! # use lightning::chain::keysinterface::{KeysManager, KeysInterface};
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
//! # let random_seed_bytes = [42u8; 32];
//!
//! let route = find_route(&payer, &route_params, &network_graph, None, &logger, &scorer, &random_seed_bytes);
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

#[derive(Clone)]
/// [`Score`] implementation that uses a fixed penalty.
pub struct FixedPenaltyScorer {
	penalty_msat: u64,
}

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

impl Writeable for FixedPenaltyScorer {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(w, {});
		Ok(())
	}
}

impl ReadableArgs<u64> for FixedPenaltyScorer {
	#[inline]
	fn read<R: Read>(r: &mut R, penalty_msat: u64) -> Result<Self, DecodeError> {
		read_tlv_fields!(r, {});
		Ok(Self { penalty_msat })
	}
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
pub struct ScorerUsingTime<T: Time> {
	params: ScoringParameters,
	// TODO: Remove entries of closed channels.
	channel_failures: HashMap<u64, ChannelFailure<T>>,
}

#[derive(Clone)]
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
pub struct ProbabilisticScorerUsingTime<G: Deref<Target = NetworkGraph>, T: Time> {
	params: ProbabilisticScoringParameters,
	network_graph: G,
	// TODO: Remove entries of closed channels.
	channel_liquidities: HashMap<u64, ChannelLiquidity<T>>,
}

/// Parameters for configuring [`ProbabilisticScorer`].
///
/// Used to configure base, liquidity, and amount penalties, the sum of which comprises the channel
/// penalty (i.e., the amount in msats willing to be paid to avoid routing through the channel).
#[derive(Clone, Copy)]
pub struct ProbabilisticScoringParameters {
	/// A fixed penalty in msats to apply to each channel.
	///
	/// Default value: 500 msat
	pub base_penalty_msat: u64,

	/// A multiplier used in conjunction with the negative `log10` of the channel's success
	/// probability for a payment to determine the liquidity penalty.
	///
	/// The penalty is based in part on the knowledge learned from prior successful and unsuccessful
	/// payments. This knowledge is decayed over time based on [`liquidity_offset_half_life`]. The
	/// penalty is effectively limited to `2 * liquidity_penalty_multiplier_msat` (corresponding to
	/// lower bounding the success probability to `0.01`) when the amount falls within the
	/// uncertainty bounds of the channel liquidity balance. Amounts above the upper bound will
	/// result in a `u64::max_value` penalty, however.
	///
	/// Default value: 40,000 msat
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

	/// A multiplier used in conjunction with a payment amount and the negative `log10` of the
	/// channel's success probability for the payment to determine the amount penalty.
	///
	/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
	/// fees plus penalty) for large payments. The penalty is computed as the product of this
	/// multiplier and `2^20`ths of the payment amount, weighted by the negative `log10` of the
	/// success probability.
	///
	/// `-log10(success_probability) * amount_penalty_multiplier_msat * amount_msat / 2^20`
	///
	/// In practice, this means for 0.1 success probability (`-log10(0.1) == 1`) each `2^20`th of
	/// the amount will result in a penalty of the multiplier. And, as the success probability
	/// decreases, the negative `log10` weighting will increase dramatically. For higher success
	/// probabilities, the multiplier will have a decreasing effect as the negative `log10` will
	/// fall below `1`.
	///
	/// Default value: 256 msat
	pub amount_penalty_multiplier_msat: u64,
}

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

impl ProbabilisticScoringParameters {
	#[cfg(test)]
	fn zero_penalty() -> Self {
		Self {
			base_penalty_msat: 0,
			liquidity_penalty_multiplier_msat: 0,
			liquidity_offset_half_life: Duration::from_secs(3600),
			amount_penalty_multiplier_msat: 0,
		}
	}
}

impl Default for ProbabilisticScoringParameters {
	fn default() -> Self {
		Self {
			base_penalty_msat: 500,
			liquidity_penalty_multiplier_msat: 40_000,
			liquidity_offset_half_life: Duration::from_secs(3600),
			amount_penalty_multiplier_msat: 256,
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

/// Bounds `-log10` to avoid excessive liquidity penalties for payments with low success
/// probabilities.
const NEGATIVE_LOG10_UPPER_BOUND: u64 = 2;

/// The divisor used when computing the amount penalty.
const AMOUNT_PENALTY_DIVISOR: u64 = 1 << 20;

impl<L: Deref<Target = u64>, T: Time, U: Deref<Target = T>> DirectedChannelLiquidity<L, T, U> {
	/// Returns a penalty for routing the given HTLC `amount_msat` through the channel in this
	/// direction.
	fn penalty_msat(&self, amount_msat: u64, params: ProbabilisticScoringParameters) -> u64 {
		let max_liquidity_msat = self.max_liquidity_msat();
		let min_liquidity_msat = core::cmp::min(self.min_liquidity_msat(), max_liquidity_msat);
		if amount_msat <= min_liquidity_msat {
			0
		} else if amount_msat >= max_liquidity_msat {
			if amount_msat > max_liquidity_msat {
				u64::max_value()
			} else if max_liquidity_msat != self.capacity_msat {
				// Avoid using the failed channel on retry.
				u64::max_value()
			} else {
				// Equivalent to hitting the else clause below with the amount equal to the
				// effective capacity and without any certainty on the liquidity upper bound.
				let negative_log10_times_1024 = NEGATIVE_LOG10_UPPER_BOUND * 1024;
				self.combined_penalty_msat(amount_msat, negative_log10_times_1024, params)
			}
		} else {
			let numerator = (max_liquidity_msat - amount_msat).saturating_add(1);
			let denominator = (max_liquidity_msat - min_liquidity_msat).saturating_add(1);
			let negative_log10_times_1024 =
				approx::negative_log10_times_1024(numerator, denominator);
			self.combined_penalty_msat(amount_msat, negative_log10_times_1024, params)
		}
	}

	/// Computes the liquidity and amount penalties and adds them to the base penalty.
	#[inline(always)]
	fn combined_penalty_msat(
		&self, amount_msat: u64, negative_log10_times_1024: u64,
		params: ProbabilisticScoringParameters
	) -> u64 {
		let liquidity_penalty_msat = {
			// Upper bound the liquidity penalty to ensure some channel is selected.
			let multiplier_msat = params.liquidity_penalty_multiplier_msat;
			let max_penalty_msat = multiplier_msat.saturating_mul(NEGATIVE_LOG10_UPPER_BOUND);
			(negative_log10_times_1024.saturating_mul(multiplier_msat) / 1024).min(max_penalty_msat)
		};
		let amount_penalty_msat = negative_log10_times_1024
			.saturating_mul(params.amount_penalty_multiplier_msat)
			.saturating_mul(amount_msat) / 1024 / AMOUNT_PENALTY_DIVISOR;

		params.base_penalty_msat
			.saturating_add(liquidity_penalty_msat)
			.saturating_add(amount_penalty_msat)
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
		let liquidity_offset_half_life = self.params.liquidity_offset_half_life;
		self.channel_liquidities
			.get(&short_channel_id)
			.unwrap_or(&ChannelLiquidity::new())
			.as_directed(source, target, capacity_msat, liquidity_offset_half_life)
			.penalty_msat(amount_msat, self.params)
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

mod approx {
	const BITS: u32 = 64;
	const HIGHEST_BIT: u32 = BITS - 1;
	const LOWER_BITS: u32 = 4;
	const LOWER_BITS_BOUND: u64 = 1 << LOWER_BITS;
	const LOWER_BITMASK: u64 = (1 << LOWER_BITS) - 1;

	/// Look-up table for `log10(x) * 1024` where row `i` is used for each `x` having `i` as the
	/// most significant bit. The next 4 bits of `x`, if applicable, are used for the second index.
	const LOG10_TIMES_1024: [[u16; LOWER_BITS_BOUND as usize]; BITS as usize] = [
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
		[308, 308, 308, 308, 308, 308, 308, 308, 489, 489, 489, 489, 489, 489, 489, 489],
		[617, 617, 617, 617, 716, 716, 716, 716, 797, 797, 797, 797, 865, 865, 865, 865],
		[925, 925, 977, 977, 1024, 1024, 1066, 1066, 1105, 1105, 1141, 1141, 1174, 1174, 1204, 1204],
		[1233, 1260, 1285, 1309, 1332, 1354, 1375, 1394, 1413, 1431, 1449, 1466, 1482, 1497, 1513, 1527],
		[1541, 1568, 1594, 1618, 1641, 1662, 1683, 1703, 1722, 1740, 1757, 1774, 1790, 1806, 1821, 1835],
		[1850, 1876, 1902, 1926, 1949, 1970, 1991, 2011, 2030, 2048, 2065, 2082, 2098, 2114, 2129, 2144],
		[2158, 2185, 2210, 2234, 2257, 2279, 2299, 2319, 2338, 2356, 2374, 2390, 2407, 2422, 2437, 2452],
		[2466, 2493, 2518, 2542, 2565, 2587, 2608, 2627, 2646, 2665, 2682, 2699, 2715, 2731, 2746, 2760],
		[2774, 2801, 2827, 2851, 2874, 2895, 2916, 2936, 2955, 2973, 2990, 3007, 3023, 3039, 3054, 3068],
		[3083, 3110, 3135, 3159, 3182, 3203, 3224, 3244, 3263, 3281, 3298, 3315, 3331, 3347, 3362, 3377],
		[3391, 3418, 3443, 3467, 3490, 3512, 3532, 3552, 3571, 3589, 3607, 3623, 3640, 3655, 3670, 3685],
		[3699, 3726, 3751, 3775, 3798, 3820, 3841, 3860, 3879, 3898, 3915, 3932, 3948, 3964, 3979, 3993],
		[4007, 4034, 4060, 4084, 4107, 4128, 4149, 4169, 4188, 4206, 4223, 4240, 4256, 4272, 4287, 4301],
		[4316, 4343, 4368, 4392, 4415, 4436, 4457, 4477, 4496, 4514, 4531, 4548, 4564, 4580, 4595, 4610],
		[4624, 4651, 4676, 4700, 4723, 4745, 4765, 4785, 4804, 4822, 4840, 4857, 4873, 4888, 4903, 4918],
		[4932, 4959, 4984, 5009, 5031, 5053, 5074, 5093, 5112, 5131, 5148, 5165, 5181, 5197, 5212, 5226],
		[5240, 5267, 5293, 5317, 5340, 5361, 5382, 5402, 5421, 5439, 5456, 5473, 5489, 5505, 5520, 5534],
		[5549, 5576, 5601, 5625, 5648, 5670, 5690, 5710, 5729, 5747, 5764, 5781, 5797, 5813, 5828, 5843],
		[5857, 5884, 5909, 5933, 5956, 5978, 5998, 6018, 6037, 6055, 6073, 6090, 6106, 6121, 6136, 6151],
		[6165, 6192, 6217, 6242, 6264, 6286, 6307, 6326, 6345, 6364, 6381, 6398, 6414, 6430, 6445, 6459],
		[6473, 6500, 6526, 6550, 6573, 6594, 6615, 6635, 6654, 6672, 6689, 6706, 6722, 6738, 6753, 6767],
		[6782, 6809, 6834, 6858, 6881, 6903, 6923, 6943, 6962, 6980, 6998, 7014, 7030, 7046, 7061, 7076],
		[7090, 7117, 7142, 7166, 7189, 7211, 7231, 7251, 7270, 7288, 7306, 7323, 7339, 7354, 7369, 7384],
		[7398, 7425, 7450, 7475, 7497, 7519, 7540, 7560, 7578, 7597, 7614, 7631, 7647, 7663, 7678, 7692],
		[7706, 7733, 7759, 7783, 7806, 7827, 7848, 7868, 7887, 7905, 7922, 7939, 7955, 7971, 7986, 8001],
		[8015, 8042, 8067, 8091, 8114, 8136, 8156, 8176, 8195, 8213, 8231, 8247, 8263, 8279, 8294, 8309],
		[8323, 8350, 8375, 8399, 8422, 8444, 8464, 8484, 8503, 8521, 8539, 8556, 8572, 8587, 8602, 8617],
		[8631, 8658, 8684, 8708, 8730, 8752, 8773, 8793, 8811, 8830, 8847, 8864, 8880, 8896, 8911, 8925],
		[8939, 8966, 8992, 9016, 9039, 9060, 9081, 9101, 9120, 9138, 9155, 9172, 9188, 9204, 9219, 9234],
		[9248, 9275, 9300, 9324, 9347, 9369, 9389, 9409, 9428, 9446, 9464, 9480, 9497, 9512, 9527, 9542],
		[9556, 9583, 9608, 9632, 9655, 9677, 9698, 9717, 9736, 9754, 9772, 9789, 9805, 9820, 9835, 9850],
		[9864, 9891, 9917, 9941, 9963, 9985, 10006, 10026, 10044, 10063, 10080, 10097, 10113, 10129, 10144, 10158],
		[10172, 10199, 10225, 10249, 10272, 10293, 10314, 10334, 10353, 10371, 10388, 10405, 10421, 10437, 10452, 10467],
		[10481, 10508, 10533, 10557, 10580, 10602, 10622, 10642, 10661, 10679, 10697, 10713, 10730, 10745, 10760, 10775],
		[10789, 10816, 10841, 10865, 10888, 10910, 10931, 10950, 10969, 10987, 11005, 11022, 11038, 11053, 11068, 11083],
		[11097, 11124, 11150, 11174, 11196, 11218, 11239, 11259, 11277, 11296, 11313, 11330, 11346, 11362, 11377, 11391],
		[11405, 11432, 11458, 11482, 11505, 11526, 11547, 11567, 11586, 11604, 11621, 11638, 11654, 11670, 11685, 11700],
		[11714, 11741, 11766, 11790, 11813, 11835, 11855, 11875, 11894, 11912, 11930, 11946, 11963, 11978, 11993, 12008],
		[12022, 12049, 12074, 12098, 12121, 12143, 12164, 12183, 12202, 12220, 12238, 12255, 12271, 12286, 12301, 12316],
		[12330, 12357, 12383, 12407, 12429, 12451, 12472, 12492, 12511, 12529, 12546, 12563, 12579, 12595, 12610, 12624],
		[12638, 12665, 12691, 12715, 12738, 12759, 12780, 12800, 12819, 12837, 12854, 12871, 12887, 12903, 12918, 12933],
		[12947, 12974, 12999, 13023, 13046, 13068, 13088, 13108, 13127, 13145, 13163, 13179, 13196, 13211, 13226, 13241],
		[13255, 13282, 13307, 13331, 13354, 13376, 13397, 13416, 13435, 13453, 13471, 13488, 13504, 13519, 13535, 13549],
		[13563, 13590, 13616, 13640, 13662, 13684, 13705, 13725, 13744, 13762, 13779, 13796, 13812, 13828, 13843, 13857],
		[13871, 13898, 13924, 13948, 13971, 13992, 14013, 14033, 14052, 14070, 14087, 14104, 14120, 14136, 14151, 14166],
		[14180, 14207, 14232, 14256, 14279, 14301, 14321, 14341, 14360, 14378, 14396, 14412, 14429, 14444, 14459, 14474],
		[14488, 14515, 14540, 14564, 14587, 14609, 14630, 14649, 14668, 14686, 14704, 14721, 14737, 14752, 14768, 14782],
		[14796, 14823, 14849, 14873, 14895, 14917, 14938, 14958, 14977, 14995, 15012, 15029, 15045, 15061, 15076, 15090],
		[15104, 15131, 15157, 15181, 15204, 15225, 15246, 15266, 15285, 15303, 15320, 15337, 15353, 15369, 15384, 15399],
		[15413, 15440, 15465, 15489, 15512, 15534, 15554, 15574, 15593, 15611, 15629, 15645, 15662, 15677, 15692, 15707],
		[15721, 15748, 15773, 15797, 15820, 15842, 15863, 15882, 15901, 15919, 15937, 15954, 15970, 15985, 16001, 16015],
		[16029, 16056, 16082, 16106, 16128, 16150, 16171, 16191, 16210, 16228, 16245, 16262, 16278, 16294, 16309, 16323],
		[16337, 16364, 16390, 16414, 16437, 16458, 16479, 16499, 16518, 16536, 16553, 16570, 16586, 16602, 16617, 16632],
		[16646, 16673, 16698, 16722, 16745, 16767, 16787, 16807, 16826, 16844, 16862, 16878, 16895, 16910, 16925, 16940],
		[16954, 16981, 17006, 17030, 17053, 17075, 17096, 17115, 17134, 17152, 17170, 17187, 17203, 17218, 17234, 17248],
		[17262, 17289, 17315, 17339, 17361, 17383, 17404, 17424, 17443, 17461, 17478, 17495, 17511, 17527, 17542, 17556],
		[17571, 17597, 17623, 17647, 17670, 17691, 17712, 17732, 17751, 17769, 17786, 17803, 17819, 17835, 17850, 17865],
		[17879, 17906, 17931, 17955, 17978, 18000, 18020, 18040, 18059, 18077, 18095, 18111, 18128, 18143, 18158, 18173],
		[18187, 18214, 18239, 18263, 18286, 18308, 18329, 18348, 18367, 18385, 18403, 18420, 18436, 18452, 18467, 18481],
		[18495, 18522, 18548, 18572, 18595, 18616, 18637, 18657, 18676, 18694, 18711, 18728, 18744, 18760, 18775, 18789],
		[18804, 18830, 18856, 18880, 18903, 18924, 18945, 18965, 18984, 19002, 19019, 19036, 19052, 19068, 19083, 19098],
		[19112, 19139, 19164, 19188, 19211, 19233, 19253, 19273, 19292, 19310, 19328, 19344, 19361, 19376, 19391, 19406],
		[19420, 19447, 19472, 19496, 19519, 19541, 19562, 19581, 19600, 19619, 19636, 19653, 19669, 19685, 19700, 19714],
	];

	/// Approximate `log10(numerator / denominator) * 1024` using a look-up table.
	#[inline]
	pub fn negative_log10_times_1024(numerator: u64, denominator: u64) -> u64 {
		// Multiply the -1 through to avoid needing to use signed numbers.
		(log10_times_1024(denominator) - log10_times_1024(numerator)) as u64
	}

	#[inline]
	fn log10_times_1024(x: u64) -> u16 {
		debug_assert_ne!(x, 0);
		let most_significant_bit = HIGHEST_BIT - x.leading_zeros();
		let lower_bits = (x >> most_significant_bit.saturating_sub(LOWER_BITS)) & LOWER_BITMASK;
		LOG10_TIMES_1024[most_significant_bit as usize][lower_bits as usize]
	}

	#[cfg(test)]
	mod tests {
		use super::*;

		#[test]
		fn prints_negative_log10_times_1024_lookup_table() {
			for msb in 0..BITS {
				for i in 0..LOWER_BITS_BOUND {
					let x = ((LOWER_BITS_BOUND + i) << (HIGHEST_BIT - LOWER_BITS)) >> (HIGHEST_BIT - msb);
					let log10_times_1024 = ((x as f64).log10() * 1024.0).round() as u16;
					assert_eq!(log10_times_1024, LOG10_TIMES_1024[msb as usize][i as usize]);

					if i % LOWER_BITS_BOUND == 0 {
						print!("\t\t[{}, ", log10_times_1024);
					} else if i % LOWER_BITS_BOUND == LOWER_BITS_BOUND - 1 {
						println!("{}],", log10_times_1024);
					} else {
						print!("{}, ", log10_times_1024);
					}
				}
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

impl<G: Deref<Target = NetworkGraph>, T: Time>
ReadableArgs<(ProbabilisticScoringParameters, G)> for ProbabilisticScorerUsingTime<G, T> {
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
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 1_024, 1_024_000, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 10_240, 1_024_000, &source, &target), 14);
		assert_eq!(scorer.channel_penalty_msat(42, 102_400, 1_024_000, &source, &target), 43);
		assert_eq!(scorer.channel_penalty_msat(42, 1_024_000, 1_024_000, &source, &target), 2_000);

		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 58);
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 125);
		assert_eq!(scorer.channel_penalty_msat(42, 374, 1_024, &source, &target), 204);
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 301);
		assert_eq!(scorer.channel_penalty_msat(42, 640, 1_024, &source, &target), 426);
		assert_eq!(scorer.channel_penalty_msat(42, 768, 1_024, &source, &target), 602);
		assert_eq!(scorer.channel_penalty_msat(42, 896, 1_024, &source, &target), 903);
	}

	#[test]
	fn constant_penalty_outside_liquidity_bounds() {
		let last_updated = SinceEpoch::now();
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringParameters::zero_penalty()
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
		assert_ne!(scorer.channel_penalty_msat(42, 50, 100, &source, &target), u64::max_value());
		assert_eq!(scorer.channel_penalty_msat(42, 61, 100, &source, &target), u64::max_value());
	}

	#[test]
	fn does_not_further_penalize_own_channel() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringParameters::zero_penalty()
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
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();
		let path = payment_path_for_amount(500);

		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 128);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), 601);

		scorer.payment_path_failed(&path.iter().collect::<Vec<_>>(), 43);

		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), 300);
	}

	#[test]
	fn sets_liquidity_upper_bound_on_failure() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();
		let path = payment_path_for_amount(500);

		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 128);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), 601);

		scorer.payment_path_failed(&path.iter().collect::<Vec<_>>(), 42);

		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), u64::max_value());
		assert_eq!(scorer.channel_penalty_msat(42, 750, 1_000, &source, &target), u64::max_value());
	}

	#[test]
	fn reduces_liquidity_upper_bound_along_path_on_success() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let sender = sender_node_id();
		let source = source_node_id();
		let target = target_node_id();
		let recipient = recipient_node_id();
		let path = payment_path_for_amount(500);

		assert_eq!(scorer.channel_penalty_msat(41, 250, 1_000, &sender, &source), 128);
		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 128);
		assert_eq!(scorer.channel_penalty_msat(43, 250, 1_000, &target, &recipient), 128);

		scorer.payment_path_successful(&path.iter().collect::<Vec<_>>());

		assert_eq!(scorer.channel_penalty_msat(41, 250, 1_000, &sender, &source), 128);
		assert_eq!(scorer.channel_penalty_msat(42, 250, 1_000, &source, &target), 300);
		assert_eq!(scorer.channel_penalty_msat(43, 250, 1_000, &target, &recipient), 300);
	}

	#[test]
	fn decays_liquidity_bounds_over_time() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_offset_half_life: Duration::from_secs(10),
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 0, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 1_024, 1_024, &source, &target), 2_000);

		scorer.payment_path_failed(&payment_path_for_amount(768).iter().collect::<Vec<_>>(), 42);
		scorer.payment_path_failed(&payment_path_for_amount(128).iter().collect::<Vec<_>>(), 43);

		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 97);
		assert_eq!(scorer.channel_penalty_msat(42, 768, 1_024, &source, &target), 1_409);
		assert_eq!(scorer.channel_penalty_msat(42, 896, 1_024, &source, &target), u64::max_value());

		SinceEpoch::advance(Duration::from_secs(9));
		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 97);
		assert_eq!(scorer.channel_penalty_msat(42, 768, 1_024, &source, &target), 1_409);
		assert_eq!(scorer.channel_penalty_msat(42, 896, 1_024, &source, &target), u64::max_value());

		SinceEpoch::advance(Duration::from_secs(1));
		assert_eq!(scorer.channel_penalty_msat(42, 64, 1_024, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 34);
		assert_eq!(scorer.channel_penalty_msat(42, 896, 1_024, &source, &target), 1_773);
		assert_eq!(scorer.channel_penalty_msat(42, 960, 1_024, &source, &target), u64::max_value());

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
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 125);

		scorer.payment_path_failed(&payment_path_for_amount(512).iter().collect::<Vec<_>>(), 42);
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 274);

		// An unchecked right shift 64 bits or more in DirectedChannelLiquidity::decayed_offset_msat
		// would cause an overflow.
		SinceEpoch::advance(Duration::from_secs(10 * 64));
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 125);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 256, 1_024, &source, &target), 125);
	}

	#[test]
	fn restricts_liquidity_bounds_after_decay() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_offset_half_life: Duration::from_secs(10),
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 301);

		// More knowledge gives higher confidence (256, 768), meaning a lower penalty.
		scorer.payment_path_failed(&payment_path_for_amount(768).iter().collect::<Vec<_>>(), 42);
		scorer.payment_path_failed(&payment_path_for_amount(256).iter().collect::<Vec<_>>(), 43);
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 274);

		// Decaying knowledge gives less confidence (128, 896), meaning a higher penalty.
		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 301);

		// Reducing the upper bound gives more confidence (128, 832) that the payment amount (512)
		// is closer to the upper bound, meaning a higher penalty.
		scorer.payment_path_successful(&payment_path_for_amount(64).iter().collect::<Vec<_>>());
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 342);

		// Increasing the lower bound gives more confidence (256, 832) that the payment amount (512)
		// is closer to the lower bound, meaning a lower penalty.
		scorer.payment_path_failed(&payment_path_for_amount(256).iter().collect::<Vec<_>>(), 43);
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 255);

		// Further decaying affects the lower bound more than the upper bound (128, 928).
		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 512, 1_024, &source, &target), 284);
	}

	#[test]
	fn restores_persisted_liquidity_bounds() {
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_offset_half_life: Duration::from_secs(10),
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		scorer.payment_path_failed(&payment_path_for_amount(500).iter().collect::<Vec<_>>(), 42);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), u64::max_value());

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 472);

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
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		scorer.payment_path_failed(&payment_path_for_amount(500).iter().collect::<Vec<_>>(), 42);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), u64::max_value());

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		SinceEpoch::advance(Duration::from_secs(10));

		let mut serialized_scorer = io::Cursor::new(&serialized_scorer);
		let deserialized_scorer =
			<ProbabilisticScorer>::read(&mut serialized_scorer, (params, &network_graph)).unwrap();
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 472);

		scorer.payment_path_failed(&payment_path_for_amount(250).iter().collect::<Vec<_>>(), 43);
		assert_eq!(scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 300);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 500, 1_000, &source, &target), 371);
	}

	#[test]
	fn scores_realistic_payments() {
		// Shows the scores of "realistic" sends of 100k sats over channels of 1-10m sats (with a
		// 50k sat reserve).
		let network_graph = network_graph();
		let params = ProbabilisticScoringParameters::default();
		let scorer = ProbabilisticScorer::new(params, &network_graph);
		let source = source_node_id();
		let target = target_node_id();

		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 950_000_000, &source, &target), 3645);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 1_950_000_000, &source, &target), 2512);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 2_950_000_000, &source, &target), 500);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 3_950_000_000, &source, &target), 1442);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 4_950_000_000, &source, &target), 500);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 5_950_000_000, &source, &target), 1820);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 6_950_000_000, &source, &target), 500);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 7_450_000_000, &source, &target), 500);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 7_950_000_000, &source, &target), 500);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 8_950_000_000, &source, &target), 500);
		assert_eq!(scorer.channel_penalty_msat(42, 100_000_000, 9_950_000_000, &source, &target), 500);
	}

	#[test]
	fn adds_base_penalty_to_liquidity_penalty() {
		let network_graph = network_graph();
		let source = source_node_id();
		let target = target_node_id();

		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(params, &network_graph);
		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 58);

		let params = ProbabilisticScoringParameters {
			base_penalty_msat: 500, liquidity_penalty_multiplier_msat: 1_000, ..Default::default()
		};
		let scorer = ProbabilisticScorer::new(params, &network_graph);
		assert_eq!(scorer.channel_penalty_msat(42, 128, 1_024, &source, &target), 558);
	}

	#[test]
	fn adds_amount_penalty_to_liquidity_penalty() {
		let network_graph = network_graph();
		let source = source_node_id();
		let target = target_node_id();

		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			amount_penalty_multiplier_msat: 0,
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(params, &network_graph);
		assert_eq!(scorer.channel_penalty_msat(42, 512_000, 1_024_000, &source, &target), 300);

		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			amount_penalty_multiplier_msat: 256,
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(params, &network_graph);
		assert_eq!(scorer.channel_penalty_msat(42, 512_000, 1_024_000, &source, &target), 337);
	}

	#[test]
	fn calculates_log10_without_overflowing_u64_max_value() {
		let network_graph = network_graph();
		let source = source_node_id();
		let target = target_node_id();

		let params = ProbabilisticScoringParameters {
			liquidity_penalty_multiplier_msat: 40_000,
			..ProbabilisticScoringParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(params, &network_graph);
		assert_eq!(
			scorer.channel_penalty_msat(42, u64::max_value(), u64::max_value(), &source, &target),
			80_000,
		);
	}
}
