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
//! finding when a custom [`ScoreLookUp`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate bitcoin;
//! #
//! # use lightning::routing::gossip::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters};
//! # use lightning::sign::KeysManager;
//! # use lightning::util::logger::{Logger, Record};
//! # use bitcoin::secp256k1::PublicKey;
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: Record) { unimplemented!() }
//! # }
//! # fn find_scored_route(payer: PublicKey, route_params: RouteParameters, network_graph: NetworkGraph<&FakeLogger>) {
//! # let logger = FakeLogger {};
//! #
//! // Use the default channel penalties.
//! let params = ProbabilisticScoringFeeParameters::default();
//! let decay_params = ProbabilisticScoringDecayParameters::default();
//! let scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
//!
//! // Or use custom channel penalties.
//! let params = ProbabilisticScoringFeeParameters {
//! 	liquidity_penalty_multiplier_msat: 2 * 1000,
//! 	..ProbabilisticScoringFeeParameters::default()
//! };
//! let decay_params = ProbabilisticScoringDecayParameters::default();
//! let scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
//! # let random_seed_bytes = [42u8; 32];
//!
//! let route = find_route(&payer, &route_params, &network_graph, None, &logger, &scorer, &params, &random_seed_bytes);
//! # }
//! ```
//!
//! # Note
//!
//! Persisting when built with feature `no-std` and restoring without it, or vice versa, uses
//! different types and thus is undefined.
//!
//! [`find_route`]: crate::routing::router::find_route

use crate::ln::msgs::DecodeError;
use crate::routing::gossip::{EffectiveCapacity, NetworkGraph, NodeId};
use crate::routing::router::{Path, CandidateRouteHop, PublicHopCandidate};
use crate::routing::log_approx;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use crate::util::logger::Logger;

use crate::prelude::*;
use core::{cmp, fmt};
use core::ops::{Deref, DerefMut};
use core::time::Duration;
use crate::io::{self, Read};
use crate::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(not(c_bindings))]
use {
	core::cell::{RefCell, RefMut, Ref},
	crate::sync::{Mutex, MutexGuard},
};

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
/// `ScoreLookUp` is used to determine the penalty for a given channel.
///
/// Scoring is in terms of fees willing to be paid in order to avoid routing through a channel.
pub trait ScoreLookUp {
	/// A configurable type which should contain various passed-in parameters for configuring the scorer,
	/// on a per-routefinding-call basis through to the scorer methods,
	/// which are used to determine the parameters for the suitability of channels for use.
	type ScoreParams;
	/// Returns the fee in msats willing to be paid to avoid routing `send_amt_msat` through the
	/// given channel in the direction from `source` to `target`.
	///
	/// The channel's capacity (less any other MPP parts that are also being considered for use in
	/// the same payment) is given by `capacity_msat`. It may be determined from various sources
	/// such as a chain data, network gossip, or invoice hints. For invoice hints, a capacity near
	/// [`u64::max_value`] is given to indicate sufficient capacity for the invoice's full amount.
	/// Thus, implementations should be overflow-safe.
	fn channel_penalty_msat(
		&self, candidate: &CandidateRouteHop, usage: ChannelUsage, score_params: &Self::ScoreParams
	) -> u64;
}

/// `ScoreUpdate` is used to update the scorer's internal state after a payment attempt.
pub trait ScoreUpdate {
	/// Handles updating channel penalties after failing to route through a channel.
	fn payment_path_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration);

	/// Handles updating channel penalties after successfully routing along a path.
	fn payment_path_successful(&mut self, path: &Path, duration_since_epoch: Duration);

	/// Handles updating channel penalties after a probe over the given path failed.
	fn probe_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration);

	/// Handles updating channel penalties after a probe over the given path succeeded.
	fn probe_successful(&mut self, path: &Path, duration_since_epoch: Duration);

	/// Scorers may wish to reduce their certainty of channel liquidity information over time.
	/// Thus, this method is provided to allow scorers to observe the passage of time - the holder
	/// of this object should call this method regularly (generally via the
	/// `lightning-background-processor` crate).
	fn time_passed(&mut self, duration_since_epoch: Duration);
}

/// A trait which can both lookup and update routing channel penalty scores.
///
/// This is used in places where both bounds are required and implemented for all types which
/// implement [`ScoreLookUp`] and [`ScoreUpdate`].
///
/// Bindings users may need to manually implement this for their custom scoring implementations.
pub trait Score : ScoreLookUp + ScoreUpdate $(+ $supertrait)* {}

#[cfg(not(c_bindings))]
impl<T: ScoreLookUp + ScoreUpdate $(+ $supertrait)*> Score for T {}

#[cfg(not(c_bindings))]
impl<S: ScoreLookUp, T: Deref<Target=S>> ScoreLookUp for T {
	type ScoreParams = S::ScoreParams;
	fn channel_penalty_msat(
		&self, candidate: &CandidateRouteHop, usage: ChannelUsage, score_params: &Self::ScoreParams
	) -> u64 {
		self.deref().channel_penalty_msat(candidate, usage, score_params)
	}
}

#[cfg(not(c_bindings))]
impl<S: ScoreUpdate, T: DerefMut<Target=S>> ScoreUpdate for T {
	fn payment_path_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration) {
		self.deref_mut().payment_path_failed(path, short_channel_id, duration_since_epoch)
	}

	fn payment_path_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
		self.deref_mut().payment_path_successful(path, duration_since_epoch)
	}

	fn probe_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration) {
		self.deref_mut().probe_failed(path, short_channel_id, duration_since_epoch)
	}

	fn probe_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
		self.deref_mut().probe_successful(path, duration_since_epoch)
	}

	fn time_passed(&mut self, duration_since_epoch: Duration) {
		self.deref_mut().time_passed(duration_since_epoch)
	}
}
} }

#[cfg(c_bindings)]
define_score!(Writeable);

#[cfg(not(c_bindings))]
define_score!();

/// A scorer that is accessed under a lock.
///
/// Needed so that calls to [`ScoreLookUp::channel_penalty_msat`] in [`find_route`] can be made while
/// having shared ownership of a scorer but without requiring internal locking in [`ScoreUpdate`]
/// implementations. Internal locking would be detrimental to route finding performance and could
/// result in [`ScoreLookUp::channel_penalty_msat`] returning a different value for the same channel.
///
/// [`find_route`]: crate::routing::router::find_route
pub trait LockableScore<'a> {
	/// The [`ScoreUpdate`] type.
	type ScoreUpdate: 'a + ScoreUpdate;
	/// The [`ScoreLookUp`] type.
	type ScoreLookUp: 'a + ScoreLookUp;

	/// The write locked [`ScoreUpdate`] type.
	type WriteLocked: DerefMut<Target = Self::ScoreUpdate> + Sized;

	/// The read locked [`ScoreLookUp`] type.
	type ReadLocked: Deref<Target = Self::ScoreLookUp> + Sized;

	/// Returns read locked scorer.
	fn read_lock(&'a self) -> Self::ReadLocked;

	/// Returns write locked scorer.
	fn write_lock(&'a self) -> Self::WriteLocked;
}

/// Refers to a scorer that is accessible under lock and also writeable to disk
///
/// We need this trait to be able to pass in a scorer to `lightning-background-processor` that will enable us to
/// use the Persister to persist it.
pub trait WriteableScore<'a>: LockableScore<'a> + Writeable {}

#[cfg(not(c_bindings))]
impl<'a, T> WriteableScore<'a> for T where T: LockableScore<'a> + Writeable {}
#[cfg(not(c_bindings))]
impl<'a, T: Score + 'a> LockableScore<'a> for Mutex<T> {
	type ScoreUpdate = T;
	type ScoreLookUp = T;

	type WriteLocked = MutexGuard<'a, Self::ScoreUpdate>;
	type ReadLocked = MutexGuard<'a, Self::ScoreLookUp>;

	fn read_lock(&'a self) -> Self::ReadLocked {
		Mutex::lock(self).unwrap()
	}

	fn write_lock(&'a self) -> Self::WriteLocked {
		Mutex::lock(self).unwrap()
	}
}

#[cfg(not(c_bindings))]
impl<'a, T: Score + 'a> LockableScore<'a> for RefCell<T> {
	type ScoreUpdate = T;
	type ScoreLookUp = T;

	type WriteLocked = RefMut<'a, Self::ScoreUpdate>;
	type ReadLocked = Ref<'a, Self::ScoreLookUp>;

	fn write_lock(&'a self) -> Self::WriteLocked {
		self.borrow_mut()
	}

	fn read_lock(&'a self) -> Self::ReadLocked {
		self.borrow()
	}
}

#[cfg(any(not(c_bindings), feature = "_test_utils", test))]
impl<'a, T: Score + 'a> LockableScore<'a> for RwLock<T> {
	type ScoreUpdate = T;
	type ScoreLookUp = T;

	type WriteLocked = RwLockWriteGuard<'a, Self::ScoreLookUp>;
	type ReadLocked = RwLockReadGuard<'a, Self::ScoreUpdate>;

	fn read_lock(&'a self) -> Self::ReadLocked {
		RwLock::read(self).unwrap()
	}

	fn write_lock(&'a self) -> Self::WriteLocked {
		RwLock::write(self).unwrap()
	}
}

#[cfg(c_bindings)]
/// A concrete implementation of [`LockableScore`] which supports multi-threading.
pub struct MultiThreadedLockableScore<T: Score> {
	score: RwLock<T>,
}

#[cfg(c_bindings)]
impl<'a, T: Score + 'a> LockableScore<'a> for MultiThreadedLockableScore<T> {
	type ScoreUpdate = T;
	type ScoreLookUp = T;
	type WriteLocked = MultiThreadedScoreLockWrite<'a, Self::ScoreUpdate>;
	type ReadLocked = MultiThreadedScoreLockRead<'a, Self::ScoreLookUp>;

	fn read_lock(&'a self) -> Self::ReadLocked {
		MultiThreadedScoreLockRead(self.score.read().unwrap())
	}

	fn write_lock(&'a self) -> Self::WriteLocked {
		MultiThreadedScoreLockWrite(self.score.write().unwrap())
	}
}

#[cfg(c_bindings)]
impl<T: Score> Writeable for MultiThreadedLockableScore<T> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.score.read().unwrap().write(writer)
	}
}

#[cfg(c_bindings)]
impl<'a, T: Score + 'a> WriteableScore<'a> for MultiThreadedLockableScore<T> {}

#[cfg(c_bindings)]
impl<T: Score> MultiThreadedLockableScore<T> {
	/// Creates a new [`MultiThreadedLockableScore`] given an underlying [`Score`].
	pub fn new(score: T) -> Self {
		MultiThreadedLockableScore { score: RwLock::new(score) }
	}
}

#[cfg(c_bindings)]
/// A locked `MultiThreadedLockableScore`.
pub struct MultiThreadedScoreLockRead<'a, T: Score>(RwLockReadGuard<'a, T>);

#[cfg(c_bindings)]
/// A locked `MultiThreadedLockableScore`.
pub struct MultiThreadedScoreLockWrite<'a, T: Score>(RwLockWriteGuard<'a, T>);

#[cfg(c_bindings)]
impl<'a, T: 'a + Score> Deref for MultiThreadedScoreLockRead<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		self.0.deref()
	}
}

#[cfg(c_bindings)]
impl<'a, T: Score> ScoreLookUp for MultiThreadedScoreLockRead<'a, T> {
	type ScoreParams = T::ScoreParams;
	fn channel_penalty_msat(&self, candidate:&CandidateRouteHop, usage: ChannelUsage, score_params: &Self::ScoreParams
	) -> u64 {
		self.0.channel_penalty_msat(candidate, usage, score_params)
	}
}

#[cfg(c_bindings)]
impl<'a, T: Score> Writeable for MultiThreadedScoreLockWrite<'a, T> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.0.write(writer)
	}
}

#[cfg(c_bindings)]
impl<'a, T: 'a + Score> Deref for MultiThreadedScoreLockWrite<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		self.0.deref()
	}
}

#[cfg(c_bindings)]
impl<'a, T: 'a + Score> DerefMut for MultiThreadedScoreLockWrite<'a, T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.0.deref_mut()
	}
}

#[cfg(c_bindings)]
impl<'a, T: Score> ScoreUpdate for MultiThreadedScoreLockWrite<'a, T> {
	fn payment_path_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration) {
		self.0.payment_path_failed(path, short_channel_id, duration_since_epoch)
	}

	fn payment_path_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
		self.0.payment_path_successful(path, duration_since_epoch)
	}

	fn probe_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration) {
		self.0.probe_failed(path, short_channel_id, duration_since_epoch)
	}

	fn probe_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
		self.0.probe_successful(path, duration_since_epoch)
	}

	fn time_passed(&mut self, duration_since_epoch: Duration) {
		self.0.time_passed(duration_since_epoch)
	}
}


/// Proposed use of a channel passed as a parameter to [`ScoreLookUp::channel_penalty_msat`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChannelUsage {
	/// The amount to send through the channel, denominated in millisatoshis.
	pub amount_msat: u64,

	/// Total amount, denominated in millisatoshis, already allocated to send through the channel
	/// as part of a multi-path payment.
	pub inflight_htlc_msat: u64,

	/// The effective capacity of the channel.
	pub effective_capacity: EffectiveCapacity,
}

#[derive(Clone)]
/// [`ScoreLookUp`] implementation that uses a fixed penalty.
pub struct FixedPenaltyScorer {
	penalty_msat: u64,
}

impl FixedPenaltyScorer {
	/// Creates a new scorer using `penalty_msat`.
	pub fn with_penalty(penalty_msat: u64) -> Self {
		Self { penalty_msat }
	}
}

impl ScoreLookUp for FixedPenaltyScorer {
	type ScoreParams = ();
	fn channel_penalty_msat(&self, _: &CandidateRouteHop, _: ChannelUsage, _score_params: &Self::ScoreParams) -> u64 {
		self.penalty_msat
	}
}

impl ScoreUpdate for FixedPenaltyScorer {
	fn payment_path_failed(&mut self, _path: &Path, _short_channel_id: u64, _duration_since_epoch: Duration) {}

	fn payment_path_successful(&mut self, _path: &Path, _duration_since_epoch: Duration) {}

	fn probe_failed(&mut self, _path: &Path, _short_channel_id: u64, _duration_since_epoch: Duration) {}

	fn probe_successful(&mut self, _path: &Path, _duration_since_epoch: Duration) {}

	fn time_passed(&mut self, _duration_since_epoch: Duration) {}
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

/// [`ScoreLookUp`] implementation using channel success probability distributions.
///
/// Channels are tracked with upper and lower liquidity bounds - when an HTLC fails at a channel,
/// we learn that the upper-bound on the available liquidity is lower than the amount of the HTLC.
/// When a payment is forwarded through a channel (but fails later in the route), we learn the
/// lower-bound on the channel's available liquidity must be at least the value of the HTLC.
///
/// These bounds are then used to determine a success probability using the formula from
/// *Optimally Reliable & Cheap Payment Flows on the Lightning Network* by Rene Pickhardt
/// and Stefan Richter [[1]] (i.e. `(upper_bound - payment_amount) / (upper_bound - lower_bound)`).
///
/// This probability is combined with the [`liquidity_penalty_multiplier_msat`] and
/// [`liquidity_penalty_amount_multiplier_msat`] parameters to calculate a concrete penalty in
/// milli-satoshis. The penalties, when added across all hops, have the property of being linear in
/// terms of the entire path's success probability. This allows the router to directly compare
/// penalties for different paths. See the documentation of those parameters for the exact formulas.
///
/// The liquidity bounds are decayed by halving them every [`liquidity_offset_half_life`].
///
/// Further, we track the history of our upper and lower liquidity bounds for each channel,
/// allowing us to assign a second penalty (using [`historical_liquidity_penalty_multiplier_msat`]
/// and [`historical_liquidity_penalty_amount_multiplier_msat`]) based on the same probability
/// formula, but using the history of a channel rather than our latest estimates for the liquidity
/// bounds.
///
/// [1]: https://arxiv.org/abs/2107.05322
/// [`liquidity_penalty_multiplier_msat`]: ProbabilisticScoringFeeParameters::liquidity_penalty_multiplier_msat
/// [`liquidity_penalty_amount_multiplier_msat`]: ProbabilisticScoringFeeParameters::liquidity_penalty_amount_multiplier_msat
/// [`liquidity_offset_half_life`]: ProbabilisticScoringDecayParameters::liquidity_offset_half_life
/// [`historical_liquidity_penalty_multiplier_msat`]: ProbabilisticScoringFeeParameters::historical_liquidity_penalty_multiplier_msat
/// [`historical_liquidity_penalty_amount_multiplier_msat`]: ProbabilisticScoringFeeParameters::historical_liquidity_penalty_amount_multiplier_msat
pub struct ProbabilisticScorer<G: Deref<Target = NetworkGraph<L>>, L: Deref>
where L::Target: Logger {
	decay_params: ProbabilisticScoringDecayParameters,
	network_graph: G,
	logger: L,
	channel_liquidities: HashMap<u64, ChannelLiquidity>,
}

/// Parameters for configuring [`ProbabilisticScorer`].
///
/// Used to configure base, liquidity, and amount penalties, the sum of which comprises the channel
/// penalty (i.e., the amount in msats willing to be paid to avoid routing through the channel).
///
/// The penalty applied to any channel by the [`ProbabilisticScorer`] is the sum of each of the
/// parameters here.
#[derive(Clone)]
pub struct ProbabilisticScoringFeeParameters {
	/// A fixed penalty in msats to apply to each channel.
	///
	/// Default value: 500 msat
	pub base_penalty_msat: u64,

	/// A multiplier used with the total amount flowing over a channel to calculate a fixed penalty
	/// applied to each channel, in excess of the [`base_penalty_msat`].
	///
	/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
	/// fees plus penalty) for large payments. The penalty is computed as the product of this
	/// multiplier and `2^30`ths of the total amount flowing over a channel (i.e. the payment
	/// amount plus the amount of any other HTLCs flowing we sent over the same channel).
	///
	/// ie `base_penalty_amount_multiplier_msat * amount_msat / 2^30`
	///
	/// Default value: 8,192 msat
	///
	/// [`base_penalty_msat`]: Self::base_penalty_msat
	pub base_penalty_amount_multiplier_msat: u64,

	/// A multiplier used in conjunction with the negative `log10` of the channel's success
	/// probability for a payment, as determined by our latest estimates of the channel's
	/// liquidity, to determine the liquidity penalty.
	///
	/// The penalty is based in part on the knowledge learned from prior successful and unsuccessful
	/// payments. This knowledge is decayed over time based on [`liquidity_offset_half_life`]. The
	/// penalty is effectively limited to `2 * liquidity_penalty_multiplier_msat` (corresponding to
	/// lower bounding the success probability to `0.01`) when the amount falls within the
	/// uncertainty bounds of the channel liquidity balance. Amounts above the upper bound will
	/// result in a `u64::max_value` penalty, however.
	///
	/// `-log10(success_probability) * liquidity_penalty_multiplier_msat`
	///
	/// Default value: 30,000 msat
	///
	/// [`liquidity_offset_half_life`]: ProbabilisticScoringDecayParameters::liquidity_offset_half_life
	pub liquidity_penalty_multiplier_msat: u64,

	/// A multiplier used in conjunction with the total amount flowing over a channel and the
	/// negative `log10` of the channel's success probability for the payment, as determined by our
	/// latest estimates of the channel's liquidity, to determine the amount penalty.
	///
	/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
	/// fees plus penalty) for large payments. The penalty is computed as the product of this
	/// multiplier and `2^20`ths of the amount flowing over this channel, weighted by the negative
	/// `log10` of the success probability.
	///
	/// `-log10(success_probability) * liquidity_penalty_amount_multiplier_msat * amount_msat / 2^20`
	///
	/// In practice, this means for 0.1 success probability (`-log10(0.1) == 1`) each `2^20`th of
	/// the amount will result in a penalty of the multiplier. And, as the success probability
	/// decreases, the negative `log10` weighting will increase dramatically. For higher success
	/// probabilities, the multiplier will have a decreasing effect as the negative `log10` will
	/// fall below `1`.
	///
	/// Default value: 192 msat
	pub liquidity_penalty_amount_multiplier_msat: u64,

	/// A multiplier used in conjunction with the negative `log10` of the channel's success
	/// probability for the payment, as determined based on the history of our estimates of the
	/// channel's available liquidity, to determine a penalty.
	///
	/// This penalty is similar to [`liquidity_penalty_multiplier_msat`], however, instead of using
	/// only our latest estimate for the current liquidity available in the channel, it estimates
	/// success probability based on the estimated liquidity available in the channel through
	/// history. Specifically, every time we update our liquidity bounds on a given channel, we
	/// track which of several buckets those bounds fall into, exponentially decaying the
	/// probability of each bucket as new samples are added.
	///
	/// Default value: 10,000 msat
	///
	/// [`liquidity_penalty_multiplier_msat`]: Self::liquidity_penalty_multiplier_msat
	pub historical_liquidity_penalty_multiplier_msat: u64,

	/// A multiplier used in conjunction with the total amount flowing over a channel and the
	/// negative `log10` of the channel's success probability for the payment, as determined based
	/// on the history of our estimates of the channel's available liquidity, to determine a
	/// penalty.
	///
	/// The purpose of the amount penalty is to avoid having fees dominate the channel cost for
	/// large payments. The penalty is computed as the product of this multiplier and `2^20`ths
	/// of the amount flowing over this channel, weighted by the negative `log10` of the success
	/// probability.
	///
	/// This penalty is similar to [`liquidity_penalty_amount_multiplier_msat`], however, instead
	/// of using only our latest estimate for the current liquidity available in the channel, it
	/// estimates success probability based on the estimated liquidity available in the channel
	/// through history. Specifically, every time we update our liquidity bounds on a given
	/// channel, we track which of several buckets those bounds fall into, exponentially decaying
	/// the probability of each bucket as new samples are added.
	///
	/// Default value: 64 msat
	///
	/// [`liquidity_penalty_amount_multiplier_msat`]: Self::liquidity_penalty_amount_multiplier_msat
	pub historical_liquidity_penalty_amount_multiplier_msat: u64,

	/// Manual penalties used for the given nodes. Allows to set a particular penalty for a given
	/// node. Note that a manual penalty of `u64::max_value()` means the node would not ever be
	/// considered during path finding.
	///
	/// This is not exported to bindings users
	pub manual_node_penalties: HashMap<NodeId, u64>,

	/// This penalty is applied when `htlc_maximum_msat` is equal to or larger than half of the
	/// channel's capacity, (ie. htlc_maximum_msat >= 0.5 * channel_capacity) which makes us
	/// prefer nodes with a smaller `htlc_maximum_msat`. We treat such nodes preferentially
	/// as this makes balance discovery attacks harder to execute, thereby creating an incentive
	/// to restrict `htlc_maximum_msat` and improve privacy.
	///
	/// Default value: 250 msat
	pub anti_probing_penalty_msat: u64,

	/// This penalty is applied when the total amount flowing over a channel exceeds our current
	/// estimate of the channel's available liquidity. The total amount is the amount of the
	/// current HTLC plus any HTLCs which we've sent over the same channel.
	///
	/// Note that in this case all other penalties, including the
	/// [`liquidity_penalty_multiplier_msat`] and [`liquidity_penalty_amount_multiplier_msat`]-based
	/// penalties, as well as the [`base_penalty_msat`] and the [`anti_probing_penalty_msat`], if
	/// applicable, are still included in the overall penalty.
	///
	/// If you wish to avoid creating paths with such channels entirely, setting this to a value of
	/// `u64::max_value()` will guarantee that.
	///
	/// Default value: 1_0000_0000_000 msat (1 Bitcoin)
	///
	/// [`liquidity_penalty_multiplier_msat`]: Self::liquidity_penalty_multiplier_msat
	/// [`liquidity_penalty_amount_multiplier_msat`]: Self::liquidity_penalty_amount_multiplier_msat
	/// [`base_penalty_msat`]: Self::base_penalty_msat
	/// [`anti_probing_penalty_msat`]: Self::anti_probing_penalty_msat
	pub considered_impossible_penalty_msat: u64,

	/// In order to calculate most of the scores above, we must first convert a lower and upper
	/// bound on the available liquidity in a channel into the probability that we think a payment
	/// will succeed. That probability is derived from a Probability Density Function for where we
	/// think the liquidity in a channel likely lies, given such bounds.
	///
	/// If this flag is set, that PDF is simply a constant - we assume that the actual available
	/// liquidity in a channel is just as likely to be at any point between our lower and upper
	/// bounds.
	///
	/// If this flag is *not* set, that PDF is `(x - 0.5*capacity) ^ 2`. That is, we use an
	/// exponential curve which expects the liquidity of a channel to lie "at the edges". This
	/// matches experimental results - most routing nodes do not aggressively rebalance their
	/// channels and flows in the network are often unbalanced, leaving liquidity usually
	/// unavailable.
	///
	/// Thus, for the "best" routes, leave this flag `false`. However, the flag does imply a number
	/// of floating-point multiplications in the hottest routing code, which may lead to routing
	/// performance degradation on some machines.
	///
	/// Default value: false
	pub linear_success_probability: bool,
}

impl Default for ProbabilisticScoringFeeParameters {
	fn default() -> Self {
		Self {
			base_penalty_msat: 500,
			base_penalty_amount_multiplier_msat: 8192,
			liquidity_penalty_multiplier_msat: 30_000,
			liquidity_penalty_amount_multiplier_msat: 192,
			manual_node_penalties: new_hash_map(),
			anti_probing_penalty_msat: 250,
			considered_impossible_penalty_msat: 1_0000_0000_000,
			historical_liquidity_penalty_multiplier_msat: 10_000,
			historical_liquidity_penalty_amount_multiplier_msat: 64,
			linear_success_probability: false,
		}
	}
}

impl ProbabilisticScoringFeeParameters {
	/// Marks the node with the given `node_id` as banned,
	/// i.e it will be avoided during path finding.
	pub fn add_banned(&mut self, node_id: &NodeId) {
		self.manual_node_penalties.insert(*node_id, u64::max_value());
	}

	/// Marks all nodes in the given list as banned, i.e.,
	/// they will be avoided during path finding.
	pub fn add_banned_from_list(&mut self, node_ids: Vec<NodeId>) {
		for id in node_ids {
			self.manual_node_penalties.insert(id, u64::max_value());
		}
	}

	/// Removes the node with the given `node_id` from the list of nodes to avoid.
	pub fn remove_banned(&mut self, node_id: &NodeId) {
		self.manual_node_penalties.remove(node_id);
	}

	/// Sets a manual penalty for the given node.
	pub fn set_manual_penalty(&mut self, node_id: &NodeId, penalty: u64) {
		self.manual_node_penalties.insert(*node_id, penalty);
	}

	/// Removes the node with the given `node_id` from the list of manual penalties.
	pub fn remove_manual_penalty(&mut self, node_id: &NodeId) {
		self.manual_node_penalties.remove(node_id);
	}

	/// Clears the list of manual penalties that are applied during path finding.
	pub fn clear_manual_penalties(&mut self) {
		self.manual_node_penalties = new_hash_map();
	}
}

#[cfg(test)]
impl ProbabilisticScoringFeeParameters {
	fn zero_penalty() -> Self {
		Self {
			base_penalty_msat: 0,
			base_penalty_amount_multiplier_msat: 0,
			liquidity_penalty_multiplier_msat: 0,
			liquidity_penalty_amount_multiplier_msat: 0,
			historical_liquidity_penalty_multiplier_msat: 0,
			historical_liquidity_penalty_amount_multiplier_msat: 0,
			manual_node_penalties: new_hash_map(),
			anti_probing_penalty_msat: 0,
			considered_impossible_penalty_msat: 0,
			linear_success_probability: true,
		}
	}
}

/// Parameters for configuring [`ProbabilisticScorer`].
///
/// Used to configure decay parameters that are static throughout the lifetime of the scorer.
/// these decay parameters affect the score of the channel penalty and are not changed on a
/// per-route penalty cost call.
#[derive(Copy, Clone)]
pub struct ProbabilisticScoringDecayParameters {
	/// If we aren't learning any new datapoints for a channel, the historical liquidity bounds
	/// tracking can simply live on with increasingly stale data. Instead, when a channel has not
	/// seen a liquidity estimate update for this amount of time, the historical datapoints are
	/// decayed by half.
	/// For an example of historical_no_updates_half_life being used see [`historical_estimated_channel_liquidity_probabilities`]
	///
	/// Note that after 16 or more half lives all historical data will be completely gone.
	///
	/// Default value: 14 days
	///
	/// [`historical_estimated_channel_liquidity_probabilities`]: ProbabilisticScorer::historical_estimated_channel_liquidity_probabilities
	pub historical_no_updates_half_life: Duration,

	/// Whenever this amount of time elapses since the last update to a channel's liquidity bounds,
	/// the distance from the bounds to "zero" is cut in half. In other words, the lower-bound on
	/// the available liquidity is halved and the upper-bound moves half-way to the channel's total
	/// capacity.
	///
	/// Because halving the liquidity bounds grows the uncertainty on the channel's liquidity,
	/// the penalty for an amount within the new bounds may change. See the [`ProbabilisticScorer`]
	/// struct documentation for more info on the way the liquidity bounds are used.
	///
	/// For example, if the channel's capacity is 1 million sats, and the current upper and lower
	/// liquidity bounds are 200,000 sats and 600,000 sats, after this amount of time the upper
	/// and lower liquidity bounds will be decayed to 100,000 and 800,000 sats.
	///
	/// Default value: 6 hours
	///
	/// # Note
	///
	/// When built with the `no-std` feature, time will never elapse. Therefore, the channel
	/// liquidity knowledge will never decay except when the bounds cross.
	pub liquidity_offset_half_life: Duration,
}

impl Default for ProbabilisticScoringDecayParameters {
	fn default() -> Self {
		Self {
			liquidity_offset_half_life: Duration::from_secs(6 * 60 * 60),
			historical_no_updates_half_life: Duration::from_secs(60 * 60 * 24 * 14),
		}
	}
}

#[cfg(test)]
impl ProbabilisticScoringDecayParameters {
	fn zero_penalty() -> Self {
		Self {
			liquidity_offset_half_life: Duration::from_secs(6 * 60 * 60),
			historical_no_updates_half_life: Duration::from_secs(60 * 60 * 24 * 14),
		}
	}
}

/// Accounting for channel liquidity balance uncertainty.
///
/// Direction is defined in terms of [`NodeId`] partial ordering, where the source node is the
/// first node in the ordering of the channel's counterparties. Thus, swapping the two liquidity
/// offset fields gives the opposite direction.
struct ChannelLiquidity {
	/// Lower channel liquidity bound in terms of an offset from zero.
	min_liquidity_offset_msat: u64,

	/// Upper channel liquidity bound in terms of an offset from the effective capacity.
	max_liquidity_offset_msat: u64,

	liquidity_history: HistoricalLiquidityTracker,

	/// Time when either liquidity bound was last modified as an offset since the unix epoch.
	last_updated: Duration,

	/// Time when the historical liquidity bounds were last modified as an offset against the unix
	/// epoch.
	offset_history_last_updated: Duration,
}

/// A snapshot of [`ChannelLiquidity`] in one direction assuming a certain channel capacity.
struct DirectedChannelLiquidity<L: Deref<Target = u64>, HT: Deref<Target = HistoricalLiquidityTracker>, T: Deref<Target = Duration>> {
	min_liquidity_offset_msat: L,
	max_liquidity_offset_msat: L,
	liquidity_history: DirectedHistoricalLiquidityTracker<HT>,
	capacity_msat: u64,
	last_updated: T,
	offset_history_last_updated: T,
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> ProbabilisticScorer<G, L> where L::Target: Logger {
	/// Creates a new scorer using the given scoring parameters for sending payments from a node
	/// through a network graph.
	pub fn new(decay_params: ProbabilisticScoringDecayParameters, network_graph: G, logger: L) -> Self {
		Self {
			decay_params,
			network_graph,
			logger,
			channel_liquidities: new_hash_map(),
		}
	}

	#[cfg(test)]
	fn with_channel(mut self, short_channel_id: u64, liquidity: ChannelLiquidity) -> Self {
		assert!(self.channel_liquidities.insert(short_channel_id, liquidity).is_none());
		self
	}

	/// Dump the contents of this scorer into the configured logger.
	///
	/// Note that this writes roughly one line per channel for which we have a liquidity estimate,
	/// which may be a substantial amount of log output.
	pub fn debug_log_liquidity_stats(&self) {
		let graph = self.network_graph.read_only();
		for (scid, liq) in self.channel_liquidities.iter() {
			if let Some(chan_debug) = graph.channels().get(scid) {
				let log_direction = |source, target| {
					if let Some((directed_info, _)) = chan_debug.as_directed_to(target) {
						let amt = directed_info.effective_capacity().as_msat();
						let dir_liq = liq.as_directed(source, target, amt);

						let min_buckets = &dir_liq.liquidity_history.min_liquidity_offset_history_buckets();
						let max_buckets = &dir_liq.liquidity_history.max_liquidity_offset_history_buckets();

						log_debug!(self.logger, core::concat!(
							"Liquidity from {} to {} via {} is in the range ({}, {}).\n",
							"\tHistorical min liquidity bucket relative probabilities:\n",
							"\t\t{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
							"\tHistorical max liquidity bucket relative probabilities:\n",
							"\t\t{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}"),
							source, target, scid, dir_liq.min_liquidity_msat(), dir_liq.max_liquidity_msat(),
							min_buckets[ 0], min_buckets[ 1], min_buckets[ 2], min_buckets[ 3],
							min_buckets[ 4], min_buckets[ 5], min_buckets[ 6], min_buckets[ 7],
							min_buckets[ 8], min_buckets[ 9], min_buckets[10], min_buckets[11],
							min_buckets[12], min_buckets[13], min_buckets[14], min_buckets[15],
							min_buckets[16], min_buckets[17], min_buckets[18], min_buckets[19],
							min_buckets[20], min_buckets[21], min_buckets[22], min_buckets[23],
							min_buckets[24], min_buckets[25], min_buckets[26], min_buckets[27],
							min_buckets[28], min_buckets[29], min_buckets[30], min_buckets[31],
							// Note that the liquidity buckets are an offset from the edge, so we
							// inverse the max order to get the probabilities from zero.
							max_buckets[31], max_buckets[30], max_buckets[29], max_buckets[28],
							max_buckets[27], max_buckets[26], max_buckets[25], max_buckets[24],
							max_buckets[23], max_buckets[22], max_buckets[21], max_buckets[20],
							max_buckets[19], max_buckets[18], max_buckets[17], max_buckets[16],
							max_buckets[15], max_buckets[14], max_buckets[13], max_buckets[12],
							max_buckets[11], max_buckets[10], max_buckets[ 9], max_buckets[ 8],
							max_buckets[ 7], max_buckets[ 6], max_buckets[ 5], max_buckets[ 4],
							max_buckets[ 3], max_buckets[ 2], max_buckets[ 1], max_buckets[ 0]);
					} else {
						log_debug!(self.logger, "No amount known for SCID {} from {:?} to {:?}", scid, source, target);
					}
				};

				log_direction(&chan_debug.node_one, &chan_debug.node_two);
				log_direction(&chan_debug.node_two, &chan_debug.node_one);
			} else {
				log_debug!(self.logger, "No network graph entry for SCID {}", scid);
			}
		}
	}

	/// Query the estimated minimum and maximum liquidity available for sending a payment over the
	/// channel with `scid` towards the given `target` node.
	pub fn estimated_channel_liquidity_range(&self, scid: u64, target: &NodeId) -> Option<(u64, u64)> {
		let graph = self.network_graph.read_only();

		if let Some(chan) = graph.channels().get(&scid) {
			if let Some(liq) = self.channel_liquidities.get(&scid) {
				if let Some((directed_info, source)) = chan.as_directed_to(target) {
					let amt = directed_info.effective_capacity().as_msat();
					let dir_liq = liq.as_directed(source, target, amt);
					return Some((dir_liq.min_liquidity_msat(), dir_liq.max_liquidity_msat()));
				}
			}
		}
		None
	}

	/// Query the historical estimated minimum and maximum liquidity available for sending a
	/// payment over the channel with `scid` towards the given `target` node.
	///
	/// Returns two sets of 32 buckets. The first set describes the lower-bound liquidity history,
	/// the second set describes the upper-bound liquidity history. Each bucket describes the
	/// relative frequency at which we've seen a liquidity bound in the bucket's range relative to
	/// the channel's total capacity, on an arbitrary scale. Because the values are slowly decayed,
	/// more recent data points are weighted more heavily than older datapoints.
	///
	/// Note that the range of each bucket varies by its location to provide more granular results
	/// at the edges of a channel's capacity, where it is more likely to sit.
	///
	/// When scoring, the estimated probability that an upper-/lower-bound lies in a given bucket
	/// is calculated by dividing that bucket's value with the total value of all buckets.
	///
	/// For example, using a lower bucket count for illustrative purposes, a value of
	/// `[0, 0, 0, ..., 0, 32]` indicates that we believe the probability of a bound being very
	/// close to the channel's capacity to be 100%, and have never (recently) seen it in any other
	/// bucket. A value of `[31, 0, 0, ..., 0, 0, 32]` indicates we've seen the bound being both
	/// in the top and bottom bucket, and roughly with similar (recent) frequency.
	///
	/// Because the datapoints are decayed slowly over time, values will eventually return to
	/// `Some(([0; 32], [0; 32]))` or `None` if no data remains for a channel.
	///
	/// In order to fetch a single success probability from the buckets provided here, as used in
	/// the scoring model, see [`Self::historical_estimated_payment_success_probability`].
	pub fn historical_estimated_channel_liquidity_probabilities(&self, scid: u64, target: &NodeId)
	-> Option<([u16; 32], [u16; 32])> {
		let graph = self.network_graph.read_only();

		if let Some(chan) = graph.channels().get(&scid) {
			if let Some(liq) = self.channel_liquidities.get(&scid) {
				if let Some((directed_info, source)) = chan.as_directed_to(target) {
					let amt = directed_info.effective_capacity().as_msat();
					let dir_liq = liq.as_directed(source, target, amt);

					let min_buckets = *dir_liq.liquidity_history.min_liquidity_offset_history_buckets();
					let mut max_buckets = *dir_liq.liquidity_history.max_liquidity_offset_history_buckets();

					// Note that the liquidity buckets are an offset from the edge, so we inverse
					// the max order to get the probabilities from zero.
					max_buckets.reverse();
					return Some((min_buckets, max_buckets));
				}
			}
		}
		None
	}

	/// Query the probability of payment success sending the given `amount_msat` over the channel
	/// with `scid` towards the given `target` node, based on the historical estimated liquidity
	/// bounds.
	///
	/// These are the same bounds as returned by
	/// [`Self::historical_estimated_channel_liquidity_probabilities`] (but not those returned by
	/// [`Self::estimated_channel_liquidity_range`]).
	pub fn historical_estimated_payment_success_probability(
		&self, scid: u64, target: &NodeId, amount_msat: u64, params: &ProbabilisticScoringFeeParameters)
	-> Option<f64> {
		let graph = self.network_graph.read_only();

		if let Some(chan) = graph.channels().get(&scid) {
			if let Some(liq) = self.channel_liquidities.get(&scid) {
				if let Some((directed_info, source)) = chan.as_directed_to(target) {
					let capacity_msat = directed_info.effective_capacity().as_msat();
					let dir_liq = liq.as_directed(source, target, capacity_msat);

					return dir_liq.liquidity_history.calculate_success_probability_times_billion(
						&params, amount_msat, capacity_msat
					).map(|p| p as f64 / (1024 * 1024 * 1024) as f64);
				}
			}
		}
		None
	}
}

impl ChannelLiquidity {
	fn new(last_updated: Duration) -> Self {
		Self {
			min_liquidity_offset_msat: 0,
			max_liquidity_offset_msat: 0,
			liquidity_history: HistoricalLiquidityTracker::new(),
			last_updated,
			offset_history_last_updated: last_updated,
		}
	}

	/// Returns a view of the channel liquidity directed from `source` to `target` assuming
	/// `capacity_msat`.
	fn as_directed(
		&self, source: &NodeId, target: &NodeId, capacity_msat: u64,
	) -> DirectedChannelLiquidity<&u64, &HistoricalLiquidityTracker, &Duration> {
		let source_less_than_target = source < target;
		let (min_liquidity_offset_msat, max_liquidity_offset_msat) =
			if source_less_than_target {
				(&self.min_liquidity_offset_msat, &self.max_liquidity_offset_msat)
			} else {
				(&self.max_liquidity_offset_msat, &self.min_liquidity_offset_msat)
			};

		DirectedChannelLiquidity {
			min_liquidity_offset_msat,
			max_liquidity_offset_msat,
			liquidity_history: self.liquidity_history.as_directed(source_less_than_target),
			capacity_msat,
			last_updated: &self.last_updated,
			offset_history_last_updated: &self.offset_history_last_updated,
		}
	}

	/// Returns a mutable view of the channel liquidity directed from `source` to `target` assuming
	/// `capacity_msat`.
	fn as_directed_mut(
		&mut self, source: &NodeId, target: &NodeId, capacity_msat: u64,
	) -> DirectedChannelLiquidity<&mut u64, &mut HistoricalLiquidityTracker, &mut Duration> {
		let source_less_than_target = source < target;
		let (min_liquidity_offset_msat, max_liquidity_offset_msat) =
			if source_less_than_target {
				(&mut self.min_liquidity_offset_msat, &mut self.max_liquidity_offset_msat)
			} else {
				(&mut self.max_liquidity_offset_msat, &mut self.min_liquidity_offset_msat)
			};

		DirectedChannelLiquidity {
			min_liquidity_offset_msat,
			max_liquidity_offset_msat,
			liquidity_history: self.liquidity_history.as_directed_mut(source_less_than_target),
			capacity_msat,
			last_updated: &mut self.last_updated,
			offset_history_last_updated: &mut self.offset_history_last_updated,
		}
	}

	fn decayed_offset(
		&self, offset: u64, duration_since_epoch: Duration,
		decay_params: ProbabilisticScoringDecayParameters,
	) -> u64 {
		let half_life = decay_params.liquidity_offset_half_life.as_secs_f64();
		if half_life != 0.0 {
			let elapsed_time = duration_since_epoch.saturating_sub(self.last_updated).as_secs_f64();
			((offset as f64) * powf64(0.5, elapsed_time / half_life)) as u64
		} else {
			0
		}
	}
}

/// Bounds `-log10` to avoid excessive liquidity penalties for payments with low success
/// probabilities.
const NEGATIVE_LOG10_UPPER_BOUND: u64 = 2;

/// The rough cutoff at which our precision falls off and we should stop bothering to try to log a
/// ratio, as X in 1/X.
const PRECISION_LOWER_BOUND_DENOMINATOR: u64 = log_approx::LOWER_BITS_BOUND;

/// The divisor used when computing the amount penalty.
const AMOUNT_PENALTY_DIVISOR: u64 = 1 << 20;
const BASE_AMOUNT_PENALTY_DIVISOR: u64 = 1 << 30;

/// Raises three `f64`s to the 3rd power, without `powi` because it requires `std` (dunno why).
#[inline(always)]
fn three_f64_pow_3(a: f64, b: f64, c: f64) -> (f64, f64, f64) {
	(a * a * a, b * b * b, c * c * c)
}

/// Given liquidity bounds, calculates the success probability (in the form of a numerator and
/// denominator) of an HTLC. This is a key assumption in our scoring models.
///
/// Must not return a numerator or denominator greater than 2^31 for arguments less than 2^31.
///
/// min_zero_implies_no_successes signals that a `min_liquidity_msat` of 0 means we've not
/// (recently) seen an HTLC successfully complete over this channel.
#[inline(always)]
fn success_probability(
	amount_msat: u64, min_liquidity_msat: u64, max_liquidity_msat: u64, capacity_msat: u64,
	params: &ProbabilisticScoringFeeParameters, min_zero_implies_no_successes: bool,
) -> (u64, u64) {
	debug_assert!(min_liquidity_msat <= amount_msat);
	debug_assert!(amount_msat < max_liquidity_msat);
	debug_assert!(max_liquidity_msat <= capacity_msat);

	let (numerator, mut denominator) =
		if params.linear_success_probability {
			(max_liquidity_msat - amount_msat,
				(max_liquidity_msat - min_liquidity_msat).saturating_add(1))
		} else {
			let capacity = capacity_msat as f64;
			let min = (min_liquidity_msat as f64) / capacity;
			let max = (max_liquidity_msat as f64) / capacity;
			let amount = (amount_msat as f64) / capacity;

			// Assume the channel has a probability density function of (x - 0.5)^2 for values from
			// 0 to 1 (where 1 is the channel's full capacity). The success probability given some
			// liquidity bounds is thus the integral under the curve from the amount to maximum
			// estimated liquidity, divided by the same integral from the minimum to the maximum
			// estimated liquidity bounds.
			//
			// Because the integral from x to y is simply (y - 0.5)^3 - (x - 0.5)^3, we can
			// calculate the cumulative density function between the min/max bounds trivially. Note
			// that we don't bother to normalize the CDF to total to 1, as it will come out in the
			// division of num / den.
			let (max_pow, amt_pow, min_pow) = three_f64_pow_3(max - 0.5, amount - 0.5, min - 0.5);
			let num = max_pow - amt_pow;
			let den = max_pow - min_pow;

			// Because our numerator and denominator max out at 0.5^3 we need to multiply them by
			// quite a large factor to get something useful (ideally in the 2^30 range).
			const BILLIONISH: f64 = 1024.0 * 1024.0 * 1024.0;
			let numerator = (num * BILLIONISH) as u64 + 1;
			let denominator = (den * BILLIONISH) as u64 + 1;
			debug_assert!(numerator <= 1 << 30, "Got large numerator ({}) from float {}.", numerator, num);
			debug_assert!(denominator <= 1 << 30, "Got large denominator ({}) from float {}.", denominator, den);
			(numerator, denominator)
		};

	if min_zero_implies_no_successes && min_liquidity_msat == 0 &&
		denominator < u64::max_value() / 21
	{
		// If we have no knowledge of the channel, scale probability down by ~75%
		// Note that we prefer to increase the denominator rather than decrease the numerator as
		// the denominator is more likely to be larger and thus provide greater precision. This is
		// mostly an overoptimization but makes a large difference in tests.
		denominator = denominator * 21 / 16
	}

	(numerator, denominator)
}

impl<L: Deref<Target = u64>, HT: Deref<Target = HistoricalLiquidityTracker>, T: Deref<Target = Duration>>
DirectedChannelLiquidity< L, HT, T> {
	/// Returns a liquidity penalty for routing the given HTLC `amount_msat` through the channel in
	/// this direction.
	fn penalty_msat(&self, amount_msat: u64, score_params: &ProbabilisticScoringFeeParameters) -> u64 {
		let available_capacity = self.capacity_msat;
		let max_liquidity_msat = self.max_liquidity_msat();
		let min_liquidity_msat = core::cmp::min(self.min_liquidity_msat(), max_liquidity_msat);

		let mut res = if amount_msat <= min_liquidity_msat {
			0
		} else if amount_msat >= max_liquidity_msat {
			// Equivalent to hitting the else clause below with the amount equal to the effective
			// capacity and without any certainty on the liquidity upper bound, plus the
			// impossibility penalty.
			let negative_log10_times_2048 = NEGATIVE_LOG10_UPPER_BOUND * 2048;
			Self::combined_penalty_msat(amount_msat, negative_log10_times_2048,
					score_params.liquidity_penalty_multiplier_msat,
					score_params.liquidity_penalty_amount_multiplier_msat)
				.saturating_add(score_params.considered_impossible_penalty_msat)
		} else {
			let (numerator, denominator) = success_probability(amount_msat,
				min_liquidity_msat, max_liquidity_msat, available_capacity, score_params, false);
			if denominator - numerator < denominator / PRECISION_LOWER_BOUND_DENOMINATOR {
				// If the failure probability is < 1.5625% (as 1 - numerator/denominator < 1/64),
				// don't bother trying to use the log approximation as it gets too noisy to be
				// particularly helpful, instead just round down to 0.
				0
			} else {
				let negative_log10_times_2048 =
					log_approx::negative_log10_times_2048(numerator, denominator);
				Self::combined_penalty_msat(amount_msat, negative_log10_times_2048,
					score_params.liquidity_penalty_multiplier_msat,
					score_params.liquidity_penalty_amount_multiplier_msat)
			}
		};

		if amount_msat >= available_capacity {
			// We're trying to send more than the capacity, use a max penalty.
			res = res.saturating_add(Self::combined_penalty_msat(amount_msat,
				NEGATIVE_LOG10_UPPER_BOUND * 2048,
				score_params.historical_liquidity_penalty_multiplier_msat,
				score_params.historical_liquidity_penalty_amount_multiplier_msat));
			return res;
		}

		if score_params.historical_liquidity_penalty_multiplier_msat != 0 ||
		   score_params.historical_liquidity_penalty_amount_multiplier_msat != 0 {
			if let Some(cumulative_success_prob_times_billion) = self.liquidity_history
				.calculate_success_probability_times_billion(
					score_params, amount_msat, self.capacity_msat)
			{
				let historical_negative_log10_times_2048 =
					log_approx::negative_log10_times_2048(cumulative_success_prob_times_billion + 1, 1024 * 1024 * 1024);
				res = res.saturating_add(Self::combined_penalty_msat(amount_msat,
					historical_negative_log10_times_2048, score_params.historical_liquidity_penalty_multiplier_msat,
					score_params.historical_liquidity_penalty_amount_multiplier_msat));
			} else {
				// If we don't have any valid points (or, once decayed, we have less than a full
				// point), redo the non-historical calculation with no liquidity bounds tracked and
				// the historical penalty multipliers.
				let (numerator, denominator) = success_probability(amount_msat, 0,
					available_capacity, available_capacity, score_params, true);
				let negative_log10_times_2048 =
					log_approx::negative_log10_times_2048(numerator, denominator);
				res = res.saturating_add(Self::combined_penalty_msat(amount_msat, negative_log10_times_2048,
					score_params.historical_liquidity_penalty_multiplier_msat,
					score_params.historical_liquidity_penalty_amount_multiplier_msat));
			}
		}

		res
	}

	/// Computes the liquidity penalty from the penalty multipliers.
	#[inline(always)]
	fn combined_penalty_msat(amount_msat: u64, mut negative_log10_times_2048: u64,
		liquidity_penalty_multiplier_msat: u64, liquidity_penalty_amount_multiplier_msat: u64,
	) -> u64 {
		negative_log10_times_2048 =
			negative_log10_times_2048.min(NEGATIVE_LOG10_UPPER_BOUND * 2048);

		// Upper bound the liquidity penalty to ensure some channel is selected.
		let liquidity_penalty_msat = negative_log10_times_2048
			.saturating_mul(liquidity_penalty_multiplier_msat) / 2048;
		let amount_penalty_msat = negative_log10_times_2048
			.saturating_mul(liquidity_penalty_amount_multiplier_msat)
			.saturating_mul(amount_msat) / 2048 / AMOUNT_PENALTY_DIVISOR;

		liquidity_penalty_msat.saturating_add(amount_penalty_msat)
	}

	/// Returns the lower bound of the channel liquidity balance in this direction.
	#[inline(always)]
	fn min_liquidity_msat(&self) -> u64 {
		*self.min_liquidity_offset_msat
	}

	/// Returns the upper bound of the channel liquidity balance in this direction.
	#[inline(always)]
	fn max_liquidity_msat(&self) -> u64 {
		self.capacity_msat
			.saturating_sub(*self.max_liquidity_offset_msat)
	}
}

impl<L: DerefMut<Target = u64>, HT: DerefMut<Target = HistoricalLiquidityTracker>, T: DerefMut<Target = Duration>>
DirectedChannelLiquidity<L, HT, T> {
	/// Adjusts the channel liquidity balance bounds when failing to route `amount_msat`.
	fn failed_at_channel<Log: Deref>(
		&mut self, amount_msat: u64, duration_since_epoch: Duration, chan_descr: fmt::Arguments, logger: &Log
	) where Log::Target: Logger {
		let existing_max_msat = self.max_liquidity_msat();
		if amount_msat < existing_max_msat {
			log_debug!(logger, "Setting max liquidity of {} from {} to {}", chan_descr, existing_max_msat, amount_msat);
			self.set_max_liquidity_msat(amount_msat, duration_since_epoch);
		} else {
			log_trace!(logger, "Max liquidity of {} is {} (already less than or equal to {})",
				chan_descr, existing_max_msat, amount_msat);
		}
		self.update_history_buckets(0, duration_since_epoch);
	}

	/// Adjusts the channel liquidity balance bounds when failing to route `amount_msat` downstream.
	fn failed_downstream<Log: Deref>(
		&mut self, amount_msat: u64, duration_since_epoch: Duration, chan_descr: fmt::Arguments, logger: &Log
	) where Log::Target: Logger {
		let existing_min_msat = self.min_liquidity_msat();
		if amount_msat > existing_min_msat {
			log_debug!(logger, "Setting min liquidity of {} from {} to {}", existing_min_msat, chan_descr, amount_msat);
			self.set_min_liquidity_msat(amount_msat, duration_since_epoch);
		} else {
			log_trace!(logger, "Min liquidity of {} is {} (already greater than or equal to {})",
				chan_descr, existing_min_msat, amount_msat);
		}
		self.update_history_buckets(0, duration_since_epoch);
	}

	/// Adjusts the channel liquidity balance bounds when successfully routing `amount_msat`.
	fn successful<Log: Deref>(&mut self,
		amount_msat: u64, duration_since_epoch: Duration, chan_descr: fmt::Arguments, logger: &Log
	) where Log::Target: Logger {
		let max_liquidity_msat = self.max_liquidity_msat().checked_sub(amount_msat).unwrap_or(0);
		log_debug!(logger, "Subtracting {} from max liquidity of {} (setting it to {})", amount_msat, chan_descr, max_liquidity_msat);
		self.set_max_liquidity_msat(max_liquidity_msat, duration_since_epoch);
		self.update_history_buckets(amount_msat, duration_since_epoch);
	}

	/// Updates the history buckets for this channel. Because the history buckets track what we now
	/// know about the channel's state *prior to our payment* (i.e. what we assume is "steady
	/// state"), we allow the caller to set an offset applied to our liquidity bounds which
	/// represents the amount of the successful payment we just made.
	fn update_history_buckets(&mut self, bucket_offset_msat: u64, duration_since_epoch: Duration) {
		self.liquidity_history.track_datapoint(
			*self.min_liquidity_offset_msat + bucket_offset_msat,
			self.max_liquidity_offset_msat.saturating_sub(bucket_offset_msat),
			self.capacity_msat,
		);
		*self.offset_history_last_updated = duration_since_epoch;
	}

	/// Adjusts the lower bound of the channel liquidity balance in this direction.
	fn set_min_liquidity_msat(&mut self, amount_msat: u64, duration_since_epoch: Duration) {
		*self.min_liquidity_offset_msat = amount_msat;
		if amount_msat > self.max_liquidity_msat() {
			*self.max_liquidity_offset_msat = 0;
		}
		*self.last_updated = duration_since_epoch;
	}

	/// Adjusts the upper bound of the channel liquidity balance in this direction.
	fn set_max_liquidity_msat(&mut self, amount_msat: u64, duration_since_epoch: Duration) {
		*self.max_liquidity_offset_msat = self.capacity_msat.checked_sub(amount_msat).unwrap_or(0);
		if amount_msat < *self.min_liquidity_offset_msat {
			*self.min_liquidity_offset_msat = 0;
		}
		*self.last_updated = duration_since_epoch;
	}
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> ScoreLookUp for ProbabilisticScorer<G, L> where L::Target: Logger {
	type ScoreParams = ProbabilisticScoringFeeParameters;
	fn channel_penalty_msat(
		&self, candidate: &CandidateRouteHop, usage: ChannelUsage, score_params: &ProbabilisticScoringFeeParameters
	) -> u64 {
		let (scid, target) = match candidate {
			CandidateRouteHop::PublicHop(PublicHopCandidate { info, short_channel_id }) => {
				(short_channel_id, info.target())
			},
			_ => return 0,
		};
		let source = candidate.source();
		if let Some(penalty) = score_params.manual_node_penalties.get(target) {
			return *penalty;
		}

		let base_penalty_msat = score_params.base_penalty_msat.saturating_add(
			score_params.base_penalty_amount_multiplier_msat
				.saturating_mul(usage.amount_msat) / BASE_AMOUNT_PENALTY_DIVISOR);

		let mut anti_probing_penalty_msat = 0;
		match usage.effective_capacity {
			EffectiveCapacity::ExactLiquidity { liquidity_msat: amount_msat } |
				EffectiveCapacity::HintMaxHTLC { amount_msat } =>
			{
				if usage.amount_msat > amount_msat {
					return u64::max_value();
				} else {
					return base_penalty_msat;
				}
			},
			EffectiveCapacity::Total { capacity_msat, htlc_maximum_msat } => {
				if htlc_maximum_msat >= capacity_msat/2 {
					anti_probing_penalty_msat = score_params.anti_probing_penalty_msat;
				}
			},
			_ => {},
		}

		let amount_msat = usage.amount_msat.saturating_add(usage.inflight_htlc_msat);
		let capacity_msat = usage.effective_capacity.as_msat();
		self.channel_liquidities
			.get(scid)
			.unwrap_or(&ChannelLiquidity::new(Duration::ZERO))
			.as_directed(&source, &target, capacity_msat)
			.penalty_msat(amount_msat, score_params)
			.saturating_add(anti_probing_penalty_msat)
			.saturating_add(base_penalty_msat)
	}
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> ScoreUpdate for ProbabilisticScorer<G, L> where L::Target: Logger {
	fn payment_path_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration) {
		let amount_msat = path.final_value_msat();
		log_trace!(self.logger, "Scoring path through to SCID {} as having failed at {} msat", short_channel_id, amount_msat);
		let network_graph = self.network_graph.read_only();
		for (hop_idx, hop) in path.hops.iter().enumerate() {
			let target = NodeId::from_pubkey(&hop.pubkey);
			let channel_directed_from_source = network_graph.channels()
				.get(&hop.short_channel_id)
				.and_then(|channel| channel.as_directed_to(&target));

			let at_failed_channel = hop.short_channel_id == short_channel_id;
			if at_failed_channel && hop_idx == 0 {
				log_warn!(self.logger, "Payment failed at the first hop - we do not attempt to learn channel info in such cases as we can directly observe local state.\n\tBecause we know the local state, we should generally not see failures here - this may be an indication that your channel peer on channel {} is broken and you may wish to close the channel.", hop.short_channel_id);
			}

			// Only score announced channels.
			if let Some((channel, source)) = channel_directed_from_source {
				let capacity_msat = channel.effective_capacity().as_msat();
				if at_failed_channel {
					self.channel_liquidities
						.entry(hop.short_channel_id)
						.or_insert_with(|| ChannelLiquidity::new(duration_since_epoch))
						.as_directed_mut(source, &target, capacity_msat)
						.failed_at_channel(amount_msat, duration_since_epoch,
							format_args!("SCID {}, towards {:?}", hop.short_channel_id, target), &self.logger);
				} else {
					self.channel_liquidities
						.entry(hop.short_channel_id)
						.or_insert_with(|| ChannelLiquidity::new(duration_since_epoch))
						.as_directed_mut(source, &target, capacity_msat)
						.failed_downstream(amount_msat, duration_since_epoch,
							format_args!("SCID {}, towards {:?}", hop.short_channel_id, target), &self.logger);
				}
			} else {
				log_debug!(self.logger, "Not able to penalize channel with SCID {} as we do not have graph info for it (likely a route-hint last-hop).",
					hop.short_channel_id);
			}
			if at_failed_channel { break; }
		}
	}

	fn payment_path_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
		let amount_msat = path.final_value_msat();
		log_trace!(self.logger, "Scoring path through SCID {} as having succeeded at {} msat.",
			path.hops.split_last().map(|(hop, _)| hop.short_channel_id).unwrap_or(0), amount_msat);
		let network_graph = self.network_graph.read_only();
		for hop in &path.hops {
			let target = NodeId::from_pubkey(&hop.pubkey);
			let channel_directed_from_source = network_graph.channels()
				.get(&hop.short_channel_id)
				.and_then(|channel| channel.as_directed_to(&target));

			// Only score announced channels.
			if let Some((channel, source)) = channel_directed_from_source {
				let capacity_msat = channel.effective_capacity().as_msat();
				self.channel_liquidities
					.entry(hop.short_channel_id)
					.or_insert_with(|| ChannelLiquidity::new(duration_since_epoch))
					.as_directed_mut(source, &target, capacity_msat)
					.successful(amount_msat, duration_since_epoch,
						format_args!("SCID {}, towards {:?}", hop.short_channel_id, target), &self.logger);
			} else {
				log_debug!(self.logger, "Not able to learn for channel with SCID {} as we do not have graph info for it (likely a route-hint last-hop).",
					hop.short_channel_id);
			}
		}
	}

	fn probe_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration) {
		self.payment_path_failed(path, short_channel_id, duration_since_epoch)
	}

	fn probe_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
		self.payment_path_failed(path, u64::max_value(), duration_since_epoch)
	}

	fn time_passed(&mut self, duration_since_epoch: Duration) {
		let decay_params = self.decay_params;
		self.channel_liquidities.retain(|_scid, liquidity| {
			liquidity.min_liquidity_offset_msat =
				liquidity.decayed_offset(liquidity.min_liquidity_offset_msat, duration_since_epoch, decay_params);
			liquidity.max_liquidity_offset_msat =
				liquidity.decayed_offset(liquidity.max_liquidity_offset_msat, duration_since_epoch, decay_params);
			liquidity.last_updated = duration_since_epoch;

			let elapsed_time =
				duration_since_epoch.saturating_sub(liquidity.offset_history_last_updated);
			if elapsed_time > decay_params.historical_no_updates_half_life {
				let half_life = decay_params.historical_no_updates_half_life.as_secs_f64();
				if half_life != 0.0 {
					liquidity.liquidity_history.decay_buckets(elapsed_time.as_secs_f64() / half_life);
					liquidity.offset_history_last_updated = duration_since_epoch;
				}
			}
			liquidity.min_liquidity_offset_msat != 0 || liquidity.max_liquidity_offset_msat != 0 ||
				liquidity.liquidity_history.has_datapoints()
		});
	}
}

#[cfg(c_bindings)]
impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> Score for ProbabilisticScorer<G, L>
where L::Target: Logger {}

#[cfg(feature = "std")]
#[inline]
fn powf64(n: f64, exp: f64) -> f64 {
	n.powf(exp)
}
#[cfg(not(feature = "std"))]
fn powf64(n: f64, exp: f64) -> f64 {
	libm::powf(n as f32, exp as f32) as f64
}

mod bucketed_history {
	use super::*;

	// Because liquidity is often skewed heavily in one direction, we store historical state
	// distribution in buckets of different size. For backwards compatibility, buckets of size 1/8th
	// must fit evenly into the buckets here.
	//
	// The smallest bucket is 2^-14th of the channel, for each of our 32 buckets here we define the
	// width of the bucket in 2^14'ths of the channel. This increases exponentially until we reach
	// a full 16th of the channel's capacity, which is reapeated a few times for backwards
	// compatibility. The four middle buckets represent full octiles of the channel's capacity.
	//
	// For a 1 BTC channel, this let's us differentiate between failures in the bottom 6k sats, or
	// between the 12,000th sat and 24,000th sat, while only needing to store and operate on 32
	// buckets in total.

	const BUCKET_START_POS: [u16; 33] = [
		0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 3072, 4096, 6144, 8192, 10240, 12288,
		13312, 14336, 15360, 15872, 16128, 16256, 16320, 16352, 16368, 16376, 16380, 16382, 16383, 16384,
	];

	const LEGACY_TO_BUCKET_RANGE: [(u8, u8); 8] = [
		(0, 12), (12, 14), (14, 15), (15, 16), (16, 17), (17, 18), (18, 20), (20, 32)
	];

	const POSITION_TICKS: u16 = 1 << 14;

	fn pos_to_bucket(pos: u16) -> usize {
		for bucket in 0..32 {
			if pos < BUCKET_START_POS[bucket + 1] {
				return bucket;
			}
		}
		debug_assert!(false);
		return 32;
	}

	#[cfg(test)]
	#[test]
	fn check_bucket_maps() {
		const BUCKET_WIDTH_IN_16384S: [u16; 32] = [
			1, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1024, 1024, 2048, 2048,
			2048, 2048, 1024, 1024, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1, 1];

		let mut min_size_iter = 0;
		let mut legacy_bucket_iter = 0;
		for (bucket, width) in BUCKET_WIDTH_IN_16384S.iter().enumerate() {
			assert_eq!(BUCKET_START_POS[bucket], min_size_iter);
			for i in 0..*width {
				assert_eq!(pos_to_bucket(min_size_iter + i) as usize, bucket);
			}
			min_size_iter += *width;
			if min_size_iter % (POSITION_TICKS / 8) == 0 {
				assert_eq!(LEGACY_TO_BUCKET_RANGE[legacy_bucket_iter].1 as usize, bucket + 1);
				if legacy_bucket_iter + 1 < 8 {
					assert_eq!(LEGACY_TO_BUCKET_RANGE[legacy_bucket_iter + 1].0 as usize, bucket + 1);
				}
				legacy_bucket_iter += 1;
			}
		}
		assert_eq!(BUCKET_START_POS[32], POSITION_TICKS);
		assert_eq!(min_size_iter, POSITION_TICKS);
	}

	#[inline]
	fn amount_to_pos(amount_msat: u64, capacity_msat: u64) -> u16 {
		let pos = if amount_msat < u64::max_value() / (POSITION_TICKS as u64) {
			(amount_msat * (POSITION_TICKS as u64) / capacity_msat.saturating_add(1))
				.try_into().unwrap_or(POSITION_TICKS)
		} else {
			// Only use 128-bit arithmetic when multiplication will overflow to avoid 128-bit
			// division. This branch should only be hit in fuzz testing since the amount would
			// need to be over 2.88 million BTC in practice.
			((amount_msat as u128) * (POSITION_TICKS as u128)
					/ (capacity_msat as u128).saturating_add(1))
				.try_into().unwrap_or(POSITION_TICKS)
		};
		// If we are running in a client that doesn't validate gossip, its possible for a channel's
		// capacity to change due to a `channel_update` message which, if received while a payment
		// is in-flight, could cause this to fail. Thus, we only assert in test.
		#[cfg(test)]
		debug_assert!(pos < POSITION_TICKS);
		pos
	}

	/// Prior to LDK 0.0.117 we used eight buckets which were split evenly across the either
	/// octiles. This was changed to use 32 buckets for accuracy reasons in 0.0.117, however we
	/// support reading the legacy values here for backwards compatibility.
	pub(super) struct LegacyHistoricalBucketRangeTracker {
		buckets: [u16; 8],
	}

	impl LegacyHistoricalBucketRangeTracker {
		pub(crate) fn into_current(&self) -> HistoricalBucketRangeTracker {
			let mut buckets = [0; 32];
			for (idx, legacy_bucket) in self.buckets.iter().enumerate() {
				let mut new_val = *legacy_bucket;
				let (start, end) = LEGACY_TO_BUCKET_RANGE[idx];
				new_val /= (end - start) as u16;
				for i in start..end {
					buckets[i as usize] = new_val;
				}
			}
			HistoricalBucketRangeTracker { buckets }
		}
	}

	/// Tracks the historical state of a distribution as a weighted average of how much time was spent
	/// in each of 32 buckets.
	#[derive(Clone, Copy)]
	pub(super) struct HistoricalBucketRangeTracker {
		buckets: [u16; 32],
	}

	/// Buckets are stored in fixed point numbers with a 5 bit fractional part. Thus, the value
	/// "one" is 32, or this constant.
	pub const BUCKET_FIXED_POINT_ONE: u16 = 32;

	impl HistoricalBucketRangeTracker {
		pub(super) fn new() -> Self { Self { buckets: [0; 32] } }
		fn track_datapoint(&mut self, liquidity_offset_msat: u64, capacity_msat: u64) {
			// We have 32 leaky buckets for min and max liquidity. Each bucket tracks the amount of time
			// we spend in each bucket as a 16-bit fixed-point number with a 5 bit fractional part.
			//
			// Each time we update our liquidity estimate, we add 32 (1.0 in our fixed-point system) to
			// the buckets for the current min and max liquidity offset positions.
			//
			// We then decay each bucket by multiplying by 2047/2048 (avoiding dividing by a
			// non-power-of-two). This ensures we can't actually overflow the u16 - when we get to
			// 63,457 adding 32 and decaying by 2047/2048 leaves us back at 63,457.
			//
			// In total, this allows us to track data for the last 8,000 or so payments across a given
			// channel.
			//
			// These constants are a balance - we try to fit in 2 bytes per bucket to reduce overhead,
			// and need to balance having more bits in the decimal part (to ensure decay isn't too
			// non-linear) with having too few bits in the mantissa, causing us to not store very many
			// datapoints.
			//
			// The constants were picked experimentally, selecting a decay amount that restricts us
			// from overflowing buckets without having to cap them manually.

			let pos: u16 = amount_to_pos(liquidity_offset_msat, capacity_msat);
			if pos < POSITION_TICKS {
				for e in self.buckets.iter_mut() {
					*e = ((*e as u32) * 2047 / 2048) as u16;
				}
				let bucket = pos_to_bucket(pos);
				self.buckets[bucket] = self.buckets[bucket].saturating_add(BUCKET_FIXED_POINT_ONE);
			}
		}
	}

	impl_writeable_tlv_based!(HistoricalBucketRangeTracker, { (0, buckets, required) });
	impl_writeable_tlv_based!(LegacyHistoricalBucketRangeTracker, { (0, buckets, required) });

	#[derive(Clone, Copy)]
	pub(super) struct HistoricalLiquidityTracker {
		min_liquidity_offset_history: HistoricalBucketRangeTracker,
		max_liquidity_offset_history: HistoricalBucketRangeTracker,
		total_valid_points_tracked: u64,
	}

	impl HistoricalLiquidityTracker {
		pub(super) fn new() -> HistoricalLiquidityTracker {
			HistoricalLiquidityTracker {
				min_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
				max_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
				total_valid_points_tracked: 0,
			}
		}

		pub(super) fn from_min_max(
			min_liquidity_offset_history: HistoricalBucketRangeTracker,
			max_liquidity_offset_history: HistoricalBucketRangeTracker,
		) -> HistoricalLiquidityTracker {
			let mut res = HistoricalLiquidityTracker {
				min_liquidity_offset_history,
				max_liquidity_offset_history,
				total_valid_points_tracked: 0,
			};
			res.recalculate_valid_point_count();
			res
		}

		pub(super) fn has_datapoints(&self) -> bool {
			self.min_liquidity_offset_history.buckets != [0; 32] ||
				self.max_liquidity_offset_history.buckets != [0; 32]
		}

		pub(super) fn decay_buckets(&mut self, half_lives: f64) {
			let divisor = powf64(2048.0, half_lives) as u64;
			for bucket in self.min_liquidity_offset_history.buckets.iter_mut() {
				*bucket = ((*bucket as u64) * 1024 / divisor) as u16;
			}
			for bucket in self.max_liquidity_offset_history.buckets.iter_mut() {
				*bucket = ((*bucket as u64) * 1024 / divisor) as u16;
			}
			self.recalculate_valid_point_count();
		}

		fn recalculate_valid_point_count(&mut self) {
			self.total_valid_points_tracked = 0;
			for (min_idx, min_bucket) in self.min_liquidity_offset_history.buckets.iter().enumerate() {
				for max_bucket in self.max_liquidity_offset_history.buckets.iter().take(32 - min_idx) {
					self.total_valid_points_tracked += (*min_bucket as u64) * (*max_bucket as u64);
				}
			}
		}

		pub(super) fn writeable_min_offset_history(&self) -> &HistoricalBucketRangeTracker {
			&self.min_liquidity_offset_history
		}

		pub(super) fn writeable_max_offset_history(&self) -> &HistoricalBucketRangeTracker {
			&self.max_liquidity_offset_history
		}

		pub(super) fn as_directed<'a>(&'a self, source_less_than_target: bool)
		-> DirectedHistoricalLiquidityTracker<&'a HistoricalLiquidityTracker> {
			DirectedHistoricalLiquidityTracker { source_less_than_target, tracker: self }
		}

		pub(super) fn as_directed_mut<'a>(&'a mut self, source_less_than_target: bool)
		-> DirectedHistoricalLiquidityTracker<&'a mut HistoricalLiquidityTracker> {
			DirectedHistoricalLiquidityTracker { source_less_than_target, tracker: self }
		}
	}

	/// A set of buckets representing the history of where we've seen the minimum- and maximum-
	/// liquidity bounds for a given channel.
	pub(super) struct DirectedHistoricalLiquidityTracker<D: Deref<Target = HistoricalLiquidityTracker>> {
		source_less_than_target: bool,
		tracker: D,
	}

	impl<D: DerefMut<Target = HistoricalLiquidityTracker>> DirectedHistoricalLiquidityTracker<D> {
		pub(super) fn track_datapoint(
			&mut self, min_offset_msat: u64, max_offset_msat: u64, capacity_msat: u64,
		) {
			if self.source_less_than_target {
				self.tracker.min_liquidity_offset_history.track_datapoint(min_offset_msat, capacity_msat);
				self.tracker.max_liquidity_offset_history.track_datapoint(max_offset_msat, capacity_msat);
			} else {
				self.tracker.max_liquidity_offset_history.track_datapoint(min_offset_msat, capacity_msat);
				self.tracker.min_liquidity_offset_history.track_datapoint(max_offset_msat, capacity_msat);
			}
			self.tracker.recalculate_valid_point_count();
		}
	}

	impl<D: Deref<Target = HistoricalLiquidityTracker>> DirectedHistoricalLiquidityTracker<D> {
		pub(super) fn min_liquidity_offset_history_buckets(&self) -> &[u16; 32] {
			if self.source_less_than_target {
				&self.tracker.min_liquidity_offset_history.buckets
			} else {
				&self.tracker.max_liquidity_offset_history.buckets
			}
		}

		pub(super) fn max_liquidity_offset_history_buckets(&self) -> &[u16; 32] {
			if self.source_less_than_target {
				&self.tracker.max_liquidity_offset_history.buckets
			} else {
				&self.tracker.min_liquidity_offset_history.buckets
			}
		}

		#[inline]
		pub(super) fn calculate_success_probability_times_billion(
			&self, params: &ProbabilisticScoringFeeParameters, amount_msat: u64,
			capacity_msat: u64
		) -> Option<u64> {
			// If historical penalties are enabled, we try to calculate a probability of success
			// given our historical distribution of min- and max-liquidity bounds in a channel.
			// To do so, we walk the set of historical liquidity bucket (min, max) combinations
			// (where min_idx < max_idx, as having a minimum above our maximum is an invalid
			// state). For each pair, we calculate the probability as if the bucket's corresponding
			// min- and max- liquidity bounds were our current liquidity bounds and then multiply
			// that probability by the weight of the selected buckets.
			let payment_pos = amount_to_pos(amount_msat, capacity_msat);
			if payment_pos >= POSITION_TICKS { return None; }

			let min_liquidity_offset_history_buckets =
				self.min_liquidity_offset_history_buckets();
			let max_liquidity_offset_history_buckets =
				self.max_liquidity_offset_history_buckets();

			let total_valid_points_tracked = self.tracker.total_valid_points_tracked;
			#[cfg(debug_assertions)] {
				let mut actual_valid_points_tracked = 0;
				for (min_idx, min_bucket) in min_liquidity_offset_history_buckets.iter().enumerate() {
					for max_bucket in max_liquidity_offset_history_buckets.iter().take(32 - min_idx) {
						actual_valid_points_tracked += (*min_bucket as u64) * (*max_bucket as u64);
					}
				}
				assert_eq!(total_valid_points_tracked, actual_valid_points_tracked);
			}

			// If the total valid points is smaller than 1.0 (i.e. 32 in our fixed-point scheme),
			// treat it as if we were fully decayed.
			const FULLY_DECAYED: u16 = BUCKET_FIXED_POINT_ONE * BUCKET_FIXED_POINT_ONE;
			if total_valid_points_tracked < FULLY_DECAYED.into() {
				return None;
			}

			let mut cumulative_success_prob_times_billion = 0;
			// Special-case the 0th min bucket - it generally means we failed a payment, so only
			// consider the highest (i.e. largest-offset-from-max-capacity) max bucket for all
			// points against the 0th min bucket. This avoids the case where we fail to route
			// increasingly lower values over a channel, but treat each failure as a separate
			// datapoint, many of which may have relatively high maximum-available-liquidity
			// values, which will result in us thinking we have some nontrivial probability of
			// routing up to that amount.
			if min_liquidity_offset_history_buckets[0] != 0 {
				let mut highest_max_bucket_with_points = 0; // The highest max-bucket with any data
				let mut total_max_points = 0; // Total points in max-buckets to consider
				for (max_idx, max_bucket) in max_liquidity_offset_history_buckets.iter().enumerate() {
					if *max_bucket >= BUCKET_FIXED_POINT_ONE {
						highest_max_bucket_with_points = cmp::max(highest_max_bucket_with_points, max_idx);
					}
					total_max_points += *max_bucket as u64;
				}
				let max_bucket_end_pos = BUCKET_START_POS[32 - highest_max_bucket_with_points] - 1;
				if payment_pos < max_bucket_end_pos {
					let (numerator, denominator) = success_probability(payment_pos as u64, 0,
						max_bucket_end_pos as u64, POSITION_TICKS as u64 - 1, params, true);
					let bucket_prob_times_billion =
						(min_liquidity_offset_history_buckets[0] as u64) * total_max_points
							* 1024 * 1024 * 1024 / total_valid_points_tracked;
					cumulative_success_prob_times_billion += bucket_prob_times_billion *
						numerator / denominator;
				}
			}

			for (min_idx, min_bucket) in min_liquidity_offset_history_buckets.iter().enumerate().skip(1) {
				let min_bucket_start_pos = BUCKET_START_POS[min_idx];
				for (max_idx, max_bucket) in max_liquidity_offset_history_buckets.iter().enumerate().take(32 - min_idx) {
					let max_bucket_end_pos = BUCKET_START_POS[32 - max_idx] - 1;
					// Note that this multiply can only barely not overflow - two 16 bit ints plus
					// 30 bits is 62 bits.
					let bucket_prob_times_billion = (*min_bucket as u64) * (*max_bucket as u64)
						* 1024 * 1024 * 1024 / total_valid_points_tracked;
					if payment_pos >= max_bucket_end_pos {
						// Success probability 0, the payment amount may be above the max liquidity
						break;
					} else if payment_pos < min_bucket_start_pos {
						cumulative_success_prob_times_billion += bucket_prob_times_billion;
					} else {
						let (numerator, denominator) = success_probability(payment_pos as u64,
							min_bucket_start_pos as u64, max_bucket_end_pos as u64,
							POSITION_TICKS as u64 - 1, params, true);
						cumulative_success_prob_times_billion += bucket_prob_times_billion *
							numerator / denominator;
					}
				}
			}

			Some(cumulative_success_prob_times_billion)
		}
	}
}
use bucketed_history::{LegacyHistoricalBucketRangeTracker, HistoricalBucketRangeTracker, DirectedHistoricalLiquidityTracker, HistoricalLiquidityTracker};

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> Writeable for ProbabilisticScorer<G, L> where L::Target: Logger {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(w, {
			(0, self.channel_liquidities, required),
		});
		Ok(())
	}
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref>
ReadableArgs<(ProbabilisticScoringDecayParameters, G, L)> for ProbabilisticScorer<G, L> where L::Target: Logger {
	#[inline]
	fn read<R: Read>(
		r: &mut R, args: (ProbabilisticScoringDecayParameters, G, L)
	) -> Result<Self, DecodeError> {
		let (decay_params, network_graph, logger) = args;
		let mut channel_liquidities = new_hash_map();
		read_tlv_fields!(r, {
			(0, channel_liquidities, required),
		});
		Ok(Self {
			decay_params,
			network_graph,
			logger,
			channel_liquidities,
		})
	}
}

impl Writeable for ChannelLiquidity {
	#[inline]
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(w, {
			(0, self.min_liquidity_offset_msat, required),
			// 1 was the min_liquidity_offset_history in octile form
			(2, self.max_liquidity_offset_msat, required),
			// 3 was the max_liquidity_offset_history in octile form
			(4, self.last_updated, required),
			(5, self.liquidity_history.writeable_min_offset_history(), required),
			(7, self.liquidity_history.writeable_max_offset_history(), required),
			(9, self.offset_history_last_updated, required),
		});
		Ok(())
	}
}

impl Readable for ChannelLiquidity {
	#[inline]
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut min_liquidity_offset_msat = 0;
		let mut max_liquidity_offset_msat = 0;
		let mut legacy_min_liq_offset_history: Option<LegacyHistoricalBucketRangeTracker> = None;
		let mut legacy_max_liq_offset_history: Option<LegacyHistoricalBucketRangeTracker> = None;
		let mut min_liquidity_offset_history: Option<HistoricalBucketRangeTracker> = None;
		let mut max_liquidity_offset_history: Option<HistoricalBucketRangeTracker> = None;
		let mut last_updated = Duration::from_secs(0);
		let mut offset_history_last_updated = None;
		read_tlv_fields!(r, {
			(0, min_liquidity_offset_msat, required),
			(1, legacy_min_liq_offset_history, option),
			(2, max_liquidity_offset_msat, required),
			(3, legacy_max_liq_offset_history, option),
			(4, last_updated, required),
			(5, min_liquidity_offset_history, option),
			(7, max_liquidity_offset_history, option),
			(9, offset_history_last_updated, option),
		});

		if min_liquidity_offset_history.is_none() {
			if let Some(legacy_buckets) = legacy_min_liq_offset_history {
				min_liquidity_offset_history = Some(legacy_buckets.into_current());
			} else {
				min_liquidity_offset_history = Some(HistoricalBucketRangeTracker::new());
			}
		}
		if max_liquidity_offset_history.is_none() {
			if let Some(legacy_buckets) = legacy_max_liq_offset_history {
				max_liquidity_offset_history = Some(legacy_buckets.into_current());
			} else {
				max_liquidity_offset_history = Some(HistoricalBucketRangeTracker::new());
			}
		}
		Ok(Self {
			min_liquidity_offset_msat,
			max_liquidity_offset_msat,
			liquidity_history: HistoricalLiquidityTracker::from_min_max(
				min_liquidity_offset_history.unwrap(), max_liquidity_offset_history.unwrap()
			),
			last_updated,
			offset_history_last_updated: offset_history_last_updated.unwrap_or(last_updated),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::{ChannelLiquidity, HistoricalLiquidityTracker, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters, ProbabilisticScorer};
	use crate::blinded_path::BlindedHop;
	use crate::util::config::UserConfig;

	use crate::ln::channelmanager;
	use crate::ln::msgs::{ChannelAnnouncement, ChannelUpdate, UnsignedChannelAnnouncement, UnsignedChannelUpdate};
	use crate::routing::gossip::{EffectiveCapacity, NetworkGraph, NodeId};
	use crate::routing::router::{BlindedTail, Path, RouteHop, CandidateRouteHop, PublicHopCandidate};
	use crate::routing::scoring::{ChannelUsage, ScoreLookUp, ScoreUpdate};
	use crate::util::ser::{ReadableArgs, Writeable};
	use crate::util::test_utils::{self, TestLogger};

	use bitcoin::constants::ChainHash;
	use bitcoin::hashes::Hash;
	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::network::Network;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use core::time::Duration;
	use crate::io;

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

	// `ProbabilisticScorer` tests

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

	fn recipient_node_id() -> NodeId {
		NodeId::from_pubkey(&recipient_pubkey())
	}

	fn network_graph(logger: &TestLogger) -> NetworkGraph<&TestLogger> {
		let mut network_graph = NetworkGraph::new(Network::Testnet, logger);
		add_channel(&mut network_graph, 42, source_privkey(), target_privkey());
		add_channel(&mut network_graph, 43, target_privkey(), recipient_privkey());

		network_graph
	}

	fn add_channel(
		network_graph: &mut NetworkGraph<&TestLogger>, short_channel_id: u64, node_1_key: SecretKey,
		node_2_key: SecretKey
	) {
		let genesis_hash = ChainHash::using_genesis_block(Network::Testnet);
		let node_1_secret = &SecretKey::from_slice(&[39; 32]).unwrap();
		let node_2_secret = &SecretKey::from_slice(&[40; 32]).unwrap();
		let secp_ctx = Secp256k1::new();
		let unsigned_announcement = UnsignedChannelAnnouncement {
			features: channelmanager::provided_channel_features(&UserConfig::default()),
			chain_hash: genesis_hash,
			short_channel_id,
			node_id_1: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_1_key)),
			node_id_2: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_2_key)),
			bitcoin_key_1: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_1_secret)),
			bitcoin_key_2: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_2_secret)),
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let signed_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign_ecdsa(&msghash, &node_1_key),
			node_signature_2: secp_ctx.sign_ecdsa(&msghash, &node_2_key),
			bitcoin_signature_1: secp_ctx.sign_ecdsa(&msghash, &node_1_secret),
			bitcoin_signature_2: secp_ctx.sign_ecdsa(&msghash, &node_2_secret),
			contents: unsigned_announcement,
		};
		let chain_source: Option<&crate::util::test_utils::TestChainSource> = None;
		network_graph.update_channel_from_announcement(
			&signed_announcement, &chain_source).unwrap();
		update_channel(network_graph, short_channel_id, node_1_key, 0, 1_000, 100);
		update_channel(network_graph, short_channel_id, node_2_key, 1, 0, 100);
	}

	fn update_channel(
		network_graph: &mut NetworkGraph<&TestLogger>, short_channel_id: u64, node_key: SecretKey,
		channel_flags: u8, htlc_maximum_msat: u64, timestamp: u32,
	) {
		let genesis_hash = ChainHash::using_genesis_block(Network::Testnet);
		let secp_ctx = Secp256k1::new();
		let unsigned_update = UnsignedChannelUpdate {
			chain_hash: genesis_hash,
			short_channel_id,
			timestamp,
			message_flags: 1, // Only must_be_one
			channel_flags,
			cltv_expiry_delta: 18,
			htlc_minimum_msat: 0,
			htlc_maximum_msat,
			fee_base_msat: 1,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_update.encode()[..])[..]);
		let signed_update = ChannelUpdate {
			signature: secp_ctx.sign_ecdsa(&msghash, &node_key),
			contents: unsigned_update,
		};
		network_graph.update_channel(&signed_update).unwrap();
	}

	fn path_hop(pubkey: PublicKey, short_channel_id: u64, fee_msat: u64) -> RouteHop {
		let config = UserConfig::default();
		RouteHop {
			pubkey,
			node_features: channelmanager::provided_node_features(&config),
			short_channel_id,
			channel_features: channelmanager::provided_channel_features(&config),
			fee_msat,
			cltv_expiry_delta: 18,
			maybe_announced_channel: true,
		}
	}

	fn payment_path_for_amount(amount_msat: u64) -> Path {
		Path {
			hops: vec![
				path_hop(source_pubkey(), 41, 1),
				path_hop(target_pubkey(), 42, 2),
				path_hop(recipient_pubkey(), 43, amount_msat),
			], blinded_tail: None,
		}
	}

	#[test]
	fn liquidity_bounds_directed_from_lowest_node_id() {
		let logger = TestLogger::new();
		let last_updated = Duration::ZERO;
		let offset_history_last_updated = Duration::ZERO;
		let network_graph = network_graph(&logger);
		let decay_params = ProbabilisticScoringDecayParameters::default();
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger)
			.with_channel(42,
				ChannelLiquidity {
					min_liquidity_offset_msat: 700, max_liquidity_offset_msat: 100,
					last_updated, offset_history_last_updated,
					liquidity_history: HistoricalLiquidityTracker::new(),
				})
			.with_channel(43,
				ChannelLiquidity {
					min_liquidity_offset_msat: 700, max_liquidity_offset_msat: 100,
					last_updated, offset_history_last_updated,
					liquidity_history: HistoricalLiquidityTracker::new(),
				});
		let source = source_node_id();
		let target = target_node_id();
		let recipient = recipient_node_id();
		assert!(source > target);
		assert!(target < recipient);

		// Update minimum liquidity.

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 100);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 900);

		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000)
			.set_min_liquidity_msat(200, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		// Update maximum liquidity.

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&target, &recipient, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 900);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&recipient, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 100);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		scorer.channel_liquidities.get_mut(&43).unwrap()
			.as_directed_mut(&target, &recipient, 1_000)
			.set_max_liquidity_msat(200, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&target, &recipient, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 200);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&recipient, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 800);
		assert_eq!(liquidity.max_liquidity_msat(), 1000);
	}

	#[test]
	fn resets_liquidity_upper_bound_when_crossed_by_lower_bound() {
		let logger = TestLogger::new();
		let last_updated = Duration::ZERO;
		let offset_history_last_updated = Duration::ZERO;
		let network_graph = network_graph(&logger);
		let decay_params = ProbabilisticScoringDecayParameters::default();
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger)
			.with_channel(42,
				ChannelLiquidity {
					min_liquidity_offset_msat: 200, max_liquidity_offset_msat: 400,
					last_updated, offset_history_last_updated,
					liquidity_history: HistoricalLiquidityTracker::new(),
				});
		let source = source_node_id();
		let target = target_node_id();
		assert!(source > target);

		// Check initial bounds.
		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		// Reset from source to target.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000)
			.set_min_liquidity_msat(900, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 900);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 100);

		// Reset from target to source.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&target, &source, 1_000)
			.set_min_liquidity_msat(400, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);
	}

	#[test]
	fn resets_liquidity_lower_bound_when_crossed_by_upper_bound() {
		let logger = TestLogger::new();
		let last_updated = Duration::ZERO;
		let offset_history_last_updated = Duration::ZERO;
		let network_graph = network_graph(&logger);
		let decay_params = ProbabilisticScoringDecayParameters::default();
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger)
			.with_channel(42,
				ChannelLiquidity {
					min_liquidity_offset_msat: 200, max_liquidity_offset_msat: 400,
					last_updated, offset_history_last_updated,
					liquidity_history: HistoricalLiquidityTracker::new(),
				});
		let source = source_node_id();
		let target = target_node_id();
		assert!(source > target);

		// Check initial bounds.
		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		// Reset from source to target.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000)
			.set_max_liquidity_msat(300, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		// Reset from target to source.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&target, &source, 1_000)
			.set_max_liquidity_msat(600, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 600);
	}

	#[test]
	fn increased_penalty_nearing_liquidity_upper_bound() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters::default();
		let scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		let source = source_node_id();

		let usage = ChannelUsage {
			amount_msat: 1_024,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024_000, htlc_maximum_msat: 1_000 },
		};
		let network_graph = network_graph.read_only();
		let channel = network_graph.channel(42).unwrap();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 10_240, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 102_400, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 47);
		let usage = ChannelUsage { amount_msat: 1_023_999, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 2_000);

		let usage = ChannelUsage {
			amount_msat: 128,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_000 },
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 58);
		let usage = ChannelUsage { amount_msat: 256, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 125);
		let usage = ChannelUsage { amount_msat: 374, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 198);
		let usage = ChannelUsage { amount_msat: 512, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);
		let usage = ChannelUsage { amount_msat: 640, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 425);
		let usage = ChannelUsage { amount_msat: 768, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 602);
		let usage = ChannelUsage { amount_msat: 896, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 902);
	}

	#[test]
	fn constant_penalty_outside_liquidity_bounds() {
		let logger = TestLogger::new();
		let last_updated = Duration::ZERO;
		let offset_history_last_updated = Duration::ZERO;
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			considered_impossible_penalty_msat: u64::max_value(),
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters {
			..ProbabilisticScoringDecayParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger)
			.with_channel(42,
				ChannelLiquidity {
					min_liquidity_offset_msat: 40, max_liquidity_offset_msat: 40,
					last_updated, offset_history_last_updated,
					liquidity_history: HistoricalLiquidityTracker::new(),
				});
		let source = source_node_id();

		let usage = ChannelUsage {
			amount_msat: 39,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 100, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 50, ..usage };
		assert_ne!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		assert_ne!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());
		let usage = ChannelUsage { amount_msat: 61, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());
	}

	#[test]
	fn does_not_further_penalize_own_channel() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: 500,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_000, htlc_maximum_msat: 1_000 },
		};
		let failed_path = payment_path_for_amount(500);
		let successful_path = payment_path_for_amount(200);
		let channel = &network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 41,
		});

		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 301);

		scorer.payment_path_failed(&failed_path, 41, Duration::ZERO);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 301);

		scorer.payment_path_successful(&successful_path, Duration::ZERO);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 301);
	}

	#[test]
	fn sets_liquidity_lower_bound_on_downstream_failure() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let source = source_node_id();
		let path = payment_path_for_amount(500);

		let usage = ChannelUsage {
			amount_msat: 250,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_000, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
		let usage = ChannelUsage { amount_msat: 500, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 301);
		let usage = ChannelUsage { amount_msat: 750, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 602);

		scorer.payment_path_failed(&path, 43, Duration::ZERO);

		let usage = ChannelUsage { amount_msat: 250, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 500, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 750, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);
	}

	#[test]
	fn sets_liquidity_upper_bound_on_failure() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			considered_impossible_penalty_msat: u64::max_value(),
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let source = source_node_id();
		let path = payment_path_for_amount(500);

		let usage = ChannelUsage {
			amount_msat: 250,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_000, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
		let usage = ChannelUsage { amount_msat: 500, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 301);
		let usage = ChannelUsage { amount_msat: 750, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 602);

		scorer.payment_path_failed(&path, 42, Duration::ZERO);

		let usage = ChannelUsage { amount_msat: 250, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);
		let usage = ChannelUsage { amount_msat: 500, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());
		let usage = ChannelUsage { amount_msat: 750, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());
	}

	#[test]
	fn ignores_channels_after_removed_failed_channel() {
		// Previously, if we'd tried to send over a channel which was removed from the network
		// graph before we call `payment_path_failed` (which is the default if the we get a "no
		// such channel" error in the `InvoicePayer`), we would call `failed_downstream` on all
		// channels in the route, even ones which they payment never reached. This tests to ensure
		// we do not score such channels.
		let secp_ctx = Secp256k1::new();
		let logger = TestLogger::new();
		let mut network_graph = NetworkGraph::new(Network::Testnet, &logger);
		let secret_a = SecretKey::from_slice(&[42; 32]).unwrap();
		let secret_b = SecretKey::from_slice(&[43; 32]).unwrap();
		let secret_c = SecretKey::from_slice(&[44; 32]).unwrap();
		let secret_d = SecretKey::from_slice(&[45; 32]).unwrap();
		add_channel(&mut network_graph, 42, secret_a, secret_b);
		// Don't add the channel from B -> C.
		add_channel(&mut network_graph, 44, secret_c, secret_d);

		let pub_a = PublicKey::from_secret_key(&secp_ctx, &secret_a);
		let pub_b = PublicKey::from_secret_key(&secp_ctx, &secret_b);
		let pub_c = PublicKey::from_secret_key(&secp_ctx, &secret_c);
		let pub_d = PublicKey::from_secret_key(&secp_ctx, &secret_d);

		let path = vec![
			path_hop(pub_b, 42, 1),
			path_hop(pub_c, 43, 2),
			path_hop(pub_d, 44, 100),
		];

		let node_a = NodeId::from_pubkey(&pub_a);
		let node_b = NodeId::from_pubkey(&pub_b);
		let node_c = NodeId::from_pubkey(&pub_c);

		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);

		let usage = ChannelUsage {
			amount_msat: 250,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_000, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_a).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
		// Note that a default liquidity bound is used for B -> C as no channel exists
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_b).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 43,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
		let channel = network_graph.read_only().channel(44).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_c).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 44,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);

		scorer.payment_path_failed(&Path { hops: path, blinded_tail: None }, 43, Duration::ZERO);

		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_a).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 80);
		// Note that a default liquidity bound is used for B -> C as no channel exists
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_b).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 43,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
		let channel = network_graph.read_only().channel(44).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_c).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 44,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
	}

	#[test]
	fn reduces_liquidity_upper_bound_along_path_on_success() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: 250,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_000, htlc_maximum_msat: 1_000 },
		};
		let network_graph = network_graph.read_only().channels().clone();
		let channel_42 = network_graph.get(&42).unwrap();
		let channel_43 = network_graph.get(&43).unwrap();
		let (info, _) = channel_42.as_directed_from(&source).unwrap();
		let candidate_41 = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 41,
		});
		let (info, target) = channel_42.as_directed_from(&source).unwrap();
		let candidate_42 = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		let (info, _) = channel_43.as_directed_from(&target).unwrap();
		let candidate_43 = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 43,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate_41, usage, &params), 128);
		assert_eq!(scorer.channel_penalty_msat(&candidate_42, usage, &params), 128);
		assert_eq!(scorer.channel_penalty_msat(&candidate_43, usage, &params), 128);

		scorer.payment_path_successful(&payment_path_for_amount(500), Duration::ZERO);

		assert_eq!(scorer.channel_penalty_msat(&candidate_41, usage, &params), 128);
		assert_eq!(scorer.channel_penalty_msat(&candidate_42, usage, &params), 300);
		assert_eq!(scorer.channel_penalty_msat(&candidate_43, usage, &params), 300);
	}

	#[test]
	fn decays_liquidity_bounds_over_time() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			considered_impossible_penalty_msat: u64::max_value(),
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters {
			liquidity_offset_half_life: Duration::from_secs(10),
			..ProbabilisticScoringDecayParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		let source = source_node_id();

		let usage = ChannelUsage {
			amount_msat: 0,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_024 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 1_023, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 2_000);

		scorer.payment_path_failed(&payment_path_for_amount(768), 42, Duration::ZERO);
		scorer.payment_path_failed(&payment_path_for_amount(128), 43, Duration::ZERO);

		// Initial penalties
		let usage = ChannelUsage { amount_msat: 128, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 256, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 93);
		let usage = ChannelUsage { amount_msat: 768, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 1_479);
		let usage = ChannelUsage { amount_msat: 896, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		// Half decay (i.e., three-quarter life)
		scorer.time_passed(Duration::from_secs(5));
		let usage = ChannelUsage { amount_msat: 128, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 22);
		let usage = ChannelUsage { amount_msat: 256, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 106);
		let usage = ChannelUsage { amount_msat: 768, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 921);
		let usage = ChannelUsage { amount_msat: 896, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		// One decay (i.e., half life)
		scorer.time_passed(Duration::from_secs(10));
		let usage = ChannelUsage { amount_msat: 64, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 128, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 34);
		let usage = ChannelUsage { amount_msat: 896, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 1_970);
		let usage = ChannelUsage { amount_msat: 960, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		// Fully decay liquidity lower bound.
		scorer.time_passed(Duration::from_secs(10 * 8));
		let usage = ChannelUsage { amount_msat: 0, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 1, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 1_023, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 2_000);
		let usage = ChannelUsage { amount_msat: 1_024, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		// Fully decay liquidity upper bound.
		scorer.time_passed(Duration::from_secs(10 * 9));
		let usage = ChannelUsage { amount_msat: 0, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 1_024, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		scorer.time_passed(Duration::from_secs(10 * 10));
		let usage = ChannelUsage { amount_msat: 0, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 1_024, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());
	}

	#[test]
	fn restricts_liquidity_bounds_after_decay() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters {
			liquidity_offset_half_life: Duration::from_secs(10),
			..ProbabilisticScoringDecayParameters::default()
		};
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: 512,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});

		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);

		// More knowledge gives higher confidence (256, 768), meaning a lower penalty.
		scorer.payment_path_failed(&payment_path_for_amount(768), 42, Duration::ZERO);
		scorer.payment_path_failed(&payment_path_for_amount(256), 43, Duration::ZERO);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 281);

		// Decaying knowledge gives less confidence (128, 896), meaning a higher penalty.
		scorer.time_passed(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 291);

		// Reducing the upper bound gives more confidence (128, 832) that the payment amount (512)
		// is closer to the upper bound, meaning a higher penalty.
		scorer.payment_path_successful(&payment_path_for_amount(64), Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 331);

		// Increasing the lower bound gives more confidence (256, 832) that the payment amount (512)
		// is closer to the lower bound, meaning a lower penalty.
		scorer.payment_path_failed(&payment_path_for_amount(256), 43, Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 245);

		// Further decaying affects the lower bound more than the upper bound (128, 928).
		scorer.time_passed(Duration::from_secs(20));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 280);
	}

	#[test]
	fn restores_persisted_liquidity_bounds() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			considered_impossible_penalty_msat: u64::max_value(),
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters {
			liquidity_offset_half_life: Duration::from_secs(10),
			..ProbabilisticScoringDecayParameters::default()
		};
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: 500,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_000, htlc_maximum_msat: 1_000 },
		};

		scorer.payment_path_failed(&payment_path_for_amount(500), 42, Duration::ZERO);
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		scorer.time_passed(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 473);

		scorer.payment_path_failed(&payment_path_for_amount(250), 43, Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		let mut serialized_scorer = io::Cursor::new(&serialized_scorer);
		let deserialized_scorer =
			<ProbabilisticScorer<_, _>>::read(&mut serialized_scorer, (decay_params, &network_graph, &logger)).unwrap();
		assert_eq!(deserialized_scorer.channel_penalty_msat(&candidate, usage, &params), 300);
	}

	fn do_decays_persisted_liquidity_bounds(decay_before_reload: bool) {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			considered_impossible_penalty_msat: u64::max_value(),
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters {
			liquidity_offset_half_life: Duration::from_secs(10),
			..ProbabilisticScoringDecayParameters::zero_penalty()
		};
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: 500,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_000, htlc_maximum_msat: 1_000 },
		};

		scorer.payment_path_failed(&payment_path_for_amount(500), 42, Duration::ZERO);
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		if decay_before_reload {
			scorer.time_passed(Duration::from_secs(10));
		}

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		let mut serialized_scorer = io::Cursor::new(&serialized_scorer);
		let mut deserialized_scorer =
			<ProbabilisticScorer<_, _>>::read(&mut serialized_scorer, (decay_params, &network_graph, &logger)).unwrap();
		if !decay_before_reload {
			scorer.time_passed(Duration::from_secs(10));
			deserialized_scorer.time_passed(Duration::from_secs(10));
		}
		assert_eq!(deserialized_scorer.channel_penalty_msat(&candidate, usage, &params), 473);

		scorer.payment_path_failed(&payment_path_for_amount(250), 43, Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);

		deserialized_scorer.time_passed(Duration::from_secs(20));
		assert_eq!(deserialized_scorer.channel_penalty_msat(&candidate, usage, &params), 370);
	}

	#[test]
	fn decays_persisted_liquidity_bounds() {
		do_decays_persisted_liquidity_bounds(false);
		do_decays_persisted_liquidity_bounds(true);
	}

	#[test]
	fn scores_realistic_payments() {
		// Shows the scores of "realistic" sends of 100k sats over channels of 1-10m sats (with a
		// 50k sat reserve).
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters::default();
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let source = source_node_id();

		let usage = ChannelUsage {
			amount_msat: 100_000_000,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 950_000_000, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 11497);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 7408);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 2_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 6151);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 3_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 5427);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 4_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 4955);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 5_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 4736);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 6_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 4484);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 7_450_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 4484);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 7_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 4263);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 8_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 4263);
		let usage = ChannelUsage {
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 9_950_000_000, htlc_maximum_msat: 1_000 }, ..usage
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 4044);
	}

	#[test]
	fn adds_base_penalty_to_liquidity_penalty() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: 128,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_000 },
		};

		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 58);

		let params = ProbabilisticScoringFeeParameters {
			base_penalty_msat: 500, liquidity_penalty_multiplier_msat: 1_000,
			anti_probing_penalty_msat: 0, ..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 558);

		let params = ProbabilisticScoringFeeParameters {
			base_penalty_msat: 500, liquidity_penalty_multiplier_msat: 1_000,
			base_penalty_amount_multiplier_msat: (1 << 30),
			anti_probing_penalty_msat: 0, ..ProbabilisticScoringFeeParameters::zero_penalty()
		};

		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 558 + 128);
	}

	#[test]
	fn adds_amount_penalty_to_liquidity_penalty() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: 512_000,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024_000, htlc_maximum_msat: 1_000 },
		};

		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_penalty_amount_multiplier_msat: 0,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);

		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			liquidity_penalty_amount_multiplier_msat: 256,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 337);
	}

	#[test]
	fn calculates_log10_without_overflowing_u64_max_value() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: u64::max_value(),
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Infinite,
		};
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 40_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters::zero_penalty();
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		let scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 80_000);
	}

	#[test]
	fn accounts_for_inflight_htlc_usage() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			considered_impossible_penalty_msat: u64::max_value(),
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let source = source_node_id();

		let usage = ChannelUsage {
			amount_msat: 750,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_000, htlc_maximum_msat: 1_000 },
		};
		let network_graph = network_graph.read_only();
		let channel = network_graph.channel(42).unwrap();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_ne!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		let usage = ChannelUsage { inflight_htlc_msat: 251, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());
	}

	#[test]
	fn removes_uncertainity_when_exact_liquidity_known() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters::default();
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);
		let source = source_node_id();

		let base_penalty_msat = params.base_penalty_msat;
		let usage = ChannelUsage {
			amount_msat: 750,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::ExactLiquidity { liquidity_msat: 1_000 },
		};
		let network_graph = network_graph.read_only();
		let channel = network_graph.channel(42).unwrap();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), base_penalty_msat);

		let usage = ChannelUsage { amount_msat: 1_000, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), base_penalty_msat);

		let usage = ChannelUsage { amount_msat: 1_001, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());
	}

	#[test]
	fn remembers_historical_failures() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			historical_liquidity_penalty_multiplier_msat: 1024,
			historical_liquidity_penalty_amount_multiplier_msat: 1024,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters {
			liquidity_offset_half_life: Duration::from_secs(60 * 60),
			historical_no_updates_half_life: Duration::from_secs(10),
		};
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		let source = source_node_id();
		let target = target_node_id();

		let usage = ChannelUsage {
			amount_msat: 100,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_024 },
		};
		let usage_1 = ChannelUsage {
			amount_msat: 1,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_024 },
		};

		{
			let network_graph = network_graph.read_only();
			let channel = network_graph.channel(42).unwrap();
			let (info, _) = channel.as_directed_from(&source).unwrap();
			let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
				info,
				short_channel_id: 42,
			});

			// With no historical data the normal liquidity penalty calculation is used.
			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 168);
		}
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
		None);
		assert_eq!(scorer.historical_estimated_payment_success_probability(42, &target, 42, &params),
		None);

		scorer.payment_path_failed(&payment_path_for_amount(1), 42, Duration::ZERO);
		{
			let network_graph = network_graph.read_only();
			let channel = network_graph.channel(42).unwrap();
			let (info, _) = channel.as_directed_from(&source).unwrap();
			let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
				info,
				short_channel_id: 42,
			});

			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 2048);
			assert_eq!(scorer.channel_penalty_msat(&candidate, usage_1, &params), 249);
		}
		// The "it failed" increment is 32, where the probability should lie several buckets into
		// the first octile.
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
			Some(([32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				[0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])));
		assert!(scorer.historical_estimated_payment_success_probability(42, &target, 1, &params)
			.unwrap() > 0.35);
		assert_eq!(scorer.historical_estimated_payment_success_probability(42, &target, 500, &params),
			Some(0.0));

		// Even after we tell the scorer we definitely have enough available liquidity, it will
		// still remember that there was some failure in the past, and assign a non-0 penalty.
		scorer.payment_path_failed(&payment_path_for_amount(1000), 43, Duration::ZERO);
		{
			let network_graph = network_graph.read_only();
			let channel = network_graph.channel(42).unwrap();
			let (info, _) = channel.as_directed_from(&source).unwrap();
			let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
				info,
				short_channel_id: 42,
			});

			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 105);
		}
		// The first points should be decayed just slightly and the last bucket has a new point.
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
			Some(([31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0],
				[0, 0, 0, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32])));

		// The exact success probability is a bit complicated and involves integer rounding, so we
		// simply check bounds here.
		let five_hundred_prob =
			scorer.historical_estimated_payment_success_probability(42, &target, 500, &params).unwrap();
		assert!(five_hundred_prob > 0.59);
		assert!(five_hundred_prob < 0.60);
		let one_prob =
			scorer.historical_estimated_payment_success_probability(42, &target, 1, &params).unwrap();
		assert!(one_prob < 0.85);
		assert!(one_prob > 0.84);

		// Advance the time forward 16 half-lives (which the docs claim will ensure all data is
		// gone), and check that we're back to where we started.
		scorer.time_passed(Duration::from_secs(10 * 16));
		{
			let network_graph = network_graph.read_only();
			let channel = network_graph.channel(42).unwrap();
			let (info, _) = channel.as_directed_from(&source).unwrap();
			let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
				info,
				short_channel_id: 42,
			});

			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 168);
		}
		// Once fully decayed we still have data, but its all-0s. In the future we may remove the
		// data entirely instead.
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
			Some(([0; 32], [0; 32])));
		assert_eq!(scorer.historical_estimated_payment_success_probability(42, &target, 1, &params), None);

		let usage = ChannelUsage {
			amount_msat: 100,
			inflight_htlc_msat: 1024,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_024 },
		};
		scorer.payment_path_failed(&payment_path_for_amount(1), 42, Duration::from_secs(10 * 16));
		{
			let network_graph = network_graph.read_only();
			let channel = network_graph.channel(42).unwrap();
			let (info, _) = channel.as_directed_from(&source).unwrap();
			let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
				info,
				short_channel_id: 42,
			});

			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 2050);

			let usage = ChannelUsage {
				amount_msat: 1,
				inflight_htlc_msat: 0,
				effective_capacity: EffectiveCapacity::AdvertisedMaxHTLC { amount_msat: 0 },
			};
			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 2048);
		}

		// Advance to decay all liquidity offsets to zero.
		scorer.time_passed(Duration::from_secs(10 * (16 + 60 * 60)));

		// Once even the bounds have decayed information about the channel should be removed
		// entirely.
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
			None);

		// Use a path in the opposite direction, which have zero for htlc_maximum_msat. This will
		// ensure that the effective capacity is zero to test division-by-zero edge cases.
		let path = vec![
			path_hop(target_pubkey(), 43, 2),
			path_hop(source_pubkey(), 42, 1),
			path_hop(sender_pubkey(), 41, 0),
		];
		scorer.payment_path_failed(&Path { hops: path, blinded_tail: None }, 42, Duration::from_secs(10 * (16 + 60 * 60)));
	}

	#[test]
	fn adds_anti_probing_penalty() {
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let source = source_node_id();
		let params = ProbabilisticScoringFeeParameters {
			anti_probing_penalty_msat: 500,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let scorer = ProbabilisticScorer::new(ProbabilisticScoringDecayParameters::default(), &network_graph, &logger);

		// Check we receive no penalty for a low htlc_maximum_msat.
		let usage = ChannelUsage {
			amount_msat: 512_000,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024_000, htlc_maximum_msat: 1_000 },
		};
		let network_graph = network_graph.read_only();
		let channel = network_graph.channel(42).unwrap();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);

		// Check we receive anti-probing penalty for htlc_maximum_msat == channel_capacity.
		let usage = ChannelUsage {
			amount_msat: 512_000,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024_000, htlc_maximum_msat: 1_024_000 },
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 500);

		// Check we receive anti-probing penalty for htlc_maximum_msat == channel_capacity/2.
		let usage = ChannelUsage {
			amount_msat: 512_000,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024_000, htlc_maximum_msat: 512_000 },
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 500);

		// Check we receive no anti-probing penalty for htlc_maximum_msat == channel_capacity/2 - 1.
		let usage = ChannelUsage {
			amount_msat: 512_000,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024_000, htlc_maximum_msat: 511_999 },
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
	}

	#[test]
	fn scores_with_blinded_path() {
		// Make sure we'll account for a blinded path's final_value_msat in scoring
		let logger = TestLogger::new();
		let network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			liquidity_penalty_multiplier_msat: 1_000,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters::default();
		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		let source = source_node_id();
		let usage = ChannelUsage {
			amount_msat: 512,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, target) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);

		let mut path = payment_path_for_amount(768);
		let recipient_hop = path.hops.pop().unwrap();
		path.blinded_tail = Some(BlindedTail {
			hops: vec![BlindedHop { blinded_node_id: test_utils::pubkey(44), encrypted_payload: Vec::new() }],
			blinding_point: test_utils::pubkey(42),
			excess_final_cltv_expiry_delta: recipient_hop.cltv_expiry_delta,
			final_value_msat: recipient_hop.fee_msat,
		});

		// Check the liquidity before and after scoring payment failures to ensure the blinded path's
		// final value is taken into account.
		assert!(scorer.channel_liquidities.get(&42).is_none());

		scorer.payment_path_failed(&path, 42, Duration::ZERO);
		path.blinded_tail.as_mut().unwrap().final_value_msat = 256;
		scorer.payment_path_failed(&path, 43, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000);
		assert_eq!(liquidity.min_liquidity_msat(), 256);
		assert_eq!(liquidity.max_liquidity_msat(), 768);
	}

	#[test]
	fn realistic_historical_failures() {
		// The motivation for the unequal sized buckets came largely from attempting to pay 10k
		// sats over a one bitcoin channel. This tests that case explicitly, ensuring that we score
		// properly.
		let logger = TestLogger::new();
		let mut network_graph = network_graph(&logger);
		let params = ProbabilisticScoringFeeParameters {
			historical_liquidity_penalty_multiplier_msat: 1024,
			historical_liquidity_penalty_amount_multiplier_msat: 1024,
			..ProbabilisticScoringFeeParameters::zero_penalty()
		};
		let decay_params = ProbabilisticScoringDecayParameters {
			liquidity_offset_half_life: Duration::from_secs(60 * 60),
			historical_no_updates_half_life: Duration::from_secs(10),
			..ProbabilisticScoringDecayParameters::default()
		};

		let capacity_msat = 100_000_000_000;
		update_channel(&mut network_graph, 42, source_privkey(), 0, capacity_msat, 200);
		update_channel(&mut network_graph, 42, target_privkey(), 1, capacity_msat, 200);

		let mut scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
		let source = source_node_id();

		let mut amount_msat = 10_000_000;
		let usage = ChannelUsage {
			amount_msat,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat, htlc_maximum_msat: capacity_msat },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, target) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop(PublicHopCandidate {
			info,
			short_channel_id: 42,
		});
		// With no historical data the normal liquidity penalty calculation is used, which results
		// in a success probability of ~75%.
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 1269);
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
			None);
		assert_eq!(scorer.historical_estimated_payment_success_probability(42, &target, 42, &params),
			None);

		// Fail to pay once, and then check the buckets and penalty.
		scorer.payment_path_failed(&payment_path_for_amount(amount_msat), 42, Duration::ZERO);
		// The penalty should be the maximum penalty, as the payment we're scoring is now in the
		// same bucket which is the only maximum datapoint.
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params),
			2048 + 2048 * amount_msat / super::AMOUNT_PENALTY_DIVISOR);
		// The "it failed" increment is 32, which we should apply to the first upper-bound (between
		// 6k sats and 12k sats).
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
			Some(([32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				[0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])));
		// The success probability estimate itself should be zero.
		assert_eq!(scorer.historical_estimated_payment_success_probability(42, &target, amount_msat, &params),
			Some(0.0));

		// Now test again with the amount in the bottom bucket.
		amount_msat /= 2;
		// The new amount is entirely within the only minimum bucket with score, so the probability
		// we assign is 1/2.
		assert_eq!(scorer.historical_estimated_payment_success_probability(42, &target, amount_msat, &params),
			Some(0.5));

		// ...but once we see a failure, we consider the payment to be substantially less likely,
		// even though not a probability of zero as we still look at the second max bucket which
		// now shows 31.
		scorer.payment_path_failed(&payment_path_for_amount(amount_msat), 42, Duration::ZERO);
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
			Some(([63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
				[32, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])));
		assert_eq!(scorer.historical_estimated_payment_success_probability(42, &target, amount_msat, &params),
			Some(0.0));
	}
}

#[cfg(ldk_bench)]
pub mod benches {
	use super::*;
	use criterion::Criterion;
	use crate::routing::router::{bench_utils, RouteHop};
	use crate::util::test_utils::TestLogger;
	use crate::ln::features::{ChannelFeatures, NodeFeatures};

	pub fn decay_100k_channel_bounds(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, mut scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let mut cur_time = Duration::ZERO;
			cur_time += Duration::from_millis(1);
			scorer.time_passed(cur_time);
		bench.bench_function("decay_100k_channel_bounds", |b| b.iter(|| {
			cur_time += Duration::from_millis(1);
			scorer.time_passed(cur_time);
		}));
	}
}
