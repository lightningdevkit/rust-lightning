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
use crate::routing::router::{Path, CandidateRouteHop};
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use crate::util::logger::Logger;

use crate::prelude::*;
use core::{cmp, fmt};
use core::cell::{RefCell, RefMut, Ref};
use core::convert::TryInto;
use core::ops::{Deref, DerefMut};
use core::time::Duration;
use crate::io::{self, Read};
use crate::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

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

#[cfg(not(c_bindings))]
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
/// # Note
///
/// Mixing the `no-std` feature between serialization and deserialization results in undefined
/// behavior.
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
			manual_node_penalties: HashMap::new(),
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
		self.manual_node_penalties = HashMap::new();
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
			manual_node_penalties: HashMap::new(),
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

	min_liquidity_offset_history: HistoricalBucketRangeTracker,
	max_liquidity_offset_history: HistoricalBucketRangeTracker,

	/// Time when the liquidity bounds were last modified as an offset since the unix epoch.
	last_updated: Duration,

	/// Time when the historical liquidity bounds were last modified as an offset against the unix
	/// epoch.
	offset_history_last_updated: Duration,
}

/// A snapshot of [`ChannelLiquidity`] in one direction assuming a certain channel capacity.
struct DirectedChannelLiquidity<L: Deref<Target = u64>, BRT: Deref<Target = HistoricalBucketRangeTracker>, T: Deref<Target = Duration>> {
	min_liquidity_offset_msat: L,
	max_liquidity_offset_msat: L,
	liquidity_history: HistoricalMinMaxBuckets<BRT>,
	capacity_msat: u64,
	last_updated: T,
	offset_history_last_updated: T,
	decay_params: ProbabilisticScoringDecayParameters,
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> ProbabilisticScorer<G, L> where L::Target: Logger {
	/// Creates a new scorer using the given scoring parameters for sending payments from a node
	/// through a network graph.
	pub fn new(decay_params: ProbabilisticScoringDecayParameters, network_graph: G, logger: L) -> Self {
		Self {
			decay_params,
			network_graph,
			logger,
			channel_liquidities: HashMap::new(),
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
						let dir_liq = liq.as_directed(source, target, amt, self.decay_params);

						let min_buckets = &dir_liq.liquidity_history.min_liquidity_offset_history.buckets;
						let max_buckets = &dir_liq.liquidity_history.max_liquidity_offset_history.buckets;

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
					let dir_liq = liq.as_directed(source, target, amt, self.decay_params);
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
					let dir_liq = liq.as_directed(source, target, amt, self.decay_params);

					let min_buckets = dir_liq.liquidity_history.min_liquidity_offset_history.buckets;
					let mut max_buckets = dir_liq.liquidity_history.max_liquidity_offset_history.buckets;

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
					let dir_liq = liq.as_directed(source, target, capacity_msat, self.decay_params);

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
			min_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
			max_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
			last_updated,
			offset_history_last_updated: last_updated,
		}
	}

	/// Returns a view of the channel liquidity directed from `source` to `target` assuming
	/// `capacity_msat`.
	fn as_directed(
		&self, source: &NodeId, target: &NodeId, capacity_msat: u64, decay_params: ProbabilisticScoringDecayParameters
	) -> DirectedChannelLiquidity<&u64, &HistoricalBucketRangeTracker, &Duration> {
		let (min_liquidity_offset_msat, max_liquidity_offset_msat, min_liquidity_offset_history, max_liquidity_offset_history) =
			if source < target {
				(&self.min_liquidity_offset_msat, &self.max_liquidity_offset_msat,
					&self.min_liquidity_offset_history, &self.max_liquidity_offset_history)
			} else {
				(&self.max_liquidity_offset_msat, &self.min_liquidity_offset_msat,
					&self.max_liquidity_offset_history, &self.min_liquidity_offset_history)
			};

		DirectedChannelLiquidity {
			min_liquidity_offset_msat,
			max_liquidity_offset_msat,
			liquidity_history: HistoricalMinMaxBuckets {
				min_liquidity_offset_history,
				max_liquidity_offset_history,
			},
			capacity_msat,
			last_updated: &self.last_updated,
			offset_history_last_updated: &self.offset_history_last_updated,
			decay_params: decay_params,
		}
	}

	/// Returns a mutable view of the channel liquidity directed from `source` to `target` assuming
	/// `capacity_msat`.
	fn as_directed_mut(
		&mut self, source: &NodeId, target: &NodeId, capacity_msat: u64, decay_params: ProbabilisticScoringDecayParameters
	) -> DirectedChannelLiquidity<&mut u64, &mut HistoricalBucketRangeTracker, &mut Duration> {
		let (min_liquidity_offset_msat, max_liquidity_offset_msat, min_liquidity_offset_history, max_liquidity_offset_history) =
			if source < target {
				(&mut self.min_liquidity_offset_msat, &mut self.max_liquidity_offset_msat,
					&mut self.min_liquidity_offset_history, &mut self.max_liquidity_offset_history)
			} else {
				(&mut self.max_liquidity_offset_msat, &mut self.min_liquidity_offset_msat,
					&mut self.max_liquidity_offset_history, &mut self.min_liquidity_offset_history)
			};

		DirectedChannelLiquidity {
			min_liquidity_offset_msat,
			max_liquidity_offset_msat,
			liquidity_history: HistoricalMinMaxBuckets {
				min_liquidity_offset_history,
				max_liquidity_offset_history,
			},
			capacity_msat,
			last_updated: &mut self.last_updated,
			offset_history_last_updated: &mut self.offset_history_last_updated,
			decay_params: decay_params,
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
const PRECISION_LOWER_BOUND_DENOMINATOR: u64 = approx::LOWER_BITS_BOUND;

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

impl<L: Deref<Target = u64>, BRT: Deref<Target = HistoricalBucketRangeTracker>, T: Deref<Target = Duration>>
DirectedChannelLiquidity< L, BRT, T> {
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
					approx::negative_log10_times_2048(numerator, denominator);
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
				let historical_negative_log10_times_2048 = approx::negative_log10_times_2048(cumulative_success_prob_times_billion + 1, 1024 * 1024 * 1024);
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
					approx::negative_log10_times_2048(numerator, denominator);
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

impl<L: DerefMut<Target = u64>, BRT: DerefMut<Target = HistoricalBucketRangeTracker>, T: DerefMut<Target = Duration>>
DirectedChannelLiquidity<L, BRT, T> {
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
		let half_lives =
			duration_since_epoch.checked_sub(*self.offset_history_last_updated)
			.unwrap_or(Duration::ZERO).as_secs()
			.checked_div(self.decay_params.historical_no_updates_half_life.as_secs())
			.map(|v| v.try_into().unwrap_or(u32::max_value())).unwrap_or(u32::max_value());
		self.liquidity_history.min_liquidity_offset_history.time_decay_data(half_lives);
		self.liquidity_history.max_liquidity_offset_history.time_decay_data(half_lives);

		self.liquidity_history.min_liquidity_offset_history.track_datapoint(
			*self.min_liquidity_offset_msat + bucket_offset_msat, self.capacity_msat
		);
		self.liquidity_history.max_liquidity_offset_history.track_datapoint(
			self.max_liquidity_offset_msat.saturating_sub(bucket_offset_msat), self.capacity_msat
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
			CandidateRouteHop::PublicHop { info, short_channel_id } => {
				(short_channel_id, info.target())
			},
			_ => return 0,
		};
		let source = candidate.source();
		if let Some(penalty) = score_params.manual_node_penalties.get(&target) {
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
			.get(&scid)
			.unwrap_or(&ChannelLiquidity::new(Duration::ZERO))
			.as_directed(&source, &target, capacity_msat, self.decay_params)
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
						.as_directed_mut(source, &target, capacity_msat, self.decay_params)
						.failed_at_channel(amount_msat, duration_since_epoch,
							format_args!("SCID {}, towards {:?}", hop.short_channel_id, target), &self.logger);
				} else {
					self.channel_liquidities
						.entry(hop.short_channel_id)
						.or_insert_with(|| ChannelLiquidity::new(duration_since_epoch))
						.as_directed_mut(source, &target, capacity_msat, self.decay_params)
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
					.as_directed_mut(source, &target, capacity_msat, self.decay_params)
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
					let divisor = powf64(2048.0, elapsed_time.as_secs_f64() / half_life) as u64;
					for bucket in liquidity.min_liquidity_offset_history.buckets.iter_mut() {
						*bucket = ((*bucket as u64) * 1024 / divisor) as u16;
					}
					for bucket in liquidity.max_liquidity_offset_history.buckets.iter_mut() {
						*bucket = ((*bucket as u64) * 1024 / divisor) as u16;
					}
					liquidity.offset_history_last_updated = duration_since_epoch;
				}
			}
			liquidity.min_liquidity_offset_msat != 0 || liquidity.max_liquidity_offset_msat != 0 ||
				liquidity.min_liquidity_offset_history.buckets != [0; 32] ||
				liquidity.max_liquidity_offset_history.buckets != [0; 32]
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

mod approx {
	const BITS: u32 = 64;
	const HIGHEST_BIT: u32 = BITS - 1;
	const LOWER_BITS: u32 = 6;
	pub(super) const LOWER_BITS_BOUND: u64 = 1 << LOWER_BITS;
	const LOWER_BITMASK: u64 = (1 << LOWER_BITS) - 1;

	/// Look-up table for `log10(x) * 2048` where row `i` is used for each `x` having `i` as the
	/// most significant bit. The next 4 bits of `x`, if applicable, are used for the second index.
	const LOG10_TIMES_2048: [[u16; (LOWER_BITS_BOUND) as usize]; BITS as usize] = [
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
		[617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617,
			617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617, 617,
			977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977,
			977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977, 977],
		[1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233, 1233,
			1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431, 1431,
			1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594, 1594,
			1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731, 1731],
		[1850, 1850, 1850, 1850, 1850, 1850, 1850, 1850, 1954, 1954, 1954, 1954, 1954, 1954, 1954, 1954,
			2048, 2048, 2048, 2048, 2048, 2048, 2048, 2048, 2133, 2133, 2133, 2133, 2133, 2133, 2133, 2133,
			2210, 2210, 2210, 2210, 2210, 2210, 2210, 2210, 2281, 2281, 2281, 2281, 2281, 2281, 2281, 2281,
			2347, 2347, 2347, 2347, 2347, 2347, 2347, 2347, 2409, 2409, 2409, 2409, 2409, 2409, 2409, 2409],
		[2466, 2466, 2466, 2466, 2520, 2520, 2520, 2520, 2571, 2571, 2571, 2571, 2619, 2619, 2619, 2619,
			2665, 2665, 2665, 2665, 2708, 2708, 2708, 2708, 2749, 2749, 2749, 2749, 2789, 2789, 2789, 2789,
			2827, 2827, 2827, 2827, 2863, 2863, 2863, 2863, 2898, 2898, 2898, 2898, 2931, 2931, 2931, 2931,
			2964, 2964, 2964, 2964, 2995, 2995, 2995, 2995, 3025, 3025, 3025, 3025, 3054, 3054, 3054, 3054],
		[3083, 3083, 3110, 3110, 3136, 3136, 3162, 3162, 3187, 3187, 3212, 3212, 3235, 3235, 3259, 3259,
			3281, 3281, 3303, 3303, 3324, 3324, 3345, 3345, 3366, 3366, 3386, 3386, 3405, 3405, 3424, 3424,
			3443, 3443, 3462, 3462, 3479, 3479, 3497, 3497, 3514, 3514, 3531, 3531, 3548, 3548, 3564, 3564,
			3580, 3580, 3596, 3596, 3612, 3612, 3627, 3627, 3642, 3642, 3656, 3656, 3671, 3671, 3685, 3685],
		[3699, 3713, 3726, 3740, 3753, 3766, 3779, 3791, 3804, 3816, 3828, 3840, 3852, 3864, 3875, 3886,
			3898, 3909, 3919, 3930, 3941, 3951, 3962, 3972, 3982, 3992, 4002, 4012, 4022, 4031, 4041, 4050,
			4060, 4069, 4078, 4087, 4096, 4105, 4114, 4122, 4131, 4139, 4148, 4156, 4164, 4173, 4181, 4189,
			4197, 4205, 4213, 4220, 4228, 4236, 4243, 4251, 4258, 4266, 4273, 4280, 4287, 4294, 4302, 4309],
		[4316, 4329, 4343, 4356, 4369, 4382, 4395, 4408, 4420, 4433, 4445, 4457, 4468, 4480, 4492, 4503,
			4514, 4525, 4536, 4547, 4557, 4568, 4578, 4589, 4599, 4609, 4619, 4629, 4638, 4648, 4657, 4667,
			4676, 4685, 4695, 4704, 4713, 4721, 4730, 4739, 4747, 4756, 4764, 4773, 4781, 4789, 4797, 4805,
			4813, 4821, 4829, 4837, 4845, 4852, 4860, 4867, 4875, 4882, 4889, 4897, 4904, 4911, 4918, 4925],
		[4932, 4946, 4959, 4973, 4986, 4999, 5012, 5024, 5037, 5049, 5061, 5073, 5085, 5097, 5108, 5119,
			5131, 5142, 5153, 5163, 5174, 5184, 5195, 5205, 5215, 5225, 5235, 5245, 5255, 5264, 5274, 5283,
			5293, 5302, 5311, 5320, 5329, 5338, 5347, 5355, 5364, 5372, 5381, 5389, 5397, 5406, 5414, 5422,
			5430, 5438, 5446, 5453, 5461, 5469, 5476, 5484, 5491, 5499, 5506, 5513, 5520, 5527, 5535, 5542],
		[5549, 5562, 5576, 5589, 5603, 5615, 5628, 5641, 5653, 5666, 5678, 5690, 5701, 5713, 5725, 5736,
			5747, 5758, 5769, 5780, 5790, 5801, 5811, 5822, 5832, 5842, 5852, 5862, 5871, 5881, 5890, 5900,
			5909, 5918, 5928, 5937, 5946, 5954, 5963, 5972, 5980, 5989, 5997, 6006, 6014, 6022, 6030, 6038,
			6046, 6054, 6062, 6070, 6078, 6085, 6093, 6100, 6108, 6115, 6122, 6130, 6137, 6144, 6151, 6158],
		[6165, 6179, 6192, 6206, 6219, 6232, 6245, 6257, 6270, 6282, 6294, 6306, 6318, 6330, 6341, 6352,
			6364, 6375, 6386, 6396, 6407, 6417, 6428, 6438, 6448, 6458, 6468, 6478, 6488, 6497, 6507, 6516,
			6526, 6535, 6544, 6553, 6562, 6571, 6580, 6588, 6597, 6605, 6614, 6622, 6630, 6639, 6647, 6655,
			6663, 6671, 6679, 6686, 6694, 6702, 6709, 6717, 6724, 6732, 6739, 6746, 6753, 6761, 6768, 6775],
		[6782, 6795, 6809, 6822, 6836, 6849, 6861, 6874, 6886, 6899, 6911, 6923, 6934, 6946, 6958, 6969,
			6980, 6991, 7002, 7013, 7023, 7034, 7044, 7055, 7065, 7075, 7085, 7095, 7104, 7114, 7124, 7133,
			7142, 7151, 7161, 7170, 7179, 7187, 7196, 7205, 7213, 7222, 7230, 7239, 7247, 7255, 7263, 7271,
			7279, 7287, 7295, 7303, 7311, 7318, 7326, 7333, 7341, 7348, 7355, 7363, 7370, 7377, 7384, 7391],
		[7398, 7412, 7425, 7439, 7452, 7465, 7478, 7490, 7503, 7515, 7527, 7539, 7551, 7563, 7574, 7585,
			7597, 7608, 7619, 7629, 7640, 7651, 7661, 7671, 7681, 7691, 7701, 7711, 7721, 7731, 7740, 7749,
			7759, 7768, 7777, 7786, 7795, 7804, 7813, 7821, 7830, 7838, 7847, 7855, 7864, 7872, 7880, 7888,
			7896, 7904, 7912, 7919, 7927, 7935, 7942, 7950, 7957, 7965, 7972, 7979, 7986, 7994, 8001, 8008],
		[8015, 8028, 8042, 8055, 8069, 8082, 8094, 8107, 8119, 8132, 8144, 8156, 8167, 8179, 8191, 8202,
			8213, 8224, 8235, 8246, 8256, 8267, 8277, 8288, 8298, 8308, 8318, 8328, 8337, 8347, 8357, 8366,
			8375, 8384, 8394, 8403, 8412, 8420, 8429, 8438, 8446, 8455, 8463, 8472, 8480, 8488, 8496, 8504,
			8512, 8520, 8528, 8536, 8544, 8551, 8559, 8566, 8574, 8581, 8588, 8596, 8603, 8610, 8617, 8624],
		[8631, 8645, 8659, 8672, 8685, 8698, 8711, 8723, 8736, 8748, 8760, 8772, 8784, 8796, 8807, 8818,
			8830, 8841, 8852, 8862, 8873, 8884, 8894, 8904, 8914, 8924, 8934, 8944, 8954, 8964, 8973, 8982,
			8992, 9001, 9010, 9019, 9028, 9037, 9046, 9054, 9063, 9071, 9080, 9088, 9097, 9105, 9113, 9121,
			9129, 9137, 9145, 9152, 9160, 9168, 9175, 9183, 9190, 9198, 9205, 9212, 9219, 9227, 9234, 9241],
		[9248, 9261, 9275, 9288, 9302, 9315, 9327, 9340, 9352, 9365, 9377, 9389, 9400, 9412, 9424, 9435,
			9446, 9457, 9468, 9479, 9490, 9500, 9510, 9521, 9531, 9541, 9551, 9561, 9570, 9580, 9590, 9599,
			9608, 9617, 9627, 9636, 9645, 9653, 9662, 9671, 9679, 9688, 9696, 9705, 9713, 9721, 9729, 9737,
			9745, 9753, 9761, 9769, 9777, 9784, 9792, 9799, 9807, 9814, 9821, 9829, 9836, 9843, 9850, 9857],
		[9864, 9878, 9892, 9905, 9918, 9931, 9944, 9956, 9969, 9981, 9993, 10005, 10017, 10029, 10040, 10051,
			10063, 10074, 10085, 10095, 10106, 10117, 10127, 10137, 10147, 10157, 10167, 10177, 10187, 10197, 10206, 10215,
			10225, 10234, 10243, 10252, 10261, 10270, 10279, 10287, 10296, 10304, 10313, 10321, 10330, 10338, 10346, 10354,
			10362, 10370, 10378, 10385, 10393, 10401, 10408, 10416, 10423, 10431, 10438, 10445, 10452, 10460, 10467, 10474],
		[10481, 10494, 10508, 10521, 10535, 10548, 10560, 10573, 10585, 10598, 10610, 10622, 10634, 10645, 10657, 10668,
			10679, 10690, 10701, 10712, 10723, 10733, 10743, 10754, 10764, 10774, 10784, 10794, 10803, 10813, 10823, 10832,
			10841, 10851, 10860, 10869, 10878, 10886, 10895, 10904, 10912, 10921, 10929, 10938, 10946, 10954, 10962, 10970,
			10978, 10986, 10994, 11002, 11010, 11017, 11025, 11032, 11040, 11047, 11054, 11062, 11069, 11076, 11083, 11090],
		[11097, 11111, 11125, 11138, 11151, 11164, 11177, 11189, 11202, 11214, 11226, 11238, 11250, 11262, 11273, 11284,
			11296, 11307, 11318, 11328, 11339, 11350, 11360, 11370, 11380, 11390, 11400, 11410, 11420, 11430, 11439, 11448,
			11458, 11467, 11476, 11485, 11494, 11503, 11512, 11520, 11529, 11538, 11546, 11554, 11563, 11571, 11579, 11587,
			11595, 11603, 11611, 11618, 11626, 11634, 11641, 11649, 11656, 11664, 11671, 11678, 11685, 11693, 11700, 11707],
		[11714, 11727, 11741, 11754, 11768, 11781, 11793, 11806, 11818, 11831, 11843, 11855, 11867, 11878, 11890, 11901,
			11912, 11923, 11934, 11945, 11956, 11966, 11976, 11987, 11997, 12007, 12017, 12027, 12036, 12046, 12056, 12065,
			12074, 12084, 12093, 12102, 12111, 12119, 12128, 12137, 12146, 12154, 12162, 12171, 12179, 12187, 12195, 12203,
			12211, 12219, 12227, 12235, 12243, 12250, 12258, 12265, 12273, 12280, 12287, 12295, 12302, 12309, 12316, 12323],
		[12330, 12344, 12358, 12371, 12384, 12397, 12410, 12423, 12435, 12447, 12459, 12471, 12483, 12495, 12506, 12517,
			12529, 12540, 12551, 12561, 12572, 12583, 12593, 12603, 12613, 12623, 12633, 12643, 12653, 12663, 12672, 12682,
			12691, 12700, 12709, 12718, 12727, 12736, 12745, 12753, 12762, 12771, 12779, 12787, 12796, 12804, 12812, 12820,
			12828, 12836, 12844, 12851, 12859, 12867, 12874, 12882, 12889, 12897, 12904, 12911, 12918, 12926, 12933, 12940],
		[12947, 12960, 12974, 12987, 13001, 13014, 13026, 13039, 13051, 13064, 13076, 13088, 13100, 13111, 13123, 13134,
			13145, 13156, 13167, 13178, 13189, 13199, 13209, 13220, 13230, 13240, 13250, 13260, 13269, 13279, 13289, 13298,
			13307, 13317, 13326, 13335, 13344, 13352, 13361, 13370, 13379, 13387, 13395, 13404, 13412, 13420, 13428, 13436,
			13444, 13452, 13460, 13468, 13476, 13483, 13491, 13498, 13506, 13513, 13521, 13528, 13535, 13542, 13549, 13556],
		[13563, 13577, 13591, 13604, 13617, 13630, 13643, 13656, 13668, 13680, 13692, 13704, 13716, 13728, 13739, 13750,
			13762, 13773, 13784, 13794, 13805, 13816, 13826, 13836, 13846, 13857, 13866, 13876, 13886, 13896, 13905, 13915,
			13924, 13933, 13942, 13951, 13960, 13969, 13978, 13986, 13995, 14004, 14012, 14020, 14029, 14037, 14045, 14053,
			14061, 14069, 14077, 14084, 14092, 14100, 14107, 14115, 14122, 14130, 14137, 14144, 14151, 14159, 14166, 14173],
		[14180, 14194, 14207, 14220, 14234, 14247, 14259, 14272, 14284, 14297, 14309, 14321, 14333, 14344, 14356, 14367,
			14378, 14389, 14400, 14411, 14422, 14432, 14443, 14453, 14463, 14473, 14483, 14493, 14502, 14512, 14522, 14531,
			14540, 14550, 14559, 14568, 14577, 14586, 14594, 14603, 14612, 14620, 14628, 14637, 14645, 14653, 14661, 14669,
			14677, 14685, 14693, 14701, 14709, 14716, 14724, 14731, 14739, 14746, 14754, 14761, 14768, 14775, 14782, 14789],
		[14796, 14810, 14824, 14837, 14850, 14863, 14876, 14889, 14901, 14913, 14925, 14937, 14949, 14961, 14972, 14984,
			14995, 15006, 15017, 15027, 15038, 15049, 15059, 15069, 15079, 15090, 15099, 15109, 15119, 15129, 15138, 15148,
			15157, 15166, 15175, 15184, 15193, 15202, 15211, 15219, 15228, 15237, 15245, 15253, 15262, 15270, 15278, 15286,
			15294, 15302, 15310, 15317, 15325, 15333, 15340, 15348, 15355, 15363, 15370, 15377, 15384, 15392, 15399, 15406],
		[15413, 15427, 15440, 15453, 15467, 15480, 15492, 15505, 15517, 15530, 15542, 15554, 15566, 15577, 15589, 15600,
			15611, 15622, 15633, 15644, 15655, 15665, 15676, 15686, 15696, 15706, 15716, 15726, 15736, 15745, 15755, 15764,
			15773, 15783, 15792, 15801, 15810, 15819, 15827, 15836, 15845, 15853, 15862, 15870, 15878, 15886, 15894, 15903,
			15910, 15918, 15926, 15934, 15942, 15949, 15957, 15964, 15972, 15979, 15987, 15994, 16001, 16008, 16015, 16022],
		[16029, 16043, 16057, 16070, 16083, 16096, 16109, 16122, 16134, 16146, 16158, 16170, 16182, 16194, 16205, 16217,
			16228, 16239, 16250, 16260, 16271, 16282, 16292, 16302, 16312, 16323, 16332, 16342, 16352, 16362, 16371, 16381,
			16390, 16399, 16408, 16417, 16426, 16435, 16444, 16452, 16461, 16470, 16478, 16486, 16495, 16503, 16511, 16519,
			16527, 16535, 16543, 16550, 16558, 16566, 16573, 16581, 16588, 16596, 16603, 16610, 16618, 16625, 16632, 16639],
		[16646, 16660, 16673, 16686, 16700, 16713, 16725, 16738, 16751, 16763, 16775, 16787, 16799, 16810, 16822, 16833,
			16844, 16855, 16866, 16877, 16888, 16898, 16909, 16919, 16929, 16939, 16949, 16959, 16969, 16978, 16988, 16997,
			17006, 17016, 17025, 17034, 17043, 17052, 17060, 17069, 17078, 17086, 17095, 17103, 17111, 17119, 17127, 17136,
			17143, 17151, 17159, 17167, 17175, 17182, 17190, 17197, 17205, 17212, 17220, 17227, 17234, 17241, 17248, 17255],
		[17262, 17276, 17290, 17303, 17316, 17329, 17342, 17355, 17367, 17379, 17391, 17403, 17415, 17427, 17438, 17450,
			17461, 17472, 17483, 17493, 17504, 17515, 17525, 17535, 17546, 17556, 17565, 17575, 17585, 17595, 17604, 17614,
			17623, 17632, 17641, 17650, 17659, 17668, 17677, 17685, 17694, 17703, 17711, 17719, 17728, 17736, 17744, 17752,
			17760, 17768, 17776, 17784, 17791, 17799, 17806, 17814, 17821, 17829, 17836, 17843, 17851, 17858, 17865, 17872],
		[17879, 17893, 17906, 17920, 17933, 17946, 17958, 17971, 17984, 17996, 18008, 18020, 18032, 18043, 18055, 18066,
			18077, 18088, 18099, 18110, 18121, 18131, 18142, 18152, 18162, 18172, 18182, 18192, 18202, 18211, 18221, 18230,
			18239, 18249, 18258, 18267, 18276, 18285, 18293, 18302, 18311, 18319, 18328, 18336, 18344, 18352, 18360, 18369,
			18377, 18384, 18392, 18400, 18408, 18415, 18423, 18430, 18438, 18445, 18453, 18460, 18467, 18474, 18481, 18488],
		[18495, 18509, 18523, 18536, 18549, 18562, 18575, 18588, 18600, 18612, 18624, 18636, 18648, 18660, 18671, 18683,
			18694, 18705, 18716, 18726, 18737, 18748, 18758, 18768, 18779, 18789, 18799, 18808, 18818, 18828, 18837, 18847,
			18856, 18865, 18874, 18883, 18892, 18901, 18910, 18919, 18927, 18936, 18944, 18952, 18961, 18969, 18977, 18985,
			18993, 19001, 19009, 19017, 19024, 19032, 19039, 19047, 19054, 19062, 19069, 19076, 19084, 19091, 19098, 19105],
		[19112, 19126, 19139, 19153, 19166, 19179, 19191, 19204, 19217, 19229, 19241, 19253, 19265, 19276, 19288, 19299,
			19310, 19321, 19332, 19343, 19354, 19364, 19375, 19385, 19395, 19405, 19415, 19425, 19435, 19444, 19454, 19463,
			19472, 19482, 19491, 19500, 19509, 19518, 19526, 19535, 19544, 19552, 19561, 19569, 19577, 19585, 19594, 19602,
			19610, 19617, 19625, 19633, 19641, 19648, 19656, 19663, 19671, 19678, 19686, 19693, 19700, 19707, 19714, 19721],
		[19728, 19742, 19756, 19769, 19782, 19795, 19808, 19821, 19833, 19845, 19857, 19869, 19881, 19893, 19904, 19916,
			19927, 19938, 19949, 19960, 19970, 19981, 19991, 20001, 20012, 20022, 20032, 20041, 20051, 20061, 20070, 20080,
			20089, 20098, 20107, 20116, 20125, 20134, 20143, 20152, 20160, 20169, 20177, 20185, 20194, 20202, 20210, 20218,
			20226, 20234, 20242, 20250, 20257, 20265, 20272, 20280, 20287, 20295, 20302, 20309, 20317, 20324, 20331, 20338],
		[20345, 20359, 20372, 20386, 20399, 20412, 20425, 20437, 20450, 20462, 20474, 20486, 20498, 20509, 20521, 20532,
			20543, 20554, 20565, 20576, 20587, 20597, 20608, 20618, 20628, 20638, 20648, 20658, 20668, 20677, 20687, 20696,
			20705, 20715, 20724, 20733, 20742, 20751, 20759, 20768, 20777, 20785, 20794, 20802, 20810, 20818, 20827, 20835,
			20843, 20850, 20858, 20866, 20874, 20881, 20889, 20896, 20904, 20911, 20919, 20926, 20933, 20940, 20947, 20954],
		[20961, 20975, 20989, 21002, 21015, 21028, 21041, 21054, 21066, 21078, 21090, 21102, 21114, 21126, 21137, 21149,
			21160, 21171, 21182, 21193, 21203, 21214, 21224, 21234, 21245, 21255, 21265, 21274, 21284, 21294, 21303, 21313,
			21322, 21331, 21340, 21349, 21358, 21367, 21376, 21385, 21393, 21402, 21410, 21418, 21427, 21435, 21443, 21451,
			21459, 21467, 21475, 21483, 21490, 21498, 21505, 21513, 21520, 21528, 21535, 21542, 21550, 21557, 21564, 21571],
		[21578, 21592, 21605, 21619, 21632, 21645, 21658, 21670, 21683, 21695, 21707, 21719, 21731, 21742, 21754, 21765,
			21776, 21787, 21798, 21809, 21820, 21830, 21841, 21851, 21861, 21871, 21881, 21891, 21901, 21910, 21920, 21929,
			21938, 21948, 21957, 21966, 21975, 21984, 21992, 22001, 22010, 22018, 22027, 22035, 22043, 22051, 22060, 22068,
			22076, 22083, 22091, 22099, 22107, 22114, 22122, 22129, 22137, 22144, 22152, 22159, 22166, 22173, 22180, 22187],
		[22194, 22208, 22222, 22235, 22248, 22261, 22274, 22287, 22299, 22311, 22323, 22335, 22347, 22359, 22370, 22382,
			22393, 22404, 22415, 22426, 22436, 22447, 22457, 22467, 22478, 22488, 22498, 22507, 22517, 22527, 22536, 22546,
			22555, 22564, 22573, 22582, 22591, 22600, 22609, 22618, 22626, 22635, 22643, 22651, 22660, 22668, 22676, 22684,
			22692, 22700, 22708, 22716, 22723, 22731, 22738, 22746, 22753, 22761, 22768, 22775, 22783, 22790, 22797, 22804],
		[22811, 22825, 22838, 22852, 22865, 22878, 22891, 22903, 22916, 22928, 22940, 22952, 22964, 22975, 22987, 22998,
			23009, 23020, 23031, 23042, 23053, 23063, 23074, 23084, 23094, 23104, 23114, 23124, 23134, 23143, 23153, 23162,
			23171, 23181, 23190, 23199, 23208, 23217, 23225, 23234, 23243, 23251, 23260, 23268, 23276, 23284, 23293, 23301,
			23309, 23316, 23324, 23332, 23340, 23347, 23355, 23363, 23370, 23377, 23385, 23392, 23399, 23406, 23413, 23420],
		[23427, 23441, 23455, 23468, 23481, 23494, 23507, 23520, 23532, 23544, 23556, 23568, 23580, 23592, 23603, 23615,
			23626, 23637, 23648, 23659, 23669, 23680, 23690, 23700, 23711, 23721, 23731, 23740, 23750, 23760, 23769, 23779,
			23788, 23797, 23806, 23815, 23824, 23833, 23842, 23851, 23859, 23868, 23876, 23884, 23893, 23901, 23909, 23917,
			23925, 23933, 23941, 23949, 23956, 23964, 23972, 23979, 23986, 23994, 24001, 24008, 24016, 24023, 24030, 24037],
		[24044, 24058, 24071, 24085, 24098, 24111, 24124, 24136, 24149, 24161, 24173, 24185, 24197, 24208, 24220, 24231,
			24242, 24253, 24264, 24275, 24286, 24296, 24307, 24317, 24327, 24337, 24347, 24357, 24367, 24376, 24386, 24395,
			24405, 24414, 24423, 24432, 24441, 24450, 24458, 24467, 24476, 24484, 24493, 24501, 24509, 24517, 24526, 24534,
			24542, 24550, 24557, 24565, 24573, 24580, 24588, 24596, 24603, 24610, 24618, 24625, 24632, 24639, 24646, 24653],
		[24660, 24674, 24688, 24701, 24714, 24727, 24740, 24753, 24765, 24777, 24790, 24801, 24813, 24825, 24836, 24848,
			24859, 24870, 24881, 24892, 24902, 24913, 24923, 24933, 24944, 24954, 24964, 24973, 24983, 24993, 25002, 25012,
			25021, 25030, 25039, 25048, 25057, 25066, 25075, 25084, 25092, 25101, 25109, 25117, 25126, 25134, 25142, 25150,
			25158, 25166, 25174, 25182, 25189, 25197, 25205, 25212, 25219, 25227, 25234, 25241, 25249, 25256, 25263, 25270],
		[25277, 25291, 25304, 25318, 25331, 25344, 25357, 25369, 25382, 25394, 25406, 25418, 25430, 25441, 25453, 25464,
			25475, 25486, 25497, 25508, 25519, 25529, 25540, 25550, 25560, 25570, 25580, 25590, 25600, 25609, 25619, 25628,
			25638, 25647, 25656, 25665, 25674, 25683, 25691, 25700, 25709, 25717, 25726, 25734, 25742, 25750, 25759, 25767,
			25775, 25783, 25790, 25798, 25806, 25813, 25821, 25829, 25836, 25843, 25851, 25858, 25865, 25872, 25879, 25886],
		[25893, 25907, 25921, 25934, 25947, 25960, 25973, 25986, 25998, 26010, 26023, 26034, 26046, 26058, 26069, 26081,
			26092, 26103, 26114, 26125, 26135, 26146, 26156, 26166, 26177, 26187, 26197, 26206, 26216, 26226, 26235, 26245,
			26254, 26263, 26272, 26281, 26290, 26299, 26308, 26317, 26325, 26334, 26342, 26351, 26359, 26367, 26375, 26383,
			26391, 26399, 26407, 26415, 26422, 26430, 26438, 26445, 26453, 26460, 26467, 26474, 26482, 26489, 26496, 26503],
		[26510, 26524, 26537, 26551, 26564, 26577, 26590, 26602, 26615, 26627, 26639, 26651, 26663, 26674, 26686, 26697,
			26708, 26719, 26730, 26741, 26752, 26762, 26773, 26783, 26793, 26803, 26813, 26823, 26833, 26842, 26852, 26861,
			26871, 26880, 26889, 26898, 26907, 26916, 26924, 26933, 26942, 26950, 26959, 26967, 26975, 26983, 26992, 27000,
			27008, 27016, 27023, 27031, 27039, 27046, 27054, 27062, 27069, 27076, 27084, 27091, 27098, 27105, 27112, 27119],
		[27126, 27140, 27154, 27167, 27180, 27193, 27206, 27219, 27231, 27243, 27256, 27267, 27279, 27291, 27302, 27314,
			27325, 27336, 27347, 27358, 27368, 27379, 27389, 27399, 27410, 27420, 27430, 27439, 27449, 27459, 27468, 27478,
			27487, 27496, 27505, 27514, 27523, 27532, 27541, 27550, 27558, 27567, 27575, 27584, 27592, 27600, 27608, 27616,
			27624, 27632, 27640, 27648, 27655, 27663, 27671, 27678, 27686, 27693, 27700, 27707, 27715, 27722, 27729, 27736],
		[27743, 27757, 27770, 27784, 27797, 27810, 27823, 27835, 27848, 27860, 27872, 27884, 27896, 27907, 27919, 27930,
			27941, 27952, 27963, 27974, 27985, 27995, 28006, 28016, 28026, 28036, 28046, 28056, 28066, 28075, 28085, 28094,
			28104, 28113, 28122, 28131, 28140, 28149, 28157, 28166, 28175, 28183, 28192, 28200, 28208, 28217, 28225, 28233,
			28241, 28249, 28256, 28264, 28272, 28280, 28287, 28295, 28302, 28309, 28317, 28324, 28331, 28338, 28345, 28352],
		[28359, 28373, 28387, 28400, 28413, 28426, 28439, 28452, 28464, 28476, 28489, 28501, 28512, 28524, 28535, 28547,
			28558, 28569, 28580, 28591, 28601, 28612, 28622, 28633, 28643, 28653, 28663, 28672, 28682, 28692, 28701, 28711,
			28720, 28729, 28738, 28747, 28756, 28765, 28774, 28783, 28791, 28800, 28808, 28817, 28825, 28833, 28841, 28849,
			28857, 28865, 28873, 28881, 28888, 28896, 28904, 28911, 28919, 28926, 28933, 28941, 28948, 28955, 28962, 28969],
		[28976, 28990, 29003, 29017, 29030, 29043, 29056, 29068, 29081, 29093, 29105, 29117, 29129, 29140, 29152, 29163,
			29174, 29185, 29196, 29207, 29218, 29228, 29239, 29249, 29259, 29269, 29279, 29289, 29299, 29308, 29318, 29327,
			29337, 29346, 29355, 29364, 29373, 29382, 29390, 29399, 29408, 29416, 29425, 29433, 29441, 29450, 29458, 29466,
			29474, 29482, 29489, 29497, 29505, 29513, 29520, 29528, 29535, 29542, 29550, 29557, 29564, 29571, 29578, 29585],
		[29592, 29606, 29620, 29633, 29646, 29659, 29672, 29685, 29697, 29709, 29722, 29734, 29745, 29757, 29768, 29780,
			29791, 29802, 29813, 29824, 29834, 29845, 29855, 29866, 29876, 29886, 29896, 29906, 29915, 29925, 29934, 29944,
			29953, 29962, 29971, 29980, 29989, 29998, 30007, 30016, 30024, 30033, 30041, 30050, 30058, 30066, 30074, 30082,
			30090, 30098, 30106, 30114, 30121, 30129, 30137, 30144, 30152, 30159, 30166, 30174, 30181, 30188, 30195, 30202],
		[30209, 30223, 30236, 30250, 30263, 30276, 30289, 30301, 30314, 30326, 30338, 30350, 30362, 30373, 30385, 30396,
			30407, 30418, 30429, 30440, 30451, 30461, 30472, 30482, 30492, 30502, 30512, 30522, 30532, 30541, 30551, 30560,
			30570, 30579, 30588, 30597, 30606, 30615, 30624, 30632, 30641, 30649, 30658, 30666, 30674, 30683, 30691, 30699,
			30707, 30715, 30722, 30730, 30738, 30746, 30753, 30761, 30768, 30775, 30783, 30790, 30797, 30804, 30811, 30818],
		[30825, 30839, 30853, 30866, 30879, 30892, 30905, 30918, 30930, 30943, 30955, 30967, 30978, 30990, 31001, 31013,
			31024, 31035, 31046, 31057, 31067, 31078, 31088, 31099, 31109, 31119, 31129, 31139, 31148, 31158, 31167, 31177,
			31186, 31195, 31204, 31213, 31222, 31231, 31240, 31249, 31257, 31266, 31274, 31283, 31291, 31299, 31307, 31315,
			31323, 31331, 31339, 31347, 31354, 31362, 31370, 31377, 31385, 31392, 31399, 31407, 31414, 31421, 31428, 31435],
		[31442, 31456, 31469, 31483, 31496, 31509, 31522, 31534, 31547, 31559, 31571, 31583, 31595, 31606, 31618, 31629,
			31640, 31652, 31662, 31673, 31684, 31694, 31705, 31715, 31725, 31735, 31745, 31755, 31765, 31774, 31784, 31793,
			31803, 31812, 31821, 31830, 31839, 31848, 31857, 31865, 31874, 31882, 31891, 31899, 31907, 31916, 31924, 31932,
			31940, 31948, 31955, 31963, 31971, 31979, 31986, 31994, 32001, 32008, 32016, 32023, 32030, 32037, 32044, 32052],
		[32058, 32072, 32086, 32099, 32112, 32125, 32138, 32151, 32163, 32176, 32188, 32200, 32211, 32223, 32234, 32246,
			32257, 32268, 32279, 32290, 32300, 32311, 32321, 32332, 32342, 32352, 32362, 32372, 32381, 32391, 32400, 32410,
			32419, 32428, 32437, 32446, 32455, 32464, 32473, 32482, 32490, 32499, 32507, 32516, 32524, 32532, 32540, 32548,
			32556, 32564, 32572, 32580, 32587, 32595, 32603, 32610, 32618, 32625, 32632, 32640, 32647, 32654, 32661, 32668],
		[32675, 32689, 32702, 32716, 32729, 32742, 32755, 32767, 32780, 32792, 32804, 32816, 32828, 32839, 32851, 32862,
			32873, 32885, 32895, 32906, 32917, 32927, 32938, 32948, 32958, 32968, 32978, 32988, 32998, 33007, 33017, 33026,
			33036, 33045, 33054, 33063, 33072, 33081, 33090, 33098, 33107, 33115, 33124, 33132, 33140, 33149, 33157, 33165,
			33173, 33181, 33188, 33196, 33204, 33212, 33219, 33227, 33234, 33241, 33249, 33256, 33263, 33270, 33278, 33285],
		[33292, 33305, 33319, 33332, 33345, 33358, 33371, 33384, 33396, 33409, 33421, 33433, 33444, 33456, 33467, 33479,
			33490, 33501, 33512, 33523, 33533, 33544, 33554, 33565, 33575, 33585, 33595, 33605, 33614, 33624, 33633, 33643,
			33652, 33661, 33670, 33680, 33688, 33697, 33706, 33715, 33723, 33732, 33740, 33749, 33757, 33765, 33773, 33781,
			33789, 33797, 33805, 33813, 33820, 33828, 33836, 33843, 33851, 33858, 33865, 33873, 33880, 33887, 33894, 33901],
		[33908, 33922, 33935, 33949, 33962, 33975, 33988, 34000, 34013, 34025, 34037, 34049, 34061, 34072, 34084, 34095,
			34106, 34118, 34128, 34139, 34150, 34160, 34171, 34181, 34191, 34201, 34211, 34221, 34231, 34240, 34250, 34259,
			34269, 34278, 34287, 34296, 34305, 34314, 34323, 34331, 34340, 34348, 34357, 34365, 34373, 34382, 34390, 34398,
			34406, 34414, 34422, 34429, 34437, 34445, 34452, 34460, 34467, 34475, 34482, 34489, 34496, 34503, 34511, 34518],
		[34525, 34538, 34552, 34565, 34578, 34591, 34604, 34617, 34629, 34642, 34654, 34666, 34677, 34689, 34700, 34712,
			34723, 34734, 34745, 34756, 34766, 34777, 34787, 34798, 34808, 34818, 34828, 34838, 34847, 34857, 34866, 34876,
			34885, 34894, 34904, 34913, 34921, 34930, 34939, 34948, 34956, 34965, 34973, 34982, 34990, 34998, 35006, 35014,
			35022, 35030, 35038, 35046, 35053, 35061, 35069, 35076, 35084, 35091, 35098, 35106, 35113, 35120, 35127, 35134],
		[35141, 35155, 35168, 35182, 35195, 35208, 35221, 35233, 35246, 35258, 35270, 35282, 35294, 35306, 35317, 35328,
			35340, 35351, 35361, 35372, 35383, 35393, 35404, 35414, 35424, 35434, 35444, 35454, 35464, 35473, 35483, 35492,
			35502, 35511, 35520, 35529, 35538, 35547, 35556, 35564, 35573, 35581, 35590, 35598, 35606, 35615, 35623, 35631,
			35639, 35647, 35655, 35662, 35670, 35678, 35685, 35693, 35700, 35708, 35715, 35722, 35729, 35736, 35744, 35751],
		[35758, 35771, 35785, 35798, 35811, 35824, 35837, 35850, 35862, 35875, 35887, 35899, 35910, 35922, 35934, 35945,
			35956, 35967, 35978, 35989, 35999, 36010, 36020, 36031, 36041, 36051, 36061, 36071, 36080, 36090, 36099, 36109,
			36118, 36127, 36137, 36146, 36154, 36163, 36172, 36181, 36189, 36198, 36206, 36215, 36223, 36231, 36239, 36247,
			36255, 36263, 36271, 36279, 36287, 36294, 36302, 36309, 36317, 36324, 36331, 36339, 36346, 36353, 36360, 36367],
		[36374, 36388, 36401, 36415, 36428, 36441, 36454, 36466, 36479, 36491, 36503, 36515, 36527, 36539, 36550, 36561,
			36573, 36584, 36594, 36605, 36616, 36626, 36637, 36647, 36657, 36667, 36677, 36687, 36697, 36706, 36716, 36725,
			36735, 36744, 36753, 36762, 36771, 36780, 36789, 36797, 36806, 36814, 36823, 36831, 36839, 36848, 36856, 36864,
			36872, 36880, 36888, 36895, 36903, 36911, 36918, 36926, 36933, 36941, 36948, 36955, 36962, 36969, 36977, 36984],
		[36991, 37004, 37018, 37031, 37044, 37057, 37070, 37083, 37095, 37108, 37120, 37132, 37143, 37155, 37167, 37178,
			37189, 37200, 37211, 37222, 37232, 37243, 37253, 37264, 37274, 37284, 37294, 37304, 37313, 37323, 37332, 37342,
			37351, 37360, 37370, 37379, 37388, 37396, 37405, 37414, 37422, 37431, 37439, 37448, 37456, 37464, 37472, 37480,
			37488, 37496, 37504, 37512, 37520, 37527, 37535, 37542, 37550, 37557, 37564, 37572, 37579, 37586, 37593, 37600],
		[37607, 37621, 37634, 37648, 37661, 37674, 37687, 37699, 37712, 37724, 37736, 37748, 37760, 37772, 37783, 37794,
			37806, 37817, 37828, 37838, 37849, 37859, 37870, 37880, 37890, 37900, 37910, 37920, 37930, 37939, 37949, 37958,
			37968, 37977, 37986, 37995, 38004, 38013, 38022, 38030, 38039, 38047, 38056, 38064, 38072, 38081, 38089, 38097,
			38105, 38113, 38121, 38128, 38136, 38144, 38151, 38159, 38166, 38174, 38181, 38188, 38195, 38202, 38210, 38217],
		[38224, 38237, 38251, 38264, 38278, 38290, 38303, 38316, 38328, 38341, 38353, 38365, 38376, 38388, 38400, 38411,
			38422, 38433, 38444, 38455, 38465, 38476, 38486, 38497, 38507, 38517, 38527, 38537, 38546, 38556, 38565, 38575,
			38584, 38593, 38603, 38612, 38621, 38629, 38638, 38647, 38655, 38664, 38672, 38681, 38689, 38697, 38705, 38713,
			38721, 38729, 38737, 38745, 38753, 38760, 38768, 38775, 38783, 38790, 38797, 38805, 38812, 38819, 38826, 38833],
		[38840, 38854, 38867, 38881, 38894, 38907, 38920, 38932, 38945, 38957, 38969, 38981, 38993, 39005, 39016, 39027,
			39039, 39050, 39061, 39071, 39082, 39092, 39103, 39113, 39123, 39133, 39143, 39153, 39163, 39172, 39182, 39191,
			39201, 39210, 39219, 39228, 39237, 39246, 39255, 39263, 39272, 39280, 39289, 39297, 39305, 39314, 39322, 39330,
			39338, 39346, 39354, 39361, 39369, 39377, 39384, 39392, 39399, 39407, 39414, 39421, 39428, 39436, 39443, 39450],
	];

	/// Approximate `log10(numerator / denominator) * 2048` using a look-up table.
	#[inline]
	pub fn negative_log10_times_2048(numerator: u64, denominator: u64) -> u64 {
		// Multiply the -1 through to avoid needing to use signed numbers.
		(log10_times_2048(denominator) - log10_times_2048(numerator)) as u64
	}

	#[inline]
	fn log10_times_2048(x: u64) -> u16 {
		debug_assert_ne!(x, 0);
		let most_significant_bit = HIGHEST_BIT - x.leading_zeros();
		let lower_bits = (x >> most_significant_bit.saturating_sub(LOWER_BITS)) & LOWER_BITMASK;
		LOG10_TIMES_2048[most_significant_bit as usize][lower_bits as usize]
	}

	#[cfg(test)]
	mod tests {
		use super::*;

		#[test]
		fn prints_negative_log10_times_2048_lookup_table() {
			for msb in 0..BITS {
				for i in 0..LOWER_BITS_BOUND {
					let x = ((LOWER_BITS_BOUND + i) << (HIGHEST_BIT - LOWER_BITS)) >> (HIGHEST_BIT - msb);
					let log10_times_2048 = ((x as f64).log10() * 2048.0).round() as u16;
					assert_eq!(log10_times_2048, LOG10_TIMES_2048[msb as usize][i as usize]);

					if i % LOWER_BITS_BOUND == 0 {
						print!("\t\t[{}, ", log10_times_2048);
					} else if i % LOWER_BITS_BOUND == LOWER_BITS_BOUND - 1 {
						println!("{}],", log10_times_2048);
					} else if i % (LOWER_BITS_BOUND/4) == LOWER_BITS_BOUND/4 - 1 {
						print!("{},\n\t\t\t", log10_times_2048);
					} else {
						print!("{}, ", log10_times_2048);
					}
				}
			}
		}
	}
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
		pub(super) buckets: [u16; 32],
	}

	/// Buckets are stored in fixed point numbers with a 5 bit fractional part. Thus, the value
	/// "one" is 32, or this constant.
	pub const BUCKET_FIXED_POINT_ONE: u16 = 32;

	impl HistoricalBucketRangeTracker {
		pub(super) fn new() -> Self { Self { buckets: [0; 32] } }
		pub(super) fn track_datapoint(&mut self, liquidity_offset_msat: u64, capacity_msat: u64) {
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
		/// Decay all buckets by the given number of half-lives. Used to more aggressively remove old
		/// datapoints as we receive newer information.
		#[inline]
		pub(super) fn time_decay_data(&mut self, half_lives: u32) {
			for e in self.buckets.iter_mut() {
				*e = e.checked_shr(half_lives).unwrap_or(0);
			}
		}
	}

	impl_writeable_tlv_based!(HistoricalBucketRangeTracker, { (0, buckets, required) });
	impl_writeable_tlv_based!(LegacyHistoricalBucketRangeTracker, { (0, buckets, required) });

	/// A set of buckets representing the history of where we've seen the minimum- and maximum-
	/// liquidity bounds for a given channel.
	pub(super) struct HistoricalMinMaxBuckets<D: Deref<Target = HistoricalBucketRangeTracker>> {
		/// Buckets tracking where and how often we've seen the minimum liquidity bound for a
		/// channel.
		pub(super) min_liquidity_offset_history: D,
		/// Buckets tracking where and how often we've seen the maximum liquidity bound for a
		/// channel.
		pub(super) max_liquidity_offset_history: D,
	}

	impl<D: Deref<Target = HistoricalBucketRangeTracker>> HistoricalMinMaxBuckets<D> {
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

			let mut total_valid_points_tracked = 0;
			for (min_idx, min_bucket) in self.min_liquidity_offset_history.buckets.iter().enumerate() {
				for max_bucket in self.max_liquidity_offset_history.buckets.iter().take(32 - min_idx) {
					total_valid_points_tracked += (*min_bucket as u64) * (*max_bucket as u64);
				}
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
			if self.min_liquidity_offset_history.buckets[0] != 0 {
				let mut highest_max_bucket_with_points = 0; // The highest max-bucket with any data
				let mut total_max_points = 0; // Total points in max-buckets to consider
				for (max_idx, max_bucket) in self.max_liquidity_offset_history.buckets.iter().enumerate() {
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
						(self.min_liquidity_offset_history.buckets[0] as u64) * total_max_points
							* 1024 * 1024 * 1024 / total_valid_points_tracked;
					cumulative_success_prob_times_billion += bucket_prob_times_billion *
						numerator / denominator;
				}
			}

			for (min_idx, min_bucket) in self.min_liquidity_offset_history.buckets.iter().enumerate().skip(1) {
				let min_bucket_start_pos = BUCKET_START_POS[min_idx];
				for (max_idx, max_bucket) in self.max_liquidity_offset_history.buckets.iter().enumerate().take(32 - min_idx) {
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
use bucketed_history::{LegacyHistoricalBucketRangeTracker, HistoricalBucketRangeTracker, HistoricalMinMaxBuckets};

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
		let mut channel_liquidities = HashMap::new();
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
			(5, Some(self.min_liquidity_offset_history), option),
			(7, Some(self.max_liquidity_offset_history), option),
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
			min_liquidity_offset_history: min_liquidity_offset_history.unwrap(),
			max_liquidity_offset_history: max_liquidity_offset_history.unwrap(),
			last_updated,
			offset_history_last_updated: offset_history_last_updated.unwrap_or(last_updated),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::{ChannelLiquidity, HistoricalBucketRangeTracker, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters, ProbabilisticScorer};
	use crate::blinded_path::{BlindedHop, BlindedPath};
	use crate::util::config::UserConfig;
	use crate::util::time::tests::SinceEpoch;

	use crate::ln::channelmanager;
	use crate::ln::msgs::{ChannelAnnouncement, ChannelUpdate, UnsignedChannelAnnouncement, UnsignedChannelUpdate};
	use crate::routing::gossip::{EffectiveCapacity, NetworkGraph, NodeId};
	use crate::routing::router::{BlindedTail, Path, RouteHop, CandidateRouteHop};
	use crate::routing::scoring::{ChannelUsage, ScoreLookUp, ScoreUpdate};
	use crate::util::ser::{ReadableArgs, Writeable};
	use crate::util::test_utils::{self, TestLogger};

	use bitcoin::blockdata::constants::ChainHash;
	use bitcoin::hashes::Hash;
	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::network::constants::Network;
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
		flags: u8, htlc_maximum_msat: u64, timestamp: u32,
	) {
		let genesis_hash = ChainHash::using_genesis_block(Network::Testnet);
		let secp_ctx = Secp256k1::new();
		let unsigned_update = UnsignedChannelUpdate {
			chain_hash: genesis_hash,
			short_channel_id,
			timestamp,
			flags,
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
					min_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
					max_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
				})
			.with_channel(43,
				ChannelLiquidity {
					min_liquidity_offset_msat: 700, max_liquidity_offset_msat: 100,
					last_updated, offset_history_last_updated,
					min_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
					max_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
				});
		let source = source_node_id();
		let target = target_node_id();
		let recipient = recipient_node_id();
		assert!(source > target);
		assert!(target < recipient);

		// Update minimum liquidity.

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 100);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 900);

		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000, decay_params)
			.set_min_liquidity_msat(200, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		// Update maximum liquidity.

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&target, &recipient, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 900);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&recipient, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 100);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		scorer.channel_liquidities.get_mut(&43).unwrap()
			.as_directed_mut(&target, &recipient, 1_000, decay_params)
			.set_max_liquidity_msat(200, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&target, &recipient, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 200);

		let liquidity = scorer.channel_liquidities.get(&43).unwrap()
			.as_directed(&recipient, &target, 1_000, decay_params);
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
					min_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
					max_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
				});
		let source = source_node_id();
		let target = target_node_id();
		assert!(source > target);

		// Check initial bounds.
		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		// Reset from source to target.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000, decay_params)
			.set_min_liquidity_msat(900, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 900);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 100);

		// Reset from target to source.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&target, &source, 1_000, decay_params)
			.set_min_liquidity_msat(400, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, decay_params);
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
					min_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
					max_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
				});
		let source = source_node_id();
		let target = target_node_id();
		assert!(source > target);

		// Check initial bounds.
		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 800);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 200);
		assert_eq!(liquidity.max_liquidity_msat(), 600);

		// Reset from source to target.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&source, &target, 1_000, decay_params)
			.set_max_liquidity_msat(300, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 0);
		assert_eq!(liquidity.max_liquidity_msat(), 300);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 700);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		// Reset from target to source.
		scorer.channel_liquidities.get_mut(&42).unwrap()
			.as_directed_mut(&target, &source, 1_000, decay_params)
			.set_max_liquidity_msat(600, Duration::ZERO);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&source, &target, 1_000, decay_params);
		assert_eq!(liquidity.min_liquidity_msat(), 400);
		assert_eq!(liquidity.max_liquidity_msat(), 1_000);

		let liquidity = scorer.channel_liquidities.get(&42).unwrap()
			.as_directed(&target, &source, 1_000, decay_params);
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
					min_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
					max_liquidity_offset_history: HistoricalBucketRangeTracker::new(),
				});
		let source = source_node_id();

		let usage = ChannelUsage {
			amount_msat: 39,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 100, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 41,
		};

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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
		// Note that a default liquidity bound is used for B -> C as no channel exists
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_b).unwrap();
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 43,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
		let channel = network_graph.read_only().channel(44).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_c).unwrap();
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 44,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);

		scorer.payment_path_failed(&Path { hops: path, blinded_tail: None }, 43, Duration::ZERO);

		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_a).unwrap();
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 80);
		// Note that a default liquidity bound is used for B -> C as no channel exists
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_b).unwrap();
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 43,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 128);
		let channel = network_graph.read_only().channel(44).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&node_c).unwrap();
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 44,
		};
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
		let candidate_41 = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 41,
		};
		let (info, target) = channel_42.as_directed_from(&source).unwrap();
		let candidate_42 = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
		let (info, _) = channel_43.as_directed_from(&target).unwrap();
		let candidate_43 = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 43,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		SinceEpoch::advance(Duration::from_secs(5));
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
		SinceEpoch::advance(Duration::from_secs(5));
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
		SinceEpoch::advance(Duration::from_secs(10 * 7));
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
		SinceEpoch::advance(Duration::from_secs(10));
		scorer.time_passed(Duration::from_secs(10 * 9));
		let usage = ChannelUsage { amount_msat: 0, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 1_024, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		SinceEpoch::advance(Duration::from_secs(10));
		scorer.time_passed(Duration::from_secs(10 * 10));
		let usage = ChannelUsage { amount_msat: 0, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 0);
		let usage = ChannelUsage { amount_msat: 1_024, ..usage };
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());
	}

	#[test]
	fn decays_liquidity_bounds_without_shift_overflow() {
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
			amount_msat: 256,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_000 },
		};
		let channel = network_graph.read_only().channel(42).unwrap().to_owned();
		let (info, _) = channel.as_directed_from(&source).unwrap();
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 125);

		scorer.payment_path_failed(&payment_path_for_amount(512), 42, Duration::ZERO);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 281);

		// An unchecked right shift 64 bits or more in DirectedChannelLiquidity::decayed_offset_msat
		// would cause an overflow.
		SinceEpoch::advance(Duration::from_secs(10 * 64));
		scorer.time_passed(Duration::from_secs(10 * 64));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 125);

		SinceEpoch::advance(Duration::from_secs(10));
		scorer.time_passed(Duration::from_secs(10 * 65));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 125);
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};

		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);

		// More knowledge gives higher confidence (256, 768), meaning a lower penalty.
		scorer.payment_path_failed(&payment_path_for_amount(768), 42, Duration::ZERO);
		scorer.payment_path_failed(&payment_path_for_amount(256), 43, Duration::ZERO);
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 281);

		// Decaying knowledge gives less confidence (128, 896), meaning a higher penalty.
		SinceEpoch::advance(Duration::from_secs(10));
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
		SinceEpoch::advance(Duration::from_secs(10));
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		SinceEpoch::advance(Duration::from_secs(10));
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), u64::max_value());

		if decay_before_reload {
			SinceEpoch::advance(Duration::from_secs(10));
			scorer.time_passed(Duration::from_secs(10));
		}

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		let mut serialized_scorer = io::Cursor::new(&serialized_scorer);
		let mut deserialized_scorer =
			<ProbabilisticScorer<_, _>>::read(&mut serialized_scorer, (decay_params, &network_graph, &logger)).unwrap();
		if !decay_before_reload {
			SinceEpoch::advance(Duration::from_secs(10));
			scorer.time_passed(Duration::from_secs(10));
			deserialized_scorer.time_passed(Duration::from_secs(10));
		}
		assert_eq!(deserialized_scorer.channel_penalty_msat(&candidate, usage, &params), 473);

		scorer.payment_path_failed(&payment_path_for_amount(250), 43, Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);

		SinceEpoch::advance(Duration::from_secs(10));
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
			let candidate = CandidateRouteHop::PublicHop {
				info,
				short_channel_id: 42,
			};

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
			let candidate = CandidateRouteHop::PublicHop {
				info,
				short_channel_id: 42,
			};

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
			let candidate = CandidateRouteHop::PublicHop {
				info,
				short_channel_id: 42,
			};

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
		SinceEpoch::advance(Duration::from_secs(10 * 16));
		scorer.time_passed(Duration::from_secs(10 * 16));
		{
			let network_graph = network_graph.read_only();
			let channel = network_graph.channel(42).unwrap();
			let (info, _) = channel.as_directed_from(&source).unwrap();
			let candidate = CandidateRouteHop::PublicHop {
				info,
				short_channel_id: 42,
			};

			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 168);
		}
		// Once fully decayed we still have data, but its all-0s. In the future we may remove the
		// data entirely instead.
		assert_eq!(scorer.historical_estimated_channel_liquidity_probabilities(42, &target),
			Some(([0; 32], [0; 32])));
		assert_eq!(scorer.historical_estimated_payment_success_probability(42, &target, 1, &params), None);

		let mut usage = ChannelUsage {
			amount_msat: 100,
			inflight_htlc_msat: 1024,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024, htlc_maximum_msat: 1_024 },
		};
		scorer.payment_path_failed(&payment_path_for_amount(1), 42, Duration::from_secs(10 * 16));
		{
			let network_graph = network_graph.read_only();
			let channel = network_graph.channel(42).unwrap();
			let (info, _) = channel.as_directed_from(&source).unwrap();
			let candidate = CandidateRouteHop::PublicHop {
				info,
				short_channel_id: 42,
			};

			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 2050);

			let usage = ChannelUsage {
				amount_msat: 1,
				inflight_htlc_msat: 0,
				effective_capacity: EffectiveCapacity::AdvertisedMaxHTLC { amount_msat: 0 },
			};
			assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 2048);
		}

		// Advance to decay all liquidity offsets to zero.
		SinceEpoch::advance(Duration::from_secs(60 * 60 * 10));
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
		assert_eq!(scorer.channel_penalty_msat(&candidate, usage, &params), 300);

		let mut path = payment_path_for_amount(768);
		let recipient_hop = path.hops.pop().unwrap();
		let blinded_path = BlindedPath {
			introduction_node_id: path.hops.last().as_ref().unwrap().pubkey,
			blinding_point: test_utils::pubkey(42),
			blinded_hops: vec![
				BlindedHop { blinded_node_id: test_utils::pubkey(44), encrypted_payload: Vec::new() }
			],
		};
		path.blinded_tail = Some(BlindedTail {
			hops: blinded_path.blinded_hops,
			blinding_point: blinded_path.blinding_point,
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
			.as_directed(&source, &target, 1_000, decay_params);
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
		let candidate = CandidateRouteHop::PublicHop {
			info,
			short_channel_id: 42,
		};
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
