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
//! custom [`Score`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate secp256k1;
//! #
//! # use lightning::routing::network_graph::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scoring::{Scorer, ScoringParameters};
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
//! Persisting when built with feature `no-std` and restoring without it, or vice versa, uses
//! different types and thus is undefined.
//!
//! [`find_route`]: crate::routing::router::find_route

use ln::msgs::DecodeError;
use routing::network_graph::NodeId;
use routing::router::RouteHop;
use util::ser::{Readable, Writeable, Writer};

use prelude::*;
use core::cell::{RefCell, RefMut};
use core::ops::DerefMut;
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
	/// The channel's capacity (less any other MPP parts which are also being considered for use in
	/// the same payment) is given by `channel_capacity_msat`. It may be guessed from various
	/// sources or assumed from no data at all.
	///
	/// For hints provided in the invoice, we assume the channel has sufficient capacity to accept
	/// the invoice's full amount, and provide a `channel_capacity_msat` of `None`. In all other
	/// cases it is set to `Some`, even if we're guessing at the channel value.
	///
	/// Your code should be overflow-safe through a `channel_capacity_msat` of 21 million BTC.
	fn channel_penalty_msat(&self, short_channel_id: u64, send_amt_msat: u64, channel_capacity_msat: Option<u64>, source: &NodeId, target: &NodeId) -> u64;

	/// Handles updating channel penalties after failing to route through a channel.
	fn payment_path_failed(&mut self, path: &[&RouteHop], short_channel_id: u64);

	/// Handles updating channel penalties after successfully routing along a path.
	fn payment_path_successful(&mut self, path: &[&RouteHop]);
}

impl<S: Score, T: DerefMut<Target=S> $(+ $supertrait)*> Score for T {
	fn channel_penalty_msat(&self, short_channel_id: u64, send_amt_msat: u64, channel_capacity_msat: Option<u64>, source: &NodeId, target: &NodeId) -> u64 {
		self.deref().channel_penalty_msat(short_channel_id, send_amt_msat, channel_capacity_msat, source, target)
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

/// [`Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. Will further penalize channels that fail to relay payments.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: crate::routing::scoring
#[cfg(not(feature = "no-std"))]
pub type Scorer = ScorerUsingTime::<std::time::Instant>;
/// [`Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. Will further penalize channels that fail to relay payments.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: crate::routing::scoring
#[cfg(feature = "no-std")]
pub type Scorer = ScorerUsingTime::<time::Eternity>;

// Note that ideally we'd hide ScorerUsingTime from public view by sealing it as well, but rustdoc
// doesn't handle this well - instead exposing a `Scorer` which has no trait implementation(s) or
// methods at all.

/// [`Score`] implementation.
///
/// See [`Scorer`] for details.
///
/// # Note
///
/// Mixing the `no-std` feature between serialization and deserialization results in undefined
/// behavior.
///
/// (C-not exported) generally all users should use the [`Scorer`] type alias.
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
	/// [`failure_penalty_half_life`].
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
	/// Accumulated penalty in msats for the channel as of `last_failed`.
	undecayed_penalty_msat: u64,

	/// Last time the channel failed. Used to decay `undecayed_penalty_msat`.
	last_failed: T,
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
			overuse_penalty_start_1024th: 1024,
			overuse_penalty_msat_per_1024th: 0,
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
			overuse_penalty_start_1024th: 1024 / 8,
			overuse_penalty_msat_per_1024th: 20,
		}
	}
}

impl<T: Time> Score for ScorerUsingTime<T> {
	fn channel_penalty_msat(
		&self, short_channel_id: u64, send_amt_msat: u64, chan_capacity_opt: Option<u64>, _source: &NodeId, _target: &NodeId
	) -> u64 {
		let failure_penalty_msat = self.channel_failures
			.get(&short_channel_id)
			.map_or(0, |value| value.decayed_penalty_msat(self.params.failure_penalty_half_life));

		let mut penalty_msat = self.params.base_penalty_msat + failure_penalty_msat;

		if let Some(chan_capacity_msat) = chan_capacity_opt {
			let send_1024ths = send_amt_msat.checked_mul(1024).unwrap_or(u64::max_value()) / chan_capacity_msat;

			if send_1024ths > self.params.overuse_penalty_start_1024th as u64 {
				penalty_msat = penalty_msat.checked_add(
						(send_1024ths - self.params.overuse_penalty_start_1024th as u64)
						.checked_mul(self.params.overuse_penalty_msat_per_1024th).unwrap_or(u64::max_value()))
					.unwrap_or(u64::max_value());
			}
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

	fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
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
		let duration_since_epoch = T::duration_since_epoch() - self.last_failed.elapsed();
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
			last_failed: T::now() - (T::duration_since_epoch() - duration_since_epoch),
		})
	}
}

pub(crate) mod time {
	use core::ops::Sub;
	use core::time::Duration;
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

	/// A state in which time has no meaning.
	#[derive(Debug, PartialEq, Eq)]
	pub struct Eternity;

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
}

pub(crate) use self::time::Time;

#[cfg(test)]
mod tests {
	use super::{ScoringParameters, ScorerUsingTime, Time};
	use super::time::Eternity;

	use routing::scoring::Score;
	use routing::network_graph::NodeId;
	use util::ser::{Readable, Writeable};

	use bitcoin::secp256k1::PublicKey;
	use core::cell::Cell;
	use core::ops::Sub;
	use core::time::Duration;
	use io;

	/// Time that can be advanced manually in tests.
	#[derive(Debug, PartialEq, Eq)]
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

	/// A scorer for testing with time that can be manually advanced.
	type Scorer = ScorerUsingTime::<SinceEpoch>;

	fn source_node_id() -> NodeId {
		NodeId::from_pubkey(&PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap())
	}

	fn target_node_id() -> NodeId {
		NodeId::from_pubkey(&PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap())
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
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_000);

		SinceEpoch::advance(Duration::from_secs(1));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_000);
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
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_000);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_064);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_128);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_192);
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
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_000);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(9));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(1));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_256);

		SinceEpoch::advance(Duration::from_secs(10 * 8));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_001);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_000);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_000);
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
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_000);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_256);

		scorer.payment_path_failed(&[], 42);
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_768);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_384);
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
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_512);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_256);

		scorer.payment_path_failed(&[], 43);
		assert_eq!(scorer.channel_penalty_msat(43, 1, Some(1), &source, &target), 1_512);

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		let deserialized_scorer = <Scorer>::read(&mut io::Cursor::new(&serialized_scorer)).unwrap();
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_256);
		assert_eq!(deserialized_scorer.channel_penalty_msat(43, 1, Some(1), &source, &target), 1_512);
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
		assert_eq!(scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_512);

		let mut serialized_scorer = Vec::new();
		scorer.write(&mut serialized_scorer).unwrap();

		SinceEpoch::advance(Duration::from_secs(10));

		let deserialized_scorer = <Scorer>::read(&mut io::Cursor::new(&serialized_scorer)).unwrap();
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_256);

		SinceEpoch::advance(Duration::from_secs(10));
		assert_eq!(deserialized_scorer.channel_penalty_msat(42, 1, Some(1), &source, &target), 1_128);
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

		assert_eq!(scorer.channel_penalty_msat(42, 1_000, None, &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 1_000, Some(1_024_000), &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 256_999, Some(1_024_000), &source, &target), 0);
		assert_eq!(scorer.channel_penalty_msat(42, 257_000, Some(1_024_000), &source, &target), 100);
		assert_eq!(scorer.channel_penalty_msat(42, 258_000, Some(1_024_000), &source, &target), 200);
		assert_eq!(scorer.channel_penalty_msat(42, 512_000, Some(1_024_000), &source, &target), 256 * 100);
	}
}
