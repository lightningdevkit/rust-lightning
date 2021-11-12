// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Structs and impls for receiving messages about the network and storing the topology live here.

pub mod network_graph;
pub mod router;
pub mod scorer;

use routing::network_graph::NodeId;
use routing::router::RouteHop;

use core::cell::{RefCell, RefMut};
use core::ops::DerefMut;
use sync::{Mutex, MutexGuard};

/// An interface used to score payment channels for path finding.
///
///	Scoring is in terms of fees willing to be paid in order to avoid routing through a channel.
pub trait Score {
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
}

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

impl<S: Score, T: DerefMut<Target=S>> Score for T {
	fn channel_penalty_msat(&self, short_channel_id: u64, send_amt_msat: u64, channel_capacity_msat: Option<u64>, source: &NodeId, target: &NodeId) -> u64 {
		self.deref().channel_penalty_msat(short_channel_id, send_amt_msat, channel_capacity_msat, source, target)
	}

	fn payment_path_failed(&mut self, path: &[&RouteHop], short_channel_id: u64) {
		self.deref_mut().payment_path_failed(path, short_channel_id)
	}
}
