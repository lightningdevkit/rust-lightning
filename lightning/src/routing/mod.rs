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

use sync::{Mutex, MutexGuard};

/// An interface used to score payment channels for path finding.
///
///	Scoring is in terms of fees willing to be paid in order to avoid routing through a channel.
pub trait Score {
	/// Returns the fee in msats willing to be paid to avoid routing through the given channel
	/// in the direction from `source` to `target`.
	fn channel_penalty_msat(&self, short_channel_id: u64, source: &NodeId, target: &NodeId) -> u64;

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
pub struct LockableScore<S: Score> {
	scorer: Mutex<S>,
}

impl<S: Score> LockableScore<S> {
	/// Constructs a new LockableScore from a Score
	pub fn new(score: S) -> Self {
		Self { scorer: Mutex::new(score) }
	}
	/// Returns the locked scorer.
	/// (C-not exported)
	pub fn lock<'a>(&'a self) -> MutexGuard<'a, S> {
		self.scorer.lock().unwrap()
	}
}
