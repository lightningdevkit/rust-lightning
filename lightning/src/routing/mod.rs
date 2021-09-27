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

/// An interface used to score payment channels for path finding.
///
///	Scoring is in terms of fees willing to be paid in order to avoid routing through a channel.
pub trait Score {
	/// Returns the fee in msats willing to be paid to avoid routing through the given channel.
	fn channel_penalty_msat(&self, short_channel_id: u64) -> u64;
}
