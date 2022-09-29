// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! [Onion message] pathfinding lives here.
//!
//! Finding paths for onion messages is necessary for retrieving invoices and fulfilling invoice
//! requests from [offers]. It differs from payment pathfinding in that channel liquidity, fees, and
//! knobs such as `htlc_maximum_msat` do not factor into path selection -- onion messages require a
//! peer connection and nothing more. However, we still use the network graph because onion messages
//! between channel peers are likely to be prioritized over those between non-channel peers.
//!
//! [Onion message]: crate::onion_message
//! [offers]: <https://github.com/lightning/bolts/pull/798>

use bitcoin::secp256k1::{self, PublicKey};

use crate::ln::channelmanager::ChannelDetails;
use crate::routing::gossip::{NetworkGraph, NodeId};
use crate::util::logger::Logger;

use alloc::collections::BinaryHeap;
use core::cmp;
use core::fmt;
use core::ops::Deref;
use crate::prelude::*;

/// Finds a route from us to the given `destination` node.
/// If we have private channels, it may be useful to fill in `first_hops` with the results from
/// [`ChannelManager::list_usable_channels`]. If `first_hops` is not filled in, connected peers
/// without public channels will not be forwarded over.
///
/// [`ChannelManager::list_usable_channels`]: crate::ln::channelmanager::ChannelManager::list_usable_channels
pub fn find_path<L: Deref, GL: Deref>(
	our_node_pubkey: &PublicKey, destination: &PublicKey, network_graph: &NetworkGraph<GL>, first_hops: Option<&[&ChannelDetails]>, logger: L
) -> Result<Vec<PublicKey>, Error> where L::Target: Logger, GL::Target: Logger
{
	log_trace!(logger, "Searching for an onion message path from origin {} to destination {} and {} first hops {}overriding the network graph",
		our_node_pubkey, destination, first_hops.map(|hops| hops.len()).unwrap_or(0),
		if first_hops.is_some() { "" } else { "not " });
	let graph_lock = network_graph.read_only();
	let network_channels = graph_lock.channels();
	let network_nodes = graph_lock.nodes();
	let our_node_id = NodeId::from_pubkey(our_node_pubkey);
	let dest_node_id = NodeId::from_pubkey(destination);
	if our_node_id == dest_node_id { return Err(Error::InvalidDestination) }

	// Add our start and first-hops to `frontier`, which is the set of hops that we'll next explore.
	let start = NodeId::from_pubkey(&our_node_pubkey);
	let mut valid_first_hops = HashSet::new();
	let mut frontier = BinaryHeap::new();
	frontier.push(PathBuildingHop { cost: 0, node_id: start, parent_node_id: start });
	if let Some(first_hops) = first_hops {
		for hop in first_hops {
			if hop.counterparty.node_id == *our_node_pubkey { return Err(Error::InvalidFirstHop) }
			if !hop.counterparty.features.supports_onion_messages() { continue; }
			let node_id = NodeId::from_pubkey(&hop.counterparty.node_id);
			frontier.push(PathBuildingHop { cost: 1, node_id, parent_node_id: start });
			valid_first_hops.insert(node_id);
		}
	}

	let mut visited = HashMap::new();
	while let Some(PathBuildingHop { cost, node_id, parent_node_id }) = frontier.pop() {
		match visited.entry(node_id) {
			hash_map::Entry::Occupied(_) => continue,
			hash_map::Entry::Vacant(e) => e.insert(parent_node_id),
		};
		if node_id == dest_node_id {
			let path = reverse_path(visited, our_node_id, dest_node_id)?;
			log_info!(logger, "Got route to {:?}: {:?}", destination, path);
			return Ok(path)
		}
		if let Some(node_info) = network_nodes.get(&node_id) {
			// Only consider the network graph if first_hops does not override it.
			if valid_first_hops.contains(&node_id) || node_id == our_node_id {
			} else if let Some(node_ann) = &node_info.announcement_info {
				if !node_ann.features.supports_onion_messages() || node_ann.features.requires_unknown_bits()
				{ continue; }
			} else { continue; }
			for scid in &node_info.channels {
				if let Some(chan_info) = network_channels.get(&scid) {
					if let Some((directed_channel, successor)) = chan_info.as_directed_from(&node_id) {
						if directed_channel.direction().enabled {
							// We may push a given successor multiple times, but the heap should sort its best
							// entry to the top. We do this because there is no way to adjust the priority of an
							// existing entry in `BinaryHeap`.
							frontier.push(PathBuildingHop {
								cost: cost + 1,
								node_id: *successor,
								parent_node_id: node_id,
							});
						}
					}
				}
			}
		}
	}

	Err(Error::PathNotFound)
}

#[derive(Debug, PartialEq)]
/// Errors that might occur running [`find_path`].
pub enum Error {
	/// We failed to find a path to the destination.
	PathNotFound,
	/// We failed to convert this node id into a [`PublicKey`].
	InvalidNodeId(secp256k1::Error),
	/// We attempted to generate a path to ourselves, which is not allowed.
	InvalidDestination,
	/// First hops cannot have our node id as a counterparty node id.
	InvalidFirstHop,
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Error::PathNotFound => write!(f, "Failed to find a path to the destination"),
			Error::InvalidNodeId(e) =>
				write!(f, "Failed to convert a node id into a PublicKey with error: {}", e),
			Error::InvalidDestination => write!(f, "Cannot generate a route to ourselves"),
			Error::InvalidFirstHop => write!(f, "First hops cannot have our node id as a counterparty node id"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Eq, PartialEq)]
struct PathBuildingHop {
	cost: u64,
	node_id: NodeId,
	parent_node_id: NodeId,
}

impl PartialOrd for PathBuildingHop {
	fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
		// We need a min-heap, whereas `BinaryHeap`s are a max-heap, so compare the costs in reverse.
		other.cost.partial_cmp(&self.cost)
	}
}

impl Ord for PathBuildingHop {
	fn cmp(&self, other: &Self) -> cmp::Ordering {
		self.partial_cmp(other).unwrap()
	}
}

fn reverse_path(
	parents: HashMap<NodeId, NodeId>, our_node_id: NodeId, destination: NodeId
)-> Result<Vec<PublicKey>, Error>
{
	let mut path = Vec::new();
	let mut curr = destination;
	loop {
		match PublicKey::from_slice(curr.as_slice()) {
			Ok(pk) => path.push(pk),
			Err(e) => return Err(Error::InvalidNodeId(e))
		}
		match parents.get(&curr) {
			None => return Err(Error::PathNotFound),
			Some(parent) => {
				if *parent == our_node_id { break; }
				curr = *parent;
			}
		}
	}

	path.reverse();
	Ok(path)
}

#[cfg(test)]
mod tests {
	use crate::ln::features::{InitFeatures, NodeFeatures};
	use crate::routing::test_utils::*;

	use crate::sync::Arc;

	#[test]
	fn three_hops() {
		let mut features = NodeFeatures::empty();
		features.set_onion_messages_optional();
		let (secp_ctx, network_graph, _, _, logger) = build_graph_with_features(features);
		let (_, our_id, _, node_pks) = get_nodes(&secp_ctx);

		let mut path = super::find_path(&our_id, &node_pks[5], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 3);
		assert!(path[0] == node_pks[1] || path[0] == node_pks[7] || path[0] == node_pks[0]);
		path.remove(0);
		assert_eq!(path, vec![node_pks[2], node_pks[5]]);
	}

	#[test]
	fn long_path() {
		let mut features = NodeFeatures::empty();
		features.set_onion_messages_optional();
		let (secp_ctx, network_graph, _, _, logger) = build_line_graph_with_features(features);
		let (_, our_id, _, node_pks) = get_nodes(&secp_ctx);

		let path = super::find_path(&our_id, &node_pks[18], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 19);
	}

	#[test]
	fn disable_nodes_test() {
		// Check that we won't route over nodes that require unknown feature bits.
		let mut features = InitFeatures::empty();
		features.set_onion_messages_optional();
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph_with_features(features.to_context());
		let (_, our_id, privkeys, node_pks) = get_nodes(&secp_ctx);

		// Disable nodes 1, 2, and 8 by requiring unknown feature bits
		let mut unknown_features = NodeFeatures::empty();
		unknown_features.set_unknown_feature_required();
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[0], unknown_features.clone(), 1);
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], unknown_features.clone(), 1);
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[7], unknown_features.clone(), 1);

		// If all nodes require some features we don't understand, route should fail
		let err = super::find_path(&our_id, &node_pks[2], &network_graph, None, Arc::clone(&logger)).unwrap_err();
		assert_eq!(err, super::Error::PathNotFound);

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), node_pks[7].clone(), features, 250_000_000)];
		let path = super::find_path(&our_id, &node_pks[2], &network_graph, Some(&our_chans.iter().collect::<Vec<_>>()), Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 2);
		assert_eq!(path[0], node_pks[7]);
		assert_eq!(path[1], node_pks[2]);
	}

	#[test]
	fn disabled_channels_test() {
		// Check that we won't attempt to route over nodes where the channel is disabled from their
		// direction (implying the peer is offline).
		let mut features = InitFeatures::empty();
		features.set_onion_messages_optional();
		let (secp_ctx, network_graph, _, _, logger) = build_graph_with_features(features.to_context());
		let (_, our_id, _, node_pks) = get_nodes(&secp_ctx);

		// Route to 1 via 2 and 3 because our channel to 1 is disabled
		let path = super::find_path(&our_id, &node_pks[0], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 3);
		assert_eq!(path[0], node_pks[1]);
		assert_eq!(path[1], node_pks[2]);
		assert_eq!(path[2], node_pks[0]);

		// If we specify a channel to node1, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), node_pks[0].clone(), features, 250_000_000)];
		let path = super::find_path(&our_id, &node_pks[0], &network_graph, Some(&our_chans.iter().collect::<Vec<_>>()), Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 1);
		assert_eq!(path[0], node_pks[0]);
	}

	#[test]
	fn invalid_first_hop() {
		// Check that we can't generate a path if first_hops contains a counterparty node id that
		// is equal to our node id.
		let mut features = InitFeatures::empty();
		features.set_onion_messages_optional();
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph_with_features(features.to_context());
		let (_, our_id, privkeys, node_pks) = get_nodes(&secp_ctx);

		let bad_first_hop = vec![get_channel_details(Some(2), our_id, features, 100000)];
		let err = super::find_path(&our_id, &node_pks[2], &network_graph, Some(&bad_first_hop.iter().collect::<Vec<_>>()), Arc::clone(&logger)).unwrap_err();
		assert_eq!(err, super::Error::InvalidFirstHop);

		let path = super::find_path(&our_id, &node_pks[2], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 2);
	}
}
