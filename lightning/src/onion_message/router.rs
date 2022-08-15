use bitcoin::secp256k1::PublicKey;

use ln::msgs::{ErrorAction, LightningError};
use routing::gossip::{NetworkGraph, NodeId};
use util::logger::{Level, Logger};

use alloc::collections::BinaryHeap;
use core::hash::Hash;
use core::ops::Deref;
use prelude::*;

/// Find a path for sending an onion message.
pub fn find_path<L: Deref, GL: Deref>(
	our_node_pubkey: &PublicKey, receiver_pubkey: &PublicKey, network_graph: &NetworkGraph<GL>, first_hops: Option<&[&PublicKey]>, logger: L
) -> Result<Vec<PublicKey>, LightningError> where L::Target: Logger, GL::Target: Logger
{
	let graph_lock = network_graph.read_only();
	let network_channels = graph_lock.channels();
	let network_nodes = graph_lock.nodes();
	let our_node_id = NodeId::from_pubkey(our_node_pubkey);

	let mut for_each_successor = |node_id, callback: &mut FnMut(&NodeId, u64)| {
		// TODO: in this method, check if OM forwarding feature bit is supported
		if node_id == our_node_id && first_hops.is_some() {
			if let Some(first_hops) = first_hops {
				for hop in first_hops {
					callback(&NodeId::from_pubkey(hop), 1);
				}
			}
		} else if let Some(node_info) = network_nodes.get(&node_id) {
			for scid in &node_info.channels {
				if let Some(chan_info) = network_channels.get(&scid) {
					let successor_node_id = if chan_info.node_one == node_id {
						&chan_info.node_two
					} else {
						debug_assert!(chan_info.node_two == node_id);
						&chan_info.node_one
					};
					callback(successor_node_id, 1); // Use a fixed cost for each hop until scoring is added
				}
			}
		}
	};

	let mut invalid_final_hop_pk = None;
	let mut convert_final_hop = |node_id: &NodeId| {
		match PublicKey::from_slice(node_id.as_slice()) {
			Ok(pk) => Ok(pk),
			Err(e) => {
				invalid_final_hop_pk = Some(*node_id);
				Err(())
			},
		}
	};

	let receiver_node_id = NodeId::from_pubkey(receiver_pubkey);
	match dijkstra(our_node_id, &mut for_each_successor, |node_id| node_id == &receiver_node_id, &mut convert_final_hop) {
		Ok(p) => Ok(p),
		Err(Error::PathNotFound) => Err(LightningError {
			err: "Failed to find a path to the given destination".to_owned(),
			action: ErrorAction::IgnoreError,
		}),
		Err(Error::FinalHopConversion) => {
			debug_assert!(invalid_final_hop_pk.is_some());
			Err(LightningError {
				err: format!("Public key {:?} is invalid", invalid_final_hop_pk),
				action: ErrorAction::IgnoreAndLog(Level::Trace)
			})
		}
	}
}

#[derive(Debug, PartialEq)]
/// Errored running `dijkstra`.
enum Error {
	/// No path exists to the destination.
	PathNotFound,
	/// Converting the processing hop type to the final hop type failed, see `dijkstra`'s
	/// `convert_final_hop` parameter.
	FinalHopConversion,
}

//  Heavily adapted from https://github.com/samueltardieu/pathfinding/blob/master/src/directed/dijkstra.rs
//  TODO: how2credit the repo (is that necessary?)?
/// Run Dijkstra's from `start` until `found_target` indicates that we've found the destination.
/// `successor_callback` must invoke the callback that it is provided on each of a given node's
/// next-hop peers. `convert_final_hop` may be used to convert an intermediate processing hop type
/// (`N`) to a final path hop type (`H`).
fn dijkstra<N, H, FN, FS, FC>(start: N, successor_callback: &mut FN, found_target: FS,
	convert_final_hop: &mut FC) -> Result<Vec<H>, Error>
	where N: Eq + Hash + Copy + Ord,
	      FN: FnMut(N, &mut FnMut(&N, u64)),
	      FS: Fn(&N) -> bool,
	      FC: FnMut(&N) -> Result<H, ()>,
{
	let mut to_see = BinaryHeap::new();
	to_see.push((start, 0));
	let mut parents: HashMap<N, (N, u64)> = HashMap::new();
	parents.insert(start, (start, 0));

	let mut target_reached = None;
	while let Some((node, cost)) = to_see.pop() {
		let &(_, c) = parents.get(&node).unwrap();
		if found_target(&node) {
			target_reached = Some(node);
			break;
		}
		// We may have inserted a node several times into the binary heap if we found a better way to
		// access it. Ensure that we are currently dealing with the best path and discard the others.
		if cost > c {
			continue;
		}
		successor_callback(node, &mut |successor, move_cost| {
			let new_cost = cost + move_cost;
			match parents.entry(*successor) {
				hash_map::Entry::Vacant(e) => {
					e.insert((node, new_cost));
					to_see.push((*successor, new_cost));
				}
				hash_map::Entry::Occupied(mut e) => {
					if e.get().1 > new_cost {
						e.insert((node, new_cost));
						to_see.push((e.get().0, new_cost));
					}
				}
			}
		});
	}

	match target_reached {
		Some(t) => reverse_path(parents, t, convert_final_hop).map_err(|()| Error::FinalHopConversion),
		None => Err(Error::PathNotFound)
	}
}

// Errors if `convert_path_hop` fails.
fn reverse_path<N, H, FC>(parents: HashMap<N, (N, u64)>, start: N, convert_path_hop: &mut FC) -> Result<Vec<H>, ()>
	where N: Eq + Hash + Copy + Ord,
				FC: FnMut(&N) -> Result<H, ()>,
{
	let mut path = vec![convert_path_hop(&start)?];
	let mut curr = start;
	loop {
		if let Some((parent_node_id, _)) = parents.get(&curr) {
			if parent_node_id != &curr {
				path.push(convert_path_hop(parent_node_id)?);
				curr = *parent_node_id;
			} else { break; }
		} else { break; }
	}
	path.reverse();
	path.remove(0);
	Ok(path)
}

#[cfg(test)]
mod tests {
	use routing::test_utils;
	use super::dijkstra;
	use super::Error;

	use sync::Arc;

	fn expected(target: u8) -> Result<Vec<u8>, Error> {
		match target {
			0 => Ok(vec![0]),
			1 => Ok(vec![]),
			2 => Ok(vec![6, 2]),
			3 => Ok(vec![0, 3]),
			4 => Ok(vec![6, 4]),
			5 => Ok(vec![6, 5]),
			6 => Ok(vec![6]),
			7 => Ok(vec![0, 3, 7]),
			8 => Err(Error::PathNotFound),
			_ => panic!("no such node"),
		}
	}

	#[test]
	fn dijkstra_ok() {
		let successors_lookup : Vec<Vec<(u8, usize)>> = vec![
			vec![(1, 7), (2, 7), (3, 6)],
			vec![(0, 8), (6, 7)],
			vec![(5, 7)],
			vec![(7, 7)],
			vec![(4, 2)],
			vec![(1, 1)],
			vec![(2, 5), (4, 5), (5, 2)],
			vec![(5, 8)],
			vec![],
		];
		let mut successors = |node, callback: &mut FnMut(&u8, u64)| {
			for successor in &successors_lookup[node as usize] {
				callback(&successor.0, 1);
			}
		};
		for target in 0..9 {
			assert_eq!(
				dijkstra(1, &mut successors, |&node| node == target, &mut |&node| Ok(node)),
				expected(target)
			);
		}
	}

	#[test]
	fn one_hop() {
		let (secp_ctx, network_graph, _, _, logger) = test_utils::build_graph();
		let (_, our_id, _, node_pks) = test_utils::get_nodes(&secp_ctx);

		let path = super::find_path(&our_id, &node_pks[0], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 1);
		assert!(path[0] == node_pks[0]);
	}

	#[test]
	fn two_hops() {
		let (secp_ctx, network_graph, _, _, logger) = test_utils::build_graph();
		let (_, our_id, _, node_pks) = test_utils::get_nodes(&secp_ctx);

		let path = super::find_path(&our_id, &node_pks[2], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 2);
		// See test_utils::build_graph ASCII graph, the first hop can be any of these
		assert!(path[0] == node_pks[1] || path[0] == node_pks[7] || path[0] == node_pks[0]);
		assert_eq!(path[1], node_pks[2]);
	}

	#[test]
	fn three_hops() {
		let (secp_ctx, network_graph, _, _, logger) = test_utils::build_graph();
		let (_, our_id, _, node_pks) = test_utils::get_nodes(&secp_ctx);

		let mut path = super::find_path(&our_id, &node_pks[5], &network_graph, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 3);
		assert!(path[0] == node_pks[1] || path[0] == node_pks[7] || path[0] == node_pks[0]);
		path.remove(0);
		assert_eq!(path, vec![node_pks[2], node_pks[5]]);
	}

	#[test]
	fn long_path() {
		let (secp_ctx, network, _, _, logger) = test_utils::build_line_graph();
		let (_, our_id, _, node_pks) = test_utils::get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let path = super::find_path(&our_id, &node_pks[18], &network, None, Arc::clone(&logger)).unwrap();
		assert_eq!(path.len(), 19);
	}
}
