// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The top-level routing/network map tracking logic lives here.
//!
//! You probably want to create a NetGraphMsgHandler and use that as your RoutingMessageHandler and then
//! interrogate it to get routes for your own payments.

use bitcoin::secp256k1::key::PublicKey;

use ln::channelmanager::ChannelDetails;
use ln::features::{ChannelFeatures, NodeFeatures};
use ln::msgs::{DecodeError, ErrorAction, LightningError, MAX_VALUE_MSAT};
use routing::network_graph::{NetworkGraph, RoutingFees};
use util::ser::{Writeable, Readable};
use util::logger::Logger;

use std::cmp;
use std::collections::{HashMap,BinaryHeap};
use std::ops::Deref;

/// A hop in a route
#[derive(Clone, PartialEq)]
pub struct RouteHop {
	/// The node_id of the node at this hop.
	pub pubkey: PublicKey,
	/// The node_announcement features of the node at this hop. For the last hop, these may be
	/// amended to match the features present in the invoice this node generated.
	pub node_features: NodeFeatures,
	/// The channel that should be used from the previous hop to reach this node.
	pub short_channel_id: u64,
	/// The channel_announcement features of the channel that should be used from the previous hop
	/// to reach this node.
	pub channel_features: ChannelFeatures,
	/// The fee taken on this hop. For the last hop, this should be the full value of the payment.
	pub fee_msat: u64,
	/// The CLTV delta added for this hop. For the last hop, this should be the full CLTV value
	/// expected at the destination, in excess of the current block height.
	pub cltv_expiry_delta: u32,
}

/// (C-not exported)
impl Writeable for Vec<RouteHop> {
	fn write<W: ::util::ser::Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		(self.len() as u8).write(writer)?;
		for hop in self.iter() {
			hop.pubkey.write(writer)?;
			hop.node_features.write(writer)?;
			hop.short_channel_id.write(writer)?;
			hop.channel_features.write(writer)?;
			hop.fee_msat.write(writer)?;
			hop.cltv_expiry_delta.write(writer)?;
		}
		Ok(())
	}
}

/// (C-not exported)
impl Readable for Vec<RouteHop> {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Vec<RouteHop>, DecodeError> {
		let hops_count: u8 = Readable::read(reader)?;
		let mut hops = Vec::with_capacity(hops_count as usize);
		for _ in 0..hops_count {
			hops.push(RouteHop {
				pubkey: Readable::read(reader)?,
				node_features: Readable::read(reader)?,
				short_channel_id: Readable::read(reader)?,
				channel_features: Readable::read(reader)?,
				fee_msat: Readable::read(reader)?,
				cltv_expiry_delta: Readable::read(reader)?,
			});
		}
		Ok(hops)
	}
}

/// A route directs a payment from the sender (us) to the recipient. If the recipient supports MPP,
/// it can take multiple paths. Each path is composed of one or more hops through the network.
#[derive(Clone, PartialEq)]
pub struct Route {
	/// The list of routes taken for a single (potentially-)multi-part payment. The pubkey of the
	/// last RouteHop in each path must be the same.
	/// Each entry represents a list of hops, NOT INCLUDING our own, where the last hop is the
	/// destination. Thus, this must always be at least length one. While the maximum length of any
	/// given path is variable, keeping the length of any path to less than 20 should currently
	/// ensure it is viable.
	pub paths: Vec<Vec<RouteHop>>,
}

impl Writeable for Route {
	fn write<W: ::util::ser::Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
		(self.paths.len() as u64).write(writer)?;
		for hops in self.paths.iter() {
			hops.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for Route {
	fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Route, DecodeError> {
		let path_count: u64 = Readable::read(reader)?;
		let mut paths = Vec::with_capacity(cmp::min(path_count, 128) as usize);
		for _ in 0..path_count {
			paths.push(Readable::read(reader)?);
		}
		Ok(Route { paths })
	}
}

/// A channel descriptor which provides a last-hop route to get_route
#[derive(Clone)]
pub struct RouteHint {
	/// The node_id of the non-target end of the route
	pub src_node_id: PublicKey,
	/// The short_channel_id of this channel
	pub short_channel_id: u64,
	/// The fees which must be paid to use this channel
	pub fees: RoutingFees,
	/// The difference in CLTV values between this node and the next node.
	pub cltv_expiry_delta: u16,
	/// The minimum value, in msat, which must be relayed to the next hop.
	pub htlc_minimum_msat: u64,
}

#[derive(Eq, PartialEq)]
struct RouteGraphNode {
	pubkey: PublicKey,
	lowest_fee_to_peer_through_node: u64,
	lowest_fee_to_node: u64,
}

impl cmp::Ord for RouteGraphNode {
	fn cmp(&self, other: &RouteGraphNode) -> cmp::Ordering {
		other.lowest_fee_to_peer_through_node.cmp(&self.lowest_fee_to_peer_through_node)
			.then_with(|| other.pubkey.serialize().cmp(&self.pubkey.serialize()))
	}
}

impl cmp::PartialOrd for RouteGraphNode {
	fn partial_cmp(&self, other: &RouteGraphNode) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}

struct DummyDirectionalChannelInfo {
	cltv_expiry_delta: u32,
	htlc_minimum_msat: u64,
	fees: RoutingFees,
}


/// Gets a route from us to the given target node.
///
/// Extra routing hops between known nodes and the target will be used if they are included in
/// last_hops.
///
/// If some channels aren't announced, it may be useful to fill in a first_hops with the
/// results from a local ChannelManager::list_usable_channels() call. If it is filled in, our
/// view of our local channels (from net_graph_msg_handler) will be ignored, and only those in first_hops
/// will be used.
///
/// Panics if first_hops contains channels without short_channel_ids
/// (ChannelManager::list_usable_channels will never include such channels).
///
/// The fees on channels from us to next-hops are ignored (as they are assumed to all be
/// equal), however the enabled/disabled bit on such channels as well as the htlc_minimum_msat
/// *is* checked as they may change based on the receiving node.
pub fn get_route<L: Deref>(our_node_id: &PublicKey, network: &NetworkGraph, target: &PublicKey, first_hops: Option<&[&ChannelDetails]>,
	last_hops: &[&RouteHint], final_value_msat: u64, final_cltv: u32, logger: L) -> Result<Route, LightningError> where L::Target: Logger {
	// TODO: Obviously *only* using total fee cost sucks. We should consider weighting by
	// uptime/success in using a node in the past.
	if *target == *our_node_id {
		return Err(LightningError{err: "Cannot generate a route to ourselves".to_owned(), action: ErrorAction::IgnoreError});
	}

	if final_value_msat > MAX_VALUE_MSAT {
		return Err(LightningError{err: "Cannot generate a route of more value than all existing satoshis".to_owned(), action: ErrorAction::IgnoreError});
	}

	// We do a dest-to-source Dijkstra's sorting by each node's distance from the destination
	// plus the minimum per-HTLC fee to get from it to another node (aka "shitty A*").
	// TODO: There are a few tweaks we could do, including possibly pre-calculating more stuff
	// to use as the A* heuristic beyond just the cost to get one node further than the current
	// one.

	let dummy_directional_info = DummyDirectionalChannelInfo { // used for first_hops routes
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		fees: RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		}
	};

	let mut targets = BinaryHeap::new(); //TODO: Do we care about switching to eg Fibbonaci heap?
	let mut dist = HashMap::with_capacity(network.get_nodes().len());

	let mut first_hop_targets = HashMap::with_capacity(if first_hops.is_some() { first_hops.as_ref().unwrap().len() } else { 0 });
	if let Some(hops) = first_hops {
		for chan in hops {
			let short_channel_id = chan.short_channel_id.expect("first_hops should be filled in with usable channels, not pending ones");
			if chan.remote_network_id == *target {
				return Ok(Route {
					paths: vec![vec![RouteHop {
						pubkey: chan.remote_network_id,
						node_features: chan.counterparty_features.to_context(),
						short_channel_id,
						channel_features: chan.counterparty_features.to_context(),
						fee_msat: final_value_msat,
						cltv_expiry_delta: final_cltv,
					}]],
				});
			}
			first_hop_targets.insert(chan.remote_network_id, (short_channel_id, chan.counterparty_features.clone()));
		}
		if first_hop_targets.is_empty() {
			return Err(LightningError{err: "Cannot route when there are no outbound routes away from us".to_owned(), action: ErrorAction::IgnoreError});
		}
	}

	macro_rules! add_entry {
		// Adds entry which goes from $src_node_id to $dest_node_id
		// over the channel with id $chan_id with fees described in
		// $directional_info.
		( $chan_id: expr, $src_node_id: expr, $dest_node_id: expr, $directional_info: expr, $chan_features: expr, $starting_fee_msat: expr ) => {
			//TODO: Explore simply adding fee to hit htlc_minimum_msat
			if $starting_fee_msat as u64 + final_value_msat >= $directional_info.htlc_minimum_msat {
				let proportional_fee_millions = ($starting_fee_msat + final_value_msat).checked_mul($directional_info.fees.proportional_millionths as u64);
				if let Some(new_fee) = proportional_fee_millions.and_then(|part| {
						($directional_info.fees.base_msat as u64).checked_add(part / 1000000) })
				{
					let mut total_fee = $starting_fee_msat as u64;
					let hm_entry = dist.entry(&$src_node_id);
					let old_entry = hm_entry.or_insert_with(|| {
						let mut fee_base_msat = u32::max_value();
						let mut fee_proportional_millionths = u32::max_value();
						if let Some(fees) = network.get_nodes().get(&$src_node_id).and_then(|node| node.lowest_inbound_channel_fees) {
							fee_base_msat = fees.base_msat;
							fee_proportional_millionths = fees.proportional_millionths;
						}
						(u64::max_value(),
							fee_base_msat,
							fee_proportional_millionths,
							RouteHop {
								pubkey: $dest_node_id.clone(),
								node_features: NodeFeatures::empty(),
								short_channel_id: 0,
								channel_features: $chan_features.clone(),
								fee_msat: 0,
								cltv_expiry_delta: 0,
							},
						)
					});
					if $src_node_id != *our_node_id {
						// Ignore new_fee for channel-from-us as we assume all channels-from-us
						// will have the same effective-fee
						total_fee += new_fee;
						if let Some(fee_inc) = final_value_msat.checked_add(total_fee).and_then(|inc| { (old_entry.2 as u64).checked_mul(inc) }) {
							total_fee += fee_inc / 1000000 + (old_entry.1 as u64);
						} else {
							// max_value means we'll always fail the old_entry.0 > total_fee check
							total_fee = u64::max_value();
						}
					}
					let new_graph_node = RouteGraphNode {
						pubkey: $src_node_id,
						lowest_fee_to_peer_through_node: total_fee,
						lowest_fee_to_node: $starting_fee_msat as u64 + new_fee,
					};
					if old_entry.0 > total_fee {
						targets.push(new_graph_node);
						old_entry.0 = total_fee;
						old_entry.3 = RouteHop {
							pubkey: $dest_node_id.clone(),
							node_features: NodeFeatures::empty(),
							short_channel_id: $chan_id.clone(),
							channel_features: $chan_features.clone(),
							fee_msat: new_fee, // This field is ignored on the last-hop anyway
							cltv_expiry_delta: $directional_info.cltv_expiry_delta as u32,
						}
					}
				}
			}
		};
	}

	macro_rules! add_entries_to_cheapest_to_target_node {
		( $node: expr, $node_id: expr, $fee_to_target_msat: expr ) => {
			if first_hops.is_some() {
				if let Some(&(ref first_hop, ref features)) = first_hop_targets.get(&$node_id) {
					add_entry!(first_hop, *our_node_id, $node_id, dummy_directional_info, features.to_context(), $fee_to_target_msat);
				}
			}

			let features;
			if let Some(node_info) = $node.announcement_info.as_ref() {
				features = node_info.features.clone();
			} else {
				features = NodeFeatures::empty();
			}

			if !features.requires_unknown_bits() {
				for chan_id in $node.channels.iter() {
					let chan = network.get_channels().get(chan_id).unwrap();
					if !chan.features.requires_unknown_bits() {
						if chan.node_one == *$node_id {
							// ie $node is one, ie next hop in A* is two, via the two_to_one channel
							if first_hops.is_none() || chan.node_two != *our_node_id {
								if let Some(two_to_one) = chan.two_to_one.as_ref() {
									if two_to_one.enabled {
										add_entry!(chan_id, chan.node_two, chan.node_one, two_to_one, chan.features, $fee_to_target_msat);
									}
								}
							}
						} else {
							if first_hops.is_none() || chan.node_one != *our_node_id {
								if let Some(one_to_two) = chan.one_to_two.as_ref() {
									if one_to_two.enabled {
										add_entry!(chan_id, chan.node_one, chan.node_two, one_to_two, chan.features, $fee_to_target_msat);
									}
								}

							}
						}
					}
				}
			}
		};
	}

	match network.get_nodes().get(target) {
		None => {},
		Some(node) => {
			add_entries_to_cheapest_to_target_node!(node, target, 0);
		},
	}

	for hop in last_hops.iter() {
		let have_hop_src_in_graph =
			if let Some(&(ref first_hop, ref features)) = first_hop_targets.get(&hop.src_node_id) {
				// If this hop connects to a node with which we have a direct channel, ignore the
				// network graph and add both the hop and our direct channel to the candidate set:
				//
				// Currently there are no channel-context features defined, so we are a
				// bit lazy here. In the future, we should pull them out via our
				// ChannelManager, but there's no reason to waste the space until we
				// need them.
				add_entry!(first_hop, *our_node_id , hop.src_node_id, dummy_directional_info, features.to_context(), 0);
				true
			} else {
				// In any other case, only add the hop if the source is in the regular network
				// graph:
				network.get_nodes().get(&hop.src_node_id).is_some()
			};
		if have_hop_src_in_graph {
			// BOLT 11 doesn't allow inclusion of features for the last hop hints, which
			// really sucks, cause we're gonna need that eventually.
			add_entry!(hop.short_channel_id, hop.src_node_id, target, hop, ChannelFeatures::empty(), 0);
		}
	}

	while let Some(RouteGraphNode { pubkey, lowest_fee_to_node, .. }) = targets.pop() {
		if pubkey == *our_node_id {
			let mut res = vec!(dist.remove(&our_node_id).unwrap().3);
			loop {
				if let Some(&(_, ref features)) = first_hop_targets.get(&res.last().unwrap().pubkey) {
					res.last_mut().unwrap().node_features = features.to_context();
				} else if let Some(node) = network.get_nodes().get(&res.last().unwrap().pubkey) {
					if let Some(node_info) = node.announcement_info.as_ref() {
						res.last_mut().unwrap().node_features = node_info.features.clone();
					} else {
						res.last_mut().unwrap().node_features = NodeFeatures::empty();
					}
				} else {
					// We should be able to fill in features for everything except the last
					// hop, if the last hop was provided via a BOLT 11 invoice (though we
					// should be able to extend it further as BOLT 11 does have feature
					// flags for the last hop node itself).
					assert!(res.last().unwrap().pubkey == *target);
				}
				if res.last().unwrap().pubkey == *target {
					break;
				}

				let new_entry = match dist.remove(&res.last().unwrap().pubkey) {
					Some(hop) => hop.3,
					None => return Err(LightningError{err: "Failed to find a non-fee-overflowing path to the given destination".to_owned(), action: ErrorAction::IgnoreError}),
				};
				res.last_mut().unwrap().fee_msat = new_entry.fee_msat;
				res.last_mut().unwrap().cltv_expiry_delta = new_entry.cltv_expiry_delta;
				res.push(new_entry);
			}
			res.last_mut().unwrap().fee_msat = final_value_msat;
			res.last_mut().unwrap().cltv_expiry_delta = final_cltv;
			let route = Route { paths: vec![res] };
			log_trace!(logger, "Got route: {}", log_route!(route));
			return Ok(route);
		}

		match network.get_nodes().get(&pubkey) {
			None => {},
			Some(node) => {
				add_entries_to_cheapest_to_target_node!(node, &pubkey, lowest_fee_to_node);
			},
		}
	}

	Err(LightningError{err: "Failed to find a path to the given destination".to_owned(), action: ErrorAction::IgnoreError})
}

#[cfg(test)]
mod tests {
	use routing::router::{get_route, RouteHint, RoutingFees};
	use routing::network_graph::{NetworkGraph, NetGraphMsgHandler};
	use ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};
	use ln::msgs::{ErrorAction, LightningError, OptionalField, UnsignedChannelAnnouncement, ChannelAnnouncement, RoutingMessageHandler,
	   NodeAnnouncement, UnsignedNodeAnnouncement, ChannelUpdate, UnsignedChannelUpdate};
	use ln::channelmanager;
	use util::test_utils;
	use util::ser::Writeable;

	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::constants::genesis_block;

	use hex;

	use bitcoin::secp256k1::key::{PublicKey,SecretKey};
	use bitcoin::secp256k1::{Secp256k1, All};

	use std::sync::Arc;

	// Using the same keys for LN and BTC ids
	fn add_channel(net_graph_msg_handler: &NetGraphMsgHandler<Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>, secp_ctx: &Secp256k1<All>, node_1_privkey: &SecretKey,
	   node_2_privkey: &SecretKey, features: ChannelFeatures, short_channel_id: u64) {
		let node_id_1 = PublicKey::from_secret_key(&secp_ctx, node_1_privkey);
		let node_id_2 = PublicKey::from_secret_key(&secp_ctx, node_2_privkey);

		let unsigned_announcement = UnsignedChannelAnnouncement {
			features,
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id,
			node_id_1,
			node_id_2,
			bitcoin_key_1: node_id_1,
			bitcoin_key_2: node_id_2,
			excess_data: Vec::new(),
		};

		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = ChannelAnnouncement {
			node_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign(&msghash, node_1_privkey),
			bitcoin_signature_2: secp_ctx.sign(&msghash, node_2_privkey),
			contents: unsigned_announcement.clone(),
		};
		match net_graph_msg_handler.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};
	}

	fn update_channel(net_graph_msg_handler: &NetGraphMsgHandler<Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>, secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, update: UnsignedChannelUpdate) {
		let msghash = hash_to_message!(&Sha256dHash::hash(&update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign(&msghash, node_privkey),
			contents: update.clone()
		};

		match net_graph_msg_handler.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(res),
			// Err(_) => panic!()
			Err(e) => println!("{:?}", e.err)
		};
	}


	fn add_or_update_node(net_graph_msg_handler: &NetGraphMsgHandler<Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>, secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey,
	   features: NodeFeatures, timestamp: u32) {
		let node_id = PublicKey::from_secret_key(&secp_ctx, node_privkey);
		let unsigned_announcement = UnsignedNodeAnnouncement {
			features,
			timestamp,
			node_id,
			rgb: [0; 3],
			alias: [0; 32],
			addresses: Vec::new(),
			excess_address_data: Vec::new(),
			excess_data: Vec::new(),
		};
		let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
		let valid_announcement = NodeAnnouncement {
			signature: secp_ctx.sign(&msghash, node_privkey),
			contents: unsigned_announcement.clone()
		};

		match net_graph_msg_handler.handle_node_announcement(&valid_announcement) {
			Ok(_) => (),
			Err(_) => panic!()
		};
	}

	fn get_nodes(secp_ctx: &Secp256k1<All>) -> (SecretKey, PublicKey, Vec<SecretKey>, Vec<PublicKey>) {
		let privkeys: Vec<SecretKey> = (2..10).map(|i| {
			SecretKey::from_slice(&hex::decode(format!("{:02}", i).repeat(32)).unwrap()[..]).unwrap()
		}).collect();

		let pubkeys = privkeys.iter().map(|secret| PublicKey::from_secret_key(&secp_ctx, secret)).collect();

		let our_privkey = SecretKey::from_slice(&hex::decode("01".repeat(32)).unwrap()[..]).unwrap();
		let our_id = PublicKey::from_secret_key(&secp_ctx, &our_privkey);

		(our_privkey, our_id, privkeys, pubkeys)
	}

	fn id_to_feature_flags(id: u8) -> Vec<u8> {
		// Set the feature flags to the id'th odd (ie non-required) feature bit so that we can
		// test for it later.
		let idx = (id - 1) * 2 + 1;
		if idx > 8*3 {
			vec![1 << (idx - 8*3), 0, 0, 0]
		} else if idx > 8*2 {
			vec![1 << (idx - 8*2), 0, 0]
		} else if idx > 8*1 {
			vec![1 << (idx - 8*1), 0]
		} else {
			vec![1 << idx]
		}
	}

	fn build_graph() -> (Secp256k1<All>, NetGraphMsgHandler<std::sync::Arc<crate::util::test_utils::TestChainSource>, std::sync::Arc<crate::util::test_utils::TestLogger>>, std::sync::Arc<test_utils::TestLogger>) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let net_graph_msg_handler = NetGraphMsgHandler::new(genesis_block(Network::Testnet).header.block_hash(), None, Arc::clone(&logger));
		// Build network from our_id to node7:
		//
		//        -1(1)2-  node0  -1(3)2-
		//       /                       \
		// our_id -1(12)2- node7 -1(13)2--- node2
		//       \                       /
		//        -1(2)2-  node1  -1(4)2-
		//
		//
		// chan1  1-to-2: disabled
		// chan1  2-to-1: enabled, 0 fee
		//
		// chan2  1-to-2: enabled, ignored fee
		// chan2  2-to-1: enabled, 0 fee
		//
		// chan3  1-to-2: enabled, 0 fee
		// chan3  2-to-1: enabled, 100 msat fee
		//
		// chan4  1-to-2: enabled, 100% fee
		// chan4  2-to-1: enabled, 0 fee
		//
		// chan12 1-to-2: enabled, ignored fee
		// chan12 2-to-1: enabled, 0 fee
		//
		// chan13 1-to-2: enabled, 200% fee
		// chan13 2-to-1: enabled, 0 fee
		//
		//
		//       -1(5)2- node3 -1(8)2--
		//       |         2          |
		//       |       (11)         |
		//      /          1           \
		// node2--1(6)2- node4 -1(9)2--- node6 (not in global route map)
		//      \                      /
		//       -1(7)2- node5 -1(10)2-
		//
		// chan5  1-to-2: enabled, 100 msat fee
		// chan5  2-to-1: enabled, 0 fee
		//
		// chan6  1-to-2: enabled, 0 fee
		// chan6  2-to-1: enabled, 0 fee
		//
		// chan7  1-to-2: enabled, 100% fee
		// chan7  2-to-1: enabled, 0 fee
		//
		// chan8  1-to-2: enabled, variable fee (0 then 1000 msat)
		// chan8  2-to-1: enabled, 0 fee
		//
		// chan9  1-to-2: enabled, 1001 msat fee
		// chan9  2-to-1: enabled, 0 fee
		//
		// chan10 1-to-2: enabled, 0 fee
		// chan10 2-to-1: enabled, 0 fee
		//
		// chan11 1-to-2: enabled, 0 fee
		// chan11 2-to-1: enabled, 0 fee

		let (our_privkey, _, privkeys, _) = get_nodes(&secp_ctx);

		add_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, &privkeys[0], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[0], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2);
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: u16::max_value(),
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, &privkeys[7], ChannelFeatures::from_le_bytes(id_to_feature_flags(12)), 12);
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: u16::max_value(),
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[7], NodeFeatures::from_le_bytes(id_to_feature_flags(8)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 8) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (3 << 8) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (4 << 8) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (4 << 8) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(13)), 13);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (13 << 8) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 2000000,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (13 << 8) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (6 << 8) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (6 << 8) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		});

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(11)), 11);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (11 << 8) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (11 << 8) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(5)), 0);

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

		add_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], &privkeys[5], ChannelFeatures::from_le_bytes(id_to_feature_flags(7)), 7);
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (7 << 8) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[5], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (7 << 8) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[5], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

		(secp_ctx, net_graph_msg_handler, logger)
	}

	#[test]
	fn simple_route_test() {
		let (secp_ctx, net_graph_msg_handler, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		// Simple route to 3 via 2
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2], None, &Vec::new(), 100, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));
	}

	#[test]
	fn disable_channels_test() {
		let (secp_ctx, net_graph_msg_handler, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);

		// // Disable channels 4 and 12 by flags=2
		update_channel(&net_graph_msg_handler, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&net_graph_msg_handler, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: OptionalField::Absent,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// If all the channels require some features we don't understand, route should fail
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2], None, &Vec::new(), 100, 42, Arc::clone(&logger)) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![channelmanager::ChannelDetails {
			channel_id: [0; 32],
			short_channel_id: Some(42),
			remote_network_id: nodes[7].clone(),
			counterparty_features: InitFeatures::from_le_bytes(vec![0b11]),
			channel_value_satoshis: 0,
			user_id: 0,
			outbound_capacity_msat: 0,
			inbound_capacity_msat: 0,
			is_live: true,
		}];
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2], Some(&our_chans.iter().collect::<Vec<_>>()),  &Vec::new(), 100, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]); // it should also override our view of their features
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 13);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));
	}

	#[test]
	fn disable_node_test() {
		let (secp_ctx, net_graph_msg_handler, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);

		// Disable nodes 1, 2, and 8 by requiring unknown feature bits
		let mut unknown_features = NodeFeatures::known();
		unknown_features.set_required_unknown_bits();
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[0], unknown_features.clone(), 1);
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[1], unknown_features.clone(), 1);
		add_or_update_node(&net_graph_msg_handler, &secp_ctx, &privkeys[7], unknown_features.clone(), 1);

		// If all nodes require some features we don't understand, route should fail
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2], None, &Vec::new(), 100, 42, Arc::clone(&logger)) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![channelmanager::ChannelDetails {
			channel_id: [0; 32],
			short_channel_id: Some(42),
			remote_network_id: nodes[7].clone(),
			counterparty_features: InitFeatures::from_le_bytes(vec![0b11]),
			channel_value_satoshis: 0,
			user_id: 0,
			outbound_capacity_msat: 0,
			inbound_capacity_msat: 0,
			is_live: true,
		}];
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2], Some(&our_chans.iter().collect::<Vec<_>>()), &Vec::new(), 100, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]); // it should also override our view of their features
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 13);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));

		// Note that we don't test disabling node 3 and failing to route to it, as we (somewhat
		// naively) assume that the user checked the feature bits on the invoice, which override
		// the node_announcement.
	}

	#[test]
	fn our_chans_test() {
		let (secp_ctx, net_graph_msg_handler, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		// Route to 1 via 2 and 3 because our channel to 1 is disabled
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0], None, &Vec::new(), 100, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 3);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (3 << 8) | 2);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[0]);
		assert_eq!(route.paths[0][2].short_channel_id, 3);
		assert_eq!(route.paths[0][2].fee_msat, 100);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(1));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(3));

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![channelmanager::ChannelDetails {
			channel_id: [0; 32],
			short_channel_id: Some(42),
			remote_network_id: nodes[7].clone(),
			counterparty_features: InitFeatures::from_le_bytes(vec![0b11]),
			channel_value_satoshis: 0,
			user_id: 0,
			outbound_capacity_msat: 0,
			inbound_capacity_msat: 0,
			is_live: true,
		}];
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2], Some(&our_chans.iter().collect::<Vec<_>>()), &Vec::new(), 100, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]);
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 13);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));
	}

	fn last_hops(nodes: &Vec<PublicKey>) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec!(RouteHint {
			src_node_id: nodes[3].clone(),
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 8) | 1,
			htlc_minimum_msat: 0,
		}, RouteHint {
			src_node_id: nodes[4].clone(),
			short_channel_id: 9,
			fees: RoutingFees {
				base_msat: 1001,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (9 << 8) | 1,
			htlc_minimum_msat: 0,
		}, RouteHint {
			src_node_id: nodes[5].clone(),
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 8) | 1,
			htlc_minimum_msat: 0,
		})
	}

	#[test]
	fn last_hops_test() {
		let (secp_ctx, net_graph_msg_handler, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		// Simple test across 2, 3, 5, and 4 via a last_hop channel
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[6], None, &last_hops(&nodes).iter().collect::<Vec<_>>(), 100, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 8) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 8) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 0);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 8) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 100);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), &Vec::<u8>::new()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[test]
	fn our_chans_last_hop_connect_test() {
		let (secp_ctx, net_graph_msg_handler, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		// Simple test with outbound channel to 4 to test that last_hops and first_hops connect
		let our_chans = vec![channelmanager::ChannelDetails {
			channel_id: [0; 32],
			short_channel_id: Some(42),
			remote_network_id: nodes[3].clone(),
			counterparty_features: InitFeatures::from_le_bytes(vec![0b11]),
			channel_value_satoshis: 0,
			user_id: 0,
			outbound_capacity_msat: 0,
			inbound_capacity_msat: 0,
			is_live: true,
		}];
		let mut last_hops = last_hops(&nodes);
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[6], Some(&our_chans.iter().collect::<Vec<_>>()), &last_hops.iter().collect::<Vec<_>>(), 100, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[3]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 0);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (8 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]);
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[6]);
		assert_eq!(route.paths[0][1].short_channel_id, 8);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &Vec::<u8>::new()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		last_hops[0].fees.base_msat = 1000;

		// Revert to via 6 as the fee on 8 goes up
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[6], None, &last_hops.iter().collect::<Vec<_>>(), 100, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 4);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200); // fee increased as its % of value transferred across node
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (7 << 8) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[5]);
		assert_eq!(route.paths[0][2].short_channel_id, 7);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (10 << 8) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(6));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(7));

		assert_eq!(route.paths[0][3].pubkey, nodes[6]);
		assert_eq!(route.paths[0][3].short_channel_id, 10);
		assert_eq!(route.paths[0][3].fee_msat, 100);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][3].node_features.le_flags(), &Vec::<u8>::new()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		// ...but still use 8 for larger payments as 6 has a variable feerate
		let route = get_route(&our_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[6], None, &last_hops.iter().collect::<Vec<_>>(), 2000, 42, Arc::clone(&logger)).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 3000);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 8) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 8) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 1000);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 8) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 2000);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), &Vec::<u8>::new()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[test]
	fn unannounced_path_test() {
		// We should be able to send a payment to a destination without any help of a routing graph
		// if we have a channel with a common counterparty that appears in the first and last hop
		// hints.
		let source_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 41).repeat(32)).unwrap()[..]).unwrap());
		let middle_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let target_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());

		// If we specify a channel to a middle hop, that overrides our local channel view and that gets used
		let last_hops = vec![RouteHint {
			src_node_id: middle_node_id,
			short_channel_id: 8,
			fees: RoutingFees {
				base_msat: 1000,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (8 << 8) | 1,
			htlc_minimum_msat: 0,
		}];
		let our_chans = vec![channelmanager::ChannelDetails {
			channel_id: [0; 32],
			short_channel_id: Some(42),
			remote_network_id: middle_node_id,
			counterparty_features: InitFeatures::from_le_bytes(vec![0b11]),
			channel_value_satoshis: 100000,
			user_id: 0,
			outbound_capacity_msat: 100000,
			inbound_capacity_msat: 100000,
			is_live: true,
		}];
		let route = get_route(&source_node_id, &NetworkGraph::new(genesis_block(Network::Testnet).header.block_hash()), &target_node_id, Some(&our_chans.iter().collect::<Vec<_>>()), &last_hops.iter().collect::<Vec<_>>(), 100, 42, Arc::new(test_utils::TestLogger::new())).unwrap();

		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, middle_node_id);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 1000);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (8 << 8) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &[0b11]);
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &[0; 0]); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0][1].pubkey, target_node_id);
		assert_eq!(route.paths[0][1].short_channel_id, 8);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &[0; 0]); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &[0; 0]); // We can't learn any flags from invoices, sadly
	}
}
