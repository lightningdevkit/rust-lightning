#![allow(missing_docs)]
// TODO: take fees into account for transfering money: add 1% for fees, compute exact fees for paths.
// TODO: Handle CTLV
// TODO: In flight HTLC
// TODO: translate the ,,big test'' from pickhardt_payments to a payments test that uses in-flight-htlcs.

use core::{ops::Deref, convert::TryInto};
use prelude::{HashMap, HashSet};
const MAX_VALUE_MSAT: u64 = 2100000000000000000;
use bitcoin::secp256k1::PublicKey;
use routing::{gossip::{NetworkGraph, NodeId}, router::{RouteParameters, Route, RouteHop, PaymentParameters}};
use util::logger::Logger;
use ln::{channelmanager::ChannelDetails, msgs::{LightningError, ErrorAction},
		features::{NodeFeatures, ChannelFeatures}};
use routing::min_cost_flow_lib::{self,OriginalEdge};
use crate::routing::{scoring::Score, gossip::ReadOnlyNetworkGraph, router::add_random_cltv_offset};

type ChannelMetaData=(u64, u16, u64, ChannelFeatures);
/// The default `features` we assume for a node in a route, when no `features` are known about that
/// specific node.
///
/// Default features are:
/// * variable_length_onion_optional
fn default_node_features() -> NodeFeatures {
	let mut features = NodeFeatures::empty();
	features.set_variable_length_onion_optional();
	features
}

/// Finds a min cost flow route from our node to the target node given in route params using the given scorer for
/// getting information about liquidity.
///
/// For the algorithm to work it's critical that the scorer updates liquidity
/// between payment attempts.
pub fn find_route<L: Deref, GL: Deref, S: Score>(
	our_node_pubkey: &PublicKey, route_params: &RouteParameters,
	network_graph: &NetworkGraph<GL>, first_hops: Option<&[&ChannelDetails]>, logger: L,
	scorer: &S, random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError>
where L::Target: Logger, GL::Target: Logger {
	let graph_lock = network_graph.read_only();
	let mut route = get_route(our_node_pubkey, &route_params.payment_params, &graph_lock, first_hops,
		route_params.final_value_msat, route_params.final_cltv_expiry_delta, logger, scorer,
		random_seed_bytes)?;
	add_random_cltv_offset(&mut route, &route_params.payment_params, &graph_lock, random_seed_bytes);
	Ok(route)
}

/// Add to value_msat for relative fees. 10 is 1 percent additional value requested for fees.
const VALUE_MSAT_FEE_MILLIS:u32=10;


/// Finds a min cost flow route from our node to the target node with target msat value using the given scorer for
/// getting information about liquidity.
///
/// For the algorithm to work it's critical that the scorer updates liquidity
/// between payment attempts.
pub(crate) fn get_route<L: Deref, S: Score>(
	our_node_pubkey: &PublicKey, payment_params: &PaymentParameters, network_graph: &ReadOnlyNetworkGraph,
	first_hops: Option<&[&ChannelDetails]>, final_value_msat: u64, final_cltv_expiry_delta: u32,
	logger: L, scorer: &S, _random_seed_bytes: &[u8; 32]
) -> Result<Route, LightningError>
where L::Target: Logger {
	let payee_pubkey=payment_params.payee_pubkey;
	let liquidity_estimator = scorer;

	// Basic checks are the same as with the Dijstra routing algorithm.
	let our_node_id=NodeId::from_pubkey(&our_node_pubkey);
	println!("our node pubkey: {}", our_node_pubkey);
	println!("first hops: {:#?}", first_hops);
	println!("last hops(route hints): {:#?}", payment_params.route_hints);

	let payee_node_id=NodeId::from_pubkey(&payee_pubkey);
	let value_msat=final_value_msat;
	let final_value_msat=value_msat;
	if payee_node_id == our_node_id {
		return Err(LightningError{err: "Cannot generate a route to ourselves".to_owned(), action: ErrorAction::IgnoreError});
	}

	if final_value_msat > MAX_VALUE_MSAT {
		return Err(LightningError{err: "Cannot generate a route of more value than all existing satoshis".to_owned(), action: ErrorAction::IgnoreError});
	}

	if final_value_msat == 0 {
		return Err(LightningError{err: "Cannot send a payment of 0 msat".to_owned(), action: ErrorAction::IgnoreError});
	}

	if payment_params.max_total_cltv_expiry_delta <= final_cltv_expiry_delta {
		return Err(LightningError{err: "Can't find a route where the maximum total CLTV expiry delta is below the final CLTV expiry.".to_owned(), action: ErrorAction::IgnoreError});
	}
	if payment_params.max_path_count == 0 {
		return Err(LightningError{err: "Can't find a route with no paths allowed.".to_owned(), action: ErrorAction::IgnoreError});
	}

	log_trace!(logger, "Searching for a Pickhardt type route from payer {} to payee {} with MPP and {} first hops {}overriding the network graph", our_node_pubkey,
		payment_params.payee_pubkey,
		first_hops.map(|hops| hops.len()).unwrap_or(0), if first_hops.is_some() { "" } else { "not " });

	let mut edges:Vec<OriginalEdge> =Vec::new();  // enumerated channels.
	let mut vidx:HashMap<NodeId,usize> =HashMap::new();  // NodeId -> enumerated node id
	let mut nodes:Vec<(NodeId,NodeFeatures)>=Vec::new();  // enumerated node id -> NodeId
	// enumerated channel -> short channel id, ctlv_expiry_delta, htlc_minimum_msat
	let mut channel_meta_data:Vec<ChannelMetaData>=Vec::new();
	let mut short_channel_ids_set:HashSet<(u64, bool)>=HashSet::new();  // set of short channel ids
	let our_node=NodeId::from_pubkey(&our_node_pubkey);
	let s=add_or_get_node(&mut vidx, our_node, &default_node_features(), &mut nodes);
	if s != 0 {
		return Err(LightningError{err: "Source node must have index 0".to_owned(),
				action: ErrorAction::IgnoreError});
	}
	if let Some(lightning_error) =
			extract_first_hops_from_payer_node(&mut channel_meta_data, &mut short_channel_ids_set,
				first_hops, our_node_pubkey, &mut vidx, &mut nodes, &mut edges, liquidity_estimator) {
		return Err(lightning_error);
	}

	extract_public_channels_from_network_graph(network_graph, &mut channel_meta_data, &mut short_channel_ids_set,
		 &mut vidx, &mut nodes, &mut edges, liquidity_estimator, first_hops.is_some());

	if let Some(value) = add_hops_to_payee_node_from_route_hints(
		&mut channel_meta_data, &mut short_channel_ids_set,
		payment_params, payee_node_id, &mut edges, &mut vidx, &mut nodes, liquidity_estimator) {
		return value;
	}

	let payee_node=NodeId::from_pubkey(&payee_pubkey);
	let t=match vidx.get(&payee_node) {
		Some(t) => *t,
		None => return Err(LightningError{err: "No last node found".to_owned(), action: ErrorAction::IgnoreError})
	};
	let mut value_sat=((value_msat as u128*(1000+VALUE_MSAT_FEE_MILLIS) as u128+999999) / (1000000 as u128)) as u64;

	if value_sat > i32::MAX as u64 {
		value_sat = i32::MAX as u64;
	}
	let value_sat = if value_sat > i32::MAX as u64 { i32::MAX } else { value_sat as i32 };
	min_cost_flow_lib::min_cost_flow(nodes.len(), s, t, value_sat,
		100000000, &mut edges,
		10);
	// Build paths from min cost flow;
	println!("Building paths from flow, edges:{:#?}, s={s}, t={t}", edges);
	let paths = flow_to_paths( &edges, s, t, nodes.len());
	println!("paths: {:#?}", paths);
	let sum_paths=paths.iter().map(|x| x.0 as u64).sum::<u64>();
	if paths.len() == 0 {
		return Err(LightningError{err: "Failed to find a path to the given destination".to_owned(), action: ErrorAction::IgnoreError});
	}
	// if sum_paths < value_sat as u64 {
	// 	println!("Error: sum_paths: {} < value_sat: {}", sum_paths, value_sat);
	// 	return Err(LightningError{err: "Failed to find a sufficient route to the given destination".to_owned(),
	// 	action: ErrorAction::IgnoreError});
	// }
	// Converts paths to hops.
	let route_paths = build_route_paths(paths, &channel_meta_data, &nodes, edges,
		value_msat, final_cltv_expiry_delta);
	if route_paths.len() > 1 && !should_allow_mpp(payment_params, network_graph, payee_node_id) {
		return Err(LightningError{err: "Payee node doesn't support MPP.".to_owned(),
			action: ErrorAction::IgnoreError});
	}
	let sum_route_paths = route_paths.iter().map(|x| x.last().unwrap().fee_msat).sum::<u64>();
	if sum_route_paths == 0 {
		return Err(LightningError{err: "Failed to find a path to the given destination".to_owned(),
			action: ErrorAction::IgnoreError});
	}
	if sum_route_paths < value_msat {
		println!("Error: sum_route_paths: {} < value_msat: {}", sum_route_paths, value_msat);
		return Err(LightningError{err: "Failed to find a sufficient route to the given destination".to_owned(),
			action: ErrorAction::IgnoreError});
	}
	let max_total_cltv = route_paths.iter().map(
			|x| x.iter().map(
					|y| y.cltv_expiry_delta).sum()).max().unwrap();
	if payment_params.max_total_cltv_expiry_delta < max_total_cltv {
		return Err(LightningError{err: "Failed to find a path to the given destination".to_owned(),
		action: ErrorAction::IgnoreError});
	}
	let r=Route {paths: route_paths, payment_params: Some(payment_params.clone()) };
	return Ok(r);
}

/// Creates a routes accounting for fees from given paths.
///
/// While creating the routes, the function
/// accounts for fees taken by nodes in the path (which is not yet done by the min cost flow finding algorithm).
///
/// Also it converts i32 sat flow values back to u64 msat
fn build_route_paths(paths: Vec<(u32, Vec<usize>)>, channel_meta_data: &Vec<ChannelMetaData>,
	nodes: &Vec<(NodeId, NodeFeatures)>, edges: Vec<OriginalEdge>, value_msat: u64,
	final_cltv_expiry_delta: u32) -> Vec<Vec<RouteHop>> {
    let mut route_paths:Vec<Vec<RouteHop>>=Vec::new();
	let mut total_msat = 0;
    for path in paths {
		    let mut route_path:Vec<RouteHop>=Vec::new();
			if path.1.is_empty() {
				continue;
			}
			let mut available_msat=path.0 as u64*1000;
			let mut requires_unknown_bits=false;
		    for i in 0..path.1.len() {
				let idx=&path.1[i];
			    let md=&channel_meta_data[*idx];
			    let short_channel_id=md.0;
			    let vnode=&nodes[edges[*idx].v];
			    let node_features=&vnode.1;
				if node_features.requires_unknown_bits() {
					requires_unknown_bits=true;
					break;
				}
			    let channel_features=&md.3;
				let is_last_hop=*idx==*path.1.last().unwrap();
			    let fee_msat=if is_last_hop { available_msat }
								    else {
										let cost=edges[path.1[i+1]].cost;
										available_msat*cost as u64/(1000000+cost) as u64};
				available_msat -= fee_msat;
			    let cltv_expiry_delta= if is_last_hop {final_cltv_expiry_delta}
											else {channel_meta_data[path.1[i+1]].1 as u32};

			    route_path.push(RouteHop {
				    pubkey: PublicKey::from_slice(vnode.0.as_slice()).unwrap(),
				    short_channel_id: short_channel_id,
				    fee_msat : fee_msat,
				    cltv_expiry_delta : cltv_expiry_delta,
				    node_features: node_features.clone(),
			    channel_features: channel_features.clone()});
		    }
			if requires_unknown_bits {
				continue;
			}
			if total_msat + route_path.last().unwrap().fee_msat > value_msat {
				// Decrease value going through route path.
				let mut value_to_route_msat=value_msat-total_msat;
				route_path.last_mut().unwrap().fee_msat=value_to_route_msat;
				for i in (0..(route_path.len()-1)).rev() {
					let hop=&mut route_path[i];
					let edge=&edges[path.1[i+1]];
					let fee_per_million_msat=edge.cost as u64;
					hop.fee_msat=value_to_route_msat*fee_per_million_msat/1000000;
					value_to_route_msat+=hop.fee_msat;
				}
			}
			total_msat += route_path.last().unwrap().fee_msat;
		    route_paths.push(route_path);
			if total_msat == value_msat {
				break;
			}
	    };
    route_paths
}

fn add_hops_to_payee_node_from_route_hints<S:Score>(channel_meta_data: &mut Vec<ChannelMetaData>,
	short_channel_ids_set: &mut HashSet<(u64, bool)>,
	payment_params: &PaymentParameters,
	payee_node_id: NodeId, edges: &mut Vec<OriginalEdge>, vidx: &mut HashMap<NodeId, usize>,
	nodes: &mut Vec<(NodeId,NodeFeatures)>, liquidity_estimator: &S) ->
		 Option<Result<Route, LightningError>> {
	for route in payment_params.route_hints.iter() {
			let mut last_node_id=payee_node_id;
			for hop in route.0.iter().rev() {
				let src_node_id=NodeId::from_pubkey(&hop.src_node_id);
				if src_node_id == payee_node_id {
					return Some(Err(LightningError{err: "Route hint cannot have the payee as the source.".to_owned(), action: ErrorAction::IgnoreError}));
				}
				let mut guaranteed_liquidity=0;   // TODO: Ask whether the liquidity for the last hop is guaranteed by default.
				// BOLT 11 doesn't specify channel capacity :(
				let mut capacity=hop.htlc_maximum_msat.unwrap_or(MAX_VALUE_MSAT);
				if let Some(liquidity_range) = liquidity_estimator.estimated_channel_liquidity_range(
					hop.short_channel_id, &last_node_id) {
						guaranteed_liquidity=liquidity_range.0;
						capacity=liquidity_range.1;
				}
				let u=add_or_get_node(vidx, src_node_id, &default_node_features(), nodes);
				let v=add_or_get_node(vidx, last_node_id, &default_node_features(), nodes);

				add_channel(hop.short_channel_id, edges, u, v, capacity, hop.fees.proportional_millionths as i32,
					guaranteed_liquidity, channel_meta_data,
					hop.cltv_expiry_delta, hop.htlc_minimum_msat.unwrap_or(0),
					ChannelFeatures::empty(), short_channel_ids_set, hop.fees.base_msat);

				last_node_id=src_node_id;
			}
		}
	None
}

fn u64_msat_to_i32_sat(msat: u64) -> i32 {
	if msat / 1000 > i32::MAX as u64 {
		return i32::MAX
	} else {
		return (msat / 1000) as i32
	}
}

fn add_channel(short_channel_id: u64, edges: &mut Vec<OriginalEdge>, u: usize, v: usize, capacity_msat: u64,
	fee_proportional_millionths: i32, guaranteed_liquidity_msat: u64, channel_meta_data: &mut Vec<ChannelMetaData>,  cltv_expiry_delta: u16, htlc_minimum_msat: u64,
	channel_features: ChannelFeatures, short_channel_ids_set: &mut HashSet<(u64, bool)>, base_msat: u32) {
	let direction = u <= v;

    if short_channel_ids_set.contains(&(short_channel_id, direction)) {
		return;
	}
	let mut fee_proportional_millionths=fee_proportional_millionths;
	let mut guaranteed_liquidity_msat=guaranteed_liquidity_msat;
	// Source node doesn't have fees to pay to itself.
	if u==0 {
		fee_proportional_millionths=0;
		guaranteed_liquidity_msat=capacity_msat;
	} else  {
		if base_msat > 0 {
			return;
		}
		if htlc_minimum_msat > 1000 {
			return;
		}
	}
	edges.push(OriginalEdge {
					    u: u,
					    v: v,
					    capacity: u64_msat_to_i32_sat(capacity_msat),
					    cost: fee_proportional_millionths,
					    flow: 0,
					    guaranteed_liquidity: u64_msat_to_i32_sat(guaranteed_liquidity_msat)});
    channel_meta_data.push((short_channel_id, cltv_expiry_delta, htlc_minimum_msat,
					    channel_features));
    short_channel_ids_set.insert((short_channel_id, direction));
}

fn extract_first_hops_from_payer_node<S:Score>(channel_meta_data: &mut Vec<ChannelMetaData>,
	short_channel_ids_set: &mut HashSet<(u64, bool)>, first_hops: Option<&[&ChannelDetails]>,
	our_node_pubkey: &PublicKey,
	 vidx: &mut HashMap<NodeId, usize>, nodes: &mut Vec<(NodeId, NodeFeatures)>,
	edges: &mut Vec<OriginalEdge>, liquidity_estimator: &S) -> Option<LightningError> {
	if first_hops.is_none() {
		return None;  // No first hops provided, it's not a problem for public node.
	}
	let hops=first_hops.unwrap();
	for chan in hops {
		if !chan.is_channel_ready || !chan.is_usable {
			continue;;
		}
		if chan.get_outbound_payment_scid().is_none() {
			panic!("first_hops should be filled in with usable channels, not pending ones");
		}
		let scid=chan.get_outbound_payment_scid().unwrap();
		if chan.counterparty.node_id == *our_node_pubkey {
			return Some(LightningError{
				err: "First hop cannot have our_node_pubkey as a destination.".to_owned(),
				action: ErrorAction::IgnoreError});
		}
		let other_node_id=NodeId::from_pubkey(&chan.counterparty.node_id);
		let other_node_idx= add_or_get_node(vidx,
				other_node_id,
				&chan.counterparty.features.to_context(),
				 nodes);
		let mut guaranteed_liquidity=chan.outbound_capacity_msat;
		let mut capacity=chan.outbound_capacity_msat;
		if let Some(liquidity_range) = liquidity_estimator.estimated_channel_liquidity_range(
				scid, &other_node_id) {
				guaranteed_liquidity=liquidity_range.0;
				capacity=liquidity_range.1;
		}
		let cltv_expiry_delta=if let Some(conf) = chan.config {conf.cltv_expiry_delta} else {0};
		add_channel(scid, edges, 0, other_node_idx, capacity,
			 0, guaranteed_liquidity,
			 channel_meta_data, cltv_expiry_delta, 0, chan.counterparty.features.to_context(),
			 short_channel_ids_set, 0);
	}
	None
}

fn should_allow_mpp(payment_params: &PaymentParameters,
	locked_network_graph: &ReadOnlyNetworkGraph, payee_node_id: NodeId) -> bool
	  {
	// Allow MPP only if we have a features set from somewhere that indicates the payee supports
	// it. If the payee supports it they're supposed to include it in the invoice, so that should
	// work reliably.
	let allow_mpp = if payment_params.max_path_count == 1 {
			false
		} else if let Some(features) = &payment_params.features {
			features.supports_basic_mpp()
		} else if let Some(node) = locked_network_graph.nodes().get(&payee_node_id) {
			if let Some(node_info) = node.announcement_info.as_ref() {
				node_info.features.supports_basic_mpp()
			} else { false }
		} else { false };
	allow_mpp
}

fn extract_public_channels_from_network_graph<S:Score>(
	locked_network_graph : &ReadOnlyNetworkGraph, channel_meta_data: &mut Vec<ChannelMetaData>, short_channel_ids_set: &mut HashSet<(u64, bool)>,
	 vidx: &mut HashMap<NodeId, usize>, nodes: &mut Vec<(NodeId,NodeFeatures)>, edges: &mut Vec<OriginalEdge>,
	liquidity_estimator: &S, first_hops_extracted: bool)   {
	for channel in locked_network_graph.channels() {
			let info=channel.1;
			if info.features.requires_unknown_bits() {
				continue;
			}
			let mut node_features=default_node_features();
			if let Some(unode)=locked_network_graph.node(&info.node_one) {
				if let Some(ai)=&unode.announcement_info {
					node_features=ai.features.clone();
				}
			}
			let u = add_or_get_node(vidx, info.node_one, &node_features, nodes);

			let mut node_features=default_node_features();
			if let Some(unode)=locked_network_graph.node(&info.node_two) {
				if let Some(ai)=&unode.announcement_info {
					node_features=ai.features.clone();
				}
			}
			let v = add_or_get_node(vidx, info.node_two, &node_features, nodes);
			if first_hops_extracted && (u==0 || v==0) {
				continue;
			}
			println!("creating channels from network graph: u:{}, v:{}, info:{:#?}", u, v, info);
			if let Some(ot)=&info.one_to_two {
				let mut guaranteed_liquidity=0;
				let mut capacity=ot.htlc_maximum_msat;
				if let Some(liquidity_range) = liquidity_estimator.estimated_channel_liquidity_range(
					*channel.0, &info.node_two) {
						guaranteed_liquidity=liquidity_range.0;
						capacity=liquidity_range.1;
				}

				if ot.enabled {
					add_channel(*channel.0, edges, u, v, capacity,
						ot.fees.proportional_millionths as i32, guaranteed_liquidity,
						channel_meta_data, ot.cltv_expiry_delta, ot.htlc_minimum_msat, info.features.clone(),
						short_channel_ids_set, ot.fees.base_msat);
				}
			}
			if let Some(to)=&info.two_to_one {
				let mut guaranteed_liquidity=0;
				let mut capacity=to.htlc_maximum_msat;
				if let Some(liquidity_range) = liquidity_estimator.estimated_channel_liquidity_range(
					*channel.0, &info.node_one) {
						guaranteed_liquidity=liquidity_range.0;
						capacity=liquidity_range.1;
				}
				if to.enabled {
					add_channel(*channel.0, edges, v, u, capacity,
						to.fees.proportional_millionths as i32, guaranteed_liquidity,
						channel_meta_data, to.cltv_expiry_delta, to.htlc_minimum_msat, info.features.clone(),
						short_channel_ids_set, to.fees.base_msat);
				}
			}
		}
}

fn add_or_get_node(vidx: &mut HashMap<NodeId, usize>, other_node: NodeId,
	node_features: &NodeFeatures, nodes: &mut Vec<(NodeId, NodeFeatures)>) -> usize {
	*vidx.entry(other_node).or_insert_with(|| {
		let r=nodes.len();
		nodes.push((other_node, node_features.clone()));
		r
	})
}

fn flow_to_paths(edges: &Vec<OriginalEdge>, s: usize, t: usize, n : usize)
			 -> Vec<(u32, Vec<usize>)> {
	let mut new_edges=edges.clone();
	let mut edges_from:Vec<Vec<usize>> =Vec::new();
	for _ in 0..n { edges_from.push(Vec::new())};
	for edge_idx in 0..edges.len() {
			edges_from[edges[edge_idx].u].push(edge_idx);
		}
	println!("edges from = {:#?}", edges_from);
	let mut paths:Vec<(u32, Vec<usize>)>=Vec::new();
	loop {
			let mut parent=vec![n; n];
			let mut parent_edge_idx=vec![None; n];
			let mut capacity=vec![0; n];
			let mut to_see=Vec::new();
			to_see.push(s);
			while !to_see.is_empty() {
				let u=to_see.pop().unwrap();
				for edge_idx in &edges_from[u] {
					let edge=&new_edges[*edge_idx];
					if edge.flow > 0 && edge.v != s && parent[edge.v] == n {
						parent[edge.v]=u;
						parent_edge_idx[edge.v]=Some(edge_idx);
						capacity[edge.v]=edge.flow.try_into().unwrap();
						if edge.v==t {
							to_see.clear();
							break;
						}
						to_see.push(edge.v);
					}
				}
			}
			if parent[t] == n {
				break;
			}
			let mut u=t;
			let mut path:Vec<usize>=Vec::new();
			let mut c=capacity[t];
			while u!=s {
				let edge_idx=*parent_edge_idx[u].unwrap();
				path.push(edge_idx);
				if capacity[u] < c { c=capacity[u]};
				u=parent[u];
			}
			// Remove part of flow
			let mut u=t;
			while u!=s {
				let edge_idx=*parent_edge_idx[u].unwrap();
				new_edges[edge_idx].flow-=c;
				u=parent[u];
			}

			path.reverse();
			paths.push((c as u32, path));
			println!("added path to paths, c={c}");
		}
	paths
}



#[cfg(test)]
mod tests {
	use routing::gossip::{NetworkGraph, P2PGossipSync, NodeId, EffectiveCapacity};
	use routing::router::{
		PaymentParameters, Route, RouteHint, RouteHintHop, RouteHop,
		DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA};
	use routing::scoring::{ChannelUsage, Score, ProbabilisticScorer, ProbabilisticScoringParameters};
	use chain::transaction::OutPoint;
	use chain::keysinterface::KeysInterface;
	use ln::features::{ChannelFeatures, InitFeatures, InvoiceFeatures, NodeFeatures};
	use ln::msgs::{ErrorAction, LightningError, UnsignedChannelAnnouncement, ChannelAnnouncement, RoutingMessageHandler,
		NodeAnnouncement, UnsignedNodeAnnouncement, ChannelUpdate, UnsignedChannelUpdate, MAX_VALUE_MSAT};
	use ln::channelmanager;
	use util::test_utils;
	use util::chacha20::ChaCha20;
	use util::ser::Writeable;
	#[cfg(c_bindings)]
	use util::ser::Writer;

	use bitcoin::hashes::sha256d::Hash as Sha256dHash;
	use bitcoin::hashes::Hash;
	use bitcoin::network::constants::Network;
	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::blockdata::script::Builder;
	use bitcoin::blockdata::opcodes;
	use bitcoin::blockdata::transaction::TxOut;

	use hex;

	use bitcoin::secp256k1::{PublicKey,SecretKey};
	use bitcoin::secp256k1::{Secp256k1, All};

	use prelude::*;
	use sync::{self, Arc};

	use core::convert::TryInto;

	/// Creates a channelmanager::ChannelDetails data structure with given channel id from own node
	/// to given node with given features and capacity.
	fn get_channel_details(short_channel_id: Option<u64>, node_id: PublicKey,
			features: InitFeatures, outbound_capacity_msat: u64) -> channelmanager::ChannelDetails {
		channelmanager::ChannelDetails {
			channel_id: [0; 32],
			counterparty: channelmanager::ChannelCounterparty {
				features,
				node_id,
				unspendable_punishment_reserve: 0,
				forwarding_info: None,
				outbound_htlc_minimum_msat: None,
				outbound_htlc_maximum_msat: None,
			},
			funding_txo: Some(OutPoint { txid: bitcoin::Txid::from_slice(&[0; 32]).unwrap(), index: 0 }),
			channel_type: None,
			short_channel_id,
			outbound_scid_alias: None,
			inbound_scid_alias: None,
			channel_value_satoshis: 0,
			user_channel_id: 0,
			balance_msat: 0,
			outbound_capacity_msat,
			next_outbound_htlc_limit_msat: outbound_capacity_msat,
			inbound_capacity_msat: 42,
			unspendable_punishment_reserve: None,
			confirmations_required: None,
			force_close_spend_delay: None,
			is_outbound: true, is_channel_ready: true,
			is_usable: true, is_public: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
			config: None,
		}
	}

	/// Creates network channel using P2P gossip sync channel announcement interface.
	///
	/// This sets features, but not capacity.
	///
	/// Using the same keys for LN and BTC ids
	fn add_channel(
		gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
		secp_ctx: &Secp256k1<All>, node_1_privkey: &SecretKey, node_2_privkey: &SecretKey, features: ChannelFeatures, short_channel_id: u64
	) {
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
			node_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_privkey),
			node_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_privkey),
			bitcoin_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_privkey),
			bitcoin_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_privkey),
			contents: unsigned_announcement.clone(),
		};
		match gossip_sync.handle_channel_announcement(&valid_announcement) {
			Ok(res) => assert!(res),
			_ => panic!()
		};
	}

	/// Updates channel data using P2P gossip sync interface in 1 direction.
	///
	/// It can be used to set channel capacity and fee.
	fn update_channel(
		gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
		secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, update: UnsignedChannelUpdate
	) {
		let msghash = hash_to_message!(&Sha256dHash::hash(&update.encode()[..])[..]);
		let valid_channel_update = ChannelUpdate {
			signature: secp_ctx.sign_ecdsa(&msghash, node_privkey),
			contents: update.clone()
		};

		match gossip_sync.handle_channel_update(&valid_channel_update) {
			Ok(res) => assert!(res),
			Err(_) => panic!()
		};
	}

	/// Creates node or updates node features using P2P gossip sync interface
	fn add_or_update_node(
		gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
		secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, features: NodeFeatures, timestamp: u32
	) {
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
			signature: secp_ctx.sign_ecdsa(&msghash, node_privkey),
			contents: unsigned_announcement.clone()
		};

		match gossip_sync.handle_node_announcement(&valid_announcement) {
			Ok(_) => (),
			Err(_) => panic!()
		};
	}

	/// Gets 22 node private/public key pairs (node 1 is our node)
	fn get_nodes(secp_ctx: &Secp256k1<All>) -> (SecretKey, PublicKey, Vec<SecretKey>, Vec<PublicKey>) {
		let privkeys: Vec<SecretKey> = (2..22).map(|i| {
			SecretKey::from_slice(&hex::decode(format!("{:02x}", i).repeat(32)).unwrap()[..]).unwrap()
		}).collect();

		let pubkeys = privkeys.iter().map(|secret| PublicKey::from_secret_key(&secp_ctx, secret)).collect();

		let our_privkey = SecretKey::from_slice(&hex::decode("01".repeat(32)).unwrap()[..]).unwrap();
		let our_id = PublicKey::from_secret_key(&secp_ctx, &our_privkey);

		(our_privkey, our_id, privkeys, pubkeys)
	}

	/// Used strangely in the tests I think...
	/// Set the feature flags to the id'th odd (ie non-required) feature bit so that we can
	/// test for it later.
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

	/// Builds a line of nodes from our node to the last node (node 22 or node 19???) with infinite capacity and 0 fee.
	fn build_line_graph() -> (
		Secp256k1<All>, sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
		P2PGossipSync<sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>>,
		sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>,
	) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let chain_monitor = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let network_graph = Arc::new(NetworkGraph::new(genesis_hash, Arc::clone(&logger)));
		let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger));

		// Build network from our_id to node 19:
		// our_id -1(1)2- node0 -1(2)2- node1 - ... - node19
		let (our_privkey, _, privkeys, _) = get_nodes(&secp_ctx);

		for (idx, (cur_privkey, next_privkey)) in core::iter::once(&our_privkey)
			.chain(privkeys.iter()).zip(privkeys.iter()).enumerate() {
			let cur_short_channel_id = (idx as u64) + 1;
			add_channel(&gossip_sync, &secp_ctx, &cur_privkey, &next_privkey,
				ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), cur_short_channel_id);
			update_channel(&gossip_sync, &secp_ctx, &cur_privkey, UnsignedChannelUpdate {
				chain_hash: genesis_block(Network::Testnet).header.block_hash(),
				short_channel_id: cur_short_channel_id,
				timestamp: idx as u32,
				flags: 0,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
			update_channel(&gossip_sync, &secp_ctx, &next_privkey, UnsignedChannelUpdate {
				chain_hash: genesis_block(Network::Testnet).header.block_hash(),
				short_channel_id: cur_short_channel_id,
				timestamp: (idx as u32)+1,
				flags: 1,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
			add_or_update_node(&gossip_sync, &secp_ctx, next_privkey,
				NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);
		}

		(secp_ctx, network_graph, gossip_sync, chain_monitor, logger)
	}

	fn build_graph() -> (
		Secp256k1<All>,
		sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
		P2PGossipSync<sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>>,
		sync::Arc<test_utils::TestChainSource>,
		sync::Arc<test_utils::TestLogger>,
	) {
		let secp_ctx = Secp256k1::new();
		let logger = Arc::new(test_utils::TestLogger::new());
		let chain_monitor = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let network_graph = Arc::new(NetworkGraph::new(genesis_hash, Arc::clone(&logger)));
		let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger));
		// Build network from our_id to node6:
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
		// chan3  2-to-1: enabled, 100 msat fee -> 50% (no base fee support)
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
		// Channels 5, 8, 9 and 10 are private channels.
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

		add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[0], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[0], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

		add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 3,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

		add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[7], ChannelFeatures::from_le_bytes(id_to_feature_flags(12)), 12);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 3,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[7], NodeFeatures::from_le_bytes(id_to_feature_flags(8)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (3 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 500000,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[1], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (4 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[7], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(13)), 13);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 2000000,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (13 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (6 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (6 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new(),
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(11)), 11);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (11 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (11 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(5)), 0);

		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[5], ChannelFeatures::from_le_bytes(id_to_feature_flags(7)), 7);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (7 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[5], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (7 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[5], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

		(secp_ctx, network_graph, gossip_sync, chain_monitor, logger)
	}
	fn set_mpp(payment_parameters : PaymentParameters) -> PaymentParameters {
		payment_parameters.with_features(InvoiceFeatures::known())
	}
	#[test]
	fn simple_route_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known()); // Set MPP
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 0, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "Cannot send a payment of 0 msat");
		} else { panic!(); }

		println!("calling with network graph {:#?}", network_graph.read_only().channels());

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
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
	fn invalid_first_hop_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		let our_chans = vec![get_channel_details(Some(2), our_id, InitFeatures::from_le_bytes(vec![0b11]), 100000)];

		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) =
			get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "First hop cannot have our_node_pubkey as a destination.");
		} else { panic!(); }

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);
	}

	// #[test]  // HTLC minimum not supported
	fn htlc_minimum_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple route to 2 via 1

		// Disable other paths
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Check against amount_to_transfer_over_msat.
		// Set minimal HTLC of 200_000_000 msat.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 200_000_000,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Second hop only allows to forward 199_999_999 at most, thus not allowing the first hop to
		// be used.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 199_999_999,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Not possible to send 199_999_999, because the minimum on channel=2 is 200_000_000.
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 199_999_999, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// Lift the restriction on the first hop.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// A payment above the minimum should pass
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 199_999_999, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);
	}

	// #[test]
	fn htlc_minimum_overpay_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// A route to node#2 via two paths.
		// One path allows transferring 35-40 sats, another one also allows 35-40 sats.
		// Thus, they can't send 60 without overpaying.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 35_000,
			htlc_maximum_msat: 40_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 35_000,
			htlc_maximum_msat: 40_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Make 0 fee.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Disable other paths
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 3,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 60_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		// Overpay fees to hit htlc_minimum_msat.
		let overpaid_fees = route.paths[0][0].fee_msat + route.paths[1][0].fee_msat;
		// TODO: this could be better balanced to overpay 10k and not 15k.
		assert_eq!(overpaid_fees, 15_000);

		// Now, test that if there are 2 paths, a "cheaper" by fee path wouldn't be prioritized
		// while taking even more fee to match htlc_minimum_msat.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 65_000,
			htlc_maximum_msat: 80_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 100_000,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 60_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		// Fine to overpay for htlc_minimum_msat if it allows us to save fee.
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0][0].short_channel_id, 12);
		let fees = route.paths[0][0].fee_msat;
		assert_eq!(fees, 5_000);

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		// Not fine to overpay for htlc_minimum_msat if it requires paying more than fee on
		// the other channel.
		assert_eq!(route.paths.len(), 1);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		let fees = route.paths[0][0].fee_msat;
		assert_eq!(fees, 5_000);
	}

	#[test]
	fn disable_channels_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// // Disable channels 4 and 12 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// If all the channels require some features we don't understand, route should fail
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
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
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Disable nodes 1, 2, and 8 by requiring unknown feature bits
		let mut unknown_features = NodeFeatures::known();
		unknown_features.set_unknown_feature_required();
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[0], unknown_features.clone(), 1);
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], unknown_features.clone(), 1);
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[7], unknown_features.clone(), 1);

		// If all nodes require some features we don't understand, route should fail
		if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
			assert_eq!(err, "Failed to find a path to the given destination");
		} else { panic!(); }

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
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
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Route to 1 via 2 and 3 because our channel to 1 is disabled
		let payment_params = PaymentParameters::from_node_id(nodes[0]);
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 3);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 150); // 100% of 150 instead of 200
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 50);  // instead of 100 (50% of 100)
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (3 << 4) | 2);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[0]);
		assert_eq!(route.paths[0][2].short_channel_id, 3);
		assert_eq!(route.paths[0][2].fee_msat, 100);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(1));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(3));

		// If we specify a channel to node7, that overrides our local channel view and that gets used
		let payment_params = PaymentParameters::from_node_id(nodes[2]);
		let our_chans = vec![get_channel_details(Some(42), nodes[7].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[7]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
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
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[3],
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}
		]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[4],
			short_channel_id: 9,
			fees: RoutingFees {
				base_msat: 1001,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (9 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[5],
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	fn last_hops_multi_private_channels(nodes: &Vec<PublicKey>) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[2],
			short_channel_id: 5,
			fees: RoutingFees {
				base_msat: 100,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (5 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}, RouteHintHop {
			src_node_id: nodes[3],
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}
		]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[4],
			short_channel_id: 9,
			fees: RoutingFees {
				base_msat: 1001,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (9 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[5],
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	#[test]
	fn partial_route_hint_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple test across 2, 3, 5, and 4 via a last_hop channel
		// Tests the behaviour when the RouteHint contains a suboptimal hop.
		// RouteHint may be partially used by the algo to build the best path.

		// First check that last hop can't have its source as the payee.
		let invalid_last_hop = RouteHint(vec![RouteHintHop {
			src_node_id: nodes[6],
			short_channel_id: 8,
			fees: RoutingFees {
				base_msat: 1000,
				proportional_millionths: 0,
			},
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]);

		let mut invalid_last_hops = last_hops_multi_private_channels(&nodes);
		invalid_last_hops.push(invalid_last_hop);
		{
			let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(invalid_last_hops);
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Route hint cannot have the payee as the source.");
			} else { panic!(); }
		}

		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops_multi_private_channels(&nodes));
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 0);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 100);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	fn empty_last_hop(nodes: &Vec<PublicKey>) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[3],
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![

		]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[5],
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	#[test]
	fn ignores_empty_last_hops_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(empty_last_hop(&nodes));
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Test handling of an empty RouteHint passed in Invoice.

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 0);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 100);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	/// Builds a trivial last-hop hint that passes through the two nodes given, with channel 0xff00
	/// and 0xff01.
	fn multi_hop_last_hops_hint(hint_hops: [PublicKey; 2]) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: hint_hops[0],
			short_channel_id: 0xff00,
			fees: RoutingFees {
				base_msat: 0,  // was 100
				proportional_millionths: 1000000,  // was 0
			},
			cltv_expiry_delta: (5 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}, RouteHintHop {
			src_node_id: hint_hops[1],
			short_channel_id: 0xff01,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	#[test]
	fn multi_hint_last_hops_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let last_hops = multi_hop_last_hops_hint([nodes[2], nodes[3]]);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops.clone());
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		// Test through channels 2, 3, 0xff00, 0xff01.
		// Test shows that multiple hop hints are considered.

		// Disabling channels 6 & 7 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 4);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, 65);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 81);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[3]);
		assert_eq!(route.paths[0][2].short_channel_id, last_hops[0].0[0].short_channel_id);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, 129);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0][3].pubkey, nodes[6]);
		assert_eq!(route.paths[0][3].short_channel_id, last_hops[0].0[1].short_channel_id);
		assert_eq!(route.paths[0][3].fee_msat, 100);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[test]
	fn private_multi_hint_last_hops_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);

		let non_announced_privkey = SecretKey::from_slice(&hex::decode(format!("{:02x}", 0xf0).repeat(32)).unwrap()[..]).unwrap();
		let non_announced_pubkey = PublicKey::from_secret_key(&secp_ctx, &non_announced_privkey);

		let last_hops = multi_hop_last_hops_hint([nodes[2], non_announced_pubkey]);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops.clone());
		let scorer = test_utils::TestScorer::with_penalty(0);
		// Test through channels 2, 3, 0xff00, 0xff01.
		// Test shows that multiple hop hints are considered.

		// Disabling channels 6 & 7 by flags=2
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2, // to disable
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &[42u8; 32]).unwrap();
		assert_eq!(route.paths[0].len(), 4);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, 65);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 81);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, non_announced_pubkey);
		assert_eq!(route.paths[0][2].short_channel_id, last_hops[0].0[0].short_channel_id);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, 129);
		assert_eq!(route.paths[0][2].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0][3].pubkey, nodes[6]);
		assert_eq!(route.paths[0][3].short_channel_id, last_hops[0].0[1].short_channel_id);
		assert_eq!(route.paths[0][3].fee_msat, 100);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	fn last_hops_with_public_channel(nodes: &Vec<PublicKey>) -> Vec<RouteHint> {
		let zero_fees = RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		};
		vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[4],
			short_channel_id: 11,
			fees: zero_fees,
			cltv_expiry_delta: (11 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}, RouteHintHop {
			src_node_id: nodes[3],
			short_channel_id: 8,
			fees: zero_fees,
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[4],
			short_channel_id: 9,
			fees: RoutingFees {
				base_msat: 0,  // was 1001
				proportional_millionths: 10010000,
			},
			cltv_expiry_delta: (9 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]), RouteHint(vec![RouteHintHop {
			src_node_id: nodes[5],
			short_channel_id: 10,
			fees: zero_fees,
			cltv_expiry_delta: (10 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])]
	}

	#[test]
	fn last_hops_with_public_channel_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops_with_public_channel(&nodes));
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		// This test shows that public routes can be present in the invoice
		// which would be handled in the same manner.

		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 100);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 0);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 100);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	}

	#[test]
	fn our_chans_last_hop_connect_test() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// Simple test with outbound channel to 4 to test that last_hops and first_hops connect
		let our_chans = vec![get_channel_details(Some(42), nodes[3].clone(), InitFeatures::from_le_bytes(vec![0b11]), 250_000_000)];
		let mut last_hops = last_hops(&nodes);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops.clone());
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, nodes[3]);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 0);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (8 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &vec![0b11]);
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &Vec::<u8>::new()); // No feature flags will meet the relevant-to-channel conversion

		assert_eq!(route.paths[0][1].pubkey, nodes[6]);
		assert_eq!(route.paths[0][1].short_channel_id, 8);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		// last_hops[0].0[0].fees.base_msat = 1000;
		last_hops[0].0[0].fees.proportional_millionths = 10000000;


		// Revert to via 6 as the fee on 8 goes up
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops);
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 4);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 200); // fee increased as its % of value transferred across node
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 100);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (7 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[5]);
		assert_eq!(route.paths[0][2].short_channel_id, 7);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (10 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(6));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(7));

		assert_eq!(route.paths[0][3].pubkey, nodes[6]);
		assert_eq!(route.paths[0][3].short_channel_id, 10);
		assert_eq!(route.paths[0][3].fee_msat, 100);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][3].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly

		/*
		// ...but still use 8 for larger payments as 6 has a variable feerate
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 2000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths[0].len(), 5);

		assert_eq!(route.paths[0][0].pubkey, nodes[1]);
		assert_eq!(route.paths[0][0].short_channel_id, 2);
		assert_eq!(route.paths[0][0].fee_msat, 3000);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (4 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(2));
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(2));

		assert_eq!(route.paths[0][1].pubkey, nodes[2]);
		assert_eq!(route.paths[0][1].short_channel_id, 4);
		assert_eq!(route.paths[0][1].fee_msat, 0);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, (6 << 4) | 1);
		assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(4));

		assert_eq!(route.paths[0][2].pubkey, nodes[4]);
		assert_eq!(route.paths[0][2].short_channel_id, 6);
		assert_eq!(route.paths[0][2].fee_msat, 0);
		assert_eq!(route.paths[0][2].cltv_expiry_delta, (11 << 4) | 1);
		assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(5));
		assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(6));

		assert_eq!(route.paths[0][3].pubkey, nodes[3]);
		assert_eq!(route.paths[0][3].short_channel_id, 11);
		assert_eq!(route.paths[0][3].fee_msat, 1000);
		assert_eq!(route.paths[0][3].cltv_expiry_delta, (8 << 4) | 1);
		// If we have a peer in the node map, we'll use their features here since we don't have
		// a way of figuring out their features from the invoice:
		assert_eq!(route.paths[0][3].node_features.le_flags(), &id_to_feature_flags(4));
		assert_eq!(route.paths[0][3].channel_features.le_flags(), &id_to_feature_flags(11));

		assert_eq!(route.paths[0][4].pubkey, nodes[6]);
		assert_eq!(route.paths[0][4].short_channel_id, 8);
		assert_eq!(route.paths[0][4].fee_msat, 2000);
		assert_eq!(route.paths[0][4].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][4].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][4].channel_features.le_flags(), &Vec::<u8>::new()); // We can't learn any flags from invoices, sadly
	 */}

	fn do_unannounced_path_test(last_hop_htlc_max: Option<u64>, last_hop_fee_prop: u32, outbound_capacity_msat: u64, route_val: u64) -> Result<Route, LightningError> {
		let source_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 41).repeat(32)).unwrap()[..]).unwrap());
		let middle_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let target_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());

		// If we specify a channel to a middle hop, that overrides our local channel view and that gets used
		let last_hops = RouteHint(vec![RouteHintHop {
			src_node_id: middle_node_id,
			short_channel_id: 8,
			fees: RoutingFees {
				base_msat: 0,  // was 1000
				proportional_millionths: last_hop_fee_prop,
			},
			cltv_expiry_delta: (8 << 4) | 1,
			htlc_minimum_msat: None,
			htlc_maximum_msat: last_hop_htlc_max,
		}]);
		let payment_params = PaymentParameters::from_node_id(target_node_id).with_route_hints(vec![last_hops]);
		let our_chans = vec![get_channel_details(Some(42), middle_node_id, InitFeatures::from_le_bytes(vec![0b11]), outbound_capacity_msat)];
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let logger = test_utils::TestLogger::new();
		let network_graph = NetworkGraph::new(genesis_hash, &logger);
		let route = get_route(&source_node_id, &payment_params, &network_graph.read_only(),
				Some(&our_chans.iter().collect::<Vec<_>>()), route_val, 42, &logger, &scorer, &random_seed_bytes);
		route
	}

	#[test]
	fn unannounced_path_test() {
		// We should be able to send a payment to a destination without any help of a routing graph
		// if we have a channel with a common counterparty that appears in the first and last hop
		// hints.
		let route = do_unannounced_path_test(None, 1001, 2000000, 1000000).unwrap();

		let middle_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 42).repeat(32)).unwrap()[..]).unwrap());
		let target_node_id = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&hex::decode(format!("{:02}", 43).repeat(32)).unwrap()[..]).unwrap());
		assert_eq!(route.paths[0].len(), 2);

		assert_eq!(route.paths[0][0].pubkey, middle_node_id);
		assert_eq!(route.paths[0][0].short_channel_id, 42);
		assert_eq!(route.paths[0][0].fee_msat, 1001);
		assert_eq!(route.paths[0][0].cltv_expiry_delta, (8 << 4) | 1);
		assert_eq!(route.paths[0][0].node_features.le_flags(), &[0b11]);
		assert_eq!(route.paths[0][0].channel_features.le_flags(), &[0; 0]); // We can't learn any flags from invoices, sadly

		assert_eq!(route.paths[0][1].pubkey, target_node_id);
		assert_eq!(route.paths[0][1].short_channel_id, 8);
		assert_eq!(route.paths[0][1].fee_msat, 1000000);
		assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
		assert_eq!(route.paths[0][1].node_features.le_flags(), default_node_features().le_flags()); // We dont pass flags in from invoices yet
		assert_eq!(route.paths[0][1].channel_features.le_flags(), &[0; 0]); // We can't learn any flags from invoices, sadly
	}

	#[test]
	fn overflow_unannounced_path_test_liquidity_underflow() {
		// Previously, when we had a last-hop hint connected directly to a first-hop channel, where
		// the last-hop had a fee which overflowed a u64, we'd panic.
		// This was due to us adding the first-hop from us unconditionally, causing us to think
		// we'd built a path (as our node is in the "best candidate" set), when we had not.
		// In this test, we previously hit a subtraction underflow due to having less available
		// liquidity at the last hop than 0.
		assert!(do_unannounced_path_test(Some(21_000_000_0000_0000_000), 0, 21_000_000_0000_0000_000, 21_000_000_0000_0000_000).is_err());
	}

	#[test]
	fn overflow_unannounced_path_test_feerate_overflow() {
		// This tests for the same case as above, except instead of hitting a subtraction
		// underflow, we hit a case where the fee charged at a hop overflowed.
		assert!(do_unannounced_path_test(Some(21_000_000_0000_0000_000), 50000, 21_000_000_0000_0000_000, 21_000_000_0000_0000_000).is_err());
	}

	#[test]
	fn available_amount_while_routing_test() {
		// Tests whether we choose the correct available channel amount while routing.

		let (secp_ctx, network_graph, mut gossip_sync, chain_monitor, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());

		// We will use a simple single-path route from
		// our node to node2 via node0: channels {1, 3}.

		// First disable all other paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Make the first channel (#1) very permissive,
		// and we will be testing all limits on the second channel.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// First, let's see if routing works if we have absolutely no idea about the available amount.
		// In this case, it should be set to 250_000 sats.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 250_000_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 250_000_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 250_000_000);
		}

		// Check that setting next_outbound_htlc_limit_msat in first_hops limits the channels.
		// Disable channel #1 and use another first hop.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 3,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Now, limit the first_hop by the next_outbound_htlc_limit_msat of 200_000 sats.
		let our_chans = vec![get_channel_details(Some(42), nodes[0].clone(), InitFeatures::from_le_bytes(vec![0b11]), 200_000_000)];

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 200_000_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&our_chans.iter().collect::<Vec<_>>()), 200_000_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 200_000_000);
		}

		// Enable channel #1 back.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 4,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 1_000_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});


		// Now let's see if routing works if we know only htlc_maximum_msat.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 3,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 15_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 15_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 15_000);
		}

		// Now let's see if routing works if we know only capacity from the UTXO.

		// We can't change UTXO capacity on the fly, so we'll disable
		// the existing channel and add another one with the capacity we need.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 4,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let good_script = Builder::new().push_opcode(opcodes::all::OP_PUSHNUM_2)
		.push_slice(&PublicKey::from_secret_key(&secp_ctx, &privkeys[0]).serialize())
		.push_slice(&PublicKey::from_secret_key(&secp_ctx, &privkeys[2]).serialize())
		.push_opcode(opcodes::all::OP_PUSHNUM_2)
		.push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script().to_v0_p2wsh();

		*chain_monitor.utxo_ret.lock().unwrap() = Ok(TxOut { value: 15, script_pubkey: good_script.clone() });
		gossip_sync.add_chain_access(Some(chain_monitor));

		add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 333);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 1,
			flags: 1,
			cltv_expiry_delta: (3 << 4) | 2,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 15_000,
			fee_base_msat: 100,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 15_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 15_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 15_000);
		}

		// Now let's see if routing chooses htlc_maximum_msat over UTXO capacity.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 333,
			timestamp: 6,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 10_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 10_001, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route an exact amount we have should be fine.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 10_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let path = route.paths.last().unwrap();
			assert_eq!(path.len(), 2);
			assert_eq!(path.last().unwrap().pubkey, nodes[2]);
			assert_eq!(path.last().unwrap().fee_msat, 10_000);
		}
	}

	#[test]
	fn available_liquidity_last_hop_test() {
		// Check that available liquidity properly limits the path even when only
		// one of the latter hops is limited.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[3]).with_features(InvoiceFeatures::known());

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// {12, 13, 11} have the capacities of 100, {6} has a capacity of 50.
		// Total capacity: 50 sats.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Limit capacities

		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 60_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 49 sats (just a bit below the capacity).
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 49_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 4);
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 49_000);
		}

		{
			// Attempt to route an exact amount is also fine
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 4);
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 50_000);
		}
	}

	// #[test]  // Too hard to fix algorithm with routes with unrealistic high cost and low liquidity.
	//  The fix requires tracking fees inside the min cost flow algorithm.
	fn ignore_fee_first_hop_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]);

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 1_000_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 50_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 50_000);
		}
	}

	#[test]
	fn simple_mpp_route_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2])
			.with_features(InvoiceFeatures::known());

		// We need a route consisting of 3 paths:
		// From our node to node2 via node0, node7, node1 (three paths one hop each).
		// To achieve this, the amount being transferred should be around
		// the total capacity of these 3 paths.

		// First, we set limits on these (previously unlimited) channels.
		// Their aggregate capacity will be 50 + 60 + 180 = 290 sats.

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node7 is channels {12, 13}. Limit them to 60 and 60 sats
		// (total limit 60).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node1 is channels {2, 4}. Limit them to 200 and 180 sats
		// (total capacity 180 sats).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 180_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
				&our_id, &payment_params, &network_graph.read_only(), None, 300_000, 42,
				Arc::clone(&logger), &scorer, &random_seed_bytes) {
					assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Attempt to route while setting max_path_count to 0 results in a failure.
			let zero_payment_params = payment_params.clone().with_max_path_count(0);
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
				&our_id, &zero_payment_params, &network_graph.read_only(), None, 100, 42,
				Arc::clone(&logger), &scorer, &random_seed_bytes) {
					assert_eq!(err, "Can't find a route with no paths allowed.");
			} else { panic!(); }
		}

		// with_max_path_count not supported
		// {
		// 	// Attempt to route while setting max_path_count to 3 results in a failure.
		// 	// This is the case because the minimal_value_contribution_msat would require each path
		// 	// to account for 1/3 of the total value, which is violated by 2 out of 3 paths.
		// 	let fail_payment_params = payment_params.clone().with_max_path_count(3);
		// 	if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
		// 		&our_id, &fail_payment_params, &network_graph.read_only(), None, 250_000, 42,
		// 		Arc::clone(&logger), &scorer, &random_seed_bytes) {
		// 			assert_eq!(err, "Failed to find a sufficient route to the given destination");
		// 	} else { panic!(); }
		// }

		{
			// Now, attempt to route 250 sats (just a bit below the capacity).
			// Our algorithm should provide us with these 3 paths.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None,
				250_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 250_000);
		}

		{
			// Attempt to route an exact amount is also fine
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None,
				290_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 290_000);
		}
	}

	#[test]
	fn test_flow_to_paths() {
		let mut edges:Vec<OriginalEdge> =Vec::new();
		let r=flow_to_paths(&edges, 0, 1, 2);
		assert_eq!(0, r.len());
		edges.push(OriginalEdge { u: 0, v: 1, capacity: 4, cost: 1, flow: 3, guaranteed_liquidity: 2 });
		let r=flow_to_paths(&edges, 0, 1, 2);
		assert_eq!(vec![(3, vec![0])], r);
		edges.push(OriginalEdge { u: 1, v: 2, capacity: 4, cost: 1, flow: 1, guaranteed_liquidity: 2 });
		edges.push(OriginalEdge { u: 1, v: 3, capacity: 4, cost: 1, flow: 2, guaranteed_liquidity: 2 });
		edges.push(OriginalEdge { u: 2, v: 4, capacity: 4, cost: 1, flow: 1, guaranteed_liquidity: 2 });
		edges.push(OriginalEdge { u: 3, v: 4, capacity: 4, cost: 1, flow: 2, guaranteed_liquidity: 2 });
		let r=flow_to_paths(&edges, 0, 4, 5);
		assert_eq!(vec![(2, vec![0,2,4]),(1, vec![0,1,3])], r);
	}
	#[test]
	fn long_mpp_route_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[3]).with_features(InvoiceFeatures::known());

		// We need a route consisting of 3 paths:
		// From our node to node3 via {node0, node2}, {node7, node2, node4} and {node7, node2}.
		// Note that these paths overlap (channels 5, 12, 13).
		// We will route 300 sats.
		// Each path will have 100 sats capacity, those channels which
		// are used twice will have 200 sats capacity.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Capacity of 200 sats because this channel will be used by 3rd path as well.
		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// Add 100 sats to the capacities of {12, 13}, because these channels
		// are also used for 3rd path. 100 sats for the rest. Total capacity: 100 sats.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2} is channels {12, 13, 5}.
		// We already limited them to 200 sats (they are used twice for 100 sats).
		// Nothing to do here.

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 350_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 300 sats (exact amount we can route).
			// Our algorithm should provide us with 2 paths, 100+200 sats, unlike DefaultRouter that gives back 3 paths with 100 sats.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 300_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);

			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 300_000);
		}

	}

	#[test]
	fn mpp_cheaper_route_test() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[3]).with_features(InvoiceFeatures::known());

		// This test checks that if we have two cheaper paths and one more expensive path,
		// so that liquidity-wise any 2 of 3 combination is sufficient,
		// two cheaper paths will be taken.
		// These paths have equal available liquidity.

		// We need a combination of 3 paths:
		// From our node to node3 via {node0, node2}, {node7, node2, node4} and {node7, node2}.
		// Note that these paths overlap (channels 5, 12, 13).
		// Each path will have 100 sats capacity, those channels which
		// are used twice will have 200 sats capacity.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Capacity of 200 sats because this channel will be used by 3rd path as well.
		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// Add 100 sats to the capacities of {12, 13}, because these channels
		// are also used for 3rd path. 100 sats for the rest. Total capacity: 100 sats.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 200_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 1_000,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2} is channels {12, 13, 5}.
		// We already limited them to 200 sats (they are used twice for 100 sats).
		// Nothing to do here.

		{
			// Now, attempt to route 180 sats.
			// Our algorithm should provide us with these 2 paths.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 180_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);

			let mut total_value_transferred_msat = 0;
			let mut total_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_value_transferred_msat += path.last().unwrap().fee_msat;
				for hop in path {
					total_paid_msat += hop.fee_msat;
				}
			}
			// If we paid fee, this would be higher.
			assert_eq!(total_value_transferred_msat, 180_000);
			let total_fees_paid = total_paid_msat - total_value_transferred_msat;
			assert_eq!(total_fees_paid, 0);
		}
	}

	// #[test]  // needs fee tracking :(
	fn fees_on_mpp_route_test() {
		// This test makes sure that MPP algorithm properly takes into account
		// fees charged on the channels, by making the fees impactful:
		// if the fee is not properly accounted for, the behavior is different.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[3]).with_features(InvoiceFeatures::known());

		// We need a route consisting of 2 paths:
		// From our node to node3 via {node0, node2} and {node7, node2, node4}.
		// We will route 200 sats, Each path will have 100 sats capacity.

		// This test is not particularly stable: e.g.,
		// there's a way to route via {node0, node2, node4}.
		// It works while pathfinding is deterministic, but can be broken otherwise.
		// It's fine to ignore this concern for now.

		// Disable other potential paths.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 7,
			timestamp: 2,
			flags: 2,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node0, node2} is channels {1, 3, 5}.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via {node7, node2, node4} is channels {12, 13, 6, 11}.
		// All channels should be 100 sats capacity. But for the fee experiment,
		// we'll add absolute fee of 150 sats paid for the use channel 6 (paid to node2 on channel 13).
		// Since channel 12 allows to deliver only 250 sats to channel 13, channel 13 can transfer only
		// 100 sats (and pay 150 sats in fees for the use of channel 6),
		// so no matter how large are other channels,
		// the whole path will be limited by 100 sats with just these 2 conditions:
		// - channel 12 capacity is 250 sats
		// - fee for channel 6 is 150 sats
		// Let's test this by enforcing these 2 conditions and removing other limits.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,  // was: 150_000
			fee_proportional_millionths: 750000,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 11,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 210_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 200 sats (exact amount we can route).
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 200_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);

			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.last().unwrap().pubkey, nodes[3]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 200_000);
			assert_eq!(route.get_total_fees(), 150_000);
		}
	}

	#[test]
	fn mpp_with_last_hops() {
		// Previously, if we tried to send an MPP payment to a destination which was only reachable
		// via a single last-hop route hint, we'd fail to route if we first collected routes
		// totaling close but not quite enough to fund the full payment.
		//
		// This was because we considered last-hop hints to have exactly the sought payment amount
		// instead of the amount we were trying to collect, needlessly limiting our path searching
		// at the very first hop.
		//
		// Specifically, this interacted with our "all paths must fund at least 5% of total target"
		// criterion to cause us to refuse all routes at the last hop hint which would be considered
		// to only have the remaining to-collect amount in available liquidity.
		//
		// This bug appeared in production in some specific channel configurations.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(PublicKey::from_slice(&[02; 33]).unwrap()).with_features(InvoiceFeatures::known())
			.with_route_hints(vec![RouteHint(vec![RouteHintHop {
				src_node_id: nodes[2],
				short_channel_id: 42,
				fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
				cltv_expiry_delta: 42,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			}])]).with_max_channel_saturation_power_of_half(0);

		// Keep only two paths from us to nodes[2], both with a 99sat HTLC maximum, with one with
		// no fee and one with a 1msat fee. Previously, trying to route 100 sats to nodes[2] here
		// would first use the no-fee route and then fail to find a path along the second route as
		// we think we can only send up to 1 additional sat over the last-hop but refuse to as its
		// under 5% of our payment amount.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 5,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 99_000,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 3,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 99_000,
			fee_base_msat: u32::max_value(),
			fee_proportional_millionths: u32::max_value(),
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,  // was: 1
			fee_proportional_millionths: 1000,  // was: 0
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0|2, // Channel disabled
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 2000000,
			excess_data: Vec::new()
		});

		// Get a route for 100 sats and check that we found the MPP route no problem and didn't
		// overpay at all.
		let mut route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		route.paths.sort_by_key(|path| path[0].short_channel_id);
		// Paths are manually ordered ordered by SCID, so:
		// * the first is channel 1 (0 fee, but 99 sat maximum) -> channel 3 -> channel 42
		// * the second is channel 2 (1 msat fee) -> channel 4 -> channel 42
		assert_eq!(route.paths[0][0].short_channel_id, 1);
		assert_eq!(route.paths[0][0].fee_msat, 0);
		// assert_eq!(route.paths[0][2].fee_msat, 99_000);  // other configuration is possible as well.
		assert_eq!(route.paths[1][0].short_channel_id, 2);
		assert_eq!(route.paths[1][0].fee_msat, 1);
		// assert_eq!(route.paths[1][2].fee_msat, 1_000);
		assert_eq!(route.get_total_fees(), 1);
		assert_eq!(route.get_total_amount(), 100_000);
	}

	#[test]
	fn drop_lowest_channel_mpp_route_test() {
		// This test checks that low-capacity channel is dropped when after
		// path finding we realize that we found more capacity than we need.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known())
			.with_max_channel_saturation_power_of_half(0);

		// We need a route consisting of 3 paths:
		// From our node to node2 via node0, node7, node1 (three paths one hop each).

		// The first and the second paths should be sufficient, but the third should be
		// cheaper, so that we select it but drop later.

		// First, we set limits on these (previously unlimited) channels.
		// Their aggregate capacity will be 50 + 60 + 20 = 130 sats.

		// Path via node0 is channels {1, 3}. Limit them to 100 and 50 sats (total limit 50);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 100_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 50_000,
			fee_base_msat: 0,  // was: 100
			fee_proportional_millionths: 2778,
			excess_data: Vec::new()
		});

		// Path via node7 is channels {12, 13}. Limit them to 60 and 60 sats (total limit 60);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,  // was: 100
			fee_proportional_millionths: 20000,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 60_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		// Path via node1 is channels {2, 4}. Limit them to 20 and 20 sats (total capacity 20 sats).
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 20_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 20_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Attempt to route more than available results in a failure.
			if let Err(LightningError{err, action: ErrorAction::IgnoreError}) = get_route(
					&our_id, &payment_params, &network_graph.read_only(), None, 150_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				assert_eq!(err, "Failed to find a sufficient route to the given destination");
			} else { panic!(); }
		}

		{
			// Now, attempt to route 125 sats (just a bit below the capacity of 3 channels).
			// Our algorithm should provide us with these 3 paths.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 125_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 3);
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 125_000);
		}

		{
			// Attempt to route without the last small cheap channel
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			// assert_eq!(route.paths.len(), 2);  // 3 paths are possible as well
			let mut total_amount_paid_msat = 0;
			for path in &route.paths {
				assert_eq!(path.len(), 2);
				assert_eq!(path.last().unwrap().pubkey, nodes[2]);
				total_amount_paid_msat += path.last().unwrap().fee_msat;
			}
			assert_eq!(total_amount_paid_msat, 90_000);
		}
	}

	#[test]
	fn min_criteria_consistency() {
		// Test that we don't use an inconsistent metric between updating and walking nodes during
		// our Dijkstra's pass. In the initial version of MPP, the "best source" for a given node
		// was updated with a different criterion from the heap sorting, resulting in loops in
		// calculated paths. We test for that specific case here.

		// We construct a network that looks like this:
		//
		//            node2 -1(3)2- node3
		//              2          2
		//               (2)     (4)
		//                  1   1
		//    node1 -1(5)2- node4 -1(1)2- node6
		//    2
		//   (6)
		//	  1
		// our_node
		//
		// We create a loop on the side of our real path - our destination is node 6, with a
		// previous hop of node 4. From 4, the cheapest previous path is channel 2 from node 2,
		// followed by node 3 over channel 3. Thereafter, the cheapest next-hop is back to node 4
		// (this time over channel 4). Channel 4 has 0 htlc_minimum_msat whereas channel 1 (the
		// other channel with a previous-hop of node 4) has a high (but irrelevant to the overall
		// payment) htlc_minimum_msat. In the original algorithm, this resulted in node4's
		// "previous hop" being set to node 3, creating a loop in the path.
		let secp_ctx = Secp256k1::new();
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let logger = Arc::new(test_utils::TestLogger::new());
		let network = Arc::new(NetworkGraph::new(genesis_hash, Arc::clone(&logger)));
		let gossip_sync = P2PGossipSync::new(Arc::clone(&network), None, Arc::clone(&logger));
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[6]);

		add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 6,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (6 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[1], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(5)), 5);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 5,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (5 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,  // was: 100
			fee_proportional_millionths: 10000,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[3], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 3,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (3 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

		add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (2 << 4) | 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		add_channel(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[6], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
		update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 1,
			timestamp: 1,
			flags: 0,
			cltv_expiry_delta: (1 << 4) | 0,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[6], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

		{
			// Now ensure the route flows simply over nodes 1 and 4 to 6.
			let route = get_route(&our_id, &payment_params, &network.read_only(), None, 10_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 3);

			assert_eq!(route.paths[0][0].pubkey, nodes[1]);
			assert_eq!(route.paths[0][0].short_channel_id, 6);
			assert_eq!(route.paths[0][0].fee_msat, 100);
			assert_eq!(route.paths[0][0].cltv_expiry_delta, (5 << 4) | 0);
			assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(1));
			assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(6));

			assert_eq!(route.paths[0][1].pubkey, nodes[4]);
			assert_eq!(route.paths[0][1].short_channel_id, 5);
			assert_eq!(route.paths[0][1].fee_msat, 0);
			assert_eq!(route.paths[0][1].cltv_expiry_delta, (1 << 4) | 0);
			assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(4));
			assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(5));

			assert_eq!(route.paths[0][2].pubkey, nodes[6]);
			assert_eq!(route.paths[0][2].short_channel_id, 1);
			assert_eq!(route.paths[0][2].fee_msat, 10_000);
			assert_eq!(route.paths[0][2].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0][2].node_features.le_flags(), &id_to_feature_flags(6));
			assert_eq!(route.paths[0][2].channel_features.le_flags(), &id_to_feature_flags(1));
		}
	}


	// #[test]  // Needs better fee handling inside routing algorithm.
	fn exact_fee_liquidity_limit() {
		// Test that if, while walking the graph, we find a hop that has exactly enough liquidity
		// for us, including later hop fees, we take it. In the first version of our MPP algorithm
		// we calculated fees on a higher value, resulting in us ignoring such paths.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, _, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = set_mpp(PaymentParameters::from_node_id(nodes[2]));
		// We modify the graph to set the htlc_maximum of channel 2 to below the value we wish to
		// send.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 85_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 12,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 270_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 1000000,
			excess_data: Vec::new()
		});

		{
			// Now, attempt to route 90 sats, which is exactly 90 sats at the last hop, plus the
			// 200% fee charged channel 13 in the 1-to-2 direction.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 2);

			assert_eq!(route.paths[0][0].pubkey, nodes[7]);
			assert_eq!(route.paths[0][0].short_channel_id, 12);
			assert_eq!(route.paths[0][0].fee_msat, 90_000*2);
			assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
			assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(8));
			assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(12));

			assert_eq!(route.paths[0][1].pubkey, nodes[2]);
			assert_eq!(route.paths[0][1].short_channel_id, 13);
			assert_eq!(route.paths[0][1].fee_msat, 90_000);
			assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0][1].node_features.le_flags(), &id_to_feature_flags(3));
			assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));
		}
	}

	// #[test] // htlc_minimum_msat not supported
	fn htlc_max_reduction_below_min() {
		// Test that if, while walking the graph, we reduce the value being sent to meet an
		// htlc_maximum_msat, we don't end up undershooting a later htlc_minimum_msat. In the
		// initial version of MPP we'd accept such routes but reject them while recalculating fees,
		// resulting in us thinking there is no possible path, even if other paths exist.
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (our_privkey, our_id, privkeys, nodes) = get_nodes(&secp_ctx);
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());

		// We modify the graph to set the htlc_minimum of channel 2 and 4 as needed - channel 2
		// gets an htlc_maximum_msat of 80_000 and channel 4 an htlc_minimum_msat of 90_000. We
		// then try to send 90_000.
		update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 2,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: 0,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 80_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 90_000,
			htlc_maximum_msat: MAX_VALUE_MSAT,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		{
			// Now, attempt to route 90 sats, hitting the htlc_minimum on channel 4, but
			// overshooting the htlc_maximum on channel 2. Thus, we should pick the (absurdly
			// expensive) channels 12-13 path.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 90_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 2);

			assert_eq!(route.paths[0][0].pubkey, nodes[7]);
			assert_eq!(route.paths[0][0].short_channel_id, 12);
			assert_eq!(route.paths[0][0].fee_msat, 90_000*2);
			assert_eq!(route.paths[0][0].cltv_expiry_delta, (13 << 4) | 1);
			assert_eq!(route.paths[0][0].node_features.le_flags(), &id_to_feature_flags(8));
			assert_eq!(route.paths[0][0].channel_features.le_flags(), &id_to_feature_flags(12));

			assert_eq!(route.paths[0][1].pubkey, nodes[2]);
			assert_eq!(route.paths[0][1].short_channel_id, 13);
			assert_eq!(route.paths[0][1].fee_msat, 90_000);
			assert_eq!(route.paths[0][1].cltv_expiry_delta, 42);
			assert_eq!(route.paths[0][1].node_features.le_flags(), InvoiceFeatures::known().le_flags());
			assert_eq!(route.paths[0][1].channel_features.le_flags(), &id_to_feature_flags(13));
		}
	}

	// #[test]  // TODO fix: Min cost algorithm can't avoid MPP :(
	fn multiple_direct_first_hops() {
		// Previously we'd only ever considered one first hop path per counterparty.
		// However, as we don't restrict users to one channel per peer, we really need to support
		// looking at all first hop paths.
		// Here we test that we do not ignore all-but-the-last first hop paths per counterparty (as
		// we used to do by overwriting the `first_hop_targets` hashmap entry) and that we can MPP
		// route over multiple channels with the same first hop.
		let secp_ctx = Secp256k1::new();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
		let logger = Arc::new(test_utils::TestLogger::new());
		let network_graph = NetworkGraph::new(genesis_hash, Arc::clone(&logger));
		let scorer = test_utils::TestScorer::with_penalty(0);
		let payment_params = PaymentParameters::from_node_id(nodes[0]).with_features(InvoiceFeatures::known());
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(3), nodes[0], InitFeatures::known(), 200_000),
				&get_channel_details(Some(2), nodes[0], InitFeatures::known(), 10_000),
			]), 100_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 1);

			assert_eq!(route.paths[0][0].pubkey, nodes[0]);
			assert_eq!(route.paths[0][0].short_channel_id, 3);
			assert_eq!(route.paths[0][0].fee_msat, 100_000);
		}
		{
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(3), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(2), nodes[0], InitFeatures::known(), 50_000),
			]), 100_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 2);
			assert_eq!(route.paths[0].len(), 1);
			assert_eq!(route.paths[1].len(), 1);

			assert!((route.paths[0][0].short_channel_id == 3 && route.paths[1][0].short_channel_id == 2) ||
				(route.paths[0][0].short_channel_id == 2 && route.paths[1][0].short_channel_id == 3));

			assert_eq!(route.paths[0][0].pubkey, nodes[0]);
			assert_eq!(route.paths[0][0].fee_msat, 50_000);

			assert_eq!(route.paths[1][0].pubkey, nodes[0]);
			assert_eq!(route.paths[1][0].fee_msat, 50_000);
		}

		{
			// If we have a bunch of outbound channels to the same node, where most are not
			// sufficient to pay the full payment, but one is, we should default to just using the
			// one single channel that has sufficient balance, avoiding MPP.
			//
			// If we have several options above the 3xpayment value threshold, we should pick the
			// smallest of them, avoiding further fragmenting our available outbound balance to
			// this node.
			let route = get_route(&our_id, &payment_params, &network_graph.read_only(), Some(&[
				&get_channel_details(Some(2), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(3), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(5), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(6), nodes[0], InitFeatures::known(), 300_000),
				&get_channel_details(Some(7), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(8), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(9), nodes[0], InitFeatures::known(), 50_000),
				&get_channel_details(Some(4), nodes[0], InitFeatures::known(), 1_000_000),
			]), 100_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
			assert_eq!(route.paths.len(), 1);
			assert_eq!(route.paths[0].len(), 1);

			assert_eq!(route.paths[0][0].pubkey, nodes[0]);
			assert_eq!(route.paths[0][0].short_channel_id, 6);
			assert_eq!(route.paths[0][0].fee_msat, 100_000);
		}
	}

	// #[test]  // Depends on fee - probability setting.
	fn prefers_shorter_route_with_higher_fees() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes));

		// Without penalizing each hop 100 msats, a longer path with lower fees is chosen.
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(
			&our_id, &payment_params, &network_graph.read_only(), None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 100);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 6, 11, 8]);

		// Applying a 100 msat penalty to each hop results in taking channels 7 and 10 to nodes[6]
		// from nodes[2] rather than channel 6, 11, and 8, even though the longer path is cheaper.
		let scorer = test_utils::TestScorer::with_penalty(100);
		let route = get_route(
			&our_id, &payment_params, &network_graph.read_only(), None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 300);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 7, 10]);
	}

	struct BadChannelScorer {
		short_channel_id: u64,
	}

	#[cfg(c_bindings)]
	impl Writeable for BadChannelScorer {
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), ::io::Error> { unimplemented!() }
	}
	impl Score for BadChannelScorer {
		fn channel_penalty_msat(&self, short_channel_id: u64, _: &NodeId, _: &NodeId, _: ChannelUsage) -> u64 {
			if short_channel_id == self.short_channel_id { u64::max_value() } else { 0 }
		}

		fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
		fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
		fn probe_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
		fn probe_successful(&mut self, _path: &[&RouteHop]) {}
		fn estimated_channel_liquidity_range(&self,scid:u64,target: &NodeId) -> Option<(u64,u64)> {
			if scid==self.short_channel_id { Some((0, 0)) } else { None }
		}
	}

	struct BadNodeScorer {
		node_id: NodeId,
	}

	#[cfg(c_bindings)]
	impl Writeable for BadNodeScorer {
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), ::io::Error> { unimplemented!() }
	}

	impl Score for BadNodeScorer {
		fn channel_penalty_msat(&self, _: u64, _: &NodeId, target: &NodeId, _: ChannelUsage) -> u64 {
			if *target == self.node_id { u64::max_value() } else { 0 }
		}

		fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
		fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
		fn probe_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
		fn probe_successful(&mut self, _path: &[&RouteHop]) {}
		fn estimated_channel_liquidity_range(&self,scid:u64,target: &NodeId) -> Option<(u64,u64)> {
			if *target == self.node_id { Some((0, 0)) } else { None }
		}
	}

	#[test]
	fn avoids_routing_through_bad_channels_and_nodes() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes));
		let network_graph = network.read_only();

		// A path to nodes[6] exists when no penalties are applied to any channel.
		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(
			&our_id, &payment_params, &network_graph, None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 100);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 6, 11, 8]);

		// A different path to nodes[6] exists if channel 6 cannot be routed over.
		let scorer = BadChannelScorer { short_channel_id: 6 };
		let route = get_route(
			&our_id, &payment_params, &network_graph, None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();

		assert_eq!(route.get_total_fees(), 300);
		assert_eq!(route.get_total_amount(), 100);
		assert_eq!(path, vec![2, 4, 7, 10]);

		// A path to nodes[6] does not exist if nodes[2] cannot be routed through.
		let scorer = BadNodeScorer { node_id: NodeId::from_pubkey(&nodes[2]) };
		match get_route(
			&our_id, &payment_params, &network_graph, None, 100, 42,
			Arc::clone(&logger), &scorer, &random_seed_bytes
		) {
			Err(LightningError { err, .. } ) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn total_fees_single_path() {
		let route = Route {
			paths: vec![vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 225, cltv_expiry_delta: 0
				},
			]],
			payment_params: None,
		};

		assert_eq!(route.get_total_fees(), 250);
		assert_eq!(route.get_total_amount(), 225);
	}

	#[test]
	fn total_fees_multi_path() {
		let route = Route {
			paths: vec![vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0
				},
			],vec![
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 100, cltv_expiry_delta: 0
				},
				RouteHop {
					pubkey: PublicKey::from_slice(&hex::decode("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").unwrap()[..]).unwrap(),
					channel_features: ChannelFeatures::empty(), node_features: NodeFeatures::empty(),
					short_channel_id: 0, fee_msat: 150, cltv_expiry_delta: 0
				},
			]],
			payment_params: None,
		};

		assert_eq!(route.get_total_fees(), 200);
		assert_eq!(route.get_total_amount(), 300);
	}

	#[test]
	fn total_empty_route_no_panic() {
		// In an earlier version of `Route::get_total_fees` and `Route::get_total_amount`, they
		// would both panic if the route was completely empty. We test to ensure they return 0
		// here, even though its somewhat nonsensical as a route.
		let route = Route { paths: Vec::new(), payment_params: None };

		assert_eq!(route.get_total_fees(), 0);
		assert_eq!(route.get_total_amount(), 0);
	}

	#[test]
	fn limits_total_cltv_delta() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = test_utils::TestScorer::with_penalty(0);

		// Make sure that generally there is at least one route available
		let feasible_max_total_cltv_delta = 1008;
		let feasible_payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes))
			.with_max_total_cltv_expiry_delta(feasible_max_total_cltv_delta);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(&our_id, &feasible_payment_params, &network_graph, None, 100, 0, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();
		assert_ne!(path.len(), 0);

		// But not if we exclude all paths on the basis of their accumulated CLTV delta
		let fail_max_total_cltv_delta = 23;
		let fail_payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes))
			.with_max_total_cltv_expiry_delta(fail_max_total_cltv_delta);
		match get_route(&our_id, &fail_payment_params, &network_graph, None, 100, 0, Arc::clone(&logger), &scorer, &random_seed_bytes)
		{
			Err(LightningError { err, .. } ) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	// #[test]  // Not implemented, works differently
	fn avoids_recently_failed_paths() {
		// Ensure that the router always avoids all of the `previously_failed_channels` channels by
		// randomly inserting channels into it until we can't find a route anymore.
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = test_utils::TestScorer::with_penalty(0);
		let mut payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes))
			.with_max_path_count(1);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// We should be able to find a route initially, and then after we fail a few random
		// channels eventually we won't be able to any longer.
		assert!(get_route(&our_id, &payment_params, &network_graph, None, 100, 0, Arc::clone(&logger), &scorer, &random_seed_bytes).is_ok());
		loop {
			if let Ok(route) = get_route(&our_id, &payment_params, &network_graph, None, 100, 0, Arc::clone(&logger), &scorer, &random_seed_bytes) {
				for chan in route.paths[0].iter() {
					assert!(!payment_params.previously_failed_channels.contains(&chan.short_channel_id));
				}
				let victim = (u64::from_ne_bytes(random_seed_bytes[0..8].try_into().unwrap()) as usize)
					% route.paths[0].len();
				payment_params.previously_failed_channels.push(route.paths[0][victim].short_channel_id);
			} else { break; }
		}
	}
	const MAX_PATH_LENGTH_ESTIMATE: u8 = 19;

	// #[test]  // Not implemented
	fn limits_path_length() {
		let (secp_ctx, network, _, _, logger) = build_line_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();

		let scorer = test_utils::TestScorer::with_penalty(0);
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First check we can actually create a long route on this graph.
		let feasible_payment_params = PaymentParameters::from_node_id(nodes[18]);
		let route = get_route(&our_id, &feasible_payment_params, &network_graph, None, 100, 0,
			Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		let path = route.paths[0].iter().map(|hop| hop.short_channel_id).collect::<Vec<_>>();
		assert!(path.len() == MAX_PATH_LENGTH_ESTIMATE.into());

		// But we can't create a path surpassing the MAX_PATH_LENGTH_ESTIMATE limit.
		let fail_payment_params = PaymentParameters::from_node_id(nodes[19]);
		match get_route(&our_id, &fail_payment_params, &network_graph, None, 100, 0,
			Arc::clone(&logger), &scorer, &random_seed_bytes)
		{
			Err(LightningError { err, .. } ) => {
				assert_eq!(err, "Failed to find a path to the given destination");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[test]
	fn adds_and_limits_cltv_offset() {
		let (secp_ctx, network_graph, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		let scorer = test_utils::TestScorer::with_penalty(0);

		let payment_params = PaymentParameters::from_node_id(nodes[6]).with_route_hints(last_hops(&nodes));
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 1);

		let cltv_expiry_deltas_before = route.paths[0].iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();

		// Check whether the offset added to the last hop by default is in [1 .. DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA]
		let mut route_default = route.clone();
		add_random_cltv_offset(&mut route_default, &payment_params, &network_graph.read_only(), &random_seed_bytes);
		let cltv_expiry_deltas_default = route_default.paths[0].iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();
		assert_eq!(cltv_expiry_deltas_before.split_last().unwrap().1, cltv_expiry_deltas_default.split_last().unwrap().1);
		assert!(cltv_expiry_deltas_default.last() > cltv_expiry_deltas_before.last());
		assert!(cltv_expiry_deltas_default.last().unwrap() <= &DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA);

		// Check that no offset is added when we restrict the max_total_cltv_expiry_delta
		let mut route_limited = route.clone();
		let limited_max_total_cltv_expiry_delta = cltv_expiry_deltas_before.iter().sum();
		let limited_payment_params = payment_params.with_max_total_cltv_expiry_delta(limited_max_total_cltv_expiry_delta);
		add_random_cltv_offset(&mut route_limited, &limited_payment_params, &network_graph.read_only(), &random_seed_bytes);
		let cltv_expiry_deltas_limited = route_limited.paths[0].iter().map(|h| h.cltv_expiry_delta).collect::<Vec<u32>>();
		assert_eq!(cltv_expiry_deltas_before, cltv_expiry_deltas_limited);
	}

	#[test]
	fn adds_plausible_cltv_offset() {
		let (secp_ctx, network, _, _, logger) = build_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
		let network_graph = network.read_only();
		let network_nodes = network_graph.nodes();
		let network_channels = network_graph.channels();
		let scorer = test_utils::TestScorer::with_penalty(0);
		let payment_params = PaymentParameters::from_node_id(nodes[3]);
		let keys_manager = test_utils::TestKeysInterface::new(&[4u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let mut route = get_route(&our_id, &payment_params, &network_graph, None, 100, 0,
								  Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		add_random_cltv_offset(&mut route, &payment_params, &network_graph, &random_seed_bytes);

		let mut path_plausibility = vec![];

		for p in route.paths {
			// 1. Select random observation point
			let mut prng = ChaCha20::new(&random_seed_bytes, &[0u8; 12]);
			let mut random_bytes = [0u8; ::core::mem::size_of::<usize>()];

			prng.process_in_place(&mut random_bytes);
			let random_path_index = usize::from_be_bytes(random_bytes).wrapping_rem(p.len());
			let observation_point = NodeId::from_pubkey(&p.get(random_path_index).unwrap().pubkey);

			// 2. Calculate what CLTV expiry delta we would observe there
			let observed_cltv_expiry_delta: u32 = p[random_path_index..].iter().map(|h| h.cltv_expiry_delta).sum();

			// 3. Starting from the observation point, find candidate paths
			let mut candidates: VecDeque<(NodeId, Vec<u32>)> = VecDeque::new();
			candidates.push_back((observation_point, vec![]));

			let mut found_plausible_candidate = false;

			'candidate_loop: while let Some((cur_node_id, cur_path_cltv_deltas)) = candidates.pop_front() {
				if let Some(remaining) = observed_cltv_expiry_delta.checked_sub(cur_path_cltv_deltas.iter().sum::<u32>()) {
					if remaining == 0 || remaining.wrapping_rem(40) == 0 || remaining.wrapping_rem(144) == 0 {
						found_plausible_candidate = true;
						break 'candidate_loop;
					}
				}

				if let Some(cur_node) = network_nodes.get(&cur_node_id) {
					for channel_id in &cur_node.channels {
						if let Some(channel_info) = network_channels.get(&channel_id) {
							if let Some((dir_info, next_id)) = channel_info.as_directed_from(&cur_node_id) {
								if let Some(channel_update_info) = dir_info.direction() {
									let next_cltv_expiry_delta = channel_update_info.cltv_expiry_delta as u32;
									if cur_path_cltv_deltas.iter().sum::<u32>()
										.saturating_add(next_cltv_expiry_delta) <= observed_cltv_expiry_delta {
										let mut new_path_cltv_deltas = cur_path_cltv_deltas.clone();
										new_path_cltv_deltas.push(next_cltv_expiry_delta);
										candidates.push_back((*next_id, new_path_cltv_deltas));
									}
								}
							}
						}
					}
				}
			}

			path_plausibility.push(found_plausible_candidate);
		}
		assert!(path_plausibility.iter().all(|x| *x));
	}

	// #[test]
	// fn builds_correct_path_from_hops() {
	// 	let (secp_ctx, network, _, _, logger) = build_graph();
	// 	let (_, our_id, _, nodes) = get_nodes(&secp_ctx);
	// 	let network_graph = network.read_only();

	// 	let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
	// 	let random_seed_bytes = keys_manager.get_secure_random_bytes();

	// 	let payment_params = PaymentParameters::from_node_id(nodes[3]);
	// 	let hops = [nodes[1], nodes[2], nodes[4], nodes[3]];
	// 	let route = build_route_from_hops_internal(&our_id, &hops, &payment_params,
	// 		 &network_graph, 100, 0, Arc::clone(&logger), &random_seed_bytes).unwrap();
	// 	let route_hop_pubkeys = route.paths[0].iter().map(|hop| hop.pubkey).collect::<Vec<_>>();
	// 	assert_eq!(hops.len(), route.paths[0].len());
	// 	for (idx, hop_pubkey) in hops.iter().enumerate() {
	// 		assert!(*hop_pubkey == route_hop_pubkeys[idx]);
	// 	}
	// }

	#[test]
	fn avoids_saturating_channels() {
		let (secp_ctx, network_graph, gossip_sync, _, logger) = build_graph();
		let (_, our_id, privkeys, nodes) = get_nodes(&secp_ctx);

		let scorer = ProbabilisticScorer::new(Default::default(), &*network_graph, Arc::clone(&logger));

		// Set the fee on channel 13 to 100% to match channel 4 giving us two equivalent paths (us
		// -> node 7 -> node2 and us -> node 1 -> node 2) which we should balance over.
		update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 4,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (4 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});
		update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
			chain_hash: genesis_block(Network::Testnet).header.block_hash(),
			short_channel_id: 13,
			timestamp: 2,
			flags: 0,
			cltv_expiry_delta: (13 << 4) | 1,
			htlc_minimum_msat: 0,
			htlc_maximum_msat: 250_000_000,
			fee_base_msat: 0,
			fee_proportional_millionths: 0,
			excess_data: Vec::new()
		});

		let payment_params = PaymentParameters::from_node_id(nodes[2]).with_features(InvoiceFeatures::known());
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		// 100,000 sats is less than the available liquidity on each channel, set above.
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100_000_000, 42, Arc::clone(&logger), &scorer, &random_seed_bytes).unwrap();
		assert_eq!(route.paths.len(), 2);
		assert!((route.paths[0][1].short_channel_id == 4 && route.paths[1][1].short_channel_id == 13) ||
			(route.paths[1][1].short_channel_id == 4 && route.paths[0][1].short_channel_id == 13));
	}

	#[cfg(not(feature = "no-std"))]
	pub(super) fn random_init_seed() -> u64 {
		// Because the default HashMap in std pulls OS randomness, we can use it as a (bad) RNG.
		use core::hash::{BuildHasher, Hasher};
		let seed = std::collections::hash_map::RandomState::new().build_hasher().finish();
		println!("Using seed of {}", seed);
		seed
	}
	#[cfg(not(feature = "no-std"))]
	use util::ser::ReadableArgs;

use crate::routing::gossip::RoutingFees;
use crate::routing::min_cost_flow_router::min_cost_flow_lib::OriginalEdge;
use crate::routing::min_cost_flow_router::{get_route, default_node_features};
use crate::routing::router::{add_random_cltv_offset};

use super::flow_to_paths;

	#[test]
	#[cfg(not(feature = "no-std"))]
	fn generate_routes() {
		use routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};

		let mut d = match super::test_utils::get_route_file() {
			Ok(f) => f,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};
		let logger = test_utils::TestLogger::new();
		let graph = NetworkGraph::read(&mut d, &logger).unwrap();
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let mut seed = random_init_seed() as usize;
		let nodes = graph.read_only().nodes().clone();
		'load_endpoints: for _ in 0..10 {
			loop {
				seed = seed.overflowing_mul(0xdeadbeef).0;
				let src = &PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				seed = seed.overflowing_mul(0xdeadbeef).0;
				let dst = PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				let payment_params = PaymentParameters::from_node_id(dst);
				let amt = seed as u64 % 200_000_000;
				let params = ProbabilisticScoringParameters::default();
				let scorer = ProbabilisticScorer::new(params, &graph, &logger);
				if get_route(src, &payment_params, &graph.read_only(), None, amt, 42, &logger, &scorer, &random_seed_bytes).is_ok() {
					continue 'load_endpoints;
				}
			}
		}
	}

	#[test]
	#[cfg(not(feature = "no-std"))]
	fn generate_routes_mpp() {
		use routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};

		let mut d = match super::test_utils::get_route_file() {
			Ok(f) => f,
			Err(e) => {
				eprintln!("{}", e);
				return;
			},
		};
		let logger = test_utils::TestLogger::new();
		let graph = NetworkGraph::read(&mut d, &logger).unwrap();
		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let mut seed = random_init_seed() as usize;
		let nodes = graph.read_only().nodes().clone();
		'load_endpoints: for _ in 0..10 {
			loop {
				seed = seed.overflowing_mul(0xdeadbeef).0;
				let src = &PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				seed = seed.overflowing_mul(0xdeadbeef).0;
				let dst = PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				let payment_params = PaymentParameters::from_node_id(dst).with_features(InvoiceFeatures::known());
				let amt = seed as u64 % 200_000_000;
				let params = ProbabilisticScoringParameters::default();
				let scorer = ProbabilisticScorer::new(params, &graph, &logger);
				if get_route(src, &payment_params, &graph.read_only(), None, amt, 42, &logger, &scorer, &random_seed_bytes).is_ok() {
					continue 'load_endpoints;
				}
			}
		}
	}

	// #[test]  // Not supported
	fn honors_manual_penalties() {
		let (secp_ctx, network_graph, _, _, logger) = build_line_graph();
		let (_, our_id, _, nodes) = get_nodes(&secp_ctx);

		let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		let scorer_params = ProbabilisticScoringParameters::default();
		let mut scorer = ProbabilisticScorer::new(scorer_params, Arc::clone(&network_graph), Arc::clone(&logger));

		// First check set manual penalties are returned by the scorer.
		let usage = ChannelUsage {
			amount_msat: 0,
			inflight_htlc_msat: 0,
			effective_capacity: EffectiveCapacity::Total { capacity_msat: 1_024_000, htlc_maximum_msat: Some(1_000) },
		};
		scorer.set_manual_penalty(&NodeId::from_pubkey(&nodes[3]), 123);
		scorer.set_manual_penalty(&NodeId::from_pubkey(&nodes[4]), 456);
		assert_eq!(scorer.channel_penalty_msat(42, &NodeId::from_pubkey(&nodes[3]), &NodeId::from_pubkey(&nodes[4]), usage), 456);

		// Then check we can get a normal route
		let payment_params = PaymentParameters::from_node_id(nodes[10]);
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes);
		assert!(route.is_ok());

		// Then check that we can't get a route if we ban an intermediate node.
		scorer.add_banned(&NodeId::from_pubkey(&nodes[3]));
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes);
		assert!(route.is_err());

		// Finally make sure we can route again, when we remove the ban.
		scorer.remove_banned(&NodeId::from_pubkey(&nodes[3]));
		let route = get_route(&our_id, &payment_params, &network_graph.read_only(), None, 100, 42, Arc::clone(&logger), &scorer, &random_seed_bytes);
		assert!(route.is_ok());
	}
}

#[cfg(all(test, not(feature = "no-std")))]
pub(crate) mod test_utils {
	use std::fs::File;
	/// Tries to open a network graph file, or panics with a URL to fetch it.
	pub(crate) fn get_route_file() -> Result<std::fs::File, &'static str> {
		let res = File::open("net_graph-2021-05-31.bin") // By default we're run in RL/lightning
			.or_else(|_| File::open("lightning/net_graph-2021-05-31.bin")) // We may be run manually in RL/
			.or_else(|_| { // Fall back to guessing based on the binary location
				// path is likely something like .../rust-lightning/target/debug/deps/lightning-...
				let mut path = std::env::current_exe().unwrap();
				path.pop(); // lightning-...
				path.pop(); // deps
				path.pop(); // debug
				path.pop(); // target
				path.push("lightning");
				path.push("net_graph-2021-05-31.bin");
				eprintln!("{}", path.to_str().unwrap());
				File::open(path)
			})
		.map_err(|_| "Please fetch https://bitcoin.ninja/ldk-net_graph-v0.0.15-2021-05-31.bin and place it at lightning/net_graph-2021-05-31.bin");
		#[cfg(require_route_graph_test)]
		return Ok(res.unwrap());
		#[cfg(not(require_route_graph_test))]
		return res;
	}
}

#[cfg(all(test, feature = "_bench_unstable", not(feature = "no-std")))]
mod benches {
	use super::*;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use chain::transaction::OutPoint;
	use chain::keysinterface::{KeysManager,KeysInterface};
	use ln::channelmanager::{ChannelCounterparty, ChannelDetails};
	use ln::features::{InitFeatures, InvoiceFeatures};
	use routing::gossip::NetworkGraph;
	use routing::scoring::{FixedPenaltyScorer, ProbabilisticScorer, ProbabilisticScoringParameters};
	use util::logger::{Logger, Record};
	use util::ser::ReadableArgs;

	use test::Bencher;

	struct DummyLogger {}
	impl Logger for DummyLogger {
		fn log(&self, _record: &Record) {}
	}

	fn read_network_graph(logger: &DummyLogger) -> NetworkGraph<&DummyLogger> {
		let mut d = test_utils::get_route_file().unwrap();
		NetworkGraph::read(&mut d, logger).unwrap()
	}

	fn payer_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	#[inline]
	fn first_hop(node_id: PublicKey) -> ChannelDetails {
		ChannelDetails {
			channel_id: [0; 32],
			counterparty: ChannelCounterparty {
				features: InitFeatures::known(),
				node_id,
				unspendable_punishment_reserve: 0,
				forwarding_info: None,
				outbound_htlc_minimum_msat: None,
				outbound_htlc_maximum_msat: None,
			},
			funding_txo: Some(OutPoint {
				txid: bitcoin::Txid::from_slice(&[0; 32]).unwrap(), index: 0
			}),
			channel_type: None,
			short_channel_id: Some(1),
			inbound_scid_alias: None,
			outbound_scid_alias: None,
			channel_value_satoshis: 10_000_000,
			user_channel_id: 0,
			balance_msat: 10_000_000,
			outbound_capacity_msat: 10_000_000,
			next_outbound_htlc_limit_msat: 10_000_000,
			inbound_capacity_msat: 0,
			unspendable_punishment_reserve: None,
			confirmations_required: None,
			force_close_spend_delay: None,
			is_outbound: true,
			is_channel_ready: true,
			is_usable: true,
			is_public: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
			config: None,
		}
	}

	#[bench]
	fn generate_routes_with_zero_penalty_scorer(bench: &mut Bencher) {
		let logger = DummyLogger {};
		let network_graph = read_network_graph(&logger);
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::empty());
	}

	#[bench]
	fn generate_mpp_routes_with_zero_penalty_scorer(bench: &mut Bencher) {
		let logger = DummyLogger {};
		let network_graph = read_network_graph(&logger);
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::known());
	}

	#[bench]
	fn generate_routes_with_probabilistic_scorer(bench: &mut Bencher) {
		let logger = DummyLogger {};
		let network_graph = read_network_graph(&logger);
		let params = ProbabilisticScoringParameters::default();
		let scorer = ProbabilisticScorer::new(params, &network_graph, &logger);
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::empty());
	}

	#[bench]
	fn generate_mpp_routes_with_probabilistic_scorer(bench: &mut Bencher) {
		let logger = DummyLogger {};
		let network_graph = read_network_graph(&logger);
		let params = ProbabilisticScoringParameters::default();
		let scorer = ProbabilisticScorer::new(params, &network_graph, &logger);
		generate_routes(bench, &network_graph, scorer, InvoiceFeatures::known());
	}

	fn generate_routes<S: Score>(
		bench: &mut Bencher, graph: &NetworkGraph<&DummyLogger>, mut scorer: S,
		features: InvoiceFeatures
	) {
		let nodes = graph.read_only().nodes().clone();
		let payer = payer_pubkey();
		let keys_manager = KeysManager::new(&[0u8; 32], 42, 42);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();

		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let mut routes = Vec::new();
		let mut route_endpoints = Vec::new();
		let mut seed: usize = 0xdeadbeef;
		'load_endpoints: for _ in 0..150 {
			loop {
				seed *= 0xdeadbeef;
				let src = PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				seed *= 0xdeadbeef;
				let dst = PublicKey::from_slice(nodes.keys().skip(seed % nodes.len()).next().unwrap().as_slice()).unwrap();
				let params = PaymentParameters::from_node_id(dst).with_features(features.clone());
				let first_hop = first_hop(src);
				let amt = seed as u64 % 1_000_000;
				if let Ok(route) = get_route(&payer, &params, &graph.read_only(), Some(&[&first_hop]), amt, 42, &DummyLogger{}, &scorer, &random_seed_bytes) {
					routes.push(route);
					route_endpoints.push((first_hop, params, amt));
					continue 'load_endpoints;
				}
			}
		}

		// ...and seed the scorer with success and failure data...
		for route in routes {
			let amount = route.get_total_amount();
			if amount < 250_000 {
				for path in route.paths {
					scorer.payment_path_successful(&path.iter().collect::<Vec<_>>());
				}
			} else if amount > 750_000 {
				for path in route.paths {
					let short_channel_id = path[path.len() / 2].short_channel_id;
					scorer.payment_path_failed(&path.iter().collect::<Vec<_>>(), short_channel_id);
				}
			}
		}

		// Because we've changed channel scores, its possible we'll take different routes to the
		// selected destinations, possibly causing us to fail because, eg, the newly-selected path
		// requires a too-high CLTV delta.
		route_endpoints.retain(|(first_hop, params, amt)| {
			get_route(&payer, params, &graph.read_only(), Some(&[first_hop]), *amt, 42, &DummyLogger{}, &scorer, &random_seed_bytes).is_ok()
		});
		route_endpoints.truncate(100);
		assert_eq!(route_endpoints.len(), 100);

		// ...then benchmark finding paths between the nodes we learned.
		let mut idx = 0;
		bench.iter(|| {
			let (first_hop, params, amt) = &route_endpoints[idx % route_endpoints.len()];
			assert!(get_route(&payer, params, &graph.read_only(), Some(&[first_hop]), *amt, 42, &DummyLogger{}, &scorer, &random_seed_bytes).is_ok());
			idx += 1;
		});
	}
}
