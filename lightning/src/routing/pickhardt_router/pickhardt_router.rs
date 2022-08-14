#![allow(missing_docs)]
// TODO: Handle base fee > 0
// TODO: Handle htlc_min_msat > 1000 (>0???)
// TODO: Handle CTLV
// TODO: In flight HTLC

use std::{ops::Deref, collections::{HashMap, HashSet}, sync::Arc, convert::TryInto};
const MAX_VALUE_MSAT: u64 = 2100000000000000000;
use bitcoin::secp256k1::PublicKey;
use routing::{scoring::Score, gossip::{NetworkGraph, NodeId}, router::{RouteParameters, Route, RouteHop, PaymentParameters}};
use util::logger::Logger;
use ln::{PaymentHash, channelmanager::{ChannelDetails, self}, msgs::{LightningError, ErrorAction}, features::{Features, NodeFeatures, ChannelFeatures}};
use routing::pickhardt_router::min_cost_lib::{self,OriginalEdge};

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

pub fn find_route<L: Deref, GL: Deref, S: Score>(
	our_node_pubkey: &PublicKey, route_params: &RouteParameters,
	network_graph: &NetworkGraph<GL>, first_hops: Option<&[&ChannelDetails]>, logger: L,
	scorer: &S) -> Result<Route, LightningError>
where L::Target: Logger, GL::Target: Logger {

	let payee_pubkey=route_params.payment_params.payee_pubkey;

	// Basic checks are the same as with the Dijstra routing algorithm.
    let our_node_id=NodeId::from_pubkey(&our_node_pubkey);
    let payee_node_id=NodeId::from_pubkey(&payee_pubkey);
    let value_msat=route_params.final_value_msat;
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
    let payment_params=&route_params.payment_params;

    let final_cltv_expiry_delta = route_params.final_cltv_expiry_delta;
	if payment_params.max_total_cltv_expiry_delta <= final_cltv_expiry_delta {
		return Err(LightningError{err: "Can't find a route where the maximum total CLTV expiry delta is below the final CLTV expiry.".to_owned(), action: ErrorAction::IgnoreError});
	}
	if payment_params.max_path_count == 0 {
		return Err(LightningError{err: "Can't find a route with no paths allowed.".to_owned(), action: ErrorAction::IgnoreError});
	}

    if !should_allow_mpp(payment_params, &network_graph, payee_node_id) {
        return Err(LightningError{err: "Payee node doesn't support MPP.".to_owned(),
            action: ErrorAction::IgnoreError});
    }

	log_trace!(logger, "Searching for a Pickhardt type route from payer {} to payee {} with MPP and {} first hops {}overriding the network graph", our_node_pubkey,
		payment_params.payee_pubkey,
		first_hops.map(|hops| hops.len()).unwrap_or(0), if first_hops.is_some() { "" } else { "not " });

	let mut edges:Vec<OriginalEdge> =Vec::new();  // enumerated channels.
	let mut vidx:HashMap<NodeId,usize> =HashMap::new();  // NodeId -> enumerated node id
	let mut nodes:Vec<(NodeId,NodeFeatures)>=Vec::new();  // enumerated node id -> NodeId
	let mut channel_meta_data:Vec<u64>=Vec::new();  // enumerated channel -> short channel id
	let mut short_channel_ids_set:HashSet<u64>=HashSet::new();  // set of short channel ids
	let our_node=NodeId::from_pubkey(&our_node_pubkey);
	let s=add_or_get_node(&mut vidx, our_node, &default_node_features(), &mut nodes);

	if let Some(lightning_error) =
			extract_first_hops_from_payer_node(&mut channel_meta_data, &mut short_channel_ids_set,
				first_hops, our_node_pubkey, &mut vidx, &mut nodes, &mut edges) {
		return Err(lightning_error);
	}
	if edges.is_empty() {
		return Err(LightningError{err: "Cannot route when there are no outbound routes away from us".to_owned(),
		action: ErrorAction::IgnoreError});
	}

	extract_public_channels_from_network_graph(network_graph, &mut channel_meta_data, &mut short_channel_ids_set,
		 &mut vidx, &mut nodes, &mut edges);

	if let Some(value) = add_hops_to_payee_node_from_route_hints(
		&mut channel_meta_data, &mut short_channel_ids_set,
		payment_params, payee_node_id, &mut edges, &mut vidx, &mut nodes) {
    	return value;
	}

	let payee_node=NodeId::from_pubkey(&payee_pubkey);
	let t=*vidx.get(&payee_node).unwrap();
	min_cost_lib::min_cost_flow(nodes.len(), s, t, value_msat as i32,
		100000000, &mut edges,
		10);
	// Build paths from min cost flow;
	let paths = flow_to_paths( &edges, s, t, nodes.len());
	println!("paths: {:#?}", paths);
	// Converts paths to hops.
	let mut route_paths:Vec<Vec<RouteHop>>=Vec::new();
	for path in paths {
		let mut route_path:Vec<RouteHop>=Vec::new();
		let mut sum_fee_msat=0;
		for idx in &path.1 {
			let short_channel_id=channel_meta_data[*idx];
			let vnode=&nodes[edges[*idx].v];
			let node_features=&vnode.1;
			let channel_features=ChannelFeatures::empty();  // TODO: create
			let fee_msat=if *idx==*path.1.last().unwrap() { path.0-sum_fee_msat }
								else {path.0*edges[*idx].cost as u32/1000000 as u32};
			sum_fee_msat+=fee_msat;
			let cltv_expiry_delta:u32=0;  // TODO: add/compute

			route_path.push(RouteHop {
				pubkey: PublicKey::from_slice(vnode.0.as_slice()).unwrap(),
				short_channel_id: short_channel_id,
				fee_msat : fee_msat as u64,  cltv_expiry_delta : cltv_expiry_delta,
				node_features: node_features.clone(),
			channel_features: channel_features});
		}
		route_paths.push(route_path);
	};
	let r=Route {paths: route_paths, payment_params: Some(payment_params.clone()) };
	return Ok(r);
}

fn add_hops_to_payee_node_from_route_hints(channel_meta_data: &mut Vec<u64>, short_channel_ids_set: &mut HashSet<u64>,
	payment_params: &PaymentParameters,
	payee_node_id: NodeId, edges: &mut Vec<OriginalEdge>, vidx: &mut HashMap<NodeId, usize>,
	nodes: &mut Vec<(NodeId,NodeFeatures)>) -> Option<Result<Route, LightningError>> {
    for route in payment_params.route_hints.iter() {
		    let mut last_node_id=payee_node_id;
		    for hop in route.0.iter().rev() {
			    let src_node_id=NodeId::from_pubkey(&hop.src_node_id);
			    if src_node_id == payee_node_id {
				    return Some(Err(LightningError{err: "Route hint cannot have the payee as the source.".to_owned(), action: ErrorAction::IgnoreError}));
			    }
			    if hop.fees.base_msat > 0 || hop.htlc_maximum_msat.is_none() {
				    continue;
			    }

			    edges.push(OriginalEdge {
				    u: add_or_get_node(vidx, src_node_id, &default_node_features(), nodes),
				    v: add_or_get_node(vidx, last_node_id, &default_node_features(), nodes),
				    capacity: hop.htlc_maximum_msat.unwrap() as i32,
				    cost: hop.fees.proportional_millionths as i32,
				    flow: 0,
				    guaranteed_liquidity: 0});  // TODO: Ask whether the liquidity for the last hop is guaranteed.
			    last_node_id=src_node_id;
		    }
	    }
    None
}

fn extract_first_hops_from_payer_node(channel_meta_data: &mut Vec<u64>, short_channel_ids_set: &mut HashSet<u64>, first_hops: Option<&[&ChannelDetails]>,
	our_node_pubkey: &PublicKey,
	 vidx: &mut HashMap<NodeId, usize>, nodes: &mut Vec<(NodeId, NodeFeatures)>,
	edges: &mut Vec<OriginalEdge>) -> Option<LightningError> {
	if first_hops.is_none() {
		return Some(LightningError {err: "No first hops provided".to_owned(),
			action: ErrorAction::IgnoreError});
	}
	let hops=first_hops.unwrap();
    for chan in hops {
		if chan.get_outbound_payment_scid().is_none() {
			panic!("first_hops should be filled in with usable channels, not pending ones");
		}
		if chan.counterparty.node_id == *our_node_pubkey {
			return Some(LightningError{
				err: "First hop cannot have our_node_pubkey as a destination.".to_owned(),
				action: ErrorAction::IgnoreError});
		}
		let other_node_idx= add_or_get_node(vidx,
				NodeId::from_pubkey(&chan.counterparty.node_id),
				&default_node_features(),
				 nodes);
		edges.push(OriginalEdge { u: 0, v: other_node_idx,
			capacity: chan.outbound_capacity_msat as i32,
			cost: 0, flow: 0,
			guaranteed_liquidity:chan.outbound_capacity_msat as i32 });
	}
    None
}


fn should_allow_mpp<L:Deref>(payment_params: &PaymentParameters,
	network_graph: &NetworkGraph<L>, payee_node_id: NodeId) -> bool
	where L::Target : Logger {
	// Allow MPP only if we have a features set from somewhere that indicates the payee supports
	// it. If the payee supports it they're supposed to include it in the invoice, so that should
	// work reliably.
	let allow_mpp = if payment_params.max_path_count == 1 {
			false
		} else if let Some(features) = &payment_params.features {
			features.supports_basic_mpp()
		} else if let Some(node) = network_graph.read_only().nodes().get(&payee_node_id) {
			if let Some(node_info) = node.announcement_info.as_ref() {
				node_info.features.supports_basic_mpp()
			} else { false }
		} else { false };
	allow_mpp
}

fn extract_public_channels_from_network_graph<L:Deref>(
	network_graph : &NetworkGraph<L>, channel_meta_data: &mut Vec<u64>, short_channel_ids_set: &mut HashSet<u64>,
	 vidx: &mut HashMap<NodeId, usize>, nodes: &mut Vec<(NodeId,NodeFeatures)>, edges: &mut Vec<OriginalEdge>) 
	 where L::Target : Logger  {
    for channel in network_graph.read_only().channels() {
		    if short_channel_ids_set.contains(channel.0) {
			    continue;
		    }
		    let info=channel.1;
			let mut node_features=default_node_features();
			if let Some(unode)=network_graph.read_only().node(&info.node_one) {
				if let Some(ai)=&unode.announcement_info {
					node_features=ai.features.clone();
				}
			}
			let u = add_or_get_node(vidx, info.node_one, &node_features, nodes);

			let mut node_features=default_node_features();
			if let Some(unode)=network_graph.read_only().node(&info.node_two) {
				if let Some(ai)=&unode.announcement_info {
					node_features=ai.features.clone();
				}
			}
			let v = add_or_get_node(vidx, info.node_two, &node_features, nodes);
		    if let Some(ot)=&info.one_to_two {
			    if ot.fees.base_msat==0 {
				    edges.push(OriginalEdge {u, v, capacity:info.capacity_sats.unwrap_or(0) as i32,
					    cost:ot.fees.proportional_millionths as i32,
					    flow: 0, guaranteed_liquidity: 0})
			    }
		    }
		    if let Some(to)=&info.two_to_one {
			    if to.fees.base_msat==0 {
				    edges.push(OriginalEdge {u:v, v:u, capacity:info.capacity_sats.unwrap_or(0) as i32,
					    cost:to.fees.proportional_millionths as i32,
					    flow: 0, guaranteed_liquidity: 0})
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
    let mut edges_from:Vec<Vec<usize>> =Vec::new();
    for _ in 0..n { edges_from.push(Vec::new())};
    for edge_idx in 0..edges.len() {
		    edges_from[edges[edge_idx].u].push(edge_idx);
	    }
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
					let edge=&edges[*edge_idx];
				    if edge.v != s && parent[edge.v] == n {
					    parent[edge.v]=u;
						parent_edge_idx[edge.v]=Some(edge_idx);
					    capacity[edge.v]=edge.capacity.try_into().unwrap();
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
		    path.reverse();
		    paths.push((c, path));
	    }
    paths
}
