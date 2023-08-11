//! Utilities that take care of running lightning networks payment channel probing as server

extern crate lightning_rapid_gossip_sync;
use async_channel::{Sender, Receiver};
use bitcoin::secp256k1::PublicKey;
use lightning::events::{Event, PathFailure};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync, NodeId, ReadOnlyNetworkGraph, NodeInfo, ChannelInfo};
use lightning::routing::utxo::UtxoLookup;
use lightning::routing::router::{PaymentParameters, RouteParameters, InFlightHtlcs, Path, build_route_from_hops};
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters, Score, WriteableScore};
use lightning::util::logger::Logger;
use lightning_rapid_gossip_sync::RapidGossipSync;
use rand::Rng;
use tokio::sync::Mutex;

use core::ops::Deref;
use core::time::Duration;
use std::cell::{RefCell, RefMut};
use std::cmp::min;
use std::collections::HashMap;
use std::sync::Arc;


/// Utilities that take care of running lightning networks payment channel probing as server 
///
/// Lightning-background-prober takes care of probing the lightning Networks, payment channels 
/// for better payment path planning and scoring of payment channels. 
/// workings :
///
/// #	Creating two MPSC queue with [’tokio::sync::mpsc’] for [’future_probes’] and [’inflight probes’]
/// #	Two MPSC are required all server will be multithreaded, so for central queuing, 
/// 	and probe <Result> will be asynchronous, so for [’EventHandler’]
/// #	Serving data to [’lightning::routing::scoring::ProbabilisticScorer’]
///
/// Note ::
///
///	#	At given time there will be fixed number of inflight probes, 
///		and will not overwhelm the lightning network

/// Either [`P2PGossipSync`] or [`RapidGossipSync`].
pub enum GossipSync<
	P: Deref<Target = P2PGossipSync<G, U, L>>,
	R: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	U: Deref,
	L: Deref,
>
where U::Target: UtxoLookup, L::Target: Logger {
	/// Gossip sync via the lightning peer-to-peer network as defined by BOLT 7.
	P2P(P),
	/// Rapid gossip sync from a trusted server.
	Rapid(R),
	/// No gossip sync.
	None,
}

impl<
	P: Deref<Target = P2PGossipSync<G, U, L>>,
	R: Deref<Target = RapidGossipSync<G, L>>,
	G: Deref<Target = NetworkGraph<L>>,
	U: Deref,
	L: Deref,
> GossipSync<P, R, G, U, L>
where U::Target: UtxoLookup, L::Target: Logger {
	fn network_graph(&self) -> Option<&G> {
		match self {
			GossipSync::P2P(gossip_sync) => Some(gossip_sync.network_graph()),
			GossipSync::Rapid(gossip_sync) => Some(gossip_sync.network_graph()),
			GossipSync::None => None,
		}
	}

	fn prunable_network_graph(&self) -> Option<&G> {
		match self {
			GossipSync::P2P(gossip_sync) => Some(gossip_sync.network_graph()),
			GossipSync::Rapid(gossip_sync) => {
				if gossip_sync.is_initial_sync_complete() {
					Some(gossip_sync.network_graph())
				} else {
					None
				}
			},
			GossipSync::None => None,
		}
	}
}

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<P: Deref<Target = P2PGossipSync<G, U, L>>, G: Deref<Target = NetworkGraph<L>>, U: Deref, L: Deref>
	GossipSync<P, &RapidGossipSync<G, L>, G, U, L>
where
	U::Target: UtxoLookup,
	L::Target: Logger,
{
	/// Initializes a new [`GossipSync::P2P`] variant.
	pub fn p2p(gossip_sync: P) -> Self {
		GossipSync::P2P(gossip_sync)
	}
}

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<'a, R: Deref<Target = RapidGossipSync<G, L>>, G: Deref<Target = NetworkGraph<L>>, L: Deref>
	GossipSync<
		&P2PGossipSync<G, &'a (dyn UtxoLookup + Send + Sync), L>,
		R,
		G,
		&'a (dyn UtxoLookup + Send + Sync),
		L,
	>
where
	L::Target: Logger,
{
	/// Initializes a new [`GossipSync::Rapid`] variant.
	pub fn rapid(gossip_sync: R) -> Self {
		GossipSync::Rapid(gossip_sync)
	}
}

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<'a, L: Deref>
	GossipSync<
		&P2PGossipSync<&'a NetworkGraph<L>, &'a (dyn UtxoLookup + Send + Sync), L>,
		&RapidGossipSync<&'a NetworkGraph<L>, L>,
		&'a NetworkGraph<L>,
		&'a (dyn UtxoLookup + Send + Sync),
		L,
	>
where
	L::Target: Logger,
{
	/// Initializes a new [`GossipSync::None`] variant.
	pub fn none() -> Self {
		GossipSync::None
	}
}

fn handle_network_graph_update<L: Deref>(
	network_graph: &NetworkGraph<L>, event: &Event
) where L::Target: Logger {
	if let Event::PaymentPathFailed {
		failure: PathFailure::OnPath { network_update: Some(ref upd) }, .. } = event
	{
		network_graph.handle_network_update(upd);
	}
}

//******************************************************************************************************************************

const NUM_THREADS: u64 = 1;
const NUM_INFLIGHT_PROBES: u64 = 1;
const NUM_CHANNEL_CAPACITY: u64 = 1;
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_FREQUENCY: Duration = Duration::from_secs(60);
const PROBE_FREQUENCY_JITTER: Duration = Duration::from_secs(10);

const FINAL_VALUE_MSAT: u64 = 1000;
const OUR_NODE_PUBKEY : bitcoin::secp256k1::PublicKey; // Need to be defined by user (maybe from config file)

// Will return a Vec<(NodeId,NodeInfo)> of nodes sorted by Number Of Channels
fn network_graph_sorted_with_respect_to_num_channels(network_graph: &ReadOnlyNetworkGraph) -> Vec<(NodeId,NodeInfo)> {

	let node_iter = network_graph.nodes().unordered_iter();
	let mut state: Vec<(NodeId,NodeInfo)> = Vec::new();
	
	for i in node_iter {
		let channel = Deref::deref(&i.1).channels.len();
		state.push((*i.0,*i.1));
	}
	state.sort_by(|(node_id_a, node_info_a), (node_id_b, node_info_b)| {
        node_info_b.channels.len().cmp(&node_info_a.channels.len())
    });

	return state;
}

// Will return top_one_percent_nodes of nodes sorted by Number Of Channels
fn top_one_percent_nodes (network_graph: &ReadOnlyNetworkGraph,sorted_node: Vec<(NodeId,NodeInfo)> ) -> Vec<(NodeId,NodeInfo)> {

	let mut temp: u64 = 0;
	let mut temp_index: Vec<(NodeId,NodeInfo)> = Vec::new();
	let one_percent = (sorted_node.len()/100) as i64;

	for i in 0..one_percent {
		temp_index.push(sorted_node[i as usize]);
	}
	return temp_index;
}

//Random seed generator
fn generate_random_seed_bytes () -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut seed_bytes: [u8; 32] = [0; 32];
    rng.fill(&mut seed_bytes);
    return seed_bytes;
}

//Random final_cltv_expiry_delta generator
fn random_final_cltv_expiry_delta_generator () -> u32 {
	let mut rng = rand::thread_rng();
    let random_number: u32 = rng.gen();
	return random_number;
}

//It will use DefaultRouter to find a path to target_pubkey
fn initial_path_builder (network_graph: &NetworkGraph<L>, target_pubkey: PublicKey, final_value_mast :u64 ) -> Path {

	let payment_params = PaymentParameters::from_node_id(target_pubkey,random_final_cltv_expiry_delta_generator ());
	let route_params = RouteParameters{
		payment_params: payment_params,
		final_value_msat: final_value_mast};
	
	let logger = lightning::util::test_utils::TestLogger::new();

	let params = ProbabilisticScoringFeeParameters::default();
	let decay_params = ProbabilisticScoringDecayParameters::default();
	let scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
	let scorer_param:ScoreParams;
	
	let random_seed_bytes: [u8; 32] = generate_random_seed_bytes();
	
	let router = lightning::routing::router::DefaultRouter::new(network_graph,logger,random_seed_bytes,scorer,scorer_param);
	let route = router.find_route(&OUR_NODE_PUBKEY, &route_params, &InFlightHtlcs::new(), None);
	let path = route.unwrap().paths[0].clone();
	return path;
} 

//Will convert Path into Box<[bitcoin::secp256k1::PublicKey]>
fn path_parser (path: Path) -> Box<[bitcoin::secp256k1::PublicKey]> {
	let vec_pubkeys = path.hops.into_iter().map(|hop| hop.pubkey).collect::<Vec<bitcoin::secp256k1::PublicKey>>();
	let publickey: Box<[bitcoin::secp256k1::PublicKey]> = vec_pubkeys.into_boxed_slice();

	return publickey;
}	

//Will return a path using build_route_from_hops
fn path_builder_for_probe (hops: Box<[bitcoin::secp256k1::PublicKey]>, network_graph: &NetworkGraph<L>, target_pubkey: PublicKey, final_value_mast :u64) -> Path {

	let payment_params = PaymentParameters::from_node_id(target_pubkey,random_final_cltv_expiry_delta_generator ());
	let route_params = RouteParameters{
		payment_params: payment_params,
		final_value_msat: final_value_mast};
	
	let logger = lightning::util::test_utils::TestLogger::new();
	let random_seed_bytes: [u8; 32] = generate_random_seed_bytes();

	let route = build_route_from_hops(&OUR_NODE_PUBKEY, &hops, &route_params, network_graph, &logger, &random_seed_bytes);
	
	return route.unwrap().paths[0].clone();
}

//Will return Sorted Vec of channel_capacity in given Path 
fn sorted_channel_liquidity_in_path(network_graph:ReadOnlyNetworkGraph, path: Path) -> Vec<Option<u64>> {

	let mut vec: Vec<Option<u64>> = Vec::new();
	let hops = path.hops;
		for i in hops {
			let scid = i.short_channel_id;
			let liquidity = network_graph.channel(scid).unwrap().capacity_sats;
			vec.push(liquidity);
		}

		vec.sort_by(|a, b| {
			match (a, b) {
				(Some(x), Some(y)) => x.cmp(y),
				(None, Some(_)) => std::cmp::Ordering::Greater,
				(Some(_), None) => std::cmp::Ordering::Less,
				(None, None) => std::cmp::Ordering::Equal,
			}
		});
	
	return vec;
}

//Will return Sorted Vec of htlc_max in given Path
fn sorted_htlc_max_in_path (path: Path, channel_info: ChannelInfo) -> Vec<u64> {
	let mut htlcs_max:Vec<u64> = Vec::new();
	for i in path.hops {
		let nodeid = NodeId::from_pubkey(&i.pubkey);
		let htlc = channel_info.as_directed_to(&nodeid).unwrap().0.htlc_maximum_msat();
		htlcs_max.push(htlc);
	}
	htlcs_max.sort();
	return htlcs_max;
}

//Main Probing Persistent Function
fn value_map () -> Arc<Mutex<HashMap<Path,Vec<(Option<bool>,u64)>>>> {
	let value_map: Arc<Mutex<HashMap<Path,Vec<(Option<bool>,u64)>>>> = Arc::new(Mutex::new(HashMap::new()));
	return value_map;
}

//Value selector for probing (Uses binary search method)
fn value_selector (path: Path, channel_info: ChannelInfo, network_graph:ReadOnlyNetworkGraph, mut path_list:HashMap<Path,Vec<(Option<bool>,u64)>>, htlc_list: Vec<u64>, liquidity_list: Vec<Option<u64>>) -> u64 {
	let temp = path_list.get(&path);
	match temp {
		Some(x) => {
			let len = x.len();
			if x[len-1].0.unwrap() == true {
				return 2*(x[len-1].1);
			}
			else {
				return (0.5*(x[len-1].1 as f64)).floor() as u64;
			}
		}
	
		None => {
			let v = min(htlc_list[0], liquidity_list[0].unwrap());
			let mut vec:Vec<(Option<bool>,u64)> = Vec::new();
			vec.push((None,v));
			path_list.insert(path, vec);
			return min(htlc_list[0], liquidity_list[0].unwrap());}
	}
}

//Event Handler for probing
fn event_handler<'a, S: 'static + Deref<Target = SC> + Send + Sync, SC: 'a + WriteableScore<'a>>(
	scorer: &'a S, event: &Event
) -> bool {
	let mut score = scorer.lock();
	match event {
		Event::ProbeSuccessful { path, .. } => {
			score.probe_successful(path);
		},
		Event::ProbeFailed { path, short_channel_id: Some(scid), .. } => {
			score.probe_failed(path, *scid);
		},
		_ => return false,
	}
	true
}

//async_channel for Path
fn initial_path_async_channel (size: usize) -> (Sender<Path>, Receiver<Path>) {
	let (tx, rx) = async_channel::bounded(size);
	return (tx, rx);
}

//async_channel for Final Path for send_probe method
fn final_async_channel (size: usize) -> (Sender<Path>, Receiver<Path>) {
	let (tx, rx) = async_channel::bounded(size);
	return (tx, rx);
}