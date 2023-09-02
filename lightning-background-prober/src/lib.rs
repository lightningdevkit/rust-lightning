//! Utilities that take care of running lightning networks payment channel probing as server
#![allow(warnings)]

extern crate lightning_rapid_gossip_sync;
use async_channel::{Sender, Receiver};
use bitcoin::PublicKey;
use lightning::events::{Event, PathFailure};
use lightning::ln::PaymentHash;
use lightning::ln::channelmanager::{PaymentId, PaymentSendFailure};
use lightning::ln::functional_test_utils::Node;
use lightning::util::ser::Writer;
use lightning::util::test_utils::TestLogger;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync, NodeId, ReadOnlyNetworkGraph, NodeInfo, ChannelInfo, DirectedChannelInfo};
use lightning::routing::utxo::UtxoLookup;
use lightning::routing::router::{PaymentParameters, RouteParameters, InFlightHtlcs, Path, build_route_from_hops, DefaultRouter, Router};
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters, FixedPenaltyScorer, LockableScore};
use lightning::util::indexed_map::IndexedMap;
use lightning::util::logger::{Logger, self, Record};
use lightning_rapid_gossip_sync::RapidGossipSync;
use rand::Rng;
use tokio::sync::Mutex;
use core::ops::Deref;
use core::time::Duration;
use std::cmp::min;
use std::fs::File;
use std::str::FromStr;
use std::sync::Arc;
use std::{thread, clone, fs};
use chrono::Utc;
//use std::sync::Mutex;
/// Utilities for probing lightning networks payment channel
/******************************************************************************************************************************************************************* */
//Logger

pub(crate) struct FilesystemLogger {
	data_dir: String,
}
impl FilesystemLogger {
	pub(crate) fn new(data_dir: String) -> Self {
		let logs_path = format!("{}/logs", data_dir);
		fs::create_dir_all(logs_path.clone()).unwrap();
		Self { data_dir: logs_path }
	}
}
impl Logger for FilesystemLogger {
	fn log(&self, record: &Record) {
		let raw_log = record.args.to_string();
		let log = format!(
			"{} {:<5} [{}:{}] {}\n",
			// Note that a "real" lightning node almost certainly does *not* want subsecond
			// precision for message-receipt information as it makes log entries a target for
			// deanonymization attacks. For testing, however, its quite useful.
			Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
			record.level.to_string(),
			record.module_path,
			record.line,
			raw_log
		);
		let logs_file_path = format!("{}/logs.txt", self.data_dir.clone());
		fs::OpenOptions::new()
			.create(true)
			.append(true)
			.open(logs_file_path)
			.unwrap()
			.write_all(log.as_bytes())
			.unwrap();
	}
}

/******************************************************************************************************************************************************************** */
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

//Constants
//******************************************************************************************************************************

const NUM_THREADS: u64 = 1;
const NUM_INFLIGHT_PROBES: u64 = 1;
const DEFAULT_FINAL_VALUE_MSAT: u64 = 1000;
const DEFAULT_PROBE_VALUE_MSAT: u64 = 1000;
const DEFAULT_PENALTY_MSAT: u64 = 1000;

//structs for persisting probes
//**************************************************************************************************************************************************************** */

// The main struct initialization that persist all probes ever sent by server
// should be initalized at the start of the program

// Define a struct named ProbeValueMap that holds a mapping of NodeId to NodeRating.
// The mapping is wrapped in an Arc (atomic reference counter) and Mutex (mutual exclusion)
// to enable concurrent access and modification from multiple threads safely.
// should be initalized at the start of the program
struct ProbeValueMap<> {
	// Holds the mapping of NodeId to NodeRating.
	value_map: Arc<Mutex<IndexedMap<NodeId, NodeRating>>>,
}

// Implementation of the ProbeValueMap struct.
impl ProbeValueMap {
	// Constructor for creating a new instance of ProbeValueMap
	fn new () -> Self {
		Self {
			// Initialize the value_map field with an Arc-wrapped Mutex-protected IndexedMap.
			value_map: Arc::new(Mutex::new(IndexedMap::<NodeId,NodeRating>::new())),
		}
	}
}

// Node Rating: Used for each probed node to holds relevant information.

// Initialized by node_selector
struct NodeRating {
	node_id : NodeId,
		// Identifier for the node being rated
	path : Option<Path>,
		// List of paths associated with the node
	channel_information_coefficient: f64,
		// Coefficient representing channel information
		// No current implementation, to be add soon
	last_successful_probe: Option<ProbePersister>,
	last_probe: Option<ProbePersister>,
}

impl NodeRating {
	fn new (node_id: NodeId) -> Self {
		Self {
			node_id,
			path: None,
			channel_information_coefficient: 0.0,
			last_successful_probe: None,
			last_probe: None,
		}
	}
}

// Enumeration representing the status of a probe operation
#[derive(PartialEq)]
#[derive(Clone)]
enum ProbeStatus {
	Success, // The probe operation was successful
	Failure, // The probe operation failed
}

// Probe Persister: Used for each porbe to hold relevent information.

// Initialized by value_selector
// updated by final_path_builder_for_probe 
#[derive(Clone)]
struct ProbePersister{
	target_nodeid : NodeId,
		// Identifier of the targeted node for the probe
	value : Option<u64>,
		// Value of probes "FINAL_VALUE_MSAT"
	path : Option<Path>,
		// Path taken by probe
	probe_status : Option<ProbeStatus>, 
		// Probe status
	send_probe_return : Option<Result<(PaymentHash, PaymentId), PaymentSendFailure>>,
		//Return value from 'send_probe'
}

impl ProbePersister {
	// Constructor to create a new instance of `ProbePersister` with a target node ID
	fn new (target_nodeid: NodeId) -> Self {
		Self {
			target_nodeid,
			value: None,
			path: None,
			probe_status: None,
			send_probe_return: None,
		}
	}

    // Method to update the path
	// to be updated by value_selector
    fn update_path(&mut self, path: Path) {
        self.path = Some(path);
    }

	// Method to update the value associated with the probe
	// to be updated by value_selector
	fn update_value (&mut self, value: u64) {
		self.value = Some(value);
	}

    // Method to update the send probe return
	// to be updated by send_probe
    fn update_send_probe_return(&mut self, result: Result<(PaymentHash, PaymentId), PaymentSendFailure>) {
        self.send_probe_return = Some(result);
    }

	 // Method to update the probe status
	 // to be updated by event_handler
	 fn update_probe_status(&mut self, status: ProbeStatus) {
        self.probe_status = Some(status);
    }

}

//end of struct for persisting probes
//******************************************************************************************************************************************************** */
 
 // Struct for hold date from network_graph
struct NodesToProbe {
	nodes_to_probe: Vec<(NodeId,NodeInfo)>,
}

impl NodesToProbe{

	// Constructor for creating a new instance of NodesToProbe
	fn new () -> Self {
		NodesToProbe{
			nodes_to_probe: Vec::<(NodeId,NodeInfo)>::new(),
		 }
	}

	// Mutable method to add a NodeId and its NodeInfro to the nodes_to_probe field
    fn add_node(&mut self, node_id: &NodeId, node_info: &NodeInfo) {
        self.nodes_to_probe.push((*node_id, node_info.clone()));
    }

	// Will return a Vec<(NodeId,NodeInfo)> of nodes sorted by Number Of Channels
	fn network_graph_sorted_with_respect_to_num_channels(
		& mut self,
		read_network_graph: &ReadOnlyNetworkGraph<'_>,
	) -> &mut Self {

		let node_iter = read_network_graph.nodes().unordered_iter();
		for i in node_iter {
			self.add_node(i.0, i.1);
		}

		self.nodes_to_probe.sort_by(|(node_id_a, node_info_a), (node_id_b, node_info_b)| {
			node_info_b.channels.len().cmp(&node_info_a.channels.len())
		});
		self
	}

	// Will return top_one_percent_nodes of nodes sorted by Number Of Channels
	fn top_one_percent_nodes (& mut self) -> &mut Self {
		let num_element = self.nodes_to_probe.len() as f64;
		self.nodes_to_probe.get(0..((0.1*num_element).floor() as usize));
		self
	}
}

// Iterator for NodesToProbe
impl Iterator for NodesToProbe {
	type Item = (NodeId,NodeInfo);

	fn next(&mut self) -> Option<Self::Item> {
		self.nodes_to_probe.pop()
	}
}

// Clone for NodesToProbe
impl clone::Clone for NodesToProbe {
	fn clone(&self) -> Self {
		Self {
			nodes_to_probe: self.nodes_to_probe.clone(),
		}
	}
}

// Function returns most favorable nodes to probe
// Will return top_one_percent_nodes of nodes sorted by Number Of Channels per node
async fn node_selector(
	top_nodes: NodesToProbe,
	probe_value_map: &ProbeValueMap,
) -> Option<NodeId> {
	let mut value_map = probe_value_map.value_map.lock().await;
	for i in top_nodes {
		let node_id = i.0;
		let node_rating = value_map.get(&node_id);

		match node_rating {
			Some(node_rating) => {
				let last_probe = &node_rating.last_probe.clone().unwrap().probe_status;
				let last_successful_probe = &node_rating.last_successful_probe.clone().unwrap().probe_status;

				let x = *last_probe != None && *last_successful_probe != None;
				if x {
					return Some(node_id);
				}
				else {
					continue;
				}
			},

			None => {
				value_map.insert(node_id, NodeRating::new(node_id));
				return Some(node_id);
			}
		}
	}
	return None;
}

//Random seed generator (This has to be replaced by keys_manager::get_secure_random_bytes())
fn generate_random_seed_bytes () -> [u8; 32] {
	let mut rng = rand::thread_rng();
	let mut seed_bytes: [u8; 32] = [0; 32];
	rng.fill(&mut seed_bytes);
	return seed_bytes;
}

//Random final_cltv_expiry_delta generator (This has to be replaced with proper function for generating final_cltv_expiry_delta)
fn random_final_cltv_expiry_delta_generator () -> u32 {
	let mut rng = rand::thread_rng();
	let random_number: u32 = rng.gen();
	return random_number;
}


//capacity = balance(A) + balance(B)
//liquidity(A) = balance(A) – channel_reserve(A) – pending_HTLCs(A)
//Will return Sorted Vec of channel_capacity in given Path

// we are halving the channel capacity to get balance of A and B
// top nodes will try to directional balance, hence channel capcity is closet to real channel liquidity 
fn sorted_channel_capacity_in_path(
	network_graph: &ReadOnlyNetworkGraph, 
	path: Path
) -> Vec<(u64,Option<u64>)> {

	let mut vec: Vec<(u64,Option<u64>)> = Vec::new();
	let hops = path.hops;
		for i in hops {
			let scid = i.short_channel_id;
			let capacity_msat = network_graph.channel(scid).unwrap().capacity_sats;
			match capacity_msat {
				Some(x) => {
					let c = (0.5*(x as f64)).floor() as u64;
					vec.push((scid, Some(c)));
				}
				None => vec.push((scid, None)),
			}
		}

		vec.sort_by(|a, b| {
			match (a.1, b.1) {
				(Some(x), Some(y)) => x.cmp(&y),
				(None, Some(_)) => std::cmp::Ordering::Greater,
				(Some(_), None) => std::cmp::Ordering::Less,
				(None, None) => std::cmp::Ordering::Equal,
			}
		});

	return vec;
}

// Will return Sorted Vec of max_htlc in given Path
struct HtlcList {
    path: Path,
    max_htlc_list: Vec<(NodeId, u64)>,
}

impl HtlcList {

	// Constructor for creating a new instance of HtlcList
    fn new(path: Path) -> Self {
        Self {
            path,
            max_htlc_list: Vec::new(),
        }
    }

	// Mutable method to add a NodeId and its max_htlc to the max_htlc_list field
    fn sorted_htlc_in_path(&mut self, channel_info: &ChannelInfo) {
		
        for i in &self.path.hops {
            let nodeid = NodeId::from_pubkey(&i.pubkey);
            let max = channel_info.get_directional_info(0).unwrap().htlc_maximum_msat;
            self.max_htlc_list.push((nodeid, max));
        }
        
        self.max_htlc_list.sort_by(|(_, a), (_, b)| a.cmp(b)); // ascending ordering of MAX_HTLC
    }
}

//It will use DefaultRouter to find a path to target_pubkey
async fn initial_path_builder(
	network_graph: Arc<NetworkGraph<Arc<FilesystemLogger>>>,
	target_nodeid: NodeId,
	final_value_mast :u64,
	probe_value_map : &ProbeValueMap,
	payee_pubkey : bitcoin::secp256k1::PublicKey,
) -> Path {

	let mut value_map = probe_value_map.value_map.lock().await;
	let node_rating = value_map.get(&target_nodeid);
	match node_rating {
		Some(node_rating) => {
			let path = node_rating.path.clone().unwrap();
			return path;
		}

		None => {
			value_map.insert(target_nodeid, NodeRating::new(target_nodeid));
			let target_pubkey = target_nodeid.as_pubkey();
			match target_pubkey {
				Ok(target_pubkey) => {
					let payment_params = PaymentParameters::from_node_id(
						target_pubkey,
						random_final_cltv_expiry_delta_generator(),);

					let route_params = RouteParameters{
						payment_params,
						final_value_msat: final_value_mast};
					
					let logger = Arc::new(FilesystemLogger::new("".to_string()));
					let scoring_fee_params = ProbabilisticScoringFeeParameters::default();
					let decay_params = ProbabilisticScoringDecayParameters::default();
					let scorer = Arc::new(std::sync::Mutex::new(ProbabilisticScorer::new(decay_params, Arc::clone(&network_graph), Arc::clone(&logger))));
					
					let random_seed_bytes: [u8; 32] = generate_random_seed_bytes();
					
					let router = Arc::new(DefaultRouter::new(
						Arc::clone(&network_graph),
						Arc::clone(&logger),
						random_seed_bytes.clone(),
						scorer,
						scoring_fee_params,
					));

					let route  = router.find_route(
						&payee_pubkey, 
						&route_params, 
						None, 
						&InFlightHtlcs::new());
					
					match route {
						Ok(route) => {
							let path = route.paths[0].clone();
							return path;
						},
						Err(_) => panic!("No route found"), //to be handled later
					}
				},
				
				Err(_) => panic!("Invalid target_pubkey"),
			}
		}
	}
}

//Value selector for probing (Uses binary search method)
async fn value_selector (
	path: Path,
	nodeid: NodeId,
	probe_value_map: &ProbeValueMap,
	max_htlc_list: Vec<(NodeId,u64)>,
	capacity_list: Vec<(u64,Option<u64>)>,
) -> u64 {
	let mut value_map = probe_value_map.value_map.lock().await;
	let temp = value_map.get_mut(&nodeid);
	match temp {
		Some(node_rating) => { 

			let last_probe_status = node_rating.last_probe.clone().unwrap().probe_status;
			let last_successful_probe_status = node_rating.last_successful_probe.clone().unwrap().probe_status;
			

			if last_probe_status == None && last_successful_probe_status == None {
				let val = min(max_htlc_list[0].1, capacity_list[0].1.unwrap());
				
				node_rating.last_probe = Some(ProbePersister::new(nodeid));
				if let Some(mut last_probe) = node_rating.last_probe.clone() {
					last_probe.update_path(path);
					last_probe.update_value(val);
				}

				return val
			}

			else if last_probe_status == Some(ProbeStatus::Success) && last_successful_probe_status != None {
				let value = node_rating.last_probe.clone().unwrap().value.unwrap();
				let val = 2*value;
				
				node_rating.last_probe = Some(ProbePersister::new(nodeid));
				if let Some(mut last_probe) = node_rating.last_probe.clone() {
					last_probe.update_path(path);
					last_probe.update_value(val);
				}

				return val
			}

			else if last_probe_status == Some(ProbeStatus::Failure) && last_successful_probe_status != None {
				
				let last_successful_val = node_rating.last_successful_probe.clone().unwrap().value.unwrap();
				let value = node_rating.last_probe.clone().unwrap().value.unwrap();
				let val = (0.5*((value + last_successful_val) as f64)).floor() as u64;
				
				node_rating.last_probe = Some(ProbePersister::new(nodeid));
				if let Some(mut last_probe) = node_rating.last_probe.clone() {
					last_probe.update_path(path);
					last_probe.update_value(val);
				}

				return val
			}
			
			else if last_probe_status == Some(ProbeStatus::Failure) && last_successful_probe_status == None {
				let value = node_rating.last_probe.clone().unwrap().value.unwrap();
				let val = (0.5*((value) as f64)).floor() as u64;
				
				node_rating.last_probe = Some(ProbePersister::new(nodeid));
				if let Some(mut last_probe) = node_rating.last_probe.clone() {
					last_probe.update_path(path);
					last_probe.update_value(val);
				}

				return val
			}

			else if last_probe_status == Some(ProbeStatus::Success) && last_successful_probe_status == None {
				let value = node_rating.last_probe.clone().unwrap().value.unwrap();
				let val = 2*value;
				
				node_rating.last_probe = Some(ProbePersister::new(nodeid));
				if let Some(mut last_probe) = node_rating.last_probe.clone() {
					last_probe.update_path(path);
					last_probe.update_value(val);
				}

				return val
			}

			else {
				panic!("Node rating error")
			}
		}
    	None => panic!("Node rating error")
	}	
}

//Will convert Path into Box<[bitcoin::secp256k1::PublicKey]> for final_path_builder_for_probe
fn path_parser (path: Path) -> Box<[bitcoin::secp256k1::PublicKey]> {
	let vec_pubkeys = {
		path.
		hops.
		into_iter().
		map(|hop| hop.pubkey).
		collect::<Vec<bitcoin::secp256k1::PublicKey>>()
	};
	let publickey: Box<[bitcoin::secp256k1::PublicKey]> = vec_pubkeys.into_boxed_slice();
	return publickey;
}

//Will return a Final path for send_probe()
fn final_path_builder_for_probe <L: Logger + std::ops::Deref>(
	hops: Box<[bitcoin::secp256k1::PublicKey]>,
	network_graph: &NetworkGraph<L>,
	nodeid: NodeId,
	final_value_mast :u64,
	payee_pubkey : bitcoin::secp256k1::PublicKey,
) -> Path where <L as Deref>::Target: Logger {

	let target_pubkey = nodeid.as_pubkey().unwrap();
	let payment_params = PaymentParameters::from_node_id(
		target_pubkey,
		random_final_cltv_expiry_delta_generator());

	let route_params = RouteParameters{
		payment_params,
		final_value_msat: final_value_mast};

	let logger = lightning::util::test_utils::TestLogger::new();
	let random_seed_bytes: [u8; 32] = generate_random_seed_bytes();

	let route = build_route_from_hops(
		&payee_pubkey,
		&hops,
		&route_params,
		network_graph,
		&logger,
		&random_seed_bytes);

	return route.unwrap().paths[0].clone();
}

// main core runner for probing
//******************************************************************************************************************************************************** */

async fn start_probing <L : Logger + std::ops::Deref> (
	network_graph: &NetworkGraph<L>, 
	read_network_graph: &ReadOnlyNetworkGraph<'_>,
	channel_info: &ChannelInfo,
	graph: Arc<NetworkGraph<Arc<FilesystemLogger>>>,
	payee_pubkey : bitcoin::secp256k1::PublicKey,
) -> () where <L as Deref>::Target: Logger {

	let probe_value_map = ProbeValueMap::new();

	let _num_spawns = NUM_THREADS;
	let (s_top_nodes, r_top_nodes) = async_channel::bounded(2); 
	let (s_selected_node, r_selected_node) = async_channel::bounded(100); //should have size top_one_percent_nodes.len() - 1
	let (s_inital_path, r_inital_path) = async_channel::bounded(100);
	let (s_value, r_value) = async_channel::bounded(100); 
	let (s_final_path, _r_final_path) = async_channel::bounded(100);
	
	
	//taking network_graph as input and returning top one percent nodes
	network_graph_looper::<L>(read_network_graph, s_top_nodes);

	//running node selection
	node_selector_looper(r_top_nodes, s_selected_node, &probe_value_map);
	
	// making initial paths for selcted nodes
	initial_path_looper::<L>(r_selected_node,s_inital_path,Arc::clone(&graph), &probe_value_map, payee_pubkey);

	//runs value selection on initial paths
	value_selector_looper::<L>(r_inital_path, s_value, &read_network_graph,channel_info, &probe_value_map);

	//final path builder loop
	final_path_builder_for_probe_looper(r_value, network_graph, s_final_path,payee_pubkey);


	// tokio::spawn(async move {
	// 	probe_sender_looper(r_final_path).await
	// });

}

// loop over top_one_percent_nodes and push to channel
// should be only called once 
async fn network_graph_looper<L: std::ops::Deref> (
	network_graph_read: &ReadOnlyNetworkGraph<'_>,
	s_top_nodes: Sender<NodesToProbe> 
) -> () where <L as Deref>::Target: Logger {
	
	loop {
		let mut nodes_to_probe = NodesToProbe::new();
		nodes_to_probe.network_graph_sorted_with_respect_to_num_channels(network_graph_read).top_one_percent_nodes();
		
		s_top_nodes.send(nodes_to_probe).await;
		thread::sleep(Duration::from_secs(24 * 60 * 60)); //sleep for 24 hours
	}
}

// running node selection
// should be only called once 
async fn node_selector_looper(
	r_top_nodes: Receiver<NodesToProbe>, 
	s_selected_node: Sender<NodeId>, 
	probe_value_map : &ProbeValueMap
) -> () {

	let nodes = r_top_nodes.recv().await.unwrap(); //should not be consumed by this function
	loop {
		let node_to_probe = nodes.clone();
		let node = node_selector(node_to_probe, probe_value_map).await.unwrap();
		s_selected_node.send(node).await;
	}
}

// making initial paths for selcted nodes and push to channel
// can be scheduled for multiple threads
async fn initial_path_looper<L: std::ops::Deref> (
	r_selected_node: Receiver<NodeId>, 
	s_inital_path: Sender<(NodeId,Path)>, 
	network_graph: Arc<NetworkGraph<Arc<FilesystemLogger>>>,
	probe_value_map : &ProbeValueMap,
	payee_pubkey : bitcoin::secp256k1::PublicKey,
) -> () where <L as Deref>::Target: Logger {
	
	loop {
		let graph = Arc::new(network_graph.clone());
		let nodeid = r_selected_node.recv().await.unwrap();
		let path = initial_path_builder(
			Arc::clone(&network_graph), 
			nodeid, 
			DEFAULT_FINAL_VALUE_MSAT, 
			probe_value_map,
			payee_pubkey).await;
		s_inital_path.send((nodeid,path)).await;
	}
}

// runs value selection on initial paths and push to channel
// can be scheduled for multiple threads
async fn value_selector_looper<L: std::ops::Deref> (
	r_inital_path: Receiver<(NodeId,Path)>, 
	s_value: Sender<(NodeId,Path,u64)>, 
	read_network_graph: &ReadOnlyNetworkGraph<'_>,
	channel_info: &ChannelInfo, 
	probe_value_map : &ProbeValueMap
 ) -> () where <L as Deref>::Target: Logger {
	
	loop {
		let (nodeid, path) = r_inital_path.recv().await.unwrap();
		let capacity_list = sorted_channel_capacity_in_path(read_network_graph, path.clone());
		
		let mut max_htlc_list = HtlcList::new(path.clone());
		max_htlc_list.sorted_htlc_in_path(channel_info);
		let value = value_selector(
			path.clone(), 
			nodeid, 
			probe_value_map,
			max_htlc_list.max_htlc_list, 
			capacity_list)
			.await;

		s_value.send((nodeid, path, value)).await;
	}
}

// runs final path builder for probing and push to channel
// can be scheduled for multiple threads
async fn final_path_builder_for_probe_looper<L: std::ops::Deref + lightning::util::logger::Logger> (
	r_value: Receiver<(NodeId,Path,u64)>,
	network_graph: &NetworkGraph<L>,
	s_final_path: Sender<Path>,
	payee_pubkey : bitcoin::secp256k1::PublicKey,
) -> () where <L as Deref>::Target: Logger {
	
	loop {
		let (nodeid, path, value) = r_value.recv().await.unwrap();
		let path_parse = path_parser(path);
		let final_path = final_path_builder_for_probe(path_parse, network_graph, nodeid, value, payee_pubkey);

		s_final_path.send(final_path).await;
	}
}

// runs send_probe
// can be scheduled for multiple threads

// async fn probe_sender_looper(
// 	r_final_path: Receiver<Path>
// ) -> () {
// 	loop {
// 		let path = r_final_path.recv().await.unwrap();
// 		//let result = channel_manager.send_probe(path);
// 		//the result should generate the probe_persister 
// 	}
// }

//Tests
//******************************************************************************************************************************************************** */

