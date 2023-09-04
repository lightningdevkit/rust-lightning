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

	channel_information_coefficient: Option<f64>,
		// Coefficient representing channel information
		// No current implementation, to be add soon

	last_successful_probe: Option<ProbePersister>,
		// Holds the last successful probe information
		// need to be updated by Event Handler
	
	last_probe: Option<ProbePersister>,
		// Holds the last probe information
}

impl NodeRating {

	// Constructor to create a new instance of `NodeRating` with a node ID
	fn new (node_id: NodeId) -> Self {
		Self {
			node_id,
			path: None,
			channel_information_coefficient: None,
			last_successful_probe: None,
			last_probe: None,
		}
	}

	fn update_path(&mut self, path: Path) {
		self.path = Some(path);
	}

	fn update_last_successful_probe(&mut self, probe_persister: ProbePersister) {
		self.last_successful_probe = Some(probe_persister);
	}

	fn update_last_probe(&mut self, probe_persister: ProbePersister) {
		self.last_probe = Some(probe_persister);
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
#[derive(PartialEq)]
struct ProbePersister{
	// Identifier of the targeted node for the probe
	target_nodeid : NodeId,
	
	// Value of probes "FINAL_VALUE_MSAT"
	value : u64,
	
	// Path taken by probe
	path : Option<Path>,
	
	// Probe status
	probe_status : Option<ProbeStatus>, 

	// Return value from 'send_probe'	
	send_probe_return :Option<(PaymentHash, PaymentId)>,
}

impl ProbePersister {

	// Constructor to create a new instance of `ProbePersister` with a target node ID
	fn new (target_nodeid: NodeId, value: u64) -> Self {
		Self {
			target_nodeid,
			value,
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

	// // Method to update the value associated with the probe
	// // to be updated by value_selector
	// fn update_value (&mut self, value: u64) {
	// 	self.value = Some(value);
	// }

    // Method to update the send probe return
	// to be updated by send_probe
    fn update_send_probe_return(&mut self, payment_hash: PaymentHash, payment_id:PaymentId) {
        self.send_probe_return = Some((payment_hash, payment_id));
    }

	 // Method to update the probe status
	 // to be updated by event_handler
	 fn update_probe_status(&mut self, status: ProbeStatus) {
        self.probe_status = Some(status);
    }

}

//end of struct for persisting probes
//******************************************************************************************************************************************************** */
 
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
// Will return top_one_percent_nodes of nodes sorted by `Number Of Channels` per node
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
			//let capacity_msat = network_graph.channel(scid).unwrap().capacity_sats;
			let channel_info = network_graph.channel(scid);
			match channel_info {
				Some(channel_info) => {
					let capacity_msat = channel_info.capacity_sats;
					match capacity_msat {
						Some(x) => {
							let c = (0.5*(x as f64)).floor() as u64;
							vec.push((scid, Some(c)));
						}
						None => continue,
					}
				}
				None => continue,
			}
		}
		vec.sort_by(|(_, a), (_, b)| a.cmp(b)); // ascending ordering for channel_capcity in path

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
            let channel_update_info = channel_info.get_directional_info(0);
			match channel_update_info {
				Some(channel_update_info) => {
					let max_htlc = channel_update_info.htlc_maximum_msat;
					self.max_htlc_list.push((nodeid, max_htlc));
				}

				None => continue,
			}
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
						InFlightHtlcs::new());
					
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
	// It works on following principle's 
	// 1. If last probe was success -> value = 2 * last_probe 
	// 2. If last probe was fail and last_successful_probe has `Some(x)` -> value = 0.5*(last_succesful_probe + last_probe)
	// 3. If last probe was fail and last_successful_probe has `None` -> value = 0.5*(last_probe)
async fn value_selector (
	path: Path,
	target_nodeid: NodeId,
	probe_value_map: &ProbeValueMap,
	max_htlc_list: Vec<(NodeId,u64)>,
	capacity_list: Vec<(u64,Option<u64>)>,
) -> u64 {
	let mut value_map = probe_value_map.value_map.lock().await;
	let node_rating = value_map.get_mut(&target_nodeid);
	match node_rating {
		Some(node_rating) => { 
			
			let last_probe = node_rating.last_probe.clone();
			let last_successful_probe_status = node_rating.last_successful_probe.clone();
			// Case 1: probe_value_map.last_probe == None, probe_value_map.last_successful_probe == None
			match last_probe {
				Some(last_probe) => {
					
					let last_probe_status = last_probe.probe_status.clone();

					// Case 2: probe_value_map.last_probe == Some(ProbeStatus::Success), probe_value_map.last_successful_probe != None
					if last_probe_status == Some(ProbeStatus::Success) && last_successful_probe_status != None {
						let value = node_rating.last_probe.clone().unwrap().value;
						let val = 2*value;
						
						node_rating.last_probe = Some(ProbePersister::new(target_nodeid, val));
						if let Some(mut last_probe) = node_rating.last_probe.clone() {
							last_probe.update_path(path);
							//last_probe.update_value(val);
						}

						return val // to be changed to val
					}

					// Case 3: probe_value_map.last_probe == Some(ProbeStatus::Failure), probe_value_map.last_successful_probe != None
					else if last_probe_status == Some(ProbeStatus::Failure) && last_successful_probe_status != None {
						let last_successful_val = node_rating.last_successful_probe.clone().unwrap().value;
						let value = node_rating.last_probe.clone().unwrap().value;
						let val = (0.5*((value + last_successful_val) as f64)).floor() as u64;
						
						node_rating.last_probe = Some(ProbePersister::new(target_nodeid, val));
						if let Some(mut last_probe) = node_rating.last_probe.clone() {
							last_probe.update_path(path);
							//last_probe.update_value(val);
						}

						return val // to be changed to val
					}
					
					// Case 4: probe_value_map.last_probe == Some(ProbeStatus::Failure), probe_value_map.last_successful_probe == None
					else if last_probe_status == Some(ProbeStatus::Failure) && last_successful_probe_status == None {
						let value = node_rating.last_probe.clone().unwrap().value;
						let val = (0.5*((value) as f64)).floor() as u64;
						
						node_rating.last_probe = Some(ProbePersister::new(target_nodeid, val));
						if let Some(mut last_probe) = node_rating.last_probe.clone() {
							last_probe.update_path(path);
							//last_probe.update_value(val);
						}

						return val //to be changed to val
					}

					else {
						panic!("Error in value_selector logic") // to be changed later
					}
				}

				// If last_probe == None (This case can only occure for first probe) of a node
				None => {
					if let a = max_htlc_list.is_empty() {
						// only if max_htlc_list is empty and last_probe == None 
						// DEFAULT_FINAL_VALUE_MSAT = 1000
						return DEFAULT_FINAL_VALUE_MSAT; 
					}

					else {
						if let c = capacity_list.is_empty() {
							let val = max_htlc_list[0].1;
			
							node_rating.last_probe = Some(ProbePersister::new(target_nodeid, val));
							if let Some(mut last_probe) = node_rating.last_probe.clone() {
								last_probe.update_path(path);
							}

							return val
						}

						else {
							let b = capacity_list[0].1;
							match b {
								Some(b) => {
									let val = min(max_htlc_list[0].1, capacity_list[0].1.unwrap());
							
									node_rating.last_probe = Some(ProbePersister::new(target_nodeid, val));
									if let Some(mut last_probe) = node_rating.last_probe.clone() {
										last_probe.update_path(path);
									}
		
									return val
								}

								None => {
									let val = max_htlc_list[0].1;
			
									node_rating.last_probe = Some(ProbePersister::new(target_nodeid, val));
									if let Some(mut last_probe) = node_rating.last_probe.clone() {
										last_probe.update_path(path);
									}
		
									return val
								}
							}
						}
					}	
				}
			}
		}
		None => panic!("NodeRating not found in probe_value_map") // to be changed later // Panic! ("NodeRating not found in probe_value_map")
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

#[cfg(test)]
mod tests {
		use super::*;
		
		extern crate lightning;
		// use lightning::{ChannelLiquidity, HistoricalBucketRangeTracker, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters, ProbabilisticScorerUsingTime, util};
		use lightning::blinded_path::{BlindedHop, BlindedPath};
		use lightning::ln::features::Features;
use lightning::util;
		use lightning::util::config::UserConfig;

		use lightning::ln::channelmanager;
		use lightning::ln::msgs::{ChannelAnnouncement, ChannelUpdate, UnsignedChannelAnnouncement, UnsignedChannelUpdate};
		use	lightning::routing::gossip::{EffectiveCapacity, NetworkGraph, NodeId};
		use lightning::routing::router::{BlindedTail, Path, RouteHop};
		// use lightning::routing::scoring::{ChannelUsage, Score};
		use lightning::util::ser::{ReadableArgs, Writeable};
		use lightning::util::test_utils::{self, TestLogger};
		

		// use crate::lightning::routing::gossip::{NetworkGraph, NodeAlias, P2PGossipSync};
		// use crate::ln::features::{ChannelFeatures, NodeFeatures};
		// use crate::ln::msgs::{UnsignedChannelAnnouncement, ChannelAnnouncement, RoutingMessageHandler,
		// 	NodeAnnouncement, UnsignedNodeAnnouncement, ChannelUpdate, UnsignedChannelUpdate, MAX_VALUE_MSAT};
		// use crate::util::test_utils;
		//use crate::util::ser::Writeable;
		

		use bitcoin::blockdata::constants::genesis_block;
		use bitcoin::hashes::Hash;
		use bitcoin::hashes::sha256d::Hash as Sha256dHash;
		use bitcoin::network::constants::Network;
		use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
		use tokio::runtime;
		use core::time::Duration;
		use std::io;

		fn source_privkey() -> SecretKey {
			SecretKey::from_slice(&[42; 32]).unwrap()
		}
	
		fn target_privkey() -> SecretKey {
			SecretKey::from_slice(&[43; 32]).unwrap()
		}
		
		fn source_pubkey() -> PublicKey {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &source_privkey())
		}
	
		fn target_pubkey() -> PublicKey {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &target_privkey())
		}
	
		fn source_node_id() -> NodeId {
			NodeId::from_pubkey(&source_pubkey())
		}
	
		fn target_node_id() -> NodeId {
			NodeId::from_pubkey(&target_pubkey())
		}
	
		fn sender_privkey() -> SecretKey {
			SecretKey::from_slice(&[41; 32]).unwrap()
		}
	
		fn recipient_privkey() -> SecretKey {
			SecretKey::from_slice(&[45; 32]).unwrap()
		}
	
		fn sender_pubkey() -> PublicKey {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &sender_privkey())
		}
	
		fn recipient_pubkey() -> PublicKey {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &recipient_privkey())
		}
	
		fn sender_node_id() -> NodeId {
			NodeId::from_pubkey(&sender_pubkey())
		}
	
		fn recipient_node_id() -> NodeId {
			NodeId::from_pubkey(&recipient_pubkey())
		}
	
		fn network_graph(logger: &TestLogger) -> NetworkGraph<&TestLogger> {
			let mut network_graph = NetworkGraph::new(Network::Testnet, logger);
			add_channel(&mut network_graph, 42, source_privkey(), target_privkey());
			add_channel(&mut network_graph, 43, target_privkey(), recipient_privkey());
	
			network_graph
		}
		macro_rules! hash_to_message {
			($slice: expr) => {
				{
					#[cfg(not(fuzzing))]
					{
						::bitcoin::secp256k1::Message::from_slice($slice).unwrap()
					}
					#[cfg(fuzzing)]
					{
						match ::bitcoin::secp256k1::Message::from_slice($slice) {
							Ok(msg) => msg,
							Err(_) => ::bitcoin::secp256k1::Message::from_slice(&[1; 32]).unwrap()
						}
					}
				}
			}
		}

		fn add_channel(
			network_graph: &mut NetworkGraph<&TestLogger>, short_channel_id: u64, node_1_key: SecretKey,
			node_2_key: SecretKey
		) {
			let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
			let node_1_secret = &SecretKey::from_slice(&[39; 32]).unwrap();
			let node_2_secret = &SecretKey::from_slice(&[40; 32]).unwrap();
			let secp_ctx = Secp256k1::new();
			let unsigned_announcement = UnsignedChannelAnnouncement {
				features: Features::empty(),
				chain_hash: genesis_hash,
				short_channel_id,
				node_id_1: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_1_key)),
				node_id_2: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_2_key)),
				bitcoin_key_1: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_1_secret)),
				bitcoin_key_2: NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, &node_2_secret)),
				excess_data: Vec::new(),
			};
			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
			let signed_announcement = ChannelAnnouncement {
				node_signature_1: secp_ctx.sign_ecdsa(&msghash, &node_1_key),
				node_signature_2: secp_ctx.sign_ecdsa(&msghash, &node_2_key),
				bitcoin_signature_1: secp_ctx.sign_ecdsa(&msghash, &node_1_secret),
				bitcoin_signature_2: secp_ctx.sign_ecdsa(&msghash, &node_2_secret),
				contents: unsigned_announcement,
			};
			let chain_source: Option<&util::test_utils::TestChainSource> = None;
			network_graph.update_channel_from_announcement(
				&signed_announcement, &chain_source).unwrap();
			update_channel(network_graph, short_channel_id, node_1_key, 0, 1_000);
			update_channel(network_graph, short_channel_id, node_2_key, 1, 0);
		}
	
		fn update_channel(
			network_graph: &mut NetworkGraph<&TestLogger>, short_channel_id: u64, node_key: SecretKey,
			flags: u8, htlc_maximum_msat: u64
		) {
			let genesis_hash = genesis_block(Network::Testnet).header.block_hash();
			let secp_ctx = Secp256k1::new();
			let unsigned_update = UnsignedChannelUpdate {
				chain_hash: genesis_hash,
				short_channel_id,
				timestamp: 100,
				flags,
				cltv_expiry_delta: 18,
				htlc_minimum_msat: 0,
				htlc_maximum_msat,
				fee_base_msat: 1,
				fee_proportional_millionths: 0,
				excess_data: Vec::new(),
			};
			let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_update.encode()[..])[..]);
			let signed_update = ChannelUpdate {
				signature: secp_ctx.sign_ecdsa(&msghash, &node_key),
				contents: unsigned_update,
			};
			network_graph.update_channel(&signed_update).unwrap();
		}
	
		fn path_hop(pubkey: PublicKey, short_channel_id: u64, fee_msat: u64) -> RouteHop {
			let config = UserConfig::default();
			RouteHop {
				pubkey,
				node_features: Features::empty(),
				short_channel_id,
				channel_features: Features::empty(),
				fee_msat,
				cltv_expiry_delta: 18,
			}
		}
	
		fn payment_path_for_amount(amount_msat: u64) -> Path {
			Path {
				hops: vec![
					path_hop(source_pubkey(), 41, 1),
					path_hop(target_pubkey(), 42, 2),
					path_hop(recipient_pubkey(), 43, amount_msat),
				], blinded_tail: None,
			}
		}

		// As value selector has variour cases depending on last probe status and last successful probe status, following tests will assert all the cases
		
		// for first test we are puting htlc list as empty and capacity list as empty for edge cases
		// Case 1: probe_value_map.last_probe == None
		#[tokio::test(flavor = "multi_thread")]
		async fn value_selector_test_case_1() {
			let logger = TestLogger::new();
			let network_graph = network_graph(&logger);
			let read_network_graph = network_graph.read_only();
			let probe_value_map = ProbeValueMap::new();
			{
				let mut value_map = probe_value_map.value_map.lock().await;
				value_map.insert(target_node_id(), NodeRating::new(target_node_id()));
			};

			// let payee_pubkey = recipient_pubkey();
			let path = payment_path_for_amount(1000);
			let target_nodeid = target_node_id();
			let capacity_list = sorted_channel_capacity_in_path(&read_network_graph, path.clone());
			
			let mut max_htlc_list = Vec::<(NodeId, u64)>::new();
			let recipient_pubkey = recipient_node_id();
			let target_pubkey = target_node_id();
			
			let value = value_selector(
				path.clone(), 
				target_nodeid, 
				&probe_value_map,
				max_htlc_list, 
				capacity_list).await;
			
			assert_eq!(value, 1000);
		}
		
		
		#[tokio::test]
		// Case 2: probe_value_map.last_probe == Some(ProbeStatus::Success), probe_value_map.last_successful_probe != None
		async fn value_selector_test_case_2() {
			let logger = TestLogger::new();
			let network_graph = network_graph(&logger);
			let read_network_graph = network_graph.read_only();
			let probe_value_map = ProbeValueMap::new();
			let target_pubkey = target_node_id();
			{
				let mut value_map = probe_value_map.value_map.lock().await;
				value_map.insert(target_node_id(), NodeRating::new(target_pubkey.clone()));
			}
			
			{
				let mut value_map = probe_value_map.value_map.lock().await;
				let node_rating = value_map.get_mut(&target_node_id()).unwrap();
				node_rating.update_last_probe(ProbePersister::new(target_pubkey.clone(),1000));

				let mut last_probe_persister = node_rating.last_probe.as_mut().unwrap();
				last_probe_persister.update_probe_status(ProbeStatus::Success);

			}

			{
				let mut value_map = probe_value_map.value_map.lock().await;
				let node_rating = value_map.get_mut(&target_node_id()).unwrap();
				node_rating.update_last_successful_probe(ProbePersister::new(target_pubkey.clone(),1000));

				let mut last_successful_probe_persister = node_rating.last_successful_probe.as_mut().unwrap();
				last_successful_probe_persister.update_probe_status(ProbeStatus::Success);
			}

			// let payee_pubkey = recipient_pubkey();
			let path = payment_path_for_amount(1000);
			let target_nodeid = target_node_id();
			let capacity_list = sorted_channel_capacity_in_path(&read_network_graph, path.clone());
			
			let mut max_htlc_list = Vec::<(NodeId, u64)>::new();
			let recipient_pubkey = recipient_node_id();
			//let target_pubkey = target_node_id();

			max_htlc_list.push((recipient_pubkey, 200));
			max_htlc_list.push((target_pubkey, 201));

			let value = value_selector(
				path.clone(), 
				target_nodeid, 
				&probe_value_map,
				max_htlc_list, 
				capacity_list).await;
			
			assert_eq!(value, 2000);
		}

		#[tokio::test]
		// Case 3: probe_value_map.last_probe == Some(ProbeStatus::Failure), probe_value_map.last_successful_probe != None
		async fn value_selector_test_case_3() {
			let logger = TestLogger::new();
			let network_graph = network_graph(&logger);
			let read_network_graph = network_graph.read_only();
			let probe_value_map = ProbeValueMap::new();
			let target_pubkey = target_node_id();
			{
				let mut value_map = probe_value_map.value_map.lock().await;
				value_map.insert(target_node_id(), NodeRating::new(target_pubkey.clone()));
			}
			
			{
				let mut value_map = probe_value_map.value_map.lock().await;
				let node_rating = value_map.get_mut(&target_node_id()).unwrap();
				node_rating.update_last_probe(ProbePersister::new(target_pubkey.clone(),1000));

				let mut last_probe_persister = node_rating.last_probe.as_mut().unwrap();
				last_probe_persister.update_probe_status(ProbeStatus::Failure);

			}

			{
				let mut value_map = probe_value_map.value_map.lock().await;
				let node_rating = value_map.get_mut(&target_node_id()).unwrap();
				node_rating.update_last_successful_probe(ProbePersister::new(target_pubkey.clone(),500));

				let mut last_successful_probe_persister = node_rating.last_successful_probe.as_mut().unwrap();
				last_successful_probe_persister.update_probe_status(ProbeStatus::Success);
			}

			// let payee_pubkey = recipient_pubkey();
			let path = payment_path_for_amount(1000);
			let target_nodeid = target_node_id();
			let capacity_list = sorted_channel_capacity_in_path(&read_network_graph, path.clone());
			
			let mut max_htlc_list = Vec::<(NodeId, u64)>::new();
			let recipient_pubkey = recipient_node_id();
			//let target_pubkey = target_node_id();

			max_htlc_list.push((recipient_pubkey, 200));
			max_htlc_list.push((target_pubkey, 201));

			let value = value_selector(
				path.clone(), 
				target_nodeid, 
				&probe_value_map,
				max_htlc_list, 
				capacity_list).await;
			
			assert_eq!(value, 750);
		}

		#[tokio::test]
		// Case 4: probe_value_map.last_probe == Some(ProbeStatus::Failure), probe_value_map.last_successful_probe == None
		async fn value_selector_test_case_4() {
			let logger = TestLogger::new();
			let network_graph = network_graph(&logger);
			let read_network_graph = network_graph.read_only();
			let probe_value_map = ProbeValueMap::new();
			let target_pubkey = target_node_id();
			{
				let mut value_map = probe_value_map.value_map.lock().await;
				value_map.insert(target_node_id(), NodeRating::new(target_pubkey.clone()));
			}
			
			{
				let mut value_map = probe_value_map.value_map.lock().await;
				let node_rating = value_map.get_mut(&target_node_id()).unwrap();
				node_rating.update_last_probe(ProbePersister::new(target_pubkey.clone(),1000));

				let mut last_probe_persister = node_rating.last_probe.as_mut().unwrap();
				last_probe_persister.update_probe_status(ProbeStatus::Failure);

			}

			// let payee_pubkey = recipient_pubkey();
			let path = payment_path_for_amount(1000);
			let target_nodeid = target_node_id();
			let capacity_list = sorted_channel_capacity_in_path(&read_network_graph, path.clone());
			
			let mut max_htlc_list = Vec::<(NodeId, u64)>::new();
			let recipient_pubkey = recipient_node_id();
			//let target_pubkey = target_node_id();

			max_htlc_list.push((recipient_pubkey, 200));
			max_htlc_list.push((target_pubkey, 201));

			let value = value_selector(
				path.clone(), 
				target_nodeid, 
				&probe_value_map,
				max_htlc_list, 
				capacity_list).await;
			
			assert_eq!(value, 500);
		}
}