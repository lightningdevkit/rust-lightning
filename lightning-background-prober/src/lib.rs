//! Utilities that take care of running lightning networks payment channel probing as server

extern crate lightning_rapid_gossip_sync;
use async_channel::{Sender, Receiver};
use lightning::events::{Event, PathFailure};
use lightning::ln::PaymentHash;
use lightning::ln::channelmanager::{PaymentId, PaymentSendFailure};
use lightning::util::test_utils::TestLogger;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync, NodeId, ReadOnlyNetworkGraph, NodeInfo, ChannelInfo};
use lightning::routing::utxo::UtxoLookup;
use lightning::routing::router::{PaymentParameters, RouteParameters, InFlightHtlcs, Path, build_route_from_hops, DefaultRouter, Router};
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters, FixedPenaltyScorer};
use lightning::util::indexed_map::IndexedMap;
use lightning::util::logger::Logger;
use lightning_rapid_gossip_sync::RapidGossipSync;
use rand::Rng;
use tokio::sync::Mutex;
use core::ops::Deref;
use core::time::Duration;
use std::cmp::min;
use std::sync::Arc;
use std::{thread, clone};


/// Utilities for probing lightning networks payment channel

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
const DEFAULT_FINAL_VALUE_MSAT: u64 = 1000;
const DEFAULT_PROBE_VALUE_MSAT: u64 = 1000;
const DEFAULT_PENALTY_MSAT: u64 = 1000;

// Need to be defined by user (maybe from config file
const OUR_NODE_PUBKEY : bitcoin::secp256k1::PublicKey = bitcoin::secp256k1::PublicKey::from_slice(&[0; 33]).unwrap();

struct NodesToProbe {
	nodes_to_probe: Vec<(NodeId,NodeInfo)>,
}

impl NodesToProbe{

	fn new () -> &'static  mut Self {
		&mut Self {
			nodes_to_probe: Vec::<(NodeId,NodeInfo)>::new()
		 }
	}

	// Will return a Vec<(NodeId,NodeInfo)> of nodes sorted by Number Of Channels
	fn network_graph_sorted_with_respect_to_num_channels(
		& mut self,
		network_graph: &ReadOnlyNetworkGraph
	) -> &mut Self {

		let node_iter = network_graph.nodes().unordered_iter();
		for i in node_iter {
			let channel = Deref::deref(&i.1).channels.len();
			self.nodes_to_probe.push((*i.0, *i.1));
		}

		self.nodes_to_probe.sort_by(|(node_id_a, node_info_a), (node_id_b, node_info_b)| {
			node_info_b.channels.len().cmp(&node_info_a.channels.len())
		});
		self
	}

	// Will return top_one_percent_nodes of nodes sorted by Number Of Channels
	fn top_one_percent_nodes (& mut self) -> &mut Self {
		let num_element = self.nodes_to_probe.len() as f64;
		self.nodes_to_probe[0..((0.1*num_element).floor() as usize)];
		self
	}

	fn as_ref (& mut self) -> Self {
		*self
	}
}

impl Iterator for NodesToProbe {
	type Item = (NodeId,NodeInfo);

	fn next(&mut self) -> Option<Self::Item> {
		self.nodes_to_probe.pop()
	}
}

impl clone::Clone for NodesToProbe {
	fn clone(&self) -> Self {
		Self {
			nodes_to_probe: self.nodes_to_probe.clone(),
		}
	}
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
//It will use DefaultRouter to find a path to target_pubkey
async fn initial_path_builder<L: std::ops::Deref> (
	network_graph: &NetworkGraph<L>,
	target_nodeid: NodeId,
	final_value_mast :u64,
	probe_value_map : &ProbeValueMap,
) -> Path where <L as Deref>::Target: Logger {

	let value_map = probe_value_map.value_map.lock().await;
	let x = value_map.get(&target_nodeid);
	match x {
		Some(x) => {
			let path = x.path[0].clone();
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

					// let logger = TestLogger::new().log(record!());
					// let params = ProbabilisticScoringFeeParameters::default();
					// let decay_params = ProbabilisticScoringDecayParameters::default();
					// let scorer = Arc::new(ProbabilisticScorer::new(decay_params, network_graph, logger.clone()));
					

					// let scorer = FixedPenaltyScorer::with_penalty(DEFAULT_PENALTY_MSAT);
					// let random_seed_bytes: [u8; 32] = generate_random_seed_bytes();

					// let router = Arc::new(DefaultRouter::new(
					// 	network_graph,
					// 	logger.clone(),
					// 	random_seed_bytes,
					// 	scorer,
					// 	scoring_fee_params.lock().await,
					// ));

					let route  = router.find_route(
						&OUR_NODE_PUBKEY, 
						&route_params, 
						None, 
						&InFlightHtlcs::new());
					
					match route {
						Ok(route) => {
							let path = route.paths[0].clone();
							
							let node_rating = value_map.get_mut(&target_nodeid).unwrap();
							node_rating.probes.push(ProbePersister::new(target_nodeid));
							
							if let Some(last_probe) = node_rating.probes.last_mut(){
								last_probe.update_path(path.clone());
							}
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


//Will convert Path into Box<[bitcoin::secp256k1::PublicKey]>
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


//capacity = balance(A) + balance(B)
//liquidity(A) = balance(A) – channel_reserve(A) – pending_HTLCs(A)
//Will return Sorted Vec of channel_capacity in given Path

// we are halving the channel capacity
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

struct HtlcList {
	path: Path,
	max_htlc_list: Vec<(NodeId,u64)>,
	min_htlc_list: Vec<(NodeId,u64)>,
}

impl HtlcList {
	fn new (path: Path) -> Self {
		Self {
			path,
			max_htlc_list: Vec::new(),
			min_htlc_list: Vec::new(),
		}
	}

	//this code has directionality issues
	fn sorted_htlc_in_path (
		& mut self, 
		path: Path, 
		channel_info: &ChannelInfo,
	) -> Self {
		
		for i in path.hops {
			let nodeid = NodeId::from_pubkey(&i.pubkey);
			let channel_update_info = channel_info.get_directional_info(0).unwrap();
			let max = channel_update_info.htlc_maximum_msat;
			let min = channel_update_info.htlc_minimum_msat;
			
			self.max_htlc_list.push((nodeid, max));
			self.min_htlc_list.push((nodeid, min));
				
		}
		self.max_htlc_list.sort_by(|(_, a), (_, b)| a.cmp(b)); // accending ordering of MAX_HTLC
		self.min_htlc_list.sort_by(|(_, a), (_, b)| b.cmp(a)); // decending sort of MIN_HTLC

		return *self;
	}
}


//Value selector for probing (Uses binary search method)
async fn value_selector (
	path: Path,
	nodeid: NodeId,
	probe_value_map: &ProbeValueMap,
	min_htlc_list: Vec<(NodeId,u64)>,
	max_htlc_list: Vec<(NodeId,u64)>,
	capacity_list: Vec<(u64,Option<u64>)>,
) -> u64 {
	let mut value_map = probe_value_map.value_map.lock().await;
	let temp = value_map.get_mut(&nodeid);
	match temp {
		Some(node_rating) => {
			let vec_len = node_rating.probes.len();
			
			//probing for Min
			if vec_len == 0 {
				let val = min_htlc_list.last().unwrap().1;
				
				if let Some(last_probe) = node_rating.probes.last_mut() {
					last_probe.set_probe_direction(ProbeDirection::Min);
					last_probe.update_path(path);
					last_probe.update_value(val);
				}
				return val
			}

			//probing for Max
			else if vec_len == 1 {
				let val = min(max_htlc_list[0].1, capacity_list[0].1.unwrap());
	
				if let Some(last_probe) = node_rating.probes.last_mut() {
					last_probe.set_probe_direction(ProbeDirection::Max);
					last_probe.update_path(path);
					last_probe.update_value(val);
				}
				return val
			}
			
			//probing for Min
			else if vec_len == 2 {
				let probe_persister = node_rating.probes.get(vec_len-2).unwrap();
				let probe_status = probe_persister.probe_status.as_ref().unwrap();
				let value = probe_persister.value.unwrap();
				match probe_status {
					ProbeStatus::Success => {
						let val = (0.5*(value as f64).floor()) as u64;
			
						if let Some(last_probe) = node_rating.probes.last_mut() {
							last_probe.set_probe_direction(ProbeDirection::Min);
							last_probe.update_path(path);
							last_probe.update_value(val);
						}
						return val
					}
					ProbeStatus::Failure => {
						let val = 2*value;
						
						if let Some(last_probe) = node_rating.probes.last_mut() {
							last_probe.set_probe_direction(ProbeDirection::Min);
							last_probe.update_path(path);
							last_probe.update_value(val);
						}
						return val
					}
				}
			}

			//probing for Max
			else if vec_len == 3 {
				let probe_persister = node_rating.probes.get(vec_len-2).unwrap();
				let probe_status = probe_persister.probe_status.as_ref().unwrap();
				let value = probe_persister.value.unwrap();
				match probe_status {
					ProbeStatus::Success => {
						let val = 2*value;
						
						if let Some(last_probe) = node_rating.probes.last_mut() {
							last_probe.set_probe_direction(ProbeDirection::Max);
							last_probe.update_path(path);
							last_probe.update_value(val);
						}
						return val
					}
					ProbeStatus::Failure => {
						let val = (0.5*(value as f64)).floor() as u64;

						if let Some(last_probe) = node_rating.probes.last_mut() {
							last_probe.set_probe_direction(ProbeDirection::Max);
							last_probe.update_path(path);
							last_probe.update_value(val);
						}
						return val
					}
				}
			}
			
			else {
				let probe_persister = node_rating.probes.get(vec_len-1);
				match probe_persister {
					Some(probe) => {
						let direction = probe.direction.as_ref().unwrap();
						match direction {
							ProbeDirection::Min => {
								
								//Probing for Max
								let probe_to_see = node_rating.probes.get(vec_len-2).unwrap();
								let value = probe_to_see.value.unwrap();
								let probe_status = probe_to_see.probe_status.as_ref().unwrap();
								match probe_status {
									ProbeStatus::Success => {
										let val = 2*value;
									
										if let Some(last_probe) = node_rating.probes.last_mut() {
											last_probe.set_probe_direction(ProbeDirection::Max);
											last_probe.update_path(path);
											last_probe.update_value(val);
										}
										return val
									}
									ProbeStatus::Failure => {
										let val_mid = node_rating.probes.get(vec_len-4).unwrap().value.unwrap();
										let val = (0.5*((value + val_mid) as f64)).floor() as u64;
										
										if let Some(last_probe) = node_rating.probes.last_mut() {
											last_probe.set_probe_direction(ProbeDirection::Max);
											last_probe.update_path(path);
											last_probe.update_value(val);
										}
										return val
									}
								}
							}
							ProbeDirection::Max => {
								
								//Probing for Min
								let probe_to_see = node_rating.probes.get(vec_len-2).unwrap();
								let value = probe_to_see.value.unwrap();
								let probe_status = probe_to_see.probe_status.as_ref().unwrap();
								match probe_status {
									ProbeStatus::Success => {
										let val_mid = node_rating.probes.get(vec_len-4).unwrap().value.unwrap();
										let val = (0.5*((value + val_mid) as f64)).floor() as u64;
										
										if let Some(last_probe) = node_rating.probes.last_mut() {
											last_probe.set_probe_direction(ProbeDirection::Min);
											last_probe.update_path(path);
											last_probe.update_value(val);
										}
										return val
									}
									ProbeStatus::Failure => {
										let val = 2*value;
										
										if let Some(last_probe) = node_rating.probes.last_mut() {
											last_probe.set_probe_direction(ProbeDirection::Min);
											last_probe.update_path(path);
											last_probe.update_value(val);
										}
										return val
									}
								}
							},
						}	
					},
					None => {
						panic!("No probe found");
					}
				}
			}
		}
		None => {
			panic!("Node not found in probe_value_map");
		}
	}
}

//Will return a path using build_route_from_hops
fn final_path_builder_for_probe <L: Logger + std::ops::Deref>(
	hops: Box<[bitcoin::secp256k1::PublicKey]>,
	network_graph: &NetworkGraph<L>,
	nodeid: NodeId,
	final_value_mast :u64
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
		&OUR_NODE_PUBKEY,
		&hops,
		&route_params,
		network_graph,
		&logger,
		&random_seed_bytes);

	return route.unwrap().paths[0].clone();
}

async fn node_selector(
	top_nodes: NodesToProbe,
	probe_value_map: &ProbeValueMap,
) -> Option<NodeId> {
	let mut value_map = probe_value_map.value_map.lock().await;
	for i in top_nodes {
		let node_id = i.0;
		let node_rating = value_map.get(&node_id);

		match node_rating {
			Some(x) => {
				let mut flag = true;
				for i in &x.probes{
					let probe_status = &i.probe_status;
					match probe_status {
						Some(_x) => {
							flag = true;
						},

						None => {
							flag = false;
							break;
						}
					}
				}
				if flag == false {
					continue;
				}
				else {
					return Some(node_id);
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


//structs for persisting probes
//**************************************************************************************************************************************************************** */

//should be initalized at the start of the program
struct ProbeValueMap<> {
	value_map: Arc<Mutex<IndexedMap<NodeId, NodeRating>>>,
}

impl ProbeValueMap {
	fn new () -> Self {
		Self {
			value_map: Arc::new(Mutex::new(IndexedMap::<NodeId,NodeRating>::new())),
		}
	}
}

//Initialized by node_selector
struct NodeRating {
	node_id : NodeId,
	path : Vec<Path>,
	channel_information_coefficient: f64,
	probes: Vec<ProbePersister>,
}

impl NodeRating {
	fn new (node_id: NodeId) -> Self {
		Self {
			node_id,
			path: Vec::new(),
			channel_information_coefficient: 0.0,
			probes: Vec::new(),
		}
	}
}

enum ProbeDirection {
	Min,
	Max,
}

enum ProbeStatus {
	Success,
	Failure,
}

//Initialized by value_selector
//updated by final_path_builder_for_probe
struct ProbePersister{
	target_nodeid : NodeId,
	value : Option<u64>,
	path : Option<Path>,
	direction : Option<ProbeDirection>,
	probe_status : Option<ProbeStatus>,  
	send_probe_return : Option<Result<(PaymentHash, PaymentId), PaymentSendFailure>>,
}

impl ProbePersister {
	
	fn new (target_nodeid: NodeId) -> Self {
		Self {
			target_nodeid,
			value: None,
			path: None,
			direction: None,
			probe_status: None,
			send_probe_return: None,
		}
	}

	// Method to set the probe direction
    fn set_probe_direction(&mut self, direction: ProbeDirection) {
        self.direction = Some(direction);
    }

    // Method to update the path
    fn update_path(&mut self, path: Path) {
        self.path = Some(path);
    }

    // Method to update the send probe return
	//has to be updated by send_probe
    fn update_send_probe_return(&mut self, result: Result<(PaymentHash, PaymentId), PaymentSendFailure>) {
        self.send_probe_return = Some(result);
    }

	 // Method to update the probe status
	 //has to be updated by event_handler
	 fn update_probe_status(&mut self, status: ProbeStatus) {
        self.probe_status = Some(status);
    }

	fn update_value (&mut self, value: u64) {
		self.value = Some(value);
	}

}

//end of struct for persisting probes
//****************************************************************************************************************************************************************** */


// main core runner for probing
//******************************************************************************************************************************************************** */

async fn start_probing <L : Logger + std::ops::Deref> (
	network_graph: &NetworkGraph<L>, 
	read_network_graph: &ReadOnlyNetworkGraph<'_>,
	channel_info: &ChannelInfo
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
	initial_path_looper(r_selected_node,s_inital_path,network_graph, &probe_value_map);

	//runs value selection on initial paths
	value_selector_looper::<L>(r_inital_path, s_value, &read_network_graph,channel_info, &probe_value_map);

	//final path builder loop
	final_path_builder_for_probe_looper(r_value, network_graph, s_final_path);


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
		let nodes_to_probe = NodesToProbe::new().network_graph_sorted_with_respect_to_num_channels(network_graph_read).top_one_percent_nodes();
		let nodes = nodes_to_probe.as_ref();
		s_top_nodes.send(nodes).await;
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
	network_graph: &NetworkGraph<L>,
	probe_value_map : &ProbeValueMap
) -> () where <L as Deref>::Target: Logger {
	
	loop {
		let nodeid = r_selected_node.recv().await.unwrap();
		let path = initial_path_builder(
			network_graph, 
			nodeid, 
			DEFAULT_FINAL_VALUE_MSAT, 
			probe_value_map).await;
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
		
		let htlc_list = HtlcList::new(path.clone()).sorted_htlc_in_path(path.clone(), channel_info);
		let min_htlc_list = htlc_list.min_htlc_list;
		let max_htlc_list = htlc_list.max_htlc_list;

		let value = value_selector(
			path.clone(), 
			nodeid, 
			probe_value_map, 
			min_htlc_list, 
			max_htlc_list, 
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
) -> () where <L as Deref>::Target: Logger {
	
	loop {
		let (nodeid, path, value) = r_value.recv().await.unwrap();
		let path_parse = path_parser(path);
		let final_path = final_path_builder_for_probe(path_parse, network_graph, nodeid, value);

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