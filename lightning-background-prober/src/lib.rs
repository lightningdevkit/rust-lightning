//! Utilities that take care of running lightning networks payment channel probing as server
#[macro_use] extern crate lightning;
extern crate lightning_rapid_gossip_sync;
extern crate lightning_net_tokio;

use bitcoin::{network, Error};
use bitcoin::util::taproot::NodeInfo;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
use lightning::ln::PaymentHash;
use lightning::ln::msgs::LightningError;
use lightning::sign::{EntropySource, NodeSigner, SignerProvider};
use lightning::events::{Event, PathFailure};
#[cfg(feature = "std")]
use lightning::events::{EventHandler, EventsProvider};
use lightning::ln::channelmanager::{ChannelManager, PaymentId};
use lightning::ln::peer_handler::APeerManager;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync, NodeId, ReadOnlyNetworkGraph};
use lightning::routing::utxo::UtxoLookup;
use lightning::routing::router::{Router, PaymentParameters, DefaultRouter, RouteParameters, InFlightHtlcs, Route};
use lightning::routing::scoring::{Score, WriteableScore, ProbabilisticScorer};
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
#[cfg(feature = "std")]
use lightning::util::wakers::Sleeper;
use lightning_rapid_gossip_sync::RapidGossipSync;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, self};

use core::ops::Deref;
use core::time::Duration;

use std::collections::HashMap;
use std::{path, clone};
#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::thread::{self, JoinHandle};
#[cfg(feature = "std")]
use std::time::Instant;

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

//***************************************************************************************************************************** *

const NUM_THREADS: u64 = 1;
const NUM_INFLIGHT_PROBES: u64 = 1;
const NUM_MPSC_CHANNEL_CAPACITY: u64 = 1;
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_FREQUENCY: Duration = Duration::from_secs(60);
const PROBE_FREQUENCY_JITTER: Duration = Duration::from_secs(10);

const FINAL_VALUE_MSAT: u64 = 1000;
const OUR_NODE_PUBKEY : &bitcoin::secp256k1::PublicKey; // Need to be defined by user (maybe from config file)


//will only return node with maximum number of channels (has no implementation for state restoration)
//Final implementation will have NetworkGraph as input, it will be cloned and then pasrsed for sorting nodes with max number of channels
fn node_selector(network_graph: &ReadOnlyNetworkGraph,) -> NodeId {
    let mut temp: u64 = 0;
	let mut node_id: NodeId;

	let node_iter = network_graph.nodes().unordered_iter();
	for i in node_iter{
		let node_info = Deref::deref(&i.1);
		let channels = node_info.channels; 
		let num_channels = channels.len();
		if temp < num_channels.try_into().unwrap(){
			temp = num_channels.try_into().unwrap();
			node_id = *i.0;
		}
	}
	let node = node_id.clone();
	return node;
}

fn node_state_handler() -> Arc<Mutex<HashMap<NodeId, ProbePerister>>> {
    let map: Arc<Mutex<HashMap<NodeId, ProbePerister>>> = Arc::new(Mutex::new(HashMap::new()));
    map
}

struct ProbePerister {
	node_info: NodeInfo,
	value : HashMap<NodeId, Vec<u64>>
}

// will return route parameters for send_probe
pub fn probe_param( network_graph: &ReadOnlyNetworkGraph) -> Result<Route, LightningError> {
	// will not call node_selector directly, else it will be handled by some form of data structure (maybe)
	let target_pubkey = node_selector(network_graph).as_pubkey().unwrap();
	let param = PaymentParameters::from_node_id(target_pubkey,100);
	let route_param = RouteParameters{
		payment_params: param,
		final_value_msat: FINAL_VALUE_MSAT,};
	let inflight_htlc = InFlightHtlcs::new();
	let route  = Router::find_route(&self, OUR_NODE_PUBKEY, &route_param, None, &inflight_htlc);
	return route;
}

pub fn send () -> (PaymentHash, PaymentId) {
	let route = probe_param().unwrap();
	let path = route.paths[0];
	let mut probe_return = ChannelManager::send_probe(self, path).unwrap();
	return probe_return;
}


macro_rules! run_body {
    ($body:block) => {{
        let mut handles = Vec::new();
        let mut probe_return_values = Vec::new();

        for _ in 0..NUM_THREADS {
            let path = $path.clone();
            let (tx, rx) = tokio::sync::oneshot::channel();

            let handle = tokio::spawn(async move {
                let probe_return = send_probe(path).await;
                let _ = tx.send(probe_return);
                $body
            });
            handles.push(handle);

            let probe_return = rx.await.unwrap();
            probe_return_values.push(probe_return);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        probe_return_values
    }};
}

use tokio::task;

pub fn channel<Route>(capacity: NUM_MPSC_CHANNEL_CAPACITY) -> (mpsc::Sender<Route>, mpsc::Receiver<Route>)
where
    Route: Send + 'static,{
    let (tx, rx) = mpsc::channel(capacity);

    task::spawn(async move {
        while let Some(Route) = rx.recv().await {
			//how to handle return values (need some write type)
            let x = send();
			//some persister return value of probe (PaymentHash, PaymentId)
        }
    });
    (tx, rx)
}

//implementation for sending probe data into the channel 
pub async fn send_message<Route>(sender: &mpsc::Sender<Route>, message: Route)
where
    Route: Send + 'static,
{
    if sender.send(message).await.is_err() {
        //logging error
    }
}