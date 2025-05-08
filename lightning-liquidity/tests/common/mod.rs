#![cfg(all(test, feature = "time"))]
// TODO: remove these flags and unused code once we know what we'll need.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use bitcoin::blockdata::constants::{genesis_block, ChainHash};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Network;

use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
use lightning::chain::Filter;
use lightning::chain::{chainmonitor, BestBlock, Confirm};
use lightning::ln::channelmanager;
use lightning::ln::channelmanager::ChainParameters;
use lightning::ln::functional_test_utils::*;
use lightning::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, Init};
use lightning::ln::peer_handler::{
	IgnoringMessageHandler, MessageHandler, PeerManager, SocketDescriptor,
};

use lightning::onion_message::messenger::DefaultMessageRouter;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::router::{CandidateRouteHop, DefaultRouter, Path};
use lightning::routing::scoring::{ChannelUsage, ScoreLookUp, ScoreUpdate};
use lightning::sign::EntropySource;
use lightning::sign::{InMemorySigner, KeysManager};
use lightning::util::config::UserConfig;
use lightning::util::persist::{
	KVStore, CHANNEL_MANAGER_PERSISTENCE_KEY, CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
	CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE, NETWORK_GRAPH_PERSISTENCE_KEY,
	NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE, NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
	SCORER_PERSISTENCE_KEY, SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
	SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::test_utils;

use lightning_liquidity::lsps5::service::TimeProvider;
use lightning_liquidity::{LiquidityClientConfig, LiquidityManager, LiquidityServiceConfig};
use lightning_persister::fs_store::FilesystemStore;

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, fs};

pub(crate) struct TestEntropy {}
impl EntropySource for TestEntropy {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		[0; 32]
	}
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) struct TestDescriptor {}
impl SocketDescriptor for TestDescriptor {
	fn send_data(&mut self, _data: &[u8], _resume_read: bool) -> usize {
		0
	}

	fn disconnect_socket(&mut self) {}
}

#[cfg(c_bindings)]
type LockingWrapper<T> = lightning::routing::scoring::MultiThreadedLockableScore<T>;
#[cfg(not(c_bindings))]
type LockingWrapper<T> = std::sync::Mutex<T>;

pub(crate) type ChannelManager = channelmanager::ChannelManager<
	Arc<ChainMonitor>,
	Arc<test_utils::TestBroadcaster>,
	Arc<KeysManager>,
	Arc<KeysManager>,
	Arc<KeysManager>,
	Arc<test_utils::TestFeeEstimator>,
	Arc<
		DefaultRouter<
			Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
			Arc<test_utils::TestLogger>,
			Arc<KeysManager>,
			Arc<LockingWrapper<TestScorer>>,
			(),
			TestScorer,
		>,
	>,
	Arc<
		DefaultMessageRouter<
			Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
			Arc<test_utils::TestLogger>,
			Arc<KeysManager>,
		>,
	>,
	Arc<test_utils::TestLogger>,
>;

type ChainMonitor = chainmonitor::ChainMonitor<
	InMemorySigner,
	Arc<test_utils::TestChainSource>,
	Arc<test_utils::TestBroadcaster>,
	Arc<test_utils::TestFeeEstimator>,
	Arc<test_utils::TestLogger>,
	Arc<FilesystemStore>,
>;

type PGS = Arc<
	P2PGossipSync<
		Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
		Arc<test_utils::TestChainSource>,
		Arc<test_utils::TestLogger>,
	>,
>;

pub(crate) struct Node {
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) keys_manager: Arc<KeysManager>,
	pub(crate) p2p_gossip_sync: PGS,
	pub(crate) peer_manager: Arc<
		PeerManager<
			TestDescriptor,
			Arc<test_utils::TestChannelMessageHandler>,
			Arc<test_utils::TestRoutingMessageHandler>,
			IgnoringMessageHandler,
			Arc<test_utils::TestLogger>,
			Arc<
				LiquidityManager<
					Arc<KeysManager>,
					Arc<ChannelManager>,
					Arc<dyn Filter + Send + Sync>,
				>,
			>,
			Arc<KeysManager>,
		>,
	>,
	pub(crate) liquidity_manager:
		Arc<LiquidityManager<Arc<KeysManager>, Arc<ChannelManager>, Arc<dyn Filter + Send + Sync>>>,
	pub(crate) chain_monitor: Arc<ChainMonitor>,
	pub(crate) kv_store: Arc<FilesystemStore>,
	pub(crate) tx_broadcaster: Arc<test_utils::TestBroadcaster>,
	pub(crate) network_graph: Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
	pub(crate) logger: Arc<test_utils::TestLogger>,
	pub(crate) best_block: BestBlock,
	pub(crate) scorer: Arc<LockingWrapper<TestScorer>>,
}

impl Drop for Node {
	fn drop(&mut self) {
		let data_dir = self.kv_store.get_data_dir();
		match fs::remove_dir_all(data_dir.clone()) {
			Err(e) => {
				println!("Failed to remove test store directory {}: {}", data_dir.display(), e)
			},
			_ => {},
		}
	}
}

struct Persister {
	graph_error: Option<(lightning::io::ErrorKind, &'static str)>,
	graph_persistence_notifier: Option<SyncSender<()>>,
	manager_error: Option<(lightning::io::ErrorKind, &'static str)>,
	scorer_error: Option<(lightning::io::ErrorKind, &'static str)>,
	kv_store: FilesystemStore,
}

impl Persister {
	fn new(data_dir: PathBuf) -> Self {
		let kv_store = FilesystemStore::new(data_dir);
		Self {
			graph_error: None,
			graph_persistence_notifier: None,
			manager_error: None,
			scorer_error: None,
			kv_store,
		}
	}

	fn with_graph_error(self, error: lightning::io::ErrorKind, message: &'static str) -> Self {
		Self { graph_error: Some((error, message)), ..self }
	}

	fn with_graph_persistence_notifier(self, sender: SyncSender<()>) -> Self {
		Self { graph_persistence_notifier: Some(sender), ..self }
	}

	fn with_manager_error(self, error: lightning::io::ErrorKind, message: &'static str) -> Self {
		Self { manager_error: Some((error, message)), ..self }
	}

	fn with_scorer_error(self, error: lightning::io::ErrorKind, message: &'static str) -> Self {
		Self { scorer_error: Some((error, message)), ..self }
	}
}

impl KVStore for Persister {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> lightning::io::Result<Vec<u8>> {
		self.kv_store.read(primary_namespace, secondary_namespace, key)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: &[u8],
	) -> lightning::io::Result<()> {
		if primary_namespace == CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE
			&& secondary_namespace == CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE
			&& key == CHANNEL_MANAGER_PERSISTENCE_KEY
		{
			if let Some((error, message)) = self.manager_error {
				return Err(lightning::io::Error::new(error, message));
			}
		}

		if primary_namespace == NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE
			&& secondary_namespace == NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE
			&& key == NETWORK_GRAPH_PERSISTENCE_KEY
		{
			if let Some(sender) = &self.graph_persistence_notifier {
				match sender.send(()) {
					Ok(()) => {},
					Err(std::sync::mpsc::SendError(())) => {
						println!("Persister failed to notify as receiver went away.")
					},
				}
			};

			if let Some((error, message)) = self.graph_error {
				return Err(lightning::io::Error::new(error, message));
			}
		}

		if primary_namespace == SCORER_PERSISTENCE_PRIMARY_NAMESPACE
			&& secondary_namespace == SCORER_PERSISTENCE_SECONDARY_NAMESPACE
			&& key == SCORER_PERSISTENCE_KEY
		{
			if let Some((error, message)) = self.scorer_error {
				return Err(lightning::io::Error::new(error, message));
			}
		}

		self.kv_store.write(primary_namespace, secondary_namespace, key, buf)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> lightning::io::Result<()> {
		self.kv_store.remove(primary_namespace, secondary_namespace, key, lazy)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> lightning::io::Result<Vec<String>> {
		self.kv_store.list(primary_namespace, secondary_namespace)
	}
}

pub(crate) struct TestScorer {
	event_expectations: Option<VecDeque<TestResult>>,
}

#[derive(Debug)]
pub(crate) enum TestResult {
	PaymentFailure { path: Path, short_channel_id: u64 },
	PaymentSuccess { path: Path },
	ProbeFailure { path: Path },
	ProbeSuccess { path: Path },
}

impl TestScorer {
	fn new() -> Self {
		Self { event_expectations: None }
	}

	fn expect(&mut self, expectation: TestResult) {
		self.event_expectations.get_or_insert_with(VecDeque::new).push_back(expectation);
	}
}

impl lightning::util::ser::Writeable for TestScorer {
	fn write<W: lightning::util::ser::Writer>(
		&self, _: &mut W,
	) -> Result<(), lightning::io::Error> {
		Ok(())
	}
}

impl ScoreLookUp for TestScorer {
	type ScoreParams = ();
	fn channel_penalty_msat(
		&self, _candidate: &CandidateRouteHop, _usage: ChannelUsage,
		_score_params: &Self::ScoreParams,
	) -> u64 {
		unimplemented!();
	}
}

impl ScoreUpdate for TestScorer {
	fn payment_path_failed(
		&mut self, actual_path: &Path, actual_short_channel_id: u64, _: Duration,
	) {
		if let Some(expectations) = &mut self.event_expectations {
			match expectations.pop_front().unwrap() {
				TestResult::PaymentFailure { path, short_channel_id } => {
					assert_eq!(actual_path, &path);
					assert_eq!(actual_short_channel_id, short_channel_id);
				},
				TestResult::PaymentSuccess { path } => {
					panic!("Unexpected successful payment path: {:?}", path)
				},
				TestResult::ProbeFailure { path } => {
					panic!("Unexpected probe failure: {:?}", path)
				},
				TestResult::ProbeSuccess { path } => {
					panic!("Unexpected probe success: {:?}", path)
				},
			}
		}
	}

	fn payment_path_successful(&mut self, actual_path: &Path, _: Duration) {
		if let Some(expectations) = &mut self.event_expectations {
			match expectations.pop_front().unwrap() {
				TestResult::PaymentFailure { path, .. } => {
					panic!("Unexpected payment path failure: {:?}", path)
				},
				TestResult::PaymentSuccess { path } => {
					assert_eq!(actual_path, &path);
				},
				TestResult::ProbeFailure { path } => {
					panic!("Unexpected probe failure: {:?}", path)
				},
				TestResult::ProbeSuccess { path } => {
					panic!("Unexpected probe success: {:?}", path)
				},
			}
		}
	}

	fn probe_failed(&mut self, actual_path: &Path, _: u64, _: Duration) {
		if let Some(expectations) = &mut self.event_expectations {
			match expectations.pop_front().unwrap() {
				TestResult::PaymentFailure { path, .. } => {
					panic!("Unexpected payment path failure: {:?}", path)
				},
				TestResult::PaymentSuccess { path } => {
					panic!("Unexpected payment path success: {:?}", path)
				},
				TestResult::ProbeFailure { path } => {
					assert_eq!(actual_path, &path);
				},
				TestResult::ProbeSuccess { path } => {
					panic!("Unexpected probe success: {:?}", path)
				},
			}
		}
	}
	fn probe_successful(&mut self, actual_path: &Path, _: Duration) {
		if let Some(expectations) = &mut self.event_expectations {
			match expectations.pop_front().unwrap() {
				TestResult::PaymentFailure { path, .. } => {
					panic!("Unexpected payment path failure: {:?}", path)
				},
				TestResult::PaymentSuccess { path } => {
					panic!("Unexpected payment path success: {:?}", path)
				},
				TestResult::ProbeFailure { path } => {
					panic!("Unexpected probe failure: {:?}", path)
				},
				TestResult::ProbeSuccess { path } => {
					assert_eq!(actual_path, &path);
				},
			}
		}
	}
	fn time_passed(&mut self, _: Duration) {}
}

#[cfg(c_bindings)]
impl lightning::routing::scoring::Score for TestScorer {}

impl Drop for TestScorer {
	fn drop(&mut self) {
		if std::thread::panicking() {
			return;
		}

		if let Some(event_expectations) = &self.event_expectations {
			if !event_expectations.is_empty() {
				panic!("Unsatisfied event expectations: {:?}", event_expectations);
			}
		}
	}
}

fn get_full_filepath(filepath: String, filename: String) -> String {
	let mut path = PathBuf::from(filepath);
	path.push(filename);
	path.to_str().unwrap().to_string()
}

pub(crate) fn create_liquidity_node(
	i: usize, persist_dir: &str, network: Network, service_config: Option<LiquidityServiceConfig>,
	client_config: Option<LiquidityClientConfig>, time_provider: Option<Arc<dyn TimeProvider>>,
) -> Node {
	let tx_broadcaster = Arc::new(test_utils::TestBroadcaster::new(network));
	let fee_estimator = Arc::new(test_utils::TestFeeEstimator::new(253));
	let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
	let genesis_block = genesis_block(network);
	let network_graph = Arc::new(NetworkGraph::new(network, logger.clone()));
	let scorer = Arc::new(LockingWrapper::new(TestScorer::new()));
	let now = Duration::from_secs(genesis_block.header.time as u64);
	let seed = [i as u8; 32];
	let keys_manager = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos()));
	let router = Arc::new(DefaultRouter::new(
		Arc::clone(&network_graph),
		logger.clone(),
		keys_manager.clone(),
		scorer.clone(),
		Default::default(),
	));
	let msg_router =
		Arc::new(DefaultMessageRouter::new(Arc::clone(&network_graph), Arc::clone(&keys_manager)));
	let chain_source = Arc::new(test_utils::TestChainSource::new(Network::Bitcoin));
	let kv_store =
		Arc::new(FilesystemStore::new(format!("{}_persister_{}", &persist_dir, i).into()));
	let chain_monitor = Arc::new(chainmonitor::ChainMonitor::new(
		Some(chain_source.clone()),
		tx_broadcaster.clone(),
		logger.clone(),
		fee_estimator.clone(),
		kv_store.clone(),
	));
	let best_block = BestBlock::from_network(network);
	let chain_params = ChainParameters { network, best_block };
	let channel_manager = Arc::new(ChannelManager::new(
		fee_estimator.clone(),
		chain_monitor.clone(),
		tx_broadcaster.clone(),
		router.clone(),
		msg_router.clone(),
		logger.clone(),
		keys_manager.clone(),
		keys_manager.clone(),
		keys_manager.clone(),
		UserConfig::default(),
		chain_params,
		genesis_block.header.time,
	));
	let p2p_gossip_sync = Arc::new(P2PGossipSync::new(
		network_graph.clone(),
		Some(chain_source.clone()),
		logger.clone(),
	));
	let liquidity_manager = Arc::new(if let Some(tp) = time_provider.clone() {
		LiquidityManager::new_with_custom_time_provider(
			keys_manager.clone(),
			channel_manager.clone(),
			None::<Arc<dyn Filter + Send + Sync>>,
			Some(chain_params.clone()),
			service_config,
			client_config,
			tp,
		)
	} else {
		LiquidityManager::new(
			keys_manager.clone(),
			channel_manager.clone(),
			None,
			Some(chain_params),
			service_config,
			client_config,
		)
	});

	let msg_handler = MessageHandler {
		chan_handler: Arc::new(test_utils::TestChannelMessageHandler::new(
			ChainHash::using_genesis_block(Network::Testnet),
		)),
		route_handler: Arc::new(test_utils::TestRoutingMessageHandler::new()),
		onion_message_handler: IgnoringMessageHandler {},
		custom_message_handler: Arc::clone(&liquidity_manager),
	};
	let peer_manager =
		Arc::new(PeerManager::new(msg_handler, 0, &seed, logger.clone(), keys_manager.clone()));

	Node {
		channel_manager,
		keys_manager,
		p2p_gossip_sync,
		peer_manager,
		liquidity_manager,
		chain_monitor,
		kv_store,
		tx_broadcaster,
		network_graph,
		logger,
		best_block,
		scorer,
	}
}

pub(crate) fn create_service_and_client_nodes(
	persist_dir: &str, service_config: LiquidityServiceConfig,
	client_config: LiquidityClientConfig, time_provider: Option<Arc<dyn TimeProvider>>,
) -> (Node, Node) {
	let persist_temp_path = env::temp_dir().join(persist_dir);
	let persist_dir = persist_temp_path.to_string_lossy().to_string();
	let network = Network::Bitcoin;

	let service_node = create_liquidity_node(
		1,
		&persist_dir,
		network,
		Some(service_config),
		None,
		time_provider.clone(),
	);
	let client_node =
		create_liquidity_node(2, &persist_dir, network, None, Some(client_config), time_provider);

	service_node
		.channel_manager
		.peer_connected(
			client_node.channel_manager.get_our_node_id(),
			&Init {
				features: client_node.channel_manager.init_features(),
				networks: None,
				remote_network_address: None,
			},
			true,
		)
		.unwrap();
	client_node
		.channel_manager
		.peer_connected(
			service_node.channel_manager.get_our_node_id(),
			&Init {
				features: service_node.channel_manager.init_features(),
				networks: None,
				remote_network_address: None,
			},
			true,
		)
		.unwrap();

	(service_node, client_node)
}

macro_rules! open_channel {
	($node_a: expr, $node_b: expr, $channel_value: expr) => {{
		begin_open_channel!($node_a, $node_b, $channel_value);
		let events = $node_a.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		let (temporary_channel_id, tx) =
			handle_funding_generation_ready!(events[0], $channel_value);
		$node_a
			.node
			.funding_transaction_generated(
				&temporary_channel_id,
				&$node_b.node.get_our_node_id(),
				tx.clone(),
			)
			.unwrap();
		$node_b.node.handle_funding_created(
			&$node_a.node.get_our_node_id(),
			&get_event_msg!(
				$node_a,
				MessageSendEvent::SendFundingCreated,
				$node_b.node.get_our_node_id()
			),
		);
		get_event!($node_b, Event::ChannelPending);
		$node_a.node.handle_funding_signed(
			&$node_b.node.get_our_node_id(),
			&get_event_msg!(
				$node_b,
				MessageSendEvent::SendFundingSigned,
				$node_a.node.get_our_node_id()
			),
		);
		get_event!($node_a, Event::ChannelPending);
		tx
	}};
}

pub(crate) use open_channel;

macro_rules! begin_open_channel {
	($node_a: expr, $node_b: expr, $channel_value: expr) => {{
		$node_a
			.node
			.create_channel($node_b.node.get_our_node_id(), $channel_value, 100, 42, None, None)
			.unwrap();
		$node_b.node.handle_open_channel(
			&$node_a.node.get_our_node_id(),
			&get_event_msg!(
				$node_a,
				MessageSendEvent::SendOpenChannel,
				$node_b.node.get_our_node_id()
			),
		);
		$node_a.node.handle_accept_channel(
			&$node_b.node.get_our_node_id(),
			&get_event_msg!(
				$node_b,
				MessageSendEvent::SendAcceptChannel,
				$node_a.node.get_our_node_id()
			),
		);
	}};
}

pub(crate) use begin_open_channel;

macro_rules! handle_funding_generation_ready {
	($event: expr, $channel_value: expr) => {{
		match $event {
			Event::FundingGenerationReady {
				temporary_channel_id,
				channel_value_satoshis,
				ref output_script,
				user_channel_id,
				..
			} => {
				assert_eq!(channel_value_satoshis, $channel_value);
				assert_eq!(user_channel_id, 42);

				let tx = Transaction {
					version: 1 as i32,
					lock_time: LockTime::ZERO,
					input: Vec::new(),
					output: vec![TxOut {
						value: channel_value_satoshis,
						script_pubkey: output_script.clone(),
					}],
				};
				(temporary_channel_id, tx)
			},
			_ => panic!("Unexpected event"),
		}
	}};
}

pub(crate) use handle_funding_generation_ready;

macro_rules! get_lsps_message {
	($node: expr, $expected_target_node_id: expr) => {{
		let msgs = $node.liquidity_manager.get_and_clear_pending_msg();
		assert_eq!(msgs.len(), 1);
		let (target_node_id, message) = msgs.into_iter().next().unwrap();
		assert_eq!(target_node_id, $expected_target_node_id);
		message
	}};
}

pub(crate) use get_lsps_message;

fn confirm_transaction_depth(node: &mut Node, tx: &Transaction, depth: u32) {
	for i in 1..=depth {
		let prev_blockhash = node.best_block.block_hash;
		let height = node.best_block.height + 1;
		let header = create_dummy_header(prev_blockhash, height);
		let txdata = vec![(0, tx)];
		node.best_block = BestBlock::new(header.block_hash(), height);
		match i {
			1 => {
				node.channel_manager.transactions_confirmed(&header, &txdata, height);
				node.chain_monitor.transactions_confirmed(&header, &txdata, height);
			},
			x if x == depth => {
				node.channel_manager.best_block_updated(&header, height);
				node.chain_monitor.best_block_updated(&header, height);
			},
			_ => {},
		}
	}
}

fn confirm_transaction(node: &mut Node, tx: &Transaction) {
	confirm_transaction_depth(node, tx, ANTI_REORG_DELAY);
}

fn advance_chain(node: &mut Node, num_blocks: u32) {
	for i in 1..=num_blocks {
		let prev_blockhash = node.best_block.block_hash;
		let height = node.best_block.height + 1;
		let header = create_dummy_header(prev_blockhash, height);
		node.best_block = BestBlock::new(header.block_hash(), height);
		if i == num_blocks {
			node.channel_manager.best_block_updated(&header, height);
			node.chain_monitor.best_block_updated(&header, height);
		}
	}
}
