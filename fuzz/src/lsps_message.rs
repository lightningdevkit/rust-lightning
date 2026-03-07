use crate::utils::test_logger;

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;

use lightning::chain::Filter;
use lightning::chain::{chainmonitor, BestBlock};
use lightning::ln::channelmanager::{ChainParameters, ChannelManager};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use lightning::onion_message::messenger::DefaultMessageRouter;
use lightning::routing::gossip::NetworkGraph;
use lightning::routing::router::DefaultRouter;
use lightning::sign::KeysManager;
use lightning::sign::NodeSigner;
use lightning::util::config::UserConfig;
use lightning::util::test_utils::{
	TestBroadcaster, TestChainSource, TestFeeEstimator, TestLogger, TestScorer, TestStore,
};

use lightning_liquidity::lsps0::ser::LSPS_MESSAGE_TYPE_ID;
use lightning_liquidity::LiquidityManagerSync;

use core::time::Duration;

type LockingWrapper<T> = std::sync::Mutex<T>;

use std::sync::Arc;

pub fn do_test(data: &[u8]) {
	let network = Network::Bitcoin;
	let tx_broadcaster = Arc::new(TestBroadcaster::new(network));
	let fee_estimator = Arc::new(TestFeeEstimator::new(253));
	let logger = Arc::new(TestLogger::with_id("node".into()));
	let genesis_block = genesis_block(network);
	let network_graph = Arc::new(NetworkGraph::new(network, Arc::clone(&logger)));
	let scorer = Arc::new(LockingWrapper::new(TestScorer::new()));
	let now = Duration::from_secs(genesis_block.header.time as u64);
	let seed = sha256::Hash::hash(b"lsps-message-seed").to_byte_array();
	let keys_manager = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos(), true));
	let router = Arc::new(DefaultRouter::new(
		Arc::clone(&network_graph),
		Arc::clone(&logger),
		Arc::clone(&keys_manager),
		Arc::clone(&scorer),
		Default::default(),
	));
	let msg_router =
		Arc::new(DefaultMessageRouter::new(Arc::clone(&network_graph), Arc::clone(&keys_manager)));
	let chain_source = Arc::new(TestChainSource::new(Network::Bitcoin));
	let kv_store = Arc::new(TestStore::new(false));
	let chain_monitor = Arc::new(chainmonitor::ChainMonitor::new(
		Some(Arc::clone(&chain_source)),
		Arc::clone(&tx_broadcaster),
		Arc::clone(&logger),
		Arc::clone(&fee_estimator),
		Arc::clone(&kv_store),
		Arc::clone(&keys_manager),
		keys_manager.get_peer_storage_key(),
		false,
	));
	let best_block = BestBlock::from_network(network);
	let params = ChainParameters { network, best_block };
	let manager = Arc::new(ChannelManager::new(
		Arc::clone(&fee_estimator),
		Arc::clone(&chain_monitor),
		Arc::clone(&tx_broadcaster),
		Arc::clone(&router),
		Arc::clone(&msg_router),
		Arc::clone(&logger),
		Arc::clone(&keys_manager),
		Arc::clone(&keys_manager),
		Arc::clone(&keys_manager),
		UserConfig::default(),
		params,
		genesis_block.header.time,
	));

	let liquidity_manager = Arc::new(
		LiquidityManagerSync::new(
			Arc::clone(&keys_manager),
			Arc::clone(&keys_manager),
			Arc::clone(&manager),
			None::<Arc<dyn Filter + Send + Sync>>,
			None,
			kv_store,
			Arc::clone(&tx_broadcaster),
			None,
			None,
		)
		.unwrap(),
	);
	let mut reader = data;
	if let Ok(Some(msg)) = liquidity_manager.read(LSPS_MESSAGE_TYPE_ID, &mut reader) {
		let secp = Secp256k1::signing_only();
		let sender_node_id =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
		let _ = liquidity_manager.handle_custom_message(msg, sender_node_id);
	}
}

pub fn lsps_message_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn lsps_message_run(data: *const u8, datalen: usize) {
	do_test(unsafe { core::slice::from_raw_parts(data, datalen) });
}
