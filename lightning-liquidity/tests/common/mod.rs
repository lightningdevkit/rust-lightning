#![cfg(test)]

use lightning_liquidity::utils::time::TimeProvider;
use lightning_liquidity::{LiquidityClientConfig, LiquidityManagerSync, LiquidityServiceConfig};

use lightning::chain::{BestBlock, Filter};
use lightning::ln::channelmanager::ChainParameters;
use lightning::ln::functional_test_utils::{Node, TestChannelManager};
use lightning::util::test_utils::{TestBroadcaster, TestKeysInterface, TestStore};

use bitcoin::Network;

use core::ops::Deref;

use std::sync::Arc;

pub(crate) struct LSPSNodes<'a, 'b, 'c> {
	pub service_node: LiquidityNode<'a, 'b, 'c>,
	pub client_node: LiquidityNode<'a, 'b, 'c>,
}

fn build_service_and_client_nodes<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, service_config: LiquidityServiceConfig,
	client_config: LiquidityClientConfig, time_provider: Arc<dyn TimeProvider + Send + Sync>,
	service_kv_store: Arc<TestStore>, client_kv_store: Arc<TestStore>,
) -> (LiquidityNode<'a, 'b, 'c>, LiquidityNode<'a, 'b, 'c>, Option<Node<'a, 'b, 'c>>) {
	assert!(nodes.len() >= 2, "Need at least two nodes (service and client)");

	let chain_params = ChainParameters {
		network: Network::Testnet,
		best_block: BestBlock::from_network(Network::Testnet),
	};

	let mut nodes_iter = nodes.into_iter();
	let service_inner = nodes_iter.next().expect("missing service node");
	let client_inner = nodes_iter.next().expect("missing client node");
	let leftover = nodes_iter.next();

	let service_lm = LiquidityManagerSync::new_with_custom_time_provider(
		service_inner.keys_manager,
		service_inner.keys_manager,
		service_inner.node,
		None::<Arc<dyn Filter + Send + Sync>>,
		Some(chain_params.clone()),
		service_kv_store,
		service_inner.tx_broadcaster,
		Some(service_config),
		None,
		Arc::clone(&time_provider),
		None,
	)
	.unwrap();

	let client_lm = LiquidityManagerSync::new_with_custom_time_provider(
		client_inner.keys_manager,
		client_inner.keys_manager,
		client_inner.node,
		None::<Arc<dyn Filter + Send + Sync>>,
		Some(chain_params),
		client_kv_store,
		client_inner.tx_broadcaster,
		None,
		Some(client_config),
		time_provider,
		None,
	)
	.unwrap();

	let service_node = LiquidityNode::new(service_inner, service_lm);
	let client_node = LiquidityNode::new(client_inner, client_lm);
	(service_node, client_node, leftover)
}

// this is ONLY used on LSPS2 so it says it's not used but it is
#[allow(dead_code)]
pub(crate) struct LSPSNodesWithPayer<'a, 'b, 'c> {
	pub service_node: LiquidityNode<'a, 'b, 'c>,
	pub client_node: LiquidityNode<'a, 'b, 'c>,
	pub payer_node: Node<'a, 'b, 'c>,
}

pub(crate) fn create_service_and_client_nodes_with_kv_stores<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, service_config: LiquidityServiceConfig,
	client_config: LiquidityClientConfig, time_provider: Arc<dyn TimeProvider + Send + Sync>,
	service_kv_store: Arc<TestStore>, client_kv_store: Arc<TestStore>,
) -> LSPSNodes<'a, 'b, 'c> {
	let (service_node, client_node, _) = build_service_and_client_nodes(
		nodes,
		service_config,
		client_config,
		time_provider,
		service_kv_store,
		client_kv_store,
	);
	LSPSNodes { service_node, client_node }
}

#[allow(dead_code)]
pub(crate) fn create_service_and_client_nodes<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, service_config: LiquidityServiceConfig,
	client_config: LiquidityClientConfig, time_provider: Arc<dyn TimeProvider + Send + Sync>,
) -> LSPSNodes<'a, 'b, 'c> {
	let service_kv_store = Arc::new(TestStore::new(false));
	let client_kv_store = Arc::new(TestStore::new(false));
	create_service_and_client_nodes_with_kv_stores(
		nodes,
		service_config,
		client_config,
		time_provider,
		service_kv_store,
		client_kv_store,
	)
}

// this is ONLY used on LSPS2 so it says it's not used but it is
#[allow(dead_code)]
pub(crate) fn create_service_client_and_payer_nodes<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, service_config: LiquidityServiceConfig,
	client_config: LiquidityClientConfig, time_provider: Arc<dyn TimeProvider + Send + Sync>,
) -> LSPSNodesWithPayer<'a, 'b, 'c> {
	assert!(nodes.len() >= 3, "Need three nodes (service, client, payer)");
	let service_kv_store = Arc::new(TestStore::new(false));
	let client_kv_store = Arc::new(TestStore::new(false));
	let (service_node, client_node, payer_opt) = build_service_and_client_nodes(
		nodes,
		service_config,
		client_config,
		time_provider,
		service_kv_store,
		client_kv_store,
	);
	let payer_node = payer_opt.expect("payer node missing");
	LSPSNodesWithPayer { service_node, client_node, payer_node }
}

pub(crate) struct LiquidityNode<'a, 'b, 'c> {
	pub inner: Node<'a, 'b, 'c>,
	pub liquidity_manager: LiquidityManagerSync<
		&'c TestKeysInterface,
		&'c TestKeysInterface,
		&'a TestChannelManager<'b, 'c>,
		Arc<dyn Filter + Send + Sync>,
		Arc<TestStore>,
		Arc<dyn TimeProvider + Send + Sync>,
		&'c TestBroadcaster,
	>,
}

impl<'a, 'b, 'c> LiquidityNode<'a, 'b, 'c> {
	pub fn new(
		node: Node<'a, 'b, 'c>,
		liquidity_manager: LiquidityManagerSync<
			&'c TestKeysInterface,
			&'c TestKeysInterface,
			&'a TestChannelManager<'b, 'c>,
			Arc<dyn Filter + Send + Sync>,
			Arc<TestStore>,
			Arc<dyn TimeProvider + Send + Sync>,
			&'c TestBroadcaster,
		>,
	) -> Self {
		Self { inner: node, liquidity_manager }
	}
}

impl<'a, 'b, 'c> Deref for LiquidityNode<'a, 'b, 'c> {
	type Target = Node<'a, 'b, 'c>;
	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

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
