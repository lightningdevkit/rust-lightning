#![cfg(test)]

use lightning_liquidity::utils::time::TimeProvider;
use lightning_liquidity::{LiquidityClientConfig, LiquidityManager, LiquidityServiceConfig};

use lightning::chain::{BestBlock, Filter};
use lightning::ln::channelmanager::ChainParameters;
use lightning::ln::functional_test_utils::{Node, TestChannelManager};
use lightning::util::test_utils::TestKeysInterface;

use bitcoin::Network;

use core::ops::Deref;

use std::sync::Arc;

pub(crate) struct LSPSNodes<'a, 'b, 'c> {
	pub service_node: LiquidityNode<'a, 'b, 'c>,
	pub client_node: LiquidityNode<'a, 'b, 'c>,
}

pub(crate) fn create_service_and_client_nodes<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>, service_config: LiquidityServiceConfig,
	client_config: LiquidityClientConfig, time_provider: Arc<dyn TimeProvider + Send + Sync>,
) -> LSPSNodes<'a, 'b, 'c> {
	let chain_params = ChainParameters {
		network: Network::Testnet,
		best_block: BestBlock::from_network(Network::Testnet),
	};
	let service_lm = LiquidityManager::new_with_custom_time_provider(
		nodes[0].keys_manager,
		nodes[0].keys_manager,
		nodes[0].node,
		None::<Arc<dyn Filter + Send + Sync>>,
		Some(chain_params.clone()),
		Some(service_config),
		None,
		Arc::clone(&time_provider),
	);

	let client_lm = LiquidityManager::new_with_custom_time_provider(
		nodes[1].keys_manager,
		nodes[1].keys_manager,
		nodes[1].node,
		None::<Arc<dyn Filter + Send + Sync>>,
		Some(chain_params),
		None,
		Some(client_config),
		time_provider,
	);

	let mut iter = nodes.into_iter();
	let service_node = LiquidityNode::new(iter.next().unwrap(), service_lm);
	let client_node = LiquidityNode::new(iter.next().unwrap(), client_lm);

	LSPSNodes { service_node, client_node }
}

pub(crate) struct LiquidityNode<'a, 'b, 'c> {
	pub inner: Node<'a, 'b, 'c>,
	pub liquidity_manager: LiquidityManager<
		&'c TestKeysInterface,
		&'c TestKeysInterface,
		&'a TestChannelManager<'b, 'c>,
		Arc<dyn Filter + Send + Sync>,
		Arc<dyn TimeProvider + Send + Sync>,
	>,
}

impl<'a, 'b, 'c> LiquidityNode<'a, 'b, 'c> {
	pub fn new(
		node: Node<'a, 'b, 'c>,
		liquidity_manager: LiquidityManager<
			&'c TestKeysInterface,
			&'c TestKeysInterface,
			&'a TestChannelManager<'b, 'c>,
			Arc<dyn Filter + Send + Sync>,
			Arc<dyn TimeProvider + Send + Sync>,
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
