// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion message testing and test utilities live here.

use chain::keysinterface::{KeysInterface, Recipient};
use super::{BlindedRoute, Destination, OnionMessenger};
use util::enforcing_trait_impls::EnforcingSigner;
use util::test_utils;

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1};

use sync::Arc;

struct MessengerNode {
	keys_manager: Arc<test_utils::TestKeysInterface>,
	messenger: OnionMessenger<EnforcingSigner, Arc<test_utils::TestKeysInterface>, Arc<test_utils::TestLogger>>,
	logger: Arc<test_utils::TestLogger>,
}

impl MessengerNode {
	fn get_node_pk(&self) -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &self.keys_manager.get_node_secret(Recipient::Node).unwrap())
	}
}

fn create_nodes(num_messengers: u8) -> Vec<MessengerNode> {
	let mut res = Vec::new();
	for i in 0..num_messengers {
		let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
		let seed = [i as u8; 32];
		let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&seed, Network::Testnet));
		res.push(MessengerNode {
			keys_manager: keys_manager.clone(),
			messenger: OnionMessenger::new(keys_manager, logger.clone()),
			logger,
		});
	}
	res
}

fn pass_along_path(mut path: Vec<MessengerNode>, expected_path_id: Option<[u8; 32]>) {
	let mut prev_node = path.remove(0);
	let num_nodes = path.len();
	for (idx, node) in path.into_iter().enumerate() {
		let events = prev_node.messenger.release_pending_msgs();
		assert_eq!(events.len(), 1);
		let onion_msg =  {
			let msgs = events.get(&node.get_node_pk()).unwrap();
			assert_eq!(msgs.len(), 1);
			msgs[0].clone()
		};
		node.messenger.handle_onion_message(&prev_node.get_node_pk(), &onion_msg);
		if idx == num_nodes - 1 {
			node.logger.assert_log_contains(
				"lightning::onion_message::messenger".to_string(),
				format!("Received an onion message with path_id: {:02x?}", expected_path_id).to_string(), 1);
		}
		prev_node = node;
	}
}

#[test]
fn one_hop() {
	let nodes = create_nodes(2);

	nodes[0].messenger.send_onion_message(&[], Destination::Node(nodes[1].get_node_pk())).unwrap();
	pass_along_path(nodes, None);
}

#[test]
fn two_unblinded_hops() {
	let nodes = create_nodes(3);

	nodes[0].messenger.send_onion_message(&[nodes[1].get_node_pk()], Destination::Node(nodes[2].get_node_pk())).unwrap();
	pass_along_path(nodes, None);
}

#[test]
fn two_unblinded_two_blinded() {
	let nodes = create_nodes(5);

	let secp_ctx = Secp256k1::new();
	let blinded_route = BlindedRoute::new::<EnforcingSigner, _, _>(&[nodes[3].get_node_pk(), nodes[4].get_node_pk()], &*nodes[4].keys_manager, &secp_ctx).unwrap();

	nodes[0].messenger.send_onion_message(&[nodes[1].get_node_pk(), nodes[2].get_node_pk()], Destination::BlindedRoute(blinded_route)).unwrap();
	pass_along_path(nodes, None);
}

#[test]
fn three_blinded_hops() {
	let nodes = create_nodes(4);

	let secp_ctx = Secp256k1::new();
	let blinded_route = BlindedRoute::new::<EnforcingSigner, _, _>(&[nodes[1].get_node_pk(), nodes[2].get_node_pk(), nodes[3].get_node_pk()], &*nodes[3].keys_manager, &secp_ctx).unwrap();

	nodes[0].messenger.send_onion_message(&[], Destination::BlindedRoute(blinded_route)).unwrap();
	pass_along_path(nodes, None);
}
