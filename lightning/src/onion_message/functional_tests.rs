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
use ln::features::InitFeatures;
use ln::msgs::{self, OnionMessageHandler};
use super::blinded_route::BlindedRoute;
use super::messenger::{Destination, OnionMessenger, SendError};
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
	let mut nodes = Vec::new();
	for i in 0..num_messengers {
		let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
		let seed = [i as u8; 32];
		let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&seed, Network::Testnet));
		nodes.push(MessengerNode {
			keys_manager: keys_manager.clone(),
			messenger: OnionMessenger::new(keys_manager, logger.clone()),
			logger,
		});
	}
	for idx in 0..num_messengers - 1 {
		let i = idx as usize;
		let mut features = InitFeatures::known();
		features.set_onion_messages_optional();
		let init_msg = msgs::Init { features, remote_network_address: None };
		nodes[i].messenger.peer_connected(&nodes[i + 1].get_node_pk(), &init_msg.clone());
		nodes[i + 1].messenger.peer_connected(&nodes[i].get_node_pk(), &init_msg.clone());
	}
	nodes
}

fn pass_along_path(path: &Vec<MessengerNode>, expected_path_id: Option<[u8; 32]>) {
	let mut prev_node = &path[0];
	let num_nodes = path.len();
	for (idx, node) in path.into_iter().skip(1).enumerate() {
		let events = prev_node.messenger.release_pending_msgs();
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

	nodes[0].messenger.send_onion_message(&[], Destination::Node(nodes[1].get_node_pk()), None).unwrap();
	pass_along_path(&nodes, None);
}

#[test]
fn two_unblinded_hops() {
	let nodes = create_nodes(3);

	nodes[0].messenger.send_onion_message(&[nodes[1].get_node_pk()], Destination::Node(nodes[2].get_node_pk()), None).unwrap();
	pass_along_path(&nodes, None);
}

#[test]
fn two_unblinded_two_blinded() {
	let nodes = create_nodes(5);

	let secp_ctx = Secp256k1::new();
	let blinded_route = BlindedRoute::new(&[nodes[3].get_node_pk(), nodes[4].get_node_pk()], &*nodes[4].keys_manager, &secp_ctx).unwrap();

	nodes[0].messenger.send_onion_message(&[nodes[1].get_node_pk(), nodes[2].get_node_pk()], Destination::BlindedRoute(blinded_route), None).unwrap();
	pass_along_path(&nodes, None);
}

#[test]
fn three_blinded_hops() {
	let nodes = create_nodes(4);

	let secp_ctx = Secp256k1::new();
	let blinded_route = BlindedRoute::new(&[nodes[1].get_node_pk(), nodes[2].get_node_pk(), nodes[3].get_node_pk()], &*nodes[3].keys_manager, &secp_ctx).unwrap();

	nodes[0].messenger.send_onion_message(&[], Destination::BlindedRoute(blinded_route), None).unwrap();
	pass_along_path(&nodes, None);
}

#[test]
fn too_big_packet_error() {
	// Make sure we error as expected if a packet is too big to send.
	let nodes = create_nodes(2);

	let hop_node_id = nodes[1].get_node_pk();
	let hops = [hop_node_id; 400];
	let err = nodes[0].messenger.send_onion_message(&hops, Destination::Node(hop_node_id), None).unwrap_err();
	assert_eq!(err, SendError::TooBigPacket);
}

#[test]
fn invalid_blinded_route_error() {
	// Make sure we error as expected if a provided blinded route has 0 or 1 hops.
	let nodes = create_nodes(3);

	// 0 hops
	let secp_ctx = Secp256k1::new();
	let mut blinded_route = BlindedRoute::new(&[nodes[1].get_node_pk(), nodes[2].get_node_pk()], &*nodes[2].keys_manager, &secp_ctx).unwrap();
	blinded_route.blinded_hops.clear();
	let err = nodes[0].messenger.send_onion_message(&[], Destination::BlindedRoute(blinded_route), None).unwrap_err();
	assert_eq!(err, SendError::TooFewBlindedHops);

	// 1 hop
	let mut blinded_route = BlindedRoute::new(&[nodes[1].get_node_pk(), nodes[2].get_node_pk()], &*nodes[2].keys_manager, &secp_ctx).unwrap();
	blinded_route.blinded_hops.remove(0);
	assert_eq!(blinded_route.blinded_hops.len(), 1);
	let err = nodes[0].messenger.send_onion_message(&[], Destination::BlindedRoute(blinded_route), None).unwrap_err();
	assert_eq!(err, SendError::TooFewBlindedHops);
}

#[test]
fn reply_path() {
	let nodes = create_nodes(4);
	let secp_ctx = Secp256k1::new();

	// Destination::Node
	let reply_path = BlindedRoute::new(&[nodes[2].get_node_pk(), nodes[1].get_node_pk(), nodes[0].get_node_pk()], &*nodes[0].keys_manager, &secp_ctx).unwrap();
	nodes[0].messenger.send_onion_message(&[nodes[1].get_node_pk(), nodes[2].get_node_pk()], Destination::Node(nodes[3].get_node_pk()), Some(reply_path)).unwrap();
	pass_along_path(&nodes, None);
	// Make sure the last node successfully decoded the reply path.
	nodes[3].logger.assert_log_contains(
		"lightning::onion_message::messenger".to_string(),
		format!("Received an onion message with path_id: None and reply_path").to_string(), 1);

	// Destination::BlindedRoute
	let blinded_route = BlindedRoute::new(&[nodes[1].get_node_pk(), nodes[2].get_node_pk(), nodes[3].get_node_pk()], &*nodes[3].keys_manager, &secp_ctx).unwrap();
	let reply_path = BlindedRoute::new(&[nodes[2].get_node_pk(), nodes[1].get_node_pk(), nodes[0].get_node_pk()], &*nodes[0].keys_manager, &secp_ctx).unwrap();

	nodes[0].messenger.send_onion_message(&[], Destination::BlindedRoute(blinded_route), Some(reply_path)).unwrap();
	pass_along_path(&nodes, None);
	nodes[3].logger.assert_log_contains(
		"lightning::onion_message::messenger".to_string(),
		format!("Received an onion message with path_id: None and reply_path").to_string(), 2);
}

#[test]
fn peer_buffer_full() {
	let nodes = create_nodes(2);
	for _ in 0..188 { // Based on MAX_PER_PEER_BUFFER_SIZE in OnionMessenger
		nodes[0].messenger.send_onion_message(&[], Destination::Node(nodes[1].get_node_pk()), None).unwrap();
	}
	let err = nodes[0].messenger.send_onion_message(&[], Destination::Node(nodes[1].get_node_pk()), None).unwrap_err();
	assert_eq!(err, SendError::BufferFull);
}
