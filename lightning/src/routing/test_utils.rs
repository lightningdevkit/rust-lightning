// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::routing::gossip::{NetworkGraph, P2PGossipSync};
use crate::ln::features::{ChannelFeatures, NodeFeatures};
use crate::ln::msgs::{UnsignedChannelAnnouncement, ChannelAnnouncement, RoutingMessageHandler,
	NodeAnnouncement, UnsignedNodeAnnouncement, ChannelUpdate, UnsignedChannelUpdate, MAX_VALUE_MSAT};
use crate::util::test_utils;
use crate::util::ser::Writeable;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::blockdata::constants::genesis_block;

use hex;

use bitcoin::secp256k1::{PublicKey,SecretKey};
use bitcoin::secp256k1::{Secp256k1, All};

use crate::prelude::*;
use crate::sync::{self, Arc};

use crate::routing::gossip::NodeId;

// Using the same keys for LN and BTC ids
pub(super) fn add_channel(
	gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
	secp_ctx: &Secp256k1<All>, node_1_privkey: &SecretKey, node_2_privkey: &SecretKey, features: ChannelFeatures, short_channel_id: u64
) {
	let node_id_1 = NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, node_1_privkey));
	let node_id_2 = NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, node_2_privkey));

	let unsigned_announcement = UnsignedChannelAnnouncement {
		features,
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id,
		node_id_1,
		node_id_2,
		bitcoin_key_1: node_id_1,
		bitcoin_key_2: node_id_2,
		excess_data: Vec::new(),
	};

	let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
	let valid_announcement = ChannelAnnouncement {
		node_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_privkey),
		node_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_privkey),
		bitcoin_signature_1: secp_ctx.sign_ecdsa(&msghash, node_1_privkey),
		bitcoin_signature_2: secp_ctx.sign_ecdsa(&msghash, node_2_privkey),
		contents: unsigned_announcement.clone(),
	};
	match gossip_sync.handle_channel_announcement(&valid_announcement) {
		Ok(res) => assert!(res),
		_ => panic!()
	};
}

pub(super) fn add_or_update_node(
	gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
	secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, features: NodeFeatures, timestamp: u32
) {
	let node_id = NodeId::from_pubkey(&PublicKey::from_secret_key(&secp_ctx, node_privkey));
	let unsigned_announcement = UnsignedNodeAnnouncement {
		features,
		timestamp,
		node_id,
		rgb: [0; 3],
		alias: [0; 32],
		addresses: Vec::new(),
		excess_address_data: Vec::new(),
		excess_data: Vec::new(),
	};
	let msghash = hash_to_message!(&Sha256dHash::hash(&unsigned_announcement.encode()[..])[..]);
	let valid_announcement = NodeAnnouncement {
		signature: secp_ctx.sign_ecdsa(&msghash, node_privkey),
		contents: unsigned_announcement.clone()
	};

	match gossip_sync.handle_node_announcement(&valid_announcement) {
		Ok(_) => (),
		Err(_) => panic!()
	};
}

pub(super) fn update_channel(
	gossip_sync: &P2PGossipSync<Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, Arc<test_utils::TestChainSource>, Arc<test_utils::TestLogger>>,
	secp_ctx: &Secp256k1<All>, node_privkey: &SecretKey, update: UnsignedChannelUpdate
) {
	let msghash = hash_to_message!(&Sha256dHash::hash(&update.encode()[..])[..]);
	let valid_channel_update = ChannelUpdate {
		signature: secp_ctx.sign_ecdsa(&msghash, node_privkey),
		contents: update.clone()
	};

	match gossip_sync.handle_channel_update(&valid_channel_update) {
		Ok(res) => assert!(res),
		Err(_) => panic!()
	};
}

pub(super) fn get_nodes(secp_ctx: &Secp256k1<All>) -> (SecretKey, PublicKey, Vec<SecretKey>, Vec<PublicKey>) {
	let privkeys: Vec<SecretKey> = (2..22).map(|i| {
		SecretKey::from_slice(&hex::decode(format!("{:02x}", i).repeat(32)).unwrap()[..]).unwrap()
	}).collect();

	let pubkeys = privkeys.iter().map(|secret| PublicKey::from_secret_key(&secp_ctx, secret)).collect();

	let our_privkey = SecretKey::from_slice(&hex::decode("01".repeat(32)).unwrap()[..]).unwrap();
	let our_id = PublicKey::from_secret_key(&secp_ctx, &our_privkey);

	(our_privkey, our_id, privkeys, pubkeys)
}

pub(super) fn id_to_feature_flags(id: u8) -> Vec<u8> {
	// Set the feature flags to the id'th odd (ie non-required) feature bit so that we can
	// test for it later.
	let idx = (id - 1) * 2 + 1;
	if idx > 8*3 {
		vec![1 << (idx - 8*3), 0, 0, 0]
	} else if idx > 8*2 {
		vec![1 << (idx - 8*2), 0, 0]
	} else if idx > 8*1 {
		vec![1 << (idx - 8*1), 0]
	} else {
		vec![1 << idx]
	}
}

pub(super) fn build_line_graph() -> (
	Secp256k1<All>, sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
	P2PGossipSync<sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>>,
	sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>,
) {
	let secp_ctx = Secp256k1::new();
	let logger = Arc::new(test_utils::TestLogger::new());
	let chain_monitor = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
	let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
	let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger));

	// Build network from our_id to node 19:
	// our_id -1(1)2- node0 -1(2)2- node1 - ... - node19
	let (our_privkey, _, privkeys, _) = get_nodes(&secp_ctx);

	for (idx, (cur_privkey, next_privkey)) in core::iter::once(&our_privkey)
		.chain(privkeys.iter()).zip(privkeys.iter()).enumerate() {
			let cur_short_channel_id = (idx as u64) + 1;
			add_channel(&gossip_sync, &secp_ctx, &cur_privkey, &next_privkey,
				ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), cur_short_channel_id);
			update_channel(&gossip_sync, &secp_ctx, &cur_privkey, UnsignedChannelUpdate {
				chain_hash: genesis_block(Network::Testnet).header.block_hash(),
				short_channel_id: cur_short_channel_id,
				timestamp: idx as u32,
				flags: 0,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
			update_channel(&gossip_sync, &secp_ctx, &next_privkey, UnsignedChannelUpdate {
				chain_hash: genesis_block(Network::Testnet).header.block_hash(),
				short_channel_id: cur_short_channel_id,
				timestamp: (idx as u32)+1,
				flags: 1,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: Vec::new()
			});
			add_or_update_node(&gossip_sync, &secp_ctx, &next_privkey,
				NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);
		}

	(secp_ctx, network_graph, gossip_sync, chain_monitor, logger)
}

pub(super) fn build_graph() -> (
	Secp256k1<All>,
	sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>,
	P2PGossipSync<sync::Arc<NetworkGraph<Arc<test_utils::TestLogger>>>, sync::Arc<test_utils::TestChainSource>, sync::Arc<test_utils::TestLogger>>,
	sync::Arc<test_utils::TestChainSource>,
	sync::Arc<test_utils::TestLogger>,
) {
	let secp_ctx = Secp256k1::new();
	let logger = Arc::new(test_utils::TestLogger::new());
	let chain_monitor = Arc::new(test_utils::TestChainSource::new(Network::Testnet));
	let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, Arc::clone(&logger)));
	let gossip_sync = P2PGossipSync::new(Arc::clone(&network_graph), None, Arc::clone(&logger));
	// Build network from our_id to node6:
	//
	//        -1(1)2-  node0  -1(3)2-
	//       /                       \
	// our_id -1(12)2- node7 -1(13)2--- node2
	//       \                       /
	//        -1(2)2-  node1  -1(4)2-
	//
	//
	// chan1  1-to-2: disabled
	// chan1  2-to-1: enabled, 0 fee
	//
	// chan2  1-to-2: enabled, ignored fee
	// chan2  2-to-1: enabled, 0 fee
	//
	// chan3  1-to-2: enabled, 0 fee
	// chan3  2-to-1: enabled, 100 msat fee
	//
	// chan4  1-to-2: enabled, 100% fee
	// chan4  2-to-1: enabled, 0 fee
	//
	// chan12 1-to-2: enabled, ignored fee
	// chan12 2-to-1: enabled, 0 fee
	//
	// chan13 1-to-2: enabled, 200% fee
	// chan13 2-to-1: enabled, 0 fee
	//
	//
	//       -1(5)2- node3 -1(8)2--
	//       |         2          |
	//       |       (11)         |
	//      /          1           \
	// node2--1(6)2- node4 -1(9)2--- node6 (not in global route map)
	//      \                      /
	//       -1(7)2- node5 -1(10)2-
	//
	// Channels 5, 8, 9 and 10 are private channels.
	//
	// chan5  1-to-2: enabled, 100 msat fee
	// chan5  2-to-1: enabled, 0 fee
	//
	// chan6  1-to-2: enabled, 0 fee
	// chan6  2-to-1: enabled, 0 fee
	//
	// chan7  1-to-2: enabled, 100% fee
	// chan7  2-to-1: enabled, 0 fee
	//
	// chan8  1-to-2: enabled, variable fee (0 then 1000 msat)
	// chan8  2-to-1: enabled, 0 fee
	//
	// chan9  1-to-2: enabled, 1001 msat fee
	// chan9  2-to-1: enabled, 0 fee
	//
	// chan10 1-to-2: enabled, 0 fee
	// chan10 2-to-1: enabled, 0 fee
	//
	// chan11 1-to-2: enabled, 0 fee
	// chan11 2-to-1: enabled, 0 fee

	let (our_privkey, _, privkeys, _) = get_nodes(&secp_ctx);

	add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[0], ChannelFeatures::from_le_bytes(id_to_feature_flags(1)), 1);
	update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 1,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[0], NodeFeatures::from_le_bytes(id_to_feature_flags(1)), 0);

	add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[1], ChannelFeatures::from_le_bytes(id_to_feature_flags(2)), 2);
	update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 2,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (5 << 4) | 3,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: u32::max_value(),
		fee_proportional_millionths: u32::max_value(),
		excess_data: Vec::new()
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 2,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[1], NodeFeatures::from_le_bytes(id_to_feature_flags(2)), 0);

	add_channel(&gossip_sync, &secp_ctx, &our_privkey, &privkeys[7], ChannelFeatures::from_le_bytes(id_to_feature_flags(12)), 12);
	update_channel(&gossip_sync, &secp_ctx, &our_privkey, UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 12,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (5 << 4) | 3,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: u32::max_value(),
		fee_proportional_millionths: u32::max_value(),
		excess_data: Vec::new()
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 12,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: 0,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[7], NodeFeatures::from_le_bytes(id_to_feature_flags(8)), 0);

	add_channel(&gossip_sync, &secp_ctx, &privkeys[0], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(3)), 3);
	update_channel(&gossip_sync, &secp_ctx, &privkeys[0], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 3,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (3 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 3,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (3 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 100,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});

	add_channel(&gossip_sync, &secp_ctx, &privkeys[1], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(4)), 4);
	update_channel(&gossip_sync, &secp_ctx, &privkeys[1], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 4,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (4 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 1000000,
		excess_data: Vec::new()
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 4,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (4 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});

	add_channel(&gossip_sync, &secp_ctx, &privkeys[7], &privkeys[2], ChannelFeatures::from_le_bytes(id_to_feature_flags(13)), 13);
	update_channel(&gossip_sync, &secp_ctx, &privkeys[7], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 13,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (13 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 2000000,
		excess_data: Vec::new()
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 13,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (13 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[2], NodeFeatures::from_le_bytes(id_to_feature_flags(3)), 0);

	add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[4], ChannelFeatures::from_le_bytes(id_to_feature_flags(6)), 6);
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 6,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (6 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 6,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (6 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new(),
	});

	add_channel(&gossip_sync, &secp_ctx, &privkeys[4], &privkeys[3], ChannelFeatures::from_le_bytes(id_to_feature_flags(11)), 11);
	update_channel(&gossip_sync, &secp_ctx, &privkeys[4], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 11,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (11 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[3], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 11,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (11 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[4], NodeFeatures::from_le_bytes(id_to_feature_flags(5)), 0);

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[3], NodeFeatures::from_le_bytes(id_to_feature_flags(4)), 0);

	add_channel(&gossip_sync, &secp_ctx, &privkeys[2], &privkeys[5], ChannelFeatures::from_le_bytes(id_to_feature_flags(7)), 7);
	update_channel(&gossip_sync, &secp_ctx, &privkeys[2], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 7,
		timestamp: 1,
		flags: 0,
		cltv_expiry_delta: (7 << 4) | 1,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 1000000,
		excess_data: Vec::new()
	});
	update_channel(&gossip_sync, &secp_ctx, &privkeys[5], UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: 7,
		timestamp: 1,
		flags: 1,
		cltv_expiry_delta: (7 << 4) | 2,
		htlc_minimum_msat: 0,
		htlc_maximum_msat: MAX_VALUE_MSAT,
		fee_base_msat: 0,
		fee_proportional_millionths: 0,
		excess_data: Vec::new()
	});

	add_or_update_node(&gossip_sync, &secp_ctx, &privkeys[5], NodeFeatures::from_le_bytes(id_to_feature_flags(6)), 0);

	(secp_ctx, network_graph, gossip_sync, chain_monitor, logger)
}
