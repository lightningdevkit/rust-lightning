// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test ChannelManager behavior with fewer confirmations required than the default and
//! other behavior that exists only on private channels or with a semi-trusted counterparty (eg
//! LSP).

use chain::Watch;
use chain::channelmonitor::ChannelMonitor;
use ln::channelmanager::{ChannelManager, ChannelManagerReadArgs, MIN_CLTV_EXPIRY_DELTA};
use routing::network_graph::RoutingFees;
use routing::router::{RouteHint, RouteHintHop};
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, RoutingMessageHandler};
use util::enforcing_trait_impls::EnforcingSigner;
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use util::config::UserConfig;
use util::ser::{Writeable, ReadableArgs};
use util::test_utils;

use prelude::*;
use core::default::Default;

use ln::functional_test_utils::*;

use bitcoin::hash_types::BlockHash;

#[test]
fn test_priv_forwarding_rejection() {
	// If we have a private channel with outbound liquidity, and
	// UserConfig::accept_forwards_to_priv_channels is set to false, we should reject any attempts
	// to forward through that channel.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut no_announce_cfg = test_default_channel_config();
	no_announce_cfg.accept_forwards_to_priv_channels = false;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(no_announce_cfg), None]);
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_1_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_id_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000, InitFeatures::known(), InitFeatures::known()).2;
	let chan_id_2 = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 500_000_000, InitFeatures::known(), InitFeatures::known()).0.channel_id;

	// We should always be able to forward through nodes[1] as long as its out through a public
	// channel:
	send_payment(&nodes[2], &[&nodes[1], &nodes[0]], 10_000);

	// ... however, if we send to nodes[2], we will have to pass the private channel from nodes[1]
	// to nodes[2], which should be rejected:
	let route_hint = RouteHint(vec![RouteHintHop {
		src_node_id: nodes[1].node.get_our_node_id(),
		short_channel_id: nodes[2].node.list_channels()[0].short_channel_id.unwrap(),
		fees: RoutingFees { base_msat: 1000, proportional_millionths: 0 },
		cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	}]);
	let last_hops = vec![route_hint];
	let (route, our_payment_hash, our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], last_hops, 10_000, TEST_FINAL_CLTV);

	nodes[0].node.send_payment(&route, our_payment_hash, &Some(our_payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let payment_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false, true);

	let htlc_fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_fail_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_fail_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_fail_updates.update_fail_malformed_htlcs.is_empty());
	assert!(htlc_fail_updates.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_fail_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_fail_updates.commitment_signed, true, true);
	expect_payment_failed_with_update!(nodes[0], our_payment_hash, false, nodes[2].node.list_channels()[0].short_channel_id.unwrap(), true);

	// Now disconnect nodes[1] from its peers and restart with accept_forwards_to_priv_channels set
	// to true. Sadly there is currently no way to change it at runtime.

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	let nodes_1_serialized = nodes[1].node.encode();
	let mut monitor_a_serialized = test_utils::TestVecWriter(Vec::new());
	let mut monitor_b_serialized = test_utils::TestVecWriter(Vec::new());
	get_monitor!(nodes[1], chan_id_1).write(&mut monitor_a_serialized).unwrap();
	get_monitor!(nodes[1], chan_id_2).write(&mut monitor_b_serialized).unwrap();

	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[1].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[1].chain_source), nodes[1].tx_broadcaster.clone(), nodes[1].logger, node_cfgs[1].fee_estimator, &persister, keys_manager);
	nodes[1].chain_monitor = &new_chain_monitor;

	let mut monitor_a_read = &monitor_a_serialized.0[..];
	let mut monitor_b_read = &monitor_b_serialized.0[..];
	let (_, mut monitor_a) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(&mut monitor_a_read, keys_manager).unwrap();
	let (_, mut monitor_b) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(&mut monitor_b_read, keys_manager).unwrap();
	assert!(monitor_a_read.is_empty());
	assert!(monitor_b_read.is_empty());

	no_announce_cfg.accept_forwards_to_priv_channels = true;

	let mut nodes_1_read = &nodes_1_serialized[..];
	let (_, nodes_1_deserialized_tmp) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(monitor_a.get_funding_txo().0, &mut monitor_a);
		channel_monitors.insert(monitor_b.get_funding_txo().0, &mut monitor_b);
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut nodes_1_read, ChannelManagerReadArgs {
			default_config: no_announce_cfg,
			keys_manager,
			fee_estimator: node_cfgs[1].fee_estimator,
			chain_monitor: nodes[1].chain_monitor,
			tx_broadcaster: nodes[1].tx_broadcaster.clone(),
			logger: nodes[1].logger,
			channel_monitors,
		}).unwrap()
	};
	assert!(nodes_1_read.is_empty());
	nodes_1_deserialized = nodes_1_deserialized_tmp;

	assert!(nodes[1].chain_monitor.watch_channel(monitor_a.get_funding_txo().0, monitor_a).is_ok());
	assert!(nodes[1].chain_monitor.watch_channel(monitor_b.get_funding_txo().0, monitor_b).is_ok());
	check_added_monitors!(nodes[1], 2);
	nodes[1].node = &nodes_1_deserialized;

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let as_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish);
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
	get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());

	nodes[1].node.peer_connected(&nodes[2].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known() });
	nodes[2].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[2].node.get_our_node_id());
	let cs_reestablish = get_event_msg!(nodes[2], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	nodes[2].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	nodes[1].node.handle_channel_reestablish(&nodes[2].node.get_our_node_id(), &cs_reestablish);
	get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[2].node.get_our_node_id());
	get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());

	nodes[0].node.send_payment(&route, our_payment_hash, &Some(our_payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], 10_000, our_payment_hash, our_payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], our_payment_preimage);
}

fn do_test_1_conf_open(connect_style: ConnectStyle) {
	// Previously, if the minium_depth config was set to 1, we'd never send a funding_locked. This
	// tests that we properly send one in that case.
	let mut alice_config = UserConfig::default();
	alice_config.own_channel_config.minimum_depth = 1;
	alice_config.channel_options.announced_channel = true;
	alice_config.peer_channel_config_limits.force_announced_channel_preference = false;
	let mut bob_config = UserConfig::default();
	bob_config.own_channel_config.minimum_depth = 1;
	bob_config.channel_options.announced_channel = true;
	bob_config.peer_channel_config_limits.force_announced_channel_preference = false;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(alice_config), Some(bob_config)]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	*nodes[0].connect_style.borrow_mut() = connect_style;

	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001, InitFeatures::known(), InitFeatures::known());
	mine_transaction(&nodes[1], &tx);
	nodes[0].node.handle_funding_locked(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingLocked, nodes[0].node.get_our_node_id()));
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	mine_transaction(&nodes[0], &tx);
	let as_msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_msg_events.len(), 2);
	let as_funding_locked = if let MessageSendEvent::SendFundingLocked { ref node_id, ref msg } = as_msg_events[0] {
		assert_eq!(*node_id, nodes[1].node.get_our_node_id());
		msg.clone()
	} else { panic!("Unexpected event"); };
	if let MessageSendEvent::SendChannelUpdate { ref node_id, msg: _ } = as_msg_events[1] {
		assert_eq!(*node_id, nodes[1].node.get_our_node_id());
	} else { panic!("Unexpected event"); }

	nodes[1].node.handle_funding_locked(&nodes[0].node.get_our_node_id(), &as_funding_locked);
	let bs_msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_msg_events.len(), 1);
	if let MessageSendEvent::SendChannelUpdate { ref node_id, msg: _ } = bs_msg_events[0] {
		assert_eq!(*node_id, nodes[0].node.get_our_node_id());
	} else { panic!("Unexpected event"); }

	send_payment(&nodes[0], &[&nodes[1]], 100_000);

	// After 6 confirmations, as required by the spec, we'll send announcement_signatures and
	// broadcast the channel_announcement (but not before exactly 6 confirmations).
	connect_blocks(&nodes[0], 4);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	connect_blocks(&nodes[0], 1);
	nodes[1].node.handle_announcement_signatures(&nodes[0].node.get_our_node_id(), &get_event_msg!(nodes[0], MessageSendEvent::SendAnnouncementSignatures, nodes[1].node.get_our_node_id()));
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	connect_blocks(&nodes[1], 5);
	let bs_announce_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_announce_events.len(), 2);
	let bs_announcement_sigs = if let MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } = bs_announce_events[0] {
		assert_eq!(*node_id, nodes[0].node.get_our_node_id());
		msg.clone()
	} else { panic!("Unexpected event"); };
	let (bs_announcement, bs_update) = if let MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } = bs_announce_events[1] {
		(msg.clone(), update_msg.clone())
	} else { panic!("Unexpected event"); };

	nodes[0].node.handle_announcement_signatures(&nodes[1].node.get_our_node_id(), &bs_announcement_sigs);
	let as_announce_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_announce_events.len(), 1);
	let (announcement, as_update) = if let MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } = as_announce_events[0] {
		(msg.clone(), update_msg.clone())
	} else { panic!("Unexpected event"); };
	assert_eq!(announcement, bs_announcement);

	for node in nodes {
		assert!(node.net_graph_msg_handler.handle_channel_announcement(&announcement).unwrap());
		node.net_graph_msg_handler.handle_channel_update(&as_update).unwrap();
		node.net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
	}
}
#[test]
fn test_1_conf_open() {
	do_test_1_conf_open(ConnectStyle::BestBlockFirst);
	do_test_1_conf_open(ConnectStyle::TransactionsFirst);
	do_test_1_conf_open(ConnectStyle::FullBlockViaListen);
}
