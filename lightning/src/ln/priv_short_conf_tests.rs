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
use chain::keysinterface::{Recipient, KeysInterface};
use ln::channelmanager::{ChannelManager, ChannelManagerReadArgs, MIN_CLTV_EXPIRY_DELTA};
use routing::network_graph::RoutingFees;
use routing::router::{PaymentParameters, RouteHint, RouteHintHop};
use ln::features::{InitFeatures, InvoiceFeatures};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, RoutingMessageHandler, OptionalField, ChannelUpdate};
use ln::wire::Encode;
use util::enforcing_trait_impls::EnforcingSigner;
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use util::config::UserConfig;
use util::ser::{Writeable, ReadableArgs};
use util::test_utils;

use prelude::*;
use core::default::Default;

use ln::functional_test_utils::*;

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;

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
	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id())
		.with_features(InvoiceFeatures::known())
		.with_route_hints(last_hops);
	let (route, our_payment_hash, our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 10_000, TEST_FINAL_CLTV);

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

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known(), remote_network_address: None });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty(), remote_network_address: None });
	let as_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &as_reestablish);
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
	get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());

	nodes[1].node.peer_connected(&nodes[2].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known(), remote_network_address: None });
	nodes[2].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty(), remote_network_address: None });
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

#[test]
fn test_routed_scid_alias() {
	// Trivially test sending a payment which is routed through an SCID alias.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut no_announce_cfg = test_default_channel_config();
	no_announce_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(no_announce_cfg), None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000, InitFeatures::known(), InitFeatures::known()).2;
	let mut as_funding_locked = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 500_000_000, InitFeatures::known(), InitFeatures::known()).0;

	let last_hop = nodes[2].node.list_usable_channels();
	let hop_hints = vec![RouteHint(vec![RouteHintHop {
		src_node_id: nodes[1].node.get_our_node_id(),
		short_channel_id: last_hop[0].inbound_scid_alias.unwrap(),
		fees: RoutingFees {
			base_msat: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_base_msat,
			proportional_millionths: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_proportional_millionths,
		},
		cltv_expiry_delta: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().cltv_expiry_delta,
		htlc_maximum_msat: None,
		htlc_minimum_msat: None,
	}])];
	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id())
		.with_features(InvoiceFeatures::known())
		.with_route_hints(hop_hints);
	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 100_000, 42);
	assert_eq!(route.paths[0][1].short_channel_id, last_hop[0].inbound_scid_alias.unwrap());
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);

	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], 100_000, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// Now test that if a peer sends us a second funding_locked after the channel is operational we
	// will use the new alias.
	as_funding_locked.short_channel_id_alias = Some(0xdeadbeef);
	nodes[2].node.handle_funding_locked(&nodes[1].node.get_our_node_id(), &as_funding_locked);
	// Note that we always respond to a funding_locked with a channel_update. Not a lot of reason
	// to bother updating that code, so just drop the message here.
	get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
	let updated_channel_info = nodes[2].node.list_usable_channels();
	assert_eq!(updated_channel_info.len(), 1);
	assert_eq!(updated_channel_info[0].inbound_scid_alias.unwrap(), 0xdeadbeef);
	// Note that because we never send a duplicate funding_locked we can't send a payment through
	// the 0xdeadbeef SCID alias.
}

#[test]
fn test_scid_privacy_on_pub_channel() {
	// Tests rejecting the scid_privacy feature for public channels and that we don't ever try to
	// send them.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let mut scid_privacy_cfg = test_default_channel_config();
	scid_privacy_cfg.channel_options.announced_channel = true;
	scid_privacy_cfg.own_channel_config.negotiate_scid_privacy = true;
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, Some(scid_privacy_cfg)).unwrap();
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	assert!(!open_channel.channel_type.as_ref().unwrap().supports_scid_privacy()); // we ignore `negotiate_scid_privacy` on pub channels
	open_channel.channel_type.as_mut().unwrap().set_scid_privacy_required();
	assert_eq!(open_channel.channel_flags & 1, 1); // The `announce_channel` bit is set.

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_channel);
	let err = get_err_msg!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(err.data, "SCID Alias/Privacy Channel Type cannot be set on a public channel");
}

#[test]
fn test_scid_privacy_negotiation() {
	// Tests of the negotiation of SCID alias and falling back to non-SCID-alias if our
	// counterparty doesn't support it.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let mut scid_privacy_cfg = test_default_channel_config();
	scid_privacy_cfg.channel_options.announced_channel = false;
	scid_privacy_cfg.own_channel_config.negotiate_scid_privacy = true;
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, Some(scid_privacy_cfg)).unwrap();

	let init_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(init_open_channel.channel_type.as_ref().unwrap().supports_scid_privacy());
	assert!(nodes[0].node.list_channels()[0].channel_type.is_none()); // channel_type is none until counterparty accepts

	// now simulate nodes[1] responding with an Error message, indicating it doesn't understand
	// SCID alias.
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage {
		channel_id: init_open_channel.temporary_channel_id,
		data: "Yo, no SCID aliases, no privacy here!".to_string()
	});
	assert!(nodes[0].node.list_channels()[0].channel_type.is_none()); // channel_type is none until counterparty accepts

	let second_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(!second_open_channel.channel_type.as_ref().unwrap().supports_scid_privacy());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &second_open_channel);
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { .. } => {},
		_ => panic!("Unexpected event"),
	}

	assert!(!nodes[0].node.list_channels()[0].channel_type.as_ref().unwrap().supports_scid_privacy());
	assert!(!nodes[1].node.list_channels()[0].channel_type.as_ref().unwrap().supports_scid_privacy());
}

#[test]
fn test_inbound_scid_privacy() {
	// Tests accepting channels with the scid_privacy feature and rejecting forwards using the
	// channel's real SCID as required by the channel feature.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(accept_forward_cfg), None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0, InitFeatures::known(), InitFeatures::known());

	let mut no_announce_cfg = test_default_channel_config();
	no_announce_cfg.channel_options.announced_channel = false;
	no_announce_cfg.own_channel_config.negotiate_scid_privacy = true;
	nodes[1].node.create_channel(nodes[2].node.get_our_node_id(), 100_000, 10_000, 42, Some(no_announce_cfg)).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[2].node.get_our_node_id());

	assert!(open_channel.channel_type.as_ref().unwrap().requires_scid_privacy());

	nodes[2].node.handle_open_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &open_channel);
	let accept_channel = get_event_msg!(nodes[2], MessageSendEvent::SendAcceptChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_accept_channel(&nodes[2].node.get_our_node_id(), InitFeatures::known(), &accept_channel);

	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[1], &nodes[2].node.get_our_node_id(), 100_000, 42);
	nodes[1].node.funding_transaction_generated(&temporary_channel_id, tx.clone()).unwrap();
	nodes[2].node.handle_funding_created(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingCreated, nodes[2].node.get_our_node_id()));
	check_added_monitors!(nodes[2], 1);

	let cs_funding_signed = get_event_msg!(nodes[2], MessageSendEvent::SendFundingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_signed(&nodes[2].node.get_our_node_id(), &cs_funding_signed);
	check_added_monitors!(nodes[1], 1);

	let conf_height = core::cmp::max(nodes[1].best_block_info().1 + 1, nodes[2].best_block_info().1 + 1);
	confirm_transaction_at(&nodes[1], &tx, conf_height);
	connect_blocks(&nodes[1], CHAN_CONFIRM_DEPTH - 1);
	confirm_transaction_at(&nodes[2], &tx, conf_height);
	connect_blocks(&nodes[2], CHAN_CONFIRM_DEPTH - 1);
	let bs_funding_locked = get_event_msg!(nodes[1], MessageSendEvent::SendFundingLocked, nodes[2].node.get_our_node_id());
	nodes[1].node.handle_funding_locked(&nodes[2].node.get_our_node_id(), &get_event_msg!(nodes[2], MessageSendEvent::SendFundingLocked, nodes[1].node.get_our_node_id()));
	let bs_update = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[2].node.get_our_node_id());
	nodes[2].node.handle_funding_locked(&nodes[1].node.get_our_node_id(), &bs_funding_locked);
	let cs_update = get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_channel_update(&nodes[2].node.get_our_node_id(), &cs_update);
	nodes[2].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &bs_update);

	// Now we can pay just fine using the SCID alias nodes[2] gave to nodes[1]...

	let last_hop = nodes[2].node.list_usable_channels();
	let mut hop_hints = vec![RouteHint(vec![RouteHintHop {
		src_node_id: nodes[1].node.get_our_node_id(),
		short_channel_id: last_hop[0].inbound_scid_alias.unwrap(),
		fees: RoutingFees {
			base_msat: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_base_msat,
			proportional_millionths: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_proportional_millionths,
		},
		cltv_expiry_delta: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().cltv_expiry_delta,
		htlc_maximum_msat: None,
		htlc_minimum_msat: None,
	}])];
	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id())
		.with_features(InvoiceFeatures::known())
		.with_route_hints(hop_hints.clone());
	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 100_000, 42);
	assert_eq!(route.paths[0][1].short_channel_id, last_hop[0].inbound_scid_alias.unwrap());
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);

	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], 100_000, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// ... but if we try to pay using the real SCID, nodes[1] will just tell us they don't know
	// what channel we're talking about.
	hop_hints[0].0[0].short_channel_id = last_hop[0].short_channel_id.unwrap();

	let payment_params_2 = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id())
		.with_features(InvoiceFeatures::known())
		.with_route_hints(hop_hints);
	let (route_2, payment_hash_2, _, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[2], payment_params_2, 100_000, 42);
	assert_eq!(route_2.paths[0][1].short_channel_id, last_hop[0].short_channel_id.unwrap());
	nodes[0].node.send_payment(&route_2, payment_hash_2, &Some(payment_secret_2)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let payment_event = SendEvent::from_node(&nodes[0]);
	assert_eq!(nodes[1].node.get_our_node_id(), payment_event.node_id);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, true, true);

	nodes[1].logger.assert_log_regex("lightning::ln::channelmanager".to_string(), regex::Regex::new(r"Refusing to forward over real channel SCID as our counterparty requested").unwrap(), 1);

	let mut updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);

	expect_payment_failed_conditions!(nodes[0], payment_hash_2, false,
		PaymentFailedConditions::new().blamed_scid(last_hop[0].short_channel_id.unwrap())
			.blamed_chan_closed(true).expected_htlc_error_data(0x4000|10, &[0; 0]));
}

#[test]
fn test_scid_alias_returned() {
	// Tests that when we fail an HTLC (in this case due to attempting to forward more than the
	// channel's available balance) we use the correct (in this case the aliased) SCID in the
	// channel_update which is returned in the onion to the sender.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(accept_forward_cfg), None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0, InitFeatures::known(), InitFeatures::known());
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000, 0, InitFeatures::known(), InitFeatures::known());

	let last_hop = nodes[2].node.list_usable_channels();
	let mut hop_hints = vec![RouteHint(vec![RouteHintHop {
		src_node_id: nodes[1].node.get_our_node_id(),
		short_channel_id: last_hop[0].inbound_scid_alias.unwrap(),
		fees: RoutingFees {
			base_msat: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_base_msat,
			proportional_millionths: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_proportional_millionths,
		},
		cltv_expiry_delta: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().cltv_expiry_delta,
		htlc_maximum_msat: None,
		htlc_minimum_msat: None,
	}])];
	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id())
		.with_features(InvoiceFeatures::known())
		.with_route_hints(hop_hints);
	let (mut route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 10_000, 42);
	assert_eq!(route.paths[0][1].short_channel_id, nodes[2].node.list_usable_channels()[0].inbound_scid_alias.unwrap());

	route.paths[0][1].fee_msat = 10_000_000; // Overshoot the last channel's value

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &as_updates.commitment_signed, false, true);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_updates.commitment_signed, false, true);

	// Build the expected channel update
	let contents = msgs::UnsignedChannelUpdate {
		chain_hash: genesis_block(Network::Testnet).header.block_hash(),
		short_channel_id: last_hop[0].inbound_scid_alias.unwrap(),
		timestamp: 21,
		flags: 1,
		cltv_expiry_delta: accept_forward_cfg.channel_options.cltv_expiry_delta,
		htlc_minimum_msat: 1_000,
		htlc_maximum_msat: OptionalField::Present(1_000_000), // Defaults to 10% of the channel value
		fee_base_msat: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_base_msat,
		fee_proportional_millionths: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_proportional_millionths,
		excess_data: Vec::new(),
	};
	let msg_hash = Sha256dHash::hash(&contents.encode()[..]);
	let signature = Secp256k1::new().sign_ecdsa(&hash_to_message!(&msg_hash[..]), &nodes[1].keys_manager.get_node_secret(Recipient::Node).unwrap());
	let msg = msgs::ChannelUpdate { signature, contents };

	let mut err_data = Vec::new();
	err_data.extend_from_slice(&(msg.serialized_length() as u16 + 2).to_be_bytes());
	err_data.extend_from_slice(&ChannelUpdate::TYPE.to_be_bytes());
	err_data.extend_from_slice(&msg.encode());

	expect_payment_failed_conditions!(nodes[0], payment_hash, false,
		PaymentFailedConditions::new().blamed_scid(last_hop[0].inbound_scid_alias.unwrap())
			.blamed_chan_closed(false).expected_htlc_error_data(0x1000|7, &err_data));

	route.paths[0][1].fee_msat = 10_000; // Reset to the correct payment amount
	route.paths[0][0].fee_msat = 0; // But set fee paid to the middle hop to 0

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let as_updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &as_updates.commitment_signed, false, true);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_updates.commitment_signed, false, true);

	let mut err_data = Vec::new();
	err_data.extend_from_slice(&10_000u64.to_be_bytes());
	err_data.extend_from_slice(&(msg.serialized_length() as u16 + 2).to_be_bytes());
	err_data.extend_from_slice(&ChannelUpdate::TYPE.to_be_bytes());
	err_data.extend_from_slice(&msg.encode());
	expect_payment_failed_conditions!(nodes[0], payment_hash, false,
		PaymentFailedConditions::new().blamed_scid(last_hop[0].inbound_scid_alias.unwrap())
			.blamed_chan_closed(false).expected_htlc_error_data(0x1000|12, &err_data));
}
