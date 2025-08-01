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

use crate::chain::ChannelMonitorUpdateStatus;
use crate::events::{ClosureReason, Event, HTLCHandlingFailureType};
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields, MIN_CLTV_EXPIRY_DELTA};
use crate::ln::msgs;
use crate::ln::msgs::{
	BaseMessageHandler, ChannelMessageHandler, ErrorAction, MessageSendEvent, RoutingMessageHandler,
};
use crate::ln::onion_utils::LocalHTLCFailureReason;
use crate::ln::types::ChannelId;
use crate::routing::gossip::RoutingFees;
use crate::routing::router::{PaymentParameters, RouteHint, RouteHintHop};
use crate::types::features::ChannelTypeFeatures;
use crate::util::config::{MaxDustHTLCExposure, UserConfig};
use crate::util::ser::Writeable;

use crate::prelude::*;

use crate::ln::functional_test_utils::*;

#[test]
fn test_priv_forwarding_rejection() {
	// If we have a private channel with outbound liquidity, and
	// UserConfig::accept_forwards_to_priv_channels is set to false, we should reject any attempts
	// to forward through that channel.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut no_announce_cfg = test_default_channel_config();
	no_announce_cfg.accept_forwards_to_priv_channels = false;
	let persister;
	let new_chain_monitor;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(no_announce_cfg.clone()), None]);
	let nodes_1_deserialized;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_id_1 =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000).2;
	let chan_id_2 =
		create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 500_000_000)
			.0
			.channel_id;

	// We should always be able to forward through nodes[1] as long as its out through a public
	// channel:
	send_payment(&nodes[2], &[&nodes[1], &nodes[0]], 10_000);

	// ... however, if we send to nodes[2], we will have to pass the private channel from nodes[1]
	// to nodes[2], which should be rejected:
	let route_hint = RouteHint(vec![RouteHintHop {
		src_node_id: node_b_id,
		short_channel_id: nodes[2].node.list_channels()[0].short_channel_id.unwrap(),
		fees: RoutingFees { base_msat: 1000, proportional_millionths: 0 },
		cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	}]);
	let last_hops = vec![route_hint];
	let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap()
		.with_route_hints(last_hops)
		.unwrap();
	let (route, our_payment_hash, our_payment_preimage, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 10_000);

	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[0].node.send_payment_with_route(route.clone(), our_payment_hash, onion, id).unwrap();
	check_added_monitors!(nodes[0], 1);
	let payment_event =
		SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_id_2 }]
	);
	check_added_monitors(&nodes[1], 1);

	let htlc_fail_updates = get_htlc_update_msgs!(nodes[1], node_a_id);
	assert!(htlc_fail_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_fail_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_fail_updates.update_fail_malformed_htlcs.is_empty());
	assert!(htlc_fail_updates.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(node_b_id, &htlc_fail_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_fail_updates.commitment_signed, true, true);

	let chan_2_scid = nodes[2].node.list_channels()[0].short_channel_id.unwrap();
	expect_payment_failed_with_update!(nodes[0], our_payment_hash, false, chan_2_scid, true);

	// Now disconnect nodes[1] from its peers and restart with accept_forwards_to_priv_channels set
	// to true. Sadly there is currently no way to change it at runtime.

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[2].node.peer_disconnected(node_b_id);

	let nodes_1_serialized = nodes[1].node.encode();
	let monitor_a_serialized = get_monitor!(nodes[1], chan_id_1).encode();
	let monitor_b_serialized = get_monitor!(nodes[1], chan_id_2).encode();

	no_announce_cfg.accept_forwards_to_priv_channels = true;
	reload_node!(
		nodes[1],
		no_announce_cfg,
		&nodes_1_serialized,
		&[&monitor_a_serialized, &monitor_b_serialized],
		persister,
		new_chain_monitor,
		nodes_1_deserialized
	);

	let bs_init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &bs_init_msg, true).unwrap();

	let as_init_msg = msgs::Init {
		features: nodes[0].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[1].node.peer_connected(node_a_id, &as_init_msg, false).unwrap();
	let as_reestablish = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[1].node.handle_channel_reestablish(node_a_id, &as_reestablish);
	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_reestablish);
	get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);
	get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_a_id);

	let cs_init_msg = msgs::Init {
		features: nodes[2].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[1].node.peer_connected(node_c_id, &cs_init_msg, true).unwrap();
	nodes[2].node.peer_connected(node_b_id, &bs_init_msg, false).unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[2]).pop().unwrap();
	let cs_reestablish = get_chan_reestablish_msgs!(nodes[2], nodes[1]).pop().unwrap();
	nodes[2].node.handle_channel_reestablish(node_b_id, &bs_reestablish);
	nodes[1].node.handle_channel_reestablish(node_c_id, &cs_reestablish);
	get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_c_id);
	get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, node_b_id);

	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(
		&nodes[0],
		&[&[&nodes[1], &nodes[2]]],
		10_000,
		our_payment_hash,
		our_payment_secret,
	);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], our_payment_preimage);
}

fn do_test_1_conf_open(connect_style: ConnectStyle) {
	// Previously, if the minium_depth config was set to 1, we'd never send a channel_ready. This
	// tests that we properly send one in that case.
	let mut alice_config = UserConfig::default();
	alice_config.channel_handshake_config.minimum_depth = 1;
	alice_config.channel_handshake_config.announce_for_forwarding = true;
	alice_config.channel_handshake_limits.force_announced_channel_preference = false;
	alice_config.channel_config.max_dust_htlc_exposure =
		MaxDustHTLCExposure::FeeRateMultiplier(5_000_000 / 253);
	let mut bob_config = UserConfig::default();
	bob_config.channel_handshake_config.minimum_depth = 1;
	bob_config.channel_handshake_config.announce_for_forwarding = true;
	bob_config.channel_handshake_limits.force_announced_channel_preference = false;
	bob_config.channel_config.max_dust_htlc_exposure =
		MaxDustHTLCExposure::FeeRateMultiplier(5_000_000 / 253);
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(alice_config), Some(bob_config)]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	*nodes[0].connect_style.borrow_mut() = connect_style;

	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001);
	mine_transaction(&nodes[1], &tx);
	nodes[0].node.handle_channel_ready(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, node_a_id),
	);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	mine_transaction(&nodes[0], &tx);
	let as_msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_msg_events.len(), 2);
	let as_channel_ready =
		if let MessageSendEvent::SendChannelReady { ref node_id, ref msg } = as_msg_events[0] {
			assert_eq!(*node_id, node_b_id);
			msg.clone()
		} else {
			panic!("Unexpected event");
		};
	if let MessageSendEvent::SendChannelUpdate { ref node_id, msg: _ } = as_msg_events[1] {
		assert_eq!(*node_id, node_b_id);
	} else {
		panic!("Unexpected event");
	}

	nodes[1].node.handle_channel_ready(node_a_id, &as_channel_ready);
	expect_channel_ready_event(&nodes[0], &node_b_id);
	expect_channel_ready_event(&nodes[1], &node_a_id);
	let bs_msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_msg_events.len(), 1);
	if let MessageSendEvent::SendChannelUpdate { ref node_id, msg: _ } = bs_msg_events[0] {
		assert_eq!(*node_id, node_a_id);
	} else {
		panic!("Unexpected event");
	}

	send_payment(&nodes[0], &[&nodes[1]], 100_000);

	// After 6 confirmations, as required by the spec, we'll send announcement_signatures and
	// broadcast the channel_announcement (but not before exactly 6 confirmations).
	connect_blocks(&nodes[0], 4);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	connect_blocks(&nodes[0], 1);
	nodes[1].node.handle_announcement_signatures(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendAnnouncementSignatures, node_b_id),
	);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	connect_blocks(&nodes[1], 5);
	let bs_announce_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_announce_events.len(), 2);
	let bs_announcement_sigs =
		if let MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } =
			bs_announce_events[1]
		{
			assert_eq!(*node_id, node_a_id);
			msg.clone()
		} else {
			panic!("Unexpected event");
		};
	let (bs_announcement, bs_update) =
		if let MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } =
			bs_announce_events[0]
		{
			(msg.clone(), update_msg.clone().unwrap())
		} else {
			panic!("Unexpected event");
		};

	nodes[0].node.handle_announcement_signatures(node_b_id, &bs_announcement_sigs);
	let as_announce_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_announce_events.len(), 1);
	let (announcement, as_update) =
		if let MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } =
			as_announce_events[0]
		{
			(msg.clone(), update_msg.clone().unwrap())
		} else {
			panic!("Unexpected event");
		};
	assert_eq!(announcement, bs_announcement);

	for (i, node) in nodes.iter().enumerate() {
		let counterparty_node_id = nodes[(i + 1) % 2].node.get_our_node_id();
		assert!(node
			.gossip_sync
			.handle_channel_announcement(Some(counterparty_node_id), &announcement)
			.unwrap());
		node.gossip_sync.handle_channel_update(Some(counterparty_node_id), &as_update).unwrap();
		node.gossip_sync.handle_channel_update(Some(counterparty_node_id), &bs_update).unwrap();
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
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000);
	let mut as_channel_ready =
		create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 500_000_000).0;

	let last_hop = nodes[2].node.list_usable_channels();
	let hop_hints = vec![RouteHint(vec![RouteHintHop {
		src_node_id: node_b_id,
		short_channel_id: last_hop[0].inbound_scid_alias.unwrap(),
		fees: RoutingFees {
			base_msat: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_base_msat,
			proportional_millionths: last_hop[0]
				.counterparty
				.forwarding_info
				.as_ref()
				.unwrap()
				.fee_proportional_millionths,
		},
		cltv_expiry_delta: last_hop[0]
			.counterparty
			.forwarding_info
			.as_ref()
			.unwrap()
			.cltv_expiry_delta,
		htlc_maximum_msat: None,
		htlc_minimum_msat: None,
	}])];
	let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap()
		.with_route_hints(hop_hints)
		.unwrap();
	let (route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 100_000);
	assert_eq!(route.paths[0].hops[1].short_channel_id, last_hop[0].inbound_scid_alias.unwrap());

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors!(nodes[0], 1);

	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], 100_000, payment_hash, payment_secret);

	as_channel_ready.short_channel_id_alias = Some(0xeadbeef);
	nodes[2].node.handle_channel_ready(node_b_id, &as_channel_ready);
	// Note that we always respond to a channel_ready with a channel_update. Not a lot of reason
	// to bother updating that code, so just drop the message here.
	get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, node_b_id);

	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// Now test that if a peer sends us a second channel_ready after the channel is operational we
	// will use the new alias.
	as_channel_ready.short_channel_id_alias = Some(0xdeadbeef);
	nodes[2].node.handle_channel_ready(node_b_id, &as_channel_ready);
	// Note that we always respond to a channel_ready with a channel_update. Not a lot of reason
	// to bother updating that code, so just drop the message here.
	get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, node_b_id);
	let updated_channel_info = nodes[2].node.list_usable_channels();
	assert_eq!(updated_channel_info.len(), 1);
	assert_eq!(updated_channel_info[0].inbound_scid_alias.unwrap(), 0xdeadbeef);
	// Note that because we never send a duplicate channel_ready we can't send a payment through
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
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let mut scid_privacy_cfg = test_default_channel_config();
	scid_privacy_cfg.channel_handshake_config.announce_for_forwarding = true;
	scid_privacy_cfg.channel_handshake_config.negotiate_scid_privacy = true;
	nodes[0]
		.node
		.create_channel(node_b_id, 100000, 10001, 42, None, Some(scid_privacy_cfg))
		.unwrap();
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	assert!(!open_channel.common_fields.channel_type.as_ref().unwrap().supports_scid_privacy()); // we ignore `negotiate_scid_privacy` on pub channels
	open_channel.common_fields.channel_type.as_mut().unwrap().set_scid_privacy_required();
	assert_eq!(open_channel.common_fields.channel_flags & 1, 1); // The `announce_channel` bit is set.

	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let err = get_err_msg(&nodes[1], &node_a_id);
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
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let mut scid_privacy_cfg = test_default_channel_config();
	scid_privacy_cfg.channel_handshake_config.announce_for_forwarding = false;
	scid_privacy_cfg.channel_handshake_config.negotiate_scid_privacy = true;
	nodes[0]
		.node
		.create_channel(node_b_id, 100000, 10001, 42, None, Some(scid_privacy_cfg))
		.unwrap();

	let init_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	assert!(init_open_channel.common_fields.channel_type.as_ref().unwrap().supports_scid_privacy());
	assert!(nodes[0].node.list_channels()[0].channel_type.is_none()); // channel_type is none until counterparty accepts

	// now simulate nodes[1] responding with an Error message, indicating it doesn't understand
	// SCID alias.
	nodes[0].node.handle_error(
		node_b_id,
		&msgs::ErrorMessage {
			channel_id: init_open_channel.common_fields.temporary_channel_id,
			data: "Yo, no SCID aliases, no privacy here!".to_string(),
		},
	);
	assert!(nodes[0].node.list_channels()[0].channel_type.is_none()); // channel_type is none until counterparty accepts

	let second_open_channel =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	assert!(!second_open_channel
		.common_fields
		.channel_type
		.as_ref()
		.unwrap()
		.supports_scid_privacy());
	nodes[1].node.handle_open_channel(node_a_id, &second_open_channel);
	nodes[0].node.handle_accept_channel(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id),
	);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { .. } => {},
		_ => panic!("Unexpected event"),
	}

	assert!(!nodes[0].node.list_channels()[0]
		.channel_type
		.as_ref()
		.unwrap()
		.supports_scid_privacy());
	assert!(!nodes[1].node.list_channels()[0]
		.channel_type
		.as_ref()
		.unwrap()
		.supports_scid_privacy());
}

#[test]
fn test_inbound_scid_privacy() {
	// Tests accepting channels with the scid_privacy feature and rejecting forwards using the
	// channel's real SCID as required by the channel feature.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut accept_forward_cfg = test_default_channel_config();
	accept_forward_cfg.accept_forwards_to_priv_channels = true;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(accept_forward_cfg), None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);

	let mut no_announce_cfg = test_default_channel_config();
	no_announce_cfg.channel_handshake_config.announce_for_forwarding = false;
	no_announce_cfg.channel_handshake_config.negotiate_scid_privacy = true;
	nodes[1]
		.node
		.create_channel(node_c_id, 100_000, 10_000, 42, None, Some(no_announce_cfg))
		.unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, node_c_id);

	assert!(open_channel.common_fields.channel_type.as_ref().unwrap().requires_scid_privacy());

	nodes[2].node.handle_open_channel(node_b_id, &open_channel);
	let accept_channel = get_event_msg!(nodes[2], MessageSendEvent::SendAcceptChannel, node_b_id);
	nodes[1].node.handle_accept_channel(node_c_id, &accept_channel);

	let (temporary_channel_id, tx, _) =
		create_funding_transaction(&nodes[1], &node_c_id, 100_000, 42);
	nodes[1]
		.node
		.funding_transaction_generated(temporary_channel_id, node_c_id, tx.clone())
		.unwrap();
	nodes[2].node.handle_funding_created(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendFundingCreated, node_c_id),
	);
	check_added_monitors!(nodes[2], 1);

	let cs_funding_signed =
		get_event_msg!(nodes[2], MessageSendEvent::SendFundingSigned, node_b_id);
	expect_channel_pending_event(&nodes[2], &node_b_id);

	nodes[1].node.handle_funding_signed(node_c_id, &cs_funding_signed);
	expect_channel_pending_event(&nodes[1], &node_c_id);
	check_added_monitors!(nodes[1], 1);

	let conf_height =
		core::cmp::max(nodes[1].best_block_info().1 + 1, nodes[2].best_block_info().1 + 1);
	confirm_transaction_at(&nodes[1], &tx, conf_height);
	connect_blocks(&nodes[1], CHAN_CONFIRM_DEPTH - 1);
	confirm_transaction_at(&nodes[2], &tx, conf_height);
	connect_blocks(&nodes[2], CHAN_CONFIRM_DEPTH - 1);
	let bs_channel_ready = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReady, node_c_id);
	nodes[1].node.handle_channel_ready(
		node_c_id,
		&get_event_msg!(nodes[2], MessageSendEvent::SendChannelReady, node_b_id),
	);
	expect_channel_ready_event(&nodes[1], &node_c_id);
	let bs_update = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_c_id);
	nodes[2].node.handle_channel_ready(node_b_id, &bs_channel_ready);
	expect_channel_ready_event(&nodes[2], &node_b_id);
	let cs_update = get_event_msg!(nodes[2], MessageSendEvent::SendChannelUpdate, node_b_id);

	nodes[1].node.handle_channel_update(node_c_id, &cs_update);
	nodes[2].node.handle_channel_update(node_b_id, &bs_update);

	// Now we can pay just fine using the SCID alias nodes[2] gave to nodes[1]...

	let last_hop = nodes[2].node.list_usable_channels();
	let mut hop_hints = vec![RouteHint(vec![RouteHintHop {
		src_node_id: node_b_id,
		short_channel_id: last_hop[0].inbound_scid_alias.unwrap(),
		fees: RoutingFees {
			base_msat: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_base_msat,
			proportional_millionths: last_hop[0]
				.counterparty
				.forwarding_info
				.as_ref()
				.unwrap()
				.fee_proportional_millionths,
		},
		cltv_expiry_delta: last_hop[0]
			.counterparty
			.forwarding_info
			.as_ref()
			.unwrap()
			.cltv_expiry_delta,
		htlc_maximum_msat: None,
		htlc_minimum_msat: None,
	}])];
	let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap()
		.with_route_hints(hop_hints.clone())
		.unwrap();
	let (route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 100_000);
	assert_eq!(route.paths[0].hops[1].short_channel_id, last_hop[0].inbound_scid_alias.unwrap());

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors!(nodes[0], 1);

	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], 100_000, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// ... but if we try to pay using the real SCID, nodes[1] will just tell us they don't know
	// what channel we're talking about.
	hop_hints[0].0[0].short_channel_id = last_hop[0].short_channel_id.unwrap();

	let payment_params_2 = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap()
		.with_route_hints(hop_hints)
		.unwrap();
	let (route_2, payment_hash_2, _, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[2], payment_params_2, 100_000);
	assert_eq!(route_2.paths[0].hops[1].short_channel_id, last_hop[0].short_channel_id.unwrap());

	let onion = RecipientOnionFields::secret_only(payment_secret_2);
	let id = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route_2, payment_hash_2, onion, id).unwrap();
	check_added_monitors!(nodes[0], 1);

	let payment_event = SendEvent::from_node(&nodes[0]);
	assert_eq!(node_b_id, payment_event.node_id);
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, true, true);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Forward {
			node_id: Some(node_c_id),
			channel_id: last_hop[0].channel_id
		}]
	);
	check_added_monitors(&nodes[1], 1);

	nodes[1].logger.assert_log_regex(
		"lightning::ln::channelmanager",
		regex::Regex::new(r"Failed to accept/forward incoming HTLC: RealSCIDForward").unwrap(),
		1,
	);

	let mut updates = get_htlc_update_msgs!(nodes[1], node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);

	expect_payment_failed_conditions(
		&nodes[0],
		payment_hash_2,
		false,
		PaymentFailedConditions::new()
			.blamed_scid(last_hop[0].short_channel_id.unwrap())
			.blamed_chan_closed(true)
			.expected_htlc_error_data(LocalHTLCFailureReason::UnknownNextPeer, &[0; 0]),
	);
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
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(accept_forward_cfg), None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0);
	let chan = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000, 0);

	let last_hop = nodes[2].node.list_usable_channels();
	let mut hop_hints = vec![RouteHint(vec![RouteHintHop {
		src_node_id: node_b_id,
		short_channel_id: last_hop[0].inbound_scid_alias.unwrap(),
		fees: RoutingFees {
			base_msat: last_hop[0].counterparty.forwarding_info.as_ref().unwrap().fee_base_msat,
			proportional_millionths: last_hop[0]
				.counterparty
				.forwarding_info
				.as_ref()
				.unwrap()
				.fee_proportional_millionths,
		},
		cltv_expiry_delta: last_hop[0]
			.counterparty
			.forwarding_info
			.as_ref()
			.unwrap()
			.cltv_expiry_delta,
		htlc_maximum_msat: None,
		htlc_minimum_msat: None,
	}])];
	let payment_params = PaymentParameters::from_node_id(node_c_id, 42)
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap()
		.with_route_hints(hop_hints)
		.unwrap();
	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 10_000);
	assert_eq!(
		route.paths[0].hops[1].short_channel_id,
		nodes[2].node.list_usable_channels()[0].inbound_scid_alias.unwrap()
	);

	route.paths[0].hops[1].fee_msat = 10_000_000; // Overshoot the last channel's value

	// Route the HTLC through to the destination.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route.clone(), payment_hash, onion, id).unwrap();

	check_added_monitors!(nodes[0], 1);
	let as_updates = get_htlc_update_msgs!(nodes[0], node_b_id);
	nodes[1].node.handle_update_add_htlc(node_a_id, &as_updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &as_updates.commitment_signed, false, true);

	expect_and_process_pending_htlcs(&nodes[1], true);
	let events = nodes[1].node.get_and_clear_pending_events();
	let expected_failures = [HTLCHandlingFailureType::Forward {
		node_id: Some(node_c_id),
		channel_id: chan.0.channel_id,
	}];
	expect_htlc_failure_conditions(events, &expected_failures);
	check_added_monitors!(nodes[1], 1);

	let bs_updates = get_htlc_update_msgs!(nodes[1], node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_updates.commitment_signed, false, true);

	let err_data = 0u16.to_be_bytes();
	expect_payment_failed_conditions(
		&nodes[0],
		payment_hash,
		false,
		PaymentFailedConditions::new()
			.blamed_scid(last_hop[0].inbound_scid_alias.unwrap())
			.blamed_chan_closed(false)
			.expected_htlc_error_data(LocalHTLCFailureReason::TemporaryChannelFailure, &err_data),
	);

	route.paths[0].hops[1].fee_msat = 10_000; // Reset to the correct payment amount
	route.paths[0].hops[0].fee_msat = 0; // But set fee paid to the middle hop to 0

	// Route the HTLC through to the destination.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();

	check_added_monitors!(nodes[0], 1);
	let as_updates = get_htlc_update_msgs!(nodes[0], node_b_id);
	nodes[1].node.handle_update_add_htlc(node_a_id, &as_updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &as_updates.commitment_signed, false, true);

	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Forward {
			node_id: Some(node_c_id),
			channel_id: chan.0.channel_id
		}]
	);
	check_added_monitors(&nodes[1], 1);

	let bs_updates = get_htlc_update_msgs!(nodes[1], node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_updates.commitment_signed, false, true);

	let mut err_data = Vec::new();
	err_data.extend_from_slice(&10_000u64.to_be_bytes());
	err_data.extend_from_slice(&0u16.to_be_bytes());
	expect_payment_failed_conditions(
		&nodes[0],
		payment_hash,
		false,
		PaymentFailedConditions::new()
			.blamed_scid(last_hop[0].inbound_scid_alias.unwrap())
			.blamed_chan_closed(false)
			.expected_htlc_error_data(LocalHTLCFailureReason::FeeInsufficient, &err_data),
	);
}

#[test]
fn test_simple_0conf_channel() {
	// If our peer tells us they will accept our channel with 0 confs, and we funded the channel,
	// we should trust the funding won't be double-spent (assuming `trust_own_funding_0conf` is
	// set)!
	// Further, if we `accept_inbound_channel_from_trusted_peer_0conf`, `channel_ready` messages
	// should fly immediately and the channel should be available for use as soon as they are
	// received.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut chan_config = test_default_channel_config();
	chan_config.manually_accept_inbound_channels = true;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(chan_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	open_zero_conf_channel(&nodes[0], &nodes[1], None);

	send_payment(&nodes[0], &[&nodes[1]], 100_000);
}

#[test]
fn test_0conf_channel_with_async_monitor() {
	// Test that we properly send out channel_ready in (both inbound- and outbound-) zero-conf
	// channels if ChannelMonitor updates return a `TemporaryFailure` during the initial channel
	// negotiation.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut chan_config = test_default_channel_config();
	chan_config.manually_accept_inbound_channels = true;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(chan_config.clone()), None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	chan_config.channel_handshake_config.announce_for_forwarding = false;
	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, Some(chan_config)).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1]
				.node
				.accept_inbound_channel_from_trusted_peer_0conf(
					&temporary_channel_id,
					&node_a_id,
					0,
					None,
				)
				.unwrap();
		},
		_ => panic!("Unexpected event"),
	};

	let mut accept_channel =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	assert_eq!(accept_channel.common_fields.minimum_depth, 0);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);

	let (temporary_channel_id, tx, funding_output) =
		create_funding_transaction(&nodes[0], &node_b_id, 100000, 42);
	nodes[0]
		.node
		.funding_transaction_generated(temporary_channel_id, node_b_id, tx.clone())
		.unwrap();
	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	let channel_id = ChannelId::v1_from_funding_outpoint(funding_output);
	nodes[1].chain_monitor.complete_sole_pending_chan_update(&channel_id);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	let bs_signed_locked = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_signed_locked.len(), 2);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	match &bs_signed_locked[0] {
		MessageSendEvent::SendFundingSigned { node_id, msg } => {
			assert_eq!(*node_id, node_a_id);
			nodes[0].node.handle_funding_signed(node_b_id, &msg);
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}
	match &bs_signed_locked[1] {
		MessageSendEvent::SendChannelReady { node_id, msg } => {
			assert_eq!(*node_id, node_a_id);
			nodes[0].node.handle_channel_ready(node_b_id, &msg);
		},
		_ => panic!("Unexpected event"),
	}

	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].chain_monitor.complete_sole_pending_chan_update(&channel_id);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		crate::events::Event::ChannelPending { ref counterparty_node_id, .. } => {
			assert_eq!(node_b_id, *counterparty_node_id);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		crate::events::Event::ChannelReady { ref counterparty_node_id, .. } => {
			assert_eq!(node_b_id, *counterparty_node_id);
		},
		_ => panic!("Unexpected event"),
	}

	let as_locked_update = nodes[0].node.get_and_clear_pending_msg_events();

	// Note that the funding transaction is actually released when
	// get_and_clear_pending_msg_events, above, checks for monitor events.
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0)[0], tx);

	match &as_locked_update[0] {
		MessageSendEvent::SendChannelReady { node_id, msg } => {
			assert_eq!(*node_id, node_b_id);
			nodes[1].node.handle_channel_ready(node_a_id, &msg);
		},
		_ => panic!("Unexpected event"),
	}
	expect_channel_ready_event(&nodes[1], &node_a_id);

	let bs_channel_update =
		get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, node_a_id);

	let as_channel_update = match &as_locked_update[1] {
		MessageSendEvent::SendChannelUpdate { node_id, msg } => {
			assert_eq!(*node_id, node_b_id);
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);

	nodes[0].node.handle_channel_update(node_b_id, &bs_channel_update);
	nodes[1].node.handle_channel_update(node_a_id, &as_channel_update);

	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
	assert_eq!(nodes[1].node.list_usable_channels().len(), 2);

	send_payment(&nodes[0], &[&nodes[1]], 100_000);

	// Now that we have useful channels, try sending a payment where the we hit a temporary monitor
	// failure before we've ever confirmed the funding transaction. This previously caused a panic.
	let (route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors!(nodes[0], 1);

	let as_send = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(node_a_id, &as_send.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_send.commitment_msg);
	check_added_monitors!(nodes[1], 1);

	let (bs_raa, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], node_a_id);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_commitment_signed);
	check_added_monitors!(nodes[0], 1);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[1].node.handle_revoke_and_ack(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id),
	);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (_, latest_update) = {
		let latest_monitor_update_id =
			nodes[1].chain_monitor.latest_monitor_update_id.lock().unwrap();
		latest_monitor_update_id.get(&bs_raa.channel_id).unwrap().clone()
	};
	nodes[1]
		.chain_monitor
		.chain_monitor
		.channel_monitor_updated(bs_raa.channel_id, latest_update)
		.unwrap();
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors!(nodes[1], 1);

	let bs_send = SendEvent::from_node(&nodes[1]);
	nodes[2].node.handle_update_add_htlc(node_b_id, &bs_send.msgs[0]);
	commitment_signed_dance!(nodes[2], nodes[1], bs_send.commitment_msg, false);
	expect_and_process_pending_htlcs(&nodes[2], false);
	expect_payment_claimable!(nodes[2], payment_hash, payment_secret, 1_000_000);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	confirm_transaction(&nodes[0], &tx);
	confirm_transaction(&nodes[1], &tx);

	send_payment(&nodes[0], &[&nodes[1]], 100_000);
}

#[test]
fn test_0conf_close_no_early_chan_update() {
	// Tests that even with a public channel 0conf channel, we don't generate a channel_update on
	// closing.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut chan_config = test_default_channel_config();
	chan_config.manually_accept_inbound_channels = true;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(chan_config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_b_id = nodes[1].node.get_our_node_id();
	let message = "Channel force-closed".to_owned();

	// This is the default but we force it on anyway
	chan_config.channel_handshake_config.announce_for_forwarding = true;
	open_zero_conf_channel(&nodes[0], &nodes[1], Some(chan_config));

	// We can use the channel immediately, but won't generate a channel_update until we get confs
	send_payment(&nodes[0], &[&nodes[1]], 100_000);

	nodes[0].node.force_close_all_channels_broadcasting_latest_txn(message.clone());
	check_added_monitors!(nodes[0], 1);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event!(&nodes[0], 1, reason, [node_b_id], 100000);
	let _ = get_err_msg(&nodes[0], &node_b_id);
}

#[test]
fn test_public_0conf_channel() {
	// Tests that we will announce a public channel (after confirmation) even if its 0conf.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut chan_config = test_default_channel_config();
	chan_config.manually_accept_inbound_channels = true;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(chan_config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// This is the default but we force it on anyway
	chan_config.channel_handshake_config.announce_for_forwarding = true;
	let (tx, ..) = open_zero_conf_channel(&nodes[0], &nodes[1], Some(chan_config));

	// We can use the channel immediately, but we can't announce it until we get 6+ confirmations
	send_payment(&nodes[0], &[&nodes[1]], 100_000);

	let scid = confirm_transaction(&nodes[0], &tx);
	let as_announcement_sigs =
		get_event_msg!(nodes[0], MessageSendEvent::SendAnnouncementSignatures, node_b_id);
	assert_eq!(confirm_transaction(&nodes[1], &tx), scid);
	let bs_announcement_sigs =
		get_event_msg!(nodes[1], MessageSendEvent::SendAnnouncementSignatures, node_a_id);

	nodes[1].node.handle_announcement_signatures(node_a_id, &as_announcement_sigs);
	nodes[0].node.handle_announcement_signatures(node_b_id, &bs_announcement_sigs);

	let bs_announcement = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_announcement.len(), 1);
	let announcement;
	let bs_update;
	match bs_announcement[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			announcement = msg.clone();
			bs_update = update_msg.clone().unwrap();
		},
		_ => panic!("Unexpected event"),
	};

	let as_announcement = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_announcement.len(), 1);
	match as_announcement[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			assert!(announcement == *msg);
			let update_msg = update_msg.as_ref().unwrap();
			assert_eq!(update_msg.contents.short_channel_id, scid);
			assert_eq!(
				update_msg.contents.short_channel_id,
				announcement.contents.short_channel_id
			);
			assert_eq!(update_msg.contents.short_channel_id, bs_update.contents.short_channel_id);
		},
		_ => panic!("Unexpected event"),
	};
}

#[test]
fn test_0conf_channel_reorg() {
	// If we accept a 0conf channel, which is then confirmed, but then changes SCID in a reorg, we
	// have to make sure we handle this correctly (or, currently, just force-close the channel).

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut chan_config = test_default_channel_config();
	chan_config.manually_accept_inbound_channels = true;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(chan_config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// This is the default but we force it on anyway
	chan_config.channel_handshake_config.announce_for_forwarding = true;
	let (tx, ..) = open_zero_conf_channel(&nodes[0], &nodes[1], Some(chan_config));

	// We can use the channel immediately, but we can't announce it until we get 6+ confirmations
	send_payment(&nodes[0], &[&nodes[1]], 100_000);

	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	// Send a payment using the channel's real SCID, which will be public in a few blocks once we
	// can generate a channel_announcement.
	let real_scid = nodes[0].node.list_usable_channels()[0].short_channel_id.unwrap();
	assert_eq!(nodes[1].node.list_usable_channels()[0].short_channel_id.unwrap(), real_scid);

	let (mut route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 10_000);
	assert_eq!(route.paths[0].hops[0].short_channel_id, real_scid);
	send_along_route_with_secret(
		&nodes[0],
		route,
		&[&[&nodes[1]]],
		10_000,
		payment_hash,
		payment_secret,
	);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	disconnect_blocks(&nodes[0], 1);
	disconnect_blocks(&nodes[1], 1);

	// At this point the channel no longer has an SCID again. In the future we should likely
	// support simply un-setting the SCID and waiting until the channel gets re-confirmed, but for
	// now we force-close the channel here.
	let reason = ClosureReason::ProcessingError {
		err: "Funding transaction was un-confirmed. Locked at 0 confs, now have 0 confs."
			.to_owned(),
	};
	check_closed_event!(&nodes[0], 1, reason, [node_b_id], 100000);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::ProcessingError {
		err: "Funding transaction was un-confirmed. Locked at 0 confs, now have 0 confs."
			.to_owned(),
	};
	check_closed_event!(&nodes[1], 1, reason, [node_a_id], 100000);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
}

#[test]
fn test_zero_conf_accept_reject() {
	let mut channel_type_features = ChannelTypeFeatures::only_static_remote_key();
	channel_type_features.set_zero_conf_required();

	// 1. Check we reject zero conf channels by default
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let mut open_channel_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	open_channel_msg.common_fields.channel_type = Some(channel_type_features.clone());

	nodes[1].node.handle_open_channel(node_a_id, &open_channel_msg);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	match msg_events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg, .. },
			..
		} => {
			assert_eq!(msg.data, "No zero confirmation channels accepted".to_owned());
		},
		_ => panic!(),
	}

	// 2. Check we can manually accept zero conf channels via the right method
	let mut manually_accept_conf = UserConfig::default();
	manually_accept_conf.manually_accept_inbound_channels = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_conf.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// 2.1 First try the non-0conf method to manually accept
	nodes[0]
		.node
		.create_channel(node_b_id, 100000, 10001, 42, None, Some(manually_accept_conf.clone()))
		.unwrap();
	let mut open_channel_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	open_channel_msg.common_fields.channel_type = Some(channel_type_features.clone());

	nodes[1].node.handle_open_channel(node_a_id, &open_channel_msg);

	// Assert that `nodes[1]` has no `MessageSendEvent::SendAcceptChannel` in the `msg_events`.
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let events = nodes[1].node.get_and_clear_pending_events();

	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			// Assert we fail to accept via the non-0conf method
			assert!(nodes[1]
				.node
				.accept_inbound_channel(&temporary_channel_id, &node_a_id, 0, None)
				.is_err());
		},
		_ => panic!(),
	}

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	match msg_events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg, .. },
			..
		} => {
			assert_eq!(msg.data, "No zero confirmation channels accepted".to_owned());
		},
		_ => panic!(),
	}

	// 2.2 Try again with the 0conf method to manually accept
	nodes[0]
		.node
		.create_channel(node_b_id, 100000, 10001, 42, None, Some(manually_accept_conf))
		.unwrap();
	let mut open_channel_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	open_channel_msg.common_fields.channel_type = Some(channel_type_features);

	nodes[1].node.handle_open_channel(node_a_id, &open_channel_msg);

	let events = nodes[1].node.get_and_clear_pending_events();

	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			// Assert we can accept via the 0conf method
			assert!(nodes[1]
				.node
				.accept_inbound_channel_from_trusted_peer_0conf(
					&temporary_channel_id,
					&node_a_id,
					0,
					None
				)
				.is_ok());
		},
		_ => panic!(),
	}

	// Check we would send accept
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	match msg_events[0] {
		MessageSendEvent::SendAcceptChannel { .. } => {},
		_ => panic!(),
	}
}

#[test]
fn test_connect_before_funding() {
	// Tests for a particularly dumb explicit panic that existed prior to 0.0.111 for 0conf
	// channels. If we received a block while awaiting funding for 0-conf channels we'd hit an
	// explicit panic when deciding if we should broadcast our channel_ready message.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);

	let mut manually_accept_conf = test_default_channel_config();
	manually_accept_conf.manually_accept_inbound_channels = true;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_conf)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100_000, 10_001, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::OpenChannelRequest { temporary_channel_id, .. } => {
			nodes[1]
				.node
				.accept_inbound_channel_from_trusted_peer_0conf(
					&temporary_channel_id,
					&node_a_id,
					0,
					None,
				)
				.unwrap();
		},
		_ => panic!("Unexpected event"),
	};

	let mut accept_channel =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	assert_eq!(accept_channel.common_fields.minimum_depth, 0);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { .. } => {},
		_ => panic!("Unexpected event"),
	}

	connect_blocks(&nodes[0], 1);
	connect_blocks(&nodes[1], 1);
}

#[test]
fn test_0conf_ann_sigs_racing_conf() {
	// Previously we had a bug where we'd panic when receiving a counterparty's
	// announcement_signatures message for a 0conf channel pending confirmation on-chain. Here we
	// check that we just error out, ignore the announcement_signatures message, and proceed
	// instead.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut chan_config = test_default_channel_config();
	chan_config.manually_accept_inbound_channels = true;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(chan_config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// This is the default but we force it on anyway
	chan_config.channel_handshake_config.announce_for_forwarding = true;
	let (tx, ..) = open_zero_conf_channel(&nodes[0], &nodes[1], Some(chan_config));

	// We can use the channel immediately, but we can't announce it until we get 6+ confirmations
	send_payment(&nodes[0], &[&nodes[1]], 100_000);

	let scid = confirm_transaction(&nodes[0], &tx);
	let as_announcement_sigs =
		get_event_msg!(nodes[0], MessageSendEvent::SendAnnouncementSignatures, node_b_id);

	// Handling the announcement_signatures prior to the first confirmation would panic before.
	nodes[1].node.handle_announcement_signatures(node_a_id, &as_announcement_sigs);

	assert_eq!(confirm_transaction(&nodes[1], &tx), scid);
	let bs_announcement_sigs =
		get_event_msg!(nodes[1], MessageSendEvent::SendAnnouncementSignatures, node_a_id);

	nodes[0].node.handle_announcement_signatures(node_b_id, &bs_announcement_sigs);
	let as_announcement = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_announcement.len(), 1);
}
