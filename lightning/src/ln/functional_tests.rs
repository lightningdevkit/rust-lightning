// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test standing up a network of ChannelManagers, creating channels, sending
//! payments/messages between them, and often checking the resulting ChannelMonitors are able to
//! claim outputs on-chain.

use chain::Watch;
use chain::channelmonitor;
use chain::channelmonitor::{ChannelMonitor, CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS, ANTI_REORG_DELAY};
use chain::transaction::OutPoint;
use chain::keysinterface::{Sign, KeysInterface};
use ln::channel::{COMMITMENT_TX_BASE_WEIGHT, COMMITMENT_TX_WEIGHT_PER_HTLC};
use ln::channelmanager::{ChannelManager, ChannelManagerReadArgs, RAACommitmentOrder, PaymentPreimage, PaymentHash, PaymentSecret, PaymentSendFailure, BREAKDOWN_TIMEOUT};
use ln::channel::{Channel, ChannelError};
use ln::{chan_utils, onion_utils};
use routing::router::{Route, RouteHop, get_route};
use ln::features::{ChannelFeatures, InitFeatures, NodeFeatures};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler,RoutingMessageHandler,HTLCFailChannelUpdate, ErrorAction};
use util::enforcing_trait_impls::EnforcingSigner;
use util::{byte_utils, test_utils};
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;
use util::ser::{Writeable, ReadableArgs};
use util::config::UserConfig;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hash_types::{Txid, BlockHash};
use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

use bitcoin::secp256k1::{Secp256k1, Message};
use bitcoin::secp256k1::key::{PublicKey,SecretKey};

use regex;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::default::Default;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use ln::functional_test_utils::*;
use ln::chan_utils::CommitmentTransaction;
use ln::msgs::OptionalField::Present;

#[test]
fn test_insane_channel_opens() {
	// Stand up a network of 2 nodes
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Instantiate channel parameters where we push the maximum msats given our
	// funding satoshis
	let channel_value_sat = 31337; // same as funding satoshis
	let channel_reserve_satoshis = Channel::<EnforcingSigner>::get_holder_selected_channel_reserve_satoshis(channel_value_sat);
	let push_msat = (channel_value_sat - channel_reserve_satoshis) * 1000;

	// Have node0 initiate a channel to node1 with aforementioned parameters
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_sat, push_msat, 42, None).unwrap();

	// Extract the channel open message from node0 to node1
	let open_channel_message = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	// Test helper that asserts we get the correct error string given a mutator
	// that supposedly makes the channel open message insane
	let insane_open_helper = |expected_error_str: &str, message_mutator: fn(msgs::OpenChannel) -> msgs::OpenChannel| {
		nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &message_mutator(open_channel_message.clone()));
		let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		let expected_regex = regex::Regex::new(expected_error_str).unwrap();
		if let MessageSendEvent::HandleError { ref action, .. } = msg_events[0] {
			match action {
				&ErrorAction::SendErrorMessage { .. } => {
					nodes[1].logger.assert_log_regex("lightning::ln::channelmanager".to_string(), expected_regex, 1);
				},
				_ => panic!("unexpected event!"),
			}
		} else { assert!(false); }
	};

	use ln::channel::MAX_FUNDING_SATOSHIS;
	use ln::channelmanager::MAX_LOCAL_BREAKDOWN_TIMEOUT;

	// Test all mutations that would make the channel open message insane
	insane_open_helper(format!("Funding must be smaller than {}. It was {}", MAX_FUNDING_SATOSHIS, MAX_FUNDING_SATOSHIS).as_str(), |mut msg| { msg.funding_satoshis = MAX_FUNDING_SATOSHIS; msg });

	insane_open_helper("Bogus channel_reserve_satoshis", |mut msg| { msg.channel_reserve_satoshis = msg.funding_satoshis + 1; msg });

	insane_open_helper(r"push_msat \d+ was larger than funding value \d+", |mut msg| { msg.push_msat = (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000 + 1; msg });

	insane_open_helper("Peer never wants payout outputs?", |mut msg| { msg.dust_limit_satoshis = msg.funding_satoshis + 1 ; msg });

	insane_open_helper(r"Bogus; channel reserve \(\d+\) is less than dust limit \(\d+\)", |mut msg| { msg.dust_limit_satoshis = msg.channel_reserve_satoshis + 1; msg });

	insane_open_helper(r"Minimum htlc value \(\d+\) was larger than full channel value \(\d+\)", |mut msg| { msg.htlc_minimum_msat = (msg.funding_satoshis - msg.channel_reserve_satoshis) * 1000; msg });

	insane_open_helper("They wanted our payments to be delayed by a needlessly long period", |mut msg| { msg.to_self_delay = MAX_LOCAL_BREAKDOWN_TIMEOUT + 1; msg });

	insane_open_helper("0 max_accepted_htlcs makes for a useless channel", |mut msg| { msg.max_accepted_htlcs = 0; msg });

	insane_open_helper("max_accepted_htlcs was 484. It must not be larger than 483", |mut msg| { msg.max_accepted_htlcs = 484; msg });
}

#[test]
fn test_async_inbound_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();
	let channel_id = chan.2;

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);

	// A                                        B
	// update_fee                            ->
	// send (1) commitment_signed            -.
	//                                       <- update_add_htlc/commitment_signed
	// send (2) RAA (awaiting remote revoke) -.
	// (1) commitment_signed is delivered    ->
	//                                       .- send (3) RAA (awaiting remote revoke)
	// (2) RAA is delivered                  ->
	//                                       .- send (4) commitment_signed
	//                                       <- (3) RAA is delivered
	// send (5) commitment_signed            -.
	//                                       <- (4) commitment_signed is delivered
	// send (6) RAA                          -.
	// (5) commitment_signed is delivered    ->
	//                                       <- RAA
	// (6) RAA is delivered                  ->

	// First nodes[0] generates an update_fee
	nodes[0].node.update_fee(channel_id, get_feerate!(nodes[0], channel_id) + 20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] { // (1)
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
	nodes[1].node.send_payment(&get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &Vec::new(), 40000, TEST_FINAL_CLTV, &logger).unwrap(), our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.remove(0))
	};
	assert_eq!(payment_event.node_id, nodes[0].node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// ...now when the messages get delivered everyone should be happy
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg); // (2)
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	// deliver(1), generate (3):
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// nodes[1] is awaiting nodes[0] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack); // deliver (2)
	let bs_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(bs_update.update_add_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fulfill_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fail_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fail_malformed_htlcs.is_empty()); // (4)
	assert!(bs_update.update_fee.is_none()); // (4)
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack); // deliver (3)
	let as_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert!(as_update.update_add_htlcs.is_empty()); // (5)
	assert!(as_update.update_fulfill_htlcs.is_empty()); // (5)
	assert!(as_update.update_fail_htlcs.is_empty()); // (5)
	assert!(as_update.update_fail_malformed_htlcs.is_empty()); // (5)
	assert!(as_update.update_fee.is_none()); // (5)
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_update.commitment_signed); // deliver (4)
	let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// only (6) so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_update.commitment_signed); // deliver (5)
	let bs_second_revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke);
	check_added_monitors!(nodes[0], 1);

	let events_2 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::PendingHTLCsForwardable {..} => {}, // If we actually processed we'd receive the payment
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_revoke); // deliver (6)
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_fee_unordered_raa() {
	// Just the intro to the previous test followed by an out-of-order RAA (which caused a
	// crash in an earlier version of the update_fee patch)
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let channel_id = chan.2;
	let logger = test_utils::TestLogger::new();

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);

	// First nodes[0] generates an update_fee
	nodes[0].node.update_fee(channel_id, get_feerate!(nodes[0], channel_id) + 20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let update_msg = match events_0[0] { // (1)
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, .. }, .. } => {
			update_fee.as_ref()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	// ...but before it's delivered, nodes[1] starts to send a payment back to nodes[0]...
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
	nodes[1].node.send_payment(&get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &Vec::new(), 40000, TEST_FINAL_CLTV, &logger).unwrap(), our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[1], 1);

	let payment_event = {
		let mut events_1 = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events_1.len(), 1);
		SendEvent::from_event(events_1.remove(0))
	};
	assert_eq!(payment_event.node_id, nodes[0].node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	// ...now when the messages get delivered everyone should be happy
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg); // (2)
	let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// nodes[0] is awaiting nodes[1] revoke_and_ack so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_msg); // deliver (2)
	check_added_monitors!(nodes[1], 1);

	// We can't continue, sadly, because our (1) now has a bogus signature
}

#[test]
fn test_multi_flight_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let channel_id = chan.2;

	// A                                        B
	// update_fee/commitment_signed          ->
	//                                       .- send (1) RAA and (2) commitment_signed
	// update_fee (never committed)          ->
	// (3) update_fee                        ->
	// We have to manually generate the above update_fee, it is allowed by the protocol but we
	// don't track which updates correspond to which revoke_and_ack responses so we're in
	// AwaitingRAA mode and will not generate the update_fee yet.
	//                                       <- (1) RAA delivered
	// (3) is generated and send (4) CS      -.
	// Note that A cannot generate (4) prior to (1) being delivered as it otherwise doesn't
	// know the per_commitment_point to use for it.
	//                                       <- (2) commitment_signed delivered
	// revoke_and_ack                        ->
	//                                          B should send no response here
	// (4) commitment_signed delivered       ->
	//                                       <- RAA/commitment_signed delivered
	// revoke_and_ack                        ->

	// First nodes[0] generates an update_fee
	let initial_feerate = get_feerate!(nodes[0], channel_id);
	nodes[0].node.update_fee(channel_id, initial_feerate + 20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg_1, commitment_signed_1) = match events_0[0] { // (1)
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref().unwrap(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	// Deliver first update_fee/commitment_signed pair, generating (1) and (2):
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg_1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed_1);
	let (bs_revoke_msg, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	// nodes[0] is awaiting a revoke from nodes[1] before it will create a new commitment
	// transaction:
	nodes[0].node.update_fee(channel_id, initial_feerate + 40).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Create the (3) update_fee message that nodes[0] will generate before it does...
	let mut update_msg_2 = msgs::UpdateFee {
		channel_id: update_msg_1.channel_id.clone(),
		feerate_per_kw: (initial_feerate + 30) as u32,
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg_2);

	update_msg_2.feerate_per_kw = (initial_feerate + 40) as u32;
	// Deliver (3)
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg_2);

	// Deliver (1), generating (3) and (4)
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_msg);
	let as_second_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	assert!(as_second_update.update_add_htlcs.is_empty());
	assert!(as_second_update.update_fulfill_htlcs.is_empty());
	assert!(as_second_update.update_fail_htlcs.is_empty());
	assert!(as_second_update.update_fail_malformed_htlcs.is_empty());
	// Check that the update_fee newly generated matches what we delivered:
	assert_eq!(as_second_update.update_fee.as_ref().unwrap().channel_id, update_msg_2.channel_id);
	assert_eq!(as_second_update.update_fee.as_ref().unwrap().feerate_per_kw, update_msg_2.feerate_per_kw);

	// Deliver (2) commitment_signed
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment_signed);
	let as_revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	// Delever (4)
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_update.commitment_signed);
	let (bs_second_revoke, bs_second_commitment) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment);
	let as_second_revoke = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_revoke);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_1_conf_open() {
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
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001, InitFeatures::known(), InitFeatures::known());
	let block = Block {
		header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
		txdata: vec![tx],
	};
	connect_block(&nodes[1], &block, 1);
	nodes[0].node.handle_funding_locked(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendFundingLocked, nodes[0].node.get_our_node_id()));

	connect_block(&nodes[0], &block, 1);
	let (funding_locked, _) = create_chan_between_nodes_with_value_confirm_second(&nodes[1], &nodes[0]);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_locked);

	for node in nodes {
		assert!(node.net_graph_msg_handler.handle_channel_announcement(&announcement).unwrap());
		node.net_graph_msg_handler.handle_channel_update(&as_update).unwrap();
		node.net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
	}
}

fn do_test_sanity_on_in_flight_opens(steps: u8) {
	// Previously, we had issues deserializing channels when we hadn't connected the first block
	// after creation. To catch that and similar issues, we lean on the Node::drop impl to test
	// serialization round-trips and simply do steps towards opening a channel and then drop the
	// Node objects.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	if steps & 0b1000_0000 != 0{
		let block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};
		connect_block(&nodes[0], &block, 1);
		connect_block(&nodes[1], &block, 1);
	}

	if steps & 0x0f == 0 { return; }
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	if steps & 0x0f == 1 { return; }
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());

	if steps & 0x0f == 2 { return; }
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &accept_channel);

	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(&nodes[0], 100000, 42);

	if steps & 0x0f == 3 { return; }
	nodes[0].node.funding_transaction_generated(&temporary_channel_id, funding_output);
	check_added_monitors!(nodes[0], 0);
	let funding_created = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

	if steps & 0x0f == 4 { return; }
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created);
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}
	let funding_signed = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

	if steps & 0x0f == 5 { return; }
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
	{
		let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	match events_4[0] {
		Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
			assert_eq!(user_channel_id, 42);
			assert_eq!(*funding_txo, funding_output);
		},
		_ => panic!("Unexpected event"),
	};

	if steps & 0x0f == 6 { return; }
	create_chan_between_nodes_with_value_confirm_first(&nodes[0], &nodes[1], &tx, 2);

	if steps & 0x0f == 7 { return; }
	confirm_transaction(&nodes[0], &tx);
	create_chan_between_nodes_with_value_confirm_second(&nodes[1], &nodes[0]);
}

#[test]
fn test_sanity_on_in_flight_opens() {
	do_test_sanity_on_in_flight_opens(0);
	do_test_sanity_on_in_flight_opens(0 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(1);
	do_test_sanity_on_in_flight_opens(1 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(2);
	do_test_sanity_on_in_flight_opens(2 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(3);
	do_test_sanity_on_in_flight_opens(3 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(4);
	do_test_sanity_on_in_flight_opens(4 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(5);
	do_test_sanity_on_in_flight_opens(5 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(6);
	do_test_sanity_on_in_flight_opens(6 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(7);
	do_test_sanity_on_in_flight_opens(7 | 0b1000_0000);
	do_test_sanity_on_in_flight_opens(8);
	do_test_sanity_on_in_flight_opens(8 | 0b1000_0000);
}

#[test]
fn test_update_fee_vanilla() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let channel_id = chan.2;

	let feerate = get_feerate!(nodes[0], channel_id);
	nodes[0].node.update_fee(channel_id, feerate+25).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (revoke_msg, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_fee_that_funder_cannot_afford() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_value = 1888;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value, 700000, InitFeatures::known(), InitFeatures::known());
	let channel_id = chan.2;

	let feerate = 260;
	nodes[0].node.update_fee(channel_id, feerate).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_msg = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update_msg.update_fee.unwrap());

	commitment_signed_dance!(nodes[1], nodes[0], update_msg.commitment_signed, false);

	//Confirm that the new fee based on the last local commitment txn is what we expected based on the feerate of 260 set above.
	//This value results in a fee that is exactly what the funder can afford (277 sat + 1000 sat channel reserve)
	{
		let commitment_tx = get_local_commitment_txn!(nodes[1], channel_id)[0].clone();

		//We made sure neither party's funds are below the dust limit so -2 non-HTLC txns from number of outputs
		let num_htlcs = commitment_tx.output.len() - 2;
		let total_fee: u64 = feerate as u64 * (COMMITMENT_TX_BASE_WEIGHT + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000;
		let mut actual_fee = commitment_tx.output.iter().fold(0, |acc, output| acc + output.value);
		actual_fee = channel_value - actual_fee;
		assert_eq!(total_fee, actual_fee);
	}

	//Add 2 to the previous fee rate to the final fee increases by 1 (with no HTLCs the fee is essentially
	//fee_rate*(724/1000) so the increment of 1*0.724 is rounded back down)
	nodes[0].node.update_fee(channel_id, feerate+2).unwrap();
	check_added_monitors!(nodes[0], 1);

	let update2_msg = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &update2_msg.update_fee.unwrap());

	//While producing the commitment_signed response after handling a received update_fee request the
	//check to see if the funder, who sent the update_fee request, can afford the new fee (funder_balance >= fee+channel_reserve)
	//Should produce and error.
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &update2_msg.commitment_signed);
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Funding remote cannot afford proposed new fee".to_string(), 1);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
}

#[test]
fn test_update_fee_with_fundee_update_add_htlc() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let channel_id = chan.2;
	let logger = test_utils::TestLogger::new();

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);

	let feerate = get_feerate!(nodes[0], channel_id);
	nodes[0].node.update_fee(channel_id, feerate+20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (revoke_msg, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[1]);
	let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
	let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &Vec::new(), 800000, TEST_FINAL_CLTV, &logger).unwrap();

	// nothing happens since node[1] is in AwaitingRemoteRevoke
	nodes[1].node.send_payment(&route, our_payment_hash, &None).unwrap();
	{
		let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 0);
		added_monitors.clear();
	}
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	// node[1] has nothing to do

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg);
	check_added_monitors!(nodes[1], 1);
	// AwaitingRemoteRevoke ends here

	let commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(commitment_update.update_add_htlcs.len(), 1);
	assert_eq!(commitment_update.update_fulfill_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fail_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fail_malformed_htlcs.len(), 0);
	assert_eq!(commitment_update.update_fee.is_none(), true);

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &commitment_update.update_add_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let (revoke, commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let revoke = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke);
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	expect_pending_htlcs_forwardable!(nodes[0]);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentReceived { .. } => { },
		_ => panic!("Unexpected event"),
	};

	claim_payment(&nodes[1], &vec!(&nodes[0])[..], our_payment_preimage, 800_000);

	send_payment(&nodes[1], &vec!(&nodes[0])[..], 800000, 800_000);
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 800000, 800_000);
	close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
}

#[test]
fn test_update_fee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let channel_id = chan.2;

	// A                                        B
	// (1) update_fee/commitment_signed      ->
	//                                       <- (2) revoke_and_ack
	//                                       .- send (3) commitment_signed
	// (4) update_fee/commitment_signed      ->
	//                                       .- send (5) revoke_and_ack (no CS as we're awaiting a revoke)
	//                                       <- (3) commitment_signed delivered
	// send (6) revoke_and_ack               -.
	//                                       <- (5) deliver revoke_and_ack
	// (6) deliver revoke_and_ack            ->
	//                                       .- send (7) commitment_signed in response to (4)
	//                                       <- (7) deliver commitment_signed
	// revoke_and_ack                        ->

	// Create and deliver (1)...
	let feerate = get_feerate!(nodes[0], channel_id);
	nodes[0].node.update_fee(channel_id, feerate+20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	// Generate (2) and (3):
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (revoke_msg, commitment_signed_0) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	// Deliver (2):
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	// Create and deliver (4)...
	nodes[0].node.update_fee(channel_id, feerate+30).unwrap();
	check_added_monitors!(nodes[0], 1);
	let events_0 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_0.len(), 1);
	let (update_msg, commitment_signed) = match events_0[0] {
			MessageSendEvent::UpdateHTLCs { node_id:_, updates: msgs::CommitmentUpdate { update_add_htlcs:_, update_fulfill_htlcs:_, update_fail_htlcs:_, update_fail_malformed_htlcs:_, ref update_fee, ref commitment_signed } } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	check_added_monitors!(nodes[1], 1);
	// ... creating (5)
	let revoke_msg = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	// Handle (3), creating (6):
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed_0);
	check_added_monitors!(nodes[0], 1);
	let revoke_msg_0 = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	// Deliver (5):
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	// Deliver (6), creating (7):
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg_0);
	let commitment_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(commitment_update.update_add_htlcs.is_empty());
	assert!(commitment_update.update_fulfill_htlcs.is_empty());
	assert!(commitment_update.update_fail_htlcs.is_empty());
	assert!(commitment_update.update_fail_malformed_htlcs.is_empty());
	assert!(commitment_update.update_fee.is_none());
	check_added_monitors!(nodes[1], 1);

	// Deliver (7)
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let revoke_msg = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &revoke_msg);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	assert_eq!(get_feerate!(nodes[0], channel_id), feerate + 30);
	assert_eq!(get_feerate!(nodes[1], channel_id), feerate + 30);
	close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true);
}

#[test]
fn pre_funding_lock_shutdown_test() {
	// Test sending a shutdown prior to funding_locked after funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 8000000, 0, InitFeatures::known(), InitFeatures::known());
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header, txdata: vec![tx.clone()]}, 1);
	connect_block(&nodes[1], &Block { header, txdata: vec![tx.clone()]}, 1);

	nodes[0].node.close_channel(&OutPoint { txid: tx.txid(), index: 0 }.to_channel_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap());
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	assert!(node_0_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
}

#[test]
fn updates_shutdown_wait() {
	// Test sending a shutdown with outstanding updates pending
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100000);

	nodes[0].node.close_channel(&chan_1.2).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);

	let net_graph_msg_handler0 = &nodes[0].net_graph_msg_handler;
	let net_graph_msg_handler1 = &nodes[1].net_graph_msg_handler;
	let route_1 = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler0.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	let route_2 = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler1.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	unwrap_send_err!(nodes[0].node.send_payment(&route_1, payment_hash, &None), true, APIError::ChannelUnavailable {..}, {});
	unwrap_send_err!(nodes[1].node.send_payment(&route_2, payment_hash, &None), true, APIError::ChannelUnavailable {..}, {});

	assert!(nodes[2].node.claim_funds(our_payment_preimage, &None, 100_000));
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(our_payment_preimage, *payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap());
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	assert!(node_0_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

#[test]
fn htlc_fail_async_shutdown() {
	// Test HTLCs fail if shutdown starts even if messages are delivered out-of-order
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert_eq!(updates.update_add_htlcs.len(), 1);
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());

	nodes[1].node.close_channel(&chan_1.2).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	commitment_signed_dance!(nodes[1], nodes[0], (), false, true, false);

	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fulfill_htlcs.is_empty());
	assert_eq!(updates_2.update_fail_htlcs.len(), 1);
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	expect_payment_failed!(nodes[0], our_payment_hash, false);

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	let node_0_closing_signed = match msg_events[0] {
		MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	match msg_events[1] {
		MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg }} => {
			assert_eq!(msg.contents.short_channel_id, chan_1.0.contents.short_channel_id);
		},
		_ => panic!("Unexpected event"),
	}

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap());
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	assert!(node_0_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

fn do_test_shutdown_rebroadcast(recv_count: u8) {
	// Test that shutdown/closing_signed is re-sent on reconnect with a variable number of
	// messages delivered prior to disconnect
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100000);

	nodes[1].node.close_channel(&chan_1.2).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	if recv_count > 0 {
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		if recv_count > 1 {
			nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let node_0_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let node_1_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_reestablish);
	let node_1_2nd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	assert!(node_1_shutdown == node_1_2nd_shutdown);

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_reestablish);
	let node_0_2nd_shutdown = if recv_count > 0 {
		let node_0_2nd_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_2nd_shutdown);
		node_0_2nd_shutdown
	} else {
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_2nd_shutdown);
		get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id())
	};
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_2nd_shutdown);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	assert!(nodes[2].node.claim_funds(our_payment_preimage, &None, 100_000));
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(our_payment_preimage, *payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	if recv_count > 0 {
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
		let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		assert!(node_1_closing_signed.is_some());
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let node_0_2nd_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, nodes[1].node.get_our_node_id());
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	if recv_count == 0 {
		// If all closing_signeds weren't delivered we can just resume where we left off...
		let node_1_2nd_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_2nd_reestablish);
		let node_0_3rd_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		assert!(node_0_2nd_shutdown == node_0_3rd_shutdown);

		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_2nd_reestablish);
		let node_1_3rd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		assert!(node_1_3rd_shutdown == node_1_2nd_shutdown);

		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_3rd_shutdown);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_3rd_shutdown);
		let node_0_2nd_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
		assert!(node_0_closing_signed == node_0_2nd_closing_signed);

		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed);
		let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap());
		let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		assert!(node_0_none.is_none());
	} else {
		// If one node, however, received + responded with an identical closing_signed we end
		// up erroring and node[0] will try to broadcast its own latest commitment transaction.
		// There isn't really anything better we can do simply, but in the future we might
		// explore storing a set of recently-closed channels that got disconnected during
		// closing_signed and avoiding broadcasting local commitment txn for some timeout to
		// give our counterparty enough time to (potentially) broadcast a cooperative closing
		// transaction.
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_2nd_reestablish);
		let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		if let MessageSendEvent::HandleError { ref action, .. } = msg_events[0] {
			match action {
				&ErrorAction::SendErrorMessage { ref msg } => {
					nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msg);
					assert_eq!(msg.channel_id, chan_1.2);
				},
				_ => panic!("Unexpected event!"),
			}
		} else { panic!("Needed SendErrorMessage close"); }

		// get_closing_signed_broadcast usually eats the BroadcastChannelUpdate for us and
		// checks it, but in this case nodes[0] didn't ever get a chance to receive a
		// closing_signed so we do it ourselves
		check_closed_broadcast!(nodes[0], false);
		check_added_monitors!(nodes[0], 1);
	}

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
}

#[test]
fn test_shutdown_rebroadcast() {
	do_test_shutdown_rebroadcast(0);
	do_test_shutdown_rebroadcast(1);
	do_test_shutdown_rebroadcast(2);
}

#[test]
fn fake_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that payments get routed and transactions broadcast in semi-reasonable ways.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known());

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000, 8_000_000);

	// Send some more payments
	send_payment(&nodes[1], &vec!(&nodes[2], &nodes[3])[..], 1000000, 1_000_000);
	send_payment(&nodes[3], &vec!(&nodes[2], &nodes[1], &nodes[0])[..], 1000000, 1_000_000);
	send_payment(&nodes[3], &vec!(&nodes[2], &nodes[1])[..], 1000000, 1_000_000);

	// Test failure packets
	let payment_hash_1 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 1000000).1;
	fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], payment_hash_1);

	// Add a new channel that skips 3
	let chan_4 = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known());

	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 1000000, 1_000_000);
	send_payment(&nodes[2], &vec!(&nodes[3])[..], 1000000, 1_000_000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000, 8_000_000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000, 8_000_000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000, 8_000_000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000, 8_000_000);
	send_payment(&nodes[1], &vec!(&nodes[3])[..], 8000000, 8_000_000);

	// Do some rebalance loop payments, simultaneously
	let mut hops = Vec::with_capacity(3);
	hops.push(RouteHop {
		pubkey: nodes[2].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_2.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 0,
		cltv_expiry_delta: chan_3.0.contents.cltv_expiry_delta as u32
	});
	hops.push(RouteHop {
		pubkey: nodes[3].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_3.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 0,
		cltv_expiry_delta: chan_4.1.contents.cltv_expiry_delta as u32
	});
	hops.push(RouteHop {
		pubkey: nodes[1].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_4.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 1000000,
		cltv_expiry_delta: TEST_FINAL_CLTV,
	});
	hops[1].fee_msat = chan_4.1.contents.fee_base_msat as u64 + chan_4.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
	hops[0].fee_msat = chan_3.0.contents.fee_base_msat as u64 + chan_3.0.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
	let payment_preimage_1 = send_along_route(&nodes[1], Route { paths: vec![hops] }, &vec!(&nodes[2], &nodes[3], &nodes[1])[..], 1000000).0;

	let mut hops = Vec::with_capacity(3);
	hops.push(RouteHop {
		pubkey: nodes[3].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_4.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 0,
		cltv_expiry_delta: chan_3.1.contents.cltv_expiry_delta as u32
	});
	hops.push(RouteHop {
		pubkey: nodes[2].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_3.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 0,
		cltv_expiry_delta: chan_2.1.contents.cltv_expiry_delta as u32
	});
	hops.push(RouteHop {
		pubkey: nodes[1].node.get_our_node_id(),
		node_features: NodeFeatures::empty(),
		short_channel_id: chan_2.0.contents.short_channel_id,
		channel_features: ChannelFeatures::empty(),
		fee_msat: 1000000,
		cltv_expiry_delta: TEST_FINAL_CLTV,
	});
	hops[1].fee_msat = chan_2.1.contents.fee_base_msat as u64 + chan_2.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
	hops[0].fee_msat = chan_3.1.contents.fee_base_msat as u64 + chan_3.1.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
	let payment_hash_2 = send_along_route(&nodes[1], Route { paths: vec![hops] }, &vec!(&nodes[3], &nodes[2], &nodes[1])[..], 1000000).1;

	// Claim the rebalances...
	fail_payment(&nodes[1], &vec!(&nodes[3], &nodes[2], &nodes[1])[..], payment_hash_2);
	claim_payment(&nodes[1], &vec!(&nodes[2], &nodes[3], &nodes[1])[..], payment_preimage_1, 1_000_000);

	// Add a duplicate new channel from 2 to 4
	let chan_5 = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known());

	// Send some payments across both channels
	let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;
	let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;
	let payment_preimage_5 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000).0;


	route_over_limit(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], 3000000);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 0);
	nodes[0].logger.assert_log_regex("lightning::ln::channelmanager".to_string(), regex::Regex::new(r"Cannot send value that would put us over the max HTLC value in flight our peer will accept \(\d+\)").unwrap(), 1);

	//TODO: Test that routes work again here as we've been notified that the channel is full

	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_3, 3_000_000);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_4, 3_000_000);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[3])[..], payment_preimage_5, 3_000_000);

	// Close down the channels...
	close_channel(&nodes[0], &nodes[1], &chan_1.2, chan_1.3, true);
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, false);
	close_channel(&nodes[2], &nodes[3], &chan_3.2, chan_3.3, true);
	close_channel(&nodes[1], &nodes[3], &chan_4.2, chan_4.3, false);
	close_channel(&nodes[1], &nodes[3], &chan_5.2, chan_5.3, false);
}

#[test]
fn holding_cell_htlc_counting() {
	// Tests that HTLCs in the holding cell count towards the pending HTLC limits on outbound HTLCs
	// to ensure we don't end up with HTLCs sitting around in our holding cell for several
	// commitment dance rounds.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let mut payments = Vec::new();
	for _ in 0..::ln::channel::OUR_MAX_HTLCS {
		let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[0]);
		let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
		let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 100000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[1].node.send_payment(&route, payment_hash, &None).unwrap();
		payments.push((payment_preimage, payment_hash));
	}
	check_added_monitors!(nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let initial_payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(initial_payment_event.node_id, nodes[2].node.get_our_node_id());

	// There is now one HTLC in an outbound commitment transaction and (OUR_MAX_HTLCS - 1) HTLCs in
	// the holding cell waiting on B's RAA to send. At this point we should not be able to add
	// another HTLC.
	let (_, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
		let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 100000, TEST_FINAL_CLTV, &logger).unwrap();
		unwrap_send_err!(nodes[1].node.send_payment(&route, payment_hash_1, &None), true, APIError::ChannelUnavailable { ref err },
			assert!(regex::Regex::new(r"Cannot push more than their max accepted HTLCs \(\d+\)").unwrap().is_match(err)));
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		nodes[1].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Cannot push more than their max accepted HTLCs".to_string(), 1);
	}

	// This should also be true if we try to forward a payment.
	let (_, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 100000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_2, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
	}

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	// We have to forward pending HTLCs twice - once tries to forward the payment forward (and
	// fails), the second will process the resulting failure and fail the HTLC backward.
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let bs_fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], bs_fail_updates.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelUpdateMessage { ref msg }} => {
			assert_eq!(msg.contents.short_channel_id, chan_2.0.contents.short_channel_id);
		},
		_ => panic!("Unexpected event"),
	}

	expect_payment_failed!(nodes[0], payment_hash_2, false);

	// Now forward all the pending HTLCs and claim them back
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &initial_payment_event.msgs[0]);
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &initial_payment_event.commitment_msg);
	check_added_monitors!(nodes[2], 1);

	let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack);
	check_added_monitors!(nodes[1], 1);
	let as_updates = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

	for ref update in as_updates.update_add_htlcs.iter() {
		nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), update);
	}
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_updates.commitment_signed);
	check_added_monitors!(nodes[2], 1);
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[2], 1);
	let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_revoke_and_ack);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &bs_commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let as_final_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_final_raa);
	check_added_monitors!(nodes[2], 1);

	expect_pending_htlcs_forwardable!(nodes[2]);

	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), payments.len());
	for (event, &(_, ref hash)) in events.iter().zip(payments.iter()) {
		match event {
			&Event::PaymentReceived { ref payment_hash, .. } => {
				assert_eq!(*payment_hash, *hash);
			},
			_ => panic!("Unexpected event"),
		};
	}

	for (preimage, _) in payments.drain(..) {
		claim_payment(&nodes[1], &[&nodes[2]], preimage, 100_000);
	}

	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000, 1_000_000);
}

#[test]
fn duplicate_htlc_test() {
	// Test that we accept duplicate payment_hash HTLCs across the network and that
	// claiming/failing them are all separate and don't affect each other
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs, &[None, None, None, None, None, None]);
	let mut nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	// Create some initial channels to route via 3 to 4/5 from 0/1/2
	create_announced_chan_between_nodes(&nodes, 0, 3, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 3, 4, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 3, 5, InitFeatures::known(), InitFeatures::known());

	let (payment_preimage, payment_hash) = route_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], 1000000);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[1], &vec!(&nodes[3])[..], 1000000).0, payment_preimage);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], 1000000).0, payment_preimage);

	claim_payment(&nodes[0], &vec!(&nodes[3], &nodes[4])[..], payment_preimage, 1_000_000);
	fail_payment(&nodes[2], &vec!(&nodes[3], &nodes[5])[..], payment_hash);
	claim_payment(&nodes[1], &vec!(&nodes[3])[..], payment_preimage, 1_000_000);
}

#[test]
fn test_duplicate_htlc_different_direction_onchain() {
	// Test that ChannelMonitor doesn't generate 2 preimage txn
	// when we have 2 HTLCs with same preimage that go across a node
	// in opposite directions.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);

	let (payment_preimage, payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 900_000);

	let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
	let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &Vec::new(), 800_000, TEST_FINAL_CLTV, &logger).unwrap();
	send_along_route_with_hash(&nodes[1], route, &vec!(&nodes[0])[..], 800_000, payment_hash);

	// Provide preimage to node 0 by claiming payment
	nodes[0].node.claim_funds(payment_preimage, &None, 800_000);
	check_added_monitors!(nodes[0], 1);

	// Broadcast node 1 commitment txn
	let remote_txn = get_local_commitment_txn!(nodes[1], chan_1.2);

	assert_eq!(remote_txn[0].output.len(), 4); // 1 local, 1 remote, 1 htlc inbound, 1 htlc outbound
	let mut has_both_htlcs = 0; // check htlcs match ones committed
	for outp in remote_txn[0].output.iter() {
		if outp.value == 800_000 / 1000 {
			has_both_htlcs += 1;
		} else if outp.value == 900_000 / 1000 {
			has_both_htlcs += 1;
		}
	}
	assert_eq!(has_both_htlcs, 2);

	let header = BlockHeader { version: 0x2000_0000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header, txdata: vec![remote_txn[0].clone()] }, 1);
	check_added_monitors!(nodes[0], 1);

	// Check we only broadcast 1 timeout tx
	let claim_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	let htlc_pair = if claim_txn[0].output[0].value == 800_000 / 1000 { (claim_txn[0].clone(), claim_txn[1].clone()) } else { (claim_txn[1].clone(), claim_txn[0].clone()) };
	assert_eq!(claim_txn.len(), 5);
	check_spends!(claim_txn[2], chan_1.3);
	check_spends!(claim_txn[3], claim_txn[2]);
	assert_eq!(htlc_pair.0.input.len(), 1);
	assert_eq!(htlc_pair.0.input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC 1 <--> 0, preimage tx
	check_spends!(htlc_pair.0, remote_txn[0]);
	assert_eq!(htlc_pair.1.input.len(), 1);
	assert_eq!(htlc_pair.1.input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // HTLC 0 <--> 1, timeout tx
	check_spends!(htlc_pair.1, remote_txn[0]);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	for e in events {
		match e {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, .. } } => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_malformed_htlcs.is_empty());
				assert_eq!(nodes[1].node.get_our_node_id(), *node_id);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_basic_channel_reserve() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;

	// The 2* and +1 are for the fee spike reserve.
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let commit_tx_fee = 2 * commit_tx_fee_msat(get_feerate!(nodes[0], chan.2), 1 + 1);
	let max_can_send = 5000000 - channel_reserve - commit_tx_fee;
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes.last().unwrap().node.get_our_node_id(), None, None, &Vec::new(), max_can_send + 1, TEST_FINAL_CLTV, &logger).unwrap();
	let err = nodes[0].node.send_payment(&route, our_payment_hash, &None).err().unwrap();
	match err {
		PaymentSendFailure::AllFailedRetrySafe(ref fails) => {
			match &fails[0] {
				&APIError::ChannelUnavailable{ref err} =>
					assert!(regex::Regex::new(r"Cannot send value that would put our balance under counterparty-announced channel reserve value \(\d+\)").unwrap().is_match(err)),
				_ => panic!("Unexpected error variant"),
			}
		},
		_ => panic!("Unexpected error variant"),
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Cannot send value that would put our balance under counterparty-announced channel reserve value".to_string(), 1);

	send_payment(&nodes[0], &vec![&nodes[1]], max_can_send, max_can_send);
}

#[test]
fn test_fee_spike_violation_fails_htlc() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	macro_rules! get_route_and_payment_hash {
		($recv_value: expr) => {{
			let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[1]);
			let net_graph_msg_handler = &nodes[0].net_graph_msg_handler.network_graph.read().unwrap();
			let route = get_route(&nodes[0].node.get_our_node_id(), net_graph_msg_handler, &nodes.last().unwrap().node.get_our_node_id(), None, None, &Vec::new(), $recv_value, TEST_FINAL_CLTV, &logger).unwrap();
			(route, payment_hash, payment_preimage)
		}}
	}

	let (route, payment_hash, _) = get_route_and_payment_hash!(3460001);
	// Need to manually create the update_add_htlc message to go around the channel reserve check in send_htlc()
	let secp_ctx = Secp256k1::new();
	let session_priv = SecretKey::from_slice(&[42; 32]).expect("RNG is bad!");

	let cur_height = nodes[1].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;

	let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv).unwrap();
	let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 3460001, &None, cur_height).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash);
	let msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: 0,
		amount_msat: htlc_msat,
		payment_hash: payment_hash,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet,
	};

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);

	// Now manually create the commitment_signed message corresponding to the update_add
	// nodes[0] just sent. In the code for construction of this message, "local" refers
	// to the sender of the message, and "remote" refers to the receiver.

	let feerate_per_kw = get_feerate!(nodes[0], chan.2);

	const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

	// Get the EnforcingSigner for each channel, which will be used to (1) get the keys
	// needed to sign the new commitment tx and (2) sign the new commitment tx.
	let (local_revocation_basepoint, local_htlc_basepoint, local_secret, next_local_point) = {
		let chan_lock = nodes[0].node.channel_state.lock().unwrap();
		let local_chan = chan_lock.by_id.get(&chan.2).unwrap();
		let chan_signer = local_chan.get_signer();
		let pubkeys = chan_signer.pubkeys();
		(pubkeys.revocation_basepoint, pubkeys.htlc_basepoint,
		 chan_signer.release_commitment_secret(INITIAL_COMMITMENT_NUMBER),
		 chan_signer.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 2, &secp_ctx))
	};
	let (remote_delayed_payment_basepoint, remote_htlc_basepoint,remote_point) = {
		let chan_lock = nodes[1].node.channel_state.lock().unwrap();
		let remote_chan = chan_lock.by_id.get(&chan.2).unwrap();
		let chan_signer = remote_chan.get_signer();
		let pubkeys = chan_signer.pubkeys();
		(pubkeys.delayed_payment_basepoint, pubkeys.htlc_basepoint,
		 chan_signer.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 1, &secp_ctx))
	};

	// Assemble the set of keys we can use for signatures for our commitment_signed message.
	let commit_tx_keys = chan_utils::TxCreationKeys::derive_new(&secp_ctx, &remote_point, &remote_delayed_payment_basepoint,
		&remote_htlc_basepoint, &local_revocation_basepoint, &local_htlc_basepoint).unwrap();

	// Build the remote commitment transaction so we can sign it, and then later use the
	// signature for the commitment_signed message.
	let local_chan_balance = 1313;

	let accepted_htlc_info = chan_utils::HTLCOutputInCommitment {
		offered: false,
		amount_msat: 3460001,
		cltv_expiry: htlc_cltv,
		payment_hash,
		transaction_output_index: Some(1),
	};

	let commitment_number = INITIAL_COMMITMENT_NUMBER - 1;

	let res = {
		let local_chan_lock = nodes[0].node.channel_state.lock().unwrap();
		let local_chan = local_chan_lock.by_id.get(&chan.2).unwrap();
		let local_chan_signer = local_chan.get_signer();
		let commitment_tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			commitment_number,
			95000,
			local_chan_balance,
			commit_tx_keys.clone(),
			feerate_per_kw,
			&mut vec![(accepted_htlc_info, ())],
			&local_chan.channel_transaction_parameters.as_counterparty_broadcastable()
		);
		local_chan_signer.sign_counterparty_commitment(&commitment_tx, &secp_ctx).unwrap()
	};

	let commit_signed_msg = msgs::CommitmentSigned {
		channel_id: chan.2,
		signature: res.0,
		htlc_signatures: res.1
	};

	// Send the commitment_signed message to the nodes[1].
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commit_signed_msg);
	let _ = nodes[1].node.get_and_clear_pending_msg_events();

	// Send the RAA to nodes[1].
	let raa_msg = msgs::RevokeAndACK {
		channel_id: chan.2,
		per_commitment_secret: local_secret,
		next_per_commitment_point: next_local_point
	};
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &raa_msg);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	// Make sure the HTLC failed in the way we expect.
	match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fail_htlcs, .. }, .. } => {
			assert_eq!(update_fail_htlcs.len(), 1);
			update_fail_htlcs[0].clone()
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].logger.assert_log("lightning::ln::channel".to_string(), "Attempting to fail HTLC due to fee spike buffer violation".to_string(), 1);

	check_added_monitors!(nodes[1], 2);
}

#[test]
fn test_chan_reserve_violation_outbound_htlc_inbound_chan() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	// Set the fee rate for the channel very high, to the point where the fundee
	// sending any above-dust amount would result in a channel reserve violation.
	// In this test we check that we would be prevented from sending an HTLC in
	// this situation.
	chanmon_cfgs[0].fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 6000 };
	chanmon_cfgs[1].fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 6000 };
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _ = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	macro_rules! get_route_and_payment_hash {
		($recv_value: expr) => {{
			let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[1]);
			let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
			let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes.first().unwrap().node.get_our_node_id(), None, None, &Vec::new(), $recv_value, TEST_FINAL_CLTV, &logger).unwrap();
			(route, payment_hash, payment_preimage)
		}}
	}

	let (route, our_payment_hash, _) = get_route_and_payment_hash!(4843000);
	unwrap_send_err!(nodes[1].node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
		assert_eq!(err, "Cannot send value that would put counterparty balance under holder-announced channel reserve value"));
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Cannot send value that would put counterparty balance under holder-announced channel reserve value".to_string(), 1);
}

#[test]
fn test_chan_reserve_violation_inbound_htlc_outbound_channel() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	// Set the fee rate for the channel very high, to the point where the funder
	// receiving 1 update_add_htlc would result in them closing the channel due
	// to channel reserve violation. This close could also happen if the fee went
	// up a more realistic amount, but many HTLCs were outstanding at the time of
	// the update_add_htlc.
	chanmon_cfgs[0].fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 6000 };
	chanmon_cfgs[1].fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 6000 };
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	macro_rules! get_route_and_payment_hash {
		($recv_value: expr) => {{
			let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[1]);
			let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
			let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes.first().unwrap().node.get_our_node_id(), None, None, &Vec::new(), $recv_value, TEST_FINAL_CLTV, &logger).unwrap();
			(route, payment_hash, payment_preimage)
		}}
	}

	let (route, payment_hash, _) = get_route_and_payment_hash!(1000);
	// Need to manually create the update_add_htlc message to go around the channel reserve check in send_htlc()
	let secp_ctx = Secp256k1::new();
	let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();
	let cur_height = nodes[1].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
	let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv).unwrap();
	let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 1000, &None, cur_height).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash);
	let msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: 1,
		amount_msat: htlc_msat + 1,
		payment_hash: payment_hash,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet,
	};

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &msg);
	// Check that the payment failed and the channel is closed in response to the malicious UpdateAdd.
	nodes[0].logger.assert_log("lightning::ln::channelmanager".to_string(), "Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value".to_string(), 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert_eq!(err_msg.data, "Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value");
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_chan_reserve_dust_inbound_htlcs_outbound_chan() {
	// Test that if we receive many dust HTLCs over an outbound channel, they don't count when
	// calculating our commitment transaction fee (this was previously broken).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Set nodes[0]'s balance such that they will consider any above-dust received HTLC to be a
	// channel reserve violation (so their balance is channel reserve (1000 sats) + commitment
	// transaction fee with 0 HTLCs (183 sats)).
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 98817000, InitFeatures::known(), InitFeatures::known());

	let dust_amt = 546000; // Dust amount
	// In the previous code, routing this dust payment would cause nodes[0] to perceive a channel
	// reserve violation even though it's a dust HTLC and therefore shouldn't count towards the
	// commitment transaction fee.
	let (_, _) = route_payment(&nodes[1], &[&nodes[0]], dust_amt);
}

#[test]
fn test_chan_reserve_dust_inbound_htlcs_inbound_chan() {
	// Test that if we receive many dust HTLCs over an inbound channel, they don't count when
	// calculating our counterparty's commitment transaction fee (this was previously broken).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 98000000, InitFeatures::known(), InitFeatures::known());

	let payment_amt = 46000; // Dust amount
	// In the previous code, these first four payments would succeed.
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);

	// Then these next 5 would be interpreted by nodes[1] as violating the fee spike buffer.
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);

	// And this last payment previously resulted in nodes[1] closing on its inbound-channel
	// counterparty, because it counted all the previous dust HTLCs against nodes[0]'s commitment
	// transaction fee and therefore perceived this next payment as a channel reserve violation.
	let (_, _) = route_payment(&nodes[0], &[&nodes[1]], payment_amt);
}

#[test]
fn test_chan_reserve_violation_inbound_htlc_inbound_chan() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let _ = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	macro_rules! get_route_and_payment_hash {
		($recv_value: expr) => {{
			let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[0]);
			let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
			let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes.last().unwrap().node.get_our_node_id(), None, None, &Vec::new(), $recv_value, TEST_FINAL_CLTV, &logger).unwrap();
			(route, payment_hash, payment_preimage)
		}}
	}

	let feemsat = 239;
	let total_routing_fee_msat = (nodes.len() - 2) as u64 * feemsat;
	let chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	let feerate = get_feerate!(nodes[0], chan.2);

	// Add a 2* and +1 for the fee spike reserve.
	let commit_tx_fee_2_htlc = 2*commit_tx_fee_msat(feerate, 2 + 1);
	let recv_value_1 = (chan_stat.value_to_self_msat - chan_stat.channel_reserve_msat - total_routing_fee_msat - commit_tx_fee_2_htlc)/2;
	let amt_msat_1 = recv_value_1 + total_routing_fee_msat;

	// Add a pending HTLC.
	let (route_1, our_payment_hash_1, _) = get_route_and_payment_hash!(amt_msat_1);
	let payment_event_1 = {
		nodes[0].node.send_payment(&route_1, our_payment_hash_1, &None).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event_1.msgs[0]);

	// Attempt to trigger a channel reserve violation --> payment failure.
	let commit_tx_fee_2_htlcs = commit_tx_fee_msat(feerate, 2);
	let recv_value_2 = chan_stat.value_to_self_msat - amt_msat_1 - chan_stat.channel_reserve_msat - total_routing_fee_msat - commit_tx_fee_2_htlcs + 1;
	let amt_msat_2 = recv_value_2 + total_routing_fee_msat;
	let (route_2, _, _) = get_route_and_payment_hash!(amt_msat_2);

	// Need to manually create the update_add_htlc message to go around the channel reserve check in send_htlc()
	let secp_ctx = Secp256k1::new();
	let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();
	let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
	let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route_2.paths[0], &session_priv).unwrap();
	let (onion_payloads, htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route_2.paths[0], recv_value_2, &None, cur_height).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &our_payment_hash_1);
	let msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: 1,
		amount_msat: htlc_msat + 1,
		payment_hash: our_payment_hash_1,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet,
	};

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);
	// Check that the payment failed and the channel is closed in response to the malicious UpdateAdd.
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Remote HTLC add would put them under remote reserve value".to_string(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert_eq!(err_msg.data, "Remote HTLC add would put them under remote reserve value");
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_inbound_outbound_capacity_is_not_zero() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _ = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let channels0 = node_chanmgrs[0].list_channels();
	let channels1 = node_chanmgrs[1].list_channels();
	assert_eq!(channels0.len(), 1);
	assert_eq!(channels1.len(), 1);

	assert_eq!(channels0[0].inbound_capacity_msat, 95000000);
	assert_eq!(channels1[0].outbound_capacity_msat, 95000000);

	assert_eq!(channels0[0].outbound_capacity_msat, 100000 * 1000 - 95000000);
	assert_eq!(channels1[0].inbound_capacity_msat, 100000 * 1000 - 95000000);
}

fn commit_tx_fee_msat(feerate: u32, num_htlcs: u64) -> u64 {
	(COMMITMENT_TX_BASE_WEIGHT + num_htlcs * COMMITMENT_TX_WEIGHT_PER_HTLC) * feerate as u64 / 1000 * 1000
}

#[test]
fn test_channel_reserve_holding_cell_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 190000, 1001, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 190000, 1001, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let mut stat01 = get_channel_value_stat!(nodes[0], chan_1.2);
	let mut stat11 = get_channel_value_stat!(nodes[1], chan_1.2);

	let mut stat12 = get_channel_value_stat!(nodes[1], chan_2.2);
	let mut stat22 = get_channel_value_stat!(nodes[2], chan_2.2);

	macro_rules! get_route_and_payment_hash {
		($recv_value: expr) => {{
			let (payment_preimage, payment_hash) = get_payment_preimage_hash!(nodes[0]);
			let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
			let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes.last().unwrap().node.get_our_node_id(), None, None, &Vec::new(), $recv_value, TEST_FINAL_CLTV, &logger).unwrap();
			(route, payment_hash, payment_preimage)
		}}
	}

	macro_rules! expect_forward {
		($node: expr) => {{
			let mut events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			check_added_monitors!($node, 1);
			let payment_event = SendEvent::from_event(events.remove(0));
			payment_event
		}}
	}

	let feemsat = 239; // somehow we know?
	let total_fee_msat = (nodes.len() - 2) as u64 * feemsat;
	let feerate = get_feerate!(nodes[0], chan_1.2);

	let recv_value_0 = stat01.counterparty_max_htlc_value_in_flight_msat - total_fee_msat;

	// attempt to send amt_msat > their_max_htlc_value_in_flight_msat
	{
		let (mut route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_0);
		route.paths[0].last_mut().unwrap().fee_msat += 1;
		assert!(route.paths[0].iter().rev().skip(1).all(|h| h.fee_msat == feemsat));
		unwrap_send_err!(nodes[0].node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
			assert!(regex::Regex::new(r"Cannot send value that would put us over the max HTLC value in flight our peer will accept \(\d+\)").unwrap().is_match(err)));
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		nodes[0].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Cannot send value that would put us over the max HTLC value in flight our peer will accept".to_string(), 1);
	}

	// channel reserve is bigger than their_max_htlc_value_in_flight_msat so loop to deplete
	// nodes[0]'s wealth
	loop {
		let amt_msat = recv_value_0 + total_fee_msat;
		// 3 for the 3 HTLCs that will be sent, 2* and +1 for the fee spike reserve.
		// Also, ensure that each payment has enough to be over the dust limit to
		// ensure it'll be included in each commit tx fee calculation.
		let commit_tx_fee_all_htlcs = 2*commit_tx_fee_msat(feerate, 3 + 1);
		let ensure_htlc_amounts_above_dust_buffer = 3 * (stat01.counterparty_dust_limit_msat + 1000);
		if stat01.value_to_self_msat < stat01.channel_reserve_msat + commit_tx_fee_all_htlcs + ensure_htlc_amounts_above_dust_buffer + amt_msat {
			break;
		}
		send_payment(&nodes[0], &vec![&nodes[1], &nodes[2]][..], recv_value_0, recv_value_0);

		let (stat01_, stat11_, stat12_, stat22_) = (
			get_channel_value_stat!(nodes[0], chan_1.2),
			get_channel_value_stat!(nodes[1], chan_1.2),
			get_channel_value_stat!(nodes[1], chan_2.2),
			get_channel_value_stat!(nodes[2], chan_2.2),
		);

		assert_eq!(stat01_.value_to_self_msat, stat01.value_to_self_msat - amt_msat);
		assert_eq!(stat11_.value_to_self_msat, stat11.value_to_self_msat + amt_msat);
		assert_eq!(stat12_.value_to_self_msat, stat12.value_to_self_msat - (amt_msat - feemsat));
		assert_eq!(stat22_.value_to_self_msat, stat22.value_to_self_msat + (amt_msat - feemsat));
		stat01 = stat01_; stat11 = stat11_; stat12 = stat12_; stat22 = stat22_;
	}

	// adding pending output.
	// 2* and +1 HTLCs on the commit tx fee for the fee spike reserve.
	// The reason we're dividing by two here is as follows: the dividend is the total outbound liquidity
	// after fees, the channel reserve, and the fee spike buffer are removed. We eventually want to
	// divide this quantity into 3 portions, that will each be sent in an HTLC. This allows us
	// to test channel channel reserve policy at the edges of what amount is sendable, i.e.
	// cases where 1 msat over X amount will cause a payment failure, but anything less than
	// that can be sent successfully. So, dividing by two is a somewhat arbitrary way of getting
	// the amount of the first of these aforementioned 3 payments. The reason we split into 3 payments
	// is to test the behavior of the holding cell with respect to channel reserve and commit tx fee
	// policy.
	let commit_tx_fee_2_htlcs = 2*commit_tx_fee_msat(feerate, 2 + 1);
	let recv_value_1 = (stat01.value_to_self_msat - stat01.channel_reserve_msat - total_fee_msat - commit_tx_fee_2_htlcs)/2;
	let amt_msat_1 = recv_value_1 + total_fee_msat;

	let (route_1, our_payment_hash_1, our_payment_preimage_1) = get_route_and_payment_hash!(recv_value_1);
	let payment_event_1 = {
		nodes[0].node.send_payment(&route_1, our_payment_hash_1, &None).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event_1.msgs[0]);

	// channel reserve test with htlc pending output > 0
	let recv_value_2 = stat01.value_to_self_msat - amt_msat_1 - stat01.channel_reserve_msat - total_fee_msat - commit_tx_fee_2_htlcs;
	{
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_2 + 1);
		unwrap_send_err!(nodes[0].node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
			assert!(regex::Regex::new(r"Cannot send value that would put our balance under counterparty-announced channel reserve value \(\d+\)").unwrap().is_match(err)));
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	// split the rest to test holding cell
	let commit_tx_fee_3_htlcs = 2*commit_tx_fee_msat(feerate, 3 + 1);
	let additional_htlc_cost_msat = commit_tx_fee_3_htlcs - commit_tx_fee_2_htlcs;
	let recv_value_21 = recv_value_2/2 - additional_htlc_cost_msat/2;
	let recv_value_22 = recv_value_2 - recv_value_21 - total_fee_msat - additional_htlc_cost_msat;
	{
		let stat = get_channel_value_stat!(nodes[0], chan_1.2);
		assert_eq!(stat.value_to_self_msat - (stat.pending_outbound_htlcs_amount_msat + recv_value_21 + recv_value_22 + total_fee_msat + total_fee_msat + commit_tx_fee_3_htlcs), stat.channel_reserve_msat);
	}

	// now see if they go through on both sides
	let (route_21, our_payment_hash_21, our_payment_preimage_21) = get_route_and_payment_hash!(recv_value_21);
	// but this will stuck in the holding cell
	nodes[0].node.send_payment(&route_21, our_payment_hash_21, &None).unwrap();
	check_added_monitors!(nodes[0], 0);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 0);

	// test with outbound holding cell amount > 0
	{
		let (route, our_payment_hash, _) = get_route_and_payment_hash!(recv_value_22+1);
		unwrap_send_err!(nodes[0].node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
			assert!(regex::Regex::new(r"Cannot send value that would put our balance under counterparty-announced channel reserve value \(\d+\)").unwrap().is_match(err)));
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		nodes[0].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Cannot send value that would put our balance under counterparty-announced channel reserve value".to_string(), 2);
	}

	let (route_22, our_payment_hash_22, our_payment_preimage_22) = get_route_and_payment_hash!(recv_value_22);
	// this will also stuck in the holding cell
	nodes[0].node.send_payment(&route_22, our_payment_hash_22, &None).unwrap();
	check_added_monitors!(nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// flush the pending htlc
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event_1.commitment_msg);
	let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	// the pending htlc should be promoted to committed
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_revoke_and_ack);
	check_added_monitors!(nodes[0], 1);
	let commitment_update_2 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &as_commitment_signed);
	let bs_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &bs_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let ref payment_event_11 = expect_forward!(nodes[1]);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_11.msgs[0]);
	commitment_signed_dance!(nodes[2], nodes[1], payment_event_11.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[2]);
	expect_payment_received!(nodes[2], our_payment_hash_1, recv_value_1);

	// flush the htlcs in the holding cell
	assert_eq!(commitment_update_2.update_add_htlcs.len(), 2);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &commitment_update_2.update_add_htlcs[0]);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &commitment_update_2.update_add_htlcs[1]);
	commitment_signed_dance!(nodes[1], nodes[0], &commitment_update_2.commitment_signed, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	let ref payment_event_3 = expect_forward!(nodes[1]);
	assert_eq!(payment_event_3.msgs.len(), 2);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_3.msgs[0]);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_3.msgs[1]);

	commitment_signed_dance!(nodes[2], nodes[1], &payment_event_3.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[2]);

	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentReceived { ref payment_hash, ref payment_secret, amt } => {
			assert_eq!(our_payment_hash_21, *payment_hash);
			assert_eq!(*payment_secret, None);
			assert_eq!(recv_value_21, amt);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentReceived { ref payment_hash, ref payment_secret, amt } => {
			assert_eq!(our_payment_hash_22, *payment_hash);
			assert_eq!(None, *payment_secret);
			assert_eq!(recv_value_22, amt);
		},
		_ => panic!("Unexpected event"),
	}

	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_1, recv_value_1);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_21, recv_value_21);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), our_payment_preimage_22, recv_value_22);

	let commit_tx_fee_0_htlcs = 2*commit_tx_fee_msat(feerate, 1);
	let recv_value_3 = commit_tx_fee_2_htlcs - commit_tx_fee_0_htlcs - total_fee_msat;
	send_payment(&nodes[0], &vec![&nodes[1], &nodes[2]][..], recv_value_3, recv_value_3);

	let commit_tx_fee_1_htlc = 2*commit_tx_fee_msat(feerate, 1 + 1);
	let expected_value_to_self = stat01.value_to_self_msat - (recv_value_1 + total_fee_msat) - (recv_value_21 + total_fee_msat) - (recv_value_22 + total_fee_msat) - (recv_value_3 + total_fee_msat);
	let stat0 = get_channel_value_stat!(nodes[0], chan_1.2);
	assert_eq!(stat0.value_to_self_msat, expected_value_to_self);
	assert_eq!(stat0.value_to_self_msat, stat0.channel_reserve_msat + commit_tx_fee_1_htlc);

	let stat2 = get_channel_value_stat!(nodes[2], chan_2.2);
	assert_eq!(stat2.value_to_self_msat, stat22.value_to_self_msat + recv_value_1 + recv_value_21 + recv_value_22 + recv_value_3);
}

#[test]
fn channel_reserve_in_flight_removes() {
	// In cases where one side claims an HTLC, it thinks it has additional available funds that it
	// can send to its counterparty, but due to update ordering, the other side may not yet have
	// considered those HTLCs fully removed.
	// This tests that we don't count HTLCs which will not be included in the next remote
	// commitment transaction towards the reserve value (as it implies no commitment transaction
	// will be generated which violates the remote reserve value).
	// This was broken previously, and discovered by the chanmon_fail_consistency fuzz test.
	// To test this we:
	//  * route two HTLCs from A to B (note that, at a high level, this test is checking that, when
	//    you consider the values of both of these HTLCs, B may not send an HTLC back to A, but if
	//    you only consider the value of the first HTLC, it may not),
	//  * start routing a third HTLC from A to B,
	//  * claim the first two HTLCs (though B will generate an update_fulfill for one, and put
	//    the other claim in its holding cell, as it immediately goes into AwaitingRAA),
	//  * deliver the first fulfill from B
	//  * deliver the update_add and an RAA from A, resulting in B freeing the second holding cell
	//    claim,
	//  * deliver A's response CS and RAA.
	//    This results in A having the second HTLC in AwaitingRemovedRemoteRevoke, but B having
	//    removed it fully. B now has the push_msat plus the first two HTLCs in value.
	//  * Now B happily sends another HTLC, potentially violating its reserve value from A's point
	//    of view (if A counts the AwaitingRemovedRemoteRevoke HTLC).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let b_chan_values = get_channel_value_stat!(nodes[1], chan_1.2);
	// Route the first two HTLCs.
	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], b_chan_values.channel_reserve_msat - b_chan_values.value_to_self_msat - 10000);
	let (payment_preimage_2, _) = route_payment(&nodes[0], &[&nodes[1]], 20000);

	// Start routing the third HTLC (this is just used to get everyone in the right state).
	let (payment_preimage_3, payment_hash_3) = get_payment_preimage_hash!(nodes[0]);
	let send_1 = {
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_3, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	// Now claim both of the first two HTLCs on B's end, putting B in AwaitingRAA and generating an
	// initial fulfill/CS.
	assert!(nodes[1].node.claim_funds(payment_preimage_1, &None, b_chan_values.channel_reserve_msat - b_chan_values.value_to_self_msat - 10000));
	check_added_monitors!(nodes[1], 1);
	let bs_removes = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	// This claim goes in B's holding cell, allowing us to have a pending B->A RAA which does not
	// remove the second HTLC when we send the HTLC back from B to A.
	assert!(nodes[1].node.claim_funds(payment_preimage_2, &None, 20000));
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_removes.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_removes.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	expect_payment_sent!(nodes[0], payment_preimage_1);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_1.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &send_1.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	// B is already AwaitingRAA, so cant generate a CS here
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	let bs_cs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	// The second HTLCis removed, but as A is in AwaitingRAA it can't generate a CS here, so the
	// RAA that B generated above doesn't fully resolve the second HTLC from A's point of view.
	// However, the RAA A generates here *does* fully resolve the HTLC from B's point of view (as A
	// can no longer broadcast a commitment transaction with it and B has the preimage so can go
	// on-chain as necessary).
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_cs.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_cs.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	expect_payment_sent!(nodes[0], payment_preimage_2);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_received!(nodes[1], payment_hash_3, 100000);

	// Note that as this RAA was generated before the delivery of the update_fulfill it shouldn't
	// resolve the second HTLC from A's point of view.
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	// Now that B doesn't have the second RAA anymore, but A still does, send a payment from B back
	// to A to ensure that A doesn't count the almost-removed HTLC in update_add processing.
	let (payment_preimage_4, payment_hash_4) = get_payment_preimage_hash!(nodes[1]);
	let send_2 = {
		let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
		let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &[], 10000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[1].node.send_payment(&route, payment_hash_4, &None).unwrap();
		check_added_monitors!(nodes[1], 1);
		let mut events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &send_2.msgs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &send_2.commitment_msg);
	check_added_monitors!(nodes[0], 1);
	let as_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	// Now just resolve all the outstanding messages/HTLCs for completeness...

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);
	let as_cs = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_raa);
	check_added_monitors!(nodes[0], 1);

	expect_pending_htlcs_forwardable!(nodes[0]);
	expect_payment_received!(nodes[0], payment_hash_4, 10000);

	claim_payment(&nodes[1], &[&nodes[0]], payment_preimage_4, 10_000);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_3, 100_000);
}

#[test]
fn channel_monitor_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that ChannelMonitor is able to recover from various states.
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, None, None, None, None]);
	let nodes = create_network(5, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known());
	let chan_4 = create_announced_chan_between_nodes(&nodes, 3, 4, InitFeatures::known(), InitFeatures::known());

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3], &nodes[4])[..], 8000000, 8_000_000);

	// Simple case with no pending HTLCs:
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), true);
	check_added_monitors!(nodes[1], 1);
	{
		let mut node_txn = test_txn_broadcast(&nodes[1], &chan_1, None, HTLCType::NONE);
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[0], &Block { header, txdata: vec![node_txn.drain(..).next().unwrap()] }, 1);
		check_added_monitors!(nodes[0], 1);
		test_txn_broadcast(&nodes[0], &chan_1, None, HTLCType::NONE);
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	// One pending HTLC is discarded by the force-close:
	let payment_preimage_1 = route_payment(&nodes[1], &vec!(&nodes[2], &nodes[3])[..], 3000000).0;

	// Simple case of one pending HTLC to HTLC-Timeout
	nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), true);
	check_added_monitors!(nodes[1], 1);
	{
		let mut node_txn = test_txn_broadcast(&nodes[1], &chan_2, None, HTLCType::TIMEOUT);
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[2], &Block { header, txdata: vec![node_txn.drain(..).next().unwrap()] }, 1);
		check_added_monitors!(nodes[2], 1);
		test_txn_broadcast(&nodes[2], &chan_2, None, HTLCType::NONE);
	}
	get_announce_close_broadcast_events(&nodes, 1, 2);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
	assert_eq!(nodes[2].node.list_channels().len(), 1);

	macro_rules! claim_funds {
		($node: expr, $prev_node: expr, $preimage: expr, $amount: expr) => {
			{
				assert!($node.node.claim_funds($preimage, &None, $amount));
				check_added_monitors!($node, 1);

				let events = $node.node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				match events[0] {
					MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, .. } } => {
						assert!(update_add_htlcs.is_empty());
						assert!(update_fail_htlcs.is_empty());
						assert_eq!(*node_id, $prev_node.node.get_our_node_id());
					},
					_ => panic!("Unexpected event"),
				};
			}
		}
	}

	// nodes[3] gets the preimage, but nodes[2] already disconnected, resulting in a nodes[2]
	// HTLC-Timeout and a nodes[3] claim against it (+ its own announces)
	nodes[2].node.peer_disconnected(&nodes[3].node.get_our_node_id(), true);
	check_added_monitors!(nodes[2], 1);
	let node2_commitment_txid;
	{
		let node_txn = test_txn_broadcast(&nodes[2], &chan_3, None, HTLCType::TIMEOUT);
		node2_commitment_txid = node_txn[0].txid();

		// Claim the payment on nodes[3], giving it knowledge of the preimage
		claim_funds!(nodes[3], nodes[2], payment_preimage_1, 3_000_000);

		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[3], &Block { header, txdata: vec![node_txn[0].clone()] }, 1);
		check_added_monitors!(nodes[3], 1);

		check_preimage_claim(&nodes[3], &node_txn);
	}
	get_announce_close_broadcast_events(&nodes, 2, 3);
	assert_eq!(nodes[2].node.list_channels().len(), 0);
	assert_eq!(nodes[3].node.list_channels().len(), 1);

	{ // Cheat and reset nodes[4]'s height to 1
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[4], &Block { header, txdata: vec![] }, 1);
	}

	assert_eq!(nodes[3].node.latest_block_height.load(Ordering::Acquire), 1);
	assert_eq!(nodes[4].node.latest_block_height.load(Ordering::Acquire), 1);
	// One pending HTLC to time out:
	let payment_preimage_2 = route_payment(&nodes[3], &vec!(&nodes[4])[..], 3000000).0;
	// CLTV expires at TEST_FINAL_CLTV + 1 (current height) + 1 (added in send_payment for
	// buffer space).

	let (close_chan_update_1, close_chan_update_2) = {
		let mut block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};
		connect_block(&nodes[3], &block, 2);
		for i in 3..TEST_FINAL_CLTV + 2 + LATENCY_GRACE_PERIOD_BLOCKS + 1 {
			block = Block {
				header: BlockHeader { version: 0x20000000, prev_blockhash: block.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
				txdata: vec![],
			};
			connect_block(&nodes[3], &block, i);
		}
		let events = nodes[3].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let close_chan_update_1 = match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};
		check_added_monitors!(nodes[3], 1);

		// Clear bumped claiming txn spending node 2 commitment tx. Bumped txn are generated after reaching some height timer.
		{
			let mut node_txn = nodes[3].tx_broadcaster.txn_broadcasted.lock().unwrap();
			node_txn.retain(|tx| {
				if tx.input[0].previous_output.txid == node2_commitment_txid {
					false
				} else { true }
			});
		}

		let node_txn = test_txn_broadcast(&nodes[3], &chan_4, None, HTLCType::TIMEOUT);

		// Claim the payment on nodes[4], giving it knowledge of the preimage
		claim_funds!(nodes[4], nodes[3], payment_preimage_2, 3_000_000);

		block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};

		connect_block(&nodes[4], &block, 2);
		for i in 3..TEST_FINAL_CLTV + 2 - CLTV_CLAIM_BUFFER + 1 {
			block = Block {
				header: BlockHeader { version: 0x20000000, prev_blockhash: block.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
				txdata: vec![],
			};
			connect_block(&nodes[4], &block, i);
		}
		let events = nodes[4].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let close_chan_update_2 = match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				msg.clone()
			},
			_ => panic!("Unexpected event"),
		};
		check_added_monitors!(nodes[4], 1);
		test_txn_broadcast(&nodes[4], &chan_4, None, HTLCType::SUCCESS);

		block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: block.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![node_txn[0].clone()],
		};
		connect_block(&nodes[4], &block, TEST_FINAL_CLTV - 5);

		check_preimage_claim(&nodes[4], &node_txn);
		(close_chan_update_1, close_chan_update_2)
	};
	nodes[3].net_graph_msg_handler.handle_channel_update(&close_chan_update_2).unwrap();
	nodes[4].net_graph_msg_handler.handle_channel_update(&close_chan_update_1).unwrap();
	assert_eq!(nodes[3].node.list_channels().len(), 0);
	assert_eq!(nodes[4].node.list_channels().len(), 0);
}

#[test]
fn test_justice_tx() {
	// Test justice txn built on revoked HTLC-Success tx, against both sides
	let mut alice_config = UserConfig::default();
	alice_config.channel_options.announced_channel = true;
	alice_config.peer_channel_config_limits.force_announced_channel_preference = false;
	alice_config.own_channel_config.our_to_self_delay = 6 * 24 * 5;
	let mut bob_config = UserConfig::default();
	bob_config.channel_options.announced_channel = true;
	bob_config.peer_channel_config_limits.force_announced_channel_preference = false;
	bob_config.own_channel_config.our_to_self_delay = 6 * 24 * 3;
	let user_cfgs = [Some(alice_config), Some(bob_config)];
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	// Create some new channels:
	let chan_5 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// A pending HTLC which will be revoked:
	let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	// Get the will-be-revoked local txn from nodes[0]
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_5.2);
	assert_eq!(revoked_local_txn.len(), 2); // First commitment tx, then HTLC tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_5.3.txid());
	assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to 0 are present
	assert_eq!(revoked_local_txn[1].input.len(), 1);
	assert_eq!(revoked_local_txn[1].input[0].previous_output.txid, revoked_local_txn[0].txid());
	assert_eq!(revoked_local_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC-Timeout
	// Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_3, 3_000_000);

	{
		let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		{
			let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 2); // ChannelMonitor: penalty tx, ChannelManager: local commitment tx
			assert_eq!(node_txn[0].input.len(), 2); // We should claim the revoked output and the HTLC output

			check_spends!(node_txn[0], revoked_local_txn[0]);
			node_txn.swap_remove(0);
			node_txn.truncate(1);
		}
		check_added_monitors!(nodes[1], 1);
		test_txn_broadcast(&nodes[1], &chan_5, None, HTLCType::NONE);

		connect_block(&nodes[0], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		// Verify broadcast of revoked HTLC-timeout
		let node_txn = test_txn_broadcast(&nodes[0], &chan_5, Some(revoked_local_txn[0].clone()), HTLCType::TIMEOUT);
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		check_added_monitors!(nodes[0], 1);
		// Broadcast revoked HTLC-timeout on node 1
		connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[1].clone()] }, 1);
		test_revoked_htlc_claim_txn_broadcast(&nodes[1], node_txn[1].clone(), revoked_local_txn[0].clone());
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);

	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);

	// We test justice_tx build by A on B's revoked HTLC-Success tx
	// Create some new channels:
	let chan_6 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		node_txn.clear();
	}

	// A pending HTLC which will be revoked:
	let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	// Get the will-be-revoked local txn from B
	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan_6.2);
	assert_eq!(revoked_local_txn.len(), 1); // Only commitment tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_6.3.txid());
	assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to A are present
	// Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_4, 3_000_000);
	{
		let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[0], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		{
			let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 2); //ChannelMonitor: penalty tx, ChannelManager: local commitment tx
			assert_eq!(node_txn[0].input.len(), 1); // We claim the received HTLC output

			check_spends!(node_txn[0], revoked_local_txn[0]);
			node_txn.swap_remove(0);
		}
		check_added_monitors!(nodes[0], 1);
		test_txn_broadcast(&nodes[0], &chan_6, None, HTLCType::NONE);

		connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
		let node_txn = test_txn_broadcast(&nodes[1], &chan_6, Some(revoked_local_txn[0].clone()), HTLCType::SUCCESS);
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		check_added_monitors!(nodes[1], 1);
		connect_block(&nodes[0], &Block { header, txdata: vec![node_txn[1].clone()] }, 1);
		test_revoked_htlc_claim_txn_broadcast(&nodes[0], node_txn[1].clone(), revoked_local_txn[0].clone());
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn revoked_output_claim() {
	// Simple test to ensure a node will claim a revoked output when a stale remote commitment
	// transaction is broadcast by its counterparty
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn.len(), 1);
	// Only output is the full channel value back to nodes[0]:
	assert_eq!(revoked_local_txn[0].output.len(), 1);
	// Send a payment through, updating everyone's latest commitment txn
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 5000000, 5_000_000);

	// Inform nodes[1] that nodes[0] broadcast a stale tx
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	check_added_monitors!(nodes[1], 1);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 2); // ChannelMonitor: justice tx against revoked to_local output, ChannelManager: local commitment tx

	check_spends!(node_txn[0], revoked_local_txn[0]);
	check_spends!(node_txn[1], chan_1.3);

	// Inform nodes[0] that a watchtower cheated on its behalf, so it will force-close the chan
	connect_block(&nodes[0], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	get_announce_close_broadcast_events(&nodes, 0, 1);
	check_added_monitors!(nodes[0], 1)
}

#[test]
fn claim_htlc_outputs_shared_tx() {
	// Node revoked old state, htlcs haven't time out yet, claim them in shared justice tx
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some new channel:
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx
	let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let (_payment_preimage_2, payment_hash_2) = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000);

	// Get the will-be-revoked local txn from node[0]
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn.len(), 2); // commitment tx + 1 HTLC-Timeout tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());
	assert_eq!(revoked_local_txn[1].input.len(), 1);
	assert_eq!(revoked_local_txn[1].input[0].previous_output.txid, revoked_local_txn[0].txid());
	assert_eq!(revoked_local_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC-Timeout
	check_spends!(revoked_local_txn[1], revoked_local_txn[0]);

	//Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1, 3_000_000);

	{
		mine_transaction(&nodes[0], &revoked_local_txn[0]);
		check_added_monitors!(nodes[0], 1);
		mine_transaction(&nodes[1], &revoked_local_txn[0]);
		check_added_monitors!(nodes[1], 1);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, CHAN_CONFIRM_DEPTH + 1, false, Default::default());
		expect_payment_failed!(nodes[1], payment_hash_2, true);

		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 3); // ChannelMonitor: penalty tx, ChannelManager: local commitment + HTLC-timeout

		assert_eq!(node_txn[0].input.len(), 3); // Claim the revoked output + both revoked HTLC outputs
		check_spends!(node_txn[0], revoked_local_txn[0]);

		let mut witness_lens = BTreeSet::new();
		witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[0].input[1].witness.last().unwrap().len());
		witness_lens.insert(node_txn[0].input[2].witness.last().unwrap().len());
		assert_eq!(witness_lens.len(), 3);
		assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
		assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), OFFERED_HTLC_SCRIPT_WEIGHT); // revoked offered HTLC
		assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // revoked received HTLC

		// Next nodes[1] broadcasts its current local tx state:
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[1].input[0].previous_output.txid, chan_1.3.txid()); //Spending funding tx unique txouput, tx broadcasted by ChannelManager

		assert_eq!(node_txn[2].input.len(), 1);
		let witness_script = node_txn[2].clone().input[0].witness.pop().unwrap();
		assert_eq!(witness_script.len(), OFFERED_HTLC_SCRIPT_WEIGHT); //Spending an offered htlc output
		assert_eq!(node_txn[2].input[0].previous_output.txid, node_txn[1].txid());
		assert_ne!(node_txn[2].input[0].previous_output.txid, node_txn[0].input[0].previous_output.txid);
		assert_ne!(node_txn[2].input[0].previous_output.txid, node_txn[0].input[1].previous_output.txid);
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn claim_htlc_outputs_single_tx() {
	// Node revoked old state, htlcs have timed out, claim each of them in separated justice tx
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx, but this
	// time as two different claim transactions as we're gonna to timeout htlc with given a high current height
	let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let (_payment_preimage_2, payment_hash_2) = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000);

	// Get the will-be-revoked local txn from node[0]
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);

	//Revoke the old state
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1, 3_000_000);

	{
		let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_block(&nodes[0], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 200);
		check_added_monitors!(nodes[0], 1);
		connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 200);
		check_added_monitors!(nodes[1], 1);
		expect_pending_htlcs_forwardable_ignore!(nodes[0]);

		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 200, true, header.block_hash());
		expect_payment_failed!(nodes[1], payment_hash_2, true);

		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 9);
		// ChannelMonitor: justice tx revoked offered htlc, justice tx revoked received htlc, justice tx revoked to_local (3)
		// ChannelManager: local commmitment + local HTLC-timeout (2)
		// ChannelMonitor: bumped justice tx, after one increase, bumps on HTLC aren't generated not being substantial anymore, bump on revoked to_local isn't generated due to more room for expiration (2)
		// ChannelMonitor: local commitment + local HTLC-timeout (2)

		// Check the pair local commitment and HTLC-timeout broadcast due to HTLC expiration
		assert_eq!(node_txn[2].input.len(), 1);
		check_spends!(node_txn[2], chan_1.3);
		assert_eq!(node_txn[3].input.len(), 1);
		let witness_script = node_txn[3].input[0].witness.last().unwrap();
		assert_eq!(witness_script.len(), OFFERED_HTLC_SCRIPT_WEIGHT); //Spending an offered htlc output
		check_spends!(node_txn[3], node_txn[2]);

		// Justice transactions are indices 1-2-4
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[4].input.len(), 1);

		check_spends!(node_txn[0], revoked_local_txn[0]);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		check_spends!(node_txn[4], revoked_local_txn[0]);

		let mut witness_lens = BTreeSet::new();
		witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[1].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[4].input[0].witness.last().unwrap().len());
		assert_eq!(witness_lens.len(), 3);
		assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
		assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), OFFERED_HTLC_SCRIPT_WEIGHT); // revoked offered HTLC
		assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // revoked received HTLC
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[test]
fn test_htlc_on_chain_success() {
	// Test that in case of a unilateral close onchain, we detect the state of output and pass
	// the preimage backward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// We test with two HTLCs simultaneously as that was not handled correctly in the past.
	// A --------------------> B ----------------------> C (preimage)
	// First, C should claim the HTLC outputs via HTLC-Success when its own latest local
	// commitment transaction was broadcast.
	// Then, B should learn the preimage from said transactions, attempting to claim backwards
	// towards B.
	// B should be able to claim via preimage if A then broadcasts its local tx.
	// Finally, when A sees B's latest local commitment transaction it should be able to claim
	// the HTLC outputs via the preimage it learned (which, once confirmed should generate a
	// PaymentSent event).

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000, 8_000_000);

	let (our_payment_preimage, _payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let (our_payment_preimage_2, _payment_hash_2) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};

	// Broadcast legit commitment tx from C on B's chain
	// Broadcast HTLC Success transaction by C on received output from C's commitment tx on B's chain
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(commitment_tx.len(), 1);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.claim_funds(our_payment_preimage, &None, 3_000_000);
	nodes[2].node.claim_funds(our_payment_preimage_2, &None, 3_000_000);
	check_added_monitors!(nodes[2], 2);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);

	connect_block(&nodes[2], &Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	check_closed_broadcast!(nodes[2], false);
	check_added_monitors!(nodes[2], 1);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 3 (commitment tx, 2*htlc-success tx), ChannelMonitor : 2 (2 * HTLC-Success tx)
	assert_eq!(node_txn.len(), 5);
	assert_eq!(node_txn[0], node_txn[3]);
	assert_eq!(node_txn[1], node_txn[4]);
	assert_eq!(node_txn[2], commitment_tx[0]);
	check_spends!(node_txn[0], commitment_tx[0]);
	check_spends!(node_txn[1], commitment_tx[0]);
	assert_eq!(node_txn[0].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(node_txn[1].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	assert!(node_txn[1].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	assert_eq!(node_txn[0].lock_time, 0);
	assert_eq!(node_txn[1].lock_time, 0);

	// Verify that B's ChannelManager is able to extract preimage from HTLC Success tx and pass it backward
	connect_block(&nodes[1], &Block { header, txdata: node_txn}, 1);
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0.txid, chan_2.3.txid());
		added_monitors.clear();
	}
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 2);
		assert_eq!(added_monitors[0].0.txid, chan_1.3.txid());
		assert_eq!(added_monitors[1].0.txid, chan_1.3.txid());
		added_monitors.clear();
	}
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fail_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};
	macro_rules! check_tx_local_broadcast {
		($node: expr, $htlc_offered: expr, $commitment_tx: expr, $chan_tx: expr) => { {
			let mut node_txn = $node.tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 5);
			// Node[1]: ChannelManager: 3 (commitment tx, 2*HTLC-Timeout tx), ChannelMonitor: 2 (timeout tx)
			// Node[0]: ChannelManager: 3 (commtiemtn tx, 2*HTLC-Timeout tx), ChannelMonitor: 2 HTLC-timeout
			check_spends!(node_txn[0], $commitment_tx);
			check_spends!(node_txn[1], $commitment_tx);
			assert_ne!(node_txn[0].lock_time, 0);
			assert_ne!(node_txn[1].lock_time, 0);
			if $htlc_offered {
				assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
				assert_eq!(node_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
				assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
				assert!(node_txn[1].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
			} else {
				assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
				assert_eq!(node_txn[1].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
				assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
				assert!(node_txn[1].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
			}
			check_spends!(node_txn[2], $chan_tx);
			check_spends!(node_txn[3], node_txn[2]);
			check_spends!(node_txn[4], node_txn[2]);
			assert_eq!(node_txn[2].input[0].witness.last().unwrap().len(), 71);
			assert_eq!(node_txn[3].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
			assert_eq!(node_txn[4].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
			assert!(node_txn[3].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
			assert!(node_txn[4].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
			assert_ne!(node_txn[3].lock_time, 0);
			assert_ne!(node_txn[4].lock_time, 0);
			node_txn.clear();
		} }
	}
	// nodes[1] now broadcasts its own local state as a fallback, suggesting an alternate
	// commitment transaction with a corresponding HTLC-Timeout transactions, as well as a
	// timeout-claim of the output that nodes[2] just claimed via success.
	check_tx_local_broadcast!(nodes[1], false, commitment_tx[0], chan_2.3);

	// Broadcast legit commitment tx from A on B's chain
	// Broadcast preimage tx by B on offered output from A commitment tx  on A's chain
	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	check_spends!(commitment_tx[0], chan_1.3);
	connect_block(&nodes[1], &Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 3 (commitment tx + HTLC-Sucess * 2), ChannelMonitor : 1 (HTLC-Success)
	assert_eq!(node_txn.len(), 4);
	check_spends!(node_txn[0], commitment_tx[0]);
	assert_eq!(node_txn[0].input.len(), 2);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(node_txn[0].input[1].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(node_txn[0].lock_time, 0);
	assert!(node_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
	check_spends!(node_txn[1], chan_1.3);
	assert_eq!(node_txn[1].input[0].witness.clone().last().unwrap().len(), 71);
	check_spends!(node_txn[2], node_txn[1]);
	check_spends!(node_txn[3], node_txn[1]);
	// We don't bother to check that B can claim the HTLC output on its commitment tx here as
	// we already checked the same situation with A.

	// Verify that A's ChannelManager is able to extract preimage from preimage tx and generate PaymentSent
	connect_block(&nodes[0], &Block { header, txdata: vec![commitment_tx[0].clone(), node_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	let mut first_claimed = false;
	for event in events {
		match event {
			Event::PaymentSent { payment_preimage } => {
				if payment_preimage == our_payment_preimage {
					assert!(!first_claimed);
					first_claimed = true;
				} else {
					assert_eq!(payment_preimage, our_payment_preimage_2);
				}
			},
			_ => panic!("Unexpected event"),
		}
	}
	check_tx_local_broadcast!(nodes[0], true, commitment_tx[0], chan_1.3);
}

#[test]
fn test_htlc_on_chain_timeout() {
	// Test that in case of a unilateral close onchain, we detect the state of output and
	// timeout the HTLC backward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// A ------------------> B ----------------------> C (timeout)
	//    B's commitment tx 		C's commitment tx
	//    	      \                                  \
	//    	   B's HTLC timeout tx		     B's timeout tx

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some intial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Rebalance the network a bit by relaying one payment thorugh all the channels...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000, 8_000_000);

	let (_payment_preimage, payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);

	// Broadcast legit commitment tx from C on B's chain
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.fail_htlc_backwards(&payment_hash, &None);
	check_added_monitors!(nodes[2], 0);
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);

	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(!update_fail_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[1].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};
	let last_block = nodes[2].best_block_info();
	mine_transaction(&nodes[2], &commitment_tx[0]);
	check_closed_broadcast!(nodes[2], false);
	check_added_monitors!(nodes[2], 1);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 1 (commitment tx)
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan_2.3);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), 71);

	// Broadcast timeout transaction by B on received output from C's commitment tx on B's chain
	// Verify that B's ChannelManager is able to detect that HTLC is timeout by its own tx and react backward in consequence
	connect_blocks(&nodes[1], 200 - last_block.1 - 1, last_block.1, false, Default::default());
	mine_transaction(&nodes[1], &commitment_tx[0]);
	let timeout_tx;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 5); // ChannelManager : 2 (commitment tx, HTLC-Timeout tx), ChannelMonitor : 2 (local commitment tx + HTLC-timeout), 1 timeout tx
		assert_eq!(node_txn[0], node_txn[3]);
		assert_eq!(node_txn[1], node_txn[4]);

		check_spends!(node_txn[2], commitment_tx[0]);
		assert_eq!(node_txn[2].clone().input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);

		check_spends!(node_txn[0], chan_2.3);
		check_spends!(node_txn[1], node_txn[0]);
		assert_eq!(node_txn[0].clone().input[0].witness.last().unwrap().len(), 71);
		assert_eq!(node_txn[1].clone().input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);

		timeout_tx = node_txn[2].clone();
		node_txn.clear();
	}

	mine_transaction(&nodes[1], &timeout_tx);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], false);
	{
		// B will rebroadcast a fee-bumped timeout transaction here.
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(node_txn.len(), 1);
		check_spends!(node_txn[0], commitment_tx[0]);
	}

	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 201, false, Default::default());
	{
		// B will rebroadcast its own holder commitment transaction here...just because
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(node_txn.len(), 1);
		check_spends!(node_txn[0], chan_2.3);
	}

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(!update_fail_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};

	// Broadcast legit commitment tx from B on A's chain
	let commitment_tx = get_local_commitment_txn!(nodes[1], chan_1.2);
	check_spends!(commitment_tx[0], chan_1.3);

	mine_transaction(&nodes[0], &commitment_tx[0]);

	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);
	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 2 (commitment tx, HTLC-Timeout tx), ChannelMonitor : 1 timeout tx
	assert_eq!(node_txn.len(), 3);
	check_spends!(node_txn[0], commitment_tx[0]);
	assert_eq!(node_txn[0].clone().input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	check_spends!(node_txn[1], chan_1.3);
	check_spends!(node_txn[2], node_txn[1]);
	assert_eq!(node_txn[1].clone().input[0].witness.last().unwrap().len(), 71);
	assert_eq!(node_txn[2].clone().input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
}

#[test]
fn test_simple_commitment_revoked_fail_backward() {
	// Test that in case of a revoked commitment tx, we detect the resolution of output by justice tx
	// and fail backward accordingly.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	let (payment_preimage, _payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage, 3_000_000);

	let (_, payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, ref commitment_signed, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
			commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

			let events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
				_ => panic!("Unexpected event"),
			}
			expect_payment_failed!(nodes[0], payment_hash, false);
		},
		_ => panic!("Unexpected event"),
	}
}

fn do_test_commitment_revoked_fail_backward_exhaustive(deliver_bs_raa: bool, use_dust: bool, no_to_remote: bool) {
	// Test that if our counterparty broadcasts a revoked commitment transaction we fail all
	// pending HTLCs on that channel backwards even if the HTLCs aren't present in our latest
	// commitment transaction anymore.
	// To do this, we have the peer which will broadcast a revoked commitment transaction send
	// a number of update_fail/commitment_signed updates without ever sending the RAA in
	// response to our commitment_signed. This is somewhat misbehavior-y, though not
	// technically disallowed and we should probably handle it reasonably.
	// Note that this is pretty exhaustive as an outbound HTLC which we haven't yet
	// failed/fulfilled backwards must be in at least one of the latest two remote commitment
	// transactions:
	// * Once we move it out of our holding cell/add it, we will immediately include it in a
	//   commitment_signed (implying it will be in the latest remote commitment transaction).
	// * Once they remove it, we will send a (the first) commitment_signed without the HTLC,
	//   and once they revoke the previous commitment transaction (allowing us to send a new
	//   commitment_signed) we will be free to fail/fulfill the HTLC backwards.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	let (payment_preimage, _payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], if no_to_remote { 10_000 } else { 3_000_000 });
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(revoked_local_txn[0].output.len(), if no_to_remote { 1 } else { 2 });
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage, if no_to_remote { 10_000 } else { 3_000_000});

	let value = if use_dust {
		// The dust limit applied to HTLC outputs considers the fee of the HTLC transaction as
		// well, so HTLCs at exactly the dust limit will not be included in commitment txn.
		nodes[2].node.channel_state.lock().unwrap().by_id.get(&chan_2.2).unwrap().holder_dust_limit_satoshis * 1000
	} else { 3000000 };

	let (_, first_payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);
	let (_, second_payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);
	let (_, third_payment_hash) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);

	assert!(nodes[2].node.fail_htlc_backwards(&first_payment_hash, &None));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	let bs_raa = commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false, true, false, true);
	// Drop the last RAA from 3 -> 2

	assert!(nodes[2].node.fail_htlc_backwards(&second_payment_hash, &None));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	// Note that nodes[1] is in AwaitingRAA, so won't send a CS
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[2], 1);

	assert!(nodes[2].node.fail_htlc_backwards(&third_payment_hash, &None));
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	// At this point first_payment_hash has dropped out of the latest two commitment
	// transactions that nodes[1] is tracking...
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	// Note that nodes[1] is (still) in AwaitingRAA, so won't send a CS
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[2].node.get_our_node_id());
	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_raa);
	check_added_monitors!(nodes[2], 1);

	// Add a fourth HTLC, this one will get sequestered away in nodes[1]'s holding cell waiting
	// on nodes[2]'s RAA.
	let (_, fourth_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[1].node.send_payment(&route, fourth_payment_hash, &None).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors!(nodes[1], 0);

	if deliver_bs_raa {
		nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &bs_raa);
		// One monitor for the new revocation preimage, no second on as we won't generate a new
		// commitment transaction for nodes[0] until process_pending_htlc_forwards().
		check_added_monitors!(nodes[1], 1);
		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
		// Deliberately don't process the pending fail-back so they all fail back at once after
		// block connection just like the !deliver_bs_raa case
	}

	let mut failed_htlcs = HashSet::new();
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	check_added_monitors!(nodes[1], 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), if deliver_bs_raa { 1 } else { 2 });
	match events[0] {
		Event::PaymentFailed { ref payment_hash, .. } => {
			assert_eq!(*payment_hash, fourth_payment_hash);
		},
		_ => panic!("Unexpected event"),
	}
	if !deliver_bs_raa {
		match events[1] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
	}
	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), if deliver_bs_raa { 3 } else { 2 });
	match events[if deliver_bs_raa { 1 } else { 0 }] {
		MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { .. } } => {},
		_ => panic!("Unexpected event"),
	}
	if deliver_bs_raa {
		match events[0] {
			MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, .. } } => {
				assert_eq!(nodes[2].node.get_our_node_id(), *node_id);
				assert_eq!(update_add_htlcs.len(), 1);
				assert!(update_fulfill_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
			},
			_ => panic!("Unexpected event"),
		}
	}
	match events[if deliver_bs_raa { 2 } else { 1 }] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, ref update_fulfill_htlcs, ref update_fail_malformed_htlcs, ref commitment_signed, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 3);
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);

			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[1]);
			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[2]);

			commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

			let events = nodes[0].node.get_and_clear_pending_msg_events();
			// If we delivered B's RAA we got an unknown preimage error, not something
			// that we should update our routing table for.
			assert_eq!(events.len(), if deliver_bs_raa { 2 } else { 3 });
			for event in events {
				match event {
					MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
					_ => panic!("Unexpected event"),
				}
			}
			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 3);
			match events[0] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
			match events[1] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
			match events[2] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
		},
		_ => panic!("Unexpected event"),
	}

	assert!(failed_htlcs.contains(&first_payment_hash.0));
	assert!(failed_htlcs.contains(&second_payment_hash.0));
	assert!(failed_htlcs.contains(&third_payment_hash.0));
}

#[test]
fn test_commitment_revoked_fail_backward_exhaustive_a() {
	do_test_commitment_revoked_fail_backward_exhaustive(false, true, false);
	do_test_commitment_revoked_fail_backward_exhaustive(true, true, false);
	do_test_commitment_revoked_fail_backward_exhaustive(false, false, false);
	do_test_commitment_revoked_fail_backward_exhaustive(true, false, false);
}

#[test]
fn test_commitment_revoked_fail_backward_exhaustive_b() {
	do_test_commitment_revoked_fail_backward_exhaustive(false, true, true);
	do_test_commitment_revoked_fail_backward_exhaustive(true, true, true);
	do_test_commitment_revoked_fail_backward_exhaustive(false, false, true);
	do_test_commitment_revoked_fail_backward_exhaustive(true, false, true);
}

#[test]
fn fail_backward_pending_htlc_upon_channel_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	// Alice -> Bob: Route a payment but without Bob sending revoke_and_ack.
	{
		let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &Vec::new(), 50_000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash, &None).unwrap();
		check_added_monitors!(nodes[0], 1);

		let payment_event = {
			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());
		assert_eq!(payment_event.msgs.len(), 1);
	}

	// Alice -> Bob: Route another payment but now Alice waits for Bob's earlier revoke_and_ack.
	let (_, failed_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &Vec::new(), 50_000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, failed_payment_hash, &None).unwrap();
		check_added_monitors!(nodes[0], 0);

		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	// Alice <- Bob: Send a malformed update_add_htlc so Alice fails the channel.
	{
		let (_, payment_hash) = get_payment_preimage_hash!(nodes[1]);

		let secp_ctx = Secp256k1::new();
		let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();
		let current_height = nodes[1].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
		let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
		let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &Vec::new(), 50_000, TEST_FINAL_CLTV, &logger).unwrap();
		let (onion_payloads, _amount_msat, cltv_expiry) = onion_utils::build_onion_payloads(&route.paths[0], 50_000, &None, current_height).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv).unwrap();
		let onion_routing_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash);

		// Send a 0-msat update_add_htlc to fail the channel.
		let update_add_htlc = msgs::UpdateAddHTLC {
			channel_id: chan.2,
			htlc_id: 0,
			amount_msat: 0,
			payment_hash,
			cltv_expiry,
			onion_routing_packet,
		};
		nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &update_add_htlc);
	}

	// Check that Alice fails backward the pending HTLC from the second payment.
	expect_payment_failed!(nodes[0], failed_payment_hash, true);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_htlc_ignore_latest_remote_commitment() {
	// Test that HTLC transactions spending the latest remote commitment transaction are simply
	// ignored if we cannot claim them. This originally tickled an invalid unwrap().
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	route_payment(&nodes[0], &[&nodes[1]], 10000000);
	nodes[0].node.force_close_channel(&nodes[0].node.list_channels()[0].channel_id).unwrap();
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 2);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[0].clone(), node_txn[1].clone()]}, 1);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);

	// Duplicate the connect_block call since this may happen due to other listeners
	// registering new transactions
	connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[0].clone(), node_txn[1].clone()]}, 1);
}

#[test]
fn test_force_close_fail_back() {
	// Check which HTLCs are failed-backwards on channel force-closure
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	let mut payment_event = {
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 1000000, 42, &logger).unwrap();
		nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	payment_event = SendEvent::from_event(events_2.remove(0));
	assert_eq!(payment_event.msgs.len(), 1);

	check_added_monitors!(nodes[1], 1);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(nodes[2], 1);
	let (_, _) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());

	// nodes[2] now has the latest commitment transaction, but hasn't revoked its previous
	// state or updated nodes[1]' state. Now force-close and broadcast that commitment/HTLC
	// transaction and ensure nodes[1] doesn't fail-backwards (this was originally a bug!).

	nodes[2].node.force_close_channel(&payment_event.commitment_msg.channel_id).unwrap();
	check_closed_broadcast!(nodes[2], false);
	check_added_monitors!(nodes[2], 1);
	let tx = {
		let mut node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// Note that we don't bother broadcasting the HTLC-Success transaction here as we don't
		// have a use for it unless nodes[2] learns the preimage somehow, the funds will go
		// back to nodes[1] upon timeout otherwise.
		assert_eq!(node_txn.len(), 1);
		node_txn.remove(0)
	};

	let block = Block {
		header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
		txdata: vec![tx.clone()],
	};
	connect_block(&nodes[1], &block, 1);

	// Note no UpdateHTLCs event here from nodes[1] to nodes[0]!
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);

	// Now check that if we add the preimage to ChannelMonitor it broadcasts our HTLC-Success..
	{
		let mut monitors = nodes[2].chain_monitor.chain_monitor.monitors.read().unwrap();
		monitors.get(&OutPoint{ txid: Txid::from_slice(&payment_event.commitment_msg.channel_id[..]).unwrap(), index: 0 }).unwrap()
			.provide_payment_preimage(&our_payment_hash, &our_payment_preimage, &node_cfgs[2].tx_broadcaster, &node_cfgs[2].fee_estimator, &&logger);
	}
	connect_block(&nodes[2], &block, 1);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);
	assert_eq!(node_txn[0].input.len(), 1);
	assert_eq!(node_txn[0].input[0].previous_output.txid, tx.txid());
	assert_eq!(node_txn[0].lock_time, 0); // Must be an HTLC-Success
	assert_eq!(node_txn[0].input[0].witness.len(), 5); // Must be an HTLC-Success

	check_spends!(node_txn[0], tx);
}

#[test]
fn test_simple_peer_disconnect() {
	// Test that we can reconnect when there are no lost messages
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	let payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
	let payment_hash_2 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;
	fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_hash_2);
	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_preimage_1, 1_000_000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	let payment_preimage_3 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
	let payment_preimage_4 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).0;
	let payment_hash_5 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;
	let payment_hash_6 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 1000000).1;

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	claim_payment_along_route(&nodes[0], &vec!(&nodes[1], &nodes[2]), true, payment_preimage_3, 1_000_000);
	fail_payment_along_route(&nodes[0], &[&nodes[1], &nodes[2]], true, payment_hash_5);

	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (1, 0), (1, 0), (false, false));
	{
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentSent { payment_preimage } => {
				assert_eq!(payment_preimage, payment_preimage_3);
			},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PaymentFailed { payment_hash, rejected_by_dest, .. } => {
				assert_eq!(payment_hash, payment_hash_5);
				assert!(rejected_by_dest);
			},
			_ => panic!("Unexpected event"),
		}
	}

	claim_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_preimage_4, 1_000_000);
	fail_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), payment_hash_6);
}

fn do_test_drop_messages_peer_disconnect(messages_delivered: u8) {
	// Test that we can reconnect when in-flight HTLC updates get dropped
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	if messages_delivered == 0 {
		create_chan_between_nodes_with_value_a(&nodes[0], &nodes[1], 100000, 10001, InitFeatures::known(), InitFeatures::known());
		// nodes[1] doesn't receive the funding_locked message (it'll be re-sent on reconnect)
	} else {
		create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	}

	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);

	let logger = test_utils::TestLogger::new();
	let payment_event = {
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(),
			&nodes[1].node.get_our_node_id(), None, Some(&nodes[0].node.list_usable_channels().iter().collect::<Vec<_>>()),
			&Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, payment_hash_1, &None).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(nodes[1].node.get_our_node_id(), payment_event.node_id);

	if messages_delivered < 2 {
		// Drop the payment_event messages, and let them get re-generated in reconnect_nodes!
	} else {
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		if messages_delivered >= 3 {
			nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
			check_added_monitors!(nodes[1], 1);
			let (bs_revoke_and_ack, bs_commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

			if messages_delivered >= 4 {
				nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
				assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(nodes[0], 1);

				if messages_delivered >= 5 {
					nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_commitment_signed);
					let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					check_added_monitors!(nodes[0], 1);

					if messages_delivered >= 6 {
						nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
						assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
						check_added_monitors!(nodes[1], 1);
					}
				}
			}
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	if messages_delivered < 3 {
		// Even if the funding_locked messages get exchanged, as long as nothing further was
		// received on either side, both sides will need to resend them.
		reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 1), (0, 0), (0, 0), (0, 0), (false, false));
	} else if messages_delivered == 3 {
		// nodes[0] still wants its RAA + commitment_signed
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (-1, 0), (0, 0), (0, 0), (0, 0), (true, false));
	} else if messages_delivered == 4 {
		// nodes[0] still wants its commitment_signed
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (-1, 0), (0, 0), (0, 0), (0, 0), (false, false));
	} else if messages_delivered == 5 {
		// nodes[1] still wants its final RAA
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, true));
	} else if messages_delivered == 6 {
		// Everything was delivered...
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	let events_1 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		Event::PendingHTLCsForwardable { .. } => { },
		_ => panic!("Unexpected event"),
	};

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	nodes[1].node.process_pending_htlc_forwards();

	let events_2 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::PaymentReceived { ref payment_hash, ref payment_secret, amt } => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(*payment_secret, None);
			assert_eq!(amt, 1000000);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.claim_funds(payment_preimage_1, &None, 1_000_000);
	check_added_monitors!(nodes[1], 1);

	let events_3 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	let (update_fulfill_htlc, commitment_signed) = match events_3[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fail_htlcs.is_empty());
			assert_eq!(updates.update_fulfill_htlcs.len(), 1);
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			(updates.update_fulfill_htlcs[0].clone(), updates.commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	if messages_delivered >= 1 {
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlc);

		let events_4 = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events_4.len(), 1);
		match events_4[0] {
			Event::PaymentSent { ref payment_preimage } => {
				assert_eq!(payment_preimage_1, *payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}

		if messages_delivered >= 2 {
			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);
			check_added_monitors!(nodes[0], 1);
			let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

			if messages_delivered >= 3 {
				nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
				assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors!(nodes[1], 1);

				if messages_delivered >= 4 {
					nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed);
					let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					check_added_monitors!(nodes[1], 1);

					if messages_delivered >= 5 {
						nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
						assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
						check_added_monitors!(nodes[0], 1);
					}
				}
			}
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	if messages_delivered < 2 {
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (1, 0), (0, 0), (0, 0), (false, false));
		//TODO: Deduplicate PaymentSent events, then enable this if:
		//if messages_delivered < 1 {
			let events_4 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_4.len(), 1);
			match events_4[0] {
				Event::PaymentSent { ref payment_preimage } => {
					assert_eq!(payment_preimage_1, *payment_preimage);
				},
				_ => panic!("Unexpected event"),
			}
		//}
	} else if messages_delivered == 2 {
		// nodes[0] still wants its RAA + commitment_signed
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, -1), (0, 0), (0, 0), (0, 0), (false, true));
	} else if messages_delivered == 3 {
		// nodes[0] still wants its commitment_signed
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, -1), (0, 0), (0, 0), (0, 0), (false, false));
	} else if messages_delivered == 4 {
		// nodes[1] still wants its final RAA
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (true, false));
	} else if messages_delivered == 5 {
		// Everything was delivered...
		reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	// Channel should still work fine...
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(),
		&nodes[1].node.get_our_node_id(), None, Some(&nodes[0].node.list_usable_channels().iter().collect::<Vec<_>>()),
		&Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	let payment_preimage_2 = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000).0;
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2, 1_000_000);
}

#[test]
fn test_drop_messages_peer_disconnect_a() {
	do_test_drop_messages_peer_disconnect(0);
	do_test_drop_messages_peer_disconnect(1);
	do_test_drop_messages_peer_disconnect(2);
	do_test_drop_messages_peer_disconnect(3);
}

#[test]
fn test_drop_messages_peer_disconnect_b() {
	do_test_drop_messages_peer_disconnect(4);
	do_test_drop_messages_peer_disconnect(5);
	do_test_drop_messages_peer_disconnect(6);
}

#[test]
fn test_funding_peer_disconnect() {
	// Test that we can lock in our funding tx while disconnected
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001, InitFeatures::known(), InitFeatures::known());

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	confirm_transaction(&nodes[0], &tx);
	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		MessageSendEvent::SendFundingLocked { ref node_id, msg: _ } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}

	reconnect_nodes(&nodes[0], &nodes[1], (false, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	confirm_transaction(&nodes[1], &tx);
	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 2);
	let funding_locked = match events_2[0] {
		MessageSendEvent::SendFundingLocked { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};
	let bs_announcement_sigs = match events_2[1] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};

	reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	nodes[0].node.handle_funding_locked(&nodes[1].node.get_our_node_id(), &funding_locked);
	nodes[0].node.handle_announcement_signatures(&nodes[1].node.get_our_node_id(), &bs_announcement_sigs);
	let events_3 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 2);
	let as_announcement_sigs = match events_3[0] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};
	let (as_announcement, as_update) = match events_3[1] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			(msg.clone(), update_msg.clone())
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_announcement_signatures(&nodes[0].node.get_our_node_id(), &as_announcement_sigs);
	let events_4 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_4.len(), 1);
	let (_, bs_update) = match events_4[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			(msg.clone(), update_msg.clone())
		},
		_ => panic!("Unexpected event"),
	};

	nodes[0].net_graph_msg_handler.handle_channel_announcement(&as_announcement).unwrap();
	nodes[0].net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
	nodes[0].net_graph_msg_handler.handle_channel_update(&as_update).unwrap();

	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	let (payment_preimage, _) = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage, 1_000_000);
}

#[test]
fn test_drop_messages_peer_disconnect_dual_htlc() {
	// Test that we can handle reconnecting when both sides of a channel have pending
	// commitment_updates when we disconnect.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (payment_preimage_1, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Now try to send a second payment which will fail to send
	let (payment_preimage_2, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, payment_hash_2, &None).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}

	assert!(nodes[1].node.claim_funds(payment_preimage_1, &None, 1_000_000));
	check_added_monitors!(nodes[1], 1);

	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());

			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]);
			let events_3 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_3.len(), 1);
			match events_3[0] {
				Event::PaymentSent { ref payment_preimage } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
				},
				_ => panic!("Unexpected event"),
			}

			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed);
			let _ = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			// No commitment_signed so get_event_msg's assert(len == 1) passes
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	assert!(as_resp.0.is_none());
	assert!(bs_resp.0.is_none());

	assert!(bs_resp.1.is_none());
	assert!(bs_resp.2.is_none());

	assert!(as_resp.3 == RAACommitmentOrder::CommitmentFirst);

	assert_eq!(as_resp.2.as_ref().unwrap().update_add_htlcs.len(), 1);
	assert!(as_resp.2.as_ref().unwrap().update_fulfill_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fail_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fail_malformed_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fee.is_none());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().commitment_signed);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), as_resp.1.as_ref().unwrap());
	let bs_second_commitment_signed = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(bs_second_commitment_signed.update_add_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fulfill_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fail_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fail_malformed_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fee.is_none());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
	let as_commitment_signed = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert!(as_commitment_signed.update_add_htlcs.is_empty());
	assert!(as_commitment_signed.update_fulfill_htlcs.is_empty());
	assert!(as_commitment_signed.update_fail_htlcs.is_empty());
	assert!(as_commitment_signed.update_fail_malformed_htlcs.is_empty());
	assert!(as_commitment_signed.update_fee.is_none());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_signed.commitment_signed);
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed.commitment_signed);
	let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentReceived { ref payment_hash, ref payment_secret, amt: _ } => {
			assert_eq!(payment_hash_2, *payment_hash);
			assert_eq!(*payment_secret, None);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2, 1_000_000);
}

fn do_test_htlc_timeout(send_partial_mpp: bool) {
	// If the user fails to claim/fail an HTLC within the HTLC CLTV timeout we fail it for them
	// to avoid our counterparty failing the channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let our_payment_hash = if send_partial_mpp {
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &Vec::new(), 100000, TEST_FINAL_CLTV, &logger).unwrap();
		let (_, our_payment_hash) = get_payment_preimage_hash!(&nodes[0]);
		let payment_secret = PaymentSecret([0xdb; 32]);
		// Use the utility function send_payment_along_path to send the payment with MPP data which
		// indicates there are more HTLCs coming.
		let cur_height = CHAN_CONFIRM_DEPTH + 1; // route_payment calls send_payment, which adds 1 to the current height. So we do the same here to match.
		nodes[0].node.send_payment_along_path(&route.paths[0], &our_payment_hash, &Some(payment_secret), 200000, cur_height).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		// Now do the relevant commitment_signed/RAA dances along the path, noting that the final
		// hop should *not* yet generate any PaymentReceived event(s).
		pass_along_path(&nodes[0], &[&nodes[1]], 100000, our_payment_hash, Some(payment_secret), events.drain(..).next().unwrap(), false);
		our_payment_hash
	} else {
		route_payment(&nodes[0], &[&nodes[1]], 100000).1
	};

	let mut block = Block {
		header: BlockHeader { version: 0x20000000, prev_blockhash: nodes[0].best_block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
		txdata: vec![],
	};
	connect_block(&nodes[0], &block, CHAN_CONFIRM_DEPTH + 1);
	connect_block(&nodes[1], &block, CHAN_CONFIRM_DEPTH + 1);
	for i in CHAN_CONFIRM_DEPTH + 2 ..TEST_FINAL_CLTV + CHAN_CONFIRM_DEPTH + 2 - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS {
		block.header.prev_blockhash = block.block_hash();
		connect_block(&nodes[0], &block, i);
		connect_block(&nodes[1], &block, i);
	}

	expect_pending_htlcs_forwardable!(nodes[1]);

	check_added_monitors!(nodes[1], 1);
	let htlc_timeout_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_timeout_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_timeout_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_timeout_updates.update_fail_malformed_htlcs.is_empty());
	assert!(htlc_timeout_updates.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_timeout_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_timeout_updates.commitment_signed, false);
	// 100_000 msat as u64, followed by a height of TEST_FINAL_CLTV + 2 as u32
	let mut expected_failure_data = byte_utils::be64_to_array(100_000).to_vec();
	expected_failure_data.extend_from_slice(&byte_utils::be32_to_array(TEST_FINAL_CLTV + 2));
	expect_payment_failed!(nodes[0], our_payment_hash, true, 0x4000 | 15, &expected_failure_data[..]);
}

#[test]
fn test_htlc_timeout() {
	do_test_htlc_timeout(true);
	do_test_htlc_timeout(false);
}

fn do_test_holding_cell_htlc_add_timeouts(forwarded_htlc: bool) {
	// Tests that HTLCs in the holding cell are timed out after the requisite number of blocks.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Make sure all nodes are at the same starting height
	connect_blocks(&nodes[0], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1, nodes[0].best_block_info().1, false, Default::default());
	connect_blocks(&nodes[1], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1, nodes[1].best_block_info().1, false, Default::default());
	connect_blocks(&nodes[2], 2*CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1, nodes[2].best_block_info().1, false, Default::default());

	let logger = test_utils::TestLogger::new();

	// Route a first payment to get the 1 -> 2 channel in awaiting_raa...
	let (_, first_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
		let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 100000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[1].node.send_payment(&route, first_payment_hash, &None).unwrap();
	}
	assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 1);
	check_added_monitors!(nodes[1], 1);

	// Now attempt to route a second payment, which should be placed in the holding cell
	let (_, second_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	if forwarded_htlc {
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 100000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, second_payment_hash, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
		let payment_event = SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
		expect_pending_htlcs_forwardable!(nodes[1]);
		check_added_monitors!(nodes[1], 0);
	} else {
		let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
		let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 100000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[1].node.send_payment(&route, second_payment_hash, &None).unwrap();
		check_added_monitors!(nodes[1], 0);
	}

	connect_blocks(&nodes[1], TEST_FINAL_CLTV - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS, nodes[1].best_block_info().1, false, Default::default());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	connect_blocks(&nodes[1], 1, nodes[1].best_block_info().1, false, Default::default());

	if forwarded_htlc {
		expect_pending_htlcs_forwardable!(nodes[1]);
		check_added_monitors!(nodes[1], 1);
		let fail_commit = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(fail_commit.len(), 1);
		match fail_commit[0] {
			MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fail_htlcs, ref commitment_signed, .. }, .. } => {
				nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlcs[0]);
				commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, true, true);
			},
			_ => unreachable!(),
		}
		expect_payment_failed!(nodes[0], second_payment_hash, false);
		if let &MessageSendEvent::PaymentFailureNetworkUpdate { ref update } = &nodes[0].node.get_and_clear_pending_msg_events()[0] {
			match update {
				&HTLCFailChannelUpdate::ChannelUpdateMessage { .. } => {},
				_ => panic!("Unexpected event"),
			}
		} else {
			panic!("Unexpected event");
		}
	} else {
		expect_payment_failed!(nodes[1], second_payment_hash, true);
	}
}

#[test]
fn test_holding_cell_htlc_add_timeouts() {
	do_test_holding_cell_htlc_add_timeouts(false);
	do_test_holding_cell_htlc_add_timeouts(true);
}

#[test]
fn test_invalid_channel_announcement() {
	//Test BOLT 7 channel_announcement msg requirement for final node, gather data to build customed channel_announcement msgs
	let secp_ctx = Secp256k1::new();
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_announcement = create_chan_between_nodes(&nodes[0], &nodes[1], InitFeatures::known(), InitFeatures::known());

	let a_channel_lock = nodes[0].node.channel_state.lock().unwrap();
	let b_channel_lock = nodes[1].node.channel_state.lock().unwrap();
	let as_chan = a_channel_lock.by_id.get(&chan_announcement.3).unwrap();
	let bs_chan = b_channel_lock.by_id.get(&chan_announcement.3).unwrap();

	nodes[0].net_graph_msg_handler.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id : as_chan.get_short_channel_id().unwrap(), is_permanent: false } );

	let as_bitcoin_key = as_chan.get_signer().inner.holder_channel_pubkeys.funding_pubkey;
	let bs_bitcoin_key = bs_chan.get_signer().inner.holder_channel_pubkeys.funding_pubkey;

	let as_network_key = nodes[0].node.get_our_node_id();
	let bs_network_key = nodes[1].node.get_our_node_id();

	let were_node_one = as_bitcoin_key.serialize()[..] < bs_bitcoin_key.serialize()[..];

	let mut chan_announcement;

	macro_rules! dummy_unsigned_msg {
		() => {
			msgs::UnsignedChannelAnnouncement {
				features: ChannelFeatures::known(),
				chain_hash: genesis_block(Network::Testnet).header.block_hash(),
				short_channel_id: as_chan.get_short_channel_id().unwrap(),
				node_id_1: if were_node_one { as_network_key } else { bs_network_key },
				node_id_2: if were_node_one { bs_network_key } else { as_network_key },
				bitcoin_key_1: if were_node_one { as_bitcoin_key } else { bs_bitcoin_key },
				bitcoin_key_2: if were_node_one { bs_bitcoin_key } else { as_bitcoin_key },
				excess_data: Vec::new(),
			};
		}
	}

	macro_rules! sign_msg {
		($unsigned_msg: expr) => {
			let msghash = Message::from_slice(&Sha256dHash::hash(&$unsigned_msg.encode()[..])[..]).unwrap();
			let as_bitcoin_sig = secp_ctx.sign(&msghash, &as_chan.get_signer().inner.funding_key);
			let bs_bitcoin_sig = secp_ctx.sign(&msghash, &bs_chan.get_signer().inner.funding_key);
			let as_node_sig = secp_ctx.sign(&msghash, &nodes[0].keys_manager.get_node_secret());
			let bs_node_sig = secp_ctx.sign(&msghash, &nodes[1].keys_manager.get_node_secret());
			chan_announcement = msgs::ChannelAnnouncement {
				node_signature_1 : if were_node_one { as_node_sig } else { bs_node_sig},
				node_signature_2 : if were_node_one { bs_node_sig } else { as_node_sig},
				bitcoin_signature_1: if were_node_one { as_bitcoin_sig } else { bs_bitcoin_sig },
				bitcoin_signature_2 : if were_node_one { bs_bitcoin_sig } else { as_bitcoin_sig },
				contents: $unsigned_msg
			}
		}
	}

	let unsigned_msg = dummy_unsigned_msg!();
	sign_msg!(unsigned_msg);
	assert_eq!(nodes[0].net_graph_msg_handler.handle_channel_announcement(&chan_announcement).unwrap(), true);
	let _ = nodes[0].net_graph_msg_handler.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id : as_chan.get_short_channel_id().unwrap(), is_permanent: false } );

	// Configured with Network::Testnet
	let mut unsigned_msg = dummy_unsigned_msg!();
	unsigned_msg.chain_hash = genesis_block(Network::Bitcoin).header.block_hash();
	sign_msg!(unsigned_msg);
	assert!(nodes[0].net_graph_msg_handler.handle_channel_announcement(&chan_announcement).is_err());

	let mut unsigned_msg = dummy_unsigned_msg!();
	unsigned_msg.chain_hash = BlockHash::hash(&[1,2,3,4,5,6,7,8,9]);
	sign_msg!(unsigned_msg);
	assert!(nodes[0].net_graph_msg_handler.handle_channel_announcement(&chan_announcement).is_err());
}

#[test]
fn test_no_txn_manager_serialize_deserialize() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let logger: test_utils::TestLogger;
	let fee_estimator: test_utils::TestFeeEstimator;
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 100000, 10001, InitFeatures::known(), InitFeatures::known());

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	let nodes_0_serialized = nodes[0].node.encode();
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().iter().next().unwrap().1.write(&mut chan_0_monitor_serialized).unwrap();

	logger = test_utils::TestLogger::new();
	fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 253 };
	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), &logger, &fee_estimator, &persister, keys_manager);
	nodes[0].chain_monitor = &new_chain_monitor;
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, mut chan_0_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
		&mut chan_0_monitor_read, keys_manager).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let mut nodes_0_read = &nodes_0_serialized[..];
	let config = UserConfig::default();
	let (_, nodes_0_deserialized_tmp) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(chan_0_monitor.get_funding_txo().0, &mut chan_0_monitor);
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
			default_config: config,
			keys_manager,
			fee_estimator: &fee_estimator,
			chain_monitor: nodes[0].chain_monitor,
			tx_broadcaster: nodes[0].tx_broadcaster.clone(),
			logger: &logger,
			channel_monitors,
		}).unwrap()
	};
	nodes_0_deserialized = nodes_0_deserialized_tmp;
	assert!(nodes_0_read.is_empty());

	assert!(nodes[0].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0, chan_0_monitor).is_ok());
	nodes[0].node = &nodes_0_deserialized;
	assert_eq!(nodes[0].node.list_channels().len(), 1);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let (funding_locked, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_locked);
	for node in nodes.iter() {
		assert!(node.net_graph_msg_handler.handle_channel_announcement(&announcement).unwrap());
		node.net_graph_msg_handler.handle_channel_update(&as_update).unwrap();
		node.net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
	}

	send_payment(&nodes[0], &[&nodes[1]], 1000000, 1_000_000);
}

#[test]
fn test_manager_serialize_deserialize_events() {
	// This test makes sure the events field in ChannelManager survives de/serialization
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let fee_estimator: test_utils::TestFeeEstimator;
	let persister: test_utils::TestPersister;
	let logger: test_utils::TestLogger;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Start creating a channel, but stop right before broadcasting the event message FundingBroadcastSafe
	let channel_value = 100000;
	let push_msat = 10001;
	let a_flags = InitFeatures::known();
	let b_flags = InitFeatures::known();
	let node_a = nodes.remove(0);
	let node_b = nodes.remove(0);
	node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42, None).unwrap();
	node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), a_flags, &get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id()));
	node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), b_flags, &get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id()));

	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(&node_a, channel_value, 42);

	node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
	check_added_monitors!(node_a, 0);

	node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id()));
	{
		let mut added_monitors = node_b.chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	node_a.node.handle_funding_signed(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingSigned, node_a.node.get_our_node_id()));
	{
		let mut added_monitors = node_a.chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}
	// Normally, this is where node_a would check for a FundingBroadcastSafe event, but the test de/serializes first instead

	nodes.push(node_a);
	nodes.push(node_b);

	// Start the de/seriailization process mid-channel creation to check that the channel manager will hold onto events that are serialized
	let nodes_0_serialized = nodes[0].node.encode();
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().iter().next().unwrap().1.write(&mut chan_0_monitor_serialized).unwrap();

	fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 253 };
	logger = test_utils::TestLogger::new();
	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), &logger, &fee_estimator, &persister, keys_manager);
	nodes[0].chain_monitor = &new_chain_monitor;
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, mut chan_0_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
		&mut chan_0_monitor_read, keys_manager).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let mut nodes_0_read = &nodes_0_serialized[..];
	let config = UserConfig::default();
	let (_, nodes_0_deserialized_tmp) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(chan_0_monitor.get_funding_txo().0, &mut chan_0_monitor);
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
			default_config: config,
			keys_manager,
			fee_estimator: &fee_estimator,
			chain_monitor: nodes[0].chain_monitor,
			tx_broadcaster: nodes[0].tx_broadcaster.clone(),
			logger: &logger,
			channel_monitors,
		}).unwrap()
	};
	nodes_0_deserialized = nodes_0_deserialized_tmp;
	assert!(nodes_0_read.is_empty());

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	assert!(nodes[0].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0, chan_0_monitor).is_ok());
	nodes[0].node = &nodes_0_deserialized;

	// After deserializing, make sure the FundingBroadcastSafe event is still held by the channel manager
	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	match events_4[0] {
		Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
			assert_eq!(user_channel_id, 42);
			assert_eq!(*funding_txo, funding_output);
		},
		_ => panic!("Unexpected event"),
	};

	// Make sure the channel is functioning as though the de/serialization never happened
	assert_eq!(nodes[0].node.list_channels().len(), 1);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let (funding_locked, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_locked);
	for node in nodes.iter() {
		assert!(node.net_graph_msg_handler.handle_channel_announcement(&announcement).unwrap());
		node.net_graph_msg_handler.handle_channel_update(&as_update).unwrap();
		node.net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
	}

	send_payment(&nodes[0], &[&nodes[1]], 1000000, 1_000_000);
}

#[test]
fn test_simple_manager_serialize_deserialize() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let logger: test_utils::TestLogger;
	let fee_estimator: test_utils::TestFeeEstimator;
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
	let (_, our_payment_hash) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	let nodes_0_serialized = nodes[0].node.encode();
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().iter().next().unwrap().1.write(&mut chan_0_monitor_serialized).unwrap();

	logger = test_utils::TestLogger::new();
	fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 253 };
	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), &logger, &fee_estimator, &persister, keys_manager);
	nodes[0].chain_monitor = &new_chain_monitor;
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, mut chan_0_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
		&mut chan_0_monitor_read, keys_manager).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let mut nodes_0_read = &nodes_0_serialized[..];
	let (_, nodes_0_deserialized_tmp) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(chan_0_monitor.get_funding_txo().0, &mut chan_0_monitor);
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
			default_config: UserConfig::default(),
			keys_manager,
			fee_estimator: &fee_estimator,
			chain_monitor: nodes[0].chain_monitor,
			tx_broadcaster: nodes[0].tx_broadcaster.clone(),
			logger: &logger,
			channel_monitors,
		}).unwrap()
	};
	nodes_0_deserialized = nodes_0_deserialized_tmp;
	assert!(nodes_0_read.is_empty());

	assert!(nodes[0].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0, chan_0_monitor).is_ok());
	nodes[0].node = &nodes_0_deserialized;
	check_added_monitors!(nodes[0], 1);

	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	fail_payment(&nodes[0], &[&nodes[1]], our_payment_hash);
	claim_payment(&nodes[0], &[&nodes[1]], our_payment_preimage, 1_000_000);
}

#[test]
fn test_manager_serialize_deserialize_inconsistent_monitor() {
	// Test deserializing a ChannelManager with an out-of-date ChannelMonitor
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let logger: test_utils::TestLogger;
	let fee_estimator: test_utils::TestFeeEstimator;
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 2, 0, InitFeatures::known(), InitFeatures::known());
	let (_, _, channel_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 3, InitFeatures::known(), InitFeatures::known());

	let mut node_0_stale_monitors_serialized = Vec::new();
	for monitor in nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().iter() {
		let mut writer = test_utils::TestVecWriter(Vec::new());
		monitor.1.write(&mut writer).unwrap();
		node_0_stale_monitors_serialized.push(writer.0);
	}

	let (our_payment_preimage, _) = route_payment(&nodes[2], &[&nodes[0], &nodes[1]], 1000000);

	// Serialize the ChannelManager here, but the monitor we keep up-to-date
	let nodes_0_serialized = nodes[0].node.encode();

	route_payment(&nodes[0], &[&nodes[3]], 1000000);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[2].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[3].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	// Now the ChannelMonitor (which is now out-of-sync with ChannelManager for channel w/
	// nodes[3])
	let mut node_0_monitors_serialized = Vec::new();
	for monitor in nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().iter() {
		let mut writer = test_utils::TestVecWriter(Vec::new());
		monitor.1.write(&mut writer).unwrap();
		node_0_monitors_serialized.push(writer.0);
	}

	logger = test_utils::TestLogger::new();
	fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 253 };
	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), &logger, &fee_estimator, &persister, keys_manager);
	nodes[0].chain_monitor = &new_chain_monitor;


	let mut node_0_stale_monitors = Vec::new();
	for serialized in node_0_stale_monitors_serialized.iter() {
		let mut read = &serialized[..];
		let (_, monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(&mut read, keys_manager).unwrap();
		assert!(read.is_empty());
		node_0_stale_monitors.push(monitor);
	}

	let mut node_0_monitors = Vec::new();
	for serialized in node_0_monitors_serialized.iter() {
		let mut read = &serialized[..];
		let (_, monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(&mut read, keys_manager).unwrap();
		assert!(read.is_empty());
		node_0_monitors.push(monitor);
	}

	let mut nodes_0_read = &nodes_0_serialized[..];
	if let Err(msgs::DecodeError::InvalidValue) =
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
		default_config: UserConfig::default(),
		keys_manager,
		fee_estimator: &fee_estimator,
		chain_monitor: nodes[0].chain_monitor,
		tx_broadcaster: nodes[0].tx_broadcaster.clone(),
		logger: &logger,
		channel_monitors: node_0_stale_monitors.iter_mut().map(|monitor| { (monitor.get_funding_txo().0, monitor) }).collect(),
	}) { } else {
		panic!("If the monitor(s) are stale, this indicates a bug and we should get an Err return");
	};

	let mut nodes_0_read = &nodes_0_serialized[..];
	let (_, nodes_0_deserialized_tmp) =
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
		default_config: UserConfig::default(),
		keys_manager,
		fee_estimator: &fee_estimator,
		chain_monitor: nodes[0].chain_monitor,
		tx_broadcaster: nodes[0].tx_broadcaster.clone(),
		logger: &logger,
		channel_monitors: node_0_monitors.iter_mut().map(|monitor| { (monitor.get_funding_txo().0, monitor) }).collect(),
	}).unwrap();
	nodes_0_deserialized = nodes_0_deserialized_tmp;
	assert!(nodes_0_read.is_empty());

	{ // Channel close should result in a commitment tx and an HTLC tx
		let txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(txn.len(), 2);
		assert_eq!(txn[0].input[0].previous_output.txid, funding_tx.txid());
		assert_eq!(txn[1].input[0].previous_output.txid, txn[0].txid());
	}

	for monitor in node_0_monitors.drain(..) {
		assert!(nodes[0].chain_monitor.watch_channel(monitor.get_funding_txo().0, monitor).is_ok());
		check_added_monitors!(nodes[0], 1);
	}
	nodes[0].node = &nodes_0_deserialized;

	// nodes[1] and nodes[2] have no lost state with nodes[0]...
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	reconnect_nodes(&nodes[0], &nodes[2], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));
	//... and we can even still claim the payment!
	claim_payment(&nodes[2], &[&nodes[0], &nodes[1]], our_payment_preimage, 1_000_000);

	nodes[3].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish = get_event_msg!(nodes[3], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());
	nodes[0].node.peer_connected(&nodes[3].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[0].node.handle_channel_reestablish(&nodes[3].node.get_our_node_id(), &reestablish);
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	if let MessageSendEvent::HandleError { ref action, .. } = msg_events[0] {
		match action {
			&ErrorAction::SendErrorMessage { ref msg } => {
				assert_eq!(msg.channel_id, channel_id);
			},
			_ => panic!("Unexpected event!"),
		}
	}
}

macro_rules! check_spendable_outputs {
	($node: expr, $der_idx: expr, $keysinterface: expr, $chan_value: expr) => {
		{
			let mut events = $node.chain_monitor.chain_monitor.get_and_clear_pending_events();
			let mut txn = Vec::new();
			let mut all_outputs = Vec::new();
			let secp_ctx = Secp256k1::new();
			for event in events.drain(..) {
				match event {
					Event::SpendableOutputs { mut outputs } => {
						for outp in outputs.drain(..) {
							txn.push($keysinterface.backing.spend_spendable_outputs(&[&outp], Vec::new(), Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &secp_ctx).unwrap());
							all_outputs.push(outp);
						}
					},
					_ => panic!("Unexpected event"),
				};
			}
			if all_outputs.len() > 1 {
				if let Ok(tx) = $keysinterface.backing.spend_spendable_outputs(&all_outputs.iter().map(|a| a).collect::<Vec<_>>(), Vec::new(), Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &secp_ctx) {
					txn.push(tx);
				}
			}
			txn
		}
	}
}

#[test]
fn test_claim_sizeable_push_msat() {
	// Incidentally test SpendableOutput event generation due to detection of to_local output on commitment tx
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000, InitFeatures::known(), InitFeatures::known());
	nodes[1].node.force_close_channel(&chan.2).unwrap();
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3);
	assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[0].clone()] }, 0);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());

	let spend_txn = check_spendable_outputs!(nodes[1], 1, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[test]
fn test_claim_on_remote_sizeable_push_msat() {
	// Same test as previous, just test on remote commitment tx, as per_commitment_point registration changes following you're funder/fundee and
	// to_remote output is encumbered by a P2WPKH
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000, InitFeatures::known(), InitFeatures::known());
	nodes[0].node.force_close_channel(&chan.2).unwrap();
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3);
	assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[0].clone()] }, 0);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());

	let spend_txn = check_spendable_outputs!(nodes[1], 1, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[test]
fn test_claim_on_remote_revoked_sizeable_push_msat() {
	// Same test as previous, just test on remote revoked commitment tx, as per_commitment_point registration changes following you're funder/fundee and
	// to_remote output is encumbered by a P2WPKH

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 59000000, InitFeatures::known(), InitFeatures::known());
	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage, 3_000_000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 0);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	let header_1 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header: header_1, txdata: vec![node_txn[0].clone()] }, 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());

	let spend_txn = check_spendable_outputs!(nodes[1], 1, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], revoked_local_txn[0]); // to_remote output on revoked remote commitment_tx
	check_spends!(spend_txn[1], node_txn[0]);
	check_spends!(spend_txn[2], revoked_local_txn[0], node_txn[0]); // Both outputs
}

#[test]
fn test_static_spendable_outputs_preimage_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;

	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(commitment_tx[0].input.len(), 1);
	assert_eq!(commitment_tx[0].input[0].previous_output.txid, chan_1.3.txid());

	// Settle A's commitment tx on B's chain
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	assert!(nodes[1].node.claim_funds(payment_preimage, &None, 3_000_000));
	check_added_monitors!(nodes[1], 1);
	connect_block(&nodes[1], &Block { header, txdata: vec![commitment_tx[0].clone()] }, 1);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}

	// Check B's monitor was able to send back output descriptor event for preimage tx on A's commitment tx
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap(); // ChannelManager : 2 (local commitment tx + HTLC-Success), ChannelMonitor: preimage tx
	assert_eq!(node_txn.len(), 3);
	check_spends!(node_txn[0], commitment_tx[0]);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	check_spends!(node_txn[1], chan_1.3);
	check_spends!(node_txn[2], node_txn[1]);

	let header_1 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header: header_1, txdata: vec![node_txn[0].clone()] }, 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());

	let spend_txn = check_spendable_outputs!(nodes[1], 1, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[test]
fn test_static_spendable_outputs_timeout_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Rebalance the network a bit by relaying one payment through all the channels ...
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);

	let (_, our_payment_hash) = route_payment(&nodes[1], &vec!(&nodes[0])[..], 3_000_000);

	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(commitment_tx[0].input.len(), 1);
	assert_eq!(commitment_tx[0].input[0].previous_output.txid, chan_1.3.txid());

	// Settle A's commitment tx on B' chain
	let header = BlockHeader { version: 0x2000_0000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	connect_block(&nodes[1], &Block { header, txdata: vec![commitment_tx[0].clone()] }, 0);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// Check B's monitor was able to send back output descriptor event for timeout tx on A's commitment tx
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 3); // ChannelManager : 2 (local commitent tx + HTLC-timeout), ChannelMonitor: timeout tx
	check_spends!(node_txn[0],  commitment_tx[0].clone());
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	check_spends!(node_txn[1], chan_1.3.clone());
	check_spends!(node_txn[2], node_txn[1]);

	let header_1 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header: header_1, txdata: vec![node_txn[0].clone()] }, 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());
	expect_payment_failed!(nodes[1], our_payment_hash, true);

	let spend_txn = check_spendable_outputs!(nodes[1], 1, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 3); // SpendableOutput: remote_commitment_tx.to_remote, timeout_tx.output
	check_spends!(spend_txn[0], commitment_tx[0]);
	check_spends!(spend_txn[1], node_txn[0]);
	check_spends!(spend_txn[2], node_txn[0], commitment_tx[0]); // All outputs
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_commitment_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage, 3_000_000);

	let  header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 0);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 2);
	assert_eq!(node_txn[0].input.len(), 2);
	check_spends!(node_txn[0], revoked_local_txn[0]);

	let header_1 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header: header_1, txdata: vec![node_txn[0].clone()] }, 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());

	let spend_txn = check_spendable_outputs!(nodes[1], 1, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_htlc_timeout_tx() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage, 3_000_000);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	// A will generate HTLC-Timeout from revoked commitment tx
	connect_block(&nodes[0], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);

	let revoked_htlc_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(revoked_htlc_txn.len(), 2);
	assert_eq!(revoked_htlc_txn[0].input.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	check_spends!(revoked_htlc_txn[0], revoked_local_txn[0]);
	check_spends!(revoked_htlc_txn[1], chan_1.3);

	// B will generate justice tx from A's revoked commitment/HTLC tx
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()] }, 0);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 3); // ChannelMonitor: bogus justice tx, justice tx on revoked outputs, ChannelManager: local commitment tx
	// The first transaction generated is bogus - it spends both outputs of revoked_local_txn[0]
	// including the one already spent by revoked_htlc_txn[0]. That's OK, we'll spend with valid
	// transactions next...
	assert_eq!(node_txn[0].input.len(), 3);
	check_spends!(node_txn[0], revoked_local_txn[0], revoked_htlc_txn[0]);

	assert_eq!(node_txn[1].input.len(), 2);
	check_spends!(node_txn[1], revoked_local_txn[0], revoked_htlc_txn[0]);
	if node_txn[1].input[1].previous_output.txid == revoked_htlc_txn[0].txid() {
		assert_ne!(node_txn[1].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	} else {
		assert_eq!(node_txn[1].input[0].previous_output.txid, revoked_htlc_txn[0].txid());
		assert_ne!(node_txn[1].input[1].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	}

	assert_eq!(node_txn[2].input.len(), 1);
	check_spends!(node_txn[2], chan_1.3);

	let header_1 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header: header_1, txdata: vec![node_txn[1].clone()] }, 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());

	// Check B's ChannelMonitor was able to generate the right spendable output descriptor
	let spend_txn = check_spendable_outputs!(nodes[1], 1, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 1);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], node_txn[1]);
}

#[test]
fn test_static_spendable_outputs_justice_tx_revoked_htlc_success_tx() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.txid());

	// The to-be-revoked commitment tx should have one HTLC and one to_remote output
	assert_eq!(revoked_local_txn[0].output.len(), 2);

	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage, 3_000_000);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	// B will generate HTLC-Success from revoked commitment tx
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);
	let revoked_htlc_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();

	assert_eq!(revoked_htlc_txn.len(), 2);
	assert_eq!(revoked_htlc_txn[0].input.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	check_spends!(revoked_htlc_txn[0], revoked_local_txn[0]);

	// Check that the unspent (of two) outputs on revoked_local_txn[0] is a P2WPKH:
	let unspent_local_txn_output = revoked_htlc_txn[0].input[0].previous_output.vout as usize ^ 1;
	assert_eq!(revoked_local_txn[0].output[unspent_local_txn_output].script_pubkey.len(), 2 + 20); // P2WPKH

	// A will generate justice tx from B's revoked commitment/HTLC tx
	connect_block(&nodes[0], &Block { header, txdata: vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(node_txn.len(), 3); // ChannelMonitor: justice tx on revoked commitment, justice tx on revoked HTLC-success, ChannelManager: local commitment tx

	// The first transaction generated is bogus - it spends both outputs of revoked_local_txn[0]
	// including the one already spent by revoked_htlc_txn[0]. That's OK, we'll spend with valid
	// transactions next...
	assert_eq!(node_txn[0].input.len(), 2);
	check_spends!(node_txn[0], revoked_local_txn[0], revoked_htlc_txn[0]);
	if node_txn[0].input[1].previous_output.txid == revoked_htlc_txn[0].txid() {
		assert_eq!(node_txn[0].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	} else {
		assert_eq!(node_txn[0].input[0].previous_output.txid, revoked_htlc_txn[0].txid());
		assert_eq!(node_txn[0].input[1].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	}

	assert_eq!(node_txn[1].input.len(), 1);
	check_spends!(node_txn[1], revoked_htlc_txn[0]);

	check_spends!(node_txn[2], chan_1.3);

	let header_1 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_1, txdata: vec![node_txn[1].clone()] }, 1);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 1, true, header.block_hash());

	// Note that nodes[0]'s tx_broadcaster is still locked, so if we get here the channelmonitor
	// didn't try to generate any new transactions.

	// Check A's ChannelMonitor was able to generate the right spendable output descriptor
	let spend_txn = check_spendable_outputs!(nodes[0], 1, node_cfgs[0].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 3);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], revoked_local_txn[0]); // spending to_remote output from revoked local tx
	assert_ne!(spend_txn[0].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	check_spends!(spend_txn[1], node_txn[1]); // spending justice tx output on the htlc success tx
	check_spends!(spend_txn[2], revoked_local_txn[0], node_txn[1]); // Both outputs
}

#[test]
fn test_onchain_to_onchain_claim() {
	// Test that in case of channel closure, we detect the state of output and claim HTLC
	// on downstream peer's remote commitment tx.
	// First, have C claim an HTLC against its own latest commitment transaction.
	// Then, broadcast these to B, which should update the monitor downstream on the A<->B
	// channel.
	// Finally, check that B will claim the HTLC output if A's latest commitment transaction
	// gets broadcast.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Rebalance the network a bit by relaying one payment through all the channels ...
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 8000000, 8_000_000);

	let (payment_preimage, _payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3000000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.claim_funds(payment_preimage, &None, 3_000_000);
	check_added_monitors!(nodes[2], 1);
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());

	connect_block(&nodes[2], &Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	check_closed_broadcast!(nodes[2], false);
	check_added_monitors!(nodes[2], 1);

	let c_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelManager : 2 (commitment tx, HTLC-Success tx), ChannelMonitor : 1 (HTLC-Success tx)
	assert_eq!(c_txn.len(), 3);
	assert_eq!(c_txn[0], c_txn[2]);
	assert_eq!(commitment_tx[0], c_txn[1]);
	check_spends!(c_txn[1], chan_2.3);
	check_spends!(c_txn[2], c_txn[1]);
	assert_eq!(c_txn[1].input[0].witness.clone().last().unwrap().len(), 71);
	assert_eq!(c_txn[2].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert!(c_txn[0].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
	assert_eq!(c_txn[0].lock_time, 0); // Success tx

	// So we broadcast C's commitment tx and HTLC-Success on B's chain, we should successfully be able to extract preimage and update downstream monitor
	connect_block(&nodes[1], &Block { header, txdata: vec![c_txn[1].clone(), c_txn[2].clone()]}, 1);
	{
		let mut b_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// ChannelMonitor: claim tx, ChannelManager: local commitment tx + HTLC-timeout tx
		assert_eq!(b_txn.len(), 3);
		check_spends!(b_txn[1], chan_2.3); // B local commitment tx, issued by ChannelManager
		check_spends!(b_txn[2], b_txn[1]); // HTLC-Timeout on B local commitment tx, issued by ChannelManager
		assert_eq!(b_txn[2].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		assert!(b_txn[2].output[0].script_pubkey.is_v0_p2wsh()); // revokeable output
		assert_ne!(b_txn[2].lock_time, 0); // Timeout tx
		check_spends!(b_txn[0], c_txn[1]); // timeout tx on C remote commitment tx, issued by ChannelMonitor
		assert_eq!(b_txn[0].input[0].witness.clone().last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		assert!(b_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
		assert_ne!(b_txn[2].lock_time, 0); // Timeout tx
		b_txn.clear();
	}
	check_added_monitors!(nodes[1], 1);
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	check_added_monitors!(nodes[1], 1);
	match msg_events[0] {
		MessageSendEvent::BroadcastChannelUpdate {  .. } => {},
		_ => panic!("Unexpected event"),
	}
	match msg_events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fail_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(nodes[0].node.get_our_node_id(), *node_id);
		},
		_ => panic!("Unexpected event"),
	};
	// Broadcast A's commitment tx on B's chain to see if we are able to claim inbound HTLC with our HTLC-Success tx
	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	connect_block(&nodes[1], &Block { header, txdata: vec![commitment_tx[0].clone()]}, 1);
	let b_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	// ChannelMonitor: HTLC-Success tx, ChannelManager: local commitment tx + HTLC-Success tx
	assert_eq!(b_txn.len(), 3);
	check_spends!(b_txn[1], chan_1.3);
	check_spends!(b_txn[2], b_txn[1]);
	check_spends!(b_txn[0], commitment_tx[0]);
	assert_eq!(b_txn[0].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert!(b_txn[0].output[0].script_pubkey.is_v0_p2wpkh()); // direct payment
	assert_eq!(b_txn[0].lock_time, 0); // Success tx

	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_duplicate_payment_hash_one_failure_one_success() {
	// Topology : A --> B --> C
	// We route 2 payments with same hash between B and C, one will be timeout, the other successfully claim
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	let (our_payment_preimage, duplicate_payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 900000);
	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 900000).1, duplicate_payment_hash);

	let commitment_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(commitment_txn[0].input.len(), 1);
	check_spends!(commitment_txn[0], chan_2.3);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![commitment_txn[0].clone()] }, 1);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);

	let htlc_timeout_tx;
	{ // Extract one of the two HTLC-Timeout transaction
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// ChannelMonitor: timeout tx * 2, ChannelManager: local commitment tx + HTLC-timeout * 2
		assert_eq!(node_txn.len(), 5);
		check_spends!(node_txn[0], commitment_txn[0]);
		assert_eq!(node_txn[0].input.len(), 1);
		check_spends!(node_txn[1], commitment_txn[0]);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_ne!(node_txn[0].input[0], node_txn[1].input[0]);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		assert_eq!(node_txn[1].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[2], chan_2.3);
		check_spends!(node_txn[3], node_txn[2]);
		check_spends!(node_txn[4], node_txn[2]);
		htlc_timeout_tx = node_txn[1].clone();
	}

	nodes[2].node.claim_funds(our_payment_preimage, &None, 900_000);
	connect_block(&nodes[2], &Block { header, txdata: vec![commitment_txn[0].clone()] }, 1);
	check_added_monitors!(nodes[2], 3);
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}
	let htlc_success_txn: Vec<_> = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(htlc_success_txn.len(), 5); // ChannelMonitor: HTLC-Success txn (*2 due to 2-HTLC outputs), ChannelManager: local commitment tx + HTLC-Success txn (*2 due to 2-HTLC outputs)
	check_spends!(htlc_success_txn[2], chan_2.3);
	check_spends!(htlc_success_txn[3], htlc_success_txn[2]);
	check_spends!(htlc_success_txn[4], htlc_success_txn[2]);
	assert_eq!(htlc_success_txn[0], htlc_success_txn[3]);
	assert_eq!(htlc_success_txn[0].input.len(), 1);
	assert_eq!(htlc_success_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(htlc_success_txn[1], htlc_success_txn[4]);
	assert_eq!(htlc_success_txn[1].input.len(), 1);
	assert_eq!(htlc_success_txn[1].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	assert_ne!(htlc_success_txn[0].input[0], htlc_success_txn[1].input[0]);
	check_spends!(htlc_success_txn[0], commitment_txn[0]);
	check_spends!(htlc_success_txn[1], commitment_txn[0]);

	connect_block(&nodes[1], &Block { header, txdata: vec![htlc_timeout_tx] }, 200);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 200, true, header.block_hash());
	expect_pending_htlcs_forwardable!(nodes[1]);
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert_eq!(htlc_updates.update_fail_htlcs[0].htlc_id, 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	{
		commitment_signed_dance!(nodes[0], nodes[1], &htlc_updates.commitment_signed, false, true);
		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::PaymentFailureNetworkUpdate { update: msgs::HTLCFailChannelUpdate::ChannelClosed { .. }  } => {
			},
			_ => { panic!("Unexpected event"); }
		}
	}
	expect_payment_failed!(nodes[0], duplicate_payment_hash, false);

	// Solve 2nd HTLC by broadcasting on B's chain HTLC-Success Tx from C
	connect_block(&nodes[1], &Block { header, txdata: vec![htlc_success_txn[0].clone()] }, 200);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	assert_eq!(updates.update_fulfill_htlcs[0].htlc_id, 0);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], &updates.commitment_signed, false);

	let events = nodes[0].node.get_and_clear_pending_events();
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(*payment_preimage, our_payment_preimage);
		}
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_dynamic_spendable_outputs_local_htlc_success_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000).0;
	let local_txn = get_local_commitment_txn!(nodes[1], chan_1.2);
	assert_eq!(local_txn.len(), 1);
	assert_eq!(local_txn[0].input.len(), 1);
	check_spends!(local_txn[0], chan_1.3);

	// Give B knowledge of preimage to be able to generate a local HTLC-Success Tx
	nodes[1].node.claim_funds(payment_preimage, &None, 9_000_000);
	check_added_monitors!(nodes[1], 1);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![local_txn[0].clone()] }, 1);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}
	let node_txn = {
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 3);
		assert_eq!(node_txn[0], node_txn[2]);
		assert_eq!(node_txn[1], local_txn[0]);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		vec![node_txn[0].clone()]
	};

	let header_201 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header: header_201, txdata: node_txn.clone() }, 201);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 201, true, header_201.block_hash());

	// Verify that B is able to spend its own HTLC-Success tx thanks to spendable output event given back by its ChannelMonitor
	let spend_txn = check_spendable_outputs!(nodes[1], 1, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

fn do_test_fail_backwards_unrevoked_remote_announce(deliver_last_raa: bool, announce_latest: bool) {
	// Test that we fail backwards the full set of HTLCs we need to when remote broadcasts an
	// unrevoked commitment transaction.
	// This includes HTLCs which were below the dust threshold as well as HTLCs which were awaiting
	// a remote RAA before they could be failed backwards (and combinations thereof).
	// We also test duplicate-hash HTLCs by adding two nodes on each side of the target nodes which
	// use the same payment hashes.
	// Thus, we use a six-node network:
	//
	// A \         / E
	//    - C - D -
	// B /         \ F
	// And test where C fails back to A/B when D announces its latest commitment transaction
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs, &[None, None, None, None, None, None]);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);
	let logger = test_utils::TestLogger::new();

	create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let chan = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 3, 4, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 3, 5, InitFeatures::known(), InitFeatures::known());

	// Rebalance and check output sanity...
	send_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 500000, 500_000);
	send_payment(&nodes[1], &[&nodes[2], &nodes[3], &nodes[5]], 500000, 500_000);
	assert_eq!(get_local_commitment_txn!(nodes[3], chan.2)[0].output.len(), 2);

	let ds_dust_limit = nodes[3].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().holder_dust_limit_satoshis;
	// 0th HTLC:
	let (_, payment_hash_1) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	// 1st HTLC:
	let (_, payment_hash_2) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
	let our_node_id = &nodes[1].node.get_our_node_id();
	let route = get_route(our_node_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[5].node.get_our_node_id(), None, None, &Vec::new(), ds_dust_limit*1000, TEST_FINAL_CLTV, &logger).unwrap();
	// 2nd HTLC:
	send_along_route_with_hash(&nodes[1], route.clone(), &[&nodes[2], &nodes[3], &nodes[5]], ds_dust_limit*1000, payment_hash_1); // not added < dust limit + HTLC tx fee
	// 3rd HTLC:
	send_along_route_with_hash(&nodes[1], route, &[&nodes[2], &nodes[3], &nodes[5]], ds_dust_limit*1000, payment_hash_2); // not added < dust limit + HTLC tx fee
	// 4th HTLC:
	let (_, payment_hash_3) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	// 5th HTLC:
	let (_, payment_hash_4) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	let route = get_route(our_node_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[5].node.get_our_node_id(), None, None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	// 6th HTLC:
	send_along_route_with_hash(&nodes[1], route.clone(), &[&nodes[2], &nodes[3], &nodes[5]], 1000000, payment_hash_3);
	// 7th HTLC:
	send_along_route_with_hash(&nodes[1], route, &[&nodes[2], &nodes[3], &nodes[5]], 1000000, payment_hash_4);

	// 8th HTLC:
	let (_, payment_hash_5) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	// 9th HTLC:
	let route = get_route(our_node_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[5].node.get_our_node_id(), None, None, &Vec::new(), ds_dust_limit*1000, TEST_FINAL_CLTV, &logger).unwrap();
	send_along_route_with_hash(&nodes[1], route, &[&nodes[2], &nodes[3], &nodes[5]], ds_dust_limit*1000, payment_hash_5); // not added < dust limit + HTLC tx fee

	// 10th HTLC:
	let (_, payment_hash_6) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], ds_dust_limit*1000); // not added < dust limit + HTLC tx fee
	// 11th HTLC:
	let route = get_route(our_node_id, &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[5].node.get_our_node_id(), None, None, &Vec::new(), 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	send_along_route_with_hash(&nodes[1], route, &[&nodes[2], &nodes[3], &nodes[5]], 1000000, payment_hash_6);

	// Double-check that six of the new HTLC were added
	// We now have six HTLCs pending over the dust limit and six HTLCs under the dust limit (ie,
	// with to_local and to_remote outputs, 8 outputs and 6 HTLCs not included).
	assert_eq!(get_local_commitment_txn!(nodes[3], chan.2).len(), 1);
	assert_eq!(get_local_commitment_txn!(nodes[3], chan.2)[0].output.len(), 8);

	// Now fail back three of the over-dust-limit and three of the under-dust-limit payments in one go.
	// Fail 0th below-dust, 4th above-dust, 8th above-dust, 10th below-dust HTLCs
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_1, &None));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_3, &None));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_5, &None));
	assert!(nodes[4].node.fail_htlc_backwards(&payment_hash_6, &None));
	check_added_monitors!(nodes[4], 0);
	expect_pending_htlcs_forwardable!(nodes[4]);
	check_added_monitors!(nodes[4], 1);

	let four_removes = get_htlc_update_msgs!(nodes[4], nodes[3].node.get_our_node_id());
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[0]);
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[1]);
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[2]);
	nodes[3].node.handle_update_fail_htlc(&nodes[4].node.get_our_node_id(), &four_removes.update_fail_htlcs[3]);
	commitment_signed_dance!(nodes[3], nodes[4], four_removes.commitment_signed, false);

	// Fail 3rd below-dust and 7th above-dust HTLCs
	assert!(nodes[5].node.fail_htlc_backwards(&payment_hash_2, &None));
	assert!(nodes[5].node.fail_htlc_backwards(&payment_hash_4, &None));
	check_added_monitors!(nodes[5], 0);
	expect_pending_htlcs_forwardable!(nodes[5]);
	check_added_monitors!(nodes[5], 1);

	let two_removes = get_htlc_update_msgs!(nodes[5], nodes[3].node.get_our_node_id());
	nodes[3].node.handle_update_fail_htlc(&nodes[5].node.get_our_node_id(), &two_removes.update_fail_htlcs[0]);
	nodes[3].node.handle_update_fail_htlc(&nodes[5].node.get_our_node_id(), &two_removes.update_fail_htlcs[1]);
	commitment_signed_dance!(nodes[3], nodes[5], two_removes.commitment_signed, false);

	let ds_prev_commitment_tx = get_local_commitment_txn!(nodes[3], chan.2);

	expect_pending_htlcs_forwardable!(nodes[3]);
	check_added_monitors!(nodes[3], 1);
	let six_removes = get_htlc_update_msgs!(nodes[3], nodes[2].node.get_our_node_id());
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[0]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[1]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[2]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[3]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[4]);
	nodes[2].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &six_removes.update_fail_htlcs[5]);
	if deliver_last_raa {
		commitment_signed_dance!(nodes[2], nodes[3], six_removes.commitment_signed, false);
	} else {
		let _cs_last_raa = commitment_signed_dance!(nodes[2], nodes[3], six_removes.commitment_signed, false, true, false, true);
	}

	// D's latest commitment transaction now contains 1st + 2nd + 9th HTLCs (implicitly, they're
	// below the dust limit) and the 5th + 6th + 11th HTLCs. It has failed back the 0th, 3rd, 4th,
	// 7th, 8th, and 10th, but as we haven't yet delivered the final RAA to C, the fails haven't
	// propagated back to A/B yet (and D has two unrevoked commitment transactions).
	//
	// We now broadcast the latest commitment transaction, which *should* result in failures for
	// the 0th, 1st, 2nd, 3rd, 4th, 7th, 8th, 9th, and 10th HTLCs, ie all the below-dust HTLCs and
	// the non-broadcast above-dust HTLCs.
	//
	// Alternatively, we may broadcast the previous commitment transaction, which should only
	// result in failures for the below-dust HTLCs, ie the 0th, 1st, 2nd, 3rd, 9th, and 10th HTLCs.
	let ds_last_commitment_tx = get_local_commitment_txn!(nodes[3], chan.2);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	if announce_latest {
		connect_block(&nodes[2], &Block { header, txdata: vec![ds_last_commitment_tx[0].clone()]}, 1);
	} else {
		connect_block(&nodes[2], &Block { header, txdata: vec![ds_prev_commitment_tx[0].clone()]}, 1);
	}
	connect_blocks(&nodes[2], ANTI_REORG_DELAY - 1, 1, true,  header.block_hash());
	check_closed_broadcast!(nodes[2], false);
	expect_pending_htlcs_forwardable!(nodes[2]);
	check_added_monitors!(nodes[2], 3);

	let cs_msgs = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(cs_msgs.len(), 2);
	let mut a_done = false;
	for msg in cs_msgs {
		match msg {
			MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
				// Both under-dust HTLCs and the one above-dust HTLC that we had already failed
				// should be failed-backwards here.
				let target = if *node_id == nodes[0].node.get_our_node_id() {
					// If announce_latest, expect 0th, 1st, 4th, 8th, 10th HTLCs, else only 0th, 1st, 10th below-dust HTLCs
					for htlc in &updates.update_fail_htlcs {
						assert!(htlc.htlc_id == 1 || htlc.htlc_id == 2 || htlc.htlc_id == 6 || if announce_latest { htlc.htlc_id == 3 || htlc.htlc_id == 5 } else { false });
					}
					assert_eq!(updates.update_fail_htlcs.len(), if announce_latest { 5 } else { 3 });
					assert!(!a_done);
					a_done = true;
					&nodes[0]
				} else {
					// If announce_latest, expect 2nd, 3rd, 7th, 9th HTLCs, else only 2nd, 3rd, 9th below-dust HTLCs
					for htlc in &updates.update_fail_htlcs {
						assert!(htlc.htlc_id == 1 || htlc.htlc_id == 2 || htlc.htlc_id == 5 || if announce_latest { htlc.htlc_id == 4 } else { false });
					}
					assert_eq!(*node_id, nodes[1].node.get_our_node_id());
					assert_eq!(updates.update_fail_htlcs.len(), if announce_latest { 4 } else { 3 });
					&nodes[1]
				};
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[1]);
				target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[2]);
				if announce_latest {
					target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[3]);
					if *node_id == nodes[0].node.get_our_node_id() {
						target.node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[4]);
					}
				}
				commitment_signed_dance!(target, nodes[2], updates.commitment_signed, false, true);
			},
			_ => panic!("Unexpected event"),
		}
	}

	let as_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(as_events.len(), if announce_latest { 5 } else { 3 });
	let mut as_failds = HashSet::new();
	for event in as_events.iter() {
		if let &Event::PaymentFailed { ref payment_hash, ref rejected_by_dest, .. } = event {
			assert!(as_failds.insert(*payment_hash));
			if *payment_hash != payment_hash_2 {
				assert_eq!(*rejected_by_dest, deliver_last_raa);
			} else {
				assert!(!rejected_by_dest);
			}
		} else { panic!("Unexpected event"); }
	}
	assert!(as_failds.contains(&payment_hash_1));
	assert!(as_failds.contains(&payment_hash_2));
	if announce_latest {
		assert!(as_failds.contains(&payment_hash_3));
		assert!(as_failds.contains(&payment_hash_5));
	}
	assert!(as_failds.contains(&payment_hash_6));

	let bs_events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(bs_events.len(), if announce_latest { 4 } else { 3 });
	let mut bs_failds = HashSet::new();
	for event in bs_events.iter() {
		if let &Event::PaymentFailed { ref payment_hash, ref rejected_by_dest, .. } = event {
			assert!(bs_failds.insert(*payment_hash));
			if *payment_hash != payment_hash_1 && *payment_hash != payment_hash_5 {
				assert_eq!(*rejected_by_dest, deliver_last_raa);
			} else {
				assert!(!rejected_by_dest);
			}
		} else { panic!("Unexpected event"); }
	}
	assert!(bs_failds.contains(&payment_hash_1));
	assert!(bs_failds.contains(&payment_hash_2));
	if announce_latest {
		assert!(bs_failds.contains(&payment_hash_4));
	}
	assert!(bs_failds.contains(&payment_hash_5));

	// For each HTLC which was not failed-back by normal process (ie deliver_last_raa), we should
	// get a PaymentFailureNetworkUpdate. A should have gotten 4 HTLCs which were failed-back due
	// to unknown-preimage-etc, B should have gotten 2. Thus, in the
	// announce_latest && deliver_last_raa case, we should have 5-4=1 and 4-2=2
	// PaymentFailureNetworkUpdates.
	let as_msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_msg_events.len(), if deliver_last_raa { 1 } else if !announce_latest { 3 } else { 5 });
	let bs_msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(bs_msg_events.len(), if deliver_last_raa { 2 } else if !announce_latest { 3 } else { 4 });
	for event in as_msg_events.iter().chain(bs_msg_events.iter()) {
		match event {
			&MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_fail_backwards_latest_remote_announce_a() {
	do_test_fail_backwards_unrevoked_remote_announce(false, true);
}

#[test]
fn test_fail_backwards_latest_remote_announce_b() {
	do_test_fail_backwards_unrevoked_remote_announce(true, true);
}

#[test]
fn test_fail_backwards_previous_remote_announce() {
	do_test_fail_backwards_unrevoked_remote_announce(false, false);
	// Note that true, true doesn't make sense as it implies we announce a revoked state, which is
	// tested for in test_commitment_revoked_fail_backward_exhaustive()
}

#[test]
fn test_dynamic_spendable_outputs_local_htlc_timeout_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let (_, our_payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000);
	let local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn[0].input.len(), 1);
	check_spends!(local_txn[0], chan_1.3);

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header, txdata: vec![local_txn[0].clone()] }, 200);
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		node_txn[0].clone()
	};

	let header_201 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_201, txdata: vec![htlc_timeout.clone()] }, 201);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 201, true, header_201.block_hash());
	expect_payment_failed!(nodes[0], our_payment_hash, true);

	// Verify that A is able to spend its own HTLC-Timeout tx thanks to spendable output event given back by its ChannelMonitor
	let spend_txn = check_spendable_outputs!(nodes[0], 1, node_cfgs[0].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], local_txn[0]);
	check_spends!(spend_txn[1], htlc_timeout);
	check_spends!(spend_txn[2], local_txn[0], htlc_timeout);
}

#[test]
fn test_key_derivation_params() {
	// This test is a copy of test_dynamic_spendable_outputs_local_htlc_timeout_tx, with
	// a key manager rotation to test that key_derivation_params returned in DynamicOutputP2WSH
	// let us re-derive the channel key set to then derive a delayed_payment_key.

	let chanmon_cfgs = create_chanmon_cfgs(3);

	// We manually create the node configuration to backup the seed.
	let seed = [42; 32];
	let keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);
	let chain_monitor = test_utils::TestChainMonitor::new(Some(&chanmon_cfgs[0].chain_source), &chanmon_cfgs[0].tx_broadcaster, &chanmon_cfgs[0].logger, &chanmon_cfgs[0].fee_estimator, &chanmon_cfgs[0].persister, &keys_manager);
	let node = NodeCfg { chain_source: &chanmon_cfgs[0].chain_source, logger: &chanmon_cfgs[0].logger, tx_broadcaster: &chanmon_cfgs[0].tx_broadcaster, fee_estimator: &chanmon_cfgs[0].fee_estimator, chain_monitor, keys_manager: &keys_manager, node_seed: seed };
	let mut node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	node_cfgs.remove(0);
	node_cfgs.insert(0, node);

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	// Create a dummy channel to advance index by one and thus test re-derivation correctness
	// for node 0
	let chan_0 = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known());
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	assert_ne!(chan_0.3.output[0].script_pubkey, chan_1.3.output[0].script_pubkey);

	let (_, our_payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9000000);
	let local_txn_0 = get_local_commitment_txn!(nodes[0], chan_0.2);
	let local_txn_1 = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn_1[0].input.len(), 1);
	check_spends!(local_txn_1[0], chan_1.3);

	// We check funding pubkey are unique
	let (from_0_funding_key_0, from_0_funding_key_1) = (PublicKey::from_slice(&local_txn_0[0].input[0].witness[3][2..35]), PublicKey::from_slice(&local_txn_0[0].input[0].witness[3][36..69]));
	let (from_1_funding_key_0, from_1_funding_key_1) = (PublicKey::from_slice(&local_txn_1[0].input[0].witness[3][2..35]), PublicKey::from_slice(&local_txn_1[0].input[0].witness[3][36..69]));
	if from_0_funding_key_0 == from_1_funding_key_0
	    || from_0_funding_key_0 == from_1_funding_key_1
	    || from_0_funding_key_1 == from_1_funding_key_0
	    || from_0_funding_key_1 == from_1_funding_key_1 {
		panic!("Funding pubkeys aren't unique");
	}

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header, txdata: vec![local_txn_1[0].clone()] }, 200);
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn_1[0]);
		node_txn[0].clone()
	};

	let header_201 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_201, txdata: vec![htlc_timeout.clone()] }, 201);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 201, true, header_201.block_hash());
	expect_payment_failed!(nodes[0], our_payment_hash, true);

	// Verify that A is able to spend its own HTLC-Timeout tx thanks to spendable output event given back by its ChannelMonitor
	let new_keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);
	let spend_txn = check_spendable_outputs!(nodes[0], 1, new_keys_manager, 100000);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], local_txn_1[0]);
	check_spends!(spend_txn[1], htlc_timeout);
	check_spends!(spend_txn[2], local_txn_1[0], htlc_timeout);
}

#[test]
fn test_static_output_closing_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);
	let closing_tx = close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true).2;

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header, txdata: vec![closing_tx.clone()] }, 0);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 0, true, header.block_hash());

	let spend_txn = check_spendable_outputs!(nodes[0], 2, node_cfgs[0].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], closing_tx);

	connect_block(&nodes[1], &Block { header, txdata: vec![closing_tx.clone()] }, 0);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1, 0, true, header.block_hash());

	let spend_txn = check_spendable_outputs!(nodes[1], 2, node_cfgs[1].keys_manager, 100000);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], closing_tx);
}

fn do_htlc_claim_local_commitment_only(use_dust: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let (our_payment_preimage, _) = route_payment(&nodes[0], &[&nodes[1]], if use_dust { 50000 } else { 3000000 });

	// Claim the payment, but don't deliver A's commitment_signed, resulting in the HTLC only being
	// present in B's local commitment transaction, but none of A's commitment transactions.
	assert!(nodes[1].node.claim_funds(our_payment_preimage, &None, if use_dust { 50_000 } else { 3_000_000 }));
	check_added_monitors!(nodes[1], 1);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fulfill_htlcs[0]);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { payment_preimage } => {
			assert_eq!(payment_preimage, our_payment_preimage);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_updates.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_updates = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_updates.0);
	check_added_monitors!(nodes[1], 1);

	let starting_block = nodes[1].best_block_info();
	let mut block = Block {
		header: BlockHeader { version: 0x20000000, prev_blockhash: starting_block.0, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
		txdata: vec![],
	};
	for i in starting_block.1 + 1..TEST_FINAL_CLTV - CLTV_CLAIM_BUFFER + starting_block.1 + 2 {
		connect_block(&nodes[1], &block, i);
		block.header.prev_blockhash = block.block_hash();
	}
	test_txn_broadcast(&nodes[1], &chan, None, if use_dust { HTLCType::NONE } else { HTLCType::SUCCESS });
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);
}

fn do_htlc_claim_current_remote_commitment_only(use_dust: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &Vec::new(), if use_dust { 50000 } else { 3000000 }, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);

	let _as_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	// As far as A is concerned, the HTLC is now present only in the latest remote commitment
	// transaction, however it is not in A's latest local commitment, so we can just broadcast that
	// to "time out" the HTLC.

	let starting_block = nodes[1].best_block_info();
	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: starting_block.0, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };

	for i in starting_block.1 + 1..TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + starting_block.1 + 2 {
		connect_block(&nodes[0], &Block { header, txdata: Vec::new()}, i);
		header.prev_blockhash = header.block_hash();
	}
	test_txn_broadcast(&nodes[0], &chan, None, HTLCType::NONE);
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);
}

fn do_htlc_claim_previous_remote_commitment_only(use_dust: bool, check_revoke_no_close: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Fail the payment, but don't deliver A's final RAA, resulting in the HTLC only being present
	// in B's previous (unrevoked) commitment transaction, but none of A's commitment transactions.
	// Also optionally test that we *don't* fail the channel in case the commitment transaction was
	// actually revoked.
	let htlc_value = if use_dust { 50000 } else { 3000000 };
	let (_, our_payment_hash) = route_payment(&nodes[0], &[&nodes[1]], htlc_value);
	assert!(nodes[1].node.fail_htlc_backwards(&our_payment_hash, &None));
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let bs_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_updates.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_updates.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let as_updates = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_updates.0);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_updates.1);
	check_added_monitors!(nodes[1], 1);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	if check_revoke_no_close {
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
		check_added_monitors!(nodes[0], 1);
	}

	let starting_block = nodes[1].best_block_info();
	let mut block = Block {
		header: BlockHeader { version: 0x20000000, prev_blockhash: starting_block.0, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
		txdata: vec![],
	};
	for i in starting_block.1 + 1..TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + CHAN_CONFIRM_DEPTH + 2 {
		connect_block(&nodes[0], &block, i);
		block.header.prev_blockhash = block.block_hash();
	}
	if !check_revoke_no_close {
		test_txn_broadcast(&nodes[0], &chan, None, HTLCType::NONE);
		check_closed_broadcast!(nodes[0], false);
		check_added_monitors!(nodes[0], 1);
	} else {
		expect_payment_failed!(nodes[0], our_payment_hash, true);
	}
}

// Test that we close channels on-chain when broadcastable HTLCs reach their timeout window.
// There are only a few cases to test here:
//  * its not really normative behavior, but we test that below-dust HTLCs "included" in
//    broadcastable commitment transactions result in channel closure,
//  * its included in an unrevoked-but-previous remote commitment transaction,
//  * its included in the latest remote or local commitment transactions.
// We test each of the three possible commitment transactions individually and use both dust and
// non-dust HTLCs.
// Note that we don't bother testing both outbound and inbound HTLC failures for each case, and we
// assume they are handled the same across all six cases, as both outbound and inbound failures are
// tested for at least one of the cases in other tests.
#[test]
fn htlc_claim_single_commitment_only_a() {
	do_htlc_claim_local_commitment_only(true);
	do_htlc_claim_local_commitment_only(false);

	do_htlc_claim_current_remote_commitment_only(true);
	do_htlc_claim_current_remote_commitment_only(false);
}

#[test]
fn htlc_claim_single_commitment_only_b() {
	do_htlc_claim_previous_remote_commitment_only(true, false);
	do_htlc_claim_previous_remote_commitment_only(false, false);
	do_htlc_claim_previous_remote_commitment_only(true, true);
	do_htlc_claim_previous_remote_commitment_only(false, true);
}

#[test]
#[should_panic]
fn bolt2_open_channel_sending_node_checks_part1() { //This test needs to be on its own as we are catching a panic
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	//Force duplicate channel ids
	for node in nodes.iter() {
		*node.keys_manager.override_channel_id_priv.lock().unwrap() = Some([0; 32]);
	}

	// BOLT #2 spec: Sending node must ensure temporary_channel_id is unique from any other channel ID with the same peer.
	let channel_value_satoshis=10000;
	let push_msat=10001;
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None).unwrap();
	let node0_to_1_send_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &node0_to_1_send_open_channel);

	//Create a second channel with a channel_id collision
	assert!(nodes[0].node.create_channel(nodes[0].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None).is_err());
}

#[test]
fn bolt2_open_channel_sending_node_checks_part2() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// BOLT #2 spec: Sending node must set funding_satoshis to less than 2^24 satoshis
	let channel_value_satoshis=2^24;
	let push_msat=10001;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None).is_err());

	// BOLT #2 spec: Sending node must set push_msat to equal or less than 1000 * funding_satoshis
	let channel_value_satoshis=10000;
	// Test when push_msat is equal to 1000 * funding_satoshis.
	let push_msat=1000*channel_value_satoshis+1;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None).is_err());

	// BOLT #2 spec: Sending node must set set channel_reserve_satoshis greater than or equal to dust_limit_satoshis
	let channel_value_satoshis=10000;
	let push_msat=10001;
	assert!(nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), channel_value_satoshis, push_msat, 42, None).is_ok()); //Create a valid channel
	let node0_to_1_send_open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert!(node0_to_1_send_open_channel.channel_reserve_satoshis>=node0_to_1_send_open_channel.dust_limit_satoshis);

	// BOLT #2 spec: Sending node must set undefined bits in channel_flags to 0
	// Only the least-significant bit of channel_flags is currently defined resulting in channel_flags only having one of two possible states 0 or 1
	assert!(node0_to_1_send_open_channel.channel_flags<=1);

	// BOLT #2 spec: Sending node should set to_self_delay sufficient to ensure the sender can irreversibly spend a commitment transaction output, in case of misbehaviour by the receiver.
	assert!(BREAKDOWN_TIMEOUT>0);
	assert!(node0_to_1_send_open_channel.to_self_delay==BREAKDOWN_TIMEOUT);

	// BOLT #2 spec: Sending node must ensure the chain_hash value identifies the chain it wishes to open the channel within.
	let chain_hash=genesis_block(Network::Testnet).header.block_hash();
	assert_eq!(node0_to_1_send_open_channel.chain_hash,chain_hash);

	// BOLT #2 spec: Sending node must set funding_pubkey, revocation_basepoint, htlc_basepoint, payment_basepoint, and delayed_payment_basepoint to valid DER-encoded, compressed, secp256k1 pubkeys.
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.funding_pubkey.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.revocation_basepoint.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.htlc_basepoint.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.payment_point.serialize()).is_ok());
	assert!(PublicKey::from_slice(&node0_to_1_send_open_channel.delayed_payment_basepoint.serialize()).is_ok());
}

// Test that if we fail to send an HTLC that is being freed from the holding cell, and the HTLC
// originated from our node, its failure is surfaced to the user. We trigger this failure to
// free the HTLC by increasing our fee while the HTLC is in the holding cell such that the HTLC
// is no longer affordable once it's freed.
#[test]
fn test_fail_holding_cell_htlc_upon_free() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	// First nodes[0] generates an update_fee, setting the channel's
	// pending_update_fee.
	nodes[0].node.update_fee(chan.2, get_feerate!(nodes[0], chan.2) + 20).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], chan.2);

	// 2* and +1 HTLCs on the commit tx fee calculation for the fee spike reserve.
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let max_can_send = 5000000 - channel_reserve - 2*commit_tx_fee_msat(feerate, 1 + 1);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], max_can_send, TEST_FINAL_CLTV, &logger).unwrap();

	// Send a payment which passes reserve checks but gets stuck in the holding cell.
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, max_can_send);

	// Flush the pending fee update.
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (as_revoke_and_ack, _) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &as_revoke_and_ack);
	check_added_monitors!(nodes[0], 1);

	// Upon receipt of the RAA, there will be an attempt to resend the holding cell
	// HTLC, but now that the fee has been raised the payment will now fail, causing
	// us to surface its failure to the user.
	chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, 0);
	nodes[0].logger.assert_log("lightning::ln::channel".to_string(), "Freeing holding cell with 1 HTLC updates".to_string(), 1);
	let failure_log = format!("Failed to send HTLC with payment_hash {} due to Cannot send value that would put our balance under counterparty-announced channel reserve value ({})", log_bytes!(our_payment_hash.0), chan_stat.channel_reserve_msat);
	nodes[0].logger.assert_log("lightning::ln::channel".to_string(), failure_log.to_string(), 1);

	// Check that the payment failed to be sent out.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		&Event::PaymentFailed { ref payment_hash, ref rejected_by_dest, ref error_code, ref error_data } => {
			assert_eq!(our_payment_hash.clone(), *payment_hash);
			assert_eq!(*rejected_by_dest, false);
			assert_eq!(*error_code, None);
			assert_eq!(*error_data, None);
		},
		_ => panic!("Unexpected event"),
	}
}

// Test that if multiple HTLCs are released from the holding cell and one is
// valid but the other is no longer valid upon release, the valid HTLC can be
// successfully completed while the other one fails as expected.
#[test]
fn test_free_and_fail_holding_cell_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	// First nodes[0] generates an update_fee, setting the channel's
	// pending_update_fee.
	nodes[0].node.update_fee(chan.2, get_feerate!(nodes[0], chan.2) + 200).unwrap();
	check_added_monitors!(nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], chan.2);

	// 2* and +1 HTLCs on the commit tx fee calculation for the fee spike reserve.
	let (payment_preimage_1, payment_hash_1) = get_payment_preimage_hash!(nodes[0]);
	let amt_1 = 20000;
	let (_, payment_hash_2) = get_payment_preimage_hash!(nodes[0]);
	let amt_2 = 5000000 - channel_reserve - 2*commit_tx_fee_msat(feerate, 2 + 1) - amt_1;
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route_1 = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], amt_1, TEST_FINAL_CLTV, &logger).unwrap();
	let route_2 = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], amt_2, TEST_FINAL_CLTV, &logger).unwrap();

	// Send 2 payments which pass reserve checks but get stuck in the holding cell.
	nodes[0].node.send_payment(&route_1, payment_hash_1, &None).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, amt_1);
	nodes[0].node.send_payment(&route_2, payment_hash_2, &None).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, amt_1 + amt_2);

	// Flush the pending fee update.
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), commitment_signed);
	let (revoke_and_ack, commitment_signed) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &revoke_and_ack);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);
	check_added_monitors!(nodes[0], 2);

	// Upon receipt of the RAA, there will be an attempt to resend the holding cell HTLCs,
	// but now that the fee has been raised the second payment will now fail, causing us
	// to surface its failure to the user. The first payment should succeed.
	chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, 0);
	nodes[0].logger.assert_log("lightning::ln::channel".to_string(), "Freeing holding cell with 2 HTLC updates".to_string(), 1);
	let failure_log = format!("Failed to send HTLC with payment_hash {} due to Cannot send value that would put our balance under counterparty-announced channel reserve value ({})", log_bytes!(payment_hash_2.0), chan_stat.channel_reserve_msat);
	nodes[0].logger.assert_log("lightning::ln::channel".to_string(), failure_log.to_string(), 1);

	// Check that the second payment failed to be sent out.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		&Event::PaymentFailed { ref payment_hash, ref rejected_by_dest, ref error_code, ref error_data } => {
			assert_eq!(payment_hash_2.clone(), *payment_hash);
			assert_eq!(*rejected_by_dest, false);
			assert_eq!(*error_code, None);
			assert_eq!(*error_data, None);
		},
		_ => panic!("Unexpected event"),
	}

	// Complete the first payment and the RAA from the fee update.
	let (payment_event, send_raa_event) = {
		let mut msgs = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msgs.len(), 2);
		(SendEvent::from_event(msgs.remove(0)), msgs.remove(0))
	};
	let raa = match send_raa_event {
		MessageSendEvent::SendRevokeAndACK { msg, .. } => msg,
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &raa);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PendingHTLCsForwardable { .. } => {},
		_ => panic!("Unexpected event"),
	}
	nodes[1].node.process_pending_htlc_forwards();
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentReceived { .. } => {},
		_ => panic!("Unexpected event"),
	}
	nodes[1].node.claim_funds(payment_preimage_1, &None, amt_1);
	check_added_monitors!(nodes[1], 1);
	let update_msgs = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_msgs.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], update_msgs.commitment_signed, false, true);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentSent { ref payment_preimage } => {
			assert_eq!(*payment_preimage, payment_preimage_1);
		}
		_ => panic!("Unexpected event"),
	}
}

// Test that if we fail to forward an HTLC that is being freed from the holding cell that the
// HTLC is failed backwards. We trigger this failure to forward the freed HTLC by increasing
// our fee while the HTLC is in the holding cell such that the HTLC is no longer affordable
// once it's freed.
#[test]
fn test_fail_holding_cell_htlc_upon_free_multihop() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_0_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let chan_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	// First nodes[1] generates an update_fee, setting the channel's
	// pending_update_fee.
	nodes[1].node.update_fee(chan_1_2.2, get_feerate!(nodes[1], chan_1_2.2) + 20).unwrap();
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. }, .. } => {
			(update_fee.as_ref(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_update_fee(&nodes[1].node.get_our_node_id(), update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], chan_0_1.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], chan_0_1.2);

	// Send a payment which passes reserve checks but gets stuck in the holding cell.
	let feemsat = 239;
	let total_routing_fee_msat = (nodes.len() - 2) as u64 * feemsat;
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let max_can_send = 5000000 - channel_reserve - 2*commit_tx_fee_msat(feerate, 1 + 1) - total_routing_fee_msat;
	let payment_event = {
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &[], max_can_send, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
		check_added_monitors!(nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);

		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	chan_stat = get_channel_value_stat!(nodes[1], chan_1_2.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, max_can_send);

	// Flush the pending fee update.
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed);
	let (raa, commitment_signed) = get_revoke_commit_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[2], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &raa);
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &commitment_signed);
	check_added_monitors!(nodes[1], 2);

	// A final RAA message is generated to finalize the fee update.
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);

	let raa_msg = match &events[0] {
		&MessageSendEvent::SendRevokeAndACK { ref msg, .. } => {
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa_msg);
	check_added_monitors!(nodes[2], 1);
	assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

	// nodes[1]'s ChannelManager will now signal that we have HTLC forwards to process.
	let process_htlc_forwards_event = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(process_htlc_forwards_event.len(), 1);
	match &process_htlc_forwards_event[0] {
		&Event::PendingHTLCsForwardable { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// In response, we call ChannelManager's process_pending_htlc_forwards
	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors!(nodes[1], 1);

	// This causes the HTLC to be failed backwards.
	let fail_event = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(fail_event.len(), 1);
	let (fail_msg, commitment_signed) = match &fail_event[0] {
		&MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			assert_eq!(updates.update_add_htlcs.len(), 0);
			assert_eq!(updates.update_fulfill_htlcs.len(), 0);
			assert_eq!(updates.update_fail_malformed_htlcs.len(), 0);
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			(updates.update_fail_htlcs[0].clone(), updates.commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	// Pass the failure messages back to nodes[0].
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &commitment_signed);

	// Complete the HTLC failure+removal process.
	let (raa, commitment_signed) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &raa);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &commitment_signed);
	check_added_monitors!(nodes[1], 2);
	let final_raa_event = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(final_raa_event.len(), 1);
	let raa = match &final_raa_event[0] {
		&MessageSendEvent::SendRevokeAndACK { ref msg, .. } => msg.clone(),
		_ => panic!("Unexpected event"),
	};
	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &raa);
	let fail_msg_event = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(fail_msg_event.len(), 1);
	match &fail_msg_event[0] {
		&MessageSendEvent::PaymentFailureNetworkUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}
	let failure_event = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(failure_event.len(), 1);
	match &failure_event[0] {
		&Event::PaymentFailed { rejected_by_dest, .. } => {
			assert!(!rejected_by_dest);
		},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors!(nodes[0], 1);
}

// BOLT 2 Requirements for the Sender when constructing and sending an update_add_htlc message.
// BOLT 2 Requirement: MUST NOT offer amount_msat it cannot pay for in the remote commitment transaction at the current feerate_per_kw (see "Updating Fees") while maintaining its channel reserve.
//TODO: I don't believe this is explicitly enforced when sending an HTLC but as the Fee aspect of the BOLT specs is in flux leaving this as a TODO.

#[test]
fn test_update_add_htlc_bolt2_sender_value_below_minimum_msat() {
	//BOLT2 Requirement: MUST NOT offer amount_msat below the receiving node's htlc_minimum_msat (same validation check catches both of these)
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let mut route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	route.paths[0][0].fee_msat = 100;

	unwrap_send_err!(nodes[0].node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
		assert!(regex::Regex::new(r"Cannot send less than their minimum HTLC value \(\d+\)").unwrap().is_match(err)));
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Cannot send less than their minimum HTLC value".to_string(), 1);
}

#[test]
fn test_update_add_htlc_bolt2_sender_zero_value_msat() {
	//BOLT2 Requirement: MUST offer amount_msat greater than 0.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let mut route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	route.paths[0][0].fee_msat = 0;
	unwrap_send_err!(nodes[0].node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
		assert_eq!(err, "Cannot send 0-msat HTLC"));

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Cannot send 0-msat HTLC".to_string(), 1);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_zero_value_msat() {
	//BOLT2 Requirement: MUST offer amount_msat greater than 0.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].amount_msat = 0;

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	nodes[1].logger.assert_log("lightning::ln::channelmanager".to_string(), "Remote side tried to send a 0-msat HTLC".to_string(), 1);
	check_closed_broadcast!(nodes[1], true).unwrap();
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_add_htlc_bolt2_sender_cltv_expiry_too_high() {
	//BOLT 2 Requirement: MUST set cltv_expiry less than 500000000.
	//It is enforced when constructing a route.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 0, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 100000000, 500000001, &logger).unwrap();
	unwrap_send_err!(nodes[0].node.send_payment(&route, our_payment_hash, &None), true, APIError::RouteError { ref err },
		assert_eq!(err, &"Channel CLTV overflowed?"));
}

#[test]
fn test_update_add_htlc_bolt2_sender_exceed_max_htlc_num_and_htlc_id_increment() {
	//BOLT 2 Requirement: if result would be offering more than the remote's max_accepted_htlcs HTLCs, in the remote commitment transaction: MUST NOT add an HTLC.
	//BOLT 2 Requirement: for the first HTLC it offers MUST set id to 0.
	//BOLT 2 Requirement: MUST increase the value of id by 1 for each successive offer.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 0, InitFeatures::known(), InitFeatures::known());
	let max_accepted_htlcs = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().counterparty_max_accepted_htlcs as u64;

	let logger = test_utils::TestLogger::new();
	for i in 0..max_accepted_htlcs {
		let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
		let payment_event = {
			let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
			let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
			nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
			check_added_monitors!(nodes[0], 1);

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			if let MessageSendEvent::UpdateHTLCs { node_id: _, updates: msgs::CommitmentUpdate{ update_add_htlcs: ref htlcs, .. }, } = events[0] {
				assert_eq!(htlcs[0].htlc_id, i);
			} else {
				assert!(false);
			}
			SendEvent::from_event(events.remove(0))
		};
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(nodes[1], 0);
		commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(nodes[1]);
		expect_payment_received!(nodes[1], our_payment_hash, 100000);
	}
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	unwrap_send_err!(nodes[0].node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
		assert!(regex::Regex::new(r"Cannot push more than their max accepted HTLCs \(\d+\)").unwrap().is_match(err)));

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Cannot push more than their max accepted HTLCs".to_string(), 1);
}

#[test]
fn test_update_add_htlc_bolt2_sender_exceed_max_htlc_value_in_flight() {
	//BOLT 2 Requirement: if the sum of total offered HTLCs would exceed the remote's max_htlc_value_in_flight_msat: MUST NOT add an HTLC.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_value = 100000;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value, 0, InitFeatures::known(), InitFeatures::known());
	let max_in_flight = get_channel_value_stat!(nodes[0], chan.2).counterparty_max_htlc_value_in_flight_msat;

	send_payment(&nodes[0], &vec!(&nodes[1])[..], max_in_flight, max_in_flight);

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	// Manually create a route over our max in flight (which our router normally automatically
	// limits us to.
	let route = Route { paths: vec![vec![RouteHop {
	   pubkey: nodes[1].node.get_our_node_id(), node_features: NodeFeatures::known(), channel_features: ChannelFeatures::known(),
	   short_channel_id: nodes[1].node.list_usable_channels()[0].short_channel_id.unwrap(),
	   fee_msat: max_in_flight + 1, cltv_expiry_delta: TEST_FINAL_CLTV
	}]] };
	unwrap_send_err!(nodes[0].node.send_payment(&route, our_payment_hash, &None), true, APIError::ChannelUnavailable { ref err },
		assert!(regex::Regex::new(r"Cannot send value that would put us over the max HTLC value in flight our peer will accept \(\d+\)").unwrap().is_match(err)));

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].logger.assert_log_contains("lightning::ln::channelmanager".to_string(), "Cannot send value that would put us over the max HTLC value in flight our peer will accept".to_string(), 1);

	send_payment(&nodes[0], &[&nodes[1]], max_in_flight, max_in_flight);
}

// BOLT 2 Requirements for the Receiver when handling an update_add_htlc message.
#[test]
fn test_update_add_htlc_bolt2_receiver_check_amount_received_more_than_min() {
	//BOLT2 Requirement: receiving an amount_msat equal to 0, OR less than its own htlc_minimum_msat -> SHOULD fail the channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let htlc_minimum_msat: u64;
	{
		let chan_lock = nodes[0].node.channel_state.lock().unwrap();
		let channel = chan_lock.by_id.get(&chan.2).unwrap();
		htlc_minimum_msat = channel.get_holder_htlc_minimum_msat();
	}

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], htlc_minimum_msat, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].amount_msat = htlc_minimum_msat-1;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert!(regex::Regex::new(r"Remote side tried to send less than our minimum HTLC value\. Lower limit: \(\d+\)\. Actual: \(\d+\)").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_sender_can_afford_amount_sent() {
	//BOLT2 Requirement: receiving an amount_msat that the sending node cannot afford at the current feerate_per_kw (while maintaining its channel reserve): SHOULD fail the channel
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let chan_stat = get_channel_value_stat!(nodes[0], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], chan.2);
	// The 2* and +1 are for the fee spike reserve.
	let commit_tx_fee_outbound = 2 * commit_tx_fee_msat(feerate, 1 + 1);

	let max_can_send = 5000000 - channel_reserve - commit_tx_fee_outbound;
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], max_can_send, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	// Even though channel-initiator senders are required to respect the fee_spike_reserve,
	// at this time channel-initiatee receivers are not required to enforce that senders
	// respect the fee_spike_reserve.
	updates.update_add_htlcs[0].amount_msat = max_can_send + commit_tx_fee_outbound + 1;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert_eq!(err_msg.data, "Remote HTLC add would put them under remote reserve value");
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_max_htlc_limit() {
	//BOLT 2 Requirement: if a sending node adds more than its max_accepted_htlcs HTLCs to its local commitment transaction: SHOULD fail the channel
	//BOLT 2 Requirement: MUST allow multiple HTLCs with the same payment_hash.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();

	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 3999999, TEST_FINAL_CLTV, &logger).unwrap();

	let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
	let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::signing_only(), &route.paths[0], &session_priv).unwrap();
	let (onion_payloads, _htlc_msat, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 3999999, &None, cur_height).unwrap();
	let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &our_payment_hash);

	let mut msg = msgs::UpdateAddHTLC {
		channel_id: chan.2,
		htlc_id: 0,
		amount_msat: 1000,
		payment_hash: our_payment_hash,
		cltv_expiry: htlc_cltv,
		onion_routing_packet: onion_packet.clone(),
	};

	for i in 0..super::channel::OUR_MAX_HTLCS {
		msg.htlc_id = i as u64;
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);
	}
	msg.htlc_id = (super::channel::OUR_MAX_HTLCS) as u64;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &msg);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to push more than our max accepted HTLCs \(\d+\)").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_max_in_flight_msat() {
	//OR adds more than its max_htlc_value_in_flight_msat worth of offered HTLCs to its local commitment transaction: SHOULD fail the channel
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].amount_msat = get_channel_value_stat!(nodes[1], chan.2).counterparty_max_htlc_value_in_flight_msat + 1;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert!(regex::Regex::new("Remote HTLC add would put them over our max HTLC value").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_cltv_expiry() {
	//BOLT2 Requirement: if sending node sets cltv_expiry to greater or equal to 500000000: SHOULD fail the channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let logger = test_utils::TestLogger::new();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000, InitFeatures::known(), InitFeatures::known());
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].cltv_expiry = 500000000;
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert_eq!(err_msg.data,"Remote provided CLTV expiry in seconds instead of block height");
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_add_htlc_bolt2_receiver_check_repeated_id_ignore() {
	//BOLT 2 requirement: if the sender did not previously acknowledge the commitment of that HTLC: MUST ignore a repeated id value after a reconnection.
	// We test this by first testing that that repeated HTLCs pass commitment signature checks
	// after disconnect and that non-sequential htlc_ids result in a channel failure.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let logger = test_utils::TestLogger::new();

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	//Disconnect and Reconnect
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	//Resend HTLC
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	assert_eq!(updates.commitment_signed.htlc_signatures.len(), 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	let _bs_responses = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	assert!(nodes[1].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[1], true).unwrap();
	assert!(regex::Regex::new(r"Remote skipped HTLC ID \(skipped ID: \d+\)").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fulfill_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let logger = test_utils::TestLogger::new();
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();

	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	let update_msg = msgs::UpdateFulfillHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		payment_preimage: our_payment_preimage,
	};

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to fulfill/fail HTLC \(\d+\) before it had been committed").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fail_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);

	let update_msg = msgs::UpdateFailHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		reason: msgs::OnionErrorPacket { data: Vec::new()},
	};

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to fulfill/fail HTLC \(\d+\) before it had been committed").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_update_fulfill_htlc_bolt2_update_fail_malformed_htlc_before_commitment() {
	//BOLT 2 Requirement: until the corresponding HTLC is irrevocably committed in both sides' commitment transactions:	MUST NOT send an update_fulfill_htlc, update_fail_htlc, or update_fail_malformed_htlc.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	let update_msg = msgs::UpdateFailMalformedHTLC{
		channel_id: chan.2,
		htlc_id: 0,
		sha256_of_onion: [1; 32],
		failure_code: 0x8000,
	};

	nodes[0].node.handle_update_fail_malformed_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to fulfill/fail HTLC \(\d+\) before it had been committed").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_update_fulfill_htlc_bolt2_incorrect_htlc_id() {
	//BOLT 2 Requirement: A receiving node:	if the id does not correspond to an HTLC in its current commitment transaction MUST fail the channel.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let our_payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 100000).0;

	nodes[1].node.claim_funds(our_payment_preimage, &None, 100_000);
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut update_fulfill_msg: msgs::UpdateFulfillHTLC = {
		match events[0] {
			MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, .. } } => {
				assert!(update_add_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
				assert!(update_fee.is_none());
				update_fulfill_htlcs[0].clone()
			},
			_ => panic!("Unexpected event"),
		}
	};

	update_fulfill_msg.htlc_id = 1;

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert_eq!(err_msg.data, "Remote tried to fulfill/fail an HTLC we couldn't find");
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_update_fulfill_htlc_bolt2_wrong_preimage() {
	//BOLT 2 Requirement: A receiving node:	if the payment_preimage value in update_fulfill_htlc doesn't SHA256 hash to the corresponding HTLC payment_hash	MUST fail the channel.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let our_payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 100000).0;

	nodes[1].node.claim_funds(our_payment_preimage, &None, 100_000);
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut update_fulfill_msg: msgs::UpdateFulfillHTLC = {
		match events[0] {
			MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, .. } } => {
				assert!(update_add_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
				assert!(update_fee.is_none());
				update_fulfill_htlcs[0].clone()
			},
			_ => panic!("Unexpected event"),
		}
	};

	update_fulfill_msg.payment_preimage = PaymentPreimage([1; 32]);

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert!(regex::Regex::new(r"Remote tried to fulfill HTLC \(\d+\) with an incorrect preimage").unwrap().is_match(err_msg.data.as_str()));
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_update_fulfill_htlc_bolt2_missing_badonion_bit_for_malformed_htlc_message() {
	//BOLT 2 Requirement: A receiving node: if the BADONION bit in failure_code is not set for update_fail_malformed_htlc MUST fail the channel.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[1].node.get_our_node_id(), None, None, &[], 1000000, TEST_FINAL_CLTV, &logger).unwrap();
	nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	updates.update_add_htlcs[0].onion_routing_packet.version = 1; //Produce a malformed HTLC message

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], updates.commitment_signed, false, true);

	let events = nodes[1].node.get_and_clear_pending_msg_events();

	let mut update_msg: msgs::UpdateFailMalformedHTLC = {
		match events[0] {
			MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, .. } } => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fulfill_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert_eq!(update_fail_malformed_htlcs.len(), 1);
				assert!(update_fee.is_none());
				update_fail_malformed_htlcs[0].clone()
			},
			_ => panic!("Unexpected event"),
		}
	};
	update_msg.failure_code &= !0x8000;
	nodes[0].node.handle_update_fail_malformed_htlc(&nodes[1].node.get_our_node_id(), &update_msg);

	assert!(nodes[0].node.list_channels().is_empty());
	let err_msg = check_closed_broadcast!(nodes[0], true).unwrap();
	assert_eq!(err_msg.data, "Got update_fail_malformed_htlc with BADONION not set");
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_update_fulfill_htlc_bolt2_after_malformed_htlc_message_must_forward_update_fail_htlc() {
	//BOLT 2 Requirement: a receiving node which has an outgoing HTLC canceled by update_fail_malformed_htlc:
	//    * MUST return an error in the update_fail_htlc sent to the link which originally sent the HTLC, using the failure_code given and setting the data to sha256_of_onion.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1000000, 1000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (_, our_payment_hash) = get_payment_preimage_hash!(nodes[0]);

	//First hop
	let mut payment_event = {
		let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
		let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &Vec::new(), 100000, TEST_FINAL_CLTV, &logger).unwrap();
		nodes[0].node.send_payment(&route, our_payment_hash, &None).unwrap();
		check_added_monitors!(nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	check_added_monitors!(nodes[1], 1);
	payment_event = SendEvent::from_event(events_2.remove(0));
	assert_eq!(payment_event.msgs.len(), 1);

	//Second Hop
	payment_event.msgs[0].onion_routing_packet.version = 1; //Produce a malformed HTLC message
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[2], 0);
	commitment_signed_dance!(nodes[2], nodes[1], payment_event.commitment_msg, false, true);

	let events_3 = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	let update_msg : (msgs::UpdateFailMalformedHTLC, msgs::CommitmentSigned) = {
		match events_3[0] {
			MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fulfill_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert_eq!(update_fail_malformed_htlcs.len(), 1);
				assert!(update_fee.is_none());
				(update_fail_malformed_htlcs[0].clone(), commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		}
	};

	nodes[1].node.handle_update_fail_malformed_htlc(&nodes[2].node.get_our_node_id(), &update_msg.0);

	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[2], update_msg.1, false, true);
	expect_pending_htlcs_forwardable!(nodes[1]);
	let events_4 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_4.len(), 1);

	//Confirm that handlinge the update_malformed_htlc message produces an update_fail_htlc message to be forwarded back along the route
	match events_4[0] {
		MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, .. } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
		},
		_ => panic!("Unexpected event"),
	};

	check_added_monitors!(nodes[1], 1);
}

fn do_test_failure_delay_dust_htlc_local_commitment(announce_latest: bool) {
	// Dust-HTLC failure updates must be delayed until failure-trigger tx (in this case local commitment) reach ANTI_REORG_DELAY
	// We can have at most two valid local commitment tx, so both cases must be covered, and both txs must be checked to get them all as
	// HTLC could have been removed from lastest local commitment tx but still valid until we get remote RAA

	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan =create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let bs_dust_limit = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().holder_dust_limit_satoshis;

	// We route 2 dust-HTLCs between A and B
	let (_, payment_hash_1) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	let (_, payment_hash_2) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Cache one local commitment tx as previous
	let as_prev_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);

	// Fail one HTLC to prune it in the will-be-latest-local commitment tx
	assert!(nodes[1].node.fail_htlc_backwards(&payment_hash_2, &None));
	check_added_monitors!(nodes[1], 0);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let remove = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &remove.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &remove.commitment_signed);
	check_added_monitors!(nodes[0], 1);

	// Cache one local commitment tx as lastest
	let as_last_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::SendRevokeAndACK { node_id, .. } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::UpdateHTLCs { node_id, .. } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
		},
		_ => panic!("Unexpected event"),
	}

	assert_ne!(as_prev_commitment_tx, as_last_commitment_tx);
	// Fail the 2 dust-HTLCs, move their failure in maturation buffer (htlc_updated_waiting_threshold_conf)
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };

	if announce_latest {
		connect_block(&nodes[0], &Block { header, txdata: vec![as_last_commitment_tx[0].clone()]}, 1);
	} else {
		connect_block(&nodes[0], &Block { header, txdata: vec![as_prev_commitment_tx[0].clone()]}, 1);
	}

	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);

	assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 1, true,  header.block_hash());
	let events = nodes[0].node.get_and_clear_pending_events();
	// Only 2 PaymentFailed events should show up, over-dust HTLC has to be failed by timeout tx
	assert_eq!(events.len(), 2);
	let mut first_failed = false;
	for event in events {
		match event {
			Event::PaymentFailed { payment_hash, .. } => {
				if payment_hash == payment_hash_1 {
					assert!(!first_failed);
					first_failed = true;
				} else {
					assert_eq!(payment_hash, payment_hash_2);
				}
			}
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_failure_delay_dust_htlc_local_commitment() {
	do_test_failure_delay_dust_htlc_local_commitment(true);
	do_test_failure_delay_dust_htlc_local_commitment(false);
}

fn do_test_sweep_outbound_htlc_failure_update(revoked: bool, local: bool) {
	// Outbound HTLC-failure updates must be cancelled if we get a reorg before we reach ANTI_REORG_DELAY.
	// Broadcast of revoked remote commitment tx, trigger failure-update of dust/non-dust HTLCs
	// Broadcast of remote commitment tx, trigger failure-update of dust-HTLCs
	// Broadcast of timeout tx on remote commitment tx, trigger failure-udate of non-dust HTLCs
	// Broadcast of local commitment tx, trigger failure-update of dust-HTLCs
	// Broadcast of HTLC-timeout tx on local commitment tx, trigger failure-update of non-dust HTLCs

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let bs_dust_limit = nodes[1].node.channel_state.lock().unwrap().by_id.get(&chan.2).unwrap().holder_dust_limit_satoshis;

	let (_payment_preimage_1, dust_hash) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit*1000);
	let (_payment_preimage_2, non_dust_hash) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	let as_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);
	let bs_commitment_tx = get_local_commitment_txn!(nodes[1], chan.2);

	// We revoked bs_commitment_tx
	if revoked {
		let (payment_preimage_3, _) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
		claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_3, 1_000_000);
	}

	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	let mut timeout_tx = Vec::new();
	if local {
		// We fail dust-HTLC 1 by broadcast of local commitment tx
		connect_block(&nodes[0], &Block { header, txdata: vec![as_commitment_tx[0].clone()]}, 1);
		check_closed_broadcast!(nodes[0], false);
		check_added_monitors!(nodes[0], 1);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		timeout_tx.push(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone());
		let parent_hash  = connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 2, true, header.block_hash());
		expect_payment_failed!(nodes[0], dust_hash, true);
		assert_eq!(timeout_tx[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		// We fail non-dust-HTLC 2 by broadcast of local HTLC-timeout tx on local commitment tx
		let header_2 = BlockHeader { version: 0x20000000, prev_blockhash: parent_hash, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		connect_block(&nodes[0], &Block { header: header_2, txdata: vec![timeout_tx[0].clone()]}, 7);
		let header_3 = BlockHeader { version: 0x20000000, prev_blockhash: header_2.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 8, true, header_3.block_hash());
		expect_payment_failed!(nodes[0], non_dust_hash, true);
	} else {
		// We fail dust-HTLC 1 by broadcast of remote commitment tx. If revoked, fail also non-dust HTLC
		connect_block(&nodes[0], &Block { header, txdata: vec![bs_commitment_tx[0].clone()]}, 1);
		check_closed_broadcast!(nodes[0], false);
		check_added_monitors!(nodes[0], 1);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		timeout_tx.push(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone());
		let parent_hash  = connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 2, true, header.block_hash());
		let header_2 = BlockHeader { version: 0x20000000, prev_blockhash: parent_hash, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		if !revoked {
			expect_payment_failed!(nodes[0], dust_hash, true);
			assert_eq!(timeout_tx[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
			// We fail non-dust-HTLC 2 by broadcast of local timeout tx on remote commitment tx
			connect_block(&nodes[0], &Block { header: header_2, txdata: vec![timeout_tx[0].clone()]}, 7);
			assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
			let header_3 = BlockHeader { version: 0x20000000, prev_blockhash: header_2.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
			connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 8, true, header_3.block_hash());
			expect_payment_failed!(nodes[0], non_dust_hash, true);
		} else {
			// If revoked, both dust & non-dust HTLCs should have been failed after ANTI_REORG_DELAY confs of revoked
			// commitment tx
			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 2);
			let first;
			match events[0] {
				Event::PaymentFailed { payment_hash, .. } => {
					if payment_hash == dust_hash { first = true; }
					else { first = false; }
				},
				_ => panic!("Unexpected event"),
			}
			match events[1] {
				Event::PaymentFailed { payment_hash, .. } => {
					if first { assert_eq!(payment_hash, non_dust_hash); }
					else { assert_eq!(payment_hash, dust_hash); }
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

#[test]
fn test_sweep_outbound_htlc_failure_update() {
	do_test_sweep_outbound_htlc_failure_update(false, true);
	do_test_sweep_outbound_htlc_failure_update(false, false);
	do_test_sweep_outbound_htlc_failure_update(true, false);
}

#[test]
fn test_upfront_shutdown_script() {
	// BOLT 2 : Option upfront shutdown script, if peer commit its closing_script at channel opening
	// enforce it at shutdown message

	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// We test that in case of peer committing upfront to a script, if it changes at closing, we refuse to sign
	let flags = InitFeatures::known();
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	// Test we enforce upfront_scriptpbukey if by providing a diffrent one at closing that  we disconnect peer
	nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
    assert!(regex::Regex::new(r"Got shutdown request with a scriptpubkey \([A-Fa-f0-9]+\) which did not match their previous scriptpubkey.").unwrap().is_match(check_closed_broadcast!(nodes[2], true).unwrap().data.as_str()));
	check_added_monitors!(nodes[2], 1);

	// We test that in case of peer committing upfront to a script, if it doesn't change at closing, we sign
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());
	// We test that in case of peer committing upfront to a script, if it oesn't change at closing, we sign
	nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[0].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	// We test that if case of peer non-signaling we don't enforce committed script at channel opening
	let flags_no = InitFeatures::known().clear_upfront_shutdown_script();
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, flags_no, flags.clone());
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id()).unwrap();
	let mut node_1_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	node_1_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[0].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	// channel smoothly, opt-out is from channel initiator here
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	//// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	//// channel smoothly
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, flags.clone(), flags.clone());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_upfront_shutdown_script_unsupport_segwit() {
	// We test that channel is closed early
	// if a segwit program is passed as upfront shutdown script,
	// but the peer does not support segwit.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();

	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	open_channel.shutdown_scriptpubkey = Present(Builder::new().push_int(16)
		.push_slice(&[0, 0])
		.into_script());

	let features = InitFeatures::known().clear_shutdown_anysegwit();
	nodes[0].node.handle_open_channel(&nodes[0].node.get_our_node_id(), features, &open_channel);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert!(regex::Regex::new(r"Peer is signaling upfront_shutdown but has provided a non-accepted scriptpubkey format. script: (\([A-Fa-f0-9]+\))").unwrap().is_match(&*msg.data));
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_shutdown_script_any_segwit_allowed() {
	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	//// We test if the remote peer accepts opt_shutdown_anysegwit, a witness program can be used on shutdown
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, InitFeatures::known(), InitFeatures::known());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_int(16)
		.push_slice(&[0, 0])
		.into_script();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_shutdown_script_any_segwit_not_allowed() {
	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	//// We test that if the remote peer does not accept opt_shutdown_anysegwit, the witness program cannot be used on shutdown
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, InitFeatures::known(), InitFeatures::known());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	// Make an any segwit version script
	node_0_shutdown.scriptpubkey = Builder::new().push_int(16)
		.push_slice(&[0, 0])
		.into_script();
	let flags_no = InitFeatures::known().clear_shutdown_anysegwit();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &flags_no, &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[1] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			assert_eq!(msg.data, "Got a nonstandard scriptpubkey (60020000) from remote peer".to_owned())
		},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_shutdown_script_segwit_but_not_anysegwit() {
	let mut config = UserConfig::default();
	config.channel_options.announced_channel = true;
	config.peer_channel_config_limits.force_announced_channel_preference = false;
	config.channel_options.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	//// We test that if shutdown any segwit is supported and we send a witness script with 0 version, this is not accepted
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, InitFeatures::known(), InitFeatures::known());
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id()).unwrap();
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	// Make a segwit script that is not a valid as any segwit
	node_0_shutdown.scriptpubkey = Builder::new().push_int(0)
		.push_slice(&[0, 0])
		.into_script();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[1] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			assert_eq!(msg.data, "Got a nonstandard scriptpubkey (00020000) from remote peer".to_owned())
		},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_user_configurable_csv_delay() {
	// We test our channel constructors yield errors when we pass them absurd csv delay

	let mut low_our_to_self_config = UserConfig::default();
	low_our_to_self_config.own_channel_config.our_to_self_delay = 6;
	let mut high_their_to_self_config = UserConfig::default();
	high_their_to_self_config.peer_channel_config_limits.their_to_self_delay = 100;
	let user_cfgs = [Some(high_their_to_self_config.clone()), None];
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// We test config.our_to_self > BREAKDOWN_TIMEOUT is enforced in Channel::new_outbound()
	if let Err(error) = Channel::new_outbound(&&test_utils::TestFeeEstimator { sat_per_kw: 253 }, &nodes[0].keys_manager, nodes[1].node.get_our_node_id(), 1000000, 1000000, 0, &low_our_to_self_config) {
		match error {
			APIError::APIMisuseError { err } => { assert!(regex::Regex::new(r"Configured with an unreasonable our_to_self_delay \(\d+\) putting user funds at risks").unwrap().is_match(err.as_str())); },
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false) }

	// We test config.our_to_self > BREAKDOWN_TIMEOUT is enforced in Channel::new_from_req()
	nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 1000000, 1000000, 42, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());
	open_channel.to_self_delay = 200;
	if let Err(error) = Channel::new_from_req(&&test_utils::TestFeeEstimator { sat_per_kw: 253 }, &nodes[0].keys_manager, nodes[1].node.get_our_node_id(), InitFeatures::known(), &open_channel, 0, &low_our_to_self_config) {
		match error {
			ChannelError::Close(err) => { assert!(regex::Regex::new(r"Configured with an unreasonable our_to_self_delay \(\d+\) putting user funds at risks").unwrap().is_match(err.as_str()));  },
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false); }

	// We test msg.to_self_delay <= config.their_to_self_delay is enforced in Chanel::accept_channel()
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 1000000, 1000000, 42, None).unwrap();
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id()));
	let mut accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	accept_channel.to_self_delay = 200;
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &accept_channel);
	if let MessageSendEvent::HandleError { ref action, .. } = nodes[0].node.get_and_clear_pending_msg_events()[0] {
		match action {
			&ErrorAction::SendErrorMessage { ref msg } => {
				assert!(regex::Regex::new(r"They wanted our payments to be delayed by a needlessly long period\. Upper limit: \d+\. Actual: \d+").unwrap().is_match(msg.data.as_str()));
			},
			_ => { assert!(false); }
		}
	} else { assert!(false); }

	// We test msg.to_self_delay <= config.their_to_self_delay is enforced in Channel::new_from_req()
	nodes[1].node.create_channel(nodes[0].node.get_our_node_id(), 1000000, 1000000, 42, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[1], MessageSendEvent::SendOpenChannel, nodes[0].node.get_our_node_id());
	open_channel.to_self_delay = 200;
	if let Err(error) = Channel::new_from_req(&&test_utils::TestFeeEstimator { sat_per_kw: 253 }, &nodes[0].keys_manager, nodes[1].node.get_our_node_id(), InitFeatures::known(), &open_channel, 0, &high_their_to_self_config) {
		match error {
			ChannelError::Close(err) => { assert!(regex::Regex::new(r"They wanted our payments to be delayed by a needlessly long period\. Upper limit: \d+\. Actual: \d+").unwrap().is_match(err.as_str())); },
			_ => panic!("Unexpected event"),
		}
	} else { assert!(false); }
}

#[test]
fn test_data_loss_protect() {
	// We want to be sure that :
	// * we don't broadcast our Local Commitment Tx in case of fallen behind
	//   (but this is not quite true - we broadcast during Drop because chanmon is out of sync with chanmgr)
	// * we close channel in case of detecting other being fallen behind
	// * we are able to claim our own outputs thanks to to_remote being static
	// TODO: this test is incomplete and the data_loss_protect implementation is incomplete - see issue #775
	let persister;
	let logger;
	let fee_estimator;
	let tx_broadcaster;
	let chain_source;
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	// We broadcast during Drop because chanmon is out of sync with chanmgr, which would cause a panic
	// during signing due to revoked tx
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	let monitor;
	let node_state_0;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000, InitFeatures::known(), InitFeatures::known());

	// Cache node A state before any channel update
	let previous_node_state = nodes[0].node.encode();
	let mut previous_chain_monitor_state = test_utils::TestVecWriter(Vec::new());
	nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().iter().next().unwrap().1.write(&mut previous_chain_monitor_state).unwrap();

	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000, 8_000_000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	// Restore node A from previous state
	logger = test_utils::TestLogger::with_id(format!("node {}", 0));
	let mut chain_monitor = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(&mut ::std::io::Cursor::new(previous_chain_monitor_state.0), keys_manager).unwrap().1;
	chain_source = test_utils::TestChainSource::new(Network::Testnet);
	tx_broadcaster = test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new())};
	fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 253 };
	persister = test_utils::TestPersister::new();
	monitor = test_utils::TestChainMonitor::new(Some(&chain_source), &tx_broadcaster, &logger, &fee_estimator, &persister, keys_manager);
	node_state_0 = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(OutPoint { txid: chan.3.txid(), index: 0 }, &mut chain_monitor);
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut ::std::io::Cursor::new(previous_node_state), ChannelManagerReadArgs {
			keys_manager: keys_manager,
			fee_estimator: &fee_estimator,
			chain_monitor: &monitor,
			logger: &logger,
			tx_broadcaster: &tx_broadcaster,
			default_config: UserConfig::default(),
			channel_monitors,
		}).unwrap().1
	};
	nodes[0].node = &node_state_0;
	assert!(monitor.watch_channel(OutPoint { txid: chan.3.txid(), index: 0 }, chain_monitor).is_ok());
	nodes[0].chain_monitor = &monitor;
	nodes[0].chain_source = &chain_source;

	check_added_monitors!(nodes[0], 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });

	let reestablish_0 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);

	// Check we don't broadcast any transactions following learning of per_commitment_point from B
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_0[0]);
	check_added_monitors!(nodes[0], 1);

	{
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
		assert_eq!(node_txn.len(), 0);
	}

	let mut reestablish_1 = Vec::with_capacity(1);
	for msg in nodes[0].node.get_and_clear_pending_msg_events() {
		if let MessageSendEvent::SendChannelReestablish { ref node_id, ref msg } = msg {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			reestablish_1.push(msg.clone());
		} else if let MessageSendEvent::BroadcastChannelUpdate { .. } = msg {
		} else if let MessageSendEvent::HandleError { ref action, .. } = msg {
			match action {
				&ErrorAction::SendErrorMessage { ref msg } => {
					assert_eq!(msg.data, "We have fallen behind - we have received proof that if we broadcast remote is going to claim our funds - we can't do any automated broadcasting");
				},
				_ => panic!("Unexpected event!"),
			}
		} else {
			panic!("Unexpected event")
		}
	}

	// Check we close channel detecting A is fallen-behind
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	assert_eq!(check_closed_broadcast!(nodes[1], true).unwrap().data, "Peer attempted to reestablish channel with a very old local commitment transaction");
	check_added_monitors!(nodes[1], 1);


	// Check A is able to claim to_remote output
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3);
	assert_eq!(node_txn[0].output.len(), 2);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
	connect_block(&nodes[0], &Block { header, txdata: vec![node_txn[0].clone()]}, 0);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 0, true, header.block_hash());
	let spend_txn = check_spendable_outputs!(nodes[0], 1, node_cfgs[0].keys_manager, 1000000);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[test]
fn test_check_htlc_underpaying() {
	// Send payment through A -> B but A is maliciously
	// sending a probe payment (i.e less than expected value0
	// to B, B should refuse payment.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let (payment_preimage, payment_hash) = route_payment(&nodes[0], &[&nodes[1]], 10_000);

	// Node 3 is expecting payment of 100_000 but receive 10_000,
	// fail htlc like we didn't know the preimage.
	nodes[1].node.claim_funds(payment_preimage, &None, 100_000);
	nodes[1].node.process_pending_htlc_forwards();

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_fail_htlc, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
			(update_fail_htlcs[0].clone(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlc);
	commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

	// 10_000 msat as u64, followed by a height of CHAN_CONFIRM_DEPTH as u32
	let mut expected_failure_data = byte_utils::be64_to_array(10_000).to_vec();
	expected_failure_data.extend_from_slice(&byte_utils::be32_to_array(CHAN_CONFIRM_DEPTH));
	expect_payment_failed!(nodes[0], payment_hash, true, 0x4000|15, &expected_failure_data[..]);
	nodes[1].node.get_and_clear_pending_events();
}

#[test]
fn test_announce_disable_channels() {
	// Create 2 channels between A and B. Disconnect B. Call timer_chan_freshness_every_min and check for generated
	// ChannelUpdate. Reconnect B, reestablish and check there is non-generated ChannelUpdate.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let short_id_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let short_id_2 = create_announced_chan_between_nodes(&nodes, 1, 0, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let short_id_3 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;

	// Disconnect peers
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	nodes[0].node.timer_chan_freshness_every_min(); // dirty -> stagged
	nodes[0].node.timer_chan_freshness_every_min(); // staged -> fresh
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3);
	for e in msg_events {
		match e {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				let short_id = msg.contents.short_channel_id;
				// Check generated channel_update match list in PendingChannelUpdate
				if short_id != short_id_1 && short_id != short_id_2 && short_id != short_id_3 {
					panic!("Generated ChannelUpdate for wrong chan!");
				}
			},
			_ => panic!("Unexpected event"),
		}
	}
	// Reconnect peers
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 3);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::empty() });
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 3);

	// Reestablish chan_1
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
	// Reestablish chan_2
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[1]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[1]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
	// Reestablish chan_3
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[2]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[2]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	nodes[0].node.timer_chan_freshness_every_min();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
}

#[test]
fn test_bump_penalty_txn_on_revoked_commitment() {
	// In case of penalty txn with too low feerates for getting into mempools, RBF-bump them to be sure
	// we're able to claim outputs on revoked commitment transaction before timelocks expiration

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
	let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &Vec::new(), 3000000, 30, &logger).unwrap();
	send_along_route(&nodes[1], route, &vec!(&nodes[0])[..], 3000000);

	let revoked_txn = get_local_commitment_txn!(nodes[0], chan.2);
	// Revoked commitment txn with 4 outputs : to_local, to_remote, 1 outgoing HTLC, 1 incoming HTLC
	assert_eq!(revoked_txn[0].output.len(), 4);
	assert_eq!(revoked_txn[0].input.len(), 1);
	assert_eq!(revoked_txn[0].input[0].previous_output.txid, chan.3.txid());
	let revoked_txid = revoked_txn[0].txid();

	let mut penalty_sum = 0;
	for outp in revoked_txn[0].output.iter() {
		if outp.script_pubkey.is_v0_p2wsh() {
			penalty_sum += outp.value;
		}
	}

	// Connect blocks to change height_timer range to see if we use right soonest_timelock
	let starting_height = nodes[1].best_block_info().1;
	let header_114 = connect_blocks(&nodes[1], 14, starting_height, false, Default::default());

	// Actually revoke tx by claiming a HTLC
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage, 3_000_000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: header_114, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_txn[0].clone()] }, 15 + starting_height);
	check_added_monitors!(nodes[1], 1);

	// One or more justice tx should have been broadcast, check it
	let penalty_1;
	let feerate_1;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 3); // justice tx (broadcasted from ChannelMonitor) + local commitment tx + local HTLC-timeout (broadcasted from ChannelManager)
		assert_eq!(node_txn[0].input.len(), 3); // Penalty txn claims to_local, offered_htlc and received_htlc outputs
		assert_eq!(node_txn[0].output.len(), 1);
		check_spends!(node_txn[0], revoked_txn[0]);
		let fee_1 = penalty_sum - node_txn[0].output[0].value;
		feerate_1 = fee_1 * 1000 / node_txn[0].get_weight() as u64;
		penalty_1 = node_txn[0].txid();
		node_txn.clear();
	};

	// After exhaustion of height timer, a new bumped justice tx should have been broadcast, check it
	let header = connect_blocks(&nodes[1], 15, 15 + starting_height,  true, header.block_hash());
	let mut penalty_2 = penalty_1;
	let mut feerate_2 = 0;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		if node_txn[0].input[0].previous_output.txid == revoked_txid {
			assert_eq!(node_txn[0].input.len(), 3); // Penalty txn claims to_local, offered_htlc and received_htlc outputs
			assert_eq!(node_txn[0].output.len(), 1);
			check_spends!(node_txn[0], revoked_txn[0]);
			penalty_2 = node_txn[0].txid();
			// Verify new bumped tx is different from last claiming transaction, we don't want spurrious rebroadcast
			assert_ne!(penalty_2, penalty_1);
			let fee_2 = penalty_sum - node_txn[0].output[0].value;
			feerate_2 = fee_2 * 1000 / node_txn[0].get_weight() as u64;
			// Verify 25% bump heuristic
			assert!(feerate_2 * 100 >= feerate_1 * 125);
			node_txn.clear();
		}
	}
	assert_ne!(feerate_2, 0);

	// After exhaustion of height timer for a 2nd time, a new bumped justice tx should have been broadcast, check it
	connect_blocks(&nodes[1], 1, 30 + starting_height, true, header);
	let penalty_3;
	let mut feerate_3 = 0;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		if node_txn[0].input[0].previous_output.txid == revoked_txid {
			assert_eq!(node_txn[0].input.len(), 3); // Penalty txn claims to_local, offered_htlc and received_htlc outputs
			assert_eq!(node_txn[0].output.len(), 1);
			check_spends!(node_txn[0], revoked_txn[0]);
			penalty_3 = node_txn[0].txid();
			// Verify new bumped tx is different from last claiming transaction, we don't want spurrious rebroadcast
			assert_ne!(penalty_3, penalty_2);
			let fee_3 = penalty_sum - node_txn[0].output[0].value;
			feerate_3 = fee_3 * 1000 / node_txn[0].get_weight() as u64;
			// Verify 25% bump heuristic
			assert!(feerate_3 * 100 >= feerate_2 * 125);
			node_txn.clear();
		}
	}
	assert_ne!(feerate_3, 0);

	nodes[1].node.get_and_clear_pending_events();
	nodes[1].node.get_and_clear_pending_msg_events();
}

#[test]
fn test_bump_penalty_txn_on_revoked_htlcs() {
	// In case of penalty txn with too low feerates for getting into mempools, RBF-bump them to sure
	// we're able to claim outputs on revoked HTLC transactions before timelocks expiration

	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000, InitFeatures::known(), InitFeatures::known());
	// Lock HTLC in both directions
	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3_000_000).0;
	route_payment(&nodes[1], &vec!(&nodes[0])[..], 3_000_000).0;

	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.txid());

	// Revoke local commitment tx
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage, 3_000_000);

	let header = BlockHeader { version: 0x20000000, prev_blockhash: nodes[1].best_block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	// B will generate both revoked HTLC-timeout/HTLC-preimage txn from revoked commitment tx
	connect_block(&nodes[1], &Block { header, txdata: vec![revoked_local_txn[0].clone()] }, CHAN_CONFIRM_DEPTH + 1);
	check_closed_broadcast!(nodes[1], false);
	check_added_monitors!(nodes[1], 1);

	let revoked_htlc_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
	assert_eq!(revoked_htlc_txn.len(), 4);
	if revoked_htlc_txn[0].input[0].witness.last().unwrap().len() == ACCEPTED_HTLC_SCRIPT_WEIGHT {
		assert_eq!(revoked_htlc_txn[0].input.len(), 1);
		check_spends!(revoked_htlc_txn[0], revoked_local_txn[0]);
		assert_eq!(revoked_htlc_txn[1].input.len(), 1);
		assert_eq!(revoked_htlc_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		assert_eq!(revoked_htlc_txn[1].output.len(), 1);
		check_spends!(revoked_htlc_txn[1], revoked_local_txn[0]);
	} else if revoked_htlc_txn[1].input[0].witness.last().unwrap().len() == ACCEPTED_HTLC_SCRIPT_WEIGHT {
		assert_eq!(revoked_htlc_txn[1].input.len(), 1);
		check_spends!(revoked_htlc_txn[1], revoked_local_txn[0]);
		assert_eq!(revoked_htlc_txn[0].input.len(), 1);
		assert_eq!(revoked_htlc_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		assert_eq!(revoked_htlc_txn[0].output.len(), 1);
		check_spends!(revoked_htlc_txn[0], revoked_local_txn[0]);
	}

	// Broadcast set of revoked txn on A
	let hash_128 = connect_blocks(&nodes[0], 40, CHAN_CONFIRM_DEPTH, false, Default::default());
	let header_11 = BlockHeader { version: 0x20000000, prev_blockhash: hash_128, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_11, txdata: vec![revoked_local_txn[0].clone()] }, CHAN_CONFIRM_DEPTH + 40 + 1);
	let header_129 = BlockHeader { version: 0x20000000, prev_blockhash: header_11.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_129, txdata: vec![revoked_htlc_txn[0].clone(), revoked_htlc_txn[1].clone()] }, CHAN_CONFIRM_DEPTH + 40 + 2);
	expect_pending_htlcs_forwardable_ignore!(nodes[0]);
	let first;
	let feerate_1;
	let penalty_txn;
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 5); // 3 penalty txn on revoked commitment tx + A commitment tx + 1 penalty tnx on revoked HTLC txn
		// Verify claim tx are spending revoked HTLC txn

		// node_txn 0-2 each spend a separate revoked output from revoked_local_txn[0]
		// Note that node_txn[0] and node_txn[1] are bogus - they double spend the revoked_htlc_txn
		// which are included in the same block (they are broadcasted because we scan the
		// transactions linearly and generate claims as we go, they likely should be removed in the
		// future).
		assert_eq!(node_txn[0].input.len(), 1);
		check_spends!(node_txn[0], revoked_local_txn[0]);
		assert_eq!(node_txn[1].input.len(), 1);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		assert_eq!(node_txn[2].input.len(), 1);
		check_spends!(node_txn[2], revoked_local_txn[0]);

		// Each of the three justice transactions claim a separate (single) output of the three
		// available, which we check here:
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[2].input[0].previous_output);
		assert_ne!(node_txn[1].input[0].previous_output, node_txn[2].input[0].previous_output);

		assert_eq!(node_txn[0].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
		assert_eq!(node_txn[1].input[0].previous_output, revoked_htlc_txn[1].input[0].previous_output);

		// node_txn[3] is the local commitment tx broadcast just because (and somewhat in case of
		// reorgs, though its not clear its ever worth broadcasting conflicting txn like this when
		// a remote commitment tx has already been confirmed).
		check_spends!(node_txn[3], chan.3);

		// node_txn[4] spends the revoked outputs from the revoked_htlc_txn (which only have one
		// output, checked above).
		assert_eq!(node_txn[4].input.len(), 2);
		assert_eq!(node_txn[4].output.len(), 1);
		check_spends!(node_txn[4], revoked_htlc_txn[0], revoked_htlc_txn[1]);

		first = node_txn[4].txid();
		// Store both feerates for later comparison
		let fee_1 = revoked_htlc_txn[0].output[0].value + revoked_htlc_txn[1].output[0].value - node_txn[4].output[0].value;
		feerate_1 = fee_1 * 1000 / node_txn[4].get_weight() as u64;
		penalty_txn = vec![node_txn[2].clone()];
		node_txn.clear();
	}

	// Connect one more block to see if bumped penalty are issued for HTLC txn
	let header_130 = BlockHeader { version: 0x20000000, prev_blockhash: header_129.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_130, txdata: penalty_txn }, CHAN_CONFIRM_DEPTH + 40 + 3);
	let header_131 = BlockHeader { version: 0x20000000, prev_blockhash: header_130.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_131, txdata: Vec::new() }, CHAN_CONFIRM_DEPTH + 40 + 4);
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 2); // 2 bumped penalty txn on revoked commitment tx

		check_spends!(node_txn[0], revoked_local_txn[0]);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		// Note that these are both bogus - they spend outputs already claimed in block 129:
		if node_txn[0].input[0].previous_output == revoked_htlc_txn[0].input[0].previous_output  {
			assert_eq!(node_txn[1].input[0].previous_output, revoked_htlc_txn[1].input[0].previous_output);
		} else {
			assert_eq!(node_txn[0].input[0].previous_output, revoked_htlc_txn[1].input[0].previous_output);
			assert_eq!(node_txn[1].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
		}

		node_txn.clear();
	};

	// Few more blocks to confirm penalty txn
	let header_135 = connect_blocks(&nodes[0], 4, CHAN_CONFIRM_DEPTH + 40 + 4, true, header_131.block_hash());
	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	let header_144 = connect_blocks(&nodes[0], 9, CHAN_CONFIRM_DEPTH + 40 + 8, true, header_135);
	let node_txn = {
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);

		assert_eq!(node_txn[0].input.len(), 2);
		check_spends!(node_txn[0], revoked_htlc_txn[0], revoked_htlc_txn[1]);
		// Verify bumped tx is different and 25% bump heuristic
		assert_ne!(first, node_txn[0].txid());
		let fee_2 = revoked_htlc_txn[0].output[0].value + revoked_htlc_txn[1].output[0].value - node_txn[0].output[0].value;
		let feerate_2 = fee_2 * 1000 / node_txn[0].get_weight() as u64;
		assert!(feerate_2 * 100 > feerate_1 * 125);
		let txn = vec![node_txn[0].clone()];
		node_txn.clear();
		txn
	};
	// Broadcast claim txn and confirm blocks to avoid further bumps on this outputs
	let header_145 = BlockHeader { version: 0x20000000, prev_blockhash: header_144, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_145, txdata: node_txn }, CHAN_CONFIRM_DEPTH + 40 + 8 + 10);
	connect_blocks(&nodes[0], 20, CHAN_CONFIRM_DEPTH + 40 + 8 + 10, true, header_145.block_hash());
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// We verify than no new transaction has been broadcast because previously
		// we were buggy on this exact behavior by not tracking for monitoring remote HTLC outputs (see #411)
		// which means we wouldn't see a spend of them by a justice tx and bumped justice tx
		// were generated forever instead of safe cleaning after confirmation and ANTI_REORG_SAFE_DELAY blocks.
		// Enforce spending of revoked htlc output by claiming transaction remove request as expected and dry
		// up bumped justice generation.
		assert_eq!(node_txn.len(), 0);
		node_txn.clear();
	}
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn test_bump_penalty_txn_on_remote_commitment() {
	// In case of claim txn with too low feerates for getting into mempools, RBF-bump them to be sure
	// we're able to claim outputs on remote commitment transaction before timelocks expiration

	// Create 2 HTLCs
	// Provide preimage for one
	// Check aggregation

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000, InitFeatures::known(), InitFeatures::known());
	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
	route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000).0;

	// Remote commitment txn with 4 outputs : to_local, to_remote, 1 outgoing HTLC, 1 incoming HTLC
	let remote_txn = get_local_commitment_txn!(nodes[0], chan.2);
	assert_eq!(remote_txn[0].output.len(), 4);
	assert_eq!(remote_txn[0].input.len(), 1);
	assert_eq!(remote_txn[0].input[0].previous_output.txid, chan.3.txid());

	// Claim a HTLC without revocation (provide B monitor with preimage)
	nodes[1].node.claim_funds(payment_preimage, &None, 3_000_000);
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![remote_txn[0].clone()] }, 1);
	check_added_monitors!(nodes[1], 2);

	// One or more claim tx should have been broadcast, check it
	let timeout;
	let preimage;
	let feerate_timeout;
	let feerate_preimage;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 5); // 2 * claim tx (broadcasted from ChannelMonitor) + local commitment tx + local HTLC-timeout + local HTLC-success (broadcasted from ChannelManager)
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		check_spends!(node_txn[1], remote_txn[0]);
		check_spends!(node_txn[2], chan.3);
		check_spends!(node_txn[3], node_txn[2]);
		check_spends!(node_txn[4], node_txn[2]);
		if node_txn[0].input[0].witness.last().unwrap().len() == ACCEPTED_HTLC_SCRIPT_WEIGHT {
			timeout = node_txn[0].txid();
			let index = node_txn[0].input[0].previous_output.vout;
			let fee = remote_txn[0].output[index as usize].value - node_txn[0].output[0].value;
			feerate_timeout = fee * 1000 / node_txn[0].get_weight() as u64;

			preimage = node_txn[1].txid();
			let index = node_txn[1].input[0].previous_output.vout;
			let fee = remote_txn[0].output[index as usize].value - node_txn[1].output[0].value;
			feerate_preimage = fee * 1000 / node_txn[1].get_weight() as u64;
		} else {
			timeout = node_txn[1].txid();
			let index = node_txn[1].input[0].previous_output.vout;
			let fee = remote_txn[0].output[index as usize].value - node_txn[1].output[0].value;
			feerate_timeout = fee * 1000 / node_txn[1].get_weight() as u64;

			preimage = node_txn[0].txid();
			let index = node_txn[0].input[0].previous_output.vout;
			let fee = remote_txn[0].output[index as usize].value - node_txn[0].output[0].value;
			feerate_preimage = fee * 1000 / node_txn[0].get_weight() as u64;
		}
		node_txn.clear();
	};
	assert_ne!(feerate_timeout, 0);
	assert_ne!(feerate_preimage, 0);

	// After exhaustion of height timer, new bumped claim txn should have been broadcast, check it
	connect_blocks(&nodes[1], 15, 1,  true, header.block_hash());
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 2);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		check_spends!(node_txn[1], remote_txn[0]);
		if node_txn[0].input[0].witness.last().unwrap().len() == ACCEPTED_HTLC_SCRIPT_WEIGHT {
			let index = node_txn[0].input[0].previous_output.vout;
			let fee = remote_txn[0].output[index as usize].value - node_txn[0].output[0].value;
			let new_feerate = fee * 1000 / node_txn[0].get_weight() as u64;
			assert!(new_feerate * 100 > feerate_timeout * 125);
			assert_ne!(timeout, node_txn[0].txid());

			let index = node_txn[1].input[0].previous_output.vout;
			let fee = remote_txn[0].output[index as usize].value - node_txn[1].output[0].value;
			let new_feerate = fee * 1000 / node_txn[1].get_weight() as u64;
			assert!(new_feerate * 100 > feerate_preimage * 125);
			assert_ne!(preimage, node_txn[1].txid());
		} else {
			let index = node_txn[1].input[0].previous_output.vout;
			let fee = remote_txn[0].output[index as usize].value - node_txn[1].output[0].value;
			let new_feerate = fee * 1000 / node_txn[1].get_weight() as u64;
			assert!(new_feerate * 100 > feerate_timeout * 125);
			assert_ne!(timeout, node_txn[1].txid());

			let index = node_txn[0].input[0].previous_output.vout;
			let fee = remote_txn[0].output[index as usize].value - node_txn[0].output[0].value;
			let new_feerate = fee * 1000 / node_txn[0].get_weight() as u64;
			assert!(new_feerate * 100 > feerate_preimage * 125);
			assert_ne!(preimage, node_txn[0].txid());
		}
		node_txn.clear();
	}

	nodes[1].node.get_and_clear_pending_events();
	nodes[1].node.get_and_clear_pending_msg_events();
}

#[test]
fn test_counterparty_raa_skip_no_crash() {
	// Previously, if our counterparty sent two RAAs in a row without us having provided a
	// commitment transaction, we would have happily carried on and provided them the next
	// commitment transaction based on one RAA forward. This would probably eventually have led to
	// channel closure, but it would not have resulted in funds loss. Still, our
	// EnforcingSigner would have paniced as it doesn't like jumps into the future. Here, we
	// check simply that the channel is closed in response to such an RAA, but don't check whether
	// we decide to punish our counterparty for revoking their funds (as we don't currently
	// implement that).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;

	let mut guard = nodes[0].node.channel_state.lock().unwrap();
	let keys = &guard.by_id.get_mut(&channel_id).unwrap().get_signer();
	const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;
	let per_commitment_secret = keys.release_commitment_secret(INITIAL_COMMITMENT_NUMBER);
	// Must revoke without gaps
	keys.release_commitment_secret(INITIAL_COMMITMENT_NUMBER - 1);
	let next_per_commitment_point = PublicKey::from_secret_key(&Secp256k1::new(),
		&SecretKey::from_slice(&keys.release_commitment_secret(INITIAL_COMMITMENT_NUMBER - 2)).unwrap());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(),
		&msgs::RevokeAndACK { channel_id, per_commitment_secret, next_per_commitment_point });
	assert_eq!(check_closed_broadcast!(nodes[1], true).unwrap().data, "Received an unexpected revoke_and_ack");
	check_added_monitors!(nodes[1], 1);
}

#[test]
fn test_bump_txn_sanitize_tracking_maps() {
	// Sanitizing pendning_claim_request and claimable_outpoints used to be buggy,
	// verify we clean then right after expiration of ANTI_REORG_DELAY.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000, InitFeatures::known(), InitFeatures::known());
	// Lock HTLC in both directions
	let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9_000_000).0;
	route_payment(&nodes[1], &vec!(&nodes[0])[..], 9_000_000).0;

	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.txid());

	// Revoke local commitment tx
	claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage, 9_000_000);

	// Broadcast set of revoked txn on A
	let header_128 = connect_blocks(&nodes[0], 128, 0,  false, Default::default());
	expect_pending_htlcs_forwardable_ignore!(nodes[0]);

	let header_129 = BlockHeader { version: 0x20000000, prev_blockhash: header_128, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_129, txdata: vec![revoked_local_txn[0].clone()] }, 129);
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);
	let penalty_txn = {
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 4); //ChannelMonitor: justice txn * 3, ChannelManager: local commitment tx
		check_spends!(node_txn[0], revoked_local_txn[0]);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		check_spends!(node_txn[2], revoked_local_txn[0]);
		let penalty_txn = vec![node_txn[0].clone(), node_txn[1].clone(), node_txn[2].clone()];
		node_txn.clear();
		penalty_txn
	};
	let header_130 = BlockHeader { version: 0x20000000, prev_blockhash: header_129.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_130, txdata: penalty_txn }, 130);
	connect_blocks(&nodes[0], 5, 130,  false, header_130.block_hash());
	{
		let monitors = nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap();
		if let Some(monitor) = monitors.get(&OutPoint { txid: chan.3.txid(), index: 0 }) {
			assert!(monitor.inner.lock().unwrap().onchain_tx_handler.pending_claim_requests.is_empty());
			assert!(monitor.inner.lock().unwrap().onchain_tx_handler.claimable_outpoints.is_empty());
		}
	}
}

#[test]
fn test_override_channel_config() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Node0 initiates a channel to node1 using the override config.
	let mut override_config = UserConfig::default();
	override_config.own_channel_config.our_to_self_delay = 200;

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 16_000_000, 12_000_000, 42, Some(override_config)).unwrap();

	// Assert the channel created by node0 is using the override config.
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert_eq!(res.channel_flags, 0);
	assert_eq!(res.to_self_delay, 200);
}

#[test]
fn test_override_0msat_htlc_minimum() {
	let mut zero_config = UserConfig::default();
	zero_config.own_channel_config.our_htlc_minimum_msat = 0;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(zero_config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 16_000_000, 12_000_000, 42, Some(zero_config)).unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	assert_eq!(res.htlc_minimum_msat, 1);

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &res);
	let res = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	assert_eq!(res.htlc_minimum_msat, 1);
}

#[test]
fn test_simple_payment_secret() {
	// Simple test of sending a payment with a payment_secret present. This does not use any AMP
	// features, however.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	let logger = test_utils::TestLogger::new();

	let (payment_preimage, payment_hash) = get_payment_preimage_hash!(&nodes[0]);
	let payment_secret = PaymentSecret([0xdb; 32]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	send_along_route_with_secret(&nodes[0], route, &[&[&nodes[1], &nodes[2]]], 100000, payment_hash, Some(payment_secret.clone()));
	// Claiming with all the correct values but the wrong secret should result in nothing...
	assert_eq!(nodes[2].node.claim_funds(payment_preimage, &None, 100_000), false);
	assert_eq!(nodes[2].node.claim_funds(payment_preimage, &Some(PaymentSecret([42; 32])), 100_000), false);
	// ...but with the right secret we should be able to claim all the way back
	claim_payment_along_route_with_secret(&nodes[0], &[&[&nodes[1], &nodes[2]]], false, payment_preimage, Some(payment_secret.clone()), 100_000);
}

#[test]
fn test_simple_mpp() {
	// Simple test of sending a multi-path payment.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let logger = test_utils::TestLogger::new();

	let (payment_preimage, payment_hash) = get_payment_preimage_hash!(&nodes[0]);
	let payment_secret = PaymentSecret([0xdb; 32]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let mut route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[3].node.get_our_node_id(), None, None, &[], 100000, TEST_FINAL_CLTV, &logger).unwrap();
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_id;
	route.paths[0][1].short_channel_id = chan_3_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_id;
	route.paths[1][1].short_channel_id = chan_4_id;
	send_along_route_with_secret(&nodes[0], route, &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], 200_000, payment_hash, Some(payment_secret.clone()));
	// Claiming with all the correct values but the wrong secret should result in nothing...
	assert_eq!(nodes[3].node.claim_funds(payment_preimage, &None, 200_000), false);
	assert_eq!(nodes[3].node.claim_funds(payment_preimage, &Some(PaymentSecret([42; 32])), 200_000), false);
	// ...but with the right secret we should be able to claim all the way back
	claim_payment_along_route_with_secret(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_preimage, Some(payment_secret), 200_000);
}

#[test]
fn test_update_err_monitor_lockdown() {
	// Our monitor will lock update of local commitment transaction if a broadcastion condition
	// has been fulfilled (either force-close from Channel or block height requiring a HTLC-
	// timeout). Trying to update monitor after lockdown should return a ChannelMonitorUpdateErr.
	//
	// This scenario may happen in a watchtower setup, where watchtower process a block height
	// triggering a timeout while a slow-block-processing ChannelManager receives a local signed
	// commitment at same time.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channel
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let outpoint = OutPoint { txid: chan_1.3.txid(), index: 0 };

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 10_000_000, 10_000_000);

	// Route a HTLC from node 0 to node 1 (but don't settle)
	let preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 9_000_000).0;

	// Copy ChainMonitor to simulate a watchtower and update block height of node 0 until its ChannelMonitor timeout HTLC onchain
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", 0));
	let persister = test_utils::TestPersister::new();
	let watchtower = {
		let monitors = nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap();
		let monitor = monitors.get(&outpoint).unwrap();
		let mut w = test_utils::TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<EnforcingSigner>)>::read(
				&mut ::std::io::Cursor::new(&w.0), &test_utils::OnlyReadsKeysInterface {}).unwrap().1;
		assert!(new_monitor == *monitor);
		let watchtower = test_utils::TestChainMonitor::new(Some(&chain_source), &chanmon_cfgs[0].tx_broadcaster, &logger, &chanmon_cfgs[0].fee_estimator, &persister, &node_cfgs[0].keys_manager);
		assert!(watchtower.watch_channel(outpoint, new_monitor).is_ok());
		watchtower
	};
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	watchtower.chain_monitor.block_connected(&header, &[], 200);

	// Try to update ChannelMonitor
	assert!(nodes[1].node.claim_funds(preimage, &None, 9_000_000));
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	if let Some(ref mut channel) = nodes[0].node.channel_state.lock().unwrap().by_id.get_mut(&chan_1.2) {
		if let Ok((_, _, _, update)) = channel.commitment_signed(&updates.commitment_signed, &node_cfgs[0].fee_estimator, &node_cfgs[0].logger) {
			if let Err(_) =  watchtower.chain_monitor.update_channel(outpoint, update.clone()) {} else { assert!(false); }
			if let Ok(_) = nodes[0].chain_monitor.update_channel(outpoint, update) {} else { assert!(false); }
		} else { assert!(false); }
	} else { assert!(false); };
	// Our local monitor is in-sync and hasn't processed yet timeout
	check_added_monitors!(nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
}

#[test]
fn test_concurrent_monitor_claim() {
	// Watchtower A receives block, broadcasts state N, then channel receives new state N+1,
	// sending it to both watchtowers, Bob accepts N+1, then receives block and broadcasts
	// the latest state N+1, Alice rejects state N+1, but Bob has already broadcast it,
	// state N+1 confirms. Alice claims output from state N+1.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channel
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let outpoint = OutPoint { txid: chan_1.3.txid(), index: 0 };

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 10_000_000, 10_000_000);

	// Route a HTLC from node 0 to node 1 (but don't settle)
	route_payment(&nodes[0], &vec!(&nodes[1])[..], 9_000_000).0;

	// Copy ChainMonitor to simulate watchtower Alice and update block height her ChannelMonitor timeout HTLC onchain
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", "Alice"));
	let persister = test_utils::TestPersister::new();
	let watchtower_alice = {
		let monitors = nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap();
		let monitor = monitors.get(&outpoint).unwrap();
		let mut w = test_utils::TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<EnforcingSigner>)>::read(
				&mut ::std::io::Cursor::new(&w.0), &test_utils::OnlyReadsKeysInterface {}).unwrap().1;
		assert!(new_monitor == *monitor);
		let watchtower = test_utils::TestChainMonitor::new(Some(&chain_source), &chanmon_cfgs[0].tx_broadcaster, &logger, &chanmon_cfgs[0].fee_estimator, &persister, &node_cfgs[0].keys_manager);
		assert!(watchtower.watch_channel(outpoint, new_monitor).is_ok());
		watchtower
	};
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	watchtower_alice.chain_monitor.block_connected(&header, &vec![], CHAN_CONFIRM_DEPTH + 1 + TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS);

	// Watchtower Alice should have broadcast a commitment/HTLC-timeout
	{
		let mut txn = chanmon_cfgs[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(txn.len(), 2);
		txn.clear();
	}

	// Copy ChainMonitor to simulate watchtower Bob and make it receive a commitment update first.
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", "Bob"));
	let persister = test_utils::TestPersister::new();
	let watchtower_bob = {
		let monitors = nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap();
		let monitor = monitors.get(&outpoint).unwrap();
		let mut w = test_utils::TestVecWriter(Vec::new());
		monitor.write(&mut w).unwrap();
		let new_monitor = <(BlockHash, channelmonitor::ChannelMonitor<EnforcingSigner>)>::read(
				&mut ::std::io::Cursor::new(&w.0), &test_utils::OnlyReadsKeysInterface {}).unwrap().1;
		assert!(new_monitor == *monitor);
		let watchtower = test_utils::TestChainMonitor::new(Some(&chain_source), &chanmon_cfgs[0].tx_broadcaster, &logger, &chanmon_cfgs[0].fee_estimator, &persister, &node_cfgs[0].keys_manager);
		assert!(watchtower.watch_channel(outpoint, new_monitor).is_ok());
		watchtower
	};
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	watchtower_bob.chain_monitor.block_connected(&header, &vec![], CHAN_CONFIRM_DEPTH + TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS);

	// Route another payment to generate another update with still previous HTLC pending
	let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
	{
		let net_graph_msg_handler = &nodes[1].net_graph_msg_handler;
		let route = get_route(&nodes[1].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[0].node.get_our_node_id(), None, None, &Vec::new(), 3000000 , TEST_FINAL_CLTV, &logger).unwrap();
		nodes[1].node.send_payment(&route, payment_hash, &None).unwrap();
	}
	check_added_monitors!(nodes[1], 1);

	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(updates.update_add_htlcs.len(), 1);
	nodes[0].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	if let Some(ref mut channel) = nodes[0].node.channel_state.lock().unwrap().by_id.get_mut(&chan_1.2) {
		if let Ok((_, _, _, update)) = channel.commitment_signed(&updates.commitment_signed, &node_cfgs[0].fee_estimator, &node_cfgs[0].logger) {
			// Watchtower Alice should already have seen the block and reject the update
			if let Err(_) =  watchtower_alice.chain_monitor.update_channel(outpoint, update.clone()) {} else { assert!(false); }
			if let Ok(_) = watchtower_bob.chain_monitor.update_channel(outpoint, update.clone()) {} else { assert!(false); }
			if let Ok(_) = nodes[0].chain_monitor.update_channel(outpoint, update) {} else { assert!(false); }
		} else { assert!(false); }
	} else { assert!(false); };
	// Our local monitor is in-sync and hasn't processed yet timeout
	check_added_monitors!(nodes[0], 1);

	//// Provide one more block to watchtower Bob, expect broadcast of commitment and HTLC-Timeout
	watchtower_bob.chain_monitor.block_connected(&header, &vec![], CHAN_CONFIRM_DEPTH + 1 + TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS);

	// Watchtower Bob should have broadcast a commitment/HTLC-timeout
	let bob_state_y;
	{
		let mut txn = chanmon_cfgs[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(txn.len(), 2);
		bob_state_y = txn[0].clone();
		txn.clear();
	};

	// We confirm Bob's state Y on Alice, she should broadcast a HTLC-timeout
	watchtower_alice.chain_monitor.block_connected(&header, &vec![(0, &bob_state_y)], CHAN_CONFIRM_DEPTH + 2 + TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS);
	{
		let htlc_txn = chanmon_cfgs[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// We broadcast twice the transaction, once due to the HTLC-timeout, once due
		// the onchain detection of the HTLC output
		assert_eq!(htlc_txn.len(), 2);
		check_spends!(htlc_txn[0], bob_state_y);
		check_spends!(htlc_txn[1], bob_state_y);
	}
}

#[test]
fn test_pre_lockin_no_chan_closed_update() {
	// Test that if a peer closes a channel in response to a funding_created message we don't
	// generate a channel update (as the channel cannot appear on chain without a funding_signed
	// message).
	//
	// Doing so would imply a channel monitor update before the initial channel monitor
	// registration, violating our API guarantees.
	//
	// Previously, full_stack_target managed to hit this case by opening then closing a channel,
	// then opening a second channel with the same funding output as the first (which is not
	// rejected because the first channel does not exist in the ChannelManager) and closing it
	// before receiving funding_signed.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create an initial channel
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_chan_msg);
	let accept_chan_msg = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &accept_chan_msg);

	// Move the first channel through the funding flow...
	let (temporary_channel_id, _tx, funding_output) = create_funding_transaction(&nodes[0], 100000, 42);

	nodes[0].node.funding_transaction_generated(&temporary_channel_id, funding_output);
	check_added_monitors!(nodes[0], 0);

	let funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	let channel_id = ::chain::transaction::OutPoint { txid: funding_created_msg.funding_txid, index: funding_created_msg.funding_output_index }.to_channel_id();
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage { channel_id, data: "Hi".to_owned() });
	assert!(nodes[0].chain_monitor.added_monitors.lock().unwrap().is_empty());
}

#[test]
fn test_htlc_no_detection() {
	// This test is a mutation to underscore the detection logic bug we had
	// before #653. HTLC value routed is above the remaining balance, thus
	// inverting HTLC and `to_remote` output. HTLC will come second and
	// it wouldn't be seen by pre-#653 detection as we were enumerate()'ing
	// on a watched outputs vector (Vec<TxOut>) thus implicitly relying on
	// outputs order detection for correct spending children filtring.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001, InitFeatures::known(), InitFeatures::known());

	send_payment(&nodes[0], &vec!(&nodes[1])[..], 1_000_000, 1_000_000);
	let (_, our_payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1])[..], 2_000_000);
	let local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn[0].input.len(), 1);
	assert_eq!(local_txn[0].output.len(), 3);
	check_spends!(local_txn[0], chan_1.3);

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header, txdata: vec![local_txn[0].clone()] }, 200);
	// We deliberately connect the local tx twice as this should provoke a failure calling
	// this test before #653 fix.
	connect_block(&nodes[0], &Block { header, txdata: vec![local_txn[0].clone()] }, 200);
	check_closed_broadcast!(nodes[0], false);
	check_added_monitors!(nodes[0], 1);

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		node_txn[0].clone()
	};

	let header_201 = BlockHeader { version: 0x20000000, prev_blockhash: header.block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[0], &Block { header: header_201, txdata: vec![htlc_timeout.clone()] }, 201);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1, 201, true, header_201.block_hash());
	expect_payment_failed!(nodes[0], our_payment_hash, true);
}

fn do_test_onchain_htlc_settlement_after_close(broadcast_alice: bool, go_onchain_before_fulfill: bool) {
	// If we route an HTLC, then learn the HTLC's preimage after the upstream channel has been
	// force-closed, we must claim that HTLC on-chain. (Given an HTLC forwarded from Alice --> Bob -->
	// Carol, Alice would be the upstream node, and Carol the downstream.)
	//
	// Steps of the test:
	// 1) Alice sends a HTLC to Carol through Bob.
	// 2) Carol doesn't settle the HTLC.
	// 3) If broadcast_alice is true, Alice force-closes her channel with Bob. Else Bob force closes.
	// Steps 4 and 5 may be reordered depending on go_onchain_before_fulfill.
	// 4) Bob sees the Alice's commitment on his chain or vice versa. An offered output is present
	//    but can't be claimed as Bob doesn't have yet knowledge of the preimage.
	// 5) Carol release the preimage to Bob off-chain.
	// 6) Bob claims the offered output on the broadcasted commitment.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_ab = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 10001, InitFeatures::known(), InitFeatures::known());

	// Steps (1) and (2):
	// Send an HTLC Alice --> Bob --> Carol, but Carol doesn't settle the HTLC back.
	let (payment_preimage, _payment_hash) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2]), 3_000_000);

	// Check that Alice's commitment transaction now contains an output for this HTLC.
	let alice_txn = get_local_commitment_txn!(nodes[0], chan_ab.2);
	check_spends!(alice_txn[0], chan_ab.3);
	assert_eq!(alice_txn[0].output.len(), 2);
	check_spends!(alice_txn[1], alice_txn[0]); // 2nd transaction is a non-final HTLC-timeout
	assert_eq!(alice_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(alice_txn.len(), 2);

	// Steps (3) and (4):
	// If `go_onchain_before_fufill`, broadcast the relevant commitment transaction and check that Bob
	// responds by (1) broadcasting a channel update and (2) adding a new ChannelMonitor.
	let mut force_closing_node = 0; // Alice force-closes
	if !broadcast_alice { force_closing_node = 1; } // Bob force-closes
	nodes[force_closing_node].node.force_close_channel(&chan_ab.2).unwrap();
	check_closed_broadcast!(nodes[force_closing_node], false);
	check_added_monitors!(nodes[force_closing_node], 1);
	if go_onchain_before_fulfill {
		let txn_to_broadcast = match broadcast_alice {
			true => alice_txn.clone(),
			false => get_local_commitment_txn!(nodes[1], chan_ab.2)
		};
		let header = BlockHeader { version: 0x20000000, prev_blockhash: nodes[1].best_block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
		connect_block(&nodes[1], &Block { header, txdata: vec![txn_to_broadcast[0].clone()]}, CHAN_CONFIRM_DEPTH * 2 + 1);
		let mut bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		if broadcast_alice {
			check_closed_broadcast!(nodes[1], false);
			check_added_monitors!(nodes[1], 1);
		}
		assert_eq!(bob_txn.len(), 1);
		check_spends!(bob_txn[0], chan_ab.3);
	}

	// Step (5):
	// Carol then claims the funds and sends an update_fulfill message to Bob, and they go through the
	// process of removing the HTLC from their commitment transactions.
	assert!(nodes[2].node.claim_funds(payment_preimage, &None, 3_000_000));
	check_added_monitors!(nodes[2], 1);
	let carol_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(carol_updates.update_add_htlcs.is_empty());
	assert!(carol_updates.update_fail_htlcs.is_empty());
	assert!(carol_updates.update_fail_malformed_htlcs.is_empty());
	assert!(carol_updates.update_fee.is_none());
	assert_eq!(carol_updates.update_fulfill_htlcs.len(), 1);

	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &carol_updates.update_fulfill_htlcs[0]);
	// If Alice broadcasted but Bob doesn't know yet, here he prepares to tell her about the preimage.
	if !go_onchain_before_fulfill && broadcast_alice {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::UpdateHTLCs { ref node_id, .. } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		};
	}
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &carol_updates.commitment_signed);
	// One monitor update for the preimage to update the Bob<->Alice channel, one monitor update
	// Carol<->Bob's updated commitment transaction info.
	check_added_monitors!(nodes[1], 2);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	let bob_revocation = match events[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[2].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	let bob_updates = match events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[2].node.get_our_node_id());
			(*updates).clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bob_revocation);
	check_added_monitors!(nodes[2], 1);
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bob_updates.commitment_signed);
	check_added_monitors!(nodes[2], 1);

	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let carol_revocation = match events[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &carol_revocation);
	check_added_monitors!(nodes[1], 1);

	// If this test requires the force-closed channel to not be on-chain until after the fulfill,
	// here's where we put said channel's commitment tx on-chain.
	let mut txn_to_broadcast = alice_txn.clone();
	if !broadcast_alice { txn_to_broadcast = get_local_commitment_txn!(nodes[1], chan_ab.2); }
	if !go_onchain_before_fulfill {
		let header = BlockHeader { version: 0x20000000, prev_blockhash: nodes[1].best_block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42};
		connect_block(&nodes[1], &Block { header, txdata: vec![txn_to_broadcast[0].clone()]}, CHAN_CONFIRM_DEPTH * 2 + 1);
		// If Bob was the one to force-close, he will have already passed these checks earlier.
		if broadcast_alice {
			check_closed_broadcast!(nodes[1], false);
			check_added_monitors!(nodes[1], 1);
		}
		let mut bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		if broadcast_alice {
			// In `connect_block()`, the ChainMonitor and ChannelManager are separately notified about a
			// new block being connected. The ChannelManager being notified triggers a monitor update,
			// which triggers broadcasting our commitment tx and an HTLC-claiming tx. The ChainMonitor
			// being notified triggers the HTLC-claiming tx redundantly, resulting in 3 total txs being
			// broadcasted.
			assert_eq!(bob_txn.len(), 3);
			check_spends!(bob_txn[1], chan_ab.3);
		} else {
			assert_eq!(bob_txn.len(), 2);
			check_spends!(bob_txn[0], chan_ab.3);
		}
	}

	// Step (6):
	// Finally, check that Bob broadcasted a preimage-claiming transaction for the HTLC output on the
	// broadcasted commitment transaction.
	{
		let bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
		if go_onchain_before_fulfill {
			// Bob should now have an extra broadcasted tx, for the preimage-claiming transaction.
			assert_eq!(bob_txn.len(), 2);
		}
		let script_weight = match broadcast_alice {
			true => OFFERED_HTLC_SCRIPT_WEIGHT,
			false => ACCEPTED_HTLC_SCRIPT_WEIGHT
		};
		// If Alice force-closed and Bob didn't receive her commitment transaction until after he
		// received Carol's fulfill, he broadcasts the HTLC-output-claiming transaction first. Else if
		// Bob force closed or if he found out about Alice's commitment tx before receiving Carol's
		// fulfill, then he broadcasts the HTLC-output-claiming transaction second.
		if broadcast_alice && !go_onchain_before_fulfill {
			check_spends!(bob_txn[0], txn_to_broadcast[0]);
			assert_eq!(bob_txn[0].input[0].witness.last().unwrap().len(), script_weight);
		} else {
			check_spends!(bob_txn[1], txn_to_broadcast[0]);
			assert_eq!(bob_txn[1].input[0].witness.last().unwrap().len(), script_weight);
		}
	}
}

#[test]
fn test_onchain_htlc_settlement_after_close() {
	do_test_onchain_htlc_settlement_after_close(true, true);
	do_test_onchain_htlc_settlement_after_close(false, true); // Technically redundant, but may as well
	do_test_onchain_htlc_settlement_after_close(true, false);
	do_test_onchain_htlc_settlement_after_close(false, false);
}

#[test]
fn test_duplicate_chan_id() {
	// Test that if a given peer tries to open a channel with the same channel_id as one that is
	// already open we reject it and keep the old channel.
	//
	// Previously, full_stack_target managed to figure out that if you tried to open two channels
	// with the same funding output (ie post-funding channel_id), we'd create a monitor update for
	// the existing channel when we detect the duplicate new channel, screwing up our monitor
	// updating logic for the existing channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create an initial channel
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_chan_msg);
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	// Try to create a second channel with the same temporary_channel_id as the first and check
	// that it is rejected.
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_chan_msg);
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
				// Technically, at this point, nodes[1] would be justified in thinking both the
				// first (valid) and second (invalid) channels are closed, given they both have
				// the same non-temporary channel_id. However, currently we do not, so we just
				// move forward with it.
				assert_eq!(msg.channel_id, open_chan_msg.temporary_channel_id);
				assert_eq!(node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	}

	// Move the first channel through the funding flow...
	let (temporary_channel_id, tx, funding_output) = create_funding_transaction(&nodes[0], 100000, 42);

	nodes[0].node.funding_transaction_generated(&temporary_channel_id, funding_output);
	check_added_monitors!(nodes[0], 0);

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}
	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());

	let funding_outpoint = ::chain::transaction::OutPoint { txid: funding_created_msg.funding_txid, index: funding_created_msg.funding_output_index };
	let channel_id = funding_outpoint.to_channel_id();

	// Now we have the first channel past funding_created (ie it has a txid-based channel_id, not a
	// temporary one).

	// First try to open a second channel with a temporary channel id equal to the txid-based one.
	// Technically this is allowed by the spec, but we don't support it and there's little reason
	// to. Still, it shouldn't cause any other issues.
	open_chan_msg.temporary_channel_id = channel_id;
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_chan_msg);
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
				// Technically, at this point, nodes[1] would be justified in thinking both
				// channels are closed, but currently we do not, so we just move forward with it.
				assert_eq!(msg.channel_id, open_chan_msg.temporary_channel_id);
				assert_eq!(node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	}

	// Now try to create a second channel which has a duplicate funding output.
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	let open_chan_2_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), InitFeatures::known(), &open_chan_2_msg);
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), InitFeatures::known(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));
	create_funding_transaction(&nodes[0], 100000, 42); // Get and check the FundingGenerationReady event

	let funding_created = {
		let mut a_channel_lock = nodes[0].node.channel_state.lock().unwrap();
		let mut as_chan = a_channel_lock.by_id.get_mut(&open_chan_2_msg.temporary_channel_id).unwrap();
		let logger = test_utils::TestLogger::new();
		as_chan.get_outbound_funding_created(funding_outpoint, &&logger).unwrap()
	};
	check_added_monitors!(nodes[0], 0);
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created);
	// At this point we'll try to add a duplicate channel monitor, which will be rejected, but
	// still needs to be cleared here.
	check_added_monitors!(nodes[1], 1);

	// ...still, nodes[1] will reject the duplicate channel.
	{
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
				// Technically, at this point, nodes[1] would be justified in thinking both
				// channels are closed, but currently we do not, so we just move forward with it.
				assert_eq!(msg.channel_id, channel_id);
				assert_eq!(node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	}

	// finally, finish creating the original channel and send a payment over it to make sure
	// everything is functional.
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	{
		let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	let events_4 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	match events_4[0] {
		Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
			assert_eq!(user_channel_id, 42);
			assert_eq!(*funding_txo, funding_output);
		},
		_ => panic!("Unexpected event"),
	};

	let (funding_locked, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &funding_locked);
	update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &as_update, &bs_update);
	send_payment(&nodes[0], &[&nodes[1]], 8000000, 8_000_000);
}

#[test]
fn test_error_chans_closed() {
	// Test that we properly handle error messages, closing appropriate channels.
	//
	// Prior to #787 we'd allow a peer to make us force-close a channel we had with a different
	// peer. The "real" fix for that is to index channels with peers_ids, however in the mean time
	// we can test various edge cases around it to ensure we don't regress.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001, InitFeatures::known(), InitFeatures::known());
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001, InitFeatures::known(), InitFeatures::known());
	let chan_3 = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001, InitFeatures::known(), InitFeatures::known());

	assert_eq!(nodes[0].node.list_usable_channels().len(), 3);
	assert_eq!(nodes[1].node.list_usable_channels().len(), 2);
	assert_eq!(nodes[2].node.list_usable_channels().len(), 1);

	// Closing a channel from a different peer has no effect
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage { channel_id: chan_3.2, data: "ERR".to_owned() });
	assert_eq!(nodes[0].node.list_usable_channels().len(), 3);

	// Closing one channel doesn't impact others
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage { channel_id: chan_2.2, data: "ERR".to_owned() });
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0], false);
	assert_eq!(nodes[0].node.list_usable_channels().len(), 2);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_1.2 || nodes[0].node.list_usable_channels()[1].channel_id == chan_1.2);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2 || nodes[0].node.list_usable_channels()[1].channel_id == chan_3.2);

	// A null channel ID should close all channels
	let _chan_4 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001, InitFeatures::known(), InitFeatures::known());
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &msgs::ErrorMessage { channel_id: [0; 32], data: "ERR".to_owned() });
	check_added_monitors!(nodes[0], 2);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
			assert_eq!(msg.contents.flags & 2, 2);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
			assert_eq!(msg.contents.flags & 2, 2);
		},
		_ => panic!("Unexpected event"),
	}
	// Note that at this point users of a standard PeerHandler will end up calling
	// peer_disconnected with no_connection_possible set to false, duplicating the
	// close-all-channels logic. That's OK, we don't want to end up not force-closing channels for
	// users with their own peer handling logic. We duplicate the call here, however.
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), true);
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2);
}
