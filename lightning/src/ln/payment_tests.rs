// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test the payment retry logic in ChannelManager, including various edge-cases around
//! serialization ordering between ChannelManager/ChannelMonitors and ensuring we can still retry
//! payments thereafter.

use crate::chain::{ChannelMonitorUpdateStatus, Confirm, Listen, Watch};
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::chain::transaction::OutPoint;
use crate::chain::keysinterface::KeysInterface;
use crate::ln::channel::EXPIRE_PREV_CONFIG_TICKS;
use crate::ln::channelmanager::{self, BREAKDOWN_TIMEOUT, ChannelManager, MPP_TIMEOUT_TICKS, MIN_CLTV_EXPIRY_DELTA, PaymentId, PaymentSendFailure, IDEMPOTENCY_TIMEOUT_TICKS};
use crate::ln::msgs;
use crate::ln::msgs::ChannelMessageHandler;
use crate::routing::router::{PaymentParameters, get_route};
use crate::util::events::{ClosureReason, Event, HTLCDestination, MessageSendEvent, MessageSendEventsProvider};
use crate::util::test_utils;
use crate::util::errors::APIError;
use crate::util::ser::Writeable;

use bitcoin::{Block, BlockHeader, TxMerkleNode};
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;

use crate::prelude::*;

use crate::ln::functional_test_utils::*;
use crate::routing::gossip::NodeId;

#[test]
fn retry_single_path_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let _chan_0 = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let chan_1 = create_announced_chan_between_nodes(&nodes, 2, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	// Rebalance to find a route
	send_payment(&nodes[2], &vec!(&nodes[1])[..], 3_000_000);

	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100_000);

	// Rebalance so that the first hop fails.
	send_payment(&nodes[1], &vec!(&nodes[2])[..], 2_000_000);

	// Make sure the payment fails on the first hop.
	let payment_id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(&nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_1.2 }]);
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_updates.commitment_signed, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain());

	// Rebalance the channel so the retry succeeds.
	send_payment(&nodes[2], &vec!(&nodes[1])[..], 3_000_000);

	// Mine two blocks (we expire retries after 3, so this will check that we don't expire early)
	connect_blocks(&nodes[0], 2);

	// Retry the payment and make sure it succeeds.
	nodes[0].node.retry_payment(&route, payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[2]], 100_000, payment_hash, Some(payment_secret), events.pop().unwrap(), true, None);
	claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], false, payment_preimage);
}

#[test]
fn mpp_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features()).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features()).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, channelmanager::provided_init_features(), channelmanager::provided_init_features()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3, channelmanager::provided_init_features(), channelmanager::provided_init_features()).0.contents.short_channel_id;

	let (mut route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_id;
	route.paths[0][1].short_channel_id = chan_3_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_id;
	route.paths[1][1].short_channel_id = chan_4_id;
	send_along_route_with_secret(&nodes[0], route, &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], 200_000, payment_hash, payment_secret);
	fail_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_hash);
}

#[test]
fn mpp_retry() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let (chan_1_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let (chan_2_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let (chan_3_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 1, 3, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let (chan_4_update, _, chan_4_id, _) = create_announced_chan_between_nodes(&nodes, 3, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	// Rebalance
	send_payment(&nodes[3], &vec!(&nodes[2])[..], 1_500_000);

	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[3], 1_000_000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_update.contents.short_channel_id;
	route.paths[0][1].short_channel_id = chan_3_update.contents.short_channel_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_update.contents.short_channel_id;
	route.paths[1][1].short_channel_id = chan_4_update.contents.short_channel_id;

	// Initiate the MPP payment.
	let payment_id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), payment_id).unwrap();
	check_added_monitors!(nodes[0], 2); // one monitor per path
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	// Pass half of the payment along the success path.
	let success_path_msgs = events.remove(0);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 2_000_000, payment_hash, Some(payment_secret), success_path_msgs, false, None);

	// Add the HTLC along the first hop.
	let fail_path_msgs_1 = events.remove(0);
	let (update_add, commitment_signed) = match fail_path_msgs_1 {
		MessageSendEvent::UpdateHTLCs { node_id: _, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert_eq!(update_add_htlcs.len(), 1);
			assert!(update_fail_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
			(update_add_htlcs[0].clone(), commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};
	nodes[2].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[2], nodes[0], commitment_signed, false);

	// Attempt to forward the payment and complete the 2nd path's failure.
	expect_pending_htlcs_forwardable!(&nodes[2]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(&nodes[2], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[3].node.get_our_node_id()), channel_id: chan_4_id }]);
	let htlc_updates = get_htlc_update_msgs!(nodes[2], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[2], 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[2], htlc_updates.commitment_signed, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain());

	// Rebalance the channel so the second half of the payment can succeed.
	send_payment(&nodes[3], &vec!(&nodes[2])[..], 1_500_000);

	// Make sure it errors as expected given a too-large amount.
	if let Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError { err })) = nodes[0].node.retry_payment(&route, payment_id) {
		assert!(err.contains("over total_payment_amt_msat"));
	} else { panic!("Unexpected error"); }

	// Make sure it errors as expected given the wrong payment_id.
	if let Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError { err })) = nodes[0].node.retry_payment(&route, PaymentId([0; 32])) {
		assert!(err.contains("not found"));
	} else { panic!("Unexpected error"); }

	// Retry the second half of the payment and make sure it succeeds.
	let mut path = route.clone();
	path.paths.remove(0);
	nodes[0].node.retry_payment(&path, payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], 2_000_000, payment_hash, Some(payment_secret), events.pop().unwrap(), true, None);
	claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_preimage);
}

fn do_mpp_receive_timeout(send_partial_mpp: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let (chan_1_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let (chan_2_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let (chan_3_update, _, chan_3_id, _) = create_announced_chan_between_nodes(&nodes, 1, 3, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let (chan_4_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 2, 3, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[3], 100_000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_update.contents.short_channel_id;
	route.paths[0][1].short_channel_id = chan_3_update.contents.short_channel_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_update.contents.short_channel_id;
	route.paths[1][1].short_channel_id = chan_4_update.contents.short_channel_id;

	// Initiate the MPP payment.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 2); // one monitor per path
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	// Pass half of the payment along the first path.
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 200_000, payment_hash, Some(payment_secret), events.remove(0), false, None);

	if send_partial_mpp {
		// Time out the partial MPP
		for _ in 0..MPP_TIMEOUT_TICKS {
			nodes[3].node.timer_tick_occurred();
		}

		// Failed HTLC from node 3 -> 1
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[3], vec![HTLCDestination::FailedPayment { payment_hash }]);
		let htlc_fail_updates_3_1 = get_htlc_update_msgs!(nodes[3], nodes[1].node.get_our_node_id());
		assert_eq!(htlc_fail_updates_3_1.update_fail_htlcs.len(), 1);
		nodes[1].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &htlc_fail_updates_3_1.update_fail_htlcs[0]);
		check_added_monitors!(nodes[3], 1);
		commitment_signed_dance!(nodes[1], nodes[3], htlc_fail_updates_3_1.commitment_signed, false);

		// Failed HTLC from node 1 -> 0
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[3].node.get_our_node_id()), channel_id: chan_3_id }]);
		let htlc_fail_updates_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert_eq!(htlc_fail_updates_1_0.update_fail_htlcs.len(), 1);
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_fail_updates_1_0.update_fail_htlcs[0]);
		check_added_monitors!(nodes[1], 1);
		commitment_signed_dance!(nodes[0], nodes[1], htlc_fail_updates_1_0.commitment_signed, false);

		expect_payment_failed_conditions(&nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain().expected_htlc_error_data(23, &[][..]));
	} else {
		// Pass half of the payment along the second path.
		pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], 200_000, payment_hash, Some(payment_secret), events.remove(0), true, None);

		// Even after MPP_TIMEOUT_TICKS we should not timeout the MPP if we have all the parts
		for _ in 0..MPP_TIMEOUT_TICKS {
			nodes[3].node.timer_tick_occurred();
		}

		claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_preimage);
	}
}

#[test]
fn mpp_receive_timeout() {
	do_mpp_receive_timeout(true);
	do_mpp_receive_timeout(false);
}

#[test]
fn retry_expired_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let _chan_0 = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let chan_1 = create_announced_chan_between_nodes(&nodes, 2, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	// Rebalance to find a route
	send_payment(&nodes[2], &vec!(&nodes[1])[..], 3_000_000);

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100_000);

	// Rebalance so that the first hop fails.
	send_payment(&nodes[1], &vec!(&nodes[2])[..], 2_000_000);

	// Make sure the payment fails on the first hop.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(&nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_1.2 }]);
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_updates.commitment_signed, false);
	expect_payment_failed!(nodes[0], payment_hash, false);

	// Mine blocks so the payment will have expired.
	connect_blocks(&nodes[0], 3);

	// Retry the payment and make sure it errors as expected.
	if let Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError { err })) = nodes[0].node.retry_payment(&route, PaymentId(payment_hash.0)) {
		assert!(err.contains("not found"));
	} else {
		panic!("Unexpected error");
	}
}

#[test]
fn no_pending_leak_on_initial_send_failure() {
	// In an earlier version of our payment tracking, we'd have a retry entry even when the initial
	// HTLC for payment failed to send due to local channel errors (e.g. peer disconnected). In this
	// case, the user wouldn't have a PaymentId to retry the payment with, but we'd think we have a
	// pending payment forever and never time it out.
	// Here we test exactly that - retrying a payment when a peer was disconnected on the first
	// try, and then check that no pending payment is being tracked.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)),
		true, APIError::ChannelUnavailable { ref err },
		assert_eq!(err, "Peer for first hop currently disconnected/pending monitor update!"));

	assert!(!nodes[0].node.has_pending_payments());
}

fn do_retry_with_no_persist(confirm_before_reload: bool) {
	// If we send a pending payment and `send_payment` returns success, we should always either
	// return a payment failure event or a payment success event, and on failure the payment should
	// be retryable.
	//
	// In order to do so when the ChannelManager isn't immediately persisted (which is normal - its
	// always persisted asynchronously), the ChannelManager has to reload some payment data from
	// ChannelMonitor(s) in some cases. This tests that reloading.
	//
	// `confirm_before_reload` confirms the channel-closing commitment transaction on-chain prior
	// to reloading the ChannelManager, increasing test coverage in ChannelMonitor HTLC tracking
	// which has separate codepaths for "commitment transaction already confirmed" and not.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features()).2;
	let (_, _, chan_id_2, _) = create_announced_chan_between_nodes(&nodes, 1, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	// Serialize the ChannelManager prior to sending payments
	let nodes_0_serialized = nodes[0].node.encode();

	// Send two payments - one which will get to nodes[2] and will be claimed, one which we'll time
	// out and retry.
	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);
	let (payment_preimage_1, payment_hash_1, _, payment_id_1) = send_along_route(&nodes[0], route.clone(), &[&nodes[1], &nodes[2]], 1_000_000);
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	// We relay the payment to nodes[1] while its disconnected from nodes[2], causing the payment
	// to be returned immediately to nodes[0], without having nodes[2] fail the inbound payment
	// which would prevent retry.
	nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), false);
	nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false, true);
	// nodes[1] now immediately fails the HTLC as the next-hop channel is disconnected
	let _ = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	reconnect_nodes(&nodes[1], &nodes[2], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	let as_commitment_tx = get_local_commitment_txn!(nodes[0], chan_id)[0].clone();
	if confirm_before_reload {
		mine_transaction(&nodes[0], &as_commitment_tx);
		nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	}

	// The ChannelMonitor should always be the latest version, as we're required to persist it
	// during the `commitment_signed_dance!()`.
	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	reload_node!(nodes[0], test_default_channel_config(), &nodes_0_serialized, &[&chan_0_monitor_serialized], persister, new_chain_monitor, nodes_0_deserialized);

	// On reload, the ChannelManager should realize it is stale compared to the ChannelMonitor and
	// force-close the channel.
	check_closed_event!(nodes[0], 1, ClosureReason::OutdatedChannelManager);
	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[0].node.has_pending_payments());
	let as_broadcasted_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_broadcasted_txn.len(), 1);
	assert_eq!(as_broadcasted_txn[0], as_commitment_tx);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: channelmanager::provided_init_features(), remote_network_address: None }).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now nodes[1] should send a channel reestablish, which nodes[0] will respond to with an
	// error, as the channel has hit the chain.
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: channelmanager::provided_init_features(), remote_network_address: None }).unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	let as_err = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_err.len(), 1);
	match as_err[0] {
		MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_error(&nodes[0].node.get_our_node_id(), msg);
			check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: "Failed to find corresponding channel".to_string() });
			check_added_monitors!(nodes[1], 1);
			assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);
		},
		_ => panic!("Unexpected event"),
	}
	check_closed_broadcast!(nodes[1], false);

	// Now claim the first payment, which should allow nodes[1] to claim the payment on-chain when
	// we close in a moment.
	nodes[2].node.claim_funds(payment_preimage_1);
	check_added_monitors!(nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_1, 1_000_000);

	let htlc_fulfill_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &htlc_fulfill_updates.update_fulfill_htlcs[0]);
	check_added_monitors!(nodes[1], 1);
	commitment_signed_dance!(nodes[1], nodes[2], htlc_fulfill_updates.commitment_signed, false);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], None, false, false);

	if confirm_before_reload {
		let best_block = nodes[0].blocks.lock().unwrap().last().unwrap().clone();
		nodes[0].node.best_block_updated(&best_block.0.header, best_block.1);
	}

	// Create a new channel on which to retry the payment before we fail the payment via the
	// HTLC-Timeout transaction. This avoids ChannelManager timing out the payment due to us
	// connecting several blocks while creating the channel (implying time has passed).
	create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);

	mine_transaction(&nodes[1], &as_commitment_tx);
	let bs_htlc_claim_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_htlc_claim_txn.len(), 1);
	check_spends!(bs_htlc_claim_txn[0], as_commitment_tx);

	if !confirm_before_reload {
		mine_transaction(&nodes[0], &as_commitment_tx);
	}
	mine_transaction(&nodes[0], &bs_htlc_claim_txn[0]);
	expect_payment_sent!(nodes[0], payment_preimage_1);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV*4 + 20);
	let as_htlc_timeout_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_htlc_timeout_txn.len(), 2);
	let (first_htlc_timeout_tx, second_htlc_timeout_tx) = (&as_htlc_timeout_txn[0], &as_htlc_timeout_txn[1]);
	check_spends!(first_htlc_timeout_tx, as_commitment_tx);
	check_spends!(second_htlc_timeout_tx, as_commitment_tx);
	if first_htlc_timeout_tx.input[0].previous_output == bs_htlc_claim_txn[0].input[0].previous_output {
		confirm_transaction(&nodes[0], &second_htlc_timeout_tx);
	} else {
		confirm_transaction(&nodes[0], &first_htlc_timeout_tx);
	}
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain());

	// Finally, retry the payment (which was reloaded from the ChannelMonitor when nodes[0] was
	// reloaded) via a route over the new channel, which work without issue and eventually be
	// received and claimed at the recipient just like any other payment.
	let (mut new_route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);

	// Update the fee on the middle hop to ensure PaymentSent events have the correct (retried) fee
	// and not the original fee. We also update node[1]'s relevant config as
	// do_claim_payment_along_route expects us to never overpay.
	{
		let mut channel_state = nodes[1].node.channel_state.lock().unwrap();
		let mut channel = channel_state.by_id.get_mut(&chan_id_2).unwrap();
		let mut new_config = channel.config();
		new_config.forwarding_fee_base_msat += 100_000;
		channel.update_config(&new_config);
		new_route.paths[0][0].fee_msat += 100_000;
	}

	// Force expiration of the channel's previous config.
	for _ in 0..EXPIRE_PREV_CONFIG_TICKS {
		nodes[1].node.timer_tick_occurred();
	}

	assert!(nodes[0].node.retry_payment(&new_route, payment_id_1).is_err()); // Shouldn't be allowed to retry a fulfilled payment
	nodes[0].node.retry_payment(&new_route, PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000, payment_hash, Some(payment_secret), events.pop().unwrap(), true, None);
	do_claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], false, payment_preimage);
	expect_payment_sent!(nodes[0], payment_preimage, Some(new_route.paths[0][0].fee_msat));
}

#[test]
fn retry_with_no_persist() {
	do_retry_with_no_persist(true);
	do_retry_with_no_persist(false);
}

fn do_test_completed_payment_not_retryable_on_reload(use_dust: bool) {
	// Test that an off-chain completed payment is not retryable on restart. This was previously
	// broken for dust payments, but we test for both dust and non-dust payments.
	//
	// `use_dust` switches to using a dust HTLC, which results in the HTLC not having an on-chain
	// output at all.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut manually_accept_config = test_default_channel_config();
	manually_accept_config.manually_accept_inbound_channels = true;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(manually_accept_config), None]);

	let first_persister: test_utils::TestPersister;
	let first_new_chain_monitor: test_utils::TestChainMonitor;
	let first_nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let second_persister: test_utils::TestPersister;
	let second_new_chain_monitor: test_utils::TestChainMonitor;
	let second_nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let third_persister: test_utils::TestPersister;
	let third_new_chain_monitor: test_utils::TestChainMonitor;
	let third_nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;

	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Because we set nodes[1] to manually accept channels, just open a 0-conf channel.
	let (funding_tx, chan_id) = open_zero_conf_channel(&nodes[0], &nodes[1], None);
	confirm_transaction(&nodes[0], &funding_tx);
	confirm_transaction(&nodes[1], &funding_tx);
	// Ignore the announcement_signatures messages
	nodes[0].node.get_and_clear_pending_msg_events();
	nodes[1].node.get_and_clear_pending_msg_events();
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 1, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features()).2;

	// Serialize the ChannelManager prior to sending payments
	let mut nodes_0_serialized = nodes[0].node.encode();

	let route = get_route_and_payment_hash!(nodes[0], nodes[2], if use_dust { 1_000 } else { 1_000_000 }).0;
	let (payment_preimage, payment_hash, payment_secret, payment_id) = send_along_route(&nodes[0], route, &[&nodes[1], &nodes[2]], if use_dust { 1_000 } else { 1_000_000 });

	// The ChannelMonitor should always be the latest version, as we're required to persist it
	// during the `commitment_signed_dance!()`.
	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();

	reload_node!(nodes[0], test_default_channel_config(), nodes_0_serialized, &[&chan_0_monitor_serialized], first_persister, first_new_chain_monitor, first_nodes_0_deserialized);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	// On reload, the ChannelManager should realize it is stale compared to the ChannelMonitor and
	// force-close the channel.
	check_closed_event!(nodes[0], 1, ClosureReason::OutdatedChannelManager);
	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[0].node.has_pending_payments());
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: channelmanager::provided_init_features(), remote_network_address: None }).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now nodes[1] should send a channel reestablish, which nodes[0] will respond to with an
	// error, as the channel has hit the chain.
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: channelmanager::provided_init_features(), remote_network_address: None }).unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	let as_err = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_err.len(), 1);
	let bs_commitment_tx;
	match as_err[0] {
		MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_error(&nodes[0].node.get_our_node_id(), msg);
			check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: "Failed to find corresponding channel".to_string() });
			check_added_monitors!(nodes[1], 1);
			bs_commitment_tx = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		},
		_ => panic!("Unexpected event"),
	}
	check_closed_broadcast!(nodes[1], false);

	// Now fail back the payment from nodes[2] to nodes[1]. This doesn't really matter as the
	// previous hop channel is already on-chain, but it makes nodes[2] willing to see additional
	// incoming HTLCs with the same payment hash later.
	nodes[2].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[2], [HTLCDestination::FailedPayment { payment_hash }]);
	check_added_monitors!(nodes[2], 1);

	let htlc_fulfill_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &htlc_fulfill_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[2], htlc_fulfill_updates.commitment_signed, false);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1],
		[HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_id_2 }]);

	// Connect the HTLC-Timeout transaction, timing out the HTLC on both nodes (but not confirming
	// the HTLC-Timeout transaction beyond 1 conf). For dust HTLCs, the HTLC is considered resolved
	// after the commitment transaction, so always connect the commitment transaction.
	mine_transaction(&nodes[0], &bs_commitment_tx[0]);
	mine_transaction(&nodes[1], &bs_commitment_tx[0]);
	if !use_dust {
		connect_blocks(&nodes[0], TEST_FINAL_CLTV - 1 + (MIN_CLTV_EXPIRY_DELTA as u32));
		connect_blocks(&nodes[1], TEST_FINAL_CLTV - 1 + (MIN_CLTV_EXPIRY_DELTA as u32));
		let as_htlc_timeout = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		check_spends!(as_htlc_timeout[0], bs_commitment_tx[0]);
		assert_eq!(as_htlc_timeout.len(), 1);

		mine_transaction(&nodes[0], &as_htlc_timeout[0]);
		// nodes[0] may rebroadcast (or RBF-bump) its HTLC-Timeout, so wipe the announced set.
		nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
		mine_transaction(&nodes[1], &as_htlc_timeout[0]);
	}

	// Create a new channel on which to retry the payment before we fail the payment via the
	// HTLC-Timeout transaction. This avoids ChannelManager timing out the payment due to us
	// connecting several blocks while creating the channel (implying time has passed).
	// We do this with a zero-conf channel to avoid connecting blocks as a side-effect.
	let (_, chan_id_3) = open_zero_conf_channel(&nodes[0], &nodes[1], None);
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);

	// If we attempt to retry prior to the HTLC-Timeout (or commitment transaction, for dust HTLCs)
	// confirming, we will fail as it's considered still-pending...
	let (new_route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[2], if use_dust { 1_000 } else { 1_000_000 });
	assert!(nodes[0].node.retry_payment(&new_route, payment_id).is_err());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// After ANTI_REORG_DELAY confirmations, the HTLC should be failed and we can try the payment
	// again. We serialize the node first as we'll then test retrying the HTLC after a restart
	// (which should also still work).
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	// We set mpp_parts_remain to avoid having abandon_payment called
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain());

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	let chan_1_monitor_serialized = get_monitor!(nodes[0], chan_id_3).encode();
	nodes_0_serialized = nodes[0].node.encode();

	assert!(nodes[0].node.retry_payment(&new_route, payment_id).is_ok());
	assert!(!nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	reload_node!(nodes[0], test_default_channel_config(), nodes_0_serialized, &[&chan_0_monitor_serialized, &chan_1_monitor_serialized], second_persister, second_new_chain_monitor, second_nodes_0_deserialized);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	// Now resend the payment, delivering the HTLC and actually claiming it this time. This ensures
	// the payment is not (spuriously) listed as still pending.
	assert!(nodes[0].node.retry_payment(&new_route, payment_id).is_ok());
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], if use_dust { 1_000 } else { 1_000_000 }, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	assert!(nodes[0].node.retry_payment(&new_route, payment_id).is_err());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	let chan_1_monitor_serialized = get_monitor!(nodes[0], chan_id_3).encode();
	nodes_0_serialized = nodes[0].node.encode();

	// Ensure that after reload we cannot retry the payment.
	reload_node!(nodes[0], test_default_channel_config(), nodes_0_serialized, &[&chan_0_monitor_serialized, &chan_1_monitor_serialized], third_persister, third_new_chain_monitor, third_nodes_0_deserialized);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	assert!(nodes[0].node.retry_payment(&new_route, payment_id).is_err());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
}

#[test]
fn test_completed_payment_not_retryable_on_reload() {
	do_test_completed_payment_not_retryable_on_reload(true);
	do_test_completed_payment_not_retryable_on_reload(false);
}


fn do_test_dup_htlc_onchain_fails_on_reload(persist_manager_post_event: bool, confirm_commitment_tx: bool, payment_timeout: bool) {
	// When a Channel is closed, any outbound HTLCs which were relayed through it are simply
	// dropped when the Channel is. From there, the ChannelManager relies on the ChannelMonitor
	// having a copy of the relevant fail-/claim-back data and processes the HTLC fail/claim when
	// the ChannelMonitor tells it to.
	//
	// If, due to an on-chain event, an HTLC is failed/claimed, we should avoid providing the
	// ChannelManager the HTLC event until after the monitor is re-persisted. This should prevent a
	// duplicate HTLC fail/claim (e.g. via a PaymentPathFailed event).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	// Route a payment, but force-close the channel before the HTLC fulfill message arrives at
	// nodes[0].
	let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 10_000_000);
	nodes[0].node.force_close_broadcasting_latest_txn(&nodes[0].node.list_channels()[0].channel_id, &nodes[1].node.get_our_node_id()).unwrap();
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);

	// Connect blocks until the CLTV timeout is up so that we get an HTLC-Timeout transaction
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 3);
	assert_eq!(node_txn[0], node_txn[1]);
	check_spends!(node_txn[1], funding_tx);
	check_spends!(node_txn[2], node_txn[1]);
	let timeout_txn = vec![node_txn[2].clone()];

	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 10_000_000);

	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: nodes[1].best_block_hash(), merkle_root: TxMerkleNode::all_zeros(), time: 42, bits: 42, nonce: 42 };
	connect_block(&nodes[1], &Block { header, txdata: vec![node_txn[1].clone()]});
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
	let claim_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(claim_txn.len(), 3);
	check_spends!(claim_txn[0], node_txn[1]);
	check_spends!(claim_txn[1], funding_tx);
	check_spends!(claim_txn[2], claim_txn[1]);

	header.prev_blockhash = nodes[0].best_block_hash();
	connect_block(&nodes[0], &Block { header, txdata: vec![node_txn[1].clone()]});

	if confirm_commitment_tx {
		connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32 - 1);
	}

	header.prev_blockhash = nodes[0].best_block_hash();
	let claim_block = Block { header, txdata: if payment_timeout { timeout_txn } else { vec![claim_txn[0].clone()] } };

	if payment_timeout {
		assert!(confirm_commitment_tx); // Otherwise we're spending below our CSV!
		connect_block(&nodes[0], &claim_block);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 2);
	}

	// Now connect the HTLC claim transaction with the ChainMonitor-generated ChannelMonitor update
	// returning InProgress. This should cause the claim event to never make its way to the
	// ChannelManager.
	chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().clear();
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);

	if payment_timeout {
		connect_blocks(&nodes[0], 1);
	} else {
		connect_block(&nodes[0], &claim_block);
	}

	let funding_txo = OutPoint { txid: funding_tx.txid(), index: 0 };
	let mon_updates: Vec<_> = chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap()
		.get_mut(&funding_txo).unwrap().drain().collect();
	// If we are using chain::Confirm instead of chain::Listen, we will get the same update twice.
	// If we're testing connection idempotency we may get substantially more.
	assert!(mon_updates.len() >= 1);
	assert!(nodes[0].chain_monitor.release_pending_monitor_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	// If we persist the ChannelManager here, we should get the PaymentSent event after
	// deserialization.
	let mut chan_manager_serialized = Vec::new();
	if !persist_manager_post_event {
		chan_manager_serialized = nodes[0].node.encode();
	}

	// Now persist the ChannelMonitor and inform the ChainMonitor that we're done, generating the
	// payment sent event.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	for update in mon_updates {
		nodes[0].chain_monitor.chain_monitor.channel_monitor_updated(funding_txo, update).unwrap();
	}
	if payment_timeout {
		expect_payment_failed!(nodes[0], payment_hash, false);
	} else {
		expect_payment_sent!(nodes[0], payment_preimage);
	}

	// If we persist the ChannelManager after we get the PaymentSent event, we shouldn't get it
	// twice.
	if persist_manager_post_event {
		chan_manager_serialized = nodes[0].node.encode();
	}

	// Now reload nodes[0]...
	reload_node!(nodes[0], &chan_manager_serialized, &[&chan_0_monitor_serialized], persister, new_chain_monitor, nodes_0_deserialized);

	if persist_manager_post_event {
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	} else if payment_timeout {
		expect_payment_failed!(nodes[0], payment_hash, false);
	} else {
		expect_payment_sent!(nodes[0], payment_preimage);
	}

	// Note that if we re-connect the block which exposed nodes[0] to the payment preimage (but
	// which the current ChannelMonitor has not seen), the ChannelManager's de-duplication of
	// payment events should kick in, leaving us with no pending events here.
	let height = nodes[0].blocks.lock().unwrap().len() as u32 - 1;
	nodes[0].chain_monitor.chain_monitor.block_connected(&claim_block, height);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
}

#[test]
fn test_dup_htlc_onchain_fails_on_reload() {
	do_test_dup_htlc_onchain_fails_on_reload(true, true, true);
	do_test_dup_htlc_onchain_fails_on_reload(true, true, false);
	do_test_dup_htlc_onchain_fails_on_reload(true, false, false);
	do_test_dup_htlc_onchain_fails_on_reload(false, true, true);
	do_test_dup_htlc_onchain_fails_on_reload(false, true, false);
	do_test_dup_htlc_onchain_fails_on_reload(false, false, false);
}

#[test]
fn test_fulfill_restart_failure() {
	// When we receive an update_fulfill_htlc message, we immediately consider the HTLC fully
	// fulfilled. At this point, the peer can reconnect and decide to either fulfill the HTLC
	// again, or fail it, giving us free money.
	//
	// Of course probably they won't fail it and give us free money, but because we have code to
	// handle it, we should test the logic for it anyway. We do that here.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_1_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features()).2;
	let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 100_000);

	// The simplest way to get a failure after a fulfill is to reload nodes[1] from a state
	// pre-fulfill, which we do by serializing it here.
	let chan_manager_serialized = nodes[1].node.encode();
	let chan_0_monitor_serialized = get_monitor!(nodes[1], chan_id).encode();

	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 100_000);

	let htlc_fulfill_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &htlc_fulfill_updates.update_fulfill_htlcs[0]);
	expect_payment_sent_without_paths!(nodes[0], payment_preimage);

	// Now reload nodes[1]...
	reload_node!(nodes[1], &chan_manager_serialized, &[&chan_0_monitor_serialized], persister, new_chain_monitor, nodes_1_deserialized);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	nodes[1].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	check_added_monitors!(nodes[1], 1);
	let htlc_fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_fail_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_fail_updates.commitment_signed, false);
	// nodes[0] shouldn't generate any events here, while it just got a payment failure completion
	// it had already considered the payment fulfilled, and now they just got free money.
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
}

#[test]
fn get_ldk_payment_preimage() {
	// Ensure that `ChannelManager::get_payment_preimage` can successfully be used to claim a payment.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	let amt_msat = 60_000;
	let expiry_secs = 60 * 60;
	let (payment_hash, payment_secret) = nodes[1].node.create_inbound_payment(Some(amt_msat), expiry_secs).unwrap();

	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id())
		.with_features(channelmanager::provided_invoice_features());
	let scorer = test_utils::TestScorer::with_penalty(0);
	let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
	let random_seed_bytes = keys_manager.get_secure_random_bytes();
	let route = get_route(
		&nodes[0].node.get_our_node_id(), &payment_params, &nodes[0].network_graph.read_only(),
		Some(&nodes[0].node.list_usable_channels().iter().collect::<Vec<_>>()),
		amt_msat, TEST_FINAL_CLTV, nodes[0].logger, &scorer, &random_seed_bytes).unwrap();
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	// Make sure to use `get_payment_preimage`
	let payment_preimage = nodes[1].node.get_payment_preimage(payment_hash, payment_secret).unwrap();
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1]], amt_msat, payment_hash, Some(payment_secret), events.pop().unwrap(), true, Some(payment_preimage));
	claim_payment_along_route(&nodes[0], &[&[&nodes[1]]], false, payment_preimage);
}

#[test]
fn sent_probe_is_probe_of_sending_node() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	create_announced_chan_between_nodes(&nodes, 1, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	// First check we refuse to build a single-hop probe
	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[1], 100_000);
	assert!(nodes[0].node.send_probe(route.paths[0].clone()).is_err());

	// Then build an actual two-hop probing path
	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[2], 100_000);

	match nodes[0].node.send_probe(route.paths[0].clone()) {
		Ok((payment_hash, payment_id)) => {
			assert!(nodes[0].node.payment_is_probe(&payment_hash, &payment_id));
			assert!(!nodes[1].node.payment_is_probe(&payment_hash, &payment_id));
			assert!(!nodes[2].node.payment_is_probe(&payment_hash, &payment_id));
		},
		_ => panic!(),
	}

	get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);
}

#[test]
fn successful_probe_yields_event() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	create_announced_chan_between_nodes(&nodes, 1, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[2], 100_000);

	let (payment_hash, payment_id) = nodes[0].node.send_probe(route.paths[0].clone()).unwrap();

	// node[0] -- update_add_htlcs -> node[1]
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let probe_event = SendEvent::from_commitment_update(nodes[1].node.get_our_node_id(), updates);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &probe_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], probe_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	// node[1] -- update_add_htlcs -> node[2]
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
	let probe_event = SendEvent::from_commitment_update(nodes[1].node.get_our_node_id(), updates);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &probe_event.msgs[0]);
	check_added_monitors!(nodes[2], 0);
	commitment_signed_dance!(nodes[2], nodes[1], probe_event.commitment_msg, true, true);

	// node[1] <- update_fail_htlcs -- node[2]
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, true);

	// node[0] <- update_fail_htlcs -- node[1]
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	check_added_monitors!(nodes[0], 0);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.drain(..).next().unwrap() {
		crate::util::events::Event::ProbeSuccessful { payment_id: ev_pid, payment_hash: ev_ph, .. } => {
			assert_eq!(payment_id, ev_pid);
			assert_eq!(payment_hash, ev_ph);
		},
		_ => panic!(),
	};
}

#[test]
fn failed_probe_yields_event() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 90000000, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id());

	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[2], &payment_params, 9_998_000, 42);

	let (payment_hash, payment_id) = nodes[0].node.send_probe(route.paths[0].clone()).unwrap();

	// node[0] -- update_add_htlcs -> node[1]
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let probe_event = SendEvent::from_commitment_update(nodes[1].node.get_our_node_id(), updates);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &probe_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], probe_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	// node[0] <- update_fail_htlcs -- node[1]
	check_added_monitors!(nodes[1], 1);
	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	// Skip the PendingHTLCsForwardable event
	let _events = nodes[1].node.get_and_clear_pending_events();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	check_added_monitors!(nodes[0], 0);
	commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.drain(..).next().unwrap() {
		crate::util::events::Event::ProbeFailed { payment_id: ev_pid, payment_hash: ev_ph, .. } => {
			assert_eq!(payment_id, ev_pid);
			assert_eq!(payment_hash, ev_ph);
		},
		_ => panic!(),
	};
}

#[test]
fn onchain_failed_probe_yields_event() {
	// Tests that an attempt to probe over a channel that is eventaully closed results in a failure
	// event.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features()).2;
	create_announced_chan_between_nodes(&nodes, 1, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id());

	// Send a dust HTLC, which will be treated as if it timed out once the channel hits the chain.
	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[2], &payment_params, 1_000, 42);
	let (payment_hash, payment_id) = nodes[0].node.send_probe(route.paths[0].clone()).unwrap();

	// node[0] -- update_add_htlcs -> node[1]
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let probe_event = SendEvent::from_commitment_update(nodes[1].node.get_our_node_id(), updates);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &probe_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], probe_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);

	check_added_monitors!(nodes[1], 1);
	let _ = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());

	// Don't bother forwarding the HTLC onwards and just confirm the force-close transaction on
	// Node A, which after 6 confirmations should result in a probe failure event.
	let bs_txn = get_local_commitment_txn!(nodes[1], chan_id);
	confirm_transaction(&nodes[0], &bs_txn[0]);
	check_closed_broadcast!(&nodes[0], true);
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	let mut found_probe_failed = false;
	for event in events.drain(..) {
		match event {
			Event::ProbeFailed { payment_id: ev_pid, payment_hash: ev_ph, .. } => {
				assert_eq!(payment_id, ev_pid);
				assert_eq!(payment_hash, ev_ph);
				found_probe_failed = true;
			},
			Event::ChannelClosed { .. } => {},
			_ => panic!(),
		}
	}
	assert!(found_probe_failed);
}

#[test]
fn claimed_send_payment_idempotent() {
	// Tests that `send_payment` (and friends) are (reasonably) idempotent.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features()).2;

	let (route, second_payment_hash, second_payment_preimage, second_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);
	let (first_payment_preimage, _, _, payment_id) = send_along_route(&nodes[0], route.clone(), &[&nodes[1]], 100_000);

	macro_rules! check_send_rejected {
		() => {
			// If we try to resend a new payment with a different payment_hash but with the same
			// payment_id, it should be rejected.
			let send_result = nodes[0].node.send_payment(&route, second_payment_hash, &Some(second_payment_secret), payment_id);
			match send_result {
				Err(PaymentSendFailure::DuplicatePayment) => {},
				_ => panic!("Unexpected send result: {:?}", send_result),
			}

			// Further, if we try to send a spontaneous payment with the same payment_id it should
			// also be rejected.
			let send_result = nodes[0].node.send_spontaneous_payment(&route, None, payment_id);
			match send_result {
				Err(PaymentSendFailure::DuplicatePayment) => {},
				_ => panic!("Unexpected send result: {:?}", send_result),
			}
		}
	}

	check_send_rejected!();

	// Claim the payment backwards, but note that the PaymentSent event is still pending and has
	// not been seen by the user. At this point, from the user perspective nothing has changed, so
	// we must remain just as idempotent as we were before.
	do_claim_payment_along_route(&nodes[0], &[&[&nodes[1]]], false, first_payment_preimage);

	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	check_send_rejected!();

	// Once the user sees and handles the `PaymentSent` event, we expect them to no longer call
	// `send_payment`, and our idempotency guarantees are off - they should have atomically marked
	// the payment complete. However, they could have called `send_payment` while the event was
	// being processed, leading to a race in our idempotency guarantees. Thus, even immediately
	// after the event is handled a duplicate payment should sitll be rejected.
	expect_payment_sent!(&nodes[0], first_payment_preimage, Some(0));
	check_send_rejected!();

	// If relatively little time has passed, a duplicate payment should still fail.
	nodes[0].node.timer_tick_occurred();
	check_send_rejected!();

	// However, after some time has passed (at least more than the one timer tick above), a
	// duplicate payment should go through, as ChannelManager should no longer have any remaining
	// references to the old payment data.
	for _ in 0..IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	nodes[0].node.send_payment(&route, second_payment_hash, &Some(second_payment_secret), payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1]]], 100_000, second_payment_hash, second_payment_secret);
	claim_payment(&nodes[0], &[&nodes[1]], second_payment_preimage);
}

#[test]
fn abandoned_send_payment_idempotent() {
	// Tests that `send_payment` (and friends) allow duplicate PaymentIds immediately after
	// abandon_payment.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features()).2;

	let (route, second_payment_hash, second_payment_preimage, second_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);
	let (_, first_payment_hash, _, payment_id) = send_along_route(&nodes[0], route.clone(), &[&nodes[1]], 100_000);

	macro_rules! check_send_rejected {
		() => {
			// If we try to resend a new payment with a different payment_hash but with the same
			// payment_id, it should be rejected.
			let send_result = nodes[0].node.send_payment(&route, second_payment_hash, &Some(second_payment_secret), payment_id);
			match send_result {
				Err(PaymentSendFailure::DuplicatePayment) => {},
				_ => panic!("Unexpected send result: {:?}", send_result),
			}

			// Further, if we try to send a spontaneous payment with the same payment_id it should
			// also be rejected.
			let send_result = nodes[0].node.send_spontaneous_payment(&route, None, payment_id);
			match send_result {
				Err(PaymentSendFailure::DuplicatePayment) => {},
				_ => panic!("Unexpected send result: {:?}", send_result),
			}
		}
	}

	check_send_rejected!();

	nodes[1].node.fail_htlc_backwards(&first_payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], [HTLCDestination::FailedPayment { payment_hash: first_payment_hash }]);

	pass_failed_payment_back_no_abandon(&nodes[0], &[&[&nodes[1]]], false, first_payment_hash);
	check_send_rejected!();

	// Until we abandon the payment, no matter how many timer ticks pass, we still cannot reuse the
	// PaymentId.
	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}
	check_send_rejected!();

	nodes[0].node.abandon_payment(payment_id);
	get_event!(nodes[0], Event::PaymentFailed);

	// However, we can reuse the PaymentId immediately after we `abandon_payment`.
	nodes[0].node.send_payment(&route, second_payment_hash, &Some(second_payment_secret), payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1]]], 100_000, second_payment_hash, second_payment_secret);
	claim_payment(&nodes[0], &[&nodes[1]], second_payment_preimage);
}

#[test]
fn test_trivial_inflight_htlc_tracking(){
	// In this test, we test three scenarios:
	// (1) Sending + claiming a payment successfully should return `None` when querying InFlightHtlcs
	// (2) Sending a payment without claiming it should return the payment's value (500000) when querying InFlightHtlcs
	// (3) After we claim the payment sent in (2), InFlightHtlcs should return `None` for the query.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_1_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features());
	let (_, _, chan_2_id, _) = create_announced_chan_between_nodes(&nodes, 1, 2, channelmanager::provided_init_features(), channelmanager::provided_init_features());

	// Send and claim the payment. Inflight HTLCs should be empty.
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 500000);
	{
		let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();

		let node_0_channel_lock = nodes[0].node.channel_state.lock().unwrap();
		let node_1_channel_lock = nodes[1].node.channel_state.lock().unwrap();
		let channel_1 = node_0_channel_lock.by_id.get(&chan_1_id).unwrap();
		let channel_2 = node_1_channel_lock.by_id.get(&chan_2_id).unwrap();

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[0].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			channel_1.get_short_channel_id().unwrap()
		);
		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[2].node.get_our_node_id()),
			channel_2.get_short_channel_id().unwrap()
		);

		assert_eq!(chan_1_used_liquidity, None);
		assert_eq!(chan_2_used_liquidity, None);
	}

	// Send the payment, but do not claim it. Our inflight HTLCs should contain the pending payment.
	let (payment_preimage, _,  _) = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 500000);
	{
		let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();

		let node_0_channel_lock = nodes[0].node.channel_state.lock().unwrap();
		let node_1_channel_lock = nodes[1].node.channel_state.lock().unwrap();
		let channel_1 = node_0_channel_lock.by_id.get(&chan_1_id).unwrap();
		let channel_2 = node_1_channel_lock.by_id.get(&chan_2_id).unwrap();

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[0].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			channel_1.get_short_channel_id().unwrap()
		);
		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[2].node.get_our_node_id()),
			channel_2.get_short_channel_id().unwrap()
		);

		// First hop accounts for expected 1000 msat fee
		assert_eq!(chan_1_used_liquidity, Some(501000));
		assert_eq!(chan_2_used_liquidity, Some(500000));
	}

	// Now, let's claim the payment. This should result in the used liquidity to return `None`.
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
	{
		let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();

		let node_0_channel_lock = nodes[0].node.channel_state.lock().unwrap();
		let node_1_channel_lock = nodes[1].node.channel_state.lock().unwrap();
		let channel_1 = node_0_channel_lock.by_id.get(&chan_1_id).unwrap();
		let channel_2 = node_1_channel_lock.by_id.get(&chan_2_id).unwrap();

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[0].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			channel_1.get_short_channel_id().unwrap()
		);
		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[2].node.get_our_node_id()),
			channel_2.get_short_channel_id().unwrap()
		);

		assert_eq!(chan_1_used_liquidity, None);
		assert_eq!(chan_2_used_liquidity, None);
	}
}

#[test]
fn test_holding_cell_inflight_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1, channelmanager::provided_init_features(), channelmanager::provided_init_features()).2;

	let (route, payment_hash_1, _, payment_secret_1) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let (_, payment_hash_2, payment_secret_2) = get_payment_preimage_hash!(nodes[1]);

	// Queue up two payments - one will be delivered right away, one immediately goes into the
	// holding cell as nodes[0] is AwaitingRAA.
	{
		nodes[0].node.send_payment(&route, payment_hash_1, &Some(payment_secret_1), PaymentId(payment_hash_1.0)).unwrap();
		check_added_monitors!(nodes[0], 1);
		nodes[0].node.send_payment(&route, payment_hash_2, &Some(payment_secret_2), PaymentId(payment_hash_2.0)).unwrap();
		check_added_monitors!(nodes[0], 0);
	}

	let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();

	{
		let channel_lock = nodes[0].node.channel_state.lock().unwrap();
		let channel = channel_lock.by_id.get(&channel_id).unwrap();

		let used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[0].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			channel.get_short_channel_id().unwrap()
		);

		assert_eq!(used_liquidity, Some(2000000));
	}

	// Clear pending events so test doesn't throw a "Had excess message on node..." error
	nodes[0].node.get_and_clear_pending_msg_events();
}
