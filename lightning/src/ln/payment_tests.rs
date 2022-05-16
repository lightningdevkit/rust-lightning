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

use chain::{ChannelMonitorUpdateErr, Confirm, Listen, Watch};
use chain::channelmonitor::{ANTI_REORG_DELAY, ChannelMonitor, LATENCY_GRACE_PERIOD_BLOCKS};
use chain::transaction::OutPoint;
use chain::keysinterface::KeysInterface;
use ln::channelmanager::{BREAKDOWN_TIMEOUT, ChannelManager, ChannelManagerReadArgs, MPP_TIMEOUT_TICKS, PaymentId, PaymentSendFailure};
use ln::features::{InitFeatures, InvoiceFeatures};
use ln::msgs;
use ln::msgs::ChannelMessageHandler;
use routing::router::{PaymentParameters, get_route};
use util::events::{ClosureReason, Event, MessageSendEvent, MessageSendEventsProvider};
use util::test_utils;
use util::errors::APIError;
use util::enforcing_trait_impls::EnforcingSigner;
use util::ser::{ReadableArgs, Writeable};
use io;

use bitcoin::{Block, BlockHeader, BlockHash};
use bitcoin::network::constants::Network;

use prelude::*;

use ln::functional_test_utils::*;

#[test]
fn retry_single_path_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let _chan_0 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let _chan_1 = create_announced_chan_between_nodes(&nodes, 2, 1, InitFeatures::known(), InitFeatures::known());
	// Rebalance to find a route
	send_payment(&nodes[2], &vec!(&nodes[1])[..], 3_000_000);

	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100_000);

	// Rebalance so that the first hop fails.
	send_payment(&nodes[1], &vec!(&nodes[2])[..], 2_000_000);

	// Make sure the payment fails on the first hop.
	let payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable!(&nodes[1]);
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_updates.commitment_signed, false);
	expect_payment_failed_conditions!(nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain());

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

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;

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

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 3, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	// Rebalance
	send_payment(&nodes[3], &vec!(&nodes[2])[..], 1_500_000);

	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[3], 1_000_000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_id;
	route.paths[0][1].short_channel_id = chan_3_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_id;
	route.paths[1][1].short_channel_id = chan_4_id;

	// Initiate the MPP payment.
	let payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
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
	expect_pending_htlcs_forwardable!(&nodes[2]);
	let htlc_updates = get_htlc_update_msgs!(nodes[2], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[2], 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[2], htlc_updates.commitment_signed, false);
	expect_payment_failed_conditions!(nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain());

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

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;

	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[3], 100_000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_id;
	route.paths[0][1].short_channel_id = chan_3_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_id;
	route.paths[1][1].short_channel_id = chan_4_id;

	// Initiate the MPP payment.
	let _ = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
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
		expect_pending_htlcs_forwardable!(nodes[3]);
		let htlc_fail_updates_3_1 = get_htlc_update_msgs!(nodes[3], nodes[1].node.get_our_node_id());
		assert_eq!(htlc_fail_updates_3_1.update_fail_htlcs.len(), 1);
		nodes[1].node.handle_update_fail_htlc(&nodes[3].node.get_our_node_id(), &htlc_fail_updates_3_1.update_fail_htlcs[0]);
		check_added_monitors!(nodes[3], 1);
		commitment_signed_dance!(nodes[1], nodes[3], htlc_fail_updates_3_1.commitment_signed, false);

		// Failed HTLC from node 1 -> 0
		expect_pending_htlcs_forwardable!(nodes[1]);
		let htlc_fail_updates_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert_eq!(htlc_fail_updates_1_0.update_fail_htlcs.len(), 1);
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_fail_updates_1_0.update_fail_htlcs[0]);
		check_added_monitors!(nodes[1], 1);
		commitment_signed_dance!(nodes[0], nodes[1], htlc_fail_updates_1_0.commitment_signed, false);

		expect_payment_failed_conditions!(nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain().expected_htlc_error_data(23, &[][..]));
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

	let _chan_0 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let _chan_1 = create_announced_chan_between_nodes(&nodes, 2, 1, InitFeatures::known(), InitFeatures::known());
	// Rebalance to find a route
	send_payment(&nodes[2], &vec!(&nodes[1])[..], 3_000_000);

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100_000);

	// Rebalance so that the first hop fails.
	send_payment(&nodes[1], &vec!(&nodes[2])[..], 2_000_000);

	// Make sure the payment fails on the first hop.
	let payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable!(&nodes[1]);
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
	if let Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError { err })) = nodes[0].node.retry_payment(&route, payment_id) {
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

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)),
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
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let (_, _, chan_id_2, _) = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Serialize the ChannelManager prior to sending payments
	let nodes_0_serialized = nodes[0].node.encode();

	// Send two payments - one which will get to nodes[2] and will be claimed, one which we'll time
	// out and retry.
	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);
	let (payment_preimage_1, _, _, payment_id_1) = send_along_route(&nodes[0], route.clone(), &[&nodes[1], &nodes[2]], 1_000_000);
	let payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
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
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	get_monitor!(nodes[0], chan_id).write(&mut chan_0_monitor_serialized).unwrap();

	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), nodes[0].logger, node_cfgs[0].fee_estimator, &persister, keys_manager);
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
			default_config: test_default_channel_config(),
			keys_manager,
			fee_estimator: node_cfgs[0].fee_estimator,
			chain_monitor: nodes[0].chain_monitor,
			tx_broadcaster: nodes[0].tx_broadcaster.clone(),
			logger: nodes[0].logger,
			channel_monitors,
		}).unwrap()
	};
	nodes_0_deserialized = nodes_0_deserialized_tmp;
	assert!(nodes_0_read.is_empty());

	assert!(nodes[0].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0, chan_0_monitor).is_ok());
	nodes[0].node = &nodes_0_deserialized;
	check_added_monitors!(nodes[0], 1);

	// On reload, the ChannelManager should realize it is stale compared to the ChannelMonitor and
	// force-close the channel.
	check_closed_event!(nodes[0], 1, ClosureReason::OutdatedChannelManager);
	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[0].node.has_pending_payments());
	let as_broadcasted_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_broadcasted_txn.len(), 1);
	assert_eq!(as_broadcasted_txn[0], as_commitment_tx);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known(), remote_network_address: None });
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now nodes[1] should send a channel reestablish, which nodes[0] will respond to with an
	// error, as the channel has hit the chain.
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known(), remote_network_address: None });
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());
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
	let htlc_fulfill_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &htlc_fulfill_updates.update_fulfill_htlcs[0]);
	check_added_monitors!(nodes[1], 1);
	commitment_signed_dance!(nodes[1], nodes[2], htlc_fulfill_updates.commitment_signed, false);

	if confirm_before_reload {
		let best_block = nodes[0].blocks.lock().unwrap().last().unwrap().clone();
		nodes[0].node.best_block_updated(&best_block.0, best_block.1);
	}

	// Create a new channel on which to retry the payment before we fail the payment via the
	// HTLC-Timeout transaction. This avoids ChannelManager timing out the payment due to us
	// connecting several blocks while creating the channel (implying time has passed).
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);

	mine_transaction(&nodes[1], &as_commitment_tx);
	let bs_htlc_claim_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_htlc_claim_txn.len(), 1);
	check_spends!(bs_htlc_claim_txn[0], as_commitment_tx);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], None, false, false);

	if !confirm_before_reload {
		mine_transaction(&nodes[0], &as_commitment_tx);
	}
	mine_transaction(&nodes[0], &bs_htlc_claim_txn[0]);
	expect_payment_sent!(nodes[0], payment_preimage_1);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV*4 + 20);
	let as_htlc_timeout_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	check_spends!(as_htlc_timeout_txn[2], funding_tx);
	check_spends!(as_htlc_timeout_txn[0], as_commitment_tx);
	check_spends!(as_htlc_timeout_txn[1], as_commitment_tx);
	assert_eq!(as_htlc_timeout_txn.len(), 3);
	if as_htlc_timeout_txn[0].input[0].previous_output == bs_htlc_claim_txn[0].input[0].previous_output {
		confirm_transaction(&nodes[0], &as_htlc_timeout_txn[1]);
	} else {
		confirm_transaction(&nodes[0], &as_htlc_timeout_txn[0]);
	}
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	expect_payment_failed_conditions!(nodes[0], payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain());

	// Finally, retry the payment (which was reloaded from the ChannelMonitor when nodes[0] was
	// reloaded) via a route over the new channel, which work without issue and eventually be
	// received and claimed at the recipient just like any other payment.
	let (mut new_route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);

	// Update the fee on the middle hop to ensure PaymentSent events have the correct (retried) fee
	// and not the original fee. We also update node[1]'s relevant config as
	// do_claim_payment_along_route expects us to never overpay.
	nodes[1].node.channel_state.lock().unwrap().by_id.get_mut(&chan_id_2).unwrap().config.forwarding_fee_base_msat += 100_000;
	new_route.paths[0][0].fee_msat += 100_000;

	assert!(nodes[0].node.retry_payment(&new_route, payment_id_1).is_err()); // Shouldn't be allowed to retry a fulfilled payment
	nodes[0].node.retry_payment(&new_route, payment_id).unwrap();
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
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Route a payment, but force-close the channel before the HTLC fulfill message arrives at
	// nodes[0].
	let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 10000000);
	nodes[0].node.force_close_channel(&nodes[0].node.list_channels()[0].channel_id).unwrap();
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

	assert!(nodes[1].node.claim_funds(payment_preimage));
	check_added_monitors!(nodes[1], 1);

	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: nodes[1].best_block_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
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
	// returning TemporaryFailure. This should cause the claim event to never make its way to the
	// ChannelManager.
	chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap().clear();
	chanmon_cfgs[0].persister.set_update_ret(Err(ChannelMonitorUpdateErr::TemporaryFailure));

	if payment_timeout {
		connect_blocks(&nodes[0], 1);
	} else {
		connect_block(&nodes[0], &claim_block);
	}

	let funding_txo = OutPoint { txid: funding_tx.txid(), index: 0 };
	let mon_updates: Vec<_> = chanmon_cfgs[0].persister.chain_sync_monitor_persistences.lock().unwrap()
		.get_mut(&funding_txo).unwrap().drain().collect();
	assert_eq!(mon_updates.len(), 1);
	assert!(nodes[0].chain_monitor.release_pending_monitor_events().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	// If we persist the ChannelManager here, we should get the PaymentSent event after
	// deserialization.
	let mut chan_manager_serialized = test_utils::TestVecWriter(Vec::new());
	if !persist_manager_post_event {
		nodes[0].node.write(&mut chan_manager_serialized).unwrap();
	}

	// Now persist the ChannelMonitor and inform the ChainMonitor that we're done, generating the
	// payment sent event.
	chanmon_cfgs[0].persister.set_update_ret(Ok(()));
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	get_monitor!(nodes[0], chan_id).write(&mut chan_0_monitor_serialized).unwrap();
	nodes[0].chain_monitor.chain_monitor.channel_monitor_updated(funding_txo, mon_updates[0]).unwrap();
	if payment_timeout {
		expect_payment_failed!(nodes[0], payment_hash, true);
	} else {
		expect_payment_sent!(nodes[0], payment_preimage);
	}

	// If we persist the ChannelManager after we get the PaymentSent event, we shouldn't get it
	// twice.
	if persist_manager_post_event {
		nodes[0].node.write(&mut chan_manager_serialized).unwrap();
	}

	// Now reload nodes[0]...
	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), nodes[0].logger, node_cfgs[0].fee_estimator, &persister, keys_manager);
	nodes[0].chain_monitor = &new_chain_monitor;
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, mut chan_0_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
		&mut chan_0_monitor_read, keys_manager).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let (_, nodes_0_deserialized_tmp) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(chan_0_monitor.get_funding_txo().0, &mut chan_0_monitor);
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>
			::read(&mut io::Cursor::new(&chan_manager_serialized.0[..]), ChannelManagerReadArgs {
				default_config: Default::default(),
				keys_manager,
				fee_estimator: node_cfgs[0].fee_estimator,
				chain_monitor: nodes[0].chain_monitor,
				tx_broadcaster: nodes[0].tx_broadcaster.clone(),
				logger: nodes[0].logger,
				channel_monitors,
			}).unwrap()
	};
	nodes_0_deserialized = nodes_0_deserialized_tmp;

	assert!(nodes[0].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0, chan_0_monitor).is_ok());
	check_added_monitors!(nodes[0], 1);
	nodes[0].node = &nodes_0_deserialized;

	if persist_manager_post_event {
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	} else if payment_timeout {
		expect_payment_failed!(nodes[0], payment_hash, true);
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
	let nodes_1_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).2;
	let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 100_000);

	// The simplest way to get a failure after a fulfill is to reload nodes[1] from a state
	// pre-fulfill, which we do by serializing it here.
	let mut chan_manager_serialized = test_utils::TestVecWriter(Vec::new());
	nodes[1].node.write(&mut chan_manager_serialized).unwrap();
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	get_monitor!(nodes[1], chan_id).write(&mut chan_0_monitor_serialized).unwrap();

	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[1], 1);
	let htlc_fulfill_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &htlc_fulfill_updates.update_fulfill_htlcs[0]);
	expect_payment_sent_without_paths!(nodes[0], payment_preimage);

	// Now reload nodes[1]...
	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[1].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[1].chain_source), nodes[1].tx_broadcaster.clone(), nodes[1].logger, node_cfgs[1].fee_estimator, &persister, keys_manager);
	nodes[1].chain_monitor = &new_chain_monitor;
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, mut chan_0_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
		&mut chan_0_monitor_read, keys_manager).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let (_, nodes_1_deserialized_tmp) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(chan_0_monitor.get_funding_txo().0, &mut chan_0_monitor);
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>
			::read(&mut io::Cursor::new(&chan_manager_serialized.0[..]), ChannelManagerReadArgs {
				default_config: Default::default(),
				keys_manager,
				fee_estimator: node_cfgs[1].fee_estimator,
				chain_monitor: nodes[1].chain_monitor,
				tx_broadcaster: nodes[1].tx_broadcaster.clone(),
				logger: nodes[1].logger,
				channel_monitors,
			}).unwrap()
	};
	nodes_1_deserialized = nodes_1_deserialized_tmp;

	assert!(nodes[1].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0, chan_0_monitor).is_ok());
	check_added_monitors!(nodes[1], 1);
	nodes[1].node = &nodes_1_deserialized;

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	nodes[1].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable!(nodes[1]);
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
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let amt_msat = 60_000;
	let expiry_secs = 60 * 60;
	let (payment_hash, payment_secret) = nodes[1].node.create_inbound_payment(Some(amt_msat), expiry_secs).unwrap();

	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id())
		.with_features(InvoiceFeatures::known());
	let scorer = test_utils::TestScorer::with_penalty(0);
	let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
	let random_seed_bytes = keys_manager.get_secure_random_bytes();
	let route = get_route(
		&nodes[0].node.get_our_node_id(), &payment_params, &nodes[0].network_graph.read_only(),
		Some(&nodes[0].node.list_usable_channels().iter().collect::<Vec<_>>()),
		amt_msat, TEST_FINAL_CLTV, nodes[0].logger, &scorer, &random_seed_bytes).unwrap();
	let _payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);

	// Make sure to use `get_payment_preimage`
	let payment_preimage = nodes[1].node.get_payment_preimage(payment_hash, payment_secret).unwrap();
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1]], amt_msat, payment_hash, Some(payment_secret), events.pop().unwrap(), true, Some(payment_preimage));
	claim_payment_along_route(&nodes[0], &[&[&nodes[1]]], false, payment_preimage);
}
