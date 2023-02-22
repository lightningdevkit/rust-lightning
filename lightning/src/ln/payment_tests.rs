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
use crate::chain::keysinterface::EntropySource;
use crate::chain::transaction::OutPoint;
use crate::ln::channel::EXPIRE_PREV_CONFIG_TICKS;
use crate::ln::channelmanager::{BREAKDOWN_TIMEOUT, ChannelManager, MPP_TIMEOUT_TICKS, MIN_CLTV_EXPIRY_DELTA, PaymentId, PaymentSendFailure, IDEMPOTENCY_TIMEOUT_TICKS, RecentPaymentDetails};
use crate::ln::features::InvoiceFeatures;
use crate::ln::msgs;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::outbound_payment::Retry;
use crate::routing::gossip::{EffectiveCapacity, RoutingFees};
use crate::routing::router::{get_route, PaymentParameters, Route, RouteHint, RouteHintHop, RouteHop, RouteParameters};
use crate::routing::scoring::ChannelUsage;
use crate::util::events::{ClosureReason, Event, HTLCDestination, MessageSendEvent, MessageSendEventsProvider, PathFailure};
use crate::util::test_utils;
use crate::util::errors::APIError;
use crate::util::ser::Writeable;

use bitcoin::{Block, BlockHeader, TxMerkleNode};
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;

use crate::prelude::*;

use crate::ln::functional_test_utils::*;
use crate::routing::gossip::NodeId;
#[cfg(feature = "std")]
use {
	crate::util::time::tests::SinceEpoch,
	std::time::{SystemTime, Instant, Duration}
};

#[test]
fn mpp_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

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

	let (chan_1_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (chan_2_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 2);
	let (chan_3_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 1, 3);
	let (chan_4_update, _, chan_4_id, _) = create_announced_chan_between_nodes(&nodes, 3, 2);
	// Rebalance
	send_payment(&nodes[3], &vec!(&nodes[2])[..], 1_500_000);

	let amt_msat = 1_000_000;
	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[3], amt_msat);
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
	let mut route_params = RouteParameters {
		payment_params: route.payment_params.clone().unwrap(),
		final_value_msat: amt_msat,
	};

	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), payment_id, route_params.clone(), Retry::Attempts(1)).unwrap();
	check_added_monitors!(nodes[0], 2); // one monitor per path
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	// Pass half of the payment along the success path.
	let success_path_msgs = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 2_000_000, payment_hash, Some(payment_secret), success_path_msgs, false, None);

	// Add the HTLC along the first hop.
	let fail_path_msgs_1 = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
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
	let mut events = nodes[0].node.get_and_clear_pending_events();
	match events[1] {
		Event::PendingHTLCsForwardable { .. } => {},
		_ => panic!("Unexpected event")
	}
	events.remove(1);
	expect_payment_failed_conditions_event(events, payment_hash, false, PaymentFailedConditions::new().mpp_parts_remain());

	// Rebalance the channel so the second half of the payment can succeed.
	send_payment(&nodes[3], &vec!(&nodes[2])[..], 1_500_000);

	// Retry the second half of the payment and make sure it succeeds.
	route.paths.remove(0);
	route_params.final_value_msat = 1_000_000;
	route_params.payment_params.previously_failed_channels.push(chan_4_update.contents.short_channel_id);
	nodes[0].router.expect_find_route(route_params, Ok(route));
	nodes[0].node.process_pending_htlc_forwards();
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

	let (chan_1_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (chan_2_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 2);
	let (chan_3_update, _, chan_3_id, _) = create_announced_chan_between_nodes(&nodes, 1, 3);
	let (chan_4_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 2, 3);

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
	let node_1_msgs = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 200_000, payment_hash, Some(payment_secret), node_1_msgs, false, None);

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
		let node_2_msgs = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
		pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], 200_000, payment_hash, Some(payment_secret), node_2_msgs, true, None);

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

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)),
		true, APIError::ChannelUnavailable { ref err },
		assert_eq!(err, "Peer for first hop currently disconnected"));

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
	let nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestRouter, &test_utils::TestLogger>;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (_, _, chan_id_2, _) = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Serialize the ChannelManager prior to sending payments
	let nodes_0_serialized = nodes[0].node.encode();

	// Send two payments - one which will get to nodes[2] and will be claimed, one which we'll time
	// out and retry.
	let amt_msat = 1_000_000;
	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], amt_msat);
	let (payment_preimage_1, payment_hash_1, _, payment_id_1) = send_along_route(&nodes[0], route.clone(), &[&nodes[1], &nodes[2]], 1_000_000);
	let route_params = RouteParameters {
		payment_params: route.payment_params.clone().unwrap(),
		final_value_msat: amt_msat,
	};
	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	// We relay the payment to nodes[1] while its disconnected from nodes[2], causing the payment
	// to be returned immediately to nodes[0], without having nodes[2] fail the inbound payment
	// which would prevent retry.
	nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id());
	nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id());

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

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: nodes[1].node.init_features(), remote_network_address: None }, true).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now nodes[1] should send a channel reestablish, which nodes[0] will respond to with an
	// error, as the channel has hit the chain.
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: nodes[0].node.init_features(), remote_network_address: None }, false).unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	let as_err = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_err.len(), 1);
	match as_err[0] {
		MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_error(&nodes[0].node.get_our_node_id(), msg);
			check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", &nodes[1].node.get_our_node_id()) });
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
	create_announced_chan_between_nodes(&nodes, 0, 1);
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
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, PaymentFailedConditions::new());

	// Finally, retry the payment (which was reloaded from the ChannelMonitor when nodes[0] was
	// reloaded) via a route over the new channel, which work without issue and eventually be
	// received and claimed at the recipient just like any other payment.
	let (mut new_route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);

	// Update the fee on the middle hop to ensure PaymentSent events have the correct (retried) fee
	// and not the original fee. We also update node[1]'s relevant config as
	// do_claim_payment_along_route expects us to never overpay.
	{
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let mut peer_state = per_peer_state.get(&nodes[2].node.get_our_node_id())
			.unwrap().lock().unwrap();
		let mut channel = peer_state.channel_by_id.get_mut(&chan_id_2).unwrap();
		let mut new_config = channel.config();
		new_config.forwarding_fee_base_msat += 100_000;
		channel.update_config(&new_config);
		new_route.paths[0][0].fee_msat += 100_000;
	}

	// Force expiration of the channel's previous config.
	for _ in 0..EXPIRE_PREV_CONFIG_TICKS {
		nodes[1].node.timer_tick_occurred();
	}

	assert!(nodes[0].node.send_payment(&new_route, payment_hash, &Some(payment_secret), payment_id_1).is_err()); // Shouldn't be allowed to retry a fulfilled payment
	nodes[0].node.send_payment(&new_route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
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
	let first_nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestRouter, &test_utils::TestLogger>;
	let second_persister: test_utils::TestPersister;
	let second_new_chain_monitor: test_utils::TestChainMonitor;
	let second_nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestRouter, &test_utils::TestLogger>;
	let third_persister: test_utils::TestPersister;
	let third_new_chain_monitor: test_utils::TestChainMonitor;
	let third_nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestRouter, &test_utils::TestLogger>;

	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Because we set nodes[1] to manually accept channels, just open a 0-conf channel.
	let (funding_tx, chan_id) = open_zero_conf_channel(&nodes[0], &nodes[1], None);
	confirm_transaction(&nodes[0], &funding_tx);
	confirm_transaction(&nodes[1], &funding_tx);
	// Ignore the announcement_signatures messages
	nodes[0].node.get_and_clear_pending_msg_events();
	nodes[1].node.get_and_clear_pending_msg_events();
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	// Serialize the ChannelManager prior to sending payments
	let mut nodes_0_serialized = nodes[0].node.encode();

	let route = get_route_and_payment_hash!(nodes[0], nodes[2], if use_dust { 1_000 } else { 1_000_000 }).0;
	let (payment_preimage, payment_hash, payment_secret, payment_id) = send_along_route(&nodes[0], route, &[&nodes[1], &nodes[2]], if use_dust { 1_000 } else { 1_000_000 });

	// The ChannelMonitor should always be the latest version, as we're required to persist it
	// during the `commitment_signed_dance!()`.
	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();

	reload_node!(nodes[0], test_default_channel_config(), nodes_0_serialized, &[&chan_0_monitor_serialized], first_persister, first_new_chain_monitor, first_nodes_0_deserialized);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	// On reload, the ChannelManager should realize it is stale compared to the ChannelMonitor and
	// force-close the channel.
	check_closed_event!(nodes[0], 1, ClosureReason::OutdatedChannelManager);
	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[0].node.has_pending_payments());
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: nodes[1].node.init_features(), remote_network_address: None }, true).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now nodes[1] should send a channel reestablish, which nodes[0] will respond to with an
	// error, as the channel has hit the chain.
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: nodes[0].node.init_features(), remote_network_address: None }, false).unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	let as_err = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_err.len(), 1);
	let bs_commitment_tx;
	match as_err[0] {
		MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_error(&nodes[0].node.get_our_node_id(), msg);
			check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", &nodes[1].node.get_our_node_id()) });
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
	match nodes[0].node.send_payment(&new_route, payment_hash, &Some(payment_secret), payment_id) {
		Err(PaymentSendFailure::DuplicatePayment) => {},
		_ => panic!("Unexpected error")
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// After ANTI_REORG_DELAY confirmations, the HTLC should be failed and we can try the payment
	// again. We serialize the node first as we'll then test retrying the HTLC after a restart
	// (which should also still work).
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, PaymentFailedConditions::new());

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	let chan_1_monitor_serialized = get_monitor!(nodes[0], chan_id_3).encode();
	nodes_0_serialized = nodes[0].node.encode();

	// After the payment failed, we're free to send it again.
	assert!(nodes[0].node.send_payment(&new_route, payment_hash, &Some(payment_secret), payment_id).is_ok());
	assert!(!nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	reload_node!(nodes[0], test_default_channel_config(), nodes_0_serialized, &[&chan_0_monitor_serialized, &chan_1_monitor_serialized], second_persister, second_new_chain_monitor, second_nodes_0_deserialized);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	reconnect_nodes(&nodes[0], &nodes[1], (true, true), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	// Now resend the payment, delivering the HTLC and actually claiming it this time. This ensures
	// the payment is not (spuriously) listed as still pending.
	assert!(nodes[0].node.send_payment(&new_route, payment_hash, &Some(payment_secret), payment_id).is_ok());
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], if use_dust { 1_000 } else { 1_000_000 }, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	match nodes[0].node.send_payment(&new_route, payment_hash, &Some(payment_secret), payment_id) {
		Err(PaymentSendFailure::DuplicatePayment) => {},
		_ => panic!("Unexpected error")
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	let chan_1_monitor_serialized = get_monitor!(nodes[0], chan_id_3).encode();
	nodes_0_serialized = nodes[0].node.encode();

	// Check that after reload we can send the payment again (though we shouldn't, since it was
	// claimed previously).
	reload_node!(nodes[0], test_default_channel_config(), nodes_0_serialized, &[&chan_0_monitor_serialized, &chan_1_monitor_serialized], third_persister, third_new_chain_monitor, third_nodes_0_deserialized);
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	reconnect_nodes(&nodes[0], &nodes[1], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	match nodes[0].node.send_payment(&new_route, payment_hash, &Some(payment_secret), payment_id) {
		Err(PaymentSendFailure::DuplicatePayment) => {},
		_ => panic!("Unexpected error")
	}
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
	let nodes_0_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestRouter, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Route a payment, but force-close the channel before the HTLC fulfill message arrives at
	// nodes[0].
	let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 10_000_000);
	nodes[0].node.force_close_broadcasting_latest_txn(&nodes[0].node.list_channels()[0].channel_id, &nodes[1].node.get_our_node_id()).unwrap();
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

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
	assert_eq!(claim_txn.len(), 1);
	check_spends!(claim_txn[0], node_txn[1]);

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
	let nodes_1_deserialized: ChannelManager<&test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestRouter, &test_utils::TestLogger>;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
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

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
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
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let amt_msat = 60_000;
	let expiry_secs = 60 * 60;
	let (payment_hash, payment_secret) = nodes[1].node.create_inbound_payment(Some(amt_msat), expiry_secs, None).unwrap();

	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_features(nodes[1].node.invoice_features());
	let scorer = test_utils::TestScorer::new();
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

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

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

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

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
	assert!(!nodes[0].node.has_pending_payments());
}

#[test]
fn failed_probe_yields_event() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 90000000);

	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), 42);

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
	assert!(!nodes[0].node.has_pending_payments());
}

#[test]
fn onchain_failed_probe_yields_event() {
	// Tests that an attempt to probe over a channel that is eventaully closed results in a failure
	// event.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), 42);

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
	assert!(!nodes[0].node.has_pending_payments());
}

#[test]
fn claimed_send_payment_idempotent() {
	// Tests that `send_payment` (and friends) are (reasonably) idempotent.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1).2;

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

	create_announced_chan_between_nodes(&nodes, 0, 1).2;

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

	// Until we abandon the payment upon path failure, no matter how many timer ticks pass, we still cannot reuse the
	// PaymentId.
	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}
	check_send_rejected!();

	pass_failed_payment_back(&nodes[0], &[&[&nodes[1]]], false, first_payment_hash);

	// However, we can reuse the PaymentId immediately after we `abandon_payment` upon passing the
	// failed payment back.
	nodes[0].node.send_payment(&route, second_payment_hash, &Some(second_payment_secret), payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1]]], 100_000, second_payment_hash, second_payment_secret);
	claim_payment(&nodes[0], &[&nodes[1]], second_payment_preimage);
}

#[derive(PartialEq)]
enum InterceptTest {
	Forward,
	Fail,
	Timeout,
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

	let (_, _, chan_1_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (_, _, chan_2_id, _) = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Send and claim the payment. Inflight HTLCs should be empty.
	let payment_hash = send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 500000).1;
	let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();
	{
		let mut node_0_per_peer_lock;
		let mut node_0_peer_state_lock;
		let channel_1 =  get_channel_ref!(&nodes[0], nodes[1], node_0_per_peer_lock, node_0_peer_state_lock, chan_1_id);

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[0].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			channel_1.get_short_channel_id().unwrap()
		);
		assert_eq!(chan_1_used_liquidity, None);
	}
	{
		let mut node_1_per_peer_lock;
		let mut node_1_peer_state_lock;
		let channel_2 =  get_channel_ref!(&nodes[1], nodes[2], node_1_per_peer_lock, node_1_peer_state_lock, chan_2_id);

		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[2].node.get_our_node_id()),
			channel_2.get_short_channel_id().unwrap()
		);

		assert_eq!(chan_2_used_liquidity, None);
	}
	let pending_payments = nodes[0].node.list_recent_payments();
	assert_eq!(pending_payments.len(), 1);
	assert_eq!(pending_payments[0], RecentPaymentDetails::Fulfilled { payment_hash: Some(payment_hash) });

	// Remove fulfilled payment
	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	// Send the payment, but do not claim it. Our inflight HTLCs should contain the pending payment.
	let (payment_preimage, payment_hash,  _) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 500000);
	let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();
	{
		let mut node_0_per_peer_lock;
		let mut node_0_peer_state_lock;
		let channel_1 =  get_channel_ref!(&nodes[0], nodes[1], node_0_per_peer_lock, node_0_peer_state_lock, chan_1_id);

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[0].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			channel_1.get_short_channel_id().unwrap()
		);
		// First hop accounts for expected 1000 msat fee
		assert_eq!(chan_1_used_liquidity, Some(501000));
	}
	{
		let mut node_1_per_peer_lock;
		let mut node_1_peer_state_lock;
		let channel_2 =  get_channel_ref!(&nodes[1], nodes[2], node_1_per_peer_lock, node_1_peer_state_lock, chan_2_id);

		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[2].node.get_our_node_id()),
			channel_2.get_short_channel_id().unwrap()
		);

		assert_eq!(chan_2_used_liquidity, Some(500000));
	}
	let pending_payments = nodes[0].node.list_recent_payments();
	assert_eq!(pending_payments.len(), 1);
	assert_eq!(pending_payments[0], RecentPaymentDetails::Pending { payment_hash, total_msat: 500000 });

	// Now, let's claim the payment. This should result in the used liquidity to return `None`.
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// Remove fulfilled payment
	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();
	{
		let mut node_0_per_peer_lock;
		let mut node_0_peer_state_lock;
		let channel_1 =  get_channel_ref!(&nodes[0], nodes[1], node_0_per_peer_lock, node_0_peer_state_lock, chan_1_id);

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[0].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()),
			channel_1.get_short_channel_id().unwrap()
		);
		assert_eq!(chan_1_used_liquidity, None);
	}
	{
		let mut node_1_per_peer_lock;
		let mut node_1_peer_state_lock;
		let channel_2 =  get_channel_ref!(&nodes[1], nodes[2], node_1_per_peer_lock, node_1_peer_state_lock, chan_2_id);

		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&nodes[1].node.get_our_node_id()) ,
			&NodeId::from_pubkey(&nodes[2].node.get_our_node_id()),
			channel_2.get_short_channel_id().unwrap()
		);
		assert_eq!(chan_2_used_liquidity, None);
	}

	let pending_payments = nodes[0].node.list_recent_payments();
	assert_eq!(pending_payments.len(), 0);
}

#[test]
fn test_holding_cell_inflight_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

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
		let mut node_0_per_peer_lock;
		let mut node_0_peer_state_lock;
		let channel =  get_channel_ref!(&nodes[0], nodes[1], node_0_per_peer_lock, node_0_peer_state_lock, channel_id);

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

#[test]
fn intercepted_payment() {
	// Test that detecting an intercept scid on payment forward will signal LDK to generate an
	// intercept event, which the LSP can then use to either (a) open a JIT channel to forward the
	// payment or (b) fail the payment.
	do_test_intercepted_payment(InterceptTest::Forward);
	do_test_intercepted_payment(InterceptTest::Fail);
	// Make sure that intercepted payments will be automatically failed back if too many blocks pass.
	do_test_intercepted_payment(InterceptTest::Timeout);
}

fn do_test_intercepted_payment(test: InterceptTest) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut zero_conf_chan_config = test_default_channel_config();
	zero_conf_chan_config.manually_accept_inbound_channels = true;
	let mut intercept_forwards_config = test_default_channel_config();
	intercept_forwards_config.accept_intercept_htlcs = true;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(intercept_forwards_config), Some(zero_conf_chan_config)]);

	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[0].keys_manager.get_secure_random_bytes();

	let _ = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let amt_msat = 100_000;
	let intercept_scid = nodes[1].node.get_intercept_scid();
	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_route_hints(vec![
			RouteHint(vec![RouteHintHop {
				src_node_id: nodes[1].node.get_our_node_id(),
				short_channel_id: intercept_scid,
				fees: RoutingFees {
					base_msat: 1000,
					proportional_millionths: 0,
				},
				cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			}])
		])
		.with_features(nodes[2].node.invoice_features());
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};
	let route = get_route(
		&nodes[0].node.get_our_node_id(), &route_params.payment_params,
		&nodes[0].network_graph.read_only(), None, route_params.final_value_msat,
		route_params.payment_params.final_cltv_expiry_delta, nodes[0].logger, &scorer,
		&random_seed_bytes,
	).unwrap();

	let (payment_hash, payment_secret) = nodes[2].node.create_inbound_payment(Some(amt_msat), 60 * 60, None).unwrap();
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	let payment_event = {
		{
			let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &payment_event.commitment_msg, false, true);

	// Check that we generate the PaymentIntercepted event when an intercept forward is detected.
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (intercept_id, expected_outbound_amount_msat) = match events[0] {
		crate::util::events::Event::HTLCIntercepted {
			intercept_id, expected_outbound_amount_msat, payment_hash: pmt_hash, inbound_amount_msat, requested_next_hop_scid: short_channel_id
		} => {
			assert_eq!(pmt_hash, payment_hash);
			assert_eq!(inbound_amount_msat, route.get_total_amount() + route.get_total_fees());
			assert_eq!(short_channel_id, intercept_scid);
			(intercept_id, expected_outbound_amount_msat)
		},
		_ => panic!()
	};

	// Check for unknown channel id error.
	let unknown_chan_id_err = nodes[1].node.forward_intercepted_htlc(intercept_id, &[42; 32], nodes[2].node.get_our_node_id(), expected_outbound_amount_msat).unwrap_err();
	assert_eq!(unknown_chan_id_err , APIError::ChannelUnavailable  { err: format!("Channel with id {} not found for the passed counterparty node_id {}", log_bytes!([42; 32]), nodes[2].node.get_our_node_id()) });

	if test == InterceptTest::Fail {
		// Ensure we can fail the intercepted payment back.
		nodes[1].node.fail_intercepted_htlc(intercept_id).unwrap();
		expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::UnknownNextHop { requested_forward_scid: intercept_scid }]);
		nodes[1].node.process_pending_htlc_forwards();
		let update_fail = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(&nodes[1], 1);
		assert!(update_fail.update_fail_htlcs.len() == 1);
		let fail_msg = update_fail.update_fail_htlcs[0].clone();
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
		commitment_signed_dance!(nodes[0], nodes[1], update_fail.commitment_signed, false);

		// Ensure the payment fails with the expected error.
		let fail_conditions = PaymentFailedConditions::new()
			.blamed_scid(intercept_scid)
			.blamed_chan_closed(true)
			.expected_htlc_error_data(0x4000 | 10, &[]);
		expect_payment_failed_conditions(&nodes[0], payment_hash, false, fail_conditions);
	} else if test == InterceptTest::Forward {
		// Check that we'll fail as expected when sending to a channel that isn't in `ChannelReady` yet.
		let temp_chan_id = nodes[1].node.create_channel(nodes[2].node.get_our_node_id(), 100_000, 0, 42, None).unwrap();
		let unusable_chan_err = nodes[1].node.forward_intercepted_htlc(intercept_id, &temp_chan_id, nodes[2].node.get_our_node_id(), expected_outbound_amount_msat).unwrap_err();
		assert_eq!(unusable_chan_err , APIError::ChannelUnavailable { err: format!("Channel with id {} not fully established", log_bytes!(temp_chan_id)) });
		assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 1);

		// Open the just-in-time channel so the payment can then be forwarded.
		let (_, channel_id) = open_zero_conf_channel(&nodes[1], &nodes[2], None);

		// Finally, forward the intercepted payment through and claim it.
		nodes[1].node.forward_intercepted_htlc(intercept_id, &channel_id, nodes[2].node.get_our_node_id(), expected_outbound_amount_msat).unwrap();
		expect_pending_htlcs_forwardable!(nodes[1]);

		let payment_event = {
			{
				let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 1);
				added_monitors.clear();
			}
			let mut events = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
		commitment_signed_dance!(nodes[2], nodes[1], &payment_event.commitment_msg, false, true);
		expect_pending_htlcs_forwardable!(nodes[2]);

		let payment_preimage = nodes[2].node.get_payment_preimage(payment_hash, payment_secret).unwrap();
		expect_payment_claimable!(&nodes[2], payment_hash, payment_secret, amt_msat, Some(payment_preimage), nodes[2].node.get_our_node_id());
		do_claim_payment_along_route(&nodes[0], &vec!(&vec!(&nodes[1], &nodes[2])[..]), false, payment_preimage);
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentSent { payment_preimage: ref ev_preimage, payment_hash: ref ev_hash, ref fee_paid_msat, .. } => {
				assert_eq!(payment_preimage, *ev_preimage);
				assert_eq!(payment_hash, *ev_hash);
				assert_eq!(fee_paid_msat, &Some(1000));
			},
			_ => panic!("Unexpected event")
		}
		match events[1] {
			Event::PaymentPathSuccessful { payment_hash: hash, .. } => {
				assert_eq!(hash, Some(payment_hash));
			},
			_ => panic!("Unexpected event")
		}
	} else if test == InterceptTest::Timeout {
		let mut block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: nodes[0].best_block_hash(), merkle_root: TxMerkleNode::all_zeros(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};
		connect_block(&nodes[0], &block);
		connect_block(&nodes[1], &block);
		for _ in 0..TEST_FINAL_CLTV {
			block.header.prev_blockhash = block.block_hash();
			connect_block(&nodes[0], &block);
			connect_block(&nodes[1], &block);
		}
		expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::InvalidForward { requested_forward_scid: intercept_scid }]);
		check_added_monitors!(nodes[1], 1);
		let htlc_timeout_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		assert!(htlc_timeout_updates.update_add_htlcs.is_empty());
		assert_eq!(htlc_timeout_updates.update_fail_htlcs.len(), 1);
		assert!(htlc_timeout_updates.update_fail_malformed_htlcs.is_empty());
		assert!(htlc_timeout_updates.update_fee.is_none());

		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_timeout_updates.update_fail_htlcs[0]);
		commitment_signed_dance!(nodes[0], nodes[1], htlc_timeout_updates.commitment_signed, false);
		expect_payment_failed!(nodes[0], payment_hash, false, 0x2000 | 2, []);

		// Check for unknown intercept id error.
		let (_, channel_id) = open_zero_conf_channel(&nodes[1], &nodes[2], None);
		let unknown_intercept_id_err = nodes[1].node.forward_intercepted_htlc(intercept_id, &channel_id, nodes[2].node.get_our_node_id(), expected_outbound_amount_msat).unwrap_err();
		assert_eq!(unknown_intercept_id_err , APIError::APIMisuseError { err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0)) });
		let unknown_intercept_id_err = nodes[1].node.fail_intercepted_htlc(intercept_id).unwrap_err();
		assert_eq!(unknown_intercept_id_err , APIError::APIMisuseError { err: format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0)) });
	}
}

#[derive(PartialEq)]
enum AutoRetry {
	Success,
	Spontaneous,
	FailAttempts,
	FailTimeout,
	FailOnRestart,
	FailOnRetry,
}

#[test]
fn automatic_retries() {
	do_automatic_retries(AutoRetry::Success);
	do_automatic_retries(AutoRetry::Spontaneous);
	do_automatic_retries(AutoRetry::FailAttempts);
	do_automatic_retries(AutoRetry::FailTimeout);
	do_automatic_retries(AutoRetry::FailOnRestart);
	do_automatic_retries(AutoRetry::FailOnRetry);
}
fn do_automatic_retries(test: AutoRetry) {
	// Test basic automatic payment retries in ChannelManager. See individual `test` variant comments
	// below.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);

	let persister;
	let new_chain_monitor;
	let node_0_deserialized;

	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let channel_id_1 = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let channel_id_2 = create_announced_chan_between_nodes(&nodes, 2, 1).2;

	// Marshall data to send the payment
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let amt_msat = 1000;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};
	let (_, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], amt_msat);

	macro_rules! pass_failed_attempt_with_retry_along_path {
		($failing_channel_id: expr, $expect_pending_htlcs_forwardable: expr) => {
			// Send a payment attempt that fails due to lack of liquidity on the second hop
			check_added_monitors!(nodes[0], 1);
			let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
			let mut update_add = update_0.update_add_htlcs[0].clone();
			nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
			commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);
			expect_pending_htlcs_forwardable_ignore!(nodes[1]);
			nodes[1].node.process_pending_htlc_forwards();
			expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1],
				vec![HTLCDestination::NextHopChannel {
					node_id: Some(nodes[2].node.get_our_node_id()),
					channel_id: $failing_channel_id,
				}]);
			nodes[1].node.process_pending_htlc_forwards();
			let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
			check_added_monitors!(&nodes[1], 1);
			assert!(update_1.update_fail_htlcs.len() == 1);
			let fail_msg = update_1.update_fail_htlcs[0].clone();
			nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
			commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

			// Ensure the attempt fails and a new PendingHTLCsForwardable event is generated for the retry
			let mut events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 2);
			match events[0] {
				Event::PaymentPathFailed { payment_hash: ev_payment_hash, payment_failed_permanently, ..  } => {
					assert_eq!(payment_hash, ev_payment_hash);
					assert_eq!(payment_failed_permanently, false);
				},
				_ => panic!("Unexpected event"),
			}
			if $expect_pending_htlcs_forwardable {
				match events[1] {
					Event::PendingHTLCsForwardable { .. } => {},
					_ => panic!("Unexpected event"),
				}
			} else {
				match events[1] {
					Event::PaymentFailed { payment_hash: ev_payment_hash, .. } => {
						assert_eq!(payment_hash, ev_payment_hash);
					},
					_ => panic!("Unexpected event"),
				}
			}
		}
	}

	if test == AutoRetry::Success {
		// Test that we can succeed on the first retry.
		nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// Open a new channel with liquidity on the second hop so we can find a route for the retry
		// attempt, since the initial second hop channel will be excluded from pathfinding
		create_announced_chan_between_nodes(&nodes, 1, 2);

		// We retry payments in `process_pending_htlc_forwards`
		nodes[0].node.process_pending_htlc_forwards();
		check_added_monitors!(nodes[0], 1);
		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1], &nodes[2]], amt_msat, payment_hash, Some(payment_secret), msg_events.pop().unwrap(), true, None);
		claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], false, payment_preimage);
	} else if test == AutoRetry::Spontaneous {
		nodes[0].node.send_spontaneous_payment_with_retry(Some(payment_preimage), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// Open a new channel with liquidity on the second hop so we can find a route for the retry
		// attempt, since the initial second hop channel will be excluded from pathfinding
		create_announced_chan_between_nodes(&nodes, 1, 2);

		// We retry payments in `process_pending_htlc_forwards`
		nodes[0].node.process_pending_htlc_forwards();
		check_added_monitors!(nodes[0], 1);
		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		pass_along_path(&nodes[0], &[&nodes[1], &nodes[2]], amt_msat, payment_hash, None, msg_events.pop().unwrap(), true, Some(payment_preimage));
		claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], false, payment_preimage);
	} else if test == AutoRetry::FailAttempts {
		// Ensure ChannelManager will not retry a payment if it has run out of payment attempts.
		nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// Open a new channel with no liquidity on the second hop so we can find a (bad) route for
		// the retry attempt, since the initial second hop channel will be excluded from pathfinding
		let channel_id_3 = create_announced_chan_between_nodes(&nodes, 2, 1).2;

		// We retry payments in `process_pending_htlc_forwards`
		nodes[0].node.process_pending_htlc_forwards();
		pass_failed_attempt_with_retry_along_path!(channel_id_3, false);

		// Ensure we won't retry a second time.
		nodes[0].node.process_pending_htlc_forwards();
		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 0);
	} else if test == AutoRetry::FailTimeout {
		#[cfg(not(feature = "no-std"))] {
			// Ensure ChannelManager will not retry a payment if it times out due to Retry::Timeout.
			nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Timeout(Duration::from_secs(60))).unwrap();
			pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

			// Advance the time so the second attempt fails due to timeout.
			SinceEpoch::advance(Duration::from_secs(61));

			// Make sure we don't retry again.
			nodes[0].node.process_pending_htlc_forwards();
			let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(msg_events.len(), 0);

			let mut events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentFailed { payment_hash: ref ev_payment_hash, payment_id: ref ev_payment_id } => {
					assert_eq!(payment_hash, *ev_payment_hash);
					assert_eq!(PaymentId(payment_hash.0), *ev_payment_id);
				},
				_ => panic!("Unexpected event"),
			}
		}
	} else if test == AutoRetry::FailOnRestart {
		// Ensure ChannelManager will not retry a payment after restart, even if there were retry
		// attempts remaining prior to restart.
		nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(2)).unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// Open a new channel with no liquidity on the second hop so we can find a (bad) route for
		// the retry attempt, since the initial second hop channel will be excluded from pathfinding
		let channel_id_3 = create_announced_chan_between_nodes(&nodes, 2, 1).2;

		// Ensure the first retry attempt fails, with 1 retry attempt remaining
		nodes[0].node.process_pending_htlc_forwards();
		pass_failed_attempt_with_retry_along_path!(channel_id_3, true);

		// Restart the node and ensure that ChannelManager does not use its remaining retry attempt
		let node_encoded = nodes[0].node.encode();
		let chan_1_monitor_serialized = get_monitor!(nodes[0], channel_id_1).encode();
		reload_node!(nodes[0], node_encoded, &[&chan_1_monitor_serialized], persister, new_chain_monitor, node_0_deserialized);

		let mut events = nodes[0].node.get_and_clear_pending_events();
		expect_pending_htlcs_forwardable_from_events!(nodes[0], events, true);
		// Make sure we don't retry again.
		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 0);

		let mut events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash: ref ev_payment_hash, payment_id: ref ev_payment_id } => {
				assert_eq!(payment_hash, *ev_payment_hash);
				assert_eq!(PaymentId(payment_hash.0), *ev_payment_id);
			},
			_ => panic!("Unexpected event"),
		}
	} else if test == AutoRetry::FailOnRetry {
		nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// We retry payments in `process_pending_htlc_forwards`. Since our channel closed, we should
		// fail to find a route.
		nodes[0].node.process_pending_htlc_forwards();
		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 0);

		let mut events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash: ref ev_payment_hash, payment_id: ref ev_payment_id } => {
				assert_eq!(payment_hash, *ev_payment_hash);
				assert_eq!(PaymentId(payment_hash.0), *ev_payment_id);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn auto_retry_partial_failure() {
	// Test that we'll retry appropriately on send partial failure and retry partial failure.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;

	// Marshall data to send the payment
	let amt_msat = 20_000;
	let (_, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};

	// Ensure the first monitor update (for the initial send path1 over chan_1) succeeds, but the
	// second (for the initial send path2 over chan_2) fails.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::PermanentFailure);
	// Ensure third monitor update (for the retry1's path1 over chan_1) succeeds, but the fourth (for
	// the retry1's path2 over chan_3) fails, and monitor updates succeed after that.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::PermanentFailure);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);

	// Configure the initial send, retry1 and retry2's paths.
	let send_route = Route {
		paths: vec![
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_id,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: amt_msat / 2,
				cltv_expiry_delta: 100,
			}],
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_2_id,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: amt_msat / 2,
				cltv_expiry_delta: 100,
			}],
		],
		payment_params: Some(route_params.payment_params.clone()),
	};
	let retry_1_route = Route {
		paths: vec![
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_id,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: amt_msat / 4,
				cltv_expiry_delta: 100,
			}],
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_3_id,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: amt_msat / 4,
				cltv_expiry_delta: 100,
			}],
		],
		payment_params: Some(route_params.payment_params.clone()),
	};
	let retry_2_route = Route {
		paths: vec![
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_id,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: amt_msat / 4,
				cltv_expiry_delta: 100,
			}],
		],
		payment_params: Some(route_params.payment_params.clone()),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(send_route));
	let mut payment_params = route_params.payment_params.clone();
	payment_params.previously_failed_channels.push(chan_2_id);
	nodes[0].router.expect_find_route(RouteParameters {
			payment_params, final_value_msat: amt_msat / 2,
		}, Ok(retry_1_route));
	let mut payment_params = route_params.payment_params.clone();
	payment_params.previously_failed_channels.push(chan_3_id);
	nodes[0].router.expect_find_route(RouteParameters {
			payment_params, final_value_msat: amt_msat / 4,
		}, Ok(retry_2_route));

	// Send a payment that will partially fail on send, then partially fail on retry, then succeed.
	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(3)).unwrap();
	let closed_chan_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(closed_chan_events.len(), 4);
	match closed_chan_events[0] {
		Event::ChannelClosed { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match closed_chan_events[1] {
		Event::PaymentPathFailed { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match closed_chan_events[2] {
		Event::ChannelClosed { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match closed_chan_events[3] {
		Event::PaymentPathFailed { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// Pass the first part of the payment along the path.
	check_added_monitors!(nodes[0], 5); // three outbound channel updates succeeded, two permanently failed
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();

	// First message is the first update_add, remaining messages are broadcasting channel updates and
	// errors for the permfailed channels
	assert_eq!(msg_events.len(), 5);
	let mut payment_event = SendEvent::from_event(msg_events.remove(0));

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
	check_added_monitors!(nodes[0], 1);
	let as_second_htlc_updates = SendEvent::from_node(&nodes[0]);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_first_cs);
	check_added_monitors!(nodes[0], 1);
	let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_first_raa);
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_second_htlc_updates.msgs[0]);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_second_htlc_updates.msgs[1]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_second_htlc_updates.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let (bs_second_raa, bs_second_cs) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_cs);
	check_added_monitors!(nodes[0], 1);
	let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
	check_added_monitors!(nodes[1], 1);

	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_payment_claimable!(nodes[1], payment_hash, payment_secret, amt_msat);
	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, amt_msat);
	let bs_claim_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(bs_claim_update.update_fulfill_htlcs.len(), 1);

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_claim_update.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_claim_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let (as_third_raa, as_third_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_third_raa);
	check_added_monitors!(nodes[1], 4);
	let bs_second_claim_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_third_cs);
	check_added_monitors!(nodes[1], 1);
	let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_third_raa);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_second_claim_update.update_fulfill_htlcs[0]);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &bs_second_claim_update.update_fulfill_htlcs[1]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_claim_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let (as_fourth_raa, as_fourth_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_fourth_raa);
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_fourth_cs);
	check_added_monitors!(nodes[1], 1);
	let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa);
	check_added_monitors!(nodes[0], 1);
	expect_payment_sent!(nodes[0], payment_preimage);
}

#[test]
fn auto_retry_zero_attempts_send_error() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;

	// Marshall data to send the payment
	let amt_msat = 20_000;
	let (_, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::PermanentFailure);
	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	assert_eq!(nodes[0].node.get_and_clear_pending_msg_events().len(), 2); // channel close messages
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 3);
	if let Event::ChannelClosed { .. } = events[0] { } else { panic!(); }
	if let Event::PaymentPathFailed { .. } = events[1] { } else { panic!(); }
	if let Event::PaymentFailed { .. } = events[2] { } else { panic!(); }
	check_added_monitors!(nodes[0], 2);
}

#[test]
fn fails_paying_after_rejected_by_payee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;

	// Marshall data to send the payment
	let amt_msat = 20_000;
	let (_, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};

	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(&nodes[1], payment_hash, payment_secret, amt_msat);

	nodes[1].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], [HTLCDestination::FailedPayment { payment_hash }]);
	pass_failed_payment_back(&nodes[0], &[&[&nodes[1]]], false, payment_hash);
}

#[test]
fn retry_multi_path_single_failed_payment() {
	// Tests that we can/will retry after a single path of an MPP payment failed immediately
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);

	let amt_msat = 100_010_000;

	let (_, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let route_params = RouteParameters {
		payment_params: payment_params.clone(),
		final_value_msat: amt_msat,
	};

	let chans = nodes[0].node.list_usable_channels();
	let mut route = Route {
		paths: vec![
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chans[0].short_channel_id.unwrap(),
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 10_000,
				cltv_expiry_delta: 100,
			}],
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chans[1].short_channel_id.unwrap(),
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 100_000_001, // Our default max-HTLC-value is 10% of the channel value, which this is one more than
				cltv_expiry_delta: 100,
			}],
		],
		payment_params: Some(payment_params),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	// On retry, split the payment across both channels.
	route.paths[0][0].fee_msat = 50_000_001;
	route.paths[1][0].fee_msat = 50_000_000;
	let mut pay_params = route.payment_params.clone().unwrap();
	pay_params.previously_failed_channels.push(chans[1].short_channel_id.unwrap());
	nodes[0].router.expect_find_route(RouteParameters {
			payment_params: pay_params,
			// Note that the second request here requests the amount we originally failed to send,
			// not the amount remaining on the full payment, which should be changed.
			final_value_msat: 100_000_001,
		}, Ok(route.clone()));

	{
		let scorer = chanmon_cfgs[0].scorer.lock().unwrap();
		// The initial send attempt, 2 paths
		scorer.expect_usage(chans[0].short_channel_id.unwrap(), ChannelUsage { amount_msat: 10_000, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown });
		scorer.expect_usage(chans[1].short_channel_id.unwrap(), ChannelUsage { amount_msat: 100_000_001, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown });
		// The retry, 2 paths. Ensure that the in-flight HTLC amount is factored in.
		scorer.expect_usage(chans[0].short_channel_id.unwrap(), ChannelUsage { amount_msat: 50_000_001, inflight_htlc_msat: 10_000, effective_capacity: EffectiveCapacity::Unknown });
		scorer.expect_usage(chans[1].short_channel_id.unwrap(), ChannelUsage { amount_msat: 50_000_000, inflight_htlc_msat: 0, effective_capacity: EffectiveCapacity::Unknown });
	}

	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentPathFailed { payment_hash: ev_payment_hash, payment_failed_permanently: false,
			failure: PathFailure::InitialSend { err: APIError::ChannelUnavailable { err: ref err_msg }},
			short_channel_id: Some(expected_scid), .. } =>
		{
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(expected_scid, route.paths[1][0].short_channel_id);
			assert!(err_msg.contains("max HTLC"));
		},
		_ => panic!("Unexpected event"),
	}
	let htlc_msgs = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(htlc_msgs.len(), 2);
	check_added_monitors!(nodes[0], 2);
}

#[test]
fn immediate_retry_on_failure() {
	// Tests that we can/will retry immediately after a failure
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);

	let amt_msat = 100_000_001;
	let (_, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};

	let chans = nodes[0].node.list_usable_channels();
	let mut route = Route {
		paths: vec![
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chans[0].short_channel_id.unwrap(),
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 100_000_001, // Our default max-HTLC-value is 10% of the channel value, which this is one more than
				cltv_expiry_delta: 100,
			}],
		],
		payment_params: Some(PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	// On retry, split the payment across both channels.
	route.paths.push(route.paths[0].clone());
	route.paths[0][0].short_channel_id = chans[1].short_channel_id.unwrap();
	route.paths[0][0].fee_msat = 50_000_000;
	route.paths[1][0].fee_msat = 50_000_001;
	let mut pay_params = route_params.payment_params.clone();
	pay_params.previously_failed_channels.push(chans[0].short_channel_id.unwrap());
	nodes[0].router.expect_find_route(RouteParameters {
			payment_params: pay_params, final_value_msat: amt_msat,
		}, Ok(route.clone()));

	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentPathFailed { payment_hash: ev_payment_hash, payment_failed_permanently: false,
			failure: PathFailure::InitialSend { err: APIError::ChannelUnavailable { err: ref err_msg }},
			short_channel_id: Some(expected_scid), .. } =>
		{
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(expected_scid, route.paths[1][0].short_channel_id);
			assert!(err_msg.contains("max HTLC"));
		},
		_ => panic!("Unexpected event"),
	}
	let htlc_msgs = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(htlc_msgs.len(), 2);
	check_added_monitors!(nodes[0], 2);
}

#[test]
fn no_extra_retries_on_back_to_back_fail() {
	// In a previous release, we had a race where we may exceed the payment retry count if we
	// get two failures in a row with the second indicating that all paths had failed (this field,
	// `all_paths_failed`, has since been removed).
	// Generally, when we give up trying to retry a payment, we don't know for sure what the
	// current state of the ChannelManager event queue is. Specifically, we cannot be sure that
	// there are not multiple additional `PaymentPathFailed` or even `PaymentSent` events
	// pending which we will see later. Thus, when we previously removed the retry tracking map
	// entry after a `all_paths_failed` `PaymentPathFailed` event, we may have dropped the
	// retry entry even though more events for the same payment were still pending. This led to
	// us retrying a payment again even though we'd already given up on it.
	//
	// We now have a separate event - `PaymentFailed` which indicates no HTLCs remain and which
	// is used to remove the payment retry counter entries instead. This tests for the specific
	// excess-retry case while also testing `PaymentFailed` generation.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_1_scid = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0).0.contents.short_channel_id;
	let chan_2_scid = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 0).0.contents.short_channel_id;

	let amt_msat = 200_000_000;
	let (_, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};

	let mut route = Route {
		paths: vec![
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_scid,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 0, // nodes[1] will fail the payment as we don't pay its fee
				cltv_expiry_delta: 100,
			}, RouteHop {
				pubkey: nodes[2].node.get_our_node_id(),
				node_features: nodes[2].node.node_features(),
				short_channel_id: chan_2_scid,
				channel_features: nodes[2].node.channel_features(),
				fee_msat: 100_000_000,
				cltv_expiry_delta: 100,
			}],
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_scid,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 0, // nodes[1] will fail the payment as we don't pay its fee
				cltv_expiry_delta: 100,
			}, RouteHop {
				pubkey: nodes[2].node.get_our_node_id(),
				node_features: nodes[2].node.node_features(),
				short_channel_id: chan_2_scid,
				channel_features: nodes[2].node.channel_features(),
				fee_msat: 100_000_000,
				cltv_expiry_delta: 100,
			}]
		],
		payment_params: Some(PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	let mut second_payment_params = route_params.payment_params.clone();
	second_payment_params.previously_failed_channels = vec![chan_2_scid, chan_2_scid];
	// On retry, we'll only return one path
	route.paths.remove(1);
	route.paths[0][1].fee_msat = amt_msat;
	nodes[0].router.expect_find_route(RouteParameters {
			payment_params: second_payment_params,
			final_value_msat: amt_msat,
		}, Ok(route.clone()));

	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
	let htlc_updates = SendEvent::from_node(&nodes[0]);
	check_added_monitors!(nodes[0], 1);
	assert_eq!(htlc_updates.msgs.len(), 1);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &htlc_updates.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &htlc_updates.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
	check_added_monitors!(nodes[0], 1);
	let second_htlc_updates = SendEvent::from_node(&nodes[0]);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_first_cs);
	check_added_monitors!(nodes[0], 1);
	let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &second_htlc_updates.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &second_htlc_updates.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_first_raa);
	check_added_monitors!(nodes[1], 1);
	let bs_fail_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_update.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_fail_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let (as_second_raa, as_third_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
	check_added_monitors!(nodes[1], 1);
	let bs_second_fail_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_third_cs);
	check_added_monitors!(nodes[1], 1);
	let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_second_fail_update.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_fail_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_third_raa);
	check_added_monitors!(nodes[0], 1);
	let (as_third_raa, as_fourth_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_third_raa);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_fourth_cs);
	check_added_monitors!(nodes[1], 1);
	let bs_fourth_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_fourth_raa);
	check_added_monitors!(nodes[0], 1);

	// At this point A has sent two HTLCs which both failed due to lack of fee. It now has two
	// pending `PaymentPathFailed` events, one with `all_paths_failed` unset, and the second
	// with it set.
	//
	// Previously, we retried payments in an event consumer, which would retry each
	// `PaymentPathFailed` individually. In that setup, we had retried the payment in response to
	// the first `PaymentPathFailed`, then seen the second `PaymentPathFailed` with
	// `all_paths_failed` set and assumed the payment was completely failed. We ultimately fixed it
	// by adding the `PaymentFailed` event.
	//
	// Because we now retry payments as a batch, we simply return a single-path route in the
	// second, batched, request, have that fail, ensure the payment was abandoned.
	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 3);
	match events[0] {
		Event::PaymentPathFailed { payment_hash: ev_payment_hash, payment_failed_permanently, ..  } => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(payment_failed_permanently, false);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PendingHTLCsForwardable { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[2] {
		Event::PaymentPathFailed { payment_hash: ev_payment_hash, payment_failed_permanently, ..  } => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(payment_failed_permanently, false);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.process_pending_htlc_forwards();
	let retry_htlc_updates = SendEvent::from_node(&nodes[0]);
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &retry_htlc_updates.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &retry_htlc_updates.commitment_msg, false, true);
	let bs_fail_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_update.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], &bs_fail_update.commitment_signed, false, true);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentPathFailed { payment_hash: ev_payment_hash, payment_failed_permanently, ..  } => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(payment_failed_permanently, false);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentFailed { payment_hash: ref ev_payment_hash, payment_id: ref ev_payment_id } => {
			assert_eq!(payment_hash, *ev_payment_hash);
			assert_eq!(PaymentId(payment_hash.0), *ev_payment_id);
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_simple_partial_retry() {
	// In the first version of the in-`ChannelManager` payment retries, retries were sent for the
	// full amount of the payment, rather than only the missing amount. Here we simply test for
	// this by sending a payment with two parts, failing one, and retrying the second. Note that
	// `TestRouter` will check that the `RouteParameters` (which contain the amount) matches the
	// request.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan_1_scid = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0).0.contents.short_channel_id;
	let chan_2_scid = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 0).0.contents.short_channel_id;

	let amt_msat = 200_000_000;
	let (_, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[2], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};

	let mut route = Route {
		paths: vec![
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_scid,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 0, // nodes[1] will fail the payment as we don't pay its fee
				cltv_expiry_delta: 100,
			}, RouteHop {
				pubkey: nodes[2].node.get_our_node_id(),
				node_features: nodes[2].node.node_features(),
				short_channel_id: chan_2_scid,
				channel_features: nodes[2].node.channel_features(),
				fee_msat: 100_000_000,
				cltv_expiry_delta: 100,
			}],
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_scid,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 100_000,
				cltv_expiry_delta: 100,
			}, RouteHop {
				pubkey: nodes[2].node.get_our_node_id(),
				node_features: nodes[2].node.node_features(),
				short_channel_id: chan_2_scid,
				channel_features: nodes[2].node.channel_features(),
				fee_msat: 100_000_000,
				cltv_expiry_delta: 100,
			}]
		],
		payment_params: Some(PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	let mut second_payment_params = route_params.payment_params.clone();
	second_payment_params.previously_failed_channels = vec![chan_2_scid];
	// On retry, we'll only be asked for one path (or 100k sats)
	route.paths.remove(0);
	nodes[0].router.expect_find_route(RouteParameters {
			payment_params: second_payment_params,
			final_value_msat: amt_msat / 2,
		}, Ok(route.clone()));

	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params, Retry::Attempts(1)).unwrap();
	let htlc_updates = SendEvent::from_node(&nodes[0]);
	check_added_monitors!(nodes[0], 1);
	assert_eq!(htlc_updates.msgs.len(), 1);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &htlc_updates.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &htlc_updates.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_first_raa);
	check_added_monitors!(nodes[0], 1);
	let second_htlc_updates = SendEvent::from_node(&nodes[0]);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_first_cs);
	check_added_monitors!(nodes[0], 1);
	let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &second_htlc_updates.msgs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &second_htlc_updates.commitment_msg);
	check_added_monitors!(nodes[1], 1);
	let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_first_raa);
	check_added_monitors!(nodes[1], 1);
	let bs_fail_update = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_raa);
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_update.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_fail_update.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	let (as_second_raa, as_third_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_second_raa);
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_third_cs);
	check_added_monitors!(nodes[1], 1);

	let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_third_raa);
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentPathFailed { payment_hash: ev_payment_hash, payment_failed_permanently, ..  } => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(payment_failed_permanently, false);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PendingHTLCsForwardable { .. } => {},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.process_pending_htlc_forwards();
	let retry_htlc_updates = SendEvent::from_node(&nodes[0]);
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &retry_htlc_updates.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &retry_htlc_updates.commitment_msg, false, true);

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let bs_forward_update = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &bs_forward_update.update_add_htlcs[0]);
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &bs_forward_update.update_add_htlcs[1]);
	commitment_signed_dance!(nodes[2], nodes[1], &bs_forward_update.commitment_signed, false);

	expect_pending_htlcs_forwardable!(nodes[2]);
	expect_payment_claimable!(nodes[2], payment_hash, payment_secret, amt_msat);
}

#[test]
#[cfg(feature = "std")]
fn test_threaded_payment_retries() {
	// In the first version of the in-`ChannelManager` payment retries, retries weren't limited to
	// a single thread and would happily let multiple threads run retries at the same time. Because
	// retries are done by first calculating the amount we need to retry, then dropping the
	// relevant lock, then actually sending, we would happily let multiple threads retry the same
	// amount at the same time, overpaying our original HTLC!
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	// There is one mitigating guardrail when retrying payments - we can never over-pay by more
	// than 10% of the original value. Thus, we want all our retries to be below that. In order to
	// keep things simple, we route one HTLC for 0.1% of the payment over channel 1 and the rest
	// out over channel 3+4. This will let us ignore 99% of the payment value and deal with only
	// our channel.
	let chan_1_scid = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0).0.contents.short_channel_id;
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 10_000_000, 0);
	let chan_3_scid = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 10_000_000, 0).0.contents.short_channel_id;
	let chan_4_scid = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 0).0.contents.short_channel_id;

	let amt_msat = 100_000_000;
	let (_, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[2], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_features(invoice_features);
	let mut route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
	};

	let mut route = Route {
		paths: vec![
			vec![RouteHop {
				pubkey: nodes[1].node.get_our_node_id(),
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_scid,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 0,
				cltv_expiry_delta: 100,
			}, RouteHop {
				pubkey: nodes[3].node.get_our_node_id(),
				node_features: nodes[2].node.node_features(),
				short_channel_id: 42, // Set a random SCID which nodes[1] will fail as unknown
				channel_features: nodes[2].node.channel_features(),
				fee_msat: amt_msat / 1000,
				cltv_expiry_delta: 100,
			}],
			vec![RouteHop {
				pubkey: nodes[2].node.get_our_node_id(),
				node_features: nodes[2].node.node_features(),
				short_channel_id: chan_3_scid,
				channel_features: nodes[2].node.channel_features(),
				fee_msat: 100_000,
				cltv_expiry_delta: 100,
			}, RouteHop {
				pubkey: nodes[3].node.get_our_node_id(),
				node_features: nodes[3].node.node_features(),
				short_channel_id: chan_4_scid,
				channel_features: nodes[3].node.channel_features(),
				fee_msat: amt_msat - amt_msat / 1000,
				cltv_expiry_delta: 100,
			}]
		],
		payment_params: Some(PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));

	nodes[0].node.send_payment_with_retry(payment_hash, &Some(payment_secret), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0xdeadbeef)).unwrap();
	check_added_monitors!(nodes[0], 2);
	let mut send_msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(send_msg_events.len(), 2);
	send_msg_events.retain(|msg|
		if let MessageSendEvent::UpdateHTLCs { node_id, .. } = msg {
			// Drop the commitment update for nodes[2], we can just let that one sit pending
			// forever.
			*node_id == nodes[1].node.get_our_node_id()
		} else { panic!(); }
	);

	// from here on out, the retry `RouteParameters` amount will be amt/1000
	route_params.final_value_msat /= 1000;
	route.paths.pop();

	let end_time = Instant::now() + Duration::from_secs(1);
	macro_rules! thread_body { () => { {
		// We really want std::thread::scope, but its not stable until 1.63. Until then, we get unsafe.
		let node_ref = NodePtr::from_node(&nodes[0]);
		move || {
			let node_a = unsafe { &*node_ref.0 };
			while Instant::now() < end_time {
				node_a.node.get_and_clear_pending_events(); // wipe the PendingHTLCsForwardable
				// Ignore if we have any pending events, just always pretend we just got a
				// PendingHTLCsForwardable
				node_a.node.process_pending_htlc_forwards();
			}
		}
	} } }
	let mut threads = Vec::new();
	for _ in 0..16 { threads.push(std::thread::spawn(thread_body!())); }

	// Back in the main thread, poll pending messages and make sure that we never have more than
	// one HTLC pending at a time. Note that the commitment_signed_dance will fail horribly if
	// there are HTLC messages shoved in while its running. This allows us to test that we never
	// generate an additional update_add_htlc until we've fully failed the first.
	let mut previously_failed_channels = Vec::new();
	loop {
		assert_eq!(send_msg_events.len(), 1);
		let send_event = SendEvent::from_event(send_msg_events.pop().unwrap());
		assert_eq!(send_event.msgs.len(), 1);

		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], send_event.commitment_msg, false, true);

		// Note that we only push one route into `expect_find_route` at a time, because that's all
		// the retries (should) need. If the bug is reintroduced "real" routes may be selected, but
		// we should still ultimately fail for the same reason - because we're trying to send too
		// many HTLCs at once.
		let mut new_route_params = route_params.clone();
		previously_failed_channels.push(route.paths[0][1].short_channel_id);
		new_route_params.payment_params.previously_failed_channels = previously_failed_channels.clone();
		route.paths[0][1].short_channel_id += 1;
		nodes[0].router.expect_find_route(new_route_params, Ok(route.clone()));

		let bs_fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &bs_fail_updates.update_fail_htlcs[0]);
		// The "normal" commitment_signed_dance delivers the final RAA and then calls
		// `check_added_monitors` to ensure only the one RAA-generated monitor update was created.
		// This races with our other threads which may generate an add-HTLCs commitment update via
		// `process_pending_htlc_forwards`. Instead, we defer the monitor update check until after
		// *we've* called `process_pending_htlc_forwards` when its guaranteed to have two updates.
		let last_raa = commitment_signed_dance!(nodes[0], nodes[1], bs_fail_updates.commitment_signed, false, true, false, true);
		nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &last_raa);

		let cur_time = Instant::now();
		if cur_time > end_time {
			for thread in threads.drain(..) { thread.join().unwrap(); }
		}

		// Make sure we have some events to handle when we go around...
		nodes[0].node.get_and_clear_pending_events(); // wipe the PendingHTLCsForwardable
		nodes[0].node.process_pending_htlc_forwards();
		send_msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		check_added_monitors!(nodes[0], 2);

		if cur_time > end_time {
			break;
		}
	}
}

fn do_no_missing_sent_on_midpoint_reload(persist_manager_with_payment: bool) {
	// Test that if we reload in the middle of an HTLC claim commitment signed dance we'll still
	// receive the PaymentSent event even if the ChannelManager had no idea about the payment when
	// it was last persisted.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let (persister_a, persister_b, persister_c);
	let (chain_monitor_a, chain_monitor_b, chain_monitor_c);
	let (nodes_0_deserialized, nodes_0_deserialized_b, nodes_0_deserialized_c);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let mut nodes_0_serialized = Vec::new();
	if !persist_manager_with_payment {
		nodes_0_serialized = nodes[0].node.encode();
	}

	let (our_payment_preimage, our_payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	if persist_manager_with_payment {
		nodes_0_serialized = nodes[0].node.encode();
	}

	nodes[1].node.claim_funds(our_payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], our_payment_hash, 1_000_000);

	let updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[0], 1);

	// The ChannelMonitor should always be the latest version, as we're required to persist it
	// during the commitment signed handling.
	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	reload_node!(nodes[0], test_default_channel_config(), &nodes_0_serialized, &[&chan_0_monitor_serialized], persister_a, chain_monitor_a, nodes_0_deserialized);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let Event::ChannelClosed { reason: ClosureReason::OutdatedChannelManager, .. } = events[0] {} else { panic!(); }
	if let Event::PaymentSent { payment_preimage, .. } = events[1] { assert_eq!(payment_preimage, our_payment_preimage); } else { panic!(); }
	// Note that we don't get a PaymentPathSuccessful here as we leave the HTLC pending to avoid
	// the double-claim that would otherwise appear at the end of this test.
	let as_broadcasted_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_broadcasted_txn.len(), 1);

	// Ensure that, even after some time, if we restart we still include *something* in the current
	// `ChannelManager` which prevents a `PaymentFailed` when we restart even if pending resolved
	// payments have since been timed out thanks to `IDEMPOTENCY_TIMEOUT_TICKS`.
	// A naive implementation of the fix here would wipe the pending payments set, causing a
	// failure event when we restart.
	for _ in 0..(IDEMPOTENCY_TIMEOUT_TICKS * 2) { nodes[0].node.timer_tick_occurred(); }

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	reload_node!(nodes[0], test_default_channel_config(), &nodes[0].node.encode(), &[&chan_0_monitor_serialized], persister_b, chain_monitor_b, nodes_0_deserialized_b);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert!(events.is_empty());

	// Ensure that we don't generate any further events even after the channel-closing commitment
	// transaction is confirmed on-chain.
	confirm_transaction(&nodes[0], &as_broadcasted_txn[0]);
	for _ in 0..(IDEMPOTENCY_TIMEOUT_TICKS * 2) { nodes[0].node.timer_tick_occurred(); }

	let events = nodes[0].node.get_and_clear_pending_events();
	assert!(events.is_empty());

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	reload_node!(nodes[0], test_default_channel_config(), &nodes[0].node.encode(), &[&chan_0_monitor_serialized], persister_c, chain_monitor_c, nodes_0_deserialized_c);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert!(events.is_empty());
}

#[test]
fn no_missing_sent_on_midpoint_reload() {
	do_no_missing_sent_on_midpoint_reload(false);
	do_no_missing_sent_on_midpoint_reload(true);
}
