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

use ln::{PaymentPreimage, PaymentHash};
use ln::channelmanager::{PaymentId, PaymentSendFailure};
use routing::router::get_route;
use ln::features::{InitFeatures, InvoiceFeatures};
use ln::msgs;
use ln::msgs::ChannelMessageHandler;
use util::test_utils;
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use util::errors::APIError;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

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

	let logger = test_utils::TestLogger::new();
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph, &nodes[2].node.get_our_node_id(), Some(InvoiceFeatures::known()), None, &Vec::new(), 100_000, TEST_FINAL_CLTV, &logger).unwrap();

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
fn mpp_retry() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 3, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let logger = test_utils::TestLogger::new();
	// Rebalance
	send_payment(&nodes[3], &vec!(&nodes[2])[..], 1_500_000);

	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash!(&nodes[3]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let mut route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph, &nodes[3].node.get_our_node_id(), Some(InvoiceFeatures::known()), None, &[], 1_000_000, TEST_FINAL_CLTV, &logger).unwrap();
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
	expect_payment_failed!(nodes[0], payment_hash, false);

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

	let logger = test_utils::TestLogger::new();
	let (_payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph, &nodes[2].node.get_our_node_id(), Some(InvoiceFeatures::known()), None, &Vec::new(), 100_000, TEST_FINAL_CLTV, &logger).unwrap();

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
