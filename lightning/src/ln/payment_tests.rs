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

use crate::chain::channelmonitor::{
	ANTI_REORG_DELAY, HTLC_FAIL_BACK_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS,
};
use crate::chain::{Confirm, Listen};
use crate::events::{
	ClosureReason, Event, HTLCHandlingFailureType, PathFailure, PaymentFailureReason,
	PaymentPurpose,
};
use crate::ln::chan_utils;
use crate::ln::channel::{
	get_holder_selected_channel_reserve_satoshis, ANCHOR_OUTPUT_VALUE_SATOSHI,
	EXPIRE_PREV_CONFIG_TICKS,
};
use crate::ln::channelmanager::{
	HTLCForwardInfo, PaymentId, PendingAddHTLCInfo, PendingHTLCRouting, RecentPaymentDetails,
	RecipientOnionFields, BREAKDOWN_TIMEOUT, MIN_CLTV_EXPIRY_DELTA, MPP_TIMEOUT_TICKS,
};
use crate::ln::msgs;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::ln::onion_utils::{self, LocalHTLCFailureReason};
use crate::ln::outbound_payment::{
	ProbeSendFailure, Retry, RetryableSendFailure, IDEMPOTENCY_TIMEOUT_TICKS,
};
use crate::ln::types::ChannelId;
use crate::routing::gossip::{EffectiveCapacity, RoutingFees};
use crate::routing::router::{
	get_route, Path, PaymentParameters, Route, RouteHint, RouteHintHop, RouteHop, RouteParameters,
	Router,
};
use crate::routing::scoring::ChannelUsage;
use crate::sign::EntropySource;
use crate::types::features::{Bolt11InvoiceFeatures, ChannelTypeFeatures};
use crate::types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
use crate::types::string::UntrustedString;
use crate::util::errors::APIError;
use crate::util::ser::Writeable;
use crate::util::test_utils;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::network::Network;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

use crate::prelude::*;

use crate::ln::functional_test_utils;
use crate::ln::functional_test_utils::*;
use crate::routing::gossip::NodeId;

use core::cmp::Ordering;
#[cfg(feature = "std")]
use std::thread;

#[cfg(feature = "std")]
use {
	crate::util::time::Instant as TestTime,
	std::time::{Duration, Instant, SystemTime},
};

#[test]
fn mpp_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = node_b_id;
	route.paths[0].hops[0].short_channel_id = chan_1_id;
	route.paths[0].hops[1].short_channel_id = chan_3_id;
	route.paths[1].hops[0].pubkey = node_c_id;
	route.paths[1].hops[0].short_channel_id = chan_2_id;
	route.paths[1].hops[1].short_channel_id = chan_4_id;
	let paths: &[&[_]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	send_along_route_with_secret(&nodes[0], route, paths, 200_000, payment_hash, payment_secret);
	fail_payment_along_route(&nodes[0], paths, false, payment_hash);
}

#[test]
fn mpp_retry() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	let (chan_1_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (chan_2_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 2);
	let (chan_3_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 1, 3);
	let (chan_4_update, _, chan_4_id, _) = create_announced_chan_between_nodes(&nodes, 3, 2);

	// Rebalance
	send_payment(&nodes[3], &[&nodes[2]], 1_500_000);

	let amt_msat = 1_000_000;
	let max_fee = 50_000;
	let payment_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[3].node.bolt11_invoice_features())
		.unwrap();
	let (mut route, hash, preimage, pay_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[3], payment_params, amt_msat, Some(max_fee));
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = node_b_id;
	route.paths[0].hops[0].short_channel_id = chan_1_update.contents.short_channel_id;
	route.paths[0].hops[1].short_channel_id = chan_3_update.contents.short_channel_id;
	route.paths[1].hops[0].pubkey = node_c_id;
	route.paths[1].hops[0].short_channel_id = chan_2_update.contents.short_channel_id;
	route.paths[1].hops[1].short_channel_id = chan_4_update.contents.short_channel_id;

	// Initiate the MPP payment.
	let id = PaymentId(hash.0);
	let mut route_params = route.route_params.clone().unwrap();

	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	let onion = RecipientOnionFields::secret_only(pay_secret);
	let retry = Retry::Attempts(1);
	nodes[0].node.send_payment(hash, onion, id, route_params.clone(), retry).unwrap();
	check_added_monitors(&nodes[0], 2); // one monitor per path
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	// Pass half of the payment along the success path.
	let init_msgs = remove_first_msg_event_to_node(&node_b_id, &mut events);
	let path = &[&nodes[1], &nodes[3]];
	pass_along_path(&nodes[0], path, 2_000_000, hash, Some(pay_secret), init_msgs, false, None);

	// Add the HTLC along the first hop.
	let second_msgs = remove_first_msg_event_to_node(&node_c_id, &mut events);
	let send_event = SendEvent::from_event(second_msgs);
	nodes[2].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[2], &nodes[0], &send_event.commitment_msg, false, false);

	// Attempt to forward the payment and complete the 2nd path's failure.
	expect_and_process_pending_htlcs(&nodes[2], true);
	let events = nodes[2].node.get_and_clear_pending_events();
	let fail = HTLCHandlingFailureType::Forward { node_id: Some(node_d_id), channel_id: chan_4_id };
	expect_htlc_failure_conditions(events, &[fail]);
	let htlc_updates = get_htlc_update_msgs(&nodes[2], &node_a_id);
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors(&nodes[2], 1);
	nodes[0].node.handle_update_fail_htlc(node_c_id, &htlc_updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[2], &htlc_updates.commitment_signed, false, false);
	let mut events = nodes[0].node.get_and_clear_pending_events();

	let conditions = PaymentFailedConditions::new().mpp_parts_remain();
	expect_payment_failed_conditions_event(events, hash, false, conditions);

	// Rebalance the channel so the second half of the payment can succeed.
	send_payment(&nodes[3], &[&nodes[2]], 1_500_000);

	// Retry the second half of the payment and make sure it succeeds.
	route.paths.remove(0);
	route_params.final_value_msat = 1_000_000;
	let chan_4_scid = chan_4_update.contents.short_channel_id;
	route_params.payment_params.previously_failed_channels.push(chan_4_scid);
	// Check the remaining max total routing fee for the second attempt is 50_000 - 1_000 msat fee
	// used by the first path
	route_params.max_total_routing_fee_msat = Some(max_fee - 1_000);
	route.route_params = Some(route_params.clone());
	nodes[0].router.expect_find_route(route_params, Ok(route));
	expect_and_process_pending_htlcs(&nodes[0], false);
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = events.pop().unwrap();
	let last_path = &[&nodes[2], &nodes[3]];
	pass_along_path(&nodes[0], last_path, 2_000_000, hash, Some(pay_secret), event, true, None);
	let claim_paths: &[&[_]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], claim_paths, preimage));
}

#[test]
fn mpp_retry_overpay() {
	// We create an MPP scenario with two paths in which we need to overpay to reach
	// htlc_minimum_msat. We then fail the overpaid path and check that on retry our
	// max_total_routing_fee_msat only accounts for the path's fees, but not for the fees overpaid
	// in the first attempt.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	let mut user_config = test_default_channel_config();
	user_config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let mut limited_1 = user_config.clone();
	limited_1.channel_handshake_config.our_htlc_minimum_msat = 35_000_000;
	let mut limited_2 = user_config.clone();
	limited_2.channel_handshake_config.our_htlc_minimum_msat = 34_500_000;
	let configs = [Some(user_config.clone()), Some(limited_1), Some(limited_2), Some(user_config)];

	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &configs);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	let (chan_1_update, _, _, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 40_000, 0);
	let (chan_2_update, _, _, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 40_000, 0);
	let (_chan_3_update, _, _, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 40_000, 0);
	let (chan_4_update, _, chan_4_id, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 3, 2, 40_000, 0);

	let amt_msat = 70_000_000;
	let max_fee = Some(1_000_000);

	let payment_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[3].node.bolt11_invoice_features())
		.unwrap();
	let (mut route, hash, payment_preimage, pay_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[3], payment_params, amt_msat, max_fee);

	// Check we overpay on the second path which we're about to fail.
	assert_eq!(chan_1_update.contents.fee_proportional_millionths, 0);
	let overpaid_amount_1 = route.paths[0].fee_msat() as u32 - chan_1_update.contents.fee_base_msat;
	assert_eq!(overpaid_amount_1, 0);

	assert_eq!(chan_2_update.contents.fee_proportional_millionths, 0);
	let overpaid_amount_2 = route.paths[1].fee_msat() as u32 - chan_2_update.contents.fee_base_msat;

	let total_overpaid_amount = overpaid_amount_1 + overpaid_amount_2;

	// Initiate the payment.
	let id = PaymentId(hash.0);
	let mut route_params = route.route_params.clone().unwrap();

	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	let onion = RecipientOnionFields::secret_only(pay_secret);
	let retry = Retry::Attempts(1);
	nodes[0].node.send_payment(hash, onion, id, route_params.clone(), retry).unwrap();
	check_added_monitors(&nodes[0], 2); // one monitor per path
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	// Pass half of the payment along the success path.
	let init_msgs = remove_first_msg_event_to_node(&node_b_id, &mut events);
	let path = &[&nodes[1], &nodes[3]];
	pass_along_path(&nodes[0], path, amt_msat, hash, Some(pay_secret), init_msgs, false, None);

	// Add the HTLC along the first hop.
	let fail_path_msgs_1 = remove_first_msg_event_to_node(&node_c_id, &mut events);
	let send_event = SendEvent::from_event(fail_path_msgs_1);
	nodes[2].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[2], &nodes[0], &send_event.commitment_msg, false, false);

	// Attempt to forward the payment and complete the 2nd path's failure.
	expect_and_process_pending_htlcs(&nodes[2], true);
	let events = nodes[2].node.get_and_clear_pending_events();
	let fail = HTLCHandlingFailureType::Forward { node_id: Some(node_d_id), channel_id: chan_4_id };
	expect_htlc_failure_conditions(events, &[fail]);

	let htlc_updates = get_htlc_update_msgs(&nodes[2], &node_a_id);
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors(&nodes[2], 1);
	nodes[0].node.handle_update_fail_htlc(node_c_id, &htlc_updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[2], &htlc_updates.commitment_signed, false, false);
	let mut events = nodes[0].node.get_and_clear_pending_events();
	let fail_conditions = PaymentFailedConditions::new().mpp_parts_remain();
	expect_payment_failed_conditions_event(events, hash, false, fail_conditions);

	// Rebalance the channel so the second half of the payment can succeed.
	send_payment(&nodes[3], &[&nodes[2]], 38_000_000);

	// Retry the second half of the payment and make sure it succeeds.
	let first_path_value = route.paths[0].final_value_msat();
	assert_eq!(first_path_value, 36_000_000);

	route.paths.remove(0);
	route_params.final_value_msat -= first_path_value;
	let chan_4_scid = chan_4_update.contents.short_channel_id;
	route_params.payment_params.previously_failed_channels.push(chan_4_scid);
	// Check the remaining max total routing fee for the second attempt accounts only for 1_000 msat
	// base fee, but not for overpaid value of the first try.
	route_params.max_total_routing_fee_msat.as_mut().map(|m| *m -= 1000);

	route.route_params = Some(route_params.clone());
	nodes[0].router.expect_find_route(route_params, Ok(route));
	nodes[0].node.process_pending_htlc_forwards();

	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = events.pop().unwrap();
	let path = &[&nodes[2], &nodes[3]];
	pass_along_path(&nodes[0], path, amt_msat, hash, Some(pay_secret), event, true, None);

	// Can't use claim_payment_along_route as it doesn't support overpayment, so we break out the
	// individual steps here.
	nodes[3].node.claim_funds(payment_preimage);
	let extra_fees = vec![0, total_overpaid_amount];
	let expected_route = &[&[&nodes[1], &nodes[3]][..], &[&nodes[2], &nodes[3]][..]];
	let args = ClaimAlongRouteArgs::new(&nodes[0], &expected_route[..], payment_preimage)
		.with_expected_min_htlc_overpay(extra_fees);
	let expected_total_fee_msat = pass_claimed_payment_along_route(args);
	expect_payment_sent!(&nodes[0], payment_preimage, Some(expected_total_fee_msat));
}

fn do_mpp_receive_timeout(send_partial_mpp: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	let (chan_1_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (chan_2_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 0, 2);
	let (chan_3_update, _, chan_3_id, _) = create_announced_chan_between_nodes(&nodes, 1, 3);
	let (chan_4_update, _, _, _) = create_announced_chan_between_nodes(&nodes, 2, 3);

	let (mut route, hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[3], 100_000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = node_b_id;
	route.paths[0].hops[0].short_channel_id = chan_1_update.contents.short_channel_id;
	route.paths[0].hops[1].short_channel_id = chan_3_update.contents.short_channel_id;
	route.paths[1].hops[0].pubkey = node_c_id;
	route.paths[1].hops[0].short_channel_id = chan_2_update.contents.short_channel_id;
	route.paths[1].hops[1].short_channel_id = chan_4_update.contents.short_channel_id;

	// Initiate the MPP payment.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0].node.send_payment_with_route(route, hash, onion, PaymentId(hash.0)).unwrap();
	check_added_monitors(&nodes[0], 2); // one monitor per path
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	// Pass half of the payment along the first path.
	let node_1_msgs = remove_first_msg_event_to_node(&node_b_id, &mut events);
	let path = &[&nodes[1], &nodes[3]];
	pass_along_path(&nodes[0], path, 200_000, hash, Some(payment_secret), node_1_msgs, false, None);

	if send_partial_mpp {
		// Time out the partial MPP
		for _ in 0..MPP_TIMEOUT_TICKS {
			nodes[3].node.timer_tick_occurred();
		}

		// Failed HTLC from node 3 -> 1
		let fail = HTLCHandlingFailureType::Receive { payment_hash: hash };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[3], &[fail]);

		let htlc_fail_updates = get_htlc_update_msgs(&nodes[3], &node_b_id);
		assert_eq!(htlc_fail_updates.update_fail_htlcs.len(), 1);
		nodes[1].node.handle_update_fail_htlc(node_d_id, &htlc_fail_updates.update_fail_htlcs[0]);
		check_added_monitors(&nodes[3], 1);

		let commitment = &htlc_fail_updates.commitment_signed;
		do_commitment_signed_dance(&nodes[1], &nodes[3], commitment, false, false);

		// Failed HTLC from node 1 -> 0
		let fail_type =
			HTLCHandlingFailureType::Forward { node_id: Some(node_d_id), channel_id: chan_3_id };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);

		let htlc_fail_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
		assert_eq!(htlc_fail_updates.update_fail_htlcs.len(), 1);
		nodes[0].node.handle_update_fail_htlc(node_b_id, &htlc_fail_updates.update_fail_htlcs[0]);
		check_added_monitors(&nodes[1], 1);
		let commitment = &htlc_fail_updates.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);

		let mut conditions = PaymentFailedConditions::new()
			.mpp_parts_remain()
			.expected_htlc_error_data(LocalHTLCFailureReason::MPPTimeout, &[][..]);
		expect_payment_failed_conditions(&nodes[0], hash, false, conditions);
	} else {
		// Pass half of the payment along the second path.
		let node_2_msgs = remove_first_msg_event_to_node(&node_c_id, &mut events);
		let path = &[&nodes[2], &nodes[3]];
		let payment_secret = Some(payment_secret);
		pass_along_path(&nodes[0], path, 200_000, hash, payment_secret, node_2_msgs, true, None);

		// Even after MPP_TIMEOUT_TICKS we should not timeout the MPP if we have all the parts
		for _ in 0..MPP_TIMEOUT_TICKS {
			nodes[3].node.timer_tick_occurred();
		}

		let full_path: &[&[_]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
		claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], full_path, payment_preimage));
	}
}

#[test]
fn mpp_receive_timeout() {
	do_mpp_receive_timeout(true);
	do_mpp_receive_timeout(false);
}

#[test]
fn test_keysend_payments() {
	do_test_keysend_payments(false);
	do_test_keysend_payments(true);
}

fn do_test_keysend_payments(public_node: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	if public_node {
		create_announced_chan_between_nodes(&nodes, 0, 1);
	} else {
		create_chan_between_nodes(&nodes[0], &nodes[1]);
	}
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::for_keysend(node_b_id, 40, false),
		10000,
	);

	{
		let preimage = Some(PaymentPreimage([42; 32]));
		let onion = RecipientOnionFields::spontaneous_empty();
		let retry = Retry::Attempts(1);
		let id = PaymentId([42; 32]);
		nodes[0].node.send_spontaneous_payment(preimage, onion, id, route_params, retry).unwrap();
	}

	check_added_monitors(&nodes[0], 1);
	let send_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	// Previously, a refactor caused us to stop including the payment preimage in the onion which
	// is sent as a part of keysend payments. Thus, to be extra careful here, we scope the preimage
	// above to demonstrate that we have no way to get the preimage at this point except by
	// extracting it from the onion nodes[1] received.
	let event = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(event.len(), 1);
	if let Event::PaymentClaimable { purpose, .. } = &event[0] {
		if let PaymentPurpose::SpontaneousPayment(preimage) = purpose {
			claim_payment(&nodes[0], &[&nodes[1]], *preimage);
		}
	} else {
		panic!();
	}
}

#[test]
fn test_mpp_keysend() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 0, 2);
	create_announced_chan_between_nodes(&nodes, 1, 3);
	create_announced_chan_between_nodes(&nodes, 2, 3);

	let recv_value = 15_000_000;
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::for_keysend(node_d_id, 40, true),
		recv_value,
	);

	let preimage = Some(PaymentPreimage([42; 32]));
	let payment_secret = PaymentSecret([42; 32]);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let retry = Retry::Attempts(0);
	let id = PaymentId([42; 32]);
	let hash =
		nodes[0].node.send_spontaneous_payment(preimage, onion, id, route_params, retry).unwrap();
	check_added_monitors(&nodes[0], 2);

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	let ev = remove_first_msg_event_to_node(&node_b_id, &mut events);
	let payment_secret = Some(payment_secret);
	pass_along_path(&nodes[0], route[0], recv_value, hash, payment_secret, ev, false, preimage);

	let ev = remove_first_msg_event_to_node(&node_c_id, &mut events);
	pass_along_path(&nodes[0], route[1], recv_value, hash, payment_secret, ev, true, preimage);
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], route, preimage.unwrap()));
}

#[test]
#[cfg(feature = "std")]
fn test_fulfill_hold_times() {
	// Tests that as a sender we correctly receive non-zero hold times for a keysend payment.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let recv_value = 5_000_000;
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::for_keysend(node_c_id, 40, true),
		recv_value,
	);

	let preimage = Some(PaymentPreimage([42; 32]));
	let payment_secret = PaymentSecret([42; 32]);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let retry = Retry::Attempts(0);
	let id = PaymentId([42; 32]);
	let hash =
		nodes[0].node.send_spontaneous_payment(preimage, onion, id, route_params, retry).unwrap();
	check_added_monitors(&nodes[0], 1);

	let route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);

	let ev = remove_first_msg_event_to_node(&node_b_id, &mut events);
	let payment_secret = Some(payment_secret);
	pass_along_path(&nodes[0], route[0], recv_value, hash, payment_secret, ev, true, preimage);

	// Delay claiming so that we get a non-zero hold time.
	thread::sleep(Duration::from_millis(200));

	let (_, path_events) =
		claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], route, preimage.unwrap()));

	assert_eq!(path_events.len(), 1);
	match &path_events[0] {
		Event::PaymentPathSuccessful { hold_times, .. } => {
			assert_eq!(hold_times.len(), 2);

			// The final node always reports a zero hold time.
			assert!(hold_times[1] == 0);

			// It's predecessor reports a non-zero hold time because we delayed claiming.
			assert!(hold_times[0] > 0);
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_reject_mpp_keysend_htlc_mismatching_secret() {
	// This test enforces that we reject MPP keysend HTLCs if the payment_secrets between MPP parts
	// don't match. To check that we enforce rejecting MPP keysends in our payment logic, here we send
	// keysend payments without payment secrets, then modify them by adding payment secrets in the
	// final node in between receiving the HTLCs and actually processing them.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let (update_a, _, chan_4_chan_id, _) = create_announced_chan_between_nodes(&nodes, 2, 3);
	let chan_4_id = update_a.contents.short_channel_id;
	let amount = 40_000;
	let (mut route, payment_hash, payment_preimage, _) =
		get_route_and_payment_hash!(nodes[0], nodes[3], amount);
	let preimage = Some(payment_preimage);

	// Pay along nodes[1]
	route.paths[0].hops[0].pubkey = node_b_id;
	route.paths[0].hops[0].short_channel_id = chan_1_id;
	route.paths[0].hops[1].short_channel_id = chan_3_id;

	let payment_id_0 = PaymentId(nodes[0].keys_manager.backing.get_secure_random_bytes());
	nodes[0].router.expect_find_route(route.route_params.clone().unwrap(), Ok(route.clone()));
	let params = route.route_params.clone().unwrap();
	let onion = RecipientOnionFields::spontaneous_empty();
	let retry = Retry::Attempts(0);
	nodes[0].node.send_spontaneous_payment(preimage, onion, payment_id_0, params, retry).unwrap();
	check_added_monitors(&nodes[0], 1);

	let update_0 = get_htlc_update_msgs(&nodes[0], &node_b_id);
	let update_add_0 = update_0.update_add_htlcs[0].clone();
	nodes[1].node.handle_update_add_htlc(node_a_id, &update_add_0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &update_0.commitment_signed, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);

	check_added_monitors(&nodes[1], 1);
	let update_1 = get_htlc_update_msgs(&nodes[1], &node_d_id);
	let update_add_1 = update_1.update_add_htlcs[0].clone();
	nodes[3].node.handle_update_add_htlc(node_b_id, &update_add_1);
	do_commitment_signed_dance(&nodes[3], &nodes[1], &update_1.commitment_signed, false, true);
	expect_htlc_failure_conditions(nodes[3].node.get_and_clear_pending_events(), &[]);
	nodes[3].node.test_process_pending_update_add_htlcs();

	assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());
	for (_, pending_forwards) in nodes[3].node.forward_htlcs.lock().unwrap().iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
					ref mut forward_info, ..
				}) => match forward_info.routing {
					PendingHTLCRouting::ReceiveKeysend { ref mut payment_data, .. } => {
						*payment_data = Some(msgs::FinalOnionHopData {
							payment_secret: PaymentSecret([42; 32]),
							total_msat: amount * 2,
						});
					},
					_ => panic!("Expected PendingHTLCRouting::ReceiveKeysend"),
				},
				_ => {},
			}
		}
	}
	nodes[3].node.process_pending_htlc_forwards();

	// Pay along nodes[2]
	route.paths[0].hops[0].pubkey = node_c_id;
	route.paths[0].hops[0].short_channel_id = chan_2_id;
	route.paths[0].hops[1].short_channel_id = chan_4_id;

	let payment_id_1 = PaymentId(nodes[0].keys_manager.backing.get_secure_random_bytes());
	nodes[0].router.expect_find_route(route.route_params.clone().unwrap(), Ok(route.clone()));

	let onion = RecipientOnionFields::spontaneous_empty();
	let params = route.route_params.clone().unwrap();
	let retry = Retry::Attempts(0);
	nodes[0].node.send_spontaneous_payment(preimage, onion, payment_id_1, params, retry).unwrap();
	check_added_monitors(&nodes[0], 1);

	let update_2 = get_htlc_update_msgs(&nodes[0], &node_c_id);
	let update_add_2 = update_2.update_add_htlcs[0].clone();
	nodes[2].node.handle_update_add_htlc(node_a_id, &update_add_2);
	do_commitment_signed_dance(&nodes[2], &nodes[0], &update_2.commitment_signed, false, true);
	expect_and_process_pending_htlcs(&nodes[2], false);

	check_added_monitors(&nodes[2], 1);
	let update_3 = get_htlc_update_msgs(&nodes[2], &node_d_id);
	let update_add_3 = update_3.update_add_htlcs[0].clone();
	nodes[3].node.handle_update_add_htlc(node_c_id, &update_add_3);
	do_commitment_signed_dance(&nodes[3], &nodes[2], &update_3.commitment_signed, false, true);
	expect_htlc_failure_conditions(nodes[3].node.get_and_clear_pending_events(), &[]);
	nodes[3].node.test_process_pending_update_add_htlcs();

	assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());
	for (_, pending_forwards) in nodes[3].node.forward_htlcs.lock().unwrap().iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
					ref mut forward_info, ..
				}) => {
					match forward_info.routing {
						PendingHTLCRouting::ReceiveKeysend { ref mut payment_data, .. } => {
							*payment_data = Some(msgs::FinalOnionHopData {
								payment_secret: PaymentSecret([43; 32]), // Doesn't match the secret used above
								total_msat: amount * 2,
							});
						},
						_ => panic!("Expected PendingHTLCRouting::ReceiveKeysend"),
					}
				},
				_ => {},
			}
		}
	}
	nodes[3].node.process_pending_htlc_forwards();
	let fail_type = HTLCHandlingFailureType::Receive { payment_hash };
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[3], &[fail_type]);
	check_added_monitors(&nodes[3], 1);

	// Fail back along nodes[2]
	let update_fail_0 = get_htlc_update_msgs(&nodes[3], &node_c_id);
	nodes[2].node.handle_update_fail_htlc(node_d_id, &update_fail_0.update_fail_htlcs[0]);
	let commitment = &update_fail_0.commitment_signed;
	do_commitment_signed_dance(&nodes[2], &nodes[3], commitment, false, false);

	let fail_type =
		HTLCHandlingFailureType::Forward { node_id: Some(node_d_id), channel_id: chan_4_chan_id };
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[2], &[fail_type]);
	check_added_monitors(&nodes[2], 1);

	let update_fail_1 = get_htlc_update_msgs(&nodes[2], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_c_id, &update_fail_1.update_fail_htlcs[0]);
	let commitment = &update_fail_1.commitment_signed;
	do_commitment_signed_dance(&nodes[0], &nodes[2], commitment, false, false);

	expect_payment_failed_conditions(&nodes[0], payment_hash, true, PaymentFailedConditions::new());
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let payment_id = PaymentId(payment_hash.0);
	let res = nodes[0].node.send_payment_with_route(route, payment_hash, onion, payment_id);
	unwrap_send_err!(nodes[0], res, true, APIError::ChannelUnavailable { ref err },
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
	let persister;
	let new_chain_monitor;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let node_a_reload;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (_, _, chan_id_2, _) = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Serialize the ChannelManager prior to sending payments
	let node_a_ser = nodes[0].node.encode();

	// Send two payments - one which will get to nodes[2] and will be claimed, one which we'll time
	// out and retry.
	let amt_msat = 1_000_000;
	let (route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], amt_msat);
	let (payment_preimage_1, payment_hash_1, _, payment_id_1) =
		send_along_route(&nodes[0], route.clone(), &[&nodes[1], &nodes[2]], 1_000_000);

	let route_params = route.route_params.unwrap().clone();
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(1)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, node_b_id);

	// We relay the payment to nodes[1] while its disconnected from nodes[2], causing the payment
	// to be returned immediately to nodes[0], without having nodes[2] fail the inbound payment
	// which would prevent retry.
	nodes[1].node.peer_disconnected(node_c_id);
	nodes[2].node.peer_disconnected(node_b_id);

	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, true);

	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_id_2 }]
	);

	check_added_monitors(&nodes[1], 1);
	// nodes[1] now immediately fails the HTLC as the next-hop channel is disconnected
	let _ = get_htlc_update_msgs(&nodes[1], &node_a_id);

	reconnect_nodes(ReconnectArgs::new(&nodes[1], &nodes[2]));

	let as_commitment_tx = get_local_commitment_txn!(nodes[0], chan_id)[0].clone();
	if confirm_before_reload {
		mine_transaction(&nodes[0], &as_commitment_tx);
		nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	}

	// The ChannelMonitor should always be the latest version, as we're required to persist it
	// during the `commitment_signed_dance!()`.
	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	let config = test_default_channel_config();
	let mons: &[_] = &[&chan_0_monitor_serialized[..]];
	reload_node!(nodes[0], config, &node_a_ser, mons, persister, new_chain_monitor, node_a_reload);

	// On reload, the ChannelManager should realize it is stale compared to the ChannelMonitor and
	// force-close the channel.
	let reason = ClosureReason::OutdatedChannelManager;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[0].node.has_pending_payments());
	nodes[0].node.timer_tick_occurred();
	if !confirm_before_reload {
		let as_broadcasted_txn =
			nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(as_broadcasted_txn.len(), 1);
		assert_eq!(as_broadcasted_txn[0].compute_txid(), as_commitment_tx.compute_txid());
	} else {
		assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	}
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.peer_disconnected(node_a_id);

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now nodes[1] should send a channel reestablish, which nodes[0] will respond to with an
	// error, as the channel has hit the chain.
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_reestablish);
	let as_err = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_err.len(), 2);
	match as_err[1] {
		MessageSendEvent::HandleError {
			node_id,
			action: msgs::ErrorAction::SendErrorMessage { ref msg },
		} => {
			assert_eq!(node_id, node_b_id);
			nodes[1].node.handle_error(node_a_id, msg);
			check_closed_event(&nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}",
				&node_b_id)) }, &[node_a_id], 100000);
			check_added_monitors(&nodes[1], 1);
			assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
			nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
		},
		_ => panic!("Unexpected event"),
	}
	check_closed_broadcast!(nodes[1], false);

	// Now claim the first payment, which should allow nodes[1] to claim the payment on-chain when
	// we close in a moment.
	nodes[2].node.claim_funds(payment_preimage_1);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_1, 1_000_000);

	let mut htlc_fulfill = get_htlc_update_msgs(&nodes[2], &node_b_id);
	let fulfill_msg = htlc_fulfill.update_fulfill_htlcs.remove(0);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, fulfill_msg);
	check_added_monitors(&nodes[1], 1);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &htlc_fulfill.commitment_signed, false, false);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], None, true, false);

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
	let bs_htlc_claim_txn = {
		let mut txn = nodes[1].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(txn.len(), 2);
		check_spends!(txn[0], funding_tx);
		check_spends!(txn[1], as_commitment_tx);
		txn.pop().unwrap()
	};

	if !confirm_before_reload {
		mine_transaction(&nodes[0], &as_commitment_tx);
		let txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(txn.len(), 1);
		assert_eq!(txn[0].compute_txid(), as_commitment_tx.compute_txid());
	}
	mine_transaction(&nodes[0], &bs_htlc_claim_txn);
	expect_payment_sent(&nodes[0], payment_preimage_1, None, true, true);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV * 4 + 20);
	let (first_htlc_timeout_tx, second_htlc_timeout_tx) = {
		let mut txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(txn.len(), 2);
		(txn.remove(0), txn.remove(0))
	};
	check_spends!(first_htlc_timeout_tx, as_commitment_tx);
	check_spends!(second_htlc_timeout_tx, as_commitment_tx);
	if first_htlc_timeout_tx.input[0].previous_output == bs_htlc_claim_txn.input[0].previous_output
	{
		confirm_transaction(&nodes[0], &second_htlc_timeout_tx);
	} else {
		confirm_transaction(&nodes[0], &first_htlc_timeout_tx);
	}
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	let conditions = PaymentFailedConditions::new().from_mon_update();
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, conditions);

	// Finally, retry the payment (which was reloaded from the ChannelMonitor when nodes[0] was
	// reloaded) via a route over the new channel, which work without issue and eventually be
	// received and claimed at the recipient just like any other payment.
	let (mut new_route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);

	// Update the fee on the middle hop to ensure PaymentSent events have the correct (retried) fee
	// and not the original fee. We also update node[1]'s relevant config as
	// do_claim_payment_along_route expects us to never overpay.
	{
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let mut peer_state = per_peer_state.get(&node_c_id).unwrap().lock().unwrap();
		let mut channel = peer_state.channel_by_id.get_mut(&chan_id_2).unwrap();
		let mut new_config = channel.context().config();
		new_config.forwarding_fee_base_msat += 100_000;
		channel.context_mut().update_config(&new_config);
		new_route.paths[0].hops[0].fee_msat += 100_000;
	}

	// Force expiration of the channel's previous config.
	for _ in 0..EXPIRE_PREV_CONFIG_TICKS {
		nodes[1].node.timer_tick_occurred();
	}

	let onion = RecipientOnionFields::secret_only(payment_secret);
	// Check that we cannot retry a fulfilled payment
	nodes[0]
		.node
		.send_payment_with_route(new_route.clone(), payment_hash, onion, payment_id_1)
		.unwrap_err();
	// ...but if we send with a different PaymentId the payment should fly
	let id = PaymentId(payment_hash.0);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0].node.send_payment_with_route(new_route.clone(), payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = events.pop().unwrap();
	let path = &[&nodes[1], &nodes[2]];
	let payment_secret = Some(payment_secret);
	pass_along_path(&nodes[0], path, 1_000_000, payment_hash, payment_secret, event, true, None);
	do_claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], &[path], payment_preimage));
	expect_payment_sent!(nodes[0], payment_preimage, Some(new_route.paths[0].hops[0].fee_msat));
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

	let persist_1;
	let chain_monitor_1;
	let persist_2;
	let chain_monitor_2;
	let persist_3;
	let chain_monitor_3;

	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[None, Some(manually_accept_config), None]);
	let node_a_1;
	let node_a_2;
	let node_a_3;

	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Because we set nodes[1] to manually accept channels, just open a 0-conf channel.
	let (funding_tx, chan_id) = open_zero_conf_channel(&nodes[0], &nodes[1], None);
	confirm_transaction(&nodes[0], &funding_tx);
	confirm_transaction(&nodes[1], &funding_tx);
	// Ignore the announcement_signatures messages
	nodes[0].node.get_and_clear_pending_msg_events();
	nodes[1].node.get_and_clear_pending_msg_events();
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 1, 2).2;

	// Serialize the ChannelManager prior to sending payments
	let mut node_a_ser = nodes[0].node.encode();

	let amt = if use_dust { 1_000 } else { 1_000_000 };
	let route = get_route_and_payment_hash!(nodes[0], nodes[2], amt).0;
	let (payment_preimage, hash, payment_secret, payment_id) =
		send_along_route(&nodes[0], route, &[&nodes[1], &nodes[2]], amt);

	// The ChannelMonitor should always be the latest version, as we're required to persist it
	// during the `commitment_signed_dance!()`.
	let mon_ser = get_monitor!(nodes[0], chan_id).encode();

	let config = test_default_channel_config();
	reload_node!(nodes[0], config, node_a_ser, &[&mon_ser], persist_1, chain_monitor_1, node_a_1);
	nodes[1].node.peer_disconnected(node_a_id);

	// On reload, the ChannelManager should realize it is stale compared to the ChannelMonitor and
	// force-close the channel.
	check_closed_event(&nodes[0], 1, ClosureReason::OutdatedChannelManager, &[node_b_id], 100000);
	nodes[0].node.timer_tick_occurred();
	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[0].node.has_pending_payments());
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);
	check_added_monitors(&nodes[0], 1);

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now nodes[1] should send a channel reestablish, which nodes[0] will respond to with an
	// error, as the channel has hit the chain.
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
	let bs_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[0].node.handle_channel_reestablish(node_b_id, &bs_reestablish);
	let as_err = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_err.len(), 2);
	let bs_commitment_tx;
	match as_err[1] {
		MessageSendEvent::HandleError {
			node_id,
			action: msgs::ErrorAction::SendErrorMessage { ref msg },
		} => {
			assert_eq!(node_id, node_b_id);
			nodes[1].node.handle_error(node_a_id, msg);
			let msg = format!(
				"Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}",
				&node_b_id
			);
			let reason = ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString(msg) };
			check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
			check_added_monitors(&nodes[1], 1);
			bs_commitment_tx = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		},
		_ => panic!("Unexpected event"),
	}
	check_closed_broadcast!(nodes[1], false);

	// Now fail back the payment from nodes[2] to nodes[1]. This doesn't really matter as the
	// previous hop channel is already on-chain, but it makes nodes[2] willing to see additional
	// incoming HTLCs with the same payment hash later.
	nodes[2].node.fail_htlc_backwards(&hash);
	let fail_type = HTLCHandlingFailureType::Receive { payment_hash: hash };
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[2], &[fail_type]);
	check_added_monitors(&nodes[2], 1);

	let htlc_fulfill_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	nodes[1].node.handle_update_fail_htlc(node_c_id, &htlc_fulfill_updates.update_fail_htlcs[0]);
	let commitment = &htlc_fulfill_updates.commitment_signed;
	do_commitment_signed_dance(&nodes[1], &nodes[2], commitment, false, false);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_id_2 }],
	);

	// Connect the HTLC-Timeout transaction, timing out the HTLC on both nodes (but not confirming
	// the HTLC-Timeout transaction beyond 1 conf). For dust HTLCs, the HTLC is considered resolved
	// after the commitment transaction, so always connect the commitment transaction.
	mine_transaction(&nodes[0], &bs_commitment_tx[0]);
	if nodes[0].connect_style.borrow().updates_best_block_first() {
		let _ = nodes[0].tx_broadcaster.txn_broadcast();
	}
	mine_transaction(&nodes[1], &bs_commitment_tx[0]);
	if !use_dust {
		connect_blocks(&nodes[0], TEST_FINAL_CLTV + (MIN_CLTV_EXPIRY_DELTA as u32));
		connect_blocks(&nodes[1], TEST_FINAL_CLTV + (MIN_CLTV_EXPIRY_DELTA as u32));
		let as_htlc_timeout = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(as_htlc_timeout.len(), 1);
		check_spends!(as_htlc_timeout[0], bs_commitment_tx[0]);

		mine_transaction(&nodes[0], &as_htlc_timeout[0]);
		mine_transaction(&nodes[1], &as_htlc_timeout[0]);
	}
	if nodes[0].connect_style.borrow().updates_best_block_first() {
		let _ = nodes[0].tx_broadcaster.txn_broadcast();
	}

	// Create a new channel on which to retry the payment before we fail the payment via the
	// HTLC-Timeout transaction. This avoids ChannelManager timing out the payment due to us
	// connecting several blocks while creating the channel (implying time has passed).
	// We do this with a zero-conf channel to avoid connecting blocks as a side-effect.
	let (_, chan_id_3) = open_zero_conf_channel(&nodes[0], &nodes[1], None);
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);

	// If we attempt to retry prior to the HTLC-Timeout (or commitment transaction, for dust HTLCs)
	// confirming, we will fail as it's considered still-pending...
	let (new_route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[2], amt);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	match nodes[0].node.send_payment_with_route(new_route.clone(), hash, onion, payment_id) {
		Err(RetryableSendFailure::DuplicatePayment) => {},
		_ => panic!("Unexpected error"),
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// After ANTI_REORG_DELAY confirmations, the HTLC should be failed and we can try the payment
	// again. We serialize the node first as we'll then test retrying the HTLC after a restart
	// (which should also still work).
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	let conditions = PaymentFailedConditions::new().from_mon_update();
	expect_payment_failed_conditions(&nodes[0], hash, false, conditions);

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	let chan_1_monitor_serialized = get_monitor!(nodes[0], chan_id_3).encode();
	node_a_ser = nodes[0].node.encode();

	// After the payment failed, we're free to send it again.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0].node.send_payment_with_route(new_route.clone(), hash, onion, payment_id).unwrap();
	assert!(!nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let config = test_default_channel_config();
	let monitors = &[&chan_0_monitor_serialized[..], &chan_1_monitor_serialized[..]];
	reload_node!(nodes[0], config, node_a_ser, monitors, persist_2, chain_monitor_2, node_a_2);
	nodes[1].node.peer_disconnected(node_a_id);

	nodes[0].node.test_process_background_events();

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_nodes(reconnect_args);

	// Now resend the payment, delivering the HTLC and actually claiming it this time. This ensures
	// the payment is not (spuriously) listed as still pending.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0].node.send_payment_with_route(new_route.clone(), hash, onion, payment_id).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], amt, hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	let onion = RecipientOnionFields::secret_only(payment_secret);
	match nodes[0].node.send_payment_with_route(new_route.clone(), hash, onion, payment_id) {
		Err(RetryableSendFailure::DuplicatePayment) => {},
		_ => panic!("Unexpected error"),
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
	let chan_1_monitor_serialized = get_monitor!(nodes[0], chan_id_3).encode();
	node_a_ser = nodes[0].node.encode();

	// Check that after reload we can send the payment again (though we shouldn't, since it was
	// claimed previously).
	let config = test_default_channel_config();
	let monitors = &[&chan_0_monitor_serialized[..], &chan_1_monitor_serialized[..]];
	reload_node!(nodes[0], config, node_a_ser, monitors, persist_3, chain_monitor_3, node_a_3);
	nodes[1].node.peer_disconnected(node_a_id);

	nodes[0].node.test_process_background_events();

	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	let onion = RecipientOnionFields::secret_only(payment_secret);
	match nodes[0].node.send_payment_with_route(new_route, hash, onion, payment_id) {
		Err(RetryableSendFailure::DuplicatePayment) => {},
		_ => panic!("Unexpected error"),
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
}

#[test]
fn test_completed_payment_not_retryable_on_reload() {
	do_test_completed_payment_not_retryable_on_reload(true);
	do_test_completed_payment_not_retryable_on_reload(false);
}

fn do_test_dup_htlc_onchain_doesnt_fail_on_reload(
	persist_manager_post_event: bool, persist_monitor_after_events: bool,
	confirm_commitment_tx: bool, payment_timeout: bool,
) {
	// When a Channel is closed, any outbound HTLCs which were relayed through it are simply
	// dropped. From there, the ChannelManager relies on the ChannelMonitor having a copy of the
	// relevant fail-/claim-back data and processes the HTLC fail/claim when the ChannelMonitor tells
	// it to.
	//
	// If, due to an on-chain event, an HTLC is failed/claimed, we provide the
	// ChannelManager with the HTLC event without waiting for ChannelMonitor persistence.
	// This might generate duplicate HTLC fail/claim (e.g. via a PaymentPathFailed event) on reload.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let chain_monitor;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let node_a_reload;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let message = "Channel force-closed".to_owned();

	// Route a payment, but force-close the channel before the HTLC fulfill message arrives at
	// nodes[0].
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 10_000_000);
	nodes[0]
		.node
		.force_close_broadcasting_latest_txn(&chan_id, &node_b_id, message.clone())
		.unwrap();
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	// Connect blocks until the CLTV timeout is up so that we get an HTLC-Timeout transaction
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
	let (commitment_tx, htlc_timeout_tx) = {
		let mut txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(txn.len(), 2);
		check_spends!(txn[0], funding_tx);
		check_spends!(txn[1], txn[0]);
		(txn.remove(0), txn.remove(0))
	};

	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 10_000_000);

	mine_transaction(&nodes[1], &commitment_tx);
	check_closed_broadcast(&nodes[1], 1, false);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	let htlc_success_tx = {
		let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		check_spends!(txn[0], commitment_tx);
		txn.pop().unwrap()
	};

	mine_transaction(&nodes[0], &commitment_tx);

	if confirm_commitment_tx {
		connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32 - 1);
	}

	let txn = if payment_timeout { vec![htlc_timeout_tx] } else { vec![htlc_success_tx] };
	let claim_block = create_dummy_block(nodes[0].best_block_hash(), 42, txn);

	if payment_timeout {
		assert!(confirm_commitment_tx); // Otherwise we're spending below our CSV!
		connect_block(&nodes[0], &claim_block);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 2);
	}

	// Now connect the HTLC claim transaction. Note that ChannelMonitors aren't re-persisted on
	// each block connection (as the block being reconnected on startup should get us the same
	// result).
	if payment_timeout {
		connect_blocks(&nodes[0], 1);
	} else {
		connect_block(&nodes[0], &claim_block);
	}
	check_added_monitors(&nodes[0], 0);

	// Note that we skip persisting ChannelMonitors. We should still be generating the payment sent
	// event without ChannelMonitor persistence. If we reset to a previous state on reload, the block
	// should be replayed and we'll regenerate the event.

	// If we persist the ChannelManager here, we should get the PaymentSent event after
	// deserialization.
	let mut node_a_ser = Vec::new();
	if !persist_manager_post_event {
		node_a_ser = nodes[0].node.encode();
	}

	let mut mon_ser = Vec::new();
	if !persist_monitor_after_events {
		mon_ser = get_monitor!(nodes[0], chan_id).encode();
	}
	if payment_timeout {
		let conditions = PaymentFailedConditions::new().from_mon_update();
		expect_payment_failed_conditions(&nodes[0], payment_hash, false, conditions);
	} else {
		expect_payment_sent(&nodes[0], payment_preimage, None, true, true);
	}
	// Note that if we persist the monitor before processing the events, above, we'll always get
	// them replayed on restart no matter what
	if persist_monitor_after_events {
		mon_ser = get_monitor!(nodes[0], chan_id).encode();
	}

	// If we persist the ChannelManager after we get the PaymentSent event, we shouldn't get it
	// twice.
	if persist_manager_post_event {
		node_a_ser = nodes[0].node.encode();
	} else if persist_monitor_after_events {
		// Persisting the monitor after the events (resulting in a new monitor being persisted) but
		// didn't persist the manager will result in an FC, which we don't test here.
		panic!();
	}

	// Now reload nodes[0]...
	reload_node!(nodes[0], &node_a_ser, &[&mon_ser], persister, chain_monitor, node_a_reload);

	check_added_monitors(&nodes[0], 0);
	if persist_manager_post_event && persist_monitor_after_events {
		assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		check_added_monitors(&nodes[0], 0);
	} else if payment_timeout {
		let mut conditions = PaymentFailedConditions::new();
		if !persist_monitor_after_events {
			conditions = conditions.from_mon_update();
		}
		expect_payment_failed_conditions(&nodes[0], payment_hash, false, conditions);
		check_added_monitors(&nodes[0], 0);
	} else {
		if persist_manager_post_event {
			assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
		} else {
			expect_payment_sent(&nodes[0], payment_preimage, None, true, false);
		}
		if persist_manager_post_event {
			// After reload, the ChannelManager identified the failed payment and queued up the
			// PaymentSent (or not, if `persist_manager_post_event` resulted in us detecting we
			// already did that) and corresponding ChannelMonitorUpdate to mark the payment
			// handled, but while processing the pending `MonitorEvent`s (which were not processed
			// before the monitor was persisted) we will end up with a duplicate
			// ChannelMonitorUpdate.
			check_added_monitors(&nodes[0], 2);
		} else {
			// ...unless we got the PaymentSent event, in which case we have de-duplication logic
			// preventing a redundant monitor event.
			check_added_monitors(&nodes[0], 1);
		}
	}

	// Note that if we re-connect the block which exposed nodes[0] to the payment preimage (but
	// which the current ChannelMonitor has not seen), the ChannelManager's de-duplication of
	// payment events should kick in, leaving us with no pending events here.
	let height = nodes[0].blocks.lock().unwrap().len() as u32 - 1;
	nodes[0].chain_monitor.chain_monitor.block_connected(&claim_block, height);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
}

#[test]
fn test_dup_htlc_onchain_doesnt_fail_on_reload() {
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(true, true, true, true);
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(true, true, true, false);
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(true, true, false, false);
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(true, false, true, true);
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(true, false, true, false);
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(true, false, false, false);
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(false, false, true, true);
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(false, false, true, false);
	do_test_dup_htlc_onchain_doesnt_fail_on_reload(false, false, false, false);
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
	let persister;
	let chain_monitor;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let node_b_reload;
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 100_000);

	// The simplest way to get a failure after a fulfill is to reload nodes[1] from a state
	// pre-fulfill, which we do by serializing it here.
	let node_b_ser = nodes[1].node.encode();
	let mon_ser = get_monitor!(nodes[1], chan_id).encode();

	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 100_000);

	let mut htlc_fulfill = get_htlc_update_msgs(&nodes[1], &node_a_id);
	let fulfill_msg = htlc_fulfill.update_fulfill_htlcs.remove(0);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, fulfill_msg);
	expect_payment_sent(&nodes[0], payment_preimage, None, false, false);

	// Now reload nodes[1]...
	reload_node!(nodes[1], &node_b_ser, &[&mon_ser], persister, chain_monitor, node_b_reload);

	nodes[0].node.peer_disconnected(node_b_id);
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	nodes[1].node.fail_htlc_backwards(&payment_hash);
	let fail_type = HTLCHandlingFailureType::Receive { payment_hash };
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);
	check_added_monitors(&nodes[1], 1);

	let htlc_fail_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &htlc_fail_updates.update_fail_htlcs[0]);
	let commitment = &htlc_fail_updates.commitment_signed;
	do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let amt_msat = 60_000;
	let expiry_secs = 60 * 60;
	let (payment_hash, payment_secret) =
		nodes[1].node.create_inbound_payment(Some(amt_msat), expiry_secs, None).unwrap();

	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let scorer = test_utils::TestScorer::new();
	let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
	let random_seed_bytes = keys_manager.get_secure_random_bytes();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	let first_hops = nodes[0].node.list_usable_channels();
	let route = get_route(
		&node_a_id,
		&route_params,
		&nodes[0].network_graph.read_only(),
		Some(&first_hops.iter().collect::<Vec<_>>()),
		nodes[0].logger,
		&scorer,
		&Default::default(),
		&random_seed_bytes,
	);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route.unwrap(), payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	// Make sure to use `get_payment_preimage`
	let preimage = Some(nodes[1].node.get_payment_preimage(payment_hash, payment_secret).unwrap());
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = events.pop().unwrap();
	let payment_secret = Some(payment_secret);
	let path = &[&nodes[1]];
	pass_along_path(&nodes[0], path, amt_msat, payment_hash, payment_secret, event, true, preimage);
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], &[path], preimage.unwrap()));
}

#[test]
fn sent_probe_is_probe_of_sending_node() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	// First check we refuse to build a single-hop probe
	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[1], 100_000);
	assert!(nodes[0].node.send_probe(route.paths[0].clone()).is_err());
	assert!(nodes[0].node.list_recent_payments().is_empty());

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

	get_htlc_update_msgs(&nodes[0], &node_b_id);
	check_added_monitors(&nodes[0], 1);
}

#[test]
fn successful_probe_yields_event() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let recv_value = 100_000;
	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[2], recv_value);

	let res = nodes[0].node.send_probe(route.paths[0].clone()).unwrap();

	let expected_route: &[(&[&Node], PaymentHash)] = &[(&[&nodes[1], &nodes[2]], res.0)];

	send_probe_along_route(&nodes[0], expected_route);

	expect_probe_successful_events(&nodes[0], vec![res]);

	assert!(!nodes[0].node.has_pending_payments());
}

#[test]
fn failed_probe_yields_event() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 90000000);

	let params = PaymentParameters::from_node_id(node_c_id, 42);
	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[2], params, 9_998_000);

	let (payment_hash, payment_id) = nodes[0].node.send_probe(route.paths[0].clone()).unwrap();

	// node[0] -- update_add_htlcs -> node[1]
	check_added_monitors(&nodes[0], 1);
	let updates = get_htlc_update_msgs(&nodes[0], &node_b_id);
	let probe_event = SendEvent::from_commitment_update(node_b_id, channel_id, updates);
	nodes[1].node.handle_update_add_htlc(node_a_id, &probe_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &probe_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], true);

	// node[0] <- update_fail_htlcs -- node[1]
	check_added_monitors(&nodes[1], 1);
	let updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	let _events = nodes[1].node.get_and_clear_pending_events();
	nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
	check_added_monitors(&nodes[0], 0);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.drain(..).next().unwrap() {
		crate::events::Event::ProbeFailed { payment_id: ev_pid, payment_hash: ev_ph, .. } => {
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let payment_params = PaymentParameters::from_node_id(node_c_id, 42);

	// Send a dust HTLC, which will be treated as if it timed out once the channel hits the chain.
	let (route, _, _, _) = get_route_and_payment_hash!(&nodes[0], nodes[2], payment_params, 1_000);
	let (payment_hash, payment_id) = nodes[0].node.send_probe(route.paths[0].clone()).unwrap();

	// node[0] -- update_add_htlcs -> node[1]
	check_added_monitors(&nodes[0], 1);
	let updates = get_htlc_update_msgs(&nodes[0], &node_b_id);
	let probe_event = SendEvent::from_commitment_update(node_b_id, chan_id, updates);
	nodes[1].node.handle_update_add_htlc(node_a_id, &probe_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &probe_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);

	check_added_monitors(&nodes[1], 1);
	let _ = get_htlc_update_msgs(&nodes[1], &node_c_id);

	// Don't bother forwarding the HTLC onwards and just confirm the force-close transaction on
	// Node A, which after 6 confirmations should result in a probe failure event.
	let bs_txn = get_local_commitment_txn!(nodes[1], chan_id);
	confirm_transaction(&nodes[0], &bs_txn[0]);
	check_closed_broadcast!(&nodes[0], true);
	check_added_monitors(&nodes[0], 1);

	check_added_monitors(&nodes[0], 0);
	let mut events = nodes[0].node.get_and_clear_pending_events();
	check_added_monitors(&nodes[0], 1);
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
fn preflight_probes_yield_event_skip_private_hop() {
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);

	// We alleviate the HTLC max-in-flight limit, as otherwise we'd always be limited through that.
	let mut config = test_default_channel_config();
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let config = Some(config);

	let configs = [config.clone(), config.clone(), config.clone(), config.clone(), config];
	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &configs[..]);
	let nodes = create_network(5, &node_cfgs, &node_chanmgrs);

	let node_d_id = nodes[3].node.get_our_node_id();

	// Setup channel topology:
	//            N0 -(1M:0)- N1 -(1M:0)- N2 -(70k:0)- N3 -(50k:0)- N4

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 70_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 3, 4, 50_000, 0);

	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_basic_mpp_optional();

	let payment_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV)
		.with_bolt11_features(invoice_features)
		.unwrap();

	let recv_value = 50_000_000;
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, recv_value);
	let res = nodes[0].node.send_preflight_probes(route_params, None).unwrap();

	let expected_route: &[(&[&Node], PaymentHash)] =
		&[(&[&nodes[1], &nodes[2], &nodes[3]], res[0].0)];

	assert_eq!(res.len(), expected_route.len());

	send_probe_along_route(&nodes[0], expected_route);

	expect_probe_successful_events(&nodes[0], res.clone());

	assert!(!nodes[0].node.has_pending_payments());
}

#[test]
fn preflight_probes_yield_event() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	// We alleviate the HTLC max-in-flight limit, as otherwise we'd always be limited through that.
	let mut config = test_default_channel_config();
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let config = Some(config);

	let configs = [config.clone(), config.clone(), config.clone(), config];
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &configs[..]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_d_id = nodes[3].node.get_our_node_id();

	// Setup channel topology:
	//                    (1M:0)- N1 -(30k:0)
	//                   /                  \
	//                 N0                    N4
	//                   \                  /
	//                    (1M:0)- N2 -(70k:0)
	//
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 30_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 70_000, 0);

	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_basic_mpp_optional();

	let payment_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV)
		.with_bolt11_features(invoice_features)
		.unwrap();

	let recv_value = 50_000_000;
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, recv_value);
	let res = nodes[0].node.send_preflight_probes(route_params, None).unwrap();

	let expected_route: &[(&[&Node], PaymentHash)] =
		&[(&[&nodes[1], &nodes[3]], res[0].0), (&[&nodes[2], &nodes[3]], res[1].0)];

	assert_eq!(res.len(), expected_route.len());

	send_probe_along_route(&nodes[0], expected_route);

	expect_probe_successful_events(&nodes[0], res.clone());

	assert!(!nodes[0].node.has_pending_payments());
}

#[test]
fn preflight_probes_yield_event_and_skip() {
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);

	// We alleviate the HTLC max-in-flight limit, as otherwise we'd always be limited through that.
	let mut config = test_default_channel_config();
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let config = Some(config);

	let configs =
		[config.clone(), config.clone(), config.clone(), config.clone(), config.clone(), config];
	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &configs[..]);
	let nodes = create_network(5, &node_cfgs, &node_chanmgrs);

	let node_e_id = nodes[4].node.get_our_node_id();

	// Setup channel topology:
	//                    (30k:0)- N2 -(1M:0)
	//                   /                  \
	//  N0 -(100k:0)-> N1                    N4
	//                   \                  /
	//                    (70k:0)- N3 -(1M:0)
	//
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 30_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 70_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 4, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 3, 4, 1_000_000, 0);

	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_basic_mpp_optional();

	let payment_params = PaymentParameters::from_node_id(node_e_id, TEST_FINAL_CLTV)
		.with_bolt11_features(invoice_features)
		.unwrap();

	let recv_value = 80_000_000;
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, recv_value);
	let res = nodes[0].node.send_preflight_probes(route_params, None).unwrap();

	let expected_route: &[(&[&Node], PaymentHash)] =
		&[(&[&nodes[1], &nodes[2], &nodes[4]], res[0].0)];

	// We check that only one probe was sent, the other one was skipped due to limited liquidity.
	assert_eq!(res.len(), 1);

	send_probe_along_route(&nodes[0], expected_route);

	expect_probe_successful_events(&nodes[0], res.clone());

	assert!(!nodes[0].node.has_pending_payments());
}

#[test]
fn claimed_send_payment_idempotent() {
	// Tests that `send_payment` (and friends) are (reasonably) idempotent.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, hash_b, preimage_b, second_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);
	let (preimage_a, _, _, payment_id) =
		send_along_route(&nodes[0], route.clone(), &[&nodes[1]], 100_000);

	macro_rules! check_send_rejected {
		() => {
			// If we try to resend a new payment with a different payment_hash but with the same
			// payment_id, it should be rejected.
			let onion = RecipientOnionFields::secret_only(second_payment_secret);
			let send_result =
				nodes[0].node.send_payment_with_route(route.clone(), hash_b, onion, payment_id);
			match send_result {
				Err(RetryableSendFailure::DuplicatePayment) => {},
				_ => panic!("Unexpected send result: {:?}", send_result),
			}

			// Further, if we try to send a spontaneous payment with the same payment_id it should
			// also be rejected.
			let send_result = nodes[0].node.send_spontaneous_payment(
				None,
				RecipientOnionFields::spontaneous_empty(),
				payment_id,
				route.route_params.clone().unwrap(),
				Retry::Attempts(0),
			);
			match send_result {
				Err(RetryableSendFailure::DuplicatePayment) => {},
				_ => panic!("Unexpected send result: {:?}", send_result),
			}
		};
	}

	check_send_rejected!();

	// Claim the payment backwards, but note that the PaymentSent event is still pending and has
	// not been seen by the user. At this point, from the user perspective nothing has changed, so
	// we must remain just as idempotent as we were before.
	do_claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1]]], preimage_a));

	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	check_send_rejected!();

	// Once the user sees and handles the `PaymentSent` event, we expect them to no longer call
	// `send_payment`, and our idempotency guarantees are off - they should have atomically marked
	// the payment complete. However, they could have called `send_payment` while the event was
	// being processed, leading to a race in our idempotency guarantees. Thus, even immediately
	// after the event is handled a duplicate payment should sitll be rejected.
	expect_payment_sent!(&nodes[0], preimage_a, Some(0));
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

	let onion = RecipientOnionFields::secret_only(second_payment_secret);
	nodes[0].node.send_payment_with_route(route, hash_b, onion, payment_id).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1]]], 100_000, hash_b, second_payment_secret);
	claim_payment(&nodes[0], &[&nodes[1]], preimage_b);
}

#[test]
fn abandoned_send_payment_idempotent() {
	// Tests that `send_payment` (and friends) allow duplicate PaymentIds immediately after
	// abandon_payment.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, hash_b, second_payment_preimage, second_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);
	let (_, first_payment_hash, _, payment_id) =
		send_along_route(&nodes[0], route.clone(), &[&nodes[1]], 100_000);

	macro_rules! check_send_rejected {
		() => {
			// If we try to resend a new payment with a different payment_hash but with the same
			// payment_id, it should be rejected.
			let onion = RecipientOnionFields::secret_only(second_payment_secret);
			let send_result =
				nodes[0].node.send_payment_with_route(route.clone(), hash_b, onion, payment_id);
			match send_result {
				Err(RetryableSendFailure::DuplicatePayment) => {},
				_ => panic!("Unexpected send result: {:?}", send_result),
			};

			// Further, if we try to send a spontaneous payment with the same payment_id it should
			// also be rejected.
			let send_result = nodes[0].node.send_spontaneous_payment(
				None,
				RecipientOnionFields::spontaneous_empty(),
				payment_id,
				route.route_params.clone().unwrap(),
				Retry::Attempts(0),
			);
			match send_result {
				Err(RetryableSendFailure::DuplicatePayment) => {},
				_ => panic!("Unexpected send result: {:?}", send_result),
			}
		};
	}

	check_send_rejected!();

	nodes[1].node.fail_htlc_backwards(&first_payment_hash);
	let fail_type = HTLCHandlingFailureType::Receive { payment_hash: first_payment_hash };
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);

	// Until we abandon the payment upon path failure, no matter how many timer ticks pass, we still cannot reuse the
	// PaymentId.
	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}
	check_send_rejected!();

	let reason = PaymentFailureReason::RecipientRejected;
	pass_failed_payment_back(&nodes[0], &[&[&nodes[1]]], false, first_payment_hash, reason);

	// However, we can reuse the PaymentId immediately after we `abandon_payment` upon passing the
	// failed payment back.
	let onion = RecipientOnionFields::secret_only(second_payment_secret);
	nodes[0].node.send_payment_with_route(route, hash_b, onion, payment_id).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1]]], 100_000, hash_b, second_payment_secret);
	claim_payment(&nodes[0], &[&nodes[1]], second_payment_preimage);
}

#[derive(PartialEq)]
enum InterceptTest {
	Forward,
	Fail,
	Timeout,
}

#[test]
fn test_trivial_inflight_htlc_tracking() {
	// In this test, we test three scenarios:
	// (1) Sending + claiming a payment successfully should return `None` when querying InFlightHtlcs
	// (2) Sending a payment without claiming it should return the payment's value (500000) when querying InFlightHtlcs
	// (3) After we claim the payment sent in (2), InFlightHtlcs should return `None` for the query.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let (_, _, chan_1_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
	let (_, _, chan_2_id, _) = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Send and claim the payment. Inflight HTLCs should be empty.
	let (_, payment_hash, _, payment_id) = send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 500000);
	let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let channel_1 =
			get_channel_ref!(&nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_1_id);

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&node_a_id),
			&NodeId::from_pubkey(&node_b_id),
			channel_1.funding().get_short_channel_id().unwrap(),
		);
		assert_eq!(chan_1_used_liquidity, None);
	}
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let channel_2 =
			get_channel_ref!(&nodes[1], nodes[2], per_peer_lock, peer_state_lock, chan_2_id);

		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&node_b_id),
			&NodeId::from_pubkey(&node_c_id),
			channel_2.funding().get_short_channel_id().unwrap(),
		);

		assert_eq!(chan_2_used_liquidity, None);
	}
	let pending_payments = nodes[0].node.list_recent_payments();
	assert_eq!(pending_payments.len(), 1);
	let details = RecentPaymentDetails::Fulfilled { payment_hash: Some(payment_hash), payment_id };
	assert_eq!(pending_payments[0], details);

	// Remove fulfilled payment
	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	// Send the payment, but do not claim it. Our inflight HTLCs should contain the pending payment.
	let (payment_preimage, payment_hash, _, payment_id) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 500000);
	let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let channel_1 =
			get_channel_ref!(&nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_1_id);

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&node_a_id),
			&NodeId::from_pubkey(&node_b_id),
			channel_1.funding().get_short_channel_id().unwrap(),
		);
		// First hop accounts for expected 1000 msat fee
		assert_eq!(chan_1_used_liquidity, Some(501000));
	}
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let channel_2 =
			get_channel_ref!(&nodes[1], nodes[2], per_peer_lock, peer_state_lock, chan_2_id);

		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&node_b_id),
			&NodeId::from_pubkey(&node_c_id),
			channel_2.funding().get_short_channel_id().unwrap(),
		);

		assert_eq!(chan_2_used_liquidity, Some(500000));
	}
	let pending_payments = nodes[0].node.list_recent_payments();
	assert_eq!(pending_payments.len(), 1);
	let details = RecentPaymentDetails::Pending { payment_id, payment_hash, total_msat: 500000 };
	assert_eq!(pending_payments[0], details);

	// Now, let's claim the payment. This should result in the used liquidity to return `None`.
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// Remove fulfilled payment
	for _ in 0..=IDEMPOTENCY_TIMEOUT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let channel_1 =
			get_channel_ref!(&nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_1_id);

		let chan_1_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&node_a_id),
			&NodeId::from_pubkey(&node_b_id),
			channel_1.funding().get_short_channel_id().unwrap(),
		);
		assert_eq!(chan_1_used_liquidity, None);
	}
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let channel_2 =
			get_channel_ref!(&nodes[1], nodes[2], per_peer_lock, peer_state_lock, chan_2_id);

		let chan_2_used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&node_b_id),
			&NodeId::from_pubkey(&node_c_id),
			channel_2.funding().get_short_channel_id().unwrap(),
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let (route, payment_hash_1, _, payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let (_, payment_hash_2, payment_secret_2) = get_payment_preimage_hash!(nodes[1]);

	// Queue up two payments - one will be delivered right away, one immediately goes into the
	// holding cell as nodes[0] is AwaitingRAA.
	{
		let onion = RecipientOnionFields::secret_only(payment_secret_1);
		let id = PaymentId(payment_hash_1.0);
		nodes[0].node.send_payment_with_route(route.clone(), payment_hash_1, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);

		let onion = RecipientOnionFields::secret_only(payment_secret_2);
		let id = PaymentId(payment_hash_2.0);
		nodes[0].node.send_payment_with_route(route, payment_hash_2, onion, id).unwrap();
		check_added_monitors(&nodes[0], 0);
	}

	let inflight_htlcs = node_chanmgrs[0].compute_inflight_htlcs();

	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let channel =
			get_channel_ref!(&nodes[0], nodes[1], per_peer_lock, peer_state_lock, channel_id);

		let used_liquidity = inflight_htlcs.used_liquidity_msat(
			&NodeId::from_pubkey(&node_a_id),
			&NodeId::from_pubkey(&node_b_id),
			channel.funding().get_short_channel_id().unwrap(),
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

	let configs = [None, Some(intercept_forwards_config), Some(zero_conf_chan_config)];
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &configs);

	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[0].keys_manager.get_secure_random_bytes();

	let _ = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let amt_msat = 100_000;
	let intercept_scid = nodes[1].node.get_intercept_scid();
	let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
		.with_route_hints(vec![RouteHint(vec![RouteHintHop {
			src_node_id: node_b_id,
			short_channel_id: intercept_scid,
			fees: RoutingFees { base_msat: 1000, proportional_millionths: 0 },
			cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])])
		.unwrap()
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	let route = get_route(
		&node_a_id,
		&route_params,
		&nodes[0].network_graph.read_only(),
		None,
		nodes[0].logger,
		&scorer,
		&Default::default(),
		&random_seed_bytes,
	)
	.unwrap();

	let (hash, payment_secret) =
		nodes[2].node.create_inbound_payment(Some(amt_msat), 60 * 60, None).unwrap();
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(hash.0);
	nodes[0].node.send_payment_with_route(route.clone(), hash, onion, id).unwrap();
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
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);

	// Check that we generate the PaymentIntercepted event when an intercept forward is detected.
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (intercept_id, outbound_amt) = match events[0] {
		crate::events::Event::HTLCIntercepted {
			intercept_id,
			expected_outbound_amount_msat,
			payment_hash,
			inbound_amount_msat,
			requested_next_hop_scid: short_channel_id,
		} => {
			assert_eq!(payment_hash, hash);
			assert_eq!(inbound_amount_msat, route.get_total_amount() + route.get_total_fees());
			assert_eq!(short_channel_id, intercept_scid);
			(intercept_id, expected_outbound_amount_msat)
		},
		_ => panic!(),
	};

	// Check for unknown channel id error.
	let chan_id = ChannelId::from_bytes([42; 32]);
	let unknown_chan_id_err =
		nodes[1].node.forward_intercepted_htlc(intercept_id, &chan_id, node_c_id, outbound_amt);
	let err = format!(
		"Channel with id {} not found for the passed counterparty node_id {}",
		chan_id, node_c_id,
	);
	assert_eq!(unknown_chan_id_err, Err(APIError::ChannelUnavailable { err }));

	if test == InterceptTest::Fail {
		// Ensure we can fail the intercepted payment back.
		nodes[1].node.fail_intercepted_htlc(intercept_id).unwrap();
		let fail =
			HTLCHandlingFailureType::InvalidForward { requested_forward_scid: intercept_scid };
		expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[fail]);
		nodes[1].node.process_pending_htlc_forwards();
		let update_fail = get_htlc_update_msgs(&nodes[1], &node_a_id);
		check_added_monitors(&nodes[1], 1);
		assert!(update_fail.update_fail_htlcs.len() == 1);
		let fail_msg = update_fail.update_fail_htlcs[0].clone();
		nodes[0].node.handle_update_fail_htlc(node_b_id, &fail_msg);
		let commitment = &update_fail.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);

		// Ensure the payment fails with the expected error.
		let fail_conditions = PaymentFailedConditions::new()
			.blamed_scid(intercept_scid)
			.blamed_chan_closed(true)
			.expected_htlc_error_data(LocalHTLCFailureReason::UnknownNextPeer, &[]);
		expect_payment_failed_conditions(&nodes[0], hash, false, fail_conditions);
	} else if test == InterceptTest::Forward {
		// Check that we'll fail as expected when sending to a channel that isn't in `ChannelReady` yet.
		let temp_id = nodes[1].node.create_channel(node_c_id, 100_000, 0, 42, None, None).unwrap();
		let unusable_chan_err =
			nodes[1].node.forward_intercepted_htlc(intercept_id, &temp_id, node_c_id, outbound_amt);
		let err = format!(
			"Channel with id {} for the passed counterparty node_id {} is still opening.",
			temp_id, node_c_id,
		);
		assert_eq!(unusable_chan_err, Err(APIError::ChannelUnavailable { err }));
		assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 1);

		// Open the just-in-time channel so the payment can then be forwarded.
		let (_, chan_id) = open_zero_conf_channel(&nodes[1], &nodes[2], None);

		// Finally, forward the intercepted payment through and claim it.
		nodes[1]
			.node
			.forward_intercepted_htlc(intercept_id, &chan_id, node_c_id, outbound_amt)
			.unwrap();
		expect_and_process_pending_htlcs(&nodes[1], false);

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
		nodes[2].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
		let commitment = &payment_event.commitment_msg;
		do_commitment_signed_dance(&nodes[2], &nodes[1], commitment, false, true);
		expect_and_process_pending_htlcs(&nodes[2], false);

		let preimage = Some(nodes[2].node.get_payment_preimage(hash, payment_secret).unwrap());
		expect_payment_claimable!(&nodes[2], hash, payment_secret, amt_msat, preimage, node_c_id);

		let path: &[&[_]] = &[&[&nodes[1], &nodes[2]]];
		do_claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], path, preimage.unwrap()));

		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 2);
		match events[0] {
			Event::PaymentSent { payment_preimage, payment_hash, ref fee_paid_msat, .. } => {
				assert_eq!(preimage.unwrap(), payment_preimage);
				assert_eq!(hash, payment_hash);
				assert_eq!(fee_paid_msat, &Some(1000));
			},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PaymentPathSuccessful { payment_hash, .. } => {
				assert_eq!(payment_hash, Some(hash));
			},
			_ => panic!("Unexpected event"),
		}
		check_added_monitors(&nodes[0], 1);
	} else if test == InterceptTest::Timeout {
		let mut block = create_dummy_block(nodes[0].best_block_hash(), 42, Vec::new());
		connect_block(&nodes[0], &block);
		connect_block(&nodes[1], &block);
		for _ in 0..TEST_FINAL_CLTV {
			block.header.prev_blockhash = block.block_hash();
			connect_block(&nodes[0], &block);
			connect_block(&nodes[1], &block);
		}
		let fail_type =
			HTLCHandlingFailureType::InvalidForward { requested_forward_scid: intercept_scid };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);
		check_added_monitors(&nodes[1], 1);

		let htlc_fail = get_htlc_update_msgs(&nodes[1], &node_a_id);
		assert!(htlc_fail.update_add_htlcs.is_empty());
		assert_eq!(htlc_fail.update_fail_htlcs.len(), 1);
		assert!(htlc_fail.update_fail_malformed_htlcs.is_empty());
		assert!(htlc_fail.update_fee.is_none());

		nodes[0].node.handle_update_fail_htlc(node_b_id, &htlc_fail.update_fail_htlcs[0]);
		let commitment = &htlc_fail.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
		let reason = LocalHTLCFailureReason::TemporaryNodeFailure;
		expect_payment_failed!(nodes[0], hash, false, reason, []);

		// Check for unknown intercept id error.
		let (_, chan_id) = open_zero_conf_channel(&nodes[1], &nodes[2], None);
		let unknown_intercept_id_err =
			nodes[1].node.forward_intercepted_htlc(intercept_id, &chan_id, node_c_id, outbound_amt);
		let err = format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0));
		assert_eq!(unknown_intercept_id_err, Err(APIError::APIMisuseError { err }));

		let unknown_intercept_id_err =
			nodes[1].node.fail_intercepted_htlc(intercept_id).unwrap_err();
		let err = format!("Payment with intercept id {} not found", log_bytes!(intercept_id.0));
		assert_eq!(unknown_intercept_id_err, APIError::APIMisuseError { err });
	}
}

#[test]
fn accept_underpaying_htlcs_config() {
	do_accept_underpaying_htlcs_config(1);
	do_accept_underpaying_htlcs_config(2);
	do_accept_underpaying_htlcs_config(3);
}

fn do_accept_underpaying_htlcs_config(num_mpp_parts: usize) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let max_in_flight_percent = 10;
	let mut intercept_forwards_config = test_default_channel_config();
	intercept_forwards_config.accept_intercept_htlcs = true;
	intercept_forwards_config
		.channel_handshake_config
		.max_inbound_htlc_value_in_flight_percent_of_channel = max_in_flight_percent;
	let mut underpay_config = test_default_channel_config();
	underpay_config.channel_config.accept_underpaying_htlcs = true;
	underpay_config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel =
		max_in_flight_percent;

	let configs = [None, Some(intercept_forwards_config), Some(underpay_config)];
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &configs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let amt_msat = 900_000;

	let mut chan_ids = Vec::new();
	for _ in 0..num_mpp_parts {
		// We choose the channel size so that there can be at most one part pending on each channel.
		let channel_size =
			amt_msat / 1000 / num_mpp_parts as u64 * 100 / max_in_flight_percent as u64 + 100;
		let _ = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_size, 0);
		let chan = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, channel_size, 0);
		chan_ids.push(chan.0.channel_id);
	}

	// Send the initial payment.
	let skimmed_fee_msat = 20;
	let mut route_hints = Vec::new();
	for _ in 0..num_mpp_parts {
		route_hints.push(RouteHint(vec![RouteHintHop {
			src_node_id: node_b_id,
			short_channel_id: nodes[1].node.get_intercept_scid(),
			fees: RoutingFees { base_msat: 1000, proportional_millionths: 0 },
			cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
			htlc_minimum_msat: None,
			htlc_maximum_msat: Some(amt_msat / num_mpp_parts as u64 + 5),
		}]));
	}
	let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
		.with_route_hints(route_hints)
		.unwrap()
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	let (payment_hash, payment_secret) =
		nodes[2].node.create_inbound_payment(Some(amt_msat), 60 * 60, None).unwrap();

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(0)).unwrap();

	check_added_monitors(&nodes[0], num_mpp_parts); // one monitor per path
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), num_mpp_parts);

	// Forward the intercepted payments.
	for (idx, ev) in events.into_iter().enumerate() {
		let ev = SendEvent::from_event(ev);
		nodes[1].node.handle_update_add_htlc(node_a_id, &ev.msgs[0]);
		do_commitment_signed_dance(&nodes[1], &nodes[0], &ev.commitment_msg, false, true);
		expect_and_process_pending_htlcs(&nodes[1], false);

		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		let (intercept_id, expected_outbound_amt_msat) = match events[0] {
			crate::events::Event::HTLCIntercepted {
				intercept_id,
				expected_outbound_amount_msat,
				payment_hash: pmt_hash,
				..
			} => {
				assert_eq!(pmt_hash, payment_hash);
				(intercept_id, expected_outbound_amount_msat)
			},
			_ => panic!(),
		};
		let amt = expected_outbound_amt_msat - skimmed_fee_msat;
		nodes[1]
			.node
			.forward_intercepted_htlc(intercept_id, &chan_ids[idx], node_c_id, amt)
			.unwrap();
		expect_and_process_pending_htlcs(&nodes[1], false);
		let pay_event = {
			{
				let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
				assert_eq!(added_monitors.len(), 1);
				added_monitors.clear();
			}
			let mut events = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		nodes[2].node.handle_update_add_htlc(node_b_id, &pay_event.msgs[0]);
		do_commitment_signed_dance(&nodes[2], &nodes[1], &pay_event.commitment_msg, false, true);
		if idx == num_mpp_parts - 1 {
			expect_and_process_pending_htlcs(&nodes[2], false);
		}
	}

	// Claim the payment and check that the skimmed fee is as expected.
	let payment_preimage =
		nodes[2].node.get_payment_preimage(payment_hash, payment_secret).unwrap();
	let events = nodes[2].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		crate::events::Event::PaymentClaimable {
			payment_hash: pmt_hash,
			ref purpose,
			amount_msat,
			counterparty_skimmed_fee_msat,
			receiver_node_id,
			..
		} => {
			assert_eq!(pmt_hash, payment_hash);
			assert_eq!(amt_msat - skimmed_fee_msat * num_mpp_parts as u64, amount_msat);
			assert_eq!(skimmed_fee_msat * num_mpp_parts as u64, counterparty_skimmed_fee_msat);
			assert_eq!(node_c_id, receiver_node_id.unwrap());
			match purpose {
				crate::events::PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage: ev_payment_preimage,
					payment_secret: ev_payment_secret,
					..
				} => {
					assert_eq!(payment_preimage, ev_payment_preimage.unwrap());
					assert_eq!(payment_secret, *ev_payment_secret);
				},
				_ => panic!(),
			}
		},
		_ => panic!("Unexpected event"),
	}
	let mut expected_paths_vecs = Vec::new();
	let mut expected_paths = Vec::new();
	for _ in 0..num_mpp_parts {
		expected_paths_vecs.push(vec![&nodes[1], &nodes[2]]);
	}
	for i in 0..num_mpp_parts {
		expected_paths.push(&expected_paths_vecs[i][..]);
	}
	expected_paths[0].last().unwrap().node.claim_funds(payment_preimage);
	let args = ClaimAlongRouteArgs::new(&nodes[0], &expected_paths[..], payment_preimage)
		.with_expected_extra_fees(vec![skimmed_fee_msat as u32; num_mpp_parts]);
	let total_fee_msat = pass_claimed_payment_along_route(args);
	// The sender doesn't know that the penultimate hop took an extra fee.
	let amt = total_fee_msat - skimmed_fee_msat * num_mpp_parts as u64;
	expect_payment_sent(&nodes[0], payment_preimage, Some(Some(amt)), true, true);
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
	let persister;
	let chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let node_a_reload;

	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let channel_id_1 = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let channel_id_2 = create_announced_chan_between_nodes(&nodes, 2, 1).2;

	// Marshall data to send the payment
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let amt_msat = 1000;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	let (_, hash, preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], amt_msat);

	macro_rules! pass_failed_attempt_with_retry_along_path {
		($failing_channel_id: expr, $expect_pending_htlcs_forwardable: expr) => {
			// Send a payment attempt that fails due to lack of liquidity on the second hop
			check_added_monitors(&nodes[0], 1);
			let update_0 = get_htlc_update_msgs(&nodes[0], &node_b_id);
			let mut update_add = update_0.update_add_htlcs[0].clone();
			nodes[1].node.handle_update_add_htlc(node_a_id, &update_add);
			let commitment = &update_0.commitment_signed;
			do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, true);
			expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
			nodes[1].node.process_pending_htlc_forwards();
			expect_htlc_failure_conditions(
				nodes[1].node.get_and_clear_pending_events(),
				&[HTLCHandlingFailureType::Forward {
					node_id: Some(node_c_id),
					channel_id: $failing_channel_id,
				}],
			);
			nodes[1].node.process_pending_htlc_forwards();
			let update_1 = get_htlc_update_msgs(&nodes[1], &node_a_id);
			check_added_monitors(&nodes[1], 1);
			assert!(update_1.update_fail_htlcs.len() == 1);
			let fail_msg = update_1.update_fail_htlcs[0].clone();
			nodes[0].node.handle_update_fail_htlc(node_b_id, &fail_msg);
			let commitment = &update_1.commitment_signed;
			do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);

			// Ensure the attempt fails
			let mut events = nodes[0].node.get_and_clear_pending_events();
			if $expect_pending_htlcs_forwardable {
				assert_eq!(events.len(), 1);
			} else {
				assert_eq!(events.len(), 2);
			}
			match events[0] {
				Event::PaymentPathFailed { payment_hash, payment_failed_permanently, .. } => {
					assert_eq!(hash, payment_hash);
					assert_eq!(payment_failed_permanently, false);
				},
				_ => panic!("Unexpected event"),
			}
			if !$expect_pending_htlcs_forwardable {
				match events[1] {
					Event::PaymentFailed { payment_hash, .. } => {
						assert_eq!(Some(hash), payment_hash);
					},
					_ => panic!("Unexpected event"),
				}
			}
		};
	}

	if test == AutoRetry::Success {
		// Test that we can succeed on the first retry.
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let id = PaymentId(hash.0);
		let retry = Retry::Attempts(1);
		nodes[0].node.send_payment(hash, onion, id, route_params, retry).unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// Open a new channel with liquidity on the second hop so we can find a route for the retry
		// attempt, since the initial second hop channel will be excluded from pathfinding
		create_announced_chan_between_nodes(&nodes, 1, 2);

		// We retry payments in `process_pending_htlc_forwards`
		nodes[0].node.process_pending_htlc_forwards();
		check_added_monitors(&nodes[0], 1);

		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		let event = msg_events.pop().unwrap();

		let path = &[&nodes[1], &nodes[2]];
		pass_along_path(&nodes[0], path, amt_msat, hash, Some(payment_secret), event, true, None);
		claim_payment_along_route(ClaimAlongRouteArgs::new(
			&nodes[0],
			&[&[&nodes[1], &nodes[2]]],
			preimage,
		));
	} else if test == AutoRetry::Spontaneous {
		let onion = RecipientOnionFields::spontaneous_empty();
		let id = PaymentId(hash.0);
		nodes[0]
			.node
			.send_spontaneous_payment(Some(preimage), onion, id, route_params, Retry::Attempts(1))
			.unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// Open a new channel with liquidity on the second hop so we can find a route for the retry
		// attempt, since the initial second hop channel will be excluded from pathfinding
		create_announced_chan_between_nodes(&nodes, 1, 2);

		// We retry payments in `process_pending_htlc_forwards`
		nodes[0].node.process_pending_htlc_forwards();
		check_added_monitors(&nodes[0], 1);

		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		let event = msg_events.pop().unwrap();

		let path = &[&nodes[1], &nodes[2]];
		pass_along_path(&nodes[0], path, amt_msat, hash, None, event, true, Some(preimage));
		claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], &[path], preimage));
	} else if test == AutoRetry::FailAttempts {
		// Ensure ChannelManager will not retry a payment if it has run out of payment attempts.
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let id = PaymentId(hash.0);
		nodes[0].node.send_payment(hash, onion, id, route_params, Retry::Attempts(1)).unwrap();
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
		#[cfg(feature = "std")]
		{
			// Ensure ChannelManager will not retry a payment if it times out due to Retry::Timeout.
			let onion = RecipientOnionFields::secret_only(payment_secret);
			let id = PaymentId(hash.0);
			let retry = Retry::Timeout(Duration::from_secs(60));
			nodes[0].node.send_payment(hash, onion, id, route_params, retry).unwrap();
			pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

			// Advance the time so the second attempt fails due to timeout.
			TestTime::advance(Duration::from_secs(61));

			// Make sure we don't retry again.
			nodes[0].node.process_pending_htlc_forwards();
			let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(msg_events.len(), 0);

			let mut events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentFailed { payment_hash, payment_id, reason } => {
					assert_eq!(Some(hash), payment_hash);
					assert_eq!(PaymentId(hash.0), payment_id);
					assert_eq!(PaymentFailureReason::RetriesExhausted, reason.unwrap());
				},
				_ => panic!("Unexpected event"),
			}
		}
	} else if test == AutoRetry::FailOnRestart {
		// Ensure ChannelManager will not retry a payment after restart, even if there were retry
		// attempts remaining prior to restart.
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let id = PaymentId(hash.0);
		nodes[0].node.send_payment(hash, onion, id, route_params, Retry::Attempts(2)).unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// Open a new channel with no liquidity on the second hop so we can find a (bad) route for
		// the retry attempt, since the initial second hop channel will be excluded from pathfinding
		let channel_id_3 = create_announced_chan_between_nodes(&nodes, 2, 1).2;

		// Ensure the first retry attempt fails, with 1 retry attempt remaining
		nodes[0].node.process_pending_htlc_forwards();
		pass_failed_attempt_with_retry_along_path!(channel_id_3, true);

		// Restart the node and ensure that ChannelManager does not use its remaining retry attempt
		let node_encoded = nodes[0].node.encode();
		let mon_ser = get_monitor!(nodes[0], channel_id_1).encode();
		reload_node!(nodes[0], node_encoded, &[&mon_ser], persister, chain_monitor, node_a_reload);

		nodes[0].node.process_pending_htlc_forwards();
		// Make sure we don't retry again.
		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 0);

		let mut events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash, payment_id, reason } => {
				assert_eq!(Some(hash), payment_hash);
				assert_eq!(PaymentId(hash.0), payment_id);
				assert_eq!(PaymentFailureReason::RetriesExhausted, reason.unwrap());
			},
			_ => panic!("Unexpected event"),
		}
	} else if test == AutoRetry::FailOnRetry {
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let id = PaymentId(hash.0);
		nodes[0].node.send_payment(hash, onion, id, route_params, Retry::Attempts(1)).unwrap();
		pass_failed_attempt_with_retry_along_path!(channel_id_2, true);

		// We retry payments in `process_pending_htlc_forwards`. Since our channel closed, we should
		// fail to find a route.
		nodes[0].node.process_pending_htlc_forwards();
		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 0);

		let mut events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentFailed { payment_hash, payment_id, reason } => {
				assert_eq!(Some(hash), payment_hash);
				assert_eq!(PaymentId(hash.0), payment_id);
				assert_eq!(PaymentFailureReason::RouteNotFound, reason.unwrap());
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Open three channels, the first has plenty of liquidity, the second and third have ~no
	// available liquidity, causing any outbound payments routed over it to fail immediately.
	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2 =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 989_000_000);
	let chan_2_id = chan_2.0.contents.short_channel_id;
	let chan_3 =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 989_000_000);
	let chan_3_id = chan_3.0.contents.short_channel_id;

	// Marshall data to send the payment
	let amt_msat = 10_000_000;
	let (_, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();

	// Configure the initial send path
	let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	route_params.max_total_routing_fee_msat = None;

	let send_route = Route {
		paths: vec![
			Path {
				hops: vec![RouteHop {
					pubkey: node_b_id,
					node_features: nodes[1].node.node_features(),
					short_channel_id: chan_1_id,
					channel_features: nodes[1].node.channel_features(),
					fee_msat: amt_msat / 2,
					cltv_expiry_delta: 100,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			},
			Path {
				hops: vec![RouteHop {
					pubkey: node_b_id,
					node_features: nodes[1].node.node_features(),
					short_channel_id: chan_2_id,
					channel_features: nodes[1].node.channel_features(),
					fee_msat: amt_msat / 2,
					cltv_expiry_delta: 100,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			},
		],
		route_params: Some(route_params.clone()),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(send_route));

	// Configure the retry1 paths
	let mut payment_params = route_params.payment_params.clone();
	payment_params.previously_failed_channels.push(chan_2_id);
	let mut retry_1_params =
		RouteParameters::from_payment_params_and_value(payment_params, amt_msat / 2);
	retry_1_params.max_total_routing_fee_msat = None;

	let retry_1_route = Route {
		paths: vec![
			Path {
				hops: vec![RouteHop {
					pubkey: node_b_id,
					node_features: nodes[1].node.node_features(),
					short_channel_id: chan_1_id,
					channel_features: nodes[1].node.channel_features(),
					fee_msat: amt_msat / 4,
					cltv_expiry_delta: 100,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			},
			Path {
				hops: vec![RouteHop {
					pubkey: node_b_id,
					node_features: nodes[1].node.node_features(),
					short_channel_id: chan_3_id,
					channel_features: nodes[1].node.channel_features(),
					fee_msat: amt_msat / 4,
					cltv_expiry_delta: 100,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			},
		],
		route_params: Some(retry_1_params.clone()),
	};
	nodes[0].router.expect_find_route(retry_1_params.clone(), Ok(retry_1_route));

	// Configure the retry2 path
	let mut payment_params = retry_1_params.payment_params.clone();
	payment_params.previously_failed_channels.push(chan_3_id);
	let mut retry_2_params =
		RouteParameters::from_payment_params_and_value(payment_params, amt_msat / 4);
	retry_2_params.max_total_routing_fee_msat = None;

	let retry_2_route = Route {
		paths: vec![Path {
			hops: vec![RouteHop {
				pubkey: node_b_id,
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_1_id,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: amt_msat / 4,
				cltv_expiry_delta: 100,
				maybe_announced_channel: true,
			}],
			blinded_tail: None,
		}],
		route_params: Some(retry_2_params.clone()),
	};
	nodes[0].router.expect_find_route(retry_2_params, Ok(retry_2_route));

	// Send a payment that will partially fail on send, then partially fail on retry, then succeed.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(3)).unwrap();

	let payment_failed_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(payment_failed_events.len(), 2);
	match payment_failed_events[0] {
		Event::PaymentPathFailed { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match payment_failed_events[1] {
		Event::PaymentPathFailed { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// Pass the first part of the payment along the path.
	check_added_monitors(&nodes[0], 1); // only one HTLC actually made it out
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();

	// Only one HTLC/channel update actually made it out
	assert_eq!(msg_events.len(), 1);
	let mut payment_event = SendEvent::from_event(msg_events.remove(0));

	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
	check_added_monitors(&nodes[1], 1);
	let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_first_raa);
	check_added_monitors(&nodes[0], 1);
	let as_2nd_htlcs = SendEvent::from_node(&nodes[0]);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_first_cs);
	check_added_monitors(&nodes[0], 1);
	let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_first_raa);
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.handle_update_add_htlc(node_a_id, &as_2nd_htlcs.msgs[0]);
	nodes[1].node.handle_update_add_htlc(node_a_id, &as_2nd_htlcs.msgs[1]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_2nd_htlcs.commitment_msg);
	check_added_monitors(&nodes[1], 1);
	let (bs_second_raa, bs_second_cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_raa);
	check_added_monitors(&nodes[0], 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_second_cs);
	check_added_monitors(&nodes[0], 1);
	let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_second_raa);
	check_added_monitors(&nodes[1], 1);

	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_payment_claimable!(nodes[1], payment_hash, payment_secret, amt_msat);
	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, amt_msat);
	let mut bs_claim = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert_eq!(bs_claim.update_fulfill_htlcs.len(), 1);

	nodes[0].node.handle_update_fulfill_htlc(node_b_id, bs_claim.update_fulfill_htlcs.remove(0));
	expect_payment_sent(&nodes[0], payment_preimage, None, false, false);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_claim.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let (as_third_raa, as_third_cs) = get_revoke_commit_msgs(&nodes[0], &node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_third_raa);
	check_added_monitors(&nodes[1], 4);
	let mut bs_2nd_claim = get_htlc_update_msgs(&nodes[1], &node_a_id);

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_third_cs);
	check_added_monitors(&nodes[1], 1);
	let bs_third_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_third_raa);
	check_added_monitors(&nodes[0], 1);
	expect_payment_path_successful!(nodes[0]);

	let bs_second_fulfill_a = bs_2nd_claim.update_fulfill_htlcs.remove(0);
	let bs_second_fulfill_b = bs_2nd_claim.update_fulfill_htlcs.remove(0);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, bs_second_fulfill_a);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, bs_second_fulfill_b);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_2nd_claim.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let (as_fourth_raa, as_fourth_cs) = get_revoke_commit_msgs(&nodes[0], &node_b_id);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_fourth_raa);
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_fourth_cs);
	check_added_monitors(&nodes[1], 1);
	let bs_second_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_raa);
	check_added_monitors(&nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let Event::PaymentPathSuccessful { .. } = events[0] {
	} else {
		panic!();
	}
	if let Event::PaymentPathSuccessful { .. } = events[1] {
	} else {
		panic!();
	}
}

#[test]
fn auto_retry_zero_attempts_send_error() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	// Open a single channel that does not have sufficient liquidity for the payment we want to
	// send.
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 989_000_000);
	let chan_id = chan.0.contents.short_channel_id;

	// Marshall data to send the payment
	let amt_msat = 10_000_000;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash(&nodes[1], Some(amt_msat), None);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);

	// Override the route search to return a route, rather than failing at the route-finding step.
	let send_route = Route {
		paths: vec![Path {
			hops: vec![RouteHop {
				pubkey: node_b_id,
				node_features: nodes[1].node.node_features(),
				short_channel_id: chan_id,
				channel_features: nodes[1].node.channel_features(),
				fee_msat: amt_msat,
				cltv_expiry_delta: 100,
				maybe_announced_channel: true,
			}],
			blinded_tail: None,
		}],
		route_params: Some(route_params.clone()),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(send_route));

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(0)).unwrap();

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let Event::PaymentPathFailed { .. } = events[0] {
	} else {
		panic!();
	}
	if let Event::PaymentFailed { .. } = events[1] {
	} else {
		panic!();
	}
	check_added_monitors(&nodes[0], 0);
}

#[test]
fn fails_paying_after_rejected_by_payee() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	// Marshall data to send the payment
	let amt_msat = 20_000;
	let (_, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(1)).unwrap();
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(&nodes[1], payment_hash, payment_secret, amt_msat);

	nodes[1].node.fail_htlc_backwards(&payment_hash);
	let fail_type = HTLCHandlingFailureType::Receive { payment_hash };
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);
	let reason = PaymentFailureReason::RecipientRejected;
	pass_failed_payment_back(&nodes[0], &[&[&nodes[1]]], false, payment_hash, reason);
}

#[test]
fn retry_multi_path_single_failed_payment() {
	// Tests that we can/will retry after a single path of an MPP payment failed immediately
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);

	let amt_msat = 100_010_000;

	let (_, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();
	let mut route_params =
		RouteParameters::from_payment_params_and_value(payment_params.clone(), amt_msat);
	route_params.max_total_routing_fee_msat = None;

	let chans = nodes[0].node.list_usable_channels();
	let mut route = Route {
		paths: vec![
			Path {
				hops: vec![RouteHop {
					pubkey: node_b_id,
					node_features: nodes[1].node.node_features(),
					short_channel_id: chans[0].short_channel_id.unwrap(),
					channel_features: nodes[1].node.channel_features(),
					fee_msat: 10_000,
					cltv_expiry_delta: 100,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			},
			Path {
				hops: vec![RouteHop {
					pubkey: node_b_id,
					node_features: nodes[1].node.node_features(),
					short_channel_id: chans[1].short_channel_id.unwrap(),
					channel_features: nodes[1].node.channel_features(),
					fee_msat: 100_000_001, // Our default max-HTLC-value is 10% of the channel value, which this is one more than
					cltv_expiry_delta: 100,
					maybe_announced_channel: true,
				}],
				blinded_tail: None,
			},
		],
		route_params: Some(route_params.clone()),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	// On retry, split the payment across both channels.
	route.paths[0].hops[0].fee_msat = 50_000_001;
	route.paths[1].hops[0].fee_msat = 50_000_000;
	let mut pay_params = route.route_params.clone().unwrap().payment_params;
	pay_params.previously_failed_channels.push(chans[1].short_channel_id.unwrap());

	let mut retry_params = RouteParameters::from_payment_params_and_value(pay_params, 100_000_000);
	retry_params.max_total_routing_fee_msat = None;
	route.route_params = Some(retry_params.clone());
	nodes[0].router.expect_find_route(retry_params, Ok(route.clone()));

	{
		let scorer = chanmon_cfgs[0].scorer.read().unwrap();
		// The initial send attempt, 2 paths
		let effective_capacity = EffectiveCapacity::Unknown;
		let usage = ChannelUsage { amount_msat: 10_000, inflight_htlc_msat: 0, effective_capacity };
		scorer.expect_usage(chans[0].short_channel_id.unwrap(), usage);
		let usage =
			ChannelUsage { amount_msat: 100_000_001, inflight_htlc_msat: 0, effective_capacity };
		scorer.expect_usage(chans[1].short_channel_id.unwrap(), usage);
		// The retry, 2 paths. Ensure that the in-flight HTLC amount is factored in.
		let usage = ChannelUsage {
			amount_msat: 50_000_001,
			inflight_htlc_msat: 10_000,
			effective_capacity,
		};
		scorer.expect_usage(chans[0].short_channel_id.unwrap(), usage);
		let usage =
			ChannelUsage { amount_msat: 50_000_000, inflight_htlc_msat: 0, effective_capacity };
		scorer.expect_usage(chans[1].short_channel_id.unwrap(), usage);
	}

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(1)).unwrap();
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentPathFailed {
			payment_hash: ev_payment_hash,
			payment_failed_permanently: false,
			failure: PathFailure::InitialSend { err: APIError::ChannelUnavailable { .. } },
			short_channel_id: Some(expected_scid),
			..
		} => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(expected_scid, route.paths[1].hops[0].short_channel_id);
		},
		_ => panic!("Unexpected event"),
	}
	let htlc_msgs = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(htlc_msgs.len(), 2);
	check_added_monitors(&nodes[0], 2);
}

#[test]
fn immediate_retry_on_failure() {
	// Tests that we can/will retry immediately after a failure
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);

	let amt_msat = 100_000_001;
	let (_, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);

	let chans = nodes[0].node.list_usable_channels();
	let mut route = Route {
		paths: vec![Path {
			hops: vec![RouteHop {
				pubkey: node_b_id,
				node_features: nodes[1].node.node_features(),
				short_channel_id: chans[0].short_channel_id.unwrap(),
				channel_features: nodes[1].node.channel_features(),
				fee_msat: 100_000_001, // Our default max-HTLC-value is 10% of the channel value, which this is one more than
				cltv_expiry_delta: 100,
				maybe_announced_channel: true,
			}],
			blinded_tail: None,
		}],
		route_params: Some(route_params.clone()),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	// On retry, split the payment across both channels.
	route.paths.push(route.paths[0].clone());
	route.paths[0].hops[0].short_channel_id = chans[1].short_channel_id.unwrap();
	route.paths[0].hops[0].fee_msat = 50_000_000;
	route.paths[1].hops[0].fee_msat = 50_000_001;
	let mut pay_params = route_params.payment_params.clone();
	pay_params.previously_failed_channels.push(chans[0].short_channel_id.unwrap());
	let retry_params = RouteParameters::from_payment_params_and_value(pay_params, amt_msat);
	route.route_params = Some(retry_params.clone());
	nodes[0].router.expect_find_route(retry_params, Ok(route.clone()));

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(1)).unwrap();
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentPathFailed {
			payment_hash: ev_payment_hash,
			payment_failed_permanently: false,
			failure: PathFailure::InitialSend { err: APIError::ChannelUnavailable { .. } },
			short_channel_id: Some(expected_scid),
			..
		} => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(expected_scid, route.paths[1].hops[0].short_channel_id);
		},
		_ => panic!("Unexpected event"),
	}
	let htlc_msgs = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(htlc_msgs.len(), 2);
	check_added_monitors(&nodes[0], 2);
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0);
	let chan_1_scid = chan_1.0.contents.short_channel_id;
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 0);
	let chan_2_scid = chan_2.0.contents.short_channel_id;

	let amt_msat = 200_000_000;
	let (_, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[1], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();
	let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	route_params.max_total_routing_fee_msat = None;

	let mut route = Route {
		paths: vec![
			Path {
				hops: vec![
					RouteHop {
						pubkey: node_b_id,
						node_features: nodes[1].node.node_features(),
						short_channel_id: chan_1_scid,
						channel_features: nodes[1].node.channel_features(),
						fee_msat: 0, // nodes[1] will fail the payment as we don't pay its fee
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: node_c_id,
						node_features: nodes[2].node.node_features(),
						short_channel_id: chan_2_scid,
						channel_features: nodes[2].node.channel_features(),
						fee_msat: 100_000_000,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			},
			Path {
				hops: vec![
					RouteHop {
						pubkey: node_b_id,
						node_features: nodes[1].node.node_features(),
						short_channel_id: chan_1_scid,
						channel_features: nodes[1].node.channel_features(),
						fee_msat: 0, // nodes[1] will fail the payment as we don't pay its fee
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: node_c_id,
						node_features: nodes[2].node.node_features(),
						short_channel_id: chan_2_scid,
						channel_features: nodes[2].node.channel_features(),
						fee_msat: 100_000_000,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			},
		],
		route_params: Some(route_params.clone()),
	};
	route.route_params.as_mut().unwrap().max_total_routing_fee_msat = None;
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	let mut second_payment_params = route_params.payment_params.clone();
	second_payment_params.previously_failed_channels = vec![chan_2_scid, chan_2_scid];
	// On retry, we'll only return one path
	route.paths.remove(1);
	route.paths[0].hops[1].fee_msat = amt_msat;
	let mut retry_params =
		RouteParameters::from_payment_params_and_value(second_payment_params, amt_msat);
	retry_params.max_total_routing_fee_msat = None;
	route.route_params = Some(retry_params.clone());
	nodes[0].router.expect_find_route(retry_params, Ok(route.clone()));

	// We can't use the commitment_signed_dance macro helper because in this test we'll be sending
	// two HTLCs back-to-back on the same channel, and the macro only expects to handle one at a
	// time.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(1)).unwrap();

	let first_htlc = SendEvent::from_node(&nodes[0]);
	check_added_monitors(&nodes[0], 1);
	assert_eq!(first_htlc.msgs.len(), 1);

	nodes[1].node.handle_update_add_htlc(node_a_id, &first_htlc.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &first_htlc.commitment_msg);
	check_added_monitors(&nodes[1], 1);

	let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_first_raa);
	check_added_monitors(&nodes[0], 1);

	let second_htlc = SendEvent::from_node(&nodes[0]);
	assert_eq!(second_htlc.msgs.len(), 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_first_cs);
	check_added_monitors(&nodes[0], 1);

	let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_first_raa);
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.handle_update_add_htlc(node_a_id, &second_htlc.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &second_htlc.commitment_msg);
	check_added_monitors(&nodes[1], 1);

	let (bs_second_raa, bs_second_cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_raa);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_second_cs);
	check_added_monitors(&nodes[0], 1);

	let as_second_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_second_raa);
	check_added_monitors(&nodes[1], 1);

	expect_and_process_pending_htlcs(&nodes[1], false);
	let next_hop_failure =
		HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 };
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[next_hop_failure.clone(), next_hop_failure.clone()]
	);
	check_added_monitors(&nodes[1], 1);

	let bs_fail_update = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert_eq!(bs_fail_update.update_fail_htlcs.len(), 2);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_fail_update.update_fail_htlcs[0]);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_fail_update.update_fail_htlcs[1]);
	let commitment = &bs_fail_update.commitment_signed;
	do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);

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
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentPathFailed {
			payment_hash: ev_payment_hash,
			payment_failed_permanently,
			..
		} => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(payment_failed_permanently, false);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentPathFailed {
			payment_hash: ev_payment_hash,
			payment_failed_permanently,
			..
		} => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(payment_failed_permanently, false);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.process_pending_htlc_forwards();
	let retry_htlc_updates = SendEvent::from_node(&nodes[0]);
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_update_add_htlc(node_a_id, &retry_htlc_updates.msgs[0]);
	let commitment = &retry_htlc_updates.commitment_msg;
	do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		core::slice::from_ref(&next_hop_failure)
	);
	check_added_monitors(&nodes[1], 1);

	let bs_fail_update = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_fail_update.update_fail_htlcs[0]);
	let commitment = &bs_fail_update.commitment_signed;
	do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, true);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentPathFailed {
			payment_hash: ev_payment_hash,
			payment_failed_permanently,
			..
		} => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(payment_failed_permanently, false);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentFailed {
			payment_hash: ref ev_payment_hash,
			payment_id: ref ev_payment_id,
			reason: ref ev_reason,
		} => {
			assert_eq!(Some(payment_hash), *ev_payment_hash);
			assert_eq!(PaymentId(payment_hash.0), *ev_payment_id);
			assert_eq!(PaymentFailureReason::RetriesExhausted, ev_reason.unwrap());
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0);
	let chan_1_scid = chan_1.0.contents.short_channel_id;
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 10_000_000, 0);
	let chan_2_scid = chan_2.0.contents.short_channel_id;

	let amt_msat = 200_000_000;
	let (_, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[2], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();
	let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	route_params.max_total_routing_fee_msat = None;

	let mut route = Route {
		paths: vec![
			Path {
				hops: vec![
					RouteHop {
						pubkey: node_b_id,
						node_features: nodes[1].node.node_features(),
						short_channel_id: chan_1_scid,
						channel_features: nodes[1].node.channel_features(),
						fee_msat: 0, // nodes[1] will fail the payment as we don't pay its fee
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: node_c_id,
						node_features: nodes[2].node.node_features(),
						short_channel_id: chan_2_scid,
						channel_features: nodes[2].node.channel_features(),
						fee_msat: 100_000_000,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			},
			Path {
				hops: vec![
					RouteHop {
						pubkey: node_b_id,
						node_features: nodes[1].node.node_features(),
						short_channel_id: chan_1_scid,
						channel_features: nodes[1].node.channel_features(),
						fee_msat: 100_000,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: node_c_id,
						node_features: nodes[2].node.node_features(),
						short_channel_id: chan_2_scid,
						channel_features: nodes[2].node.channel_features(),
						fee_msat: 100_000_000,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			},
		],
		route_params: Some(route_params.clone()),
	};

	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));

	let mut second_payment_params = route_params.payment_params.clone();
	second_payment_params.previously_failed_channels = vec![chan_2_scid];
	// On retry, we'll only be asked for one path (or 100k sats)
	route.paths.remove(0);
	let mut retry_params =
		RouteParameters::from_payment_params_and_value(second_payment_params, amt_msat / 2);
	retry_params.max_total_routing_fee_msat = None;
	route.route_params = Some(retry_params.clone());
	nodes[0].router.expect_find_route(retry_params, Ok(route.clone()));

	// We can't use the commitment_signed_dance macro helper because in this test we'll be sending
	// two HTLCs back-to-back on the same channel, and the macro only expects to handle one at a
	// time.
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params, Retry::Attempts(1)).unwrap();
	let first_htlc = SendEvent::from_node(&nodes[0]);
	check_added_monitors(&nodes[0], 1);
	assert_eq!(first_htlc.msgs.len(), 1);

	nodes[1].node.handle_update_add_htlc(node_a_id, &first_htlc.msgs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &first_htlc.commitment_msg);
	check_added_monitors(&nodes[1], 1);

	let (bs_first_raa, bs_first_cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_first_raa);
	check_added_monitors(&nodes[0], 1);

	let second_htlc_updates = SendEvent::from_node(&nodes[0]);
	assert_eq!(second_htlc_updates.msgs.len(), 1);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_first_cs);
	check_added_monitors(&nodes[0], 1);

	let as_first_raa = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_first_raa);
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.handle_update_add_htlc(node_a_id, &second_htlc_updates.msgs[0]);
	let commitment = &second_htlc_updates.commitment_msg;
	do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);

	expect_and_process_pending_htlcs(&nodes[1], false);
	let next_hop_failure =
		HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 };
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		core::slice::from_ref(&next_hop_failure)
	);
	check_added_monitors(&nodes[1], 2);

	{
		let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 2);
		let mut handle_update_htlcs = |event: MessageSendEvent| {
			if let MessageSendEvent::UpdateHTLCs { node_id, channel_id: _, updates } = event {
				let commitment = &updates.commitment_signed;
				if node_id == node_a_id {
					assert_eq!(updates.update_fail_htlcs.len(), 1);
					nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
					do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
				} else if node_id == node_c_id {
					assert_eq!(updates.update_add_htlcs.len(), 1);
					nodes[2].node.handle_update_add_htlc(node_b_id, &updates.update_add_htlcs[0]);
					do_commitment_signed_dance(&nodes[2], &nodes[1], commitment, false, false);
				} else {
					panic!("Unexpected node_id for UpdateHTLCs send");
				}
			} else {
				panic!("Unexpected event");
			}
		};
		handle_update_htlcs(msg_events.remove(0));
		handle_update_htlcs(msg_events.remove(0));
	}

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentPathFailed {
			payment_hash: ev_payment_hash,
			payment_failed_permanently,
			..
		} => {
			assert_eq!(payment_hash, ev_payment_hash);
			assert_eq!(payment_failed_permanently, false);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.process_pending_htlc_forwards();
	let retry_htlc_updates = SendEvent::from_node(&nodes[0]);
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.handle_update_add_htlc(node_a_id, &retry_htlc_updates.msgs[0]);
	let commitment = &retry_htlc_updates.commitment_msg;
	do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, true);

	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);

	let bs_second_forward = get_htlc_update_msgs(&nodes[1], &node_c_id);
	nodes[2].node.handle_update_add_htlc(node_b_id, &bs_second_forward.update_add_htlcs[0]);
	let commitment = &bs_second_forward.commitment_signed;
	do_commitment_signed_dance(&nodes[2], &nodes[1], commitment, false, false);

	expect_and_process_pending_htlcs(&nodes[2], false);
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

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	// There is one mitigating guardrail when retrying payments - we can never over-pay by more
	// than 10% of the original value. Thus, we want all our retries to be below that. In order to
	// keep things simple, we route one HTLC for 0.1% of the payment over channel 1 and the rest
	// out over channel 3+4. This will let us ignore 99% of the payment value and deal with only
	// our channel.
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 0);
	let chan_1_scid = chan_1.0.contents.short_channel_id;
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 10_000_000, 0);
	let chan_3 = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 10_000_000, 0);
	let chan_3_scid = chan_3.0.contents.short_channel_id;
	let chan_4 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 10_000_000, 0);
	let chan_4_scid = chan_4.0.contents.short_channel_id;

	let amt_msat = 100_000_000;
	let (_, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[2], amt_msat);
	#[cfg(feature = "std")]
	let payment_expiry_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() + 60 * 60;
	#[cfg(not(feature = "std"))]
	let payment_expiry_secs = 60 * 60;
	let mut invoice_features = Bolt11InvoiceFeatures::empty();
	invoice_features.set_variable_length_onion_required();
	invoice_features.set_payment_secret_required();
	invoice_features.set_basic_mpp_optional();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_expiry_time(payment_expiry_secs as u64)
		.with_bolt11_features(invoice_features)
		.unwrap();
	let mut route_params = RouteParameters {
		payment_params,
		final_value_msat: amt_msat,
		max_total_routing_fee_msat: Some(500_000),
	};

	let mut route = Route {
		paths: vec![
			Path {
				hops: vec![
					RouteHop {
						pubkey: node_b_id,
						node_features: nodes[1].node.node_features(),
						short_channel_id: chan_1_scid,
						channel_features: nodes[1].node.channel_features(),
						fee_msat: 0,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: node_d_id,
						node_features: nodes[2].node.node_features(),
						short_channel_id: 42, // Set a random SCID which nodes[1] will fail as unknown
						channel_features: nodes[2].node.channel_features(),
						fee_msat: amt_msat / 1000,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			},
			Path {
				hops: vec![
					RouteHop {
						pubkey: node_c_id,
						node_features: nodes[2].node.node_features(),
						short_channel_id: chan_3_scid,
						channel_features: nodes[2].node.channel_features(),
						fee_msat: 100_000,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
					RouteHop {
						pubkey: node_d_id,
						node_features: nodes[3].node.node_features(),
						short_channel_id: chan_4_scid,
						channel_features: nodes[3].node.channel_features(),
						fee_msat: amt_msat - amt_msat / 1000,
						cltv_expiry_delta: 100,
						maybe_announced_channel: true,
					},
				],
				blinded_tail: None,
			},
		],
		route_params: Some(route_params.clone()),
	};
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	let retry = Retry::Attempts(0xdeadbeef);
	nodes[0].node.send_payment(payment_hash, onion, id, route_params.clone(), retry).unwrap();
	check_added_monitors(&nodes[0], 2);
	let mut send_msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(send_msg_events.len(), 2);
	send_msg_events.retain(|msg| {
		if let MessageSendEvent::UpdateHTLCs { node_id, channel_id: _, .. } = msg {
			// Drop the commitment update for nodes[2], we can just let that one sit pending
			// forever.
			*node_id == node_b_id
		} else {
			panic!();
		}
	});

	// from here on out, the retry `RouteParameters` amount will be amt/1000
	route_params.final_value_msat /= 1000;
	route.route_params = Some(route_params.clone());
	route.paths.pop();

	let end_time = Instant::now() + Duration::from_secs(1);
	macro_rules! thread_body { () => { {
		// We really want std::thread::scope, but its not stable until 1.63. Until then, we get unsafe.
		let node_ref = NodePtr::from_node(&nodes[0]);
		move || {
			let _ = &node_ref;
			let node_a = unsafe { &*node_ref.0 };
			while Instant::now() < end_time {
				node_a.node.get_and_clear_pending_events();
				node_a.node.process_pending_htlc_forwards();
				node_a.node.process_pending_htlc_forwards();
			}
		}
	} } }
	let mut threads = Vec::new();
	for _ in 0..16 {
		threads.push(std::thread::spawn(thread_body!()));
	}

	// Back in the main thread, poll pending messages and make sure that we never have more than
	// one HTLC pending at a time. Note that the commitment_signed_dance will fail horribly if
	// there are HTLC messages shoved in while its running. This allows us to test that we never
	// generate an additional update_add_htlc until we've fully failed the first.
	let mut previously_failed_channels = Vec::new();
	loop {
		assert_eq!(send_msg_events.len(), 1);
		let send_event = SendEvent::from_event(send_msg_events.pop().unwrap());
		assert_eq!(send_event.msgs.len(), 1);

		nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
		do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, true);
		expect_and_process_pending_htlcs(&nodes[1], false);
		nodes[1].node.process_pending_htlc_forwards();
		expect_htlc_handling_failed_destinations!(
			nodes[1].node.get_and_clear_pending_events(),
			&[HTLCHandlingFailureType::InvalidForward {
				requested_forward_scid: route.paths[0].hops[1].short_channel_id
			}]
		);
		check_added_monitors(&nodes[1], 1);

		// Note that we only push one route into `expect_find_route` at a time, because that's all
		// the retries (should) need. If the bug is reintroduced "real" routes may be selected, but
		// we should still ultimately fail for the same reason - because we're trying to send too
		// many HTLCs at once.
		let mut new_route_params = route_params.clone();
		previously_failed_channels.push(route.paths[0].hops[1].short_channel_id);
		new_route_params.payment_params.previously_failed_channels =
			previously_failed_channels.clone();
		new_route_params.max_total_routing_fee_msat.as_mut().map(|m| *m -= 100_000);
		route.paths[0].hops[1].short_channel_id += 1;
		route.route_params = Some(new_route_params.clone());
		nodes[0].router.expect_find_route(new_route_params, Ok(route.clone()));

		let bs_fail_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
		nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_fail_updates.update_fail_htlcs[0]);
		// The "normal" commitment_signed_dance delivers the final RAA and then calls
		// `check_added_monitors` to ensure only the one RAA-generated monitor update was created.
		// This races with our other threads which may generate an add-HTLCs commitment update via
		// `process_pending_htlc_forwards`. Instead, we defer the monitor update check until after
		// *we've* called `process_pending_htlc_forwards` when its guaranteed to have two updates.
		let cs = bs_fail_updates.commitment_signed;
		let last_raa = commitment_signed_dance_return_raa(&nodes[0], &nodes[1], &cs, false);
		nodes[0].node.handle_revoke_and_ack(node_b_id, &last_raa);

		let cur_time = Instant::now();
		if cur_time > end_time {
			for thread in threads.drain(..) {
				thread.join().unwrap();
			}
		}

		// We give the node some time before we process messages and check the added monitors.
		std::thread::sleep(Duration::from_secs(1));

		// Make sure we have some events to handle when we go around...
		nodes[0].node.get_and_clear_pending_events();
		nodes[0].node.process_pending_htlc_forwards();
		nodes[0].node.process_pending_htlc_forwards();
		send_msg_events = nodes[0].node.get_and_clear_pending_msg_events();

		check_added_monitors(&nodes[0], 2);

		if cur_time > end_time {
			break;
		}
	}
}

fn do_no_missing_sent_on_reload(persist_manager_with_payment: bool, at_midpoint: bool) {
	// Test that if we reload in the middle of an HTLC claim commitment signed dance we'll still
	// receive the PaymentSent event even if the ChannelManager had no idea about the payment when
	// it was last persisted.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persist_a, persist_b, persist_c);
	let (chain_monitor_a, chain_monitor_b, chain_monitor_c);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let (node_a_1, node_a_2, node_a_3);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let mut node_a_ser = Vec::new();
	if !persist_manager_with_payment {
		node_a_ser = nodes[0].node.encode();
	}

	let (our_payment_preimage, our_payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	if persist_manager_with_payment {
		node_a_ser = nodes[0].node.encode();
	}

	nodes[1].node.claim_funds(our_payment_preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], our_payment_hash, 1_000_000);

	if at_midpoint {
		let mut updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
		nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates.update_fulfill_htlcs.remove(0));
		nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &updates.commitment_signed);
		check_added_monitors(&nodes[0], 1);
	} else {
		let mut fulfill = get_htlc_update_msgs(&nodes[1], &node_a_id);
		nodes[0].node.handle_update_fulfill_htlc(node_b_id, fulfill.update_fulfill_htlcs.remove(0));
		do_commitment_signed_dance(&nodes[0], &nodes[1], &fulfill.commitment_signed, false, false);
		// Ignore the PaymentSent event which is now pending on nodes[0] - if we were to handle it we'd
		// be expected to ignore the eventual conflicting PaymentFailed, but by not looking at it we
		// expect to get the PaymentSent again later.
		check_added_monitors(&nodes[0], 0);
	}

	// The ChannelMonitor should always be the latest version, as we're required to persist it
	// during the commitment signed handling.
	let mon_ser = get_monitor!(nodes[0], chan_id).encode();
	let config = test_default_channel_config();
	reload_node!(nodes[0], config, &node_a_ser, &[&mon_ser], persist_a, chain_monitor_a, node_a_1);

	// When we first process background events, we'll apply a channel-closed monitor update...
	check_added_monitors(&nodes[0], 0);
	nodes[0].node.test_process_background_events();
	check_added_monitors(&nodes[0], 1);
	// Then once we process the PaymentSent event we'll apply a monitor update to remove the
	// pending payment from being re-hydrated on the next startup.
	let events = nodes[0].node.get_and_clear_pending_events();
	check_added_monitors(&nodes[0], 1);
	assert_eq!(events.len(), 3, "{events:?}");
	if let Event::ChannelClosed { reason: ClosureReason::OutdatedChannelManager, .. } = events[0] {
	} else {
		panic!();
	}
	if let Event::PaymentSent { payment_preimage, .. } = events[1] {
		assert_eq!(payment_preimage, our_payment_preimage);
	} else {
		panic!();
	}
	if let Event::PaymentPathSuccessful { .. } = events[2] {
	} else {
		panic!();
	}
	// Note that we don't get a PaymentPathSuccessful here as we leave the HTLC pending to avoid
	// the double-claim that would otherwise appear at the end of this test.
	nodes[0].node.timer_tick_occurred();
	let as_broadcasted_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_broadcasted_txn.len(), 1);

	// Ensure that, even after some time, if we restart we still include *something* in the current
	// `ChannelManager` which prevents a `PaymentFailed` when we restart even if pending resolved
	// payments have since been timed out thanks to `IDEMPOTENCY_TIMEOUT_TICKS`.
	// A naive implementation of the fix here would wipe the pending payments set, causing a
	// failure event when we restart.
	for _ in 0..(IDEMPOTENCY_TIMEOUT_TICKS * 2) {
		nodes[0].node.timer_tick_occurred();
	}

	let mon_ser = get_monitor!(nodes[0], chan_id).encode();
	let node_ser = nodes[0].node.encode();
	let config = test_default_channel_config();
	reload_node!(nodes[0], config, &node_ser, &[&mon_ser], persist_b, chain_monitor_b, node_a_2);

	nodes[0].node.test_process_background_events();
	let events = nodes[0].node.get_and_clear_pending_events();
	assert!(events.is_empty());

	// Ensure that we don't generate any further events even after the channel-closing commitment
	// transaction is confirmed on-chain.
	confirm_transaction(&nodes[0], &as_broadcasted_txn[0]);
	for _ in 0..(IDEMPOTENCY_TIMEOUT_TICKS * 2) {
		nodes[0].node.timer_tick_occurred();
	}

	let events = nodes[0].node.get_and_clear_pending_events();
	assert!(events.is_empty());
	check_added_monitors(&nodes[0], 0);

	let mon_ser = get_monitor!(nodes[0], chan_id).encode();
	let config = test_default_channel_config();
	let node_ser = nodes[0].node.encode();
	reload_node!(nodes[0], config, &node_ser, &[&mon_ser], persist_c, chain_monitor_c, node_a_3);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert!(events.is_empty());
}

#[test]
fn no_missing_sent_on_midpoint_reload() {
	do_no_missing_sent_on_reload(false, true);
	do_no_missing_sent_on_reload(true, true);
}

#[test]
fn no_missing_sent_on_reload() {
	do_no_missing_sent_on_reload(false, false);
	do_no_missing_sent_on_reload(true, false);
}

fn do_claim_from_closed_chan(fail_payment: bool) {
	// Previously, LDK would refuse to claim a payment if a channel on which the payment was
	// received had been closed between when the HTLC was received and when we went to claim it.
	// This makes sense in the payment case - why pay an on-chain fee to claim the HTLC when
	// presumably the sender may retry later. Long ago it also reduced total code in the claim
	// pipeline.
	//
	// However, this doesn't make sense if you're trying to do an atomic swap or some other
	// protocol that requires atomicity with some other action - if your money got claimed
	// elsewhere you need to be able to claim the HTLC in lightning no matter what. Further, this
	// is an over-optimization - there should be a very, very low likelihood that a channel closes
	// between when we receive the last HTLC for a payment and the user goes to claim the payment.
	// Since we now have code to handle this anyway we should allow it.

	// Build 4 nodes and send an MPP payment across two paths. By building a route manually set the
	// CLTVs on the paths to different value resulting in a different claim deadline.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0);
	let chan_bd = create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 1_000_000, 0).2;
	create_announced_chan_between_nodes(&nodes, 2, 3);

	let (payment_preimage, hash, payment_secret) = get_payment_preimage_hash!(nodes[3]);
	let payment_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();

	let amt_msat = 10_000_000;
	let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	let inflight = nodes[0].node.compute_inflight_htlcs();
	let mut route = nodes[0].router.find_route(&node_a_id, &route_params, None, inflight).unwrap();

	// Make sure the route is ordered as the B->D path before C->D
	route.paths.sort_by(|a, _| {
		if a.hops[0].pubkey == node_b_id {
			Ordering::Less
		} else {
			Ordering::Greater
		}
	});

	// Note that we add an extra 1 in the send pipeline to compensate for any blocks found while
	// the HTLC is being relayed.
	route.paths[0].hops[1].cltv_expiry_delta = TEST_FINAL_CLTV + 8;
	route.paths[1].hops[1].cltv_expiry_delta = TEST_FINAL_CLTV + 12;
	let final_cltv = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 8 + 1;

	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(hash.0);
	nodes[0].node.send_payment(hash, onion, id, route_params, Retry::Attempts(1)).unwrap();

	check_added_monitors(&nodes[0], 2);
	let mut send_msgs = nodes[0].node.get_and_clear_pending_msg_events();
	send_msgs.sort_by(|a, _| {
		let a_node_id =
			if let MessageSendEvent::UpdateHTLCs { node_id, .. } = a { node_id } else { panic!() };
		if *a_node_id == node_b_id {
			Ordering::Less
		} else {
			Ordering::Greater
		}
	});

	assert_eq!(send_msgs.len(), 2);
	let (msg_a, msg_b) = (send_msgs.remove(0), send_msgs.remove(0));
	let (path_a, path_b) = (&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]);

	pass_along_path(&nodes[0], path_a, amt_msat, hash, Some(payment_secret), msg_a, false, None);
	let receive_event =
		pass_along_path(&nodes[0], path_b, amt_msat, hash, Some(payment_secret), msg_b, true, None);

	match receive_event.unwrap() {
		Event::PaymentClaimable { claim_deadline, .. } => {
			assert_eq!(claim_deadline.unwrap(), final_cltv - HTLC_FAIL_BACK_BUFFER);
		},
		_ => panic!(),
	}

	// Ensure that the claim_deadline is correct, with the payment failing at exactly the given
	// height.
	let blocks = final_cltv
		- HTLC_FAIL_BACK_BUFFER
		- nodes[3].best_block_info().1
		- if fail_payment { 0 } else { 2 };
	connect_blocks(&nodes[3], blocks);
	if fail_payment {
		// We fail the HTLC on the A->B->D path first as it expires 4 blocks earlier. We go ahead
		// and expire both immediately, though, by connecting another 4 blocks.
		let reason = HTLCHandlingFailureType::Receive { payment_hash: hash };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[3],
			core::slice::from_ref(&reason),
		);
		connect_blocks(&nodes[3], 4);
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[3], &[reason]);

		let reason = PaymentFailureReason::RecipientRejected;
		pass_failed_payment_back(&nodes[0], &[path_a, path_b], false, hash, reason);
	} else {
		let message = "Channel force-closed".to_owned();
		nodes[1]
			.node
			.force_close_broadcasting_latest_txn(&chan_bd, &node_d_id, message.clone())
			.unwrap();
		let reason =
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
		check_closed_event(&nodes[1], 1, reason, &[node_d_id], 1000000);
		check_closed_broadcast(&nodes[1], 1, true);
		let bs_tx = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(bs_tx.len(), 1);

		mine_transaction(&nodes[3], &bs_tx[0]);
		check_closed_broadcast(&nodes[3], 1, true);
		check_added_monitors(&nodes[3], 1);
		let reason = ClosureReason::CommitmentTxConfirmed;
		check_closed_event(&nodes[3], 1, reason, &[node_b_id], 1000000);

		nodes[3].node.claim_funds(payment_preimage);
		check_added_monitors(&nodes[3], 2);
		expect_payment_claimed!(nodes[3], hash, 10_000_000);

		let ds_tx = nodes[3].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(ds_tx.len(), 1);
		check_spends!(&ds_tx[0], &bs_tx[0]);

		mine_transactions(&nodes[1], &[&bs_tx[0], &ds_tx[0]]);
		check_added_monitors(&nodes[1], 1);
		expect_payment_forwarded!(nodes[1], nodes[0], nodes[3], Some(1000), false, true);

		let mut bs_claims = nodes[1].node.get_and_clear_pending_msg_events();
		check_added_monitors(&nodes[1], 1);
		assert_eq!(bs_claims.len(), 1);
		if let MessageSendEvent::UpdateHTLCs { mut updates, .. } = bs_claims.remove(0) {
			let fulfill = updates.update_fulfill_htlcs.remove(0);
			nodes[0].node.handle_update_fulfill_htlc(node_b_id, fulfill);
			let commitment = &updates.commitment_signed;
			do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, true);
		} else {
			panic!();
		}

		expect_payment_sent!(nodes[0], payment_preimage);

		let mut ds_claim_msgs = nodes[3].node.get_and_clear_pending_msg_events();
		assert_eq!(ds_claim_msgs.len(), 1);
		let mut cs_claim_msgs =
			if let MessageSendEvent::UpdateHTLCs { mut updates, .. } = ds_claim_msgs.remove(0) {
				let fulfill = updates.update_fulfill_htlcs.remove(0);
				nodes[2].node.handle_update_fulfill_htlc(node_d_id, fulfill);
				let cs_claim_msgs = nodes[2].node.get_and_clear_pending_msg_events();
				check_added_monitors(&nodes[2], 1);
				let commitment = &updates.commitment_signed;
				do_commitment_signed_dance(&nodes[2], &nodes[3], commitment, false, true);
				expect_payment_forwarded!(nodes[2], nodes[0], nodes[3], Some(1000), false, false);
				cs_claim_msgs
			} else {
				panic!();
			};

		assert_eq!(cs_claim_msgs.len(), 1);
		if let MessageSendEvent::UpdateHTLCs { mut updates, .. } = cs_claim_msgs.remove(0) {
			let fulfill = updates.update_fulfill_htlcs.remove(0);
			nodes[0].node.handle_update_fulfill_htlc(node_c_id, fulfill);
			let commitment = &updates.commitment_signed;
			do_commitment_signed_dance(&nodes[0], &nodes[2], commitment, false, true);
		} else {
			panic!();
		}

		expect_payment_path_successful!(nodes[0]);
	}
}

#[test]
fn claim_from_closed_chan() {
	do_claim_from_closed_chan(true);
	do_claim_from_closed_chan(false);
}

#[test]
fn test_custom_tlvs_basic() {
	do_test_custom_tlvs(false, false, false);
	do_test_custom_tlvs(true, false, false);
}

#[test]
fn test_custom_tlvs_explicit_claim() {
	// Test that when receiving even custom TLVs the user must explicitly accept in case they
	// are unknown.
	do_test_custom_tlvs(false, true, false);
	do_test_custom_tlvs(false, true, true);
}

fn do_test_custom_tlvs(spontaneous: bool, even_tlvs: bool, known_tlvs: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let amt_msat = 100_000;
	let (mut route, hash, preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], &nodes[1], amt_msat);
	let id = PaymentId(hash.0);
	let custom_tlvs = vec![
		(if even_tlvs { 5482373482 } else { 5482373483 }, vec![1, 2, 3, 4]),
		(5482373487, vec![0x42u8; 16]),
	];
	let onion = RecipientOnionFields {
		payment_secret: if spontaneous { None } else { Some(payment_secret) },
		payment_metadata: None,
		custom_tlvs: custom_tlvs.clone(),
	};
	if spontaneous {
		let params = route.route_params.unwrap();
		let retry = Retry::Attempts(0);
		nodes[0].node.send_spontaneous_payment(Some(preimage), onion, id, params, retry).unwrap();
	} else {
		nodes[0].node.send_payment_with_route(route, hash, onion, id).unwrap();
	}
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	let ev = remove_first_msg_event_to_node(&node_b_id, &mut events);
	let mut payment_event = SendEvent::from_event(ev);

	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable { ref onion_fields, .. } => {
			assert_eq!(onion_fields.clone().unwrap().custom_tlvs().clone(), custom_tlvs);
		},
		_ => panic!("Unexpected event"),
	}

	match (known_tlvs, even_tlvs) {
		(true, _) => {
			nodes[1].node.claim_funds_with_known_custom_tlvs(preimage);
			let expected_total_fee_msat = pass_claimed_payment_along_route(
				ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1]]], preimage)
					.with_custom_tlvs(custom_tlvs),
			);
			expect_payment_sent!(&nodes[0], preimage, Some(expected_total_fee_msat));
		},
		(false, false) => {
			claim_payment_along_route(
				ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1]]], preimage)
					.with_custom_tlvs(custom_tlvs),
			);
		},
		(false, true) => {
			nodes[1].node.claim_funds(preimage);
			let fail_type = HTLCHandlingFailureType::Receive { payment_hash: hash };
			expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);
			let reason = PaymentFailureReason::RecipientRejected;
			pass_failed_payment_back(&nodes[0], &[&[&nodes[1]]], false, hash, reason);
		},
	}
}

#[test]
fn test_retry_custom_tlvs() {
	// Test that custom TLVs are successfully sent on retries
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let (chan_2_update, _, chan_2_id, _) = create_announced_chan_between_nodes(&nodes, 2, 1);

	// Rebalance
	send_payment(&nodes[2], &[&nodes[1]], 1_500_000);

	let amt_msat = 1_000_000;
	let (mut route, hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], amt_msat);

	// Initiate the payment
	let id = PaymentId(hash.0);
	let mut route_params = route.route_params.clone().unwrap();

	let custom_tlvs = vec![((1 << 16) + 1, vec![0x42u8; 16])];
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let onion = onion.with_custom_tlvs(custom_tlvs.clone()).unwrap();

	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	nodes[0].node.send_payment(hash, onion, id, route_params.clone(), Retry::Attempts(1)).unwrap();
	check_added_monitors(&nodes[0], 1); // one monitor per path

	// Add the HTLC along the first hop.
	let htlc_updates = get_htlc_update_msgs(&nodes[0], &node_b_id);
	let msgs::CommitmentUpdate { update_add_htlcs, commitment_signed, .. } = htlc_updates;
	assert_eq!(update_add_htlcs.len(), 1);
	nodes[1].node.handle_update_add_htlc(node_a_id, &update_add_htlcs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &commitment_signed, false, false);

	// Attempt to forward the payment and complete the path's failure.
	expect_and_process_pending_htlcs(&nodes[1], true);
	let events = nodes[1].node.get_and_clear_pending_events();
	let fail = HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2_id };
	expect_htlc_failure_conditions(events, &[fail]);
	check_added_monitors(&nodes[1], 1);

	let htlc_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	let msgs::CommitmentUpdate { update_fail_htlcs, commitment_signed, .. } = htlc_updates;
	assert_eq!(update_fail_htlcs.len(), 1);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &commitment_signed, false, false);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	let conditions = PaymentFailedConditions::new().mpp_parts_remain();
	expect_payment_failed_conditions_event(events, hash, false, conditions);

	// Rebalance the channel so the retry of the payment can succeed.
	send_payment(&nodes[2], &[&nodes[1]], 1_500_000);

	// Retry the payment and make sure it succeeds
	let chan_2_scid = chan_2_update.contents.short_channel_id;
	route_params.payment_params.previously_failed_channels.push(chan_2_scid);
	route.route_params = Some(route_params.clone());
	nodes[0].router.expect_find_route(route_params, Ok(route));
	nodes[0].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1], &nodes[2]];
	let args = PassAlongPathArgs::new(&nodes[0], path, 1_000_000, hash, events.pop().unwrap())
		.with_payment_secret(payment_secret)
		.with_custom_tlvs(custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2]]], payment_preimage)
			.with_custom_tlvs(custom_tlvs),
	);
}

#[test]
fn test_custom_tlvs_consistency() {
	let even_type_1 = 1 << 16;
	let odd_type_1 = (1 << 16) + 1;
	let even_type_2 = (1 << 16) + 2;
	let odd_type_2 = (1 << 16) + 3;
	let value_1 = || vec![1, 2, 3, 4];
	let differing_value_1 = || vec![1, 2, 3, 5];
	let value_2 = || vec![42u8; 16];

	// Drop missing odd tlvs
	do_test_custom_tlvs_consistency(
		vec![(odd_type_1, value_1()), (odd_type_2, value_2())],
		vec![(odd_type_1, value_1())],
		Some(vec![(odd_type_1, value_1())]),
	);
	// Drop non-matching odd tlvs
	do_test_custom_tlvs_consistency(
		vec![(odd_type_1, value_1()), (odd_type_2, value_2())],
		vec![(odd_type_1, differing_value_1()), (odd_type_2, value_2())],
		Some(vec![(odd_type_2, value_2())]),
	);
	// Fail missing even tlvs
	do_test_custom_tlvs_consistency(
		vec![(odd_type_1, value_1()), (even_type_2, value_2())],
		vec![(odd_type_1, value_1())],
		None,
	);
	// Fail non-matching even tlvs
	do_test_custom_tlvs_consistency(
		vec![(even_type_1, value_1()), (odd_type_2, value_2())],
		vec![(even_type_1, differing_value_1()), (odd_type_2, value_2())],
		None,
	);
}

fn do_test_custom_tlvs_consistency(
	first_tlvs: Vec<(u64, Vec<u8>)>, second_tlvs: Vec<(u64, Vec<u8>)>,
	expected_receive_tlvs: Option<Vec<(u64, Vec<u8>)>>,
) {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 100_000, 0);
	let chan_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 100_000, 0);

	let payment_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[3].node.bolt11_invoice_features())
		.unwrap();
	let mut route = get_route!(nodes[0], payment_params, 15_000_000).unwrap();
	assert_eq!(route.paths.len(), 2);
	route.paths.sort_by(|path_a, _| {
		// Sort the path so that the path through nodes[1] comes first
		if path_a.hops[0].pubkey == node_b_id {
			Ordering::Less
		} else {
			Ordering::Greater
		}
	});

	let (preimage, hash, payment_secret) = get_payment_preimage_hash!(&nodes[3]);
	let id = PaymentId([42; 32]);
	let amt_msat = 15_000_000;

	// Send first part
	let onion = RecipientOnionFields {
		payment_secret: Some(payment_secret),
		payment_metadata: None,
		custom_tlvs: first_tlvs,
	};
	let session_privs =
		nodes[0].node.test_add_new_pending_payment(hash, onion.clone(), id, &route).unwrap();
	let cur_height = nodes[0].best_block_info().1;
	let path_a = &route.paths[0];
	let priv_a = session_privs[0];
	nodes[0]
		.node
		.test_send_payment_along_path(path_a, &hash, onion, amt_msat, cur_height, id, &None, priv_a)
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = events.pop().unwrap();
	let path_a = &[&nodes[1], &nodes[3]];
	pass_along_path(&nodes[0], path_a, amt_msat, hash, Some(payment_secret), event, false, None);

	assert!(nodes[3].node.get_and_clear_pending_events().is_empty());

	// Send second part
	let onion = RecipientOnionFields {
		payment_secret: Some(payment_secret),
		payment_metadata: None,
		custom_tlvs: second_tlvs,
	};
	let path_b = &route.paths[1];
	let priv_b = session_privs[1];
	nodes[0]
		.node
		.test_send_payment_along_path(path_b, &hash, onion, amt_msat, cur_height, id, &None, priv_b)
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	{
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.pop().unwrap());

		nodes[2].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
		let commitment = &payment_event.commitment_msg;
		do_commitment_signed_dance(&nodes[2], &nodes[0], commitment, false, false);

		expect_and_process_pending_htlcs(&nodes[2], false);
		check_added_monitors(&nodes[2], 1);

		let mut events = nodes[2].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.pop().unwrap());

		nodes[3].node.handle_update_add_htlc(node_c_id, &payment_event.msgs[0]);
		check_added_monitors(&nodes[3], 0);
		do_commitment_signed_dance(&nodes[3], &nodes[2], &payment_event.commitment_msg, true, true);
	}
	expect_htlc_failure_conditions(nodes[3].node.get_and_clear_pending_events(), &[]);
	nodes[3].node.process_pending_htlc_forwards();

	if let Some(expected_tlvs) = expected_receive_tlvs {
		// Claim and match expected
		let events = nodes[3].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentClaimable { ref onion_fields, .. } => {
				assert_eq!(onion_fields.clone().unwrap().custom_tlvs, expected_tlvs);
			},
			_ => panic!("Unexpected event"),
		}

		do_claim_payment_along_route(
			ClaimAlongRouteArgs::new(&nodes[0], &[path_a, &[&nodes[2], &nodes[3]]], preimage)
				.with_custom_tlvs(expected_tlvs),
		);
		expect_payment_sent(&nodes[0], preimage, Some(Some(2000)), true, true);
	} else {
		// Expect fail back
		let expected_destinations = [HTLCHandlingFailureType::Receive { payment_hash: hash }];
		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[3],
			&expected_destinations,
		);
		check_added_monitors(&nodes[3], 1);

		let fail_updates_1 = get_htlc_update_msgs(&nodes[3], &node_c_id);
		nodes[2].node.handle_update_fail_htlc(node_d_id, &fail_updates_1.update_fail_htlcs[0]);
		let commitment = &fail_updates_1.commitment_signed;
		do_commitment_signed_dance(&nodes[2], &nodes[3], commitment, false, false);

		let fail =
			HTLCHandlingFailureType::Forward { node_id: Some(node_d_id), channel_id: chan_2_3.2 };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[2], &[fail]);
		check_added_monitors(&nodes[2], 1);

		let fail_updates_2 = get_htlc_update_msgs(&nodes[2], &node_a_id);
		nodes[0].node.handle_update_fail_htlc(node_c_id, &fail_updates_2.update_fail_htlcs[0]);
		let commitment = &fail_updates_2.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[2], commitment, false, false);

		let conditions = PaymentFailedConditions::new().mpp_parts_remain();
		expect_payment_failed_conditions(&nodes[0], hash, true, conditions);
	}
}

fn do_test_payment_metadata_consistency(do_reload: bool, do_modify: bool) {
	// Check that a payment metadata received on one HTLC that doesn't match the one received on
	// another results in the HTLC being rejected.
	//
	// We first set up a diamond shaped network, allowing us to split a payment into two HTLCs, the
	// first of which we'll deliver and the second of which we'll fail and then re-send with
	// modified payment metadata, which will in turn result in it being failed by the recipient.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let persister;
	let chain_mon;

	let mut config = test_default_channel_config();
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 50;
	let configs = [None, Some(config.clone()), Some(config.clone()), Some(config.clone())];
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &configs);
	let node_d_reload;

	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_id_bd = create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 1_000_000, 0).2;
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0);
	let chan_id_cd = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).2;

	// Pay more than half of each channel's max, requiring MPP
	let amt_msat = 750_000_000;
	let (payment_preimage, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[3], Some(amt_msat));
	let payment_id = PaymentId(payment_hash.0);
	let payment_metadata = vec![44, 49, 52, 142];

	let payment_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let mut route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);

	// Send the MPP payment, delivering the updated commitment state to nodes[1].
	let onion = RecipientOnionFields {
		payment_secret: Some(payment_secret),
		payment_metadata: Some(payment_metadata),
		custom_tlvs: vec![],
	};
	let retry = Retry::Attempts(1);
	nodes[0].node.send_payment(payment_hash, onion, payment_id, route_params, retry).unwrap();
	check_added_monitors(&nodes[0], 2);

	let mut send_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(send_events.len(), 2);
	let first_send = SendEvent::from_event(send_events.pop().unwrap());
	let second_send = SendEvent::from_event(send_events.pop().unwrap());

	let (b_recv_ev, c_recv_ev) = if first_send.node_id == node_b_id {
		(&first_send, &second_send)
	} else {
		(&second_send, &first_send)
	};
	nodes[1].node.handle_update_add_htlc(node_a_id, &b_recv_ev.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &b_recv_ev.commitment_msg, false, true);

	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);
	let b_forward_ev = SendEvent::from_node(&nodes[1]);
	nodes[3].node.handle_update_add_htlc(node_b_id, &b_forward_ev.msgs[0]);
	do_commitment_signed_dance(&nodes[3], &nodes[1], &b_forward_ev.commitment_msg, false, true);

	expect_and_process_pending_htlcs(&nodes[3], false);

	// Before delivering the second MPP HTLC to nodes[2], disconnect nodes[2] and nodes[3], which
	// will result in nodes[2] failing the HTLC back.
	nodes[2].node.peer_disconnected(node_d_id);
	nodes[3].node.peer_disconnected(node_c_id);

	nodes[2].node.handle_update_add_htlc(node_a_id, &c_recv_ev.msgs[0]);
	do_commitment_signed_dance(&nodes[2], &nodes[0], &c_recv_ev.commitment_msg, false, true);
	expect_and_process_pending_htlcs(&nodes[2], false);
	expect_htlc_handling_failed_destinations!(
		nodes[2].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_d_id), channel_id: chan_id_cd }]
	);
	check_added_monitors(&nodes[2], 1);

	let cs_fail = get_htlc_update_msgs(&nodes[2], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_c_id, &cs_fail.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[2], &cs_fail.commitment_signed, false, true);

	let payment_fail_retryable_evs = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(payment_fail_retryable_evs.len(), 1);
	if let Event::PaymentPathFailed { .. } = payment_fail_retryable_evs[0] {
	} else {
		panic!();
	}

	// Before we allow the HTLC to be retried, optionally change the payment_metadata we have
	// stored for our payment.
	if do_modify {
		nodes[0].node.test_set_payment_metadata(payment_id, Some(Vec::new()));
	}

	// Optionally reload nodes[3] to check that the payment_metadata is properly serialized with
	// the payment state.
	if do_reload {
		let mon_bd = get_monitor!(nodes[3], chan_id_bd).encode();
		let mon_cd = get_monitor!(nodes[3], chan_id_cd).encode();
		let mons = [&mon_bd[..], &mon_cd[..]];
		let node_d_ser = nodes[3].node.encode();
		reload_node!(nodes[3], config, &node_d_ser, &mons[..], persister, chain_mon, node_d_reload);
		nodes[1].node.peer_disconnected(node_d_id);
		reconnect_nodes(ReconnectArgs::new(&nodes[1], &nodes[3]));
	}
	let mut reconnect_args = ReconnectArgs::new(&nodes[2], &nodes[3]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	// Create a new channel between C and D as A will refuse to retry on the existing one because
	// it just failed.
	create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);

	// Now retry the failed HTLC.
	nodes[0].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[0], 1);
	let as_resend = SendEvent::from_node(&nodes[0]);
	nodes[2].node.handle_update_add_htlc(node_a_id, &as_resend.msgs[0]);
	do_commitment_signed_dance(&nodes[2], &nodes[0], &as_resend.commitment_msg, false, true);

	expect_and_process_pending_htlcs(&nodes[2], false);
	check_added_monitors(&nodes[2], 1);
	let cs_forward = SendEvent::from_node(&nodes[2]);
	let cd_chan_id = cs_forward.msgs[0].channel_id;
	nodes[3].node.handle_update_add_htlc(node_c_id, &cs_forward.msgs[0]);
	do_commitment_signed_dance(&nodes[3], &nodes[2], &cs_forward.commitment_msg, false, true);

	// Finally, check that nodes[3] does the correct thing - either accepting the payment or, if
	// the payment metadata was modified, failing only the one modified HTLC and retaining the
	// other.
	if do_modify {
		expect_htlc_failure_conditions(nodes[3].node.get_and_clear_pending_events(), &[]);
		nodes[3].node.process_pending_htlc_forwards();
		expect_htlc_failure_conditions(
			nodes[3].node.get_and_clear_pending_events(),
			&[HTLCHandlingFailureType::Receive { payment_hash }],
		);
		nodes[3].node.process_pending_htlc_forwards();

		check_added_monitors(&nodes[3], 1);
		let ds_fail = get_htlc_update_msgs(&nodes[3], &node_c_id);

		nodes[2].node.handle_update_fail_htlc(node_d_id, &ds_fail.update_fail_htlcs[0]);
		do_commitment_signed_dance(&nodes[2], &nodes[3], &ds_fail.commitment_signed, false, true);
		let events = nodes[2].node.get_and_clear_pending_events();
		let fail_type =
			HTLCHandlingFailureType::Forward { node_id: Some(node_d_id), channel_id: cd_chan_id };
		expect_htlc_failure_conditions(events, &[fail_type]);
	} else {
		expect_and_process_pending_htlcs(&nodes[3], false);
		expect_payment_claimable!(nodes[3], payment_hash, payment_secret, amt_msat);
		let route: &[&[_]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
		claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], route, payment_preimage));
	}
}

#[test]
fn test_payment_metadata_consistency() {
	do_test_payment_metadata_consistency(true, true);
	do_test_payment_metadata_consistency(true, false);
	do_test_payment_metadata_consistency(false, true);
	do_test_payment_metadata_consistency(false, false);
}

#[test]
fn test_htlc_forward_considers_anchor_outputs_value() {
	// Tests that:
	//
	// 1) Forwarding nodes don't forward HTLCs that would cause their balance to dip below the
	//    reserve when considering the value of anchor outputs.
	//
	// 2) Recipients of `update_add_htlc` properly reject HTLCs that would cause the initiator's
	//    balance to dip below the reserve when considering the value of anchor outputs.
	let mut config = test_default_channel_config();
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	config.manually_accept_inbound_channels = true;
	config.channel_config.forwarding_fee_base_msat = 0;
	config.channel_config.forwarding_fee_proportional_millionths = 0;

	// Set up a test network of three nodes that replicates a production failure leading to the
	// discovery of this bug.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let configs = [Some(config.clone()), Some(config.clone()), Some(config.clone())];
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &configs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	const CHAN_AMT: u64 = 1_000_000;
	const PUSH_MSAT: u64 = 900_000_000;
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, CHAN_AMT, 500_000_000);
	let (_, _, chan_id_2, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 2, CHAN_AMT, PUSH_MSAT);

	let channel_reserve_msat =
		get_holder_selected_channel_reserve_satoshis(CHAN_AMT, &config) * 1000;
	let commitment_fee_msat = chan_utils::commit_tx_fee_sat(
		*nodes[1].fee_estimator.sat_per_kw.lock().unwrap(),
		2,
		&ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(),
	) * 1000;
	let anchor_outpus_value_msat = ANCHOR_OUTPUT_VALUE_SATOSHI * 2 * 1000;
	let sendable_balance_msat = CHAN_AMT * 1000
		- PUSH_MSAT
		- channel_reserve_msat
		- commitment_fee_msat
		- anchor_outpus_value_msat;
	let channel_details = nodes[1]
		.node
		.list_channels()
		.into_iter()
		.find(|channel| channel.channel_id == chan_id_2)
		.unwrap();
	assert!(sendable_balance_msat >= channel_details.next_outbound_htlc_minimum_msat);
	assert!(sendable_balance_msat <= channel_details.next_outbound_htlc_limit_msat);

	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], sendable_balance_msat);
	send_payment(&nodes[2], &[&nodes[1], &nodes[0]], sendable_balance_msat);

	// Send out an HTLC that would cause the forwarding node to dip below its reserve when
	// considering the value of anchor outputs.
	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(
		nodes[0],
		nodes[2],
		sendable_balance_msat + anchor_outpus_value_msat
	);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut update_add_htlc =
		if let MessageSendEvent::UpdateHTLCs { updates, .. } = events.pop().unwrap() {
			nodes[1].node.handle_update_add_htlc(node_a_id, &updates.update_add_htlcs[0]);
			check_added_monitors(&nodes[1], 0);
			let commitment = &updates.commitment_signed;
			do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);
			updates.update_add_htlcs[0].clone()
		} else {
			panic!("Unexpected event");
		};

	// The forwarding node should reject forwarding it as expected.
	expect_and_process_pending_htlcs(&nodes[1], true);
	let events = nodes[1].node.get_and_clear_pending_events();
	let fail = HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_id_2 };
	expect_htlc_failure_conditions(events, &[fail]);
	check_added_monitors(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	if let MessageSendEvent::UpdateHTLCs { updates, .. } = events.pop().unwrap() {
		nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
		check_added_monitors(&nodes[0], 0);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	} else {
		panic!("Unexpected event");
	}

	expect_payment_failed!(nodes[0], payment_hash, false);

	// Assume that the forwarding node did forward it, and make sure the recipient rejects it as an
	// invalid update and closes the channel.
	update_add_htlc.channel_id = chan_id_2;
	nodes[2].node.handle_update_add_htlc(node_b_id, &update_add_htlc);

	let err = "Remote HTLC add would put them under remote reserve value".to_owned();
	let reason = ClosureReason::ProcessingError { err };
	check_closed_event(&nodes[2], 1, reason, &[node_b_id], 1_000_000);
	check_closed_broadcast(&nodes[2], 1, true);
	check_added_monitors(&nodes[2], 1);
}

#[test]
fn peel_payment_onion_custom_tlvs() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let secp_ctx = Secp256k1::new();

	let amt_msat = 1000;
	let payment_params = PaymentParameters::for_keysend(node_b_id, TEST_FINAL_CLTV, false);
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, amt_msat);
	let route = functional_test_utils::get_route(&nodes[0], &route_params).unwrap();
	let mut recipient_onion = RecipientOnionFields::spontaneous_empty()
		.with_custom_tlvs(vec![(414141, vec![42; 1200])])
		.unwrap();
	let prng_seed = chanmon_cfgs[0].keys_manager.get_secure_random_bytes();
	let session_priv = SecretKey::from_slice(&prng_seed[..]).expect("RNG is busted");
	let keysend_preimage = PaymentPreimage([42; 32]);
	let payment_hash = PaymentHash(Sha256::hash(&keysend_preimage.0).to_byte_array());

	let (onion_routing_packet, first_hop_msat, cltv_expiry) = onion_utils::create_payment_onion(
		&secp_ctx,
		&route.paths[0],
		&session_priv,
		amt_msat,
		&recipient_onion,
		nodes[0].best_block_info().1,
		&payment_hash,
		&Some(keysend_preimage),
		None,
		prng_seed,
	)
	.unwrap();

	let update_add = msgs::UpdateAddHTLC {
		channel_id: ChannelId([0; 32]),
		htlc_id: 42,
		amount_msat: first_hop_msat,
		payment_hash,
		cltv_expiry,
		skimmed_fee_msat: None,
		onion_routing_packet,
		blinding_point: None,
		hold_htlc: None,
		accountable: None,
	};
	let peeled_onion = crate::ln::onion_payment::peel_payment_onion(
		&update_add,
		&chanmon_cfgs[1].keys_manager,
		&chanmon_cfgs[1].logger,
		&secp_ctx,
		nodes[1].best_block_info().1,
		false,
	)
	.unwrap();
	assert_eq!(peeled_onion.incoming_amt_msat, Some(amt_msat));
	match peeled_onion.routing {
		PendingHTLCRouting::ReceiveKeysend {
			payment_data, payment_metadata, custom_tlvs, ..
		} => {
			#[cfg(not(c_bindings))]
			assert_eq!(&custom_tlvs, recipient_onion.custom_tlvs());
			#[cfg(c_bindings)]
			assert_eq!(custom_tlvs, recipient_onion.custom_tlvs());
			assert!(payment_metadata.is_none());
			assert!(payment_data.is_none());
		},
		_ => panic!(),
	}
}

#[test]
fn test_non_strict_forwarding() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut config = test_default_channel_config();
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let configs = [Some(config.clone()), Some(config.clone()), Some(config)];

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &configs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Create a routing node with two outbound channels, each of which can forward 2 payments of
	// the given value.
	let payment_value = 1_500_000;
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	let (chan_update_1, _, channel_id_1, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 4_950, 0);
	let (chan_update_2, _, channel_id_2, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 5_000, 0);

	// Create a route once.
	let payment_params = PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
		.unwrap();
	let route_params =
		RouteParameters::from_payment_params_and_value(payment_params, payment_value);
	let route = functional_test_utils::get_route(&nodes[0], &route_params).unwrap();

	// Send 4 payments over the same route.
	for i in 0..4 {
		let (payment_preimage, payment_hash, payment_secret) =
			get_payment_preimage_hash(&nodes[2], Some(payment_value), None);
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let id = PaymentId(payment_hash.0);
		nodes[0].node.send_payment_with_route(route.clone(), payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		let mut send_event = SendEvent::from_event(msg_events.remove(0));
		nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
		do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);

		expect_and_process_pending_htlcs(&nodes[1], false);
		check_added_monitors(&nodes[1], 1);
		msg_events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		send_event = SendEvent::from_event(msg_events.remove(0));
		// The HTLC will be forwarded over the most appropriate channel with the corresponding peer,
		// applying non-strict forwarding.
		// The channel with the least amount of outbound liquidity will be used to maximize the
		// probability of being able to successfully forward a subsequent HTLC.
		let exp_id = if i < 2 { channel_id_1 } else { channel_id_2 };
		assert_eq!(send_event.msgs[0].channel_id, exp_id);
		nodes[2].node.handle_update_add_htlc(node_b_id, &send_event.msgs[0]);
		do_commitment_signed_dance(&nodes[2], &nodes[1], &send_event.commitment_msg, false, false);

		expect_and_process_pending_htlcs(&nodes[2], false);
		let events = nodes[2].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		assert!(matches!(events[0], Event::PaymentClaimable { .. }));

		claim_payment_along_route(ClaimAlongRouteArgs::new(
			&nodes[0],
			&[&[&nodes[1], &nodes[2]]],
			payment_preimage,
		));
	}

	// Send a 5th payment which will fail.
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash(&nodes[2], Some(payment_value), None);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route.clone(), payment_hash, onion, id).unwrap();

	check_added_monitors(&nodes[0], 1);
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let mut send_event = SendEvent::from_event(msg_events.remove(0));
	nodes[1].node.handle_update_add_htlc(node_a_id, &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);

	expect_and_process_pending_htlcs(&nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let routed_scid = route.paths[0].hops[1].short_channel_id;
	let routed_chan_id = match routed_scid {
		scid if scid == chan_update_1.contents.short_channel_id => channel_id_1,
		scid if scid == chan_update_2.contents.short_channel_id => channel_id_2,
		_ => panic!("Unexpected short channel id in route"),
	};
	// The failure to forward will refer to the channel given in the onion.
	let events = nodes[1].node.get_and_clear_pending_events();
	let fail =
		HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: routed_chan_id };
	expect_htlc_failure_conditions(events, &[fail]);

	let updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	let events = nodes[0].node.get_and_clear_pending_events();
	let conditions = PaymentFailedConditions::new().blamed_scid(routed_scid);
	expect_payment_failed_conditions_event(events, payment_hash, false, conditions);
}

#[test]
fn remove_pending_outbounds_on_buggy_router() {
	// Ensure that if a payment errors due to a bogus route, we'll abandon the payment and remove the
	// pending outbound from storage.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let amt_msat = 10_000;
	let payment_id = PaymentId([42; 32]);
	let payment_params = PaymentParameters::from_node_id(node_b_id, 0)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], payment_params, amt_msat);

	// Extend the path by itself, essentially simulating route going through same channel twice
	let cloned_hops = route.paths[0].hops.clone();
	route.paths[0].hops.extend_from_slice(&cloned_hops);
	let route_params = route.route_params.clone().unwrap();
	nodes[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));

	// Send the payment with one retry allowed, but the payment should still fail
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let retry = Retry::Attempts(1);
	nodes[0].node.send_payment(payment_hash, onion, payment_id, route_params, retry).unwrap();
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match &events[0] {
		Event::PaymentPathFailed { failure, payment_failed_permanently, .. } => {
			let err = "Path went through the same channel twice".to_string();
			assert_eq!(failure, &PathFailure::InitialSend { err: APIError::InvalidRoute { err } });
			assert!(!payment_failed_permanently);
		},
		_ => panic!(),
	}
	match events[1] {
		Event::PaymentFailed { reason, .. } => {
			assert_eq!(reason.unwrap(), PaymentFailureReason::UnexpectedError);
		},
		_ => panic!(),
	}
	assert!(nodes[0].node.list_recent_payments().is_empty());
}

#[test]
fn remove_pending_outbound_probe_on_buggy_path() {
	// Ensure that if a probe errors due to a bogus route, we'll return an error and remove the
	// pending outbound from storage.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let amt_msat = 10_000;
	let payment_params = PaymentParameters::from_node_id(node_b_id, 0)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let (mut route, _, _, _) =
		get_route_and_payment_hash!(nodes[0], nodes[1], payment_params, amt_msat);

	// Extend the path by itself, essentially simulating route going through same channel twice
	let cloned_hops = route.paths[0].hops.clone();
	route.paths[0].hops.extend_from_slice(&cloned_hops);

	assert_eq!(
		nodes[0].node.send_probe(route.paths.pop().unwrap()).unwrap_err(),
		ProbeSendFailure::ParameterError(APIError::InvalidRoute {
			err: "Path went through the same channel twice".to_string()
		})
	);
	assert!(nodes[0].node.list_recent_payments().is_empty());
}

#[test]
fn pay_route_without_params() {
	// Make sure we can use ChannelManager::send_payment_with_route to pay a route where
	// Route::route_parameters is None.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let amt_msat = 10_000;
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let (mut route, hash, preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], payment_params, amt_msat);
	route.route_params.take();

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(hash.0);
	nodes[0].node.send_payment_with_route(route, hash, onion, id).unwrap();

	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let node_1_msgs = remove_first_msg_event_to_node(&node_b_id, &mut events);
	let path = &[&nodes[1]];
	pass_along_path(&nodes[0], path, amt_msat, hash, Some(payment_secret), node_1_msgs, true, None);
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], &[path], preimage));
}

#[test]
fn max_out_mpp_path() {
	// In this setup, the sender is attempting to route an MPP payment split across the two channels
	// that it has with its LSP, where the LSP has a single large channel to the recipient.
	//
	// Previously a user ran into a pathfinding failure here because our router was not sending the
	// maximum possible value over the first MPP path it found due to overestimating the fees needed
	// to cover the following hops. Because the path that had just been found was not maxxed out, our
	// router assumed that we had already found enough paths to cover the full payment amount and that
	// we were finding additional paths for the purpose of redundant path selection. This caused the
	// router to mark the recipient's only channel as exhausted, with the intention of choosing more
	// unique paths in future iterations. In reality, this ended up with the recipient's only channel
	// being disabled and subsequently failing to find a route entirely.
	//
	// The router has since been updated to fully utilize the capacity of any paths it finds in this
	// situation, preventing the "redundant path selection" behavior from kicking in.

	let mut user_cfg = test_default_channel_config();
	user_cfg.channel_config.forwarding_fee_base_msat = 0;
	user_cfg.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
	let mut lsp_cfg = test_default_channel_config();
	lsp_cfg.channel_config.forwarding_fee_base_msat = 0;
	lsp_cfg.channel_config.forwarding_fee_proportional_millionths = 3000;
	lsp_cfg.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let configs = [Some(user_cfg.clone()), Some(lsp_cfg), Some(user_cfg)];
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &configs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 200_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 300_000, 0);
	create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 600_000, 0);

	let amt_msat = 350_000_000;
	let invoice_params = crate::ln::channelmanager::Bolt11InvoiceParameters {
		amount_msats: Some(amt_msat),
		..Default::default()
	};
	let invoice = nodes[2].node.create_bolt11_invoice(invoice_params).unwrap();
	let route_params_cfg = crate::routing::router::RouteParametersConfig::default();

	let id = PaymentId([42; 32]);
	let retry = Retry::Attempts(0);
	nodes[0].node.pay_for_bolt11_invoice(&invoice, id, None, route_params_cfg, retry).unwrap();

	assert!(nodes[0].node.list_recent_payments().len() == 1);
	check_added_monitors(&nodes[0], 2); // one monitor update per MPP part
	nodes[0].node.get_and_clear_pending_msg_events();
}
