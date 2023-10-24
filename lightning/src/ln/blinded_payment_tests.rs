// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use crate::blinded_path::BlindedPath;
use crate::blinded_path::payment::{ForwardNode, ForwardTlvs, PaymentConstraints, PaymentRelay, ReceiveTlvs};
use crate::events::{HTLCDestination, MessageSendEventsProvider};
use crate::ln::PaymentSecret;
use crate::ln::channelmanager;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
use crate::ln::features::BlindedHopFeatures;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::onion_utils;
use crate::ln::onion_utils::INVALID_ONION_BLINDING;
use crate::ln::outbound_payment::Retry;
use crate::prelude::*;
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::util::config::UserConfig;
use crate::util::test_utils;

pub fn get_blinded_route_parameters(
	amt_msat: u64, payment_secret: PaymentSecret, node_ids: Vec<PublicKey>,
	channel_upds: &[&msgs::UnsignedChannelUpdate], keys_manager: &test_utils::TestKeysInterface
) -> RouteParameters {
	let mut intermediate_nodes = Vec::new();
	for (node_id, chan_upd) in node_ids.iter().zip(channel_upds) {
		intermediate_nodes.push(ForwardNode {
			node_id: *node_id,
			tlvs: ForwardTlvs {
				short_channel_id: chan_upd.short_channel_id,
				payment_relay: PaymentRelay {
					cltv_expiry_delta: chan_upd.cltv_expiry_delta,
					fee_proportional_millionths: chan_upd.fee_proportional_millionths,
					fee_base_msat: chan_upd.fee_base_msat,
				},
				payment_constraints: PaymentConstraints {
					max_cltv_expiry: u32::max_value(),
					htlc_minimum_msat: chan_upd.htlc_minimum_msat,
				},
				features: BlindedHopFeatures::empty(),
			},
			htlc_maximum_msat: chan_upd.htlc_maximum_msat,
		});
	}
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: channel_upds.last().unwrap().htlc_minimum_msat,
		},
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_payment(
		&intermediate_nodes[..], *node_ids.last().unwrap(), payee_tlvs,
		channel_upds.last().unwrap().htlc_maximum_msat, keys_manager, &secp_ctx
	).unwrap();

	RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_path]), amt_msat
	)
}

#[test]
fn one_hop_blinded_path() {
	do_one_hop_blinded_path(true);
	do_one_hop_blinded_path(false);
}

fn do_one_hop_blinded_path(success: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_upd = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[1], Some(amt_msat), None);
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd.htlc_minimum_msat,
		},
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::one_hop_for_payment(
		nodes[1].node.get_our_node_id(), payee_tlvs, &chanmon_cfgs[1].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_path]),
		amt_msat,
	);
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(),
	PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1]]], amt_msat, payment_hash, payment_secret);
	if success {
		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
	} else {
		fail_payment(&nodes[0], &[&nodes[1]], payment_hash);
	}
}

#[test]
fn mpp_to_one_hop_blinded_path() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	let mut secp_ctx = Secp256k1::new();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_upd_1_3 = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents;
	create_announced_chan_between_nodes(&nodes, 2, 3).0.contents;

	let amt_msat = 15_000_000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd_1_3.htlc_minimum_msat,
		},
	};
	let blinded_path = BlindedPath::one_hop_for_payment(
		nodes[3].node.get_our_node_id(), payee_tlvs, &chanmon_cfgs[3].keys_manager, &secp_ctx
	).unwrap();

	let bolt12_features =
		channelmanager::provided_bolt12_invoice_features(&UserConfig::default());
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_path]).with_bolt12_features(bolt12_features).unwrap(),
		amt_msat,
	);
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 2);

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[0], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), false, None);

	let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[1], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), true, None);
	claim_payment_along_route(&nodes[0], expected_route, false, payment_preimage);
}

enum ForwardCheckFail {
	// Fail a check on the inbound onion payload. In this case, we underflow when calculating the
	// outgoing cltv_expiry.
	InboundOnionCheck,
	// The forwarding node's payload is encoded as a receive, i.e. the next hop HMAC is [0; 32].
	ForwardPayloadEncodedAsReceive,
	// Fail a check on the outbound channel. In this case, our next-hop peer is offline.
	OutboundChannelCheck,
}

#[test]
fn forward_checks_failure() {
	do_forward_checks_failure(ForwardCheckFail::InboundOnionCheck);
	do_forward_checks_failure(ForwardCheckFail::ForwardPayloadEncodedAsReceive);
	do_forward_checks_failure(ForwardCheckFail::OutboundChannelCheck);
}

fn do_forward_checks_failure(check: ForwardCheckFail) {
	// Ensure we'll fail backwards properly if a forwarding check fails on initial update_add
	// receipt.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	// We need the session priv to construct a bogus onion packet later.
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some([3; 32]);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_1_2],
		&chanmon_cfgs[2].keys_manager);

	let route = get_route(&nodes[0], &route_params).unwrap();
	node_cfgs[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let mut payment_event = SendEvent::from_event(ev);

	let mut update_add = &mut payment_event.msgs[0];
	match check {
		ForwardCheckFail::InboundOnionCheck => {
			update_add.cltv_expiry = 10; // causes outbound CLTV expiry to underflow
		},
		ForwardCheckFail::ForwardPayloadEncodedAsReceive => {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
			let cur_height = nodes[0].best_block_info().1;
			let (mut onion_payloads, ..) = onion_utils::build_onion_payloads(
				&route.paths[0], amt_msat, RecipientOnionFields::spontaneous_empty(), cur_height, &None).unwrap();
			// Remove the receive payload so the blinded forward payload is encoded as a final payload
			// (i.e. next_hop_hmac == [0; 32])
			onion_payloads.pop();
			update_add.onion_routing_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash).unwrap();
		},
		ForwardCheckFail::OutboundChannelCheck => {
			// The intro node will see that the next-hop peer is disconnected and fail the HTLC backwards.
			nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id());
		},
	}
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, true, true);

	let mut updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
}

#[test]
fn failed_backwards_to_intro_node() {
	// Ensure the intro node will error backwards properly even if the downstream node did not blind
	// their error.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_1_2],
		&chanmon_cfgs[2].keys_manager);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let mut payment_event = SendEvent::from_event(ev);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	let mut payment_event = SendEvent::from_event(ev);

	// Ensure the final node fails to handle the HTLC.
	payment_event.msgs[0].onion_routing_packet.hop_data[0] ^= 1;
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[2], 0);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event.commitment_msg, true, true);
	nodes[2].node.process_pending_htlc_forwards();

	let mut updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	let mut update_malformed = &mut updates.update_fail_malformed_htlcs[0];
	// Check that the final node encodes its failure correctly.
	assert_eq!(update_malformed.failure_code, INVALID_ONION_BLINDING);
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);

	// Modify such the final hop does not correctly blind their error so we can ensure the intro node
	// converts it to the correct error.
	update_malformed.sha256_of_onion = [1; 32];
	nodes[1].node.handle_update_fail_malformed_htlc(&nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, true, false);

	let mut updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
}

enum ProcessPendingHTLCsCheck {
	FwdPeerDisconnected,
	FwdChannelClosed,
}

#[test]
fn forward_fail_in_process_pending_htlc_fwds() {
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdPeerDisconnected);
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdChannelClosed);
}
fn do_forward_fail_in_process_pending_htlc_fwds(check: ProcessPendingHTLCsCheck) {
	// Ensure the intro node will error backwards properly if the HTLC fails in
	// process_pending_htlc_forwards.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let (chan_upd_1_2, channel_id) = {
		let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
		(chan.0.contents, chan.2)
	};

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_1_2],
		&chanmon_cfgs[2].keys_manager);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let mut payment_event = SendEvent::from_event(ev);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);

	match check {
		ProcessPendingHTLCsCheck::FwdPeerDisconnected => {
			// Disconnect the next-hop peer so when we go to forward in process_pending_htlc_forwards, the
			// intro node will error backwards.
			nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id());
			expect_pending_htlcs_forwardable!(nodes[1]);
			expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1],
				vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id }]);
		},
		ProcessPendingHTLCsCheck::FwdChannelClosed => {
			// Force close the next-hop channel so when we go to forward in process_pending_htlc_forwards,
			// the intro node will error backwards.
			nodes[1].node.force_close_broadcasting_latest_txn(&channel_id, &nodes[2].node.get_our_node_id()).unwrap();
			let events = nodes[1].node.get_and_clear_pending_events();
			match events[0] {
				crate::events::Event::PendingHTLCsForwardable { .. } => {},
				_ => panic!("Unexpected event {:?}", events),
			};
			match events[1] {
				crate::events::Event::ChannelClosed { .. } => {},
				_ => panic!("Unexpected event {:?}", events),
			}

			nodes[1].node.process_pending_htlc_forwards();
			expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1],
				vec![HTLCDestination::UnknownNextHop { requested_forward_scid: chan_upd_1_2.short_channel_id }]);
			check_closed_broadcast(&nodes[1], 1, true);
			check_added_monitors!(nodes[1], 1);
			nodes[1].node.process_pending_htlc_forwards();
		},
	}

	let mut updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	check_added_monitors!(nodes[1], 1);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);

	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
}

#[test]
fn blinded_intercept_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut intercept_forwards_config = test_default_channel_config();
	intercept_forwards_config.accept_intercept_htlcs = true;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(intercept_forwards_config), None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let intercept_scid = nodes[1].node.get_intercept_scid();
	let mut intercept_chan_upd = chan_upd;
	intercept_chan_upd.short_channel_id = intercept_scid;
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&intercept_chan_upd],
		&chanmon_cfgs[2].keys_manager);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(),
	PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	let payment_event = {
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], &payment_event.commitment_msg, false, true);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let intercept_id = match events[0] {
		crate::events::Event::HTLCIntercepted {
			intercept_id, payment_hash: pmt_hash,
			requested_next_hop_scid: short_channel_id, ..
		} => {
			assert_eq!(pmt_hash, payment_hash);
			assert_eq!(short_channel_id, intercept_scid);
			intercept_id
		},
		_ => panic!()
	};

	nodes[1].node.fail_intercepted_htlc(intercept_id).unwrap();
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::UnknownNextHop { requested_forward_scid: intercept_scid }]);
	nodes[1].node.process_pending_htlc_forwards();
	let update_fail = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_fail.update_fail_htlcs.len() == 1);
	let fail_msg = update_fail.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_fail.commitment_signed, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
}

#[test]
fn two_hop_blinded_path_success() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_1_2],
		&chanmon_cfgs[2].keys_manager);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], amt_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
}

enum ReceiveCheckFail {
	// The recipient fails the payment upon `PaymentClaimable`.
	RecipientFail,
	// Failure to decode the recipient's onion payload.
	OnionDecodeFail,
}

#[test]
fn multi_hop_receiver_fail() {
	do_multi_hop_receiver_fail(ReceiveCheckFail::RecipientFail);
	do_multi_hop_receiver_fail(ReceiveCheckFail::OnionDecodeFail);
}

fn do_multi_hop_receiver_fail(check: ReceiveCheckFail) {
	// Test that the receiver to a multihop blinded path fails back correctly.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	// We need the session priv to construct an invalid onion packet later.
	let session_priv = [3; 32];
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(session_priv);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_1_2],
		&chanmon_cfgs[2].keys_manager);

	let route = find_route(&nodes[0], &route_params).unwrap();
	node_cfgs[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut payment_event_0_1 = {
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
		SendEvent::from_event(ev)
	};
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event_0_1.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event_0_1.commitment_msg, false, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(&nodes[1], 1);

	let mut payment_event_1_2 = {
		let mut events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
		SendEvent::from_event(ev)
	};

	match check {
		ReceiveCheckFail::RecipientFail => {
			nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_1_2.msgs[0]);
			check_added_monitors!(nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
			expect_pending_htlcs_forwardable!(nodes[2]);
			check_payment_claimable(
				&nodes[2].node.get_and_clear_pending_events()[0], payment_hash, payment_secret, amt_msat,
				None, nodes[2].node.get_our_node_id()
			);
			nodes[2].node.fail_htlc_backwards(&payment_hash);
			expect_pending_htlcs_forwardable_conditions(
				nodes[2].node.get_and_clear_pending_events(), &[HTLCDestination::FailedPayment { payment_hash }]
			);
			nodes[2].node.process_pending_htlc_forwards();
			check_added_monitors!(nodes[2], 1);
		},
		ReceiveCheckFail::OnionDecodeFail => {
			let session_priv = SecretKey::from_slice(&session_priv).unwrap();
			let mut onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
			let cur_height = nodes[0].best_block_info().1;
			let (mut onion_payloads, ..) = onion_utils::build_onion_payloads(
				&route.paths[0], amt_msat, RecipientOnionFields::spontaneous_empty(), cur_height, &None).unwrap();

			let update_add = &mut payment_event_1_2.msgs[0];
			onion_payloads.last_mut().map(|p| {
				if let msgs::OutboundOnionPayload::BlindedReceive { ref mut intro_node_blinding_point, .. } = p {
					// The receiver should error if both the update_add blinding_point and the
					// intro_node_blinding_point are set.
					assert!(intro_node_blinding_point.is_none() && update_add.blinding_point.is_some());
					*intro_node_blinding_point = Some(PublicKey::from_slice(&[2; 33]).unwrap());
				} else { panic!() }
			});
			update_add.onion_routing_packet = onion_utils::construct_onion_packet(
				vec![onion_payloads.pop().unwrap()], vec![onion_keys.pop().unwrap()], [0; 32],
				&payment_hash
			).unwrap();
			nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), update_add);
			check_added_monitors!(nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
		}
	}

	let updates_2_1 = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert_eq!(updates_2_1.update_fail_malformed_htlcs.len(), 1);
	let update_malformed = &updates_2_1.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);
	assert_eq!(update_malformed.failure_code, INVALID_ONION_BLINDING);
	nodes[1].node.handle_update_fail_malformed_htlc(&nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates_2_1.commitment_signed, true, false);

	let updates_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert_eq!(updates_1_0.update_fail_htlcs.len(), 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates_1_0.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates_1_0.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
}
