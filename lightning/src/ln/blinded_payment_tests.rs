// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use crate::blinded_path::BlindedPath;
use crate::blinded_path::payment::{ForwardNode, ForwardTlvs, PaymentConstraints, PaymentRelay, ReceiveTlvs};
use crate::events::MessageSendEventsProvider;
use crate::ln::channelmanager;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
use crate::ln::features::BlindedHopFeatures;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::onion_utils;
use crate::ln::onion_utils::INVALID_ONION_BLINDING;
use crate::ln::outbound_payment::Retry;
use crate::prelude::*;
use crate::routing::router::{PaymentParameters, RouteParameters};
use crate::util::config::UserConfig;

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
}

#[test]
fn forward_checks_failure() {
	do_forward_checks_failure(ForwardCheckFail::InboundOnionCheck);
	do_forward_checks_failure(ForwardCheckFail::ForwardPayloadEncodedAsReceive);
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
	let intermediate_nodes = vec![ForwardNode {
		node_id: nodes[1].node.get_our_node_id(),
		tlvs: ForwardTlvs {
			short_channel_id: chan_upd_1_2.short_channel_id,
			payment_relay: PaymentRelay {
				cltv_expiry_delta: chan_upd_1_2.cltv_expiry_delta,
				fee_proportional_millionths: chan_upd_1_2.fee_proportional_millionths,
				fee_base_msat: chan_upd_1_2.fee_base_msat,
			},
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: chan_upd_1_2.htlc_minimum_msat,
			},
			features: BlindedHopFeatures::empty(),
		},
		htlc_maximum_msat: chan_upd_1_2.htlc_maximum_msat,
	}];
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd_1_2.htlc_minimum_msat,
		},
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_payment(
		&intermediate_nodes[..], nodes[2].node.get_our_node_id(), payee_tlvs,
		chan_upd_1_2.htlc_maximum_msat, &chanmon_cfgs[2].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_path]), amt_msat);
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
