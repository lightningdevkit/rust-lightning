// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, schnorr};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use crate::blinded_path;
use crate::blinded_path::payment::{BlindedPaymentPath, ForwardNode, ForwardTlvs, PaymentConstraints, PaymentContext, PaymentRelay, ReceiveTlvs};
use crate::events::{Event, HTLCDestination, MessageSendEvent, MessageSendEventsProvider, PaymentFailureReason};
use crate::ln::types::{ChannelId, PaymentHash, PaymentSecret};
use crate::ln::channelmanager;
use crate::ln::channelmanager::{HTLCFailureMsg, PaymentId, RecipientOnionFields};
use crate::ln::features::{BlindedHopFeatures, ChannelFeatures, NodeFeatures};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::msgs::{ChannelMessageHandler, UnsignedGossipMessage};
use crate::ln::onion_payment;
use crate::ln::onion_utils;
use crate::ln::onion_utils::INVALID_ONION_BLINDING;
use crate::ln::outbound_payment::{Retry, IDEMPOTENCY_TIMEOUT_TICKS};
use crate::offers::invoice::{BlindedPayInfo, UnsignedBolt12Invoice};
use crate::offers::invoice_request::UnsignedInvoiceRequest;
use crate::prelude::*;
use crate::routing::router::{BlindedTail, Path, Payee, PaymentParameters, RouteHop, RouteParameters};
use crate::sign::{KeyMaterial, NodeSigner, Recipient};
use crate::util::config::UserConfig;
use crate::util::ser::WithoutLength;
use crate::util::test_utils;
use lightning_invoice::RawBolt11Invoice;

fn blinded_payment_path(
	payment_secret: PaymentSecret, intro_node_min_htlc: u64, intro_node_max_htlc: u64,
	node_ids: Vec<PublicKey>, channel_upds: &[&msgs::UnsignedChannelUpdate],
	keys_manager: &test_utils::TestKeysInterface
) -> (BlindedPayInfo, BlindedPaymentPath) {
	let mut intermediate_nodes = Vec::new();
	let mut intro_node_min_htlc_opt = Some(intro_node_min_htlc);
	let mut intro_node_max_htlc_opt = Some(intro_node_max_htlc);
	for (idx, (node_id, chan_upd)) in node_ids.iter().zip(channel_upds).enumerate() {
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
					htlc_minimum_msat: intro_node_min_htlc_opt.take()
						.unwrap_or_else(|| channel_upds[idx - 1].htlc_minimum_msat),
				},
				next_blinding_override: None,
				features: BlindedHopFeatures::empty(),
			},
			htlc_maximum_msat: intro_node_max_htlc_opt.take()
				.unwrap_or_else(|| channel_upds[idx - 1].htlc_maximum_msat),
		});
	}
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat:
				intro_node_min_htlc_opt.unwrap_or_else(|| channel_upds.last().unwrap().htlc_minimum_msat),
		},
		payment_context: PaymentContext::unknown(),
	};
	let mut secp_ctx = Secp256k1::new();
	BlindedPaymentPath::new(
		&intermediate_nodes[..], *node_ids.last().unwrap(), payee_tlvs,
		intro_node_max_htlc_opt.unwrap_or_else(|| channel_upds.last().unwrap().htlc_maximum_msat),
		TEST_FINAL_CLTV as u16, keys_manager, &secp_ctx
	).unwrap()
}

pub fn get_blinded_route_parameters(
	amt_msat: u64, payment_secret: PaymentSecret, intro_node_min_htlc: u64, intro_node_max_htlc: u64,
	node_ids: Vec<PublicKey>, channel_upds: &[&msgs::UnsignedChannelUpdate],
	keys_manager: &test_utils::TestKeysInterface
) -> RouteParameters {
	RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![
			blinded_payment_path(
				payment_secret, intro_node_min_htlc, intro_node_max_htlc, node_ids, channel_upds,
				keys_manager
			)
		]), amt_msat
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
		payment_context: PaymentContext::unknown(),
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPaymentPath::new(
		&[], nodes[1].node.get_our_node_id(), payee_tlvs, u64::MAX, TEST_FINAL_CLTV as u16,
		&chanmon_cfgs[1].keys_manager, &secp_ctx
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
		payment_context: PaymentContext::unknown(),
	};
	let blinded_path = BlindedPaymentPath::new(
		&[], nodes[3].node.get_our_node_id(), payee_tlvs, u64::MAX, TEST_FINAL_CLTV as u16,
		&chanmon_cfgs[3].keys_manager, &secp_ctx
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
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], expected_route, payment_preimage)
	);
}

#[test]
fn mpp_to_three_hop_blinded_paths() {
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs, &[None, None, None, None, None, None]);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	// Create this network topology so node 0 MPP's over 2 3-hop blinded paths:
	//     n1 -- n3
	//    /        \
	// n0           n5
	//    \        /
	//     n2 -- n4
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_upd_1_3 = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents;
	let chan_upd_2_4 = create_announced_chan_between_nodes(&nodes, 2, 4).0.contents;
	let chan_upd_3_5 = create_announced_chan_between_nodes(&nodes, 3, 5).0.contents;
	let chan_upd_4_5 = create_announced_chan_between_nodes(&nodes, 4, 5).0.contents;

	let amt_msat = 15_000_000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[5], Some(amt_msat), None);
	let route_params = {
		let path_1_params = get_blinded_route_parameters(
			amt_msat, payment_secret, 1, 1_0000_0000, vec![
				nodes[1].node.get_our_node_id(), nodes[3].node.get_our_node_id(),
				nodes[5].node.get_our_node_id()
			], &[&chan_upd_1_3, &chan_upd_3_5], &chanmon_cfgs[5].keys_manager
		);
		let path_2_params = get_blinded_route_parameters(
			amt_msat, payment_secret, 1, 1_0000_0000, vec![
				nodes[2].node.get_our_node_id(), nodes[4].node.get_our_node_id(),
				nodes[5].node.get_our_node_id()
			], &[&chan_upd_2_4, &chan_upd_4_5], &chanmon_cfgs[5].keys_manager
		);
		let pay_params = PaymentParameters::blinded(
			vec![
				path_1_params.payment_params.payee.blinded_route_hints()[0].clone(),
				path_2_params.payment_params.payee.blinded_route_hints()[0].clone()
			]
		)
			.with_bolt12_features(channelmanager::provided_bolt12_invoice_features(&UserConfig::default()))
			.unwrap();
		RouteParameters::from_payment_params_and_value(pay_params, amt_msat)
	};

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(),
		PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 2);

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[3], &nodes[5]], &[&nodes[2], &nodes[4], &nodes[5]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[0], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), false, None);

	let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[1], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), true, None);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], expected_route, payment_preimage)
	);
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
	do_forward_checks_failure(ForwardCheckFail::InboundOnionCheck, true);
	do_forward_checks_failure(ForwardCheckFail::InboundOnionCheck, false);
	do_forward_checks_failure(ForwardCheckFail::ForwardPayloadEncodedAsReceive, true);
	do_forward_checks_failure(ForwardCheckFail::ForwardPayloadEncodedAsReceive, false);
	do_forward_checks_failure(ForwardCheckFail::OutboundChannelCheck, true);
	do_forward_checks_failure(ForwardCheckFail::OutboundChannelCheck, false);
}

fn do_forward_checks_failure(check: ForwardCheckFail, intro_fails: bool) {
	// Ensure we'll fail backwards properly if a forwarding check fails on initial update_add
	// receipt.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	// We need the session priv to construct a bogus onion packet later.
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some([3; 32]);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;
	let chan_upd_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let mut route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(),
		&[&chan_upd_1_2, &chan_upd_2_3], &chanmon_cfgs[3].keys_manager);
	route_params.payment_params.max_path_length = 18;

	let route = get_route(&nodes[0], &route_params).unwrap();
	node_cfgs[0].router.expect_find_route(route_params.clone(), Ok(route.clone()));
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	macro_rules! cause_error {
		($src_node_idx: expr, $target_node_idx: expr, $update_add: expr) => {
			match check {
				ForwardCheckFail::InboundOnionCheck => {
					$update_add.cltv_expiry = 10; // causes outbound CLTV expiry to underflow
				},
				ForwardCheckFail::ForwardPayloadEncodedAsReceive => {
					let recipient_onion_fields = RecipientOnionFields::spontaneous_empty();
					let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
					let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
					let cur_height = nodes[0].best_block_info().1;
					let (mut onion_payloads, ..) = onion_utils::build_onion_payloads(
						&route.paths[0], amt_msat, &recipient_onion_fields, cur_height, &None).unwrap();
					// Remove the receive payload so the blinded forward payload is encoded as a final payload
					// (i.e. next_hop_hmac == [0; 32])
					onion_payloads.pop();
					if $target_node_idx + 1 < nodes.len() {
						onion_payloads.pop();
					}
					$update_add.onion_routing_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash).unwrap();
				},
				ForwardCheckFail::OutboundChannelCheck => {
					// The intro node will see that the next-hop peer is disconnected and fail the HTLC backwards.
					nodes[$src_node_idx].node.peer_disconnected(&nodes[$target_node_idx].node.get_our_node_id());
				}
			}
		}
	}

	let mut updates_0_1 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let update_add = &mut updates_0_1.update_add_htlcs[0];

	if intro_fails {
		cause_error!(1, 2, update_add);
	}

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	check_added_monitors!(nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &updates_0_1.commitment_signed, true, true);

	if intro_fails {
		let mut updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
		expect_payment_failed_conditions(&nodes[0], payment_hash, false,
			PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
		return
	}

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let mut updates_1_2 = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
	let mut update_add = &mut updates_1_2.update_add_htlcs[0];

	cause_error!(2, 3, update_add);

	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &update_add);
	check_added_monitors!(nodes[2], 0);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &updates_1_2.commitment_signed, true, true);

	let mut updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	let update_malformed = &mut updates.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.failure_code, INVALID_ONION_BLINDING);
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);

	// Ensure the intro node will properly blind the error if its downstream node failed to do so.
	update_malformed.sha256_of_onion = [1; 32];
	update_malformed.failure_code = INVALID_ONION_BLINDING ^ 1;
	nodes[1].node.handle_update_fail_malformed_htlc(&nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, true, false);

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
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
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
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdPeerDisconnected, true);
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdPeerDisconnected, false);
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdChannelClosed, true);
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdChannelClosed, false);
}
fn do_forward_fail_in_process_pending_htlc_fwds(check: ProcessPendingHTLCsCheck, intro_fails: bool) {
	// Ensure the intro node will error backwards properly if the HTLC fails in
	// process_pending_htlc_forwards.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let (chan_upd_1_2, chan_id_1_2) = {
		let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
		(chan.0.contents, chan.2)
	};
	let (chan_upd_2_3, chan_id_2_3) = {
		let chan = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);
		(chan.0.contents, chan.2)
	};

	let error_message = "Channel force-closed";
	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_1_2, &chan_upd_2_3],
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

	macro_rules! cause_error {
		($prev_node: expr, $curr_node: expr, $next_node: expr, $failed_chan_id: expr, $failed_scid: expr) => {
			match check {
				ProcessPendingHTLCsCheck::FwdPeerDisconnected => {
					// Disconnect the next-hop peer so when we go to forward in process_pending_htlc_forwards, the
					// intro node will error backwards.
					$curr_node.node.peer_disconnected(&$next_node.node.get_our_node_id());
					expect_pending_htlcs_forwardable!($curr_node);
					expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!($curr_node,
						vec![HTLCDestination::NextHopChannel { node_id: Some($next_node.node.get_our_node_id()), channel_id: $failed_chan_id }]);
				},
				ProcessPendingHTLCsCheck::FwdChannelClosed => {
					// Force close the next-hop channel so when we go to forward in process_pending_htlc_forwards,
					// the intro node will error backwards.
					$curr_node.node.force_close_broadcasting_latest_txn(&$failed_chan_id, &$next_node.node.get_our_node_id(), error_message.to_string()).unwrap();
					let events = $curr_node.node.get_and_clear_pending_events();
					match events[0] {
						crate::events::Event::PendingHTLCsForwardable { .. } => {},
						_ => panic!("Unexpected event {:?}", events),
					};
					match events[1] {
						crate::events::Event::ChannelClosed { .. } => {},
						_ => panic!("Unexpected event {:?}", events),
					}

					$curr_node.node.process_pending_htlc_forwards();
					expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!($curr_node,
						vec![HTLCDestination::UnknownNextHop { requested_forward_scid: $failed_scid }]);
					check_closed_broadcast(&$curr_node, 1, true);
					check_added_monitors!($curr_node, 1);
					$curr_node.node.process_pending_htlc_forwards();
				},
			}
		}
	}

	if intro_fails {
		cause_error!(nodes[0], nodes[1], nodes[2], chan_id_1_2, chan_upd_1_2.short_channel_id);
		let mut updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		check_added_monitors!(nodes[1], 1);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);

		expect_payment_failed_conditions(&nodes[0], payment_hash, false,
			PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
		return
	}

	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);

	let mut updates_1_2 = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
	let mut update_add = &mut updates_1_2.update_add_htlcs[0];
	nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &update_add);
	check_added_monitors!(nodes[2], 0);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &updates_1_2.commitment_signed, true, true);

	cause_error!(nodes[1], nodes[2], nodes[3], chan_id_2_3, chan_upd_2_3.short_channel_id);
	check_added_monitors!(nodes[2], 1);

	let mut updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	let update_malformed = &mut updates.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.failure_code, INVALID_ONION_BLINDING);
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);

	// Ensure the intro node will properly blind the error if its downstream node failed to do so.
	update_malformed.sha256_of_onion = [1; 32];
	update_malformed.failure_code = INVALID_ONION_BLINDING ^ 1;
	nodes[1].node.handle_update_fail_malformed_htlc(&nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, true, false);

	let mut updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
}

#[test]
fn blinded_intercept_payment() {
	do_blinded_intercept_payment(true);
	do_blinded_intercept_payment(false);
}
fn do_blinded_intercept_payment(intercept_node_fails: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut intercept_forwards_config = test_default_channel_config();
	intercept_forwards_config.accept_intercept_htlcs = true;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(intercept_forwards_config), None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let (channel_id, chan_upd) = {
		let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
		(chan.2, chan.0.contents)
	};

	let amt_msat = 5000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let intercept_scid = nodes[1].node.get_intercept_scid();
	let mut intercept_chan_upd = chan_upd;
	intercept_chan_upd.short_channel_id = intercept_scid;
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
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
	let (intercept_id, expected_outbound_amount_msat) = match events[0] {
		crate::events::Event::HTLCIntercepted {
			intercept_id, payment_hash: pmt_hash,
			requested_next_hop_scid: short_channel_id, expected_outbound_amount_msat, ..
		} => {
			assert_eq!(pmt_hash, payment_hash);
			assert_eq!(short_channel_id, intercept_scid);
			(intercept_id, expected_outbound_amount_msat)
		},
		_ => panic!()
	};

	if intercept_node_fails {
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
		return
	}

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

	expect_payment_claimable!(&nodes[2], payment_hash, payment_secret, amt_msat, None, nodes[2].node.get_our_node_id());
	do_claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2]]], payment_preimage)
	);
	expect_payment_sent(&nodes[0], payment_preimage, Some(Some(1000)), true, true);
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
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_1_2],
		&chanmon_cfgs[2].keys_manager);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], amt_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
}

#[test]
fn three_hop_blinded_path_success() {
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, None, None, None, None]);
	let mut nodes = create_network(5, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	let chan_upd_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;
	let chan_upd_3_4 = create_announced_chan_between_nodes_with_value(&nodes, 3, 4, 1_000_000, 0).0.contents;

	// Get all our nodes onto the same height so payments don't fail for CLTV violations.
	connect_blocks(&nodes[0], nodes[4].best_block_info().1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], nodes[4].best_block_info().1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], nodes[4].best_block_info().1 - nodes[2].best_block_info().1);
	assert_eq!(nodes[4].best_block_info().1, nodes[3].best_block_info().1);

	let amt_msat = 5000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[4], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(2).map(|n| n.node.get_our_node_id()).collect(),
		&[&chan_upd_2_3, &chan_upd_3_4], &chanmon_cfgs[4].keys_manager);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3], &nodes[4]]], amt_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]], payment_preimage);
}

#[test]
fn three_hop_blinded_path_fail() {
	// Test that an intermediate blinded forwarding node gets failed back to with
	// malformed and also fails back themselves with malformed.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;
	let chan_upd_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(),
		&[&chan_upd_1_2, &chan_upd_2_3], &chanmon_cfgs[3].keys_manager);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3]]], amt_msat, payment_hash, payment_secret);

	nodes[3].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable_conditions(
		nodes[3].node.get_and_clear_pending_events(), &[HTLCDestination::FailedPayment { payment_hash }]
	);
	nodes[3].node.process_pending_htlc_forwards();
	check_added_monitors!(nodes[3], 1);

	let updates_3_2 = get_htlc_update_msgs!(nodes[3], nodes[2].node.get_our_node_id());
	assert_eq!(updates_3_2.update_fail_malformed_htlcs.len(), 1);
	let update_malformed = &updates_3_2.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);
	assert_eq!(update_malformed.failure_code, INVALID_ONION_BLINDING);
	nodes[2].node.handle_update_fail_malformed_htlc(&nodes[3].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[2], &nodes[3], &updates_3_2.commitment_signed, true, false);

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

#[derive(PartialEq)]
enum ReceiveCheckFail {
	// The recipient fails the payment upon `PaymentClaimable`.
	RecipientFail,
	// Failure to decode the recipient's onion payload.
	OnionDecodeFail,
	// The incoming HTLC did not satisfy our requirements; in this case it underpaid us according to
	// the expected receive amount in the onion.
	ReceiveRequirements,
	// The incoming HTLC errors when added to the Channel, in this case due to the HTLC being
	// delivered out-of-order with a shutdown message.
	ChannelCheck,
	// The HTLC is successfully added to the inbound channel but fails receive checks in
	// process_pending_htlc_forwards.
	ProcessPendingHTLCsCheck,
	// The HTLC violates the `PaymentConstraints` contained within the receiver's encrypted payload.
	PaymentConstraints,
}

#[test]
fn multi_hop_receiver_fail() {
	do_multi_hop_receiver_fail(ReceiveCheckFail::RecipientFail);
	do_multi_hop_receiver_fail(ReceiveCheckFail::OnionDecodeFail);
	do_multi_hop_receiver_fail(ReceiveCheckFail::ReceiveRequirements);
	do_multi_hop_receiver_fail(ReceiveCheckFail::ChannelCheck);
	do_multi_hop_receiver_fail(ReceiveCheckFail::ProcessPendingHTLCsCheck);
	do_multi_hop_receiver_fail(ReceiveCheckFail::PaymentConstraints);
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
	let (chan_upd_1_2, chan_id_1_2) = {
		let (chan_upd, _, channel_id, ..) = create_announced_chan_between_nodes_with_value(
			&nodes, 1, 2, 1_000_000, 0
		);
		(chan_upd.contents, channel_id)
	};

	let amt_msat = 5000;
	let excess_final_cltv_delta_opt = if check == ReceiveCheckFail::ProcessPendingHTLCsCheck {
		// Set the final CLTV expiry too low to trigger the failure in process_pending_htlc_forwards.
		Some(TEST_FINAL_CLTV as u16 - 2)
	} else { None };
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), excess_final_cltv_delta_opt);
	let mut route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_1_2],
		&chanmon_cfgs[2].keys_manager);

	let route = if check == ReceiveCheckFail::ProcessPendingHTLCsCheck {
		let mut route = get_route(&nodes[0], &route_params).unwrap();
		// Set the final CLTV expiry too low to trigger the failure in process_pending_htlc_forwards.
		route.paths[0].hops.last_mut().map(|h| h.cltv_expiry_delta += excess_final_cltv_delta_opt.unwrap() as u32);
		route.paths[0].blinded_tail.as_mut().map(|bt| bt.excess_final_cltv_expiry_delta = excess_final_cltv_delta_opt.unwrap() as u32);
		route
	} else if check == ReceiveCheckFail::PaymentConstraints {
		// Create a blinded path where the receiver's encrypted payload has an htlc_minimum_msat that is
		// violated by `amt_msat`, and stick it in the route_params without changing the corresponding
		// BlindedPayInfo (to ensure pathfinding still succeeds).
		let high_htlc_min_bp = {
			let mut high_htlc_minimum_upd = chan_upd_1_2.clone();
			high_htlc_minimum_upd.htlc_minimum_msat = amt_msat + 1000;
			let high_htlc_min_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
				nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(), &[&high_htlc_minimum_upd],
				&chanmon_cfgs[2].keys_manager);
			if let Payee::Blinded { route_hints, .. } = high_htlc_min_params.payment_params.payee {
				route_hints[0].1.clone()
			} else { panic!() }
		};
		if let Payee::Blinded { ref mut route_hints, .. } = route_params.payment_params.payee {
			route_hints[0].1 = high_htlc_min_bp;
		} else { panic!() }
		find_route(&nodes[0], &route_params).unwrap()
	} else {
		find_route(&nodes[0], &route_params).unwrap()
	};
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
			let recipient_onion_fields = RecipientOnionFields::spontaneous_empty();
			let (mut onion_payloads, ..) = onion_utils::build_onion_payloads(
				&route.paths[0], amt_msat, &recipient_onion_fields, cur_height, &None).unwrap();

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
		},
		ReceiveCheckFail::ReceiveRequirements => {
			let update_add = &mut payment_event_1_2.msgs[0];
			update_add.amount_msat -= 1;
			nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), update_add);
			check_added_monitors!(nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
		},
		ReceiveCheckFail::ChannelCheck => {
			nodes[2].node.close_channel(&chan_id_1_2, &nodes[1].node.get_our_node_id()).unwrap();
			let node_2_shutdown = get_event_msg!(nodes[2], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_shutdown(&nodes[2].node.get_our_node_id(), &node_2_shutdown);
			let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());

			nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_1_2.msgs[0]);
			nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &payment_event_1_2.commitment_msg);
			check_added_monitors!(nodes[2], 1);

			nodes[2].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);
			commitment_signed_dance!(nodes[2], nodes[1], (), false, true, false, false);
		},
		ReceiveCheckFail::ProcessPendingHTLCsCheck => {
			assert_eq!(payment_event_1_2.msgs[0].cltv_expiry, nodes[0].best_block_info().1 + 1 + excess_final_cltv_delta_opt.unwrap() as u32 + TEST_FINAL_CLTV);
			nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_1_2.msgs[0]);
			check_added_monitors!(nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
			expect_pending_htlcs_forwardable!(nodes[2]);
			expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[2],
				vec![HTLCDestination::FailedPayment { payment_hash }]);
			check_added_monitors!(nodes[2], 1);
		},
		ReceiveCheckFail::PaymentConstraints => {
			nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &payment_event_1_2.msgs[0]);
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

	let updates_1_0 = if check == ReceiveCheckFail::ChannelCheck {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		events.into_iter().find_map(|ev| {
			match ev {
				MessageSendEvent:: UpdateHTLCs { node_id, updates } => {
					assert_eq!(node_id, nodes[0].node.get_our_node_id());
					return Some(updates)
				},
				MessageSendEvent::SendClosingSigned { .. } => None,
				_ => panic!()
			}
		}).unwrap()
	} else { get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id()) };
	assert_eq!(updates_1_0.update_fail_htlcs.len(), 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates_1_0.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates_1_0.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
}

#[test]
fn blinded_path_retries() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	// Make one blinded path's fees slightly higher so they are tried in a deterministic order.
	let mut higher_fee_chan_cfg = test_default_channel_config();
	higher_fee_chan_cfg.channel_config.forwarding_fee_base_msat += 1;
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, Some(higher_fee_chan_cfg), None]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	// Create this network topology so nodes[0] has a blinded route hint to retry over.
	//      n1
	//    /    \
	// n0       n3
	//    \    /
	//      n2
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1_000_000, 0);
	let chan_1_3 = create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 1_000_000, 0);
	let chan_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let route_params = {
		let pay_params = PaymentParameters::blinded(
			vec![
				blinded_payment_path(payment_secret, 1, 1_0000_0000,
					vec![nodes[1].node.get_our_node_id(), nodes[3].node.get_our_node_id()], &[&chan_1_3.0.contents],
					&chanmon_cfgs[3].keys_manager
				),
				blinded_payment_path(payment_secret, 1, 1_0000_0000,
					vec![nodes[2].node.get_our_node_id(), nodes[3].node.get_our_node_id()], &[&chan_2_3.0.contents],
					&chanmon_cfgs[3].keys_manager
				),
			]
		)
			.with_bolt12_features(channelmanager::provided_bolt12_invoice_features(&UserConfig::default()))
			.unwrap();
		RouteParameters::from_payment_params_and_value(pay_params, amt_msat)
	};

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(2)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[3]]], amt_msat, payment_hash, payment_secret);

	macro_rules! fail_payment_back {
		($intro_node: expr) => {
			nodes[3].node.fail_htlc_backwards(&payment_hash);
			expect_pending_htlcs_forwardable_conditions(
				nodes[3].node.get_and_clear_pending_events(), &[HTLCDestination::FailedPayment { payment_hash }]
			);
			nodes[3].node.process_pending_htlc_forwards();
			check_added_monitors!(nodes[3], 1);

			let updates = get_htlc_update_msgs!(nodes[3], $intro_node.node.get_our_node_id());
			assert_eq!(updates.update_fail_malformed_htlcs.len(), 1);
			let update_malformed = &updates.update_fail_malformed_htlcs[0];
			assert_eq!(update_malformed.sha256_of_onion, [0; 32]);
			assert_eq!(update_malformed.failure_code, INVALID_ONION_BLINDING);
			$intro_node.node.handle_update_fail_malformed_htlc(&nodes[3].node.get_our_node_id(), update_malformed);
			do_commitment_signed_dance(&$intro_node, &nodes[3], &updates.commitment_signed, true, false);

			let updates =  get_htlc_update_msgs!($intro_node, nodes[0].node.get_our_node_id());
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			nodes[0].node.handle_update_fail_htlc(&$intro_node.node.get_our_node_id(), &updates.update_fail_htlcs[0]);
			do_commitment_signed_dance(&nodes[0], &$intro_node, &updates.commitment_signed, false, false);

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
		}
	}

	fail_payment_back!(nodes[1]);

	// Pass the retry along.
	check_added_monitors!(nodes[0], 1);
	let mut msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], amt_msat, payment_hash, Some(payment_secret), msg_events.pop().unwrap(), true, None);

	fail_payment_back!(nodes[2]);
	let evs = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(evs.len(), 1);
	match evs[0] {
		Event::PaymentFailed { payment_hash: ev_payment_hash, reason, .. } => {
			assert_eq!(ev_payment_hash, Some(payment_hash));
			// We have 1 retry attempt remaining, but we're out of blinded paths to try.
			assert_eq!(reason, Some(PaymentFailureReason::RouteNotFound));
		},
		_ => panic!()
	}
}

#[test]
fn min_htlc() {
	// The min htlc of a blinded path is the max (htlc_min - following_fees) along the path. Make sure
	// the payment succeeds when we calculate the min htlc this way.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let mut node_1_cfg = test_default_channel_config();
	node_1_cfg.channel_handshake_config.our_htlc_minimum_msat = 2000;
	node_1_cfg.channel_config.forwarding_fee_base_msat = 1000;
	node_1_cfg.channel_config.forwarding_fee_proportional_millionths = 100_000;
	let mut node_2_cfg = test_default_channel_config();
	node_2_cfg.channel_handshake_config.our_htlc_minimum_msat = 5000;
	node_2_cfg.channel_config.forwarding_fee_base_msat = 200;
	node_2_cfg.channel_config.forwarding_fee_proportional_millionths = 150_000;
	let mut node_3_cfg = test_default_channel_config();
	node_3_cfg.channel_handshake_config.our_htlc_minimum_msat = 2000;
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, Some(node_1_cfg), Some(node_2_cfg), Some(node_3_cfg)]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	let chan_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);

	let min_htlc_msat = {
		// The min htlc for this setup is nodes[2]'s htlc_minimum_msat minus the
		// following fees.
		let post_base_fee = chan_2_3.1.contents.htlc_minimum_msat - chan_2_3.0.contents.fee_base_msat as u64;
		let prop_fee = chan_2_3.0.contents.fee_proportional_millionths as u64;
		(post_base_fee * 1_000_000 + 1_000_000 + prop_fee - 1) / (prop_fee + 1_000_000)
	};
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(min_htlc_msat), None);
	let mut route_params = get_blinded_route_parameters(
		min_htlc_msat, payment_secret, chan_1_2.1.contents.htlc_minimum_msat,
		chan_1_2.1.contents.htlc_maximum_msat, vec![nodes[1].node.get_our_node_id(),
		nodes[2].node.get_our_node_id(), nodes[3].node.get_our_node_id()],
		&[&chan_1_2.0.contents, &chan_2_3.0.contents], &chanmon_cfgs[3].keys_manager);
	assert_eq!(min_htlc_msat,
		route_params.payment_params.payee.blinded_route_hints()[0].0.htlc_minimum_msat);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3]]], min_htlc_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], payment_preimage);

	// Paying 1 less than the min fails.
	for _ in 0..IDEMPOTENCY_TIMEOUT_TICKS + 1 {
		nodes[0].node.timer_tick_occurred();
	}
	if let Payee::Blinded { ref mut route_hints, .. } = route_params.payment_params.payee {
		route_hints[0].0.htlc_minimum_msat -= 1;
	} else { panic!() }
	route_params.final_value_msat -= 1;
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
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event_0_1.commitment_msg, true, true);
	let mut updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(INVALID_ONION_BLINDING, &[0; 32]));
}

#[test]
fn conditionally_round_fwd_amt() {
	// Previously, the (rng-found) feerates below caught a bug where an intermediate node would
	// calculate an amt_to_forward that underpaid them by 1 msat, caused by rounding up the outbound
	// amount on top of an already rounded-up total routing fee. Ensure that we'll conditionally round
	// down intermediate nodes' outbound amounts based on whether rounding up will result in
	// undercharging for relay.
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);

	let mut node_1_cfg = test_default_channel_config();
	node_1_cfg.channel_config.forwarding_fee_base_msat = 247371;
	node_1_cfg.channel_config.forwarding_fee_proportional_millionths = 86552;

	let mut node_2_cfg = test_default_channel_config();
	node_2_cfg.channel_config.forwarding_fee_base_msat = 198921;
	node_2_cfg.channel_config.forwarding_fee_proportional_millionths = 681759;

	let mut node_3_cfg = test_default_channel_config();
	node_3_cfg.channel_config.forwarding_fee_base_msat = 132845;
	node_3_cfg.channel_config.forwarding_fee_proportional_millionths = 552561;

	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, Some(node_1_cfg), Some(node_2_cfg), Some(node_3_cfg), None]);
	let nodes = create_network(5, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	let chan_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);
	let chan_3_4 = create_announced_chan_between_nodes_with_value(&nodes, 3, 4, 1_000_000, 0);

	let amt_msat = 100_000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[4], Some(amt_msat), None);
	let mut route_params = get_blinded_route_parameters(amt_msat, payment_secret,
		chan_1_2.1.contents.htlc_minimum_msat, chan_1_2.1.contents.htlc_maximum_msat,
		vec![nodes[1].node.get_our_node_id(), nodes[2].node.get_our_node_id(),
		nodes[3].node.get_our_node_id(), nodes[4].node.get_our_node_id()],
		&[&chan_1_2.0.contents, &chan_2_3.0.contents, &chan_3_4.0.contents],
		&chanmon_cfgs[4].keys_manager);
	route_params.max_total_routing_fee_msat = None;

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3], &nodes[4]]], amt_msat, payment_hash, payment_secret);
	nodes[4].node.claim_funds(payment_preimage);
	let expected_path = &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]];
	let expected_route = &[&expected_path[..]];
	let mut args = ClaimAlongRouteArgs::new(&nodes[0], &expected_route[..], payment_preimage)
		.allow_1_msat_fee_overpay();
	let expected_fee = pass_claimed_payment_along_route(args);
	expect_payment_sent(&nodes[0], payment_preimage, Some(Some(expected_fee)), true, true);
}

#[test]
fn blinded_keysend() {
	let mut mpp_keysend_config = test_default_channel_config();
	mpp_keysend_config.accept_mpp_keysend = true;
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, Some(mpp_keysend_config)]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	let amt_msat = 5000;
	let (keysend_preimage, _, payment_secret) = get_payment_preimage_hash(&nodes[2], None, None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1,
		1_0000_0000,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(),
		&[&chan_upd_1_2], &chanmon_cfgs[2].keys_manager);

	let payment_hash = nodes[0].node.send_spontaneous_payment_with_retry(Some(keysend_preimage), RecipientOnionFields::spontaneous_empty(), PaymentId(keysend_preimage.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[2]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);

	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[0], amt_msat, payment_hash, Some(payment_secret), ev.clone(), true, Some(keysend_preimage));
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], expected_route, keysend_preimage)
	);
}

#[test]
fn blinded_mpp_keysend() {
	let mut mpp_keysend_config = test_default_channel_config();
	mpp_keysend_config.accept_mpp_keysend = true;
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, Some(mpp_keysend_config)]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_1_3 = create_announced_chan_between_nodes(&nodes, 1, 3);
	let chan_2_3 = create_announced_chan_between_nodes(&nodes, 2, 3);

	let amt_msat = 15_000_000;
	let (keysend_preimage, _, payment_secret) = get_payment_preimage_hash(&nodes[3], None, None);
	let route_params = {
		let pay_params = PaymentParameters::blinded(
			vec![
				blinded_payment_path(payment_secret, 1, 1_0000_0000,
					vec![nodes[1].node.get_our_node_id(), nodes[3].node.get_our_node_id()], &[&chan_1_3.0.contents],
					&chanmon_cfgs[3].keys_manager
				),
				blinded_payment_path(payment_secret, 1, 1_0000_0000,
					vec![nodes[2].node.get_our_node_id(), nodes[3].node.get_our_node_id()], &[&chan_2_3.0.contents],
					&chanmon_cfgs[3].keys_manager
				),
			]
		)
			.with_bolt12_features(channelmanager::provided_bolt12_invoice_features(&UserConfig::default()))
			.unwrap();
		RouteParameters::from_payment_params_and_value(pay_params, amt_msat)
	};

	let payment_hash = nodes[0].node.send_spontaneous_payment_with_retry(Some(keysend_preimage), RecipientOnionFields::spontaneous_empty(), PaymentId(keysend_preimage.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors!(nodes[0], 2);

	let expected_route: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[0], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), false, Some(keysend_preimage));

	let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	pass_along_path(&nodes[0], expected_route[1], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), true, Some(keysend_preimage));
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], expected_route, keysend_preimage)
	);
}

#[test]
fn custom_tlvs_to_blinded_path() {
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
		payment_context: PaymentContext::unknown(),
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPaymentPath::new(
		&[], nodes[1].node.get_our_node_id(), payee_tlvs, u64::MAX, TEST_FINAL_CLTV as u16,
		&chanmon_cfgs[1].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_path]),
		amt_msat,
	);

	let recipient_onion_fields = RecipientOnionFields::spontaneous_empty()
		.with_custom_tlvs(vec![((1 << 16) + 1, vec![42, 42])])
		.unwrap();
	nodes[0].node.send_payment(payment_hash, recipient_onion_fields.clone(),
		PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);

	let path = &[&nodes[1]];
	let args = PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash, ev)
		.with_payment_secret(payment_secret)
		.with_custom_tlvs(recipient_onion_fields.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1]]], payment_preimage)
			.with_custom_tlvs(recipient_onion_fields.custom_tlvs.clone())
	);
}

fn secret_from_hex(hex: &str) -> SecretKey {
	SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()).unwrap()
}

fn bytes_from_hex(hex: &str) -> Vec<u8> {
	<Vec<u8>>::from_hex(hex).unwrap()
}

fn pubkey_from_hex(hex: &str) -> PublicKey {
	PublicKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()).unwrap()
}

fn update_add_msg(
	amount_msat: u64, cltv_expiry: u32, blinding_point: Option<PublicKey>,
	onion_routing_packet: msgs::OnionPacket
) -> msgs::UpdateAddHTLC {
	msgs::UpdateAddHTLC {
		channel_id: ChannelId::from_bytes([0; 32]),
		htlc_id: 0,
		amount_msat,
		cltv_expiry,
		payment_hash: PaymentHash([0; 32]),
		onion_routing_packet,
		skimmed_fee_msat: None,
		blinding_point,
	}
}

#[test]
fn route_blinding_spec_test_vector() {
	let mut secp_ctx = Secp256k1::new();
	let bob_secret = secret_from_hex("4242424242424242424242424242424242424242424242424242424242424242");
	let bob_node_id = PublicKey::from_secret_key(&secp_ctx, &bob_secret);
	let bob_unblinded_tlvs = bytes_from_hex("011a0000000000000000000000000000000000000000000000000000020800000000000006c10a0800240000009627100c06000b69e505dc0e00fd023103123456");
	let carol_secret = secret_from_hex("4343434343434343434343434343434343434343434343434343434343434343");
	let carol_node_id = PublicKey::from_secret_key(&secp_ctx, &carol_secret);
	let carol_unblinded_tlvs = bytes_from_hex("020800000000000004510821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0a0800300000006401f40c06000b69c105dc0e00");
	let dave_secret = secret_from_hex("4444444444444444444444444444444444444444444444444444444444444444");
	let dave_node_id = PublicKey::from_secret_key(&secp_ctx, &dave_secret);
	let dave_unblinded_tlvs = bytes_from_hex("01230000000000000000000000000000000000000000000000000000000000000000000000020800000000000002310a060090000000fa0c06000b699105dc0e00");
	let eve_secret = secret_from_hex("4545454545454545454545454545454545454545454545454545454545454545");
	let eve_node_id = PublicKey::from_secret_key(&secp_ctx, &eve_secret);
	let eve_unblinded_tlvs = bytes_from_hex("011a00000000000000000000000000000000000000000000000000000604deadbeef0c06000b690105dc0e0f020000000000000000000000000000fdffff0206c1");

	// Eve creates a blinded path to herself through Dave:
	let dave_eve_session_priv = secret_from_hex("0101010101010101010101010101010101010101010101010101010101010101");
	let blinding_override = PublicKey::from_secret_key(&secp_ctx, &dave_eve_session_priv);
	assert_eq!(blinding_override, pubkey_from_hex("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"));
	// Can't use the public API here as the encrypted payloads contain unknown TLVs.
	let mut dave_eve_blinded_hops = blinded_path::utils::construct_blinded_hops(
		&secp_ctx, [dave_node_id, eve_node_id].iter(),
		&mut [WithoutLength(&dave_unblinded_tlvs), WithoutLength(&eve_unblinded_tlvs)].iter(),
		&dave_eve_session_priv
	).unwrap();

	// Concatenate an additional Bob -> Carol blinded path to the Eve -> Dave blinded path.
	let bob_carol_session_priv = secret_from_hex("0202020202020202020202020202020202020202020202020202020202020202");
	let bob_blinding_point = PublicKey::from_secret_key(&secp_ctx, &bob_carol_session_priv);
	let bob_carol_blinded_hops = blinded_path::utils::construct_blinded_hops(
		&secp_ctx, [bob_node_id, carol_node_id].iter(),
		&mut [WithoutLength(&bob_unblinded_tlvs), WithoutLength(&carol_unblinded_tlvs)].iter(),
		&bob_carol_session_priv
	).unwrap();

	let mut blinded_hops = bob_carol_blinded_hops;
	blinded_hops.append(&mut dave_eve_blinded_hops);
	assert_eq!(
		vec![
			pubkey_from_hex("03da173ad2aee2f701f17e59fbd16cb708906d69838a5f088e8123fb36e89a2c25"),
			pubkey_from_hex("02e466727716f044290abf91a14a6d90e87487da160c2a3cbd0d465d7a78eb83a7"),
			pubkey_from_hex("036861b366f284f0a11738ffbf7eda46241a8977592878fe3175ae1d1e4754eccf"),
			pubkey_from_hex("021982a48086cb8984427d3727fe35a03d396b234f0701f5249daa12e8105c8dae")
		],
		blinded_hops.iter().map(|bh| bh.blinded_node_id).collect::<Vec<PublicKey>>()
	);
	assert_eq!(
		vec![
			bytes_from_hex("cd4100ff9c09ed28102b210ac73aa12d63e90852cebc496c49f57c49982088b49f2e70b99287fdee0aa58aa39913ab405813b999f66783aa2fe637b3cda91ffc0913c30324e2c6ce327e045183e4bffecb"),
			bytes_from_hex("cc0f16524fd7f8bb0b1d8d40ad71709ef140174c76faa574cac401bb8992fef76c4d004aa485dd599ed1cf2715f57ff62da5aaec5d7b10d59b04d8a9d77e472b9b3ecc2179334e411be22fa4c02b467c7e"),
			bytes_from_hex("0fa0a72cff3b64a3d6e1e4903cf8c8b0a17144aeb249dcb86561adee1f679ee8db3e561d9c43815fd4bcebf6f58c546da0cd8a9bf5cebd0d554802f6c0255e28e4a27343f761fe518cd897463187991105"),
			bytes_from_hex("da1a7e5f7881219884beae6ae68971de73bab4c3055d9865b1afb60724a2e4d3f0489ad884f7f3f77149209f0df51efd6b276294a02e3949c7254fbc8b5cab58212d9a78983e1cf86fe218b30c4ca8f6d8")
		],
		blinded_hops.iter().map(|bh| bh.encrypted_payload.clone()).collect::<Vec<Vec<u8>>>()
	);

	let mut amt_msat = 100_000;
	let session_priv = secret_from_hex("0303030303030303030303030303030303030303030303030303030303030303");
	let path = Path {
		hops: vec![RouteHop {
			pubkey: bob_node_id,
			node_features: NodeFeatures::empty(),
			short_channel_id: 42,
			channel_features: ChannelFeatures::empty(),
			fee_msat: 100,
			cltv_expiry_delta: 42,
			maybe_announced_channel: false,
		}],
		blinded_tail: Some(BlindedTail {
			hops: blinded_hops,
			blinding_point: bob_blinding_point,
			excess_final_cltv_expiry_delta: 0,
			final_value_msat: amt_msat
		}),
	};
	let cur_height = 747_000;
	let (bob_onion, _, _) = onion_utils::create_payment_onion(&secp_ctx, &path, &session_priv, amt_msat, &RecipientOnionFields::spontaneous_empty(), cur_height, &PaymentHash([0; 32]), &None, [0; 32]).unwrap();

	struct TestEcdhSigner {
		node_secret: SecretKey,
	}
	impl NodeSigner for TestEcdhSigner {
		fn ecdh(
			&self, _recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
		) -> Result<SharedSecret, ()> {
			let mut node_secret = self.node_secret.clone();
			if let Some(tweak) = tweak {
				node_secret = self.node_secret.mul_tweak(tweak).map_err(|_| ())?;
			}
			Ok(SharedSecret::new(other_key, &node_secret))
		}
		fn get_inbound_payment_key_material(&self) -> KeyMaterial { unreachable!() }
		fn get_node_id(&self, _recipient: Recipient) -> Result<PublicKey, ()> { unreachable!() }
		fn sign_invoice(
			&self, _invoice: &RawBolt11Invoice, _recipient: Recipient,
		) -> Result<RecoverableSignature, ()> { unreachable!() }
		fn sign_bolt12_invoice_request(
			&self, _invoice_request: &UnsignedInvoiceRequest,
		) -> Result<schnorr::Signature, ()> { unreachable!() }
		fn sign_bolt12_invoice(
			&self, _invoice: &UnsignedBolt12Invoice,
		) -> Result<schnorr::Signature, ()> { unreachable!() }
		fn sign_gossip_message(&self, _msg: UnsignedGossipMessage) -> Result<Signature, ()> { unreachable!() }
	}
	let logger = test_utils::TestLogger::with_id("".to_owned());

	let bob_update_add = update_add_msg(110_000, 747_500, None, bob_onion);
	let bob_node_signer = TestEcdhSigner { node_secret: bob_secret };
	// Can't use the public API here as we need to avoid the CLTV delta checks (test vector uses
	// < MIN_CLTV_EXPIRY_DELTA).
	let (bob_peeled_onion, _, next_packet_details_opt) =
		match onion_payment::decode_incoming_update_add_htlc_onion(
			&bob_update_add, &bob_node_signer, &logger, &secp_ctx
		) {
			Ok(res) => res,
			_ => panic!("Unexpected error")
		};
	let (carol_packet_bytes, carol_hmac) = if let onion_utils::Hop::Forward {
		next_hop_data: msgs::InboundOnionPayload::BlindedForward {
			short_channel_id, payment_relay, payment_constraints, features, intro_node_blinding_point, next_blinding_override
		}, next_hop_hmac, new_packet_bytes
	} = bob_peeled_onion {
		assert_eq!(short_channel_id, 1729);
		assert!(next_blinding_override.is_none());
		assert_eq!(intro_node_blinding_point, Some(bob_blinding_point));
		assert_eq!(payment_relay, PaymentRelay { cltv_expiry_delta: 36, fee_proportional_millionths: 150, fee_base_msat: 10_000 });
		assert_eq!(features, BlindedHopFeatures::empty());
		assert_eq!(payment_constraints, PaymentConstraints { max_cltv_expiry: 748_005, htlc_minimum_msat: 1500 });
		(new_packet_bytes, next_hop_hmac)
	} else { panic!() };

	let carol_packet_details = next_packet_details_opt.unwrap();
	let carol_onion = msgs::OnionPacket {
		version: 0,
		public_key: carol_packet_details.next_packet_pubkey,
		hop_data: carol_packet_bytes,
		hmac: carol_hmac,
	};
	let carol_update_add = update_add_msg(
		carol_packet_details.outgoing_amt_msat, carol_packet_details.outgoing_cltv_value,
		Some(pubkey_from_hex("034e09f450a80c3d252b258aba0a61215bf60dda3b0dc78ffb0736ea1259dfd8a0")),
		carol_onion
	);
	let carol_node_signer = TestEcdhSigner { node_secret: carol_secret };
	let (carol_peeled_onion, _, next_packet_details_opt) =
		match onion_payment::decode_incoming_update_add_htlc_onion(
			&carol_update_add, &carol_node_signer, &logger, &secp_ctx
		) {
			Ok(res) => res,
			_ => panic!("Unexpected error")
		};
	let (dave_packet_bytes, dave_hmac) = if let onion_utils::Hop::Forward {
		next_hop_data: msgs::InboundOnionPayload::BlindedForward {
			short_channel_id, payment_relay, payment_constraints, features, intro_node_blinding_point, next_blinding_override
		}, next_hop_hmac, new_packet_bytes
	} = carol_peeled_onion {
		assert_eq!(short_channel_id, 1105);
		assert_eq!(next_blinding_override, Some(pubkey_from_hex("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")));
		assert!(intro_node_blinding_point.is_none());
		assert_eq!(payment_relay, PaymentRelay { cltv_expiry_delta: 48, fee_proportional_millionths: 100, fee_base_msat: 500 });
		assert_eq!(features, BlindedHopFeatures::empty());
		assert_eq!(payment_constraints, PaymentConstraints { max_cltv_expiry: 747_969, htlc_minimum_msat: 1500 });
		(new_packet_bytes, next_hop_hmac)
	} else { panic!() };

	let dave_packet_details = next_packet_details_opt.unwrap();
	let dave_onion = msgs::OnionPacket {
		version: 0,
		public_key: dave_packet_details.next_packet_pubkey,
		hop_data: dave_packet_bytes,
		hmac: dave_hmac,
	};
	let dave_update_add = update_add_msg(
		dave_packet_details.outgoing_amt_msat, dave_packet_details.outgoing_cltv_value,
		Some(pubkey_from_hex("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")),
		dave_onion
	);
	let dave_node_signer = TestEcdhSigner { node_secret: dave_secret };
	let (dave_peeled_onion, _, next_packet_details_opt) =
		match onion_payment::decode_incoming_update_add_htlc_onion(
			&dave_update_add, &dave_node_signer, &logger, &secp_ctx
		) {
			Ok(res) => res,
			_ => panic!("Unexpected error")
		};
	let (eve_packet_bytes, eve_hmac) = if let onion_utils::Hop::Forward {
		next_hop_data: msgs::InboundOnionPayload::BlindedForward {
			short_channel_id, payment_relay, payment_constraints, features, intro_node_blinding_point, next_blinding_override
		}, next_hop_hmac, new_packet_bytes
	} = dave_peeled_onion {
		assert_eq!(short_channel_id, 561);
		assert!(next_blinding_override.is_none());
		assert!(intro_node_blinding_point.is_none());
		assert_eq!(payment_relay, PaymentRelay { cltv_expiry_delta: 144, fee_proportional_millionths: 250, fee_base_msat: 0 });
		assert_eq!(features, BlindedHopFeatures::empty());
		assert_eq!(payment_constraints, PaymentConstraints { max_cltv_expiry: 747_921, htlc_minimum_msat: 1500 });
		(new_packet_bytes, next_hop_hmac)
	} else { panic!() };

	let eve_packet_details = next_packet_details_opt.unwrap();
	let eve_onion = msgs::OnionPacket {
		version: 0,
		public_key: eve_packet_details.next_packet_pubkey,
		hop_data: eve_packet_bytes,
		hmac: eve_hmac,
	};
	let eve_update_add = update_add_msg(
		eve_packet_details.outgoing_amt_msat, eve_packet_details.outgoing_cltv_value,
		Some(pubkey_from_hex("03e09038ee76e50f444b19abf0a555e8697e035f62937168b80adf0931b31ce52a")),
		eve_onion
	);
	let eve_node_signer = TestEcdhSigner { node_secret: eve_secret };
	// We can't decode the final payload because it contains a path_id and is missing some LDK
	// specific fields.
	match onion_payment::decode_incoming_update_add_htlc_onion(
		&eve_update_add, &eve_node_signer, &logger, &secp_ctx
	) {
		Err(HTLCFailureMsg::Malformed(msg)) => assert_eq!(msg.failure_code, INVALID_ONION_BLINDING),
		_ => panic!("Unexpected error")
	}
}
