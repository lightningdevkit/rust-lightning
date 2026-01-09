// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::blinded_path::payment::{
	BlindedPaymentPath, Bolt12RefundContext, ForwardTlvs, PaymentConstraints, PaymentContext,
	PaymentForwardNode, PaymentRelay, ReceiveTlvs, PAYMENT_PADDING_ROUND_OFF,
};
use crate::blinded_path::utils::is_padded;
use crate::blinded_path::{self, BlindedHop};
use crate::events::{Event, HTLCHandlingFailureType, PaymentFailureReason};
use crate::ln::channelmanager::{self, HTLCFailureMsg, PaymentId, RecipientOnionFields};
use crate::ln::functional_test_utils::*;
use crate::ln::inbound_payment::ExpandedKey;
use crate::ln::msgs::{
	self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent, UnsignedGossipMessage,
};
use crate::ln::onion_payment;
use crate::ln::onion_utils::{self, LocalHTLCFailureReason};
use crate::ln::outbound_payment::{Retry, IDEMPOTENCY_TIMEOUT_TICKS};
use crate::ln::types::ChannelId;
use crate::offers::invoice::UnsignedBolt12Invoice;
use crate::prelude::*;
use crate::routing::router::{
	BlindedTail, Path, Payee, PaymentParameters, Route, RouteHop, RouteParameters, TrampolineHop,
};
use crate::sign::{NodeSigner, PeerStorageKey, ReceiveAuthKey, Recipient};
use crate::types::features::{BlindedHopFeatures, ChannelFeatures, NodeFeatures};
use crate::types::payment::{PaymentHash, PaymentSecret};
use crate::util::config::UserConfig;
use crate::util::ser::{WithoutLength, Writeable};
use crate::util::test_utils::{self, bytes_from_hex, pubkey_from_hex, secret_from_hex};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::{schnorr, All, PublicKey, Scalar, Secp256k1, SecretKey};
use lightning_invoice::RawBolt11Invoice;
use types::features::Features;

#[rustfmt::skip]
pub fn blinded_payment_path(
	payment_secret: PaymentSecret, intro_node_min_htlc: u64, intro_node_max_htlc: u64,
	node_ids: Vec<PublicKey>, channel_upds: &[&msgs::UnsignedChannelUpdate],
	keys_manager: &test_utils::TestKeysInterface
) -> BlindedPaymentPath {
	let mut intermediate_nodes = Vec::new();
	let mut intro_node_min_htlc_opt = Some(intro_node_min_htlc);
	let mut intro_node_max_htlc_opt = Some(intro_node_max_htlc);
	for (idx, (node_id, chan_upd)) in node_ids.iter().zip(channel_upds).enumerate() {
		intermediate_nodes.push(PaymentForwardNode {
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
		payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
	};

	let receive_auth_key = keys_manager.get_receive_auth_key();

	let mut secp_ctx = Secp256k1::new();
	BlindedPaymentPath::new(
		&intermediate_nodes[..], *node_ids.last().unwrap(), receive_auth_key,
		payee_tlvs, intro_node_max_htlc_opt.unwrap_or_else(|| channel_upds.last().unwrap().htlc_maximum_msat),
		TEST_FINAL_CLTV as u16, keys_manager, &secp_ctx
	).unwrap()
}

pub fn get_blinded_route_parameters(
	amt_msat: u64, payment_secret: PaymentSecret, intro_node_min_htlc: u64,
	intro_node_max_htlc: u64, node_ids: Vec<PublicKey>,
	channel_upds: &[&msgs::UnsignedChannelUpdate], keys_manager: &test_utils::TestKeysInterface,
) -> RouteParameters {
	RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_payment_path(
			payment_secret,
			intro_node_min_htlc,
			intro_node_max_htlc,
			node_ids,
			channel_upds,
			keys_manager,
		)]),
		amt_msat,
	)
}

#[rustfmt::skip]
pub fn fail_blinded_htlc_backwards(
	payment_hash: PaymentHash, intro_node_idx: usize, nodes: &[&Node],
	retry_expected: bool
) {
	for i in (0..nodes.len()).rev() {
		match i {
			0 => {
				let mut payment_failed_conditions = PaymentFailedConditions::new()
					.expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]);
				if retry_expected {
					payment_failed_conditions = payment_failed_conditions.retry_expected();
				}
				expect_payment_failed_conditions(&nodes[0], payment_hash, false, payment_failed_conditions);
			},
			i if i <= intro_node_idx => {
				let unblinded_node_updates = get_htlc_update_msgs(&nodes[i], &nodes[i-1].node.get_our_node_id());
				assert_eq!(unblinded_node_updates.update_fail_htlcs.len(), 1);
				nodes[i-1].node.handle_update_fail_htlc(
					nodes[i].node.get_our_node_id(), &unblinded_node_updates.update_fail_htlcs[i-1]
				);
				do_commitment_signed_dance(&nodes[i-1], &nodes[i], &unblinded_node_updates.commitment_signed, false, false);
			},
			_ => {
				let blinded_node_updates = get_htlc_update_msgs(&nodes[i], &nodes[i-1].node.get_our_node_id());
				assert_eq!(blinded_node_updates.update_fail_malformed_htlcs.len(), 1);
				let update_malformed = &blinded_node_updates.update_fail_malformed_htlcs[0];
				assert_eq!(update_malformed.sha256_of_onion, [0; 32]);
				assert_eq!(update_malformed.failure_code, LocalHTLCFailureReason::InvalidOnionBlinding.failure_code());
				nodes[i-1].node.handle_update_fail_malformed_htlc(nodes[i].node.get_our_node_id(), update_malformed);
				do_commitment_signed_dance(&nodes[i-1], &nodes[i], &blinded_node_updates.commitment_signed, true, false);
			}
		}
	}
}

#[test]
fn one_hop_blinded_path() {
	do_one_hop_blinded_path(true);
	do_one_hop_blinded_path(false);
}

#[rustfmt::skip]
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
		payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
	};
	let receive_auth_key = chanmon_cfgs[1].keys_manager.get_receive_auth_key();

	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPaymentPath::new(
		&[], nodes[1].node.get_our_node_id(), receive_auth_key,
		payee_tlvs, u64::MAX, TEST_FINAL_CLTV as u16,
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
#[rustfmt::skip]
fn mpp_to_one_hop_blinded_path() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	let mut secp_ctx = Secp256k1::new();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_upd_1_3 = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents;
	create_announced_chan_between_nodes(&nodes, 2, 3);

	// Ensure all nodes start at the same height.
	connect_blocks(&nodes[0], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[3].best_block_info().1);

	let amt_msat = 15_000_000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd_1_3.htlc_minimum_msat,
		},
		payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
	};
	let receive_auth_key = chanmon_cfgs[3].keys_manager.get_receive_auth_key();
	let blinded_path = BlindedPaymentPath::new(
		&[], nodes[3].node.get_our_node_id(), receive_auth_key,
		payee_tlvs, u64::MAX, TEST_FINAL_CLTV as u16,
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
	let event = pass_along_path(&nodes[0], expected_route[1], amt_msat, payment_hash.clone(),
		Some(payment_secret), ev.clone(), true, None);

	match event.unwrap() {
		Event::PaymentClaimable { mut receiving_channel_ids, .. } => {
			let mut expected_receiving_channel_ids = nodes[3].node.list_channels()
				.iter()
				.map(|d| (d.channel_id, Some(d.user_channel_id)))
				.collect::<Vec<(_, _)>>();

			// `list_channels` returns channels in arbitrary order, so we sort both vectors
			// to ensure the comparison is order-agnostic.
			receiving_channel_ids.sort();
			expected_receiving_channel_ids.sort();

			assert_eq!(receiving_channel_ids, expected_receiving_channel_ids);
		}
		_ => panic!("Unexpected event"),
	}

	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], expected_route, payment_preimage)
	);
}

#[test]
#[rustfmt::skip]
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

	// Start every node on the same block height to make reasoning about timeouts easier
	connect_blocks(&nodes[0], 6*CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 6*CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 6*CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], 6*CHAN_CONFIRM_DEPTH + 1 - nodes[3].best_block_info().1);
	connect_blocks(&nodes[4], 6*CHAN_CONFIRM_DEPTH + 1 - nodes[4].best_block_info().1);
	connect_blocks(&nodes[5], 6*CHAN_CONFIRM_DEPTH + 1 - nodes[5].best_block_info().1);

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

#[rustfmt::skip]
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
	let chan_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);
	let chan_upd_1_2 = chan_1_2.0.contents;
	let chan_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0);
	let chan_upd_2_3 = chan_2_3.0.contents;

	let amt_msat = 5000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let mut route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(),
		&[&chan_upd_1_2, &chan_upd_2_3], &chanmon_cfgs[3].keys_manager);
	route_params.payment_params.max_path_length = 16;

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
					let mut onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
					let cur_height = nodes[0].best_block_info().1;
					let (mut onion_payloads, ..) = onion_utils::build_onion_payloads(
						&route.paths[0], amt_msat, &recipient_onion_fields, cur_height, &None, None, None).unwrap();
					// Remove the receive payload so the blinded forward payload is encoded as a final payload
					// (i.e. next_hop_hmac == [0; 32])
					onion_payloads.pop();
					onion_keys.pop();
					if $target_node_idx + 1 < nodes.len() {
						onion_payloads.pop();
						onion_keys.pop();
					}
					$update_add.onion_routing_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash).unwrap();
				},
				ForwardCheckFail::OutboundChannelCheck => {
					// The intro node will see that the next-hop peer is disconnected and fail the HTLC backwards.
					nodes[$src_node_idx].node.peer_disconnected(nodes[$target_node_idx].node.get_our_node_id());
				}
			}
		}
	}

	let mut updates_0_1 = get_htlc_update_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
	let update_add = &mut updates_0_1.update_add_htlcs[0];

	if intro_fails {
		cause_error!(1, 2, update_add);
	}

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &updates_0_1.commitment_signed, true, true);

	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);

	if intro_fails {
		let mut updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
		let failed_destination = match check {
			ForwardCheckFail::InboundOnionCheck => HTLCHandlingFailureType::InvalidOnion,
			ForwardCheckFail::ForwardPayloadEncodedAsReceive => HTLCHandlingFailureType::InvalidOnion,
			ForwardCheckFail::OutboundChannelCheck =>
				HTLCHandlingFailureType::Forward { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_1_2.2 },
		};
		expect_htlc_handling_failed_destinations!(
			nodes[1].node.get_and_clear_pending_events(), core::slice::from_ref(&failed_destination)
		);
		match check {
			ForwardCheckFail::ForwardPayloadEncodedAsReceive => {
				expect_payment_failed_conditions(&nodes[0], payment_hash, false,
					PaymentFailedConditions::new().expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionPayload, &[0; 0]));
			}
			_ => {
				expect_payment_failed_conditions(&nodes[0], payment_hash, false,
					PaymentFailedConditions::new().expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]));
			}
		};
		return
	}

	let mut updates_1_2 = get_htlc_update_msgs(&nodes[1], &nodes[2].node.get_our_node_id());
	let mut update_add = &mut updates_1_2.update_add_htlcs[0];

	cause_error!(2, 3, update_add);

	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &update_add);
	check_added_monitors(&nodes[2], 0);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &updates_1_2.commitment_signed, true, true);

	expect_and_process_pending_htlcs(&nodes[2], false);
	let failed_destination = match check {
		ForwardCheckFail::InboundOnionCheck|ForwardCheckFail::ForwardPayloadEncodedAsReceive => HTLCHandlingFailureType::InvalidOnion,
		ForwardCheckFail::OutboundChannelCheck =>
			HTLCHandlingFailureType::Forward { node_id: Some(nodes[3].node.get_our_node_id()), channel_id: chan_2_3.2 },
	};
	expect_htlc_handling_failed_destinations!(
		nodes[2].node.get_and_clear_pending_events(), core::slice::from_ref(&failed_destination)
	);
	check_added_monitors(&nodes[2], 1);

	let mut updates = get_htlc_update_msgs(&nodes[2], &nodes[1].node.get_our_node_id());
	let update_malformed = &mut updates.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.failure_code, LocalHTLCFailureReason::InvalidOnionBlinding.failure_code());
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);

	// Ensure the intro node will properly blind the error if its downstream node failed to do so.
	update_malformed.sha256_of_onion = [1; 32];
	update_malformed.failure_code = LocalHTLCFailureReason::InvalidOnionBlinding.failure_code() ^ 1;
	nodes[1].node.handle_update_fail_malformed_htlc(nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, true, false);

	let mut updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]));
}

#[test]
#[rustfmt::skip]
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

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
	let mut payment_event = SendEvent::from_event(ev);

	// Ensure the final node fails to handle the HTLC.
	payment_event.msgs[0].onion_routing_packet.hop_data[0] ^= 1;
	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors(&nodes[2], 0);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event.commitment_msg, true, true);

	expect_and_process_pending_htlcs(&nodes[2], false);
	expect_htlc_handling_failed_destinations!(nodes[2].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::InvalidOnion]);
	check_added_monitors(&nodes[2], 1);

	let mut updates = get_htlc_update_msgs(&nodes[2], &nodes[1].node.get_our_node_id());
	let mut update_malformed = &mut updates.update_fail_malformed_htlcs[0];
	// Check that the final node encodes its failure correctly.
	assert_eq!(update_malformed.failure_code, LocalHTLCFailureReason::InvalidOnionBlinding.failure_code());
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);

	// Modify such the final hop does not correctly blind their error so we can ensure the intro node
	// converts it to the correct error.
	update_malformed.sha256_of_onion = [1; 32];
	nodes[1].node.handle_update_fail_malformed_htlc(nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, true, false);

	let mut updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]));
}

enum ProcessPendingHTLCsCheck {
	FwdPeerDisconnected,
	FwdChannelClosed,
}

#[test]
#[rustfmt::skip]
fn forward_fail_in_process_pending_htlc_fwds() {
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdPeerDisconnected, true);
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdPeerDisconnected, false);
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdChannelClosed, true);
	do_forward_fail_in_process_pending_htlc_fwds(ProcessPendingHTLCsCheck::FwdChannelClosed, false);
}
#[rustfmt::skip]
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

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);

	macro_rules! cause_error {
		($prev_node: expr, $curr_node: expr, $next_node: expr, $failed_chan_id: expr, $failed_scid: expr) => {
			match check {
				ProcessPendingHTLCsCheck::FwdPeerDisconnected => {
					// Disconnect the next-hop peer so when we go to forward in process_pending_htlc_forwards, the
					// intro node will error backwards.
					$curr_node.node.peer_disconnected($next_node.node.get_our_node_id());
					expect_and_process_pending_htlcs(&$curr_node, false);
					expect_htlc_handling_failed_destinations!($curr_node.node.get_and_clear_pending_events(),
						vec![HTLCHandlingFailureType::Forward { node_id: Some($next_node.node.get_our_node_id()), channel_id: $failed_chan_id }]);
				},
				ProcessPendingHTLCsCheck::FwdChannelClosed => {
					// Force close the next-hop channel so when we go to forward in process_pending_htlc_forwards,
					// the intro node will error backwards.
					$curr_node.node.force_close_broadcasting_latest_txn(&$failed_chan_id, &$next_node.node.get_our_node_id(), error_message.to_string()).unwrap();
					let events = $curr_node.node.get_and_clear_pending_events();
					match events[0] {
						crate::events::Event::ChannelClosed { .. } => {},
						_ => panic!("Unexpected event {:?}", events),
					}
					check_closed_broadcast(&$curr_node, 1, true);
					check_added_monitors(&$curr_node, 1);

					$curr_node.node.process_pending_htlc_forwards();
					expect_htlc_handling_failed_destinations!($curr_node.node.get_and_clear_pending_events(),
						vec![HTLCHandlingFailureType::InvalidForward { requested_forward_scid: $failed_scid }]);
				},
			}
		}
	}

	if intro_fails {
		cause_error!(nodes[0], nodes[1], nodes[2], chan_id_1_2, chan_upd_1_2.short_channel_id);
		check_added_monitors(&nodes[1], 1);
		fail_blinded_htlc_backwards(payment_hash, 1, &[&nodes[0], &nodes[1]], false);
		return
	}

	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);

	let mut updates_1_2 = get_htlc_update_msgs(&nodes[1], &nodes[2].node.get_our_node_id());
	let mut update_add = &mut updates_1_2.update_add_htlcs[0];
	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &update_add);
	check_added_monitors(&nodes[2], 0);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &updates_1_2.commitment_signed, true, true);

	cause_error!(nodes[1], nodes[2], nodes[3], chan_id_2_3, chan_upd_2_3.short_channel_id);
	check_added_monitors(&nodes[2], 1);

	let mut updates = get_htlc_update_msgs(&nodes[2], &nodes[1].node.get_our_node_id());
	let update_malformed = &mut updates.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.failure_code, LocalHTLCFailureReason::InvalidOnionBlinding.failure_code());
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);

	// Ensure the intro node will properly blind the error if its downstream node failed to do so.
	update_malformed.sha256_of_onion = [1; 32];
	update_malformed.failure_code = LocalHTLCFailureReason::InvalidOnionBlinding.failure_code() ^ 1;
	nodes[1].node.handle_update_fail_malformed_htlc(nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, true, false);

	let mut updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]));
}

#[test]
fn blinded_intercept_payment() {
	do_blinded_intercept_payment(true);
	do_blinded_intercept_payment(false);
}

#[rustfmt::skip]
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
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);

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
		expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::InvalidForward { requested_forward_scid: intercept_scid }]);
		nodes[1].node.process_pending_htlc_forwards();
		check_added_monitors(&nodes[1], 1);
		fail_blinded_htlc_backwards(payment_hash, 1, &[&nodes[0], &nodes[1]], false);
		return
	}

	nodes[1].node.forward_intercepted_htlc(intercept_id, &channel_id, nodes[2].node.get_our_node_id(), expected_outbound_amount_msat).unwrap();
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
	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event.commitment_msg, false, true);
	expect_and_process_pending_htlcs(&nodes[2], false);

	expect_payment_claimable!(&nodes[2], payment_hash, payment_secret, amt_msat, None, nodes[2].node.get_our_node_id());
	do_claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2]]], payment_preimage)
	);
	expect_payment_sent(&nodes[0], payment_preimage, Some(Some(1000)), true, true);
}

#[test]
#[rustfmt::skip]
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
#[rustfmt::skip]
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
#[rustfmt::skip]
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
	expect_htlc_failure_conditions(
		nodes[3].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash }]
	);
	nodes[3].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[3], 1);
	fail_blinded_htlc_backwards(payment_hash, 1, &[&nodes[0], &nodes[1], &nodes[2], &nodes[3]], false);
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

#[rustfmt::skip]
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

	route_params.payment_params.max_path_length = 17;

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
				route_hints[0].clone()
			} else { panic!() }
		};
		if let Payee::Blinded { ref mut route_hints, .. } = route_params.payment_params.payee {
			route_hints[0] = high_htlc_min_bp;
			route_hints[0].payinfo.htlc_minimum_msat = amt_msat;
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
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event_0_1.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event_0_1.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);

	let mut payment_event_1_2 = {
		let mut events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let ev = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut events);
		SendEvent::from_event(ev)
	};

	match check {
		ReceiveCheckFail::RecipientFail => {
			nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &payment_event_1_2.msgs[0]);
			check_added_monitors(&nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
			expect_and_process_pending_htlcs(&nodes[2], false);
			check_payment_claimable(
				&nodes[2].node.get_and_clear_pending_events()[0], payment_hash, payment_secret, amt_msat,
				None, nodes[2].node.get_our_node_id()
			);
			nodes[2].node.fail_htlc_backwards(&payment_hash);
			expect_htlc_failure_conditions(
				nodes[2].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash }]
			);
			nodes[2].node.process_pending_htlc_forwards();
			check_added_monitors(&nodes[2], 1);
		},
		ReceiveCheckFail::OnionDecodeFail => {
			let session_priv = SecretKey::from_slice(&session_priv).unwrap();
			let mut onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let cur_height = nodes[0].best_block_info().1;
			let recipient_onion_fields = RecipientOnionFields::spontaneous_empty();
			let (mut onion_payloads, ..) = onion_utils::build_onion_payloads(
				&route.paths[0], amt_msat, &recipient_onion_fields, cur_height, &None, None, None).unwrap();

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
			nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), update_add);
			check_added_monitors(&nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
			expect_and_process_pending_htlcs(&nodes[2], false);
			expect_htlc_handling_failed_destinations!(nodes[2].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::InvalidOnion]);
			check_added_monitors(&nodes[2], 1);
		},
		ReceiveCheckFail::ReceiveRequirements => {
			let update_add = &mut payment_event_1_2.msgs[0];
			update_add.amount_msat -= 1;
			nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), update_add);
			check_added_monitors(&nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
			expect_and_process_pending_htlcs(&nodes[2], false);
			expect_htlc_handling_failed_destinations!(nodes[2].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash }]);
			check_added_monitors(&nodes[2], 1);
		},
		ReceiveCheckFail::ChannelCheck => {
			nodes[2].node.close_channel(&chan_id_1_2, &nodes[1].node.get_our_node_id()).unwrap();
			let node_2_shutdown = get_event_msg!(nodes[2], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_shutdown(nodes[2].node.get_our_node_id(), &node_2_shutdown);
			let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());

			nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &payment_event_1_2.msgs[0]);
			nodes[2].node.handle_commitment_signed_batch_test(nodes[1].node.get_our_node_id(), &payment_event_1_2.commitment_msg);
			check_added_monitors(&nodes[2], 1);

			nodes[2].node.handle_shutdown(nodes[1].node.get_our_node_id(), &node_1_shutdown);
			assert!(commitment_signed_dance_through_cp_raa(&nodes[2], &nodes[1], false, false).is_none());
			expect_and_process_pending_htlcs(&nodes[2], false);
			expect_htlc_handling_failed_destinations!(nodes[2].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash }]);
			check_added_monitors(&nodes[2], 1);
		},
		ReceiveCheckFail::ProcessPendingHTLCsCheck => {
			assert_eq!(payment_event_1_2.msgs[0].cltv_expiry, nodes[0].best_block_info().1 + 1 + excess_final_cltv_delta_opt.unwrap() as u32 + TEST_FINAL_CLTV);
			nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &payment_event_1_2.msgs[0]);
			check_added_monitors(&nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
			expect_and_process_pending_htlcs(&nodes[2], true);
			expect_htlc_failure_conditions(nodes[2].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash }]);
			check_added_monitors(&nodes[2], 1);
		},
		ReceiveCheckFail::PaymentConstraints => {
			nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &payment_event_1_2.msgs[0]);
			check_added_monitors(&nodes[2], 0);
			do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event_1_2.commitment_msg, true, true);
			expect_and_process_pending_htlcs(&nodes[2], false);
			expect_htlc_handling_failed_destinations!(nodes[2].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash }]);
			check_added_monitors(&nodes[2], 1);
		}
	}

	let updates_2_1 = get_htlc_update_msgs(&nodes[2], &nodes[1].node.get_our_node_id());
	assert_eq!(updates_2_1.update_fail_malformed_htlcs.len(), 1);
	let update_malformed = &updates_2_1.update_fail_malformed_htlcs[0];
	assert_eq!(update_malformed.sha256_of_onion, [0; 32]);
	assert_eq!(update_malformed.failure_code, LocalHTLCFailureReason::InvalidOnionBlinding.failure_code());
	nodes[1].node.handle_update_fail_malformed_htlc(nodes[2].node.get_our_node_id(), update_malformed);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates_2_1.commitment_signed, true, false);

	let updates_1_0 = if check == ReceiveCheckFail::ChannelCheck {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		events.into_iter().find_map(|ev| {
			match ev {
				MessageSendEvent::UpdateHTLCs { node_id, channel_id: _, updates } => {
					assert_eq!(node_id, nodes[0].node.get_our_node_id());
					return Some(updates)
				},
				MessageSendEvent::SendClosingSigned { .. } => None,
				_ => panic!()
			}
		}).unwrap()
	} else { get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id()) };
	assert_eq!(updates_1_0.update_fail_htlcs.len(), 1);
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates_1_0.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates_1_0.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]));
}

#[test]
#[rustfmt::skip]
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

	// Ensure all nodes start at the same height.
	connect_blocks(&nodes[0], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], 4*CHAN_CONFIRM_DEPTH + 1 - nodes[3].best_block_info().1);

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
			expect_htlc_failure_conditions(
				nodes[3].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::Receive { payment_hash }]
			);
			nodes[3].node.process_pending_htlc_forwards();
			check_added_monitors(&nodes[3], 1);

			let updates = get_htlc_update_msgs(&nodes[3], &$intro_node.node.get_our_node_id());
			assert_eq!(updates.update_fail_malformed_htlcs.len(), 1);
			let update_malformed = &updates.update_fail_malformed_htlcs[0];
			assert_eq!(update_malformed.sha256_of_onion, [0; 32]);
			assert_eq!(update_malformed.failure_code, LocalHTLCFailureReason::InvalidOnionBlinding.failure_code());
			$intro_node.node.handle_update_fail_malformed_htlc(nodes[3].node.get_our_node_id(), update_malformed);
			do_commitment_signed_dance(&$intro_node, &nodes[3], &updates.commitment_signed, true, false);

			let updates =  get_htlc_update_msgs(&$intro_node, &nodes[0].node.get_our_node_id());
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			nodes[0].node.handle_update_fail_htlc($intro_node.node.get_our_node_id(), &updates.update_fail_htlcs[0]);
			do_commitment_signed_dance(&nodes[0], &$intro_node, &updates.commitment_signed, false, false);

			let mut events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				Event::PaymentPathFailed { payment_hash: ev_payment_hash, payment_failed_permanently, ..  } => {
					assert_eq!(payment_hash, ev_payment_hash);
					assert_eq!(payment_failed_permanently, false);
				},
				_ => panic!("Unexpected event"),
			}
			nodes[0].node.process_pending_htlc_forwards();
		}
	}

	fail_payment_back!(nodes[1]);

	// Pass the retry along.
	check_added_monitors(&nodes[0], 1);
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
#[rustfmt::skip]
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
		route_params.payment_params.payee.blinded_route_hints()[0].payinfo.htlc_minimum_msat);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3]]], min_htlc_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], payment_preimage);

	// Paying 1 less than the min fails.
	for _ in 0..IDEMPOTENCY_TIMEOUT_TICKS + 1 {
		nodes[0].node.timer_tick_occurred();
	}
	if let Payee::Blinded { ref mut route_hints, .. } = route_params.payment_params.payee {
		route_hints[0].payinfo.htlc_minimum_msat -= 1;
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
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event_0_1.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event_0_1.commitment_msg, true, true);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Forward { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_1_2.2 }]
	);
	check_added_monitors(&nodes[1], 1);
	let mut updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false,
		PaymentFailedConditions::new().expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]));
}

#[test]
#[rustfmt::skip]
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
#[rustfmt::skip]
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
		payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
	};
	let receive_auth_key = chanmon_cfgs[1].keys_manager.get_receive_auth_key();

	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPaymentPath::new(
		&[], nodes[1].node.get_our_node_id(), receive_auth_key,
		payee_tlvs, u64::MAX, TEST_FINAL_CLTV as u16,
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

#[test]
#[rustfmt::skip]
fn fails_receive_tlvs_authentication() {
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
		payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
	};
	let receive_auth_key = chanmon_cfgs[1].keys_manager.get_receive_auth_key();

	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPaymentPath::new(
		&[], nodes[1].node.get_our_node_id(), receive_auth_key,
		payee_tlvs, u64::MAX, TEST_FINAL_CLTV as u16,
		&chanmon_cfgs[1].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_path]),
		amt_msat,
	);

	// Test authentication works normally.
	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1]]], amt_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	// Swap in a different nonce to force authentication to fail.
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[1], Some(amt_msat), None);
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd.htlc_minimum_msat,
		},
		payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
	};
	// Use a mismatched ReceiveAuthKey to force auth failure:
	let mismatched_receive_auth_key = ReceiveAuthKey([0u8; 32]);

	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPaymentPath::new(
		&[], nodes[1].node.get_our_node_id(), mismatched_receive_auth_key,
		payee_tlvs, u64::MAX, TEST_FINAL_CLTV as u16,
		&chanmon_cfgs[1].keys_manager, &secp_ctx
	).unwrap();

	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_path]),
		amt_msat,
	);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let mut payment_event = SendEvent::from_event(ev);

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, true, true);
	expect_and_process_pending_htlcs(&nodes[1], false);
	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[1], 1);
	expect_htlc_handling_failed_destinations!(nodes[1].node.get_and_clear_pending_events(), &[HTLCHandlingFailureType::InvalidOnion]);

	let mut update_fail = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
	assert!(update_fail.update_fail_htlcs.len() == 1);
	let fail_msg = &update_fail.update_fail_htlcs[0];
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), fail_msg);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &update_fail.commitment_signed, false, false);
	expect_payment_failed_conditions(
		&nodes[0], payment_hash, true,
		PaymentFailedConditions::new().expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionPayload, &[]),
	);
}

#[test]
#[rustfmt::skip]
fn blinded_payment_path_padding() {
	// Make sure that for a blinded payment path, all encrypted payloads are padded to equal lengths.
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

	let blinded_path = blinded_payment_path(payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(2).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_2_3, &chan_upd_3_4],
		&chanmon_cfgs[4].keys_manager
	);

	assert!(is_padded(&blinded_path.blinded_hops(), PAYMENT_PADDING_ROUND_OFF));

	let route_params = RouteParameters::from_payment_params_and_value(PaymentParameters::blinded(vec![blinded_path]), amt_msat);

	nodes[0].node.send_payment(payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0), route_params, Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3], &nodes[4]]], amt_msat, payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]], payment_preimage);
}

fn update_add_msg(
	amount_msat: u64, cltv_expiry: u32, blinding_point: Option<PublicKey>,
	onion_routing_packet: msgs::OnionPacket,
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
		hold_htlc: None,
		accountable: None,
	}
}

#[test]
#[rustfmt::skip]
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
	let path = [
		((dave_node_id, None), WithoutLength(&dave_unblinded_tlvs)),
		((eve_node_id, None), WithoutLength(&eve_unblinded_tlvs)),
	];
	let mut dave_eve_blinded_hops = blinded_path::utils::construct_blinded_hops(
		&secp_ctx, path.into_iter(), &dave_eve_session_priv,
	);

	// Concatenate an additional Bob -> Carol blinded path to the Eve -> Dave blinded path.
	let bob_carol_session_priv = secret_from_hex("0202020202020202020202020202020202020202020202020202020202020202");
	let bob_blinding_point = PublicKey::from_secret_key(&secp_ctx, &bob_carol_session_priv);
	let path = [
		((bob_node_id, None), WithoutLength(&bob_unblinded_tlvs)),
		((carol_node_id, None), WithoutLength(&carol_unblinded_tlvs)),
	];
	let bob_carol_blinded_hops = blinded_path::utils::construct_blinded_hops(
		&secp_ctx, path.into_iter(), &bob_carol_session_priv,
	);

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
			trampoline_hops: vec![],
			hops: blinded_hops,
			blinding_point: bob_blinding_point,
			excess_final_cltv_expiry_delta: 0,
			final_value_msat: amt_msat
		}),
	};
	let cur_height = 747_000;
	let (bob_onion, _, _) = onion_utils::create_payment_onion(&secp_ctx, &path, &session_priv, amt_msat, &RecipientOnionFields::spontaneous_empty(), cur_height, &PaymentHash([0; 32]), &None, None, [0; 32]).unwrap();

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
		fn get_expanded_key(&self) -> ExpandedKey { unreachable!() }
		fn get_node_id(&self, _recipient: Recipient) -> Result<PublicKey, ()> { unreachable!() }
		fn sign_invoice(
			&self, _invoice: &RawBolt11Invoice, _recipient: Recipient,
		) -> Result<RecoverableSignature, ()> { unreachable!() }
		fn get_peer_storage_key(&self) -> PeerStorageKey { unreachable!() }
		fn get_receive_auth_key(&self) -> ReceiveAuthKey { ReceiveAuthKey([41; 32]) }
		fn sign_bolt12_invoice(
			&self, _invoice: &UnsignedBolt12Invoice,
		) -> Result<schnorr::Signature, ()> { unreachable!() }
		fn sign_gossip_message(&self, _msg: UnsignedGossipMessage) -> Result<Signature, ()> { unreachable!() }

		fn sign_message(&self, msg: &[u8]) -> Result<String, ()> { Ok(crate::util::message_signing::sign(msg, &self.node_secret)) }
	}
	let logger = test_utils::TestLogger::with_id("".to_owned());

	let bob_update_add = update_add_msg(110_000, 747_500, None, bob_onion);
	let bob_node_signer = TestEcdhSigner { node_secret: bob_secret };
	// Can't use the public API here as we need to avoid the CLTV delta checks (test vector uses
	// < MIN_CLTV_EXPIRY_DELTA).
	let (bob_peeled_onion, next_packet_details_opt) =
		match onion_payment::decode_incoming_update_add_htlc_onion(
			&bob_update_add, &bob_node_signer, &logger, &secp_ctx
		) {
			Ok(res) => res,
			_ => panic!("Unexpected error")
		};
	let (carol_packet_bytes, carol_hmac) = if let onion_utils::Hop::BlindedForward {
		next_hop_data: msgs::InboundOnionBlindedForwardPayload {
			short_channel_id, payment_relay, payment_constraints, features, intro_node_blinding_point, next_blinding_override
		}, next_hop_hmac, new_packet_bytes, ..
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
	let (carol_peeled_onion, next_packet_details_opt) =
		match onion_payment::decode_incoming_update_add_htlc_onion(
			&carol_update_add, &carol_node_signer, &logger, &secp_ctx
		) {
			Ok(res) => res,
			_ => panic!("Unexpected error")
		};
	let (dave_packet_bytes, dave_hmac) = if let onion_utils::Hop::BlindedForward {
		next_hop_data: msgs::InboundOnionBlindedForwardPayload {
			short_channel_id, payment_relay, payment_constraints, features, intro_node_blinding_point, next_blinding_override
		}, next_hop_hmac, new_packet_bytes, ..
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
	let (dave_peeled_onion, next_packet_details_opt) =
		match onion_payment::decode_incoming_update_add_htlc_onion(
			&dave_update_add, &dave_node_signer, &logger, &secp_ctx
		) {
			Ok(res) => res,
			_ => panic!("Unexpected error")
		};
	let (eve_packet_bytes, eve_hmac) = if let onion_utils::Hop::BlindedForward {
		next_hop_data: msgs::InboundOnionBlindedForwardPayload {
			short_channel_id, payment_relay, payment_constraints, features, intro_node_blinding_point, next_blinding_override
		}, next_hop_hmac, new_packet_bytes, ..
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
		Err((HTLCFailureMsg::Malformed(msg), _)) => assert_eq!(msg.failure_code,
			LocalHTLCFailureReason::InvalidOnionBlinding.failure_code()),
		_ => panic!("Unexpected error")
	}
}

#[test]
#[rustfmt::skip]
fn test_combined_trampoline_onion_creation_vectors() {
	// As per https://github.com/lightning/bolts/blob/fa0594ac2af3531d734f1d707a146d6e13679451/bolt04/trampoline-to-blinded-path-payment-onion-test.json#L251

	let mut secp_ctx = Secp256k1::new();
	let session_priv = secret_from_hex("a64feb81abd58e473df290e9e1c07dc3e56114495cadf33191f44ba5448ebe99");

	let path = Path {
		hops: vec![
			// Bob
			RouteHop {
				pubkey: pubkey_from_hex("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"),
				node_features: NodeFeatures::empty(),
				short_channel_id: 0,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 3_000,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			},

			// Carol
			RouteHop {
				pubkey: pubkey_from_hex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007"),
				node_features: NodeFeatures::empty(),
				short_channel_id: (572330 << 40) + (42 << 16) + 2821,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 153_000,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			},
		],
		blinded_tail: Some(BlindedTail {
			trampoline_hops: vec![
				// Carol's pubkey
				TrampolineHop {
					pubkey: pubkey_from_hex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007"),
					node_features: Features::empty(),
					fee_msat: 2_500,
					cltv_expiry_delta: 24,
				},
				// Dave's pubkey (the intro node needs to be duplicated)
				TrampolineHop {
					pubkey: pubkey_from_hex("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"),
					node_features: Features::empty(),
					fee_msat: 150_500, // incorporate both base and proportional fee
					cltv_expiry_delta: 36,
				}
			],
			hops: vec![
				// Dave's blinded node id
				BlindedHop {
					blinded_node_id: pubkey_from_hex("0295d40514096a8be54859e7dfe947b376eaafea8afe5cb4eb2c13ff857ed0b4be"),
					encrypted_payload: bytes_from_hex("0ccf3c8a58deaa603f657ee2a5ed9d604eb5c8ca1e5f801989afa8f3ea6d789bbdde2c7e7a1ef9ca8c38d2c54760febad8446d3f273ddb537569ef56613846ccd3aba78a"),
				},
				// Eve's blinded node id
				BlindedHop {
					blinded_node_id: pubkey_from_hex("020e2dbadcc2005e859819ddebbe88a834ae8a6d2b049233c07335f15cd1dc5f22"),
					encrypted_payload: bytes_from_hex("bcd747394fbd4d99588da075a623316e15a576df5bc785cccc7cd6ec7b398acce6faf520175f9ec920f2ef261cdb83dc28cc3a0eeb970107b3306489bf771ef5b1213bca811d345285405861d08a655b6c237fa247a8b4491beee20c878a60e9816492026d8feb9dafa84585b253978db6a0aa2945df5ef445c61e801fb82f43d5f00716baf9fc9b3de50bc22950a36bda8fc27bfb1242e5860c7e687438d4133e058770361a19b6c271a2a07788d34dccc27e39b9829b061a4d960eac4a2c2b0f4de506c24f9af3868c0aff6dda27281c"),
				}
			],
			blinding_point: pubkey_from_hex("02988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e"),
			excess_final_cltv_expiry_delta: 0,
			final_value_msat: 150_000_000
		}),
	};

	let associated_data_slice = secret_from_hex("e89bc505e84aaca09613833fc58c9069078fb43bfbea0488f34eec9db99b5f82");
	let associated_data = PaymentHash(associated_data_slice.secret_bytes());
	let payment_secret = PaymentSecret(secret_from_hex("7494b65bc092b48a75465e43e29be807eb2cc535ce8aaba31012b8ff1ceac5da").secret_bytes());
	let outer_session_key = secret_from_hex("4f777e8dac16e6dfe333066d9efb014f7a51d11762ff76eca4d3a95ada99ba3e");
	let outer_onion_prng_seed = onion_utils::gen_pad_from_shared_secret(&outer_session_key.secret_bytes());

	let amt_msat = 150_000_000;
	let cur_height = 800_000;
	let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
	let (bob_onion, htlc_msat, htlc_cltv) = onion_utils::create_payment_onion_internal(&secp_ctx, &path, &outer_session_key, amt_msat, &recipient_onion_fields, cur_height, &associated_data, &None, None, outer_onion_prng_seed, Some(session_priv), Some([0; 32])).unwrap();

	let outer_onion_packet_hex = bob_onion.encode().to_lower_hex_string();
	assert_eq!(outer_onion_packet_hex, "00025fd60556c134ae97e4baedba220a644037754ee67c54fd05e93bf40c17cbb73362fb9dee96001ff229945595b6edb59437a6bc143406d3f90f749892a84d8d430c6890437d26d5bfc599d565316ef51347521075bbab87c59c57bcf20af7e63d7192b46cf171e4f73cb11f9f603915389105d91ad630224bea95d735e3988add1e24b5bf28f1d7128db64284d90a839ba340d088c74b1fb1bd21136b1809428ec5399c8649e9bdf92d2dcfc694deae5046fa5b2bdf646847aaad73f5e95275763091c90e71031cae1f9a770fdea559642c9c02f424a2a28163dd0957e3874bd28a97bec67d18c0321b0e68bc804aa8345b17cb626e2348ca06c8312a167c989521056b0f25c55559d446507d6c491d50605cb79fa87929ce64b0a9860926eeaec2c431d926a1cadb9a1186e4061cb01671a122fc1f57602cbef06d6c194ec4b715c2e3dd4120baca3172cd81900b49fef857fb6d6afd24c983b608108b0a5ac0c1c6c52011f23b8778059ffadd1bb7cd06e2525417365f485a7fd1d4a9ba3818ede7cdc9e71afee8532252d08e2531ca52538655b7e8d912f7ec6d37bbcce8d7ec690709dbf9321e92c565b78e7fe2c22edf23e0902153d1ca15a112ad32fb19695ec65ce11ddf670da7915f05ad4b86c154fb908cb567315d1124f303f75fa075ebde8ef7bb12e27737ad9e4924439097338ea6d7a6fc3721b88c9b830a34e8d55f4c582b74a3895cc848fe57f4fe29f115dabeb6b3175be15d94408ed6771109cfaf57067ae658201082eae7605d26b1449af4425ae8e8f58cdda5c6265f1fd7a386fc6cea3074e4f25b909b96175883676f7610a00fdf34df9eb6c7b9a4ae89b839c69fd1f285e38cdceb634d782cc6d81179759bc9fd47d7fd060470d0b048287764c6837963274e708314f017ac7dc26d0554d59bfcfd3136225798f65f0b0fea337c6b256ebbb63a90b994c0ab93fd8b1d6bd4c74aebe535d6110014cd3d525394027dfe8faa98b4e9b2bee7949eb1961f1b026791092f84deea63afab66603dbe9b6365a102a1fef2f6b9744bc1bb091a8da9130d34d4d39f25dbad191649cfb67e10246364b7ce0c6ec072f9690cabb459d9fda0c849e17535de4357e9907270c75953fca3c845bb613926ecf73205219c7057a4b6bb244c184362bb4e2f24279dc4e60b94a5b1ec11c34081a628428ba5646c995b9558821053ba9c84a05afbf00dabd60223723096516d2f5668f3ec7e11612b01eb7a3a0506189a2272b88e89807943adb34291a17f6cb5516ffd6f945a1c42a524b21f096d66f350b1dad4db455741ae3d0e023309fbda5ef55fb0dc74f3297041448b2be76c525141963934c6afc53d263fb7836626df502d7c2ee9e79cbbd87afd84bbb8dfbf45248af3cd61ad5fac827e7683ca4f91dfad507a8eb9c17b2c9ac5ec051fe645a4a6cb37136f6f19b611e0ea8da7960af2d779507e55f57305bc74b7568928c5dd5132990fe54c22117df91c257d8c7b61935a018a28c1c3b17bab8e4294fa699161ec21123c9fc4e71079df31f300c2822e1246561e04765d3aab333eafd026c7431ac7616debb0e022746f4538e1c6348b600c988eeb2d051fc60c468dca260a84c79ab3ab8342dc345a764672848ea234e17332bc124799daf7c5fcb2e2358514a7461357e1c19c802c5ee32deccf1776885dd825bedd5f781d459984370a6b7ae885d4483a76ddb19b30f47ed47cd56aa5a079a89793dbcad461c59f2e002067ac98dd5a534e525c9c46c2af730741bf1f8629357ec0bfc0bc9ecb31af96777e507648ff4260dc3673716e098d9111dfd245f1d7c55a6de340deb8bd7a053e5d62d760f184dc70ca8fa255b9023b9b9aedfb6e419a5b5951ba0f83b603793830ee68d442d7b88ee1bbf6bbd1bcd6f68cc1af");
	assert_eq!(htlc_msat, 150_156_000);
	assert_eq!(htlc_cltv, 800_060);
}

#[test]
#[rustfmt::skip]
fn test_trampoline_inbound_payment_decoding() {
	let secp_ctx = Secp256k1::new();
	let session_priv = secret_from_hex("0303030303030303030303030303030303030303030303030303030303030303");

	let bob_secret = secret_from_hex("4242424242424242424242424242424242424242424242424242424242424242");
	let bob_node_id = PublicKey::from_secret_key(&secp_ctx, &bob_secret);
	let _bob_unblinded_tlvs = bytes_from_hex("011a0000000000000000000000000000000000000000000000000000020800000000000006c10a0800240000009627100c06000b69e505dc0e00fd023103123456");
	let carol_secret = secret_from_hex("4343434343434343434343434343434343434343434343434343434343434343");
	let carol_node_id = PublicKey::from_secret_key(&secp_ctx, &carol_secret);
	let _carol_unblinded_tlvs = bytes_from_hex("020800000000000004510821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0a0800300000006401f40c06000b69c105dc0e00");
	let dave_secret = secret_from_hex("4444444444444444444444444444444444444444444444444444444444444444");
	let dave_node_id = PublicKey::from_secret_key(&secp_ctx, &dave_secret);
	let _dave_unblinded_tlvs = bytes_from_hex("01230000000000000000000000000000000000000000000000000000000000000000000000020800000000000002310a060090000000fa0c06000b699105dc0e00");
	let eve_secret = secret_from_hex("4545454545454545454545454545454545454545454545454545454545454545");
	let _eve_node_id = PublicKey::from_secret_key(&secp_ctx, &eve_secret);
	let _eve_unblinded_tlvs = bytes_from_hex("011a00000000000000000000000000000000000000000000000000000604deadbeef0c06000b690105dc0e0f020000000000000000000000000000fdffff0206c1");

	let path = Path {
		hops: vec![
			// Bob
			RouteHop {
				pubkey: bob_node_id,
				node_features: NodeFeatures::empty(),
				short_channel_id: 0,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 0,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			},

			// Carol
			RouteHop {
				pubkey: carol_node_id,
				node_features: NodeFeatures::empty(),
				short_channel_id: (572330 << 40) + (42 << 16) + 2821,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 150_153_000,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			},
		],
		blinded_tail: Some(BlindedTail {
			trampoline_hops: vec![
				// Carol's pubkey
				TrampolineHop {
					pubkey: carol_node_id,
					node_features: Features::empty(),
					fee_msat: 2_500,
					cltv_expiry_delta: 24,
				},
				// Dave's pubkey (the intro node needs to be duplicated)
				TrampolineHop {
					pubkey: dave_node_id,
					node_features: Features::empty(),
					fee_msat: 150_500, // incorporate both base and proportional fee
					cltv_expiry_delta: 36,
				}
			],
			hops: vec![
				// Dave's blinded node id
				BlindedHop {
					blinded_node_id: pubkey_from_hex("0295d40514096a8be54859e7dfe947b376eaafea8afe5cb4eb2c13ff857ed0b4be"),
					encrypted_payload: bytes_from_hex("0ccf3c8a58deaa603f657ee2a5ed9d604eb5c8ca1e5f801989afa8f3ea6d789bbdde2c7e7a1ef9ca8c38d2c54760febad8446d3f273ddb537569ef56613846ccd3aba78a"),
				},
				// Eve's blinded node id
				BlindedHop {
					blinded_node_id: pubkey_from_hex("020e2dbadcc2005e859819ddebbe88a834ae8a6d2b049233c07335f15cd1dc5f22"),
					encrypted_payload: bytes_from_hex("bcd747394fbd4d99588da075a623316e15a576df5bc785cccc7cd6ec7b398acce6faf520175f9ec920f2ef261cdb83dc28cc3a0eeb970107b3306489bf771ef5b1213bca811d345285405861d08a655b6c237fa247a8b4491beee20c878a60e9816492026d8feb9dafa84585b253978db6a0aa2945df5ef445c61e801fb82f43d5f00716baf9fc9b3de50bc22950a36bda8fc27bfb1242e5860c7e687438d4133e058770361a19b6c271a2a07788d34dccc27e39b9829b061a4d960eac4a2c2b0f4de506c24f9af3868c0aff6dda27281c"),
				}
			],
			blinding_point: pubkey_from_hex("02988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e"),
			excess_final_cltv_expiry_delta: 0,
			final_value_msat: 150_000_000
		})
	};

	let payment_secret = PaymentSecret(secret_from_hex("7494b65bc092b48a75465e43e29be807eb2cc535ce8aaba31012b8ff1ceac5da").secret_bytes());

	let amt_msat = 150_000_001;
	let cur_height = 800_001;
	let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
	let (bob_onion, _, _) = onion_utils::create_payment_onion(&secp_ctx, &path, &session_priv, amt_msat, &recipient_onion_fields, cur_height, &PaymentHash([0; 32]), &None, None, [0; 32]).unwrap();

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
		fn get_expanded_key(&self) -> ExpandedKey { unreachable!() }
		fn get_node_id(&self, _recipient: Recipient) -> Result<PublicKey, ()> { unreachable!() }
		fn sign_invoice(
			&self, _invoice: &RawBolt11Invoice, _recipient: Recipient,
		) -> Result<RecoverableSignature, ()> { unreachable!() }
		fn get_peer_storage_key(&self) -> PeerStorageKey { unreachable!() }
		fn get_receive_auth_key(&self) -> ReceiveAuthKey { ReceiveAuthKey([41; 32]) }
		fn sign_bolt12_invoice(
			&self, _invoice: &UnsignedBolt12Invoice,
		) -> Result<schnorr::Signature, ()> { unreachable!() }
		fn sign_gossip_message(&self, _msg: UnsignedGossipMessage) -> Result<Signature, ()> { unreachable!() }
		fn sign_message(&self, msg: &[u8]) -> Result<String, ()> { Ok(crate::util::message_signing::sign(msg, &self.node_secret)) }
	}
	let logger = test_utils::TestLogger::with_id("".to_owned());

	let bob_update_add = update_add_msg(111_000, 747_501, None, bob_onion);
	let bob_node_signer = TestEcdhSigner { node_secret: bob_secret };

	let (bob_peeled_onion, next_packet_details_opt) = onion_payment::decode_incoming_update_add_htlc_onion(
		&bob_update_add, &bob_node_signer, &logger, &secp_ctx
	).unwrap_or_else(|_| panic!());

	let (carol_packet_bytes, carol_hmac) = if let onion_utils::Hop::Forward {
		next_hop_data: msgs::InboundOnionForwardPayload {..}, next_hop_hmac, new_packet_bytes, ..
	} = bob_peeled_onion {
		(new_packet_bytes, next_hop_hmac)
	} else { panic!() };

	let carol_packet_details = next_packet_details_opt.unwrap();
	let carol_onion = msgs::OnionPacket {
		version: 0,
		public_key: carol_packet_details.next_packet_pubkey,
		hop_data: carol_packet_bytes,
		hmac: carol_hmac,
	};
	let carol_update_add = update_add_msg(carol_packet_details.outgoing_amt_msat, carol_packet_details.outgoing_cltv_value, None, carol_onion);

	let carol_node_signer = TestEcdhSigner { node_secret: carol_secret };
	let (carol_peeled_onion, _) = onion_payment::decode_incoming_update_add_htlc_onion(
		&carol_update_add, &carol_node_signer, &logger, &secp_ctx
	).unwrap_or_else(|_| panic!());

	if let onion_utils::Hop::TrampolineForward { next_trampoline_hop_data, .. } = carol_peeled_onion {
		assert_eq!(next_trampoline_hop_data.next_trampoline, dave_node_id);
	} else {
		panic!();
	};
}

#[test]
#[rustfmt::skip]
fn test_trampoline_forward_payload_encoded_as_receive() {
	// Test that we'll fail backwards as expected when receiving a well-formed blinded forward
	// trampoline onion payload with no next hop present.
	const TOTAL_NODE_COUNT: usize = 3;
	let secp_ctx = Secp256k1::new();

	let chanmon_cfgs = create_chanmon_cfgs(TOTAL_NODE_COUNT);
	let node_cfgs = create_node_cfgs(TOTAL_NODE_COUNT, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(TOTAL_NODE_COUNT, &node_cfgs, &vec![None; TOTAL_NODE_COUNT]);
	let mut nodes = create_network(TOTAL_NODE_COUNT, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id_alice_bob, _) = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let (_, _, chan_id_bob_carol, _) = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	for i in 0..TOTAL_NODE_COUNT { // connect all nodes' blocks
		connect_blocks(&nodes[i], (TOTAL_NODE_COUNT as u32) * CHAN_CONFIRM_DEPTH + 1 - nodes[i].best_block_info().1);
	}

	let alice_node_id = nodes[0].node().get_our_node_id();
	let bob_node_id = nodes[1].node().get_our_node_id();
	let carol_node_id = nodes[2].node().get_our_node_id();

	let alice_bob_scid = nodes[0].node().list_channels().iter().find(|c| c.channel_id == chan_id_alice_bob).unwrap().short_channel_id.unwrap();
	let bob_carol_scid = nodes[1].node().list_channels().iter().find(|c| c.channel_id == chan_id_bob_carol).unwrap().short_channel_id.unwrap();

	let amt_msat = 1000;
	let (payment_preimage, payment_hash, _) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);

	// We need the session priv to construct an invalid onion packet later.
	let override_random_bytes = [3; 32];
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(override_random_bytes);

	let outer_session_priv = SecretKey::from_slice(&override_random_bytes).unwrap();
	let trampoline_session_priv = onion_utils::compute_trampoline_session_priv(&outer_session_priv);

	// Create a blinded hop for the recipient that is encoded as a trampoline forward.
	let carol_blinding_point = PublicKey::from_secret_key(&secp_ctx, &trampoline_session_priv);
	let carol_blinded_hops =  {
		let payee_tlvs = blinded_path::payment::TrampolineForwardTlvs {
			next_trampoline: alice_node_id,
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: amt_msat,
			},
			features: BlindedHopFeatures::empty(),
			payment_relay: PaymentRelay {
				cltv_expiry_delta: 0,
				fee_proportional_millionths: 0,
				fee_base_msat: 0,
			},
			next_blinding_override: None,
		};

		let carol_unblinded_tlvs = payee_tlvs.encode();
		let path = [((carol_node_id, None), WithoutLength(&carol_unblinded_tlvs))];
		blinded_path::utils::construct_blinded_hops(
			&secp_ctx, path.into_iter(), &trampoline_session_priv,
		)
  };

	let route = Route {
		paths: vec![Path {
			hops: vec![
				// Bob
				RouteHop {
					pubkey: bob_node_id,
					node_features: NodeFeatures::empty(),
					short_channel_id: alice_bob_scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 1000,
					cltv_expiry_delta: 48,
					maybe_announced_channel: false,
				},

				// Carol
				RouteHop {
					pubkey: carol_node_id,
					node_features: NodeFeatures::empty(),
					short_channel_id: bob_carol_scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 0,
					cltv_expiry_delta: 48,
					maybe_announced_channel: false,
				}
			],
			blinded_tail: Some(BlindedTail {
				trampoline_hops: vec![
					// Carol
					TrampolineHop {
						pubkey: carol_node_id,
						node_features: Features::empty(),
						fee_msat: amt_msat,
						cltv_expiry_delta: 24,
					},
				],
				hops: carol_blinded_hops,
				blinding_point: carol_blinding_point,
				excess_final_cltv_expiry_delta: 39,
				final_value_msat: amt_msat,
			})
		}],
		route_params: None,
	};

	nodes[0].node.send_payment_with_route(route.clone(), payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let replacement_onion = {
		// create a substitute onion where the last Trampoline hop is a forward
		let recipient_onion_fields = RecipientOnionFields::spontaneous_empty();

		let mut blinded_tail = route.paths[0].blinded_tail.clone().unwrap();

		// append some dummy blinded hop so the intro hop looks like a forward
		blinded_tail.hops.push(BlindedHop {
			blinded_node_id: alice_node_id,
			encrypted_payload: vec![],
		});

		let (mut trampoline_payloads, outer_total_msat, outer_starting_htlc_offset) = onion_utils::build_trampoline_onion_payloads(&blinded_tail, amt_msat, &recipient_onion_fields, 32, &None).unwrap();

		// pop the last dummy hop
		trampoline_payloads.pop();

		let trampoline_onion_keys = onion_utils::construct_trampoline_onion_keys(&secp_ctx, &route.paths[0].blinded_tail.as_ref().unwrap(), &trampoline_session_priv);
		let trampoline_packet = onion_utils::construct_trampoline_onion_packet(
			trampoline_payloads,
			trampoline_onion_keys,
			override_random_bytes,
			&payment_hash,
			None,
		).unwrap();

		let (outer_payloads, _, _) = onion_utils::build_onion_payloads(&route.paths[0], outer_total_msat, &recipient_onion_fields, outer_starting_htlc_offset, &None, None, Some(trampoline_packet)).unwrap();
		let outer_onion_keys = onion_utils::construct_onion_keys(&secp_ctx, &route.clone().paths[0], &outer_session_priv);
		let outer_packet = onion_utils::construct_onion_packet(
			outer_payloads,
			outer_onion_keys,
			override_random_bytes,
			&payment_hash,
		).unwrap();

		outer_packet
	};

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut first_message_event = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);
	let mut update_message = match first_message_event {
		MessageSendEvent::UpdateHTLCs { ref mut updates, .. } => {
			assert_eq!(updates.update_add_htlcs.len(), 1);
			updates.update_add_htlcs.get_mut(0)
		},
		_ => panic!()
	};
	update_message.map(|msg| {
		msg.onion_routing_packet = replacement_onion.clone();
	});

	let route: &[&Node] = &[&nodes[1], &nodes[2]];
	let args = PassAlongPathArgs::new(&nodes[0], route, amt_msat, payment_hash, first_message_event)
		.with_payment_preimage(payment_preimage)
		.without_claimable_event()
		.expect_failure(HTLCHandlingFailureType::InvalidOnion);
	do_pass_along_path(args);

	{
		let unblinded_node_updates = get_htlc_update_msgs(&nodes[2], &nodes[1].node.get_our_node_id());
		nodes[1].node.handle_update_fail_htlc(
			nodes[2].node.get_our_node_id(), &unblinded_node_updates.update_fail_htlcs[0]
		);
		do_commitment_signed_dance(&nodes[1], &nodes[2], &unblinded_node_updates.commitment_signed, true, false);
	}
	{
		let unblinded_node_updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(
			nodes[1].node.get_our_node_id(), &unblinded_node_updates.update_fail_htlcs[0]
		);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &unblinded_node_updates.commitment_signed, false, false);
	}
	{
		let payment_failed_conditions = PaymentFailedConditions::new()
			.expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionPayload, &[0; 0]);
		expect_payment_failed_conditions(&nodes[0], payment_hash, true, payment_failed_conditions);
	}
}

#[rustfmt::skip]
fn do_test_trampoline_single_hop_receive(success: bool) {
	const TOTAL_NODE_COUNT: usize = 3;
	let secp_ctx = Secp256k1::new();

	let chanmon_cfgs = create_chanmon_cfgs(TOTAL_NODE_COUNT);
	let node_cfgs = create_node_cfgs(TOTAL_NODE_COUNT, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(TOTAL_NODE_COUNT, &node_cfgs, &vec![None; TOTAL_NODE_COUNT]);
	let mut nodes = create_network(TOTAL_NODE_COUNT, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id_alice_bob, _) = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let (_, _, chan_id_bob_carol, _) = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	for i in 0..TOTAL_NODE_COUNT { // connect all nodes' blocks
		connect_blocks(&nodes[i], (TOTAL_NODE_COUNT as u32) * CHAN_CONFIRM_DEPTH + 1 - nodes[i].best_block_info().1);
	}

	let bob_node_id = nodes[1].node().get_our_node_id();
	let carol_node_id = nodes[2].node().get_our_node_id();

	let alice_bob_scid = nodes[0].node().list_channels().iter().find(|c| c.channel_id == chan_id_alice_bob).unwrap().short_channel_id.unwrap();
	let bob_carol_scid = nodes[1].node().list_channels().iter().find(|c| c.channel_id == chan_id_bob_carol).unwrap().short_channel_id.unwrap();

	let amt_msat = 1000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);

	// Create a 1-hop blinded path for Carol.
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: amt_msat,
		},
		payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
	};
	let receive_auth_key = nodes[2].keys_manager.get_receive_auth_key();
	let blinded_path = BlindedPaymentPath::new(&[], carol_node_id, receive_auth_key, payee_tlvs, u64::MAX, 0, nodes[2].keys_manager, &secp_ctx).unwrap();

	let route = Route {
		paths: vec![Path {
			hops: vec![
				// Bob
				RouteHop {
					pubkey: bob_node_id,
					node_features: NodeFeatures::empty(),
					short_channel_id: alice_bob_scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 1000,
					cltv_expiry_delta: 48,
					maybe_announced_channel: false,
				},

				// Carol
				RouteHop {
					pubkey: carol_node_id,
					node_features: NodeFeatures::empty(),
					short_channel_id: bob_carol_scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 0,
					cltv_expiry_delta: 48,
					maybe_announced_channel: false,
				}
			],
			blinded_tail: Some(BlindedTail {
				trampoline_hops: vec![
					// Carol
					TrampolineHop {
						pubkey: carol_node_id,
						node_features: Features::empty(),
						fee_msat: amt_msat,
						cltv_expiry_delta: 104,
					},
				],
				hops: blinded_path.blinded_hops().to_vec(),
				blinding_point: blinded_path.blinding_point(),
				excess_final_cltv_expiry_delta: 39,
				final_value_msat: amt_msat,
			})
		}],
		route_params: None,
	};

	nodes[0].node.send_payment_with_route(route.clone(), payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], amt_msat, payment_hash, payment_secret);
	if success {
		claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
	} else {
		fail_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_hash);
	}
}

#[test]
fn test_trampoline_single_hop_receive() {
	// Simulate a payment of A (0) -> B (1) -> C(Trampoline (blinded intro)) (2)
	do_test_trampoline_single_hop_receive(true);

	// Simulate a payment failure of A (0) -> B (1) -> C(Trampoline (blinded forward)) (2)
	do_test_trampoline_single_hop_receive(false);
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum TrampolineTestCase {
	Success,
	Underpayment,
	OuterCLTVLessThanTrampoline,
}

impl<'a> TrampolineTestCase {
	fn payment_failed_conditions(
		self, final_payment_amt: &'a [u8], final_cltv_delta: &'a [u8],
	) -> Option<PaymentFailedConditions<'a>> {
		match self {
			TrampolineTestCase::Success => None,
			TrampolineTestCase::Underpayment => {
				Some(PaymentFailedConditions::new().expected_htlc_error_data(
					LocalHTLCFailureReason::FinalIncorrectHTLCAmount,
					final_payment_amt,
				))
			},
			TrampolineTestCase::OuterCLTVLessThanTrampoline => {
				Some(PaymentFailedConditions::new().expected_htlc_error_data(
					LocalHTLCFailureReason::FinalIncorrectCLTVExpiry,
					final_cltv_delta,
				))
			},
		}
	}

	fn expected_log(&self) -> Option<(&str, &str, usize)> {
		match self {
			TrampolineTestCase::Success => None,
			TrampolineTestCase::Underpayment => Some((
				"lightning::ln::channelmanager",
				"Trampoline onion's amt value exceeded the outer onion's",
				1,
			)),
			TrampolineTestCase::OuterCLTVLessThanTrampoline => Some((
				"lightning::ln::channelmanager",
				"Trampoline onion's CLTV value exceeded the outer onion's",
				1,
			)),
		}
	}

	fn outer_onion_cltv(&self, outer_cltv: u32) -> u32 {
		if *self == TrampolineTestCase::OuterCLTVLessThanTrampoline {
			return outer_cltv / 2;
		}
		outer_cltv
	}

	fn outer_onion_amt(&self, original_amt: u64) -> u64 {
		if *self == TrampolineTestCase::Underpayment {
			return original_amt / 2;
		}
		original_amt
	}
}

#[test]
fn test_trampoline_unblinded_receive() {
	do_test_trampoline_relay(false, TrampolineTestCase::Success);
	do_test_trampoline_relay(false, TrampolineTestCase::Underpayment);
	do_test_trampoline_relay(false, TrampolineTestCase::OuterCLTVLessThanTrampoline);
}

#[test]
fn test_trampoline_blinded_receive() {
	do_test_trampoline_relay(true, TrampolineTestCase::Success);
	do_test_trampoline_relay(true, TrampolineTestCase::Underpayment);
	do_test_trampoline_relay(true, TrampolineTestCase::OuterCLTVLessThanTrampoline);
}

/// Creates a blinded tail where Carol receives via a blinded path.
fn create_blinded_tail(
	secp_ctx: &Secp256k1<All>, override_random_bytes: [u8; 32], carol_node_id: PublicKey,
	carol_auth_key: ReceiveAuthKey, trampoline_cltv_expiry_delta: u32, final_value_msat: u64,
	payment_secret: PaymentSecret,
) -> BlindedTail {
	let outer_session_priv = SecretKey::from_slice(&override_random_bytes).unwrap();
	let trampoline_session_priv = onion_utils::compute_trampoline_session_priv(&outer_session_priv);

	let carol_blinding_point = PublicKey::from_secret_key(&secp_ctx, &trampoline_session_priv);
	let carol_blinded_hops = {
		let payee_tlvs = ReceiveTlvs {
			payment_secret,
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: u32::max_value(),
				htlc_minimum_msat: final_value_msat,
			},
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
		}
		.encode();

		let path = [((carol_node_id, Some(carol_auth_key)), WithoutLength(&payee_tlvs))];

		blinded_path::utils::construct_blinded_hops(
			&secp_ctx,
			path.into_iter(),
			&trampoline_session_priv,
		)
	};

	BlindedTail {
		trampoline_hops: vec![TrampolineHop {
			pubkey: carol_node_id,
			node_features: Features::empty(),
			fee_msat: final_value_msat,
			cltv_expiry_delta: trampoline_cltv_expiry_delta,
		}],
		hops: carol_blinded_hops,
		blinding_point: carol_blinding_point,
		excess_final_cltv_expiry_delta: 39,
		final_value_msat,
	}
}

// Creates a replacement onion that is used to produce scenarios that we don't support, specifically
// payloads that send to unblinded receives and invalid payloads.
fn replacement_onion(
	test_case: TrampolineTestCase, secp_ctx: &Secp256k1<All>, override_random_bytes: [u8; 32],
	route: Route, original_amt_msat: u64, starting_htlc_offset: u32, original_trampoline_cltv: u32,
	payment_hash: PaymentHash, payment_secret: PaymentSecret, blinded: bool,
) -> msgs::OnionPacket {
	let outer_session_priv = SecretKey::from_slice(&override_random_bytes[..]).unwrap();
	let trampoline_session_priv = onion_utils::compute_trampoline_session_priv(&outer_session_priv);
	let recipient_onion_fields = RecipientOnionFields::spontaneous_empty();

	let blinded_tail = route.paths[0].blinded_tail.clone().unwrap();

	// Rebuild our trampoline packet from the original route. If we want to test Carol receiving
	// as an unblinded trampoline hop, we switch out her inner trampoline onion with a direct
	// receive payload because LDK doesn't support unblinded trampoline receives.
	let (trampoline_packet, outer_total_msat, outer_starting_htlc_offset) = {
		let (mut trampoline_payloads, outer_total_msat, outer_starting_htlc_offset) =
			onion_utils::build_trampoline_onion_payloads(
				&blinded_tail,
				original_amt_msat,
				&recipient_onion_fields,
				starting_htlc_offset,
				&None,
			)
			.unwrap();

		if !blinded {
			trampoline_payloads = vec![msgs::OutboundTrampolinePayload::Receive {
				payment_data: Some(msgs::FinalOnionHopData {
					payment_secret,
					total_msat: original_amt_msat,
				}),
				sender_intended_htlc_amt_msat: original_amt_msat,
				cltv_expiry_height: original_trampoline_cltv + starting_htlc_offset,
			}];
		}

		let trampoline_onion_keys = onion_utils::construct_trampoline_onion_keys(
			&secp_ctx,
			&blinded_tail,
			&trampoline_session_priv,
		);
		let trampoline_packet = onion_utils::construct_trampoline_onion_packet(
			trampoline_payloads,
			trampoline_onion_keys,
			override_random_bytes,
			&payment_hash,
			None,
		)
		.unwrap();

		(trampoline_packet, outer_total_msat, outer_starting_htlc_offset)
	};

	// Use a different session key to construct the replacement onion packet. Note that the
	// sender isn't aware of this and won't be able to decode the fulfill hold times.
	let (mut outer_payloads, _, _) = onion_utils::build_onion_payloads(
		&route.paths[0],
		outer_total_msat,
		&recipient_onion_fields,
		outer_starting_htlc_offset,
		&None,
		None,
		Some(trampoline_packet),
	)
	.unwrap();
	assert_eq!(outer_payloads.len(), 2);

	// If we're trying to test invalid payloads, we modify Carol's *outer* onion to have values
	// that are inconsistent with her inner onion. We need to do this manually because we
	// (obviously) can't construct an invalid onion with LDK's built in functions.
	match &mut outer_payloads[1] {
		msgs::OutboundOnionPayload::TrampolineEntrypoint {
			amt_to_forward,
			outgoing_cltv_value,
			..
		} => {
			*amt_to_forward = test_case.outer_onion_amt(original_amt_msat);
			let outer_cltv = original_trampoline_cltv + starting_htlc_offset;
			*outgoing_cltv_value = test_case.outer_onion_cltv(outer_cltv);
		},
		_ => panic!("final payload is not trampoline entrypoint"),
	}

	let outer_onion_keys =
		onion_utils::construct_onion_keys(&secp_ctx, &route.clone().paths[0], &outer_session_priv);
	onion_utils::construct_onion_packet(
		outer_payloads,
		outer_onion_keys,
		override_random_bytes,
		&payment_hash,
	)
	.unwrap()
}

// Test relay of payments to a trampoline, testing success and trampoline-related relay failures.
// This test relies on manually replacing parts of our onion to:
// - Test unblinded trampoline receives, which are not natively supported in LDK.
// - To hit validation errors by manipulating the trampoline's outer packet. Without this, we would
//   have to manually construct the onion.
fn do_test_trampoline_relay(blinded: bool, test_case: TrampolineTestCase) {
	const TOTAL_NODE_COUNT: usize = 3;
	let secp_ctx = Secp256k1::new();

	let chanmon_cfgs = create_chanmon_cfgs(TOTAL_NODE_COUNT);
	let node_cfgs = create_node_cfgs(TOTAL_NODE_COUNT, &chanmon_cfgs);
	let user_cfgs = &vec![None; TOTAL_NODE_COUNT];
	let node_chanmgrs = create_node_chanmgrs(TOTAL_NODE_COUNT, &node_cfgs, &user_cfgs);
	let mut nodes = create_network(TOTAL_NODE_COUNT, &node_cfgs, &node_chanmgrs);

	let alice_bob_chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let bob_carol_chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	for i in 0..TOTAL_NODE_COUNT {
		connect_blocks(
			&nodes[i],
			(TOTAL_NODE_COUNT as u32) * CHAN_CONFIRM_DEPTH + 1 - nodes[i].best_block_info().1,
		);
	}

	let alice_node_id = nodes[0].node.get_our_node_id();
	let bob_node_id = nodes[1].node().get_our_node_id();
	let carol_node_id = nodes[2].node().get_our_node_id();

	let alice_bob_scid = get_scid_from_channel_id(&nodes[0], alice_bob_chan.2);
	let bob_carol_scid = get_scid_from_channel_id(&nodes[1], bob_carol_chan.2);

	let original_amt_msat = 1000;
	let original_trampoline_cltv = 72;
	let starting_htlc_offset = 32;

	let (payment_preimage, payment_hash, payment_secret) =
		get_payment_preimage_hash(&nodes[2], Some(original_amt_msat), None);

	// We need the session priv to replace the onion packet later.
	let override_random_bytes = [42; 32];
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(override_random_bytes);

	let route = Route {
		paths: vec![Path {
			hops: vec![
				RouteHop {
					pubkey: bob_node_id,
					node_features: NodeFeatures::empty(),
					short_channel_id: alice_bob_scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 1000,
					cltv_expiry_delta: 48,
					maybe_announced_channel: false,
				},
				RouteHop {
					pubkey: carol_node_id,
					node_features: NodeFeatures::empty(),
					short_channel_id: bob_carol_scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 0,
					cltv_expiry_delta: 48,
					maybe_announced_channel: false,
				},
			],
			// Create a blinded tail where Carol is receiving. In our unblinded test cases, we'll
			// override this anyway (with a tail sending to an unblinded receive, which LDK doesn't
			// allow).
			blinded_tail: Some(create_blinded_tail(
				&secp_ctx,
				override_random_bytes,
				carol_node_id,
				nodes[2].keys_manager.get_receive_auth_key(),
				original_trampoline_cltv,
				original_amt_msat,
				payment_secret,
			)),
		}],
		route_params: None,
	};

	nodes[0]
		.node
		.send_payment_with_route(
			route.clone(),
			payment_hash,
			RecipientOnionFields::spontaneous_empty(),
			PaymentId(payment_hash.0),
		)
		.unwrap();

	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut first_message_event = remove_first_msg_event_to_node(&bob_node_id, &mut events);
	let mut update_message = match first_message_event {
		MessageSendEvent::UpdateHTLCs { ref mut updates, .. } => {
			assert_eq!(updates.update_add_htlcs.len(), 1);
			updates.update_add_htlcs.get_mut(0)
		},
		_ => panic!(),
	};

	// Replace the onion to test different scenarios:
	// - If !blinded: Creates a payload sending to an unblinded trampoline
	// - If blinded: Modifies outer onion to create outer/inner mismatches if testing failures
	update_message.map(|msg| {
		msg.onion_routing_packet = replacement_onion(
			test_case,
			&secp_ctx,
			override_random_bytes,
			route,
			original_amt_msat,
			starting_htlc_offset,
			original_trampoline_cltv,
			payment_hash,
			payment_secret,
			blinded,
		)
	});

	let route: &[&Node] = &[&nodes[1], &nodes[2]];
	let args = PassAlongPathArgs::new(
		&nodes[0],
		route,
		original_amt_msat,
		payment_hash,
		first_message_event,
	);

	let amt_bytes = test_case.outer_onion_amt(original_amt_msat).to_be_bytes();
	let cltv_bytes =
		test_case.outer_onion_cltv(original_trampoline_cltv + starting_htlc_offset).to_be_bytes();
	let payment_failure = test_case.payment_failed_conditions(&amt_bytes, &cltv_bytes).map(|p| {
		if blinded {
			PaymentFailedConditions::new()
				.expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32])
		} else {
			p
		}
	});
	let args = if payment_failure.is_some() {
		args.with_payment_preimage(payment_preimage)
			.without_claimable_event()
			.expect_failure(HTLCHandlingFailureType::Receive { payment_hash })
	} else {
		args.with_payment_secret(payment_secret)
	};

	do_pass_along_path(args);

	if let Some(failure) = payment_failure {
		let node_updates = get_htlc_update_msgs(&nodes[2], &bob_node_id);
		nodes[1].node.handle_update_fail_htlc(carol_node_id, &node_updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(
			&nodes[1],
			&nodes[2],
			&node_updates.commitment_signed,
			true,
			false,
		);

		let node_updates = get_htlc_update_msgs(&nodes[1], &alice_node_id);
		nodes[0].node.handle_update_fail_htlc(bob_node_id, &node_updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(
			&nodes[0],
			&nodes[1],
			&node_updates.commitment_signed,
			false,
			false,
		);

		expect_payment_failed_conditions(&nodes[0], payment_hash, false, failure);

		// Because we support blinded paths, we also assert on our expected logs to make sure
		// that the failure reason hidden by obfuscated blinded errors is as expected.
		if let Some((module, line, count)) = test_case.expected_log() {
			nodes[2].logger.assert_log_contains(module, line, count);
		}
	} else {
		claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
	}
}

#[test]
#[rustfmt::skip]
fn test_trampoline_forward_rejection() {
	const TOTAL_NODE_COUNT: usize = 3;

	let chanmon_cfgs = create_chanmon_cfgs(TOTAL_NODE_COUNT);
	let node_cfgs = create_node_cfgs(TOTAL_NODE_COUNT, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(TOTAL_NODE_COUNT, &node_cfgs, &vec![None; TOTAL_NODE_COUNT]);
	let mut nodes = create_network(TOTAL_NODE_COUNT, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id_alice_bob, _) = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let (_, _, chan_id_bob_carol, _) = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0);

	for i in 0..TOTAL_NODE_COUNT { // connect all nodes' blocks
		connect_blocks(&nodes[i], (TOTAL_NODE_COUNT as u32) * CHAN_CONFIRM_DEPTH + 1 - nodes[i].best_block_info().1);
	}

	let alice_node_id = nodes[0].node().get_our_node_id();
	let bob_node_id = nodes[1].node().get_our_node_id();
	let carol_node_id = nodes[2].node().get_our_node_id();

	let alice_bob_scid = nodes[0].node().list_channels().iter().find(|c| c.channel_id == chan_id_alice_bob).unwrap().short_channel_id.unwrap();
	let bob_carol_scid = nodes[1].node().list_channels().iter().find(|c| c.channel_id == chan_id_bob_carol).unwrap().short_channel_id.unwrap();

	let amt_msat = 1000;
	let (payment_preimage, payment_hash, _) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);

	let route = Route {
		paths: vec![Path {
			hops: vec![
				// Bob
				RouteHop {
					pubkey: bob_node_id,
					node_features: NodeFeatures::empty(),
					short_channel_id: alice_bob_scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 1000,
					cltv_expiry_delta: 48,
					maybe_announced_channel: false,
				},

				// Carol
				RouteHop {
					pubkey: carol_node_id,
					node_features: NodeFeatures::empty(),
					short_channel_id: bob_carol_scid,
					channel_features: ChannelFeatures::empty(),
					fee_msat: 0,
					cltv_expiry_delta: 48,
					maybe_announced_channel: false,
				}
			],
			blinded_tail: Some(BlindedTail {
				trampoline_hops: vec![
					// Carol
					TrampolineHop {
						pubkey: carol_node_id,
						node_features: Features::empty(),
						fee_msat: amt_msat,
						cltv_expiry_delta: 24,
					},

					// Alice (unreachable)
					TrampolineHop {
						pubkey: alice_node_id,
						node_features: Features::empty(),
						fee_msat: amt_msat,
						cltv_expiry_delta: 24,
					},
				],
				hops: vec![BlindedHop{
					// Fake public key
					blinded_node_id: alice_node_id,
					encrypted_payload: vec![],
				}],
				blinding_point: alice_node_id,
				excess_final_cltv_expiry_delta: 39,
				final_value_msat: amt_msat,
			})
		}],
		route_params: None,
	};

	nodes[0].node.send_payment_with_route(route.clone(), payment_hash, RecipientOnionFields::spontaneous_empty(), PaymentId(payment_hash.0)).unwrap();

	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let first_message_event = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut events);

	let route: &[&Node] = &[&nodes[1], &nodes[2]];
	let args = PassAlongPathArgs::new(&nodes[0], route, amt_msat, payment_hash, first_message_event)
		.with_payment_preimage(payment_preimage)
		.without_claimable_event()
		.expect_failure(HTLCHandlingFailureType::Receive { payment_hash });
	do_pass_along_path(args);

	{
		let unblinded_node_updates = get_htlc_update_msgs(&nodes[2], &nodes[1].node.get_our_node_id());
		nodes[1].node.handle_update_fail_htlc(
			nodes[2].node.get_our_node_id(), &unblinded_node_updates.update_fail_htlcs[0]
		);
		do_commitment_signed_dance(&nodes[1], &nodes[2], &unblinded_node_updates.commitment_signed, true, false);
	}
	{
		let unblinded_node_updates = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		nodes[0].node.handle_update_fail_htlc(
			nodes[1].node.get_our_node_id(), &unblinded_node_updates.update_fail_htlcs[0]
		);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &unblinded_node_updates.commitment_signed, false, false);
	}
	{
		// Expect UnknownNextPeer error while we are unable to route forwarding Trampoline payments.
		let payment_failed_conditions = PaymentFailedConditions::new()
			.expected_htlc_error_data(LocalHTLCFailureReason::UnknownNextPeer, &[0; 0]);
		expect_payment_failed_conditions(&nodes[0], payment_hash, false, payment_failed_conditions);
	}
}
