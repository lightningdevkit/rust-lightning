// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests for calculating the maximum length of a path based on the payment metadata, custom TLVs,
//! and/or blinded paths present.

use bitcoin::secp256k1::Secp256k1;
use crate::blinded_path::BlindedPath;
use crate::blinded_path::payment::{PaymentConstraints, PaymentContext, ReceiveTlvs};
use crate::events::MessageSendEventsProvider;
use crate::ln::PaymentSecret;
use crate::ln::blinded_payment_tests::get_blinded_route_parameters;
use crate::ln::channelmanager::PaymentId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::onion_utils;
use crate::ln::onion_utils::MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY;
use crate::ln::outbound_payment::{RecipientOnionFields, Retry, RetryableSendFailure};
use crate::prelude::*;
use crate::routing::router::{DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA, PaymentParameters, RouteParameters};
use crate::util::errors::APIError;
use crate::util::ser::Writeable;
use crate::util::test_utils;

// 3+32 (payload length and HMAC) + 2+8 (amt_to_forward) +
// 2+4 (outgoing_cltv_value) + 2+8 (short_channel_id)
const INTERMED_PAYLOAD_LEN_ESTIMATE: usize = 61;

// Length of the HMAC of an onion payload when encoded into the packet.
const PAYLOAD_HMAC_LEN: usize = 32;

#[test]
fn large_payment_metadata() {
	// Test that we'll limit our maximum path length based on the size of the provided
	// payment_metadata, and refuse to send at all prior to pathfinding if it's too large.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let amt_msat = 100_000;

	// Construct payment_metadata such that we can send the payment to the next hop but no further
	// without exceeding the max onion packet size.
	let final_payload_len_without_metadata = msgs::OutboundOnionPayload::Receive {
		payment_data: Some(msgs::FinalOnionHopData {
			payment_secret: PaymentSecret([0; 32]), total_msat: MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY
		}),
		payment_metadata: None,
		keysend_preimage: None,
		custom_tlvs: &Vec::new(),
		sender_intended_htlc_amt_msat: MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		cltv_expiry_height: nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
	}.serialized_length();
	let max_metadata_len = 1300
		- 1 // metadata type
		- crate::util::ser::BigSize(1200).serialized_length() // metadata length
		- 2 // onion payload varint prefix increased ser size due to metadata
		- PAYLOAD_HMAC_LEN
		- final_payload_len_without_metadata;
	let mut payment_metadata = vec![42; max_metadata_len];

	// Check that the maximum-size metadata is sendable.
	let (mut route_0_1, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(&nodes[0], &nodes[1], amt_msat);
	let mut recipient_onion_max_md_size = RecipientOnionFields {
		payment_secret: Some(payment_secret),
		payment_metadata: Some(payment_metadata.clone()),
		custom_tlvs: Vec::new(),
	};
	nodes[0].node.send_payment(payment_hash, recipient_onion_max_md_size.clone(), PaymentId(payment_hash.0), route_0_1.route_params.clone().unwrap(), Retry::Attempts(0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1]];
	let args = PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash, events.pop().unwrap())
		.with_payment_secret(payment_secret)
		.with_payment_metadata(payment_metadata.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1]]], payment_preimage)
	);

	// Check that the payment parameter for max path length will prevent us from routing past our
	// next-hop peer given the payment_metadata size.
	let (mut route_0_2, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(&nodes[0], &nodes[2], amt_msat);
	let mut route_params_0_2 = route_0_2.route_params.clone().unwrap();
	route_params_0_2.payment_params.max_path_length = 1;
	nodes[0].router.expect_find_route_query(route_params_0_2);
	let err = nodes[0].node.send_payment(payment_hash_2, recipient_onion_max_md_size.clone(), PaymentId(payment_hash_2.0), route_0_2.route_params.clone().unwrap(), Retry::Attempts(0)).unwrap_err();
	assert_eq!(err, RetryableSendFailure::RouteNotFound);

	// If our payment_metadata contains 1 additional byte, we'll fail prior to pathfinding.
	let mut recipient_onion_too_large_md = recipient_onion_max_md_size.clone();
	recipient_onion_too_large_md.payment_metadata.as_mut().map(|mut md| md.push(42));
	let err = nodes[0].node.send_payment(payment_hash, recipient_onion_too_large_md.clone(), PaymentId(payment_hash.0), route_0_1.route_params.clone().unwrap(), Retry::Attempts(0)).unwrap_err();
	assert_eq!(err, RetryableSendFailure::OnionPacketSizeExceeded);

	// Confirm that we'll fail to construct an onion packet given this payment_metadata that's too
	// large for even a 1-hop path.
	let secp_ctx = Secp256k1::signing_only();
	route_0_1.paths[0].hops[0].fee_msat = MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY;
	route_0_1.paths[0].hops[0].cltv_expiry_delta = DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA;
	let err = onion_utils::create_payment_onion(&secp_ctx, &route_0_1.paths[0], &test_utils::privkey(42), MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY, &recipient_onion_too_large_md, nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA, &payment_hash, &None, [0; 32]).unwrap_err();
	match err {
		APIError::InvalidRoute { err } => {
			assert_eq!(err, "Route size too large considering onion data");
		},
		_ => panic!(),
	}

	// If we remove enough payment_metadata bytes to allow for 2 hops, we're now able to send to
	// nodes[2].
	let mut recipient_onion_allows_2_hops = RecipientOnionFields {
		payment_secret: Some(payment_secret_2),
		payment_metadata: Some(vec![42; max_metadata_len - INTERMED_PAYLOAD_LEN_ESTIMATE]),
		custom_tlvs: Vec::new(),
	};
	let mut route_params_0_2 = route_0_2.route_params.clone().unwrap();
	route_params_0_2.payment_params.max_path_length = 2;
	nodes[0].router.expect_find_route_query(route_params_0_2);
	nodes[0].node.send_payment(payment_hash_2, recipient_onion_allows_2_hops.clone(), PaymentId(payment_hash_2.0), route_0_2.route_params.unwrap(), Retry::Attempts(0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1], &nodes[2]];
	let args = PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash_2, events.pop().unwrap())
		.with_payment_secret(payment_secret_2)
		.with_payment_metadata(recipient_onion_allows_2_hops.payment_metadata.unwrap());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2]]], payment_preimage_2)
	);
}

#[test]
fn one_hop_blinded_path_with_custom_tlv() {
	// Test that we'll limit our maximum path length when paying to a 1-hop blinded path based on the
	// size of the provided custom TLV, and refuse to send at all prior to pathfinding if it's too
	// large.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_upd_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	// Construct the route parameters for sending to nodes[2]'s 1-hop blinded path.
	let amt_msat = 100_000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let payee_tlvs = ReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd_1_2.htlc_minimum_msat,
		},
		payment_context: PaymentContext::unknown(),
	};
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::one_hop_for_payment(
		nodes[2].node.get_our_node_id(), payee_tlvs, TEST_FINAL_CLTV as u16,
		&chanmon_cfgs[2].keys_manager, &secp_ctx
	).unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::blinded(vec![blinded_path.clone()]),
		amt_msat,
	);

	// Calculate the maximum custom TLV value size where a valid onion packet is still possible.
	const CUSTOM_TLV_TYPE: u64 = 65537;
	let final_payload_len_without_custom_tlv = msgs::OutboundOnionPayload::BlindedReceive {
		sender_intended_htlc_amt_msat: MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		total_msat: MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		cltv_expiry_height: nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
		encrypted_tlvs: &blinded_path.1.blinded_hops[0].encrypted_payload,
		intro_node_blinding_point: Some(blinded_path.1.blinding_point),
		keysend_preimage: None,
		custom_tlvs: &Vec::new()
	}.serialized_length();
	let max_custom_tlv_len = 1300
		- crate::util::ser::BigSize(CUSTOM_TLV_TYPE).serialized_length() // custom TLV type
		- crate::util::ser::BigSize(1200).serialized_length() // custom TLV length
		- 1 // onion payload varint prefix increased ser size due to custom TLV
		- PAYLOAD_HMAC_LEN
		- final_payload_len_without_custom_tlv;

	// Check that we can send the maximum custom TLV with 1 blinded hop.
	let recipient_onion_max_custom_tlv_size = RecipientOnionFields::spontaneous_empty()
		.with_custom_tlvs(vec![(CUSTOM_TLV_TYPE, vec![42; max_custom_tlv_len])])
		.unwrap();
	nodes[1].node.send_payment(payment_hash, recipient_onion_max_custom_tlv_size.clone(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[2]];
	let args = PassAlongPathArgs::new(&nodes[1], path, amt_msat, payment_hash, events.pop().unwrap())
		.with_payment_secret(payment_secret)
		.with_custom_tlvs(recipient_onion_max_custom_tlv_size.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[1], &[&[&nodes[2]]], payment_preimage)
			.with_custom_tlvs(recipient_onion_max_custom_tlv_size.custom_tlvs.clone())
	);

	// If 1 byte is added to the custom TLV value, we'll fail to send prior to pathfinding.
	let mut recipient_onion_too_large_custom_tlv = recipient_onion_max_custom_tlv_size.clone();
	recipient_onion_too_large_custom_tlv.custom_tlvs[0].1.push(42);
	let err = nodes[1].node.send_payment(payment_hash, recipient_onion_too_large_custom_tlv, PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap_err();
	assert_eq!(err, RetryableSendFailure::OnionPacketSizeExceeded);

	// With the maximum-size custom TLV, our max path length is limited to 1, so attempting to route
	// nodes[0] -> nodes[2] will fail.
	let err = nodes[0].node.send_payment(payment_hash, recipient_onion_max_custom_tlv_size.clone(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap_err();
	assert_eq!(err, RetryableSendFailure::RouteNotFound);

	// If we remove enough custom TLV bytes to allow for 1 intermediate unblinded hop, we're now able
	// to send nodes[0] -> nodes[2].
	let mut recipient_onion_allows_2_hops = recipient_onion_max_custom_tlv_size.clone();
	recipient_onion_allows_2_hops.custom_tlvs[0].1.resize(max_custom_tlv_len - INTERMED_PAYLOAD_LEN_ESTIMATE, 0);
	nodes[0].node.send_payment(payment_hash, recipient_onion_allows_2_hops.clone(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1], &nodes[2]];
	let args = PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash, events.pop().unwrap())
		.with_payment_secret(payment_secret)
		.with_custom_tlvs(recipient_onion_allows_2_hops.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2]]], payment_preimage)
			.with_custom_tlvs(recipient_onion_allows_2_hops.custom_tlvs)
	);
}

#[test]
fn blinded_path_with_custom_tlv() {
	// Test that we'll limit our maximum path length when paying to a blinded path based on the size
	// of the provided custom TLV, and refuse to send at all prior to pathfinding if it's too large.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan_upd_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;

	// Construct the route parameters for sending to nodes[3]'s blinded path.
	let amt_msat = 100_000;
	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(amt_msat, payment_secret, 1, 1_0000_0000,
		nodes.iter().skip(2).map(|n| n.node.get_our_node_id()).collect(), &[&chan_upd_2_3],
		&chanmon_cfgs[3].keys_manager);

	// Calculate the maximum custom TLV value size where a valid onion packet is still possible.
	const CUSTOM_TLV_TYPE: u64 = 65537;
	let mut route = get_route(&nodes[1], &route_params).unwrap();
	let reserved_packet_bytes_without_custom_tlv: usize = onion_utils::build_onion_payloads(
		&route.paths[0], MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		&RecipientOnionFields::spontaneous_empty(),
		nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA, &None
	)
		.unwrap()
		.0
		.iter()
		.map(|payload| payload.serialized_length() + PAYLOAD_HMAC_LEN)
		.sum();
	let max_custom_tlv_len = 1300
		- crate::util::ser::BigSize(CUSTOM_TLV_TYPE).serialized_length() // custom TLV type
		- crate::util::ser::BigSize(1200).serialized_length() // custom TLV length
		- 2 // onion payload varint prefix increased ser size due to custom TLV
		- reserved_packet_bytes_without_custom_tlv;

	// Check that we can send the maximum custom TLV size with 0 intermediate unblinded hops.
	let recipient_onion_max_custom_tlv_size = RecipientOnionFields::spontaneous_empty()
		.with_custom_tlvs(vec![(CUSTOM_TLV_TYPE, vec![42; max_custom_tlv_len])])
		.unwrap();
	nodes[1].node.send_payment(payment_hash, recipient_onion_max_custom_tlv_size.clone(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[2], &nodes[3]];
	let args = PassAlongPathArgs::new(&nodes[1], path, amt_msat, payment_hash, events.pop().unwrap())
		.with_payment_secret(payment_secret)
		.with_custom_tlvs(recipient_onion_max_custom_tlv_size.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[1], &[&[&nodes[2], &nodes[3]]], payment_preimage)
			.with_custom_tlvs(recipient_onion_max_custom_tlv_size.custom_tlvs.clone())
	);

	// If 1 byte is added to the custom TLV value, we'll fail to send prior to pathfinding.
	let mut recipient_onion_too_large_custom_tlv = recipient_onion_max_custom_tlv_size.clone();
	recipient_onion_too_large_custom_tlv.custom_tlvs[0].1.push(42);
	let err = nodes[1].node.send_payment(payment_hash, recipient_onion_too_large_custom_tlv.clone(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap_err();
	assert_eq!(err, RetryableSendFailure::OnionPacketSizeExceeded);

	// Confirm that we can't construct an onion packet given this too-large custom TLV.
	let secp_ctx = Secp256k1::signing_only();
	route.paths[0].hops[0].fee_msat = MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY;
	route.paths[0].hops[0].cltv_expiry_delta = DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA;
	let err = onion_utils::create_payment_onion(&secp_ctx, &route.paths[0], &test_utils::privkey(42), MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY, &recipient_onion_too_large_custom_tlv, nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA, &payment_hash, &None, [0; 32]).unwrap_err();
	match err {
		APIError::InvalidRoute { err } => {
			assert_eq!(err, "Route size too large considering onion data");
		},
		_ => panic!(),
	}

	// With the maximum-size custom TLV, we can't have any intermediate unblinded hops, so attempting
	// to route nodes[0] -> nodes[3] will fail.
	let err = nodes[0].node.send_payment(payment_hash, recipient_onion_max_custom_tlv_size.clone(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap_err();
	assert_eq!(err, RetryableSendFailure::RouteNotFound);

	// If we remove enough custom TLV bytes to allow for 1 intermediate unblinded hop, we're now able
	// to send nodes[0] -> nodes[3].
	let mut recipient_onion_allows_2_hops = recipient_onion_max_custom_tlv_size.clone();
	recipient_onion_allows_2_hops.custom_tlvs[0].1.resize(max_custom_tlv_len - INTERMED_PAYLOAD_LEN_ESTIMATE, 0);
	nodes[0].node.send_payment(payment_hash, recipient_onion_allows_2_hops.clone(), PaymentId(payment_hash.0), route_params.clone(), Retry::Attempts(0)).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1], &nodes[2], &nodes[3]];
	let args = PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash, events.pop().unwrap())
		.with_payment_secret(payment_secret)
		.with_custom_tlvs(recipient_onion_allows_2_hops.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2], &nodes[3]]], payment_preimage)
			.with_custom_tlvs(recipient_onion_allows_2_hops.custom_tlvs)
	);
}
