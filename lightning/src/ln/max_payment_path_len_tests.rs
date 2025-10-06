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

use crate::blinded_path::payment::{
	BlindedPayInfo, BlindedPaymentPath, Bolt12RefundContext, PaymentConstraints, PaymentContext,
	UnauthenticatedReceiveTlvs,
};
use crate::blinded_path::BlindedHop;
use crate::events::Event;
use crate::ln::blinded_payment_tests::get_blinded_route_parameters;
use crate::ln::channelmanager::{OptionalOfferPaymentParams, PaymentId};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::msgs::{BaseMessageHandler, OnionMessageHandler};
use crate::ln::onion_utils;
use crate::ln::onion_utils::MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY;
use crate::ln::outbound_payment::{RecipientOnionFields, Retry, RetryableSendFailure};
use crate::offers::nonce::Nonce;
use crate::prelude::*;
use crate::routing::router::{
	PaymentParameters, RouteParameters, DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
};
use crate::sign::NodeSigner;
use crate::types::features::BlindedHopFeatures;
use crate::types::payment::PaymentSecret;
use crate::util::errors::APIError;
use crate::util::ser::Writeable;
use crate::util::test_utils;
use bitcoin::secp256k1::{PublicKey, Secp256k1};

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
			payment_secret: PaymentSecret([0; 32]),
			total_msat: MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		}),
		payment_metadata: None,
		keysend_preimage: None,
		custom_tlvs: &Vec::new(),
		sender_intended_htlc_amt_msat: MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		cltv_expiry_height: nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
	}
	.serialized_length();
	let max_metadata_len = 1300
		- 1 // metadata type
		- crate::util::ser::BigSize(1200).serialized_length() // metadata length
		- 2 // onion payload varint prefix increased ser size due to metadata
		- PAYLOAD_HMAC_LEN
		- final_payload_len_without_metadata;
	let mut payment_metadata = vec![42; max_metadata_len];

	// Check that the maximum-size metadata is sendable.
	let (mut route_0_1, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], &nodes[1], amt_msat);
	let mut max_sized_onion = RecipientOnionFields {
		payment_secret: Some(payment_secret),
		payment_metadata: Some(payment_metadata.clone()),
		custom_tlvs: Vec::new(),
	};
	let route_params = route_0_1.route_params.clone().unwrap();
	let id = PaymentId(payment_hash.0);
	nodes[0]
		.node
		.send_payment(payment_hash, max_sized_onion.clone(), id, route_params, Retry::Attempts(0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1]];
	let args =
		PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash, events.pop().unwrap())
			.with_payment_secret(payment_secret)
			.with_payment_metadata(payment_metadata.clone());
	do_pass_along_path(args);
	claim_payment_along_route(ClaimAlongRouteArgs::new(
		&nodes[0],
		&[&[&nodes[1]]],
		payment_preimage,
	));

	// Check that the payment parameter for max path length will prevent us from routing past our
	// next-hop peer given the payment_metadata size.
	let (mut route_0_2, payment_hash_2, payment_preimage_2, payment_secret_2) =
		get_route_and_payment_hash!(&nodes[0], &nodes[2], amt_msat);
	let mut route_params_0_2 = route_0_2.route_params.clone().unwrap();
	route_params_0_2.payment_params.max_path_length = 1;
	nodes[0].router.expect_find_route_query(route_params_0_2);

	let id = PaymentId(payment_hash_2.0);
	let route_params = route_0_2.route_params.clone().unwrap();
	let err = nodes[0]
		.node
		.send_payment(payment_hash_2, max_sized_onion.clone(), id, route_params, Retry::Attempts(0))
		.unwrap_err();
	assert_eq!(err, RetryableSendFailure::RouteNotFound);

	// If our payment_metadata contains 1 additional byte, we'll fail prior to pathfinding.
	let mut too_large_onion = max_sized_onion.clone();
	too_large_onion.payment_metadata.as_mut().map(|mut md| md.push(42));

	// First confirm we'll fail to create the onion packet directly.
	let secp_ctx = Secp256k1::signing_only();
	route_0_1.paths[0].hops[0].fee_msat = MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY;
	route_0_1.paths[0].hops[0].cltv_expiry_delta = DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA;
	let err = onion_utils::create_payment_onion(
		&secp_ctx,
		&route_0_1.paths[0],
		&test_utils::privkey(42),
		MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		&too_large_onion,
		nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
		&payment_hash,
		&None,
		None,
		[0; 32],
	)
	.unwrap_err();
	match err {
		APIError::InvalidRoute { err } => {
			assert_eq!(err, "Route size too large considering onion data");
		},
		_ => panic!(),
	}

	let route_params = route_0_1.route_params.clone().unwrap();
	let err = nodes[0]
		.node
		.send_payment(payment_hash_2, too_large_onion, id, route_params, Retry::Attempts(0))
		.unwrap_err();
	assert_eq!(err, RetryableSendFailure::OnionPacketSizeExceeded);

	// If we remove enough payment_metadata bytes to allow for 2 hops, we're now able to send to
	// nodes[2].
	let two_hop_metadata = vec![42; max_metadata_len - INTERMED_PAYLOAD_LEN_ESTIMATE];
	let mut onion_allowing_2_hops = RecipientOnionFields {
		payment_secret: Some(payment_secret_2),
		payment_metadata: Some(two_hop_metadata.clone()),
		custom_tlvs: Vec::new(),
	};
	let mut route_params_0_2 = route_0_2.route_params.clone().unwrap();
	route_params_0_2.payment_params.max_path_length = 2;
	nodes[0].router.expect_find_route_query(route_params_0_2);
	let route_params = route_0_2.route_params.unwrap();
	nodes[0]
		.node
		.send_payment(payment_hash_2, onion_allowing_2_hops, id, route_params, Retry::Attempts(0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1], &nodes[2]];
	let args =
		PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash_2, events.pop().unwrap())
			.with_payment_secret(payment_secret_2)
			.with_payment_metadata(two_hop_metadata);
	do_pass_along_path(args);
	claim_payment_along_route(ClaimAlongRouteArgs::new(
		&nodes[0],
		&[&[&nodes[1], &nodes[2]]],
		payment_preimage_2,
	));
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
	let chan_upd_1_2 =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1_000_000, 0).0.contents;

	// Start with all nodes at the same height
	connect_blocks(&nodes[0], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);

	// Construct the route parameters for sending to nodes[2]'s 1-hop blinded path.
	let amt_msat = 100_000;
	let (payment_preimage, payment_hash, payment_secret) =
		get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let payee_tlvs = UnauthenticatedReceiveTlvs {
		payment_secret,
		payment_constraints: PaymentConstraints {
			max_cltv_expiry: u32::max_value(),
			htlc_minimum_msat: chan_upd_1_2.htlc_minimum_msat,
		},
		payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {}),
	};
	let nonce = Nonce([42u8; 16]);
	let expanded_key = chanmon_cfgs[2].keys_manager.get_expanded_key();
	let receive_auth_key = chanmon_cfgs[2].keys_manager.get_receive_auth_key();
	let payee_tlvs = payee_tlvs.authenticate(nonce, &expanded_key);
	let mut secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPaymentPath::new(
		&[],
		nodes[2].node.get_our_node_id(),
		receive_auth_key,
		payee_tlvs,
		u64::MAX,
		TEST_FINAL_CLTV as u16,
		&chanmon_cfgs[2].keys_manager,
		&secp_ctx,
	)
	.unwrap();
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
		encrypted_tlvs: &blinded_path.blinded_hops()[0].encrypted_payload,
		intro_node_blinding_point: Some(blinded_path.blinding_point()),
		keysend_preimage: None,
		invoice_request: None,
		custom_tlvs: &Vec::new(),
	}
	.serialized_length();
	let max_custom_tlv_len = 1300
		- crate::util::ser::BigSize(CUSTOM_TLV_TYPE).serialized_length() // custom TLV type
		- crate::util::ser::BigSize(1200).serialized_length() // custom TLV length
		- 1 // onion payload varint prefix increased ser size due to custom TLV
		- PAYLOAD_HMAC_LEN
		- final_payload_len_without_custom_tlv;

	// Check that we can send the maximum custom TLV with 1 blinded hop.
	let max_sized_onion = RecipientOnionFields::spontaneous_empty()
		.with_custom_tlvs(vec![(CUSTOM_TLV_TYPE, vec![42; max_custom_tlv_len])])
		.unwrap();
	let id = PaymentId(payment_hash.0);
	let no_retry = Retry::Attempts(0);
	nodes[1]
		.node
		.send_payment(payment_hash, max_sized_onion.clone(), id, route_params.clone(), no_retry)
		.unwrap();
	check_added_monitors(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[2]];
	let args =
		PassAlongPathArgs::new(&nodes[1], path, amt_msat, payment_hash, events.pop().unwrap())
			.with_payment_secret(payment_secret)
			.with_custom_tlvs(max_sized_onion.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[1], &[&[&nodes[2]]], payment_preimage)
			.with_custom_tlvs(max_sized_onion.custom_tlvs.clone()),
	);

	// If 1 byte is added to the custom TLV value, we'll fail to send prior to pathfinding.
	let mut too_large_custom_tlv_onion = max_sized_onion.clone();
	too_large_custom_tlv_onion.custom_tlvs[0].1.push(42);
	let err = nodes[1]
		.node
		.send_payment(payment_hash, too_large_custom_tlv_onion, id, route_params.clone(), no_retry)
		.unwrap_err();
	assert_eq!(err, RetryableSendFailure::OnionPacketSizeExceeded);

	// With the maximum-size custom TLV, our max path length is limited to 1, so attempting to route
	// nodes[0] -> nodes[2] will fail.
	let err = nodes[0]
		.node
		.send_payment(payment_hash, max_sized_onion.clone(), id, route_params.clone(), no_retry)
		.unwrap_err();
	assert_eq!(err, RetryableSendFailure::RouteNotFound);

	// If we remove enough custom TLV bytes to allow for 1 intermediate unblinded hop, we're now able
	// to send nodes[0] -> nodes[2].
	let mut onion_allows_2_hops = max_sized_onion.clone();
	onion_allows_2_hops.custom_tlvs[0]
		.1
		.resize(max_custom_tlv_len - INTERMED_PAYLOAD_LEN_ESTIMATE, 0);
	nodes[0]
		.node
		.send_payment(payment_hash, onion_allows_2_hops.clone(), id, route_params.clone(), no_retry)
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1], &nodes[2]];
	let args =
		PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash, events.pop().unwrap())
			.with_payment_secret(payment_secret)
			.with_custom_tlvs(onion_allows_2_hops.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2]]], payment_preimage)
			.with_custom_tlvs(onion_allows_2_hops.custom_tlvs),
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
	let chan_upd_2_3 =
		create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 1_000_000, 0).0.contents;

	// Ensure all nodes are at the same height
	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], node_max_height - nodes[3].best_block_info().1);

	// Construct the route parameters for sending to nodes[3]'s blinded path.
	let amt_msat = 100_000;
	let (payment_preimage, payment_hash, payment_secret) =
		get_payment_preimage_hash(&nodes[3], Some(amt_msat), None);
	let route_params = get_blinded_route_parameters(
		amt_msat,
		payment_secret,
		1,
		1_0000_0000,
		nodes.iter().skip(2).map(|n| n.node.get_our_node_id()).collect(),
		&[&chan_upd_2_3],
		&chanmon_cfgs[3].keys_manager,
	);

	// Calculate the maximum custom TLV value size where a valid onion packet is still possible.
	const CUSTOM_TLV_TYPE: u64 = 65537;
	let mut route = get_route(&nodes[1], &route_params).unwrap();
	let reserved_packet_bytes_without_custom_tlv: usize = onion_utils::build_onion_payloads(
		&route.paths[0],
		MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		&RecipientOnionFields::spontaneous_empty(),
		nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
		&None,
		None,
		None,
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
	let max_sized_onion = RecipientOnionFields::spontaneous_empty()
		.with_custom_tlvs(vec![(CUSTOM_TLV_TYPE, vec![42; max_custom_tlv_len])])
		.unwrap();
	let no_retry = Retry::Attempts(0);
	let id = PaymentId(payment_hash.0);
	nodes[1]
		.node
		.send_payment(payment_hash, max_sized_onion.clone(), id, route_params.clone(), no_retry)
		.unwrap();
	check_added_monitors(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[2], &nodes[3]];
	let args =
		PassAlongPathArgs::new(&nodes[1], path, amt_msat, payment_hash, events.pop().unwrap())
			.with_payment_secret(payment_secret)
			.with_custom_tlvs(max_sized_onion.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[1], &[&[&nodes[2], &nodes[3]]], payment_preimage)
			.with_custom_tlvs(max_sized_onion.custom_tlvs.clone()),
	);

	// If 1 byte is added to the custom TLV value, we'll fail to send prior to pathfinding.
	let mut too_large_onion = max_sized_onion.clone();
	too_large_onion.custom_tlvs[0].1.push(42);
	let err = nodes[1]
		.node
		.send_payment(payment_hash, too_large_onion.clone(), id, route_params.clone(), no_retry)
		.unwrap_err();
	assert_eq!(err, RetryableSendFailure::OnionPacketSizeExceeded);

	// Confirm that we can't construct an onion packet given this too-large custom TLV.
	let secp_ctx = Secp256k1::signing_only();
	route.paths[0].hops[0].fee_msat = MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY;
	route.paths[0].hops[0].cltv_expiry_delta = DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA;
	let err = onion_utils::create_payment_onion(
		&secp_ctx,
		&route.paths[0],
		&test_utils::privkey(42),
		MIN_FINAL_VALUE_ESTIMATE_WITH_OVERPAY,
		&too_large_onion,
		nodes[0].best_block_info().1 + DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
		&payment_hash,
		&None,
		None,
		[0; 32],
	)
	.unwrap_err();
	match err {
		APIError::InvalidRoute { err } => {
			assert_eq!(err, "Route size too large considering onion data");
		},
		_ => panic!(),
	}

	// With the maximum-size custom TLV, we can't have any intermediate unblinded hops, so attempting
	// to route nodes[0] -> nodes[3] will fail.
	let err = nodes[0]
		.node
		.send_payment(payment_hash, max_sized_onion.clone(), id, route_params.clone(), no_retry)
		.unwrap_err();
	assert_eq!(err, RetryableSendFailure::RouteNotFound);

	// If we remove enough custom TLV bytes to allow for 1 intermediate unblinded hop, we're now able
	// to send nodes[0] -> nodes[3].
	let mut onion_allowing_2_hops = max_sized_onion.clone();
	onion_allowing_2_hops.custom_tlvs[0]
		.1
		.resize(max_custom_tlv_len - INTERMED_PAYLOAD_LEN_ESTIMATE, 0);
	nodes[0]
		.node
		.send_payment(payment_hash, onion_allowing_2_hops.clone(), id, route_params, no_retry)
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path = &[&nodes[1], &nodes[2], &nodes[3]];
	let args =
		PassAlongPathArgs::new(&nodes[0], path, amt_msat, payment_hash, events.pop().unwrap())
			.with_payment_secret(payment_secret)
			.with_custom_tlvs(onion_allowing_2_hops.custom_tlvs.clone());
	do_pass_along_path(args);
	claim_payment_along_route(
		ClaimAlongRouteArgs::new(
			&nodes[0],
			&[&[&nodes[1], &nodes[2], &nodes[3]]],
			payment_preimage,
		)
		.with_custom_tlvs(onion_allowing_2_hops.custom_tlvs),
	);
}

#[test]
fn bolt12_invoice_too_large_blinded_paths() {
	// Check that we'll fail paying BOLT 12 invoices with too-large blinded paths prior to
	// pathfinding.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	nodes[1].router.expect_blinded_payment_paths(vec![
		BlindedPaymentPath::from_blinded_path_and_payinfo(
			PublicKey::from_slice(&[2; 33]).unwrap(),
			PublicKey::from_slice(&[2; 33]).unwrap(),
			vec![
				BlindedHop {
					blinded_node_id: PublicKey::from_slice(&[2; 33]).unwrap(),
					encrypted_payload: vec![42; 1300],
				},
				BlindedHop {
					blinded_node_id: PublicKey::from_slice(&[2; 33]).unwrap(),
					encrypted_payload: vec![42; 1300],
				},
			],
			BlindedPayInfo {
				fee_base_msat: 42,
				fee_proportional_millionths: 42,
				cltv_expiry_delta: 42,
				htlc_minimum_msat: 42,
				htlc_maximum_msat: 42_000_000,
				features: BlindedHopFeatures::empty(),
			},
		),
	]);

	let offer = nodes[1].node.create_offer_builder().unwrap().build().unwrap();
	let payment_id = PaymentId([1; 32]);
	nodes[0]
		.node
		.pay_for_offer(&offer, Some(5000), payment_id, OptionalOfferPaymentParams::default())
		.unwrap();
	let invreq_om = nodes[0]
		.onion_messenger
		.next_onion_message_for_peer(nodes[1].node.get_our_node_id())
		.unwrap();
	nodes[1].onion_messenger.handle_onion_message(nodes[0].node.get_our_node_id(), &invreq_om);

	let invoice_om = nodes[1]
		.onion_messenger
		.next_onion_message_for_peer(nodes[0].node.get_our_node_id())
		.unwrap();
	nodes[0].onion_messenger.handle_onion_message(nodes[1].node.get_our_node_id(), &invoice_om);
	// TODO: assert on the invoice error once we support replying to invoice OMs with failure info
	nodes[0].logger.assert_log_contains(
		"lightning::ln::channelmanager",
		"Failed paying invoice: OnionPacketSizeExceeded",
		1,
	);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentFailed { payment_id: id, .. } => {
			assert_eq!(id, payment_id)
		},
		_ => panic!("Unexpected event"),
	}
}
