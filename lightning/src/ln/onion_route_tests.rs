// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests of the onion error messages/codes which are returned when routing a payment fails.
//! These tests work by standing up full nodes and route payments across the network, checking the
//! returned errors decode to the correct thing.

use crate::chain::channelmonitor::{CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS};
use crate::events::{Event, HTLCHandlingFailureType, PathFailure, PaymentFailureReason};
use crate::ln::channel::EXPIRE_PREV_CONFIG_TICKS;
use crate::ln::channelmanager::{
	FailureCode, HTLCForwardInfo, PaymentId, PendingAddHTLCInfo, PendingHTLCInfo,
	PendingHTLCRouting, RecipientOnionFields, CLTV_FAR_FAR_AWAY, DISABLE_GOSSIP_TICKS,
	MIN_CLTV_EXPIRY_DELTA,
};
use crate::ln::functional_test_utils::test_default_channel_config;
use crate::ln::msgs;
use crate::ln::msgs::{
	BaseMessageHandler, ChannelMessageHandler, ChannelUpdate, FinalOnionHopData, MessageSendEvent,
	OutboundOnionPayload, OutboundTrampolinePayload,
};
use crate::ln::onion_utils::{
	self, build_onion_payloads, construct_onion_keys, LocalHTLCFailureReason,
};
use crate::ln::wire::Encode;
use crate::routing::gossip::{NetworkUpdate, RoutingFees};
use crate::routing::router::{
	get_route, BlindedTail, Path, PaymentParameters, Route, RouteHint, RouteHintHop, RouteHop,
	RouteParameters, TrampolineHop,
};
use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::types::features::{Bolt11InvoiceFeatures, InitFeatures};
use crate::types::payment::{PaymentHash, PaymentSecret};
use crate::util::config::{ChannelConfig, MaxDustHTLCExposure, UserConfig};
use crate::util::errors::APIError;
use crate::util::ser::{BigSize, Writeable, Writer};
use crate::util::test_utils;

use bitcoin::constants::ChainHash;
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

use bitcoin::secp256k1;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::blinded_path::BlindedHop;
use crate::io;
use crate::ln::functional_test_utils::*;
use crate::ln::onion_utils::{construct_trampoline_onion_keys, construct_trampoline_onion_packet};
use crate::prelude::*;
use bitcoin::hex::{DisplayHex, FromHex};
use types::features::{ChannelFeatures, Features, NodeFeatures};

use super::msgs::OnionErrorPacket;
use super::onion_utils::AttributionData;

fn run_onion_failure_test<F1, F2>(
	_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash,
	payment_secret: &PaymentSecret, callback_msg: F1, callback_node: F2, expected_retryable: bool,
	expected_error_code: Option<LocalHTLCFailureReason>,
	expected_channel_update: Option<NetworkUpdate>, expected_short_channel_id: Option<u64>,
	expected_failure_type: Option<HTLCHandlingFailureType>,
) where
	F1: for<'a> FnMut(&'a mut msgs::UpdateAddHTLC),
	F2: FnMut(),
{
	run_onion_failure_test_with_fail_intercept(
		_name,
		test_case,
		nodes,
		route,
		payment_hash,
		payment_secret,
		callback_msg,
		|_| {},
		callback_node,
		expected_retryable,
		expected_error_code,
		expected_channel_update,
		expected_short_channel_id,
		expected_failure_type,
	);
}

// test_case
// 0: node1 fails backward
// 1: final node fails backward
// 2: payment completed but the user rejects the payment
// 3: final node fails backward (but tamper onion payloads from node0)
// 100: trigger error in the intermediate node and tamper returning fail_htlc
// 200: trigger error in the final node and tamper returning fail_htlc
// 201: trigger error in the final node and delay
fn run_onion_failure_test_with_fail_intercept<F1, F2, F3>(
	_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash,
	payment_secret: &PaymentSecret, mut callback_msg: F1, mut callback_fail: F2,
	mut callback_node: F3, expected_retryable: bool,
	expected_error_reason: Option<LocalHTLCFailureReason>,
	expected_channel_update: Option<NetworkUpdate>, expected_short_channel_id: Option<u64>,
	expected_failure_type: Option<HTLCHandlingFailureType>,
) where
	F1: for<'a> FnMut(&'a mut msgs::UpdateAddHTLC),
	F2: for<'a> FnMut(&'a mut msgs::UpdateFailHTLC),
	F3: FnMut(),
{
	macro_rules! expect_event {
		($node: expr, $event_type: path) => {{
			let events = $node.node.get_and_clear_pending_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				$event_type { .. } => {},
				_ => panic!("Unexpected event"),
			}
		}};
	}

	macro_rules! expect_htlc_forward {
		($node: expr) => {{
			$node.node.process_pending_htlc_forwards();
		}};
	}

	// 0 ~~> 2 send payment
	let payment_id = PaymentId(nodes[0].keys_manager.backing.get_secure_random_bytes());
	let recipient_onion = RecipientOnionFields::secret_only(*payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route.clone(), *payment_hash, recipient_onion, payment_id)
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	// temper update_add (0 => 1)
	let mut update_add_0 = update_0.update_add_htlcs[0].clone();
	if test_case == 0 || test_case == 3 || test_case == 100 {
		callback_msg(&mut update_add_0);
		callback_node();
	}
	// 0 => 1 update_add & CS
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add_0);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	let update_1_0 = match test_case {
		0 | 100 => {
			// intermediate node failure; fail backward to 0
			expect_and_process_pending_htlcs(&nodes[1], false);
			expect_htlc_handling_failed_destinations!(
				nodes[1].node.get_and_clear_pending_events(),
				&[expected_failure_type.clone().unwrap()]
			);
			check_added_monitors(&nodes[1], 1);
			let update_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
			let fail_len = update_1_0.update_fail_htlcs.len();
			let malformed_len = update_1_0.update_fail_malformed_htlcs.len();
			assert!(fail_len + malformed_len == 1);
			update_1_0
		},
		1 | 2 | 3 | 200 | 201 => {
			// final node failure; forwarding to 2
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
			// forwarding on 1
			if test_case != 200 && test_case != 201 {
				callback_node();
			}
			expect_htlc_forward!(&nodes[1]);

			let update_1 = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
			check_added_monitors!(&nodes[1], 1);
			assert_eq!(update_1.update_add_htlcs.len(), 1);
			// tamper update_add (1 => 2)
			let mut update_add_1 = update_1.update_add_htlcs[0].clone();
			if test_case != 3 && test_case != 200 {
				callback_msg(&mut update_add_1);
			}

			// 1 => 2
			nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &update_add_1);
			commitment_signed_dance!(nodes[2], nodes[1], update_1.commitment_signed, false, true);

			match test_case {
				2 | 200 | 201 => {
					expect_htlc_forward!(&nodes[2]);
					expect_event!(&nodes[2], Event::PaymentClaimable);
					callback_node();
					expect_and_process_pending_htlcs_and_htlc_handling_failed(
						&nodes[2],
						&[HTLCHandlingFailureType::Receive { payment_hash: *payment_hash }],
					);
				},
				1 | 3 => {
					expect_htlc_forward!(&nodes[2]);
					expect_htlc_handling_failed_destinations!(
						nodes[2].node.get_and_clear_pending_events(),
						[expected_failure_type.clone().unwrap()]
					);
				},
				_ => {},
			}
			check_added_monitors!(&nodes[2], 1);

			let update_2_1 = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
			assert!(update_2_1.update_fail_htlcs.len() == 1);

			let mut fail_msg = update_2_1.update_fail_htlcs[0].clone();
			match test_case {
				// Trigger error in the final node and tamper returning fail_htlc.
				200 => callback_fail(&mut fail_msg),
				// Trigger error in the final node and delay.
				201 => {
					std::thread::sleep(std::time::Duration::from_millis(200));
				},
				_ => {},
			}

			// 2 => 1
			nodes[1].node.handle_update_fail_htlc(nodes[2].node.get_our_node_id(), &fail_msg);
			commitment_signed_dance!(nodes[1], nodes[2], update_2_1.commitment_signed, true);

			// backward fail on 1
			let update_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
			assert!(update_1_0.update_fail_htlcs.len() == 1);
			update_1_0
		},
		_ => unreachable!(),
	};

	// 1 => 0 commitment_signed_dance
	if update_1_0.update_fail_htlcs.len() > 0 {
		let mut fail_msg = update_1_0.update_fail_htlcs[0].clone();
		if test_case == 100 {
			callback_fail(&mut fail_msg);
		}
		nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	} else {
		nodes[0].node.handle_update_fail_malformed_htlc(
			nodes[1].node.get_our_node_id(),
			&update_1_0.update_fail_malformed_htlcs[0],
		);
	};

	commitment_signed_dance!(nodes[0], nodes[1], update_1_0.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let &Event::PaymentPathFailed {
		ref payment_failed_permanently,
		ref short_channel_id,
		ref error_code,
		failure: PathFailure::OnPath { ref network_update },
		ref hold_times,
		..
	} = &events[0]
	{
		// When resolution is delayed, we expect that to show up in the hold times. Hold times are only reported in std.
		if test_case == 201 {
			#[cfg(feature = "std")]
			assert!(hold_times.iter().any(|ht| *ht > 0));
			#[cfg(not(feature = "std"))]
			assert!(hold_times.iter().all(|ht| *ht == 0));
		}
		assert_eq!(*payment_failed_permanently, !expected_retryable);
		assert_eq!(error_code.is_none(), expected_error_reason.is_none());
		if let Some(expected_reason) = expected_error_reason {
			assert_eq!(expected_reason, error_code.unwrap().into())
		}
		if expected_channel_update.is_some() {
			match network_update {
				Some(update) => match update {
					&NetworkUpdate::ChannelFailure { ref short_channel_id, ref is_permanent } => {
						if let NetworkUpdate::ChannelFailure {
							short_channel_id: ref expected_short_channel_id,
							is_permanent: ref expected_is_permanent,
						} = expected_channel_update.unwrap()
						{
							assert!(*short_channel_id == *expected_short_channel_id);
							assert!(*is_permanent == *expected_is_permanent);
						} else {
							panic!("Unexpected message event");
						}
					},
					&NetworkUpdate::NodeFailure { ref node_id, ref is_permanent } => {
						if let NetworkUpdate::NodeFailure {
							node_id: ref expected_node_id,
							is_permanent: ref expected_is_permanent,
						} = expected_channel_update.unwrap()
						{
							assert!(*node_id == *expected_node_id);
							assert!(*is_permanent == *expected_is_permanent);
						} else {
							panic!("Unexpected message event");
						}
					},
				},
				None => panic!("Expected channel update"),
			}
		} else {
			assert!(network_update.is_none());
		}
		if let Some(expected_short_channel_id) = expected_short_channel_id {
			match short_channel_id {
				Some(short_channel_id) => assert_eq!(*short_channel_id, expected_short_channel_id),
				None => panic!("Expected short channel id"),
			}
		} else {
			assert!(short_channel_id.is_none());
		}
	} else {
		panic!("Unexpected event");
	}
	match events[1] {
		Event::PaymentFailed {
			payment_hash: ev_payment_hash,
			payment_id: ev_payment_id,
			reason: ref ev_reason,
		} => {
			assert_eq!(Some(*payment_hash), ev_payment_hash);
			assert_eq!(payment_id, ev_payment_id);

			let expected_reason = if expected_retryable {
				PaymentFailureReason::RetriesExhausted
			} else {
				PaymentFailureReason::RecipientRejected
			};
			assert_eq!(expected_reason, ev_reason.unwrap());
		},
		_ => panic!("Unexpected second event"),
	}
}

impl msgs::ChannelUpdate {
	fn dummy(short_channel_id: u64) -> msgs::ChannelUpdate {
		use bitcoin::hash_types::BlockHash;
		use bitcoin::secp256k1::ecdsa::Signature;
		use bitcoin::secp256k1::ffi::Signature as FFISignature;
		msgs::ChannelUpdate {
			signature: Signature::from(unsafe { FFISignature::new() }),
			contents: msgs::UnsignedChannelUpdate {
				chain_hash: ChainHash::from(BlockHash::hash(&vec![0u8][..]).as_ref()),
				short_channel_id,
				timestamp: 0,
				message_flags: 1, // Only must_be_one
				channel_flags: 0,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: msgs::MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: vec![],
			},
		}
	}
}

struct BogusOnionHopData {
	data: Vec<u8>,
}
impl BogusOnionHopData {
	fn new(orig: msgs::OutboundOnionPayload) -> Self {
		Self { data: orig.encode() }
	}
}
impl Writeable for BogusOnionHopData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&self.data[..])
	}
}

#[test]
fn test_fee_failures() {
	// Tests that the fee required when forwarding remains consistent over time. This was
	// previously broken, with forwarding fees floating based on the fee estimator at the time of
	// forwarding.
	//
	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 196;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(config.clone()), Some(config.clone()), Some(config)],
	);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let channels = [
		create_announced_chan_between_nodes(&nodes, 0, 1),
		create_announced_chan_between_nodes(&nodes, 1, 2),
	];

	// positive case
	let (route, payment_hash_success, payment_preimage_success, payment_secret_success) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 40_000);
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret_success);
	let payment_id = PaymentId(payment_hash_success.0);
	nodes[0]
		.node
		.send_payment_with_route(route.clone(), payment_hash_success, recipient_onion, payment_id)
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(
		&nodes[0],
		&[&[&nodes[1], &nodes[2]]],
		40_000,
		payment_hash_success,
		payment_secret_success,
	);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_success);

	// If the hop gives fee_insufficient but enough fees were provided, then the previous hop
	// malleated the payment before forwarding, taking funds when they shouldn't have. However,
	// because we ignore channel update contents, we will still blame the 2nd channel.
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);
	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test(
		"fee_insufficient",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::FeeInsufficient),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(HTLCHandlingFailureType::Forward {
			node_id: Some(nodes[2].node.get_our_node_id()),
			channel_id: channels[1].2,
		}),
	);

	// In an earlier version, we spuriously failed to forward payments if the expected feerate
	// changed between the channel open and the payment.
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 2;
	}

	let (payment_preimage_success, payment_hash_success, payment_secret_success) =
		get_payment_preimage_hash!(nodes[2]);
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret_success);
	let payment_id = PaymentId(payment_hash_success.0);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash_success, recipient_onion, payment_id)
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(
		&nodes[0],
		&[&[&nodes[1], &nodes[2]]],
		40_000,
		payment_hash_success,
		payment_secret_success,
	);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_success);
}

#[test]
fn test_onion_failure() {
	// When we check for amount_below_minimum below, we want to test that we're using the *right*
	// amount, thus we need different htlc_minimum_msat values. We set node[2]'s htlc_minimum_msat
	// to 2000, which is above the default value of 1000 set in create_node_chanmgrs.
	// This exposed a previous bug because we were using the wrong value all the way down in
	// Channel::get_counterparty_htlc_minimum_msat().
	let mut node_2_cfg: UserConfig = test_default_channel_config();
	node_2_cfg.channel_handshake_config.our_htlc_minimum_msat = 2000;
	node_2_cfg.channel_handshake_config.announce_for_forwarding = true;
	node_2_cfg.channel_handshake_limits.force_announced_channel_preference = false;

	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 196;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(config.clone()), Some(config), Some(node_2_cfg)],
	);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let channels = [
		create_announced_chan_between_nodes(&nodes, 0, 1),
		create_announced_chan_between_nodes(&nodes, 1, 2),
	];
	for node in nodes.iter() {
		*node.keys_manager.override_random_bytes.lock().unwrap() = Some([3; 32]);
	}
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 40000);
	// positive case
	send_payment(&nodes[0], &vec![&nodes[1], &nodes[2]][..], 40000);

	let next_hop_failure = HTLCHandlingFailureType::Forward {
		node_id: Some(nodes[2].node.get_our_node_id()),
		channel_id: channels[1].2,
	};

	// intermediate node failure
	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test(
		"invalid_realm",
		0,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let cur_height = nodes[0].best_block_info().1 + 1;
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let recipient_fields = RecipientOnionFields::spontaneous_empty();
			let path = &route.paths[0];
			let (mut onion_payloads, _htlc_msat, _htlc_cltv) =
				build_onion_payloads(path, 40000, &recipient_fields, cur_height, &None, None, None)
					.unwrap();
			let mut new_payloads = Vec::new();
			for payload in onion_payloads.drain(..) {
				new_payloads.push(BogusOnionHopData::new(payload));
			}
			// break the first (non-final) hop payload by swapping the realm (0) byte for a byte
			// describing a length-1 TLV payload, which is obviously bogus.
			new_payloads[0].data[0] = 1;
			msg.onion_routing_packet = onion_utils::construct_onion_packet_with_writable_hopdata(
				new_payloads,
				onion_keys,
				[0; 32],
				&payment_hash,
			)
			.unwrap();
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::InvalidOnionPayload),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true }),
		Some(short_channel_id),
		Some(HTLCHandlingFailureType::InvalidOnion),
	);

	// final node failure
	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test(
		"invalid_realm",
		3,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let cur_height = nodes[0].best_block_info().1 + 1;
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let recipient_fields = RecipientOnionFields::spontaneous_empty();
			let path = &route.paths[0];
			let (mut onion_payloads, _htlc_msat, _htlc_cltv) =
				build_onion_payloads(path, 40000, &recipient_fields, cur_height, &None, None, None)
					.unwrap();
			let mut new_payloads = Vec::new();
			for payload in onion_payloads.drain(..) {
				new_payloads.push(BogusOnionHopData::new(payload));
			}
			// break the last-hop payload by swapping the realm (0) byte for a byte describing a
			// length-1 TLV payload, which is obviously bogus.
			new_payloads[1].data[0] = 1;
			msg.onion_routing_packet = onion_utils::construct_onion_packet_with_writable_hopdata(
				new_payloads,
				onion_keys,
				[0; 32],
				&payment_hash,
			)
			.unwrap();
		},
		|| {},
		false,
		Some(LocalHTLCFailureReason::InvalidOnionPayload),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true }),
		Some(short_channel_id),
		Some(HTLCHandlingFailureType::InvalidOnion),
	);

	// the following three with run_onion_failure_test_with_fail_intercept() test only the origin node
	// receiving simulated fail messages
	// intermediate node failure
	run_onion_failure_test_with_fail_intercept(
		"temporary_node_failure",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			// trigger error
			msg.amount_msat -= 1;
		},
		|msg| {
			// and tamper returning error message
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[0].shared_secret.as_ref(),
				LocalHTLCFailureReason::TemporaryNodeFailure,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::TemporaryNodeFailure),
		Some(NetworkUpdate::NodeFailure {
			node_id: route.paths[0].hops[0].pubkey,
			is_permanent: false,
		}),
		Some(route.paths[0].hops[0].short_channel_id),
		Some(next_hop_failure.clone()),
	);

	// final node failure
	run_onion_failure_test_with_fail_intercept(
		"temporary_node_failure",
		200,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_msg| {},
		|msg| {
			// and tamper returning error message
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[1].shared_secret.as_ref(),
				LocalHTLCFailureReason::TemporaryNodeFailure,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {
			nodes[2].node.fail_htlc_backwards(&payment_hash);
		},
		true,
		Some(LocalHTLCFailureReason::TemporaryNodeFailure),
		Some(NetworkUpdate::NodeFailure {
			node_id: route.paths[0].hops[1].pubkey,
			is_permanent: false,
		}),
		Some(route.paths[0].hops[1].short_channel_id),
		None,
	);
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept(
		"permanent_node_failure",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[0].shared_secret.as_ref(),
				LocalHTLCFailureReason::PermanentNodeFailure,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::PermanentNodeFailure),
		Some(NetworkUpdate::NodeFailure {
			node_id: route.paths[0].hops[0].pubkey,
			is_permanent: true,
		}),
		Some(route.paths[0].hops[0].short_channel_id),
		Some(next_hop_failure.clone()),
	);

	// final node failure
	run_onion_failure_test_with_fail_intercept(
		"permanent_node_failure",
		200,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_msg| {},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[1].shared_secret.as_ref(),
				LocalHTLCFailureReason::PermanentNodeFailure,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {
			nodes[2].node.fail_htlc_backwards(&payment_hash);
		},
		false,
		Some(LocalHTLCFailureReason::PermanentNodeFailure),
		Some(NetworkUpdate::NodeFailure {
			node_id: route.paths[0].hops[1].pubkey,
			is_permanent: true,
		}),
		Some(route.paths[0].hops[1].short_channel_id),
		None,
	);
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept(
		"required_node_feature_missing",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[0].shared_secret.as_ref(),
				LocalHTLCFailureReason::RequiredNodeFeature,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {
			nodes[2].node.fail_htlc_backwards(&payment_hash);
		},
		true,
		Some(LocalHTLCFailureReason::RequiredNodeFeature),
		Some(NetworkUpdate::NodeFailure {
			node_id: route.paths[0].hops[0].pubkey,
			is_permanent: true,
		}),
		Some(route.paths[0].hops[0].short_channel_id),
		Some(next_hop_failure.clone()),
	);

	// final node failure
	run_onion_failure_test_with_fail_intercept(
		"required_node_feature_missing",
		200,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_msg| {},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[1].shared_secret.as_ref(),
				LocalHTLCFailureReason::RequiredNodeFeature,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {
			nodes[2].node.fail_htlc_backwards(&payment_hash);
		},
		false,
		Some(LocalHTLCFailureReason::RequiredNodeFeature),
		Some(NetworkUpdate::NodeFailure {
			node_id: route.paths[0].hops[1].pubkey,
			is_permanent: true,
		}),
		Some(route.paths[0].hops[1].short_channel_id),
		None,
	);
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);

	// Our immediate peer sent UpdateFailMalformedHTLC because it couldn't understand the onion in
	// the UpdateAddHTLC that we sent.
	let short_channel_id = channels[0].0.contents.short_channel_id;
	run_onion_failure_test(
		"invalid_onion_version",
		0,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.onion_routing_packet.version = 1;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::InvalidOnionVersion),
		None,
		Some(short_channel_id),
		Some(HTLCHandlingFailureType::InvalidOnion),
	);

	run_onion_failure_test(
		"invalid_onion_hmac",
		0,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.onion_routing_packet.hmac = [3; 32];
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::InvalidOnionHMAC),
		None,
		Some(short_channel_id),
		Some(HTLCHandlingFailureType::InvalidOnion),
	);

	run_onion_failure_test(
		"invalid_onion_key",
		0,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.onion_routing_packet.public_key = Err(secp256k1::Error::InvalidPublicKey);
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::InvalidOnionKey),
		None,
		Some(short_channel_id),
		Some(HTLCHandlingFailureType::InvalidOnion),
	);

	let short_channel_id = channels[1].0.contents.short_channel_id;
	let chan_update = ChannelUpdate::dummy(short_channel_id);

	let mut err_data = Vec::new();
	err_data.extend_from_slice(&(chan_update.serialized_length() as u16 + 2).to_be_bytes());
	err_data.extend_from_slice(&ChannelUpdate::TYPE.to_be_bytes());
	err_data.extend_from_slice(&chan_update.encode());
	run_onion_failure_test_with_fail_intercept(
		"temporary_channel_failure",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[0].shared_secret.as_ref(),
				LocalHTLCFailureReason::TemporaryChannelFailure,
				&err_data,
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::TemporaryChannelFailure),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);

	// Check we can still handle onion failures that include channel updates without a type prefix
	let err_data_without_type = chan_update.encode_with_len();
	run_onion_failure_test_with_fail_intercept(
		"temporary_channel_failure",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[0].shared_secret.as_ref(),
				LocalHTLCFailureReason::TemporaryChannelFailure,
				&err_data_without_type,
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::TemporaryChannelFailure),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test_with_fail_intercept(
		"permanent_channel_failure",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[0].shared_secret.as_ref(),
				LocalHTLCFailureReason::PermanentChannelFailure,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
			// short_channel_id from the processing node
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::PermanentChannelFailure),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test_with_fail_intercept(
		"required_channel_feature_missing",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[0].shared_secret.as_ref(),
				LocalHTLCFailureReason::RequiredChannelFeature,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
			// short_channel_id from the processing node
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::RequiredChannelFeature),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);

	let mut bogus_route = route.clone();
	bogus_route.paths[0].hops[1].short_channel_id -= 1;
	let short_channel_id = bogus_route.paths[0].hops[1].short_channel_id;
	run_onion_failure_test(
		"unknown_next_peer",
		100,
		&nodes,
		&bogus_route,
		&payment_hash,
		&payment_secret,
		|_| {},
		|| {},
		true,
		Some(LocalHTLCFailureReason::UnknownNextPeer),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true }),
		Some(short_channel_id),
		Some(HTLCHandlingFailureType::InvalidForward { requested_forward_scid: short_channel_id }),
	);

	let short_channel_id = channels[1].0.contents.short_channel_id;
	let amt_to_forward = {
		let (per_peer_state, mut peer_state);
		let chan = get_channel_ref!(nodes[1], nodes[2], per_peer_state, peer_state, channels[1].2);
		chan.context().get_counterparty_htlc_minimum_msat() - 1
	};
	let mut bogus_route = route.clone();
	let route_len = bogus_route.paths[0].hops.len();
	bogus_route.paths[0].hops[route_len - 1].fee_msat = amt_to_forward;
	run_onion_failure_test(
		"amount_below_minimum",
		100,
		&nodes,
		&bogus_route,
		&payment_hash,
		&payment_secret,
		|_| {},
		|| {},
		true,
		Some(LocalHTLCFailureReason::AmountBelowMinimum),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);

	// Clear pending payments so that the following positive test has the correct payment hash.
	for node in nodes.iter() {
		node.node.clear_pending_payments();
	}

	// Test a positive test-case with one extra msat, meeting the minimum.
	bogus_route.paths[0].hops[route_len - 1].fee_msat = amt_to_forward + 1;
	let preimage =
		send_along_route(&nodes[0], bogus_route, &[&nodes[1], &nodes[2]], amt_to_forward + 1).0;
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], preimage);

	// We ignore channel update contents in onion errors, so will blame the 2nd channel even though
	// the first node is the one that messed up.
	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test(
		"fee_insufficient",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::FeeInsufficient),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test(
		"incorrect_cltv_expiry",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			// need to violate: cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value
			msg.cltv_expiry -= 1;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::IncorrectCLTVExpiry),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test(
		"expiry_too_soon",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS + 1;
			connect_blocks(&nodes[0], height - nodes[0].best_block_info().1);
			connect_blocks(&nodes[1], height - nodes[1].best_block_info().1);
			connect_blocks(&nodes[2], height - nodes[2].best_block_info().1);
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::CLTVExpiryTooSoon),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);

	run_onion_failure_test(
		"unknown_payment_hash",
		2,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_| {},
		|| {
			nodes[2].node.fail_htlc_backwards(&payment_hash);
		},
		false,
		Some(LocalHTLCFailureReason::IncorrectPaymentDetails),
		None,
		None,
		None,
	);
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);

	run_onion_failure_test(
		"final_expiry_too_soon",
		1,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS + 1;
			connect_blocks(&nodes[0], height - nodes[0].best_block_info().1);
			connect_blocks(&nodes[1], height - nodes[1].best_block_info().1);
			connect_blocks(&nodes[2], height - nodes[2].best_block_info().1);
		},
		|| {},
		false,
		Some(LocalHTLCFailureReason::IncorrectPaymentDetails),
		None,
		None,
		Some(HTLCHandlingFailureType::Receive { payment_hash }),
	);

	run_onion_failure_test(
		"final_incorrect_cltv_expiry",
		1,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_| {},
		|| {
			nodes[1].node.process_pending_update_add_htlcs();
			for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
				for f in pending_forwards.iter_mut() {
					match f {
						&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
							ref mut forward_info,
							..
						}) => forward_info.outgoing_cltv_value -= 1,
						_ => {},
					}
				}
			}
		},
		true,
		Some(LocalHTLCFailureReason::FinalIncorrectCLTVExpiry),
		None,
		Some(channels[1].0.contents.short_channel_id),
		Some(HTLCHandlingFailureType::Receive { payment_hash }),
	);

	run_onion_failure_test(
		"final_incorrect_htlc_amount",
		1,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_| {},
		|| {
			nodes[1].node.process_pending_update_add_htlcs();
			// violate amt_to_forward > msg.amount_msat
			for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
				for f in pending_forwards.iter_mut() {
					match f {
						&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
							ref mut forward_info,
							..
						}) => forward_info.outgoing_amt_msat -= 1,
						_ => {},
					}
				}
			}
		},
		true,
		Some(LocalHTLCFailureReason::FinalIncorrectHTLCAmount),
		None,
		Some(channels[1].0.contents.short_channel_id),
		Some(HTLCHandlingFailureType::Receive { payment_hash }),
	);

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test(
		"channel_disabled",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_| {},
		|| {
			// disconnect event to the channel between nodes[1] ~ nodes[2]
			nodes[1].node.peer_disconnected(nodes[2].node.get_our_node_id());
			nodes[2].node.peer_disconnected(nodes[1].node.get_our_node_id());
		},
		true,
		Some(LocalHTLCFailureReason::TemporaryChannelFailure),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);
	run_onion_failure_test(
		"channel_disabled",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_| {},
		|| {
			// disconnect event to the channel between nodes[1] ~ nodes[2]
			for _ in 0..DISABLE_GOSSIP_TICKS + 1 {
				nodes[1].node.timer_tick_occurred();
				nodes[2].node.timer_tick_occurred();
			}
			nodes[1].node.get_and_clear_pending_msg_events();
			nodes[2].node.get_and_clear_pending_msg_events();
		},
		true,
		Some(LocalHTLCFailureReason::ChannelDisabled),
		Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false }),
		Some(short_channel_id),
		Some(next_hop_failure.clone()),
	);
	reconnect_nodes(ReconnectArgs::new(&nodes[1], &nodes[2]));

	run_onion_failure_test(
		"expiry_too_far",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let mut route = route.clone();
			let height = nodes[2].best_block_info().1;
			route.paths[0].hops[1].cltv_expiry_delta +=
				CLTV_FAR_FAR_AWAY + route.paths[0].hops[0].cltv_expiry_delta + 1;
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let recipient_fields = RecipientOnionFields::spontaneous_empty();
			let path = &route.paths[0];
			let (onion_payloads, _, htlc_cltv) =
				build_onion_payloads(path, 40000, &recipient_fields, height, &None, None, None)
					.unwrap();
			let onion_packet = onion_utils::construct_onion_packet(
				onion_payloads,
				onion_keys,
				[0; 32],
				&payment_hash,
			)
			.unwrap();
			msg.cltv_expiry = htlc_cltv;
			msg.onion_routing_packet = onion_packet;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::CLTVExpiryTooFar),
		Some(NetworkUpdate::NodeFailure {
			node_id: route.paths[0].hops[0].pubkey,
			is_permanent: true,
		}),
		Some(route.paths[0].hops[0].short_channel_id),
		Some(next_hop_failure.clone()),
	);

	run_onion_failure_test_with_fail_intercept(
		"mpp_timeout",
		200,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_msg| {},
		|msg| {
			// Tamper returning error message
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let failure = onion_utils::build_failure_packet(
				onion_keys[1].shared_secret.as_ref(),
				LocalHTLCFailureReason::MPPTimeout,
				&[0; 0],
				0,
			);
			msg.reason = failure.data;
			msg.attribution_data = failure.attribution_data;
		},
		|| {
			nodes[2].node.fail_htlc_backwards(&payment_hash);
		},
		true,
		Some(LocalHTLCFailureReason::MPPTimeout),
		None,
		None,
		None,
	);

	run_onion_failure_test_with_fail_intercept(
		"bogus err packet with valid hmac",
		200,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_msg| {},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let mut decoded_err_packet = msgs::DecodedOnionErrorPacket {
				failuremsg: vec![0],
				pad: vec![0; 255],
				hmac: [0; 32],
			};
			let um = onion_utils::gen_um_from_shared_secret(&onion_keys[1].shared_secret.as_ref());
			let mut hmac = HmacEngine::<Sha256>::new(&um);
			hmac.input(&decoded_err_packet.encode()[32..]);
			decoded_err_packet.hmac = Hmac::from_engine(hmac).to_byte_array();
			let mut onion_error = OnionErrorPacket {
				data: decoded_err_packet.encode(),
				attribution_data: Some(AttributionData::new()),
			};
			onion_error
				.attribution_data
				.as_mut()
				.unwrap()
				.add_hmacs(&onion_keys[1].shared_secret.as_ref(), &onion_error.data);
			onion_utils::test_crypt_failure_packet(
				&onion_keys[1].shared_secret.as_ref(),
				&mut onion_error,
			);
			msg.reason = onion_error.data;
			msg.attribution_data = onion_error.attribution_data;
		},
		|| nodes[2].node.fail_htlc_backwards(&payment_hash),
		false,
		None,
		Some(NetworkUpdate::NodeFailure {
			node_id: route.paths[0].hops[1].pubkey,
			is_permanent: true,
		}),
		Some(channels[1].0.contents.short_channel_id),
		None,
	);

	run_onion_failure_test_with_fail_intercept(
		"bogus err packet that is too short for an hmac",
		200,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_msg| {},
		|msg| {
			msg.reason = vec![1, 2, 3];
		},
		|| nodes[2].node.fail_htlc_backwards(&payment_hash),
		false,
		None,
		None,
		None,
		None,
	);

	run_onion_failure_test_with_fail_intercept(
		"0-length channel update in intermediate node UPDATE onion failure",
		100,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|msg| {
			msg.amount_msat -= 1;
		},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let mut decoded_err_packet = msgs::DecodedOnionErrorPacket {
				failuremsg: vec![
					0x10, 0x7, // UPDATE|7
					0x0, 0x0, // 0-len channel update
				],
				pad: vec![0; 255 - 4 /* 4-byte error message */],
				hmac: [0; 32],
			};
			let um = onion_utils::gen_um_from_shared_secret(&onion_keys[0].shared_secret.as_ref());
			let mut hmac = HmacEngine::<Sha256>::new(&um);
			hmac.input(&decoded_err_packet.encode()[32..]);
			decoded_err_packet.hmac = Hmac::from_engine(hmac).to_byte_array();
			let mut onion_error = OnionErrorPacket {
				data: decoded_err_packet.encode(),
				attribution_data: Some(AttributionData::new()),
			};
			onion_error
				.attribution_data
				.as_mut()
				.unwrap()
				.add_hmacs(&onion_keys[0].shared_secret.as_ref(), &onion_error.data);
			onion_utils::test_crypt_failure_packet(
				&onion_keys[0].shared_secret.as_ref(),
				&mut onion_error,
			);
			msg.reason = onion_error.data;
			msg.attribution_data = onion_error.attribution_data;
		},
		|| {},
		true,
		Some(LocalHTLCFailureReason::TemporaryChannelFailure),
		Some(NetworkUpdate::ChannelFailure {
			short_channel_id: channels[1].0.contents.short_channel_id,
			is_permanent: false,
		}),
		Some(channels[1].0.contents.short_channel_id),
		Some(next_hop_failure.clone()),
	);
	run_onion_failure_test_with_fail_intercept(
		"0-length channel update in final node UPDATE onion failure",
		200,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_msg| {},
		|msg| {
			let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
			let onion_keys =
				construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
			let mut decoded_err_packet = msgs::DecodedOnionErrorPacket {
				failuremsg: vec![
					0x10, 0x7, // UPDATE|7
					0x0, 0x0, // 0-len channel update
				],
				pad: vec![0; 255 - 4 /* 4-byte error message */],
				hmac: [0; 32],
			};
			let um = onion_utils::gen_um_from_shared_secret(&onion_keys[1].shared_secret.as_ref());
			let mut hmac = HmacEngine::<Sha256>::new(&um);
			hmac.input(&decoded_err_packet.encode()[32..]);
			decoded_err_packet.hmac = Hmac::from_engine(hmac).to_byte_array();
			let mut onion_error = OnionErrorPacket {
				data: decoded_err_packet.encode(),
				attribution_data: Some(AttributionData::new()),
			};
			onion_error
				.attribution_data
				.as_mut()
				.unwrap()
				.add_hmacs(&onion_keys[1].shared_secret.as_ref(), &onion_error.data);
			onion_utils::test_crypt_failure_packet(
				&onion_keys[1].shared_secret.as_ref(),
				&mut onion_error,
			);
			msg.reason = onion_error.data;
			msg.attribution_data = onion_error.attribution_data;
		},
		|| nodes[2].node.fail_htlc_backwards(&payment_hash),
		true,
		Some(LocalHTLCFailureReason::TemporaryChannelFailure),
		Some(NetworkUpdate::ChannelFailure {
			short_channel_id: channels[1].0.contents.short_channel_id,
			is_permanent: false,
		}),
		Some(channels[1].0.contents.short_channel_id),
		None,
	);
	run_onion_failure_test(
		"delayed_fail",
		201,
		&nodes,
		&route,
		&payment_hash,
		&payment_secret,
		|_| {},
		|| {
			nodes[2].node.fail_htlc_backwards(&payment_hash);
		},
		false,
		Some(LocalHTLCFailureReason::IncorrectPaymentDetails),
		None,
		None,
		None,
	);
}

#[test]
fn test_overshoot_final_cltv() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);
	let (route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 40000);

	let payment_id = PaymentId(nodes[0].keys_manager.backing.get_secure_random_bytes());
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash, recipient_onion, payment_id)
		.unwrap();

	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add_0 = update_0.update_add_htlcs[0].clone();
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add_0);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
					ref mut forward_info, ..
				}) => forward_info.outgoing_cltv_value += 1,
				_ => {},
			}
		}
	}
	expect_and_process_pending_htlcs(&nodes[1], false);

	check_added_monitors!(&nodes[1], 1);
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
	let mut update_add_1 = update_1.update_add_htlcs[0].clone();
	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), &update_add_1);
	commitment_signed_dance!(nodes[2], nodes[1], update_1.commitment_signed, false, true);

	expect_and_process_pending_htlcs(&nodes[2], false);
	expect_payment_claimable!(nodes[2], payment_hash, payment_secret, 40_000);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
}

fn do_test_onion_failure_stale_channel_update(announce_for_forwarding: bool) {
	// Create a network of three nodes and two channels connecting them. We'll be updating the
	// HTLC relay policy of the second channel, causing forwarding failures at the first hop.
	let mut config = UserConfig::default();
	config.channel_handshake_config.announce_for_forwarding = announce_for_forwarding;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.accept_forwards_to_priv_channels = !announce_for_forwarding;
	config.channel_config.max_dust_htlc_exposure =
		MaxDustHTLCExposure::FeeRateMultiplier(5_000_000 / 253);
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let persister;
	let chain_monitor;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(config), None]);
	let channel_manager_1_deserialized;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let other_channel = create_chan_between_nodes(&nodes[0], &nodes[1]);
	let channel_to_update = if announce_for_forwarding {
		let channel = create_announced_chan_between_nodes(&nodes, 1, 2);
		(channel.2, channel.0.contents.short_channel_id)
	} else {
		let channel = create_unannounced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 10001);
		(channel.0.channel_id, channel.0.short_channel_id_alias.unwrap())
	};
	let channel_to_update_counterparty = &nodes[2].node.get_our_node_id();

	let default_config = ChannelConfig::default();

	// A test payment should succeed as the ChannelConfig has not been changed yet.
	const PAYMENT_AMT: u64 = 40000;
	let (route, payment_hash, payment_preimage, payment_secret) = if announce_for_forwarding {
		get_route_and_payment_hash!(nodes[0], nodes[2], PAYMENT_AMT)
	} else {
		let hop_hints = vec![RouteHint(vec![RouteHintHop {
			src_node_id: nodes[1].node.get_our_node_id(),
			short_channel_id: channel_to_update.1,
			fees: RoutingFees {
				base_msat: default_config.forwarding_fee_base_msat,
				proportional_millionths: default_config.forwarding_fee_proportional_millionths,
			},
			cltv_expiry_delta: default_config.cltv_expiry_delta,
			htlc_maximum_msat: None,
			htlc_minimum_msat: None,
		}])];
		let payment_params =
			PaymentParameters::from_node_id(*channel_to_update_counterparty, TEST_FINAL_CLTV)
				.with_bolt11_features(nodes[2].node.bolt11_invoice_features())
				.unwrap()
				.with_route_hints(hop_hints)
				.unwrap();
		get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, PAYMENT_AMT)
	};
	send_along_route_with_secret(
		&nodes[0],
		route.clone(),
		&[&[&nodes[1], &nodes[2]]],
		PAYMENT_AMT,
		payment_hash,
		payment_secret,
	);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// Closure to force expiry of a channel's previous config.
	let expire_prev_config = || {
		for _ in 0..EXPIRE_PREV_CONFIG_TICKS {
			nodes[1].node.timer_tick_occurred();
		}
	};

	// Closure to update and retrieve the latest ChannelUpdate.
	let update_and_get_channel_update = |config: &ChannelConfig,
	                                     expect_new_update: bool,
	                                     prev_update: Option<&msgs::ChannelUpdate>,
	                                     should_expire_prev_config: bool|
	 -> Option<msgs::ChannelUpdate> {
		nodes[1]
			.node
			.update_channel_config(channel_to_update_counterparty, &[channel_to_update.0], config)
			.unwrap();
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), expect_new_update as usize);
		if !expect_new_update {
			return None;
		}
		let new_update = match &events[0] {
			MessageSendEvent::BroadcastChannelUpdate { msg } => {
				assert!(announce_for_forwarding);
				msg.clone()
			},
			MessageSendEvent::SendChannelUpdate { node_id, msg } => {
				assert_eq!(node_id, channel_to_update_counterparty);
				assert!(!announce_for_forwarding);
				msg.clone()
			},
			_ => panic!("expected Broadcast/SendChannelUpdate event"),
		};
		if prev_update.is_some() {
			assert!(new_update.contents.timestamp > prev_update.unwrap().contents.timestamp)
		}
		if should_expire_prev_config {
			expire_prev_config();
		}
		Some(new_update)
	};

	// We'll be attempting to route payments using the default ChannelUpdate for channels. This will
	// lead to onion failures at the first hop once we update the ChannelConfig for the
	// second hop.
	let expect_onion_failure = |name: &str, error_reason: LocalHTLCFailureReason| {
		let short_channel_id = channel_to_update.1;
		let network_update =
			NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: false };
		run_onion_failure_test(
			name,
			100,
			&nodes,
			&route,
			&payment_hash,
			&payment_secret,
			|_| {},
			|| {},
			true,
			Some(error_reason),
			Some(network_update),
			Some(short_channel_id),
			Some(HTLCHandlingFailureType::Forward {
				node_id: Some(nodes[2].node.get_our_node_id()),
				channel_id: channel_to_update.0,
			}),
		);
	};

	// Updates to cltv_expiry_delta below MIN_CLTV_EXPIRY_DELTA should fail with APIMisuseError.
	let mut invalid_config = default_config.clone();
	invalid_config.cltv_expiry_delta = 0;
	match nodes[1].node.update_channel_config(
		channel_to_update_counterparty,
		&[channel_to_update.0],
		&invalid_config,
	) {
		Err(APIError::APIMisuseError { .. }) => {},
		_ => panic!("unexpected result applying invalid cltv_expiry_delta"),
	}

	// Increase the base fee which should trigger a new ChannelUpdate.
	let mut config = nodes[1]
		.node
		.list_usable_channels()
		.iter()
		.find(|channel| channel.channel_id == channel_to_update.0)
		.unwrap()
		.config
		.unwrap();
	config.forwarding_fee_base_msat = u32::max_value();
	let msg = update_and_get_channel_update(&config.clone(), true, None, false).unwrap();

	// The old policy should still be in effect until a new block is connected.
	send_along_route_with_secret(
		&nodes[0],
		route.clone(),
		&[&[&nodes[1], &nodes[2]]],
		PAYMENT_AMT,
		payment_hash,
		payment_secret,
	);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// Connect a block, which should expire the previous config, leading to a failure when
	// forwarding the HTLC.
	expire_prev_config();
	expect_onion_failure("fee_insufficient", LocalHTLCFailureReason::FeeInsufficient);

	// Redundant updates should not trigger a new ChannelUpdate.
	assert!(update_and_get_channel_update(&config, false, None, false).is_none());

	// Similarly, updates that do not have an affect on ChannelUpdate should not trigger a new one.
	config.force_close_avoidance_max_fee_satoshis *= 2;
	assert!(update_and_get_channel_update(&config, false, None, false).is_none());

	// Reset the base fee to the default and increase the proportional fee which should trigger a
	// new ChannelUpdate.
	config.forwarding_fee_base_msat = default_config.forwarding_fee_base_msat;
	config.cltv_expiry_delta = u16::max_value();
	assert!(update_and_get_channel_update(&config, true, Some(&msg), true).is_some());
	expect_onion_failure("incorrect_cltv_expiry", LocalHTLCFailureReason::IncorrectCLTVExpiry);

	// Reset the proportional fee and increase the CLTV expiry delta which should trigger a new
	// ChannelUpdate.
	config.cltv_expiry_delta = default_config.cltv_expiry_delta;
	config.forwarding_fee_proportional_millionths = u32::max_value();
	assert!(update_and_get_channel_update(&config, true, Some(&msg), true).is_some());
	expect_onion_failure("fee_insufficient", LocalHTLCFailureReason::FeeInsufficient);

	// To test persistence of the updated config, we'll re-initialize the ChannelManager.
	let config_after_restart = {
		let chan_1_monitor_serialized = get_monitor!(nodes[1], other_channel.3).encode();
		let chan_2_monitor_serialized = get_monitor!(nodes[1], channel_to_update.0).encode();
		reload_node!(
			nodes[1],
			nodes[1].node.get_current_config(),
			&nodes[1].node.encode(),
			&[&chan_1_monitor_serialized, &chan_2_monitor_serialized],
			persister,
			chain_monitor,
			channel_manager_1_deserialized
		);
		nodes[1]
			.node
			.list_channels()
			.iter()
			.find(|channel| channel.channel_id == channel_to_update.0)
			.unwrap()
			.config
			.unwrap()
	};
	assert_eq!(config, config_after_restart);
}

#[test]
fn test_onion_failure_stale_channel_update() {
	do_test_onion_failure_stale_channel_update(false);
	do_test_onion_failure_stale_channel_update(true);
}

#[test]
fn test_always_create_tlv_format_onion_payloads() {
	// Verify that we always generate tlv onion format payloads, even if the features specifically
	// specifies no support for variable length onions, as the legacy payload format has been
	// deprecated in BOLT4.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let mut node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	// Set `node[1]`'s init features to features which return `false` for
	// `supports_variable_length_onion()`
	let mut no_variable_length_onion_features = InitFeatures::empty();
	no_variable_length_onion_features.set_static_remote_key_required();
	*node_cfgs[1].override_init_features.borrow_mut() = Some(no_variable_length_onion_features);

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let payment_params =
		PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)
			.with_bolt11_features(Bolt11InvoiceFeatures::empty())
			.unwrap();
	let (route, _payment_hash, _payment_preimage, _payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 40000);

	let hops = &route.paths[0].hops;
	// Asserts that the first hop to `node[1]` signals no support for variable length onions.
	assert!(!hops[0].node_features.supports_variable_length_onion());
	// Asserts that the first hop to `node[1]` signals no support for variable length onions.
	assert!(!hops[1].node_features.supports_variable_length_onion());

	let cur_height = nodes[0].best_block_info().1 + 1;
	let recipient_fields = RecipientOnionFields::spontaneous_empty();
	let path = &route.paths[0];
	let (onion_payloads, _htlc_msat, _htlc_cltv) =
		build_onion_payloads(path, 40000, &recipient_fields, cur_height, &None, None, None)
			.unwrap();

	match onion_payloads[0] {
		msgs::OutboundOnionPayload::Forward { .. } => {},
		_ => {
			panic!(
			"Should have generated a `msgs::OnionHopDataFormat::NonFinalNode` payload for `hops[0]`,
			despite that the features signals no support for variable length onions"
		)
		},
	}
	match onion_payloads[1] {
		msgs::OutboundOnionPayload::Receive { .. } => {},
		_ => {
			panic!(
			"Should have generated a `msgs::OnionHopDataFormat::FinalNode` payload for `hops[1]`,
			despite that the features signals no support for variable length onions"
		)
		},
	}
}

const BOB_HEX: &str = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c";
const CAROL_HEX: &str = "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007";
const DAVE_HEX: &str = "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991";
const DAVE_BLINDED_HEX: &str = "0295d40514096a8be54859e7dfe947b376eaafea8afe5cb4eb2c13ff857ed0b4be";
const EVE_BLINDED_HEX: &str = "020e2dbadcc2005e859819ddebbe88a834ae8a6d2b049233c07335f15cd1dc5f22";
const BLINDING_POINT_HEX: &str =
	"02988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e";
const SECRET_HEX: &str = "7494b65bc092b48a75465e43e29be807eb2cc535ce8aaba31012b8ff1ceac5da";
const SESSION_HEX: &str = "a64feb81abd58e473df290e9e1c07dc3e56114495cadf33191f44ba5448ebe99";

#[test]
fn test_trampoline_onion_payload_serialization() {
	// As per https://github.com/lightning/bolts/blob/c01d2e6267d4a8d1095f0f1188970055a9a22d29/bolt04/trampoline-payment-onion-test.json#L3
	let hex = "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145";
	let trampoline_payload = OutboundTrampolinePayload::Forward {
		amt_to_forward: 100000000,
		outgoing_cltv_value: 800000,
		outgoing_node_id: PublicKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()).unwrap(),
	};

	let slice_to_hex =
		|slice: &[u8]| slice.iter().map(|b| format!("{:02x}", b).to_string()).collect::<String>();

	let carol_payload_hex = slice_to_hex(&trampoline_payload.encode());
	assert_eq!(carol_payload_hex, "2e020405f5e10004030c35000e2102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145");
}

#[test]
fn test_trampoline_onion_payload_assembly_values() {
	// Test that we produce Trampoline and outer onion payloads that align with our expectations
	// from the Path argument. Additionally, ensure that the fee and HTLC values using the
	// `create_payment_onion` method, which hides some of the Trampoline onion inner workings, match
	// the values we arrive at by assembling each onion explicitly in this test
	let amt_msat = 150_000_000;
	let cur_height = 800_000;

	let path = Path {
		hops: vec![
			// Bob
			RouteHop {
				pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex(BOB_HEX).unwrap()).unwrap(),
				node_features: NodeFeatures::empty(),
				short_channel_id: 0,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 3_000,
				cltv_expiry_delta: 24,
				maybe_announced_channel: false,
			},
			// Carol
			RouteHop {
				pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex(CAROL_HEX).unwrap()).unwrap(),
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
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex(CAROL_HEX).unwrap())
						.unwrap(),
					node_features: Features::empty(),
					fee_msat: 2_500,
					cltv_expiry_delta: 24,
				},
				// Dave's pubkey (the intro node needs to be duplicated)
				TrampolineHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex(DAVE_HEX).unwrap()).unwrap(),
					node_features: Features::empty(),
					fee_msat: 150_500,
					cltv_expiry_delta: 36,
				},
			],
			hops: vec![
				// Dave's blinded node id
				BlindedHop {
					blinded_node_id: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(DAVE_BLINDED_HEX).unwrap(),
					)
					.unwrap(),
					encrypted_payload: vec![],
				},
				// Eve's blinded node id
				BlindedHop {
					blinded_node_id: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(EVE_BLINDED_HEX).unwrap(),
					)
					.unwrap(),
					encrypted_payload: vec![],
				},
			],
			blinding_point: PublicKey::from_slice(
				&<Vec<u8>>::from_hex(BLINDING_POINT_HEX).unwrap(),
			)
			.unwrap(),
			excess_final_cltv_expiry_delta: 0,
			final_value_msat: amt_msat,
		}),
	};
	assert_eq!(path.fee_msat(), 156_000);
	assert_eq!(path.final_value_msat(), amt_msat);
	assert_eq!(path.final_cltv_expiry_delta(), None);

	let payment_secret = PaymentSecret(
		SecretKey::from_slice(&<Vec<u8>>::from_hex(SECRET_HEX).unwrap()).unwrap().secret_bytes(),
	);
	let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
	let (trampoline_payloads, outer_total_msat, outer_starting_htlc_offset) =
		onion_utils::build_trampoline_onion_payloads(
			&path.blinded_tail.as_ref().unwrap(),
			amt_msat,
			&recipient_onion_fields,
			cur_height,
			&None,
		)
		.unwrap();
	assert_eq!(trampoline_payloads.len(), 3);
	assert_eq!(outer_total_msat, 150_153_000);
	assert_eq!(outer_starting_htlc_offset, 800_060);

	let trampoline_carol_payload = &trampoline_payloads[0];
	let trampoline_dave_payload = &trampoline_payloads[1];
	let trampoline_eve_payload = &trampoline_payloads[2];
	if let OutboundTrampolinePayload::BlindedReceive {
		sender_intended_htlc_amt_msat,
		total_msat,
		cltv_expiry_height,
		..
	} = trampoline_eve_payload
	{
		assert_eq!(sender_intended_htlc_amt_msat, &150_000_000);
		assert_eq!(total_msat, &150_000_000);
		assert_eq!(cltv_expiry_height, &800_000);
	} else {
		panic!("Eve Trampoline payload must be BlindedReceive");
	}

	if let OutboundTrampolinePayload::BlindedForward { .. } = trampoline_dave_payload {
	} else {
		panic!("Dave Trampoline payload must be BlindedForward");
	}

	if let OutboundTrampolinePayload::Forward { amt_to_forward, outgoing_cltv_value, .. } =
		trampoline_carol_payload
	{
		assert_eq!(amt_to_forward, &150_150_500);
		assert_eq!(outgoing_cltv_value, &800_036);
	} else {
		panic!("Carol Trampoline payload must be Forward");
	}

	// all dummy values
	let secp_ctx = Secp256k1::new();
	let session_priv = SecretKey::from_slice(&<Vec<u8>>::from_hex(SESSION_HEX).unwrap()).unwrap();
	let prng_seed = onion_utils::gen_pad_from_shared_secret(&session_priv.secret_bytes());
	let payment_hash = PaymentHash(session_priv.secret_bytes());

	let onion_keys = construct_trampoline_onion_keys(
		&secp_ctx,
		&path.blinded_tail.as_ref().unwrap(),
		&session_priv,
	);
	let trampoline_packet = construct_trampoline_onion_packet(
		trampoline_payloads,
		onion_keys,
		prng_seed,
		&payment_hash,
		None,
	)
	.unwrap();

	let (outer_payloads, total_msat, total_htlc_offset) = build_onion_payloads(
		&path,
		outer_total_msat,
		&recipient_onion_fields,
		outer_starting_htlc_offset,
		&None,
		None,
		Some(trampoline_packet),
	)
	.unwrap();
	assert_eq!(outer_payloads.len(), 2);
	assert_eq!(total_msat, 150_156_000);
	assert_eq!(total_htlc_offset, 800_084);

	let outer_bob_payload = &outer_payloads[0];
	let outer_carol_payload = &outer_payloads[1];
	if let OutboundOnionPayload::TrampolineEntrypoint {
		amt_to_forward, outgoing_cltv_value, ..
	} = outer_carol_payload
	{
		assert_eq!(amt_to_forward, &150_153_000);
		assert_eq!(outgoing_cltv_value, &800_060);
	} else {
		panic!("Carol payload must be TrampolineEntrypoint");
	}
	if let OutboundOnionPayload::Forward { amt_to_forward, outgoing_cltv_value, .. } =
		outer_bob_payload
	{
		assert_eq!(amt_to_forward, &150_153_000);
		assert_eq!(outgoing_cltv_value, &800_084);
	} else {
		panic!("Bob payload must be Forward");
	}

	let (_, total_msat_combined, total_htlc_offset_combined) = onion_utils::create_payment_onion(
		&Secp256k1::new(),
		&path,
		&session_priv,
		amt_msat,
		&recipient_onion_fields,
		cur_height,
		&payment_hash,
		&None,
		None,
		prng_seed,
	)
	.unwrap();
	assert_eq!(total_msat_combined, total_msat);
	assert_eq!(total_htlc_offset_combined, total_htlc_offset);
}

#[test]
fn test_trampoline_onion_payload_construction_vectors() {
	// As per https://github.com/lightning/bolts/blob/fa0594ac2af3531d734f1d707a146d6e13679451/bolt04/trampoline-to-blinded-path-payment-onion-test.json#L251

	let trampoline_payload_carol = OutboundTrampolinePayload::Forward {
		amt_to_forward: 150_150_500,
		outgoing_cltv_value: 800_036,
		outgoing_node_id: PublicKey::from_slice(&<Vec<u8>>::from_hex(DAVE_HEX).unwrap()).unwrap(),
	};
	let carol_payload = trampoline_payload_carol.encode().to_lower_hex_string();
	assert_eq!(carol_payload, "2e020408f31d6404030c35240e21032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");

	let trampoline_payload_dave = OutboundTrampolinePayload::BlindedForward {
		encrypted_tlvs: &<Vec<u8>>::from_hex("0ccf3c8a58deaa603f657ee2a5ed9d604eb5c8ca1e5f801989afa8f3ea6d789bbdde2c7e7a1ef9ca8c38d2c54760febad8446d3f273ddb537569ef56613846ccd3aba78a").unwrap(),
		intro_node_blinding_point: Some(PublicKey::from_slice(&<Vec<u8>>::from_hex(BLINDING_POINT_HEX).unwrap()).unwrap()),
	};
	let dave_payload = trampoline_payload_dave.encode().to_lower_hex_string();
	assert_eq!(dave_payload, "690a440ccf3c8a58deaa603f657ee2a5ed9d604eb5c8ca1e5f801989afa8f3ea6d789bbdde2c7e7a1ef9ca8c38d2c54760febad8446d3f273ddb537569ef56613846ccd3aba78a0c2102988face71e92c345a068f740191fd8e53be14f0bb957ef730d3c5f76087b960e");

	let trampoline_payload_eve = OutboundTrampolinePayload::BlindedReceive {
		sender_intended_htlc_amt_msat: 150_000_000,
		total_msat: 150_000_000,
		cltv_expiry_height: 800_000,
		encrypted_tlvs: &<Vec<u8>>::from_hex("bcd747394fbd4d99588da075a623316e15a576df5bc785cccc7cd6ec7b398acce6faf520175f9ec920f2ef261cdb83dc28cc3a0eeb970107b3306489bf771ef5b1213bca811d345285405861d08a655b6c237fa247a8b4491beee20c878a60e9816492026d8feb9dafa84585b253978db6a0aa2945df5ef445c61e801fb82f43d5f00716baf9fc9b3de50bc22950a36bda8fc27bfb1242e5860c7e687438d4133e058770361a19b6c271a2a07788d34dccc27e39b9829b061a4d960eac4a2c2b0f4de506c24f9af3868c0aff6dda27281c").unwrap(),
		intro_node_blinding_point: None,
		keysend_preimage: None,
		custom_tlvs: &vec![],
	};
	let eve_payload = trampoline_payload_eve.encode().to_lower_hex_string();
	assert_eq!(eve_payload, "e4020408f0d18004030c35000ad1bcd747394fbd4d99588da075a623316e15a576df5bc785cccc7cd6ec7b398acce6faf520175f9ec920f2ef261cdb83dc28cc3a0eeb970107b3306489bf771ef5b1213bca811d345285405861d08a655b6c237fa247a8b4491beee20c878a60e9816492026d8feb9dafa84585b253978db6a0aa2945df5ef445c61e801fb82f43d5f00716baf9fc9b3de50bc22950a36bda8fc27bfb1242e5860c7e687438d4133e058770361a19b6c271a2a07788d34dccc27e39b9829b061a4d960eac4a2c2b0f4de506c24f9af3868c0aff6dda27281c120408f0d180");

	let trampoline_payloads =
		vec![trampoline_payload_carol, trampoline_payload_dave, trampoline_payload_eve];

	let trampoline_session_key =
		SecretKey::from_slice(&<Vec<u8>>::from_hex(SESSION_HEX).unwrap()).unwrap();
	let associated_data_slice = SecretKey::from_slice(
		&<Vec<u8>>::from_hex("e89bc505e84aaca09613833fc58c9069078fb43bfbea0488f34eec9db99b5f82")
			.unwrap(),
	)
	.unwrap();
	let associated_data = PaymentHash(associated_data_slice.secret_bytes());

	let trampoline_hops = Path {
		hops: vec![],
		blinded_tail: Some(BlindedTail {
			trampoline_hops: vec![
				// Carol's pubkey
				TrampolineHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex(CAROL_HEX).unwrap())
						.unwrap(),
					node_features: Features::empty(),
					fee_msat: 0,
					cltv_expiry_delta: 0,
				},
				// Dave's pubkey (the intro node needs to be duplicated)
				TrampolineHop {
					pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex(DAVE_HEX).unwrap()).unwrap(),
					node_features: Features::empty(),
					fee_msat: 0,
					cltv_expiry_delta: 0,
				},
			],
			hops: vec![
				// Dave's blinded node id
				BlindedHop {
					blinded_node_id: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(DAVE_BLINDED_HEX).unwrap(),
					)
					.unwrap(),
					encrypted_payload: vec![],
				},
				// Eve's blinded node id
				BlindedHop {
					blinded_node_id: PublicKey::from_slice(
						&<Vec<u8>>::from_hex(EVE_BLINDED_HEX).unwrap(),
					)
					.unwrap(),
					encrypted_payload: vec![],
				},
			],
			blinding_point: PublicKey::from_slice(
				&<Vec<u8>>::from_hex(BLINDING_POINT_HEX).unwrap(),
			)
			.unwrap(),
			excess_final_cltv_expiry_delta: 0,
			final_value_msat: 0,
		}),
	};

	let trampoline_onion_keys = construct_trampoline_onion_keys(
		&Secp256k1::new(),
		&trampoline_hops.blinded_tail.unwrap(),
		&trampoline_session_key,
	);
	let trampoline_onion_packet = construct_trampoline_onion_packet(
		trampoline_payloads,
		trampoline_onion_keys,
		[0u8; 32],
		&associated_data,
		None,
	)
	.unwrap();
	let trampoline_onion_packet_hex = trampoline_onion_packet.encode().to_lower_hex_string();
	assert_eq!(trampoline_onion_packet_hex, "0002bc59a9abc893d75a8d4f56a6572f9a3507323a8de22abe0496ea8d37da166a8b4bba0e560f1a9deb602bfd98fe9167141d0b61d669df90c0149096d505b85d3d02806e6c12caeb308b878b6bc7f1b15839c038a6443cd3bec3a94c2293165375555f6d7720862b525930f41fddcc02260d197abd93fb58e60835fd97d9dc14e7979c12f59df08517b02e3e4d50e1817de4271df66d522c4e9675df71c635c4176a8381bc22b342ff4e9031cede87f74cc039fca74aa0a3786bc1db2e158a9a520ecb99667ef9a6bbfaf5f0e06f81c27ca48134ba2103229145937c5dc7b8ecc5201d6aeb592e78faa3c05d3a035df77628f0be9b1af3ef7d386dd5cc87b20778f47ebd40dbfcf12b9071c5d7112ab84c3e0c5c14867e684d09a18bc93ac47d73b7343e3403ef6e3b70366835988920e7d772c3719d3596e53c29c4017cb6938421a557ce81b4bb26701c25bf622d4c69f1359dc85857a375c5c74987a4d3152f66987001c68a50c4bf9e0b1dab4ad1a64b0535319bbf6c4fbe4f9c50cb65f5ef887bfb91b0a57c0f86ba3d91cbeea1607fb0c12c6c75d03bbb0d3a3019c40597027f5eebca23083e50ec79d41b1152131853525bf3fc13fb0be62c2e3ce733f59671eee5c4064863fb92ae74be9ca68b9c716f9519fd268478ee27d91d466b0de51404de3226b74217d28250ead9d2c95411e0230570f547d4cc7c1d589791623131aa73965dccc5aa17ec12b442215ce5d346df664d799190df5dd04a13");

	let outer_payloads = vec![
		// Bob
		OutboundOnionPayload::Forward {
			short_channel_id: (572330 << 40) + (42 << 16) + 2821,
			amt_to_forward: 150153000,
			outgoing_cltv_value: 800060,
		},
		// Carol
		OutboundOnionPayload::TrampolineEntrypoint {
			amt_to_forward: 150153000,
			outgoing_cltv_value: 800060,
			trampoline_packet: trampoline_onion_packet,
			multipath_trampoline_data: Some(FinalOnionHopData {
				payment_secret: PaymentSecret(
					SecretKey::from_slice(&<Vec<u8>>::from_hex(SECRET_HEX).unwrap())
						.unwrap()
						.secret_bytes(),
				),
				total_msat: 150153000,
			}),
		},
	];

	let outer_hops = Path {
		hops: vec![
			// Bob
			RouteHop {
				pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex(BOB_HEX).unwrap()).unwrap(),
				node_features: NodeFeatures::empty(),
				short_channel_id: 0,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 0,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			},
			// Carol
			RouteHop {
				pubkey: PublicKey::from_slice(&<Vec<u8>>::from_hex(CAROL_HEX).unwrap()).unwrap(),
				node_features: NodeFeatures::empty(),
				short_channel_id: 0,
				channel_features: ChannelFeatures::empty(),
				fee_msat: 0,
				cltv_expiry_delta: 0,
				maybe_announced_channel: false,
			},
		],
		blinded_tail: None,
	};

	let bob_payload = outer_payloads[0].encode().to_lower_hex_string();
	assert_eq!(bob_payload, "15020408f3272804030c353c060808bbaa00002a0b05");

	let carol_payload = outer_payloads[1].encode().to_lower_hex_string();
	assert_eq!(carol_payload, "fd0255020408f3272804030c353c08247494b65bc092b48a75465e43e29be807eb2cc535ce8aaba31012b8ff1ceac5da08f3272814fd02200002bc59a9abc893d75a8d4f56a6572f9a3507323a8de22abe0496ea8d37da166a8b4bba0e560f1a9deb602bfd98fe9167141d0b61d669df90c0149096d505b85d3d02806e6c12caeb308b878b6bc7f1b15839c038a6443cd3bec3a94c2293165375555f6d7720862b525930f41fddcc02260d197abd93fb58e60835fd97d9dc14e7979c12f59df08517b02e3e4d50e1817de4271df66d522c4e9675df71c635c4176a8381bc22b342ff4e9031cede87f74cc039fca74aa0a3786bc1db2e158a9a520ecb99667ef9a6bbfaf5f0e06f81c27ca48134ba2103229145937c5dc7b8ecc5201d6aeb592e78faa3c05d3a035df77628f0be9b1af3ef7d386dd5cc87b20778f47ebd40dbfcf12b9071c5d7112ab84c3e0c5c14867e684d09a18bc93ac47d73b7343e3403ef6e3b70366835988920e7d772c3719d3596e53c29c4017cb6938421a557ce81b4bb26701c25bf622d4c69f1359dc85857a375c5c74987a4d3152f66987001c68a50c4bf9e0b1dab4ad1a64b0535319bbf6c4fbe4f9c50cb65f5ef887bfb91b0a57c0f86ba3d91cbeea1607fb0c12c6c75d03bbb0d3a3019c40597027f5eebca23083e50ec79d41b1152131853525bf3fc13fb0be62c2e3ce733f59671eee5c4064863fb92ae74be9ca68b9c716f9519fd268478ee27d91d466b0de51404de3226b74217d28250ead9d2c95411e0230570f547d4cc7c1d589791623131aa73965dccc5aa17ec12b442215ce5d346df664d799190df5dd04a13");

	let outer_session_key = SecretKey::from_slice(
		&<Vec<u8>>::from_hex("4f777e8dac16e6dfe333066d9efb014f7a51d11762ff76eca4d3a95ada99ba3e")
			.unwrap(),
	)
	.unwrap();
	let outer_onion_keys = construct_onion_keys(&Secp256k1::new(), &outer_hops, &outer_session_key);
	let outer_onion_prng_seed =
		onion_utils::gen_pad_from_shared_secret(&outer_session_key.secret_bytes());
	let outer_onion_packet = onion_utils::construct_onion_packet(
		outer_payloads,
		outer_onion_keys,
		outer_onion_prng_seed,
		&associated_data,
	)
	.unwrap();
	let outer_onion_packet_hex = outer_onion_packet.encode().to_lower_hex_string();
	assert_eq!(outer_onion_packet_hex, "00025fd60556c134ae97e4baedba220a644037754ee67c54fd05e93bf40c17cbb73362fb9dee96001ff229945595b6edb59437a6bc143406d3f90f749892a84d8d430c6890437d26d5bfc599d565316ef51347521075bbab87c59c57bcf20af7e63d7192b46cf171e4f73cb11f9f603915389105d91ad630224bea95d735e3988add1e24b5bf28f1d7128db64284d90a839ba340d088c74b1fb1bd21136b1809428ec5399c8649e9bdf92d2dcfc694deae5046fa5b2bdf646847aaad73f5e95275763091c90e71031cae1f9a770fdea559642c9c02f424a2a28163dd0957e3874bd28a97bec67d18c0321b0e68bc804aa8345b17cb626e2348ca06c8312a167c989521056b0f25c55559d446507d6c491d50605cb79fa87929ce64b0a9860926eeaec2c431d926a1cadb9a1186e4061cb01671a122fc1f57602cbef06d6c194ec4b715c2e3dd4120baca3172cd81900b49fef857fb6d6afd24c983b608108b0a5ac0c1c6c52011f23b8778059ffadd1bb7cd06e2525417365f485a7fd1d4a9ba3818ede7cdc9e71afee8532252d08e2531ca52538655b7e8d912f7ec6d37bbcce8d7ec690709dbf9321e92c565b78e7fe2c22edf23e0902153d1ca15a112ad32fb19695ec65ce11ddf670da7915f05ad4b86c154fb908cb567315d1124f303f75fa075ebde8ef7bb12e27737ad9e4924439097338ea6d7a6fc3721b88c9b830a34e8d55f4c582b74a3895cc848fe57f4fe29f115dabeb6b3175be15d94408ed6771109cfaf57067ae658201082eae7605d26b1449af4425ae8e8f58cdda5c6265f1fd7a386fc6cea3074e4f25b909b96175883676f7610a00fdf34df9eb6c7b9a4ae89b839c69fd1f285e38cdceb634d782cc6d81179759bc9fd47d7fd060470d0b048287764c6837963274e708314f017ac7dc26d0554d59bfcfd3136225798f65f0b0fea337c6b256ebbb63a90b994c0ab93fd8b1d6bd4c74aebe535d6110014cd3d525394027dfe8faa98b4e9b2bee7949eb1961f1b026791092f84deea63afab66603dbe9b6365a102a1fef2f6b9744bc1bb091a8da9130d34d4d39f25dbad191649cfb67e10246364b7ce0c6ec072f9690cabb459d9fda0c849e17535de4357e9907270c75953fca3c845bb613926ecf73205219c7057a4b6bb244c184362bb4e2f24279dc4e60b94a5b1ec11c34081a628428ba5646c995b9558821053ba9c84a05afbf00dabd60223723096516d2f5668f3ec7e11612b01eb7a3a0506189a2272b88e89807943adb34291a17f6cb5516ffd6f945a1c42a524b21f096d66f350b1dad4db455741ae3d0e023309fbda5ef55fb0dc74f3297041448b2be76c525141963934c6afc53d263fb7836626df502d7c2ee9e79cbbd87afd84bbb8dfbf45248af3cd61ad5fac827e7683ca4f91dfad507a8eb9c17b2c9ac5ec051fe645a4a6cb37136f6f19b611e0ea8da7960af2d779507e55f57305bc74b7568928c5dd5132990fe54c22117df91c257d8c7b61935a018a28c1c3b17bab8e4294fa699161ec21123c9fc4e71079df31f300c2822e1246561e04765d3aab333eafd026c7431ac7616debb0e022746f4538e1c6348b600c988eeb2d051fc60c468dca260a84c79ab3ab8342dc345a764672848ea234e17332bc124799daf7c5fcb2e2358514a7461357e1c19c802c5ee32deccf1776885dd825bedd5f781d459984370a6b7ae885d4483a76ddb19b30f47ed47cd56aa5a079a89793dbcad461c59f2e002067ac98dd5a534e525c9c46c2af730741bf1f8629357ec0bfc0bc9ecb31af96777e507648ff4260dc3673716e098d9111dfd245f1d7c55a6de340deb8bd7a053e5d62d760f184dc70ca8fa255b9023b9b9aedfb6e419a5b5951ba0f83b603793830ee68d442d7b88ee1bbf6bbd1bcd6f68cc1af");
}

fn do_test_fail_htlc_backwards_with_reason(failure_code: FailureCode) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_amount = 100_000;
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], payment_amount);
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash, recipient_onion, PaymentId(payment_hash.0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash, payment_secret, payment_amount);
	nodes[1].node.fail_htlc_backwards_with_reason(&payment_hash, failure_code);

	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_fail_htlc, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs {
			node_id: _,
			channel_id: _,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_htlcs,
					ref update_fail_malformed_htlcs,
					ref update_fee,
					ref commitment_signed,
				},
		} => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
			(update_fail_htlcs[0].clone(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &update_fail_htlc);
	commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

	let failure_data = match failure_code {
		FailureCode::TemporaryNodeFailure => vec![],
		FailureCode::RequiredNodeFeatureMissing => vec![],
		FailureCode::IncorrectOrUnknownPaymentDetails => {
			let mut htlc_msat_height_data = (payment_amount as u64).to_be_bytes().to_vec();
			htlc_msat_height_data.extend_from_slice(&CHAN_CONFIRM_DEPTH.to_be_bytes());
			htlc_msat_height_data
		},
		FailureCode::InvalidOnionPayload(data) => match data {
			Some((typ, offset)) => [BigSize(typ).encode(), offset.encode()].concat(),
			None => Vec::new(),
		},
	};

	let failure_code = failure_code.into();
	expect_payment_failed!(
		nodes[0],
		payment_hash,
		failure_code.is_permanent(),
		failure_code,
		failure_data
	);
}

#[test]
fn test_fail_htlc_backwards_with_reason() {
	do_test_fail_htlc_backwards_with_reason(FailureCode::TemporaryNodeFailure);
	do_test_fail_htlc_backwards_with_reason(FailureCode::RequiredNodeFeatureMissing);
	do_test_fail_htlc_backwards_with_reason(FailureCode::IncorrectOrUnknownPaymentDetails);
	do_test_fail_htlc_backwards_with_reason(FailureCode::InvalidOnionPayload(Some((1 << 16, 42))));
	do_test_fail_htlc_backwards_with_reason(FailureCode::InvalidOnionPayload(None));
}

macro_rules! get_phantom_route {
	($nodes: expr, $amt: expr, $channel: expr) => {{
		let phantom_pubkey = $nodes[1].keys_manager.get_node_id(Recipient::PhantomNode).unwrap();
		let phantom_route_hint = $nodes[1].node.get_phantom_route_hints();
		let payment_params = PaymentParameters::from_node_id(phantom_pubkey, TEST_FINAL_CLTV)
			.with_bolt11_features($nodes[1].node.bolt11_invoice_features())
			.unwrap()
			.with_route_hints(vec![RouteHint(vec![
				RouteHintHop {
					src_node_id: $nodes[0].node.get_our_node_id(),
					short_channel_id: $channel.0.contents.short_channel_id,
					fees: RoutingFees {
						base_msat: $channel.0.contents.fee_base_msat,
						proportional_millionths: $channel.0.contents.fee_proportional_millionths,
					},
					cltv_expiry_delta: $channel.0.contents.cltv_expiry_delta,
					htlc_minimum_msat: None,
					htlc_maximum_msat: None,
				},
				RouteHintHop {
					src_node_id: phantom_route_hint.real_node_pubkey,
					short_channel_id: phantom_route_hint.phantom_scid,
					fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
					cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
					htlc_minimum_msat: None,
					htlc_maximum_msat: None,
				},
			])])
			.unwrap();
		let scorer = test_utils::TestScorer::new();
		let first_hops = $nodes[0].node.list_usable_channels();
		let network_graph = $nodes[0].network_graph.read_only();
		let route_params = RouteParameters::from_payment_params_and_value(payment_params, $amt);
		(
			get_route(
				&$nodes[0].node.get_our_node_id(),
				&route_params,
				&network_graph,
				Some(&first_hops.iter().collect::<Vec<_>>()),
				$nodes[0].logger,
				&scorer,
				&Default::default(),
				&[0u8; 32],
			)
			.unwrap(),
			phantom_route_hint.phantom_scid,
		)
	}};
}

#[test]
fn test_phantom_onion_hmac_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash, recipient_onion, PaymentId(payment_hash.0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);
	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_update_add_htlcs();

	// Modify the payload so the phantom hop's HMAC is bogus.
	let sha256_of_onion = {
		let mut forward_htlcs = nodes[1].node.forward_htlcs.lock().unwrap();
		let mut pending_forward = forward_htlcs.get_mut(&phantom_scid).unwrap();
		match pending_forward[0] {
			HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
				forward_info:
					PendingHTLCInfo {
						routing: PendingHTLCRouting::Forward { ref mut onion_packet, .. },
						..
					},
				..
			}) => {
				onion_packet.hmac[onion_packet.hmac.len() - 1] ^= 1;
				Sha256::hash(&onion_packet.hop_data).to_byte_array().to_vec()
			},
			_ => panic!("Unexpected forward"),
		}
	};
	nodes[1].node.process_pending_htlc_forwards();
	expect_htlc_failure_conditions(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.blamed_chan_closed(true)
		.expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionHMAC, &sha256_of_onion);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_invalid_onion_payload() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// We'll use the session priv later when constructing an invalid onion packet.
	let session_priv = [3; 32];
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(session_priv);
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	let payment_id = PaymentId(payment_hash.0);
	nodes[0]
		.node
		.send_payment_with_route(route.clone(), payment_hash, recipient_onion, payment_id)
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);
	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_update_add_htlcs();

	// Modify the onion packet to have an invalid payment amount.
	for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
					forward_info:
						PendingHTLCInfo {
							routing: PendingHTLCRouting::Forward { ref mut onion_packet, .. },
							..
						},
					..
				}) => {
					// Construct the onion payloads for the entire route and an invalid amount.
					let height = nodes[0].best_block_info().1;
					let session_priv = SecretKey::from_slice(&session_priv).unwrap();
					let mut onion_keys =
						construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv);
					let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
					let (mut onion_payloads, _, _) = build_onion_payloads(
						&route.paths[0],
						msgs::MAX_VALUE_MSAT + 1,
						&recipient_onion_fields,
						height + 1,
						&None,
						None,
						None,
					)
					.unwrap();
					// We only want to construct the onion packet for the last hop, not the entire route, so
					// remove the first hop's payload and its keys.
					onion_keys.remove(0);
					onion_payloads.remove(0);

					let new_onion_packet = onion_utils::construct_onion_packet(
						onion_payloads,
						onion_keys,
						[0; 32],
						&payment_hash,
					)
					.unwrap();
					onion_packet.hop_data = new_onion_packet.hop_data;
					onion_packet.hmac = new_onion_packet.hmac;
				},
				_ => panic!("Unexpected forward"),
			}
		}
	}
	nodes[1].node.process_pending_htlc_forwards();
	expect_htlc_failure_conditions(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let error_data = Vec::new();
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.blamed_chan_closed(true)
		.expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionPayload, &error_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, true, fail_conditions);
}

#[test]
fn test_phantom_final_incorrect_cltv_expiry() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash, recipient_onion, PaymentId(payment_hash.0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);
	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_update_add_htlcs();

	// Modify the payload so the phantom hop's HMAC is bogus.
	for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
					forward_info: PendingHTLCInfo { ref mut outgoing_cltv_value, .. },
					..
				}) => {
					*outgoing_cltv_value -= 1;
				},
				_ => panic!("Unexpected forward"),
			}
		}
	}
	nodes[1].node.process_pending_htlc_forwards();
	expect_htlc_failure_conditions(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let expected_cltv: u32 = 80;
	let error_data = expected_cltv.to_be_bytes().to_vec();
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(LocalHTLCFailureReason::FinalIncorrectCLTVExpiry, &error_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_failure_too_low_cltv() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Modify the route to have a too-low cltv.
	route.paths[0].hops[1].cltv_expiry_delta = 5;

	// Route the HTLC through to the destination.
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash, recipient_onion, PaymentId(payment_hash.0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_htlc_failure_conditions(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut error_data = recv_value_msat.to_be_bytes().to_vec();
	error_data.extend_from_slice(&nodes[0].node.best_block.read().unwrap().height.to_be_bytes());
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(LocalHTLCFailureReason::IncorrectPaymentDetails, &error_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, true, fail_conditions);
}

#[test]
fn test_phantom_failure_modified_cltv() {
	// Test that we fail back phantoms if the upstream node fiddled with the CLTV too much with the
	// correct error code.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash, recipient_onion, PaymentId(payment_hash.0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	// Modify the route to have a too-low cltv.
	update_add.cltv_expiry -= 10;

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::InvalidForward { requested_forward_scid: phantom_scid }]
	);
	check_added_monitors(&nodes[1], 1);

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut err_data = Vec::new();
	err_data.extend_from_slice(&update_add.cltv_expiry.to_be_bytes());
	err_data.extend_from_slice(&0u16.to_be_bytes());
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(LocalHTLCFailureReason::IncorrectCLTVExpiry, &err_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_failure_expires_too_soon() {
	// Test that we fail back phantoms if the HTLC got delayed and we got blocks in between with
	// the correct error code.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash, recipient_onion, PaymentId(payment_hash.0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	connect_blocks(&nodes[1], CLTV_FAR_FAR_AWAY);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::InvalidForward { requested_forward_scid: phantom_scid }]
	);
	check_added_monitors(&nodes[1], 1);

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let err_data = 0u16.to_be_bytes();
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(LocalHTLCFailureReason::CLTVExpiryTooSoon, &err_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_failure_too_low_recv_amt() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route with a too-low amount.
	let recv_amt_msat = 10_000;
	let bad_recv_amt_msat = recv_amt_msat - 10;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(recv_amt_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, bad_recv_amt_msat, channel);

	// Route the HTLC through to the destination.
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0]
		.node
		.send_payment_with_route(route, payment_hash, recipient_onion, PaymentId(payment_hash.0))
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_htlc_failure_conditions(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash: payment_hash.clone() }],
	);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut error_data = bad_recv_amt_msat.to_be_bytes().to_vec();
	error_data.extend_from_slice(&nodes[1].node.best_block.read().unwrap().height.to_be_bytes());
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(LocalHTLCFailureReason::IncorrectPaymentDetails, &error_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, true, fail_conditions);
}

#[test]
fn test_phantom_dust_exposure_failure() {
	do_test_phantom_dust_exposure_failure(false);
	do_test_phantom_dust_exposure_failure(true);
}

fn do_test_phantom_dust_exposure_failure(multiplier_dust_limit: bool) {
	// Set the max dust exposure to the dust limit.
	let max_dust_exposure = 546;
	let mut receiver_config = UserConfig::default();
	// Default test fee estimator rate is 253, so to set the max dust exposure to the dust limit,
	// we need to set the multiplier to 2.
	receiver_config.channel_config.max_dust_htlc_exposure = if multiplier_dust_limit {
		MaxDustHTLCExposure::FeeRateMultiplier(2)
	} else {
		MaxDustHTLCExposure::FixedLimitMsat(max_dust_exposure)
	};
	receiver_config.channel_handshake_config.announce_for_forwarding = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(receiver_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route with an amount exceeding the dust exposure threshold of nodes[1].
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(max_dust_exposure + 1));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, max_dust_exposure + 1, channel);

	// Route the HTLC through to the destination.
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	let payment_id = PaymentId(payment_hash.0);
	nodes[0]
		.node
		.send_payment_with_route(route.clone(), payment_hash, recipient_onion, payment_id)
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::InvalidForward { requested_forward_scid: phantom_scid }]
	);
	check_added_monitors(&nodes[1], 1);

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let err_data = 0u16.to_be_bytes();
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(LocalHTLCFailureReason::TemporaryChannelFailure, &err_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_failure_reject_payment() {
	// Test that the user can successfully fail back a phantom node payment.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route with a too-low amount.
	let recv_amt_msat = 10_000;
	let (_, payment_hash, payment_secret) =
		get_payment_preimage_hash!(nodes[1], Some(recv_amt_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_amt_msat, channel);

	// Route the HTLC through to the destination.
	let recipient_onion = RecipientOnionFields::secret_only(payment_secret);
	let payment_id = PaymentId(payment_hash.0);
	nodes[0]
		.node
		.send_payment_with_route(route.clone(), payment_hash, recipient_onion, payment_id)
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_payment_claimable!(
		nodes[1],
		payment_hash,
		payment_secret,
		recv_amt_msat,
		None,
		route.paths[0].hops.last().unwrap().pubkey
	);
	nodes[1].node.fail_htlc_backwards(&payment_hash);
	expect_htlc_failure_conditions(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }],
	);
	nodes[1].node.process_pending_htlc_forwards();

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut error_data = recv_amt_msat.to_be_bytes().to_vec();
	error_data.extend_from_slice(&nodes[1].node.best_block.read().unwrap().height.to_be_bytes());
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(LocalHTLCFailureReason::IncorrectPaymentDetails, &error_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, true, fail_conditions);
}
