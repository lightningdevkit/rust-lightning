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
use crate::chain::keysinterface::{EntropySource, NodeSigner, Recipient};
use crate::ln::{PaymentHash, PaymentSecret};
use crate::ln::channel::EXPIRE_PREV_CONFIG_TICKS;
use crate::ln::channelmanager::{HTLCForwardInfo, FailureCode, CLTV_FAR_FAR_AWAY, MIN_CLTV_EXPIRY_DELTA, PendingAddHTLCInfo, PendingHTLCInfo, PendingHTLCRouting, PaymentId};
use crate::ln::onion_utils;
use crate::routing::gossip::{NetworkUpdate, RoutingFees};
use crate::routing::router::{get_route, PaymentParameters, Route, RouteHint, RouteHintHop};
use crate::ln::features::{InitFeatures, InvoiceFeatures};
use crate::ln::msgs;
use crate::ln::msgs::{ChannelMessageHandler, ChannelUpdate};
use crate::ln::wire::Encode;
use crate::util::events::{Event, HTLCDestination, MessageSendEvent, MessageSendEventsProvider, PathFailure};
use crate::util::ser::{Writeable, Writer};
use crate::util::test_utils;
use crate::util::config::{UserConfig, ChannelConfig};
use crate::util::errors::APIError;

use bitcoin::hash_types::BlockHash;

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;

use bitcoin::secp256k1;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

use crate::io;
use crate::prelude::*;
use core::default::Default;

use crate::ln::functional_test_utils::*;

fn run_onion_failure_test<F1,F2>(_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash, payment_secret: &PaymentSecret, callback_msg: F1, callback_node: F2, expected_retryable: bool, expected_error_code: Option<u16>, expected_channel_update: Option<NetworkUpdate>, expected_short_channel_id: Option<u64>)
	where F1: for <'a> FnMut(&'a mut msgs::UpdateAddHTLC),
				F2: FnMut(),
{
	run_onion_failure_test_with_fail_intercept(_name, test_case, nodes, route, payment_hash, payment_secret, callback_msg, |_|{}, callback_node, expected_retryable, expected_error_code, expected_channel_update, expected_short_channel_id);
}

// test_case
// 0: node1 fails backward
// 1: final node fails backward
// 2: payment completed but the user rejects the payment
// 3: final node fails backward (but tamper onion payloads from node0)
// 100: trigger error in the intermediate node and tamper returning fail_htlc
// 200: trigger error in the final node and tamper returning fail_htlc
fn run_onion_failure_test_with_fail_intercept<F1,F2,F3>(_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash, payment_secret: &PaymentSecret, mut callback_msg: F1, mut callback_fail: F2, mut callback_node: F3, expected_retryable: bool, expected_error_code: Option<u16>, expected_channel_update: Option<NetworkUpdate>, expected_short_channel_id: Option<u64>)
	where F1: for <'a> FnMut(&'a mut msgs::UpdateAddHTLC),
				F2: for <'a> FnMut(&'a mut msgs::UpdateFailHTLC),
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
		}}
	}

	macro_rules! expect_htlc_forward {
		($node: expr) => {{
			expect_event!($node, Event::PendingHTLCsForwardable);
			$node.node.process_pending_htlc_forwards();
		}}
	}

	// 0 ~~> 2 send payment
	let payment_id = PaymentId(nodes[0].keys_manager.backing.get_secure_random_bytes());
	nodes[0].node.send_payment(&route, *payment_hash, &Some(*payment_secret), payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	// temper update_add (0 => 1)
	let mut update_add_0 = update_0.update_add_htlcs[0].clone();
	if test_case == 0 || test_case == 3 || test_case == 100 {
		callback_msg(&mut update_add_0);
		callback_node();
	}
	// 0 => 1 update_add & CS
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add_0);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	let update_1_0 = match test_case {
		0|100 => { // intermediate node failure; fail backward to 0
			let update_1_0 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
			assert!(update_1_0.update_fail_htlcs.len()+update_1_0.update_fail_malformed_htlcs.len()==1 && (update_1_0.update_fail_htlcs.len()==1 || update_1_0.update_fail_malformed_htlcs.len()==1));
			update_1_0
		},
		1|2|3|200 => { // final node failure; forwarding to 2
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
			// forwarding on 1
			if test_case != 200 {
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
			nodes[2].node.handle_update_add_htlc(&nodes[1].node.get_our_node_id(), &update_add_1);
			commitment_signed_dance!(nodes[2], nodes[1], update_1.commitment_signed, false, true);

			if test_case == 2 || test_case == 200 {
				expect_htlc_forward!(&nodes[2]);
				expect_event!(&nodes[2], Event::PaymentClaimable);
				callback_node();
				expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[2], vec![HTLCDestination::FailedPayment { payment_hash: payment_hash.clone() }]);
			}

			let update_2_1 = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
			if test_case == 2 || test_case == 200 {
				check_added_monitors!(&nodes[2], 1);
			}
			assert!(update_2_1.update_fail_htlcs.len() == 1);

			let mut fail_msg = update_2_1.update_fail_htlcs[0].clone();
			if test_case == 200 {
				callback_fail(&mut fail_msg);
			}

			// 2 => 1
			nodes[1].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &fail_msg);
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
		nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	} else {
		nodes[0].node.handle_update_fail_malformed_htlc(&nodes[1].node.get_our_node_id(), &update_1_0.update_fail_malformed_htlcs[0]);
	};

	commitment_signed_dance!(nodes[0], nodes[1], update_1_0.commitment_signed, false, true);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if let &Event::PaymentPathFailed { ref payment_failed_permanently, ref short_channel_id, ref error_code, failure: PathFailure::OnPath { ref network_update }, .. } = &events[0] {
		assert_eq!(*payment_failed_permanently, !expected_retryable);
		assert_eq!(*error_code, expected_error_code);
		if expected_channel_update.is_some() {
			match network_update {
				Some(update) => match update {
					&NetworkUpdate::ChannelUpdateMessage { .. } => {
						if let NetworkUpdate::ChannelUpdateMessage { .. } = expected_channel_update.unwrap() {} else {
							panic!("channel_update not found!");
						}
					},
					&NetworkUpdate::ChannelFailure { ref short_channel_id, ref is_permanent } => {
						if let NetworkUpdate::ChannelFailure { short_channel_id: ref expected_short_channel_id, is_permanent: ref expected_is_permanent } = expected_channel_update.unwrap() {
							assert!(*short_channel_id == *expected_short_channel_id);
							assert!(*is_permanent == *expected_is_permanent);
						} else {
							panic!("Unexpected message event");
						}
					},
					&NetworkUpdate::NodeFailure { ref node_id, ref is_permanent } => {
						if let NetworkUpdate::NodeFailure { node_id: ref expected_node_id, is_permanent: ref expected_is_permanent } = expected_channel_update.unwrap() {
							assert!(*node_id == *expected_node_id);
							assert!(*is_permanent == *expected_is_permanent);
						} else {
							panic!("Unexpected message event");
						}
					},
				}
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
		Event::PaymentFailed { payment_hash: ev_payment_hash, payment_id: ev_payment_id } => {
			assert_eq!(*payment_hash, ev_payment_hash);
			assert_eq!(payment_id, ev_payment_id);
		}
		_ => panic!("Unexpected second event"),
	}
}

impl msgs::ChannelUpdate {
	fn dummy(short_channel_id: u64) -> msgs::ChannelUpdate {
		use bitcoin::secp256k1::ffi::Signature as FFISignature;
		use bitcoin::secp256k1::ecdsa::Signature;
		msgs::ChannelUpdate {
			signature: Signature::from(unsafe { FFISignature::new() }),
			contents: msgs::UnsignedChannelUpdate {
				chain_hash: BlockHash::hash(&vec![0u8][..]),
				short_channel_id,
				timestamp: 0,
				flags: 0,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				htlc_maximum_msat: msgs::MAX_VALUE_MSAT,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: vec![],
			}
		}
	}
}

struct BogusOnionHopData {
	data: Vec<u8>
}
impl BogusOnionHopData {
	fn new(orig: msgs::OnionHopData) -> Self {
		Self { data: orig.encode() }
	}
}
impl Writeable for BogusOnionHopData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&self.data[..])
	}
}

const BADONION: u16 = 0x8000;
const PERM: u16 = 0x4000;
const NODE: u16 = 0x2000;
const UPDATE: u16 = 0x1000;

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
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(config), Some(config), Some(config)]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let channels = [create_announced_chan_between_nodes(&nodes, 0, 1), create_announced_chan_between_nodes(&nodes, 1, 2)];

	// positive case
	let (route, payment_hash_success, payment_preimage_success, payment_secret_success) = get_route_and_payment_hash!(nodes[0], nodes[2], 40_000);
	nodes[0].node.send_payment(&route, payment_hash_success, &Some(payment_secret_success), PaymentId(payment_hash_success.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], 40_000, payment_hash_success, payment_secret_success);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_success);

	// If the hop gives fee_insufficient but enough fees were provided, then the previous hop
	// malleated the payment before forwarding, taking funds when they shouldn't have.
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);
	let short_channel_id = channels[0].0.contents.short_channel_id;
	run_onion_failure_test("fee_insufficient", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, || {}, true, Some(UPDATE|12), Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true}), Some(short_channel_id));

	// In an earlier version, we spuriously failed to forward payments if the expected feerate
	// changed between the channel open and the payment.
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 2;
	}

	let (payment_preimage_success, payment_hash_success, payment_secret_success) = get_payment_preimage_hash!(nodes[2]);
	nodes[0].node.send_payment(&route, payment_hash_success, &Some(payment_secret_success), PaymentId(payment_hash_success.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], 40_000, payment_hash_success, payment_secret_success);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_success);
}

#[test]
fn test_onion_failure() {
	// When we check for amount_below_minimum below, we want to test that we're using the *right*
	// amount, thus we need different htlc_minimum_msat values. We set node[2]'s htlc_minimum_msat
	// to 2000, which is above the default value of 1000 set in create_node_chanmgrs.
	// This exposed a previous bug because we were using the wrong value all the way down in
	// Channel::get_counterparty_htlc_minimum_msat().
	let mut node_2_cfg: UserConfig = Default::default();
	node_2_cfg.channel_handshake_config.our_htlc_minimum_msat = 2000;
	node_2_cfg.channel_handshake_config.announced_channel = true;
	node_2_cfg.channel_handshake_limits.force_announced_channel_preference = false;

	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 196;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(config), Some(config), Some(node_2_cfg)]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let channels = [create_announced_chan_between_nodes(&nodes, 0, 1), create_announced_chan_between_nodes(&nodes, 1, 2)];
	for node in nodes.iter() {
		*node.keys_manager.override_random_bytes.lock().unwrap() = Some([3; 32]);
	}
	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 40000);
	// positive case
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 40000);

	// intermediate node failure
	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test("invalid_realm", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let cur_height = nodes[0].best_block_info().1 + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		let (mut onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 40000, &None, cur_height, &None).unwrap();
		let mut new_payloads = Vec::new();
		for payload in onion_payloads.drain(..) {
			new_payloads.push(BogusOnionHopData::new(payload));
		}
		// break the first (non-final) hop payload by swapping the realm (0) byte for a byte
		// describing a length-1 TLV payload, which is obviously bogus.
		new_payloads[0].data[0] = 1;
		msg.onion_routing_packet = onion_utils::construct_onion_packet_with_writable_hopdata(new_payloads, onion_keys, [0; 32], &payment_hash);
	}, ||{}, true, Some(PERM|22), Some(NetworkUpdate::ChannelFailure{short_channel_id, is_permanent: true}), Some(short_channel_id));

	// final node failure
	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test("invalid_realm", 3, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let cur_height = nodes[0].best_block_info().1 + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		let (mut onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 40000, &None, cur_height, &None).unwrap();
		let mut new_payloads = Vec::new();
		for payload in onion_payloads.drain(..) {
			new_payloads.push(BogusOnionHopData::new(payload));
		}
		// break the last-hop payload by swapping the realm (0) byte for a byte describing a
		// length-1 TLV payload, which is obviously bogus.
		new_payloads[1].data[0] = 1;
		msg.onion_routing_packet = onion_utils::construct_onion_packet_with_writable_hopdata(new_payloads, onion_keys, [0; 32], &payment_hash);
	}, ||{}, false, Some(PERM|22), Some(NetworkUpdate::ChannelFailure{short_channel_id, is_permanent: true}), Some(short_channel_id));

	// the following three with run_onion_failure_test_with_fail_intercept() test only the origin node
	// receiving simulated fail messages
	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("temporary_node_failure", 100, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		// trigger error
		msg.amount_msat -= 1;
	}, |msg| {
		// and tamper returning error message
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[0].shared_secret.as_ref(), NODE|2, &[0;0]);
	}, ||{}, true, Some(NODE|2), Some(NetworkUpdate::NodeFailure{node_id: route.paths[0][0].pubkey, is_permanent: false}), Some(route.paths[0][0].short_channel_id));

	// final node failure
	run_onion_failure_test_with_fail_intercept("temporary_node_failure", 200, &nodes, &route, &payment_hash, &payment_secret, |_msg| {}, |msg| {
		// and tamper returning error message
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[1].shared_secret.as_ref(), NODE|2, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, true, Some(NODE|2), Some(NetworkUpdate::NodeFailure{node_id: route.paths[0][1].pubkey, is_permanent: false}), Some(route.paths[0][1].short_channel_id));
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("permanent_node_failure", 100, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[0].shared_secret.as_ref(), PERM|NODE|2, &[0;0]);
	}, ||{}, true, Some(PERM|NODE|2), Some(NetworkUpdate::NodeFailure{node_id: route.paths[0][0].pubkey, is_permanent: true}), Some(route.paths[0][0].short_channel_id));

	// final node failure
	run_onion_failure_test_with_fail_intercept("permanent_node_failure", 200, &nodes, &route, &payment_hash, &payment_secret, |_msg| {}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[1].shared_secret.as_ref(), PERM|NODE|2, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, false, Some(PERM|NODE|2), Some(NetworkUpdate::NodeFailure{node_id: route.paths[0][1].pubkey, is_permanent: true}), Some(route.paths[0][1].short_channel_id));
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("required_node_feature_missing", 100, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[0].shared_secret.as_ref(), PERM|NODE|3, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, true, Some(PERM|NODE|3), Some(NetworkUpdate::NodeFailure{node_id: route.paths[0][0].pubkey, is_permanent: true}), Some(route.paths[0][0].short_channel_id));

	// final node failure
	run_onion_failure_test_with_fail_intercept("required_node_feature_missing", 200, &nodes, &route, &payment_hash, &payment_secret, |_msg| {}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[1].shared_secret.as_ref(), PERM|NODE|3, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, false, Some(PERM|NODE|3), Some(NetworkUpdate::NodeFailure{node_id: route.paths[0][1].pubkey, is_permanent: true}), Some(route.paths[0][1].short_channel_id));
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);

	// Our immediate peer sent UpdateFailMalformedHTLC because it couldn't understand the onion in
	// the UpdateAddHTLC that we sent.
	let short_channel_id = channels[0].0.contents.short_channel_id;
	run_onion_failure_test("invalid_onion_version", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| { msg.onion_routing_packet.version = 1; }, ||{}, true,
		Some(BADONION|PERM|4), None, Some(short_channel_id));

	run_onion_failure_test("invalid_onion_hmac", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| { msg.onion_routing_packet.hmac = [3; 32]; }, ||{}, true,
		Some(BADONION|PERM|5), None, Some(short_channel_id));

	run_onion_failure_test("invalid_onion_key", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| { msg.onion_routing_packet.public_key = Err(secp256k1::Error::InvalidPublicKey);}, ||{}, true,
		Some(BADONION|PERM|6), None, Some(short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	let chan_update = ChannelUpdate::dummy(short_channel_id);

	let mut err_data = Vec::new();
	err_data.extend_from_slice(&(chan_update.serialized_length() as u16 + 2).to_be_bytes());
	err_data.extend_from_slice(&ChannelUpdate::TYPE.to_be_bytes());
	err_data.extend_from_slice(&chan_update.encode());
	run_onion_failure_test_with_fail_intercept("temporary_channel_failure", 100, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[0].shared_secret.as_ref(), UPDATE|7, &err_data);
	}, ||{}, true, Some(UPDATE|7), Some(NetworkUpdate::ChannelUpdateMessage{msg: chan_update.clone()}), Some(short_channel_id));

	// Check we can still handle onion failures that include channel updates without a type prefix
	let err_data_without_type = chan_update.encode_with_len();
	run_onion_failure_test_with_fail_intercept("temporary_channel_failure", 100, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[0].shared_secret.as_ref(), UPDATE|7, &err_data_without_type);
	}, ||{}, true, Some(UPDATE|7), Some(NetworkUpdate::ChannelUpdateMessage{msg: chan_update}), Some(short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test_with_fail_intercept("permanent_channel_failure", 100, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[0].shared_secret.as_ref(), PERM|8, &[0;0]);
		// short_channel_id from the processing node
	}, ||{}, true, Some(PERM|8), Some(NetworkUpdate::ChannelFailure{short_channel_id, is_permanent: true}), Some(short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test_with_fail_intercept("required_channel_feature_missing", 100, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[0].shared_secret.as_ref(), PERM|9, &[0;0]);
		// short_channel_id from the processing node
	}, ||{}, true, Some(PERM|9), Some(NetworkUpdate::ChannelFailure{short_channel_id, is_permanent: true}), Some(short_channel_id));

	let mut bogus_route = route.clone();
	bogus_route.paths[0][1].short_channel_id -= 1;
	let short_channel_id = bogus_route.paths[0][1].short_channel_id;
	run_onion_failure_test("unknown_next_peer", 0, &nodes, &bogus_route, &payment_hash, &payment_secret, |_| {}, ||{}, true, Some(PERM|10),
	  Some(NetworkUpdate::ChannelFailure{short_channel_id, is_permanent:true}), Some(short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	let amt_to_forward = nodes[1].node.per_peer_state.read().unwrap().get(&nodes[2].node.get_our_node_id())
		.unwrap().lock().unwrap().channel_by_id.get(&channels[1].2).unwrap()
		.get_counterparty_htlc_minimum_msat() - 1;
	let mut bogus_route = route.clone();
	let route_len = bogus_route.paths[0].len();
	bogus_route.paths[0][route_len-1].fee_msat = amt_to_forward;
	run_onion_failure_test("amount_below_minimum", 0, &nodes, &bogus_route, &payment_hash, &payment_secret, |_| {}, ||{}, true, Some(UPDATE|11), Some(NetworkUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy(short_channel_id)}), Some(short_channel_id));

	// Clear pending payments so that the following positive test has the correct payment hash.
	for node in nodes.iter() {
		node.node.clear_pending_payments();
	}

	// Test a positive test-case with one extra msat, meeting the minimum.
	bogus_route.paths[0][route_len-1].fee_msat = amt_to_forward + 1;
	let preimage = send_along_route(&nodes[0], bogus_route, &[&nodes[1], &nodes[2]], amt_to_forward+1).0;
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], preimage);

	let short_channel_id = channels[0].0.contents.short_channel_id;
	run_onion_failure_test("fee_insufficient", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, || {}, true, Some(UPDATE|12), Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true}), Some(short_channel_id));

	let short_channel_id = channels[0].0.contents.short_channel_id;
	run_onion_failure_test("incorrect_cltv_expiry", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		// need to violate: cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value
		msg.cltv_expiry -= 1;
	}, || {}, true, Some(UPDATE|13), Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent: true}), Some(short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test("expiry_too_soon", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS + 1;
		connect_blocks(&nodes[0], height - nodes[0].best_block_info().1);
		connect_blocks(&nodes[1], height - nodes[1].best_block_info().1);
		connect_blocks(&nodes[2], height - nodes[2].best_block_info().1);
	}, ||{}, true, Some(UPDATE|14), Some(NetworkUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy(short_channel_id)}), Some(short_channel_id));

	run_onion_failure_test("unknown_payment_hash", 2, &nodes, &route, &payment_hash, &payment_secret, |_| {}, || {
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, false, Some(PERM|15), None, None);
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);

	run_onion_failure_test("final_expiry_too_soon", 1, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS + 1;
		connect_blocks(&nodes[0], height - nodes[0].best_block_info().1);
		connect_blocks(&nodes[1], height - nodes[1].best_block_info().1);
		connect_blocks(&nodes[2], height - nodes[2].best_block_info().1);
	}, || {}, false, Some(0x4000 | 15), None, None);

	run_onion_failure_test("final_incorrect_cltv_expiry", 1, &nodes, &route, &payment_hash, &payment_secret, |_| {}, || {
		for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
			for f in pending_forwards.iter_mut() {
				match f {
					&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo { ref mut forward_info, .. }) =>
						forward_info.outgoing_cltv_value += 1,
					_ => {},
				}
			}
		}
	}, true, Some(18), None, Some(channels[1].0.contents.short_channel_id));

	run_onion_failure_test("final_incorrect_htlc_amount", 1, &nodes, &route, &payment_hash, &payment_secret, |_| {}, || {
		// violate amt_to_forward > msg.amount_msat
		for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
			for f in pending_forwards.iter_mut() {
				match f {
					&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo { ref mut forward_info, .. }) =>
						forward_info.outgoing_amt_msat -= 1,
					_ => {},
				}
			}
		}
	}, true, Some(19), None, Some(channels[1].0.contents.short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test("channel_disabled", 0, &nodes, &route, &payment_hash, &payment_secret, |_| {}, || {
		// disconnect event to the channel between nodes[1] ~ nodes[2]
		nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id());
		nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	}, true, Some(UPDATE|20), Some(NetworkUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy(short_channel_id)}), Some(short_channel_id));
	reconnect_nodes(&nodes[1], &nodes[2], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	run_onion_failure_test("expiry_too_far", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let mut route = route.clone();
		let height = nodes[2].best_block_info().1;
		route.paths[0][1].cltv_expiry_delta += CLTV_FAR_FAR_AWAY + route.paths[0][0].cltv_expiry_delta + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		let (onion_payloads, _, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 40000, &None, height, &None).unwrap();
		let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash);
		msg.cltv_expiry = htlc_cltv;
		msg.onion_routing_packet = onion_packet;
	}, ||{}, true, Some(21), Some(NetworkUpdate::NodeFailure{node_id: route.paths[0][0].pubkey, is_permanent: true}), Some(route.paths[0][0].short_channel_id));

	run_onion_failure_test_with_fail_intercept("mpp_timeout", 200, &nodes, &route, &payment_hash, &payment_secret, |_msg| {}, |msg| {
		// Tamper returning error message
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[1].shared_secret.as_ref(), 23, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash);
	}, true, Some(23), None, None);
}

fn do_test_onion_failure_stale_channel_update(announced_channel: bool) {
	// Create a network of three nodes and two channels connecting them. We'll be updating the
	// HTLC relay policy of the second channel, causing forwarding failures at the first hop.
	let mut config = UserConfig::default();
	config.channel_handshake_config.announced_channel = announced_channel;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.accept_forwards_to_priv_channels = !announced_channel;
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let persister;
	let chain_monitor;
	let channel_manager_1_deserialized;
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, Some(config), None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let other_channel = create_chan_between_nodes(
		&nodes[0], &nodes[1],
	);
	let channel_to_update = if announced_channel {
		let channel = create_announced_chan_between_nodes(
			&nodes, 1, 2,
		);
		(channel.2, channel.0.contents.short_channel_id)
	} else {
		let channel = create_unannounced_chan_between_nodes_with_value(
			&nodes, 1, 2, 100000, 10001,
		);
		(channel.0.channel_id, channel.0.short_channel_id_alias.unwrap())
	};
	let channel_to_update_counterparty = &nodes[2].node.get_our_node_id();

	let default_config = ChannelConfig::default();

	// A test payment should succeed as the ChannelConfig has not been changed yet.
	const PAYMENT_AMT: u64 = 40000;
	let (route, payment_hash, payment_preimage, payment_secret) = if announced_channel {
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
		let payment_params = PaymentParameters::from_node_id(*channel_to_update_counterparty, TEST_FINAL_CLTV)
			.with_features(nodes[2].node.invoice_features())
			.with_route_hints(hop_hints);
		get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, PAYMENT_AMT, TEST_FINAL_CLTV)
	};
	send_along_route_with_secret(&nodes[0], route.clone(), &[&[&nodes[1], &nodes[2]]], PAYMENT_AMT,
		payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// Closure to force expiry of a channel's previous config.
	let expire_prev_config = || {
		for _ in 0..EXPIRE_PREV_CONFIG_TICKS {
			nodes[1].node.timer_tick_occurred();
		}
	};

	// Closure to update and retrieve the latest ChannelUpdate.
	let update_and_get_channel_update = |config: &ChannelConfig, expect_new_update: bool,
		prev_update: Option<&msgs::ChannelUpdate>, should_expire_prev_config: bool| -> Option<msgs::ChannelUpdate> {
		nodes[1].node.update_channel_config(
			channel_to_update_counterparty, &[channel_to_update.0], config,
		).unwrap();
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), expect_new_update as usize);
		if !expect_new_update {
			return None;
		}
		let new_update = match &events[0] {
			MessageSendEvent::BroadcastChannelUpdate { msg } => {
				assert!(announced_channel);
				msg.clone()
			},
			MessageSendEvent::SendChannelUpdate { node_id, msg } => {
				assert_eq!(node_id, channel_to_update_counterparty);
				assert!(!announced_channel);
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
	let expect_onion_failure = |name: &str, error_code: u16, channel_update: &msgs::ChannelUpdate| {
		let short_channel_id = channel_to_update.1;
		let network_update = NetworkUpdate::ChannelUpdateMessage { msg: channel_update.clone() };
		run_onion_failure_test(
			name, 0, &nodes, &route, &payment_hash, &payment_secret, |_| {}, || {}, true,
			Some(error_code), Some(network_update), Some(short_channel_id),
		);
	};

	// Updates to cltv_expiry_delta below MIN_CLTV_EXPIRY_DELTA should fail with APIMisuseError.
	let mut invalid_config = default_config.clone();
	invalid_config.cltv_expiry_delta = 0;
	match nodes[1].node.update_channel_config(
		channel_to_update_counterparty, &[channel_to_update.0], &invalid_config,
	) {
		Err(APIError::APIMisuseError{ .. }) => {},
		_ => panic!("unexpected result applying invalid cltv_expiry_delta"),
	}

	// Increase the base fee which should trigger a new ChannelUpdate.
	let mut config = nodes[1].node.list_usable_channels().iter()
		.find(|channel| channel.channel_id == channel_to_update.0).unwrap()
		.config.unwrap();
	config.forwarding_fee_base_msat = u32::max_value();
	let msg = update_and_get_channel_update(&config, true, None, false).unwrap();

	// The old policy should still be in effect until a new block is connected.
	send_along_route_with_secret(&nodes[0], route.clone(), &[&[&nodes[1], &nodes[2]]], PAYMENT_AMT,
		payment_hash, payment_secret);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	// Connect a block, which should expire the previous config, leading to a failure when
	// forwarding the HTLC.
	expire_prev_config();
	expect_onion_failure("fee_insufficient", UPDATE|12, &msg);

	// Redundant updates should not trigger a new ChannelUpdate.
	assert!(update_and_get_channel_update(&config, false, None, false).is_none());

	// Similarly, updates that do not have an affect on ChannelUpdate should not trigger a new one.
	config.force_close_avoidance_max_fee_satoshis *= 2;
	assert!(update_and_get_channel_update(&config, false, None, false).is_none());

	// Reset the base fee to the default and increase the proportional fee which should trigger a
	// new ChannelUpdate.
	config.forwarding_fee_base_msat = default_config.forwarding_fee_base_msat;
	config.cltv_expiry_delta = u16::max_value();
	let msg = update_and_get_channel_update(&config, true, Some(&msg), true).unwrap();
	expect_onion_failure("incorrect_cltv_expiry", UPDATE|13, &msg);

	// Reset the proportional fee and increase the CLTV expiry delta which should trigger a new
	// ChannelUpdate.
	config.cltv_expiry_delta = default_config.cltv_expiry_delta;
	config.forwarding_fee_proportional_millionths = u32::max_value();
	let msg = update_and_get_channel_update(&config, true, Some(&msg), true).unwrap();
	expect_onion_failure("fee_insufficient", UPDATE|12, &msg);

	// To test persistence of the updated config, we'll re-initialize the ChannelManager.
	let config_after_restart = {
		let chan_1_monitor_serialized = get_monitor!(nodes[1], other_channel.3).encode();
		let chan_2_monitor_serialized = get_monitor!(nodes[1], channel_to_update.0).encode();
		reload_node!(nodes[1], *nodes[1].node.get_current_default_configuration(), &nodes[1].node.encode(),
			&[&chan_1_monitor_serialized, &chan_2_monitor_serialized], persister, chain_monitor, channel_manager_1_deserialized);
		nodes[1].node.list_channels().iter()
			.find(|channel| channel.channel_id == channel_to_update.0).unwrap()
			.config.unwrap()
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

	let payment_params = PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV)
		.with_features(InvoiceFeatures::empty());
	let (route, _payment_hash, _payment_preimage, _payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], payment_params, 40000, TEST_FINAL_CLTV);

	let hops = &route.paths[0];
	// Asserts that the first hop to `node[1]` signals no support for variable length onions.
	assert!(!hops[0].node_features.supports_variable_length_onion());
	// Asserts that the first hop to `node[1]` signals no support for variable length onions.
	assert!(!hops[1].node_features.supports_variable_length_onion());

	let cur_height = nodes[0].best_block_info().1 + 1;
	let (onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 40000, &None, cur_height, &None).unwrap();

	match onion_payloads[0].format {
		msgs::OnionHopDataFormat::NonFinalNode {..} => {},
		_ => { panic!(
			"Should have generated a `msgs::OnionHopDataFormat::NonFinalNode` payload for `hops[0]`,
			despite that the features signals no support for variable length onions"
		)}
	}
	match onion_payloads[1].format {
		msgs::OnionHopDataFormat::FinalNode {..} => {},
		_ => {panic!(
			"Should have generated a `msgs::OnionHopDataFormat::FinalNode` payload for `hops[1]`,
			despite that the features signals no support for variable length onions"
		)}
	}
}

fn do_test_fail_htlc_backwards_with_reason(failure_code: FailureCode) {

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_amount = 100_000;
	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], payment_amount);
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(nodes[1], payment_hash, payment_secret, payment_amount);
	nodes[1].node.fail_htlc_backwards_with_reason(&payment_hash, failure_code);

	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: payment_hash }]);
	check_added_monitors!(nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_fail_htlc, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs { node_id: _ , updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
			(update_fail_htlcs[0].clone(), commitment_signed)
		},
		_ => panic!("Unexpected event"),
	};

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &update_fail_htlc);
	commitment_signed_dance!(nodes[0], nodes[1], commitment_signed, false, true);

	let failure_data = match failure_code {
		FailureCode::TemporaryNodeFailure => vec![],
		FailureCode::RequiredNodeFeatureMissing => vec![],
		FailureCode::IncorrectOrUnknownPaymentDetails => {
			let mut htlc_msat_height_data = (payment_amount as u64).to_be_bytes().to_vec();
			htlc_msat_height_data.extend_from_slice(&CHAN_CONFIRM_DEPTH.to_be_bytes());
			htlc_msat_height_data
		}
	};

	let failure_code = failure_code as u16;
	let permanent_flag = 0x4000;
	let permanent_fail = (failure_code & permanent_flag) != 0;
	expect_payment_failed!(nodes[0], payment_hash, permanent_fail, failure_code, failure_data);

}

#[test]
fn test_fail_htlc_backwards_with_reason() {
	do_test_fail_htlc_backwards_with_reason(FailureCode::TemporaryNodeFailure);
	do_test_fail_htlc_backwards_with_reason(FailureCode::RequiredNodeFeatureMissing);
	do_test_fail_htlc_backwards_with_reason(FailureCode::IncorrectOrUnknownPaymentDetails);
}

macro_rules! get_phantom_route {
	($nodes: expr, $amt: expr, $channel: expr) => {{
		let phantom_pubkey = $nodes[1].keys_manager.get_node_id(Recipient::PhantomNode).unwrap();
		let phantom_route_hint = $nodes[1].node.get_phantom_route_hints();
		let payment_params = PaymentParameters::from_node_id(phantom_pubkey, TEST_FINAL_CLTV)
			.with_features($nodes[1].node.invoice_features())
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
						fees: RoutingFees {
							base_msat: 0,
							proportional_millionths: 0,
						},
						cltv_expiry_delta: MIN_CLTV_EXPIRY_DELTA,
						htlc_minimum_msat: None,
						htlc_maximum_msat: None,
					}
		])]);
		let scorer = test_utils::TestScorer::new();
		let network_graph = $nodes[0].network_graph.read_only();
		(get_route(
			&$nodes[0].node.get_our_node_id(), &payment_params, &network_graph,
			Some(&$nodes[0].node.list_usable_channels().iter().collect::<Vec<_>>()),
			$amt, TEST_FINAL_CLTV, $nodes[0].logger, &scorer, &[0u8; 32]
		).unwrap(), phantom_route_hint.phantom_scid)
	}
}}

#[test]
fn test_phantom_onion_hmac_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	// Modify the payload so the phantom hop's HMAC is bogus.
	let sha256_of_onion = {
		let mut forward_htlcs = nodes[1].node.forward_htlcs.lock().unwrap();
		let mut pending_forward = forward_htlcs.get_mut(&phantom_scid).unwrap();
		match pending_forward[0] {
			HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
				forward_info: PendingHTLCInfo {
					routing: PendingHTLCRouting::Forward { ref mut onion_packet, .. },
					..
				}, ..
			}) => {
				onion_packet.hmac[onion_packet.hmac.len() - 1] ^= 1;
				Sha256::hash(&onion_packet.hop_data).into_inner().to_vec()
			},
			_ => panic!("Unexpected forward"),
		}
	};
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.blamed_chan_closed(true)
		.expected_htlc_error_data(0x8000 | 0x4000 | 5, &sha256_of_onion);
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
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// We'll use the session priv later when constructing an invalid onion packet.
	let session_priv = [3; 32];
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(session_priv);
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	// Modify the onion packet to have an invalid payment amount.
	for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
					forward_info: PendingHTLCInfo {
						routing: PendingHTLCRouting::Forward { ref mut onion_packet, .. },
						..
					}, ..
				}) => {
					// Construct the onion payloads for the entire route and an invalid amount.
					let height = nodes[0].best_block_info().1;
					let session_priv = SecretKey::from_slice(&session_priv).unwrap();
					let mut onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
					let (mut onion_payloads, _, _) = onion_utils::build_onion_payloads(&route.paths[0], msgs::MAX_VALUE_MSAT + 1, &Some(payment_secret), height + 1, &None).unwrap();
					// We only want to construct the onion packet for the last hop, not the entire route, so
					// remove the first hop's payload and its keys.
					onion_keys.remove(0);
					onion_payloads.remove(0);

					let new_onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash);
					onion_packet.hop_data = new_onion_packet.hop_data;
					onion_packet.hmac = new_onion_packet.hmac;
				},
				_ => panic!("Unexpected forward"),
			}
		}
	}
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let error_data = Vec::new();
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.blamed_chan_closed(true)
		.expected_htlc_error_data(0x4000 | 22, &error_data);
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
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	// Modify the payload so the phantom hop's HMAC is bogus.
	for (_, pending_forwards) in nodes[1].node.forward_htlcs.lock().unwrap().iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC(PendingAddHTLCInfo {
					forward_info: PendingHTLCInfo { ref mut outgoing_cltv_value, .. }, ..
				}) => {
					*outgoing_cltv_value += 1;
				},
				_ => panic!("Unexpected forward"),
			}
		}
	}
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let expected_cltv: u32 = 82;
	let error_data = expected_cltv.to_be_bytes().to_vec();
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(18, &error_data);
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
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Modify the route to have a too-low cltv.
	route.paths[0][1].cltv_expiry_delta = 5;

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut error_data = recv_value_msat.to_be_bytes().to_vec();
	error_data.extend_from_slice(
		&nodes[0].node.best_block.read().unwrap().height().to_be_bytes(),
	);
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(0x4000 | 15, &error_data);
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
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	// Modify the route to have a too-low cltv.
	update_add.cltv_expiry -= 10;

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(0x2000 | 2, &[]);
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
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	connect_blocks(&nodes[1], CLTV_FAR_FAR_AWAY);
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(0x2000 | 2, &[]);
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
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_amt_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, bad_recv_amt_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash: payment_hash.clone() }]);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut error_data = bad_recv_amt_msat.to_be_bytes().to_vec();
	error_data.extend_from_slice(&nodes[1].node.best_block.read().unwrap().height().to_be_bytes());
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(0x4000 | 15, &error_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, true, fail_conditions);
}

#[test]
fn test_phantom_dust_exposure_failure() {
	// Set the max dust exposure to the dust limit.
	let max_dust_exposure = 546;
	let mut receiver_config = UserConfig::default();
	receiver_config.channel_config.max_dust_htlc_exposure_msat = max_dust_exposure;
	receiver_config.channel_handshake_config.announced_channel = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(receiver_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Get the route with an amount exceeding the dust exposure threshold of nodes[1].
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(max_dust_exposure + 1));
	let (mut route, _) = get_phantom_route!(nodes, max_dust_exposure + 1, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut err_data = Vec::new();
	err_data.extend_from_slice(&(channel.1.serialized_length() as u16 + 2).to_be_bytes());
	err_data.extend_from_slice(&ChannelUpdate::TYPE.to_be_bytes());
	err_data.extend_from_slice(&channel.1.encode());

	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(channel.0.contents.short_channel_id)
		.blamed_chan_closed(false)
		.expected_htlc_error_data(0x1000 | 7, &err_data);
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
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_amt_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_amt_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_payment_claimable!(nodes[1], payment_hash, payment_secret, recv_amt_msat, None, route.paths[0].last().unwrap().pubkey);
	nodes[1].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(nodes[1], vec![HTLCDestination::FailedPayment { payment_hash }]);
	nodes[1].node.process_pending_htlc_forwards();

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut error_data = recv_amt_msat.to_be_bytes().to_vec();
	error_data.extend_from_slice(&nodes[1].node.best_block.read().unwrap().height().to_be_bytes());
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(0x4000 | 15, &error_data);
	expect_payment_failed_conditions(&nodes[0], payment_hash, true, fail_conditions);
}
