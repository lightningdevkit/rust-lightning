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

use chain::channelmonitor::{CLTV_CLAIM_BUFFER, LATENCY_GRACE_PERIOD_BLOCKS};
use chain::keysinterface::{KeysInterface, Recipient};
use ln::{PaymentHash, PaymentSecret};
use ln::channelmanager::{HTLCForwardInfo, CLTV_FAR_FAR_AWAY, MIN_CLTV_EXPIRY_DELTA, PendingHTLCInfo, PendingHTLCRouting};
use ln::onion_utils;
use routing::network_graph::{NetworkUpdate, RoutingFees, NodeId};
use routing::router::{get_route, PaymentParameters, Route, RouteHint, RouteHintHop};
use ln::features::{InitFeatures, InvoiceFeatures, NodeFeatures};
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, ChannelUpdate, OptionalField};
use ln::wire::Encode;
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use util::ser::{Writeable, Writer};
use util::{byte_utils, test_utils};
use util::config::UserConfig;

use bitcoin::hash_types::BlockHash;

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;

use bitcoin::secp256k1;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};

use io;
use prelude::*;
use core::default::Default;

use ln::functional_test_utils::*;

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
	nodes[0].node.send_payment(&route, payment_hash.clone(), &Some(*payment_secret)).unwrap();
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
				expect_event!(&nodes[2], Event::PaymentReceived);
				callback_node();
				expect_pending_htlcs_forwardable!(nodes[2]);
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
	assert_eq!(events.len(), 1);
	if let &Event::PaymentPathFailed { ref rejected_by_dest, ref network_update, ref all_paths_failed, ref short_channel_id, ref error_code, .. } = &events[0] {
		assert_eq!(*rejected_by_dest, !expected_retryable);
		assert_eq!(*all_paths_failed, true);
		assert_eq!(*error_code, expected_error_code);
		if expected_channel_update.is_some() {
			match network_update {
				Some(update) => match update {
					&NetworkUpdate::ChannelUpdateMessage { .. } => {
						if let NetworkUpdate::ChannelUpdateMessage { .. } = expected_channel_update.unwrap() {} else {
							panic!("channel_update not found!");
						}
					},
					&NetworkUpdate::ChannelClosed { ref short_channel_id, ref is_permanent } => {
						if let NetworkUpdate::ChannelClosed { short_channel_id: ref expected_short_channel_id, is_permanent: ref expected_is_permanent } = expected_channel_update.unwrap() {
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
				htlc_maximum_msat: OptionalField::Absent,
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
	config.channel_options.forwarding_fee_base_msat = 196;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(config), Some(config), Some(config)]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let channels = [create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()), create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known())];

	// positive case
	let (route, payment_hash_success, payment_preimage_success, payment_secret_success) = get_route_and_payment_hash!(nodes[0], nodes[2], 40_000);
	nodes[0].node.send_payment(&route, payment_hash_success, &Some(payment_secret_success)).unwrap();
	check_added_monitors!(nodes[0], 1);
	pass_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], 40_000, payment_hash_success, payment_secret_success);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_success);

	// If the hop gives fee_insufficient but enough fees were provided, then the previous hop
	// malleated the payment before forwarding, taking funds when they shouldn't have.
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);
	let short_channel_id = channels[0].0.contents.short_channel_id;
	run_onion_failure_test("fee_insufficient", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, || {}, true, Some(UPDATE|12), Some(NetworkUpdate::ChannelClosed { short_channel_id, is_permanent: true}), Some(short_channel_id));

	// In an earlier version, we spuriously failed to forward payments if the expected feerate
	// changed between the channel open and the payment.
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 2;
	}

	let (payment_preimage_success, payment_hash_success, payment_secret_success) = get_payment_preimage_hash!(nodes[2]);
	nodes[0].node.send_payment(&route, payment_hash_success, &Some(payment_secret_success)).unwrap();
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
	node_2_cfg.own_channel_config.our_htlc_minimum_msat = 2000;
	node_2_cfg.channel_options.announced_channel = true;
	node_2_cfg.peer_channel_config_limits.force_announced_channel_preference = false;

	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_options.forwarding_fee_base_msat = 196;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(config), Some(config), Some(node_2_cfg)]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let channels = [create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()), create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known())];
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
		msg.onion_routing_packet = onion_utils::construct_onion_packet_bogus_hopdata(new_payloads, onion_keys, [0; 32], &payment_hash);
	}, ||{}, true, Some(PERM|22), Some(NetworkUpdate::ChannelClosed{short_channel_id, is_permanent: true}), Some(short_channel_id));

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
		msg.onion_routing_packet = onion_utils::construct_onion_packet_bogus_hopdata(new_payloads, onion_keys, [0; 32], &payment_hash);
	}, ||{}, false, Some(PERM|22), Some(NetworkUpdate::ChannelClosed{short_channel_id, is_permanent: true}), Some(short_channel_id));

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
	}, ||{}, true, Some(PERM|8), Some(NetworkUpdate::ChannelClosed{short_channel_id, is_permanent: true}), Some(short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test_with_fail_intercept("required_channel_feature_missing", 100, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(onion_keys[0].shared_secret.as_ref(), PERM|9, &[0;0]);
		// short_channel_id from the processing node
	}, ||{}, true, Some(PERM|9), Some(NetworkUpdate::ChannelClosed{short_channel_id, is_permanent: true}), Some(short_channel_id));

	let mut bogus_route = route.clone();
	bogus_route.paths[0][1].short_channel_id -= 1;
	let short_channel_id = bogus_route.paths[0][1].short_channel_id;
	run_onion_failure_test("unknown_next_peer", 0, &nodes, &bogus_route, &payment_hash, &payment_secret, |_| {}, ||{}, true, Some(PERM|10),
	  Some(NetworkUpdate::ChannelClosed{short_channel_id, is_permanent:true}), Some(short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	let amt_to_forward = nodes[1].node.channel_state.lock().unwrap().by_id.get(&channels[1].2).unwrap().get_counterparty_htlc_minimum_msat() - 1;
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

	//TODO: with new config API, we will be able to generate both valid and
	//invalid channel_update cases.
	let short_channel_id = channels[0].0.contents.short_channel_id;
	run_onion_failure_test("fee_insufficient", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		msg.amount_msat -= 1;
	}, || {}, true, Some(UPDATE|12), Some(NetworkUpdate::ChannelClosed { short_channel_id, is_permanent: true}), Some(short_channel_id));

	let short_channel_id = channels[0].0.contents.short_channel_id;
	run_onion_failure_test("incorrect_cltv_expiry", 0, &nodes, &route, &payment_hash, &payment_secret, |msg| {
		// need to violate: cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value
		msg.cltv_expiry -= 1;
	}, || {}, true, Some(UPDATE|13), Some(NetworkUpdate::ChannelClosed { short_channel_id, is_permanent: true}), Some(short_channel_id));

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
	}, || {}, true, Some(17), None, None);

	run_onion_failure_test("final_incorrect_cltv_expiry", 1, &nodes, &route, &payment_hash, &payment_secret, |_| {}, || {
		for (_, pending_forwards) in nodes[1].node.channel_state.lock().unwrap().forward_htlcs.iter_mut() {
			for f in pending_forwards.iter_mut() {
				match f {
					&mut HTLCForwardInfo::AddHTLC { ref mut forward_info, .. } =>
						forward_info.outgoing_cltv_value += 1,
					_ => {},
				}
			}
		}
	}, true, Some(18), None, Some(channels[1].0.contents.short_channel_id));

	run_onion_failure_test("final_incorrect_htlc_amount", 1, &nodes, &route, &payment_hash, &payment_secret, |_| {}, || {
		// violate amt_to_forward > msg.amount_msat
		for (_, pending_forwards) in nodes[1].node.channel_state.lock().unwrap().forward_htlcs.iter_mut() {
			for f in pending_forwards.iter_mut() {
				match f {
					&mut HTLCForwardInfo::AddHTLC { ref mut forward_info, .. } =>
						forward_info.amt_to_forward -= 1,
					_ => {},
				}
			}
		}
	}, true, Some(19), None, Some(channels[1].0.contents.short_channel_id));

	let short_channel_id = channels[1].0.contents.short_channel_id;
	run_onion_failure_test("channel_disabled", 0, &nodes, &route, &payment_hash, &payment_secret, |_| {}, || {
		// disconnect event to the channel between nodes[1] ~ nodes[2]
		nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), false);
		nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
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

#[test]
fn test_default_to_onion_payload_tlv_format() {
	// Tests that we default to creating tlv format onion payloads when no `NodeAnnouncementInfo`
	// `features` for a node in the `network_graph` exists, or when the node isn't in the
	// `network_graph`, and no other known `features` for the node exists.
	let mut priv_channels_conf = UserConfig::default();
	priv_channels_conf.channel_options.announced_channel = false;
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, None, None, None, Some(priv_channels_conf)]);
	let mut nodes = create_network(5, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known());
	create_unannounced_chan_between_nodes_with_value(&nodes, 3, 4, 100000, 10001, InitFeatures::known(), InitFeatures::known());

	let payment_params = PaymentParameters::from_node_id(nodes[3].node.get_our_node_id());
	let origin_node = &nodes[0];
	let network_graph = origin_node.network_graph;

	// Clears all the `NodeAnnouncementInfo` for all nodes of `nodes[0]`'s `network_graph`, so that
	// their `features` aren't used when creating the `route`.
	network_graph.clear_nodes_announcement_info();

	let (announced_route, _, _, _) = get_route_and_payment_hash!(
		origin_node, nodes[3], payment_params, 10_000, TEST_FINAL_CLTV);

	let hops = &announced_route.paths[0];
	// Assert that the hop between `nodes[1]` and `nodes[2]` defaults to supporting variable length
	// onions, as `nodes[0]` has no `NodeAnnouncementInfo` `features` for `node[2]`
	assert!(hops[1].node_features.supports_variable_length_onion());
	// Assert that the hop between `nodes[2]` and `nodes[3]` defaults to supporting variable length
	// onions, as `nodes[0]` has no `NodeAnnouncementInfo` `features` for `node[3]`, and no `InvoiceFeatures`
	// for the `payment_params`, which would otherwise have been used.
	assert!(hops[2].node_features.supports_variable_length_onion());
	// Note that we do not assert that `hops[0]` (the channel between `nodes[0]` and `nodes[1]`)
	// supports variable length onions, as the `InitFeatures` exchanged in the init message
	// between the nodes will be used when creating the route. We therefore do not default to
	// supporting variable length onions for that hop, as the `InitFeatures` in this case are
	// `InitFeatures::known()`.

	let unannounced_chan = &nodes[4].node.list_usable_channels()[0];

	let last_hop = RouteHint(vec![RouteHintHop {
		src_node_id: nodes[3].node.get_our_node_id(),
		short_channel_id: unannounced_chan.short_channel_id.unwrap(),
		fees: RoutingFees {
			base_msat: 0,
			proportional_millionths: 0,
		},
		cltv_expiry_delta: 42,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	}]);

	let unannounced_chan_params = PaymentParameters::from_node_id(nodes[4].node.get_our_node_id()).with_route_hints(vec![last_hop]);
	let (unannounced_route, _, _, _) = get_route_and_payment_hash!(
		origin_node, nodes[4], unannounced_chan_params, 10_000, TEST_FINAL_CLTV);

	let unannounced_chan_hop = &unannounced_route.paths[0][3];
	// Ensure that `nodes[4]` doesn't exist in `nodes[0]`'s `network_graph`, as it's not public.
	assert!(&network_graph.read_only().nodes().get(&NodeId::from_pubkey(&nodes[4].node.get_our_node_id())).is_none());
	// Assert that the hop between `nodes[3]` and `nodes[4]` defaults to supporting variable length
	// onions, even though `nodes[4]` as `nodes[0]` doesn't exists in `nodes[0]`'s `network_graph`,
	// and no `InvoiceFeatures` for the `payment_params` exists, which would otherwise have been
	// used.
	assert!(unannounced_chan_hop.node_features.supports_variable_length_onion());

	let cur_height = nodes[0].best_block_info().1 + 1;
	let (announced_route_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&announced_route.paths[0], 40000, &None, cur_height, &None).unwrap();
	let (unannounced_route_paylods, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&unannounced_route.paths[0], 40000, &None, cur_height, &None).unwrap();

	for onion_payloads in vec![announced_route_payloads, unannounced_route_paylods] {
		for onion_payload in onion_payloads.iter() {
			match onion_payload.format {
				msgs::OnionHopDataFormat::Legacy {..} => {
					panic!("Generated a `msgs::OnionHopDataFormat::Legacy` payload, even though that shouldn't have happend.");
				}
				_ => {}
			}
		}
	}
}

#[test]
fn test_do_not_default_to_onion_payload_tlv_format_when_unsupported() {
	// Tests that we do not default to creating tlv onions if either of these types features
	// exists, which specifies no support for variable length onions for a specific hop, when
	// creating a route:
	// 1. `InitFeatures` to the counterparty node exchanged with the init message to the node.
	// 2. `NodeFeatures` in the `NodeAnnouncementInfo` of a node in sender node's `network_graph`.
	// 3. `InvoiceFeatures` specified by the receiving node, when no `NodeAnnouncementInfo`
	// `features` exists for the receiver in the sender's `network_graph`.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let mut node_cfgs = create_node_cfgs(4, &chanmon_cfgs);

	// Set `node[1]` config to `InitFeatures::empty()` which return `false` for
	// `supports_variable_length_onion()`
	let mut node_1_cfg = &mut node_cfgs[1];
	node_1_cfg.features = InitFeatures::empty();

	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let mut nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known());

	let payment_params = PaymentParameters::from_node_id(nodes[3].node.get_our_node_id())
		.with_features(InvoiceFeatures::empty());
	let origin_node = &nodes[0];
	let network_graph = origin_node.network_graph;
	network_graph.clear_nodes_announcement_info();

	// Set `NodeAnnouncementInfo` `features` which do not support variable length onions for
	// `nodes[2]` in `nodes[0]`'s `network_graph`.
	let nodes_2_unsigned_node_announcement = msgs::UnsignedNodeAnnouncement {
		features: NodeFeatures::empty(),
		timestamp: 0,
		node_id: nodes[2].node.get_our_node_id(),
		rgb: [32; 3],
		alias: [16;32],
		addresses: Vec::new(),
		excess_address_data: Vec::new(),
		excess_data: Vec::new(),
	};
	let _res = network_graph.update_node_from_unsigned_announcement(&nodes_2_unsigned_node_announcement);

	let (route, _, _, _) = get_route_and_payment_hash!(
		origin_node, nodes[3], payment_params, 10_000, TEST_FINAL_CLTV);

	let hops = &route.paths[0];

	// Assert that the hop between `nodes[0]` and `nodes[1]` doesn't support variable length
	// onions, as as the `InitFeatures` exchanged (`InitFeatures::empty()`) in the init message
	// between the nodes when setting up the channel is used when creating the `route` and that we
	// therefore do not default to supporting variable length onions. Despite `nodes[0]` having no
	// `NodeAnnouncementInfo` `features` for `node[1]`.
	assert!(!hops[0].node_features.supports_variable_length_onion());
	// Assert that the hop between `nodes[1]` and `nodes[2]` uses the `features` from
	// `nodes_2_unsigned_node_announcement` that doesn't support variable length onions.
	assert!(!hops[1].node_features.supports_variable_length_onion());
	// Assert that the hop between `nodes[2]` and `nodes[3]` uses the `InvoiceFeatures` set to the
	// `payment_params`, that doesn't support variable length onions. We therefore do not end up
	// defaulting to supporting variable length onions, despite `nodes[0]` having no
	// `NodeAnnouncementInfo` `features` for `node[3]`.
	assert!(!hops[2].node_features.supports_variable_length_onion());

	let cur_height = nodes[0].best_block_info().1 + 1;
	let (onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 40000, &None, cur_height, &None).unwrap();

	for onion_payload in onion_payloads.iter() {
		match onion_payload.format {
			msgs::OnionHopDataFormat::Legacy {..} => {}
			_ => {
				panic!("Should have only have generated `msgs::OnionHopDataFormat::Legacy` payloads");
			}
		}
	}
}

macro_rules! get_phantom_route {
	($nodes: expr, $amt: expr, $channel: expr) => {{
		let secp_ctx = Secp256k1::new();
		let phantom_secret = $nodes[1].keys_manager.get_node_secret(Recipient::PhantomNode).unwrap();
		let phantom_pubkey = PublicKey::from_secret_key(&secp_ctx, &phantom_secret);
		let phantom_route_hint = $nodes[1].node.get_phantom_route_hints();
		let payment_params = PaymentParameters::from_node_id(phantom_pubkey)
			.with_features(InvoiceFeatures::known())
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
		let scorer = test_utils::TestScorer::with_penalty(0);
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

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash.clone(), &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	// Modify the payload so the phantom hop's HMAC is bogus.
	let sha256_of_onion = {
		let mut channel_state = nodes[1].node.channel_state.lock().unwrap();
		let mut pending_forward = channel_state.forward_htlcs.get_mut(&phantom_scid).unwrap();
		match pending_forward[0] {
			HTLCForwardInfo::AddHTLC {
				forward_info: PendingHTLCInfo {
					routing: PendingHTLCRouting::Forward { ref mut onion_packet, .. },
					..
				}, ..
			} => {
				onion_packet.hmac[onion_packet.hmac.len() - 1] ^= 1;
				Sha256::hash(&onion_packet.hop_data).into_inner().to_vec()
			},
			_ => panic!("Unexpected forward"),
		}
	};
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
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
	expect_payment_failed_conditions!(nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_invalid_onion_payload() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// We'll use the session priv later when constructing an invalid onion packet.
	let session_priv = [3; 32];
	*nodes[0].keys_manager.override_random_bytes.lock().unwrap() = Some(session_priv);
	nodes[0].node.send_payment(&route, payment_hash.clone(), &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	// Modify the onion packet to have an invalid payment amount.
	for (_, pending_forwards) in nodes[1].node.channel_state.lock().unwrap().forward_htlcs.iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC {
					forward_info: PendingHTLCInfo {
						routing: PendingHTLCRouting::Forward { ref mut onion_packet, .. },
						..
					}, ..
				} => {
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
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
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
	expect_payment_failed_conditions!(nodes[0], payment_hash, true, fail_conditions);
}

#[test]
fn test_phantom_final_incorrect_cltv_expiry() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash.clone(), &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	// Modify the payload so the phantom hop's HMAC is bogus.
	for (_, pending_forwards) in nodes[1].node.channel_state.lock().unwrap().forward_htlcs.iter_mut() {
		for f in pending_forwards.iter_mut() {
			match f {
				&mut HTLCForwardInfo::AddHTLC {
					forward_info: PendingHTLCInfo { ref mut outgoing_cltv_value, .. }, ..
				} => {
					*outgoing_cltv_value += 1;
				},
				_ => panic!("Unexpected forward"),
			}
		}
	}
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let expected_cltv = 82;
	let error_data = byte_utils::be32_to_array(expected_cltv).to_vec();
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(18, &error_data);
	expect_payment_failed_conditions!(nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_failure_too_low_cltv() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Get the route.
	let recv_value_msat = 10_000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_value_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_value_msat, channel);

	// Modify the route to have a too-low cltv.
	route.paths[0][1].cltv_expiry_delta = 5;

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash.clone(), &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
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
		.expected_htlc_error_data(17, &error_data);
	expect_payment_failed_conditions!(nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_failure_too_low_recv_amt() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Get the route with a too-low amount.
	let recv_amt_msat = 10_000;
	let bad_recv_amt_msat = recv_amt_msat - 10;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_amt_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, bad_recv_amt_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash.clone(), &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut error_data = byte_utils::be64_to_array(bad_recv_amt_msat).to_vec();
	error_data.extend_from_slice(
		&byte_utils::be32_to_array(nodes[1].node.best_block.read().unwrap().height()),
	);
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(0x4000 | 15, &error_data);
	expect_payment_failed_conditions!(nodes[0], payment_hash, true, fail_conditions);
}

#[test]
fn test_phantom_dust_exposure_failure() {
	// Set the max dust exposure to the dust limit.
	let max_dust_exposure = 546;
	let mut receiver_config = UserConfig::default();
	receiver_config.channel_options.max_dust_htlc_exposure_msat = max_dust_exposure;
	receiver_config.channel_options.announced_channel = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(receiver_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Get the route with an amount exceeding the dust exposure threshold of nodes[1].
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(max_dust_exposure + 1));
	let (mut route, _) = get_phantom_route!(nodes, max_dust_exposure + 1, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash.clone(), &Some(payment_secret)).unwrap();
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
		expect_payment_failed_conditions!(nodes[0], payment_hash, false, fail_conditions);
}

#[test]
fn test_phantom_failure_reject_payment() {
	// Test that the user can successfully fail back a phantom node payment.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let channel = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	// Get the route with a too-low amount.
	let recv_amt_msat = 10_000;
	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[1], Some(recv_amt_msat));
	let (mut route, phantom_scid) = get_phantom_route!(nodes, recv_amt_msat, channel);

	// Route the HTLC through to the destination.
	nodes[0].node.send_payment(&route, payment_hash.clone(), &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let update_0 = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	let mut update_add = update_0.update_add_htlcs[0].clone();

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[1], nodes[0], &update_0.commitment_signed, false, true);

	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();
	expect_payment_received!(nodes[1], payment_hash, payment_secret, recv_amt_msat);
	nodes[1].node.fail_htlc_backwards(&payment_hash);
	expect_pending_htlcs_forwardable_ignore!(nodes[1]);
	nodes[1].node.process_pending_htlc_forwards();

	let update_1 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(&nodes[1], 1);
	assert!(update_1.update_fail_htlcs.len() == 1);
	let fail_msg = update_1.update_fail_htlcs[0].clone();
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_msg);
	commitment_signed_dance!(nodes[0], nodes[1], update_1.commitment_signed, false);

	// Ensure the payment fails with the expected error.
	let mut error_data = byte_utils::be64_to_array(recv_amt_msat).to_vec();
	error_data.extend_from_slice(
		&byte_utils::be32_to_array(nodes[1].node.best_block.read().unwrap().height()),
	);
	let mut fail_conditions = PaymentFailedConditions::new()
		.blamed_scid(phantom_scid)
		.expected_htlc_error_data(0x4000 | 15, &error_data);
	expect_payment_failed_conditions!(nodes[0], payment_hash, true, fail_conditions);
}
