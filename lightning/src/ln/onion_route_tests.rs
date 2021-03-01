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
use ln::channelmanager::{HTLCForwardInfo, PaymentPreimage, PaymentHash};
use ln::onion_utils;
use routing::router::{Route, get_route};
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, HTLCFailChannelUpdate, OptionalField};
use util::test_utils;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use util::ser::{Writeable, Writer};
use util::config::UserConfig;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::hash_types::BlockHash;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::key::SecretKey;

use std::default::Default;
use std::sync::atomic::Ordering;
use std::io;

use ln::functional_test_utils::*;

fn run_onion_failure_test<F1,F2>(_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash, callback_msg: F1, callback_node: F2, expected_retryable: bool, expected_error_code: Option<u16>, expected_channel_update: Option<HTLCFailChannelUpdate>)
	where F1: for <'a> FnMut(&'a mut msgs::UpdateAddHTLC),
				F2: FnMut(),
{
	run_onion_failure_test_with_fail_intercept(_name, test_case, nodes, route, payment_hash, callback_msg, |_|{}, callback_node, expected_retryable, expected_error_code, expected_channel_update);
}

// test_case
// 0: node1 fails backward
// 1: final node fails backward
// 2: payment completed but the user rejects the payment
// 3: final node fails backward (but tamper onion payloads from node0)
// 100: trigger error in the intermediate node and tamper returning fail_htlc
// 200: trigger error in the final node and tamper returning fail_htlc
fn run_onion_failure_test_with_fail_intercept<F1,F2,F3>(_name: &str, test_case: u8, nodes: &Vec<Node>, route: &Route, payment_hash: &PaymentHash, mut callback_msg: F1, mut callback_fail: F2, mut callback_node: F3, expected_retryable: bool, expected_error_code: Option<u16>, expected_channel_update: Option<HTLCFailChannelUpdate>)
	where F1: for <'a> FnMut(&'a mut msgs::UpdateAddHTLC),
				F2: for <'a> FnMut(&'a mut msgs::UpdateFailHTLC),
				F3: FnMut(),
{

	// reset block height
	let block = Block {
		header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
		txdata: vec![],
	};
	for ix in 0..nodes.len() {
		connect_block(&nodes[ix], &block, 1);
	}

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
	nodes[0].node.send_payment(&route, payment_hash.clone(), &None).unwrap();
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
	if let &Event::PaymentFailed { payment_hash:_, ref rejected_by_dest, ref error_code, error_data: _ } = &events[0] {
		assert_eq!(*rejected_by_dest, !expected_retryable);
		assert_eq!(*error_code, expected_error_code);
	} else {
		panic!("Uexpected event");
	}

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	if expected_channel_update.is_some() {
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::PaymentFailureNetworkUpdate { ref update } => {
				match update {
					&HTLCFailChannelUpdate::ChannelUpdateMessage { .. } => {
						if let HTLCFailChannelUpdate::ChannelUpdateMessage { .. } = expected_channel_update.unwrap() {} else {
							panic!("channel_update not found!");
						}
					},
					&HTLCFailChannelUpdate::ChannelClosed { ref short_channel_id, ref is_permanent } => {
						if let HTLCFailChannelUpdate::ChannelClosed { short_channel_id: ref expected_short_channel_id, is_permanent: ref expected_is_permanent } = expected_channel_update.unwrap() {
							assert!(*short_channel_id == *expected_short_channel_id);
							assert!(*is_permanent == *expected_is_permanent);
						} else {
							panic!("Unexpected message event");
						}
					},
					&HTLCFailChannelUpdate::NodeFailure { ref node_id, ref is_permanent } => {
						if let HTLCFailChannelUpdate::NodeFailure { node_id: ref expected_node_id, is_permanent: ref expected_is_permanent } = expected_channel_update.unwrap() {
							assert!(*node_id == *expected_node_id);
							assert!(*is_permanent == *expected_is_permanent);
						} else {
							panic!("Unexpected message event");
						}
					},
				}
			},
			_ => panic!("Unexpected message event"),
		}
	} else {
		assert_eq!(events.len(), 0);
	}
}

impl msgs::ChannelUpdate {
	fn dummy() -> msgs::ChannelUpdate {
		use bitcoin::secp256k1::ffi::Signature as FFISignature;
		use bitcoin::secp256k1::Signature;
		msgs::ChannelUpdate {
			signature: Signature::from(unsafe { FFISignature::new() }),
			contents: msgs::UnsignedChannelUpdate {
				chain_hash: BlockHash::hash(&vec![0u8][..]),
				short_channel_id: 0,
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

#[test]
fn test_onion_failure() {
	use ln::msgs::ChannelUpdate;
	use ln::channelmanager::CLTV_FAR_FAR_AWAY;
	use bitcoin::secp256k1;

	const BADONION: u16 = 0x8000;
	const PERM: u16 = 0x4000;
	const NODE: u16 = 0x2000;
	const UPDATE: u16 = 0x1000;

	// When we check for amount_below_minimum below, we want to test that we're using the *right*
	// amount, thus we need different htlc_minimum_msat values. We set node[2]'s htlc_minimum_msat
	// to 2000, which is above the default value of 1000 set in create_node_chanmgrs.
	// This exposed a previous bug because we were using the wrong value all the way down in
	// Channel::get_counterparty_htlc_minimum_msat().
	let mut node_2_cfg: UserConfig = Default::default();
	node_2_cfg.own_channel_config.our_htlc_minimum_msat = 2000;
	node_2_cfg.channel_options.announced_channel = true;
	node_2_cfg.peer_channel_config_limits.force_announced_channel_preference = false;

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, Some(node_2_cfg)]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	for node in nodes.iter() {
		*node.keys_manager.override_session_priv.lock().unwrap() = Some([3; 32]);
	}
	let channels = [create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()), create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known())];
	let (_, payment_hash) = get_payment_preimage_hash!(nodes[0]);
	let net_graph_msg_handler = &nodes[0].net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let route = get_route(&nodes[0].node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &nodes[2].node.get_our_node_id(), None, &Vec::new(), 40000, TEST_FINAL_CLTV, &logger).unwrap();
	// positve case
	send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 40000, 40_000);

	// intermediate node failure
	run_onion_failure_test("invalid_realm", 0, &nodes, &route, &payment_hash, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		let (mut onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 40000, &None, cur_height).unwrap();
		let mut new_payloads = Vec::new();
		for payload in onion_payloads.drain(..) {
			new_payloads.push(BogusOnionHopData::new(payload));
		}
		// break the first (non-final) hop payload by swapping the realm (0) byte for a byte
		// describing a length-1 TLV payload, which is obviously bogus.
		new_payloads[0].data[0] = 1;
		msg.onion_routing_packet = onion_utils::construct_onion_packet_bogus_hopdata(new_payloads, onion_keys, [0; 32], &payment_hash);
	}, ||{}, true, Some(PERM|22), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));//XXX incremented channels idx here

	// final node failure
	run_onion_failure_test("invalid_realm", 3, &nodes, &route, &payment_hash, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let cur_height = nodes[0].node.latest_block_height.load(Ordering::Acquire) as u32 + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		let (mut onion_payloads, _htlc_msat, _htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 40000, &None, cur_height).unwrap();
		let mut new_payloads = Vec::new();
		for payload in onion_payloads.drain(..) {
			new_payloads.push(BogusOnionHopData::new(payload));
		}
		// break the last-hop payload by swapping the realm (0) byte for a byte describing a
		// length-1 TLV payload, which is obviously bogus.
		new_payloads[1].data[0] = 1;
		msg.onion_routing_packet = onion_utils::construct_onion_packet_bogus_hopdata(new_payloads, onion_keys, [0; 32], &payment_hash);
	}, ||{}, false, Some(PERM|22), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));

	// the following three with run_onion_failure_test_with_fail_intercept() test only the origin node
	// receiving simulated fail messages
	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("temporary_node_failure", 100, &nodes, &route, &payment_hash, |msg| {
		// trigger error
		msg.amount_msat -= 1;
	}, |msg| {
		// and tamper returning error message
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], NODE|2, &[0;0]);
	}, ||{}, true, Some(NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.paths[0][0].pubkey, is_permanent: false}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("temporary_node_failure", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		// and tamper returning error message
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], NODE|2, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash, &None);
	}, true, Some(NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.paths[0][1].pubkey, is_permanent: false}));

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("permanent_node_failure", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|NODE|2, &[0;0]);
	}, ||{}, true, Some(PERM|NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.paths[0][0].pubkey, is_permanent: true}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("permanent_node_failure", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], PERM|NODE|2, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash, &None);
	}, false, Some(PERM|NODE|2), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.paths[0][1].pubkey, is_permanent: true}));

	// intermediate node failure
	run_onion_failure_test_with_fail_intercept("required_node_feature_missing", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|NODE|3, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash, &None);
	}, true, Some(PERM|NODE|3), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.paths[0][0].pubkey, is_permanent: true}));

	// final node failure
	run_onion_failure_test_with_fail_intercept("required_node_feature_missing", 200, &nodes, &route, &payment_hash, |_msg| {}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[1].shared_secret[..], PERM|NODE|3, &[0;0]);
	}, ||{
		nodes[2].node.fail_htlc_backwards(&payment_hash, &None);
	}, false, Some(PERM|NODE|3), Some(msgs::HTLCFailChannelUpdate::NodeFailure{node_id: route.paths[0][1].pubkey, is_permanent: true}));

	run_onion_failure_test("invalid_onion_version", 0, &nodes, &route, &payment_hash, |msg| { msg.onion_routing_packet.version = 1; }, ||{}, true,
		Some(BADONION|PERM|4), None);

	run_onion_failure_test("invalid_onion_hmac", 0, &nodes, &route, &payment_hash, |msg| { msg.onion_routing_packet.hmac = [3; 32]; }, ||{}, true,
		Some(BADONION|PERM|5), None);

	run_onion_failure_test("invalid_onion_key", 0, &nodes, &route, &payment_hash, |msg| { msg.onion_routing_packet.public_key = Err(secp256k1::Error::InvalidPublicKey);}, ||{}, true,
		Some(BADONION|PERM|6), None);

	run_onion_failure_test_with_fail_intercept("temporary_channel_failure", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], UPDATE|7, &ChannelUpdate::dummy().encode_with_len()[..]);
	}, ||{}, true, Some(UPDATE|7), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));

	run_onion_failure_test_with_fail_intercept("permanent_channel_failure", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|8, &[0;0]);
		// short_channel_id from the processing node
	}, ||{}, true, Some(PERM|8), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));

	run_onion_failure_test_with_fail_intercept("required_channel_feature_missing", 100, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		msg.reason = onion_utils::build_first_hop_failure_packet(&onion_keys[0].shared_secret[..], PERM|9, &[0;0]);
		// short_channel_id from the processing node
	}, ||{}, true, Some(PERM|9), Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: channels[1].0.contents.short_channel_id, is_permanent: true}));

	let mut bogus_route = route.clone();
	bogus_route.paths[0][1].short_channel_id -= 1;
	run_onion_failure_test("unknown_next_peer", 0, &nodes, &bogus_route, &payment_hash, |_| {}, ||{}, true, Some(PERM|10),
	  Some(msgs::HTLCFailChannelUpdate::ChannelClosed{short_channel_id: bogus_route.paths[0][1].short_channel_id, is_permanent:true}));

	let amt_to_forward = nodes[1].node.channel_state.lock().unwrap().by_id.get(&channels[1].2).unwrap().get_counterparty_htlc_minimum_msat() - 1;
	let mut bogus_route = route.clone();
	let route_len = bogus_route.paths[0].len();
	bogus_route.paths[0][route_len-1].fee_msat = amt_to_forward;
	run_onion_failure_test("amount_below_minimum", 0, &nodes, &bogus_route, &payment_hash, |_| {}, ||{}, true, Some(UPDATE|11), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));

	// Test a positive test-case with one extra msat, meeting the minimum.
	bogus_route.paths[0][route_len-1].fee_msat = amt_to_forward + 1;
	let (preimage, _) = send_along_route(&nodes[0], bogus_route, &[&nodes[1], &nodes[2]], amt_to_forward+1);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], preimage, amt_to_forward+1);

	//TODO: with new config API, we will be able to generate both valid and
	//invalid channel_update cases.
	run_onion_failure_test("fee_insufficient", 0, &nodes, &route, &payment_hash, |msg| {
		msg.amount_msat -= 1;
	}, || {}, true, Some(UPDATE|12), Some(msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id: channels[0].0.contents.short_channel_id, is_permanent: true}));

	run_onion_failure_test("incorrect_cltv_expiry", 0, &nodes, &route, &payment_hash, |msg| {
		// need to violate: cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value
		msg.cltv_expiry -= 1;
	}, || {}, true, Some(UPDATE|13), Some(msgs::HTLCFailChannelUpdate::ChannelClosed { short_channel_id: channels[0].0.contents.short_channel_id, is_permanent: true}));

	run_onion_failure_test("expiry_too_soon", 0, &nodes, &route, &payment_hash, |msg| {
		let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS + 1;
		let block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};

		connect_block(&nodes[1], &block, height);
	}, ||{}, true, Some(UPDATE|14), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));

	run_onion_failure_test("unknown_payment_hash", 2, &nodes, &route, &payment_hash, |_| {}, || {
		nodes[2].node.fail_htlc_backwards(&payment_hash, &None);
	}, false, Some(PERM|15), None);

	run_onion_failure_test("final_expiry_too_soon", 1, &nodes, &route, &payment_hash, |msg| {
		let height = msg.cltv_expiry - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS + 1;
		let block = Block {
			header: BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 },
			txdata: vec![],
		};

		connect_block(&nodes[2], &block, height);
	}, || {}, true, Some(17), None);

	run_onion_failure_test("final_incorrect_cltv_expiry", 1, &nodes, &route, &payment_hash, |_| {}, || {
		for (_, pending_forwards) in nodes[1].node.channel_state.lock().unwrap().forward_htlcs.iter_mut() {
			for f in pending_forwards.iter_mut() {
				match f {
					&mut HTLCForwardInfo::AddHTLC { ref mut forward_info, .. } =>
						forward_info.outgoing_cltv_value += 1,
					_ => {},
				}
			}
		}
	}, true, Some(18), None);

	run_onion_failure_test("final_incorrect_htlc_amount", 1, &nodes, &route, &payment_hash, |_| {}, || {
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
	}, true, Some(19), None);

	run_onion_failure_test("channel_disabled", 0, &nodes, &route, &payment_hash, |_| {}, || {
		// disconnect event to the channel between nodes[1] ~ nodes[2]
		nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), false);
		nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	}, true, Some(UPDATE|20), Some(msgs::HTLCFailChannelUpdate::ChannelUpdateMessage{msg: ChannelUpdate::dummy()}));
	reconnect_nodes(&nodes[1], &nodes[2], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	run_onion_failure_test("expiry_too_far", 0, &nodes, &route, &payment_hash, |msg| {
		let session_priv = SecretKey::from_slice(&[3; 32]).unwrap();
		let mut route = route.clone();
		let height = 1;
		route.paths[0][1].cltv_expiry_delta += CLTV_FAR_FAR_AWAY + route.paths[0][0].cltv_expiry_delta + 1;
		let onion_keys = onion_utils::construct_onion_keys(&Secp256k1::new(), &route.paths[0], &session_priv).unwrap();
		let (onion_payloads, _, htlc_cltv) = onion_utils::build_onion_payloads(&route.paths[0], 40000, &None, height).unwrap();
		let onion_packet = onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash);
		msg.cltv_expiry = htlc_cltv;
		msg.onion_routing_packet = onion_packet;
	}, ||{}, true, Some(21), None);
}


