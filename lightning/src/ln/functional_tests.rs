// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test standing up a network of ChannelManagers, creating channels, sending
//! payments/messages between them, and often checking the resulting ChannelMonitors are able to
//! claim outputs on-chain.

use crate::chain;
use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use crate::chain::channelmonitor;
use crate::chain::channelmonitor::{
	Balance, ANTI_REORG_DELAY, CLTV_CLAIM_BUFFER, COUNTERPARTY_CLAIMABLE_WITHIN_BLOCKS_PINNABLE,
	LATENCY_GRACE_PERIOD_BLOCKS,
};
use crate::chain::transaction::OutPoint;
use crate::chain::{ChannelMonitorUpdateStatus, Confirm, Listen, Watch};
use crate::events::{
	ClosureReason, Event, HTLCHandlingFailureType, PathFailure, PaymentFailureReason,
	PaymentPurpose,
};
use crate::ln::chan_utils::{
	commitment_tx_base_weight, second_stage_tx_fees_sat, COMMITMENT_TX_WEIGHT_PER_HTLC,
	OFFERED_HTLC_SCRIPT_WEIGHT,
};
use crate::ln::channel::{
	get_holder_selected_channel_reserve_satoshis, Channel, DISCONNECT_PEER_AWAITING_RESPONSE_TICKS,
	MIN_CHAN_DUST_LIMIT_SATOSHIS, UNFUNDED_CHANNEL_AGE_LIMIT_TICKS,
};
use crate::ln::channelmanager::{
	PaymentId, RAACommitmentOrder, RecipientOnionFields, BREAKDOWN_TIMEOUT, DISABLE_GOSSIP_TICKS,
	ENABLE_GOSSIP_TICKS, MIN_CLTV_EXPIRY_DELTA,
};
use crate::ln::msgs;
use crate::ln::msgs::{
	BaseMessageHandler, ChannelMessageHandler, ErrorAction, MessageSendEvent, RoutingMessageHandler,
};
use crate::ln::onion_utils::LocalHTLCFailureReason;
use crate::ln::types::ChannelId;
use crate::ln::{chan_utils, onion_utils};
use crate::routing::gossip::{NetworkGraph, NetworkUpdate};
use crate::routing::router::{
	get_route, Path, PaymentParameters, Route, RouteHop, RouteParameters,
};
use crate::sign::{EntropySource, OutputSpender, SignerProvider};
use crate::types::features::{ChannelFeatures, ChannelTypeFeatures, NodeFeatures};
use crate::types::payment::{PaymentHash, PaymentSecret};
use crate::types::string::UntrustedString;
use crate::util::config::{ChannelConfigUpdate, MaxDustHTLCExposure, UserConfig};
use crate::util::errors::APIError;
use crate::util::ser::{ReadableArgs, Writeable};
use crate::util::test_channel_signer::TestChannelSigner;
use crate::util::test_utils::{self, WatchtowerPersister};

use bitcoin::hash_types::BlockHash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::network::Network;
use bitcoin::opcodes;
use bitcoin::script::Builder;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};

use crate::io;
use crate::prelude::*;
use crate::sync::{Arc, Mutex, RwLock};
use alloc::collections::BTreeSet;
use bitcoin::hashes::Hash;
use core::iter::repeat;
use lightning_macros::xtest;

use crate::ln::functional_test_utils::*;

#[xtest(feature = "_externalize_tests")]
pub fn fake_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that payments get routed and transactions broadcast in semi-reasonable ways.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3);

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], 8000000);

	// Send some more payments
	send_payment(&nodes[1], &[&nodes[2], &nodes[3]], 1000000);
	send_payment(&nodes[3], &[&nodes[2], &nodes[1], &nodes[0]], 1000000);
	send_payment(&nodes[3], &[&nodes[2], &nodes[1]], 1000000);

	// Test failure packets
	let payment_hash_1 = route_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], 1000000).1;
	fail_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], payment_hash_1);

	// Add a new channel that skips 3
	let chan_4 = create_announced_chan_between_nodes(&nodes, 1, 3);

	send_payment(&nodes[0], &[&nodes[1], &nodes[3]], 1000000);
	send_payment(&nodes[2], &[&nodes[3]], 1000000);
	send_payment(&nodes[1], &[&nodes[3]], 8000000);
	send_payment(&nodes[1], &[&nodes[3]], 8000000);
	send_payment(&nodes[1], &[&nodes[3]], 8000000);
	send_payment(&nodes[1], &[&nodes[3]], 8000000);
	send_payment(&nodes[1], &[&nodes[3]], 8000000);

	// Do some rebalance loop payments, simultaneously
	let mut hops = vec![
		RouteHop {
			pubkey: node_c_id,
			node_features: NodeFeatures::empty(),
			short_channel_id: chan_2.0.contents.short_channel_id,
			channel_features: ChannelFeatures::empty(),
			fee_msat: 0,
			cltv_expiry_delta: chan_3.0.contents.cltv_expiry_delta as u32,
			maybe_announced_channel: true,
		},
		RouteHop {
			pubkey: node_d_id,
			node_features: NodeFeatures::empty(),
			short_channel_id: chan_3.0.contents.short_channel_id,
			channel_features: ChannelFeatures::empty(),
			fee_msat: 0,
			cltv_expiry_delta: chan_4.1.contents.cltv_expiry_delta as u32,
			maybe_announced_channel: true,
		},
		RouteHop {
			pubkey: node_b_id,
			node_features: nodes[1].node.node_features(),
			short_channel_id: chan_4.0.contents.short_channel_id,
			channel_features: nodes[1].node.channel_features(),
			fee_msat: 1000000,
			cltv_expiry_delta: TEST_FINAL_CLTV,
			maybe_announced_channel: true,
		},
	];
	hops[1].fee_msat = chan_4.1.contents.fee_base_msat as u64
		+ chan_4.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
	hops[0].fee_msat = chan_3.0.contents.fee_base_msat as u64
		+ chan_3.0.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, 1000000);
	let route = Route {
		paths: vec![Path { hops, blinded_tail: None }],
		route_params: Some(route_params.clone()),
	};
	let path: &[_] = &[&nodes[2], &nodes[3], &nodes[1]];
	let payment_preimage_1 = send_along_route(&nodes[1], route, path, 1000000).0;

	let mut hops = vec![
		RouteHop {
			pubkey: node_d_id,
			node_features: NodeFeatures::empty(),
			short_channel_id: chan_4.0.contents.short_channel_id,
			channel_features: ChannelFeatures::empty(),
			fee_msat: 0,
			cltv_expiry_delta: chan_3.1.contents.cltv_expiry_delta as u32,
			maybe_announced_channel: true,
		},
		RouteHop {
			pubkey: node_c_id,
			node_features: NodeFeatures::empty(),
			short_channel_id: chan_3.0.contents.short_channel_id,
			channel_features: ChannelFeatures::empty(),
			fee_msat: 0,
			cltv_expiry_delta: chan_2.1.contents.cltv_expiry_delta as u32,
			maybe_announced_channel: true,
		},
		RouteHop {
			pubkey: node_b_id,
			node_features: nodes[1].node.node_features(),
			short_channel_id: chan_2.0.contents.short_channel_id,
			channel_features: nodes[1].node.channel_features(),
			fee_msat: 1000000,
			cltv_expiry_delta: TEST_FINAL_CLTV,
			maybe_announced_channel: true,
		},
	];
	hops[1].fee_msat = chan_2.1.contents.fee_base_msat as u64
		+ chan_2.1.contents.fee_proportional_millionths as u64 * hops[2].fee_msat as u64 / 1000000;
	hops[0].fee_msat = chan_3.1.contents.fee_base_msat as u64
		+ chan_3.1.contents.fee_proportional_millionths as u64 * hops[1].fee_msat as u64 / 1000000;
	let route =
		Route { paths: vec![Path { hops, blinded_tail: None }], route_params: Some(route_params) };
	let path: &[_] = &[&nodes[3], &nodes[2], &nodes[1]];
	let payment_hash_2 = send_along_route(&nodes[1], route, path, 1000000).1;

	// Claim the rebalances...
	fail_payment(&nodes[1], &[&nodes[3], &nodes[2], &nodes[1]], payment_hash_2);
	claim_payment(&nodes[1], &[&nodes[2], &nodes[3], &nodes[1]], payment_preimage_1);

	// Close down the channels...
	close_channel(&nodes[0], &nodes[1], &chan_1.2, chan_1.3, true);
	let node_a_reason = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, node_a_reason, &[node_b_id], 100000);
	let node_b_reason = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, node_b_reason, &[node_a_id], 100000);

	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, false);
	let node_b_reason = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, node_b_reason, &[node_c_id], 100000);
	let node_c_reason = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[2], 1, node_c_reason, &[node_b_id], 100000);

	close_channel(&nodes[2], &nodes[3], &chan_3.2, chan_3.3, true);
	let node_c_reason = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[2], 1, node_c_reason, &[node_d_id], 100000);
	let node_d_reason = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[3], 1, node_d_reason, &[node_c_id], 100000);

	close_channel(&nodes[1], &nodes[3], &chan_4.2, chan_4.3, false);
	let node_b_reason = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, node_b_reason, &[node_d_id], 100000);
	let node_d_reason = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[3], 1, node_d_reason, &[node_b_id], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn duplicate_htlc_test() {
	// Test that we accept duplicate payment_hash HTLCs across the network and that
	// claiming/failing them are all separate and don't affect each other
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs, &[None, None, None, None, None, None]);
	let mut nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	// Create some initial channels to route via 3 to 4/5 from 0/1/2
	create_announced_chan_between_nodes(&nodes, 0, 3);
	create_announced_chan_between_nodes(&nodes, 1, 3);
	create_announced_chan_between_nodes(&nodes, 2, 3);
	create_announced_chan_between_nodes(&nodes, 3, 4);
	create_announced_chan_between_nodes(&nodes, 3, 5);

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[3], &nodes[4]], 1000000);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[1], &[&nodes[3]], 1000000).0, payment_preimage);

	*nodes[0].network_payment_count.borrow_mut() -= 1;
	assert_eq!(route_payment(&nodes[2], &[&nodes[3], &nodes[5]], 1000000).0, payment_preimage);

	claim_payment(&nodes[0], &[&nodes[3], &nodes[4]], payment_preimage);
	fail_payment(&nodes[2], &[&nodes[3], &nodes[5]], payment_hash);
	claim_payment(&nodes[1], &[&nodes[3]], payment_preimage);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_duplicate_htlc_different_direction_onchain() {
	// Test that ChannelMonitor doesn't generate 2 preimage txn
	// when we have 2 HTLCs with same preimage that go across a node
	// in opposite directions, even with the same payment secret.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// post-bump fee (288 satoshis) + dust threshold for output type (294 satoshis) = 582
	let payment_value_sats = 582;
	let payment_value_msats = payment_value_sats * 1000;

	// balancing
	send_payment(&nodes[0], &[&nodes[1]], 8000000);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 900_000);

	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[0], payment_value_msats);
	let node_a_payment_secret =
		nodes[0].node.create_inbound_payment_for_hash(payment_hash, None, 7200, None).unwrap();
	send_along_route_with_secret(
		&nodes[1],
		route,
		&[&[&nodes[0]]],
		payment_value_msats,
		payment_hash,
		node_a_payment_secret,
	);

	// Provide preimage to node 0 by claiming payment
	nodes[0].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[0], payment_hash, payment_value_msats);
	check_added_monitors(&nodes[0], 1);

	// Broadcast node 1 commitment txn
	let remote_txn = get_local_commitment_txn!(nodes[1], chan_1.2);

	assert_eq!(remote_txn[0].output.len(), 4); // 1 local, 1 remote, 1 htlc inbound, 1 htlc outbound
	let mut has_both_htlcs = 0; // check htlcs match ones committed
	for outp in remote_txn[0].output.iter() {
		if outp.value.to_sat() == payment_value_sats {
			has_both_htlcs += 1;
		} else if outp.value.to_sat() == 900_000 / 1000 {
			has_both_htlcs += 1;
		}
	}
	assert_eq!(has_both_htlcs, 2);

	mine_transaction(&nodes[0], &remote_txn[0]);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 3);
	for e in events {
		match e {
			MessageSendEvent::BroadcastChannelUpdate { .. } => {},
			MessageSendEvent::HandleError {
				node_id,
				action: msgs::ErrorAction::SendErrorMessage { ref msg },
			} => {
				assert_eq!(node_id, node_b_id);
				assert_eq!(msg.data, "Channel closed because commitment or closing transaction was confirmed on chain.");
			},
			MessageSendEvent::UpdateHTLCs {
				ref node_id,
				updates:
					msgs::CommitmentUpdate {
						ref update_add_htlcs,
						ref update_fulfill_htlcs,
						ref update_fail_htlcs,
						ref update_fail_malformed_htlcs,
						..
					},
				..
			} => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert_eq!(update_fulfill_htlcs.len(), 1);
				assert!(update_fail_malformed_htlcs.is_empty());
				assert_eq!(node_b_id, *node_id);
			},
			_ => panic!("Unexpected event"),
		}
	}
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	let claim_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(claim_txn.len(), 3);

	check_spends!(claim_txn[0], remote_txn[0]); // Immediate HTLC claim with preimage
	check_spends!(claim_txn[1], remote_txn[0]);
	check_spends!(claim_txn[2], remote_txn[0]);
	let preimage_tx = &claim_txn[0];
	let timeout_tx = claim_txn
		.iter()
		.skip(1)
		.find(|t| t.input[0].previous_output != preimage_tx.input[0].previous_output)
		.unwrap();
	let preimage_bump_tx = claim_txn
		.iter()
		.skip(1)
		.find(|t| t.input[0].previous_output == preimage_tx.input[0].previous_output)
		.unwrap();

	assert_eq!(preimage_tx.input.len(), 1);
	assert_eq!(preimage_bump_tx.input.len(), 1);

	assert_eq!(preimage_tx.input.len(), 1);
	assert_eq!(preimage_tx.input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT); // HTLC 1 <--> 0, preimage tx
	assert_eq!(
		remote_txn[0].output[preimage_tx.input[0].previous_output.vout as usize].value.to_sat(),
		payment_value_sats
	);

	assert_eq!(timeout_tx.input.len(), 1);
	assert_eq!(timeout_tx.input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // HTLC 0 <--> 1, timeout tx
	check_spends!(timeout_tx, remote_txn[0]);
	assert_eq!(
		remote_txn[0].output[timeout_tx.input[0].previous_output.vout as usize].value.to_sat(),
		900
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_inbound_outbound_capacity_is_not_zero() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let _ = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);
	let channels0 = node_chanmgrs[0].list_channels();
	let channels1 = node_chanmgrs[1].list_channels();
	let default_config = UserConfig::default();
	assert_eq!(channels0.len(), 1);
	assert_eq!(channels1.len(), 1);

	let reserve = get_holder_selected_channel_reserve_satoshis(100_000, &default_config);
	assert_eq!(channels0[0].inbound_capacity_msat, 95000000 - reserve * 1000);
	assert_eq!(channels1[0].outbound_capacity_msat, 95000000 - reserve * 1000);

	assert_eq!(channels0[0].outbound_capacity_msat, 100000 * 1000 - 95000000 - reserve * 1000);
	assert_eq!(channels1[0].inbound_capacity_msat, 100000 * 1000 - 95000000 - reserve * 1000);
}

enum PostFailBackAction {
	TimeoutOnChain,
	ClaimOnChain,
	FailOffChain,
	ClaimOffChain,
}

#[test]
fn test_fail_back_before_backwards_timeout() {
	do_test_fail_back_before_backwards_timeout(PostFailBackAction::TimeoutOnChain);
	do_test_fail_back_before_backwards_timeout(PostFailBackAction::ClaimOnChain);
	do_test_fail_back_before_backwards_timeout(PostFailBackAction::FailOffChain);
	do_test_fail_back_before_backwards_timeout(PostFailBackAction::ClaimOffChain);
}

fn do_test_fail_back_before_backwards_timeout(post_fail_back_action: PostFailBackAction) {
	// Test that we fail an HTLC upstream if we are still waiting for confirmation downstream
	// just before the upstream timeout expires
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	for node in nodes.iter() {
		*node.fee_estimator.sat_per_kw.lock().unwrap() = 2000;
	}

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Start every node on the same block height to make reasoning about timeouts easier
	connect_blocks(&nodes[0], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);

	// Force close the B<->C channel by timing out the HTLC
	let timeout_blocks = TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1;
	connect_blocks(&nodes[1], timeout_blocks);
	let node_1_txn = test_txn_broadcast(&nodes[1], &chan_2, None, HTLCType::TIMEOUT);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
	check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100_000);
	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);

	// After the A<->B HTLC gets within LATENCY_GRACE_PERIOD_BLOCKS we will fail the HTLC to avoid
	// the channel force-closing. Note that we already connected `TEST_FINAL_CLTV +
	// LATENCY_GRACE_PERIOD_BLOCKS` blocks above, so we subtract that from the HTLC expiry (which
	// is `TEST_FINAL_CLTV` + `MIN_CLTV_EXPIRY_DELTA`).
	let upstream_timeout_blocks = MIN_CLTV_EXPIRY_DELTA as u32 - LATENCY_GRACE_PERIOD_BLOCKS * 2;
	connect_blocks(&nodes[1], upstream_timeout_blocks);

	// Connect blocks for nodes[0] to make sure they don't go on-chain
	connect_blocks(&nodes[0], timeout_blocks + upstream_timeout_blocks);

	// Check that nodes[1] fails the HTLC upstream
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }],
	);
	check_added_monitors(&nodes[1], 1);
	let htlc_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	let msgs::CommitmentUpdate { update_fail_htlcs, commitment_signed, .. } = htlc_updates;

	nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &commitment_signed, false, false);
	let conditions = PaymentFailedConditions::new().blamed_chan_closed(true);
	expect_payment_failed_conditions(&nodes[0], payment_hash, false, conditions);

	// Make sure we handle possible duplicate fails or extra messages after failing back
	match post_fail_back_action {
		PostFailBackAction::TimeoutOnChain => {
			// Confirm nodes[1]'s claim with timeout, make sure we don't fail upstream again
			mine_transaction(&nodes[1], &node_1_txn[0]); // Commitment
			mine_transaction(&nodes[1], &node_1_txn[1]); // HTLC timeout
			connect_blocks(&nodes[1], ANTI_REORG_DELAY);
			// Expect handling another fail back event, but the HTLC is already gone
			expect_and_process_pending_htlcs_and_htlc_handling_failed(
				&nodes[1],
				&[HTLCHandlingFailureType::Forward {
					node_id: Some(node_c_id),
					channel_id: chan_2.2,
				}],
			);
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		},
		PostFailBackAction::ClaimOnChain => {
			nodes[2].node.claim_funds(payment_preimage);
			expect_payment_claimed!(nodes[2], payment_hash, 3_000_000);
			check_added_monitors(&nodes[2], 1);
			get_htlc_update_msgs(&nodes[2], &node_b_id);

			connect_blocks(&nodes[2], TEST_FINAL_CLTV - CLTV_CLAIM_BUFFER + 2);
			let node_2_txn = test_txn_broadcast(&nodes[2], &chan_2, None, HTLCType::SUCCESS);
			check_closed_broadcast!(nodes[2], true);
			let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
			check_closed_event(&nodes[2], 1, reason, &[node_b_id], 100_000);
			check_added_monitors(&nodes[2], 1);

			mine_transaction(&nodes[1], &node_2_txn[0]); // Commitment
			mine_transaction(&nodes[1], &node_2_txn[1]); // HTLC success
			connect_blocks(&nodes[1], ANTI_REORG_DELAY);
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		},
		PostFailBackAction::FailOffChain => {
			nodes[2].node.fail_htlc_backwards(&payment_hash);
			expect_and_process_pending_htlcs_and_htlc_handling_failed(
				&nodes[2],
				&[HTLCHandlingFailureType::Receive { payment_hash }],
			);
			check_added_monitors(&nodes[2], 1);
			let commitment_update = get_htlc_update_msgs(&nodes[2], &node_b_id);
			let update_fail = commitment_update.update_fail_htlcs[0].clone();

			nodes[1].node.handle_update_fail_htlc(node_c_id, &update_fail);
			let err_msg = get_err_msg(&nodes[1], &node_c_id);
			assert_eq!(err_msg.channel_id, chan_2.2);
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		},
		PostFailBackAction::ClaimOffChain => {
			nodes[2].node.claim_funds(payment_preimage);
			expect_payment_claimed!(nodes[2], payment_hash, 3_000_000);
			check_added_monitors(&nodes[2], 1);
			let mut commitment_update = get_htlc_update_msgs(&nodes[2], &node_b_id);
			let update_fulfill = commitment_update.update_fulfill_htlcs.remove(0);

			nodes[1].node.handle_update_fulfill_htlc(node_c_id, update_fulfill);
			let err_msg = get_err_msg(&nodes[1], &node_c_id);
			assert_eq!(err_msg.channel_id, chan_2.2);
			assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		},
	};
}

#[xtest(feature = "_externalize_tests")]
pub fn channel_monitor_network_test() {
	// Simple test which builds a network of ChannelManagers, connects them to each other, and
	// tests that ChannelMonitor is able to recover from various states.
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &[None, None, None, None, None]);
	let nodes = create_network(5, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();
	let node_e_id = nodes[4].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3);
	let chan_4 = create_announced_chan_between_nodes(&nodes, 3, 4);

	// Make sure all nodes are at the same starting height
	connect_blocks(&nodes[0], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[3].best_block_info().1);
	connect_blocks(&nodes[4], 4 * CHAN_CONFIRM_DEPTH + 1 - nodes[4].best_block_info().1);

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3], &nodes[4]], 8000000);

	// Simple case with no pending HTLCs:
	let message = "Channel force-closed".to_owned();
	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(&chan_1.2, &node_a_id, message.clone())
		.unwrap();
	check_added_monitors(&nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	{
		let mut node_txn = test_txn_broadcast(&nodes[1], &chan_1, None, HTLCType::NONE);
		assert_eq!(node_txn.len(), 1);
		mine_transaction(&nodes[1], &node_txn[0]);
		if nodes[1].connect_style.borrow().updates_best_block_first() {
			let _ = nodes[1].tx_broadcaster.txn_broadcast();
		}

		mine_transaction(&nodes[0], &node_txn[0]);
		check_closed_broadcast(&nodes[0], 1, true);
		check_added_monitors(&nodes[0], 1);
		test_txn_broadcast(&nodes[0], &chan_1, Some(node_txn[0].clone()), HTLCType::NONE);
	}
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);

	// One pending HTLC is discarded by the force-close:
	let (payment_preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[1], &[&nodes[2], &nodes[3]], 3_000_000);

	// Simple case of one pending HTLC to HTLC-Timeout (note that the HTLC-Timeout is not
	// broadcasted until we reach the timelock time).
	let message = "Channel force-closed".to_owned();
	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(&chan_2.2, &node_c_id, message.clone())
		.unwrap();
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	{
		let mut node_txn = test_txn_broadcast(&nodes[1], &chan_2, None, HTLCType::NONE);
		connect_blocks(
			&nodes[1],
			TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + MIN_CLTV_EXPIRY_DELTA as u32 + 1,
		);
		test_txn_broadcast(&nodes[1], &chan_2, None, HTLCType::TIMEOUT);
		mine_transaction(&nodes[2], &node_txn[0]);
		check_closed_broadcast(&nodes[2], 1, true);
		check_added_monitors(&nodes[2], 1);
		test_txn_broadcast(&nodes[2], &chan_2, Some(node_txn[0].clone()), HTLCType::NONE);
	}
	assert_eq!(nodes[1].node.list_channels().len(), 0);
	assert_eq!(nodes[2].node.list_channels().len(), 1);
	let node_b_reason =
		ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[1], 1, node_b_reason, &[node_c_id], 100000);
	let node_c_reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[2], 1, node_c_reason, &[node_b_id], 100000);

	macro_rules! claim_funds {
		($node: expr, $prev_node: expr, $preimage: expr, $payment_hash: expr) => {{
			$node.node.claim_funds($preimage);
			expect_payment_claimed!($node, $payment_hash, 3_000_000);
			check_added_monitors(&$node, 1);

			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::UpdateHTLCs {
					ref node_id,
					channel_id: _,
					updates:
						msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fail_htlcs, .. },
				} => {
					assert!(update_add_htlcs.is_empty());
					assert!(update_fail_htlcs.is_empty());
					assert_eq!(*node_id, $prev_node.node.get_our_node_id());
				},
				_ => panic!("Unexpected event"),
			};
		}};
	}

	// nodes[3] gets the preimage, but nodes[2] already disconnected, resulting in a nodes[2]
	// HTLC-Timeout and a nodes[3] claim against it (+ its own announces)
	let message = "Channel force-closed".to_owned();
	nodes[2]
		.node
		.force_close_broadcasting_latest_txn(&chan_3.2, &node_d_id, message.clone())
		.unwrap();
	check_added_monitors(&nodes[2], 1);
	check_closed_broadcast!(nodes[2], true);
	let node2_commitment_txid;
	{
		let node_txn = test_txn_broadcast(&nodes[2], &chan_3, None, HTLCType::NONE);
		connect_blocks(&nodes[2], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS);
		test_txn_broadcast(&nodes[2], &chan_3, None, HTLCType::TIMEOUT);
		node2_commitment_txid = node_txn[0].compute_txid();

		// Claim the payment on nodes[3], giving it knowledge of the preimage
		claim_funds!(nodes[3], nodes[2], payment_preimage_1, payment_hash_1);
		mine_transaction(&nodes[3], &node_txn[0]);
		check_closed_broadcast(&nodes[3], 1, true);
		check_added_monitors(&nodes[3], 1);
		check_preimage_claim(&nodes[3], &node_txn);
	}
	assert_eq!(nodes[2].node.list_channels().len(), 0);
	assert_eq!(nodes[3].node.list_channels().len(), 1);
	let node_c_reason =
		ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[2], 1, node_c_reason, &[node_d_id], 100000);
	let node_d_reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[3], 1, node_d_reason, &[node_c_id], 100000);

	// Drop the ChannelMonitor for the previous channel to avoid it broadcasting transactions and
	// confusing us in the following tests.
	let chan_3_mon = nodes[3].chain_monitor.chain_monitor.remove_monitor(&chan_3.2);

	// One pending HTLC to time out:
	let (payment_preimage_2, payment_hash_2, ..) =
		route_payment(&nodes[3], &[&nodes[4]], 3_000_000);
	// CLTV expires at TEST_FINAL_CLTV + 1 (current height) + 1 (added in send_payment for
	// buffer space).

	let (close_chan_update_1, close_chan_update_2) = {
		connect_blocks(&nodes[3], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
		let events = nodes[3].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		let close_chan_update_1 = match events[1] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg, .. } => msg.clone(),
			_ => panic!("Unexpected event"),
		};
		match events[0] {
			MessageSendEvent::HandleError {
				action: ErrorAction::SendErrorMessage { .. },
				node_id,
			} => {
				assert_eq!(node_id, node_e_id);
			},
			_ => panic!("Unexpected event"),
		}
		check_added_monitors(&nodes[3], 1);

		// Clear bumped claiming txn spending node 2 commitment tx. Bumped txn are generated after reaching some height timer.
		{
			let mut node_txn = nodes[3].tx_broadcaster.txn_broadcasted.lock().unwrap();
			node_txn.retain(|tx| {
				if tx.input[0].previous_output.txid == node2_commitment_txid {
					false
				} else {
					true
				}
			});
		}

		let node_txn = test_txn_broadcast(&nodes[3], &chan_4, None, HTLCType::TIMEOUT);

		// Claim the payment on nodes[4], giving it knowledge of the preimage
		claim_funds!(nodes[4], nodes[3], payment_preimage_2, payment_hash_2);

		connect_blocks(&nodes[4], TEST_FINAL_CLTV - CLTV_CLAIM_BUFFER + 2);
		let events = nodes[4].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		let close_chan_update_2 = match events[1] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg, .. } => msg.clone(),
			_ => panic!("Unexpected event"),
		};
		match events[0] {
			MessageSendEvent::HandleError {
				action: ErrorAction::SendErrorMessage { .. },
				node_id,
			} => {
				assert_eq!(node_id, node_d_id);
			},
			_ => panic!("Unexpected event"),
		}
		check_added_monitors(&nodes[4], 1);
		test_txn_broadcast(&nodes[4], &chan_4, None, HTLCType::SUCCESS);
		let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash_2) };
		check_closed_event(&nodes[4], 1, reason, &[node_d_id], 100000);

		mine_transaction(&nodes[4], &node_txn[0]);
		check_preimage_claim(&nodes[4], &node_txn);
		(close_chan_update_1, close_chan_update_2)
	};
	let node_id_4 = node_e_id;
	let node_id_3 = node_d_id;
	nodes[3].gossip_sync.handle_channel_update(Some(node_id_4), &close_chan_update_2).unwrap();
	nodes[4].gossip_sync.handle_channel_update(Some(node_id_3), &close_chan_update_1).unwrap();
	assert_eq!(nodes[3].node.list_channels().len(), 0);
	assert_eq!(nodes[4].node.list_channels().len(), 0);

	assert_eq!(
		nodes[3].chain_monitor.chain_monitor.watch_channel(chan_3.2, chan_3_mon),
		Ok(ChannelMonitorUpdateStatus::Completed)
	);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash_2) };
	check_closed_event(&nodes[3], 1, reason, &[node_id_4], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_justice_tx_htlc_timeout() {
	// Test justice txn built on revoked HTLC-Timeout tx, against both sides
	let mut alice_config = test_default_channel_config();
	alice_config.channel_handshake_config.announce_for_forwarding = true;
	alice_config.channel_handshake_limits.force_announced_channel_preference = false;
	alice_config.channel_handshake_config.our_to_self_delay = 6 * 24 * 5;
	let mut bob_config = test_default_channel_config();
	bob_config.channel_handshake_config.announce_for_forwarding = true;
	bob_config.channel_handshake_limits.force_announced_channel_preference = false;
	bob_config.channel_handshake_config.our_to_self_delay = 6 * 24 * 3;
	let user_cfgs = [Some(alice_config), Some(bob_config)];
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;

	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some new channels:
	let chan_5 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// A pending HTLC which will be revoked:
	let payment_preimage_3 = route_payment(&nodes[0], &[&nodes[1]], 3000000).0;
	// Get the will-be-revoked local txn from nodes[0]
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_5.2);
	assert_eq!(revoked_local_txn.len(), 2); // First commitment tx, then HTLC tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_5.3.compute_txid());
	assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to 0 are present
	assert_eq!(revoked_local_txn[1].input.len(), 1);
	assert_eq!(
		revoked_local_txn[1].input[0].previous_output.txid,
		revoked_local_txn[0].compute_txid()
	);
	assert_eq!(
		revoked_local_txn[1].input[0].witness.last().unwrap().len(),
		OFFERED_HTLC_SCRIPT_WEIGHT
	); // HTLC-Timeout
   // Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_3);

	{
		mine_transaction(&nodes[1], &revoked_local_txn[0]);
		{
			let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
			// The revoked HTLC output is not pinnable for another `TEST_FINAL_CLTV` blocks, and is
			// thus claimed in the same transaction with the revoked to_self output.
			assert_eq!(node_txn.len(), 1);
			assert_eq!(node_txn[0].input.len(), 2);
			check_spends!(node_txn[0], revoked_local_txn[0]);
			assert_ne!(node_txn[0].input[0].previous_output, node_txn[0].input[1].previous_output);
			node_txn.clear();
		}
		let reason = ClosureReason::CommitmentTxConfirmed;
		check_closed_event(&nodes[1], 1, reason.clone(), &[node_a_id], 100000);
		check_added_monitors(&nodes[1], 1);
		test_txn_broadcast(&nodes[1], &chan_5, Some(revoked_local_txn[0].clone()), HTLCType::NONE);

		mine_transaction(&nodes[0], &revoked_local_txn[0]);
		connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

		// Verify broadcast of revoked HTLC-timeout
		let node_txn = test_txn_broadcast(
			&nodes[0],
			&chan_5,
			Some(revoked_local_txn[0].clone()),
			HTLCType::TIMEOUT,
		);
		check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
		check_added_monitors(&nodes[0], 1);
		// Broadcast revoked HTLC-timeout on node 1
		mine_transaction(&nodes[1], &node_txn[1]);
		test_revoked_htlc_claim_txn_broadcast(
			&nodes[1],
			node_txn[1].clone(),
			revoked_local_txn[0].clone(),
		);
	}
	get_announce_close_broadcast_events(&nodes, 0, 1);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_justice_tx_htlc_success() {
	// Test justice txn built on revoked HTLC-Success tx, against both sides
	let mut alice_config = test_default_channel_config();
	alice_config.channel_handshake_config.announce_for_forwarding = true;
	alice_config.channel_handshake_limits.force_announced_channel_preference = false;
	alice_config.channel_handshake_config.our_to_self_delay = 6 * 24 * 5;
	let mut bob_config = test_default_channel_config();
	bob_config.channel_handshake_config.announce_for_forwarding = true;
	bob_config.channel_handshake_limits.force_announced_channel_preference = false;
	bob_config.channel_handshake_config.our_to_self_delay = 6 * 24 * 3;
	let user_cfgs = [Some(alice_config), Some(bob_config)];
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;

	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &user_cfgs);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some new channels:
	let chan_6 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// A pending HTLC which will be revoked:
	let payment_preimage_4 = route_payment(&nodes[0], &[&nodes[1]], 3000000).0;
	// Get the will-be-revoked local txn from B
	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan_6.2);
	assert_eq!(revoked_local_txn.len(), 1); // Only commitment tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_6.3.compute_txid());
	assert_eq!(revoked_local_txn[0].output.len(), 2); // Only HTLC and output back to A are present

	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_4);
	{
		mine_transaction(&nodes[0], &revoked_local_txn[0]);
		{
			let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
			assert_eq!(node_txn.len(), 1); // ChannelMonitor: penalty tx
			assert_eq!(node_txn[0].input.len(), 1); // We claim the received HTLC output

			check_spends!(node_txn[0], revoked_local_txn[0]);
			node_txn.swap_remove(0);
		}
		check_closed_broadcast(&nodes[0], 1, true);
		check_added_monitors(&nodes[0], 1);
		test_txn_broadcast(&nodes[0], &chan_6, Some(revoked_local_txn[0].clone()), HTLCType::NONE);

		mine_transaction(&nodes[1], &revoked_local_txn[0]);
		check_closed_broadcast(&nodes[1], 1, true);
		let reason = ClosureReason::CommitmentTxConfirmed;
		check_closed_event(&nodes[1], 1, reason.clone(), &[node_a_id], 100000);
		let node_txn = test_txn_broadcast(
			&nodes[1],
			&chan_6,
			Some(revoked_local_txn[0].clone()),
			HTLCType::SUCCESS,
		);
		check_added_monitors(&nodes[1], 1);
		mine_transaction(&nodes[0], &node_txn[1]);
		check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
		test_revoked_htlc_claim_txn_broadcast(
			&nodes[0],
			node_txn[1].clone(),
			revoked_local_txn[0].clone(),
		);
	}
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

#[xtest(feature = "_externalize_tests")]
pub fn revoked_output_claim() {
	// Simple test to ensure a node will claim a revoked output when a stale remote commitment
	// transaction is broadcast by its counterparty
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn.len(), 1);
	// Only output is the full channel value back to nodes[0]:
	assert_eq!(revoked_local_txn[0].output.len(), 1);
	// Send a payment through, updating everyone's latest commitment txn
	send_payment(&nodes[0], &[&nodes[1]], 5000000);

	// Inform nodes[1] that nodes[0] broadcast a stale tx
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason.clone(), &[node_a_id], 100000);
	check_added_monitors(&nodes[1], 1);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 1); // ChannelMonitor: justice tx against revoked to_local output

	check_spends!(node_txn[0], revoked_local_txn[0]);

	// Inform nodes[0] that a watchtower cheated on its behalf, so it will force-close the chan
	mine_transaction(&nodes[0], &revoked_local_txn[0]);
	get_announce_close_broadcast_events(&nodes, 0, 1);
	check_added_monitors(&nodes[0], 1);
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_forming_justice_tx_from_monitor_updates() {
	do_test_forming_justice_tx_from_monitor_updates(true);
	do_test_forming_justice_tx_from_monitor_updates(false);
}

fn do_test_forming_justice_tx_from_monitor_updates(broadcast_initial_commitment: bool) {
	// Simple test to make sure that the justice tx formed in WatchtowerPersister
	// is properly formed and can be broadcasted/confirmed successfully in the event
	// that a revoked commitment transaction is broadcasted
	// (Similar to `revoked_output_claim` test but we get the justice tx + broadcast manually)
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let destination_script0 = chanmon_cfgs[0].keys_manager.get_destination_script([0; 32]).unwrap();
	let destination_script1 = chanmon_cfgs[1].keys_manager.get_destination_script([0; 32]).unwrap();
	let persisters = [
		WatchtowerPersister::new(destination_script0),
		WatchtowerPersister::new(destination_script1),
	];
	let node_cfgs = create_node_cfgs_with_persisters(2, &chanmon_cfgs, persisters.iter().collect());
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	if !broadcast_initial_commitment {
		// Send a payment to move the channel forward
		send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
	}

	// node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output.
	// We'll keep this commitment transaction to broadcast once it's revoked.
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], channel_id);
	assert_eq!(revoked_local_txn.len(), 1);
	let revoked_commitment_tx = &revoked_local_txn[0];

	// Send another payment, now revoking the previous commitment tx
	send_payment(&nodes[0], &[&nodes[1]], 5_000_000);

	let justice_tx =
		persisters[1].justice_tx(channel_id, &revoked_commitment_tx.compute_txid()).unwrap();
	check_spends!(justice_tx, revoked_commitment_tx);

	mine_transactions(&nodes[1], &[revoked_commitment_tx, &justice_tx]);
	mine_transactions(&nodes[0], &[revoked_commitment_tx, &justice_tx]);

	get_announce_close_broadcast_events(&nodes, 1, 0);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100_000);

	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100_000);

	// Check that the justice tx has sent the revoked output value to nodes[1]
	let monitor = get_monitor!(nodes[1], channel_id);
	let total_claimable_balance =
		monitor.get_claimable_balances().iter().fold(0, |sum, balance| match balance {
			channelmonitor::Balance::ClaimableAwaitingConfirmations { amount_satoshis, .. } => {
				sum + amount_satoshis
			},
			_ => panic!("Unexpected balance type"),
		});
	// On the first commitment, node[1]'s balance was below dust so it didn't have an output
	let node1_channel_balance = if broadcast_initial_commitment {
		0
	} else {
		revoked_commitment_tx.output[0].value.to_sat()
	};
	let expected_claimable_balance = node1_channel_balance + justice_tx.output[0].value.to_sat();
	assert_eq!(total_claimable_balance, expected_claimable_balance);
}

#[xtest(feature = "_externalize_tests")]
pub fn claim_htlc_outputs() {
	// Node revoked old state, htlcs haven't time out yet, claim them in shared justice tx
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some new channel:
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &[&nodes[1]], 8_000_000);
	// node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx
	let payment_preimage_1 = route_payment(&nodes[0], &[&nodes[1]], 3_000_000).0;
	let (_payment_preimage_2, payment_hash_2, ..) =
		route_payment(&nodes[1], &[&nodes[0]], 3_000_000);

	// Get the will-be-revoked local txn from node[0]
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn.len(), 2); // commitment tx + 1 HTLC-Timeout tx
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.compute_txid());
	assert_eq!(revoked_local_txn[1].input.len(), 1);
	assert_eq!(
		revoked_local_txn[1].input[0].previous_output.txid,
		revoked_local_txn[0].compute_txid()
	);
	assert_eq!(
		revoked_local_txn[1].input[0].witness.last().unwrap().len(),
		OFFERED_HTLC_SCRIPT_WEIGHT
	); // HTLC-Timeout
	check_spends!(revoked_local_txn[1], revoked_local_txn[0]);

	// Revoke the old state.
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);

	{
		mine_transaction(&nodes[0], &revoked_local_txn[0]);
		check_closed_broadcast(&nodes[0], 1, true);
		check_added_monitors(&nodes[0], 1);
		let reason = ClosureReason::CommitmentTxConfirmed;
		check_closed_event(&nodes[0], 1, reason.clone(), &[node_b_id], 100000);
		mine_transaction(&nodes[1], &revoked_local_txn[0]);
		check_closed_broadcast(&nodes[1], 1, true);
		check_added_monitors(&nodes[1], 1);
		check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
		assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(node_txn.len(), 2); // ChannelMonitor: penalty txn

		// The ChannelMonitor should claim the accepted HTLC output separately from the offered
		// HTLC and to_self outputs.
		let accepted_claim = node_txn.iter().find(|tx| tx.input.len() == 1).unwrap();
		let offered_to_self_claim = node_txn.iter().find(|tx| tx.input.len() == 2).unwrap();
		check_spends!(accepted_claim, revoked_local_txn[0]);
		check_spends!(offered_to_self_claim, revoked_local_txn[0]);
		assert_eq!(
			accepted_claim.input[0].witness.last().unwrap().len(),
			ACCEPTED_HTLC_SCRIPT_WEIGHT
		);

		let mut witness_lens = BTreeSet::new();
		witness_lens.insert(offered_to_self_claim.input[0].witness.last().unwrap().len());
		witness_lens.insert(offered_to_self_claim.input[1].witness.last().unwrap().len());
		assert_eq!(witness_lens.len(), 2);
		assert_eq!(*witness_lens.iter().next().unwrap(), 77); // revoked to_local
		assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), OFFERED_HTLC_SCRIPT_WEIGHT);

		// Finally, mine the penalty transaction and check that we get an HTLC failure after
		// ANTI_REORG_DELAY confirmations.
		mine_transaction(&nodes[1], accepted_claim);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
		let conditions = PaymentFailedConditions::new().from_mon_update();
		expect_payment_failed_conditions(&nodes[1], payment_hash_2, false, conditions);
	}
	assert_eq!(nodes[0].node.list_channels().len(), 0);
	assert_eq!(nodes[1].node.list_channels().len(), 0);
}

pub fn do_test_multiple_package_conflicts(p2a_anchor: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut user_cfg = test_default_channel_config();

	// Anchor channels are required so that multiple HTLC-Successes can be aggregated into a single
	// transaction.
	user_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	user_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = p2a_anchor;
	user_cfg.manually_accept_inbound_channels = true;

	let configs = [Some(user_cfg.clone()), Some(user_cfg.clone()), Some(user_cfg)];
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &configs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let coinbase_tx = provide_anchor_reserves(&nodes);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Create the network.
	//   0 -- 1 -- 2
	//
	// Payments will be routed from node 0 to node 2.  Node 2 will force close and spend HTLCs from
	// two of node 1's packages.  We will then verify that node 1 correctly removes the conflicting
	// HTLC spends from its packages.
	const CHAN_CAPACITY: u64 = 10_000_000;
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, CHAN_CAPACITY, 0);
	let (_, _, cid_1_2, funding_tx_1_2) =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 2, CHAN_CAPACITY, 0);

	// Ensure all nodes are at the same initial height.
	let node_max_height = nodes.iter().map(|node| node.best_block_info().1).max().unwrap();
	for node in &nodes {
		let blocks_to_mine = node_max_height - node.best_block_info().1;
		if blocks_to_mine > 0 {
			connect_blocks(node, blocks_to_mine);
		}
	}

	// Route HTLC 1.
	let (preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);

	// Route HTLCs 2 and 3, with CLTVs 1 higher than HTLC 1.  The higher CLTVs will cause these
	// HTLCs to be included in a different package than HTLC 1.
	connect_blocks(&nodes[0], 1);
	connect_blocks(&nodes[1], 1);
	connect_blocks(&nodes[2], 1);
	let (preimage_2, payment_hash_2, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);
	route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 900_000_000);

	// Mine blocks until HTLC 1 times out in 1 block and HTLCs 2 and 3 time out in 2 blocks.
	connect_blocks(&nodes[1], TEST_FINAL_CLTV - 1);

	// Node 2 force closes, causing node 1 to group the HTLCs into the following packages:
	//   Package 1: HTLC 1
	//   Package 2: HTLCs 2 and 3
	let node2_commit_tx = get_local_commitment_txn!(nodes[2], cid_1_2);
	assert_eq!(node2_commit_tx.len(), 1);
	let node2_commit_tx = &node2_commit_tx[0];
	check_spends!(node2_commit_tx, funding_tx_1_2);
	mine_transaction(&nodes[1], node2_commit_tx);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_c_id], CHAN_CAPACITY);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);

	// Node 1 should immediately claim package 1 but has to wait a block to claim package 2.
	let timeout_tx = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(timeout_tx.len(), 1);
	check_spends!(timeout_tx[0], node2_commit_tx);
	assert_eq!(timeout_tx[0].input.len(), 1);

	// After one block, node 1 should also attempt to claim package 2.
	connect_blocks(&nodes[1], 1);
	let timeout_tx = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(timeout_tx.len(), 1);
	check_spends!(timeout_tx[0], node2_commit_tx);
	assert_eq!(timeout_tx[0].input.len(), 2);

	// Force node 2 to broadcast an aggregated HTLC-Success transaction spending HTLCs 1 and 2.
	// This will conflict with both of node 1's HTLC packages.
	{
		let broadcaster = &node_cfgs[2].tx_broadcaster;
		let fee_estimator = &LowerBoundedFeeEstimator::new(node_cfgs[2].fee_estimator);
		let logger = &node_cfgs[2].logger;
		let monitor = get_monitor!(nodes[2], cid_1_2);
		monitor.provide_payment_preimage_unsafe_legacy(
			&payment_hash_1,
			&preimage_1,
			broadcaster,
			fee_estimator,
			logger,
		);
		monitor.provide_payment_preimage_unsafe_legacy(
			&payment_hash_2,
			&preimage_2,
			broadcaster,
			fee_estimator,
			logger,
		);
	}
	mine_transaction(&nodes[2], node2_commit_tx);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[2], 1, reason, &[node_b_id], CHAN_CAPACITY);
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors(&nodes[2], 1);

	let process_bump_event = |node: &Node| {
		let events = node.chain_monitor.chain_monitor.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		let bump_event = match &events[0] {
			Event::BumpTransaction(bump_event) => bump_event,
			_ => panic!("Unexepected event"),
		};
		node.bump_tx_handler.handle_event(bump_event);

		let mut tx = node.tx_broadcaster.txn_broadcast();
		assert_eq!(tx.len(), 1);
		tx.pop().unwrap()
	};

	let conflict_tx = process_bump_event(&nodes[2]);
	assert_eq!(conflict_tx.input.len(), 3);
	assert_eq!(conflict_tx.input[0].previous_output.txid, node2_commit_tx.compute_txid());
	assert_eq!(conflict_tx.input[1].previous_output.txid, node2_commit_tx.compute_txid());
	assert_eq!(conflict_tx.input[2].previous_output.txid, coinbase_tx.compute_txid());

	// Mine node 2's aggregated HTLC-Success transaction on node 1, causing the package splitting
	// logic to run.  Package 2 should get split so that only HTLC 3 gets claimed.
	mine_transaction(&nodes[1], &conflict_tx);

	// Check that node 1 only attempts to claim HTLC 3 now.  There should be no conflicting spends
	// in the newly broadcasted transaction.
	let broadcasted_txs = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(broadcasted_txs.len(), 1);
	let txins = &broadcasted_txs[0].input;
	assert_eq!(txins.len(), 1);
	assert_eq!(txins[0].previous_output.txid, node2_commit_tx.compute_txid());
	for conflict_in in &conflict_tx.input {
		assert_ne!(txins[0].previous_output, conflict_in.previous_output);
	}

	// Node 1 should also extract the preimages from the mined transaction and claim them upstream.
	//
	// Because two update_fulfill_htlc messages are created at once, the commitment_signed_dance
	// macro doesn't work properly and we must process the first update_fulfill_htlc manually.
	let mut updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates.update_fulfill_htlcs.remove(0));
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &updates.commitment_signed);
	check_added_monitors(&nodes[0], 1);

	let (revoke_ack, commit_signed) = get_revoke_commit_msgs(&nodes[0], &node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &revoke_ack);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &commit_signed);
	check_added_monitors(&nodes[1], 4);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	let revoke_ack = match events.remove(1) {
		MessageSendEvent::SendRevokeAndACK { node_id: _, msg } => msg,
		_ => panic!("Unexpected event"),
	};
	nodes[0].node.handle_revoke_and_ack(node_b_id, &revoke_ack);
	expect_payment_sent!(nodes[0], preimage_1);

	let mut updates = match events.remove(0) {
		MessageSendEvent::UpdateHTLCs { node_id: _, channel_id: _, updates } => updates,
		_ => panic!("Unexpected event"),
	};
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_sent!(nodes[0], preimage_2);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	expect_payment_forwarded(
		events.pop().unwrap(),
		&nodes[1],
		&nodes[0],
		&nodes[2],
		Some(1000),
		None,
		false,
		true,
		false,
	);
	expect_payment_forwarded(
		events.pop().unwrap(),
		&nodes[1],
		&nodes[0],
		&nodes[2],
		Some(1000),
		None,
		false,
		true,
		false,
	);
}

// Test that the HTLC package logic removes HTLCs from the package when they are claimed by the
// counterparty, even when the counterparty claims HTLCs from multiple packages in a single
// transaction.
//
// This is a regression test for https://github.com/lightningdevkit/rust-lightning/issues/3537.
#[xtest(feature = "_externalize_tests")]
pub fn test_multiple_package_conflicts() {
	do_test_multiple_package_conflicts(false);
	do_test_multiple_package_conflicts(true);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_htlc_on_chain_success() {
	// Test that in case of a unilateral close onchain, we detect the state of output and pass
	// the preimage backward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// We test with two HTLCs simultaneously as that was not handled correctly in the past.
	// A --------------------> B ----------------------> C (preimage)
	// First, C should claim the HTLC outputs via HTLC-Success when its own latest local
	// commitment transaction was broadcast.
	// Then, B should learn the preimage from said transactions, attempting to claim backwards
	// towards B.
	// B should be able to claim via preimage if A then broadcasts its local tx.
	// Finally, when A sees B's latest local commitment transaction it should be able to claim
	// the HTLC outputs via the preimage it learned (which, once confirmed should generate a
	// PaymentSent event).

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Ensure all nodes are at the same height
	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	// Rebalance the network a bit by relaying one payment through all the channels...
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 8000000);

	let (our_payment_preimage, payment_hash_1, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);
	let (our_payment_preimage_2, payment_hash_2, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);

	// Broadcast legit commitment tx from C on B's chain
	// Broadcast HTLC Success transaction by C on received output from C's commitment tx on B's chain
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(commitment_tx.len(), 1);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.claim_funds(our_payment_preimage);
	expect_payment_claimed!(nodes[2], payment_hash_1, 3_000_000);
	nodes[2].node.claim_funds(our_payment_preimage_2);
	expect_payment_claimed!(nodes[2], payment_hash_2, 3_000_000);
	check_added_monitors(&nodes[2], 2);
	let updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);

	mine_transaction(&nodes[2], &commitment_tx[0]);
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors(&nodes[2], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[2], 1, reason, &[node_b_id], 100000);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelMonitor: 2 (2 * HTLC-Success tx)
	assert_eq!(node_txn.len(), 2);
	check_spends!(node_txn[0], commitment_tx[0]);
	check_spends!(node_txn[1], commitment_tx[0]);
	assert_eq!(
		node_txn[0].input[0].witness.clone().last().unwrap().len(),
		ACCEPTED_HTLC_SCRIPT_WEIGHT
	);
	assert_eq!(
		node_txn[1].input[0].witness.clone().last().unwrap().len(),
		ACCEPTED_HTLC_SCRIPT_WEIGHT
	);
	assert!(node_txn[0].output[0].script_pubkey.is_p2wsh()); // revokeable output
	assert!(node_txn[1].output[0].script_pubkey.is_p2wsh()); // revokeable output
	assert_eq!(node_txn[0].lock_time, LockTime::ZERO);
	assert_eq!(node_txn[1].lock_time, LockTime::ZERO);

	// Verify that B's ChannelManager is able to extract preimage from HTLC Success tx and pass it backward
	let txn = vec![commitment_tx[0].clone(), node_txn[0].clone(), node_txn[1].clone()];
	connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, txn));
	connect_blocks(&nodes[1], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires
	let forwarded_events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(forwarded_events.len(), 3);
	let chan_id = Some(chan_1.2);
	match forwarded_events[0] {
		Event::PaymentForwarded {
			total_fee_earned_msat,
			prev_channel_id,
			claim_from_onchain_tx,
			next_channel_id,
			outbound_amount_forwarded_msat,
			..
		} => {
			assert_eq!(total_fee_earned_msat, Some(1000));
			assert_eq!(prev_channel_id, chan_id);
			assert_eq!(claim_from_onchain_tx, true);
			assert_eq!(next_channel_id, Some(chan_2.2));
			assert_eq!(outbound_amount_forwarded_msat, Some(3000000));
		},
		_ => panic!(),
	}
	match forwarded_events[1] {
		Event::PaymentForwarded {
			total_fee_earned_msat,
			prev_channel_id,
			claim_from_onchain_tx,
			next_channel_id,
			outbound_amount_forwarded_msat,
			..
		} => {
			assert_eq!(total_fee_earned_msat, Some(1000));
			assert_eq!(prev_channel_id, chan_id);
			assert_eq!(claim_from_onchain_tx, true);
			assert_eq!(next_channel_id, Some(chan_2.2));
			assert_eq!(outbound_amount_forwarded_msat, Some(3000000));
		},
		_ => panic!(),
	}
	match forwarded_events[2] {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {},
		_ => panic!("Unexpected event"),
	}
	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	{
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 3);
		assert_eq!(added_monitors[0].0, chan_2.2);
		assert_eq!(added_monitors[1].0, chan_1.2);
		assert_eq!(added_monitors[2].0, chan_1.2);
		added_monitors.clear();
	}
	assert_eq!(events.len(), 3);

	let nodes_2_event = remove_first_msg_event_to_node(&node_c_id, &mut events);
	let nodes_0_event = remove_first_msg_event_to_node(&node_a_id, &mut events);

	match nodes_2_event {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { .. }, .. } => {},
		_ => panic!("Unexpected event"),
	}

	match nodes_0_event {
		MessageSendEvent::UpdateHTLCs {
			ref node_id,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fail_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_malformed_htlcs,
					..
				},
			..
		} => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fail_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(node_a_id, *node_id);
		},
		_ => panic!("Unexpected event"),
	};

	// Ensure that the last remaining message event is the BroadcastChannelUpdate msg for chan_2
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// nodes[1] does not broadcast its own timeout-claim of the output as nodes[2] just claimed it
	// via success.
	assert!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());

	// Broadcast legit commitment tx from A on B's chain
	// Broadcast preimage tx by B on offered output from A commitment tx  on A's chain
	let node_a_commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	check_spends!(node_a_commitment_tx[0], chan_1.3);
	mine_transaction(&nodes[1], &node_a_commitment_tx[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert!(node_txn.len() == 1 || node_txn.len() == 2); // HTLC-Success, RBF bump of above aggregated HTLC txn
	let commitment_spend = if node_txn.len() == 1 {
		&node_txn[0]
	} else {
		// Certain `ConnectStyle`s will cause RBF bumps of the previous HTLC transaction to be broadcast.
		// FullBlockViaListen
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
		if node_txn[0].input[0].previous_output.txid == node_a_commitment_tx[0].compute_txid() {
			check_spends!(node_txn[1], commitment_tx[0]);
			&node_txn[0]
		} else {
			check_spends!(node_txn[0], commitment_tx[0]);
			&node_txn[1]
		}
	};

	check_spends!(commitment_spend, node_a_commitment_tx[0]);
	assert_eq!(commitment_spend.input.len(), 2);
	assert_eq!(commitment_spend.input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(commitment_spend.input[1].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(commitment_spend.lock_time.to_consensus_u32(), nodes[1].best_block_info().1);
	assert!(commitment_spend.output[0].script_pubkey.is_p2wpkh()); // direct payment

	// We don't bother to check that B can claim the HTLC output on its commitment tx here as
	// we already checked the same situation with A.

	// Verify that A's ChannelManager is able to extract preimage from preimage tx and generate PaymentSent
	let txn = vec![node_a_commitment_tx[0].clone(), commitment_spend.clone()];
	connect_block(&nodes[0], &create_dummy_block(nodes[0].best_block_hash(), 42, txn));
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + MIN_CLTV_EXPIRY_DELTA as u32); // Confirm blocks until the HTLC expires
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	check_added_monitors(&nodes[0], 2);
	assert_eq!(events.len(), 5);
	let mut first_claimed = false;
	for event in events {
		match event {
			Event::PaymentSent { payment_preimage, payment_hash, .. } => {
				if payment_preimage == our_payment_preimage && payment_hash == payment_hash_1 {
					assert!(!first_claimed);
					first_claimed = true;
				} else {
					assert_eq!(payment_preimage, our_payment_preimage_2);
					assert_eq!(payment_hash, payment_hash_2);
				}
			},
			Event::PaymentPathSuccessful { .. } => {},
			Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {},
			_ => panic!("Unexpected event"),
		}
	}
	// HTLC timeout claims for non-anchor channels are only aggregated when claimed from the
	// remote commitment transaction.
	let mut node_txn = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(node_txn.len(), 2);
	for tx in node_txn.iter() {
		check_spends!(tx, node_a_commitment_tx[0]);
		assert_ne!(tx.lock_time, LockTime::ZERO);
		assert_eq!(tx.input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		assert!(tx.output[0].script_pubkey.is_p2wsh()); // revokeable output
	}
	assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
}

fn do_test_htlc_on_chain_timeout(connect_style: ConnectStyle) {
	// Test that in case of a unilateral close onchain, we detect the state of output and
	// timeout the HTLC backward accordingly. So here we test that ChannelManager is
	// broadcasting the right event to other nodes in payment path.
	// A ------------------> B ----------------------> C (timeout)
	//    B's commitment tx 		C's commitment tx
	//    	      \                                  \
	//    	   B's HTLC timeout tx		     B's timeout tx

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	*nodes[0].connect_style.borrow_mut() = connect_style;
	*nodes[1].connect_style.borrow_mut() = connect_style;
	*nodes[2].connect_style.borrow_mut() = connect_style;

	// Create some intial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Rebalance the network a bit by relaying one payment thorugh all the channels...
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 8000000);

	let (_payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);

	// Broadcast legit commitment tx from C on B's chain
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.fail_htlc_backwards(&payment_hash);
	check_added_monitors(&nodes[2], 0);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[2],
		&[HTLCHandlingFailureType::Receive { payment_hash: payment_hash.clone() }],
	);
	check_added_monitors(&nodes[2], 1);

	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs {
			ref node_id,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_htlcs,
					ref update_fail_malformed_htlcs,
					..
				},
			..
		} => {
			assert!(update_add_htlcs.is_empty());
			assert!(!update_fail_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(node_b_id, *node_id);
		},
		_ => panic!("Unexpected event"),
	};
	mine_transaction(&nodes[2], &commitment_tx[0]);
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors(&nodes[2], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[2], 1, reason, &[node_b_id], 100000);
	let node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 0);

	// Broadcast timeout transaction by B on received output from C's commitment tx on B's chain
	// Verify that B's ChannelManager is able to detect that HTLC is timeout by its own tx and react backward in consequence
	mine_transaction(&nodes[1], &commitment_tx[0]);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100000);
	let htlc_expiry = get_monitor!(nodes[1], chan_2.2)
		.get_claimable_balances()
		.iter()
		.filter_map(|bal| {
			if let Balance::MaybeTimeoutClaimableHTLC { claimable_height, .. } = bal {
				Some(*claimable_height)
			} else {
				None
			}
		})
		.next()
		.unwrap();
	connect_blocks(&nodes[1], htlc_expiry - nodes[1].best_block_info().1);
	let timeout_tx = {
		let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		txn.iter().for_each(|tx| check_spends!(tx, commitment_tx[0]));
		assert_eq!(
			txn[0].clone().input[0].witness.last().unwrap().len(),
			ACCEPTED_HTLC_SCRIPT_WEIGHT
		);
		txn.remove(0)
	};

	// Make sure that if we connect only one block we aren't aggressively fee-bumping the HTLC
	// claim which was only just broadcasted (and as at least `MIN_CLTV_EXPIRY_DELTA` blocks to
	// confirm).
	connect_blocks(&nodes[1], 1);
	assert_eq!(nodes[1].tx_broadcaster.txn_broadcast().len(), 0);

	mine_transaction(&nodes[1], &timeout_tx);
	check_added_monitors(&nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);

	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }],
	);
	check_added_monitors(&nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs {
			ref node_id,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fail_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_malformed_htlcs,
					..
				},
			..
		} => {
			assert!(update_add_htlcs.is_empty());
			assert!(!update_fail_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(node_a_id, *node_id);
		},
		_ => panic!("Unexpected event"),
	};

	// Broadcast legit commitment tx from B on A's chain
	let commitment_tx = get_local_commitment_txn!(nodes[1], chan_1.2);
	check_spends!(commitment_tx[0], chan_1.3);

	mine_transaction(&nodes[0], &commitment_tx[0]);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + MIN_CLTV_EXPIRY_DELTA as u32); // Confirm blocks until the HTLC expires

	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // 1 timeout tx
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], commitment_tx[0]);
	assert_eq!(
		node_txn[0].clone().input[0].witness.last().unwrap().len(),
		ACCEPTED_HTLC_SCRIPT_WEIGHT + 1
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_htlc_on_chain_timeout() {
	do_test_htlc_on_chain_timeout(ConnectStyle::BestBlockFirstSkippingBlocks);
	do_test_htlc_on_chain_timeout(ConnectStyle::TransactionsFirstSkippingBlocks);
	do_test_htlc_on_chain_timeout(ConnectStyle::FullBlockViaListen);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_simple_commitment_revoked_fail_backward() {
	// Test that in case of a revoked commitment tx, we detect the resolution of output by justice tx
	// and fail backward accordingly.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, _payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	let (_, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3000000);

	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	check_added_monitors(&nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);

	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }],
	);
	check_added_monitors(&nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::UpdateHTLCs {
			ref node_id,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fail_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_malformed_htlcs,
					ref commitment_signed,
					..
				},
			..
		} => {
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(node_a_id, *node_id);

			nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlcs[0]);
			do_commitment_signed_dance(&nodes[0], &nodes[1], commitment_signed, false, true);
			let scid = chan_2.0.contents.short_channel_id;
			expect_payment_failed_with_update!(nodes[0], payment_hash, false, scid, true);
		},
		_ => panic!("Unexpected event"),
	}
}

fn do_test_commitment_revoked_fail_backward_exhaustive(
	deliver_bs_raa: bool, use_dust: bool, no_to_remote: bool,
) {
	// Test that if our counterparty broadcasts a revoked commitment transaction we fail all
	// pending HTLCs on that channel backwards even if the HTLCs aren't present in our latest
	// commitment transaction anymore.
	// To do this, we have the peer which will broadcast a revoked commitment transaction send
	// a number of update_fail/commitment_signed updates without ever sending the RAA in
	// response to our commitment_signed. This is somewhat misbehavior-y, though not
	// technically disallowed and we should probably handle it reasonably.
	// Note that this is pretty exhaustive as an outbound HTLC which we haven't yet
	// failed/fulfilled backwards must be in at least one of the latest two remote commitment
	// transactions:
	// * Once we move it out of our holding cell/add it, we will immediately include it in a
	//   commitment_signed (implying it will be in the latest remote commitment transaction).
	// * Once they remove it, we will send a (the first) commitment_signed without the HTLC,
	//   and once they revoke the previous commitment transaction (allowing us to send a new
	//   commitment_signed) we will be free to fail/fulfill the HTLC backwards.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let amt = if no_to_remote { 10_000 } else { 3_000_000 };
	let (payment_preimage, _payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], amt);
	// Get the will-be-revoked local txn from nodes[2]
	let revoked_local_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(revoked_local_txn[0].output.len(), if no_to_remote { 1 } else { 2 });
	// Revoke the old state
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);

	let value = if use_dust {
		// The dust limit applied to HTLC outputs considers the fee of the HTLC transaction as
		// well, so HTLCs at exactly the dust limit will not be included in commitment txn.
		let per_peer_state_lock;
		let mut peer_state_lock;
		let chan =
			get_channel_ref!(nodes[2], nodes[1], per_peer_state_lock, peer_state_lock, chan_2.2);
		chan.context().holder_dust_limit_satoshis * 1000
	} else {
		3000000
	};

	let (_, first_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);
	let (_, second_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);
	let (_, third_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], value);

	nodes[2].node.fail_htlc_backwards(&first_payment_hash);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[2],
		&[HTLCHandlingFailureType::Receive { payment_hash: first_payment_hash }],
	);
	check_added_monitors(&nodes[2], 1);
	let updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[0]);
	let cs = updates.commitment_signed;
	let bs_raa = commitment_signed_dance_return_raa(&nodes[1], &nodes[2], &cs, false);
	// Drop the last RAA from 3 -> 2

	nodes[2].node.fail_htlc_backwards(&second_payment_hash);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[2],
		&[HTLCHandlingFailureType::Receive { payment_hash: second_payment_hash }],
	);
	check_added_monitors(&nodes[2], 1);
	let updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	// Note that nodes[1] is in AwaitingRAA, so won't send a CS
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_c_id);
	nodes[2].node.handle_revoke_and_ack(node_b_id, &as_raa);
	check_added_monitors(&nodes[2], 1);

	nodes[2].node.fail_htlc_backwards(&third_payment_hash);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[2],
		&[HTLCHandlingFailureType::Receive { payment_hash: third_payment_hash }],
	);
	check_added_monitors(&nodes[2], 1);
	let updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[0]);
	// At this point first_payment_hash has dropped out of the latest two commitment
	// transactions that nodes[1] is tracking...
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	// Note that nodes[1] is (still) in AwaitingRAA, so won't send a CS
	let as_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_c_id);
	nodes[2].node.handle_revoke_and_ack(node_b_id, &as_raa);
	check_added_monitors(&nodes[2], 1);

	// Add a fourth HTLC, this one will get sequestered away in nodes[1]'s holding cell waiting
	// on nodes[2]'s RAA.
	let (route, fourth_payment_hash, _, fourth_payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[2], 1000000);
	let onion = RecipientOnionFields::secret_only(fourth_payment_secret);
	let id = PaymentId(fourth_payment_hash.0);
	nodes[1].node.send_payment_with_route(route, fourth_payment_hash, onion, id).unwrap();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors(&nodes[1], 0);

	if deliver_bs_raa {
		nodes[1].node.handle_revoke_and_ack(node_c_id, &bs_raa);
		// One monitor for the new revocation preimage, no second on as we won't generate a new
		// commitment transaction for nodes[0] until process_pending_htlc_forwards().
		check_added_monitors(&nodes[1], 1);
		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::HTLCHandlingFailed { .. } => {},
			_ => panic!("Unexpected event"),
		}
		// Deliberately don't process the pending fail-back so they all fail back at once after
		// block connection just like the !deliver_bs_raa case
	}

	let mut failed_htlcs = new_hash_set();
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	check_added_monitors(&nodes[1], 0);
	let events = nodes[1].node.get_and_clear_pending_events();
	if deliver_bs_raa {
		check_added_monitors(&nodes[1], 2);
	} else {
		check_added_monitors(&nodes[1], 1);
	}
	assert_eq!(events.len(), if deliver_bs_raa { 3 + nodes.len() - 1 } else { 3 + nodes.len() });
	assert!(events.iter().any(|ev| matches!(
		ev,
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. }
	)));
	assert!(events.iter().any(|ev| matches!(
		ev,
		Event::PaymentPathFailed { ref payment_hash, .. } if *payment_hash == fourth_payment_hash
	)));
	assert!(events.iter().any(|ev| matches!(
		ev,
		Event::PaymentFailed { ref payment_hash, .. } if *payment_hash == Some(fourth_payment_hash)
	)));

	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[1], 1);

	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), if deliver_bs_raa { 4 } else { 3 });

	if deliver_bs_raa {
		let nodes_2_event = remove_first_msg_event_to_node(&node_c_id, &mut events);
		match nodes_2_event {
			MessageSendEvent::UpdateHTLCs {
				ref node_id,
				updates:
					msgs::CommitmentUpdate {
						ref update_add_htlcs,
						ref update_fail_htlcs,
						ref update_fulfill_htlcs,
						ref update_fail_malformed_htlcs,
						..
					},
				..
			} => {
				assert_eq!(node_c_id, *node_id);
				assert_eq!(update_add_htlcs.len(), 1);
				assert!(update_fulfill_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert!(update_fail_malformed_htlcs.is_empty());
			},
			_ => panic!("Unexpected event"),
		}
	}

	let nodes_2_event = remove_first_msg_event_to_node(&node_c_id, &mut events);
	match nodes_2_event {
		MessageSendEvent::HandleError {
			action:
				ErrorAction::SendErrorMessage { msg: msgs::ErrorMessage { channel_id, ref data } },
			..
		} => {
			assert_eq!(channel_id, chan_2.2);
			assert_eq!(
				data.as_str(),
				"Channel closed because commitment or closing transaction was confirmed on chain."
			);
		},
		_ => panic!("Unexpected event"),
	}

	let nodes_0_event = remove_first_msg_event_to_node(&node_a_id, &mut events);
	match nodes_0_event {
		MessageSendEvent::UpdateHTLCs {
			ref node_id,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fail_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_malformed_htlcs,
					ref commitment_signed,
					..
				},
			..
		} => {
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 3);
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(node_a_id, *node_id);

			nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlcs[0]);
			nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlcs[1]);
			nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlcs[2]);

			do_commitment_signed_dance(&nodes[0], &nodes[1], commitment_signed, false, true);

			let events = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events.len(), 6);
			match events[0] {
				Event::PaymentPathFailed { ref payment_hash, ref failure, .. } => {
					assert!(failed_htlcs.insert(payment_hash.0));
					// If we delivered B's RAA we got an unknown preimage error, not something
					// that we should update our routing table for.
					if !deliver_bs_raa {
						if let PathFailure::OnPath { network_update: Some(_) } = failure {
						} else {
							panic!("Unexpected path failure")
						}
					}
				},
				_ => panic!("Unexpected event"),
			}
			match events[1] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert_eq!(*payment_hash, Some(first_payment_hash));
				},
				_ => panic!("Unexpected event"),
			}
			match events[2] {
				Event::PaymentPathFailed {
					ref payment_hash,
					failure: PathFailure::OnPath { network_update: Some(_) },
					..
				} => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
			match events[3] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert_eq!(*payment_hash, Some(second_payment_hash));
				},
				_ => panic!("Unexpected event"),
			}
			match events[4] {
				Event::PaymentPathFailed {
					ref payment_hash,
					failure: PathFailure::OnPath { network_update: Some(_) },
					..
				} => {
					assert!(failed_htlcs.insert(payment_hash.0));
				},
				_ => panic!("Unexpected event"),
			}
			match events[5] {
				Event::PaymentFailed { ref payment_hash, .. } => {
					assert_eq!(*payment_hash, Some(third_payment_hash));
				},
				_ => panic!("Unexpected event"),
			}
		},
		_ => panic!("Unexpected event"),
	}

	// Ensure that the last remaining message event is the BroadcastChannelUpdate msg for chan_2
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { msg: msgs::ChannelUpdate { .. }, .. } => {},
		_ => panic!("Unexpected event"),
	}

	assert!(failed_htlcs.contains(&first_payment_hash.0));
	assert!(failed_htlcs.contains(&second_payment_hash.0));
	assert!(failed_htlcs.contains(&third_payment_hash.0));
}

#[xtest(feature = "_externalize_tests")]
pub fn test_commitment_revoked_fail_backward_exhaustive_a() {
	do_test_commitment_revoked_fail_backward_exhaustive(false, true, false);
	do_test_commitment_revoked_fail_backward_exhaustive(true, true, false);
	do_test_commitment_revoked_fail_backward_exhaustive(false, false, false);
	do_test_commitment_revoked_fail_backward_exhaustive(true, false, false);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_commitment_revoked_fail_backward_exhaustive_b() {
	do_test_commitment_revoked_fail_backward_exhaustive(false, true, true);
	do_test_commitment_revoked_fail_backward_exhaustive(true, true, true);
	do_test_commitment_revoked_fail_backward_exhaustive(false, false, true);
	do_test_commitment_revoked_fail_backward_exhaustive(true, false, true);
}

#[xtest(feature = "_externalize_tests")]
pub fn fail_backward_pending_htlc_upon_channel_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000);

	// Alice -> Bob: Route a payment but without Bob sending revoke_and_ack.
	{
		let (route, payment_hash, _, payment_secret) =
			get_route_and_payment_hash!(nodes[0], nodes[1], 50_000);
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let id = PaymentId(payment_hash.0);
		nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);

		let payment_event = {
			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))
		};
		assert_eq!(payment_event.node_id, node_b_id);
		assert_eq!(payment_event.msgs.len(), 1);
	}

	// Alice -> Bob: Route another payment but now Alice waits for Bob's earlier revoke_and_ack.
	let (route, failed_payment_hash, _, failed_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 50_000);
	{
		let onion = RecipientOnionFields::secret_only(failed_payment_secret);
		let id = PaymentId(failed_payment_hash.0);
		nodes[0].node.send_payment_with_route(route, failed_payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 0);

		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	}

	// Alice <- Bob: Send a malformed update_add_htlc so Alice fails the channel.
	{
		let (route, payment_hash, _, payment_secret) =
			get_route_and_payment_hash!(nodes[1], nodes[0], 50_000);

		let secp_ctx = Secp256k1::new();
		let session_priv = SecretKey::from_slice(&[42; 32]).unwrap();
		let current_height = nodes[1].node.best_block.read().unwrap().height + 1;
		let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
		let (onion_payloads, _amount_msat, cltv_expiry) = onion_utils::build_onion_payloads(
			&route.paths[0],
			50_000,
			&recipient_onion_fields,
			current_height,
			&None,
			None,
			None,
		)
		.unwrap();
		let onion_keys =
			onion_utils::construct_onion_keys(&secp_ctx, &route.paths[0], &session_priv);
		let onion_routing_packet =
			onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &payment_hash)
				.unwrap();

		// Send a 0-msat update_add_htlc to fail the channel.
		let update_add_htlc = msgs::UpdateAddHTLC {
			channel_id: chan.2,
			htlc_id: 0,
			amount_msat: 0,
			payment_hash,
			cltv_expiry,
			onion_routing_packet,
			skimmed_fee_msat: None,
			blinding_point: None,
			hold_htlc: None,
			accountable: None,
		};
		nodes[0].node.handle_update_add_htlc(node_b_id, &update_add_htlc);
	}
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 3);
	// Check that Alice fails backward the pending HTLC from the second payment.
	match events[0] {
		Event::PaymentPathFailed { payment_hash, .. } => {
			assert_eq!(payment_hash, failed_payment_hash);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::PaymentFailed { payment_hash, .. } => {
			assert_eq!(payment_hash, Some(failed_payment_hash));
		},
		_ => panic!("Unexpected event"),
	}
	match events[2] {
		Event::ChannelClosed { reason: ClosureReason::ProcessingError { ref err }, .. } => {
			assert_eq!(err, "Remote side tried to send a 0-msat HTLC");
		},
		_ => panic!("Unexpected event {:?}", events[1]),
	}
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_htlc_ignore_latest_remote_commitment() {
	// Test that HTLC transactions spending the latest remote commitment transaction are simply
	// ignored if we cannot claim them. This originally tickled an invalid unwrap().
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	match *nodes[1].connect_style.borrow() {
		ConnectStyle::FullBlockViaListen
		| ConnectStyle::FullBlockDisconnectionsSkippingViaListen => {
			// We rely on the ability to connect a block redundantly, which isn't allowed via
			// `chain::Listen`, so we never run the test if we randomly get assigned that
			// connect_style.
			return;
		},
		_ => {},
	}
	let funding_tx = create_announced_chan_between_nodes(&nodes, 0, 1).3;
	let message = "Channel force-closed".to_owned();
	route_payment(&nodes[0], &[&nodes[1]], 10000000);
	let chan_id = nodes[0].node.list_channels()[0].channel_id;
	nodes[0]
		.node
		.force_close_broadcasting_latest_txn(&chan_id, &node_b_id, message.clone())
		.unwrap();
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);

	let node_txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
	assert_eq!(node_txn.len(), 2);
	check_spends!(node_txn[0], funding_tx);
	check_spends!(node_txn[1], node_txn[0]);

	let block = create_dummy_block(nodes[1].best_block_hash(), 42, vec![node_txn[0].clone()]);
	connect_block(&nodes[1], &block);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);

	// Duplicate the connect_block call since this may happen due to other listeners
	// registering new transactions
	connect_block(&nodes[1], &block);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_force_close_fail_back() {
	// Check which HTLCs are failed-backwards on channel force-closure
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let (route, our_payment_hash, our_payment_preimage, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 1000000);

	let mut payment_event = {
		let onion = RecipientOnionFields::secret_only(our_payment_secret);
		let id = PaymentId(our_payment_hash.0);
		nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);

	expect_and_process_pending_htlcs(&nodes[1], false);

	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	payment_event = SendEvent::from_event(events_2.remove(0));
	assert_eq!(payment_event.msgs.len(), 1);

	check_added_monitors(&nodes[1], 1);
	nodes[2].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
	nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &payment_event.commitment_msg);
	check_added_monitors(&nodes[2], 1);
	let _ = get_revoke_commit_msgs(&nodes[2], &node_b_id);

	// nodes[2] now has the latest commitment transaction, but hasn't revoked its previous
	// state or updated nodes[1]' state. Now force-close and broadcast that commitment/HTLC
	// transaction and ensure nodes[1] doesn't fail-backwards (this was originally a bug!).
	let message = "Channel force-closed".to_owned();
	let channel_id = payment_event.commitment_msg[0].channel_id;
	nodes[2]
		.node
		.force_close_broadcasting_latest_txn(&channel_id, &node_b_id, message.clone())
		.unwrap();
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors(&nodes[2], 1);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[2], 1, reason, &[node_b_id], 100000);

	let commitment_tx = {
		let mut node_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// Note that we don't bother broadcasting the HTLC-Success transaction here as we don't
		// have a use for it unless nodes[2] learns the preimage somehow, the funds will go
		// back to nodes[1] upon timeout otherwise.
		assert_eq!(node_txn.len(), 1);
		node_txn.remove(0)
	};

	mine_transaction(&nodes[1], &commitment_tx);

	// Note no UpdateHTLCs event here from nodes[1] to nodes[0]!
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100000);

	// Now check that if we add the preimage to ChannelMonitor it broadcasts our HTLC-Success..
	{
		get_monitor!(nodes[2], channel_id).provide_payment_preimage_unsafe_legacy(
			&our_payment_hash,
			&our_payment_preimage,
			&node_cfgs[2].tx_broadcaster,
			&LowerBoundedFeeEstimator::new(node_cfgs[2].fee_estimator),
			&node_cfgs[2].logger,
		);
	}
	mine_transaction(&nodes[2], &commitment_tx);
	let mut node_txn = nodes[2].tx_broadcaster.txn_broadcast();
	assert_eq!(
		node_txn.len(),
		if nodes[2].connect_style.borrow().updates_best_block_first() { 2 } else { 1 }
	);
	let htlc_tx = node_txn.pop().unwrap();
	assert_eq!(htlc_tx.input.len(), 1);
	assert_eq!(htlc_tx.input[0].previous_output.txid, commitment_tx.compute_txid());
	assert_eq!(htlc_tx.lock_time, LockTime::ZERO); // Must be an HTLC-Success
	assert_eq!(htlc_tx.input[0].witness.len(), 5); // Must be an HTLC-Success

	check_spends!(htlc_tx, commitment_tx);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_dup_events_on_peer_disconnect() {
	// Test that if we receive a duplicative update_fulfill_htlc message after a reconnect we do
	// not generate a corresponding duplicative PaymentSent event. This did not use to be the case
	// as we used to generate the event immediately upon receipt of the payment preimage in the
	// update_fulfill_htlc message.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, 1_000_000);
	check_added_monitors(&nodes[1], 1);
	let mut claim_msgs = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, claim_msgs.update_fulfill_htlcs.remove(0));
	expect_payment_sent(&nodes[0], payment_preimage, None, false, false);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.pending_htlc_claims.0 = 1;
	reconnect_nodes(reconnect_args);
	expect_payment_path_successful!(nodes[0]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_peer_disconnected_before_funding_broadcasted() {
	// Test that channels are closed with `ClosureReason::DisconnectedPeer` if the peer disconnects
	// before the funding transaction has been broadcasted, and doesn't reconnect back within time.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Open a channel between `nodes[0]` and `nodes[1]`, for which the funding transaction is never
	// broadcasted, even though it's created by `nodes[0]`.
	let expected_temporary_channel_id =
		nodes[0].node.create_channel(node_b_id, 1_000_000, 500_000_000, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);

	let (temporary_channel_id, tx, _funding_output) =
		create_funding_transaction(&nodes[0], &node_b_id, 1_000_000, 42);
	assert_eq!(temporary_channel_id, expected_temporary_channel_id);

	assert!(nodes[0]
		.node
		.funding_transaction_generated(temporary_channel_id, node_b_id, tx.clone())
		.is_ok());

	let funding_created_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	assert_eq!(funding_created_msg.temporary_channel_id, expected_temporary_channel_id);

	// Even though the funding transaction is created by `nodes[0]`, the `FundingCreated` msg is
	// never sent to `nodes[1]`, and therefore the tx is never signed by either party nor
	// broadcasted.
	{
		assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 0);
	}

	// The peers disconnect before the funding is broadcasted.
	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	// The time for peers to reconnect expires.
	for _ in 0..UNFUNDED_CHANNEL_AGE_LIMIT_TICKS {
		nodes[0].node.timer_tick_occurred();
	}

	// Ensure that the channel is closed with `ClosureReason::DisconnectedPeer` and a
	// `DiscardFunding` event when the peers are disconnected and do not reconnect before the
	// funding transaction is broadcasted.
	let reason = ClosureReason::DisconnectedPeer;
	check_closed_event_internal(&nodes[0], 2, reason, true, &[node_b_id], 1000000);
	check_closed_event(&nodes[1], 1, ClosureReason::DisconnectedPeer, &[node_a_id], 1000000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_simple_peer_disconnect() {
	// Test that we can reconnect when there are no lost messages
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (true, true);
	reconnect_args.send_announcement_sigs = (true, true);
	reconnect_nodes(reconnect_args);

	let payment_preimage_1 = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000).0;
	let payment_hash_2 = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000).1;
	fail_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_hash_2);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_1);

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	let (payment_preimage_3, payment_hash_3, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000);
	let payment_preimage_4 = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000).0;
	let payment_hash_5 = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000).1;
	let payment_hash_6 = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1000000).1;

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	claim_payment_along_route(
		ClaimAlongRouteArgs::new(&nodes[0], &[&[&nodes[1], &nodes[2]]], payment_preimage_3)
			.skip_last(true),
	);
	fail_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], true, payment_hash_5);

	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.pending_cell_htlc_fails.0 = 1;
	reconnect_args.pending_cell_htlc_claims.0 = 1;
	reconnect_nodes(reconnect_args);
	{
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 4);
		match events[0] {
			Event::PaymentSent { payment_preimage, payment_hash, .. } => {
				assert_eq!(payment_preimage, payment_preimage_3);
				assert_eq!(payment_hash, payment_hash_3);
			},
			_ => panic!("Unexpected event"),
		}
		match events[1] {
			Event::PaymentPathSuccessful { .. } => {},
			_ => panic!("Unexpected event"),
		}
		match events[2] {
			Event::PaymentPathFailed { payment_hash, payment_failed_permanently, .. } => {
				assert_eq!(payment_hash, payment_hash_5);
				assert!(payment_failed_permanently);
			},
			_ => panic!("Unexpected event"),
		}
		match events[3] {
			Event::PaymentFailed { payment_hash, .. } => {
				assert_eq!(payment_hash, Some(payment_hash_5));
			},
			_ => panic!("Unexpected event"),
		}
	}
	check_added_monitors(&nodes[0], 1);

	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage_4);
	fail_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_hash_6);
}

fn do_test_drop_messages_peer_disconnect(messages_delivered: u8, simulate_broken_lnd: bool) {
	// Test that we can reconnect when in-flight HTLC updates get dropped
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let mut as_channel_ready = None;
	let channel_id = if messages_delivered == 0 {
		let (channel_ready, chan_id, _) =
			create_chan_between_nodes_with_value_a(&nodes[0], &nodes[1], 100000, 10001);
		as_channel_ready = Some(channel_ready);
		// nodes[1] doesn't receive the channel_ready message (it'll be re-sent on reconnect)
		// Note that we store it so that if we're running with `simulate_broken_lnd` we can deliver
		// it before the channel_reestablish message.
		chan_id
	} else {
		create_announced_chan_between_nodes(&nodes, 0, 1).2
	};
	let user_channel_id = nodes[1].node.list_channels()[0].user_channel_id;

	let (route, payment_hash_1, payment_preimage_1, payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1_000_000);

	let payment_event = {
		let onion = RecipientOnionFields::secret_only(payment_secret_1);
		let id = PaymentId(payment_hash_1.0);
		nodes[0].node.send_payment_with_route(route, payment_hash_1, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(node_b_id, payment_event.node_id);

	if messages_delivered < 2 {
		// Drop the payment_event messages, and let them get re-generated in reconnect_nodes!
	} else {
		nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
		if messages_delivered >= 3 {
			nodes[1]
				.node
				.handle_commitment_signed_batch_test(node_a_id, &payment_event.commitment_msg);
			check_added_monitors(&nodes[1], 1);
			let (bs_revoke_and_ack, bs_commitment_signed) =
				get_revoke_commit_msgs(&nodes[1], &node_a_id);

			if messages_delivered >= 4 {
				nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_revoke_and_ack);
				assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors(&nodes[0], 1);

				if messages_delivered >= 5 {
					nodes[0]
						.node
						.handle_commitment_signed_batch_test(node_b_id, &bs_commitment_signed);
					let as_revoke_and_ack =
						get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					check_added_monitors(&nodes[0], 1);

					if messages_delivered >= 6 {
						nodes[1].node.handle_revoke_and_ack(node_a_id, &as_revoke_and_ack);
						assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
						check_added_monitors(&nodes[1], 1);
					}
				}
			}
		}
	}

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	if messages_delivered < 3 {
		if simulate_broken_lnd {
			// lnd has a long-standing bug where they send a channel_ready prior to a
			// channel_reestablish if you reconnect prior to channel_ready time.
			//
			// Here we simulate that behavior, delivering a channel_ready immediately on
			// reconnect. Note that we don't bother skipping the now-duplicate channel_ready sent
			// in `reconnect_nodes` but we currently don't fail based on that.
			//
			// See-also <https://github.com/lightningnetwork/lnd/issues/4006>
			nodes[1].node.handle_channel_ready(node_a_id, &as_channel_ready.as_ref().unwrap().0);
		}
		// Even if the channel_ready messages get exchanged, as long as nothing further was
		// received on either side, both sides will need to resend them.
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.send_channel_ready = (true, true);
		if simulate_broken_lnd || messages_delivered > 0 {
			reconnect_args.send_announcement_sigs.0 = true;
		}
		reconnect_args.send_announcement_sigs.1 = true;
		reconnect_args.pending_htlc_adds.1 = 1;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 3 {
		// nodes[0] still wants its RAA + commitment_signed
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.send_announcement_sigs = (true, true);
		reconnect_args.pending_responding_commitment_signed.0 = true;
		reconnect_args.pending_raa.0 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 4 {
		// nodes[0] still wants its commitment_signed
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.send_announcement_sigs.0 = true;
		reconnect_args.pending_responding_commitment_signed.0 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 5 {
		// nodes[1] still wants its final RAA
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.send_announcement_sigs.0 = true;
		reconnect_args.pending_raa.1 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 6 {
		// Everything was delivered...
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	}

	let events_1 = nodes[1].node.get_and_clear_pending_events();
	if messages_delivered == 0 {
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			Event::ChannelReady { .. } => {},
			_ => panic!("Unexpected event"),
		};
	} else {
		assert_eq!(events_1.len(), 0);
	}

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	if !simulate_broken_lnd
		&& (messages_delivered == 0 || (messages_delivered > 2 && messages_delivered < 6))
	{
		reconnect_args.send_announcement_sigs.0 = true;
	}
	if messages_delivered < 4 {
		reconnect_args.send_announcement_sigs.1 = true;
	}
	reconnect_nodes(reconnect_args);

	nodes[1].node.process_pending_htlc_forwards();

	let events_2 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::PaymentClaimable {
			ref payment_hash,
			ref purpose,
			amount_msat,
			receiver_node_id,
			ref receiving_channel_ids,
			..
		} => {
			assert_eq!(payment_hash_1, *payment_hash);
			assert_eq!(amount_msat, 1_000_000);
			assert_eq!(receiver_node_id.unwrap(), node_b_id);
			assert_eq!(*receiving_channel_ids, vec![(channel_id, Some(user_channel_id))]);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage, payment_secret, ..
				} => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_1, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment"),
			}
		},
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);

	let events_3 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	let (update_fulfill_htlc, commitment_signed) = match events_3[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, channel_id: _, ref updates } => {
			assert_eq!(*node_id, node_a_id);
			assert!(updates.update_add_htlcs.is_empty());
			assert!(updates.update_fail_htlcs.is_empty());
			assert_eq!(updates.update_fulfill_htlcs.len(), 1);
			assert!(updates.update_fail_malformed_htlcs.is_empty());
			assert!(updates.update_fee.is_none());
			(updates.update_fulfill_htlcs[0].clone(), updates.commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	if messages_delivered >= 1 {
		nodes[0].node.handle_update_fulfill_htlc(node_b_id, update_fulfill_htlc);

		let events_4 = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events_4.len(), 1);
		match events_4[0] {
			Event::PaymentSent { ref payment_preimage, ref payment_hash, .. } => {
				assert_eq!(payment_preimage_1, *payment_preimage);
				assert_eq!(payment_hash_1, *payment_hash);
			},
			_ => panic!("Unexpected event"),
		}

		if messages_delivered >= 2 {
			nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &commitment_signed);
			check_added_monitors(&nodes[0], 1);
			let (as_revoke_and_ack, as_commitment_signed) =
				get_revoke_commit_msgs(&nodes[0], &node_b_id);

			if messages_delivered >= 3 {
				nodes[1].node.handle_revoke_and_ack(node_a_id, &as_revoke_and_ack);
				assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
				check_added_monitors(&nodes[1], 1);

				if messages_delivered >= 4 {
					nodes[1]
						.node
						.handle_commitment_signed_batch_test(node_a_id, &as_commitment_signed);
					let bs_revoke_and_ack =
						get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
					// No commitment_signed so get_event_msg's assert(len == 1) passes
					check_added_monitors(&nodes[1], 1);

					if messages_delivered >= 5 {
						nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_revoke_and_ack);
						assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
						check_added_monitors(&nodes[0], 1);
					}
				}
			}
		}
	}

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	if messages_delivered < 2 {
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		if !simulate_broken_lnd && messages_delivered == 0 {
			reconnect_args.send_announcement_sigs.0 = true;
		}
		reconnect_args.send_announcement_sigs.1 = true;
		reconnect_args.pending_htlc_claims.0 = 1;
		reconnect_nodes(reconnect_args);
		if messages_delivered < 1 {
			expect_payment_sent!(nodes[0], payment_preimage_1);
		} else {
			assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
		}
	} else if messages_delivered == 2 {
		// nodes[0] still wants its RAA + commitment_signed
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.send_announcement_sigs.1 = true;
		reconnect_args.pending_responding_commitment_signed.1 = true;
		reconnect_args.pending_raa.1 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 3 {
		// nodes[0] still wants its commitment_signed
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.send_announcement_sigs.1 = true;
		reconnect_args.pending_responding_commitment_signed.1 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 4 {
		// nodes[1] still wants its final RAA
		let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect_args.pending_raa.0 = true;
		reconnect_nodes(reconnect_args);
	} else if messages_delivered == 5 {
		// Everything was delivered...
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	}

	if messages_delivered == 1 || messages_delivered == 2 {
		expect_payment_path_successful!(nodes[0]);
	}
	if messages_delivered <= 5 {
		nodes[0].node.peer_disconnected(node_b_id);
		nodes[1].node.peer_disconnected(node_a_id);
	}
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	if !simulate_broken_lnd {
		if messages_delivered == 0 {
			reconnect_args.send_announcement_sigs.0 = true;
		} else if messages_delivered == 2 || messages_delivered == 3 {
			reconnect_args.send_announcement_sigs.1 = true;
		}
	}
	reconnect_nodes(reconnect_args);

	if messages_delivered > 2 {
		expect_payment_path_successful!(nodes[0]);
	}

	// Channel should still work fine...
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let payment_preimage_2 = send_along_route(&nodes[0], route, &[&nodes[1]], 1000000).0;
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_drop_messages_peer_disconnect_a() {
	do_test_drop_messages_peer_disconnect(0, true);
	do_test_drop_messages_peer_disconnect(0, false);
	do_test_drop_messages_peer_disconnect(1, false);
	do_test_drop_messages_peer_disconnect(2, false);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_drop_messages_peer_disconnect_b() {
	do_test_drop_messages_peer_disconnect(3, false);
	do_test_drop_messages_peer_disconnect(4, false);
	do_test_drop_messages_peer_disconnect(5, false);
	do_test_drop_messages_peer_disconnect(6, false);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_channel_ready_without_best_block_updated() {
	// Previously, if we were offline when a funding transaction was locked in, and then we came
	// back online, calling best_block_updated once followed by transactions_confirmed, we'd not
	// generate a channel_ready until a later best_block_updated. This tests that we generate the
	// channel_ready immediately instead.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	*nodes[0].connect_style.borrow_mut() = ConnectStyle::BestBlockFirstSkippingBlocks;

	let funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);

	let conf_height = nodes[0].best_block_info().1 + 1;
	connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH);
	let block_txn = [funding_tx];
	let conf_txn: Vec<_> = block_txn.iter().enumerate().collect();
	let conf_block_header = nodes[0].get_block_header(conf_height);
	nodes[0].node.transactions_confirmed(&conf_block_header, &conf_txn[..], conf_height);

	// Ensure nodes[0] generates a channel_ready after the transactions_confirmed
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_b_id);
	nodes[1].node.handle_channel_ready(node_a_id, &as_channel_ready);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_channel_monitor_skipping_block_when_channel_manager_is_leading() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Let channel_manager get ahead of chain_monitor by 1 block.
	// This is to emulate race-condition where newly added channel_monitor skips processing 1 block,
	// in case where client calls block_connect on channel_manager first and then on chain_monitor.
	let height_1 = nodes[0].best_block_info().1 + 1;
	let mut block_1 = create_dummy_block(nodes[0].best_block_hash(), height_1, Vec::new());

	nodes[0].blocks.lock().unwrap().push((block_1.clone(), height_1));
	nodes[0].node.block_connected(&block_1, height_1);

	// Create channel, and it gets added to chain_monitor in funding_created.
	let funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);

	// Now, newly added channel_monitor in chain_monitor hasn't processed block_1,
	// but it's best_block is block_1, since that was populated by channel_manager, and channel_manager
	// was running ahead of chain_monitor at the time of funding_created.
	// Later on, subsequent blocks are connected to both channel_manager and chain_monitor.
	// Hence, this channel's channel_monitor skipped block_1, directly tries to process subsequent blocks.
	confirm_transaction_at(&nodes[0], &funding_tx, nodes[0].best_block_info().1 + 1);
	connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH);

	// Ensure nodes[0] generates a channel_ready after the transactions_confirmed
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_b_id);
	nodes[1].node.handle_channel_ready(node_a_id, &as_channel_ready);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_channel_monitor_skipping_block_when_channel_manager_is_lagging() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Let chain_monitor get ahead of channel_manager by 1 block.
	// This is to emulate race-condition where newly added channel_monitor skips processing 1 block,
	// in case where client calls block_connect on chain_monitor first and then on channel_manager.
	let height_1 = nodes[0].best_block_info().1 + 1;
	let mut block_1 = create_dummy_block(nodes[0].best_block_hash(), height_1, Vec::new());

	nodes[0].blocks.lock().unwrap().push((block_1.clone(), height_1));
	nodes[0].chain_monitor.chain_monitor.block_connected(&block_1, height_1);

	// Create channel, and it gets added to chain_monitor in funding_created.
	let funding_tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 0);

	// channel_manager can't really skip block_1, it should get it eventually.
	nodes[0].node.block_connected(&block_1, height_1);

	// Now, newly added channel_monitor in chain_monitor hasn't processed block_1, it's best_block is
	// the block before block_1, since that was populated by channel_manager, and channel_manager was
	// running behind at the time of funding_created.
	// Later on, subsequent blocks are connected to both channel_manager and chain_monitor.
	// Hence, this channel's channel_monitor skipped block_1, directly tries to process subsequent blocks.
	confirm_transaction_at(&nodes[0], &funding_tx, nodes[0].best_block_info().1 + 1);
	connect_blocks(&nodes[0], CHAN_CONFIRM_DEPTH);

	// Ensure nodes[0] generates a channel_ready after the transactions_confirmed
	let as_channel_ready = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, node_b_id);
	nodes[1].node.handle_channel_ready(node_a_id, &as_channel_ready);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_drop_messages_peer_disconnect_dual_htlc() {
	// Test that we can handle reconnecting when both sides of a channel have pending
	// commitment_updates when we disconnect.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage_1, payment_hash_1, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Now try to send a second payment which will fail to send
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	let onion = RecipientOnionFields::secret_only(payment_secret_2);
	let id = PaymentId(payment_hash_2.0);
	nodes[0].node.send_payment_with_route(route, payment_hash_2, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let events_1 = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events_1.len(), 1);
	match events_1[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}

	nodes[1].node.claim_funds(payment_preimage_1);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);
	check_added_monitors(&nodes[1], 1);

	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	match events_2.remove(0) {
		MessageSendEvent::UpdateHTLCs {
			ref node_id,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					mut update_fulfill_htlcs,
					ref update_fail_htlcs,
					ref update_fail_malformed_htlcs,
					ref update_fee,
					ref commitment_signed,
				},
			..
		} => {
			assert_eq!(*node_id, node_a_id);
			assert!(update_add_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());

			nodes[0].node.handle_update_fulfill_htlc(node_b_id, update_fulfill_htlcs.remove(0));
			let events_3 = nodes[0].node.get_and_clear_pending_events();
			assert_eq!(events_3.len(), 1);
			match events_3[0] {
				Event::PaymentSent { ref payment_preimage, ref payment_hash, .. } => {
					assert_eq!(*payment_preimage, payment_preimage_1);
					assert_eq!(*payment_hash, payment_hash_1);
				},
				_ => panic!("Unexpected event"),
			}

			nodes[0].node.handle_commitment_signed_batch_test(node_b_id, commitment_signed);
			let _ = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
			// No commitment_signed so get_event_msg's assert(len == 1) passes
			check_added_monitors(&nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};

	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	nodes[0].node.handle_channel_reestablish(node_b_id, &reestablish_2[0]);
	let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(node_a_id, &reestablish_1[0]);
	let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	assert!(as_resp.0.is_none());
	assert!(bs_resp.0.is_none());

	assert!(bs_resp.1.is_none());
	assert!(bs_resp.2.is_none());

	assert!(as_resp.3 == RAACommitmentOrder::CommitmentFirst);

	assert_eq!(as_resp.2.as_ref().unwrap().update_add_htlcs.len(), 1);
	assert!(as_resp.2.as_ref().unwrap().update_fulfill_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fail_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fail_malformed_htlcs.is_empty());
	assert!(as_resp.2.as_ref().unwrap().update_fee.is_none());
	nodes[1]
		.node
		.handle_update_add_htlc(node_a_id, &as_resp.2.as_ref().unwrap().update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(
		node_a_id,
		&as_resp.2.as_ref().unwrap().commitment_signed,
	);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, as_resp.1.as_ref().unwrap());
	let bs_second_commitment_signed = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(bs_second_commitment_signed.update_add_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fulfill_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fail_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fail_malformed_htlcs.is_empty());
	assert!(bs_second_commitment_signed.update_fee.is_none());
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_revoke_and_ack);
	let as_commitment_signed = get_htlc_update_msgs(&nodes[0], &node_b_id);
	assert!(as_commitment_signed.update_add_htlcs.is_empty());
	assert!(as_commitment_signed.update_fulfill_htlcs.is_empty());
	assert!(as_commitment_signed.update_fail_htlcs.is_empty());
	assert!(as_commitment_signed.update_fail_malformed_htlcs.is_empty());
	assert!(as_commitment_signed.update_fee.is_none());
	check_added_monitors(&nodes[0], 1);

	nodes[0].node.handle_commitment_signed_batch_test(
		node_b_id,
		&bs_second_commitment_signed.commitment_signed,
	);
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[0], 1);

	nodes[1]
		.node
		.handle_commitment_signed_batch_test(node_a_id, &as_commitment_signed.commitment_signed);
	let bs_second_revoke_and_ack =
		get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors(&nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 1);

	expect_and_process_pending_htlcs(&nodes[1], false);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 1);
	match events_5[0] {
		Event::PaymentClaimable { ref payment_hash, ref purpose, .. } => {
			assert_eq!(payment_hash_2, *payment_hash);
			match &purpose {
				PaymentPurpose::Bolt11InvoicePayment {
					payment_preimage, payment_secret, ..
				} => {
					assert!(payment_preimage.is_none());
					assert_eq!(payment_secret_2, *payment_secret);
				},
				_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment"),
			}
		},
		_ => panic!("Unexpected event"),
	}

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_second_revoke_and_ack);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[0], 1);

	expect_payment_path_successful!(nodes[0]);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

fn do_test_htlc_timeout(send_partial_mpp: bool) {
	// If the user fails to claim/fail an HTLC within the HTLC CLTV timeout we fail it for them
	// to avoid our counterparty failing the channel.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let our_payment_hash = if send_partial_mpp {
		let (route, our_payment_hash, _, payment_secret) =
			get_route_and_payment_hash!(&nodes[0], nodes[1], 100000);
		// Use the utility function send_payment_along_path to send the payment with MPP data which
		// indicates there are more HTLCs coming.
		let cur_height = CHAN_CONFIRM_DEPTH + 1; // route_payment calls send_payment, which adds 1 to the current height. So we do the same here to match.
		let payment_id = PaymentId([42; 32]);
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let session_privs = nodes[0]
			.node
			.test_add_new_pending_payment(our_payment_hash, onion, payment_id, &route)
			.unwrap();

		nodes[0]
			.node
			.test_send_payment_along_path(
				&route.paths[0],
				&our_payment_hash,
				RecipientOnionFields::secret_only(payment_secret),
				200_000,
				cur_height,
				payment_id,
				&None,
				session_privs[0],
			)
			.unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		// Now do the relevant commitment_signed/RAA dances along the path, noting that the final
		// hop should *not* yet generate any PaymentClaimable event(s).
		pass_along_path(
			&nodes[0],
			&[&nodes[1]],
			100000,
			our_payment_hash,
			Some(payment_secret),
			events.drain(..).next().unwrap(),
			false,
			None,
		);
		our_payment_hash
	} else {
		route_payment(&nodes[0], &[&nodes[1]], 100000).1
	};

	let mut block = create_dummy_block(nodes[0].best_block_hash(), 42, Vec::new());
	connect_block(&nodes[0], &block);
	connect_block(&nodes[1], &block);
	let block_count =
		TEST_FINAL_CLTV + CHAN_CONFIRM_DEPTH + 2 - CLTV_CLAIM_BUFFER - LATENCY_GRACE_PERIOD_BLOCKS;
	for _ in CHAN_CONFIRM_DEPTH + 2..block_count {
		block.header.prev_blockhash = block.block_hash();
		connect_block(&nodes[0], &block);
		connect_block(&nodes[1], &block);
	}

	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Receive { payment_hash: our_payment_hash }],
	);

	check_added_monitors(&nodes[1], 1);
	let htlc_timeout_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(htlc_timeout_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_timeout_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_timeout_updates.update_fail_malformed_htlcs.is_empty());
	assert!(htlc_timeout_updates.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(node_b_id, &htlc_timeout_updates.update_fail_htlcs[0]);
	let commitment = &htlc_timeout_updates.commitment_signed;
	do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
	// 100_000 msat as u64, followed by the height at which we failed back above
	let mut expected_failure_data = (100_000 as u64).to_be_bytes().to_vec();
	expected_failure_data.extend_from_slice(&(block_count - 1).to_be_bytes());
	let reason = LocalHTLCFailureReason::IncorrectPaymentDetails;
	expect_payment_failed!(nodes[0], our_payment_hash, true, reason, &expected_failure_data[..]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_htlc_timeout() {
	do_test_htlc_timeout(true);
	do_test_htlc_timeout(false);
}

fn do_test_holding_cell_htlc_add_timeouts(forwarded_htlc: bool) {
	// Tests that HTLCs in the holding cell are timed out after the requisite number of blocks.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Make sure all nodes are at the same starting height
	connect_blocks(&nodes[0], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], 2 * CHAN_CONFIRM_DEPTH + 1 - nodes[2].best_block_info().1);

	// Route a first payment to get the 1 -> 2 channel in awaiting_raa...
	let (route, first_payment_hash, _, first_payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[2], 100000);
	let onion = RecipientOnionFields::secret_only(first_payment_secret);
	let id = PaymentId(first_payment_hash.0);
	nodes[1].node.send_payment_with_route(route, first_payment_hash, onion, id).unwrap();
	assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 1);
	check_added_monitors(&nodes[1], 1);

	// Now attempt to route a second payment, which should be placed in the holding cell
	let sending_node = if forwarded_htlc { &nodes[0] } else { &nodes[1] };
	let (route, second_payment_hash, _, second_payment_secret) =
		get_route_and_payment_hash!(sending_node, nodes[2], 100000);
	let onion = RecipientOnionFields::secret_only(second_payment_secret);
	let id = PaymentId(second_payment_hash.0);
	sending_node.node.send_payment_with_route(route, second_payment_hash, onion, id).unwrap();

	if forwarded_htlc {
		check_added_monitors(&nodes[0], 1);
		let payment_event =
			SendEvent::from_event(nodes[0].node.get_and_clear_pending_msg_events().remove(0));
		nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
		let commitment = &payment_event.commitment_msg;
		do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);
		expect_and_process_pending_htlcs(&nodes[1], false);
	}
	check_added_monitors(&nodes[1], 0);

	connect_blocks(&nodes[1], TEST_FINAL_CLTV - LATENCY_GRACE_PERIOD_BLOCKS);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	connect_blocks(&nodes[1], 1);

	if forwarded_htlc {
		let fail_type =
			HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[fail_type]);
		check_added_monitors(&nodes[1], 1);
		let fail_commit = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(fail_commit.len(), 1);
		match fail_commit[0] {
			MessageSendEvent::UpdateHTLCs {
				updates: msgs::CommitmentUpdate { ref update_fail_htlcs, ref commitment_signed, .. },
				..
			} => {
				nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlcs[0]);
				do_commitment_signed_dance(&nodes[0], &nodes[1], commitment_signed, true, true);
			},
			_ => unreachable!(),
		}
		let scid = chan_2.0.contents.short_channel_id;
		expect_payment_failed_with_update!(nodes[0], second_payment_hash, false, scid, false);
	} else {
		expect_payment_failed!(nodes[1], second_payment_hash, false);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_holding_cell_htlc_add_timeouts() {
	do_test_holding_cell_htlc_add_timeouts(false);
	do_test_holding_cell_htlc_add_timeouts(true);
}

macro_rules! check_spendable_outputs {
	($node: expr, $keysinterface: expr) => {{
		let mut events = $node.chain_monitor.chain_monitor.get_and_clear_pending_events();
		let mut txn = Vec::new();
		let mut all_outputs = Vec::new();
		let secp_ctx = Secp256k1::new();
		for event in events.drain(..) {
			match event {
				Event::SpendableOutputs { mut outputs, channel_id: _ } => {
					for outp in outputs.drain(..) {
						let script =
							Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script();
						let tx = $keysinterface.backing.spend_spendable_outputs(
							&[&outp],
							Vec::new(),
							script,
							253,
							None,
							&secp_ctx,
						);
						txn.push(tx.unwrap());
						all_outputs.push(outp);
					}
				},
				_ => panic!("Unexpected event"),
			};
		}
		if all_outputs.len() > 1 {
			if let Ok(tx) = $keysinterface.backing.spend_spendable_outputs(
				&all_outputs.iter().map(|a| a).collect::<Vec<_>>(),
				Vec::new(),
				Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(),
				253,
				None,
				&secp_ctx,
			) {
				txn.push(tx);
			}
		}
		txn
	}};
}

#[xtest(feature = "_externalize_tests")]
pub fn test_claim_sizeable_push_msat() {
	// Incidentally test SpendableOutput event generation due to detection of to_local output on commitment tx
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 98_000_000);
	let message = "Channel force-closed".to_owned();
	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(&chan.2, &node_a_id, message.clone())
		.unwrap();
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3);
	assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

	mine_transaction(&nodes[1], &node_txn[0]);
	connect_blocks(&nodes[1], BREAKDOWN_TIMEOUT as u32 - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
	assert_eq!(spend_txn[0].input[0].sequence.0, BREAKDOWN_TIMEOUT as u32);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_claim_on_remote_sizeable_push_msat() {
	// Same test as previous, just test on remote commitment tx, as per_commitment_point registration changes following you're funder/fundee and
	// to_remote output is encumbered by a P2WPKH
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let message = "Channel force-closed".to_owned();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 98_000_000);
	nodes[0]
		.node
		.force_close_broadcasting_latest_txn(&chan.2, &node_b_id, message.clone())
		.unwrap();
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);

	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan.3);
	assert_eq!(node_txn[0].output.len(), 2); // We can't force trimming of to_remote output as channel_reserve_satoshis block us to do so at channel opening

	mine_transaction(&nodes[1], &node_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_claim_on_remote_revoked_sizeable_push_msat() {
	// Same test as previous, just test on remote revoked commitment tx, as per_commitment_point registration changes following you're funder/fundee and
	// to_remote output is encumbered by a P2WPKH

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 59000000);
	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	mine_transaction(&nodes[1], &node_txn[0]);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], revoked_local_txn[0]); // to_remote output on revoked remote commitment_tx
	check_spends!(spend_txn[1], node_txn[0]);
	check_spends!(spend_txn[2], revoked_local_txn[0], node_txn[0]); // Both outputs
}

#[xtest(feature = "_externalize_tests")]
pub fn test_static_spendable_outputs_preimage_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);

	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(commitment_tx[0].input.len(), 1);
	assert_eq!(commitment_tx[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	// Settle A's commitment tx on B's chain
	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, 3_000_000);
	check_added_monitors(&nodes[1], 1);
	mine_transaction(&nodes[1], &commitment_tx[0]);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[2] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}
	check_added_monitors(&nodes[1], 1);

	// Check B's monitor was able to send back output descriptor event for preimage tx on A's commitment tx
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelMonitor: preimage tx
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], commitment_tx[0]);
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);

	mine_transaction(&nodes[1], &node_txn[0]);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_static_spendable_outputs_timeout_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Rebalance the network a bit by relaying one payment through all the channels ...
	send_payment(&nodes[0], &[&nodes[1]], 8000000);

	let (_, our_payment_hash, ..) = route_payment(&nodes[1], &[&nodes[0]], 3_000_000);

	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(commitment_tx[0].input.len(), 1);
	assert_eq!(commitment_tx[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	// Settle A's commitment tx on B' chain
	mine_transaction(&nodes[1], &commitment_tx[0]);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors(&nodes[1], 1);
	connect_blocks(&nodes[1], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	// Check B's monitor was able to send back output descriptor event for timeout tx on A's commitment tx
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 1); // ChannelMonitor: timeout tx
	check_spends!(node_txn[0], commitment_tx[0].clone());
	assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);

	mine_transaction(&nodes[1], &node_txn[0]);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	let conditions = PaymentFailedConditions::new().from_mon_update();
	expect_payment_failed_conditions(&nodes[1], our_payment_hash, false, conditions);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 3); // SpendableOutput: remote_commitment_tx.to_remote, timeout_tx.output
	check_spends!(spend_txn[0], commitment_tx[0]);
	check_spends!(spend_txn[1], node_txn[0]);
	check_spends!(spend_txn[2], node_txn[0], commitment_tx[0]); // All outputs
}

fn do_test_static_spendable_outputs_justice_tx_revoked_commitment_tx(split_tx: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	if split_tx {
		connect_blocks(
			&nodes[1],
			TEST_FINAL_CLTV - COUNTERPARTY_CLAIMABLE_WITHIN_BLOCKS_PINNABLE + 1,
		);
	}

	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);

	// If the HTLC expires in more than COUNTERPARTY_CLAIMABLE_WITHIN_BLOCKS_PINNABLE blocks, we'll
	// claim both the revoked and HTLC outputs in one transaction, otherwise we'll split them as we
	// consider the HTLC output as pinnable and want to claim pinnable and unpinnable outputs
	// separately.
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), if split_tx { 2 } else { 1 });
	for tx in node_txn.iter() {
		assert_eq!(tx.input.len(), if split_tx { 1 } else { 2 });
		check_spends!(tx, revoked_local_txn[0]);
	}
	if split_tx {
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
	}

	mine_transaction(&nodes[1], &node_txn[0]);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_static_spendable_outputs_justice_tx_revoked_commitment_tx() {
	do_test_static_spendable_outputs_justice_tx_revoked_commitment_tx(true);
	do_test_static_spendable_outputs_justice_tx_revoked_commitment_tx(false);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_static_spendable_outputs_justice_tx_revoked_htlc_timeout_tx() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	// A will generate HTLC-Timeout from revoked commitment tx
	mine_transaction(&nodes[0], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	let revoked_htlc_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(revoked_htlc_txn.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input.len(), 1);
	assert_eq!(
		revoked_htlc_txn[0].input[0].witness.last().unwrap().len(),
		OFFERED_HTLC_SCRIPT_WEIGHT
	);
	check_spends!(revoked_htlc_txn[0], revoked_local_txn[0]);
	assert_ne!(revoked_htlc_txn[0].lock_time, LockTime::ZERO); // HTLC-Timeout

	// In order to connect `revoked_htlc_txn[0]` we must first advance the chain by
	// `TEST_FINAL_CLTV` blocks as otherwise the transaction is consensus-invalid due to its
	// locktime.
	connect_blocks(&nodes[1], TEST_FINAL_CLTV);
	// B will generate justice tx from A's revoked commitment/HTLC tx
	let txn = vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()];
	connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, txn));
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);

	// There will be 2 justice transactions:
	// - One on the unpinnable, revoked to_self output on the commitment transaction and on
	//   the unpinnable, revoked to_self output on the HTLC-timeout transaction.
	// - One on the pinnable, revoked HTLC output on the commitment transaction.
	// The latter transaction will become out-of-date as it spends the output already spent by
	// revoked_htlc_txn[0]. That's OK, we'll spend with valid transactions next.
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 2);
	assert_eq!(node_txn[0].input.len(), 2);
	check_spends!(node_txn[0], revoked_local_txn[0], revoked_htlc_txn[0]);
	assert_ne!(node_txn[0].input[0].previous_output, node_txn[0].input[1].previous_output);

	assert_eq!(node_txn[1].input.len(), 1);
	check_spends!(node_txn[1], revoked_local_txn[0]);
	assert_eq!(node_txn[1].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
	assert_ne!(node_txn[0].input[1].previous_output, node_txn[1].input[0].previous_output);

	mine_transaction(&nodes[1], &node_txn[0]);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	// Check B's ChannelMonitor was able to generate the right spendable output descriptor
	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], node_txn[0]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_static_spendable_outputs_justice_tx_revoked_htlc_success_tx() {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 3000000).0;
	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan_1.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan_1.3.compute_txid());

	// The to-be-revoked commitment tx should have one HTLC and one to_remote output
	assert_eq!(revoked_local_txn[0].output.len(), 2);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	// B will generate HTLC-Success from revoked commitment tx
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	let revoked_htlc_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();

	assert_eq!(revoked_htlc_txn.len(), 1);
	assert_eq!(revoked_htlc_txn[0].input.len(), 1);
	assert_eq!(
		revoked_htlc_txn[0].input[0].witness.last().unwrap().len(),
		ACCEPTED_HTLC_SCRIPT_WEIGHT
	);
	check_spends!(revoked_htlc_txn[0], revoked_local_txn[0]);

	// Check that the unspent (of two) outputs on revoked_local_txn[0] is a P2WPKH:
	let unspent_local_txn_output = revoked_htlc_txn[0].input[0].previous_output.vout as usize ^ 1;
	assert_eq!(revoked_local_txn[0].output[unspent_local_txn_output].script_pubkey.len(), 2 + 20); // P2WPKH

	// A will generate justice tx from B's revoked commitment/HTLC tx
	let txn = vec![revoked_local_txn[0].clone(), revoked_htlc_txn[0].clone()];
	connect_block(&nodes[0], &create_dummy_block(nodes[0].best_block_hash(), 42, txn));
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);

	// There will be 2 justice transactions, one on the revoked HTLC output on the commitment
	// transaction, and one on the revoked to_self output on the HTLC-success transaction.
	let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(node_txn.len(), 2);

	// The first transaction generated will become out-of-date as it spends the output already spent
	// by revoked_htlc_txn[0]. That's OK, we'll spend with valid transactions next...
	assert_eq!(node_txn[0].input.len(), 1);
	check_spends!(node_txn[0], revoked_local_txn[0]);
	assert_eq!(node_txn[1].input.len(), 1);
	check_spends!(node_txn[1], revoked_htlc_txn[0]);

	mine_transaction(&nodes[0], &node_txn[1]);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);

	// Note that nodes[0]'s tx_broadcaster is still locked, so if we get here the channelmonitor
	// didn't try to generate any new transactions.

	// Check A's ChannelMonitor was able to generate the right spendable output descriptor
	let spend_txn = check_spendable_outputs!(nodes[0], node_cfgs[0].keys_manager);
	assert_eq!(spend_txn.len(), 3);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], revoked_local_txn[0]); // spending to_remote output from revoked local tx
	assert_ne!(spend_txn[0].input[0].previous_output, revoked_htlc_txn[0].input[0].previous_output);
	check_spends!(spend_txn[1], node_txn[1]); // spending justice tx output on the htlc success tx
	check_spends!(spend_txn[2], revoked_local_txn[0], node_txn[1]); // Both outputs
}

#[xtest(feature = "_externalize_tests")]
pub fn test_onchain_to_onchain_claim() {
	// Test that in case of channel closure, we detect the state of output and claim HTLC
	// on downstream peer's remote commitment tx.
	// First, have C claim an HTLC against its own latest commitment transaction.
	// Then, broadcast these to B, which should update the monitor downstream on the A<->B
	// channel.
	// Finally, check that B will claim the HTLC output if A's latest commitment transaction
	// gets broadcast.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	// Ensure all nodes are at the same height
	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	// Rebalance the network a bit by relaying one payment through all the channels ...
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 8000000);
	send_payment(&nodes[0], &[&nodes[1], &nodes[2]], 8000000);

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);
	let commitment_tx = get_local_commitment_txn!(nodes[2], chan_2.2);
	check_spends!(commitment_tx[0], chan_2.3);
	nodes[2].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[2], payment_hash, 3_000_000);
	check_added_monitors(&nodes[2], 1);
	let updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());

	mine_transaction(&nodes[2], &commitment_tx[0]);
	check_closed_broadcast!(nodes[2], true);
	check_added_monitors(&nodes[2], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[2], 1, reason, &[node_b_id], 100000);

	let c_txn = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone(); // ChannelMonitor: 1 (HTLC-Success tx)
	assert_eq!(c_txn.len(), 1);
	check_spends!(c_txn[0], commitment_tx[0]);
	assert_eq!(
		c_txn[0].input[0].witness.clone().last().unwrap().len(),
		ACCEPTED_HTLC_SCRIPT_WEIGHT
	);
	assert!(c_txn[0].output[0].script_pubkey.is_p2wsh()); // revokeable output
	assert_eq!(c_txn[0].lock_time, LockTime::ZERO); // Success tx

	// So we broadcast C's commitment tx and HTLC-Success on B's chain, we should successfully be able to extract preimage and update downstream monitor
	let txn = vec![commitment_tx[0].clone(), c_txn[0].clone()];
	connect_block(&nodes[1], &create_dummy_block(nodes[1].best_block_hash(), 42, txn));
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		Event::PaymentForwarded {
			total_fee_earned_msat,
			prev_channel_id,
			claim_from_onchain_tx,
			next_channel_id,
			outbound_amount_forwarded_msat,
			..
		} => {
			assert_eq!(total_fee_earned_msat, Some(1000));
			assert_eq!(prev_channel_id, Some(chan_1.2));
			assert_eq!(claim_from_onchain_tx, true);
			assert_eq!(next_channel_id, Some(chan_2.2));
			assert_eq!(outbound_amount_forwarded_msat, Some(3000000));
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {},
		_ => panic!("Unexpected event"),
	}
	check_added_monitors(&nodes[1], 2);
	let mut msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3);
	let nodes_2_event = remove_first_msg_event_to_node(&node_c_id, &mut msg_events);
	let nodes_0_event = remove_first_msg_event_to_node(&node_a_id, &mut msg_events);

	match nodes_2_event {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { .. },
			node_id: _,
		} => {},
		_ => panic!("Unexpected event"),
	}

	match nodes_0_event {
		MessageSendEvent::UpdateHTLCs {
			ref node_id,
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_htlcs,
					ref update_fail_malformed_htlcs,
					..
				},
			..
		} => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fail_htlcs.is_empty());
			assert_eq!(update_fulfill_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert_eq!(node_a_id, *node_id);
		},
		_ => panic!("Unexpected event"),
	};

	// Ensure that the last remaining message event is the BroadcastChannelUpdate msg for chan_2
	match msg_events[0] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexpected event"),
	}

	// Broadcast A's commitment tx on B's chain to see if we are able to claim inbound HTLC with our HTLC-Success tx
	let commitment_tx = get_local_commitment_txn!(nodes[0], chan_1.2);
	mine_transaction(&nodes[1], &commitment_tx[0]);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	let b_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	// ChannelMonitor: HTLC-Success tx
	assert_eq!(b_txn.len(), 1);
	check_spends!(b_txn[0], commitment_tx[0]);
	assert_eq!(b_txn[0].input[0].witness.clone().last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert!(b_txn[0].output[0].script_pubkey.is_p2wpkh()); // direct payment
	assert_eq!(b_txn[0].lock_time.to_consensus_u32(), nodes[1].best_block_info().1); // Success tx

	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_duplicate_payment_hash_one_failure_one_success() {
	// Topology : A --> B --> C --> D
	//                          \-> E
	// We route 2 payments with same hash between B and C, one we will time out on chain, the other
	// successfully claim.
	let chanmon_cfgs = create_chanmon_cfgs(5);
	let node_cfgs = create_node_cfgs(5, &chanmon_cfgs);
	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 196;

	let configs = [
		Some(config.clone()),
		Some(config.clone()),
		Some(config.clone()),
		Some(config.clone()),
		Some(config.clone()),
	];
	let node_chanmgrs = create_node_chanmgrs(5, &node_cfgs, &configs);
	let mut nodes = create_network(5, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_e_id = nodes[4].node.get_our_node_id();

	// Create the required channels and route one HTLC from A to D and another from A to E.
	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	create_announced_chan_between_nodes(&nodes, 2, 3);
	create_announced_chan_between_nodes(&nodes, 2, 4);

	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height * 2 - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height * 2 - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height * 2 - nodes[2].best_block_info().1);
	connect_blocks(&nodes[3], node_max_height * 2 - nodes[3].best_block_info().1);
	connect_blocks(&nodes[4], node_max_height * 2 - nodes[4].best_block_info().1);

	let (our_payment_preimage, dup_payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2], &nodes[3]], 900_000);

	let payment_secret =
		nodes[4].node.create_inbound_payment_for_hash(dup_payment_hash, None, 7200, None).unwrap();
	let payment_params = PaymentParameters::from_node_id(node_e_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[4].node.bolt11_invoice_features())
		.unwrap();
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[4], payment_params, 800_000);
	let path: &[&[_]] = &[&[&nodes[1], &nodes[2], &nodes[4]]];
	send_along_route_with_secret(&nodes[0], route, path, 800_000, dup_payment_hash, payment_secret);

	// Now mine C's commitment transaction on node B and mine enough blocks to get the HTLC timeout
	// transaction (which we'll split in two so that we can resolve the HTLCs differently).
	let commitment_txn = get_local_commitment_txn!(nodes[2], chan_2.2);
	assert_eq!(commitment_txn[0].input.len(), 1);
	assert_eq!(commitment_txn[0].output.len(), 3);
	check_spends!(commitment_txn[0], chan_2.3);

	mine_transaction(&nodes[1], &commitment_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100000);

	// Confirm blocks until both HTLCs expire and get a transaction which times out one HTLC.
	connect_blocks(&nodes[1], TEST_FINAL_CLTV + config.channel_config.cltv_expiry_delta as u32);

	let htlc_timeout_tx = {
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);

		let mut tx = node_txn.pop().unwrap();
		check_spends!(tx, commitment_txn[0]);
		assert_eq!(tx.input.len(), 2);
		assert_eq!(tx.output.len(), 1);
		// Note that the witness script lengths are one longer than our constant as the CLTV value
		// went to two bytes rather than one.
		assert_eq!(tx.input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT + 1);
		assert_eq!(tx.input[1].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT + 1);

		// Split the HTLC claim transaction into two, one for each HTLC.
		if commitment_txn[0].output[tx.input[1].previous_output.vout as usize].value.to_sat() < 850
		{
			tx.input.remove(1);
		}
		if commitment_txn[0].output[tx.input[0].previous_output.vout as usize].value.to_sat() < 850
		{
			tx.input.remove(0);
		}
		assert_eq!(tx.input.len(), 1);
		tx
	};

	// Now give node E the payment preimage and pass it back to C.
	nodes[4].node.claim_funds(our_payment_preimage);
	expect_payment_claimed!(nodes[4], dup_payment_hash, 800_000);
	check_added_monitors(&nodes[4], 1);
	let mut updates = get_htlc_update_msgs(&nodes[4], &node_c_id);
	nodes[2].node.handle_update_fulfill_htlc(node_e_id, updates.update_fulfill_htlcs.remove(0));
	let _cs_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	expect_payment_forwarded!(nodes[2], nodes[1], nodes[4], Some(196), false, false);
	check_added_monitors(&nodes[2], 1);
	do_commitment_signed_dance(&nodes[2], &nodes[4], &updates.commitment_signed, false, false);

	// Mine the commitment transaction on node C and get the HTLC success transactions it will
	// generate (note that the ChannelMonitor doesn't differentiate between HTLCs once it has the
	// preimage).
	mine_transaction(&nodes[2], &commitment_txn[0]);
	check_closed_broadcast(&nodes[2], 1, true);
	check_added_monitors(&nodes[2], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[2], 1, reason, &[node_b_id], 100000);

	let htlc_success_txn: Vec<_> = nodes[2].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(htlc_success_txn.len(), 2); // ChannelMonitor: HTLC-Success txn (*2 due to 2-HTLC outputs)
	check_spends!(htlc_success_txn[0], commitment_txn[0]);
	check_spends!(htlc_success_txn[1], commitment_txn[0]);
	assert_eq!(htlc_success_txn[0].input.len(), 1);
	// Note that the witness script lengths are one longer than our constant as the CLTV value went
	// to two bytes rather than one.
	assert_eq!(
		htlc_success_txn[0].input[0].witness.last().unwrap().len(),
		ACCEPTED_HTLC_SCRIPT_WEIGHT + 1
	);
	assert_eq!(htlc_success_txn[1].input.len(), 1);
	assert_eq!(
		htlc_success_txn[1].input[0].witness.last().unwrap().len(),
		ACCEPTED_HTLC_SCRIPT_WEIGHT + 1
	);
	assert_ne!(
		htlc_success_txn[0].input[0].previous_output,
		htlc_success_txn[1].input[0].previous_output
	);

	let htlc_success_tx_to_confirm = if htlc_success_txn[0].input[0].previous_output
		== htlc_timeout_tx.input[0].previous_output
	{
		&htlc_success_txn[1]
	} else {
		&htlc_success_txn[0]
	};
	assert_ne!(
		htlc_success_tx_to_confirm.input[0].previous_output,
		htlc_timeout_tx.input[0].previous_output
	);

	// Mine the HTLC timeout transaction on node B.
	mine_transaction(&nodes[1], &htlc_timeout_tx);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }],
	);
	let htlc_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	let first_htlc_id = htlc_updates.update_fail_htlcs[0].htlc_id;
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_update_fail_htlc(node_b_id, &htlc_updates.update_fail_htlcs[0]);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	do_commitment_signed_dance(&nodes[0], &nodes[1], &htlc_updates.commitment_signed, false, true);
	let failing_scid = chan_2.0.contents.short_channel_id;
	expect_payment_failed_with_update!(nodes[0], dup_payment_hash, false, failing_scid, true);

	// Finally, give node B the HTLC success transaction and ensure it extracts the preimage to
	// provide to node A.
	mine_transaction(&nodes[1], htlc_success_tx_to_confirm);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(392), true, true);
	let mut updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	assert_ne!(updates.update_fulfill_htlcs[0].htlc_id, first_htlc_id);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_sent(&nodes[0], our_payment_preimage, None, true, true);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_dynamic_spendable_outputs_local_htlc_success_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 9_000_000);
	let local_txn = get_local_commitment_txn!(nodes[1], chan_1.2);
	assert_eq!(local_txn.len(), 1);
	assert_eq!(local_txn[0].input.len(), 1);
	check_spends!(local_txn[0], chan_1.3);

	// Give B knowledge of preimage to be able to generate a local HTLC-Success Tx
	nodes[1].node.claim_funds(payment_preimage);
	expect_payment_claimed!(nodes[1], payment_hash, 9_000_000);
	check_added_monitors(&nodes[1], 1);

	mine_transaction(&nodes[1], &local_txn[0]);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::UpdateHTLCs { .. } => {},
		_ => panic!("Unexpected event"),
	}
	match events[2] {
		MessageSendEvent::BroadcastChannelUpdate { .. } => {},
		_ => panic!("Unexepected event"),
	}
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	let node_tx = {
		let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		node_txn[0].clone()
	};

	mine_transaction(&nodes[1], &node_tx);
	connect_blocks(&nodes[1], BREAKDOWN_TIMEOUT as u32 - 1);

	// Verify that B is able to spend its own HTLC-Success tx thanks to spendable output event given back by its ChannelMonitor
	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	assert_eq!(spend_txn[0].input.len(), 1);
	check_spends!(spend_txn[0], node_tx);
	assert_eq!(spend_txn[0].input[0].sequence.0, BREAKDOWN_TIMEOUT as u32);
}

fn do_test_fail_backwards_unrevoked_remote_announce(deliver_last_raa: bool, announce_latest: bool) {
	// Test that we fail backwards the full set of HTLCs we need to when remote broadcasts an
	// unrevoked commitment transaction.
	// This includes HTLCs which were below the dust threshold as well as HTLCs which were awaiting
	// a remote RAA before they could be failed backwards (and combinations thereof).
	// We also test duplicate-hash HTLCs by adding two nodes on each side of the target nodes which
	// use the same payment hashes.
	// Thus, we use a six-node network:
	//
	// A \         / E
	//    - C - D -
	// B /         \ F
	// And test where C fails back to A/B when D announces its latest commitment transaction
	let chanmon_cfgs = create_chanmon_cfgs(6);
	let node_cfgs = create_node_cfgs(6, &chanmon_cfgs);
	// When this test was written, the default base fee floated based on the HTLC count.
	// It is now fixed, so we simply set the fee to the expected value here.
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 196;

	let configs = [
		Some(config.clone()),
		Some(config.clone()),
		Some(config.clone()),
		Some(config.clone()),
		Some(config.clone()),
		Some(config.clone()),
	];
	let node_chanmgrs = create_node_chanmgrs(6, &node_cfgs, &configs);
	let nodes = create_network(6, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();
	let node_e_id = nodes[4].node.get_our_node_id();
	let node_f_id = nodes[5].node.get_our_node_id();

	let _chan_0_2 = create_announced_chan_between_nodes(&nodes, 0, 2);
	let _chan_1_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let chan_2_3 = create_announced_chan_between_nodes(&nodes, 2, 3);
	let chan_3_4 = create_announced_chan_between_nodes(&nodes, 3, 4);
	let chan_3_5 = create_announced_chan_between_nodes(&nodes, 3, 5);

	// Rebalance and check output sanity...
	send_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 500000);
	send_payment(&nodes[1], &[&nodes[2], &nodes[3], &nodes[5]], 500000);
	assert_eq!(get_local_commitment_txn!(nodes[3], chan_2_3.2)[0].output.len(), 2);

	let dust_limit_msat = {
		let per_peer_state_lock;
		let mut peer_state_lock;
		let chan =
			get_channel_ref!(nodes[3], nodes[2], per_peer_state_lock, peer_state_lock, chan_2_3.2);
		chan.context().holder_dust_limit_satoshis * 1000
	};

	// 0th HTLC (not added - smaller than dust limit + HTLC tx fee):
	let path_4: &[_] = &[&nodes[2], &nodes[3], &nodes[4]];
	let (_, hash_1, ..) = route_payment(&nodes[0], path_4, dust_limit_msat);

	// 1st HTLC (not added - smaller than dust limit + HTLC tx fee):
	let (_, hash_2, ..) = route_payment(&nodes[0], path_4, dust_limit_msat);
	let (route_to_5, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[5], dust_limit_msat);

	// 2nd HTLC (not added - smaller than dust limit + HTLC tx fee):
	let path_5: &[&[_]] = &[&[&nodes[2], &nodes[3], &nodes[5]]];
	let payment_secret =
		nodes[5].node.create_inbound_payment_for_hash(hash_1, None, 7200, None).unwrap();
	let route = route_to_5.clone();
	send_along_route_with_secret(&nodes[1], route, path_5, dust_limit_msat, hash_1, payment_secret);

	// 3rd HTLC (not added - smaller than dust limit + HTLC tx fee):
	let payment_secret =
		nodes[5].node.create_inbound_payment_for_hash(hash_2, None, 7200, None).unwrap();
	let route = route_to_5;
	send_along_route_with_secret(&nodes[1], route, path_5, dust_limit_msat, hash_2, payment_secret);

	// 4th HTLC:
	let (_, hash_3, ..) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);

	// 5th HTLC:
	let (_, hash_4, ..) = route_payment(&nodes[0], &[&nodes[2], &nodes[3], &nodes[4]], 1000000);
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[5], 1000000);

	// 6th HTLC:
	let payment_secret =
		nodes[5].node.create_inbound_payment_for_hash(hash_3, None, 7200, None).unwrap();
	send_along_route_with_secret(&nodes[1], route.clone(), path_5, 1000000, hash_3, payment_secret);

	// 7th HTLC:
	let payment_secret =
		nodes[5].node.create_inbound_payment_for_hash(hash_4, None, 7200, None).unwrap();
	send_along_route_with_secret(&nodes[1], route, path_5, 1000000, hash_4, payment_secret);

	// 8th HTLC:
	let (_, hash_5, ..) = route_payment(&nodes[0], path_4, 1000000);

	// 9th HTLC (not added - smaller than dust limit + HTLC tx fee):
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[5], dust_limit_msat);
	let payment_secret =
		nodes[5].node.create_inbound_payment_for_hash(hash_5, None, 7200, None).unwrap();
	send_along_route_with_secret(&nodes[1], route, path_5, dust_limit_msat, hash_5, payment_secret);

	// 10th HTLC (not added - smaller than dust limit + HTLC tx fee):
	let (_, hash_6, ..) = route_payment(&nodes[0], path_4, dust_limit_msat);

	// 11th HTLC:
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[5], 1000000);
	let payment_secret =
		nodes[5].node.create_inbound_payment_for_hash(hash_6, None, 7200, None).unwrap();
	send_along_route_with_secret(&nodes[1], route, path_5, 1000000, hash_6, payment_secret);

	// Double-check that six of the new HTLC were added
	// We now have six HTLCs pending over the dust limit and six HTLCs under the dust limit (ie,
	// with to_local and to_remote outputs, 8 outputs and 6 HTLCs not included).
	assert_eq!(get_local_commitment_txn!(nodes[3], chan_2_3.2).len(), 1);
	assert_eq!(get_local_commitment_txn!(nodes[3], chan_2_3.2)[0].output.len(), 8);

	// Now fail back three of the over-dust-limit and three of the under-dust-limit payments in one go.
	// Fail 0th below-dust, 4th above-dust, 8th above-dust, 10th below-dust HTLCs
	nodes[4].node.fail_htlc_backwards(&hash_1);
	nodes[4].node.fail_htlc_backwards(&hash_3);
	nodes[4].node.fail_htlc_backwards(&hash_5);
	nodes[4].node.fail_htlc_backwards(&hash_6);
	check_added_monitors(&nodes[4], 0);

	let failed_destinations = vec![
		HTLCHandlingFailureType::Receive { payment_hash: hash_1 },
		HTLCHandlingFailureType::Receive { payment_hash: hash_3 },
		HTLCHandlingFailureType::Receive { payment_hash: hash_5 },
		HTLCHandlingFailureType::Receive { payment_hash: hash_6 },
	];
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[4], &failed_destinations);
	check_added_monitors(&nodes[4], 1);

	let four_removes = get_htlc_update_msgs(&nodes[4], &node_d_id);
	nodes[3].node.handle_update_fail_htlc(node_e_id, &four_removes.update_fail_htlcs[0]);
	nodes[3].node.handle_update_fail_htlc(node_e_id, &four_removes.update_fail_htlcs[1]);
	nodes[3].node.handle_update_fail_htlc(node_e_id, &four_removes.update_fail_htlcs[2]);
	nodes[3].node.handle_update_fail_htlc(node_e_id, &four_removes.update_fail_htlcs[3]);
	do_commitment_signed_dance(&nodes[3], &nodes[4], &four_removes.commitment_signed, false, false);

	// Fail 3rd below-dust and 7th above-dust HTLCs
	nodes[5].node.fail_htlc_backwards(&hash_2);
	nodes[5].node.fail_htlc_backwards(&hash_4);
	check_added_monitors(&nodes[5], 0);

	let failed_destinations_2 = vec![
		HTLCHandlingFailureType::Receive { payment_hash: hash_2 },
		HTLCHandlingFailureType::Receive { payment_hash: hash_4 },
	];
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[5], &failed_destinations_2);
	check_added_monitors(&nodes[5], 1);

	let two_removes = get_htlc_update_msgs(&nodes[5], &node_d_id);
	nodes[3].node.handle_update_fail_htlc(node_f_id, &two_removes.update_fail_htlcs[0]);
	nodes[3].node.handle_update_fail_htlc(node_f_id, &two_removes.update_fail_htlcs[1]);
	do_commitment_signed_dance(&nodes[3], &nodes[5], &two_removes.commitment_signed, false, false);

	let ds_prev_commitment_tx = get_local_commitment_txn!(nodes[3], chan_2_3.2);

	// After 4 and 2 removes respectively above in nodes[4] and nodes[5], nodes[3] should receive 6 PaymentForwardedFailed events
	let failed_destinations_3 = vec![
		HTLCHandlingFailureType::Forward { node_id: Some(node_e_id), channel_id: chan_3_4.2 },
		HTLCHandlingFailureType::Forward { node_id: Some(node_e_id), channel_id: chan_3_4.2 },
		HTLCHandlingFailureType::Forward { node_id: Some(node_e_id), channel_id: chan_3_4.2 },
		HTLCHandlingFailureType::Forward { node_id: Some(node_e_id), channel_id: chan_3_4.2 },
		HTLCHandlingFailureType::Forward { node_id: Some(node_f_id), channel_id: chan_3_5.2 },
		HTLCHandlingFailureType::Forward { node_id: Some(node_f_id), channel_id: chan_3_5.2 },
	];
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[3], &failed_destinations_3);
	check_added_monitors(&nodes[3], 1);
	let six_removes = get_htlc_update_msgs(&nodes[3], &node_c_id);
	nodes[2].node.handle_update_fail_htlc(node_d_id, &six_removes.update_fail_htlcs[0]);
	nodes[2].node.handle_update_fail_htlc(node_d_id, &six_removes.update_fail_htlcs[1]);
	nodes[2].node.handle_update_fail_htlc(node_d_id, &six_removes.update_fail_htlcs[2]);
	nodes[2].node.handle_update_fail_htlc(node_d_id, &six_removes.update_fail_htlcs[3]);
	nodes[2].node.handle_update_fail_htlc(node_d_id, &six_removes.update_fail_htlcs[4]);
	nodes[2].node.handle_update_fail_htlc(node_d_id, &six_removes.update_fail_htlcs[5]);
	if deliver_last_raa {
		let commitment = &six_removes.commitment_signed;
		do_commitment_signed_dance(&nodes[2], &nodes[3], commitment, false, false);
	} else {
		let cs = six_removes.commitment_signed;
		commitment_signed_dance_return_raa(&nodes[2], &nodes[3], &cs, false);
	}

	// D's latest commitment transaction now contains 1st + 2nd + 9th HTLCs (implicitly, they're
	// below the dust limit) and the 5th + 6th + 11th HTLCs. It has failed back the 0th, 3rd, 4th,
	// 7th, 8th, and 10th, but as we haven't yet delivered the final RAA to C, the fails haven't
	// propagated back to A/B yet (and D has two unrevoked commitment transactions).
	//
	// We now broadcast the latest commitment transaction, which *should* result in failures for
	// the 0th, 1st, 2nd, 3rd, 4th, 7th, 8th, 9th, and 10th HTLCs, ie all the below-dust HTLCs and
	// the non-broadcast above-dust HTLCs.
	//
	// Alternatively, we may broadcast the previous commitment transaction, which should only
	// result in failures for the below-dust HTLCs, ie the 0th, 1st, 2nd, 3rd, 9th, and 10th HTLCs.
	let ds_last_commitment_tx = get_local_commitment_txn!(nodes[3], chan_2_3.2);

	if announce_latest {
		mine_transaction(&nodes[2], &ds_last_commitment_tx[0]);
	} else {
		mine_transaction(&nodes[2], &ds_prev_commitment_tx[0]);
	}
	let events = nodes[2].node.get_and_clear_pending_events();
	let close_event = if deliver_last_raa {
		assert_eq!(events.len(), 2 + 5);
		events.last().clone().unwrap()
	} else {
		assert_eq!(events.len(), 1);
		events.last().clone().unwrap()
	};
	match close_event {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {},
		_ => panic!("Unexpected event"),
	}

	connect_blocks(&nodes[2], ANTI_REORG_DELAY - 1);
	check_closed_broadcast!(nodes[2], true);
	if deliver_last_raa {
		nodes[2].node.process_pending_htlc_forwards();

		let expected_destinations: Vec<HTLCHandlingFailureType> =
			repeat(HTLCHandlingFailureType::Forward {
				node_id: Some(node_d_id),
				channel_id: chan_2_3.2,
			})
			.take(3)
			.collect();
		expect_htlc_handling_failed_destinations!(
			nodes[2].node.get_and_clear_pending_events(),
			expected_destinations
		);
	} else {
		let expected_destinations: Vec<HTLCHandlingFailureType> = if announce_latest {
			repeat(HTLCHandlingFailureType::Forward {
				node_id: Some(node_d_id),
				channel_id: chan_2_3.2,
			})
			.take(9)
			.collect()
		} else {
			repeat(HTLCHandlingFailureType::Forward {
				node_id: Some(node_d_id),
				channel_id: chan_2_3.2,
			})
			.take(6)
			.collect()
		};

		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[2],
			&expected_destinations,
		);
	}
	check_added_monitors(&nodes[2], 3);

	let cs_msgs = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(cs_msgs.len(), 2);
	let mut a_done = false;
	for msg in cs_msgs {
		match msg {
			MessageSendEvent::UpdateHTLCs { ref node_id, ref updates, .. } => {
				// Both under-dust HTLCs and the one above-dust HTLC that we had already failed
				// should be failed-backwards here.
				let target = if *node_id == node_a_id {
					// If announce_latest, expect 0th, 1st, 4th, 8th, 10th HTLCs, else only 0th, 1st, 10th below-dust HTLCs
					for htlc in &updates.update_fail_htlcs {
						assert!(
							htlc.htlc_id == 1
								|| htlc.htlc_id == 2 || htlc.htlc_id == 6
								|| if announce_latest {
									htlc.htlc_id == 3 || htlc.htlc_id == 5
								} else {
									false
								}
						);
					}
					assert_eq!(
						updates.update_fail_htlcs.len(),
						if announce_latest { 5 } else { 3 }
					);
					assert!(!a_done);
					a_done = true;
					&nodes[0]
				} else {
					// If announce_latest, expect 2nd, 3rd, 7th, 9th HTLCs, else only 2nd, 3rd, 9th below-dust HTLCs
					for htlc in &updates.update_fail_htlcs {
						assert!(
							htlc.htlc_id == 1
								|| htlc.htlc_id == 2 || htlc.htlc_id == 5
								|| if announce_latest { htlc.htlc_id == 4 } else { false }
						);
					}
					assert_eq!(*node_id, node_b_id);
					assert_eq!(
						updates.update_fail_htlcs.len(),
						if announce_latest { 4 } else { 3 }
					);
					&nodes[1]
				};
				target.node.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[0]);
				target.node.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[1]);
				target.node.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[2]);
				if announce_latest {
					target.node.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[3]);
					if *node_id == node_a_id {
						target
							.node
							.handle_update_fail_htlc(node_c_id, &updates.update_fail_htlcs[4]);
					}
				}
				let commitment = &updates.commitment_signed;
				do_commitment_signed_dance(target, &nodes[2], commitment, false, true);
			},
			_ => panic!("Unexpected event"),
		}
	}

	let as_events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(as_events.len(), if announce_latest { 10 } else { 6 });
	let mut as_faileds = new_hash_set();
	let mut as_updates = 0;
	for event in as_events.iter() {
		if let &Event::PaymentPathFailed {
			ref payment_hash,
			ref payment_failed_permanently,
			ref failure,
			..
		} = event
		{
			assert!(as_faileds.insert(*payment_hash));
			if *payment_hash != hash_2 {
				assert_eq!(*payment_failed_permanently, deliver_last_raa);
			} else {
				assert!(!payment_failed_permanently);
			}
			if let PathFailure::OnPath { network_update: Some(_) } = failure {
				as_updates += 1;
			}
		} else if let &Event::PaymentFailed { .. } = event {
		} else {
			panic!("Unexpected event");
		}
	}
	assert!(as_faileds.contains(&hash_1));
	assert!(as_faileds.contains(&hash_2));
	if announce_latest {
		assert!(as_faileds.contains(&hash_3));
		assert!(as_faileds.contains(&hash_5));
	}
	assert!(as_faileds.contains(&hash_6));

	let bs_events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(bs_events.len(), if announce_latest { 8 } else { 6 });
	let mut bs_faileds = new_hash_set();
	let mut bs_updates = 0;
	for event in bs_events.iter() {
		if let &Event::PaymentPathFailed {
			ref payment_hash,
			ref payment_failed_permanently,
			ref failure,
			..
		} = event
		{
			assert!(bs_faileds.insert(*payment_hash));
			if *payment_hash != hash_1 && *payment_hash != hash_5 {
				assert_eq!(*payment_failed_permanently, deliver_last_raa);
			} else {
				assert!(!payment_failed_permanently);
			}
			if let PathFailure::OnPath { network_update: Some(_) } = failure {
				bs_updates += 1;
			}
		} else if let &Event::PaymentFailed { .. } = event {
		} else {
			panic!("Unexpected event");
		}
	}
	assert!(bs_faileds.contains(&hash_1));
	assert!(bs_faileds.contains(&hash_2));
	if announce_latest {
		assert!(bs_faileds.contains(&hash_4));
	}
	assert!(bs_faileds.contains(&hash_5));

	// For each HTLC which was not failed-back by normal process (ie deliver_last_raa), we should
	// get a NetworkUpdate. A should have gotten 4 HTLCs which were failed-back due to
	// unknown-preimage-etc, B should have gotten 2. Thus, in the
	// announce_latest && deliver_last_raa case, we should have 5-4=1 and 4-2=2 NetworkUpdates.
	assert_eq!(
		as_updates,
		if deliver_last_raa {
			1
		} else if !announce_latest {
			3
		} else {
			5
		}
	);
	assert_eq!(
		bs_updates,
		if deliver_last_raa {
			2
		} else if !announce_latest {
			3
		} else {
			4
		}
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_fail_backwards_latest_remote_announce_a() {
	do_test_fail_backwards_unrevoked_remote_announce(false, true);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_fail_backwards_latest_remote_announce_b() {
	do_test_fail_backwards_unrevoked_remote_announce(true, true);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_fail_backwards_previous_remote_announce() {
	do_test_fail_backwards_unrevoked_remote_announce(false, false);
	// Note that true, true doesn't make sense as it implies we announce a revoked state, which is
	// tested for in test_commitment_revoked_fail_backward_exhaustive()
}

#[xtest(feature = "_externalize_tests")]
pub fn test_dynamic_spendable_outputs_local_htlc_timeout_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 9000000);
	let local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn[0].input.len(), 1);
	check_spends!(local_txn[0], chan_1.3);

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	mine_transaction(&nodes[0], &local_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		node_txn[0].clone()
	};

	mine_transaction(&nodes[0], &htlc_timeout);
	connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32 - 1);
	let conditions = PaymentFailedConditions::new().from_mon_update();
	expect_payment_failed_conditions(&nodes[0], our_payment_hash, false, conditions);

	// Verify that A is able to spend its own HTLC-Timeout tx thanks to spendable output event given back by its ChannelMonitor
	let spend_txn = check_spendable_outputs!(nodes[0], node_cfgs[0].keys_manager);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], local_txn[0]);
	assert_eq!(spend_txn[1].input.len(), 1);
	check_spends!(spend_txn[1], htlc_timeout);
	assert_eq!(spend_txn[1].input[0].sequence.0, BREAKDOWN_TIMEOUT as u32);
	assert_eq!(spend_txn[2].input.len(), 2);
	check_spends!(spend_txn[2], local_txn[0], htlc_timeout);
	assert!(
		spend_txn[2].input[0].sequence.0 == BREAKDOWN_TIMEOUT as u32
			|| spend_txn[2].input[1].sequence.0 == BREAKDOWN_TIMEOUT as u32
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_key_derivation_params() {
	// This test is a copy of test_dynamic_spendable_outputs_local_htlc_timeout_tx, with a key
	// manager rotation to test that `channel_keys_id` returned in
	// [`SpendableOutputDescriptor::DelayedPaymentOutput`] let us re-derive the channel key set to
	// then derive a `delayed_payment_key`.

	let chanmon_cfgs = create_chanmon_cfgs(3);

	// We manually create the node configuration to backup the seed.
	let seed = [42; 32];
	let keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);
	let chain_monitor = test_utils::TestChainMonitor::new(
		Some(&chanmon_cfgs[0].chain_source),
		&chanmon_cfgs[0].tx_broadcaster,
		&chanmon_cfgs[0].logger,
		&chanmon_cfgs[0].fee_estimator,
		&chanmon_cfgs[0].persister,
		&keys_manager,
	);
	let network_graph = Arc::new(NetworkGraph::new(Network::Testnet, &chanmon_cfgs[0].logger));
	let scorer = RwLock::new(test_utils::TestScorer::new());
	let router =
		test_utils::TestRouter::new(Arc::clone(&network_graph), &chanmon_cfgs[0].logger, &scorer);
	let message_router =
		test_utils::TestMessageRouter::new_default(Arc::clone(&network_graph), &keys_manager);
	let node = NodeCfg {
		chain_source: &chanmon_cfgs[0].chain_source,
		logger: &chanmon_cfgs[0].logger,
		tx_broadcaster: &chanmon_cfgs[0].tx_broadcaster,
		fee_estimator: &chanmon_cfgs[0].fee_estimator,
		router,
		message_router,
		chain_monitor,
		keys_manager: &keys_manager,
		network_graph,
		node_seed: seed,
		override_init_features: alloc::rc::Rc::new(core::cell::RefCell::new(None)),
	};
	let mut node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	node_cfgs.remove(0);
	node_cfgs.insert(0, node);

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channels
	// Create a dummy channel to advance index by one and thus test re-derivation correctness
	// for node 0
	let chan_0 = create_announced_chan_between_nodes(&nodes, 0, 2);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	assert_ne!(chan_0.3.output[0].script_pubkey, chan_1.3.output[0].script_pubkey);

	// Ensure all nodes are at the same height
	let node_max_height =
		nodes.iter().map(|node| node.blocks.lock().unwrap().len()).max().unwrap() as u32;
	connect_blocks(&nodes[0], node_max_height - nodes[0].best_block_info().1);
	connect_blocks(&nodes[1], node_max_height - nodes[1].best_block_info().1);
	connect_blocks(&nodes[2], node_max_height - nodes[2].best_block_info().1);

	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 9000000);
	let local_txn_0 = get_local_commitment_txn!(nodes[0], chan_0.2);
	let local_txn_1 = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn_1[0].input.len(), 1);
	check_spends!(local_txn_1[0], chan_1.3);

	// We check funding pubkey are unique
	let (from_0_funding_key_0, from_0_funding_key_1) = (
		PublicKey::from_slice(&local_txn_0[0].input[0].witness.to_vec()[3][2..35]),
		PublicKey::from_slice(&local_txn_0[0].input[0].witness.to_vec()[3][36..69]),
	);
	let (from_1_funding_key_0, from_1_funding_key_1) = (
		PublicKey::from_slice(&local_txn_1[0].input[0].witness.to_vec()[3][2..35]),
		PublicKey::from_slice(&local_txn_1[0].input[0].witness.to_vec()[3][36..69]),
	);
	if from_0_funding_key_0 == from_1_funding_key_0
		|| from_0_funding_key_0 == from_1_funding_key_1
		|| from_0_funding_key_1 == from_1_funding_key_0
		|| from_0_funding_key_1 == from_1_funding_key_1
	{
		panic!("Funding pubkeys aren't unique");
	}

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	mine_transaction(&nodes[0], &local_txn_1[0]);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn_1[0]);
		node_txn[0].clone()
	};

	mine_transaction(&nodes[0], &htlc_timeout);
	connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32 - 1);
	let conditions = PaymentFailedConditions::new().from_mon_update();
	expect_payment_failed_conditions(&nodes[0], our_payment_hash, false, conditions);

	// Verify that A is able to spend its own HTLC-Timeout tx thanks to spendable output event given back by its ChannelMonitor
	let new_keys_manager = test_utils::TestKeysInterface::new(&seed, Network::Testnet);
	let spend_txn = check_spendable_outputs!(nodes[0], new_keys_manager);
	assert_eq!(spend_txn.len(), 3);
	check_spends!(spend_txn[0], local_txn_1[0]);
	assert_eq!(spend_txn[1].input.len(), 1);
	check_spends!(spend_txn[1], htlc_timeout);
	assert_eq!(spend_txn[1].input[0].sequence.0, BREAKDOWN_TIMEOUT as u32);
	assert_eq!(spend_txn[2].input.len(), 2);
	check_spends!(spend_txn[2], local_txn_1[0], htlc_timeout);
	assert!(
		spend_txn[2].input[0].sequence.0 == BREAKDOWN_TIMEOUT as u32
			|| spend_txn[2].input[1].sequence.0 == BREAKDOWN_TIMEOUT as u32
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_static_output_closing_tx() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	send_payment(&nodes[0], &[&nodes[1]], 8000000);
	let closing_tx = close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true).2;

	mine_transaction(&nodes[0], &closing_tx);
	let reason = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[0], node_cfgs[0].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], closing_tx);

	mine_transaction(&nodes[1], &closing_tx);
	let reason = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	let spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
	assert_eq!(spend_txn.len(), 1);
	check_spends!(spend_txn[0], closing_tx);
}

fn do_htlc_claim_local_commitment_only(use_dust: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1]], if use_dust { 50000 } else { 3_000_000 });

	// Claim the payment, but don't deliver A's commitment_signed, resulting in the HTLC only being
	// present in B's local commitment transaction, but none of A's commitment transactions.
	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, if use_dust { 50000 } else { 3_000_000 });

	let mut bs_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, bs_updates.update_fulfill_htlcs.remove(0));
	expect_payment_sent(&nodes[0], payment_preimage, None, false, false);

	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_updates.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let as_updates = get_revoke_commit_msgs(&nodes[0], &node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_updates.0);
	check_added_monitors(&nodes[1], 1);

	let starting_block = nodes[1].best_block_info();
	let mut block = create_dummy_block(starting_block.0, 42, Vec::new());
	for _ in starting_block.1 + 1..TEST_FINAL_CLTV - CLTV_CLAIM_BUFFER + starting_block.1 + 2 {
		connect_block(&nodes[1], &block);
		block.header.prev_blockhash = block.block_hash();
	}
	let htlc_type = if use_dust { HTLCType::NONE } else { HTLCType::SUCCESS };
	test_txn_broadcast(&nodes[1], &chan, None, htlc_type);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
}

fn do_htlc_claim_current_remote_commitment_only(use_dust: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], if use_dust { 50000 } else { 3000000 });
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let _as_update = get_htlc_update_msgs(&nodes[0], &node_b_id);

	// As far as A is concerned, the HTLC is now present only in the latest remote commitment
	// transaction, however it is not in A's latest local commitment, so we can just broadcast that
	// to "time out" the HTLC.

	let starting_block = nodes[1].best_block_info();
	let mut block = create_dummy_block(starting_block.0, 42, Vec::new());

	for _ in
		starting_block.1 + 1..TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + starting_block.1 + 2
	{
		connect_block(&nodes[0], &block);
		block.header.prev_blockhash = block.block_hash();
	}
	test_txn_broadcast(&nodes[0], &chan, None, HTLCType::NONE);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
}

fn do_htlc_claim_previous_remote_commitment_only(use_dust: bool, check_revoke_no_close: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Fail the payment, but don't deliver A's final RAA, resulting in the HTLC only being present
	// in B's previous (unrevoked) commitment transaction, but none of A's commitment transactions.
	// Also optionally test that we *don't* fail the channel in case the commitment transaction was
	// actually revoked.
	let htlc_value = if use_dust { 50000 } else { 3000000 };
	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], htlc_value);
	nodes[1].node.fail_htlc_backwards(&our_payment_hash);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Receive { payment_hash: our_payment_hash }],
	);
	check_added_monitors(&nodes[1], 1);

	let bs_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &bs_updates.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_updates.commitment_signed);
	check_added_monitors(&nodes[0], 1);
	let as_updates = get_revoke_commit_msgs(&nodes[0], &node_b_id);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &as_updates.0);
	check_added_monitors(&nodes[1], 1);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &as_updates.1);
	check_added_monitors(&nodes[1], 1);
	let bs_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, node_a_id);

	if check_revoke_no_close {
		nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_revoke_and_ack);
		check_added_monitors(&nodes[0], 1);
	}

	let starting_block = nodes[1].best_block_info();
	let mut block = create_dummy_block(starting_block.0, 42, Vec::new());
	for _ in
		starting_block.1 + 1..TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + CHAN_CONFIRM_DEPTH + 2
	{
		connect_block(&nodes[0], &block);
		block.header.prev_blockhash = block.block_hash();
	}
	if !check_revoke_no_close {
		test_txn_broadcast(&nodes[0], &chan, None, HTLCType::NONE);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors(&nodes[0], 1);
		let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(our_payment_hash) };
		check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	} else {
		expect_payment_failed!(nodes[0], our_payment_hash, true);
	}
}

// Test that we close channels on-chain when broadcastable HTLCs reach their timeout window.
// There are only a few cases to test here:
//  * its not really normative behavior, but we test that below-dust HTLCs "included" in
//    broadcastable commitment transactions result in channel closure,
//  * its included in an unrevoked-but-previous remote commitment transaction,
//  * its included in the latest remote or local commitment transactions.
// We test each of the three possible commitment transactions individually and use both dust and
// non-dust HTLCs.
// Note that we don't bother testing both outbound and inbound HTLC failures for each case, and we
// assume they are handled the same across all six cases, as both outbound and inbound failures are
// tested for at least one of the cases in other tests.
#[xtest(feature = "_externalize_tests")]
pub fn htlc_claim_single_commitment_only_a() {
	do_htlc_claim_local_commitment_only(true);
	do_htlc_claim_local_commitment_only(false);

	do_htlc_claim_current_remote_commitment_only(true);
	do_htlc_claim_current_remote_commitment_only(false);
}

#[xtest(feature = "_externalize_tests")]
pub fn htlc_claim_single_commitment_only_b() {
	do_htlc_claim_previous_remote_commitment_only(true, false);
	do_htlc_claim_previous_remote_commitment_only(false, false);
	do_htlc_claim_previous_remote_commitment_only(true, true);
	do_htlc_claim_previous_remote_commitment_only(false, true);
}

// Test that if we fail to send an HTLC that is being freed from the holding cell, and the HTLC
// originated from our node, its failure is surfaced to the user. We trigger this failure to
// free the HTLC by increasing our fee while the HTLC is in the holding cell such that the HTLC
// is no longer affordable once it's freed.
#[xtest(feature = "_externalize_tests")]
pub fn test_fail_holding_cell_htlc_upon_free() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	// First nodes[0] generates an update_fee, setting the channel's
	// pending_update_fee.
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref(), commitment_signed),
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(node_a_id, update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], nodes[1], chan.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan.2);

	// 2* and +1 HTLCs on the commit tx fee calculation for the fee spike reserve.
	let max_can_send =
		5000000 - channel_reserve - 2 * commit_tx_fee_msat(feerate, 1 + 1, &channel_type_features);
	let (route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], max_can_send);

	// Send a payment which passes reserve checks but gets stuck in the holding cell.
	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[0].node.send_payment_with_route(route.clone(), our_payment_hash, onion, id).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, max_can_send);

	// Flush the pending fee update.
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, commitment_signed);
	let (as_revoke_and_ack, _) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &as_revoke_and_ack);
	check_added_monitors(&nodes[0], 1);

	// Upon receipt of the RAA, there will be an attempt to resend the holding cell
	// HTLC, but now that the fee has been raised the payment will now fail, causing
	// us to surface its failure to the user.
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, 0);
	nodes[0].logger.assert_log(
		"lightning::ln::channel",
		"Freeing holding cell with 1 HTLC updates".to_string(),
		1,
	);

	// Check that the payment failed to be sent out.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match &events[0] {
		&Event::PaymentPathFailed {
			ref payment_id,
			ref payment_hash,
			ref payment_failed_permanently,
			failure: PathFailure::OnPath { network_update: None },
			ref short_channel_id,
			..
		} => {
			assert_eq!(PaymentId(our_payment_hash.0), *payment_id.as_ref().unwrap());
			assert_eq!(our_payment_hash.clone(), *payment_hash);
			assert_eq!(*payment_failed_permanently, false);
			assert_eq!(*short_channel_id, Some(route.paths[0].hops[0].short_channel_id));
		},
		_ => panic!("Unexpected event"),
	}
	match &events[1] {
		&Event::PaymentFailed { ref payment_hash, .. } => {
			assert_eq!(Some(our_payment_hash), *payment_hash);
		},
		_ => panic!("Unexpected event"),
	}
}

// Test that if multiple HTLCs are released from the holding cell and one is
// valid but the other is no longer valid upon release, the valid HTLC can be
// successfully completed while the other one fails as expected.
#[xtest(feature = "_externalize_tests")]
pub fn test_free_and_fail_holding_cell_htlcs() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);

	// First nodes[0] generates an update_fee, setting the channel's
	// pending_update_fee.
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 200;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&nodes[0], 1);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref(), commitment_signed),
		_ => panic!("Unexpected event"),
	};

	nodes[1].node.handle_update_fee(node_a_id, update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], nodes[1], chan.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan.2);

	// 2* and +1 HTLCs on the commit tx fee calculation for the fee spike reserve.
	let amt_1 = 20000;
	let amt_2 = 5000000
		- channel_reserve
		- 2 * commit_tx_fee_msat(feerate, 2 + 1, &channel_type_features)
		- amt_1;
	let (route_1, payment_hash_1, payment_preimage_1, payment_secret_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], amt_1);
	let (route_2, payment_hash_2, _, payment_secret_2) =
		get_route_and_payment_hash!(nodes[0], nodes[1], amt_2);

	// Send 2 payments which pass reserve checks but get stuck in the holding cell.
	let onion = RecipientOnionFields::secret_only(payment_secret_1);
	let id_1 = PaymentId(payment_hash_1.0);
	nodes[0].node.send_payment_with_route(route_1, payment_hash_1, onion, id_1).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, amt_1);

	let id_2 = PaymentId(nodes[0].keys_manager.get_secure_random_bytes());
	let onion = RecipientOnionFields::secret_only(payment_secret_2);
	nodes[0].node.send_payment_with_route(route_2.clone(), payment_hash_2, onion, id_2).unwrap();
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, amt_1 + amt_2);

	// Flush the pending fee update.
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, commitment_signed);
	let (revoke_and_ack, commitment_signed) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	check_added_monitors(&nodes[1], 1);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &revoke_and_ack);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &commitment_signed);
	check_added_monitors(&nodes[0], 2);

	// Upon receipt of the RAA, there will be an attempt to resend the holding cell HTLCs,
	// but now that the fee has been raised the second payment will now fail, causing us
	// to surface its failure to the user. The first payment should succeed.
	chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, 0);
	nodes[0].logger.assert_log(
		"lightning::ln::channel",
		"Freeing holding cell with 2 HTLC updates".to_string(),
		1,
	);

	// Check that the second payment failed to be sent out.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	match &events[0] {
		&Event::PaymentPathFailed {
			ref payment_id,
			ref payment_hash,
			ref payment_failed_permanently,
			failure: PathFailure::OnPath { network_update: None },
			ref short_channel_id,
			..
		} => {
			assert_eq!(id_2, *payment_id.as_ref().unwrap());
			assert_eq!(payment_hash_2.clone(), *payment_hash);
			assert_eq!(*payment_failed_permanently, false);
			assert_eq!(*short_channel_id, Some(route_2.paths[0].hops[0].short_channel_id));
		},
		_ => panic!("Unexpected event"),
	}
	match &events[1] {
		&Event::PaymentFailed { ref payment_hash, .. } => {
			assert_eq!(Some(payment_hash_2), *payment_hash);
		},
		_ => panic!("Unexpected event"),
	}

	// Complete the first payment and the RAA from the fee update.
	let (payment_event, send_raa_event) = {
		let mut msgs = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msgs.len(), 2);
		(SendEvent::from_event(msgs.remove(0)), msgs.remove(0))
	};
	let raa = match send_raa_event {
		MessageSendEvent::SendRevokeAndACK { msg, .. } => msg,
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_revoke_and_ack(node_a_id, &raa);
	check_added_monitors(&nodes[1], 1);
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	nodes[1].node.process_pending_htlc_forwards();
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable { .. } => {},
		_ => panic!("Unexpected event"),
	}
	nodes[1].node.claim_funds(payment_preimage_1);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash_1, amt_1);

	let mut update_msgs = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, update_msgs.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &update_msgs.commitment_signed, false, true);
	expect_payment_sent!(nodes[0], payment_preimage_1);
}

// Test that if we fail to forward an HTLC that is being freed from the holding cell that the
// HTLC is failed backwards. We trigger this failure to forward the freed HTLC by increasing
// our fee while the HTLC is in the holding cell such that the HTLC is no longer affordable
// once it's freed.
#[xtest(feature = "_externalize_tests")]
pub fn test_fail_holding_cell_htlc_upon_free_multihop() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	// Avoid having to include routing fees in calculations
	let mut config = test_default_channel_config();
	config.channel_config.forwarding_fee_base_msat = 0;
	config.channel_config.forwarding_fee_proportional_millionths = 0;
	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(config.clone()), Some(config.clone()), Some(config.clone())],
	);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_0_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 95000000);
	let chan_1_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 95000000);

	// First nodes[1] generates an update_fee, setting the channel's
	// pending_update_fee.
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock += 20;
	}
	nodes[1].node.timer_tick_occurred();
	check_added_monitors(&nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_msg, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs {
			updates: msgs::CommitmentUpdate { ref update_fee, ref commitment_signed, .. },
			..
		} => (update_fee.as_ref(), commitment_signed),
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_update_fee(node_b_id, update_msg.unwrap());

	let mut chan_stat = get_channel_value_stat!(nodes[0], nodes[1], chan_0_1.2);
	let channel_reserve = chan_stat.channel_reserve_msat;
	let feerate = get_feerate!(nodes[0], nodes[1], chan_0_1.2);
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_0_1.2);

	// Send a payment which passes reserve checks but gets stuck in the holding cell.
	let max_can_send =
		5000000 - channel_reserve - 2 * commit_tx_fee_msat(feerate, 1 + 1, &channel_type_features);
	let (route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], max_can_send);
	let payment_event = {
		let onion = RecipientOnionFields::secret_only(our_payment_secret);
		let id = PaymentId(our_payment_hash.0);
		nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);

		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);

		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);

	chan_stat = get_channel_value_stat!(nodes[1], nodes[2], chan_1_2.2);
	assert_eq!(chan_stat.holding_cell_outbound_amount_msat, max_can_send);

	// Flush the pending fee update.
	nodes[2].node.handle_commitment_signed_batch_test(node_b_id, commitment_signed);
	let (raa, commitment_signed) = get_revoke_commit_msgs(&nodes[2], &node_b_id);
	check_added_monitors(&nodes[2], 1);
	nodes[1].node.handle_revoke_and_ack(node_c_id, &raa);
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &commitment_signed);
	check_added_monitors(&nodes[1], 2);

	// A final RAA message is generated to finalize the fee update.
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);

	let raa_msg = match &events[0] {
		&MessageSendEvent::SendRevokeAndACK { ref msg, .. } => msg.clone(),
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_revoke_and_ack(node_b_id, &raa_msg);
	check_added_monitors(&nodes[2], 1);
	assert!(nodes[2].node.get_and_clear_pending_msg_events().is_empty());

	// Call ChannelManager's process_pending_htlc_forwards
	let process_htlc_forwards_event = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(process_htlc_forwards_event.len(), 1);
	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[1], 1);

	// This causes the HTLC to be failed backwards.
	let fail_event = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(fail_event.len(), 1);
	let (fail_msg, commitment_signed) = match &fail_event[0] {
		&MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			assert_eq!(updates.update_add_htlcs.len(), 0);
			assert_eq!(updates.update_fulfill_htlcs.len(), 0);
			assert_eq!(updates.update_fail_malformed_htlcs.len(), 0);
			assert_eq!(updates.update_fail_htlcs.len(), 1);
			(updates.update_fail_htlcs[0].clone(), updates.commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};

	// Pass the failure messages back to nodes[0].
	nodes[0].node.handle_update_fail_htlc(node_b_id, &fail_msg);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &commitment_signed);

	// Complete the HTLC failure+removal process.
	let (raa, commitment_signed) = get_revoke_commit_msgs(&nodes[0], &node_b_id);
	check_added_monitors(&nodes[0], 1);
	nodes[1].node.handle_revoke_and_ack(node_a_id, &raa);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &commitment_signed);
	check_added_monitors(&nodes[1], 2);
	let final_raa_event = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(final_raa_event.len(), 1);
	let raa = match &final_raa_event[0] {
		&MessageSendEvent::SendRevokeAndACK { ref msg, .. } => msg.clone(),
		_ => panic!("Unexpected event"),
	};
	nodes[0].node.handle_revoke_and_ack(node_b_id, &raa);
	expect_payment_failed_with_update!(
		nodes[0],
		our_payment_hash,
		false,
		chan_1_2.0.contents.short_channel_id,
		false
	);
	check_added_monitors(&nodes[0], 1);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_update_fulfill_htlc_bolt2_after_malformed_htlc_message_must_forward_update_fail_htlc() {
	//BOLT 2 Requirement: a receiving node which has an outgoing HTLC canceled by update_fail_malformed_htlc:
	//    * MUST return an error in the update_fail_htlc sent to the link which originally sent the HTLC, using the failure_code given and setting the data to sha256_of_onion.

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 1000000, 1000000);

	let (route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 100000);

	//First hop
	let mut payment_event = {
		let onion = RecipientOnionFields::secret_only(our_payment_secret);
		let id = PaymentId(our_payment_hash.0);
		nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	let mut events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	check_added_monitors(&nodes[1], 1);
	payment_event = SendEvent::from_event(events_2.remove(0));
	assert_eq!(payment_event.msgs.len(), 1);

	//Second Hop
	payment_event.msgs[0].onion_routing_packet.version = 1; //Produce a malformed HTLC message
	nodes[2].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
	check_added_monitors(&nodes[2], 0);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event.commitment_msg, false, true);
	expect_and_process_pending_htlcs(&nodes[2], false);
	expect_htlc_handling_failed_destinations!(
		nodes[2].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::InvalidOnion]
	);
	check_added_monitors(&nodes[2], 1);

	let events_3 = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	let update_msg: (msgs::UpdateFailMalformedHTLC, Vec<msgs::CommitmentSigned>) = {
		match events_3[0] {
			MessageSendEvent::UpdateHTLCs {
				updates:
					msgs::CommitmentUpdate {
						ref update_add_htlcs,
						ref update_fulfill_htlcs,
						ref update_fail_htlcs,
						ref update_fail_malformed_htlcs,
						ref update_fee,
						ref commitment_signed,
					},
				..
			} => {
				assert!(update_add_htlcs.is_empty());
				assert!(update_fulfill_htlcs.is_empty());
				assert!(update_fail_htlcs.is_empty());
				assert_eq!(update_fail_malformed_htlcs.len(), 1);
				assert!(update_fee.is_none());
				(update_fail_malformed_htlcs[0].clone(), commitment_signed.clone())
			},
			_ => panic!("Unexpected event"),
		}
	};

	nodes[1].node.handle_update_fail_malformed_htlc(node_c_id, &update_msg.0);

	check_added_monitors(&nodes[1], 0);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &update_msg.1, false, true);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }],
	);
	let events_4 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_4.len(), 1);

	//Confirm that handlinge the update_malformed_htlc message produces an update_fail_htlc message to be forwarded back along the route
	match events_4[0] {
		MessageSendEvent::UpdateHTLCs {
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_htlcs,
					ref update_fail_malformed_htlcs,
					ref update_fee,
					..
				},
			..
		} => {
			assert!(update_add_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert_eq!(update_fail_htlcs.len(), 1);
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
		},
		_ => panic!("Unexpected event"),
	};

	check_added_monitors(&nodes[1], 1);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_channel_failed_after_message_with_badonion_node_perm_bits_set() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (route, our_payment_hash, _, our_payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[2], 100_000);

	// First hop
	let mut payment_event = {
		let onion = RecipientOnionFields::secret_only(our_payment_secret);
		let id = PaymentId(our_payment_hash.0);
		nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);
		SendEvent::from_node(&nodes[0])
	};

	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);
	payment_event = SendEvent::from_node(&nodes[1]);
	assert_eq!(payment_event.msgs.len(), 1);

	// Second Hop
	payment_event.msgs[0].onion_routing_packet.version = 1; // Trigger an invalid_onion_version error
	nodes[2].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
	check_added_monitors(&nodes[2], 0);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &payment_event.commitment_msg, false, true);
	expect_and_process_pending_htlcs(&nodes[2], false);
	expect_htlc_handling_failed_destinations!(
		nodes[2].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::InvalidOnion]
	);
	check_added_monitors(&nodes[2], 1);

	let events_3 = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events_3.len(), 1);
	match events_3[0] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			let mut update_msg = updates.update_fail_malformed_htlcs[0].clone();
			// Set the NODE bit (BADONION and PERM already set in invalid_onion_version error)
			update_msg.failure_code |= 0x2000;

			nodes[1].node.handle_update_fail_malformed_htlc(node_c_id, &update_msg);
			let commitment = &updates.commitment_signed;
			do_commitment_signed_dance(&nodes[1], &nodes[2], commitment, false, true);
		},
		_ => panic!("Unexpected event"),
	}

	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }],
	);
	let events_4 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_4.len(), 1);
	check_added_monitors(&nodes[1], 1);

	match events_4[0] {
		MessageSendEvent::UpdateHTLCs { ref updates, .. } => {
			nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
			let commitment = &updates.commitment_signed;
			do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, true);
		},
		_ => panic!("Unexpected event"),
	}

	let events_5 = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events_5.len(), 2);

	// Expect a PaymentPathFailed event with a ChannelFailure network update for the channel between
	// the node originating the error to its next hop.
	match events_5[0] {
		Event::PaymentPathFailed {
			error_code,
			failure:
				PathFailure::OnPath {
					network_update:
						Some(NetworkUpdate::ChannelFailure { short_channel_id, is_permanent }),
				},
			..
		} => {
			assert_eq!(short_channel_id, chan_2.0.contents.short_channel_id);
			assert!(is_permanent);
			assert_eq!(error_code, Some(0x8000 | 0x4000 | 0x2000 | 4));
		},
		_ => panic!("Unexpected event"),
	}
	match events_5[1] {
		Event::PaymentFailed { payment_hash, .. } => {
			assert_eq!(payment_hash, Some(our_payment_hash));
		},
		_ => panic!("Unexpected event"),
	}

	// TODO: Test actual removal of channel from NetworkGraph when it's implemented.
}

fn do_test_failure_delay_dust_htlc_local_commitment(announce_latest: bool) {
	// Dust-HTLC failure updates must be delayed until failure-trigger tx (in this case local commitment) reach ANTI_REORG_DELAY
	// We can have at most two valid local commitment tx, so both cases must be covered, and both txs must be checked to get them all as
	// HTLC could have been removed from lastest local commitment tx but still valid until we get remote RAA

	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let bs_dust_limit = {
		let per_peer_state_lock;
		let mut peer_state_lock;
		let chan =
			get_channel_ref!(nodes[1], nodes[0], per_peer_state_lock, peer_state_lock, chan.2);
		chan.context().holder_dust_limit_satoshis
	};

	// We route 2 dust-HTLCs between A and B
	let (_, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit * 1000);
	let (_, payment_hash_2, ..) = route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit * 1000);
	route_payment(&nodes[0], &[&nodes[1]], 1000000);

	// Cache one local commitment tx as previous
	let as_prev_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);

	// Fail one HTLC to prune it in the will-be-latest-local commitment tx
	nodes[1].node.fail_htlc_backwards(&payment_hash_2);
	check_added_monitors(&nodes[1], 0);
	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[1],
		&[HTLCHandlingFailureType::Receive { payment_hash: payment_hash_2 }],
	);
	check_added_monitors(&nodes[1], 1);

	let remove = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &remove.update_fail_htlcs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &remove.commitment_signed);
	check_added_monitors(&nodes[0], 1);

	// Cache one local commitment tx as lastest
	let as_last_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	match events[0] {
		MessageSendEvent::SendRevokeAndACK { node_id, .. } => {
			assert_eq!(node_id, node_b_id);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::UpdateHTLCs { node_id, .. } => {
			assert_eq!(node_id, node_b_id);
		},
		_ => panic!("Unexpected event"),
	}

	assert_ne!(as_prev_commitment_tx, as_last_commitment_tx);
	// Fail the 2 dust-HTLCs, move their failure in maturation buffer (htlc_updated_waiting_threshold_conf)
	if announce_latest {
		mine_transaction(&nodes[0], &as_last_commitment_tx[0]);
	} else {
		mine_transaction(&nodes[0], &as_prev_commitment_tx[0]);
	}

	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);

	assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	check_added_monitors(&nodes[0], 0);
	let events = nodes[0].node.get_and_clear_pending_events();
	check_added_monitors(&nodes[0], 2);
	// Only 2 PaymentPathFailed events should show up, over-dust HTLC has to be failed by timeout tx
	assert_eq!(events.len(), 4);
	let mut first_failed = false;
	for event in events {
		match event {
			Event::PaymentPathFailed { payment_hash, .. } => {
				if payment_hash == payment_hash_1 {
					assert!(!first_failed);
					first_failed = true;
				} else {
					assert_eq!(payment_hash, payment_hash_2);
				}
			},
			Event::PaymentFailed { .. } => {},
			_ => panic!("Unexpected event"),
		}
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_failure_delay_dust_htlc_local_commitment() {
	do_test_failure_delay_dust_htlc_local_commitment(true);
	do_test_failure_delay_dust_htlc_local_commitment(false);
}

fn do_test_sweep_outbound_htlc_failure_update(revoked: bool, local: bool) {
	// Outbound HTLC-failure updates must be cancelled if we get a reorg before we reach ANTI_REORG_DELAY.
	// Broadcast of revoked remote commitment tx, trigger failure-update of dust/non-dust HTLCs
	// Broadcast of remote commitment tx, trigger failure-update of dust-HTLCs
	// Broadcast of timeout tx on remote commitment tx, trigger failure-udate of non-dust HTLCs
	// Broadcast of local commitment tx, trigger failure-update of dust-HTLCs
	// Broadcast of HTLC-timeout tx on local commitment tx, trigger failure-update of non-dust HTLCs

	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let bs_dust_limit = {
		let per_peer_state_lock;
		let mut peer_state_lock;
		let chan =
			get_channel_ref!(nodes[1], nodes[0], per_peer_state_lock, peer_state_lock, chan.2);
		chan.context().holder_dust_limit_satoshis
	};

	let (_payment_preimage_1, dust_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1]], bs_dust_limit * 1000);
	let (_payment_preimage_2, non_dust_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 1000000);

	let as_commitment_tx = get_local_commitment_txn!(nodes[0], chan.2);
	let bs_commitment_tx = get_local_commitment_txn!(nodes[1], chan.2);

	// We revoked bs_commitment_tx
	if revoked {
		let (payment_preimage_3, ..) = route_payment(&nodes[0], &[&nodes[1]], 1000000);
		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_3);
	}

	let mut timeout_tx = Vec::new();
	if local {
		// We fail dust-HTLC 1 by broadcast of local commitment tx
		mine_transaction(&nodes[0], &as_commitment_tx[0]);
		let reason = ClosureReason::CommitmentTxConfirmed;
		check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors(&nodes[0], 1);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		let conditions = PaymentFailedConditions::new().from_mon_update();
		expect_payment_failed_conditions(&nodes[0], dust_hash, false, conditions);

		connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS - ANTI_REORG_DELAY);
		check_added_monitors(&nodes[0], 0);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		timeout_tx.push(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0].clone());
		assert_eq!(
			timeout_tx[0].input[0].witness.last().unwrap().len(),
			OFFERED_HTLC_SCRIPT_WEIGHT
		);
		// We fail non-dust-HTLC 2 by broadcast of local HTLC-timeout tx on local commitment tx
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		mine_transaction(&nodes[0], &timeout_tx[0]);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		let conditions = PaymentFailedConditions::new().from_mon_update();
		expect_payment_failed_conditions(&nodes[0], non_dust_hash, false, conditions);
	} else {
		// We fail dust-HTLC 1 by broadcast of remote commitment tx. If revoked, fail also non-dust HTLC
		mine_transaction(&nodes[0], &bs_commitment_tx[0]);
		check_closed_broadcast!(nodes[0], true);
		check_added_monitors(&nodes[0], 1);
		let reason = ClosureReason::CommitmentTxConfirmed;
		check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);

		connect_blocks(&nodes[0], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires
		timeout_tx = nodes[0]
			.tx_broadcaster
			.txn_broadcasted
			.lock()
			.unwrap()
			.drain(..)
			.filter(|tx| tx.input[0].previous_output.txid == bs_commitment_tx[0].compute_txid())
			.collect();
		check_spends!(timeout_tx[0], bs_commitment_tx[0]);
		// For both a revoked or non-revoked commitment transaction, after ANTI_REORG_DELAY the
		// dust HTLC should have been failed.
		let conditions = PaymentFailedConditions::new().from_mon_update();
		expect_payment_failed_conditions(&nodes[0], dust_hash, false, conditions);

		if !revoked {
			assert_eq!(
				timeout_tx[0].input[0].witness.last().unwrap().len(),
				ACCEPTED_HTLC_SCRIPT_WEIGHT
			);
		} else {
			assert_eq!(timeout_tx[0].lock_time.to_consensus_u32(), 11);
		}
		// We fail non-dust-HTLC 2 by broadcast of local timeout/revocation-claim tx
		mine_transaction(&nodes[0], &timeout_tx[0]);
		assert_eq!(nodes[0].node.get_and_clear_pending_events().len(), 0);
		connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
		let conditions = PaymentFailedConditions::new().from_mon_update();
		expect_payment_failed_conditions(&nodes[0], non_dust_hash, false, conditions);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_sweep_outbound_htlc_failure_update() {
	do_test_sweep_outbound_htlc_failure_update(false, true);
	do_test_sweep_outbound_htlc_failure_update(false, false);
	do_test_sweep_outbound_htlc_failure_update(true, false);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_check_htlc_underpaying() {
	// Send payment through A -> B but A is maliciously
	// sending a probe payment (i.e less than expected value0
	// to B, B should refuse payment.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channels
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, 10_000);
	let route = get_route(
		&node_a_id,
		&route_params,
		&nodes[0].network_graph.read_only(),
		None,
		nodes[0].logger,
		&scorer,
		&Default::default(),
		&random_seed_bytes,
	)
	.unwrap();

	let (_, our_payment_hash, _) = get_payment_preimage_hash!(nodes[0]);
	let our_payment_secret = nodes[1]
		.node
		.create_inbound_payment_for_hash(our_payment_hash, Some(100_000), 7200, None)
		.unwrap();
	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);

	// Note that we first have to wait a random delay before processing the receipt of the HTLC,
	// and then will wait a second random delay before failing the HTLC back:
	expect_and_process_pending_htlcs(&nodes[1], true);
	let events = nodes[1].node.get_and_clear_pending_events();
	let fail = HTLCHandlingFailureType::Receive { payment_hash: our_payment_hash };
	expect_htlc_failure_conditions(events, &[fail]);

	// Node 3 is expecting payment of 100_000 but received 10_000,
	// it should fail htlc like we didn't know the preimage.
	nodes[1].node.process_pending_htlc_forwards();

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let (update_fail_htlc, commitment_signed) = match events[0] {
		MessageSendEvent::UpdateHTLCs {
			updates:
				msgs::CommitmentUpdate {
					ref update_add_htlcs,
					ref update_fulfill_htlcs,
					ref update_fail_htlcs,
					ref update_fail_malformed_htlcs,
					ref update_fee,
					ref commitment_signed,
				},
			..
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
	check_added_monitors(&nodes[1], 1);

	nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlc);
	do_commitment_signed_dance(&nodes[0], &nodes[1], commitment_signed, false, true);

	// 10_000 msat as u64, followed by a height of CHAN_CONFIRM_DEPTH as u32
	let mut expected_failure_data = (10_000 as u64).to_be_bytes().to_vec();
	expected_failure_data.extend_from_slice(&CHAN_CONFIRM_DEPTH.to_be_bytes());
	let reason = LocalHTLCFailureReason::IncorrectPaymentDetails;
	expect_payment_failed!(nodes[0], our_payment_hash, true, reason, &expected_failure_data[..]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_announce_disable_channels() {
	// Create 2 channels between A and B. Disconnect B. Call timer_tick_occurred and check for generated
	// ChannelUpdate. Reconnect B, reestablish and check there is non-generated ChannelUpdate.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Connect a dummy node for proper future events broadcasting
	connect_dummy_node(&nodes[0]);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 0);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// Disconnect peers
	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	for _ in 0..DISABLE_GOSSIP_TICKS + 1 {
		nodes[0].node.timer_tick_occurred();
	}
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3);
	let mut chans_disabled = new_hash_map();
	for e in msg_events {
		match e {
			MessageSendEvent::BroadcastChannelUpdate { ref msg, .. } => {
				assert_eq!(msg.contents.channel_flags & (1 << 1), 1 << 1); // The "channel disabled" bit should be set
														   // Check that each channel gets updated exactly once
				if chans_disabled
					.insert(msg.contents.short_channel_id, msg.contents.timestamp)
					.is_some()
				{
					panic!("Generated ChannelUpdate for wrong chan!");
				}
			},
			_ => panic!("Unexpected event"),
		}
	}
	// Reconnect peers
	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 3);
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 3);

	// Reestablish chan_1
	nodes[0].node.handle_channel_reestablish(node_b_id, &reestablish_2[0]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(node_a_id, &reestablish_1[0]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
	// Reestablish chan_2
	nodes[0].node.handle_channel_reestablish(node_b_id, &reestablish_2[1]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(node_a_id, &reestablish_1[1]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);
	// Reestablish chan_3
	nodes[0].node.handle_channel_reestablish(node_b_id, &reestablish_2[2]);
	handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(node_a_id, &reestablish_1[2]);
	handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	for _ in 0..ENABLE_GOSSIP_TICKS {
		nodes[0].node.timer_tick_occurred();
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.timer_tick_occurred();
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 3);
	for e in msg_events {
		match e {
			MessageSendEvent::BroadcastChannelUpdate { ref msg, .. } => {
				assert_eq!(msg.contents.channel_flags & (1 << 1), 0); // The "channel disabled" bit should be off
				match chans_disabled.remove(&msg.contents.short_channel_id) {
					// Each update should have a higher timestamp than the previous one, replacing
					// the old one.
					Some(prev_timestamp) => assert!(msg.contents.timestamp > prev_timestamp),
					None => panic!("Generated ChannelUpdate for wrong chan!"),
				}
			},
			_ => panic!("Unexpected event"),
		}
	}
	// Check that each channel gets updated exactly once
	assert!(chans_disabled.is_empty());
}

#[xtest(feature = "_externalize_tests")]
pub fn test_bump_penalty_txn_on_revoked_commitment() {
	// In case of penalty txn with too low feerates for getting into mempools, RBF-bump them to be sure
	// we're able to claim outputs on revoked commitment transaction before timelocks expiration

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);

	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 3000000).0;
	let payment_params = PaymentParameters::from_node_id(node_a_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[0].node.bolt11_invoice_features())
		.unwrap();
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[1], nodes[0], payment_params, 3000000);
	send_along_route(&nodes[1], route, &[&nodes[0]], 3000000);

	let revoked_txn = get_local_commitment_txn!(nodes[0], chan.2);
	// Revoked commitment txn with 4 outputs : to_local, to_remote, 1 outgoing HTLC, 1 incoming HTLC
	assert_eq!(revoked_txn[0].output.len(), 4);
	assert_eq!(revoked_txn[0].input.len(), 1);
	assert_eq!(revoked_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

	// Connect blocks to change height_timer range to see if we use right soonest_timelock
	let header_114 = connect_blocks(&nodes[1], 14);

	// Actually revoke tx by claiming a HTLC
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
	connect_block(&nodes[1], &create_dummy_block(header_114, 42, vec![revoked_txn[0].clone()]));
	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);

	macro_rules! check_broadcasted_txn {
		($penalty_txids:ident, $fee_rates:ident) => {
			let mut $penalty_txids = new_hash_map();
			let mut $fee_rates = new_hash_map();
			{
				let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
				// 2 justice txs can be broadcasted from ChannelMonitor:
				// - 1 unpinnable, revoked to_self output.
				// - 2 pinnable, revoked HTLC outputs.
				// Note that the revoked HTLC output has a slow timer, as we can always claim
				// from the second stage HTLC transaction.
				assert_eq!(node_txn.len(), 2);
				for tx in node_txn.iter() {
					assert!(tx.input.len() == 1 || tx.input.len() == 2);
					assert_eq!(tx.output.len(), 1);
					check_spends!(tx, revoked_txn[0]);
					let total_input: u64 = tx
						.input
						.iter()
						.map(|i| {
							revoked_txn[0].output[i.previous_output.vout as usize].value.to_sat()
						})
						.sum();
					let fee_rate: u64 =
						(total_input - tx.output[0].value.to_sat()) * 1000 / tx.weight().to_wu();
					assert_ne!(fee_rate, 0);
					for input in &tx.input {
						$fee_rates.insert(input.previous_output, fee_rate);
						$penalty_txids.insert(input.previous_output, tx.compute_txid());
					}
				}
				assert_eq!($fee_rates.len(), 3);
				assert_eq!($penalty_txids.len(), 3);
				node_txn.clear();
			}
		};
	}

	// One or more justice tx should have been broadcast, check it.
	check_broadcasted_txn!(penalty_txids_1, fee_rates_1);

	// After 15 blocks, the height timer for both the to_self claim and HTLC claims should be triggered,
	// and new bumped justice transactions should have been broadcast.
	connect_blocks(&nodes[1], 15);
	check_broadcasted_txn!(penalty_txids_2, fee_rates_2);
	// Verify new bumped tx is different from last claiming transaction, we don't want spurious rebroadcasts.
	for (outpoint, txid) in &penalty_txids_2 {
		assert_ne!(txid, &penalty_txids_1[outpoint]);
	}
	// Verify 25% bump heuristic.
	for (outpoint, fee_rate) in &fee_rates_2 {
		assert!(fee_rate * 100 >= fee_rates_1[outpoint] * 125);
	}

	// After another 15 blocks, the height timers should be triggered again.
	connect_blocks(&nodes[1], 15);
	check_broadcasted_txn!(penalty_txids_3, fee_rates_3);
	// Verify new bumped tx is different from last claiming transaction, we don't want spurious rebroadcasts.
	for (outpoint, txid) in &penalty_txids_3 {
		assert_ne!(txid, &penalty_txids_1[outpoint]);
	}
	// Verify 25% bump heuristic.
	for (outpoint, fee_rate) in &fee_rates_3 {
		assert!(fee_rate * 100 >= fee_rates_2[outpoint] * 125);
	}

	nodes[1].node.get_and_clear_pending_events();
	nodes[1].node.get_and_clear_pending_msg_events();
}

#[xtest(feature = "_externalize_tests")]
pub fn test_bump_penalty_txn_on_revoked_htlcs() {
	// In case of penalty txn with too low feerates for getting into mempools, RBF-bump them to sure
	// we're able to claim outputs on revoked HTLC transactions before timelocks expiration

	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);
	// Lock HTLC in both directions (using a slightly lower CLTV delay to provide timely RBF bumps)
	let payment_params = PaymentParameters::from_node_id(node_b_id, 50)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let scorer = test_utils::TestScorer::new();
	let random_seed_bytes = chanmon_cfgs[1].keys_manager.get_secure_random_bytes();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, 3_000_000);
	let route = get_route(
		&node_a_id,
		&route_params,
		&nodes[0].network_graph.read_only(),
		None,
		nodes[0].logger,
		&scorer,
		&Default::default(),
		&random_seed_bytes,
	)
	.unwrap();
	let payment_preimage = send_along_route(&nodes[0], route, &[&nodes[1]], 3_000_000).0;
	let payment_params = PaymentParameters::from_node_id(node_a_id, 50)
		.with_bolt11_features(nodes[0].node.bolt11_invoice_features())
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params, 3_000_000);
	let route = get_route(
		&node_b_id,
		&route_params,
		&nodes[1].network_graph.read_only(),
		None,
		nodes[0].logger,
		&scorer,
		&Default::default(),
		&random_seed_bytes,
	)
	.unwrap();
	let failed_payment_hash = send_along_route(&nodes[1], route, &[&nodes[0]], 3_000_000).1;

	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

	// Revoke local commitment tx
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	// B will generate both revoked HTLC-timeout/HTLC-preimage txn from revoked commitment tx
	connect_block(
		&nodes[1],
		&create_dummy_block(nodes[1].best_block_hash(), 42, vec![revoked_local_txn[0].clone()]),
	);
	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 1000000);
	connect_blocks(&nodes[1], 50); // Confirm blocks until the HTLC expires (note CLTV was explicitly 50 above)

	let revoked_htlc_txn = {
		let txn = nodes[1].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(txn.len(), 2);

		assert_eq!(txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		assert_eq!(txn[0].input.len(), 1);
		check_spends!(txn[0], revoked_local_txn[0]);

		assert_eq!(txn[1].input.len(), 1);
		assert_eq!(txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		assert_eq!(txn[1].output.len(), 1);
		check_spends!(txn[1], revoked_local_txn[0]);

		txn
	};

	// Broadcast set of revoked txn on A
	let hash_128 = connect_blocks(&nodes[0], 40);
	let block_11 = create_dummy_block(hash_128, 42, vec![revoked_local_txn[0].clone()]);
	connect_block(&nodes[0], &block_11);
	check_closed_broadcast(&nodes[0], 1, true);
	check_added_monitors(&nodes[0], 1);
	let block_129 = create_dummy_block(
		block_11.block_hash(),
		42,
		vec![revoked_htlc_txn[0].clone(), revoked_htlc_txn[1].clone()],
	);
	connect_block(&nodes[0], &block_129);
	let events = nodes[0].node.get_and_clear_pending_events();
	expect_htlc_failure_conditions(
		events[0..1].to_vec(),
		&[HTLCHandlingFailureType::Receive { payment_hash: failed_payment_hash }],
	);
	match events.last().unwrap() {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {},
		_ => panic!("Unexpected event"),
	}
	let first;
	let feerate_1;
	let penalty_txn;
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// 1 penalty transaction of the to_remote output on the revoked commitment tx,
		// 1 aggregated penalty transaction of the htlc outputs on the revoked commitment tx,
		// 1 aggregated penalty transaction of the two revoked HTLC txs.
		assert_eq!(node_txn.len(), 3);
		// Verify claim tx are spending revoked HTLC txn

		// node_txn 0-2 each spend a separate revoked output from revoked_local_txn[0]
		// Note that node_txn[1] and node_txn[2] are bogus - they double spend the revoked_htlc_txn
		// which are included in the same block (they are broadcasted because we scan the
		// transactions linearly and generate claims as we go, they likely should be removed in the
		// future).
		assert_eq!(node_txn[0].input.len(), 1);
		check_spends!(node_txn[0], revoked_local_txn[0]);
		assert_eq!(node_txn[1].input.len(), 2);
		check_spends!(node_txn[1], revoked_local_txn[0]);

		// Each of the three justice transactions claim a separate (single) output of the three
		// available, which we check here:
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[1].previous_output);
		assert_ne!(node_txn[1].input[0].previous_output, node_txn[1].input[1].previous_output);

		assert_eq!(
			node_txn[1].input[0].previous_output,
			revoked_htlc_txn[1].input[0].previous_output
		);
		assert_eq!(
			node_txn[1].input[1].previous_output,
			revoked_htlc_txn[0].input[0].previous_output
		);

		// node_txn[3] spends the revoked outputs from the revoked_htlc_txn (which only have one
		// output, checked above).
		assert_eq!(node_txn[2].input.len(), 2);
		assert_eq!(node_txn[2].output.len(), 1);
		check_spends!(node_txn[2], revoked_htlc_txn[0], revoked_htlc_txn[1]);

		first = node_txn[2].compute_txid();
		// Store both feerates for later comparison
		let fee_1 = revoked_htlc_txn[0].output[0].value + revoked_htlc_txn[1].output[0].value
			- node_txn[2].output[0].value;
		feerate_1 = fee_1 * 1000 / node_txn[2].weight().to_wu();
		penalty_txn = vec![node_txn[0].clone()];
		node_txn.clear();
	}

	// Connect one more block to see if bumped penalty are issued for HTLC txn
	let block_130 = create_dummy_block(block_129.block_hash(), 42, penalty_txn);
	connect_block(&nodes[0], &block_130);
	let block_131 = create_dummy_block(block_130.block_hash(), 42, Vec::new());
	connect_block(&nodes[0], &block_131);

	// Few more blocks to confirm penalty txn
	connect_blocks(&nodes[0], 4);
	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	let header_144 = connect_blocks(&nodes[0], 9);
	let node_txn = {
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);

		assert_eq!(node_txn[0].input.len(), 2);
		check_spends!(node_txn[0], revoked_htlc_txn[0], revoked_htlc_txn[1]);
		// Verify bumped tx is different and 25% bump heuristic
		assert_ne!(first, node_txn[0].compute_txid());
		let fee_2 = revoked_htlc_txn[0].output[0].value + revoked_htlc_txn[1].output[0].value
			- node_txn[0].output[0].value;
		let feerate_2 = fee_2 * 1000 / node_txn[0].weight().to_wu();
		assert!(feerate_2 * 100 > feerate_1 * 125);
		let txn = vec![node_txn[0].clone()];
		node_txn.clear();
		txn
	};
	// Broadcast claim txn and confirm blocks to avoid further bumps on this outputs
	connect_block(&nodes[0], &create_dummy_block(header_144, 42, node_txn));
	connect_blocks(&nodes[0], 20);
	{
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// We verify than no new transaction has been broadcast because previously
		// we were buggy on this exact behavior by not tracking for monitoring remote HTLC outputs (see #411)
		// which means we wouldn't see a spend of them by a justice tx and bumped justice tx
		// were generated forever instead of safe cleaning after confirmation and ANTI_REORG_SAFE_DELAY blocks.
		// Enforce spending of revoked htlc output by claiming transaction remove request as expected and dry
		// up bumped justice generation.
		assert_eq!(node_txn.len(), 0);
		node_txn.clear();
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_bump_penalty_txn_on_remote_commitment() {
	// In case of claim txn with too low feerates for getting into mempools, RBF-bump them to be sure
	// we're able to claim outputs on remote commitment transaction before timelocks expiration

	// Create 2 HTLCs
	// Provide preimage for one
	// Check aggregation

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let remote_txn = {
		// post-bump fee (288 satoshis) + dust threshold for output type (294 satoshis) = 582
		let htlc_value_a_msats = 582_000;
		let htlc_value_b_msats = 583_000;

		let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);
		let (payment_preimage, payment_hash, ..) =
			route_payment(&nodes[0], &[&nodes[1]], htlc_value_a_msats);
		route_payment(&nodes[1], &[&nodes[0]], htlc_value_b_msats);

		// Remote commitment txn with 4 outputs : to_local, to_remote, 1 outgoing HTLC, 1 incoming HTLC
		let remote_txn = get_local_commitment_txn!(nodes[0], chan.2);
		assert_eq!(remote_txn[0].output.len(), 4);
		assert_eq!(remote_txn[0].input.len(), 1);
		assert_eq!(remote_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

		// Claim a HTLC without revocation (provide B monitor with preimage)
		nodes[1].node.claim_funds(payment_preimage);
		expect_payment_claimed!(nodes[1], payment_hash, htlc_value_a_msats);
		let _ = get_htlc_update_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
		mine_transaction(&nodes[1], &remote_txn[0]);
		check_closed_broadcast(&nodes[1], 1, true);
		check_added_monitors(&nodes[1], 2);
		connect_blocks(&nodes[1], TEST_FINAL_CLTV); // Confirm blocks until the HTLC expires

		// depending on the block connection style, node 1 may have broadcast either 3 or 10 txs

		remote_txn
	};

	// One or more claim tx should have been broadcast, check it
	let timeout;
	let preimage;
	let preimage_bump;
	let feerate_timeout;
	let feerate_preimage;
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		// 3 transactions including:
		//   preimage and timeout sweeps from remote commitment + preimage sweep bump
		assert_eq!(node_txn.len(), 3);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[2].input.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		check_spends!(node_txn[1], remote_txn[0]);
		check_spends!(node_txn[2], remote_txn[0]);

		preimage = node_txn[0].compute_txid();
		let index = node_txn[0].input[0].previous_output.vout;
		let fee = remote_txn[0].output[index as usize].value.to_sat()
			- node_txn[0].output[0].value.to_sat();
		feerate_preimage = fee * 1000 / node_txn[0].weight().to_wu();

		let (preimage_bump_tx, timeout_tx) =
			if node_txn[2].input[0].previous_output == node_txn[0].input[0].previous_output {
				(node_txn[2].clone(), node_txn[1].clone())
			} else {
				(node_txn[1].clone(), node_txn[2].clone())
			};

		preimage_bump = preimage_bump_tx;
		check_spends!(preimage_bump, remote_txn[0]);
		assert_eq!(node_txn[0].input[0].previous_output, preimage_bump.input[0].previous_output);

		timeout = timeout_tx.compute_txid();
		let index = timeout_tx.input[0].previous_output.vout;
		let fee = remote_txn[0].output[index as usize].value.to_sat()
			- timeout_tx.output[0].value.to_sat();
		feerate_timeout = fee * 1000 / timeout_tx.weight().to_wu();

		node_txn.clear();
	};
	assert_ne!(feerate_timeout, 0);
	assert_ne!(feerate_preimage, 0);

	// After exhaustion of height timer, new bumped claim txn should have been broadcast, check it
	connect_blocks(&nodes[1], crate::chain::package::LOW_FREQUENCY_BUMP_INTERVAL);
	{
		let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(preimage_bump.input.len(), 1);
		check_spends!(node_txn[0], remote_txn[0]);
		check_spends!(preimage_bump, remote_txn[0]);

		let index = preimage_bump.input[0].previous_output.vout;
		let fee = remote_txn[0].output[index as usize].value.to_sat()
			- preimage_bump.output[0].value.to_sat();
		let new_feerate = fee * 1000 / preimage_bump.weight().to_wu();
		assert!(new_feerate * 100 > feerate_timeout * 125);
		assert_ne!(timeout, preimage_bump.compute_txid());

		let index = node_txn[0].input[0].previous_output.vout;
		let fee = remote_txn[0].output[index as usize].value.to_sat()
			- node_txn[0].output[0].value.to_sat();
		let new_feerate = fee * 1000 / node_txn[0].weight().to_wu();
		assert!(new_feerate * 100 > feerate_preimage * 125);
		assert_ne!(preimage, node_txn[0].compute_txid());

		node_txn.clear();
	}

	nodes[1].node.get_and_clear_pending_events();
	nodes[1].node.get_and_clear_pending_msg_events();
}

#[xtest(feature = "_externalize_tests")]
pub fn test_counterparty_raa_skip_no_crash() {
	// Previously, if our counterparty sent two RAAs in a row without us having provided a
	// commitment transaction, we would have happily carried on and provided them the next
	// commitment transaction based on one RAA forward. This would probably eventually have led to
	// channel closure, but it would not have resulted in funds loss. Still, our
	// TestChannelSigner would have panicked as it doesn't like jumps into the future. Here, we
	// check simply that the channel is closed in response to such an RAA, but don't check whether
	// we decide to punish our counterparty for revoking their funds (as we don't currently
	// implement that).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let channel_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let per_commitment_secret;
	let next_per_commitment_point;
	{
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let mut guard = per_peer_state.get(&node_b_id).unwrap().lock().unwrap();
		let keys =
			guard.channel_by_id.get(&channel_id).and_then(Channel::as_funded).unwrap().get_signer();

		const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

		// Make signer believe we got a counterparty signature, so that it allows the revocation
		keys.as_ecdsa().unwrap().get_enforcement_state().last_holder_commitment -= 1;
		per_commitment_secret =
			keys.as_ref().release_commitment_secret(INITIAL_COMMITMENT_NUMBER).unwrap();

		// Must revoke without gaps
		keys.as_ecdsa().unwrap().get_enforcement_state().last_holder_commitment -= 1;
		keys.as_ref().release_commitment_secret(INITIAL_COMMITMENT_NUMBER - 1).unwrap();

		keys.as_ecdsa().unwrap().get_enforcement_state().last_holder_commitment -= 1;
		let sec = keys.as_ref().release_commitment_secret(INITIAL_COMMITMENT_NUMBER - 2).unwrap();
		let key = SecretKey::from_slice(&sec).unwrap();
		next_per_commitment_point = PublicKey::from_secret_key(&Secp256k1::new(), &key);
	}

	let raa = msgs::RevokeAndACK {
		channel_id,
		per_commitment_secret,
		next_per_commitment_point,
		#[cfg(taproot)]
		next_local_nonce: None,
		release_htlc_message_paths: Vec::new(),
	};
	nodes[1].node.handle_revoke_and_ack(node_a_id, &raa);
	assert_eq!(
		check_closed_broadcast!(nodes[1], true).unwrap().data,
		"Received an unexpected revoke_and_ack"
	);
	check_added_monitors(&nodes[1], 1);
	let reason =
		ClosureReason::ProcessingError { err: "Received an unexpected revoke_and_ack".to_string() };
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_bump_txn_sanitize_tracking_maps() {
	// Sanitizing pending_claim_request and claimable_outpoints used to be buggy,
	// verify we clean then right after expiration of ANTI_REORG_DELAY.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000);
	// Lock HTLC in both directions
	let (payment_preimage_1, ..) = route_payment(&nodes[0], &[&nodes[1]], 9_000_000);
	let (_, payment_hash_2, ..) = route_payment(&nodes[1], &[&nodes[0]], 9_000_000);

	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan.2);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, chan.3.compute_txid());

	// Revoke local commitment tx
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_1);

	// Broadcast set of revoked txn on A
	connect_blocks(&nodes[0], TEST_FINAL_CLTV + 2 - CHAN_CONFIRM_DEPTH);
	expect_htlc_failure_conditions(
		nodes[0].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash: payment_hash_2 }],
	);
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 0);

	mine_transaction(&nodes[0], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 1000000);
	let penalty_txn = {
		let mut node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 2); //ChannelMonitor: justice txn * 2
		check_spends!(node_txn[0], revoked_local_txn[0]);
		assert_eq!(node_txn[0].input.len(), 1);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		assert_eq!(node_txn[1].input.len(), 2);
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[0].previous_output);
		assert_ne!(node_txn[0].input[0].previous_output, node_txn[1].input[1].previous_output);
		assert_ne!(node_txn[1].input[0].previous_output, node_txn[1].input[1].previous_output);
		let penalty_txn = vec![node_txn[0].clone(), node_txn[1].clone()];
		node_txn.clear();
		penalty_txn
	};
	connect_block(&nodes[0], &create_dummy_block(nodes[0].best_block_hash(), 42, penalty_txn));
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	{
		let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(chan.2).unwrap();
		assert!(monitor.inner.lock().unwrap().onchain_tx_handler.pending_claim_requests.is_empty());
		assert!(monitor.inner.lock().unwrap().onchain_tx_handler.claimable_outpoints.is_empty());
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_channel_conf_timeout() {
	// Tests that, for inbound channels, we give up on them if the funding transaction does not
	// confirm within 2016 blocks, as recommended by BOLT 2.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	let funding_tx =
		create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 1_000_000, 100_000);

	// Inbound channels which haven't advanced state at all and never were funded will generate
	// claimable `Balance`s until they're closed.
	assert!(!nodes[1].chain_monitor.chain_monitor.get_claimable_balances(&[]).is_empty());

	// The outbound node should wait forever for confirmation:
	// This matches `channel::FUNDING_CONF_DEADLINE_BLOCKS` and BOLT 2's suggested timeout, thus is
	// copied here instead of directly referencing the constant.
	connect_blocks(&nodes[0], 2016);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// The inbound node should fail the channel after exactly 2016 blocks
	connect_blocks(&nodes[1], 2015);
	check_added_monitors(&nodes[1], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	nodes[1].chain_monitor.chain_monitor.archive_fully_resolved_channel_monitors();
	assert_eq!(nodes[1].chain_monitor.chain_monitor.list_monitors().len(), 1);
	assert!(!nodes[1].chain_monitor.chain_monitor.get_claimable_balances(&[]).is_empty());

	connect_blocks(&nodes[1], 1);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::FundingTimedOut;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 1000000);
	let close_ev = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(close_ev.len(), 1);
	match close_ev[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg },
			ref node_id,
		} => {
			assert_eq!(*node_id, node_a_id);
			assert_eq!(
				msg.data,
				"Channel closed because funding transaction failed to confirm within 2016 blocks"
			);
		},
		_ => panic!("Unexpected event"),
	}

	// Once an inbound never-confirmed channel is closed, it will no longer generate any claimable
	// `Balance`s.
	assert!(nodes[1].chain_monitor.chain_monitor.get_claimable_balances(&[]).is_empty());

	// Once the funding times out the monitor should be immediately archived.
	nodes[1].chain_monitor.chain_monitor.archive_fully_resolved_channel_monitors();
	assert_eq!(nodes[1].chain_monitor.chain_monitor.list_monitors().len(), 0);
	assert!(nodes[1].chain_monitor.chain_monitor.get_claimable_balances(&[]).is_empty());

	// Remove the corresponding outputs and transactions the chain source is
	// watching. This is to make sure the `Drop` function assertions pass.
	nodes[1].chain_source.remove_watched_txn_and_outputs(
		OutPoint { txid: funding_tx.compute_txid(), index: 0 },
		funding_tx.output[0].script_pubkey.clone(),
	);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_override_channel_config() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	// Node0 initiates a channel to node1 using the override config.
	let mut override_config = UserConfig::default();
	override_config.channel_handshake_config.our_to_self_delay = 200;

	nodes[0]
		.node
		.create_channel(node_b_id, 16_000_000, 12_000_000, 42, None, Some(override_config))
		.unwrap();

	// Assert the channel created by node0 is using the override config.
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	assert_eq!(res.common_fields.channel_flags, 0);
	assert_eq!(res.common_fields.to_self_delay, 200);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_override_0msat_htlc_minimum() {
	let mut zero_config = UserConfig::default();
	zero_config.channel_handshake_config.our_htlc_minimum_msat = 0;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(zero_config.clone())]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0]
		.node
		.create_channel(node_b_id, 16_000_000, 12_000_000, 42, None, Some(zero_config))
		.unwrap();
	let res = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	assert_eq!(res.common_fields.htlc_minimum_msat, 1);

	nodes[1].node.handle_open_channel(node_a_id, &res);
	let res = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	assert_eq!(res.common_fields.htlc_minimum_msat, 1);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_channel_update_has_correct_htlc_maximum_msat() {
	// Tests that the `ChannelUpdate` message has the correct values for `htlc_maximum_msat` set.
	// Bolt 7 specifies that if present `htlc_maximum_msat`:
	// 1. MUST be set to less than or equal to the channel capacity. In LDK, this is capped to
	// 90% of the `channel_value`.
	// 2. MUST be set to less than or equal to the `max_htlc_value_in_flight_msat` received from the peer.

	let mut config_30_percent = UserConfig::default();
	config_30_percent.channel_handshake_config.announce_for_forwarding = true;
	config_30_percent
		.channel_handshake_config
		.max_inbound_htlc_value_in_flight_percent_of_channel = 30;
	let mut config_50_percent = UserConfig::default();
	config_50_percent.channel_handshake_config.announce_for_forwarding = true;
	config_50_percent
		.channel_handshake_config
		.max_inbound_htlc_value_in_flight_percent_of_channel = 50;
	let mut config_95_percent = UserConfig::default();
	config_95_percent.channel_handshake_config.announce_for_forwarding = true;
	config_95_percent
		.channel_handshake_config
		.max_inbound_htlc_value_in_flight_percent_of_channel = 95;
	let mut config_100_percent = UserConfig::default();
	config_100_percent.channel_handshake_config.announce_for_forwarding = true;
	config_100_percent
		.channel_handshake_config
		.max_inbound_htlc_value_in_flight_percent_of_channel = 100;

	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let configs = [
		Some(config_30_percent),
		Some(config_50_percent),
		Some(config_95_percent),
		Some(config_100_percent),
	];
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &configs);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let channel_value_satoshis = 100000;
	let channel_value_msat = channel_value_satoshis * 1000;
	let channel_value_30_percent_msat = (channel_value_msat as f64 * 0.3) as u64;
	let channel_value_50_percent_msat = (channel_value_msat as f64 * 0.5) as u64;
	let channel_value_90_percent_msat = (channel_value_msat as f64 * 0.9) as u64;

	let (node_0_chan_update, node_1_chan_update, _, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, channel_value_satoshis, 10001);
	let (node_2_chan_update, node_3_chan_update, _, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 2, 3, channel_value_satoshis, 10001);

	// Assert that `node[0]`'s `ChannelUpdate` is capped at 50 percent of the `channel_value`, as
	// that's the value of `node[1]`'s `holder_max_htlc_value_in_flight_msat`.
	assert_eq!(node_0_chan_update.contents.htlc_maximum_msat, channel_value_50_percent_msat);
	// Assert that `node[1]`'s `ChannelUpdate` is capped at 30 percent of the `channel_value`, as
	// that's the value of `node[0]`'s `holder_max_htlc_value_in_flight_msat`.
	assert_eq!(node_1_chan_update.contents.htlc_maximum_msat, channel_value_30_percent_msat);

	// Assert that `node[2]`'s `ChannelUpdate` is capped at 90 percent of the `channel_value`, as
	// the value of `node[3]`'s `holder_max_htlc_value_in_flight_msat` (100%), exceeds 90% of the
	// `channel_value`.
	assert_eq!(node_2_chan_update.contents.htlc_maximum_msat, channel_value_90_percent_msat);
	// Assert that `node[3]`'s `ChannelUpdate` is capped at 90 percent of the `channel_value`, as
	// the value of `node[2]`'s `holder_max_htlc_value_in_flight_msat` (95%), exceeds 90% of the
	// `channel_value`.
	assert_eq!(node_3_chan_update.contents.htlc_maximum_msat, channel_value_90_percent_msat);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_onion_value_mpp_set_calculation() {
	// Test that we use the onion value `amt_to_forward` when
	// calculating whether we've reached the `total_msat` of an MPP
	// by having a routing node forward more than `amt_to_forward`
	// and checking that the receiving node doesn't generate
	// a PaymentClaimable event too early
	let node_count = 4;
	let chanmon_cfgs = create_chanmon_cfgs(node_count);
	let node_cfgs = create_node_cfgs(node_count, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(node_count, &node_cfgs, &vec![None; node_count]);
	let mut nodes = create_network(node_count, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

	let total_msat = 100_000;
	let expected_paths: &[&[&Node]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	let (mut route, hash, preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[3], total_msat);
	let sample_path = route.paths.pop().unwrap();

	let mut path_1 = sample_path.clone();
	path_1.hops[0].pubkey = node_b_id;
	path_1.hops[0].short_channel_id = chan_1_id;
	path_1.hops[1].pubkey = node_d_id;
	path_1.hops[1].short_channel_id = chan_3_id;
	path_1.hops[1].fee_msat = 100_000;
	route.paths.push(path_1);

	let mut path_2 = sample_path.clone();
	path_2.hops[0].pubkey = node_c_id;
	path_2.hops[0].short_channel_id = chan_2_id;
	path_2.hops[1].pubkey = node_d_id;
	path_2.hops[1].short_channel_id = chan_4_id;
	path_2.hops[1].fee_msat = 1_000;
	route.paths.push(path_2);

	// Send payment
	let id = PaymentId(nodes[0].keys_manager.backing.get_secure_random_bytes());
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let onion_session_privs =
		nodes[0].node.test_add_new_pending_payment(hash, onion.clone(), id, &route).unwrap();
	let amt = Some(total_msat);
	nodes[0]
		.node
		.test_send_payment_internal(&route, hash, onion, None, id, amt, onion_session_privs)
		.unwrap();
	check_added_monitors(&nodes[0], expected_paths.len());

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_paths.len());

	// First path
	let ev =
		remove_first_msg_event_to_node(&expected_paths[0][0].node.get_our_node_id(), &mut events);
	let mut payment_event = SendEvent::from_event(ev);
	let mut prev_node = &nodes[0];

	for (idx, &node) in expected_paths[0].iter().enumerate() {
		assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

		if idx == 0 {
			// Manipulate the onion packet for the routing node. Note that we pick a dummy session_priv here. The sender
			// won't be able to decode fulfill attribution data.
			let session_priv = [3; 32];
			let height = nodes[0].best_block_info().1;
			let session_priv = SecretKey::from_slice(&session_priv).unwrap();
			let mut onion_keys = onion_utils::construct_onion_keys(
				&Secp256k1::new(),
				&route.paths[0],
				&session_priv,
			);
			let recipient_onion_fields = RecipientOnionFields::secret_only(payment_secret);
			let (mut onion_payloads, _, _) = onion_utils::build_onion_payloads(
				&route.paths[0],
				100_000,
				&recipient_onion_fields,
				height + 1,
				&None,
				None,
				None,
			)
			.unwrap();
			// Edit amt_to_forward to simulate the sender having set
			// the final amount and the routing node taking less fee
			if let msgs::OutboundOnionPayload::Receive {
				ref mut sender_intended_htlc_amt_msat,
				..
			} = onion_payloads[1]
			{
				*sender_intended_htlc_amt_msat = 99_000;
			} else {
				panic!()
			}
			let new_onion_packet =
				onion_utils::construct_onion_packet(onion_payloads, onion_keys, [0; 32], &hash)
					.unwrap();
			payment_event.msgs[0].onion_routing_packet = new_onion_packet;
		}

		node.node.handle_update_add_htlc(prev_node.node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors(&node, 0);
		do_commitment_signed_dance(&node, &prev_node, &payment_event.commitment_msg, false, false);
		expect_and_process_pending_htlcs(&node, false);

		if idx == 0 {
			let mut events_2 = node.node.get_and_clear_pending_msg_events();
			assert_eq!(events_2.len(), 1);
			check_added_monitors(&node, 1);
			payment_event = SendEvent::from_event(events_2.remove(0));
			assert_eq!(payment_event.msgs.len(), 1);
		} else {
			let events_2 = node.node.get_and_clear_pending_events();
			assert!(events_2.is_empty());
		}

		prev_node = node;
	}

	// Second path
	let ev =
		remove_first_msg_event_to_node(&expected_paths[1][0].node.get_our_node_id(), &mut events);
	let payment_secret = Some(payment_secret);
	pass_along_path(&nodes[0], expected_paths[1], 101_000, hash, payment_secret, ev, true, None);

	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], expected_paths, preimage));
}

fn do_test_overshoot_mpp(msat_amounts: &[u64], total_msat: u64) {
	let routing_node_count = msat_amounts.len();
	let node_count = routing_node_count + 2;

	let chanmon_cfgs = create_chanmon_cfgs(node_count);
	let node_cfgs = create_node_cfgs(node_count, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(node_count, &node_cfgs, &vec![None; node_count]);
	let nodes = create_network(node_count, &node_cfgs, &node_chanmgrs);

	let src_idx = 0;
	let dst_idx = 1;

	// Create channels for each amount
	let mut expected_paths = Vec::with_capacity(routing_node_count);
	let mut src_chan_ids = Vec::with_capacity(routing_node_count);
	let mut dst_chan_ids = Vec::with_capacity(routing_node_count);
	for i in 0..routing_node_count {
		let routing_node = 2 + i;
		let src_chan = create_announced_chan_between_nodes(&nodes, src_idx, routing_node);
		let src_chan_id = src_chan.0.contents.short_channel_id;
		src_chan_ids.push(src_chan_id);

		let dst_chan = create_announced_chan_between_nodes(&nodes, routing_node, dst_idx);
		let dst_chan_id = dst_chan.0.contents.short_channel_id;
		dst_chan_ids.push(dst_chan_id);
		let path = vec![&nodes[routing_node], &nodes[dst_idx]];
		expected_paths.push(path);
	}
	let expected_paths: Vec<&[&Node]> =
		expected_paths.iter().map(|route| route.as_slice()).collect();

	// Create a route for each amount
	let example_amount = 100000;
	let (mut route, hash, preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[src_idx], nodes[dst_idx], example_amount);
	let sample_path = route.paths.pop().unwrap();
	for i in 0..routing_node_count {
		let routing_node = 2 + i;
		let mut path = sample_path.clone();
		path.hops[0].pubkey = nodes[routing_node].node.get_our_node_id();
		path.hops[0].short_channel_id = src_chan_ids[i];
		path.hops[1].pubkey = nodes[dst_idx].node.get_our_node_id();
		path.hops[1].short_channel_id = dst_chan_ids[i];
		path.hops[1].fee_msat = msat_amounts[i];
		route.paths.push(path);
	}

	// Send payment with manually set total_msat
	let id = PaymentId(nodes[src_idx].keys_manager.backing.get_secure_random_bytes());
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let onion_session_privs =
		nodes[src_idx].node.test_add_new_pending_payment(hash, onion, id, &route).unwrap();
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let amt = Some(total_msat);
	nodes[src_idx]
		.node
		.test_send_payment_internal(&route, hash, onion, None, id, amt, onion_session_privs)
		.unwrap();
	check_added_monitors(&nodes[src_idx], expected_paths.len());

	let mut events = nodes[src_idx].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_paths.len());
	let mut amount_received = 0;
	for (path_idx, expected_path) in expected_paths.iter().enumerate() {
		let ev =
			remove_first_msg_event_to_node(&expected_path[0].node.get_our_node_id(), &mut events);

		let current_path_amount = msat_amounts[path_idx];
		amount_received += current_path_amount;
		let became_claimable_now =
			amount_received >= total_msat && amount_received - current_path_amount < total_msat;
		pass_along_path(
			&nodes[src_idx],
			expected_path,
			amount_received,
			hash.clone(),
			Some(payment_secret),
			ev,
			became_claimable_now,
			None,
		);
	}

	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[src_idx], &expected_paths, preimage));
}

#[xtest(feature = "_externalize_tests")]
pub fn test_overshoot_mpp() {
	do_test_overshoot_mpp(&[100_000, 101_000], 200_000);
	do_test_overshoot_mpp(&[100_000, 10_000, 100_000], 200_000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_simple_mpp() {
	// Simple test of sending a multi-path payment.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3).0.contents.short_channel_id;

	let (mut route, payment_hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0].hops[0].pubkey = node_b_id;
	route.paths[0].hops[0].short_channel_id = chan_1_id;
	route.paths[0].hops[1].short_channel_id = chan_3_id;
	route.paths[1].hops[0].pubkey = node_c_id;
	route.paths[1].hops[0].short_channel_id = chan_2_id;
	route.paths[1].hops[1].short_channel_id = chan_4_id;
	let paths: &[&[_]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	send_along_route_with_secret(&nodes[0], route, paths, 200_000, payment_hash, payment_secret);
	claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], paths, payment_preimage));
}

#[xtest(feature = "_externalize_tests")]
pub fn test_preimage_storage() {
	// Simple test of payment preimage storage allowing no client-side storage to claim payments
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	{
		let (payment_hash, payment_secret) =
			nodes[1].node.create_inbound_payment(Some(100_000), 7200, None).unwrap();
		let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let id = PaymentId(payment_hash.0);
		nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();

		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		let mut payment_event = SendEvent::from_event(events.pop().unwrap());
		nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
		let commitment = &payment_event.commitment_msg;
		do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);
	}
	// Note that after leaving the above scope we have no knowledge of any arguments or return
	// values from previous calls.
	expect_and_process_pending_htlcs(&nodes[1], false);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::PaymentClaimable { ref purpose, .. } => match &purpose {
			PaymentPurpose::Bolt11InvoicePayment { payment_preimage, .. } => {
				claim_payment(&nodes[0], &[&nodes[1]], payment_preimage.unwrap());
			},
			_ => panic!("expected PaymentPurpose::Bolt11InvoicePayment"),
		},
		_ => panic!("Unexpected event"),
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_bad_secret_hash() {
	// Simple test of unregistered payment hash/invalid payment secret handling
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);

	let random_hash = PaymentHash([42; 32]);
	let random_secret = PaymentSecret([43; 32]);
	let (our_payment_hash, our_payment_secret) =
		nodes[1].node.create_inbound_payment(Some(100_000), 2, None).unwrap();
	let (route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);

	// All the below cases should end up being handled exactly identically, so we macro the
	// resulting events.
	macro_rules! handle_unknown_invalid_payment_data {
		($payment_hash: expr) => {
			check_added_monitors(&nodes[0], 1);
			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			let payment_event = SendEvent::from_event(events.pop().unwrap());
			nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
			let commitment = &payment_event.commitment_msg;
			do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);

			// We have to forward pending HTLCs once to process the receipt of the HTLC and then
			// again to process the pending backwards-failure of the HTLC
			expect_and_process_pending_htlcs(&nodes[1], true);
			let events = nodes[1].node.get_and_clear_pending_events();
			let fail = HTLCHandlingFailureType::Receive { payment_hash: $payment_hash };
			expect_htlc_failure_conditions(events, &[fail]);
			check_added_monitors(&nodes[1], 1);

			// We should fail the payment back
			let mut events = nodes[1].node.get_and_clear_pending_msg_events();
			match events.pop().unwrap() {
				MessageSendEvent::UpdateHTLCs {
					node_id: _,
					channel_id: _,
					updates: msgs::CommitmentUpdate { update_fail_htlcs, commitment_signed, .. },
				} => {
					nodes[0].node.handle_update_fail_htlc(node_b_id, &update_fail_htlcs[0]);
					do_commitment_signed_dance(
						&nodes[0],
						&nodes[1],
						&commitment_signed,
						false,
						false,
					);
				},
				_ => panic!("Unexpected event"),
			}
		};
	}

	let expected_err_code = LocalHTLCFailureReason::IncorrectPaymentDetails;
	// Error data is the HTLC value (100,000) and current block height
	let expected_err_data = [0, 0, 0, 0, 0, 1, 0x86, 0xa0, 0, 0, 0, CHAN_CONFIRM_DEPTH as u8];

	// Send a payment with the right payment hash but the wrong payment secret
	let onion = RecipientOnionFields::secret_only(random_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[0].node.send_payment_with_route(route.clone(), our_payment_hash, onion, id).unwrap();
	handle_unknown_invalid_payment_data!(our_payment_hash);
	expect_payment_failed!(nodes[0], our_payment_hash, true, expected_err_code, expected_err_data);

	// Send a payment with a random payment hash, but the right payment secret
	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	nodes[0].node.send_payment_with_route(route.clone(), random_hash, onion, id).unwrap();
	handle_unknown_invalid_payment_data!(random_hash);
	expect_payment_failed!(nodes[0], random_hash, true, expected_err_code, expected_err_data);

	// Send a payment with a random payment hash and random payment secret
	let onion = RecipientOnionFields::secret_only(random_secret);
	nodes[0].node.send_payment_with_route(route, random_hash, onion, id).unwrap();
	handle_unknown_invalid_payment_data!(random_hash);
	expect_payment_failed!(nodes[0], random_hash, true, expected_err_code, expected_err_data);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_update_err_monitor_lockdown() {
	// Our monitor will lock update of local commitment transaction if a broadcastion condition
	// has been fulfilled (either force-close from Channel or block height requiring a HTLC-
	// timeout). Trying to update monitor after lockdown should return a ChannelMonitorUpdateStatus
	// error.
	//
	// This scenario may happen in a watchtower setup, where watchtower process a block height
	// triggering a timeout while a slow-block-processing ChannelManager receives a local signed
	// commitment at same time.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channel
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &[&nodes[1]], 10_000_000);

	// Route a HTLC from node 0 to node 1 (but don't settle)
	let (preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 9_000_000);

	// Copy ChainMonitor to simulate a watchtower and update block height of node 0 until its ChannelMonitor timeout HTLC onchain
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id(format!("node {}", 0));
	let persister = test_utils::TestPersister::new();
	let watchtower = {
		let new_monitor = {
			let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(chan_1.2).unwrap();
			let new_monitor =
				<(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
					&mut io::Cursor::new(&monitor.encode()),
					(nodes[0].keys_manager, nodes[0].keys_manager),
				)
				.unwrap()
				.1;
			assert!(new_monitor == *monitor);
			new_monitor
		};
		let watchtower = test_utils::TestChainMonitor::new(
			Some(&chain_source),
			&chanmon_cfgs[0].tx_broadcaster,
			&logger,
			&chanmon_cfgs[0].fee_estimator,
			&persister,
			&node_cfgs[0].keys_manager,
		);
		assert_eq!(
			watchtower.watch_channel(chan_1.2, new_monitor),
			Ok(ChannelMonitorUpdateStatus::Completed)
		);
		watchtower
	};
	let block = create_dummy_block(BlockHash::all_zeros(), 42, Vec::new());
	// Make the tx_broadcaster aware of enough blocks that it doesn't think we're violating
	// transaction lock time requirements here.
	chanmon_cfgs[0].tx_broadcaster.blocks.lock().unwrap().resize(200, (block.clone(), 200));
	watchtower.chain_monitor.block_connected(&block, 200);

	// Try to update ChannelMonitor
	nodes[1].node.claim_funds(preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 9_000_000);

	let mut updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates.update_fulfill_htlcs.remove(0));
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let chan_ref =
			get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_1.2);
		if let Some(channel) = chan_ref.as_funded_mut() {
			assert_eq!(updates.commitment_signed.len(), 1);
			let feeest = LowerBoundedFeeEstimator::new(&chanmon_cfgs[0].fee_estimator);
			if let Ok(Some(update)) = channel.commitment_signed(
				&updates.commitment_signed[0],
				&feeest,
				&node_cfgs[0].logger,
			) {
				assert_eq!(
					watchtower.chain_monitor.update_channel(chan_1.2, &update),
					ChannelMonitorUpdateStatus::InProgress
				);
				assert_eq!(
					nodes[0].chain_monitor.update_channel(chan_1.2, &update),
					ChannelMonitorUpdateStatus::Completed
				);
			} else {
				assert!(false);
			}
		} else {
			assert!(false);
		}
	}
	// Our local monitor is in-sync and hasn't processed yet timeout
	check_added_monitors(&nodes[0], 1);
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_concurrent_monitor_claim() {
	// Watchtower A receives block, broadcasts state N, then channel receives new state N+1,
	// sending it to both watchtowers, Bob accepts N+1, then receives block and broadcasts
	// the latest state N+1, Alice rejects state N+1, but Bob has already broadcast it,
	// state N+1 confirms. Alice claims output from state N+1.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channel
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Rebalance the network to generate htlc in the two directions
	send_payment(&nodes[0], &[&nodes[1]], 10_000_000);

	// Route a HTLC from node 0 to node 1 (but don't settle)
	let (_, payment_hash_timeout, ..) = route_payment(&nodes[0], &[&nodes[1]], 9_000_000);

	// Copy ChainMonitor to simulate watchtower Alice and update block height her ChannelMonitor timeout HTLC onchain
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id("alice".to_string());
	let persister = test_utils::TestPersister::new();
	let alice_broadcaster = test_utils::TestBroadcaster::with_blocks(Arc::new(Mutex::new(
		nodes[0].blocks.lock().unwrap().clone(),
	)));
	let watchtower_alice = {
		let new_monitor = {
			let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(chan_1.2).unwrap();
			let new_monitor =
				<(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
					&mut io::Cursor::new(&monitor.encode()),
					(nodes[0].keys_manager, nodes[0].keys_manager),
				)
				.unwrap()
				.1;
			assert!(new_monitor == *monitor);
			new_monitor
		};
		let watchtower = test_utils::TestChainMonitor::new(
			Some(&chain_source),
			&alice_broadcaster,
			&logger,
			&chanmon_cfgs[0].fee_estimator,
			&persister,
			&node_cfgs[0].keys_manager,
		);
		assert_eq!(
			watchtower.watch_channel(chan_1.2, new_monitor),
			Ok(ChannelMonitorUpdateStatus::Completed)
		);
		watchtower
	};
	let block = create_dummy_block(BlockHash::all_zeros(), 42, Vec::new());
	// Make Alice aware of enough blocks that it doesn't think we're violating transaction lock time
	// requirements here.
	const HTLC_TIMEOUT_BROADCAST: u32 =
		CHAN_CONFIRM_DEPTH + 1 + TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS;
	let next_block = (block.clone(), HTLC_TIMEOUT_BROADCAST);
	alice_broadcaster.blocks.lock().unwrap().resize((HTLC_TIMEOUT_BROADCAST) as usize, next_block);
	watchtower_alice.chain_monitor.block_connected(&block, HTLC_TIMEOUT_BROADCAST);

	// Watchtower Alice should have broadcast a commitment/HTLC-timeout
	{
		let mut txn = alice_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 2);
		check_spends!(txn[0], chan_1.3);
		check_spends!(txn[1], txn[0]);
	};

	// Copy ChainMonitor to simulate watchtower Bob and make it receive a commitment update first.
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let logger = test_utils::TestLogger::with_id("bob".to_string());
	let persister = test_utils::TestPersister::new();
	let bob_broadcaster =
		test_utils::TestBroadcaster::with_blocks(Arc::clone(&alice_broadcaster.blocks));
	let watchtower_bob = {
		let new_monitor = {
			let monitor = nodes[0].chain_monitor.chain_monitor.get_monitor(chan_1.2).unwrap();
			let new_monitor =
				<(BlockHash, channelmonitor::ChannelMonitor<TestChannelSigner>)>::read(
					&mut io::Cursor::new(&monitor.encode()),
					(nodes[0].keys_manager, nodes[0].keys_manager),
				)
				.unwrap()
				.1;
			assert!(new_monitor == *monitor);
			new_monitor
		};
		let watchtower = test_utils::TestChainMonitor::new(
			Some(&chain_source),
			&bob_broadcaster,
			&logger,
			&chanmon_cfgs[0].fee_estimator,
			&persister,
			&node_cfgs[0].keys_manager,
		);
		assert_eq!(
			watchtower.watch_channel(chan_1.2, new_monitor),
			Ok(ChannelMonitorUpdateStatus::Completed)
		);
		watchtower
	};
	let block = create_dummy_block(BlockHash::all_zeros(), 42, Vec::new());
	watchtower_bob.chain_monitor.block_connected(&block, HTLC_TIMEOUT_BROADCAST - 1);

	// Route another payment to generate another update with still previous HTLC pending
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 3000000);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[1].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[1], 1);

	let updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert_eq!(updates.update_add_htlcs.len(), 1);
	nodes[0].node.handle_update_add_htlc(node_b_id, &updates.update_add_htlcs[0]);
	{
		let mut per_peer_lock;
		let mut peer_state_lock;
		let chan_ref =
			get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_1.2);
		if let Some(channel) = chan_ref.as_funded_mut() {
			assert_eq!(updates.commitment_signed.len(), 1);
			let feeest = LowerBoundedFeeEstimator::new(&chanmon_cfgs[0].fee_estimator);
			if let Ok(Some(update)) = channel.commitment_signed(
				&updates.commitment_signed[0],
				&feeest,
				&node_cfgs[0].logger,
			) {
				// Watchtower Alice should already have seen the block and reject the update
				assert_eq!(
					watchtower_alice.chain_monitor.update_channel(chan_1.2, &update),
					ChannelMonitorUpdateStatus::InProgress
				);
				assert_eq!(
					watchtower_bob.chain_monitor.update_channel(chan_1.2, &update),
					ChannelMonitorUpdateStatus::Completed
				);
				assert_eq!(
					nodes[0].chain_monitor.update_channel(chan_1.2, &update),
					ChannelMonitorUpdateStatus::Completed
				);
			} else {
				assert!(false);
			}
		} else {
			assert!(false);
		}
	}
	// Our local monitor is in-sync and hasn't processed yet timeout
	check_added_monitors(&nodes[0], 1);

	//// Provide one more block to watchtower Bob, expect broadcast of commitment and HTLC-Timeout
	watchtower_bob.chain_monitor.block_connected(
		&create_dummy_block(BlockHash::all_zeros(), 42, Vec::new()),
		HTLC_TIMEOUT_BROADCAST,
	);

	// Watchtower Bob should have broadcast a commitment/HTLC-timeout
	let bob_state_y;
	{
		let mut txn = bob_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 2);
		bob_state_y = txn.remove(0);
	};

	// We confirm Bob's state Y on Alice, she should broadcast a HTLC-timeout
	let height = HTLC_TIMEOUT_BROADCAST + 1;
	connect_blocks(&nodes[0], height - nodes[0].best_block_info().1);
	check_closed_broadcast(&nodes[0], 1, true);
	let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash_timeout) };
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	watchtower_alice.chain_monitor.block_connected(
		&create_dummy_block(BlockHash::all_zeros(), 42, vec![bob_state_y.clone()]),
		height,
	);
	check_added_monitors(&nodes[0], 1);
	{
		let htlc_txn = alice_broadcaster.txn_broadcast();
		assert_eq!(htlc_txn.len(), 1);
		check_spends!(htlc_txn[0], bob_state_y);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_pre_lockin_no_chan_closed_update() {
	// Test that if a peer closes a channel in response to a funding_created message we don't
	// generate a channel update (as the channel cannot appear on chain without a funding_signed
	// message).
	//
	// Doing so would imply a channel monitor update before the initial channel monitor
	// registration, violating our API guarantees.
	//
	// Previously, full_stack_target managed to hit this case by opening then closing a channel,
	// then opening a second channel with the same funding output as the first (which is not
	// rejected because the first channel does not exist in the ChannelManager) and closing it
	// before receiving funding_signed.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Create an initial channel
	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_chan_msg);
	let accept_chan_msg = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_chan_msg);

	// Move the first channel through the funding flow...
	let (temp_channel_id, tx, _) = create_funding_transaction(&nodes[0], &node_b_id, 100000, 42);

	nodes[0].node.funding_transaction_generated(temp_channel_id, node_b_id, tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);

	let funding_created_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	let channel_id = ChannelId::v1_from_funding_outpoint(crate::chain::transaction::OutPoint {
		txid: funding_created_msg.funding_txid,
		index: funding_created_msg.funding_output_index,
	});

	let err_msg = msgs::ErrorMessage { channel_id, data: "Hi".to_owned() };
	nodes[0].node.handle_error(node_b_id, &err_msg);

	assert!(nodes[0].chain_monitor.added_monitors.lock().unwrap().is_empty());
	let reason =
		ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString("Hi".to_string()) };
	check_closed_event_internal(&nodes[0], 2, reason, true, &[node_b_id], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_htlc_no_detection() {
	// This test is a mutation to underscore the detection logic bug we had
	// before #653. HTLC value routed is above the remaining balance, thus
	// inverting HTLC and `to_remote` output. HTLC will come second and
	// it wouldn't be seen by pre-#653 detection as we were enumerate()'ing
	// on a watched outputs vector (Vec<TxOut>) thus implicitly relying on
	// outputs order detection for correct spending children filtring.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);

	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let (_, our_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 2_000_000);
	let local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
	assert_eq!(local_txn[0].input.len(), 1);
	assert_eq!(local_txn[0].output.len(), 3);
	check_spends!(local_txn[0], chan_1.3);

	// Timeout HTLC on A's chain and so it can generate a HTLC-Timeout tx
	let block = create_dummy_block(nodes[0].best_block_hash(), 42, vec![local_txn[0].clone()]);
	connect_block(&nodes[0], &block);
	// We deliberately connect the local tx twice as this should provoke a failure calling
	// this test before #653 fix.
	chain::Listen::block_connected(
		&nodes[0].chain_monitor.chain_monitor,
		&block,
		nodes[0].best_block_info().1 + 1,
	);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV);

	let htlc_timeout = {
		let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
		assert_eq!(node_txn.len(), 1);
		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
		check_spends!(node_txn[0], local_txn[0]);
		node_txn[0].clone()
	};

	connect_block(
		&nodes[0],
		&create_dummy_block(nodes[0].best_block_hash(), 42, vec![htlc_timeout.clone()]),
	);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	let conditions = PaymentFailedConditions::new().from_mon_update();
	expect_payment_failed_conditions(&nodes[0], our_payment_hash, false, conditions);
}

fn do_test_onchain_htlc_settlement_after_close(
	broadcast_alice: bool, go_onchain_before_fulfill: bool,
) {
	// If we route an HTLC, then learn the HTLC's preimage after the upstream channel has been
	// force-closed, we must claim that HTLC on-chain. (Given an HTLC forwarded from Alice --> Bob -->
	// Carol, Alice would be the upstream node, and Carol the downstream.)
	//
	// Steps of the test:
	// 1) Alice sends a HTLC to Carol through Bob.
	// 2) Carol doesn't settle the HTLC.
	// 3) If broadcast_alice is true, Alice force-closes her channel with Bob. Else Bob force closes.
	// Steps 4 and 5 may be reordered depending on go_onchain_before_fulfill.
	// 4) Bob sees the Alice's commitment on his chain or vice versa. An offered output is present
	//    but can't be claimed as Bob doesn't have yet knowledge of the preimage.
	// 5) Carol release the preimage to Bob off-chain.
	// 6) Bob claims the offered output on the broadcasted commitment.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Create some initial channels
	let chan_ab = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 10001);

	// Steps (1) and (2):
	// Send an HTLC Alice --> Bob --> Carol, but Carol doesn't settle the HTLC back.
	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);

	// Check that Alice's commitment transaction now contains an output for this HTLC.
	let alice_txn = get_local_commitment_txn!(nodes[0], chan_ab.2);
	check_spends!(alice_txn[0], chan_ab.3);
	assert_eq!(alice_txn[0].output.len(), 2);
	check_spends!(alice_txn[1], alice_txn[0]); // 2nd transaction is a non-final HTLC-timeout
	assert_eq!(alice_txn[1].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	assert_eq!(alice_txn.len(), 2);

	// Steps (3) and (4):
	// If `go_onchain_before_fufill`, broadcast the relevant commitment transaction and check that Bob
	// responds by (1) broadcasting a channel update and (2) adding a new ChannelMonitor.
	let mut force_closing_node = 0; // Alice force-closes
	let mut counterparty_node = 1; // Bob if Alice force-closes

	// Bob force-closes
	if !broadcast_alice {
		force_closing_node = 1;
		counterparty_node = 0;
	}
	let message = "Channel force-closed".to_owned();
	let counterparty_node_id = nodes[counterparty_node].node.get_our_node_id();
	nodes[force_closing_node]
		.node
		.force_close_broadcasting_latest_txn(&chan_ab.2, &counterparty_node_id, message.clone())
		.unwrap();
	check_closed_broadcast!(nodes[force_closing_node], true);
	check_added_monitors(&nodes[force_closing_node], 1);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[force_closing_node], 1, reason, &[counterparty_node_id], 100000);

	if go_onchain_before_fulfill {
		let txn_to_broadcast = match broadcast_alice {
			true => alice_txn.clone(),
			false => get_local_commitment_txn!(nodes[1], chan_ab.2),
		};
		connect_block(
			&nodes[1],
			&create_dummy_block(nodes[1].best_block_hash(), 42, vec![txn_to_broadcast[0].clone()]),
		);
		if broadcast_alice {
			check_closed_broadcast!(nodes[1], true);
			check_added_monitors(&nodes[1], 1);
			let reason = ClosureReason::CommitmentTxConfirmed;
			check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
		}
	}

	// Step (5):
	// Carol then claims the funds and sends an update_fulfill message to Bob, and they go through the
	// process of removing the HTLC from their commitment transactions.
	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 3_000_000);

	let mut carol_updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(carol_updates.update_add_htlcs.is_empty());
	assert!(carol_updates.update_fail_htlcs.is_empty());
	assert!(carol_updates.update_fail_malformed_htlcs.is_empty());
	assert!(carol_updates.update_fee.is_none());
	assert_eq!(carol_updates.update_fulfill_htlcs.len(), 1);

	let carol_fulfill = carol_updates.update_fulfill_htlcs.remove(0);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, carol_fulfill);
	let went_onchain = go_onchain_before_fulfill || force_closing_node == 1;
	let fee = if went_onchain { None } else { Some(1000) };
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], fee, went_onchain, false);
	// If Alice broadcasted but Bob doesn't know yet, here he prepares to tell her about the preimage.
	if !go_onchain_before_fulfill && broadcast_alice {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::UpdateHTLCs { ref node_id, .. } => {
				assert_eq!(*node_id, node_a_id);
			},
			_ => panic!("Unexpected event"),
		};
	}
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &carol_updates.commitment_signed);
	// One monitor update for the preimage to update the Bob<->Alice channel, one monitor update
	// Carol<->Bob's updated commitment transaction info.
	check_added_monitors(&nodes[1], 2);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	let bob_revocation = match events[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_c_id);
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	let bob_updates = match events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, channel_id: _, ref updates } => {
			assert_eq!(*node_id, node_c_id);
			(*updates).clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_revoke_and_ack(node_b_id, &bob_revocation);
	check_added_monitors(&nodes[2], 1);
	nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &bob_updates.commitment_signed);
	check_added_monitors(&nodes[2], 1);

	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let carol_revocation = match events[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_b_id);
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_revoke_and_ack(node_c_id, &carol_revocation);
	check_added_monitors(&nodes[1], 1);

	// If this test requires the force-closed channel to not be on-chain until after the fulfill,
	// here's where we put said channel's commitment tx on-chain.
	let mut txn_to_broadcast = alice_txn.clone();
	if !broadcast_alice {
		txn_to_broadcast = get_local_commitment_txn!(nodes[1], chan_ab.2);
	}
	if !go_onchain_before_fulfill {
		connect_block(
			&nodes[1],
			&create_dummy_block(nodes[1].best_block_hash(), 42, vec![txn_to_broadcast[0].clone()]),
		);
		// If Bob was the one to force-close, he will have already passed these checks earlier.
		if broadcast_alice {
			check_closed_broadcast!(nodes[1], true);
			check_added_monitors(&nodes[1], 1);
			let reason = ClosureReason::CommitmentTxConfirmed;
			check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
		}
		let mut bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		if broadcast_alice {
			assert_eq!(bob_txn.len(), 1);
			check_spends!(bob_txn[0], txn_to_broadcast[0]);
		} else {
			if nodes[1].connect_style.borrow().updates_best_block_first() {
				assert_eq!(bob_txn.len(), 3);
				assert_eq!(bob_txn[0].compute_txid(), bob_txn[1].compute_txid());
			} else {
				assert_eq!(bob_txn.len(), 2);
			}
			check_spends!(bob_txn[0], chan_ab.3);
		}
	}

	// Step (6):
	// Finally, check that Bob broadcasted a preimage-claiming transaction for the HTLC output on the
	// broadcasted commitment transaction.
	// If Alice force-closed, Bob only broadcasts a HTLC-output-claiming transaction. Otherwise,
	// Bob force-closed and broadcasts the commitment transaction along with a
	// HTLC-output-claiming transaction.
	let mut bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	if broadcast_alice {
		assert_eq!(bob_txn.len(), 1);
		check_spends!(bob_txn[0], txn_to_broadcast[0]);
		assert_eq!(bob_txn[0].input[0].witness.last().unwrap().len(), OFFERED_HTLC_SCRIPT_WEIGHT);
	} else {
		assert_eq!(
			bob_txn.len(),
			if nodes[1].connect_style.borrow().updates_best_block_first() { 3 } else { 2 }
		);
		let htlc_tx = bob_txn.pop().unwrap();
		check_spends!(htlc_tx, txn_to_broadcast[0]);
		assert_eq!(htlc_tx.input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT + 1);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_onchain_htlc_settlement_after_close() {
	do_test_onchain_htlc_settlement_after_close(true, true);
	do_test_onchain_htlc_settlement_after_close(false, true); // Technically redundant, but may as well
	do_test_onchain_htlc_settlement_after_close(true, false);
	do_test_onchain_htlc_settlement_after_close(false, false);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_peer_funding_sidechannel() {
	// Test that if a peer somehow learns which txid we'll use for our channel funding before we
	// receive `funding_transaction_generated` the peer cannot cause us to crash. We'd previously
	// assumed that LDK would receive `funding_transaction_generated` prior to our peer learning
	// the txid and panicked if the peer tried to open a redundant channel to us with the same
	// funding outpoint.
	//
	// While this assumption is generally safe, some users may have out-of-band protocols where
	// they notify their LSP about a funding outpoint first, or this may be violated in the future
	// with collaborative transaction construction protocols, i.e. dual-funding.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let temp_chan_id_ab = exchange_open_accept_chan(&nodes[0], &nodes[1], 1_000_000, 0);
	let temp_chan_id_ca = exchange_open_accept_chan(&nodes[1], &nodes[0], 1_000_000, 0);

	let (_, tx, funding_output) = create_funding_transaction(&nodes[0], &node_b_id, 1_000_000, 42);

	let cs_funding_events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(cs_funding_events.len(), 1);
	match cs_funding_events[0] {
		Event::FundingGenerationReady { .. } => {},
		_ => panic!("Unexpected event {:?}", cs_funding_events),
	}

	let output_idx = funding_output.index;
	nodes[1]
		.node
		.funding_transaction_generated_unchecked(temp_chan_id_ca, node_a_id, tx.clone(), output_idx)
		.unwrap();
	let funding_created_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendFundingCreated, node_a_id);
	nodes[0].node.handle_funding_created(node_b_id, &funding_created_msg);
	get_event_msg!(nodes[0], MessageSendEvent::SendFundingSigned, node_b_id);
	expect_channel_pending_event(&nodes[0], &node_b_id);
	check_added_monitors(&nodes[0], 1);

	let res = nodes[0].node.funding_transaction_generated(temp_chan_id_ab, node_b_id, tx);
	let err_msg = format!("{:?}", res.unwrap_err());
	assert!(err_msg.contains("An existing channel using ID"));
	assert!(err_msg.contains("is open with peer"));

	let channel_id = ChannelId::v1_from_funding_outpoint(funding_output);
	let err =
		format!("An existing channel using ID {} is open with peer {}", channel_id, node_b_id);
	let reason = ClosureReason::ProcessingError { err };
	let close_event = ExpectedCloseEvent::from_id_reason(temp_chan_id_ab, true, reason);
	check_closed_events(&nodes[0], &[close_event]);
	get_err_msg(&nodes[0], &node_b_id);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_duplicate_conflicting_funding_from_second_peer() {
	// Test that if a user tries to fund a channel with a channel ID they'd previously used
	// we don't try to remove the previous ChannelMonitor. This is largely a test to ensure we
	// don't regress in the fuzzer, as such funding getting passed our channel_id-matches checks
	// implies the user (and our counterparty) has reused cryptographic keys across channels, which
	// we require the user not do.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let temp_chan_id = exchange_open_accept_chan(&nodes[0], &nodes[1], 1_000_000, 0);

	let (_, tx, funding_outpoint) =
		create_funding_transaction(&nodes[0], &node_b_id, 1_000_000, 42);
	let real_chan_id = ChannelId::v1_from_funding_outpoint(funding_outpoint);

	// Now that we have a funding outpoint, create a dummy `ChannelMonitor` and insert it into
	// nodes[0]'s ChainMonitor so that the initial `ChannelMonitor` write fails.
	let dummy_chan_id = create_chan_between_nodes(&nodes[2], &nodes[3]).3;
	let dummy_monitor = get_monitor!(nodes[2], dummy_chan_id).clone();
	nodes[0].chain_monitor.chain_monitor.watch_channel(real_chan_id, dummy_monitor).unwrap();

	nodes[0].node.funding_transaction_generated(temp_chan_id, node_b_id, tx.clone()).unwrap();

	let mut funding_created_msg =
		get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id);
	nodes[1].node.handle_funding_created(node_a_id, &funding_created_msg);
	let funding_signed_msg =
		get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	nodes[0].node.handle_funding_signed(node_b_id, &funding_signed_msg);
	// At this point, the channel should be closed, after having generated one monitor write (the
	// watch_channel call which failed), but zero monitor updates.
	check_added_monitors(&nodes[0], 1);
	get_err_msg(&nodes[0], &node_b_id);

	let reason = ClosureReason::ProcessingError { err: "Channel ID was a duplicate".to_owned() };
	let close_event = ExpectedCloseEvent::from_id_reason(temp_chan_id, true, reason);
	check_closed_events(&nodes[0], &[close_event]);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_error_chans_closed() {
	// Test that we properly handle error messages, closing appropriate channels.
	//
	// Prior to #787 we'd allow a peer to make us force-close a channel we had with a different
	// peer. The "real" fix for that is to index channels with peers_ids, however in the mean time
	// we can test various edge cases around it to ensure we don't regress.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	// Create some initial channels
	let chan_1 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	let chan_2 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	let chan_3 = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100000, 10001);

	assert_eq!(nodes[0].node.list_usable_channels().len(), 3);
	assert_eq!(nodes[1].node.list_usable_channels().len(), 2);
	assert_eq!(nodes[2].node.list_usable_channels().len(), 1);

	// Closing a channel from a different peer has no effect
	nodes[0].node.handle_error(
		node_b_id,
		&msgs::ErrorMessage { channel_id: chan_3.2, data: "ERR".to_owned() },
	);
	assert_eq!(nodes[0].node.list_usable_channels().len(), 3);

	// Closing one channel doesn't impact others
	nodes[0].node.handle_error(
		node_b_id,
		&msgs::ErrorMessage { channel_id: chan_2.2, data: "ERR".to_owned() },
	);
	check_added_monitors(&nodes[0], 1);
	check_closed_broadcast!(nodes[0], false);

	let reason =
		ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString("ERR".to_string()) };
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);

	assert_eq!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);
	assert_eq!(nodes[0].node.list_usable_channels().len(), 2);
	assert!(
		nodes[0].node.list_usable_channels()[0].channel_id == chan_1.2
			|| nodes[0].node.list_usable_channels()[1].channel_id == chan_1.2
	);
	assert!(
		nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2
			|| nodes[0].node.list_usable_channels()[1].channel_id == chan_3.2
	);

	// A null channel ID should close all channels
	let _chan_4 = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	nodes[0].node.handle_error(
		node_b_id,
		&msgs::ErrorMessage { channel_id: ChannelId::new_zero(), data: "ERR".to_owned() },
	);
	check_added_monitors(&nodes[0], 2);

	let reason =
		ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString("ERR".to_string()) };
	check_closed_event(&nodes[0], 2, reason, &[node_b_id; 2], 100000);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg, .. } => {
			assert_eq!(msg.contents.channel_flags & 2, 2);
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::BroadcastChannelUpdate { ref msg, .. } => {
			assert_eq!(msg.contents.channel_flags & 2, 2);
		},
		_ => panic!("Unexpected event"),
	}
	// Note that at this point users of a standard PeerHandler will end up calling
	// peer_disconnected.
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2);

	nodes[0].node.peer_disconnected(node_b_id);
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
	assert!(nodes[0].node.list_usable_channels()[0].channel_id == chan_3.2);
}

fn do_test_tx_confirmed_skipping_blocks_immediate_broadcast(test_height_before_timelock: bool) {
	// In the first version of the chain::Confirm interface, after a refactor was made to not
	// broadcast CSV-locked transactions until their CSV lock is up, we wouldn't reliably broadcast
	// transactions after a `transactions_confirmed` call. Specifically, if the chain, provided via
	// `best_block_updated` is at height N, and a transaction output which we wish to spend at
	// height N-1 (due to a CSV to height N-1) is provided at height N, we will not broadcast the
	// spending transaction until height N+1 (or greater). This was due to the way
	// `ChannelMonitor::transactions_confirmed` worked, only checking if we should broadcast a
	// spending transaction at the height the input transaction was confirmed at, not whether we
	// should broadcast a spending transaction at the current height.
	// A second, similar, issue involved failing HTLCs backwards - because we only provided the
	// height at which transactions were confirmed to `OnchainTx::update_claims_view`, it wasn't
	// aware that the anti-reorg-delay had, in fact, already expired, waiting to fail-backwards
	// until we learned about an additional block.
	//
	// As an additional check, if `test_height_before_timelock` is set, we instead test that we
	// aren't broadcasting transactions too early (ie not broadcasting them at all).
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	*nodes[0].connect_style.borrow_mut() = ConnectStyle::BestBlockFirstSkippingBlocks;

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let (chan_announce, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 1, 2);
	let (_, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000);
	nodes[1].node.peer_disconnected(node_c_id);
	nodes[2].node.peer_disconnected(node_b_id);

	let message = "Channel force-closed".to_owned();
	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(&channel_id, &node_c_id, message.clone())
		.unwrap();

	check_closed_broadcast(&nodes[1], 1, false);
	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[1], 1, reason, &[node_c_id], 100000);
	check_added_monitors(&nodes[1], 1);
	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 1);

	let conf_height = nodes[1].best_block_info().1;
	if !test_height_before_timelock {
		connect_blocks(&nodes[1], TEST_FINAL_CLTV - LATENCY_GRACE_PERIOD_BLOCKS);
	}
	nodes[1].chain_monitor.chain_monitor.transactions_confirmed(
		&nodes[1].get_block_header(conf_height),
		&[(0, &node_txn[0])],
		conf_height,
	);
	if test_height_before_timelock {
		// If we confirmed the close transaction, but timelocks have not yet expired, we should not
		// generate any events or broadcast any transactions
		assert!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
		assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	} else {
		// We should broadcast an HTLC transaction spending our funding transaction first
		let spending_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(spending_txn.len(), 2);
		let htlc_tx = if spending_txn[0].compute_txid() == node_txn[0].compute_txid() {
			&spending_txn[1]
		} else {
			&spending_txn[0]
		};
		check_spends!(htlc_tx, node_txn[0]);

		// If we also discover that the HTLC-Timeout transaction was confirmed some time ago, we
		// should immediately fail-backwards the HTLC to the previous hop, without waiting for an
		// additional block built on top of the current chain.
		nodes[1].chain_monitor.chain_monitor.transactions_confirmed(
			&nodes[1].get_block_header(conf_height + 1),
			&[(0, htlc_tx)],
			conf_height + 1,
		);
		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[1],
			&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id }],
		);
		check_added_monitors(&nodes[1], 1);

		let updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
		assert!(updates.update_add_htlcs.is_empty());
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert_eq!(updates.update_fail_htlcs.len(), 1);
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
		do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, true, true);

		let failed_scid = chan_announce.contents.short_channel_id;
		expect_payment_failed_with_update!(nodes[0], payment_hash, false, failed_scid, true);

		// We should also generate a SpendableOutputs event with the to_self output (once the
		// timelock is up).
		connect_blocks(
			&nodes[1],
			(BREAKDOWN_TIMEOUT as u32) - TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS - 1,
		);
		let descriptor_spend_txn = check_spendable_outputs!(nodes[1], node_cfgs[1].keys_manager);
		assert_eq!(descriptor_spend_txn.len(), 1);

		// When the HTLC times out on the A<->B edge, the B<->C channel will fail the HTLC back to
		// avoid the A<->B channel closing (even though it already has). This will generate a
		// spurious HTLCHandlingFailed event.
		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[1],
			&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id }],
		);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_tx_confirmed_skipping_blocks_immediate_broadcast() {
	do_test_tx_confirmed_skipping_blocks_immediate_broadcast(false);
	do_test_tx_confirmed_skipping_blocks_immediate_broadcast(true);
}

fn do_test_dup_htlc_second_rejected(test_for_second_fail_panic: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let _chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);

	let payment_params = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let route = get_route!(nodes[0], payment_params, 10_000).unwrap();

	let (our_payment_preimage, our_payment_hash, our_payment_secret) =
		get_payment_preimage_hash!(&nodes[1]);

	{
		let onion = RecipientOnionFields::secret_only(our_payment_secret);
		let id = PaymentId(our_payment_hash.0);
		nodes[0].node.send_payment_with_route(route.clone(), our_payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let mut payment_event = SendEvent::from_event(events.pop().unwrap());
		nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
		let commitment = &payment_event.commitment_msg;
		do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);
	}
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], our_payment_hash, our_payment_secret, 10_000);

	{
		// Note that we use a different PaymentId here to allow us to duplicativly pay
		let onion = RecipientOnionFields::secret_only(our_payment_secret);
		let id = PaymentId(our_payment_secret.0);
		nodes[0].node.send_payment_with_route(route, our_payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[0], 1);
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let mut payment_event = SendEvent::from_event(events.pop().unwrap());
		nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
		let commitment = &payment_event.commitment_msg;
		do_commitment_signed_dance(&nodes[1], &nodes[0], commitment, false, false);
		// At this point, nodes[1] would notice it has too much value for the payment. It will
		// assume the second is a privacy attack (no longer particularly relevant
		// post-payment_secrets) and fail back the new HTLC. Previously, it'd also have failed back
		// the first HTLC delivered above.
	}

	expect_htlc_failure_conditions(nodes[1].node.get_and_clear_pending_events(), &[]);
	nodes[1].node.process_pending_htlc_forwards();

	if test_for_second_fail_panic {
		// Now we go fail back the first HTLC from the user end.
		nodes[1].node.fail_htlc_backwards(&our_payment_hash);

		let expected_destinations = &[
			HTLCHandlingFailureType::Receive { payment_hash: our_payment_hash },
			HTLCHandlingFailureType::Receive { payment_hash: our_payment_hash },
		];
		expect_htlc_failure_conditions(
			nodes[1].node.get_and_clear_pending_events(),
			expected_destinations,
		);
		nodes[1].node.process_pending_htlc_forwards();

		check_added_monitors(&nodes[1], 1);
		let fail_updates_1 = get_htlc_update_msgs(&nodes[1], &node_a_id);
		assert_eq!(fail_updates_1.update_fail_htlcs.len(), 2);

		nodes[0].node.handle_update_fail_htlc(node_b_id, &fail_updates_1.update_fail_htlcs[0]);
		nodes[0].node.handle_update_fail_htlc(node_b_id, &fail_updates_1.update_fail_htlcs[1]);
		let commitment = &fail_updates_1.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);

		let failure_events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(failure_events.len(), 4);
		if let Event::PaymentPathFailed { .. } = failure_events[0] {
		} else {
			panic!();
		}
		if let Event::PaymentFailed { .. } = failure_events[1] {
		} else {
			panic!();
		}
		if let Event::PaymentPathFailed { .. } = failure_events[2] {
		} else {
			panic!();
		}
		if let Event::PaymentFailed { .. } = failure_events[3] {
		} else {
			panic!();
		}
	} else {
		// Let the second HTLC fail and claim the first
		expect_htlc_failure_conditions(
			nodes[1].node.get_and_clear_pending_events(),
			&[HTLCHandlingFailureType::Receive { payment_hash: our_payment_hash }],
		);
		nodes[1].node.process_pending_htlc_forwards();

		check_added_monitors(&nodes[1], 1);
		let fail_updates_1 = get_htlc_update_msgs(&nodes[1], &node_a_id);
		nodes[0].node.handle_update_fail_htlc(node_b_id, &fail_updates_1.update_fail_htlcs[0]);
		let commitment = &fail_updates_1.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);

		let conditions = PaymentFailedConditions::new();
		expect_payment_failed_conditions(&nodes[0], our_payment_hash, true, conditions);

		claim_payment(&nodes[0], &[&nodes[1]], our_payment_preimage);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_dup_htlc_second_fail_panic() {
	// Previously, if we received two HTLCs back-to-back, where the second overran the expected
	// value for the payment, we'd fail back both HTLCs after generating a `PaymentClaimable` event.
	// Then, if the user failed the second payment, they'd hit a "tried to fail an already failed
	// HTLC" debug panic. This tests for this behavior, checking that only one HTLC is auto-failed.
	do_test_dup_htlc_second_rejected(true);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_dup_htlc_second_rejected() {
	// Test that if we receive a second HTLC for an MPP payment that overruns the payment amount we
	// simply reject the second HTLC but are still able to claim the first HTLC.
	do_test_dup_htlc_second_rejected(false);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_inconsistent_mpp_params() {
	// Test that if we recieve two HTLCs with different payment parameters we fail back the first
	// such HTLC and allow the second to stay.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let node_d_id = nodes[3].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 100_000, 0);
	let chan_2_3 = create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 100_000, 0);

	let payment_params = PaymentParameters::from_node_id(node_d_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[3].node.bolt11_invoice_features())
		.unwrap();
	let mut route = get_route!(nodes[0], payment_params, 15_000_000).unwrap();
	assert_eq!(route.paths.len(), 2);
	route.paths.sort_by(|path_a, _| {
		// Sort the path so that the path through nodes[1] comes first
		if path_a.hops[0].pubkey == node_b_id {
			core::cmp::Ordering::Less
		} else {
			core::cmp::Ordering::Greater
		}
	});

	let (preimage, hash, payment_secret) = get_payment_preimage_hash!(&nodes[3]);

	let cur_height = nodes[0].best_block_info().1;
	let id = PaymentId([42; 32]);

	let session_privs = {
		// We create a fake route here so that we start with three pending HTLCs, which we'll
		// ultimately have, just not right away.
		let mut dup_route = route.clone();
		dup_route.paths.push(route.paths[1].clone());
		let onion = RecipientOnionFields::secret_only(payment_secret);
		nodes[0].node.test_add_new_pending_payment(hash, onion, id, &dup_route).unwrap()
	};
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let path_a = &route.paths[0];
	let real_amt = 15_000_000;
	let priv_a = session_privs[0];
	nodes[0]
		.node
		.test_send_payment_along_path(path_a, &hash, onion, real_amt, cur_height, id, &None, priv_a)
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let path_a = &[&nodes[1], &nodes[3]];
	let event = events.pop().unwrap();
	pass_along_path(&nodes[0], path_a, real_amt, hash, Some(payment_secret), event, false, None);
	assert!(nodes[3].node.get_and_clear_pending_events().is_empty());

	let path_b = &route.paths[1];
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let amt_b = 14_000_000;
	let priv_b = session_privs[1];
	nodes[0]
		.node
		.test_send_payment_along_path(path_b, &hash, onion, amt_b, cur_height, id, &None, priv_b)
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	{
		let mut events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.pop().unwrap());

		nodes[2].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
		let commitment = &payment_event.commitment_msg;
		do_commitment_signed_dance(&nodes[2], &nodes[0], commitment, false, false);

		expect_and_process_pending_htlcs(&nodes[2], false);
		check_added_monitors(&nodes[2], 1);

		let mut events = nodes[2].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.pop().unwrap());

		nodes[3].node.handle_update_add_htlc(node_c_id, &payment_event.msgs[0]);
		check_added_monitors(&nodes[3], 0);
		do_commitment_signed_dance(&nodes[3], &nodes[2], &payment_event.commitment_msg, true, true);

		// At this point, nodes[3] should notice the two HTLCs don't contain the same total payment
		// amount. It will assume the second is a privacy attack (no longer particularly relevant
		// post-payment_secrets) and fail back the new HTLC.
	}
	expect_htlc_failure_conditions(nodes[3].node.get_and_clear_pending_events(), &[]);
	nodes[3].node.process_pending_htlc_forwards();
	let fail_type = HTLCHandlingFailureType::Receive { payment_hash: hash };
	expect_htlc_failure_conditions(nodes[3].node.get_and_clear_pending_events(), &[fail_type]);
	nodes[3].node.process_pending_htlc_forwards();

	check_added_monitors(&nodes[3], 1);

	let fail_updates_1 = get_htlc_update_msgs(&nodes[3], &node_c_id);
	nodes[2].node.handle_update_fail_htlc(node_d_id, &fail_updates_1.update_fail_htlcs[0]);
	let commitment = &fail_updates_1.commitment_signed;
	do_commitment_signed_dance(&nodes[2], &nodes[3], commitment, false, false);

	expect_and_process_pending_htlcs_and_htlc_handling_failed(
		&nodes[2],
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_d_id), channel_id: chan_2_3.2 }],
	);
	check_added_monitors(&nodes[2], 1);

	let fail_updates_2 = get_htlc_update_msgs(&nodes[2], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_c_id, &fail_updates_2.update_fail_htlcs[0]);
	let commitment = &fail_updates_2.commitment_signed;
	do_commitment_signed_dance(&nodes[0], &nodes[2], commitment, false, false);

	let conditions = PaymentFailedConditions::new().mpp_parts_remain();
	expect_payment_failed_conditions(&nodes[0], hash, true, conditions);

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let path_b = &route.paths[1];
	let priv_c = session_privs[2];
	nodes[0]
		.node
		.test_send_payment_along_path(path_b, &hash, onion, real_amt, cur_height, id, &None, priv_c)
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let event = events.pop().unwrap();
	let path_b = &[&nodes[2], &nodes[3]];
	pass_along_path(&nodes[0], path_b, real_amt, hash, Some(payment_secret), event, true, None);

	do_claim_payment_along_route(ClaimAlongRouteArgs::new(&nodes[0], &[path_a, path_b], preimage));
	expect_payment_sent(&nodes[0], preimage, Some(None), true, true);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_double_partial_claim() {
	// Test what happens if a node receives a payment, generates a PaymentClaimable event, the HTLCs
	// time out, the sender resends only some of the MPP parts, then the user processes the
	// PaymentClaimable event, ensuring they don't inadvertently claim only part of the full payment
	// amount.
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let node_b_id = nodes[1].node.get_our_node_id();

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 3, 100_000, 0);
	create_announced_chan_between_nodes_with_value(&nodes, 2, 3, 100_000, 0);

	let (mut route, hash, payment_preimage, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[3], 15_000_000);
	assert_eq!(route.paths.len(), 2);
	route.paths.sort_by(|path_a, _| {
		// Sort the path so that the path through nodes[1] comes first
		if path_a.hops[0].pubkey == node_b_id {
			core::cmp::Ordering::Less
		} else {
			core::cmp::Ordering::Greater
		}
	});

	let paths: &[&[_]] = &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]];
	send_along_route_with_secret(&nodes[0], route.clone(), paths, 15_000_000, hash, payment_secret);
	// nodes[3] has now received a PaymentClaimable event...which it will take some (exorbitant)
	// amount of time to respond to.

	// Connect some blocks to time out the payment
	connect_blocks(&nodes[3], TEST_FINAL_CLTV);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV); // To get the same height for sending later

	let failed_destinations = vec![
		HTLCHandlingFailureType::Receive { payment_hash: hash },
		HTLCHandlingFailureType::Receive { payment_hash: hash },
	];
	expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[3], &failed_destinations);

	let reason = PaymentFailureReason::RecipientRejected;
	pass_failed_payment_back(&nodes[0], paths, false, hash, reason);

	// nodes[1] now retries one of the two paths...
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(hash.0);
	nodes[0].node.send_payment_with_route(route, hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 2);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	let msgs = remove_first_msg_event_to_node(&node_b_id, &mut events);
	let path = &[&nodes[1], &nodes[3]];
	pass_along_path(&nodes[0], path, 15_000_000, hash, Some(payment_secret), msgs, false, None);

	// At this point nodes[3] has received one half of the payment, and the user goes to handle
	// that PaymentClaimable event they got hours ago and never handled...we should refuse to claim.
	nodes[3].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[3], 0);
	assert!(nodes[3].node.get_and_clear_pending_msg_events().is_empty());
}

/// The possible events which may trigger a `max_dust_htlc_exposure` breach
#[derive(Clone, Copy, PartialEq)]
enum ExposureEvent {
	/// Breach occurs at HTLC forwarding (see `send_htlc`)
	AtHTLCForward,
	/// Breach occurs at HTLC reception (see `update_add_htlc`)
	AtHTLCReception,
	/// Breach occurs at outbound update_fee (see `send_update_fee`)
	AtUpdateFeeOutbound,
}

fn do_test_max_dust_htlc_exposure(
	dust_outbound_balance: bool, exposure_breach_event: ExposureEvent, on_holder_tx: bool,
	multiplier_dust_limit: bool, apply_excess_fee: bool,
) {
	// Test that we properly reject dust HTLC violating our `max_dust_htlc_exposure_msat`
	// policy.
	//
	// At HTLC forward (`send_payment()`), if the sum of the trimmed-to-dust HTLC inbound and
	// trimmed-to-dust HTLC outbound balance and this new payment as included on next
	// counterparty commitment are above our `max_dust_htlc_exposure_msat`, we'll reject the
	// update. At HTLC reception (`update_add_htlc()`), if the sum of the trimmed-to-dust HTLC
	// inbound and trimmed-to-dust HTLC outbound balance and this new received HTLC as included
	// on next counterparty commitment are above our `max_dust_htlc_exposure_msat`, we'll fail
	// the update. Note, we return a `temporary_channel_failure` (0x1000 | 7), as the channel
	// might be available again for HTLC processing once the dust bandwidth has cleared up.

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut config = test_default_channel_config();

	// We hard-code the feerate values here but they're re-calculated furter down and asserted.
	// If the values ever change below these constants should simply be updated.
	const AT_FEE_OUTBOUND_HTLCS: u64 = 20;
	let nondust_htlc_count_in_limit = if exposure_breach_event == ExposureEvent::AtUpdateFeeOutbound
	{
		AT_FEE_OUTBOUND_HTLCS
	} else {
		0
	};
	let initial_feerate = if apply_excess_fee { 253 * 2 } else { 253 };
	let expected_dust_buffer_feerate = initial_feerate + 2530;
	let mut commitment_tx_cost_msat = commit_tx_fee_msat(
		initial_feerate - 253,
		nondust_htlc_count_in_limit,
		&ChannelTypeFeatures::empty(),
	);
	let (htlc_success_tx_fee_sat, htlc_timeout_tx_fee_sat) =
		second_stage_tx_fees_sat(&ChannelTypeFeatures::empty(), initial_feerate as u32 - 253);
	let per_htlc_cost_sat =
		if on_holder_tx { htlc_success_tx_fee_sat } else { htlc_timeout_tx_fee_sat };

	commitment_tx_cost_msat += per_htlc_cost_sat * 1000 * nondust_htlc_count_in_limit;
	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = initial_feerate;
	}
	config.channel_config.max_dust_htlc_exposure = if multiplier_dust_limit {
		// Default test fee estimator rate is 253 sat/kw, so we set the multiplier to 5_000_000 / 253
		// to get roughly the same initial value as the default setting when this test was
		// originally written.
		MaxDustHTLCExposure::FeeRateMultiplier((5_000_000 + commitment_tx_cost_msat) / 253)
	} else {
		MaxDustHTLCExposure::FixedLimitMsat(5_000_000 + commitment_tx_cost_msat)
	};
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config), None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 1_000_000, 500_000_000, 42, None, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	open_channel.common_fields.max_htlc_value_in_flight_msat = 50_000_000;
	open_channel.common_fields.max_accepted_htlcs = 60;
	if on_holder_tx {
		open_channel.common_fields.dust_limit_satoshis = 546;
	}
	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let mut accept_channel =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);

	let (chan_id, tx, _) = create_funding_transaction(&nodes[0], &node_b_id, 1_000_000, 42);

	if on_holder_tx {
		let mut per_peer_lock;
		let mut peer_state_lock;
		let channel = get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_id);
		if let Some(mut chan) = channel.as_unfunded_outbound_v1_mut() {
			chan.context.holder_dust_limit_satoshis = 546;
		} else {
			panic!("Unexpected Channel phase");
		}
	}

	nodes[0].node.funding_transaction_generated(chan_id, node_b_id, tx.clone()).unwrap();
	nodes[1].node.handle_funding_created(
		node_a_id,
		&get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, node_b_id),
	);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &node_a_id);

	nodes[0].node.handle_funding_signed(
		node_b_id,
		&get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, node_a_id),
	);
	check_added_monitors(&nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &node_b_id);

	let (channel_ready, channel_id) =
		create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, as_update, bs_update) =
		create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
	update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &as_update, &bs_update);

	{
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = 253;
	}

	// Fetch a route in advance as we will be unable to once we're unable to send.
	let (mut route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], 1000);

	let (
		dust_buffer_feerate,
		max_dust_htlc_exposure_msat,
		htlc_success_tx_fee_sat,
		htlc_timeout_tx_fee_sat,
	) = {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&node_b_id).unwrap().lock().unwrap();
		let chan = chan_lock.channel_by_id.get(&channel_id).unwrap();
		let dust_buffer_feerate = chan.context().get_dust_buffer_feerate(None);
		let (htlc_success_tx_fee_sat, htlc_timeout_tx_fee_sat) = second_stage_tx_fees_sat(
			&chan.as_funded().unwrap().funding.get_channel_type(),
			dust_buffer_feerate,
		);
		(
			dust_buffer_feerate,
			chan.context().get_max_dust_htlc_exposure_msat(Some(253)),
			htlc_success_tx_fee_sat,
			htlc_timeout_tx_fee_sat,
		)
	};
	assert_eq!(dust_buffer_feerate, expected_dust_buffer_feerate);
	let dust_outbound_htlc_on_holder_tx_msat: u64 =
		(htlc_timeout_tx_fee_sat + open_channel.common_fields.dust_limit_satoshis - 1) * 1000;
	let dust_outbound_htlc_on_holder_tx: u64 =
		max_dust_htlc_exposure_msat / dust_outbound_htlc_on_holder_tx_msat;

	// Substract 3 sats for multiplier and 2 sats for fixed limit to make sure we are 50% below the dust limit.
	// This is to make sure we fully use the dust limit. If we don't, we could end up with `dust_ibd_htlc_on_holder_tx` being 1
	// while `max_dust_htlc_exposure_msat` is not equal to `dust_outbound_htlc_on_holder_tx_msat`.
	let dust_inbound_htlc_on_holder_tx_msat: u64 = (htlc_success_tx_fee_sat
		+ open_channel.common_fields.dust_limit_satoshis
		- if multiplier_dust_limit { 3 } else { 2 })
		* 1000;
	let dust_inbound_htlc_on_holder_tx: u64 =
		max_dust_htlc_exposure_msat / dust_inbound_htlc_on_holder_tx_msat;

	// This test was written with a fixed dust value here, which we retain, but assert that it is,
	// indeed, dust on both transactions.
	let dust_htlc_on_counterparty_tx: u64 = 4;
	let dust_htlc_on_counterparty_tx_msat: u64 = 1_250_000;
	let calcd_dust_htlc_on_counterparty_tx_msat: u64 = (htlc_timeout_tx_fee_sat
		+ open_channel.common_fields.dust_limit_satoshis
		- if multiplier_dust_limit { 3 } else { 2 })
		* 1000;
	assert!(dust_htlc_on_counterparty_tx_msat < dust_inbound_htlc_on_holder_tx_msat);
	assert!(dust_htlc_on_counterparty_tx_msat < calcd_dust_htlc_on_counterparty_tx_msat);

	if on_holder_tx {
		if dust_outbound_balance {
			// Outbound dust threshold: 2223 sats (`dust_buffer_feerate` * HTLC_TIMEOUT_TX_WEIGHT / 1000 + holder's `dust_limit_satoshis`)
			// Outbound dust balance: 4372 sats
			// Note, we need sent payment to be above outbound dust threshold on counterparty_tx of 2132 sats
			for _ in 0..dust_outbound_htlc_on_holder_tx {
				route_payment(&nodes[0], &[&nodes[1]], dust_outbound_htlc_on_holder_tx_msat);
			}
		} else {
			// Inbound dust threshold: 2324 sats (`dust_buffer_feerate` * HTLC_SUCCESS_TX_WEIGHT / 1000 + holder's `dust_limit_satoshis`)
			// Inbound dust balance: 4372 sats
			// Note, we need sent payment to be above outbound dust threshold on counterparty_tx of 2031 sats
			for _ in 0..dust_inbound_htlc_on_holder_tx {
				route_payment(&nodes[1], &[&nodes[0]], dust_inbound_htlc_on_holder_tx_msat);
			}
		}
	} else {
		if dust_outbound_balance {
			// Outbound dust threshold: 2132 sats (`dust_buffer_feerate` * HTLC_TIMEOUT_TX_WEIGHT / 1000 + counteparty's `dust_limit_satoshis`)
			// Outbound dust balance: 5000 sats
			for _ in 0..dust_htlc_on_counterparty_tx - 1 {
				route_payment(&nodes[0], &[&nodes[1]], dust_htlc_on_counterparty_tx_msat);
			}
		} else {
			// Inbound dust threshold: 2031 sats (`dust_buffer_feerate` * HTLC_TIMEOUT_TX_WEIGHT / 1000 + counteparty's `dust_limit_satoshis`)
			// Inbound dust balance: 5000 sats
			for _ in 0..dust_htlc_on_counterparty_tx - 1 {
				route_payment(&nodes[1], &[&nodes[0]], dust_htlc_on_counterparty_tx_msat);
			}
		}
	}

	if exposure_breach_event == ExposureEvent::AtHTLCForward {
		route.paths[0].hops.last_mut().unwrap().fee_msat = if on_holder_tx {
			dust_outbound_htlc_on_holder_tx_msat
		} else {
			dust_htlc_on_counterparty_tx_msat + 1
		};
		// With default dust exposure: 5000 sats
		if on_holder_tx {
			let onion = RecipientOnionFields::secret_only(payment_secret);
			let id = PaymentId(payment_hash.0);
			let res = nodes[0].node.send_payment_with_route(route, payment_hash, onion, id);
			unwrap_send_err!(nodes[0], res, true, APIError::ChannelUnavailable { .. }, {});
		} else {
			let onion = RecipientOnionFields::secret_only(payment_secret);
			let id = PaymentId(payment_hash.0);
			let res = nodes[0].node.send_payment_with_route(route, payment_hash, onion, id);
			unwrap_send_err!(nodes[0], res, true, APIError::ChannelUnavailable { .. }, {});
		}
	} else if exposure_breach_event == ExposureEvent::AtHTLCReception {
		let amount_msats = if on_holder_tx {
			dust_inbound_htlc_on_holder_tx_msat
		} else {
			dust_htlc_on_counterparty_tx_msat + 4
		};
		let (route, payment_hash, _, payment_secret) =
			get_route_and_payment_hash!(nodes[1], nodes[0], amount_msats);

		let onion = RecipientOnionFields::secret_only(payment_secret);
		let id = PaymentId(payment_hash.0);
		nodes[1].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
		check_added_monitors(&nodes[1], 1);

		let mut events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		let payment_event = SendEvent::from_event(events.remove(0));
		nodes[0].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
		let commitment = &payment_event.commitment_msg;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, false);
		expect_and_process_pending_htlcs(&nodes[0], false);
		expect_htlc_handling_failed_destinations!(
			nodes[0].node.get_and_clear_pending_events(),
			&[HTLCHandlingFailureType::Receive { payment_hash }]
		);
		// With default dust exposure: 5000 sats
		if on_holder_tx {
			// Outbound dust balance: 6399 sats
			let dust_inbound_overflow =
				dust_inbound_htlc_on_holder_tx_msat * (dust_inbound_htlc_on_holder_tx + 1);
			let dust_outbound_overflow = dust_outbound_htlc_on_holder_tx_msat
				* dust_outbound_htlc_on_holder_tx
				+ dust_inbound_htlc_on_holder_tx_msat;
			nodes[0].logger.assert_log("lightning::ln::channel", format!("Cannot accept value that would put our exposure to dust HTLCs at {} over the limit {} on holder commitment tx", if dust_outbound_balance { dust_outbound_overflow } else { dust_inbound_overflow }, max_dust_htlc_exposure_msat), 1);
		} else {
			// Outbound dust balance: 5200 sats
			nodes[0].logger.assert_log("lightning::ln::channel",
				format!("Cannot accept value that would put our total dust exposure at {} over the limit {} on counterparty commitment tx",
					dust_htlc_on_counterparty_tx_msat * dust_htlc_on_counterparty_tx + commitment_tx_cost_msat + 4,
					max_dust_htlc_exposure_msat), 1);
		}
	} else if exposure_breach_event == ExposureEvent::AtUpdateFeeOutbound {
		route.paths[0].hops.last_mut().unwrap().fee_msat = 2_500_000;
		// For the multiplier dust exposure limit, since it scales with feerate,
		// we need to add a lot of HTLCs that will become dust at the new feerate
		// to cross the threshold.
		for _ in 0..AT_FEE_OUTBOUND_HTLCS {
			let (_, hash, payment_secret) = get_payment_preimage_hash(&nodes[1], Some(1_000), None);
			let onion = RecipientOnionFields::secret_only(payment_secret);
			let id = PaymentId(hash.0);
			nodes[0].node.send_payment_with_route(route.clone(), hash, onion, id).unwrap();
		}
		{
			let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
			*feerate_lock *= 10;
		}
		nodes[0].node.timer_tick_occurred();
		check_added_monitors(&nodes[0], 1);
		nodes[0].logger.assert_log_contains(
			"lightning::ln::channel",
			"Cannot afford to send new feerate at 2530 without infringing max dust htlc exposure",
			1,
		);
	}

	let _ = nodes[0].node.get_and_clear_pending_msg_events();
	let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
	added_monitors.clear();
}

fn do_test_max_dust_htlc_exposure_by_threshold_type(
	multiplier_dust_limit: bool, apply_excess_fee: bool,
) {
	do_test_max_dust_htlc_exposure(
		true,
		ExposureEvent::AtHTLCForward,
		true,
		multiplier_dust_limit,
		apply_excess_fee,
	);
	do_test_max_dust_htlc_exposure(
		false,
		ExposureEvent::AtHTLCForward,
		true,
		multiplier_dust_limit,
		apply_excess_fee,
	);
	do_test_max_dust_htlc_exposure(
		false,
		ExposureEvent::AtHTLCReception,
		true,
		multiplier_dust_limit,
		apply_excess_fee,
	);
	do_test_max_dust_htlc_exposure(
		false,
		ExposureEvent::AtHTLCReception,
		false,
		multiplier_dust_limit,
		apply_excess_fee,
	);
	do_test_max_dust_htlc_exposure(
		true,
		ExposureEvent::AtHTLCForward,
		false,
		multiplier_dust_limit,
		apply_excess_fee,
	);
	do_test_max_dust_htlc_exposure(
		true,
		ExposureEvent::AtHTLCReception,
		false,
		multiplier_dust_limit,
		apply_excess_fee,
	);
	do_test_max_dust_htlc_exposure(
		true,
		ExposureEvent::AtHTLCReception,
		true,
		multiplier_dust_limit,
		apply_excess_fee,
	);
	do_test_max_dust_htlc_exposure(
		false,
		ExposureEvent::AtHTLCForward,
		false,
		multiplier_dust_limit,
		apply_excess_fee,
	);
	if !multiplier_dust_limit && !apply_excess_fee {
		// Because non-dust HTLC transaction fees are included in the dust exposure, trying to
		// increase the fee to hit a higher dust exposure with a
		// `MaxDustHTLCExposure::FeeRateMultiplier` is no longer super practical, so we skip these
		// in the `multiplier_dust_limit` case.
		do_test_max_dust_htlc_exposure(
			true,
			ExposureEvent::AtUpdateFeeOutbound,
			true,
			multiplier_dust_limit,
			apply_excess_fee,
		);
		do_test_max_dust_htlc_exposure(
			true,
			ExposureEvent::AtUpdateFeeOutbound,
			false,
			multiplier_dust_limit,
			apply_excess_fee,
		);
		do_test_max_dust_htlc_exposure(
			false,
			ExposureEvent::AtUpdateFeeOutbound,
			false,
			multiplier_dust_limit,
			apply_excess_fee,
		);
		do_test_max_dust_htlc_exposure(
			false,
			ExposureEvent::AtUpdateFeeOutbound,
			true,
			multiplier_dust_limit,
			apply_excess_fee,
		);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_max_dust_htlc_exposure() {
	do_test_max_dust_htlc_exposure_by_threshold_type(false, false);
	do_test_max_dust_htlc_exposure_by_threshold_type(false, true);
	do_test_max_dust_htlc_exposure_by_threshold_type(true, false);
	do_test_max_dust_htlc_exposure_by_threshold_type(true, true);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_nondust_htlc_excess_fees_are_dust() {
	// Test that the excess transaction fees paid in nondust HTLCs count towards our dust limit
	const DEFAULT_FEERATE: u32 = 253;
	const HIGH_FEERATE: u32 = 275;
	const EXCESS_FEERATE: u32 = HIGH_FEERATE - DEFAULT_FEERATE;
	let chanmon_cfgs = create_chanmon_cfgs(3);
	{
		// Set the feerate of the channel funder above the `dust_exposure_limiting_feerate` of
		// the fundee. This delta means that the fundee will add the mining fees of the commitment and
		// htlc transactions in excess of its `dust_exposure_limiting_feerate` to its total dust htlc
		// exposure.
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = HIGH_FEERATE;
	}
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let mut config = test_default_channel_config();
	// Set the dust limit to the default value
	config.channel_config.max_dust_htlc_exposure = MaxDustHTLCExposure::FeeRateMultiplier(10_000);
	// Make sure the HTLC limits don't get in the way
	let chan_ty = ChannelTypeFeatures::only_static_remote_key();
	config.channel_handshake_limits.min_max_accepted_htlcs = chan_utils::max_htlcs(&chan_ty);
	config.channel_handshake_config.our_max_accepted_htlcs = chan_utils::max_htlcs(&chan_ty);
	config.channel_handshake_config.our_htlc_minimum_msat = 1;
	config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;

	let node_chanmgrs = create_node_chanmgrs(
		3,
		&node_cfgs,
		&[Some(config.clone()), Some(config.clone()), Some(config)],
	);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// Leave enough on the funder side to let it pay the mining fees for a commit tx with tons of htlcs
	let chan_id_1 =
		create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 1_000_000, 750_000_000).2;

	// First get the channel one HTLC_VALUE HTLC away from the dust limit by sending dust HTLCs
	// repeatedly until we run out of space.
	const HTLC_VALUE: u64 = 1_000_000; // Doesn't matter, tune until the test passes
	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], HTLC_VALUE).0;

	while nodes[0].node.list_channels()[0].next_outbound_htlc_minimum_msat == 0 {
		route_payment(&nodes[0], &[&nodes[1]], HTLC_VALUE);
	}
	assert_ne!(
		nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat,
		0,
		"We don't want to run out of ability to send because of some non-dust limit"
	);
	assert!(
		nodes[0].node.list_channels()[0].pending_outbound_htlcs.len() < 10,
		"We should be able to fill our dust limit without too many HTLCs"
	);

	let dust_limit = nodes[0].node.list_channels()[0].next_outbound_htlc_minimum_msat;
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
	assert_ne!(
		nodes[0].node.list_channels()[0].next_outbound_htlc_minimum_msat,
		0,
		"Make sure we are able to send once we clear one HTLC"
	);

	// Skip the router complaint when node 0 will attempt to pay node 1
	let (route_0_1, payment_hash_0_1, _, payment_secret_0_1) =
		get_route_and_payment_hash!(nodes[0], nodes[1], dust_limit * 2);

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);

	// At this point we have somewhere between dust_limit and dust_limit * 2 left in our dust
	// exposure limit, and we want to max that out using non-dust HTLCs.
	let (htlc_success_tx_fee_sat, _) =
		second_stage_tx_fees_sat(&ChannelTypeFeatures::empty(), EXCESS_FEERATE);
	let max_htlcs_remaining = dust_limit * 2 / (htlc_success_tx_fee_sat * 1000);
	assert!(
		max_htlcs_remaining < chan_utils::max_htlcs(&chan_ty).into(),
		"We should be able to fill our dust limit without too many HTLCs"
	);
	for i in 0..max_htlcs_remaining + 1 {
		assert_ne!(i, max_htlcs_remaining);
		if nodes[0].node.list_channels()[0].next_outbound_htlc_limit_msat <= dust_limit {
			// We found our limit, and it was less than max_htlcs_remaining!
			// At this point we can only send dust HTLCs as any non-dust HTLCs will overuse our
			// remaining dust exposure.
			break;
		}
		route_payment(&nodes[0], &[&nodes[1]], dust_limit * 2);
	}

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);

	// Send an additional non-dust htlc from 1 to 0, and check the complaint
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[1], nodes[0], dust_limit * 2);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[1].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[1], 1);
	let mut events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.remove(0));
	nodes[0].node.handle_update_add_htlc(node_b_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &payment_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[0], false);
	expect_htlc_handling_failed_destinations!(
		nodes[0].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }]
	);
	nodes[0].logger.assert_log("lightning::ln::channel",
		format!("Cannot accept value that would put our total dust exposure at {} over the limit {} on counterparty commitment tx",
			2531000, 2530000), 1);
	check_added_monitors(&nodes[0], 1);

	// Clear the failed htlc
	let updates = get_htlc_update_msgs(&nodes[0], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[1].node.handle_update_fail_htlc(node_a_id, &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &updates.commitment_signed, false, false);
	expect_payment_failed!(nodes[1], payment_hash, false);

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);

	// Send an additional non-dust htlc from 0 to 1 using the pre-calculated route above, and check the immediate complaint
	let onion = RecipientOnionFields::secret_only(payment_secret_0_1);
	let id = PaymentId(payment_hash_0_1.0);
	let res = nodes[0].node.send_payment_with_route(route_0_1, payment_hash_0_1, onion, id);
	unwrap_send_err!(nodes[0], res, true, APIError::ChannelUnavailable { .. }, {});
	nodes[0].logger.assert_log("lightning::ln::outbound_payment",
		format!("Failed to send along path due to error: Channel unavailable: Cannot send more than our next-HTLC maximum - {} msat", 2325000), 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);
	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);

	// At this point non-dust HTLCs are no longer accepted from node 0 -> 1, we also check that
	// such HTLCs can't be routed over the same channel either.
	create_announced_chan_between_nodes(&nodes, 2, 0);
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[2], nodes[1], dust_limit * 2);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[2].node.send_payment_with_route(route, payment_hash, onion, PaymentId([0; 32])).unwrap();
	check_added_monitors(&nodes[2], 1);
	let send = SendEvent::from_node(&nodes[2]);

	nodes[0].node.handle_update_add_htlc(node_c_id, &send.msgs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[2], &send.commitment_msg, false, true);

	expect_and_process_pending_htlcs(&nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let node_id_1 = node_b_id;
	expect_htlc_handling_failed_destinations!(
		nodes[0].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_id_1), channel_id: chan_id_1 }]
	);

	let fail = get_htlc_update_msgs(&nodes[0], &node_c_id);
	nodes[2].node.handle_update_fail_htlc(node_a_id, &fail.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[2], &nodes[0], &fail.commitment_signed, false, false);
	let conditions = PaymentFailedConditions::new();
	expect_payment_failed_conditions(&nodes[2], payment_hash, false, conditions);
}

fn do_test_nondust_htlc_fees_dust_exposure_delta(features: ChannelTypeFeatures) {
	// Tests the increase in htlc dust exposure due to the excess mining fees of a single non-dust
	// HTLC on the counterparty commitment transaction, for both incoming and outgoing htlcs.
	//
	// Brings the dust exposure up to the base dust exposure using dust htlcs.
	// Sets the max dust exposure to 1msat below the expected dust exposure given an additional non-dust htlc.
	// Checks a failed payment for a non-dust htlc.
	// Sets the max dust exposure equal to the expected dust exposure given an additional non-dust htlc.
	// Checks a successful payment for a non-dust htlc.
	//
	// Runs this sequence for both directions.

	let chanmon_cfgs = create_chanmon_cfgs(2);

	const DEFAULT_FEERATE: u64 = 253;
	const HIGH_FEERATE: u64 = 275;
	const EXCESS_FEERATE: u64 = HIGH_FEERATE - DEFAULT_FEERATE;

	const DUST_HTLC_COUNT: usize = 4;
	// Set dust htlcs to a satoshi value plus a non-zero msat amount to assert that
	// the dust accounting rounds transaction fees to the lower satoshi, but does not round dust htlc values.
	const DUST_HTLC_MSAT: u64 = 125_123;
	const BASE_DUST_EXPOSURE_MSAT: u64 = DUST_HTLC_COUNT as u64 * DUST_HTLC_MSAT;

	const NON_DUST_HTLC_MSAT: u64 = 4_000_000;

	{
		// Set the feerate of the channel funder above the `dust_exposure_limiting_feerate` of
		// the fundee. This delta means that the fundee will add the mining fees of the commitment and
		// htlc transactions in excess of its `dust_exposure_limiting_feerate` to its total dust htlc
		// exposure.
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = HIGH_FEERATE as u32;
	}

	// Set `expected_dust_exposure_msat` to match the calculation in `FundedChannel::can_accept_incoming_htlc`
	// only_static_remote_key: 500_492 + 22 * (724 + 172) / 1000 * 1000 + 22 * 663 / 1000 * 1000 = 533_492
	// anchors_zero_htlc_fee: 500_492 + 22 * (1_124 + 172) / 1000 * 1000 = 528_492
	let mut expected_dust_exposure_msat = BASE_DUST_EXPOSURE_MSAT
		+ EXCESS_FEERATE * (commitment_tx_base_weight(&features) + COMMITMENT_TX_WEIGHT_PER_HTLC)
			/ 1000 * 1000;

	let (_, htlc_timeout_tx_fee_sat) = second_stage_tx_fees_sat(&features, EXCESS_FEERATE as u32);
	if features == ChannelTypeFeatures::only_static_remote_key() {
		expected_dust_exposure_msat += htlc_timeout_tx_fee_sat * 1000;
		assert_eq!(expected_dust_exposure_msat, 533_492);
	} else {
		assert_eq!(expected_dust_exposure_msat, 528_492);
	}

	let mut default_config = test_default_channel_config();
	if features == ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies() {
		default_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
		// in addition to the one above, this setting is also needed to create an anchor channel
		default_config.manually_accept_inbound_channels = true;
	}

	// Set node 1's max dust htlc exposure to 1msat below `expected_dust_exposure_msat`
	let mut fixed_limit_config = default_config.clone();
	fixed_limit_config.channel_config.max_dust_htlc_exposure =
		MaxDustHTLCExposure::FixedLimitMsat(expected_dust_exposure_msat - 1);

	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(default_config), Some(fixed_limit_config)]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_id = create_chan_between_nodes_with_value(&nodes[0], &nodes[1], 100_000, 50_000_000).3;

	let node_1_dust_buffer_feerate = {
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&node_a_id).unwrap().lock().unwrap();
		let chan = chan_lock.channel_by_id.get(&chan_id).unwrap();
		chan.context().get_dust_buffer_feerate(None) as u64
	};

	// Skip the router complaint when node 1 will attempt to pay node 0
	let (route_1_0, payment_hash_1_0, _, payment_secret_1_0) =
		get_route_and_payment_hash!(nodes[1], nodes[0], NON_DUST_HTLC_MSAT);

	// Bring node 1's dust htlc exposure up to `BASE_DUST_EXPOSURE_MSAT`
	for _ in 0..DUST_HTLC_COUNT {
		route_payment(&nodes[0], &[&nodes[1]], DUST_HTLC_MSAT);
	}

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);
	assert_eq!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.len(), DUST_HTLC_COUNT);
	assert_eq!(nodes[1].node.list_channels()[0].pending_inbound_htlcs.len(), DUST_HTLC_COUNT);

	// Send an additional non-dust htlc from 0 to 1, and check the complaint
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(nodes[0], nodes[1], NON_DUST_HTLC_MSAT);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.remove(0));
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }]
	);
	nodes[1].logger.assert_log("lightning::ln::channel",
		format!("Cannot accept value that would put our total dust exposure at {} over the limit {} on counterparty commitment tx",
			expected_dust_exposure_msat, expected_dust_exposure_msat - 1), 1);
	check_added_monitors(&nodes[1], 1);

	// Clear the failed htlc
	let updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert_eq!(updates.update_fail_htlcs.len(), 1);
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	nodes[0].node.handle_update_fail_htlc(node_b_id, &updates.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates.commitment_signed, false, false);
	expect_payment_failed!(nodes[0], payment_hash, false);

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);
	assert_eq!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.len(), DUST_HTLC_COUNT);
	assert_eq!(nodes[1].node.list_channels()[0].pending_inbound_htlcs.len(), DUST_HTLC_COUNT);

	// Set node 1's max dust htlc exposure equal to the `expected_dust_exposure_msat`
	let config = ChannelConfigUpdate {
		max_dust_htlc_exposure_msat: Some(MaxDustHTLCExposure::FixedLimitMsat(
			expected_dust_exposure_msat,
		)),
		..ChannelConfigUpdate::default()
	};
	nodes[1].node.update_partial_channel_config(&node_a_id, &[chan_id], &config).unwrap();

	// Check a successful payment
	send_payment(&nodes[0], &[&nodes[1]], NON_DUST_HTLC_MSAT);

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);
	assert_eq!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.len(), DUST_HTLC_COUNT);
	assert_eq!(nodes[1].node.list_channels()[0].pending_inbound_htlcs.len(), DUST_HTLC_COUNT);

	// The `expected_dust_exposure_msat` for the outbound htlc changes in the non-anchor case, as the htlc success and timeout transactions have different weights
	// only_static_remote_key: 500_492 + 22 * (724 + 172) / 1000 * 1000 + 22 * 703 / 1000 * 1000 = 534_492
	let (htlc_success_tx_fee_sat, _) = second_stage_tx_fees_sat(&features, EXCESS_FEERATE as u32);
	if features == ChannelTypeFeatures::only_static_remote_key() {
		expected_dust_exposure_msat = BASE_DUST_EXPOSURE_MSAT
			+ EXCESS_FEERATE
				* (commitment_tx_base_weight(&features) + COMMITMENT_TX_WEIGHT_PER_HTLC)
				/ 1000 * 1000
			+ htlc_success_tx_fee_sat * 1000;
		assert_eq!(expected_dust_exposure_msat, 534_492);
	} else {
		assert_eq!(expected_dust_exposure_msat, 528_492);
	}

	// Set node 1's max dust htlc exposure to 1msat below `expected_dust_exposure_msat`
	let update = ChannelConfigUpdate {
		max_dust_htlc_exposure_msat: Some(MaxDustHTLCExposure::FixedLimitMsat(
			expected_dust_exposure_msat - 1,
		)),
		..ChannelConfigUpdate::default()
	};
	nodes[1].node.update_partial_channel_config(&node_a_id, &[chan_id], &update).unwrap();

	// Send an additional non-dust htlc from 1 to 0 using the pre-calculated route above, and check the immediate complaint
	let onion = RecipientOnionFields::secret_only(payment_secret_1_0);
	let id = PaymentId(payment_hash_1_0.0);
	let res = nodes[1].node.send_payment_with_route(route_1_0, payment_hash_1_0, onion, id);
	unwrap_send_err!(nodes[1], res, true, APIError::ChannelUnavailable { .. }, {});

	let (htlc_success_tx_fee_sat, _) =
		second_stage_tx_fees_sat(&features, node_1_dust_buffer_feerate as u32);
	let dust_limit = if features == ChannelTypeFeatures::only_static_remote_key() {
		MIN_CHAN_DUST_LIMIT_SATOSHIS * 1000 + htlc_success_tx_fee_sat * 1000
	} else {
		MIN_CHAN_DUST_LIMIT_SATOSHIS * 1000
	};
	nodes[1].logger.assert_log("lightning::ln::outbound_payment",
		format!("Failed to send along path due to error: Channel unavailable: Cannot send more than our next-HTLC maximum - {} msat", dust_limit), 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);
	assert_eq!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.len(), DUST_HTLC_COUNT);
	assert_eq!(nodes[1].node.list_channels()[0].pending_inbound_htlcs.len(), DUST_HTLC_COUNT);

	// Set node 1's max dust htlc exposure equal to `expected_dust_exposure_msat`
	let update = ChannelConfigUpdate {
		max_dust_htlc_exposure_msat: Some(MaxDustHTLCExposure::FixedLimitMsat(
			expected_dust_exposure_msat,
		)),
		..ChannelConfigUpdate::default()
	};
	nodes[1].node.update_partial_channel_config(&node_a_id, &[chan_id], &update).unwrap();

	// Check a successful payment
	send_payment(&nodes[1], &[&nodes[0]], NON_DUST_HTLC_MSAT);

	assert_eq!(nodes[0].node.list_channels().len(), 1);
	assert_eq!(nodes[1].node.list_channels().len(), 1);

	assert_eq!(nodes[0].node.list_channels()[0].pending_inbound_htlcs.len(), 0);
	assert_eq!(nodes[1].node.list_channels()[0].pending_outbound_htlcs.len(), 0);
	assert_eq!(nodes[0].node.list_channels()[0].pending_outbound_htlcs.len(), DUST_HTLC_COUNT);
	assert_eq!(nodes[1].node.list_channels()[0].pending_inbound_htlcs.len(), DUST_HTLC_COUNT);
}

#[test]
fn test_nondust_htlc_fees_dust_exposure_delta() {
	do_test_nondust_htlc_fees_dust_exposure_delta(ChannelTypeFeatures::only_static_remote_key());
	do_test_nondust_htlc_fees_dust_exposure_delta(
		ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies(),
	);
}

fn do_payment_with_custom_min_final_cltv_expiry(valid_delta: bool, use_user_hash: bool) {
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let min_cltv_expiry_delta = 120;
	let final_cltv_expiry_delta =
		if valid_delta { min_cltv_expiry_delta + 2 } else { min_cltv_expiry_delta - 2 };
	let recv_value = 100_000;

	create_chan_between_nodes(&nodes[0], &nodes[1]);

	let payment_parameters =
		PaymentParameters::from_node_id(node_b_id, final_cltv_expiry_delta as u32);
	let (hash, payment_preimage, payment_secret) = if use_user_hash {
		let (payment_preimage, hash, payment_secret) =
			get_payment_preimage_hash!(nodes[1], Some(recv_value), Some(min_cltv_expiry_delta));
		(hash, payment_preimage, payment_secret)
	} else {
		let (hash, payment_secret) = nodes[1]
			.node
			.create_inbound_payment(Some(recv_value), 7200, Some(min_cltv_expiry_delta))
			.unwrap();
		(hash, nodes[1].node.get_payment_preimage(hash, payment_secret).unwrap(), payment_secret)
	};
	let route = get_route!(nodes[0], payment_parameters, recv_value).unwrap();
	let onion = RecipientOnionFields::secret_only(payment_secret);
	nodes[0].node.send_payment_with_route(route, hash, onion, PaymentId(hash.0)).unwrap();
	check_added_monitors(&nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(node_a_id, &payment_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &payment_event.commitment_msg, false, false);

	if valid_delta {
		expect_and_process_pending_htlcs(&nodes[1], false);
		let preimage = if use_user_hash { None } else { Some(payment_preimage) };
		expect_payment_claimable!(nodes[1], hash, payment_secret, recv_value, preimage, node_b_id);

		claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);
	} else {
		expect_and_process_pending_htlcs(&nodes[1], true);
		let events = nodes[1].node.get_and_clear_pending_events();
		let fail_type = HTLCHandlingFailureType::Receive { payment_hash: hash };
		expect_htlc_failure_conditions(events, &[fail_type]);

		check_added_monitors(&nodes[1], 1);

		let fail_updates = get_htlc_update_msgs(&nodes[1], &node_a_id);
		nodes[0].node.handle_update_fail_htlc(node_b_id, &fail_updates.update_fail_htlcs[0]);
		let commitment = &fail_updates.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[1], commitment, false, true);

		expect_payment_failed!(nodes[0], hash, true);
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_payment_with_custom_min_cltv_expiry_delta() {
	do_payment_with_custom_min_final_cltv_expiry(false, false);
	do_payment_with_custom_min_final_cltv_expiry(false, true);
	do_payment_with_custom_min_final_cltv_expiry(true, false);
	do_payment_with_custom_min_final_cltv_expiry(true, true);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_disconnects_peer_awaiting_response_ticks() {
	// Tests that nodes which are awaiting on a response critical for channel responsiveness
	// disconnect their counterparty after `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Asserts a disconnect event is queued to the user.
	let check_disconnect_event = |node: &Node, should_disconnect: bool| {
		let disconnect_event =
			node.node.get_and_clear_pending_msg_events().iter().find_map(|event| {
				if let MessageSendEvent::HandleError { action, .. } = event {
					if let msgs::ErrorAction::DisconnectPeerWithWarning { .. } = action {
						Some(())
					} else {
						None
					}
				} else {
					None
				}
			});
		assert_eq!(disconnect_event.is_some(), should_disconnect);
	};

	// Fires timer ticks ensuring we only attempt to disconnect peers after reaching
	// `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let check_disconnect = |node: &Node| {
		// No disconnect without any timer ticks.
		check_disconnect_event(node, false);

		// No disconnect with 1 timer tick less than required.
		for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS - 1 {
			node.node.timer_tick_occurred();
			check_disconnect_event(node, false);
		}

		// Disconnect after reaching the required ticks.
		node.node.timer_tick_occurred();
		check_disconnect_event(node, true);

		// Disconnect again on the next tick if the peer hasn't been disconnected yet.
		node.node.timer_tick_occurred();
		check_disconnect_event(node, true);
	};

	create_chan_between_nodes(&nodes[0], &nodes[1]);

	// We'll start by performing a fee update with Alice (nodes[0]) on the channel.
	*nodes[0].fee_estimator.sat_per_kw.lock().unwrap() *= 2;
	nodes[0].node.timer_tick_occurred();
	check_added_monitors(&&nodes[0], 1);
	let alice_fee_update = get_htlc_update_msgs(&nodes[0], &node_b_id);
	nodes[1].node.handle_update_fee(node_a_id, alice_fee_update.update_fee.as_ref().unwrap());
	nodes[1]
		.node
		.handle_commitment_signed_batch_test(node_a_id, &alice_fee_update.commitment_signed);
	check_added_monitors(&&nodes[1], 1);

	// This will prompt Bob (nodes[1]) to respond with his `CommitmentSigned` and `RevokeAndACK`.
	let (bob_revoke_and_ack, bob_commitment_signed) = get_revoke_commit_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_revoke_and_ack(node_b_id, &bob_revoke_and_ack);
	check_added_monitors(&&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bob_commitment_signed);
	check_added_monitors(&nodes[0], 1);

	// Alice then needs to send her final `RevokeAndACK` to complete the commitment dance. We
	// pretend Bob hasn't received the message and check whether he'll disconnect Alice after
	// reaching `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let alice_revoke_and_ack =
		get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, node_b_id);
	check_disconnect(&nodes[1]);

	// Now, we'll reconnect them to test awaiting a `ChannelReestablish` message.
	//
	// Note that since the commitment dance didn't complete above, Alice is expected to resend her
	// final `RevokeAndACK` to Bob to complete it.
	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);
	let bob_init = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &bob_init, true).unwrap();
	let alice_init = msgs::Init {
		features: nodes[0].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[1].node.peer_connected(node_a_id, &alice_init, true).unwrap();

	// Upon reconnection, Alice sends her `ChannelReestablish` to Bob. Alice, however, hasn't
	// received Bob's yet, so she should disconnect him after reaching
	// `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let alice_channel_reestablish =
		get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, node_b_id);
	nodes[1].node.handle_channel_reestablish(node_a_id, &alice_channel_reestablish);
	check_disconnect(&nodes[0]);

	// Bob now sends his `ChannelReestablish` to Alice to resume the channel and consider it "live".
	let bob_channel_reestablish = nodes[1]
		.node
		.get_and_clear_pending_msg_events()
		.iter()
		.find_map(|event| {
			if let MessageSendEvent::SendChannelReestablish { node_id, msg } = event {
				assert_eq!(*node_id, node_a_id);
				Some(msg.clone())
			} else {
				None
			}
		})
		.unwrap();
	nodes[0].node.handle_channel_reestablish(node_b_id, &bob_channel_reestablish);

	// Sanity check that Alice won't disconnect Bob since she's no longer waiting for any messages.
	for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS {
		nodes[0].node.timer_tick_occurred();
		check_disconnect_event(&nodes[0], false);
	}

	// However, Bob is still waiting on Alice's `RevokeAndACK`, so he should disconnect her after
	// reaching `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	check_disconnect(&nodes[1]);

	// Finally, have Bob process the last message.
	nodes[1].node.handle_revoke_and_ack(node_a_id, &alice_revoke_and_ack);
	check_added_monitors(&nodes[1], 1);

	// At this point, neither node should attempt to disconnect each other, since they aren't
	// waiting on any messages.
	for node in &nodes {
		for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS {
			node.node.timer_tick_occurred();
			check_disconnect_event(node, false);
		}
	}
}

#[xtest(feature = "_externalize_tests")]
pub fn test_remove_expired_outbound_unfunded_channels() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let temp_channel_id =
		nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).unwrap();
	let open_channel_message =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_channel_message);
	let accept_channel_message =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel_message);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { .. } => (),
		_ => panic!("Unexpected event"),
	};

	// Asserts the outbound channel has been removed from a nodes[0]'s peer state map.
	let check_outbound_channel_existence = |should_exist: bool| {
		let per_peer_state = nodes[0].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&node_b_id).unwrap().lock().unwrap();
		assert_eq!(chan_lock.channel_by_id.contains_key(&temp_channel_id), should_exist);
	};

	// Channel should exist without any timer ticks.
	check_outbound_channel_existence(true);

	// Channel should exist with 1 timer tick less than required.
	for _ in 0..UNFUNDED_CHANNEL_AGE_LIMIT_TICKS - 1 {
		nodes[0].node.timer_tick_occurred();
		check_outbound_channel_existence(true)
	}

	// Remove channel after reaching the required ticks.
	nodes[0].node.timer_tick_occurred();
	check_outbound_channel_existence(false);

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match msg_events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg },
			node_id: _,
		} => {
			assert_eq!(
				msg.data,
				"Force-closing pending channel due to timeout awaiting establishment handshake"
			);
		},
		_ => panic!("Unexpected event"),
	}
	let reason = ClosureReason::FundingTimedOut;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_remove_expired_inbound_unfunded_channels() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let temp_channel_id =
		nodes[0].node.create_channel(node_b_id, 100_000, 0, 42, None, None).unwrap();
	let open_channel_message =
		get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	nodes[1].node.handle_open_channel(node_a_id, &open_channel_message);
	let accept_channel_message =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel_message);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { .. } => (),
		_ => panic!("Unexpected event"),
	};

	// Asserts the inbound channel has been removed from a nodes[1]'s peer state map.
	let check_inbound_channel_existence = |should_exist: bool| {
		let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
		let chan_lock = per_peer_state.get(&node_a_id).unwrap().lock().unwrap();
		assert_eq!(chan_lock.channel_by_id.contains_key(&temp_channel_id), should_exist);
	};

	// Channel should exist without any timer ticks.
	check_inbound_channel_existence(true);

	// Channel should exist with 1 timer tick less than required.
	for _ in 0..UNFUNDED_CHANNEL_AGE_LIMIT_TICKS - 1 {
		nodes[1].node.timer_tick_occurred();
		check_inbound_channel_existence(true)
	}

	// Remove channel after reaching the required ticks.
	nodes[1].node.timer_tick_occurred();
	check_inbound_channel_existence(false);

	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	match msg_events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg },
			node_id: _,
		} => {
			assert_eq!(
				msg.data,
				"Force-closing pending channel due to timeout awaiting establishment handshake"
			);
		},
		_ => panic!("Unexpected event"),
	}
	let reason = ClosureReason::FundingTimedOut;
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
}

fn do_test_manual_broadcast_skips_commitment_until_funding(
	force_broadcast: bool, close_by_timeout: bool, zero_conf_open: bool,
) {
	// Checks that commitment (and HTLC) transactions will not be broadcast for manual-funded
	// channels until either the funding transaction is seen on-chain or the channel is manually
	// forced to broadcast using `ChannelMonitor::broadcast_latest_holder_commitment_txn`.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut chan_config = test_default_channel_config();
	if zero_conf_open {
		chan_config.manually_accept_inbound_channels = true;
	}
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(chan_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let (channel_id, funding_tx, funding_outpoint) =
		create_channel_manual_funding(&nodes, 0, 1, 100_000, 10_000, zero_conf_open);

	if close_by_timeout {
		if !zero_conf_open {
			panic!("Cant send a payment if we didn't open 0-conf");
		}
		let (_payment_preimage, payment_hash, _payment_secret, _payment_id) =
			route_payment(&nodes[0], &[&nodes[1]], 10_000_000);
		nodes[1].node.get_and_clear_pending_events();

		connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
		let reason = ClosureReason::HTLCsTimedOut { payment_hash: Some(payment_hash) };
		check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100_000);

		// On timeout, B will try to fail the HTLC back, but its too late - A has already FC'd.
		connect_blocks(&nodes[1], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
		let failure = HTLCHandlingFailureType::Receive { payment_hash };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[failure]);
		get_htlc_update_msgs(&nodes[1], &node_a_id);
		check_added_monitors(&nodes[1], 1);
	} else {
		let msg = "manual close".to_owned();
		nodes[0]
			.node
			.force_close_broadcasting_latest_txn(&channel_id, &node_b_id, msg.clone())
			.unwrap();
		let reason =
			ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message: msg };
		check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100_000);
	}
	check_added_monitors(&nodes[0], 1);
	assert_eq!(get_err_msg(&nodes[0], &node_b_id).channel_id, channel_id);
	assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());

	let monitor_events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert!(monitor_events.is_empty());

	// The funding tx should be broadcasted after either a manual broadcast call or if the funding
	// transaction appears on chain.
	if force_broadcast {
		let monitor = get_monitor!(&nodes[0], channel_id);
		monitor.broadcast_latest_holder_commitment_txn(
			&nodes[0].tx_broadcaster,
			&nodes[0].fee_estimator,
			&nodes[0].logger,
		);
	} else {
		mine_transaction(&nodes[0], &funding_tx);
		mine_transaction(&nodes[1], &funding_tx);
	}

	let funding_txid = funding_tx.compute_txid();
	let broadcasts = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(broadcasts.len(), if close_by_timeout { 2 } else { 1 });
	let commitment_tx = broadcasts
		.iter()
		.find(|tx| {
			tx.input.iter().any(|input| {
				input.previous_output.txid == funding_txid
					&& input.previous_output.vout == u32::from(funding_outpoint.index)
			})
		})
		.expect("commitment transaction not broadcast");
	check_spends!(commitment_tx, funding_tx);
	assert_eq!(commitment_tx.input.len(), 1);
	let commitment_input = &commitment_tx.input[0];
	assert_eq!(commitment_input.previous_output.txid, funding_txid);
	assert_eq!(commitment_input.previous_output.vout, u32::from(funding_outpoint.index));

	if close_by_timeout {
		let htlc_tx = broadcasts
			.iter()
			.find(|tx| {
				tx.input
					.iter()
					.any(|input| input.previous_output.txid == commitment_tx.compute_txid())
			})
			.expect("HTLC claim transaction not broadcast");
		check_spends!(htlc_tx, commitment_tx);
	}

	let monitor_events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert!(monitor_events.iter().all(|event| !matches!(event, Event::BumpTransaction(_))));
}

#[test]
fn test_manual_broadcast_skips_commitment_until_funding() {
	do_test_manual_broadcast_skips_commitment_until_funding(true, true, true);
	do_test_manual_broadcast_skips_commitment_until_funding(true, false, true);
	do_test_manual_broadcast_skips_commitment_until_funding(true, false, false);
	do_test_manual_broadcast_skips_commitment_until_funding(false, true, true);
	do_test_manual_broadcast_skips_commitment_until_funding(false, false, true);
	do_test_manual_broadcast_skips_commitment_until_funding(false, false, false);
}

fn do_test_multi_post_event_actions(do_reload: bool) {
	// Tests handling multiple post-Event actions at once.
	// There is specific code in ChannelManager to handle channels where multiple post-Event
	// `ChannelMonitorUpdates` are pending at once. This test exercises that code.
	//
	// Specifically, we test calling `get_and_clear_pending_events` while there are two
	// PaymentSents from different channels and one channel has two pending `ChannelMonitorUpdate`s
	// - one from an RAA and one from an inbound commitment_signed.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let (persister, chain_monitor);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let node_a_reload;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;
	let chan_id_2 = create_announced_chan_between_nodes(&nodes, 0, 2).2;

	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	send_payment(&nodes[0], &[&nodes[2]], 1_000_000);

	let (our_payment_preimage, our_payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let (payment_preimage_2, payment_hash_2, ..) =
		route_payment(&nodes[0], &[&nodes[2]], 1_000_000);

	nodes[1].node.claim_funds(our_payment_preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(nodes[1], our_payment_hash, 1_000_000);

	nodes[2].node.claim_funds(payment_preimage_2);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_2, 1_000_000);

	for dest in &[1, 2] {
		let mut htlc_fulfill = get_htlc_update_msgs(&nodes[*dest], &node_a_id);
		let dest_node_id = nodes[*dest].node.get_our_node_id();
		nodes[0]
			.node
			.handle_update_fulfill_htlc(dest_node_id, htlc_fulfill.update_fulfill_htlcs.remove(0));
		let commitment = &htlc_fulfill.commitment_signed;
		do_commitment_signed_dance(&nodes[0], &nodes[*dest], commitment, false, false);
		check_added_monitors(&nodes[0], 0);
	}

	let (route, payment_hash_3, _, payment_secret_3) =
		get_route_and_payment_hash!(nodes[1], nodes[0], 100_000);
	let payment_id = PaymentId(payment_hash_3.0);
	let onion = RecipientOnionFields::secret_only(payment_secret_3);
	nodes[1].node.send_payment_with_route(route, payment_hash_3, onion, payment_id).unwrap();
	check_added_monitors(&nodes[1], 1);

	let send_event = SendEvent::from_node(&nodes[1]);
	nodes[0].node.handle_update_add_htlc(node_b_id, &send_event.msgs[0]);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &send_event.commitment_msg);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	if do_reload {
		let node_ser = nodes[0].node.encode();
		let chan_0_monitor_serialized = get_monitor!(nodes[0], chan_id).encode();
		let chan_1_monitor_serialized = get_monitor!(nodes[0], chan_id_2).encode();
		let mons = [&chan_0_monitor_serialized[..], &chan_1_monitor_serialized[..]];
		let config = test_default_channel_config();
		reload_node!(nodes[0], config, &node_ser, &mons, persister, chain_monitor, node_a_reload);

		nodes[1].node.peer_disconnected(node_a_id);
		nodes[2].node.peer_disconnected(node_a_id);

		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
		reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[2]));
	}

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 4);
	if let Event::PaymentSent { payment_preimage, .. } = events[0] {
		assert!(payment_preimage == our_payment_preimage || payment_preimage == payment_preimage_2);
	} else {
		panic!();
	}
	if let Event::PaymentSent { payment_preimage, .. } = events[1] {
		assert!(payment_preimage == our_payment_preimage || payment_preimage == payment_preimage_2);
	} else {
		panic!();
	}
	if let Event::PaymentPathSuccessful { .. } = events[2] {
	} else {
		panic!();
	}
	if let Event::PaymentPathSuccessful { .. } = events[3] {
	} else {
		panic!();
	}

	// After the events are processed, the ChannelMonitorUpdates will be released and, upon their
	// completion, we'll respond to nodes[1] with an RAA + CS.
	get_revoke_commit_msgs(&nodes[0], &node_b_id);
	check_added_monitors(&nodes[0], 3);
}

#[xtest(feature = "_externalize_tests")]
pub fn test_multi_post_event_actions() {
	do_test_multi_post_event_actions(true);
	do_test_multi_post_event_actions(false);
}
