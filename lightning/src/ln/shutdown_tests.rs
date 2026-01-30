// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests of our shutdown and closing_signed negotiation logic as well as some assorted force-close
//! handling tests.

use crate::chain::transaction::OutPoint;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::events::{ClosureReason, Event, HTLCHandlingFailureReason, HTLCHandlingFailureType};
use crate::ln::channel_state::{ChannelDetails, ChannelShutdownState};
use crate::ln::channelmanager::{self, PaymentId, RecipientOnionFields, Retry};
use crate::ln::msgs;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, ErrorAction, MessageSendEvent};
use crate::ln::onion_utils::LocalHTLCFailureReason;
use crate::ln::script::ShutdownScript;
use crate::ln::types::ChannelId;
use crate::prelude::*;
use crate::routing::router::{get_route, PaymentParameters, RouteParameters};
use crate::sign::{EntropySource, SignerProvider};
use crate::types::string::UntrustedString;
use crate::util::config::UserConfig;
use crate::util::errors::APIError;
use crate::util::test_utils;
use crate::util::test_utils::OnGetShutdownScriptpubkey;

use bitcoin::amount::Amount;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::network::Network;
use bitcoin::opcodes;
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{Transaction, TxOut, WitnessProgram, WitnessVersion};

use crate::ln::functional_test_utils::*;

#[test]
fn pre_funding_lock_shutdown_test() {
	// Test sending a shutdown prior to channel_ready after funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 8000000, 0);
	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	nodes[0]
		.node
		.close_channel(
			&ChannelId::v1_from_funding_outpoint(OutPoint { txid: tx.compute_txid(), index: 0 }),
			&node_b_id,
		)
		.unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);

	let node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
	let node_1_closing_signed =
		get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
	nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 8000000);
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 8000000);
}

#[test]
fn expect_channel_shutdown_state() {
	// Test sending a shutdown prior to channel_ready after funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NotShuttingDown);

	nodes[0].node.close_channel(&chan_1.2, &node_b_id).unwrap();

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NotShuttingDown);

	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);

	// node1 goes into NegotiatingClosingFee since there are no HTLCs in flight, note that it
	// doesnt mean that node1 has sent/recved its closing signed message
	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);

	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);

	let node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
	let node_1_closing_signed =
		get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
	nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);
}

#[test]
fn expect_channel_shutdown_state_with_htlc() {
	// Test sending a shutdown with outstanding updates pending.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let _chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage_0, payment_hash_0, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NotShuttingDown);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NotShuttingDown);

	nodes[0].node.close_channel(&chan_1.2, &node_b_id).unwrap();

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NotShuttingDown);

	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::ResolvingHTLCs);

	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ResolvingHTLCs);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::ResolvingHTLCs);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Claim Funds on Node2
	nodes[2].node.claim_funds(payment_preimage_0);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_0, 100_000);

	// Fulfil HTLCs on node1 and node0
	let mut updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, updates.update_fulfill_htlcs.remove(0));
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
	check_added_monitors(&nodes[1], 1);
	let mut updates_2 = get_htlc_update_msgs(&nodes[1], &node_a_id);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, false, false);

	// Still in "resolvingHTLCs" on chan1 after htlc removed on chan2
	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ResolvingHTLCs);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::ResolvingHTLCs);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates_2.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates_2.commitment_signed, false, true);
	expect_payment_sent!(nodes[0], payment_preimage_0);

	// all htlcs removed, chan1 advances to NegotiatingClosingFee
	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);

	// ClosingSignNegotion process
	let node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
	let node_1_closing_signed =
		get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
	nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	assert!(node_1_none.is_none());
	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);

	// Shutdown basically removes the channelDetails, testing of shutdowncomplete state unnecessary
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn test_lnd_bug_6039() {
	// LND sends a nonsense error message any time it gets a shutdown if there are still HTLCs
	// pending. We currently swallow that error to work around LND's bug #6039. This test emulates
	// the LND nonsense and ensures we at least kinda handle it.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, ..) = route_payment(&nodes[0], &[&nodes[1]], 100_000);

	nodes[0].node.close_channel(&chan.2, &node_b_id).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);

	// Generate an lnd-like error message and check that we respond by simply screaming louder to
	// see if LND will accept our protocol compliance.
	let err_msg =
		msgs::ErrorMessage { channel_id: chan.2, data: "link failed to shutdown".to_string() };
	nodes[0].node.handle_error(node_b_id, &err_msg);
	let node_a_responses = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(
		node_a_responses[0],
		MessageSendEvent::SendShutdown { node_id: node_b_id, msg: node_0_shutdown }
	);
	if let MessageSendEvent::HandleError {
		action: msgs::ErrorAction::SendWarningMessage { .. },
		..
	} = node_a_responses[1]
	{
	} else {
		panic!();
	}

	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	// Assume that LND will eventually respond to our Shutdown if we clear all the remaining HTLCs
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);

	// ClosingSignNegotion process
	let node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
	let node_1_closing_signed =
		get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
	nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	assert!(node_1_none.is_none());

	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);

	// Shutdown basically removes the channelDetails, testing of shutdowncomplete state unnecessary
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn shutdown_on_unfunded_channel() {
	// Test receiving a shutdown prior to funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 1_000_000, 100_000, 0, None, None).unwrap();
	let open_chan = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	// Create a dummy P2WPKH script
	let script = Builder::new().push_int(0).push_slice(&[0; 20]).into_script();

	nodes[0].node.handle_shutdown(
		node_b_id,
		&msgs::Shutdown {
			channel_id: open_chan.common_fields.temporary_channel_id,
			scriptpubkey: script,
		},
	);
	let reason = ClosureReason::CounterpartyCoopClosedUnfundedChannel;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 1_000_000);
}

#[test]
fn close_on_unfunded_channel() {
	// Test the user asking us to close prior to funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_id =
		nodes[0].node.create_channel(node_b_id, 1_000_000, 100_000, 0, None, None).unwrap();
	let _open_chan = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);

	nodes[0].node.close_channel(&chan_id, &node_b_id).unwrap();
	let reason = ClosureReason::LocallyCoopClosedUnfundedChannel;
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 1_000_000);
}

#[test]
fn expect_channel_shutdown_state_with_force_closure() {
	// Test sending a shutdown prior to channel_ready after funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let message = "Channel force-closed".to_owned();

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NotShuttingDown);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NotShuttingDown);

	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(&chan_1.2, &node_a_id, message.clone())
		.unwrap();
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NotShuttingDown);
	assert!(nodes[1].node.list_channels().is_empty());

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan_1.3);
	mine_transaction(&nodes[0], &node_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_event(&nodes[0], 1, ClosureReason::CommitmentTxConfirmed, &[node_b_id], 100000);
	let reason_b = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);
}

#[test]
fn updates_shutdown_wait() {
	// Test sending a shutdown with outstanding updates pending
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let logger = test_utils::TestLogger::new();
	let scorer = test_utils::TestScorer::new();
	let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
	let random_seed_bytes = keys_manager.get_secure_random_bytes();

	let (payment_preimage_0, payment_hash_0, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	nodes[0].node.close_channel(&chan_1.2, &node_b_id).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[0]);

	let payment_params_1 = PaymentParameters::from_node_id(node_b_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params_1, 100_000);
	let route_1 = get_route(
		&node_a_id,
		&route_params,
		&nodes[0].network_graph.read_only(),
		None,
		&logger,
		&scorer,
		&Default::default(),
		&random_seed_bytes,
	)
	.unwrap();
	let payment_params_2 = PaymentParameters::from_node_id(node_a_id, TEST_FINAL_CLTV)
		.with_bolt11_features(nodes[0].node.bolt11_invoice_features())
		.unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params_2, 100_000);
	let route_2 = get_route(
		&node_b_id,
		&route_params,
		&nodes[1].network_graph.read_only(),
		None,
		&logger,
		&scorer,
		&Default::default(),
		&random_seed_bytes,
	)
	.unwrap();

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let id = PaymentId(payment_hash.0);
	let res = nodes[0].node.send_payment_with_route(route_1, payment_hash, onion, id);
	unwrap_send_err!(nodes[0], res, true, APIError::ChannelUnavailable { .. }, {});

	let onion = RecipientOnionFields::secret_only(payment_secret);
	let res = nodes[1].node.send_payment_with_route(route_2, payment_hash, onion, id);
	unwrap_send_err!(nodes[1], res, true, APIError::ChannelUnavailable { .. }, {});

	nodes[2].node.claim_funds(payment_preimage_0);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_0, 100_000);

	let mut updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, updates.update_fulfill_htlcs.remove(0));
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
	check_added_monitors(&nodes[1], 1);
	let mut updates_2 = get_htlc_update_msgs(&nodes[1], &node_a_id);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, false, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates_2.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates_2.commitment_signed, false, true);
	expect_payment_sent!(nodes[0], payment_preimage_0);

	let node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
	let node_1_closing_signed =
		get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
	nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	assert!(node_1_none.is_none());

	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);

	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_c_id], 100000);
	let reason_c = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[2], 1, reason_c, &[node_b_id], 100000);
}

#[test]
fn htlc_fail_async_shutdown() {
	do_htlc_fail_async_shutdown(true);
	do_htlc_fail_async_shutdown(false);
}

fn do_htlc_fail_async_shutdown(blinded_recipient: bool) {
	// Test HTLCs fail if shutdown starts even if messages are delivered out-of-order
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let amt_msat = 100000;
	let (_, our_payment_hash, our_payment_secret) =
		get_payment_preimage_hash(&nodes[2], Some(amt_msat), None);
	let route_params = if blinded_recipient {
		crate::ln::blinded_payment_tests::get_blinded_route_parameters(
			amt_msat,
			our_payment_secret,
			1,
			100000000,
			nodes.iter().skip(1).map(|n| n.node.get_our_node_id()).collect(),
			&[&chan_2.0.contents],
			&chanmon_cfgs[2].keys_manager,
		)
	} else {
		RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(node_c_id, TEST_FINAL_CLTV),
			amt_msat,
		)
	};
	let onion = RecipientOnionFields::secret_only(our_payment_secret);
	let id = PaymentId(our_payment_hash.0);
	nodes[0]
		.node
		.send_payment(our_payment_hash, onion, id, route_params, Retry::Attempts(0))
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	let updates = get_htlc_update_msgs(&nodes[0], &node_b_id);
	assert_eq!(updates.update_add_htlcs.len(), 1);
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());

	nodes[1].node.close_channel(&chan_1.2, &node_a_id).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);

	nodes[1].node.handle_update_add_htlc(node_a_id, &updates.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);
	assert!(commitment_signed_dance_through_cp_raa(&nodes[1], &nodes[0], false, false).is_none());
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_htlc_handling_failed_destinations!(
		nodes[1].node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Forward { node_id: Some(node_c_id), channel_id: chan_2.2 }]
	);
	check_added_monitors(&nodes[1], 1);

	let updates_2 = get_htlc_update_msgs(&nodes[1], &node_a_id);
	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fulfill_htlcs.is_empty());
	assert_eq!(updates_2.update_fail_htlcs.len(), 1);
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(node_b_id, &updates_2.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates_2.commitment_signed, false, true);

	if blinded_recipient {
		expect_payment_failed_conditions(
			&nodes[0],
			our_payment_hash,
			false,
			PaymentFailedConditions::new()
				.expected_htlc_error_data(LocalHTLCFailureReason::InvalidOnionBlinding, &[0; 32]),
		);
	} else {
		expect_payment_failed_with_update!(
			nodes[0],
			our_payment_hash,
			false,
			chan_2.0.contents.short_channel_id,
			true
		);
	}

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let node_0_closing_signed = match msg_events[0] {
		MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_b_id);
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
	let node_1_closing_signed =
		get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
	nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
	let reason_a = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let event1 = ExpectedCloseEvent {
		channel_capacity_sats: Some(100000),
		channel_id: None,
		counterparty_node_id: Some(node_a_id),
		discard_funding: false,
		splice_failed: false,
		reason: Some(ClosureReason::LocallyInitiatedCooperativeClosure),
		channel_funding_txo: None,
		user_channel_id: None,
	};
	let event2 = ExpectedCloseEvent {
		channel_capacity_sats: Some(100000),
		channel_id: None,
		counterparty_node_id: Some(node_c_id),
		discard_funding: false,
		splice_failed: false,
		reason: Some(ClosureReason::CounterpartyInitiatedCooperativeClosure),
		channel_funding_txo: None,
		user_channel_id: None,
	};
	check_closed_events(&nodes[1], &[event1, event2]);
	let reason_c = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[2], 1, reason_c, &[node_b_id], 100000);
}

fn do_test_shutdown_rebroadcast(recv_count: u8) {
	// Test that shutdown/closing_signed is re-sent on reconnect with a variable number of
	// messages delivered prior to disconnect
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, payment_hash, ..) =
		route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	nodes[1].node.close_channel(&chan_1.2, &node_a_id).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	if recv_count > 0 {
		nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
		if recv_count > 1 {
			nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);
		}
	}

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	let node_0_reestablish = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, false).unwrap();
	let node_1_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();

	nodes[1].node.handle_channel_reestablish(node_a_id, &node_0_reestablish);
	let node_1_2nd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	assert!(node_1_shutdown == node_1_2nd_shutdown);

	nodes[0].node.handle_channel_reestablish(node_b_id, &node_1_reestablish);
	let node_0_2nd_shutdown = if recv_count > 0 {
		let node_0_2nd_shutdown =
			get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
		nodes[0].node.handle_shutdown(node_b_id, &node_1_2nd_shutdown);
		node_0_2nd_shutdown
	} else {
		let node_0_chan_update =
			get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);
		assert_eq!(node_0_chan_update.contents.channel_flags & 2, 0); // "disabled" flag must not be set as we just reconnected.
		nodes[0].node.handle_shutdown(node_b_id, &node_1_2nd_shutdown);
		get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id)
	};
	nodes[1].node.handle_shutdown(node_a_id, &node_0_2nd_shutdown);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 100_000);

	let mut updates = get_htlc_update_msgs(&nodes[2], &node_b_id);
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, updates.update_fulfill_htlcs.remove(0));
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
	check_added_monitors(&nodes[1], 1);
	let mut updates_2 = get_htlc_update_msgs(&nodes[1], &node_a_id);
	do_commitment_signed_dance(&nodes[1], &nodes[2], &updates.commitment_signed, false, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(node_b_id, updates_2.update_fulfill_htlcs.remove(0));
	do_commitment_signed_dance(&nodes[0], &nodes[1], &updates_2.commitment_signed, false, true);
	expect_payment_sent!(nodes[0], payment_preimage);

	let node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	if recv_count > 0 {
		nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
		let node_1_closing_signed =
			get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
		nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
		let (_, node_0_2nd_closing_signed) =
			get_closing_signed_broadcast!(nodes[0].node, node_b_id);
		assert!(node_0_2nd_closing_signed.is_some());
	}

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	nodes[1].node.peer_connected(node_a_id, &init_msg, true).unwrap();
	let node_1_2nd_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[0].node.peer_connected(node_b_id, &init_msg, false).unwrap();
	if recv_count == 0 {
		// If all closing_signeds weren't delivered we can just resume where we left off...
		let node_0_2nd_reestablish = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();

		nodes[0].node.handle_channel_reestablish(node_b_id, &node_1_2nd_reestablish);
		let node_0_msgs = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(node_0_msgs.len(), 2);
		let node_0_2nd_closing_signed = match node_0_msgs[1] {
			MessageSendEvent::SendClosingSigned { ref msg, .. } => {
				assert_eq!(node_0_closing_signed, *msg);
				msg.clone()
			},
			_ => panic!(),
		};

		let node_0_3rd_shutdown = match node_0_msgs[0] {
			MessageSendEvent::SendShutdown { ref msg, .. } => {
				assert_eq!(node_0_2nd_shutdown, *msg);
				msg.clone()
			},
			_ => panic!(),
		};
		assert!(node_0_2nd_shutdown == node_0_3rd_shutdown);

		nodes[1].node.handle_channel_reestablish(node_a_id, &node_0_2nd_reestablish);
		let node_1_3rd_shutdown =
			get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
		assert!(node_1_3rd_shutdown == node_1_2nd_shutdown);

		nodes[1].node.handle_shutdown(node_a_id, &node_0_3rd_shutdown);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.handle_shutdown(node_b_id, &node_1_3rd_shutdown);

		nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed);
		let node_1_closing_signed =
			get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
		nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
		let (_, node_0_2nd_closing_signed) =
			get_closing_signed_broadcast!(nodes[0].node, node_b_id);
		nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed.unwrap());
		let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
		assert!(node_1_none.is_none());
		let reason = ClosureReason::LocallyInitiatedCooperativeClosure;
		check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	} else {
		// If one node, however, received + responded with an identical closing_signed we end
		// up erroring and node[0] will try to broadcast its own latest commitment transaction.
		// There isn't really anything better we can do simply, but in the future we might
		// explore storing a set of recently-closed channels that got disconnected during
		// closing_signed and avoiding broadcasting local commitment txn for some timeout to
		// give our counterparty enough time to (potentially) broadcast a cooperative closing
		// transaction.
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.handle_channel_reestablish(node_b_id, &node_1_2nd_reestablish);
		let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 2);
		if let MessageSendEvent::HandleError { ref action, .. } = msg_events[1] {
			match action {
				&ErrorAction::SendErrorMessage { ref msg } => {
					nodes[1].node.handle_error(node_a_id, &msg);
					assert_eq!(msg.channel_id, chan_1.2);
				},
				_ => panic!("Unexpected event!"),
			}
		} else {
			panic!("Needed SendErrorMessage close");
		}

		// get_closing_signed_broadcast usually eats the BroadcastChannelUpdate for us and
		// checks it, but in this case nodes[1] didn't ever get a chance to receive a
		// closing_signed so we do it ourselves
		check_closed_broadcast!(nodes[1], false);
		check_added_monitors(&nodes[1], 1);
		let reason = ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", &node_b_id)) };
		check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	}

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);

	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());

	let reason_a = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_c_id], 100000);
	let reason_c = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[2], 1, reason_c, &[node_b_id], 100000);
}

#[test]
fn test_shutdown_rebroadcast() {
	do_test_shutdown_rebroadcast(0);
	do_test_shutdown_rebroadcast(1);
	do_test_shutdown_rebroadcast(2);
}

#[test]
fn test_upfront_shutdown_script() {
	// BOLT 2 : Option upfront shutdown script, if peer commit its closing_script at channel opening
	// enforce it at shutdown message

	let mut config = UserConfig::default();
	config.channel_handshake_config.announce_for_forwarding = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	// We test that in case of peer committing upfront to a script, if it changes at closing, we refuse to sign
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000);
	nodes[0].node.close_channel(&chan.2, &node_c_id).unwrap();
	let node_0_orig_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_c_id);
	let mut node_0_shutdown = node_0_orig_shutdown.clone();
	node_0_shutdown.scriptpubkey =
		Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	// Test we enforce upfront_scriptpbukey if by providing a different one at closing that we warn
	// the peer and ignore the message.
	nodes[2].node.handle_shutdown(node_a_id, &node_0_shutdown);
	assert!(regex::Regex::new(r"Got shutdown request with a scriptpubkey \([A-Fa-f0-9]+\) which did not match their previous scriptpubkey.")
			.unwrap().is_match(&check_warn_msg!(nodes[2], node_a_id, chan.2)));
	// This allows nodes[2] to retry the shutdown message, which should get a response:
	nodes[2].node.handle_shutdown(node_a_id, &node_0_orig_shutdown);
	get_event_msg!(nodes[2], MessageSendEvent::SendShutdown, node_a_id);

	// We test that in case of peer committing upfront to a script, if it doesn't change at closing, we sign
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000);
	nodes[0].node.close_channel(&chan.2, &node_c_id).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_c_id);
	// We test that in case of peer committing upfront to a script, if it oesn't change at closing, we sign
	nodes[2].node.handle_shutdown(node_a_id, &node_0_shutdown);
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => {
			assert_eq!(node_id, node_a_id)
		},
		_ => panic!("Unexpected event"),
	}

	// We test that if case of peer non-signaling we don't enforce committed script at channel opening
	let mut features = nodes[0].node.init_features();
	features.clear_upfront_shutdown_script();
	*nodes[0].override_init_features.borrow_mut() = Some(features);
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);
	nodes[0].node.close_channel(&chan.2, &node_b_id).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1].node.handle_shutdown(node_a_id, &node_1_shutdown);
	check_added_monitors(&nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => {
			assert_eq!(node_id, node_a_id)
		},
		_ => panic!("Unexpected event"),
	}

	// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	// channel smoothly, opt-out is from channel initiator here
	*nodes[0].override_init_features.borrow_mut() = None;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 1000000, 1000000);
	nodes[1].node.close_channel(&chan.2, &node_a_id).unwrap();
	check_added_monitors(&nodes[1], 1);
	let node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => {
			assert_eq!(node_id, node_b_id)
		},
		_ => panic!("Unexpected event"),
	}

	//// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	//// channel smoothly
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);
	nodes[1].node.close_channel(&chan.2, &node_a_id).unwrap();
	check_added_monitors(&nodes[1], 1);
	let node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => {
			assert_eq!(node_id, node_b_id)
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => {
			assert_eq!(node_id, node_b_id)
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_unsupported_anysegwit_upfront_shutdown_script() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	// Clear shutdown_anysegwit on initiator
	let mut features = channelmanager::provided_init_features(&test_default_channel_config());
	features.clear_shutdown_anysegwit();
	*node_cfgs[0].override_init_features.borrow_mut() = Some(features);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Use a non-v0 segwit script supported by option_shutdown_anysegwit
	let anysegwit_shutdown_script = Builder::new().push_int(16).push_slice(&[0, 40]).into_script();

	// Check script when handling an open_channel message
	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	open_channel.common_fields.shutdown_scriptpubkey = Some(anysegwit_shutdown_script.clone());
	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::OpenChannelRequest { temporary_channel_id, counterparty_node_id, .. } => {
			assert!(nodes[1]
				.node
				.accept_inbound_channel(temporary_channel_id, counterparty_node_id, 42, None,)
				.is_err());
		},
		_ => panic!("Unexpected event"),
	};

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg },
			node_id,
		} => {
			assert_eq!(node_id, node_a_id);
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: OP_PUSHNUM_16 OP_PUSHBYTES_2 0028");
		},
		_ => panic!("Unexpected event"),
	}

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	// Clear shutdown_anysegwit on responder
	let mut features = channelmanager::provided_init_features(&test_default_channel_config());
	features.clear_shutdown_anysegwit();
	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Check script when handling an accept_channel message
	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	handle_and_accept_open_channel(&nodes[1], node_a_id, &open_channel);

	let mut accept_channel =
		get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, node_a_id);
	accept_channel.common_fields.shutdown_scriptpubkey = Some(anysegwit_shutdown_script.clone());
	nodes[0].node.handle_accept_channel(node_b_id, &accept_channel);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg },
			node_id,
		} => {
			assert_eq!(node_id, node_b_id);
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: OP_PUSHNUM_16 OP_PUSHBYTES_2 0028");
		},
		_ => panic!("Unexpected event"),
	}
	let reason = ClosureReason::ProcessingError { err: "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: OP_PUSHNUM_16 OP_PUSHBYTES_2 0028".to_string() };
	check_closed_event(&nodes[0], 1, reason, &[node_b_id], 100000);
}

#[test]
fn test_invalid_upfront_shutdown_script() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	nodes[0].node.create_channel(node_b_id, 100000, 10001, 42, None, None).unwrap();

	// Use a segwit v0 script with an unsupported witness program
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, node_b_id);
	open_channel.common_fields.shutdown_scriptpubkey =
		Some(Builder::new().push_int(0).push_slice(&[0, 0]).into_script());
	nodes[1].node.handle_open_channel(node_a_id, &open_channel);
	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::OpenChannelRequest { temporary_channel_id, counterparty_node_id, .. } => {
			assert!(nodes[1]
				.node
				.accept_inbound_channel(temporary_channel_id, counterparty_node_id, 42, None,)
				.is_err());
		},
		_ => panic!("Unexpected event"),
	};

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::SendErrorMessage { ref msg },
			node_id,
		} => {
			assert_eq!(node_id, node_a_id);
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: OP_0 OP_PUSHBYTES_2 0000");
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_segwit_v0_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_handshake_config.announce_for_forwarding = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[1].node.close_channel(&chan.2, &node_a_id).unwrap();
	check_added_monitors(&nodes[1], 1);

	// Use a segwit v0 script supported even without option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	node_0_shutdown.scriptpubkey = Builder::new().push_int(0).push_slice(&[0; 20]).into_script();
	nodes[0].node.handle_shutdown(node_b_id, &node_0_shutdown);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => {
			assert_eq!(node_id, node_b_id)
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => {
			assert_eq!(node_id, node_b_id)
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_anysegwit_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_handshake_config.announce_for_forwarding = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[1].node.close_channel(&chan.2, &node_a_id).unwrap();
	check_added_monitors(&nodes[1], 1);

	// Use a non-v0 segwit script supported by option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	node_0_shutdown.scriptpubkey = Builder::new().push_int(16).push_slice(&[0, 0]).into_script();
	nodes[0].node.handle_shutdown(node_b_id, &node_0_shutdown);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => {
			assert_eq!(node_id, node_b_id)
		},
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => {
			assert_eq!(node_id, node_b_id)
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_unsupported_anysegwit_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_handshake_config.announce_for_forwarding = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config.clone()), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let mut node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut features = channelmanager::provided_init_features(&config);
	features.clear_shutdown_anysegwit();
	*node_cfgs[0].override_init_features.borrow_mut() = Some(features.clone());
	*node_cfgs[1].override_init_features.borrow_mut() = Some(features);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// Check that using an unsupported shutdown script fails and a supported one succeeds.
	let supported_shutdown_script =
		chanmon_cfgs[1].keys_manager.get_shutdown_scriptpubkey().unwrap();
	let unsupported_witness_program = WitnessProgram::new(WitnessVersion::V16, &[0, 40]).unwrap();
	let unsupported_shutdown_script =
		ShutdownScript::new_witness_program(&unsupported_witness_program).unwrap();
	chanmon_cfgs[1]
		.keys_manager
		.expect(OnGetShutdownScriptpubkey { returns: unsupported_shutdown_script.clone() })
		.expect(OnGetShutdownScriptpubkey { returns: supported_shutdown_script });

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	match nodes[1].node.close_channel(&chan.2, &node_a_id) {
		Err(APIError::IncompatibleShutdownScript { script }) => {
			assert_eq!(script.into_inner(), unsupported_shutdown_script.clone().into_inner());
		},
		Err(e) => panic!("Unexpected error: {:?}", e),
		Ok(_) => panic!("Expected error"),
	}
	nodes[1].node.close_channel(&chan.2, &node_a_id).unwrap();
	check_added_monitors(&nodes[1], 1);

	// Use a non-v0 segwit script unsupported without option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	node_0_shutdown.scriptpubkey = unsupported_shutdown_script.into_inner();
	nodes[0].node.handle_shutdown(node_b_id, &node_0_shutdown);

	assert_eq!(
		&check_warn_msg!(nodes[0], node_b_id, chan.2),
		"Got a nonstandard scriptpubkey (60020028) from remote peer"
	);
}

#[test]
fn test_invalid_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_handshake_config.announce_for_forwarding = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[1].node.close_channel(&chan.2, &node_a_id).unwrap();
	check_added_monitors(&nodes[1], 1);

	// Use a segwit v0 script with an unsupported witness program
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	node_0_shutdown.scriptpubkey = Builder::new().push_int(0).push_slice(&[0, 0]).into_script();
	nodes[0].node.handle_shutdown(node_b_id, &node_0_shutdown);

	assert_eq!(
		&check_warn_msg!(nodes[0], node_b_id, chan.2),
		"Got a nonstandard scriptpubkey (00020000) from remote peer"
	);
}

#[test]
fn test_user_shutdown_script() {
	let mut config = test_default_channel_config();
	config.channel_handshake_config.announce_for_forwarding = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();

	// Segwit v0 script of the form OP_0 <20-byte hash>
	let script = Builder::new().push_int(0).push_slice(&[0; 20]).into_script();

	let shutdown_script = ShutdownScript::try_from(script.clone()).unwrap();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[1]
		.node
		.close_channel_with_feerate_and_script(&chan.2, &node_a_id, None, Some(shutdown_script))
		.unwrap();
	check_added_monitors(&nodes[1], 1);

	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);

	assert_eq!(node_0_shutdown.scriptpubkey, script);
}

#[test]
fn test_already_set_user_shutdown_script() {
	let mut config = test_default_channel_config();
	config.channel_handshake_config.announce_for_forwarding = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();

	// Segwit v0 script of the form OP_0 <20-byte hash>
	let script = Builder::new().push_int(0).push_slice(&[0; 20]).into_script();

	let shutdown_script = ShutdownScript::try_from(script).unwrap();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	let result = nodes[1].node.close_channel_with_feerate_and_script(
		&chan.2,
		&node_a_id,
		None,
		Some(shutdown_script),
	);

	assert_eq!(
		result,
		Err(APIError::APIMisuseError {
			err: "Cannot override shutdown script for a channel with one already set".to_string()
		})
	);
}

#[derive(PartialEq)]
enum TimeoutStep {
	AfterShutdown,
	AfterClosingSigned,
	NoTimeout,
}

fn do_test_closing_signed_reinit_timeout(timeout_step: TimeoutStep) {
	// The range-based closing signed negotiation allows the funder to restart the process with a
	// new range if the previous range did not overlap. This allows implementations to request user
	// intervention allowing users to enter a new fee range. We do not implement the sending side
	// of this, instead opting to allow users to enter an explicit "willing to pay up to X to avoid
	// force-closing" value and relying on that instead.
	//
	// Here we run test the fundee side of that restart mechanism, implementing the funder side of
	// it manually.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	send_payment(&nodes[0], &[&nodes[1]], 8_000_000);

	nodes[0].node.close_channel(&chan_id, &node_b_id).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);

	{
		// Now we set nodes[1] to require a relatively high feerate for closing. This should result
		// in it rejecting nodes[0]'s initial closing_signed, giving nodes[0] a chance to try
		// again.
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 10;
	}

	let mut node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	// nodes[0] should use a "reasonable" feerate, well under the 10 sat/vByte that nodes[1] thinks
	// is the current prevailing feerate.
	assert!(node_0_closing_signed.fee_satoshis <= 500);

	if timeout_step != TimeoutStep::AfterShutdown {
		nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
		assert!(check_warn_msg!(nodes[1], node_a_id, chan_id)
			.starts_with("Unable to come to consensus about closing feerate"));

		// Now deliver a mutated closing_signed indicating a higher acceptable fee range, which
		// nodes[1] should happily accept and respond to.
		node_0_closing_signed.fee_range.as_mut().unwrap().max_fee_satoshis *= 10;
		{
			let mut per_peer_lock;
			let mut peer_state_lock;
			let chan =
				get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_id);

			chan.context_mut().closing_fee_limits.as_mut().unwrap().1 *= 10;
		}
		nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
		let node_1_closing_signed =
			get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
		nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
		let node_0_2nd_closing_signed = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
		if timeout_step == TimeoutStep::NoTimeout {
			nodes[1].node.handle_closing_signed(node_a_id, &node_0_2nd_closing_signed.1.unwrap());
			let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
			check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);
		}
		let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
		check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	}

	if timeout_step != TimeoutStep::NoTimeout {
		assert!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());
	} else {
		assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	}

	nodes[1].node.timer_tick_occurred();
	nodes[1].node.timer_tick_occurred();

	let txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	assert_eq!(txn.len(), 1);
	assert_eq!(txn[0].output.len(), 2);

	if timeout_step != TimeoutStep::NoTimeout {
		assert!(
			(txn[0].output[0].script_pubkey.is_p2wpkh()
				&& txn[0].output[1].script_pubkey.is_p2wsh())
				|| (txn[0].output[1].script_pubkey.is_p2wpkh()
					&& txn[0].output[0].script_pubkey.is_p2wsh())
		);
		check_closed_broadcast!(nodes[1], true);
		check_added_monitors(&nodes[1], 1);
		let reason = ClosureReason::ProcessingError {
			err: "closing_signed negotiation failed to finish within two timer ticks".to_string(),
		};
		check_closed_event(&nodes[1], 1, reason, &[node_a_id], 100000);
	} else {
		assert!(txn[0].output[0].script_pubkey.is_p2wpkh());
		assert!(txn[0].output[1].script_pubkey.is_p2wpkh());

		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg, .. } => {
				assert_eq!(msg.contents.channel_flags & 2, 2);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

#[test]
fn test_closing_signed_reinit_timeout() {
	do_test_closing_signed_reinit_timeout(TimeoutStep::AfterShutdown);
	do_test_closing_signed_reinit_timeout(TimeoutStep::AfterClosingSigned);
	do_test_closing_signed_reinit_timeout(TimeoutStep::NoTimeout);
}

fn do_simple_legacy_shutdown_test(high_initiator_fee: bool) {
	// A simpe test of the legacy shutdown fee negotiation logic.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	if high_initiator_fee {
		// If high_initiator_fee is set, set nodes[0]'s feerate significantly higher. This
		// shouldn't impact the flow at all given nodes[1] will happily accept the higher fee.
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 10;
	}

	nodes[0].node.close_channel(&chan.2, &node_b_id).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);

	let mut node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	node_0_closing_signed.fee_range = None;
	if high_initiator_fee {
		assert!(node_0_closing_signed.fee_satoshis > 500);
	} else {
		assert!(node_0_closing_signed.fee_satoshis < 500);
	}

	nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
	let (_, mut node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	node_1_closing_signed.as_mut().unwrap().fee_range = None;

	nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed.unwrap());
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	assert!(node_0_none.is_none());
	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::CounterpartyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);
}

#[test]
fn simple_legacy_shutdown_test() {
	do_simple_legacy_shutdown_test(false);
	do_simple_legacy_shutdown_test(true);
}

#[test]
fn simple_target_feerate_shutdown() {
	// Simple test of target in `close_channel_with_target_feerate`.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_id = chan.2;

	nodes[0]
		.node
		.close_channel_with_feerate_and_script(&chan_id, &node_b_id, Some(253 * 10), None)
		.unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);
	nodes[1]
		.node
		.close_channel_with_feerate_and_script(&chan_id, &node_a_id, Some(253 * 5), None)
		.unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);

	nodes[1].node.handle_shutdown(node_a_id, &node_0_shutdown);
	nodes[0].node.handle_shutdown(node_b_id, &node_1_shutdown);

	let node_0_closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &node_0_closing_signed);
	let (_, node_1_closing_signed_opt) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	let node_1_closing_signed = node_1_closing_signed_opt.unwrap();

	// nodes[1] was passed a target which was larger than the current channel feerate, which it
	// should ignore in favor of the channel fee, as there is no use demanding a minimum higher
	// than what will be paid on a force-close transaction. Note that we have to consider rounding,
	// so only check that we're within 10 sats.
	assert!(
		node_0_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis
			>= node_1_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis * 10 - 5
	);
	assert!(
		node_0_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis
			<= node_1_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis * 10 + 5
	);

	// Further, because nodes[0]'s target fee is larger than the `Normal` fee estimation plus our
	// force-closure-avoidance buffer, min should equal max, and the nodes[1]-selected fee should
	// be the nodes[0] only available fee.
	assert_eq!(
		node_0_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis,
		node_0_closing_signed.fee_range.as_ref().unwrap().max_fee_satoshis
	);
	assert_eq!(
		node_0_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis,
		node_0_closing_signed.fee_satoshis
	);
	assert_eq!(node_0_closing_signed.fee_satoshis, node_1_closing_signed.fee_satoshis);

	nodes[0].node.handle_closing_signed(node_b_id, &node_1_closing_signed);
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	assert!(node_0_none.is_none());
	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);
}

fn do_outbound_update_no_early_closing_signed(use_htlc: bool) {
	// Previously, if we have a pending inbound HTLC (or fee update) on a channel which has
	// initiated shutdown, we'd send our initial closing_signed immediately after receiving the
	// peer's last RAA to remove the HTLC/fee update, but before receiving their final
	// commitment_signed for a commitment without the HTLC/with the new fee. This caused at least
	// LDK peers to force-close as we initiated closing_signed prior to the channel actually being
	// fully empty of pending updates/HTLCs.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	send_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let payment_hash_opt =
		if use_htlc { Some(route_payment(&nodes[1], &[&nodes[0]], 10_000).1) } else { None };

	if use_htlc {
		nodes[0].node.fail_htlc_backwards(&payment_hash_opt.unwrap());
		expect_and_process_pending_htlcs_and_htlc_handling_failed(
			&nodes[0],
			&[HTLCHandlingFailureType::Receive { payment_hash: payment_hash_opt.unwrap() }],
		);
	} else {
		*chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap() *= 10;
		nodes[0].node.timer_tick_occurred();
	}
	let updates = get_htlc_update_msgs(&nodes[0], &node_b_id);
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.close_channel(&chan_id, &node_a_id).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_a_id);
	nodes[0].node.close_channel(&chan_id, &node_b_id).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_b_id);

	nodes[0].node.handle_shutdown(node_b_id, &node_0_shutdown);
	nodes[1].node.handle_shutdown(node_a_id, &node_1_shutdown);

	if use_htlc {
		nodes[1].node.handle_update_fail_htlc(node_a_id, &updates.update_fail_htlcs[0]);
	} else {
		nodes[1].node.handle_update_fee(node_a_id, &updates.update_fee.unwrap());
	}
	nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &updates.commitment_signed);
	check_added_monitors(&nodes[1], 1);
	let (bs_raa, bs_cs) = get_revoke_commit_msgs(&nodes[1], &node_a_id);

	nodes[0].node.handle_revoke_and_ack(node_b_id, &bs_raa);
	check_added_monitors(&nodes[0], 1);

	// At this point the Channel on nodes[0] has no record of any HTLCs but the latest
	// broadcastable commitment does contain the HTLC (but only the ChannelMonitor knows this).
	// Thus, the channel should not yet initiate closing_signed negotiation (but previously did).
	assert_eq!(nodes[0].node.get_and_clear_pending_msg_events(), Vec::new());

	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &bs_cs);
	check_added_monitors(&nodes[0], 1);
	assert_eq!(nodes[0].node.get_and_clear_pending_msg_events(), Vec::new());

	expect_channel_shutdown_state!(nodes[0], chan_id, ChannelShutdownState::ResolvingHTLCs);
	assert_eq!(nodes[0].node.get_and_clear_pending_msg_events(), Vec::new());
	let (latest_update, _) = {
		let latest_monitor_update_id =
			nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap();
		latest_monitor_update_id.get(&chan_id).unwrap().clone()
	};
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(chan_id, latest_update);

	let as_raa_closing_signed = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_raa_closing_signed.len(), 2);

	if let MessageSendEvent::SendRevokeAndACK { msg, .. } = &as_raa_closing_signed[0] {
		nodes[1].node.handle_revoke_and_ack(node_a_id, &msg);
		check_added_monitors(&nodes[1], 1);
		if use_htlc {
			expect_payment_failed!(nodes[1], payment_hash_opt.unwrap(), true);
		}
	} else {
		panic!("Unexpected message {:?}", as_raa_closing_signed[0]);
	}

	if let MessageSendEvent::SendClosingSigned { msg, .. } = &as_raa_closing_signed[1] {
		nodes[1].node.handle_closing_signed(node_a_id, &msg);
	} else {
		panic!("Unexpected message {:?}", as_raa_closing_signed[1]);
	}

	let bs_closing_signed =
		get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, node_a_id);
	nodes[0].node.handle_closing_signed(node_b_id, &bs_closing_signed);
	let (_, as_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, node_b_id);
	nodes[1].node.handle_closing_signed(node_a_id, &as_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, node_a_id);
	assert!(node_1_none.is_none());

	let reason_a = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[0], 1, reason_a, &[node_b_id], 100000);
	let reason_b = ClosureReason::LocallyInitiatedCooperativeClosure;
	check_closed_event(&nodes[1], 1, reason_b, &[node_a_id], 100000);
}

#[test]
fn outbound_update_no_early_closing_signed() {
	do_outbound_update_no_early_closing_signed(true);
	do_outbound_update_no_early_closing_signed(false);
}

#[test]
fn batch_funding_failure() {
	// Provides test coverage of batch funding failure, which previously deadlocked
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let temp_chan_id_a = exchange_open_accept_chan(&nodes[0], &nodes[1], 1_000_000, 0);
	let temp_chan_id_b = exchange_open_accept_chan(&nodes[0], &nodes[2], 1_000_000, 0);

	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	// Build a transaction which only has the output for one of the two channels we're trying to
	// confirm. Previously this led to a deadlock in channel closure handling.
	let mut tx = Transaction {
		version: Version::TWO,
		lock_time: LockTime::ZERO,
		input: Vec::new(),
		output: Vec::new(),
	};
	let mut chans = Vec::new();
	for (idx, ev) in events.iter().enumerate() {
		if let Event::FundingGenerationReady {
			temporary_channel_id,
			counterparty_node_id,
			output_script,
			..
		} = ev
		{
			if idx == 0 {
				tx.output.push(TxOut {
					value: Amount::from_sat(1_000_000),
					script_pubkey: output_script.clone(),
				});
			}
			chans.push((temporary_channel_id, counterparty_node_id));
		} else {
			panic!();
		}
	}

	let err = "Error in transaction funding: Misuse error: No output matched the script_pubkey and value in the FundingGenerationReady event".to_string();
	let temp_err =
		"No output matched the script_pubkey and value in the FundingGenerationReady event"
			.to_string();
	let post_funding_chan_id_a = ChannelId::v1_from_funding_txid(tx.compute_txid().as_ref(), 0);
	let close = [
		ExpectedCloseEvent::from_id_reason(
			post_funding_chan_id_a,
			true,
			ClosureReason::ProcessingError { err: err.clone() },
		),
		ExpectedCloseEvent::from_id_reason(
			temp_chan_id_b,
			false,
			ClosureReason::ProcessingError { err: temp_err },
		),
	];

	nodes[0].node.batch_funding_transaction_generated(&chans, tx).unwrap_err();

	let msgs = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msgs.len(), 3);
	// We currently spuriously send `FundingCreated` for the first channel and then immediately
	// fail both channels, which isn't ideal but should be fine.
	assert!(msgs.iter().any(|msg| {
		if let MessageSendEvent::HandleError {
			action:
				msgs::ErrorAction::SendErrorMessage {
					msg: msgs::ErrorMessage { channel_id, .. }, ..
				},
			..
		} = msg
		{
			*channel_id == temp_chan_id_b
		} else {
			false
		}
	}));
	let funding_created_pos = msgs
		.iter()
		.position(|msg| {
			if let MessageSendEvent::SendFundingCreated {
				msg: msgs::FundingCreated { temporary_channel_id, .. },
				..
			} = msg
			{
				assert_eq!(*temporary_channel_id, temp_chan_id_a);
				true
			} else {
				false
			}
		})
		.unwrap();
	let funded_channel_close_pos = msgs
		.iter()
		.position(|msg| {
			if let MessageSendEvent::HandleError {
				action:
					msgs::ErrorAction::SendErrorMessage {
						msg: msgs::ErrorMessage { channel_id, .. },
						..
					},
				..
			} = msg
			{
				*channel_id == post_funding_chan_id_a
			} else {
				false
			}
		})
		.unwrap();

	// The error message uses the funded channel_id so must come after the funding_created
	assert!(funded_channel_close_pos > funding_created_pos);

	check_closed_events(&nodes[0], &close);
	assert_eq!(nodes[0].node.list_channels().len(), 0);
}

#[test]
fn test_force_closure_on_low_stale_fee() {
	// Check that we force-close channels if they have a low fee and that has gotten stale (without
	// update).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	// Start by connecting lots of blocks to give LDK some feerate history
	for _ in 0..super::channelmanager::FEERATE_TRACKING_BLOCKS * 2 {
		connect_blocks(&nodes[1], 1);
	}

	// Now connect a handful of blocks with a "high" feerate
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 2;
	}
	for _ in 0..super::channelmanager::FEERATE_TRACKING_BLOCKS - 1 {
		connect_blocks(&nodes[1], 1);
	}
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Now, note that one more block would cause us to force-close, it won't because we've dropped
	// the feerate
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock /= 2;
	}
	connect_blocks(&nodes[1], super::channelmanager::FEERATE_TRACKING_BLOCKS as u32 * 2);
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Now, connect another FEERATE_TRACKING_BLOCKS - 1 blocks at a high feerate, note that none of
	// these will cause a force-closure because LDK only looks at the minimium feerate over the
	// last FEERATE_TRACKING_BLOCKS blocks.
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 2;
	}

	for _ in 0..super::channelmanager::FEERATE_TRACKING_BLOCKS - 1 {
		connect_blocks(&nodes[1], 1);
	}
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Finally, connect one more block and check the force-close happened.
	connect_blocks(&nodes[1], 1);
	check_added_monitors(&nodes[1], 1);
	check_closed_broadcast(&nodes[1], 1, true);
	let reason = ClosureReason::PeerFeerateTooLow {
		peer_feerate_sat_per_kw: 253,
		required_feerate_sat_per_kw: 253 * 2,
	};
	check_closed_events(&nodes[1], &[ExpectedCloseEvent::from_id_reason(chan_id, false, reason)]);
}

#[test]
fn test_pending_htlcs_arent_lost_on_mon_delay() {
	// Test that HTLCs which were queued to be sent to peers but which never made it out due to a
	// pending, not-completed `ChannelMonitorUpdate` which got dropped with the `Channel`. This is
	// only possible when the `ChannelMonitorUpdate` is blocked, as otherwise it will be queued in
	// the `ChannelManager` and go out before any closure update.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);

	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();
	let node_c_id = nodes[2].node.get_our_node_id();

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let (_, _, chan_id_bc, ..) = create_announced_chan_between_nodes(&nodes, 1, 2);

	// First route a payment from node B to C, which will allow us to block `ChannelMonitorUpdate`s
	// by not processing the `PaymentSent` event upon claim.
	let (preimage_a, payment_hash_a, ..) = route_payment(&nodes[1], &[&nodes[2]], 500_000);

	nodes[2].node.claim_funds(preimage_a);
	check_added_monitors(&nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_a, 500_000);

	let mut claim = get_htlc_update_msgs(&nodes[2], &node_b_id);
	nodes[1].node.handle_update_fulfill_htlc(node_c_id, claim.update_fulfill_htlcs.pop().unwrap());

	// Now, while sitting on the `PaymentSent` event, move the B <-> C channel forward until B is
	// just waiting on C's last RAA.
	nodes[1].node.handle_commitment_signed_batch_test(node_c_id, &claim.commitment_signed);
	check_added_monitors(&nodes[1], 1);

	let (raa, cs) = get_revoke_commit_msgs(&nodes[1], &node_c_id);

	nodes[2].node.handle_revoke_and_ack(node_b_id, &raa);
	check_added_monitors(&nodes[2], 1);
	nodes[2].node.handle_commitment_signed_batch_test(node_b_id, &cs);
	check_added_monitors(&nodes[2], 1);

	let cs_last_raa = get_event_msg!(nodes[2], MessageSendEvent::SendRevokeAndACK, node_b_id);

	// Now, while still sitting on the `PaymentSent` event, send an HTLC which will be relayed the
	// moment `cs_last_raa` is received by B.
	let (route_b, payment_hash_b, _preimage, payment_secret_b) =
		get_route_and_payment_hash!(&nodes[0], nodes[2], 900_000);
	let onion = RecipientOnionFields::secret_only(payment_secret_b);
	let id = PaymentId(payment_hash_b.0);
	nodes[0].node.send_payment_with_route(route_b, payment_hash_b, onion, id).unwrap();
	check_added_monitors(&nodes[0], 1);
	let as_send = get_htlc_update_msgs(&nodes[0], &node_b_id);

	nodes[1].node.handle_update_add_htlc(node_a_id, &as_send.update_add_htlcs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &as_send.commitment_signed, false, false);

	// Place the HTLC in the B <-> C channel holding cell for release upon RAA and finally deliver
	// `cs_last_raa`. Because we're still waiting to handle the `PaymentSent` event, the
	// `ChannelMonitorUpdate` and update messages will be held.
	nodes[1].node.process_pending_htlc_forwards();
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors(&nodes[1], 0);

	nodes[1].node.handle_revoke_and_ack(node_c_id, &cs_last_raa);
	check_added_monitors(&nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now force-close the B <-> C channel, making sure that we (finally) see the `PaymentSent`, as
	// well as the channel closure and, importantly, the HTLC fail-back to A.
	let message = "".to_string();
	nodes[1].node.force_close_broadcasting_latest_txn(&chan_id_bc, &node_c_id, message).unwrap();
	check_closed_broadcast(&nodes[1], 1, true);
	check_added_monitors(&nodes[1], 1);

	let events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 3, "{events:?}");
	assert!(events.iter().any(|ev| {
		if let Event::PaymentSent { payment_preimage: ev_preimage, .. } = ev {
			assert_eq!(*ev_preimage, preimage_a);
			true
		} else {
			false
		}
	}));
	assert!(events.iter().any(|ev| matches!(ev, Event::ChannelClosed { .. })));
	assert!(events.iter().any(|ev| {
		if let Event::HTLCHandlingFailed { failure_type, failure_reason, .. } = ev {
			assert!(matches!(failure_type, HTLCHandlingFailureType::Forward { .. }));
			if let Some(HTLCHandlingFailureReason::Local { reason }) = failure_reason {
				assert_eq!(*reason, LocalHTLCFailureReason::ChannelClosed);
			} else {
				panic!("Unexpected failure reason {failure_reason:?}");
			}
			true
		} else {
			false
		}
	}));

	nodes[1].node.process_pending_htlc_forwards();
	check_added_monitors(&nodes[1], 1);

	let failures = get_htlc_update_msgs(&nodes[1], &node_a_id);
	nodes[0].node.handle_update_fail_htlc(node_b_id, &failures.update_fail_htlcs[0]);
	do_commitment_signed_dance(&nodes[0], &nodes[1], &failures.commitment_signed, false, false);
	expect_payment_failed!(nodes[0], payment_hash_b, false);
}
