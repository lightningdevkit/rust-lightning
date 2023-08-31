// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests of our shutdown and closing_signed negotiation logic.

use crate::sign::{EntropySource, SignerProvider};
use crate::chain::transaction::OutPoint;
use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider, ClosureReason};
use crate::ln::channelmanager::{self, PaymentSendFailure, PaymentId, RecipientOnionFields, ChannelShutdownState, ChannelDetails};
use crate::routing::router::{PaymentParameters, get_route, RouteParameters};
use crate::ln::msgs;
use crate::ln::msgs::{ChannelMessageHandler, ErrorAction};
use crate::ln::script::ShutdownScript;
use crate::util::test_utils;
use crate::util::test_utils::OnGetShutdownScriptpubkey;
use crate::util::errors::APIError;
use crate::util::config::UserConfig;
use crate::util::string::UntrustedString;

use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::network::constants::Network;
use bitcoin::util::address::WitnessVersion;

use regex;

use core::default::Default;
use std::convert::TryFrom;

use crate::ln::functional_test_utils::*;

#[test]
fn pre_funding_lock_shutdown_test() {
	// Test sending a shutdown prior to channel_ready after funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let tx = create_chan_between_nodes_with_value_init(&nodes[0], &nodes[1], 8000000, 0);
	mine_transaction(&nodes[0], &tx);
	mine_transaction(&nodes[1], &tx);

	nodes[0].node.close_channel(&OutPoint { txid: tx.txid(), index: 0 }.to_channel_id(), &nodes[1].node.get_our_node_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 8000000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 8000000);
}

#[test]
fn expect_channel_shutdown_state() {
	// Test sending a shutdown prior to channel_ready after funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NotShuttingDown);

	nodes[0].node.close_channel(&chan_1.2, &nodes[1].node.get_our_node_id()).unwrap();

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NotShuttingDown);

	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);

	// node1 goes into NegotiatingClosingFee since there are no HTLCs in flight, note that it
	// doesnt mean that node1 has sent/recved its closing signed message
	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);

	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn expect_channel_shutdown_state_with_htlc() {
	// Test sending a shutdown with outstanding updates pending.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let _chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage_0, payment_hash_0, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NotShuttingDown);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NotShuttingDown);

	nodes[0].node.close_channel(&chan_1.2, &nodes[1].node.get_our_node_id()).unwrap();

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NotShuttingDown);

	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::ResolvingHTLCs);

	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ResolvingHTLCs);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::ResolvingHTLCs);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Claim Funds on Node2
	nodes[2].node.claim_funds(payment_preimage_0);
	check_added_monitors!(nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_0, 100_000);

	// Fulfil HTLCs on node1 and node0
	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	// Still in "resolvingHTLCs" on chan1 after htlc removed on chan2
	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ResolvingHTLCs);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::ResolvingHTLCs);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);
	expect_payment_sent!(nodes[0], payment_preimage_0);

	// all htlcs removed, chan1 advances to NegotiatingClosingFee
	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);

	// ClosingSignNegotion process
	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);

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
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage, ..) = route_payment(&nodes[0], &[&nodes[1]], 100_000);

	nodes[0].node.close_channel(&chan.2, &nodes[1].node.get_our_node_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);

	// Generate an lnd-like error message and check that we respond by simply screaming louder to
	// see if LND will accept our protocol compliance.
	let err_msg = msgs::ErrorMessage { channel_id: chan.2, data: "link failed to shutdown".to_string() };
	nodes[0].node.handle_error(&nodes[1].node.get_our_node_id(), &err_msg);
	let node_a_responses = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(node_a_responses[0], MessageSendEvent::SendShutdown {
			node_id: nodes[1].node.get_our_node_id(),
			msg: node_0_shutdown,
		});
	if let MessageSendEvent::HandleError { action: msgs::ErrorAction::SendWarningMessage { .. }, .. }
		= node_a_responses[1] {} else { panic!(); }

	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	// Assume that LND will eventually respond to our Shutdown if we clear all the remaining HTLCs
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	// ClosingSignNegotion process
	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);

	// Shutdown basically removes the channelDetails, testing of shutdowncomplete state unnecessary
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn expect_channel_shutdown_state_with_force_closure() {
	// Test sending a shutdown prior to channel_ready after funding generation
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NotShuttingDown);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NotShuttingDown);

	nodes[1].node.force_close_broadcasting_latest_txn(&chan_1.2, &nodes[0].node.get_our_node_id()).unwrap();
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NotShuttingDown);
	assert!(nodes[1].node.list_channels().is_empty());

	let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(node_txn.len(), 1);
	check_spends!(node_txn[0], chan_1.3);
	mine_transaction(&nodes[0], &node_txn[0]);
	check_added_monitors!(nodes[0], 1);

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0], true);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::HolderForceClosed, [nodes[0].node.get_our_node_id()], 100000);
}

#[test]
fn updates_shutdown_wait() {
	// Test sending a shutdown with outstanding updates pending
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);
	let logger = test_utils::TestLogger::new();
	let scorer = test_utils::TestScorer::new();
	let keys_manager = test_utils::TestKeysInterface::new(&[0u8; 32], Network::Testnet);
	let random_seed_bytes = keys_manager.get_secure_random_bytes();

	let (payment_preimage_0, payment_hash_0, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	nodes[0].node.close_channel(&chan_1.2, &nodes[1].node.get_our_node_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	let (_, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[0]);

	let payment_params_1 = PaymentParameters::from_node_id(nodes[1].node.get_our_node_id(), TEST_FINAL_CLTV).with_bolt11_features(nodes[1].node.invoice_features()).unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params_1, 100_000);
	let route_1 = get_route(&nodes[0].node.get_our_node_id(), &route_params,
		&nodes[0].network_graph.read_only(), None, &logger, &scorer, &(), &random_seed_bytes).unwrap();
	let payment_params_2 = PaymentParameters::from_node_id(nodes[0].node.get_our_node_id(),
		TEST_FINAL_CLTV).with_bolt11_features(nodes[0].node.invoice_features()).unwrap();
	let route_params = RouteParameters::from_payment_params_and_value(payment_params_2, 100_000);
	let route_2 = get_route(&nodes[1].node.get_our_node_id(), &route_params,
		&nodes[1].network_graph.read_only(), None, &logger, &scorer, &(), &random_seed_bytes).unwrap();
	unwrap_send_err!(nodes[0].node.send_payment_with_route(&route_1, payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)
		), true, APIError::ChannelUnavailable {..}, {});
	unwrap_send_err!(nodes[1].node.send_payment_with_route(&route_2, payment_hash,
			RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)
		), true, APIError::ChannelUnavailable {..}, {});

	nodes[2].node.claim_funds(payment_preimage_0);
	check_added_monitors!(nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash_0, 100_000);

	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);
	expect_payment_sent!(nodes[0], payment_preimage_0);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[2].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[2], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn htlc_fail_async_shutdown() {
	// Test HTLCs fail if shutdown starts even if messages are delivered out-of-order
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (route, our_payment_hash, _, our_payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100000);
	nodes[0].node.send_payment_with_route(&route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	assert_eq!(updates.update_add_htlcs.len(), 1);
	assert!(updates.update_fulfill_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());

	nodes[1].node.close_channel(&chan_1.2, &nodes[0].node.get_our_node_id()).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &updates.commitment_signed);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	commitment_signed_dance!(nodes[1], nodes[0], (), false, true, false, false);

	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fulfill_htlcs.is_empty());
	assert_eq!(updates_2.update_fail_htlcs.len(), 1);
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);

	expect_payment_failed_with_update!(nodes[0], our_payment_hash, false, chan_2.0.contents.short_channel_id, true);

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let node_0_closing_signed = match msg_events[0] {
		MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 2, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id(), nodes[2].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[2], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
}

fn do_test_shutdown_rebroadcast(recv_count: u8) {
	// Test that shutdown/closing_signed is re-sent on reconnect with a variable number of
	// messages delivered prior to disconnect
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 100_000);

	nodes[1].node.close_channel(&chan_1.2, &nodes[0].node.get_our_node_id()).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	if recv_count > 0 {
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);
		let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		if recv_count > 1 {
			nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
		}
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let node_0_reestablish = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let node_1_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();

	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_reestablish);
	let node_1_2nd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	assert!(node_1_shutdown == node_1_2nd_shutdown);

	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_reestablish);
	let node_0_2nd_shutdown = if recv_count > 0 {
		let node_0_2nd_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_2nd_shutdown);
		node_0_2nd_shutdown
	} else {
		let node_0_chan_update = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
		assert_eq!(node_0_chan_update.contents.flags & 2, 0); // "disabled" flag must not be set as we just reconnected.
		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_2nd_shutdown);
		get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id())
	};
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_2nd_shutdown);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 100_000);

	let updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(updates.update_add_htlcs.is_empty());
	assert!(updates.update_fail_htlcs.is_empty());
	assert!(updates.update_fail_malformed_htlcs.is_empty());
	assert!(updates.update_fee.is_none());
	assert_eq!(updates.update_fulfill_htlcs.len(), 1);
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &updates.update_fulfill_htlcs[0]);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], Some(1000), false, false);
	check_added_monitors!(nodes[1], 1);
	let updates_2 = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	commitment_signed_dance!(nodes[1], nodes[2], updates.commitment_signed, false);

	assert!(updates_2.update_add_htlcs.is_empty());
	assert!(updates_2.update_fail_htlcs.is_empty());
	assert!(updates_2.update_fail_malformed_htlcs.is_empty());
	assert!(updates_2.update_fee.is_none());
	assert_eq!(updates_2.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &updates_2.update_fulfill_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], updates_2.commitment_signed, false, true);
	expect_payment_sent!(nodes[0], payment_preimage);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	if recv_count > 0 {
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
		let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
		let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		assert!(node_0_2nd_closing_signed.is_some());
	}

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let node_1_2nd_reestablish = get_chan_reestablish_msgs!(nodes[1], nodes[0]).pop().unwrap();
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	if recv_count == 0 {
		// If all closing_signeds weren't delivered we can just resume where we left off...
		let node_0_2nd_reestablish = get_chan_reestablish_msgs!(nodes[0], nodes[1]).pop().unwrap();

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_2nd_reestablish);
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

		nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &node_0_2nd_reestablish);
		let node_1_3rd_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
		assert!(node_1_3rd_shutdown == node_1_2nd_shutdown);

		nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_3rd_shutdown);
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_3rd_shutdown);

		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed);
		let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
		let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
		let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
		assert!(node_1_none.is_none());
		check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
	} else {
		// If one node, however, received + responded with an identical closing_signed we end
		// up erroring and node[0] will try to broadcast its own latest commitment transaction.
		// There isn't really anything better we can do simply, but in the future we might
		// explore storing a set of recently-closed channels that got disconnected during
		// closing_signed and avoiding broadcasting local commitment txn for some timeout to
		// give our counterparty enough time to (potentially) broadcast a cooperative closing
		// transaction.
		assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

		nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &node_1_2nd_reestablish);
		let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(msg_events.len(), 1);
		if let MessageSendEvent::HandleError { ref action, .. } = msg_events[0] {
			match action {
				&ErrorAction::SendErrorMessage { ref msg } => {
					nodes[1].node.handle_error(&nodes[0].node.get_our_node_id(), &msg);
					assert_eq!(msg.channel_id, chan_1.2);
				},
				_ => panic!("Unexpected event!"),
			}
		} else { panic!("Needed SendErrorMessage close"); }

		// get_closing_signed_broadcast usually eats the BroadcastChannelUpdate for us and
		// checks it, but in this case nodes[1] didn't ever get a chance to receive a
		// closing_signed so we do it ourselves
		check_closed_broadcast!(nodes[1], false);
		check_added_monitors!(nodes[1], 1);
		check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: UntrustedString(format!("Got a message for a channel from the wrong node! No such channel for the passed counterparty_node_id {}", &nodes[1].node.get_our_node_id())) }
			, [nodes[0].node.get_our_node_id()], 100000);
	}

	assert!(nodes[0].node.list_channels().is_empty());

	assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	close_channel(&nodes[1], &nodes[2], &chan_2.2, chan_2.3, true);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[2].node.list_channels().is_empty());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[2].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[2], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
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
	config.channel_handshake_config.announced_channel = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// We test that in case of peer committing upfront to a script, if it changes at closing, we refuse to sign
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000);
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[2].node.get_our_node_id()).unwrap();
	let node_0_orig_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());
	let mut node_0_shutdown = node_0_orig_shutdown.clone();
	node_0_shutdown.scriptpubkey = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script().to_p2sh();
	// Test we enforce upfront_scriptpbukey if by providing a different one at closing that we warn
	// the peer and ignore the message.
	nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	assert!(regex::Regex::new(r"Got shutdown request with a scriptpubkey \([A-Fa-f0-9]+\) which did not match their previous scriptpubkey.")
			.unwrap().is_match(&check_warn_msg!(nodes[2], nodes[0].node.get_our_node_id(), chan.2)));
	// This allows nodes[2] to retry the shutdown message, which should get a response:
	nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_orig_shutdown);
	get_event_msg!(nodes[2], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());

	// We test that in case of peer committing upfront to a script, if it doesn't change at closing, we sign
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 2, 1000000, 1000000);
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[2].node.get_our_node_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[2].node.get_our_node_id());
	// We test that in case of peer committing upfront to a script, if it oesn't change at closing, we sign
	nodes[2].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[0].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	// We test that if case of peer non-signaling we don't enforce committed script at channel opening
	*nodes[0].override_init_features.borrow_mut() = Some(nodes[0].node.init_features().clear_upfront_shutdown_script());
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);
	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[1].node.get_our_node_id()).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_1_shutdown);
	check_added_monitors!(nodes[1], 1);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[0].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	// channel smoothly, opt-out is from channel initiator here
	*nodes[0].override_init_features.borrow_mut() = None;
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 1, 0, 1000000, 1000000);
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id()).unwrap();
	check_added_monitors!(nodes[1], 1);
	let node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}

	//// We test that if user opt-out, we provide a zero-length script at channel opening and we are able to close
	//// channel smoothly
	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 1000000);
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id()).unwrap();
	check_added_monitors!(nodes[1], 1);
	let node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_0_shutdown);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_unsupported_anysegwit_upfront_shutdown_script() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	// Clear shutdown_anysegwit on initiator
	*node_cfgs[0].override_init_features.borrow_mut() = Some(channelmanager::provided_init_features(&test_default_channel_config()).clear_shutdown_anysegwit());
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Use a non-v0 segwit script supported by option_shutdown_anysegwit
	let anysegwit_shutdown_script = Builder::new()
		.push_int(16)
		.push_slice(&[0, 40])
		.into_script();

	// Check script when handling an open_channel message
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	open_channel.shutdown_scriptpubkey = Some(anysegwit_shutdown_script.clone());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: Script(OP_PUSHNUM_16 OP_PUSHBYTES_2 0028)");
		},
		_ => panic!("Unexpected event"),
	}

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	// Clear shutdown_anysegwit on responder
	*node_cfgs[1].override_init_features.borrow_mut() = Some(channelmanager::provided_init_features(&test_default_channel_config()).clear_shutdown_anysegwit());
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Check script when handling an accept_channel message
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);
	let mut accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	accept_channel.shutdown_scriptpubkey = Some(anysegwit_shutdown_script.clone());
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: Script(OP_PUSHNUM_16 OP_PUSHBYTES_2 0028)");
		},
		_ => panic!("Unexpected event"),
	}
	check_closed_event!(nodes[0], 1, ClosureReason::ProcessingError { err: "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: Script(OP_PUSHNUM_16 OP_PUSHBYTES_2 0028)".to_string() }
		, [nodes[1].node.get_our_node_id()], 100000);
}

#[test]
fn test_invalid_upfront_shutdown_script() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();

	// Use a segwit v0 script with an unsupported witness program
	let mut open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	open_channel.shutdown_scriptpubkey = Some(Builder::new().push_int(0)
		.push_slice(&[0, 0])
		.into_script());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id } => {
			assert_eq!(node_id, nodes[0].node.get_our_node_id());
			assert_eq!(msg.data, "Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: Script(OP_0 OP_PUSHBYTES_2 0000)");
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_segwit_v0_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_handshake_config.announced_channel = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id()).unwrap();
	check_added_monitors!(nodes[1], 1);

	// Use a segwit v0 script supported even without option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_int(0)
		.push_slice(&[0; 20])
		.into_script();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_0_shutdown);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_anysegwit_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_handshake_config.announced_channel = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id()).unwrap();
	check_added_monitors!(nodes[1], 1);

	// Use a non-v0 segwit script supported by option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_int(16)
		.push_slice(&[0, 0])
		.into_script();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_0_shutdown);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	match events[0] {
		MessageSendEvent::SendShutdown { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
	match events[1] {
		MessageSendEvent::SendClosingSigned { node_id, .. } => { assert_eq!(node_id, nodes[1].node.get_our_node_id()) }
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn test_unsupported_anysegwit_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_handshake_config.announced_channel = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let mut node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	*node_cfgs[0].override_init_features.borrow_mut() = Some(channelmanager::provided_init_features(&config).clear_shutdown_anysegwit());
	*node_cfgs[1].override_init_features.borrow_mut() = Some(channelmanager::provided_init_features(&config).clear_shutdown_anysegwit());
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Check that using an unsupported shutdown script fails and a supported one succeeds.
	let supported_shutdown_script = chanmon_cfgs[1].keys_manager.get_shutdown_scriptpubkey().unwrap();
	let unsupported_shutdown_script =
		ShutdownScript::new_witness_program(WitnessVersion::V16, &[0, 40]).unwrap();
	chanmon_cfgs[1].keys_manager
		.expect(OnGetShutdownScriptpubkey { returns: unsupported_shutdown_script.clone() })
		.expect(OnGetShutdownScriptpubkey { returns: supported_shutdown_script });

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	match nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id()) {
		Err(APIError::IncompatibleShutdownScript { script }) => {
			assert_eq!(script.into_inner(), unsupported_shutdown_script.clone().into_inner());
		},
		Err(e) => panic!("Unexpected error: {:?}", e),
		Ok(_) => panic!("Expected error"),
	}
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id()).unwrap();
	check_added_monitors!(nodes[1], 1);

	// Use a non-v0 segwit script unsupported without option_shutdown_anysegwit
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = unsupported_shutdown_script.into_inner();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_0_shutdown);

	assert_eq!(&check_warn_msg!(nodes[0], nodes[1].node.get_our_node_id(), chan.2),
			"Got a nonstandard scriptpubkey (60020028) from remote peer");
}

#[test]
fn test_invalid_shutdown_script() {
	let mut config = UserConfig::default();
	config.channel_handshake_config.announced_channel = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[1].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id()).unwrap();
	check_added_monitors!(nodes[1], 1);

	// Use a segwit v0 script with an unsupported witness program
	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	node_0_shutdown.scriptpubkey = Builder::new().push_int(0)
		.push_slice(&[0, 0])
		.into_script();
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_0_shutdown);

	assert_eq!(&check_warn_msg!(nodes[0], nodes[1].node.get_our_node_id(), chan.2),
			"Got a nonstandard scriptpubkey (00020000) from remote peer");
}

#[test]
fn test_user_shutdown_script() {
	let mut config = test_default_channel_config();
	config.channel_handshake_config.announced_channel = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	config.channel_handshake_config.commit_upfront_shutdown_pubkey = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Segwit v0 script of the form OP_0 <20-byte hash>
	let script = Builder::new().push_int(0)
		.push_slice(&[0; 20])
		.into_script();

	let shutdown_script = ShutdownScript::try_from(script.clone()).unwrap();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	nodes[1].node.close_channel_with_feerate_and_script(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id(), None, Some(shutdown_script)).unwrap();
	check_added_monitors!(nodes[1], 1);

	let mut node_0_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());

	assert_eq!(node_0_shutdown.scriptpubkey, script);
}

#[test]
fn test_already_set_user_shutdown_script() {
	let mut config = test_default_channel_config();
	config.channel_handshake_config.announced_channel = true;
	config.channel_handshake_limits.force_announced_channel_preference = false;
	let user_cfgs = [None, Some(config), None];
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &user_cfgs);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Segwit v0 script of the form OP_0 <20-byte hash>
	let script = Builder::new().push_int(0)
		.push_slice(&[0; 20])
		.into_script();

	let shutdown_script = ShutdownScript::try_from(script).unwrap();

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	let result = nodes[1].node.close_channel_with_feerate_and_script(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[0].node.get_our_node_id(), None, Some(shutdown_script));

	assert_eq!(result, Err(APIError::APIMisuseError { err: "Cannot override shutdown script for a channel with one already set".to_string() }));
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
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	send_payment(&nodes[0], &[&nodes[1]], 8_000_000);

	nodes[0].node.close_channel(&chan_id, &nodes[1].node.get_our_node_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	{
		// Now we set nodes[1] to require a relatively high feerate for closing. This should result
		// in it rejecting nodes[0]'s initial closing_signed, giving nodes[0] a chance to try
		// again.
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 10;
	}

	let mut node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	// nodes[0] should use a "reasonable" feerate, well under the 10 sat/vByte that nodes[1] thinks
	// is the current prevailing feerate.
	assert!(node_0_closing_signed.fee_satoshis <= 500);

	if timeout_step != TimeoutStep::AfterShutdown {
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
		assert!(check_warn_msg!(nodes[1], nodes[0].node.get_our_node_id(), chan_id)
			.starts_with("Unable to come to consensus about closing feerate"));

		// Now deliver a mutated closing_signed indicating a higher acceptable fee range, which
		// nodes[1] should happily accept and respond to.
		node_0_closing_signed.fee_range.as_mut().unwrap().max_fee_satoshis *= 10;
		{
			let mut node_0_per_peer_lock;
			let mut node_0_peer_state_lock;
			get_channel_ref!(nodes[0], nodes[1], node_0_per_peer_lock, node_0_peer_state_lock, chan_id).context_mut().closing_fee_limits.as_mut().unwrap().1 *= 10;
		}
		nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
		let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
		let node_0_2nd_closing_signed = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
		if timeout_step == TimeoutStep::NoTimeout {
			nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.1.unwrap());
			check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
		}
		check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
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
		assert!((txn[0].output[0].script_pubkey.is_v0_p2wpkh() &&
		         txn[0].output[1].script_pubkey.is_v0_p2wsh()) ||
		        (txn[0].output[1].script_pubkey.is_v0_p2wpkh() &&
		         txn[0].output[0].script_pubkey.is_v0_p2wsh()));
		check_closed_broadcast!(nodes[1], true);
		check_added_monitors!(nodes[1], 1);
		check_closed_event!(nodes[1], 1, ClosureReason::ProcessingError { err: "closing_signed negotiation failed to finish within two timer ticks".to_string() }
			, [nodes[0].node.get_our_node_id()], 100000);
	} else {
		assert!(txn[0].output[0].script_pubkey.is_v0_p2wpkh());
		assert!(txn[0].output[1].script_pubkey.is_v0_p2wpkh());

		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				assert_eq!(msg.contents.flags & 2, 2);
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

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);

	if high_initiator_fee {
		// If high_initiator_fee is set, set nodes[0]'s feerate significantly higher. This
		// shouldn't impact the flow at all given nodes[1] will happily accept the higher fee.
		let mut feerate_lock = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock *= 10;
	}

	nodes[0].node.close_channel(&OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id(), &nodes[1].node.get_our_node_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	let mut node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	node_0_closing_signed.fee_range = None;
	if high_initiator_fee {
		assert!(node_0_closing_signed.fee_satoshis > 500);
	} else {
		assert!(node_0_closing_signed.fee_satoshis < 500);
	}

	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let (_, mut node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	node_1_closing_signed.as_mut().unwrap().fee_range = None;

	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed.unwrap());
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	assert!(node_0_none.is_none());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
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

	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	let chan_id = OutPoint { txid: chan.3.txid(), index: 0 }.to_channel_id();

	nodes[0].node.close_channel_with_feerate_and_script(&chan_id, &nodes[1].node.get_our_node_id(), Some(253 * 10), None).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.close_channel_with_feerate_and_script(&chan_id, &nodes[0].node.get_our_node_id(), Some(253 * 5), None).unwrap();
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());

	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let (_, node_1_closing_signed_opt) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	let node_1_closing_signed = node_1_closing_signed_opt.unwrap();

	// nodes[1] was passed a target which was larger than the current channel feerate, which it
	// should ignore in favor of the channel fee, as there is no use demanding a minimum higher
	// than what will be paid on a force-close transaction. Note that we have to consider rounding,
	// so only check that we're within 10 sats.
	assert!(node_0_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis >=
	        node_1_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis * 10 - 5);
	assert!(node_0_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis <=
	        node_1_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis * 10 + 5);

	// Further, because nodes[0]'s target fee is larger than the `Normal` fee estimation plus our
	// force-closure-avoidance buffer, min should equal max, and the nodes[1]-selected fee should
	// be the nodes[0] only available fee.
	assert_eq!(node_0_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis,
	           node_0_closing_signed.fee_range.as_ref().unwrap().max_fee_satoshis);
	assert_eq!(node_0_closing_signed.fee_range.as_ref().unwrap().min_fee_satoshis,
	           node_0_closing_signed.fee_satoshis);
	assert_eq!(node_0_closing_signed.fee_satoshis, node_1_closing_signed.fee_satoshis);

	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_none) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	assert!(node_0_none.is_none());
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
}
