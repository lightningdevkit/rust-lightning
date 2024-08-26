// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests for asynchronous signing. These tests verify that the channel state machine behaves
//! properly with a signer implementation that asynchronously derives signatures.

use std::collections::HashSet;
use bitcoin::key::Secp256k1;
use bitcoin::{Transaction, TxOut, TxIn, Amount};
use bitcoin::locktime::absolute::LockTime;
use bitcoin::transaction::Version;

use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::events::bump_transaction::WalletSource;
use crate::events::{ClosureReason, Event, MessageSendEvent, MessageSendEventsProvider};
use crate::ln::chan_utils::ClosingTransaction;
use crate::ln::channel_state::{ChannelDetails, ChannelShutdownState};
use crate::ln::channelmanager::{PaymentId, RAACommitmentOrder, RecipientOnionFields};
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::{functional_test_utils::*, msgs};
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::SignerProvider;
use crate::util::test_channel_signer::SignerOp;
use crate::util::logger::Logger;

#[test]
fn test_async_commitment_signature_for_funding_created() {
	// Simulate acquiring the signature for `funding_created` asynchronously.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();

	// nodes[0] --- open_channel --> nodes[1]
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_msg);

	// nodes[0] <-- accept_channel --- nodes[1]
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	// nodes[0] --- funding_created --> nodes[1]
	//
	// But! Let's make node[0]'s signer be unavailable: we should *not* broadcast a funding_created
	// message...
	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);
	nodes[0].disable_channel_signer_op(&nodes[1].node.get_our_node_id(), &temporary_channel_id, SignerOp::SignCounterpartyCommitment);
	nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);

	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now re-enable the signer and simulate a retry. The temporary_channel_id won't work anymore so
	// we have to dig out the real channel ID.
	let chan_id = {
		let channels = nodes[0].node.list_channels();
		assert_eq!(channels.len(), 1, "expected one channel, not {}", channels.len());
		channels[0].channel_id
	};

	nodes[0].enable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	nodes[0].node.signer_unblocked(Some((nodes[1].node.get_our_node_id(), chan_id)));

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	check_added_monitors(&nodes[1], 1);
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	// nodes[0] <-- funding_signed --- nodes[1]
	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
}

#[test]
fn test_async_commitment_signature_for_funding_signed() {
	// Simulate acquiring the signature for `funding_signed` asynchronously.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();

	// nodes[0] --- open_channel --> nodes[1]
	let mut open_chan_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_chan_msg);

	// nodes[0] <-- accept_channel --- nodes[1]
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id()));

	// nodes[0] --- funding_created --> nodes[1]
	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);
	nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

	// Now let's make node[1]'s signer be unavailable while handling the `funding_created`. It should
	// *not* broadcast a `funding_signed`...
	nodes[1].disable_channel_signer_op(&nodes[0].node.get_our_node_id(), &temporary_channel_id, SignerOp::SignCounterpartyCommitment);
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	check_added_monitors(&nodes[1], 1);

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now re-enable the signer and simulate a retry. The temporary_channel_id won't work anymore so
	// we have to dig out the real channel ID.
	let chan_id = {
		let channels = nodes[0].node.list_channels();
		assert_eq!(channels.len(), 1, "expected one channel, not {}", channels.len());
		channels[0].channel_id
	};
	nodes[1].enable_channel_signer_op(&nodes[0].node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	nodes[1].node.signer_unblocked(Some((nodes[0].node.get_our_node_id(), chan_id)));

	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());

	// nodes[0] <-- funding_signed --- nodes[1]
	let funding_signed_msg = get_event_msg!(nodes[1], MessageSendEvent::SendFundingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed_msg);
	check_added_monitors(&nodes[0], 1);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
}

#[test]
fn test_async_commitment_signature_for_commitment_signed() {
	for i in 0..=8 {
		let enable_signer_op_order = vec![
			SignerOp::GetPerCommitmentPoint,
			SignerOp::ReleaseCommitmentSecret,
			SignerOp::SignCounterpartyCommitment,
		].into_iter().filter(|&op| i & (1 << op as u8) != 0).collect();
		do_test_async_commitment_signature_for_commitment_signed_revoke_and_ack(enable_signer_op_order);
	}
}

fn do_test_async_commitment_signature_for_commitment_signed_revoke_and_ack(enable_signer_op_order: Vec<SignerOp>) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Send a payment.
	let src = &nodes[0];
	let dst = &nodes[1];
	let (route, our_payment_hash, _our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(src, dst, 8000000);
	src.node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(src, 1);

	// Pass the payment along the route.
	let payment_event = {
		let mut events = src.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(payment_event.node_id, dst.node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	dst.node.handle_update_add_htlc(&src.node.get_our_node_id(), &payment_event.msgs[0]);

	// Mark dst's signer as unavailable and handle src's commitment_signed: while dst won't yet have a
	// `commitment_signed` of its own to offer, it should publish a `revoke_and_ack`.
	dst.disable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::GetPerCommitmentPoint);
	dst.disable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::ReleaseCommitmentSecret);
	dst.disable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	dst.node.handle_commitment_signed(&src.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors(dst, 1);

	let mut enabled_signer_ops = HashSet::new();
	log_trace!(dst.logger, "enable_signer_op_order={:?}", enable_signer_op_order);
	for op in enable_signer_op_order {
		enabled_signer_ops.insert(op);
		dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, op);
		dst.node.signer_unblocked(Some((src.node.get_our_node_id(), chan_id)));

		if enabled_signer_ops.contains(&SignerOp::GetPerCommitmentPoint) && enabled_signer_ops.contains(&SignerOp::ReleaseCommitmentSecret) {
			// We are just able to send revoke_and_ack
			if op == SignerOp::GetPerCommitmentPoint || op == SignerOp::ReleaseCommitmentSecret {
				get_event_msg!(dst, MessageSendEvent::SendRevokeAndACK, src.node.get_our_node_id());
			}
			// We either just sent or previously sent revoke_and_ack
			// and now we are able to send commitment_signed
			if op == SignerOp::SignCounterpartyCommitment {
				get_htlc_update_msgs(dst, &src.node.get_our_node_id());
			}
		} else {
			// We can't send either message until RAA is unblocked
			let events = dst.node.get_and_clear_pending_msg_events();
			assert!(events.is_empty(), "expected no message, got {}", events.len());
		}
	}
}

#[test]
fn test_async_commitment_signature_for_funding_signed_0conf() {
	// Simulate acquiring the signature for `funding_signed` asynchronously for a zero-conf channel.
	let mut manually_accept_config = test_default_channel_config();
	manually_accept_config.manually_accept_inbound_channels = true;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(manually_accept_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// nodes[0] --- open_channel --> nodes[1]
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None, None).unwrap();
	let open_channel = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannel, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_open_channel(&nodes[0].node.get_our_node_id(), &open_channel);

	{
		let events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1, "Expected one event, got {}", events.len());
		match &events[0] {
			Event::OpenChannelRequest { temporary_channel_id, .. } => {
				nodes[1].node.accept_inbound_channel_from_trusted_peer_0conf(
					temporary_channel_id, &nodes[0].node.get_our_node_id(), 0)
					.expect("Unable to accept inbound zero-conf channel");
			},
			ev => panic!("Expected OpenChannelRequest, not {:?}", ev)
		}
	}

	// nodes[0] <-- accept_channel --- nodes[1]
	let accept_channel = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannel, nodes[0].node.get_our_node_id());
	assert_eq!(accept_channel.common_fields.minimum_depth, 0, "Expected minimum depth of 0");
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

	// nodes[0] --- funding_created --> nodes[1]
	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);
	nodes[0].node.funding_transaction_generated(temporary_channel_id, nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

	// Now let's make node[1]'s signer be unavailable while handling the `funding_created`. It should
	// *not* broadcast a `funding_signed`...
	nodes[1].disable_channel_signer_op(&nodes[0].node.get_our_node_id(), &temporary_channel_id, SignerOp::SignCounterpartyCommitment);
	nodes[1].node.handle_funding_created(&nodes[0].node.get_our_node_id(), &funding_created_msg);
	check_added_monitors(&nodes[1], 1);

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Now re-enable the signer and simulate a retry. The temporary_channel_id won't work anymore so
	// we have to dig out the real channel ID.
	let chan_id = {
		let channels = nodes[0].node.list_channels();
		assert_eq!(channels.len(), 1, "expected one channel, not {}", channels.len());
		channels[0].channel_id
	};

	// At this point, we basically expect the channel to open like a normal zero-conf channel.
	nodes[1].enable_channel_signer_op(&nodes[0].node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	nodes[1].node.signer_unblocked(Some((nodes[0].node.get_our_node_id(), chan_id)));

	let (funding_signed, channel_ready_1) = {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
		let funding_signed = match &events[0] {
			MessageSendEvent::SendFundingSigned { msg, .. } => msg.clone(),
			ev => panic!("Expected SendFundingSigned, not {:?}", ev)
		};
		let channel_ready = match &events[1] {
			MessageSendEvent::SendChannelReady { msg, .. } => msg.clone(),
			ev => panic!("Expected SendChannelReady, not {:?}", ev)
		};
		(funding_signed, channel_ready)
	};

	nodes[0].node.handle_funding_signed(&nodes[1].node.get_our_node_id(), &funding_signed);
	expect_channel_pending_event(&nodes[0], &nodes[1].node.get_our_node_id());
	expect_channel_pending_event(&nodes[1], &nodes[0].node.get_our_node_id());
	check_added_monitors(&nodes[0], 1);

	let channel_ready_0 = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReady, nodes[1].node.get_our_node_id());

	nodes[0].node.handle_channel_ready(&nodes[1].node.get_our_node_id(), &channel_ready_1);
	expect_channel_ready_event(&nodes[0], &nodes[1].node.get_our_node_id());

	nodes[1].node.handle_channel_ready(&nodes[0].node.get_our_node_id(), &channel_ready_0);
	expect_channel_ready_event(&nodes[1], &nodes[0].node.get_our_node_id());

	let channel_update_0 = get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, nodes[1].node.get_our_node_id());
	let channel_update_1 = get_event_msg!(nodes[1], MessageSendEvent::SendChannelUpdate, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_channel_update(&nodes[1].node.get_our_node_id(), &channel_update_1);
	nodes[1].node.handle_channel_update(&nodes[0].node.get_our_node_id(), &channel_update_0);

	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);
	assert_eq!(nodes[1].node.list_usable_channels().len(), 1);
}

#[derive(PartialEq)]
enum UnblockSignerAcrossDisconnectCase {
	AtEnd,
	BeforeMonitorRestored,
	BeforeReestablish,
}

#[test]
fn test_async_raa_peer_disconnect() {
	do_test_async_raa_peer_disconnect(UnblockSignerAcrossDisconnectCase::AtEnd, true);
	do_test_async_raa_peer_disconnect(UnblockSignerAcrossDisconnectCase::AtEnd, false);
	do_test_async_raa_peer_disconnect(UnblockSignerAcrossDisconnectCase::BeforeMonitorRestored, true);
	do_test_async_raa_peer_disconnect(UnblockSignerAcrossDisconnectCase::BeforeMonitorRestored, false);
	do_test_async_raa_peer_disconnect(UnblockSignerAcrossDisconnectCase::BeforeReestablish, true);
	do_test_async_raa_peer_disconnect(UnblockSignerAcrossDisconnectCase::BeforeReestablish, false);
}

fn do_test_async_raa_peer_disconnect(test_case: UnblockSignerAcrossDisconnectCase, raa_blocked_by_commit_point: bool) {
	// `raa_blocked_by_commit_point` determines whether we block the RAA by blocking the
	// signer on `GetPerCommitmentPoint` or `ReleaseCommitmentSecret`.
	let block_raa_signer_op = if raa_blocked_by_commit_point {
		SignerOp::GetPerCommitmentPoint
	} else {
		SignerOp::ReleaseCommitmentSecret
	};
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Send a payment.
	let src = &nodes[0];
	let dst = &nodes[1];
	let (route, our_payment_hash, _our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(src, dst, 8000000);
	src.node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(src, 1);

	// Pass the payment along the route.
	let payment_event = {
		let mut events = src.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(payment_event.node_id, dst.node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	dst.node.handle_update_add_htlc(&src.node.get_our_node_id(), &payment_event.msgs[0]);

	if test_case == UnblockSignerAcrossDisconnectCase::BeforeMonitorRestored {
		// Fail to persist the monitor update when handling the commitment_signed.
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	}

	// Mark dst's signer as unavailable and handle src's commitment_signed: while dst won't yet have a
	// `commitment_signed` of its own to offer, it should publish a `revoke_and_ack`.
	dst.disable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, block_raa_signer_op);
	dst.node.handle_commitment_signed(&src.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors(dst, 1);

	let events = dst.node.get_and_clear_pending_msg_events();
	assert!(events.is_empty(), "expected no message, got {}", events.len());

	// Now disconnect and reconnect the peers.
	src.node.peer_disconnected(&dst.node.get_our_node_id());
	dst.node.peer_disconnected(&src.node.get_our_node_id());

	// do reestablish stuff
	src.node.peer_connected(&dst.node.get_our_node_id(), &msgs::Init {
		features: dst.node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(src, dst);
	assert_eq!(reestablish_1.len(), 1);
	dst.node.peer_connected(&src.node.get_our_node_id(), &msgs::Init {
		features: src.node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(dst, src);
	assert_eq!(reestablish_2.len(), 1);

	if test_case == UnblockSignerAcrossDisconnectCase::BeforeReestablish {
		// Reenable the signer before the reestablish.
		dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, block_raa_signer_op);
	}

	dst.node.handle_channel_reestablish(&src.node.get_our_node_id(), &reestablish_1[0]);

	if test_case == UnblockSignerAcrossDisconnectCase::BeforeMonitorRestored {
		dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, block_raa_signer_op);
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
		let (outpoint, latest_update, _) = dst.chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_id).unwrap().clone();
		dst.chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
		check_added_monitors!(dst, 0);
	}

	// Expect the RAA
	let (_, revoke_and_ack, commitment_signed, resend_order) = handle_chan_reestablish_msgs!(dst, src);
	if test_case == UnblockSignerAcrossDisconnectCase::AtEnd {
		assert!(revoke_and_ack.is_none());
		assert!(commitment_signed.is_none());
	} else {
		assert!(revoke_and_ack.is_some());
		assert!(commitment_signed.is_some());
		assert!(resend_order == RAACommitmentOrder::RevokeAndACKFirst);
	}

	// Mark dst's signer as available and retry: we now expect to see dst's RAA + CS.
	dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, block_raa_signer_op);
	dst.node.signer_unblocked(Some((src.node.get_our_node_id(), chan_id)));

	if test_case == UnblockSignerAcrossDisconnectCase::AtEnd {
		let (_, revoke_and_ack, commitment_signed, resend_order) = handle_chan_reestablish_msgs!(dst, src);
		assert!(revoke_and_ack.is_some());
		assert!(commitment_signed.is_some());
		assert!(resend_order == RAACommitmentOrder::RevokeAndACKFirst);
	} else {
		// Make sure we don't double send the RAA.
		let (_, revoke_and_ack, commitment_signed, _) = handle_chan_reestablish_msgs!(dst, src);
		assert!(revoke_and_ack.is_none());
		assert!(commitment_signed.is_none());
	}
}


#[test]
fn test_async_commitment_signature_peer_disconnect() {
	// This tests that if our signer is blocked and gets unblocked
	// after a peer disconnect + channel reestablish, we'll send the right messages.
	do_test_async_commitment_signature_peer_disconnect(UnblockSignerAcrossDisconnectCase::AtEnd);
}

#[test]
fn test_async_commitment_signature_peer_disconnect_signer_restored_before_monitor_completion() {
	// This tests that if we were pending a monitor update completion across a disconnect,
	// and needed to send a CS, that if our signer becomes available before the monitor
	// update completes, then we don't send duplicate messages upon calling `signer_unblocked`
	// after the monitor update completes.
	do_test_async_commitment_signature_peer_disconnect(UnblockSignerAcrossDisconnectCase::BeforeMonitorRestored);
}

#[test]
fn test_async_commitment_signature_peer_disconnect_signer_restored_before_reestablish() {
	// This tests that if we tried to send a commitment_signed, but our signer was blocked,
	// if we disconnect, reconnect, the signer becomes available, then handle channel_reestablish,
	// that we don't send duplicate messages upon calling `signer_unblocked`.
	do_test_async_commitment_signature_peer_disconnect(UnblockSignerAcrossDisconnectCase::BeforeReestablish);
}

fn do_test_async_commitment_signature_peer_disconnect(test_case: UnblockSignerAcrossDisconnectCase) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Send a payment.
	let src = &nodes[0];
	let dst = &nodes[1];
	let (route, our_payment_hash, _our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(src, dst, 8000000);
	src.node.send_payment_with_route(route, our_payment_hash,
		RecipientOnionFields::secret_only(our_payment_secret), PaymentId(our_payment_hash.0)).unwrap();
	check_added_monitors!(src, 1);

	// Pass the payment along the route.
	let payment_event = {
		let mut events = src.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	assert_eq!(payment_event.node_id, dst.node.get_our_node_id());
	assert_eq!(payment_event.msgs.len(), 1);

	dst.node.handle_update_add_htlc(&src.node.get_our_node_id(), &payment_event.msgs[0]);

	if test_case == UnblockSignerAcrossDisconnectCase::BeforeMonitorRestored {
		// Fail to persist the monitor update when handling the commitment_signed.
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	}

	// Mark dst's signer as unavailable and handle src's commitment_signed: while dst won't yet have a
	// `commitment_signed` of its own to offer, it should publish a `revoke_and_ack`.
	dst.disable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	dst.node.handle_commitment_signed(&src.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors(dst, 1);

	if test_case != UnblockSignerAcrossDisconnectCase::BeforeMonitorRestored {
		get_event_msg!(dst, MessageSendEvent::SendRevokeAndACK, src.node.get_our_node_id());
	}

	// Now disconnect and reconnect the peers.
	src.node.peer_disconnected(&dst.node.get_our_node_id());
	dst.node.peer_disconnected(&src.node.get_our_node_id());

	// do reestablish stuff
	src.node.peer_connected(&dst.node.get_our_node_id(), &msgs::Init {
		features: dst.node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(src, dst);
	assert_eq!(reestablish_1.len(), 1);
	dst.node.peer_connected(&src.node.get_our_node_id(), &msgs::Init {
		features: src.node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(dst, src);
	assert_eq!(reestablish_2.len(), 1);

	if test_case == UnblockSignerAcrossDisconnectCase::BeforeReestablish {
		// Reenable the signer before the reestablish.
		dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	}

	dst.node.handle_channel_reestablish(&src.node.get_our_node_id(), &reestablish_1[0]);

	if test_case == UnblockSignerAcrossDisconnectCase::BeforeMonitorRestored {
		dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
		chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
		let (outpoint, latest_update, _) = dst.chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_id).unwrap().clone();
		dst.chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
		check_added_monitors!(dst, 0);
	}

	// Expect the RAA
	let (_, revoke_and_ack, commitment_signed, _) = handle_chan_reestablish_msgs!(dst, src);
	assert!(revoke_and_ack.is_some());
	if test_case == UnblockSignerAcrossDisconnectCase::AtEnd {
		assert!(commitment_signed.is_none());
	} else {
		assert!(commitment_signed.is_some());
	}

	// Mark dst's signer as available and retry: we now expect to see dst's `commitment_signed`.
	dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	dst.node.signer_unblocked(Some((src.node.get_our_node_id(), chan_id)));

	if test_case == UnblockSignerAcrossDisconnectCase::AtEnd {
		let (_, _, commitment_signed, _) = handle_chan_reestablish_msgs!(dst, src);
		assert!(commitment_signed.is_some());
	} else {
		// Make sure we don't double send the CS.
		let (_, _, commitment_signed, _) = handle_chan_reestablish_msgs!(dst, src);
		assert!(commitment_signed.is_none());
	}
}

#[test]
fn test_async_commitment_signature_ordering_reestablish() {
	do_test_async_commitment_signature_ordering(false);
}

#[test]
fn test_async_commitment_signature_ordering_monitor_restored() {
	do_test_async_commitment_signature_ordering(true);
}

fn do_test_async_commitment_signature_ordering(monitor_update_failure: bool) {
	// Across disconnects we may end up in a situation where we need to send a
	// commitment_signed and then revoke_and_ack. We need to make sure that if
	// the signer is pending for commitment_signed but not revoke_and_ack, we don't
	// screw up the order by sending the revoke_and_ack first.
	//
	// We test this for both the case where we send messages after a channel
	// reestablish, as well as restoring a channel after persisting
	// a monitor update.
	//
	// The set up for this test is based on
	// `test_drop_messages_peer_disconnect_dual_htlc`.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	let (payment_preimage_1, payment_hash_1, ..) = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	// Start to send the second update_add_htlc + commitment_signed, but don't actually make it
	// to the peer.
	let (route, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], 1000000);
	nodes[0].node.send_payment_with_route(route, payment_hash_2,
		RecipientOnionFields::secret_only(payment_secret_2), PaymentId(payment_hash_2.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	get_htlc_update_msgs(&nodes[0], &nodes[1].node.get_our_node_id());

	// Send back update_fulfill_htlc + commitment_signed for the first payment.
	nodes[1].node.claim_funds(payment_preimage_1);
	expect_payment_claimed!(nodes[1], payment_hash_1, 1_000_000);
	check_added_monitors!(nodes[1], 1);

	// Handle the update_fulfill_htlc, but fail to persist the monitor update when handling the
	// commitment_signed.
	let events_2 = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		MessageSendEvent::UpdateHTLCs { node_id: _, updates: msgs::CommitmentUpdate { ref update_fulfill_htlcs, ref commitment_signed, .. } } => {
			nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &update_fulfill_htlcs[0]);
			expect_payment_sent(&nodes[0], payment_preimage_1, None, false, false);
			if monitor_update_failure {
				chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
			}
			nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), commitment_signed);
			if monitor_update_failure {
				assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
			} else {
				let _ = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
			}
			// No commitment_signed so get_event_msg's assert(len == 1) passes
			check_added_monitors!(nodes[0], 1);
		},
		_ => panic!("Unexpected event"),
	}

	// Disconnect and reconnect the peers so that nodes[0] will
	// need to re-send the commitment update *and then* revoke_and_ack.
	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id());
	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id());

	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init {
		features: nodes[1].node.init_features(), networks: None, remote_network_address: None
	}, true).unwrap();
	let reestablish_1 = get_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert_eq!(reestablish_1.len(), 1);
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init {
		features: nodes[0].node.init_features(), networks: None, remote_network_address: None
	}, false).unwrap();
	let reestablish_2 = get_chan_reestablish_msgs!(nodes[1], nodes[0]);
	assert_eq!(reestablish_2.len(), 1);

	// With a fully working signer, here we would send a commitment_signed,
	// and then revoke_and_ack. With commitment_signed disabled, since
	// our ordering is CS then RAA, we should make sure we don't send the RAA.
	nodes[0].disable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &reestablish_2[0]);
	let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert!(as_resp.0.is_none());
	assert!(as_resp.1.is_none());
	assert!(as_resp.2.is_none());

	if monitor_update_failure {
		chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
		let (outpoint, latest_update, _) = nodes[0].chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_id).unwrap().clone();
		nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(outpoint, latest_update);
		check_added_monitors!(nodes[0], 0);
	}

	// Make sure that on signer_unblocked we have the same behavior (even though RAA is ready,
	// we don't send CS yet).
	nodes[0].node.signer_unblocked(Some((nodes[1].node.get_our_node_id(), chan_id)));
	let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	assert!(as_resp.0.is_none());
	assert!(as_resp.1.is_none());
	assert!(as_resp.2.is_none());

	nodes[0].enable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	nodes[0].node.signer_unblocked(Some((nodes[1].node.get_our_node_id(), chan_id)));

	let as_resp = handle_chan_reestablish_msgs!(nodes[0], nodes[1]);
	nodes[1].node.handle_channel_reestablish(&nodes[0].node.get_our_node_id(), &reestablish_1[0]);
	let bs_resp = handle_chan_reestablish_msgs!(nodes[1], nodes[0]);

	assert!(as_resp.0.is_none());
	assert!(bs_resp.0.is_none());

	assert!(bs_resp.1.is_none());
	assert!(bs_resp.2.is_none());

	assert!(as_resp.3 == RAACommitmentOrder::CommitmentFirst);

	// Now that everything is restored, get the CS + RAA and handle them.
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_resp.2.as_ref().unwrap().commitment_signed);
	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), as_resp.1.as_ref().unwrap());
	let (bs_revoke_and_ack, bs_second_commitment_signed) = get_revoke_commit_msgs(&nodes[1], &nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 2);

	// The rest of this is boilerplate for resolving the previous state.

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_revoke_and_ack);
	let as_commitment_signed = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	check_added_monitors!(nodes[0], 1);

	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bs_second_commitment_signed);
	let as_revoke_and_ack = get_event_msg!(nodes[0], MessageSendEvent::SendRevokeAndACK, nodes[1].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[0], 1);

	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_commitment_signed.commitment_signed);
	let bs_second_revoke_and_ack = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
	// No commitment_signed so get_event_msg's assert(len == 1) passes
	check_added_monitors!(nodes[1], 1);

	nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_revoke_and_ack);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);

	nodes[0].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bs_second_revoke_and_ack);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[0], 1);

	expect_pending_htlcs_forwardable!(nodes[1]);

	let events_5 = nodes[1].node.get_and_clear_pending_events();
	check_payment_claimable(&events_5[0], payment_hash_2, payment_secret_2, 1_000_000, None, nodes[1].node.get_our_node_id());

	expect_payment_path_successful!(nodes[0]);
	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage_2);
}

fn do_test_async_holder_signatures(anchors: bool, remote_commitment: bool) {
	// Ensures that we can obtain holder signatures for commitment and HTLC transactions
	// asynchronously by allowing their retrieval to fail and retrying via
	// `ChannelMonitor::signer_unblocked`.
	let mut config = test_default_channel_config();
	if anchors {
		config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
		config.manually_accept_inbound_channels = true;
	}

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let closing_node = if remote_commitment { &nodes[1] } else { &nodes[0] };
	let coinbase_tx = Transaction {
		version: Version::TWO,
		lock_time: LockTime::ZERO,
		input: vec![TxIn { ..Default::default() }],
		output: vec![
			TxOut {
				value: Amount::ONE_BTC,
				script_pubkey: closing_node.wallet_source.get_change_script().unwrap(),
			},
		],
	};
	if anchors {
		*nodes[0].fee_estimator.sat_per_kw.lock().unwrap() *= 2;
		*nodes[1].fee_estimator.sat_per_kw.lock().unwrap() *= 2;
		closing_node.wallet_source.add_utxo(bitcoin::OutPoint { txid: coinbase_tx.compute_txid(), vout: 0 }, coinbase_tx.output[0].value);
	}

	// Route an HTLC and set the signer as unavailable.
	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1);
	route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let error_message = "Channel force-closed";


	if remote_commitment {
		// Make the counterparty broadcast its latest commitment.
		nodes[1].node.force_close_broadcasting_latest_txn(&chan_id, &nodes[0].node.get_our_node_id(), error_message.to_string()).unwrap();
		check_added_monitors(&nodes[1], 1);
		check_closed_broadcast(&nodes[1], 1, true);
		check_closed_event(&nodes[1], 1, ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true) }, false, &[nodes[0].node.get_our_node_id()], 100_000);
	} else {
		nodes[0].disable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignHolderCommitment);
		nodes[0].disable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignHolderHtlcTransaction);
		// We'll connect blocks until the sender has to go onchain to time out the HTLC.
		connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);

		// No transaction should be broadcast since the signer is not available yet.
		assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
		assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

		// Mark it as available now, we should see the signed commitment transaction.
		nodes[0].enable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignHolderCommitment);
		nodes[0].enable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignHolderHtlcTransaction);
		get_monitor!(nodes[0], chan_id).signer_unblocked(nodes[0].tx_broadcaster, nodes[0].fee_estimator, &nodes[0].logger);
	}

	let commitment_tx = {
		let mut txn = closing_node.tx_broadcaster.txn_broadcast();
		if anchors || remote_commitment {
			assert_eq!(txn.len(), 1);
			check_spends!(txn[0], funding_tx);
			txn.remove(0)
		} else {
			assert_eq!(txn.len(), 2);
			if txn[0].input[0].previous_output.txid == funding_tx.compute_txid() {
				check_spends!(txn[0], funding_tx);
				check_spends!(txn[1], txn[0]);
				txn.remove(0)
			} else {
				check_spends!(txn[1], funding_tx);
				check_spends!(txn[0], txn[1]);
				txn.remove(1)
			}
		}
	};

	// Mark it as unavailable again to now test the HTLC transaction. We'll mine the commitment such
	// that the HTLC transaction is retried.
	let sign_htlc_op = if remote_commitment {
		SignerOp::SignCounterpartyHtlcTransaction
	} else {
		SignerOp::SignHolderHtlcTransaction
	};
	nodes[0].disable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignHolderCommitment);
	nodes[0].disable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, sign_htlc_op);
	mine_transaction(&nodes[0], &commitment_tx);

	check_added_monitors(&nodes[0], 1);
	check_closed_broadcast(&nodes[0], 1, true);
	check_closed_event(&nodes[0], 1, ClosureReason::CommitmentTxConfirmed, false, &[nodes[1].node.get_our_node_id()], 100_000);

	// If the counterparty broadcast its latest commitment, we need to mine enough blocks for the
	// HTLC timeout.
	if remote_commitment {
		connect_blocks(&nodes[0], TEST_FINAL_CLTV);
	}

	// No HTLC transaction should be broadcast as the signer is not available yet.
	if anchors && !remote_commitment {
		handle_bump_htlc_event(&nodes[0], 1);
	}
	let txn = nodes[0].tx_broadcaster.txn_broadcast();
	assert!(txn.is_empty(), "expected no transaction to be broadcast, got {:?}", txn);

	// Mark it as available now, we should see the signed HTLC transaction.
	nodes[0].enable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, SignerOp::SignHolderCommitment);
	nodes[0].enable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_id, sign_htlc_op);
	get_monitor!(nodes[0], chan_id).signer_unblocked(nodes[0].tx_broadcaster, nodes[0].fee_estimator, &nodes[0].logger);

	if anchors && !remote_commitment {
		handle_bump_htlc_event(&nodes[0], 1);
	}
	{
		let txn = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		check_spends!(txn[0], commitment_tx, coinbase_tx);
	}
}

#[test]
fn test_async_holder_signatures_no_anchors() {
	do_test_async_holder_signatures(false, false);
}

#[test]
fn test_async_holder_signatures_remote_commitment_no_anchors() {
	do_test_async_holder_signatures(false, true);
}

#[test]
fn test_async_holder_signatures_anchors() {
	do_test_async_holder_signatures(true, false);
}

#[test]
fn test_async_holder_signatures_remote_commitment_anchors() {
	do_test_async_holder_signatures(true, true);
}

#[test]
fn test_closing_signed() {
	do_test_closing_signed(false);
	do_test_closing_signed(true);
}

fn do_test_closing_signed(extra_closing_signed: bool) {
	// Based off of `expect_channel_shutdown_state`.
	// Test that we can asynchronously sign closing transactions.
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

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::ShutdownInitiated);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);

	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].disable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_1.2, SignerOp::SignClosingTransaction);
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	expect_channel_shutdown_state!(nodes[0], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);
	expect_channel_shutdown_state!(nodes[1], chan_1.2, ChannelShutdownState::NegotiatingClosingFee);

	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert!(events.is_empty(), "Expected no events, got {:?}", events);
	nodes[0].enable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_1.2, SignerOp::SignClosingTransaction);
	nodes[0].node.signer_unblocked(None);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].disable_channel_signer_op(&nodes[0].node.get_our_node_id(), &chan_1.2, SignerOp::SignClosingTransaction);
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert!(events.is_empty(), "Expected no events, got {:?}", events);
	nodes[1].enable_channel_signer_op(&nodes[0].node.get_our_node_id(), &chan_1.2, SignerOp::SignClosingTransaction);
	nodes[1].node.signer_unblocked(None);

	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());

	nodes[0].disable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_1.2, SignerOp::SignClosingTransaction);
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let events = nodes[0].node.get_and_clear_pending_msg_events();
	assert!(events.is_empty(), "Expected no events, got {:?}", events);
	nodes[0].enable_channel_signer_op(&nodes[1].node.get_our_node_id(), &chan_1.2, SignerOp::SignClosingTransaction);

	if extra_closing_signed {
		let node_1_closing_signed_2_bad = {
			let mut node_1_closing_signed_2 = node_1_closing_signed.clone();
			let holder_script = nodes[0].keys_manager.get_shutdown_scriptpubkey().unwrap();
			let counterparty_script = nodes[1].keys_manager.get_shutdown_scriptpubkey().unwrap();
			let funding_outpoint = bitcoin::OutPoint { txid: chan_1.3.txid(), vout: 0 };
			let closing_tx_2 = ClosingTransaction::new(50000, 0, holder_script.into(),
				counterparty_script.into(), funding_outpoint);

			let per_peer_state = nodes[1].node.per_peer_state.read().unwrap();
			let mut chan_lock = per_peer_state.get(&nodes[0].node.get_our_node_id()).unwrap().lock().unwrap();
			let chan = chan_lock.channel_by_id.get_mut(&chan_1.2).map(|phase| phase.context_mut()).unwrap();

			let signer = chan.get_mut_signer().as_mut_ecdsa().unwrap();
			let signature = signer.sign_closing_transaction(&closing_tx_2, &Secp256k1::new()).unwrap();
			node_1_closing_signed_2.signature = signature;
			node_1_closing_signed_2
		};
		nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed_2_bad);

		let events = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::HandleError {
				action: msgs::ErrorAction::SendWarningMessage { .. }, ref node_id
			} => {
				assert_eq!(node_id, &nodes[1].node.get_our_node_id());
			},
			_ => panic!("Unexpected event: {:?}", events[0]),
		};
	}

	nodes[0].node.signer_unblocked(None);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());

	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_closing_signed) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_closing_signed.is_none());

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_event!(nodes[0], 1, ClosureReason::LocallyInitiatedCooperativeClosure, [nodes[1].node.get_our_node_id()], 100000);
	check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyInitiatedCooperativeClosure, [nodes[0].node.get_our_node_id()], 100000);
}
