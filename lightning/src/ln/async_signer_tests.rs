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

use bitcoin::{Transaction, TxOut, TxIn, Amount};
use bitcoin::locktime::absolute::LockTime;
use bitcoin::transaction::Version;

use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::events::bump_transaction::WalletSource;
use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider, ClosureReason};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};
use crate::util::test_channel_signer::SignerOp;

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
	nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
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
	nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Send a payment.
	let src = &nodes[0];
	let dst = &nodes[1];
	let (route, our_payment_hash, _our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(src, dst, 8000000);
	src.node.send_payment_with_route(&route, our_payment_hash,
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
	dst.disable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	dst.node.handle_commitment_signed(&src.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors(dst, 1);

	get_event_msg!(dst, MessageSendEvent::SendRevokeAndACK, src.node.get_our_node_id());

	// Mark dst's signer as available and retry: we now expect to see dst's `commitment_signed`.
	dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	dst.node.signer_unblocked(Some((src.node.get_our_node_id(), chan_id)));

	let events = dst.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1, "expected one message, got {}", events.len());
	if let MessageSendEvent::UpdateHTLCs { ref node_id, .. } = events[0] {
		assert_eq!(node_id, &src.node.get_our_node_id());
	} else {
		panic!("expected UpdateHTLCs message, not {:?}", events[0]);
	};
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
	nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
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

#[test]
fn test_async_commitment_signature_for_peer_disconnect() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, chan_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);

	// Send a payment.
	let src = &nodes[0];
	let dst = &nodes[1];
	let (route, our_payment_hash, _our_payment_preimage, our_payment_secret) = get_route_and_payment_hash!(src, dst, 8000000);
	src.node.send_payment_with_route(&route, our_payment_hash,
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
	dst.disable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	dst.node.handle_commitment_signed(&src.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors(dst, 1);

	get_event_msg!(dst, MessageSendEvent::SendRevokeAndACK, src.node.get_our_node_id());

	// Now disconnect and reconnect the peers.
	src.node.peer_disconnected(&dst.node.get_our_node_id());
	dst.node.peer_disconnected(&src.node.get_our_node_id());
	let mut reconnect_args = ReconnectArgs::new(&nodes[0], &nodes[1]);
	reconnect_args.send_channel_ready = (false, false);
	reconnect_args.pending_raa = (true, false);
	reconnect_nodes(reconnect_args);

	// Mark dst's signer as available and retry: we now expect to see dst's `commitment_signed`.
	dst.enable_channel_signer_op(&src.node.get_our_node_id(), &chan_id, SignerOp::SignCounterpartyCommitment);
	dst.node.signer_unblocked(Some((src.node.get_our_node_id(), chan_id)));

	{
		let events = dst.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1, "expected one message, got {}", events.len());
		if let MessageSendEvent::UpdateHTLCs { ref node_id, .. } = events[0] {
			assert_eq!(node_id, &src.node.get_our_node_id());
		} else {
			panic!("expected UpdateHTLCs message, not {:?}", events[0]);
		};
	}
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
		closing_node.wallet_source.add_utxo(bitcoin::OutPoint { txid: coinbase_tx.txid(), vout: 0 }, coinbase_tx.output[0].value);
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
			if txn[0].input[0].previous_output.txid == funding_tx.txid() {
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
