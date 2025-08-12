use crate::chain::ChannelMonitorUpdateStatus;
use crate::events::{Event, HTLCHandlingFailureType};
use crate::ln::channel::DISCONNECT_PEER_AWAITING_RESPONSE_TICKS;
use crate::ln::channelmanager::PaymentId;
use crate::ln::channelmanager::RecipientOnionFields;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, ErrorAction, MessageSendEvent};
use crate::util::errors::APIError;
use crate::util::test_channel_signer::SignerOp;

#[test]
fn test_quiescence_tie() {
	// Test that both nodes proposing quiescence at the same time results in the channel funder
	// becoming the quiescence initiator.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	nodes[0].node.maybe_propose_quiescence(&nodes[1].node.get_our_node_id(), &chan_id).unwrap();
	nodes[1].node.maybe_propose_quiescence(&nodes[0].node.get_our_node_id(), &chan_id).unwrap();

	let stfu_node_0 =
		get_event_msg!(nodes[0], MessageSendEvent::SendStfu, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_stfu(nodes[0].node.get_our_node_id(), &stfu_node_0);

	let stfu_node_1 =
		get_event_msg!(nodes[1], MessageSendEvent::SendStfu, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_stfu(nodes[1].node.get_our_node_id(), &stfu_node_1);

	assert!(stfu_node_0.initiator && stfu_node_1.initiator);

	assert!(nodes[0].node.exit_quiescence(&nodes[1].node.get_our_node_id(), &chan_id).unwrap());
	assert!(nodes[1].node.exit_quiescence(&nodes[0].node.get_our_node_id(), &chan_id).unwrap());
}

#[test]
fn test_quiescence_shutdown_ignored() {
	// Test that a shutdown sent/received during quiescence is ignored.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	nodes[0].node.maybe_propose_quiescence(&nodes[1].node.get_our_node_id(), &chan_id).unwrap();
	let _ = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, nodes[1].node.get_our_node_id());

	if let Err(e) = nodes[0].node.close_channel(&chan_id, &nodes[1].node.get_our_node_id()) {
		assert_eq!(
			e,
			APIError::APIMisuseError { err: "Cannot begin shutdown while quiescent".to_owned() }
		);
	} else {
		panic!("Expected shutdown to be ignored while quiescent");
	}

	nodes[1].node.close_channel(&chan_id, &nodes[0].node.get_our_node_id()).unwrap();
	let shutdown =
		get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_shutdown(nodes[1].node.get_our_node_id(), &shutdown);
	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	match msg_events[0] {
		MessageSendEvent::HandleError {
			action: ErrorAction::DisconnectPeerWithWarning { ref msg, .. },
			..
		} => {
			assert_eq!(msg.data, "Got shutdown request while quiescent".to_owned());
		},
		_ => panic!(),
	}
}

#[test]
fn test_allow_shutdown_while_awaiting_quiescence() {
	allow_shutdown_while_awaiting_quiescence(false);
	allow_shutdown_while_awaiting_quiescence(true);
}

fn allow_shutdown_while_awaiting_quiescence(local_shutdown: bool) {
	// Test that a shutdown sent/received while we're still awaiting quiescence (stfu has not been
	// sent yet) is honored and the channel is closed cooperatively.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let local_node = &nodes[0];
	let remote_node = &nodes[1];
	let local_node_id = local_node.node.get_our_node_id();
	let remote_node_id = remote_node.node.get_our_node_id();

	let payment_amount = 1_000_000;
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(local_node, remote_node, payment_amount);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let payment_id = PaymentId(payment_hash.0);
	local_node.node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();
	check_added_monitors!(local_node, 1);

	// Attempt to send an HTLC, but don't fully commit it yet.
	let update_add = get_htlc_update_msgs!(local_node, remote_node_id);
	remote_node.node.handle_update_add_htlc(local_node_id, &update_add.update_add_htlcs[0]);
	remote_node
		.node
		.handle_commitment_signed_batch_test(local_node_id, &update_add.commitment_signed);
	let (revoke_and_ack, commit_sig) = get_revoke_commit_msgs!(remote_node, local_node_id);
	local_node.node.handle_revoke_and_ack(remote_node_id, &revoke_and_ack);
	check_added_monitors(local_node, 1);

	// Request the local node to propose quiescence, and immediately try to close the channel. Since
	// we haven't sent `stfu` yet as the state machine is pending, we should forget about our
	// quiescence attempt.
	local_node.node.maybe_propose_quiescence(&remote_node_id, &chan_id).unwrap();
	assert!(local_node.node.get_and_clear_pending_msg_events().is_empty());

	let (closer_node, closee_node) =
		if local_shutdown { (local_node, remote_node) } else { (remote_node, local_node) };
	let closer_node_id = closer_node.node.get_our_node_id();
	let closee_node_id = closee_node.node.get_our_node_id();

	closer_node.node.close_channel(&chan_id, &closee_node_id).unwrap();
	check_added_monitors(&remote_node, 1);
	let shutdown_initiator =
		get_event_msg!(closer_node, MessageSendEvent::SendShutdown, closee_node_id);
	closee_node.node.handle_shutdown(closer_node_id, &shutdown_initiator);
	let shutdown_responder =
		get_event_msg!(closee_node, MessageSendEvent::SendShutdown, closer_node_id);
	closer_node.node.handle_shutdown(closee_node_id, &shutdown_responder);

	// Continue exchanging messages until the HTLC is irrevocably committed and eventually failed
	// back as we are shutting down.
	local_node.node.handle_commitment_signed_batch_test(remote_node_id, &commit_sig);
	check_added_monitors(local_node, 1);

	let last_revoke_and_ack =
		get_event_msg!(local_node, MessageSendEvent::SendRevokeAndACK, remote_node_id);
	remote_node.node.handle_revoke_and_ack(local_node_id, &last_revoke_and_ack);
	check_added_monitors(remote_node, 1);
	expect_and_process_pending_htlcs(remote_node, false);
	expect_htlc_handling_failed_destinations!(
		remote_node.node.get_and_clear_pending_events(),
		&[HTLCHandlingFailureType::Receive { payment_hash }]
	);
	check_added_monitors(remote_node, 1);

	let update_fail = get_htlc_update_msgs!(remote_node, local_node_id);
	local_node.node.handle_update_fail_htlc(remote_node_id, &update_fail.update_fail_htlcs[0]);
	local_node
		.node
		.handle_commitment_signed_batch_test(remote_node_id, &update_fail.commitment_signed);

	let (revoke_and_ack, commit_sig) = get_revoke_commit_msgs!(local_node, remote_node_id);
	remote_node.node.handle_revoke_and_ack(local_node_id, &revoke_and_ack);
	check_added_monitors(remote_node, 1);
	remote_node.node.handle_commitment_signed_batch_test(local_node_id, &commit_sig);
	check_added_monitors(remote_node, 1);

	let last_revoke_and_ack =
		get_event_msg!(remote_node, MessageSendEvent::SendRevokeAndACK, local_node_id);
	local_node.node.handle_revoke_and_ack(remote_node_id, &last_revoke_and_ack);

	expect_payment_failed_conditions(
		local_node,
		payment_hash,
		true,
		PaymentFailedConditions::new(),
	);

	// Now that the state machine is no longer pending, and `closing_signed` is ready to be sent,
	// make sure we're still not waiting for the quiescence handshake to complete.
	// Note that we never actually reached full quiescence here.
	assert!(!local_node.node.exit_quiescence(&remote_node_id, &chan_id).unwrap());

	let _ = get_event_msg!(local_node, MessageSendEvent::SendClosingSigned, remote_node_id);
	check_added_monitors(local_node, 2); // One for the last revoke_and_ack, another for closing_signed
}

#[test]
fn test_quiescence_waits_for_async_signer_and_monitor_update() {
	// Test that quiescence:
	//   a) considers an async signer when determining whether a pending channel update exists
	//   b) waits until pending monitor updates complete to send `stfu`/become quiescent
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let payment_amount = 1_000_000;
	let (preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], payment_amount);
	nodes[1].node.claim_funds(preimage);
	check_added_monitors(&nodes[1], 1);
	expect_payment_claimed!(&nodes[1], payment_hash, payment_amount);

	let mut update = get_htlc_update_msgs!(&nodes[1], node_id_0);
	nodes[0].node.handle_update_fulfill_htlc(node_id_1, update.update_fulfill_htlcs.remove(0));
	nodes[0].node.handle_commitment_signed_batch_test(node_id_1, &update.commitment_signed);
	check_added_monitors(&nodes[0], 1);

	// While settling back the payment, propose quiescence from nodes[1]. We won't see its `stfu` go
	// out yet as the `update_fulfill` is still pending on both sides.
	nodes[1].node.maybe_propose_quiescence(&node_id_0, &chan_id).unwrap();

	// Disable releasing commitment secrets on nodes[1], to hold back their `stfu` until the
	// `revoke_and_ack` goes out, and drive the state machine forward.
	nodes[1].disable_channel_signer_op(&node_id_0, &chan_id, SignerOp::ReleaseCommitmentSecret);

	let (revoke_and_ack, commit_sig) = get_revoke_commit_msgs!(&nodes[0], node_id_1);
	nodes[1].node.handle_revoke_and_ack(node_id_0, &revoke_and_ack);
	check_added_monitors(&nodes[1], 1);
	nodes[1].node.handle_commitment_signed_batch_test(node_id_0, &commit_sig);
	check_added_monitors(&nodes[1], 1);

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Resume the signer. We should now expect to see both messages.
	nodes[1].enable_channel_signer_op(&node_id_0, &chan_id, SignerOp::ReleaseCommitmentSecret);
	nodes[1].node.signer_unblocked(Some((node_id_0, chan_id)));

	macro_rules! find_msg {
		($events: expr, $msg: ident) => {{
			$events
				.iter()
				.find_map(|event| {
					if let MessageSendEvent::$msg { ref msg, .. } = event {
						Some(msg)
					} else {
						None
					}
				})
				.unwrap()
		}};
	}
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	let revoke_and_ack = find_msg!(msg_events, SendRevokeAndACK);
	let stfu = find_msg!(msg_events, SendStfu);

	// While handling the last `revoke_and_ack` on nodes[0], we'll hold the monitor update. We
	// cannot become quiescent until it completes.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_revoke_and_ack(node_id_1, &revoke_and_ack);

	nodes[0].node.handle_stfu(node_id_1, &stfu);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// We have two updates pending:
	{
		let test_chain_mon = &nodes[0].chain_monitor;
		let (_, latest_update) =
			test_chain_mon.latest_monitor_update_id.lock().unwrap().get(&chan_id).unwrap().clone();
		let chain_monitor = &nodes[0].chain_monitor.chain_monitor;
		// One for the latest commitment transaction update from the last `revoke_and_ack`
		chain_monitor.channel_monitor_updated(chan_id, latest_update).unwrap();
		expect_payment_sent(&nodes[0], preimage, None, false, true);

		let (_, new_latest_update) =
			test_chain_mon.latest_monitor_update_id.lock().unwrap().get(&chan_id).unwrap().clone();
		assert_eq!(new_latest_update, latest_update + 1);
		// One for the commitment secret update from the last `revoke_and_ack`
		chain_monitor.channel_monitor_updated(chan_id, new_latest_update).unwrap();
		// Once that update completes, we'll get the `PaymentPathSuccessful` event
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		if let Event::PaymentPathSuccessful { .. } = &events[0] {
		} else {
			panic!("{events:?}");
		}
	}

	// With the updates completed, we can now become quiescent.
	let stfu = get_event_msg!(&nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu);

	assert!(nodes[0].node.exit_quiescence(&node_id_1, &chan_id).unwrap());
	assert!(nodes[1].node.exit_quiescence(&node_id_0, &chan_id).unwrap());

	// After exiting quiescence, we should be able to resume payments from nodes[0].
	send_payment(&nodes[0], &[&nodes[1]], payment_amount);
}

#[test]
fn test_quiescence_on_final_revoke_and_ack_pending_monitor_update() {
	// Test that we do not let a pending monitor update for a final `revoke_and_ack` prevent us from
	// entering quiescence. This was caught by the fuzzer, reported as #3805.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	let payment_amount = 1_000_000;
	let (route, payment_hash, _, payment_secret) =
		get_route_and_payment_hash!(&nodes[0], &nodes[1], payment_amount);
	let onion = RecipientOnionFields::secret_only(payment_secret);
	let payment_id = PaymentId(payment_hash.0);
	nodes[0].node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();
	check_added_monitors(&nodes[0], 1);

	nodes[1].node.maybe_propose_quiescence(&node_id_0, &chan_id).unwrap();
	let stfu = get_event_msg!(&nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu);

	let update_add = get_htlc_update_msgs!(&nodes[0], node_id_1);
	nodes[1].node.handle_update_add_htlc(node_id_0, &update_add.update_add_htlcs[0]);
	nodes[1].node.handle_commitment_signed_batch_test(node_id_0, &update_add.commitment_signed);
	check_added_monitors(&nodes[1], 1);

	let (revoke_and_ack, commit_sig) = get_revoke_commit_msgs!(&nodes[1], node_id_0);
	nodes[0].node.handle_revoke_and_ack(node_id_1, &revoke_and_ack);
	check_added_monitors(&nodes[0], 1);
	nodes[0].node.handle_commitment_signed_batch_test(node_id_1, &commit_sig);
	check_added_monitors(&nodes[0], 1);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	let msgs = nodes[0].node.get_and_clear_pending_msg_events();
	if let MessageSendEvent::SendRevokeAndACK { msg, .. } = &msgs[0] {
		nodes[1].node.handle_revoke_and_ack(node_id_0, &msg);
		check_added_monitors(&nodes[1], 1);
	} else {
		panic!();
	}
	if let MessageSendEvent::SendStfu { msg, .. } = &msgs[1] {
		nodes[1].node.handle_stfu(node_id_0, &msg);
	} else {
		panic!();
	}

	assert!(nodes[0].node.exit_quiescence(&node_id_1, &chan_id).unwrap());
	assert!(nodes[1].node.exit_quiescence(&node_id_0, &chan_id).unwrap());
}

#[test]
fn test_quiescence_updates_go_to_holding_cell() {
	quiescence_updates_go_to_holding_cell(false);
	quiescence_updates_go_to_holding_cell(true);
}

fn quiescence_updates_go_to_holding_cell(fail_htlc: bool) {
	// Test that any updates made to a channel while quiescent go to the holding cell.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	// Send enough to be able to pay from both directions.
	let payment_amount = 1_000_000;
	send_payment(&nodes[0], &[&nodes[1]], payment_amount * 4);

	// Propose quiescence from nodes[1], and immediately try to send a payment. Since its `stfu` has
	// already gone out first, the outbound HTLC will go into the holding cell.
	nodes[1].node.maybe_propose_quiescence(&node_id_0, &chan_id).unwrap();
	let stfu = get_event_msg!(&nodes[1], MessageSendEvent::SendStfu, node_id_0);

	let (route1, payment_hash1, payment_preimage1, payment_secret1) =
		get_route_and_payment_hash!(&nodes[1], &nodes[0], payment_amount);
	let onion1 = RecipientOnionFields::secret_only(payment_secret1);
	let payment_id1 = PaymentId(payment_hash1.0);
	nodes[1].node.send_payment_with_route(route1, payment_hash1, onion1, payment_id1).unwrap();
	check_added_monitors!(&nodes[1], 0);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Send a payment in the opposite direction. Since nodes[0] hasn't sent its own `stfu` yet, it's
	// allowed to make updates.
	let (route2, payment_hash2, payment_preimage2, payment_secret2) =
		get_route_and_payment_hash!(&nodes[0], &nodes[1], payment_amount);
	let onion2 = RecipientOnionFields::secret_only(payment_secret2);
	let payment_id2 = PaymentId(payment_hash2.0);
	nodes[0].node.send_payment_with_route(route2, payment_hash2, onion2, payment_id2).unwrap();
	check_added_monitors!(&nodes[0], 1);

	let update_add = get_htlc_update_msgs!(&nodes[0], node_id_1);
	nodes[1].node.handle_update_add_htlc(node_id_0, &update_add.update_add_htlcs[0]);
	commitment_signed_dance!(&nodes[1], &nodes[0], update_add.commitment_signed, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	expect_payment_claimable!(nodes[1], payment_hash2, payment_secret2, payment_amount);

	// Have nodes[1] attempt to fail/claim nodes[0]'s payment. Since nodes[1] already sent out
	// `stfu`, the `update_fail/fulfill` will go into the holding cell.
	if fail_htlc {
		nodes[1].node.fail_htlc_backwards(&payment_hash2);
		let failed_payment = HTLCHandlingFailureType::Receive { payment_hash: payment_hash2 };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[1], &[failed_payment]);
	} else {
		nodes[1].node.claim_funds(payment_preimage2);
		check_added_monitors(&nodes[1], 1);
	}
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Finish the quiescence handshake.
	nodes[0].node.handle_stfu(node_id_1, &stfu);
	let stfu = get_event_msg!(&nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu);

	assert!(nodes[0].node.exit_quiescence(&node_id_1, &chan_id).unwrap());
	assert!(nodes[1].node.exit_quiescence(&node_id_0, &chan_id).unwrap());

	// Now that quiescence is over, nodes are allowed to make updates again. nodes[1] will have its
	// outbound HTLC finally go out, along with the fail/claim of nodes[0]'s payment.
	let mut update = get_htlc_update_msgs!(&nodes[1], node_id_0);
	check_added_monitors(&nodes[1], 1);
	nodes[0].node.handle_update_add_htlc(node_id_1, &update.update_add_htlcs[0]);
	if fail_htlc {
		nodes[0].node.handle_update_fail_htlc(node_id_1, &update.update_fail_htlcs[0]);
	} else {
		expect_payment_claimed!(nodes[1], payment_hash2, payment_amount);
		nodes[0].node.handle_update_fulfill_htlc(node_id_1, update.update_fulfill_htlcs.remove(0));
	}
	commitment_signed_dance!(&nodes[0], &nodes[1], update.commitment_signed, false);

	// The payment from nodes[0] should now be seen as failed/successful.
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	if fail_htlc {
		assert!(events.iter().find(|e| matches!(e, Event::PaymentFailed { .. })).is_some());
		assert!(events.iter().find(|e| matches!(e, Event::PaymentPathFailed { .. })).is_some());
	} else {
		assert!(events.iter().find(|e| matches!(e, Event::PaymentSent { .. })).is_some());
		assert!(events.iter().find(|e| matches!(e, Event::PaymentPathSuccessful { .. })).is_some());
		check_added_monitors(&nodes[0], 1);
	}
	nodes[0].node.process_pending_htlc_forwards();
	expect_payment_claimable!(nodes[0], payment_hash1, payment_secret1, payment_amount);

	// Have nodes[0] fail/claim nodes[1]'s payment.
	if fail_htlc {
		nodes[0].node.fail_htlc_backwards(&payment_hash1);
		let failed_payment = HTLCHandlingFailureType::Receive { payment_hash: payment_hash1 };
		expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[0], &[failed_payment]);
	} else {
		nodes[0].node.claim_funds(payment_preimage1);
	}
	check_added_monitors(&nodes[0], 1);

	let mut update = get_htlc_update_msgs!(&nodes[0], node_id_1);
	if fail_htlc {
		nodes[1].node.handle_update_fail_htlc(node_id_0, &update.update_fail_htlcs[0]);
	} else {
		expect_payment_claimed!(nodes[0], payment_hash1, payment_amount);
		nodes[1].node.handle_update_fulfill_htlc(node_id_0, update.update_fulfill_htlcs.remove(0));
	}
	commitment_signed_dance!(&nodes[1], &nodes[0], update.commitment_signed, false);

	// The payment from nodes[1] should now be seen as failed/successful.
	if fail_htlc {
		let conditions = PaymentFailedConditions::new();
		expect_payment_failed_conditions(&nodes[1], payment_hash1, true, conditions);
	} else {
		expect_payment_sent(&nodes[1], payment_preimage1, None, true, true);
	}
}

#[test]
fn test_quiescence_timeout() {
	// Test that we'll disconnect if we remain quiescent for `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	nodes[0].node.maybe_propose_quiescence(&nodes[1].node.get_our_node_id(), &chan_id).unwrap();

	let stfu_initiator = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu_initiator);

	let stfu_responder = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);
	nodes[0].node.handle_stfu(node_id_1, &stfu_responder);

	assert!(stfu_initiator.initiator && !stfu_responder.initiator);

	for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS {
		nodes[0].node.timer_tick_occurred();
		nodes[1].node.timer_tick_occurred();
	}

	let f = |event| {
		if let MessageSendEvent::HandleError { action, .. } = event {
			if let msgs::ErrorAction::DisconnectPeerWithWarning { .. } = action {
				Some(())
			} else {
				None
			}
		} else {
			None
		}
	};
	assert!(nodes[0].node.get_and_clear_pending_msg_events().into_iter().find_map(f).is_some());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().into_iter().find_map(f).is_some());
}

#[test]
fn test_quiescence_timeout_while_waiting_for_counterparty_stfu() {
	// Test that we'll disconnect if the counterparty does not send their stfu within a reasonable
	// time if we've already sent ours.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let node_id_0 = nodes[0].node.get_our_node_id();

	nodes[1].node.maybe_propose_quiescence(&node_id_0, &chan_id).unwrap();
	let _ = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);

	// Route a payment in between to ensure expecting to receive `revoke_and_ack` doesn't override
	// the expectation of receiving `stfu` as well.
	let _ = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);

	for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS {
		nodes[0].node.timer_tick_occurred();
		nodes[1].node.timer_tick_occurred();
	}

	// nodes[0] hasn't received stfu from nodes[1], so it's not enforcing any timeouts.
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// nodes[1] didn't receive nodes[0]'s stfu within the timeout so it'll disconnect.
	let f = |&ref event| {
		if let MessageSendEvent::HandleError { action, .. } = event {
			if let msgs::ErrorAction::DisconnectPeerWithWarning { .. } = action {
				Some(())
			} else {
				None
			}
		} else {
			None
		}
	};
	assert!(nodes[1].node.get_and_clear_pending_msg_events().iter().find_map(f).is_some());
}

#[test]
fn test_quiescence_timeout_while_waiting_for_counterparty_something_fundamental() {
	// Test that we'll disconnect if the counterparty does not send their "something fundamental"
	// within a reasonable time if we've reached quiescence.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let node_id_0 = nodes[0].node.get_our_node_id();
	let node_id_1 = nodes[1].node.get_our_node_id();

	nodes[1].node.maybe_propose_quiescence(&node_id_0, &chan_id).unwrap();
	let stfu = get_event_msg!(nodes[1], MessageSendEvent::SendStfu, node_id_0);

	nodes[0].node.handle_stfu(node_id_1, &stfu);
	let _stfu = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_id_1);

	for _ in 0..DISCONNECT_PEER_AWAITING_RESPONSE_TICKS {
		nodes[0].node.timer_tick_occurred();
		nodes[1].node.timer_tick_occurred();
	}

	// Node B didn't receive node A's stfu within the timeout so it'll disconnect.
	let f = |event| {
		if let MessageSendEvent::HandleError { action, .. } = event {
			if let msgs::ErrorAction::DisconnectPeerWithWarning { .. } = action {
				Some(())
			} else {
				None
			}
		} else {
			None
		}
	};
	// At this point, node A is waiting on B to do something fundamental, and node B is waiting on
	// A's stfu that we never delivered. Thus both should disconnect each other.
	assert!(nodes[0].node.get_and_clear_pending_msg_events().into_iter().find_map(&f).is_some());
	assert!(nodes[1].node.get_and_clear_pending_msg_events().into_iter().find_map(&f).is_some());
}

fn do_test_quiescence_during_disconnection(with_pending_claim: bool, propose_disconnected: bool) {
	// Test that we'll start trying for quiescence immediately after reconnection if we're waiting
	// to do some quiescence-required action.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let node_a_id = nodes[0].node.get_our_node_id();
	let node_b_id = nodes[1].node.get_our_node_id();

	// First get both nodes off the starting state so we don't have to deal with channel_ready
	// retransmissions on reconect.
	send_payment(&nodes[0], &[&nodes[1]], 100_000);

	let (preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 100_000);
	if with_pending_claim {
		// Optionally reconnect with pending quiescence while there's some pending messages to
		// deliver.
		nodes[1].node.claim_funds(preimage);
		check_added_monitors(&nodes[1], 1);
		expect_payment_claimed!(nodes[1], payment_hash, 100_000);
		let _ = get_htlc_update_msgs(&nodes[1], &node_a_id);
	}

	if !propose_disconnected {
		nodes[1].node.maybe_propose_quiescence(&node_a_id, &chan_id).unwrap();
	}

	nodes[0].node.peer_disconnected(node_b_id);
	nodes[1].node.peer_disconnected(node_a_id);

	if propose_disconnected {
		nodes[1].node.maybe_propose_quiescence(&node_a_id, &chan_id).unwrap();
	}

	let init_msg = msgs::Init {
		features: nodes[1].node.init_features(),
		networks: None,
		remote_network_address: None,
	};
	nodes[0].node.peer_connected(node_b_id, &init_msg, true).unwrap();
	nodes[1].node.peer_connected(node_a_id, &init_msg, true).unwrap();

	let reestab_a = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, node_b_id);
	let reestab_b = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, node_a_id);

	nodes[0].node.handle_channel_reestablish(node_b_id, &reestab_b);
	get_event_msg!(nodes[0], MessageSendEvent::SendChannelUpdate, node_b_id);

	nodes[1].node.handle_channel_reestablish(node_a_id, &reestab_a);
	let mut bs_msgs = nodes[1].node.get_and_clear_pending_msg_events();
	bs_msgs.retain(|msg| !matches!(msg, MessageSendEvent::SendChannelUpdate { .. }));
	assert_eq!(bs_msgs.len(), 1, "{bs_msgs:?}");
	let stfu = if with_pending_claim {
		// Node B should first re-send its channel update, then try to enter quiescence once that
		// completes...
		let msg = bs_msgs.pop().unwrap();
		if let MessageSendEvent::UpdateHTLCs { mut updates, .. } = msg {
			let fulfill = updates.update_fulfill_htlcs.pop().unwrap();
			nodes[0].node.handle_update_fulfill_htlc(node_b_id, fulfill);
			let cs = updates.commitment_signed;
			nodes[0].node.handle_commitment_signed_batch_test(node_b_id, &cs);
			check_added_monitors(&nodes[0], 1);

			let (raa, cs) = get_revoke_commit_msgs(&nodes[0], &node_b_id);
			nodes[1].node.handle_revoke_and_ack(node_a_id, &raa);
			check_added_monitors(&nodes[1], 1);
			nodes[1].node.handle_commitment_signed_batch_test(node_a_id, &cs);
			check_added_monitors(&nodes[1], 1);

			let mut bs_raa_stfu = nodes[1].node.get_and_clear_pending_msg_events();
			assert_eq!(bs_raa_stfu.len(), 2);
			if let MessageSendEvent::SendRevokeAndACK { msg, .. } = &bs_raa_stfu[0] {
				nodes[0].node.handle_revoke_and_ack(node_b_id, &msg);
				expect_payment_sent!(&nodes[0], preimage);
			} else {
				panic!("Unexpected first message {bs_raa_stfu:?}");
			}

			bs_raa_stfu.pop().unwrap()
		} else {
			panic!("Unexpected message {msg:?}");
		}
	} else {
		bs_msgs.pop().unwrap()
	};
	if let MessageSendEvent::SendStfu { msg, .. } = stfu {
		nodes[0].node.handle_stfu(node_b_id, &msg);
	} else {
		panic!("Unexpected message {stfu:?}");
	}

	let stfu_resp = get_event_msg!(nodes[0], MessageSendEvent::SendStfu, node_b_id);
	nodes[1].node.handle_stfu(node_a_id, &stfu_resp);

	assert!(nodes[0].node.exit_quiescence(&node_b_id, &chan_id).unwrap());
	assert!(nodes[1].node.exit_quiescence(&node_a_id, &chan_id).unwrap());
}

#[test]
fn test_quiescence_during_disconnection() {
	do_test_quiescence_during_disconnection(false, false);
	do_test_quiescence_during_disconnection(true, false);
	do_test_quiescence_during_disconnection(false, true);
	do_test_quiescence_during_disconnection(true, true);
}
