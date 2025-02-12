use crate::chain::ChannelMonitorUpdateStatus;
use crate::events::HTLCDestination;
use crate::events::MessageSendEvent;
use crate::events::MessageSendEventsProvider;
use crate::ln::channelmanager::PaymentId;
use crate::ln::channelmanager::RecipientOnionFields;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{ChannelMessageHandler, ErrorAction};
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
	assert!(!nodes[1].node.exit_quiescence(&nodes[0].node.get_our_node_id(), &chan_id).unwrap());
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
	remote_node.node.handle_commitment_signed(local_node_id, &update_add.commitment_signed);
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
	local_node.node.handle_commitment_signed(remote_node_id, &commit_sig);
	check_added_monitors(local_node, 1);

	let last_revoke_and_ack =
		get_event_msg!(local_node, MessageSendEvent::SendRevokeAndACK, remote_node_id);
	remote_node.node.handle_revoke_and_ack(local_node_id, &last_revoke_and_ack);
	check_added_monitors(remote_node, 1);
	expect_pending_htlcs_forwardable!(remote_node);
	expect_htlc_handling_failed_destinations!(
		remote_node.node.get_and_clear_pending_events(),
		&[HTLCDestination::FailedPayment { payment_hash }]
	);
	check_added_monitors(remote_node, 1);

	let update_fail = get_htlc_update_msgs!(remote_node, local_node_id);
	local_node.node.handle_update_fail_htlc(remote_node_id, &update_fail.update_fail_htlcs[0]);
	local_node.node.handle_commitment_signed(remote_node_id, &update_fail.commitment_signed);

	let (revoke_and_ack, commit_sig) = get_revoke_commit_msgs!(local_node, remote_node_id);
	remote_node.node.handle_revoke_and_ack(local_node_id, &revoke_and_ack);
	check_added_monitors(remote_node, 1);
	remote_node.node.handle_commitment_signed(local_node_id, &commit_sig);
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
	local_node.node.exit_quiescence(&remote_node_id, &chan_id).unwrap();

	let _ = get_event_msg!(local_node, MessageSendEvent::SendClosingSigned, remote_node_id);
	check_added_monitors(local_node, 2); // One for the last revoke_and_ack, another for closing_signed
}

#[test]
fn test_quiescence_tracks_monitor_update_in_progress_and_waits_for_async_signer() {
	// Test that quiescence:
	//   a) considers an async signer when determining whether a pending channel update exists
	//   b) tracks in-progress monitor updates until no longer quiescent
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

	let update = get_htlc_update_msgs!(&nodes[1], node_id_0);
	nodes[0].node.handle_update_fulfill_htlc(node_id_1, &update.update_fulfill_htlcs[0]);
	nodes[0].node.handle_commitment_signed(node_id_1, &update.commitment_signed);
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
	nodes[1].node.handle_commitment_signed(node_id_0, &commit_sig);
	check_added_monitors(&nodes[1], 1);

	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	// Resume the signer. We should now expect to see both messages.
	nodes[1].enable_channel_signer_op(&node_id_0, &chan_id, SignerOp::ReleaseCommitmentSecret);
	nodes[1].node.signer_unblocked(Some((node_id_0, chan_id)));

	expect_payment_claimed!(&nodes[1], payment_hash, payment_amount);

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

	// While handling the last `revoke_and_ack` on nodes[0], we'll hold the monitor update and
	// become quiescent.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_revoke_and_ack(node_id_1, &revoke_and_ack);

	nodes[0].node.handle_stfu(node_id_1, &stfu);
	let stfu = get_event_msg!(&nodes[0], MessageSendEvent::SendStfu, node_id_1);
	nodes[1].node.handle_stfu(node_id_0, &stfu);

	nodes[0].node.exit_quiescence(&node_id_1, &chan_id).unwrap();
	nodes[1].node.exit_quiescence(&node_id_0, &chan_id).unwrap();

	// After exiting quiescence, we should be able to resume payments from nodes[0], but the monitor
	// update has yet to complete. Attempting to send a payment now will be delayed until the
	// monitor update completes.
	{
		let (route, payment_hash, _, payment_secret) =
			get_route_and_payment_hash!(&nodes[0], &nodes[1], payment_amount);
		let onion = RecipientOnionFields::secret_only(payment_secret);
		let payment_id = PaymentId(payment_hash.0);
		nodes[0].node.send_payment_with_route(route, payment_hash, onion, payment_id).unwrap();
	}
	check_added_monitors(&nodes[0], 0);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// We have two updates pending:
	{
		let chain_monitor = &nodes[0].chain_monitor;
		let (_, latest_update) =
			chain_monitor.latest_monitor_update_id.lock().unwrap().get(&chan_id).unwrap().clone();
		let chain_monitor = &nodes[0].chain_monitor.chain_monitor;
		// One for the latest commitment transaction update from the last `revoke_and_ack`
		chain_monitor.channel_monitor_updated(chan_id, latest_update - 1).unwrap();
		expect_payment_sent(&nodes[0], preimage, None, true, true);
		// One for the commitment secret update from the last `revoke_and_ack`
		chain_monitor.channel_monitor_updated(chan_id, latest_update).unwrap();
	}

	// With the pending monitor updates complete, we'll see a new monitor update go out when freeing
	// the holding cells to send out the new HTLC.
	nodes[0].chain_monitor.complete_sole_pending_chan_update(&chan_id);
	let _ = get_htlc_update_msgs!(&nodes[0], node_id_1);
	check_added_monitors(&nodes[0], 1);
}
