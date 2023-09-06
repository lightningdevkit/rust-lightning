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

use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields};

#[test]
fn test_async_commitment_signature_for_funding_created() {
	// Simulate acquiring the signature for `funding_created` asynchronously.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();

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
	nodes[0].set_channel_signer_available(&nodes[1].node.get_our_node_id(), &temporary_channel_id, false);
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

	nodes[0].set_channel_signer_available(&nodes[1].node.get_our_node_id(), &chan_id, true);
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

	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();

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
	nodes[1].set_channel_signer_available(&nodes[0].node.get_our_node_id(), &temporary_channel_id, false);
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
	nodes[1].set_channel_signer_available(&nodes[0].node.get_our_node_id(), &chan_id, true);
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
	dst.set_channel_signer_available(&src.node.get_our_node_id(), &chan_id, false);
	dst.node.handle_commitment_signed(&src.node.get_our_node_id(), &payment_event.commitment_msg);
	check_added_monitors(dst, 1);

	get_event_msg!(dst, MessageSendEvent::SendRevokeAndACK, src.node.get_our_node_id());

	// Mark dst's signer as available and retry: we now expect to see dst's `commitment_signed`.
	dst.set_channel_signer_available(&src.node.get_our_node_id(), &chan_id, true);
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
	nodes[0].node.create_channel(nodes[1].node.get_our_node_id(), 100000, 10001, 42, None).unwrap();
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
	assert_eq!(accept_channel.minimum_depth, 0, "Expected minimum depth of 0");
	nodes[0].node.handle_accept_channel(&nodes[1].node.get_our_node_id(), &accept_channel);

	// nodes[0] --- funding_created --> nodes[1]
	let (temporary_channel_id, tx, _) = create_funding_transaction(&nodes[0], &nodes[1].node.get_our_node_id(), 100000, 42);
	nodes[0].node.funding_transaction_generated(&temporary_channel_id, &nodes[1].node.get_our_node_id(), tx.clone()).unwrap();
	check_added_monitors(&nodes[0], 0);

	let mut funding_created_msg = get_event_msg!(nodes[0], MessageSendEvent::SendFundingCreated, nodes[1].node.get_our_node_id());

	// Now let's make node[1]'s signer be unavailable while handling the `funding_created`. It should
	// *not* broadcast a `funding_signed`...
	nodes[1].set_channel_signer_available(&nodes[0].node.get_our_node_id(), &temporary_channel_id, false);
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
	nodes[1].set_channel_signer_available(&nodes[0].node.get_our_node_id(), &chan_id, true);
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
	dst.set_channel_signer_available(&src.node.get_our_node_id(), &chan_id, false);
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
	dst.set_channel_signer_available(&src.node.get_our_node_id(), &chan_id, true);
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
